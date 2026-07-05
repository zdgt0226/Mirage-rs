//! Mirage 服务端入站. 协议解密 + 上游 TCP/UDP 转发.
//!
//! 模块拓扑 (v0.4.2 重组):
//! - `mod.rs` 本文件: start_server + accept 循环 + UNAUTH 限流 (本模块共享状态)
//! - `handshake`: ClientHello 解析 + token 验证 + ServerHello 模拟 + 63B tail
//! - `camouflage`: auth 失败时伪装成正常 TLS 转发到真实站点 (反 GFW 探测)
//! - `control`: crypto channel 建立 + TIME_SYNC 帧 + first_chunk 接收 + TCP/UDP 分发
//! - `tcp_relay`: TCP 上游转发 (协议解密后)
//! - `udp_relay`: UDP 上游转发 (协议解密后)

mod handshake;
mod camouflage;
mod camouflage_pool;
mod control;
mod tcp_relay;
mod udp_relay;

use camouflage_pool::CamouflagePool;

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use tokio::net::TcpListener;
use tracing::{error, info};

// UNAUTH 限流 (整个 mirage_server 子模块共用). handshake.rs 在 auth 失败时
// 增 count, IpSlotGuard 在 drop 时回收.
pub(super) static UNAUTH_CONNS: OnceLock<Mutex<HashMap<IpAddr, usize>>> = OnceLock::new();
pub(super) static GLOBAL_UNAUTH: AtomicUsize = AtomicUsize::new(0);

pub(super) struct IpSlotGuard(pub(super) IpAddr);
impl Drop for IpSlotGuard {
    fn drop(&mut self) {
        GLOBAL_UNAUTH.fetch_sub(1, Ordering::SeqCst);
        // ⚠️ 决不在 Drop 里对锁 .unwrap(): 若此 drop 发生在 panic 栈展开中, 锁又
        // 恰好中毒 (持锁线程 panic 过), unwrap 二次 panic → double-panic abort
        // 当场杀进程. 用 into_inner 容忍中毒继续 —— 临界区只做 get_mut/
        // saturating_sub/remove, 数据结构不会被破坏到不可用. get() 而非
        // get_or_init: 能存在 Guard 说明插入侧已初始化过 map, 没有就没东西可减.
        if let Some(mutex) = UNAUTH_CONNS.get() {
            let mut map = match mutex.lock() {
                Ok(g) => g,
                Err(poisoned) => poisoned.into_inner(),
            };
            if let Some(c) = map.get_mut(&self.0) {
                *c = c.saturating_sub(1);
                if *c == 0 { map.remove(&self.0); }
            }
        }
    }
}

pub async fn start_server(
    listen_addr: &str,
    password: &str,
    camouflage_host: &str,
    ebpf_engine: Option<Arc<tokio::sync::Mutex<crate::ebpf::EbpfEngine>>>,
    brutal_rate_bytes_per_sec: Option<u64>,
) {
    let listener = match TcpListener::bind(listen_addr).await {
        Ok(l) => l,
        Err(e) => {
            error!("Failed to bind Mirage Server on {}: {}", listen_addr, e);
            return;
        }
    };
    info!("Mirage Server listening on {}", listen_addr);

    // Brutal CC 必须在 listener 上预设算法名, 让 accept 出来的子 socket 从
    // SYN-ACK 起就是 brutal. 在已 ESTABLISHED 的 accepted socket 上中途切换
    // CC 会导致 kernel pacing 状态不一致, 实测吞吐塌方 (跟 Python POC 对比
    // 发现这个差异, 见 v0.4.4-alpha.8 CHANGELOG).
    if let Some(bps) = brutal_rate_bytes_per_sec {
        use std::os::unix::io::AsRawFd;
        crate::proxy::brutal::set_brutal_on_listener(listener.as_raw_fd());
        info!("Brutal CC enabled for downloads (server→client): {} Mbps", bps / 125_000);
    }

    // v0.4.5-alpha.7: 启动 camouflage_host 预热连接池, 消除 auth-fail 分支
    // TCP 3-way RTT 时序侧信道. 详见 camouflage_pool.rs 顶注释.
    let cam_pool = CamouflagePool::new(camouflage_host.to_string());

    // v0.4.5-alpha.15: accept 前主动预热 HandshakeCache. 消除懒预热的冷启动窗口
    // (重启后首个连接不再触发 fetch 或拿 fallback → 时序异常). camouflage 不可达
    // 时最多阻塞 ~5s 后放行 (懒路径兜底), 不长期挂起启动.
    crate::crypto::handshake_cache::prewarm(camouflage_host).await;

    let password = password.to_string();
    loop {
        match listener.accept().await {
            Ok((stream, peer_addr)) => {
                // 把客户端 IP 登记到 BPF mirage_target_ips 白名单, 让 sockops
                // RTT_CB 收集这条连接的 RTT/cwnd/重传 (没登记的连接 BPF 直接
                // return 0 不写 map). 用 try_lock 避免阻塞 accept 循环.
                if let Some(engine) = &ebpf_engine {
                    if let Ok(mut e) = engine.try_lock() {
                        let _ = e.set_target_ip(peer_addr.ip());
                    }
                }
                // accepted socket 已从 listener 继承 brutal 算法名, 只需补
                // 速率参数 (TCP_BRUTAL_PARAMS). brutal 的设计哲学就是"丢包
                // 是噪声, 死磕设定速率", 高 retrans 是 brutal 工作中的正常
                // 现象, 不是 brutal "不适合"的信号. alpha.6 加的 autofallback
                // 在 10s 内就因 retrans > 5% 把 brutal 切掉, 反而让 brutal
                // 没机会发挥, 实测速度低于 Python POC (POC 无 autofallback,
                // brutal 顶着丢包硬跑). spawn_fallback_monitor 代码保留在
                // brutal.rs, 留作未来 tuning.brutal_autofallback = true 的
                // opt-in 高级选项, 默认不调用.
                if let Some(rate) = brutal_rate_bytes_per_sec {
                    use std::os::unix::io::AsRawFd;
                    crate::proxy::brutal::set_brutal_rate(stream.as_raw_fd(), rate);
                }

                // alpha.25 撤回 alpha.21 加的显式 SO_SNDBUF/SO_RCVBUF. 手动
                // 固定 8MB 反而 disable TCP auto-tune 拖垮吞吐 (7× 回归),
                // 让 kernel 自适应 BDP+丢包动态调节. 详见 tcp_relay.rs 注释.

                let pwd = password.clone();
                let cam = camouflage_host.to_string();
                let pool = cam_pool.clone();
                tokio::spawn(async move {
                    handshake::handle_connection(stream, peer_addr, pwd, cam, pool).await;
                });
            }
            Err(e) => {
                error!("Mirage Server accept error: {}", e);
            }
        }
    }
}
