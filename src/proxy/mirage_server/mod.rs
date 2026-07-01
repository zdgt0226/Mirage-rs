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
mod control;
mod tcp_relay;
mod udp_relay;

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
        let mut map = UNAUTH_CONNS.get_or_init(|| Mutex::new(HashMap::new())).lock().unwrap();
        if let Some(c) = map.get_mut(&self.0) {
            *c = c.saturating_sub(1);
            if *c == 0 { map.remove(&self.0); }
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

                // 显式设 SO_SNDBUF + SO_RCVBUF = 8MB. server→client 是视频下
                // 载的主要方向, 长 BDP 链路 (200ms × 40Mbps ≈ 1MB) 起手 buffer
                // 太小会 rwnd_limited 反复卡. kernel auto-tune 慢启动, 手动置
                // 大值 disable auto-tune 立即拿满 buffer.
                {
                    use std::os::unix::io::AsRawFd;
                    let fd = stream.as_raw_fd();
                    unsafe {
                        let val: libc::c_int = 8 * 1024 * 1024;
                        libc::setsockopt(fd, libc::SOL_SOCKET, libc::SO_SNDBUF,
                            &val as *const _ as *const libc::c_void,
                            std::mem::size_of::<libc::c_int>() as libc::socklen_t);
                        libc::setsockopt(fd, libc::SOL_SOCKET, libc::SO_RCVBUF,
                            &val as *const _ as *const libc::c_void,
                            std::mem::size_of::<libc::c_int>() as libc::socklen_t);
                    }
                }

                let pwd = password.clone();
                let cam = camouflage_host.to_string();
                tokio::spawn(async move {
                    handshake::handle_connection(stream, peer_addr, pwd, cam).await;
                });
            }
            Err(e) => {
                error!("Mirage Server accept error: {}", e);
            }
        }
    }
}
