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
pub(crate) mod udp_relay;

// 供隧道 DNS 目标头回归测试直接调服务端真解析 (dns::server 测试用)。
#[cfg(test)]
pub(crate) use control::parse_tcp_target;

use camouflage_pool::CamouflagePool;

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use tokio::net::TcpListener;
use tracing::{debug, error, info};

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
    auth_ts_tolerance_secs: u64,
    upstream: Option<std::sync::Arc<crate::proxy::upstream::UpstreamOutlet>>,
    pfs: bool,
) {
    let listener = match TcpListener::bind(listen_addr).await {
        Ok(l) => l,
        Err(e) => {
            error!("Failed to bind Mirage Server on {}: {}", listen_addr, e);
            return;
        }
    };
    info!("Mirage Server listening on {} (auth 时钟容差 ±{}s)", listen_addr, auth_ts_tolerance_secs);

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
                // 屏蔽名单 (WebUI 管理): 被屏蔽的客户端 IP 立即关连接, 省掉握手/BPF/brutal 全部开销。
                if crate::blocklist::is_blocked(&peer_addr.ip()) {
                    debug!("Mirage Server: 拒绝被屏蔽客户端 {}", peer_addr.ip());
                    drop(stream);
                    continue;
                }
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
                let up = upstream.clone();
                tokio::spawn(async move {
                    handshake::handle_connection(stream, peer_addr, pwd, cam, pool, auth_ts_tolerance_secs, up, pfs).await;
                });
            }
            Err(e) => {
                error!("Mirage Server accept error: {}", e);
            }
        }
    }
}

/// QUIC 服务端 (P0 实验, `--features quic`)。监听 UDP, 每条双向流当一条隧道, 复用 TCP 路径的
/// 握手/鉴权/中继逻辑 (经 handle_connection_quic → run_handshake 泛型)。brutal/eBPF sockops RTT
/// 是 TCP 内核特性, QUIC 不适用故不接。⚠️ 指纹不隐蔽, 见 docs/quic-transport-design.md。
#[cfg(feature = "quic")]
#[allow(clippy::too_many_arguments)]
pub async fn start_quic_server(
    listen_addr: &str,
    password: &str,
    camouflage_host: &str,
    auth_ts_tolerance_secs: u64,
    upstream: Option<std::sync::Arc<crate::proxy::upstream::UpstreamOutlet>>,
    pfs: bool,
    quic_window_mb: u64,
    quic_erasure_cc: bool,
    quic_obfs: Option<String>,
) {
    let addr: std::net::SocketAddr = match listen_addr.parse() {
        Ok(a) => a,
        Err(e) => {
            error!("Mirage QUIC Server: listen 地址须为 IP:port ({}): {}", listen_addr, e);
            return;
        }
    };
    let endpoint = match crate::proxy::quic::server_endpoint(addr, quic_window_mb, quic_erasure_cc, quic_obfs.as_deref()) {
        Ok(ep) => ep,
        Err(e) => {
            error!("Mirage QUIC Server: 绑定失败 {}: {:#}", listen_addr, e);
            return;
        }
    };
    info!("Mirage QUIC Server listening on {} (UDP, 实验传输 · auth 容差 ±{}s)", listen_addr, auth_ts_tolerance_secs);

    let _ = (camouflage_host, pfs); // Model X 精简: QUIC 路径不用 camouflage/fake-TLS/pfs
    let password = password.to_string();

    while let Some(incoming) = endpoint.accept().await {
        let pwd = password.clone();
        let up = upstream.clone();
        tokio::spawn(async move {
            let conn = match incoming.await {
                Ok(c) => c,
                Err(_) => return, // QUIC 握手失败 (对端非法/超时)
            };
            let peer = conn.remote_address();
            if crate::blocklist::is_blocked(&peer.ip()) {
                debug!("Mirage QUIC Server: 拒绝被屏蔽客户端 {}", peer.ip());
                return;
            }
            // 一条 QUIC 连接可承载多条双向流 (每条 = 一条隧道)。逐条 accept_bi, 各自成 task。
            // Model X 精简: 每流 [token][target][data], 无 per-stream fake-TLS、无内层 AEAD (QUIC 自加密)。
            loop {
                match conn.accept_bi().await {
                    Ok((send, recv)) => {
                        let pwd2 = pwd.clone();
                        let up2 = up.clone();
                        tokio::spawn(async move {
                            handle_quic_stream_lean(send, recv, peer.ip(), pwd2, auth_ts_tolerance_secs, up2).await;
                        });
                    }
                    Err(_) => break, // 连接关闭
                }
            }
        });
    }
}

/// Model X 精简 QUIC 流处理: `[token(32B)][2B target_len][target][data...]`, 无 per-stream fake-TLS、
/// 无内层 AEAD (QUIC 自己的 TLS1.3 已加密所有流)。token 为无状态每流认证 (HMAC 密码+时间, 32B 无往返)。
/// 直连出口 (upstream=SS/WG 的 lean 路径暂不支持, 有则拒)。
#[cfg(feature = "quic")]
async fn handle_quic_stream_lean(
    send: quinn::SendStream,
    mut recv: quinn::RecvStream,
    peer_ip: IpAddr,
    password: String,
    tol: u64,
    upstream: Option<std::sync::Arc<crate::proxy::upstream::UpstreamOutlet>>,
) {
    if upstream.is_some() {
        debug!("Mirage QUIC(lean): 暂不支持上游中继, 拒绝 (改用 TCP 传输或 direct)");
        return;
    }
    // 1. token (32B) — 无状态每流认证。
    let mut token = [0u8; 32];
    match tokio::time::timeout(std::time::Duration::from_secs(5), recv.read_exact(&mut token)).await {
        Ok(Ok(_)) => {}
        _ => return,
    }
    if !crate::crypto::hello_auth::verify_session_token(&password, &token, tol) {
        static HINTED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
        if !HINTED.swap(true, Ordering::Relaxed) {
            tracing::warn!("Mirage QUIC(lean): token 认证失败 from {} ({})", peer_ip,
                crate::crypto::hello_auth::session_decrypt_failure_hint());
        }
        return;
    }
    // 2. target: [2B len][host:port]
    let mut lenb = [0u8; 2];
    if tokio::time::timeout(std::time::Duration::from_secs(10), recv.read_exact(&mut lenb)).await.map(|r| r.is_err()).unwrap_or(true) {
        return;
    }
    let n = u16::from_be_bytes(lenb) as usize;
    if n == 0 || n > 512 { return; }
    let mut tb = vec![0u8; n];
    if tokio::time::timeout(std::time::Duration::from_secs(10), recv.read_exact(&mut tb)).await.map(|r| r.is_err()).unwrap_or(true) {
        return;
    }
    let target = match String::from_utf8(tb) {
        Ok(t) => t,
        Err(_) => return,
    };
    // 3. 直连出口
    let mut up = match crate::proxy::resolver::connect_smart(&target).await {
        Ok(s) => s,
        Err(e) => { tracing::warn!("Mirage QUIC(lean): 连 {} 失败: {}", target, e); return; }
    };
    let _conn = crate::monitor::register(
        target.clone(), peer_ip.to_string(), "direct".to_string(), "quic", None, Some(peer_ip.to_string()),
    );
    // 4. 裸转发 (QUIC 加密, 无内层 AEAD)。
    let mut stream = crate::proxy::quic::QuicBiStream::new(send, recv);
    let _ = tokio::io::copy_bidirectional(&mut stream, &mut up).await;
}
