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
    if let Some(bps) = brutal_rate_bytes_per_sec {
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
                // 控制 server→client 方向的发送速率 (下载速度). 这是代理用户
                // 最关心的方向, 比客户端 outbound 那侧的 brutal 重要得多.
                //
                // apply_brutal 同时启自适应回落 monitor: 部分链路 (跨洲 CDN 等)
                // 实际丢包率高, brutal 死磕设定速率会让 retrans 吃光带宽. monitor
                // 检测到单窗口 retrans > 5% 自动 setsockopt 切回 BBR, 让 kernel
                // 自适应. 这样服务端默认开 brutal 在适合的链路 (高 RTT 低丢包)
                // 享受加速, 不适合的链路 (高丢包) 也不会比 BBR 差.
                if let Some(rate) = brutal_rate_bytes_per_sec {
                    use std::os::unix::io::AsRawFd;
                    let fd = stream.as_raw_fd();
                    crate::proxy::brutal::apply_brutal(fd, rate);
                    crate::proxy::brutal::spawn_fallback_monitor(fd);
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
