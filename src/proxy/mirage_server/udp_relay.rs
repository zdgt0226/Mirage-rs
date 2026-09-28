//! 服务端 UDP 上游转发. 加密 channel 内嵌"伪 SOCKS5 UDP" 帧格式封装多目标
//! UDP 包. 跟 src/proxy/udp_relay.rs (客户端 UDP forwarding) 语义不同, 故独立.
//!
//! 帧格式: [2B Len N][1B ATYP][ADDR][2B PORT][PAYLOAD]
//! ATYP: 1=IPv4, 3=Domain, 4=IPv6

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::UdpSocket;
use tracing::{debug, error};

/// UDP 会话双向 idle 上限。任一方向静默超此值即拆流, 防客户端弱网断连(无 FIN)
/// 导致 task/UdpSocket/64KB buf 僵尸泄露 (对齐 tcp_relay 的 1800s 兜底思路; UDP
/// 流更短, 且客户端透明 UDP 自身 60s idle 即拆, 300s 只作服务端兜底不误杀活跃流)。
const UDP_IDLE_TIMEOUT: Duration = Duration::from_secs(300);

/// 白名单最大目标数 (防无限膨胀)
pub(crate) const MAX_SENT_TARGETS: usize = 1024;

/// 记录上行发送目标地址及时间戳。
/// 满额 (>= capacity) 时先淘汰超过 idle_timeout 未刷新的目标;
/// 若仍满额, 淘汰最旧的一条 (按时间戳最早)。
pub(crate) fn record_sent_target(
    targets: &mut std::collections::HashMap<SocketAddr, std::time::Instant>,
    target: SocketAddr,
    now: std::time::Instant,
    idle_timeout: Duration,
    capacity: usize,
) {
    if let std::collections::hash_map::Entry::Occupied(mut e) = targets.entry(target) {
        e.insert(now);
        return;
    }
    if targets.len() >= capacity {
        targets.retain(|_, last_sent| now.saturating_duration_since(*last_sent) <= idle_timeout);
        if targets.len() >= capacity {
            if let Some((&oldest, _)) = targets.iter().min_by_key(|(_, t)| *t) {
                targets.remove(&oldest);
            }
        }
    }
    targets.insert(target, now);
}

/// 下行回包帧体: `[1B ATYP][ADDR][2B PORT][PAYLOAD]` (外层再加 2B 长度)。
/// `from` 须已经过 normalize_addr (IPv4-mapped 还原为 IPv4), 否则双栈 socket 上的 IPv4 回包会被编码成 IPv6。
pub(crate) fn encode_reply_frame(from: SocketAddr, payload: &[u8]) -> Vec<u8> {
    let mut frame = Vec::with_capacity(1 + 16 + 2 + payload.len());
    match from.ip() {
        std::net::IpAddr::V4(ip) => {
            frame.push(1);
            frame.extend_from_slice(&ip.octets());
        }
        std::net::IpAddr::V6(ip) => {
            frame.push(4);
            frame.extend_from_slice(&ip.octets());
        }
    }
    frame.extend_from_slice(&from.port().to_be_bytes());
    frame.extend_from_slice(payload);
    frame
}

/// 将目标地址转换为双栈/单栈 direct socket 所需的目标地址。
/// 若 socket 为双栈 (`is_dual_stack == true`):
/// - IPv4 转换为 IPv4-mapped IPv6 (`::ffff:a.b.c.d:port`)
/// - IPv6 保持不变
///
/// 若 socket 为 IPv4 单栈 (`is_dual_stack == false`):
/// - IPv4 保持不变
/// - IPv6 返回 None (调用方丢弃并记录 debug 日志)
pub(crate) fn prepare_target_addr(target: SocketAddr, is_dual_stack: bool) -> Option<SocketAddr> {
    match target {
        SocketAddr::V4(v4) => {
            if is_dual_stack {
                Some(SocketAddr::V6(std::net::SocketAddrV6::new(
                    v4.ip().to_ipv6_mapped(),
                    v4.port(),
                    0,
                    0,
                )))
            } else {
                Some(SocketAddr::V4(v4))
            }
        }
        SocketAddr::V6(_) => {
            if is_dual_stack {
                Some(target)
            } else {
                None
            }
        }
    }
}

/// 将 SocketAddr 归一化 (IPv4-mapped IPv6 转为 IPv4, 便于地址比较)。
fn normalize_addr(addr: std::net::SocketAddr) -> std::net::SocketAddr {
    match addr {
        std::net::SocketAddr::V6(v6) => {
            if let Some(v4) = v6.ip().to_ipv4_mapped() {
                std::net::SocketAddr::new(std::net::IpAddr::V4(v4), v6.port())
            } else {
                std::net::SocketAddr::V6(v6)
            }
        }
        v4 => v4,
    }
}

/// UDP 中继的出口。
///
/// `Direct` = 从本机 IP 发出去 (不配上游、或上游 udp=direct);
/// `Wireguard` = 经 WG 隧道发出去, **与 TCP 同一个出口 IP** —— 这正是配中转的本意。
enum UdpEgress {
    Direct(Arc<UdpSocket>),
    Wireguard(Arc<crate::proxy::wg::socket::WgUdpSocket>),
}

impl UdpEgress {
    async fn send_to(&self, payload: &[u8], addr: std::net::SocketAddr) -> std::io::Result<()> {
        match self {
            Self::Direct(s) => s.send_to(payload, addr).await.map(|_| ()),
            // 隧道侧是同步入队 (数据进 smoltcp 缓冲后由 pump 加密发出), 不阻塞。
            Self::Wireguard(s) => s
                .send_to(payload, addr)
                .map_err(|e| std::io::Error::other(e.to_string())),
        }
    }

    async fn recv_from(
        &self,
        buf: &mut [u8],
    ) -> std::io::Result<(usize, std::net::SocketAddr)> {
        match self {
            Self::Direct(s) => s.recv_from(buf).await,
            Self::Wireguard(s) => s
                .recv_from(buf)
                .await
                .map_err(|e| std::io::Error::other(e.to_string())),
        }
    }
}

pub(super) async fn handle_udp_relay(
    mut reader: crate::crypto::aead::CryptoReader<crate::proxy::tunnel::TunnelRead>,
    writer: crate::crypto::aead::CryptoWriter<crate::proxy::tunnel::TunnelWrite>,
    upstream: Option<Arc<crate::proxy::upstream::UpstreamOutlet>>,
    client_ip: Option<std::net::IpAddr>,
    user: String,
    session_auth: super::SessionAuth,
    allow_local_targets: bool,
) {
    debug!("Mirage Server: Started UDP relay session");

    // 服务端按连接的客户端 IP 限速 (device_profiles rate_limit_kbps): UDP 无背压 → policing
    // (令牌不足丢包), 与 SOCKS/transparent UDP 一致; 全局 limiter 同 tcp_relay::server_buckets_for。
    let dev_buckets = client_ip.and_then(crate::proxy::rate_limit::server_buckets_for);

    // 上游是 WG 且策略为 tunnel → UDP 也走隧道, 出口与 TCP 一致。否则从本机直发。
    // 非 mux 路径直发: 优先绑定 [::]:0 双栈; 失败则回退 0.0.0.0:0。
    let (egress, is_dual_stack) = match upstream.as_deref() {
        Some(crate::proxy::upstream::UpstreamOutlet::Wireguard(wg))
            if matches!(wg.udp, crate::config::UdpPolicy::Tunnel) =>
        {
            let tunnel = match wg.tunnel().await {
                Ok(t) => t,
                Err(e) => {
                    error!("UDP 中继: 建立 WG 上游隧道失败: {}", e);
                    return;
                }
            };
            match crate::proxy::wg::socket::WgUdpSocket::bind(tunnel) {
                Ok(s) => (UdpEgress::Wireguard(Arc::new(s)), false),
                Err(e) => {
                    error!("UDP 中继: 隧道内绑 UDP 失败: {}", e);
                    return;
                }
            }
        }
        // 双栈: 绑 [::]:0, 发往 IPv4 目标时转 IPv4-mapped (见 prepare_target_addr)。依赖 IPV6_V6ONLY=0
        // (Linux 默认); 若主机设了 net.ipv6.bindv6only=1 则该 socket 只通 IPv6 → 退回 0.0.0.0:0 保 IPv4
        // (Linux 上 bind 后不能再改 v6only, 故绑后探测而非强设)。
        _ => match UdpSocket::bind("[::]:0").await.ok().filter(|s| {
            !nix::sys::socket::getsockopt(s, nix::sys::socket::sockopt::Ipv6V6Only).unwrap_or(true)
        }) {
            Some(s) => (UdpEgress::Direct(Arc::new(s)), true),
            None => {
                debug!("[::]:0 dual-stack UDP socket unavailable (bind failed or v6only), falling back to 0.0.0.0:0");
                match UdpSocket::bind("0.0.0.0:0").await {
                    Ok(s) => (UdpEgress::Direct(Arc::new(s)), false),
                    Err(e) => {
                        error!("Failed to bind server UDP socket: {}", e);
                        return;
                    }
                }
            }
        },
    };
    let udp_socket = Arc::new(egress);

    let (tx, mut rx) = tokio::sync::mpsc::channel(256);
    let udp_clone = udp_socket.clone();

    // 维护该会话已发送过的目标地址集合 (限制 1024 条防膨胀)。
    // 记最近一次向该目标发送的时间, 供下行校验回包来源 (阻止未授权来源注入数据及恶意消耗用户配额)。
    let sent_targets: Arc<std::sync::Mutex<std::collections::HashMap<SocketAddr, std::time::Instant>>> =
        Arc::new(std::sync::Mutex::new(std::collections::HashMap::new()));
    let sent_targets_down = sent_targets.clone();
    let sent_targets_up = sent_targets.clone();

    let writer = std::sync::Arc::new(tokio::sync::Mutex::new(writer));
    let writer_clone = writer.clone();

    let dn_buckets = dev_buckets.clone();
    let dn_auth = session_auth.clone();
    let downlink = tokio::spawn(async move {
        let mut buf = vec![0u8; 65536];
        loop {
            if dn_auth.should_stop() {
                break;
            }
            match tokio::time::timeout(UDP_IDLE_TIMEOUT, udp_clone.recv_from(&mut buf)).await {
                Ok(Ok((size, addr))) => {
                    // 校验回包来源: 丢弃未知来源的包 (不计费、不回送)。
                    // 自动处理 IPv4-mapped IPv6 (::ffff:a.b.c.d)。
                    // 注意: 这会收紧 full-cone UDP (如某些 STUN/P2P 游戏) 语义为 restricted-cone。
                    let norm = normalize_addr(addr);
                    if !sent_targets_down
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .contains_key(&norm)
                    {
                        continue;
                    }
                    // 下行限速 (policing): 令牌不足丢本报文 (按 payload 字节计), 两桶都扣 (取更严)
                    if !crate::proxy::rate_limit::try_consume_two(
                        dn_buckets.as_ref().map(|b| &b.down),
                        dn_auth.user_limit.as_ref().and_then(|u| u.buckets()).as_ref().map(|b| &b.down),
                        size,
                    ) {
                        continue;
                    }
                    if dn_auth.record_bytes(size) {
                        break; // 越额或吊销退出
                    }
                    // Frame format: [2B Len N][1B ATYP][ADDR][2B PORT][PAYLOAD]
                    // 用归一化后的来源地址封帧: 双栈 socket 上 IPv4 目标的回包来源是 ::ffff:a.b.c.d,
                    // 原样编码会成 ATYP=4 + 16B, 客户端按 IPv6 回给应用 → IPv4 UDP 回包全丢。
                    let frame = encode_reply_frame(norm, &buf[..size]);

                    if frame.len() > u16::MAX as usize {
                        debug!(
                            "Mirage Server UDP: 下行帧长度 ({}B) 超过 u16::MAX, 丢弃该报文以防解帧失步",
                            frame.len()
                        );
                        continue;
                    }

                    let frame_len = frame.len() as u16;
                    let mut packet = Vec::with_capacity(2 + frame.len());
                    packet.extend_from_slice(&frame_len.to_be_bytes());
                    packet.extend_from_slice(&frame);

                    if tx.send(packet).await.is_err() {
                        break;
                    }
                }
                _ => break, // 上游静默超 UDP_IDLE_TIMEOUT 或 socket 错误 → 拆流
            }
        }
    });

    // 修 bug: cancel-safety. 旧版用 tokio::select!(uplink, downlink), 一方完成
    // 时 select! 暴力 drop 另一方, 若 downlink 正在 writer.send_data 半截
    // (TLS 5 字节 header 已写出去, AEAD payload 没写完) 会留下半截帧, 接着外层
    // send_close_notify 又写一个 alert, 客户端 AEAD MAC 校验崩 → bad record mac.
    //
    // 修复: 用 watch 频道做协作式停止信号. 两 task 都 tokio::join! (而不是 select),
    // select! 仅围绕 read 点 (recv_data / rx.recv 都是 cancel-safe), write 全部
    // 在 select! 外面执行, 永远不会被中途打断. 任一方退出时 send(true), 另一方
    // 在下一次 read 边界 (changed() 返回) 检测到信号, 干净退出. 之后才 send_close_notify,
    // 此时绝无半截帧.
    let (stop_tx, _stop_rx_seed) = tokio::sync::watch::channel(false);
    let mut stop_rx_down = stop_tx.subscribe();
    let mut stop_rx_up = stop_tx.subscribe();
    let stop_tx_down = stop_tx.clone();
    let stop_tx_up = stop_tx.clone();

    let dn_auth_tunnel = session_auth.clone();
    let tunnel_downlink = async move {
        loop {
            if dn_auth_tunnel.should_stop() {
                break;
            }
            let packet = tokio::select! {
                biased;
                _ = stop_rx_down.changed() => break,
                p = rx.recv() => match p {
                    Some(p) => p,
                    None => break,
                }
            };
            // AEAD 写在 select! 外, 不会被中途取消
            if writer_clone.lock().await.send_data(&packet).await.is_err() {
                break;
            }
        }
        let _ = stop_tx_down.send(true);
    };

    let up_auth = session_auth.clone();
    let tunnel_uplink = async move {
        let mut buffer = Vec::new();
        'outer: loop {
            if up_auth.should_stop() {
                break;
            }
            let chunk = tokio::select! {
                biased;
                _ = stop_rx_up.changed() => break,
                r = tokio::time::timeout(UDP_IDLE_TIMEOUT, reader.recv_data()) => match r {
                    Ok(Ok(c)) => c,
                    _ => break, // 隧道静默超 UDP_IDLE_TIMEOUT (客户端弱网断连无 FIN) 或读错误
                }
            };

            buffer.extend_from_slice(&chunk);

            // 处理多包: 一次 recv 可能拿到多个 UDP 包帧
            while buffer.len() >= 2 {
                let frame_len = u16::from_be_bytes([buffer[0], buffer[1]]) as usize;
                if buffer.len() < 2 + frame_len {
                    break;
                }

                let frame = buffer[2..2+frame_len].to_vec();
                buffer.drain(0..2+frame_len);

                if frame.is_empty() { continue; }

                // Parse ATYP
                let atyp = frame[0];
                let mut offset = 1;
                let target_addr_str = match atyp {
                    1 => {
                        if frame.len() < offset + 4 { continue; }
                        let ip = std::net::Ipv4Addr::new(frame[offset], frame[offset+1], frame[offset+2], frame[offset+3]);
                        offset += 4;
                        ip.to_string()
                    }
                    3 => {
                        if frame.len() < offset + 1 { continue; }
                        let domain_len = frame[offset] as usize;
                        offset += 1;
                        if frame.len() < offset + domain_len { continue; }
                        let domain = String::from_utf8_lossy(&frame[offset..offset+domain_len]).to_string();
                        offset += domain_len;
                        domain
                    }
                    4 => {
                        if frame.len() < offset + 16 { continue; }
                        let mut octets = [0u8; 16];
                        octets.copy_from_slice(&frame[offset..offset+16]);
                        let ip = std::net::Ipv6Addr::from(octets);
                        offset += 16;
                        ip.to_string()
                    }
                    _ => continue,
                };

                if frame.len() < offset + 2 { continue; }
                let port = u16::from_be_bytes([frame[offset], frame[offset+1]]);
                offset += 2;

                let payload = &frame[offset..];

                // 上行限速 (policing): 令牌不足丢本报文 (按 payload 字节计), 两桶都扣 (取更严)
                if !crate::proxy::rate_limit::try_consume_two(
                    dev_buckets.as_ref().map(|b| &b.up),
                    up_auth.user_limit.as_ref().and_then(|u| u.buckets()).as_ref().map(|b| &b.up),
                    payload.len(),
                ) {
                    continue;
                }
                if up_auth.record_bytes(payload.len()) {
                    break 'outer; // 越额或吊销退出整个会话
                }

                // v0.4.5-alpha.16: 走 resolver::resolve_first_filtered (60s 缓存 + IPv4 优先 +
                // 并发限流 + 出站 SSRF 白名单过滤), 不再每 UDP 包裸调 lookup_host 打满阻塞池.
                // send_to 不是 AEAD 写, cancel 也无害 (UDP 本来就尽力而为).
                match crate::proxy::resolver::resolve_first_filtered(&target_addr_str, port, |ip| {
                    crate::net_util::egress_allowed(ip, allow_local_targets)
                }).await {
                    Ok(socket_addr) => {
                        let send_addr = if matches!(*udp_socket, UdpEgress::Direct(_)) {
                            match prepare_target_addr(socket_addr, is_dual_stack) {
                                Some(a) => a,
                                None => {
                                    debug!("UDP direct socket (IPv4 only): dropping IPv6 target {}", socket_addr);
                                    continue;
                                }
                            }
                        } else {
                            socket_addr
                        };

                        // P2-3 + P3-1: 发送前插入白名单并刷新时间 (先发后记可能导致极快回包被丢)
                        let norm = normalize_addr(socket_addr);
                        record_sent_target(
                            &mut sent_targets_up.lock().unwrap_or_else(|e| e.into_inner()),
                            norm,
                            std::time::Instant::now(),
                            UDP_IDLE_TIMEOUT,
                            MAX_SENT_TARGETS,
                        );

                        // send_to 失败以前被静默吞掉 —— VPS 封出向 UDP 时这里就是第一现场,
                        // 却完全无痕 (真机排障卡过)。一次性记下, 不刷屏 (高频 QUIC)。
                        // send_to 失败以前被静默吞掉 —— VPS 封出向 UDP 时这里就是第一现场,
                        // 却完全无痕 (真机排障卡过)。一次性记下, 不刷屏 (高频 QUIC)。
                        match udp_socket.send_to(payload, send_addr).await {
                            Ok(()) => {}
                            Err(e) => {
                                static WARNED: std::sync::atomic::AtomicBool =
                                    std::sync::atomic::AtomicBool::new(false);
                                if !WARNED.swap(true, std::sync::atomic::Ordering::Relaxed) {
                                    tracing::warn!(
                                        "UDP relay send_to {} 失败: {} —— 若持续, 本机(VPS)可能禁止出向 UDP",
                                        socket_addr, e
                                    );
                                }
                            }
                        }
                    }
                    Err(e) => {
                        if e.kind() == std::io::ErrorKind::PermissionDenied {
                            super::warn_egress_blocked(
                                "Mirage Server UDP",
                                &user,
                                &crate::net_util::join_host_port(&target_addr_str, port),
                            );
                        }
                        continue;
                    }
                }
            }
        }
        let _ = stop_tx_up.send(true);
    };

    // 用 join 而不是 select: 两 task 通过 stop_tx/rx 协作退出, 不被中途 drop.
    tokio::join!(tunnel_uplink, tunnel_downlink);

    // 此时两 task 都已干净退出, 没有任何 in-flight AEAD 写. close_notify 安全.
    let _ = writer.lock().await.send_close_notify().await;
    downlink.abort();
}

// ── UDP mux relay (session-id 多路复用) ──────────────────────────────────────
//
// 与 handle_udp_relay (一隧道一流) 的区别: 一条隧道复用多条客户端 UDP 流, 每流一个
// u32 sid。服务端按 sid 维护**独立 egress socket** (连接式, 两 sid 打同目标不串) + 独立
// 下行泵。所有下行回包经单一 mpsc 汇入唯一 AEAD writer (cancel-safe: 唯一写点在 writer
// 泵, 各 sid 泵只 recv UDP + send channel, 中途 abort 无半截 AEAD 帧)。

/// 单条 mux 隧道内的 sid 上限, 封顶资源 (每 sid ≈ 1 socket FD + 1 task + 64KB buf)。
const MAX_MUX_SIDS: usize = 512;

/// mux per-sid 下行泵 idle 上限。**远短于** legacy 的 300s (UDP_IDLE_TIMEOUT) —— 客户端对
/// mux 流 60s 即拆并单调分新 sid, 服务端若也留 300s, 高翻转 (QUIC 迁移/短连/游戏) 下死 sid
/// 会在窗口内堆满 512 → 新流黑洞。缩到 60s 对齐客户端, 让死 sid 快速自然回收。
const MUX_SID_IDLE_TIMEOUT: Duration = Duration::from_secs(60);

/// sid 表满时的丢弃计数 (限流打印, 免刷屏)。
static MUX_CAP_DROPS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// abort-on-drop: session 从表移除即中止其下行泵。
struct AbortOnDrop(tokio::task::JoinHandle<()>);
impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// 单个 sid 的出口: Direct=连接式 UDP socket; Wireguard=隧道内 socket + 目标地址。
enum SidEgress {
    Direct(UdpSocket),
    Wireguard(Arc<crate::proxy::wg::socket::WgUdpSocket>, std::net::SocketAddr),
}
impl SidEgress {
    async fn send(&self, payload: &[u8]) -> std::io::Result<()> {
        match self {
            Self::Direct(s) => s.send(payload).await.map(|_| ()),
            Self::Wireguard(s, dst) => s
                .send_to(payload, *dst)
                .map_err(|e| std::io::Error::other(e.to_string())),
        }
    }
    async fn recv(&self, buf: &mut [u8]) -> std::io::Result<usize> {
        match self {
            Self::Direct(s) => s.recv(buf).await,
            Self::Wireguard(s, dst) => loop {
                let (n, from) = s
                    .recv_from(buf)
                    .await
                    .map_err(|e| std::io::Error::other(e.to_string()))?;
                if normalize_addr(from) == normalize_addr(*dst) {
                    return Ok(n);
                }
            },
        }
    }
}

struct SidSession {
    egress: Arc<SidEgress>,
    _pump: AbortOnDrop,
}

type MuxSessions = Arc<std::sync::Mutex<std::collections::HashMap<u32, SidSession>>>;

fn lock_mux(s: &MuxSessions) -> std::sync::MutexGuard<'_, std::collections::HashMap<u32, SidSession>> {
    s.lock().unwrap_or_else(|e| e.into_inner())
}

pub(crate) async fn handle_udp_mux_relay(
    mut reader: crate::crypto::aead::CryptoReader<crate::proxy::tunnel::TunnelRead>,
    writer: crate::crypto::aead::CryptoWriter<crate::proxy::tunnel::TunnelWrite>,
    upstream: Option<Arc<crate::proxy::upstream::UpstreamOutlet>>,
    client_ip: Option<std::net::IpAddr>,
    user: String,
    session_auth: super::SessionAuth,
    allow_local_targets: bool,
) {
    debug!("Mirage Server: Started UDP MUX relay session");

    // 服务端按客户端 IP 限速 (device_profiles): mux 复用一条隧道多 sid, 但都同一客户端 IP →
    // 共享同一对桶, policing (令牌不足丢包)。同 handle_udp_relay。
    let dev_buckets = client_ip.and_then(crate::proxy::rate_limit::server_buckets_for);

    // 上游是否 WG-tunnel 出口 (与 TCP 同出口 IP)。是则各 sid 在同一 WG 隧道内绑独立端口。
    let wg_tunnel = match upstream.as_deref() {
        Some(crate::proxy::upstream::UpstreamOutlet::Wireguard(wg))
            if matches!(wg.udp, crate::config::UdpPolicy::Tunnel) =>
        {
            match wg.tunnel().await {
                Ok(t) => Some(t),
                Err(e) => {
                    error!("UDP mux: 建立 WG 上游隧道失败: {}", e);
                    return;
                }
            }
        }
        _ => None,
    };

    let writer = Arc::new(tokio::sync::Mutex::new(writer));
    // 所有 sid 下行泵的回包经此汇入唯一 AEAD writer 泵。
    let (tx, mut rx) = tokio::sync::mpsc::channel::<Vec<u8>>(1024);
    let sessions: MuxSessions = Arc::new(std::sync::Mutex::new(std::collections::HashMap::new()));

    // 协作式停止信号: writer_pump 检测到吊销/写失败时通知 uplink 立即退出 (不再阻塞在最长 300s 的 recv_data);
    // 反之 uplink 退出时也通知 writer_pump 立即结束。
    let (stop_tx, _stop_rx_seed) = tokio::sync::watch::channel(false);
    let mut stop_rx_up = stop_tx.subscribe();
    let mut stop_rx_writer = stop_tx.subscribe();
    let stop_tx_up = stop_tx.clone();
    let stop_tx_writer = stop_tx;

    // uplink: 读隧道 → 解 mux 帧 → 按 sid 分发 (新 sid 建 egress + spawn 下行泵)。
    let up_auth = session_auth.clone();
    let up_sessions = sessions.clone();
    let up_tx = tx.clone();
    let uplink = async move {
        let mut buffer: Vec<u8> = Vec::new();
        'outer: loop {
            if up_auth.should_stop() {
                break;
            }
            let chunk = tokio::select! {
                biased;
                _ = stop_rx_up.changed() => break,
                r = tokio::time::timeout(UDP_IDLE_TIMEOUT, reader.recv_data()) => match r {
                    Ok(Ok(c)) => c,
                    _ => break,
                }
            };
            buffer.extend_from_slice(&chunk);
            while let Some((consumed, frame_opt)) =
                crate::proxy::udp_mux::parse_mux_uplink(&buffer)
            {
                buffer.drain(0..consumed);
                let Some(uf) = frame_opt else { continue }; // 畸形帧, 跳过重同步

                // 上行限速 (policing): 令牌不足丢本报文 (choke point, 覆盖已有/新 sid 两路), 两桶都扣 (取更严)
                if !crate::proxy::rate_limit::try_consume_two(
                    dev_buckets.as_ref().map(|b| &b.up),
                    up_auth.user_limit.as_ref().and_then(|u| u.buckets()).as_ref().map(|b| &b.up),
                    uf.payload.len(),
                ) {
                    continue;
                }
                if up_auth.record_bytes(uf.payload.len()) {
                    break 'outer; // 越额或吊销退出整个会话
                }

                // 已有 sid → 直接发 (锁内只取 egress Arc, await 在锁外, 避免 guard 跨 await)。
                let existing = lock_mux(&up_sessions).get(&uf.sid).map(|s| s.egress.clone());
                if let Some(egress) = existing {
                    let _ = egress.send(&uf.payload).await;
                    continue;
                }
                // 新 sid: 到顶则丢 + 限流告警 (别静默黑洞 —— 客户端无信号, 只会看到 UDP 流死掉)。
                if lock_mux(&up_sessions).len() >= MAX_MUX_SIDS {
                    let n = MUX_CAP_DROPS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    if n.is_multiple_of(1000) {
                        tracing::warn!(
                            "UDP mux: 单隧道 sid 到上限 {}, 丢弃新流 (累计丢 {})。若持续, 说明 UDP 流\
                             翻转率高 —— 客户端会回落 TCP。",
                            MAX_MUX_SIDS,
                            n + 1
                        );
                    }
                    continue;
                }
                // 解析目标 (带 SSRF 校验: IP 字面量不解析, 域名走 60s 缓存 resolver)。
                let target_sa = match crate::proxy::resolver::resolve_first_filtered(&uf.target, uf.port, |ip| {
                    crate::net_util::egress_allowed(ip, allow_local_targets)
                }).await {
                    Ok(sa) => sa,
                    Err(e) => {
                        if e.kind() == std::io::ErrorKind::PermissionDenied {
                            super::warn_egress_blocked(
                                "Mirage Server UDP mux",
                                &user,
                                &crate::net_util::join_host_port(&uf.target, uf.port),
                            );
                        }
                        continue;
                    }
                };
                // 建 egress。
                let egress = match &wg_tunnel {
                    Some(t) => match crate::proxy::wg::socket::WgUdpSocket::bind(t.clone()) {
                        Ok(s) => SidEgress::Wireguard(Arc::new(s), target_sa),
                        Err(e) => {
                            debug!("UDP mux: WG 内绑 UDP 失败: {}", e);
                            continue;
                        }
                    },
                    None => {
                        let bind_addr = match target_sa {
                            SocketAddr::V4(_) => "0.0.0.0:0",
                            SocketAddr::V6(_) => "[::]:0",
                        };
                        match UdpSocket::bind(bind_addr).await {
                            Ok(s) => match s.connect(target_sa).await {
                                Ok(()) => SidEgress::Direct(s),
                                Err(_) => continue,
                            },
                            Err(_) => continue,
                        }
                    }
                };
                let egress = Arc::new(egress);
                // spawn 下行泵: egress.recv → frame_mux_addr(sid) → tx。
                let pump_egress = egress.clone();
                let pump_tx = up_tx.clone();
                let pump_sessions = up_sessions.clone();
                let pump_buckets = dev_buckets.clone();
                let pump_auth = up_auth.clone();
                let sid = uf.sid;
                let pump = tokio::spawn(async move {
                    let mut buf = vec![0u8; 65536];
                    loop {
                        if pump_auth.should_stop() {
                            break;
                        }
                        match tokio::time::timeout(MUX_SID_IDLE_TIMEOUT, pump_egress.recv(&mut buf))
                            .await
                        {
                            Ok(Ok(n)) => {
                                // 下行限速 (policing): 令牌不足丢本报文, 两桶都扣 (取更严)
                                if !crate::proxy::rate_limit::try_consume_two(
                                    pump_buckets.as_ref().map(|b| &b.down),
                                    pump_auth.user_limit.as_ref().and_then(|u| u.buckets()).as_ref().map(|b| &b.down),
                                    n,
                                ) {
                                    continue;
                                }
                                if pump_auth.record_bytes(n) {
                                    break; // 越额或吊销退出
                                }
                                if let Some(f) = crate::proxy::udp_mux::frame_mux_addr(
                                    sid,
                                    target_sa,
                                    &buf[..n],
                                ) {
                                    if pump_tx.send(f).await.is_err() {
                                        break;
                                    }
                                }
                            }
                            _ => break, // idle / 错误 → 拆此 sid
                        }
                    }
                    lock_mux(&pump_sessions).remove(&sid);
                });
                lock_mux(&up_sessions).insert(
                    sid,
                    SidSession { egress: egress.clone(), _pump: AbortOnDrop(pump) },
                );
                let _ = egress.send(&uf.payload).await;
            }
            if buffer.len() > 65536 * 2 {
                break; // 防异常累积
            }
        }
        // uplink 结束: 清 session 表 → 各 SidSession drop → 下行泵 abort → 释放 tx clone。
        lock_mux(&up_sessions).clear();
        let _ = stop_tx_up.send(true);
    };

    // writer 泵: 唯一 AEAD 写点。rx 在 uplink 结束清表 + 主 tx drop 后关闭 → 退出。
    drop(tx); // 只留 up_tx (uplink 持有) 与各泵 clone; uplink 退出后全部释放
    let writer_auth = session_auth.clone();
    let writer_pump = {
        let writer = writer.clone();
        async move {
            loop {
                let pkt = tokio::select! {
                    biased;
                    _ = stop_rx_writer.changed() => break,
                    p = rx.recv() => match p {
                        Some(p) => p,
                        None => break,
                    }
                };
                if writer_auth.should_stop() {
                    break;
                }
                if writer.lock().await.send_data(&pkt).await.is_err() {
                    break;
                }
            }
            let _ = stop_tx_writer.send(true);
        }
    };

    tokio::join!(uplink, writer_pump);

    let _ = writer.lock().await.send_close_notify().await;
}

#[cfg(test)]
mod mux_tests {
    use super::*;
    use crate::proxy::udp_mux::{frame_mux_ipv4, parse_mux_frame};
    use tokio::net::{TcpListener, TcpStream, UdpSocket as TokioUdp};

    /// 服务端 mux relay: 两条 sid 打**同一目标**, 回包不串 (per-sid 连接式 egress 的正确性)。
    #[tokio::test]
    async fn mux_two_sids_same_target_no_crosstalk() {
        // 1. UDP echo (回显 payload 给发送者)
        let echo = TokioUdp::bind("127.0.0.1:0").await.unwrap();
        let echo_addr = echo.local_addr().unwrap();
        tokio::spawn(async move {
            let mut b = [0u8; 2048];
            loop {
                if let Ok((n, from)) = echo.recv_from(&mut b).await {
                    let _ = echo.send_to(&b[..n], from).await;
                }
            }
        });

        // 2. TCP loopback 对
        let lis = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = lis.local_addr().unwrap();
        let cli = TcpStream::connect(addr).await.unwrap();
        let (srv, _) = lis.accept().await.unwrap();

        // 3. crypto 对 (client=initiator, server=非)
        let (cr, cw) = {
            let (r, w) = cli.into_split();
            crate::crypto::aead::create_crypto_pair(r, w, "pw", &[0u8; 32], &[1u8; 32], true)
        };
        let (sr, sw) = {
            let (r, w) = srv.into_split();
            crate::crypto::aead::create_crypto_pair(
                crate::proxy::tunnel::TunnelRead::Tcp(r),
                crate::proxy::tunnel::TunnelWrite::Tcp(w),
                "pw",
                &[0u8; 32],
                &[1u8; 32],
                false,
            )
        };

        // 4. 起服务端 mux relay (upstream=None → Direct egress, 测试环境连本地 echo 需 allow_local_targets=true)
        let server = tokio::spawn(async move {
            handle_udp_mux_relay(sr, sw, None, None, "default".to_string(), crate::proxy::mirage_server::SessionAuth::unlimited(), true).await;
        });

        // 5. 客户端发两帧: 同目标, 不同 sid + payload
        let mut cw = cw;
        let ip = match echo_addr.ip() {
            std::net::IpAddr::V4(v) => v,
            _ => unreachable!(),
        };
        let port = echo_addr.port();
        cw.send_data(&frame_mux_ipv4(1, &ip, port, b"AAA").unwrap())
            .await
            .unwrap();
        cw.send_data(&frame_mux_ipv4(2, &ip, port, b"BBB").unwrap())
            .await
            .unwrap();

        // 6. 读回包, 按 sid demux
        let mut cr = cr;
        let mut acc = Vec::new();
        let mut got = std::collections::HashMap::new();
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(5);
        while got.len() < 2 && tokio::time::Instant::now() < deadline {
            match tokio::time::timeout(std::time::Duration::from_secs(2), cr.recv_data()).await {
                Ok(Ok(c)) => {
                    acc.extend_from_slice(&c);
                    while let Some((sid, payload, consumed)) = parse_mux_frame(&acc) {
                        if !payload.is_empty() {
                            got.insert(sid, payload);
                        }
                        acc.drain(0..consumed);
                    }
                }
                _ => break,
            }
        }
        assert_eq!(got.get(&1u32).map(|v| v.as_slice()), Some(&b"AAA"[..]));
        assert_eq!(got.get(&2u32).map(|v| v.as_slice()), Some(&b"BBB"[..]));
        server.abort();
    }

    #[test]
    fn test_record_sent_target_eviction() {
        use std::collections::HashMap;
        use std::time::{Duration, Instant};

        let mut map = HashMap::new();
        let now = Instant::now();
        let idle_timeout = Duration::from_secs(300);

        let a1: SocketAddr = "1.1.1.1:53".parse().unwrap();
        let a2: SocketAddr = "2.2.2.2:53".parse().unwrap();
        let a3: SocketAddr = "3.3.3.3:53".parse().unwrap();

        // 1. 正常插入并在满额前不淘汰
        record_sent_target(&mut map, a1, now - Duration::from_secs(400), idle_timeout, 2);
        record_sent_target(&mut map, a2, now - Duration::from_secs(10), idle_timeout, 2);
        assert_eq!(map.len(), 2);

        // 2. 满额 (capacity=2) 插入新目标 a3: a1 超时 (400s > 300s), 应被优先淘汰
        record_sent_target(&mut map, a3, now, idle_timeout, 2);
        assert_eq!(map.len(), 2);
        assert!(!map.contains_key(&a1), "超时的 a1 应被淘汰");
        assert!(map.contains_key(&a2));
        assert!(map.contains_key(&a3));

        // 3. 满额时所有目标均未超时, 淘汰最旧的一条
        let a4: SocketAddr = "4.4.4.4:53".parse().unwrap();
        record_sent_target(&mut map, a4, now, idle_timeout, 2);
        assert_eq!(map.len(), 2);
        assert!(!map.contains_key(&a2), "未超时但最旧的 a2 应被淘汰");
        assert!(map.contains_key(&a3));
        assert!(map.contains_key(&a4));

        // 4. 重复向已有目标发送: 刷新时间戳且不淘汰其他目标
        let now2 = now + Duration::from_secs(5);
        record_sent_target(&mut map, a3, now2, idle_timeout, 2);
        assert_eq!(map.len(), 2);
        assert_eq!(map[&a3], now2);
    }

    /// 双栈 socket 上 IPv4 目标回包来源为 ::ffff:a.b.c.d: 归一化后必须编码为 ATYP=1 + 4B。
    #[test]
    fn test_encode_reply_frame_mapped_v4_is_atyp1() {
        let mapped: SocketAddr = "[::ffff:8.8.8.8]:53".parse().unwrap();
        let f = encode_reply_frame(normalize_addr(mapped), b"hi");
        assert_eq!(f, vec![1, 8, 8, 8, 8, 0, 53, b'h', b'i']);
        let v6: SocketAddr = "[2001:db8::1]:53".parse().unwrap();
        let f6 = encode_reply_frame(normalize_addr(v6), b"x");
        assert_eq!(f6[0], 4);
        assert_eq!(f6.len(), 1 + 16 + 2 + 1);
    }

    #[test]
    fn test_prepare_target_addr() {
        let v4: SocketAddr = "1.2.3.4:80".parse().unwrap();
        let v6: SocketAddr = "[2001:db8::1]:80".parse().unwrap();

        // 双栈模式
        let p_v4_dual = prepare_target_addr(v4, true).unwrap();
        assert_eq!(p_v4_dual, SocketAddr::V6(std::net::SocketAddrV6::new(
            std::net::Ipv4Addr::new(1, 2, 3, 4).to_ipv6_mapped(),
            80,
            0,
            0
        )));
        let p_v6_dual = prepare_target_addr(v6, true).unwrap();
        assert_eq!(p_v6_dual, v6);

        // IPv4 单栈模式
        let p_v4_single = prepare_target_addr(v4, false).unwrap();
        assert_eq!(p_v4_single, v4);
        let p_v6_single = prepare_target_addr(v6, false);
        assert!(p_v6_single.is_none(), "IPv4 单栈下应丢弃 IPv6 目标");
    }

    #[tokio::test]
    async fn test_dual_stack_send_recv_loopback() {
        // 如果环境支持 ::1, 进行实际双栈收发测试
        let Ok(server) = tokio::net::UdpSocket::bind("[::1]:0").await else {
            return; // 环境不支持 IPv6 loopback, 跳过
        };
        let server_addr = server.local_addr().unwrap();

        let Ok(client) = tokio::net::UdpSocket::bind("[::]:0").await else {
            return;
        };
        let client_port = client.local_addr().unwrap().port();

        // 从 client 发送给 server (::1)
        client.send_to(b"ping-v6", server_addr).await.unwrap();

        let mut buf = [0u8; 64];
        let (n, from) = server.recv_from(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"ping-v6");
        assert_eq!(from.port(), client_port);
        assert_eq!(from.ip(), std::net::Ipv6Addr::LOCALHOST);

        // 从 server 回包给 client
        server.send_to(b"pong-v6", from).await.unwrap();
        let (n_reply, from_srv) = client.recv_from(&mut buf).await.unwrap();
        assert_eq!(&buf[..n_reply], b"pong-v6");
        assert_eq!(from_srv, server_addr);
    }

    /// 非 mux UDP 下行帧长溢出检查: 帧长超过 u16::MAX 时丢弃, 避免截断后解帧失步
    #[test]
    fn test_encode_reply_frame_overflow_check() {
        let v6: SocketAddr = "[2001:db8::1]:53".parse().unwrap();
        // IPv6 帧头: 1B ATYP + 16B IP + 2B PORT = 19B
        // 若 payload 为 65535 - 18 = 65517B, frame.len() = 65536 > u16::MAX (65535)
        let large_payload = vec![0x42; 65518];
        let frame = encode_reply_frame(normalize_addr(v6), &large_payload);
        assert_eq!(frame.len(), 19 + 65518);
        assert!(frame.len() > u16::MAX as usize);

        let small_payload = vec![0x42; 100];
        let frame_ok = encode_reply_frame(normalize_addr(v6), &small_payload);
        assert!(frame_ok.len() <= u16::MAX as usize);
    }
}
