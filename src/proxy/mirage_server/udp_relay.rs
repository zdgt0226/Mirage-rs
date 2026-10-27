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
/// 非 mux UDP 会话的一个上游 WG 出口 (按出站 tag 懒建): 隧道内 socket + 隧道 (隧道内解析用)
/// + 本出口独立的回包来源白名单 (各出口分开记, 发往 WG 的目标不能从直连 socket 冒名注入回包)。
#[derive(Clone)]
struct WgEgress {
    socket: Arc<crate::proxy::wg::socket::WgUdpSocket>,
    tunnel: Arc<crate::proxy::wg::tunnel::WgTunnel>,
    sent: SentTargets,
}

type SentTargets = Arc<std::sync::Mutex<std::collections::HashMap<SocketAddr, std::time::Instant>>>;

/// 回包准入: 来源须在本出口白名单内, 并过限速与配额。None = 丢本包; Some(true) = 越额/吊销, 停会话。
fn admit_reply(
    sent: &SentTargets,
    from: SocketAddr,
    size: usize,
    buckets: &Option<Arc<crate::proxy::rate_limit::DeviceBuckets>>,
    auth: &super::SessionAuth,
) -> Option<bool> {
    // 校验回包来源: 丢弃未知来源的包 (不计费、不回送)。
    // 注意: 这会收紧 full-cone UDP (如某些 STUN/P2P 游戏) 语义为 restricted-cone。
    if !sent.lock().unwrap_or_else(|e| e.into_inner()).contains_key(&from) {
        return None;
    }
    // 下行限速 (policing): 令牌不足丢本报文 (按 payload 字节计), 两桶都扣 (取更严)
    if !crate::proxy::rate_limit::try_consume_two(
        buckets.as_ref().map(|b| &b.down),
        auth.user_limit.as_ref().and_then(|u| u.buckets()).as_ref().map(|b| &b.down),
        size,
    ) {
        return None;
    }
    Some(auth.record_bytes(size))
}

/// 回包封帧送入下行通道。false = 通道已关 (会话在收尾)。
async fn forward_reply(tx: &tokio::sync::mpsc::Sender<Vec<u8>>, from: SocketAddr, data: &[u8]) -> bool {
    // Frame format: [2B Len N][1B ATYP][ADDR][2B PORT][PAYLOAD]
    // 用归一化后的来源地址封帧: 双栈 socket 上 IPv4 目标的回包来源是 ::ffff:a.b.c.d,
    // 原样编码会成 ATYP=4 + 16B, 客户端按 IPv6 回给应用 → IPv4 UDP 回包全丢。
    let frame = encode_reply_frame(from, data);
    if frame.len() > u16::MAX as usize {
        debug!(
            "Mirage Server UDP: 下行帧长度 ({}B) 超过 u16::MAX, 丢弃该报文以防解帧失步",
            frame.len()
        );
        return true;
    }
    let mut packet = Vec::with_capacity(2 + frame.len());
    packet.extend_from_slice(&(frame.len() as u16).to_be_bytes());
    packet.extend_from_slice(&frame);
    tx.send(packet).await.is_ok()
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn handle_udp_relay(
    mut reader: crate::crypto::aead::CryptoReader<crate::proxy::tunnel::TunnelRead>,
    writer: crate::crypto::aead::CryptoWriter<crate::proxy::tunnel::TunnelWrite>,
    upstream: Option<Arc<crate::proxy::upstream::UpstreamOutlet>>,
    client_ip: Option<std::net::IpAddr>,
    user: String,
    session_auth: super::SessionAuth,
    allow_local_targets: bool,
    inbound_tag: Option<Arc<str>>,
) {
    debug!("Mirage Server: Started UDP relay session");

    // 服务端按连接的客户端 IP 限速 (device_profiles rate_limit_kbps): UDP 无背压 → policing
    // (令牌不足丢包), 与 SOCKS/transparent UDP 一致; 全局 limiter 同 tcp_relay::server_buckets_for。
    let dev_buckets = client_ip.and_then(crate::proxy::rate_limit::server_buckets_for);

    // 出口按每个目标的选路结果决定 (与 TCP / UDP mux 一致): 主 socket 恒为直连, 选到 WG 出站的
    // 目标走按 tag 懒建的隧道内 socket。直连优先绑定 [::]:0 双栈; 失败则回退 0.0.0.0:0。
    // 双栈: 发往 IPv4 目标时转 IPv4-mapped (见 prepare_target_addr)。依赖 IPV6_V6ONLY=0
    // (Linux 默认); 若主机设了 net.ipv6.bindv6only=1 则该 socket 只通 IPv6 → 退回 0.0.0.0:0 保 IPv4
    // (Linux 上 bind 后不能再改 v6only, 故绑后探测而非强设)。
    let (direct_socket, is_dual_stack) = match UdpSocket::bind("[::]:0").await.ok().filter(|s| {
        !nix::sys::socket::getsockopt(s, nix::sys::socket::sockopt::Ipv6V6Only).unwrap_or(true)
    }) {
        Some(s) => (Arc::new(s), true),
        None => {
            debug!("[::]:0 dual-stack UDP socket unavailable (bind failed or v6only), falling back to 0.0.0.0:0");
            match UdpSocket::bind("0.0.0.0:0").await {
                Ok(s) => (Arc::new(s), false),
                Err(e) => {
                    error!("Failed to bind server UDP socket: {}", e);
                    return;
                }
            }
        }
    };

    let (tx, mut rx) = tokio::sync::mpsc::channel(256);

    // 修 bug: cancel-safety. 旧版用 tokio::select!(uplink, downlink), 一方完成
    // 时 select! 暴力 drop 另一方, 若 downlink 正在 writer.send_data 半截
    // (TLS 5 字节 header 已写出去, AEAD payload 没写完) 会留下半截帧, 接着外层
    // send_close_notify 又写一个 alert, 客户端 AEAD MAC 校验崩 → bad record mac.
    //
    // 修复: 用 watch 频道做协作式停止信号. 两 task 都 tokio::join! (而不是 select),
    // select! 仅围绕 read 点, write 全部在 select! 外面执行, 永远不会被中途打断.
    // 注意 recv_data **不是** cancel-safe (头/体两段 read_exact, 中途取消会丢字节失步),
    // 这里安全只因为它被取消后本会话立即退出、reader 不再复用 (rx.recv 才是真 cancel-safe).
    // 任一方退出时 send(true), 另一方
    // 在下一次 read 边界 (changed() 返回) 检测到信号, 干净退出. 之后才 send_close_notify,
    // 此时绝无半截帧.
    // 下行泵有多个 (直连 + 每个 WG 出口), 各泵与上行都持有 tx, 会话结束一律靠这个信号,
    // 不靠 mpsc 通道关闭。
    let (stop_tx, _stop_rx_seed) = tokio::sync::watch::channel(false);
    let mut stop_rx_down = stop_tx.subscribe();
    let mut stop_rx_up = stop_tx.subscribe();
    let stop_tx_down = stop_tx.clone();
    let stop_tx_up = stop_tx.clone();

    // 会话空闲以「任一出口最后一次收到回包」为准 (相对 session_start 的毫秒)。只有直连泵判空闲:
    // 所有出口都静默超 UDP_IDLE_TIMEOUT 才拆会话 —— 流量全走 WG 时直连 socket 本身收不到包。
    let session_start = std::time::Instant::now();
    let last_rx = Arc::new(std::sync::atomic::AtomicU64::new(0));

    // 直连出口的回包来源白名单 (限制 1024 条防膨胀); 每个 WG 出口各有一份 (见 WgEgress)。
    // 记最近一次向该目标发送的时间, 供下行校验回包来源 (阻止未授权来源注入数据及恶意消耗用户配额)。
    let sent_direct: SentTargets = Arc::new(std::sync::Mutex::new(std::collections::HashMap::new()));

    let writer = std::sync::Arc::new(tokio::sync::Mutex::new(writer));
    let writer_clone = writer.clone();

    let dn_socket = direct_socket.clone();
    let dn_sent = sent_direct.clone();
    let dn_buckets = dev_buckets.clone();
    let dn_auth = session_auth.clone();
    let dn_tx = tx.clone();
    let dn_last_rx = last_rx.clone();
    let mut dn_stop = stop_tx.subscribe();
    let dn_stop_tx = stop_tx.clone();
    let downlink = tokio::spawn(async move {
        let mut buf = vec![0u8; 65536];
        loop {
            if dn_auth.should_stop() {
                break;
            }
            let res = tokio::select! {
                biased;
                _ = dn_stop.changed() => break,
                r = tokio::time::timeout(UDP_IDLE_TIMEOUT, dn_socket.recv_from(&mut buf)) => r,
            };
            match res {
                Ok(Ok((size, addr))) => {
                    // 自动处理 IPv4-mapped IPv6 (::ffff:a.b.c.d)。
                    let norm = normalize_addr(addr);
                    match admit_reply(&dn_sent, norm, size, &dn_buckets, &dn_auth) {
                        None => continue,
                        Some(true) => break, // 越额或吊销退出
                        Some(false) => {}
                    }
                    dn_last_rx.store(session_start.elapsed().as_millis() as u64, std::sync::atomic::Ordering::Relaxed);
                    if !forward_reply(&dn_tx, norm, &buf[..size]).await {
                        break;
                    }
                }
                Ok(Err(_)) => break, // socket 错误 → 拆流
                Err(_) => {
                    // 直连静默超时: 其它出口 (WG) 期间收过回包则会话仍活跃, 继续等
                    let idle_ms = (session_start.elapsed().as_millis() as u64)
                        .saturating_sub(dn_last_rx.load(std::sync::atomic::Ordering::Relaxed));
                    if idle_ms < UDP_IDLE_TIMEOUT.as_millis() as u64 {
                        continue;
                    }
                    break; // 全部出口静默超 UDP_IDLE_TIMEOUT → 拆流
                }
            }
        }
        let _ = dn_stop_tx.send(true);
    });

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
    let inbound_tag_up = inbound_tag.clone();
    let user_up = user.clone();
    let upstream_up = upstream.clone();
    let tx_wg = tx;
    let wg_stop_tx = stop_tx.clone();
    let tunnel_uplink = async move {
        let mut buffer = Vec::new();
        // 选路结果按目标缓存 (本会话内): UDP 逐包走一遍规则匹配 (含 geosite、可能的解析) 太贵。
        // 热重载对已建会话不生效, 与 TCP 已建连接沿用旧出口一致。
        let mut route_cache: std::collections::HashMap<String, super::server_router::ServerRouteDecision> =
            std::collections::HashMap::new();
        // 选到 WG 出站的目标按 tag 懒建隧道内 socket; 泵出错退出时把自己移出表, 下个包重建。
        let wg_egresses: Arc<tokio::sync::Mutex<std::collections::HashMap<String, WgEgress>>> =
            Arc::new(tokio::sync::Mutex::new(std::collections::HashMap::new()));
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

                // 服务端选路 (IPv6 目标用 [addr]:port, split_host_port 才能拆开)
                let target_str = crate::net_util::join_host_port(&target_addr_str, port);
                let decision = match route_cache.get(&target_str) {
                    Some(d) => d.clone(),
                    None => {
                        let d = super::server_router::server_route(
                            inbound_tag_up.as_deref(),
                            &target_str,
                            "udp",
                            client_ip,
                            &user_up,
                            upstream_up.as_ref(),
                        )
                        .await;
                        if route_cache.len() >= MAX_SENT_TARGETS {
                            route_cache.clear();
                        }
                        route_cache.insert(target_str.clone(), d.clone());
                        d
                    }
                };

                // 选出口: None = 直连 socket; Some = 某个 WG 出口。拒绝 / block 策略直接丢包。
                let wg_outlet = match &decision.target {
                    super::server_router::ServerOutboundTarget::Reject => continue,
                    super::server_router::ServerOutboundTarget::Direct => None,
                    super::server_router::ServerOutboundTarget::Upstream(outlet) => match &**outlet {
                        crate::proxy::upstream::UpstreamOutlet::Shadowsocks(ss) => {
                            if ss.block_udp {
                                debug!("UDP: 丢弃发往 {} 的报文, 出站 `{}` 的 udp 策略为 block", target_str, decision.tag);
                                continue;
                            }
                            None // SS 的 udp=direct: 本机直发 (既有语义, 出口与 TCP 不同)
                        }
                        crate::proxy::upstream::UpstreamOutlet::Wireguard(wg) => match wg.udp {
                            crate::config::UdpPolicy::Block => {
                                debug!("UDP: 丢弃发往 {} 的报文, 出站 `{}` 的 udp 策略为 block", target_str, decision.tag);
                                continue;
                            }
                            crate::config::UdpPolicy::Direct => None,
                            crate::config::UdpPolicy::Tunnel => Some(wg),
                        },
                    },
                };

                let Some(wg) = wg_outlet else {
                    // 直连: v0.4.5-alpha.16 起走 resolver::resolve_first_filtered (60s 缓存 + IPv4 优先 +
                    // 并发限流 + 出站 SSRF 白名单过滤), 不再每 UDP 包裸调 lookup_host 打满阻塞池.
                    // send_to 不是 AEAD 写, cancel 也无害 (UDP 本来就尽力而为).
                    let socket_addr = match crate::proxy::resolver::resolve_first_filtered(&target_addr_str, port, |ip| {
                        crate::net_util::egress_allowed(ip, allow_local_targets)
                    }).await {
                        Ok(a) => a,
                        Err(e) => {
                            if e.kind() == std::io::ErrorKind::PermissionDenied {
                                super::warn_egress_blocked("Mirage Server UDP", &user, &target_str);
                            }
                            continue;
                        }
                    };
                    let Some(send_addr) = prepare_target_addr(socket_addr, is_dual_stack) else {
                        debug!("UDP direct socket (IPv4 only): dropping IPv6 target {}", socket_addr);
                        continue;
                    };
                    // P2-3 + P3-1: 发送前插入白名单并刷新时间 (先发后记可能导致极快回包被丢)
                    record_sent_target(
                        &mut sent_direct.lock().unwrap_or_else(|e| e.into_inner()),
                        normalize_addr(socket_addr),
                        std::time::Instant::now(),
                        UDP_IDLE_TIMEOUT,
                        MAX_SENT_TARGETS,
                    );
                    // send_to 失败以前被静默吞掉 —— VPS 封出向 UDP 时这里就是第一现场,
                    // 却完全无痕 (真机排障卡过)。一次性记下, 不刷屏 (高频 QUIC)。
                    if let Err(e) = direct_socket.send_to(payload, send_addr).await {
                        static WARNED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
                        if !WARNED.swap(true, std::sync::atomic::Ordering::Relaxed) {
                            tracing::warn!(
                                "UDP relay send_to {} 失败: {} —— 若持续, 本机(VPS)可能禁止出向 UDP",
                                socket_addr, e
                            );
                        }
                    }
                    continue;
                };

                // WG 出口: 取 (或懒建) 本 tag 的隧道内 socket 与其下行泵
                let egress = {
                    let mut map = wg_egresses.lock().await;
                    match map.get(&decision.tag) {
                        Some(e) => e.clone(),
                        None => {
                            let tunnel = match wg.tunnel().await {
                                Ok(t) => t,
                                Err(e) => {
                                    debug!("UDP: 建立 WG 上游 `{}` 失败: {e}", decision.tag);
                                    continue;
                                }
                            };
                            let socket = match crate::proxy::wg::socket::WgUdpSocket::bind(tunnel.clone()) {
                                Ok(s) => Arc::new(s),
                                Err(e) => {
                                    debug!("UDP: 在 WG 上游 `{}` 内绑 UDP 失败: {e}", decision.tag);
                                    continue;
                                }
                            };
                            let eg = WgEgress {
                                socket,
                                tunnel,
                                sent: Arc::new(std::sync::Mutex::new(std::collections::HashMap::new())),
                            };
                            map.insert(decision.tag.clone(), eg.clone());
                            // 本出口的下行泵: 无独立空闲超时 (会话空闲由直连泵统一判), 会话结束
                            // (stop 信号) 时退出; socket 出错退出时移出表, 下个包重建。
                            let pump_eg = eg.clone();
                            let pump_tag = decision.tag.clone();
                            let pump_map = wg_egresses.clone();
                            let pump_tx = tx_wg.clone();
                            let pump_auth = up_auth.clone();
                            let pump_buckets = dev_buckets.clone();
                            let pump_last_rx = last_rx.clone();
                            let pump_stop_tx = wg_stop_tx.clone();
                            let mut pump_stop = wg_stop_tx.subscribe();
                            tokio::spawn(async move {
                                let mut buf = vec![0u8; 65536];
                                loop {
                                    if pump_auth.should_stop() {
                                        break;
                                    }
                                    let res = tokio::select! {
                                        biased;
                                        _ = pump_stop.changed() => return,
                                        r = pump_eg.socket.recv_from(&mut buf) => r,
                                    };
                                    let Ok((size, addr)) = res else {
                                        pump_map.lock().await.remove(&pump_tag);
                                        return;
                                    };
                                    let norm = normalize_addr(addr);
                                    match admit_reply(&pump_eg.sent, norm, size, &pump_buckets, &pump_auth) {
                                        None => continue,
                                        Some(true) => break, // 越额或吊销 → 停整个会话
                                        Some(false) => {}
                                    }
                                    pump_last_rx.store(session_start.elapsed().as_millis() as u64, std::sync::atomic::Ordering::Relaxed);
                                    if !forward_reply(&pump_tx, norm, &buf[..size]).await {
                                        return;
                                    }
                                }
                                let _ = pump_stop_tx.send(true);
                            });
                            eg
                        }
                    }
                };

                // 隧道内解析 (WG 出站配了 dns 时用对端 DNS, 拿对端地区的结果), 不过 SSRF 白名单
                // (只作用于直连; 目标可能本就是对端内网地址) —— 与 TCP / UDP mux 的 WG 路径一致。
                let socket_addr = match crate::proxy::wg::resolve_target(&egress.tunnel, &target_addr_str, port).await {
                    Ok(a) => a,
                    Err(e) => {
                        debug!("UDP: WG 上游 `{}` 解析 {} 失败: {e}", decision.tag, target_str);
                        continue;
                    }
                };
                record_sent_target(
                    &mut egress.sent.lock().unwrap_or_else(|e| e.into_inner()),
                    normalize_addr(socket_addr),
                    std::time::Instant::now(),
                    UDP_IDLE_TIMEOUT,
                    MAX_SENT_TARGETS,
                );
                // 隧道侧是同步入队 (数据进 smoltcp 缓冲后由 pump 加密发出), 不阻塞。
                if let Err(e) = egress.socket.send_to(payload, socket_addr) {
                    debug!("UDP: 经 WG 上游 `{}` 发往 {} 失败: {e}", decision.tag, socket_addr);
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
    reader: crate::crypto::aead::CryptoReader<crate::proxy::tunnel::TunnelRead>,
    writer: crate::crypto::aead::CryptoWriter<crate::proxy::tunnel::TunnelWrite>,
    upstream: Option<Arc<crate::proxy::upstream::UpstreamOutlet>>,
    client_ip: Option<std::net::IpAddr>,
    user: String,
    session_auth: super::SessionAuth,
    allow_local_targets: bool,
    inbound_tag: Option<Arc<str>>,
) {
    handle_udp_mux_relay_inner(
        reader,
        writer,
        upstream,
        client_ip,
        user,
        session_auth,
        allow_local_targets,
        super::REVOKE_CHECK_INTERVAL,
        inbound_tag,
    )
    .await
}

pub(crate) async fn handle_udp_mux_relay_inner(
    mut reader: crate::crypto::aead::CryptoReader<crate::proxy::tunnel::TunnelRead>,
    writer: crate::crypto::aead::CryptoWriter<crate::proxy::tunnel::TunnelWrite>,
    upstream: Option<Arc<crate::proxy::upstream::UpstreamOutlet>>,
    client_ip: Option<std::net::IpAddr>,
    user: String,
    session_auth: super::SessionAuth,
    allow_local_targets: bool,
    revoke_check_interval: Duration,
    inbound_tag: Option<Arc<str>>,
) {
    debug!("Mirage Server: Started UDP MUX relay session");

    // 服务端按客户端 IP 限速 (device_profiles): mux 复用一条隧道多 sid, 但都同一客户端 IP →
    // 共享同一对桶, policing (令牌不足丢包)。同 handle_udp_relay。
    let dev_buckets = client_ip.and_then(crate::proxy::rate_limit::server_buckets_for);

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
    let inbound_tag_mux = inbound_tag.clone();
    let user_mux = user.clone();
    let upstream_mux = upstream.clone();
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
                let target_str = crate::net_util::join_host_port(&uf.target, uf.port);
                let decision = super::server_router::server_route(
                    inbound_tag_mux.as_deref(),
                    &target_str,
                    "udp",
                    client_ip,
                    &user_mux,
                    upstream_mux.as_ref(),
                )
                .await;

                let (egress, target_sa) = match &decision.target {
                    super::server_router::ServerOutboundTarget::Reject => continue,
                    super::server_router::ServerOutboundTarget::Direct => {
                        let target_sa = match crate::proxy::resolver::resolve_first_filtered(&uf.target, uf.port, |ip| {
                            crate::net_util::egress_allowed(ip, allow_local_targets)
                        }).await {
                            Ok(sa) => sa,
                            Err(e) => {
                                if e.kind() == std::io::ErrorKind::PermissionDenied {
                                    super::warn_egress_blocked(
                                        "Mirage Server UDP mux",
                                        &user_mux,
                                        &target_str,
                                    );
                                }
                                continue;
                            }
                        };
                        let bind_addr = match target_sa {
                            SocketAddr::V4(_) => "0.0.0.0:0",
                            SocketAddr::V6(_) => "[::]:0",
                        };
                        match UdpSocket::bind(bind_addr).await {
                            Ok(s) => match s.connect(target_sa).await {
                                Ok(()) => (SidEgress::Direct(s), target_sa),
                                Err(_) => continue,
                            },
                            Err(_) => continue,
                        }
                    }
                    super::server_router::ServerOutboundTarget::Upstream(outlet) => match &**outlet {
                        crate::proxy::upstream::UpstreamOutlet::Shadowsocks(ss) => {
                            if ss.block_udp {
                                debug!("UDP mux: sid {} 命中 SS 上游 {} 但 SS udp 策略为 block, 丢弃", uf.sid, decision.tag);
                                continue;
                            } else {
                                let target_sa = match crate::proxy::resolver::resolve_first_filtered(&uf.target, uf.port, |ip| {
                                    crate::net_util::egress_allowed(ip, allow_local_targets)
                                }).await {
                                    Ok(sa) => sa,
                                    Err(e) => {
                                        if e.kind() == std::io::ErrorKind::PermissionDenied {
                                            super::warn_egress_blocked(
                                                "Mirage Server UDP mux",
                                                &user_mux,
                                                &target_str,
                                            );
                                        }
                                        continue;
                                    }
                                };
                                let bind_addr = match target_sa {
                                    SocketAddr::V4(_) => "0.0.0.0:0",
                                    SocketAddr::V6(_) => "[::]:0",
                                };
                                match UdpSocket::bind(bind_addr).await {
                                    Ok(s) => match s.connect(target_sa).await {
                                        Ok(()) => (SidEgress::Direct(s), target_sa),
                                        Err(_) => continue,
                                    },
                                    Err(_) => continue,
                                }
                            }
                        }
                        crate::proxy::upstream::UpstreamOutlet::Wireguard(wg) => match wg.udp {
                            crate::config::UdpPolicy::Block => {
                                debug!("UDP mux: sid {} 命中 WG 上游 {} 但 udp 策略为 block, 丢弃", uf.sid, decision.tag);
                                continue;
                            }
                            crate::config::UdpPolicy::Direct => {
                                let target_sa = match crate::proxy::resolver::resolve_first_filtered(&uf.target, uf.port, |ip| {
                                    crate::net_util::egress_allowed(ip, allow_local_targets)
                                }).await {
                                    Ok(sa) => sa,
                                    Err(e) => {
                                        if e.kind() == std::io::ErrorKind::PermissionDenied {
                                            super::warn_egress_blocked(
                                                "Mirage Server UDP mux",
                                                &user_mux,
                                                &target_str,
                                            );
                                        }
                                        continue;
                                    }
                                };
                                let bind_addr = match target_sa {
                                    SocketAddr::V4(_) => "0.0.0.0:0",
                                    SocketAddr::V6(_) => "[::]:0",
                                };
                                match UdpSocket::bind(bind_addr).await {
                                    Ok(s) => match s.connect(target_sa).await {
                                        Ok(()) => (SidEgress::Direct(s), target_sa),
                                        Err(_) => continue,
                                    },
                                    Err(_) => continue,
                                }
                            }
                            crate::config::UdpPolicy::Tunnel => {
                                let tunnel = match wg.tunnel().await {
                                    Ok(t) => t,
                                    Err(e) => {
                                        error!("UDP mux: 建立 WG 上游隧道失败: {}", e);
                                        continue;
                                    }
                                };
                                let target_sa = match crate::proxy::wg::resolve_target(&tunnel, &uf.target, uf.port).await {
                                    Ok(sa) => sa,
                                    Err(e) => {
                                        debug!("UDP mux: WG 内解析目标 {} 失败: {}", target_str, e);
                                        continue;
                                    }
                                };
                                match crate::proxy::wg::socket::WgUdpSocket::bind(tunnel) {
                                    Ok(s) => (SidEgress::Wireguard(Arc::new(s), target_sa), target_sa),
                                    Err(e) => {
                                        debug!("UDP mux: WG 内绑 UDP 失败: {}", e);
                                        continue;
                                    }
                                }
                            }
                        },
                    },
                };
                let egress = Arc::new(egress);
                // spawn 下行泵: egress.recv → frame_mux_addr(sid) → tx。
                let pump_egress = egress.clone();
                let pump_tx = up_tx.clone();
                let pump_sessions = up_sessions.clone();
                let pump_buckets = dev_buckets.clone();
                let pump_auth = up_auth.clone();
                let sid = uf.sid;
                let pump_target_sa = target_sa;
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
                                    pump_target_sa,
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
    // 在 select 中增加定时唤醒检查 session_auth.should_stop():
    // 避免双向空闲时吊销必须等待最长 300s UDP_IDLE_TIMEOUT 才能感知。
    // 由于 rx.recv() 满足 cancel-safe，在 writer_pump 的 select 中增加 tick 唤醒是完全安全的。
    // 发现 should_stop 后通过 stop watch 通道通知 uplink，uplink 随之 break 终止会话。
    drop(tx); // 只留 up_tx (uplink 持有) 与各泵 clone; uplink 退出后全部释放
    let writer_auth = session_auth.clone();
    let writer_pump = {
        let writer = writer.clone();
        async move {
            let mut revoke_tick = tokio::time::interval(revoke_check_interval);
            revoke_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                let pkt = tokio::select! {
                    biased;
                    _ = stop_rx_writer.changed() => break,
                    _ = revoke_tick.tick() => {
                        if writer_auth.should_stop() {
                            break;
                        }
                        continue;
                    }
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
    use crate::proxy::udp_mux::{frame_mux_ipv4, parse_mux_frame, MuxFrameDecode};
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
            handle_udp_mux_relay(sr, sw, None, None, "default".to_string(), crate::proxy::mirage_server::SessionAuth::unlimited(), true, None).await;
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
                    loop {
                        match parse_mux_frame(&acc) {
                            MuxFrameDecode::Incomplete => break,
                            MuxFrameDecode::Malformed { consumed } => {
                                acc.drain(0..consumed);
                            }
                            MuxFrameDecode::Frame {
                                sid,
                                payload,
                                consumed,
                            } => {
                                got.insert(sid, payload);
                                acc.drain(0..consumed);
                            }
                        }
                    }
                }
                _ => break,
            }
        }
        assert_eq!(got.get(&1u32).map(|v| v.as_slice()), Some(&b"AAA"[..]));
        assert_eq!(got.get(&2u32).map(|v| v.as_slice()), Some(&b"BBB"[..]));
        server.abort();
    }

    /// 吊销后双向空闲的 UDP mux 会话在 ~REVOKE_CHECK_INTERVAL 内结束
    #[tokio::test]
    async fn mux_revocation_terminates_idle_session_promptly() {
        // 1. TCP loopback 对
        let lis = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = lis.local_addr().unwrap();
        let cli = TcpStream::connect(addr).await.unwrap();
        let (srv, _) = lis.accept().await.unwrap();

        // 2. crypto 对
        let (_cr, _cw) = {
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

        // 3. 构造受控 SessionAuth (初始未吊销)
        let revoked = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let auth = crate::proxy::mirage_server::SessionAuth {
            user_limit: None,
            cred_revoked: revoked.clone(),
        };

        // 4. 起参数化更短唤醒间隔 (50ms) 的 mux relay 会话
        let revoke_interval = std::time::Duration::from_millis(50);
        let server = tokio::spawn(async move {
            handle_udp_mux_relay_inner(
                sr,
                sw,
                None,
                None,
                "default".to_string(),
                auth,
                true,
                revoke_interval,
                None,
            )
            .await;
        });

        // 双向完全空闲: 客户端既不发 UDP 包, 下行也没有回包
        tokio::time::sleep(std::time::Duration::from_millis(30)).await;
        assert!(!server.is_finished(), "会话不应提前结束");

        // 触发吊销
        revoked.store(true, std::sync::atomic::Ordering::Relaxed);

        // 预期在 ~50ms 内感知吊销并结束, 远早于 300s UDP_IDLE_TIMEOUT
        let res = tokio::time::timeout(std::time::Duration::from_millis(500), server).await;
        assert!(res.is_ok(), "双向空闲 mux 会话未能及时在吊销唤醒周期内退出");
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
