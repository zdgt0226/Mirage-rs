//! 服务端 UDP 上游转发. 加密 channel 内嵌"伪 SOCKS5 UDP" 帧格式封装多目标
//! UDP 包. 跟 src/proxy/udp_relay.rs (客户端 UDP forwarding) 语义不同, 故独立.
//!
//! 帧格式: [2B Len N][1B ATYP][ADDR][2B PORT][PAYLOAD]
//! ATYP: 1=IPv4, 3=Domain, 4=IPv6

use std::sync::Arc;
use std::time::Duration;
use tokio::net::UdpSocket;
use tracing::{debug, error};

/// UDP 会话双向 idle 上限。任一方向静默超此值即拆流, 防客户端弱网断连(无 FIN)
/// 导致 task/UdpSocket/64KB buf 僵尸泄露 (对齐 tcp_relay 的 1800s 兜底思路; UDP
/// 流更短, 且客户端透明 UDP 自身 60s idle 即拆, 300s 只作服务端兜底不误杀活跃流)。
const UDP_IDLE_TIMEOUT: Duration = Duration::from_secs(300);

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
    mut reader: crate::crypto::aead::CryptoReader<tokio::net::tcp::OwnedReadHalf>,
    writer: crate::crypto::aead::CryptoWriter<tokio::net::tcp::OwnedWriteHalf>,
    upstream: Option<Arc<crate::proxy::upstream::UpstreamOutlet>>,
) {
    debug!("Mirage Server: Started UDP relay session");

    // 上游是 WG 且策略为 tunnel → UDP 也走隧道, 出口与 TCP 一致。否则从本机直发。
    let egress = match upstream.as_deref() {
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
                Ok(s) => UdpEgress::Wireguard(Arc::new(s)),
                Err(e) => {
                    error!("UDP 中继: 隧道内绑 UDP 失败: {}", e);
                    return;
                }
            }
        }
        _ => match UdpSocket::bind("0.0.0.0:0").await {
            Ok(s) => UdpEgress::Direct(Arc::new(s)),
            Err(e) => {
                error!("Failed to bind server UDP socket: {}", e);
                return;
            }
        },
    };
    let udp_socket = Arc::new(egress);

    let (tx, mut rx) = tokio::sync::mpsc::channel(256);
    let udp_clone = udp_socket.clone();

    let writer = std::sync::Arc::new(tokio::sync::Mutex::new(writer));
    let writer_clone = writer.clone();

    let downlink = tokio::spawn(async move {
        let mut buf = vec![0u8; 65536];
        loop {
            match tokio::time::timeout(UDP_IDLE_TIMEOUT, udp_clone.recv_from(&mut buf)).await {
                Ok(Ok((size, addr))) => {
                    // Frame format: [2B Len N][1B ATYP][ADDR][2B PORT][PAYLOAD]
                    let atyp: u8; // Declared but assigned in match
                    let mut addr_bytes = Vec::new();
                    match addr.ip() {
                        std::net::IpAddr::V4(ip) => {
                            atyp = 1;
                            addr_bytes.extend_from_slice(&ip.octets());
                        }
                        std::net::IpAddr::V6(ip) => {
                            atyp = 4;
                            addr_bytes.extend_from_slice(&ip.octets());
                        }
                    }

                    let mut frame = vec![atyp];
                    frame.extend_from_slice(&addr_bytes);
                    frame.extend_from_slice(&addr.port().to_be_bytes());
                    frame.extend_from_slice(&buf[..size]);

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

    let tunnel_downlink = async move {
        loop {
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

    let tunnel_uplink = async move {
        let mut buffer = Vec::new();
        loop {
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

                // v0.4.5-alpha.16: 走 resolver::resolve_first (60s 缓存 + IPv4 优先 +
                // 并发限流), 不再每 UDP 包裸调 lookup_host 打满阻塞池 (高频 QUIC /
                // 唯一域名洪泛防护). IP 字面量 (ATYP 1/4) 直接构造不解析.
                // send_to 不是 AEAD 写, cancel 也无害 (UDP 本来就尽力而为).
                if let Ok(socket_addr) =
                    crate::proxy::resolver::resolve_first(&target_addr_str, port).await
                {
                    // send_to 失败以前被静默吞掉 —— VPS 封出向 UDP 时这里就是第一现场,
                    // 却完全无痕 (真机排障卡过)。一次性记下, 不刷屏 (高频 QUIC)。
                    if let Err(e) = udp_socket.send_to(payload, socket_addr).await {
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
        }
        let _ = stop_tx_up.send(true);
    };

    // 用 join 而不是 select: 两 task 通过 stop_tx/rx 协作退出, 不被中途 drop.
    tokio::join!(tunnel_uplink, tunnel_downlink);

    // 此时两 task 都已干净退出, 没有任何 in-flight AEAD 写. close_notify 安全.
    let _ = writer.lock().await.send_close_notify().await;
    downlink.abort();
}
