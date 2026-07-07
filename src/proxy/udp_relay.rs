use crate::proxy::pool::WarmPool;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tracing::{debug, error, info, warn};

pub async fn handle_udp_associate(mut local_tcp: TcpStream, pool: Arc<WarmPool>) {
    // 1. Bind local UDP socket on an ephemeral port
    let udp_socket = match UdpSocket::bind("0.0.0.0:0").await {
        Ok(s) => Arc::new(s),
        Err(e) => {
            error!("Failed to bind UDP socket for relay: {}", e);
            return;
        }
    };
    
    let local_addr = match udp_socket.local_addr() {
        Ok(a) => a,
        Err(_) => return,
    };
    
    // 2. Send SOCKS5 reply with bound UDP port
    let port = local_addr.port();
    let mut reply = vec![0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0];
    reply.extend_from_slice(&port.to_be_bytes());
    
    if local_tcp.write_all(&reply).await.is_err() {
        return;
    }
    
    info!("UDP Relay started on port {}", port);

    // 3. Acquire tunnel and send UDP Mode Sentinel (\x00)
    let mut tunnel = match pool.get().await {
        Ok(t) => t,
        Err(e) => {
            error!("UDP relay: pool unavailable ({}). Session aborted.", e);
            return;
        }
    };
    if tunnel.writer.send_data(&[0x00]).await.is_err() {
        error!("Failed to send UDP sentinel");
        return;
    }
    let mut tunnel_reader = tunnel.reader;
    let tunnel_writer = std::sync::Arc::new(tokio::sync::Mutex::new(tunnel.writer));
    
    // 4. Run Relay Loops
    let (tx, mut rx) = tokio::sync::mpsc::channel(1);
    
    let udp_rx = udp_socket.clone();
    let udp_tx = udp_socket;
    
    let tunnel_writer_clone = tunnel_writer.clone();
    let uplink = tokio::spawn(async move {
        let mut buf = vec![0u8; 65536];
        let mut client_addr = None;
        
        loop {
            match udp_rx.recv_from(&mut buf).await {
                Ok((size, addr)) => {
                    // Update client address on first packet
                    if client_addr.is_none() {
                        client_addr = Some(addr);
                        let _ = tx.send(addr).await;
                    }
                    
                    let data = &buf[..size];
                    // Parse SOCKS5 UDP header
                    // [2B RSV][1B FRAG][1B ATYP][ADDR][2B PORT][PAYLOAD]
                    if data.len() < 4 || data[0] != 0 || data[1] != 0 {
                        continue;
                    }
                    if data[2] != 0 {
                        continue; // Fragmentation not supported
                    }
                    
                    // Extract payload starting from ATYP
                    let packed_and_payload = &data[3..];
                    
                    // Frame for tunnel: [2B len][packed_and_payload]
                    let frame_len = packed_and_payload.len() as u16;
                    let mut frame = Vec::with_capacity(2 + packed_and_payload.len());
                    frame.extend_from_slice(&frame_len.to_be_bytes());
                    frame.extend_from_slice(packed_and_payload);
                    
                    if tunnel_writer_clone.lock().await.send_data(&frame).await.is_err() {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
    });
    
    let downlink = tokio::spawn(async move {
        // Wait for first uplink to know where to send replies
        let client_addr = match rx.recv().await {
            Some(a) => a,
            None => return,
        };
        
        let mut buffer = Vec::new();
        loop {
            match tunnel_reader.recv_data().await {
                Ok(chunk) => {
                    buffer.extend_from_slice(&chunk);
                    
                    // Parse frames
                    while buffer.len() >= 2 {
                        let frame_len = u16::from_be_bytes([buffer[0], buffer[1]]) as usize;
                        if buffer.len() < 2 + frame_len {
                            break; // Incomplete frame
                        }
                        
                        let frame = &buffer[2..2+frame_len];
                        // Reconstruct SOCKS5 header: RSV(2) + FRAG(1) + ATYP...
                        let mut sock_resp = vec![0, 0, 0];
                        sock_resp.extend_from_slice(frame);
                        
                        let _ = udp_tx.send_to(&sock_resp, client_addr).await;
                        
                        buffer.drain(0..2+frame_len);
                    }
                }
                Err(_) => break,
            }
        }
    });
    
    // Watch TCP connection, SOCKS5 standard dictates UDP relay stops when TCP closes
    let tcp_watcher = tokio::spawn(async move {
        let mut buf = [0u8; 1];
        let _ = local_tcp.read(&mut buf).await;
    });
    
    // abort_handle 只借用不消费, 可在 select 移动 handle 前取。
    let ah_up = uplink.abort_handle();
    let ah_down = downlink.abort_handle();
    let ah_tcp = tcp_watcher.abort_handle();

    // Terminate when any task ends
    tokio::select! {
        _ = uplink => {},
        _ = downlink => {},
        _ = tcp_watcher => {},
    }

    // ⚠️ select! 结束只 drop 另两个 JoinHandle —— drop JoinHandle **不 abort** task,
    // uplink 会作为僵尸永久阻塞在 recv_from, 泄漏那个临时 UDP socket。必须显式
    // abort 未完成的 (已完成的 abort 是 no-op)。(服务端 udp_relay 早有 downlink.abort())
    ah_up.abort();
    ah_down.abort();
    ah_tcp.abort();

    let _ = tunnel_writer.lock().await.send_close_notify().await;

    debug!("UDP Relay gracefully closed for port {}", port);
}

// ── Direct 出口 UDP 转发 (SOCKS5 UDP ASSOCIATE, 不走隧道) ──
// 复用 handle_udp_associate 的 SOCKS5-UDP 封装语义, 但把"隧道收发"换成
// 直发 socket 收发. v1: outbound 绑 v4, IPv6 目标显式告警丢弃 (非静默).

/// SOCKS5 UDP 请求头里的目标地址.
enum UdpTarget {
    Ip(SocketAddr),
    Domain(String, u16),
}

/// 解析从 ATYP 开始的 SOCKS5 地址. 返回 (目标, payload 相对偏移).
fn parse_socks_udp_addr(b: &[u8]) -> Option<(UdpTarget, usize)> {
    match b.first()? {
        0x01 => {
            if b.len() < 1 + 4 + 2 {
                return None;
            }
            let ip = std::net::Ipv4Addr::new(b[1], b[2], b[3], b[4]);
            let port = u16::from_be_bytes([b[5], b[6]]);
            Some((UdpTarget::Ip(SocketAddr::from((ip, port))), 7))
        }
        0x04 => {
            if b.len() < 1 + 16 + 2 {
                return None;
            }
            let mut o = [0u8; 16];
            o.copy_from_slice(&b[1..17]);
            let ip = std::net::Ipv6Addr::from(o);
            let port = u16::from_be_bytes([b[17], b[18]]);
            Some((UdpTarget::Ip(SocketAddr::from((ip, port))), 19))
        }
        0x03 => {
            let len = *b.get(1)? as usize;
            if b.len() < 2 + len + 2 {
                return None;
            }
            let host = std::str::from_utf8(&b[2..2 + len]).ok()?.to_string();
            let port = u16::from_be_bytes([b[2 + len], b[3 + len]]);
            Some((UdpTarget::Domain(host, port), 2 + len + 2))
        }
        _ => None,
    }
}

/// 把回程源地址编码成 SOCKS5 UDP 头的 [ATYP][ADDR][PORT] 部分.
fn encode_socks_udp_addr(addr: SocketAddr) -> Vec<u8> {
    let mut out = Vec::with_capacity(19);
    match addr {
        SocketAddr::V4(a) => {
            out.push(0x01);
            out.extend_from_slice(&a.ip().octets());
        }
        SocketAddr::V6(a) => {
            out.push(0x04);
            out.extend_from_slice(&a.ip().octets());
        }
    }
    out.extend_from_slice(&addr.port().to_be_bytes());
    out
}

pub async fn handle_udp_associate_direct(mut local_tcp: TcpStream) {
    // 1. Bind client-facing relay socket
    let client_socket = match UdpSocket::bind("0.0.0.0:0").await {
        Ok(s) => Arc::new(s),
        Err(e) => {
            error!("Direct UDP: bind relay socket failed: {}", e);
            return;
        }
    };
    let port = match client_socket.local_addr() {
        Ok(a) => a.port(),
        Err(_) => return,
    };

    // 2. SOCKS5 reply with bound UDP port
    let mut reply = vec![0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0];
    reply.extend_from_slice(&port.to_be_bytes());
    if local_tcp.write_all(&reply).await.is_err() {
        return;
    }
    info!("Direct UDP relay started on port {}", port);

    // 3. Outbound socket (v1: IPv4). IPv6 目标在 uplink 里告警丢弃.
    let outbound = match UdpSocket::bind("0.0.0.0:0").await {
        Ok(s) => Arc::new(s),
        Err(e) => {
            error!("Direct UDP: bind outbound socket failed: {}", e);
            return;
        }
    };

    // client_addr 首包学到, 传给 downlink 决定回包目的地
    let (tx, mut rx) = tokio::sync::mpsc::channel::<SocketAddr>(1);

    // uplink: client → target
    let up_client = client_socket.clone();
    let up_out = outbound.clone();
    let uplink = async move {
        let mut buf = vec![0u8; 65536];
        let mut client_addr: Option<SocketAddr> = None;
        let mut dns_cache: HashMap<(String, u16), SocketAddr> = HashMap::new();
        loop {
            let (size, addr) = match up_client.recv_from(&mut buf).await {
                Ok(v) => v,
                Err(_) => break,
            };
            if client_addr.is_none() {
                client_addr = Some(addr);
                let _ = tx.send(addr).await;
            } else if client_addr != Some(addr) {
                continue; // 只服务已关联的客户端
            }

            let data = &buf[..size];
            // [RSV(2)][FRAG(1)][ATYP...]
            if data.len() < 4 || data[0] != 0 || data[1] != 0 {
                continue;
            }
            if data[2] != 0 {
                continue; // 不支持分片
            }
            let (target, off) = match parse_socks_udp_addr(&data[3..]) {
                Some(v) => v,
                None => continue,
            };
            let payload = &data[3 + off..];

            let dst = match target {
                UdpTarget::Ip(sa) => sa,
                UdpTarget::Domain(host, p) => {
                    let key = (host, p);
                    if let Some(sa) = dns_cache.get(&key) {
                        *sa
                    } else {
                        match crate::proxy::resolver::resolve_first(&key.0, key.1).await {
                            Ok(sa) => {
                                dns_cache.insert(key, sa);
                                sa
                            }
                            Err(_) => {
                                debug!("Direct UDP: resolve {} failed", key.0);
                                continue;
                            }
                        }
                    }
                }
            };

            if dst.is_ipv6() {
                warn!("Direct UDP: IPv6 target {} unsupported in v1, dropping", dst);
                continue;
            }
            if up_out.send_to(payload, dst).await.is_err() {
                break;
            }
        }
    };

    // downlink: target → client
    let dn_client = client_socket.clone();
    let dn_out = outbound.clone();
    let downlink = async move {
        let client_addr = match rx.recv().await {
            Some(a) => a,
            None => return,
        };
        let mut buf = vec![0u8; 65536];
        loop {
            let (size, src) = match dn_out.recv_from(&mut buf).await {
                Ok(v) => v,
                Err(_) => break,
            };
            let mut resp = vec![0u8, 0, 0]; // RSV + FRAG
            resp.extend_from_slice(&encode_socks_udp_addr(src));
            resp.extend_from_slice(&buf[..size]);
            let _ = dn_client.send_to(&resp, client_addr).await;
        }
    };

    // SOCKS5 标准: 控制 TCP 关闭即结束 UDP 关联
    let tcp_watcher = async move {
        let mut b = [0u8; 1];
        let _ = local_tcp.read(&mut b).await;
    };

    // 非 spawn: 任一分支结束, 其余 future 被 drop, socket 立即释放 (无后台泄漏)
    tokio::select! {
        _ = uplink => {},
        _ = downlink => {},
        _ = tcp_watcher => {},
    }

    debug!("Direct UDP relay closed for port {}", port);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::SocketAddr;
    use std::time::Duration;
    use tokio::net::TcpListener;

    #[test]
    fn parse_v4_addr() {
        // ATYP=1, 1.2.3.4:443, payload "hi"
        let b = [0x01, 1, 2, 3, 4, 0x01, 0xBB, b'h', b'i'];
        let (t, off) = parse_socks_udp_addr(&b).unwrap();
        assert_eq!(off, 7);
        assert!(matches!(t, UdpTarget::Ip(sa) if sa == "1.2.3.4:443".parse().unwrap()));
        assert_eq!(&b[off..], b"hi");
    }

    #[test]
    fn parse_domain_addr() {
        // ATYP=3, len=3 "abc", :80, payload "x"
        let b = [0x03, 3, b'a', b'b', b'c', 0x00, 0x50, b'x'];
        let (t, off) = parse_socks_udp_addr(&b).unwrap();
        assert_eq!(off, 7);
        match t {
            UdpTarget::Domain(h, p) => {
                assert_eq!(h, "abc");
                assert_eq!(p, 80);
            }
            _ => panic!("expected domain"),
        }
    }

    #[test]
    fn parse_truncated_returns_none() {
        assert!(parse_socks_udp_addr(&[]).is_none());
        assert!(parse_socks_udp_addr(&[0x01, 1, 2]).is_none()); // v4 too short
        assert!(parse_socks_udp_addr(&[0x03, 5, b'a']).is_none()); // domain len exceeds
        assert!(parse_socks_udp_addr(&[0x02, 0, 0]).is_none()); // bad ATYP
    }

    #[test]
    fn encode_v4_roundtrip() {
        let sa: SocketAddr = "9.8.7.6:1234".parse().unwrap();
        let enc = encode_socks_udp_addr(sa);
        assert_eq!(enc, vec![0x01, 9, 8, 7, 6, 0x04, 0xD2]);
    }

    // 端到端: 本地 echo UDP server + 走 Direct relay 打一发, 验证回程封装正确
    #[tokio::test]
    async fn direct_udp_echo_roundtrip() {
        // echo server
        let echo = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let echo_addr = echo.local_addr().unwrap();
        tokio::spawn(async move {
            let mut b = vec![0u8; 1500];
            loop {
                match echo.recv_from(&mut b).await {
                    Ok((n, from)) => {
                        let _ = echo.send_to(&b[..n], from).await;
                    }
                    Err(_) => break,
                }
            }
        });

        // 控制 TCP (loopback)
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let laddr = listener.local_addr().unwrap();
        let mut client_tcp = TcpStream::connect(laddr).await.unwrap();
        let (server_tcp, _) = listener.accept().await.unwrap();

        tokio::spawn(handle_udp_associate_direct(server_tcp));

        // 读 SOCKS5 reply 拿 relay UDP 端口
        let mut reply = [0u8; 10];
        client_tcp.read_exact(&mut reply).await.unwrap();
        let relay_port = u16::from_be_bytes([reply[8], reply[9]]);
        let relay_addr: SocketAddr = ([127, 0, 0, 1], relay_port).into();

        // 构造 SOCKS5-UDP 包发到 relay: RSV+FRAG+ATYP(v4)+IP+PORT+"hello"
        let cli = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let mut pkt = vec![0u8, 0, 0, 0x01];
        if let SocketAddr::V4(v4) = echo_addr {
            pkt.extend_from_slice(&v4.ip().octets());
            pkt.extend_from_slice(&v4.port().to_be_bytes());
        }
        pkt.extend_from_slice(b"hello");
        cli.send_to(&pkt, relay_addr).await.unwrap();

        // 收回程
        let mut rbuf = vec![0u8; 1500];
        let n = tokio::time::timeout(Duration::from_secs(2), cli.recv_from(&mut rbuf))
            .await
            .expect("timed out waiting for echo")
            .unwrap()
            .0;
        // 回程 = RSV(2)+FRAG(1)+ATYP(1)+IP(4)+PORT(2)+"hello"
        assert_eq!(rbuf[0], 0);
        assert_eq!(rbuf[3], 0x01); // v4 ATYP
        assert_eq!(&rbuf[n - 5..n], b"hello");
    }
}
