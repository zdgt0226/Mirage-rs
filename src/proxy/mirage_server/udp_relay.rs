//! 服务端 UDP 上游转发. 加密 channel 内嵌"伪 SOCKS5 UDP" 帧格式封装多目标
//! UDP 包. 跟 src/proxy/udp_relay.rs (客户端 UDP forwarding) 语义不同, 故独立.
//!
//! 帧格式: [2B Len N][1B ATYP][ADDR][2B PORT][PAYLOAD]
//! ATYP: 1=IPv4, 3=Domain, 4=IPv6

use std::sync::Arc;
use tokio::net::UdpSocket;
use tracing::{debug, error};

pub(super) async fn handle_udp_relay(
    mut reader: crate::crypto::aead::CryptoReader<tokio::net::tcp::OwnedReadHalf>,
    writer: crate::crypto::aead::CryptoWriter<tokio::net::tcp::OwnedWriteHalf>
) {
    debug!("Mirage Server: Started UDP relay session");

    // Bind an ephemeral UDP socket for sending/receiving
    let udp_socket = match UdpSocket::bind("0.0.0.0:0").await {
        Ok(s) => Arc::new(s),
        Err(e) => {
            error!("Failed to bind server UDP socket: {}", e);
            return;
        }
    };

    let (tx, mut rx) = tokio::sync::mpsc::channel(256);
    let udp_clone = udp_socket.clone();

    let writer = std::sync::Arc::new(tokio::sync::Mutex::new(writer));
    let writer_clone = writer.clone();

    let downlink = tokio::spawn(async move {
        let mut buf = vec![0u8; 65536];
        loop {
            match udp_clone.recv_from(&mut buf).await {
                Ok((size, addr)) => {
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
                Err(_) => break,
            }
        }
    });

    let tunnel_downlink = async move {
        while let Some(packet) = rx.recv().await {
            if writer_clone.lock().await.send_data(&packet).await.is_err() {
                break;
            }
        }
    };

    let tunnel_uplink = async move {
        let mut buffer = Vec::new();
        loop {
            match reader.recv_data().await {
                Ok(chunk) => {
                    buffer.extend_from_slice(&chunk);

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

                        // Convert to SocketAddr via tokio lookup or fast path
                        if let Ok(mut addrs) = tokio::net::lookup_host((target_addr_str.clone(), port)).await {
                            if let Some(socket_addr) = addrs.next() {
                                let _ = udp_socket.send_to(payload, socket_addr).await;
                            }
                        }
                    }
                }
                Err(_) => break,
            }
        }
    };

    tokio::select! {
        _ = tunnel_uplink => {}
        _ = tunnel_downlink => {}
    }

    let _ = writer.lock().await.send_close_notify().await;
    downlink.abort();
}
