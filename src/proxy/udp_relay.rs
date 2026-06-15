use crate::proxy::pool::WarmPool;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tracing::{debug, error, info};

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
    let mut tunnel = pool.get().await;
    if tunnel.writer.send_data(&[0x00]).await.is_err() {
        error!("Failed to send UDP sentinel");
        return;
    }
    
    let mut tunnel_reader = tunnel.reader;
    let mut tunnel_writer = tunnel.writer;
    
    // 4. Run Relay Loops
    let (tx, mut rx) = tokio::sync::mpsc::channel(1);
    
    let udp_rx = udp_socket.clone();
    let udp_tx = udp_socket;
    
    let uplink = tokio::spawn(async move {
        let mut buf = [0u8; 65536];
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
                    
                    if tunnel_writer.send_data(&frame).await.is_err() {
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
    
    // Terminate when any task ends
    tokio::select! {
        _ = uplink => {},
        _ = downlink => {},
        _ = tcp_watcher => {},
    }
    
    debug!("UDP Relay gracefully closed for port {}", port);
}
