use std::net::SocketAddr;
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Mutex, OnceLock};

static UNAUTH_CONNS: OnceLock<Mutex<HashMap<IpAddr, usize>>> = OnceLock::new();

static GLOBAL_UNAUTH: AtomicUsize = AtomicUsize::new(0);

struct IpSlotGuard(IpAddr);
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
use tracing::{debug, error, info, warn};
use std::sync::Arc;

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
                if let Some(rate) = brutal_rate_bytes_per_sec {
                    use std::os::unix::io::AsRawFd;
                    crate::proxy::brutal::apply_brutal(stream.as_raw_fd(), rate);
                }
                let pwd = password.clone();
                let cam = camouflage_host.to_string();
                tokio::spawn(async move {
                    handle_connection(stream, peer_addr, pwd, cam).await;
                });
            }
            Err(e) => {
                error!("Mirage Server accept error: {}", e);
            }
        }
    }
}

async fn handle_connection(mut stream: TcpStream, peer_addr: SocketAddr, password: String, camouflage_host: String) {
    stream.set_nodelay(true).unwrap_or_default();

    // 1. Parse ClientHello
    let mut hello_buf = vec![0u8; 1024];
    let n = match tokio::time::timeout(std::time::Duration::from_secs(5), stream.read(&mut hello_buf)).await {
        Ok(Ok(n)) if n > 0 => n,
        _ => return,
    };
    let client_hello = &hello_buf[..n];

    // Authenticate by searching for the token
    let mut authenticated = false;
    let mut client_random = [0u8; 32];
    
    if client_hello.len() >= 43 && client_hello[0] == 0x16 && client_hello[5] == 0x01 {
        let sid_len = client_hello[43] as usize;
        if client_hello.len() >= 44 + sid_len {
            let session_id = &client_hello[44..44+sid_len];
            if session_id.len() == 32 {
                let mut sid_array = [0u8; 32];
                sid_array.copy_from_slice(session_id);
                if crate::crypto::hello_auth::verify_session_token(&password, &sid_array) {
                    authenticated = true;
                    client_random.copy_from_slice(&client_hello[11..43]);
                }
            }
        }
    }
    
    if !authenticated {
        warn!("Mirage Server auth failed from {}", peer_addr);
        
        let global_count = GLOBAL_UNAUTH.fetch_add(1, Ordering::SeqCst);
        if global_count >= 5000 {
            GLOBAL_UNAUTH.fetch_sub(1, Ordering::SeqCst);
            return;
        }

        let ip = peer_addr.ip();
        let _slot_guard = {
            let mut map = UNAUTH_CONNS.get_or_init(|| Mutex::new(HashMap::new())).lock().unwrap();
            let count = map.entry(ip).or_insert(0);
            if *count >= 100 {
                GLOBAL_UNAUTH.fetch_sub(1, Ordering::SeqCst);
                return;
            }
            *count += 1;
            IpSlotGuard(ip)
        };

        let camouflage_fut = async {
            if let Ok(mut cam_stream) = tokio::time::timeout(
                std::time::Duration::from_secs(5),
                TcpStream::connect(&format!("{}:443", camouflage_host))
            ).await.unwrap_or(Err(std::io::Error::new(std::io::ErrorKind::TimedOut, "Camouflage connect timeout"))) {
                let _ = cam_stream.write_all(client_hello).await;
                let _ = tokio::time::timeout(
                    std::time::Duration::from_secs(300),
                    tokio::io::copy_bidirectional(&mut stream, &mut cam_stream)
                ).await;
            } else {
                // camouflage_host is unreachable, fallback to HandshakeCache
                let template = crate::crypto::handshake_cache::get_server_hello(&camouflage_host, client_hello).await;
                let _ = tokio::time::timeout(
                    std::time::Duration::from_secs(5),
                    stream.write_all(&template)
                ).await;
            }
        };
        camouflage_fut.await;
        
        return;
    }



    // 2.5 Send ServerHello template back to satisfy Mirage Client's TLS state machine
    let template = crate::crypto::handshake_cache::get_server_hello(&camouflage_host, client_hello).await;
    if let Err(e) = stream.write_all(&template).await {
        tracing::error!("Mirage Server: write_all template failed: {}", e);
        return;
    }

    // 2.7 Consume Fake Client Tail (63 bytes)
    let mut tail = [0u8; 63];
    match tokio::time::timeout(std::time::Duration::from_secs(5), stream.read_exact(&mut tail)).await {
        Ok(Err(e)) => {
            tracing::error!("Mirage Server: read_exact tail failed: {}", e);
            return;
        }
        Err(_) => {
            tracing::error!("Mirage Server: read_exact tail timed out!");
            return;
        }
        Ok(Ok(_)) => {
            tracing::info!("Mirage Server: Successfully consumed 63 bytes tail");
        }
    }

    // 3. Setup Crypto Stream
    let (read_half, write_half) = stream.into_split();
    let (mut reader, mut writer) = crate::crypto::aead::create_crypto_pair(
        read_half,
        write_half,
        &password,
        &client_random,
        false, // is_initiator = false (Server)
    );

    // 3.5 v0.4 协议: 通过加密 channel 主动下发服务器时间, 让客户端无需 NTP/HTTP 探测.
    //     帧格式: [0x01 type=TIME_SYNC][0x01 proto_ver][8B u64 BE server unix sec] = 10 字节
    {
        use std::time::{SystemTime, UNIX_EPOCH};
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        let mut frame = [0u8; 10];
        frame[0] = 0x01; // type = TIME_SYNC
        frame[1] = 0x01; // proto version
        frame[2..10].copy_from_slice(&now.to_be_bytes());
        if let Err(e) = writer.send_data(&frame).await {
            tracing::error!("Mirage Server: failed to send TIME_SYNC frame: {:?}", e);
            return;
        }
    }

    // 4. Read first data chunk to determine TCP or UDP
    let first_chunk = match tokio::time::timeout(std::time::Duration::from_secs(5), reader.recv_data()).await {
        Ok(Ok(data)) => data,
        Ok(Err(e)) => {
            tracing::error!("Mirage Server: recv_data failed: {:?}", e);
            return;
        }
        Err(_) => {
            tracing::error!("Mirage Server: recv_data timed out!");
            return;
        }
    };
    
    tracing::info!("Mirage Server: Received first_chunk of len {}", first_chunk.len());

    if first_chunk.len() == 1 && first_chunk[0] == 0x00 {
        // UDP Mode
        handle_udp_relay(reader, writer).await;
    } else if first_chunk.len() >= 2 {
        // TCP Mode
        let target_len = u16::from_be_bytes([first_chunk[0], first_chunk[1]]) as usize;
        tracing::info!("Mirage Server: Parsed target_len = {}", target_len);
        
        if first_chunk.len() >= 2 + target_len {
            let target = match String::from_utf8(first_chunk[2..2+target_len].to_vec()) {
                Ok(t) => t,
                Err(_) => {
                    tracing::error!("Mirage Server: Target UTF-8 parsing failed!");
                    return;
                }
            };
            
            tracing::info!("Mirage Server: Target resolved to {}", target);
            
            // Check if there's any piggybacked payload after the target string
            let payload = if first_chunk.len() > 2 + target_len {
                Some(first_chunk[2+target_len..].to_vec())
            } else {
                None
            };
            
            handle_tcp_relay(target, payload, reader, writer).await;
        } else {
            tracing::error!("Mirage Server: first_chunk too short for target_len!");
        }
    } else {
        tracing::error!("Mirage Server: first_chunk too short to be valid!");
    }
}

async fn handle_tcp_relay(
    target: String, 
    initial_payload: Option<Vec<u8>>, 
    mut reader: crate::crypto::aead::CryptoReader<tokio::net::tcp::OwnedReadHalf>, 
    mut writer: crate::crypto::aead::CryptoWriter<tokio::net::tcp::OwnedWriteHalf>
) {
    debug!("Mirage Server: Connecting to TCP target {}", target);
    let mut upstream = match tokio::net::TcpStream::connect(&target).await {
        Ok(s) => s,
        Err(e) => {
            warn!("Mirage Server failed to connect to {}: {}", target, e);
            return;
        }
    };
    
    if let Some(payload) = initial_payload {
        if !payload.is_empty() {
            let _ = upstream.write_all(&payload).await;
        }
    }

    let (mut up_read, mut up_write) = upstream.into_split();

    let upload = async {
        loop {
            match tokio::time::timeout(std::time::Duration::from_secs(1800), reader.recv_data()).await {
                Ok(Ok(data)) => {
                    if up_write.write_all(&data).await.is_err() {
                        break;
                    }
                }
                _ => break,
            }
        }
    };

    let download = async {
        let mut buf = [0u8; 16384];
        loop {
            match tokio::time::timeout(std::time::Duration::from_secs(1800), up_read.read(&mut buf)).await {
                Ok(Ok(0)) => break,
                Ok(Ok(n)) => {
                    if writer.send_data(&buf[..n]).await.is_err() {
                        break;
                    }
                }
                _ => break,
            }
        }
        let _ = writer.send_close_notify().await;
    };

    tokio::join!(upload, download);
}

async fn handle_udp_relay(
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
