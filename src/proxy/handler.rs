use crate::proxy::outbound::OutboundNode;
use crate::proxy::socks5::{self, SocksCommand};
use crate::proxy::udp_relay;
use crate::config_watcher::CoreState;
use crate::router::RoutingRequest;
use arc_swap::ArcSwap;
use std::net::IpAddr;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tracing::{debug, error, info};

/**
 * [SOCKS5 客户端接入点]
 * 负责接收局域网设备或本机发来的代理请求，执行 SOCKS5 握手，
 * 解析目标地址，并将其分流至 TCP 或 UDP 处理流程。
 */
pub async fn handle_client(
    mut local: TcpStream,
    state: Arc<ArcSwap<CoreState>>,
    ebpf_engine: Option<Arc<tokio::sync::Mutex<crate::ebpf::EbpfEngine>>>,
    fake_ip_mapper: Option<Arc<crate::dns::fake_ip::FakeIpMapper>>,
) {
    let command = match socks5::handshake(&mut local).await {
        Ok(c) => c,
        Err(e) => {
            error!("SOCKS5 handshake failed: {}", e);
            return;
        }
    };
    
    let current_state = state.load();

    let target = match command {
        SocksCommand::TcpConnect(t) => t,
        SocksCommand::UdpAssociate => {
            info!("Starting UDP relay for client");
            let default_outbound_tag = &current_state.router.default_outbound;
            if let Some(outbound) = current_state.outbounds.get(default_outbound_tag) {
                let leaf = outbound.resolve_leaf();
                drop(current_state);
                match &*leaf {
                    OutboundNode::Mirage { pool, .. } => {
                        udp_relay::handle_udp_associate(local, pool.clone()).await;
                    }
                    OutboundNode::Direct { .. } => {
                        info!("UDP associate on Direct is currently dropping silently");
                    }
                    OutboundNode::Block { .. } => {
                        return;
                    }
                    _ => {
                        tracing::warn!("Unexpected leaf type {:?}, dropping", leaf.tag());
                        return;
                    }
                }
            }
            return;
        }
    };

    proxy_tcp_target(local, target, Vec::new(), state, ebpf_engine, fake_ip_mapper).await;
}

/**
 * [TCP 流量核心路由与转发]
 * 核心流程：
 * 1. 域名还原：检查请求是否命中 Fake-IP（如命中，还原真实域名）。
 * 2. 路由分发：基于 RuleEngine 进行正则匹配与 IP 匹配，决定该走哪个出站节点。
 * 3. 动态拨号：如果出站是 Mirage (Mirage 私有协议)，则直接从 WarmPool 中抽取一条极速隧道 (Zero-RTT)；如果是直连，则直接发起 TCP 连接。
 * 4. 全双工转发：启动 tokio 协程将本地和远端的读写流打通。
 */
pub async fn proxy_tcp_target(
    local: TcpStream,
    target: String,
    initial_payload: Vec<u8>,
    state: Arc<ArcSwap<CoreState>>,
    ebpf_engine: Option<Arc<tokio::sync::Mutex<crate::ebpf::EbpfEngine>>>,
    fake_ip_mapper: Option<Arc<crate::dns::fake_ip::FakeIpMapper>>,
) {
    let current_state = state.load();
    let mut final_target = target;
    let mut final_host = String::new();
    let mut final_port = 0;
    
    let parts: Vec<&str> = final_target.rsplitn(2, ':').collect();
    if parts.len() == 2 {
        let mut host = parts[1];
        if host.starts_with('[') && host.ends_with(']') {
            host = &host[1..host.len()-1];
        }
        if let Ok(port) = parts[0].parse() {
            final_port = port;
            final_host = host.to_string();
            if let Ok(ip) = host.parse::<IpAddr>() {
                if let IpAddr::V4(v4) = ip {
                    if let Some(mapper) = &fake_ip_mapper {
                        if mapper.is_fake_ip(&v4) {
                            if let Some(domain) = mapper.lookup_domain(&v4) {
                                info!("Fake-IP reverse lookup: {} -> {}", v4, domain);
                                final_host = domain.clone();
                                final_target = format!("{}:{}", domain, port);
                            }
                        }
                    }
                }
            }
        }
    }

    info!("Proxying TCP request to {}", final_target);
    
    // Parse target for router
    let mut routing_req = RoutingRequest {
        domain: None,
        ip: None,
        port: final_port,
        protocol: "tcp",
        source_ip: None, // Can extract from local if needed
        source_mac: None,
    };
    
    if let Ok(ip) = final_host.parse::<IpAddr>() {
        routing_req.ip = Some(ip);
    } else if !final_host.is_empty() {
        routing_req.domain = Some(&final_host);
    }

    let outbound_tag = current_state.router.route(routing_req);
    
    // Crucial: Use the reversed Fake-IP domain (if any) as the target for proxy and direct connections
    let target = final_target;
    
    info!("Router selected outbound [{}] for target {}", outbound_tag, target);
    
    let outbound = match current_state.outbounds.get(&outbound_tag) {
        Some(o) => o,
        None => {
            error!("Selected outbound {} not found in OutboundManager", outbound_tag);
            return;
        }
    };

    let leaf = outbound.resolve_leaf();
    drop(current_state);
    match &*leaf {
        OutboundNode::Mirage { pool, .. } => {
            let mut tunnel = match pool.get().await {
                Ok(t) => t,
                Err(e) => {
                    error!("Mirage outbound unavailable for {}: {}", target, e);
                    return;
                }
            };

            let target_bytes = target.as_bytes();
            let mut target_header = Vec::with_capacity(2 + target_bytes.len());
            target_header.extend_from_slice(&(target_bytes.len() as u16).to_be_bytes());
            target_header.extend_from_slice(target_bytes);

            if let Err(e) = tunnel.writer.send_data(&target_header).await {
                error!("Failed to send target address to upstream: {:?}", e);
                return;
            }

            if !initial_payload.is_empty() {
                if let Err(e) = tunnel.writer.send_data(&initial_payload).await {
                    error!("Failed to send initial payload: {:?}", e);
                    return;
                }
            }

            let active_fd = tunnel.get_raw_fd();
            let _guard = pool.active_fd_guard(active_fd);

            let (mut local_read, mut local_write) = local.into_split();
            let tunnel_reader = tunnel.reader;
            let mut tunnel_writer = tunnel.writer;

            let upload = async {
                let _ = tokio::time::timeout(std::time::Duration::from_secs(300), async {
                    let mut buf = [0u8; 16384];
                    loop {
                        match local_read.read(&mut buf).await {
                            Ok(0) => {
                                let _ = tunnel_writer.send_close_notify().await;
                                break;
                            }
                            Ok(n) => {
                                if tunnel_writer.send_data(&buf[..n]).await.is_err() {
                                    break;
                                }
                            }
                            Err(_) => {
                                let _ = tunnel_writer.send_close_notify().await;
                                break;
                            }
                        }
                    }
                }).await;

                // 退出前排空残留的本地数据，确保发送给本地的是 FIN 而不是 RST
                let _ = tokio::time::timeout(std::time::Duration::from_millis(500), async {
                    let mut discard = [0u8; 8192];
                    while let Ok(n) = local_read.read(&mut discard).await {
                        if n == 0 { break; }
                    }
                }).await;
                
                tunnel_writer
            };

            let download = async {
                // Producer/consumer 拆分: 老版本 loop 内 read + write 串行,
                // 读到 1 帧 (≤16KB) 就得等 write 完再读下一帧. 视频下载场景
                // (server → client 大量 AEAD 帧连发) 客户端 recv 队列被 kernel
                // 排空慢 → advertised window 缩 → server 见 rwnd_limited 67%.
                //
                // 新架构: 单 task 读进 mpsc channel, 消费端从 channel 拉多帧
                // 攒到 64KB 再一次 write_all. TCP 层面: 读者持续排空 kernel
                // recv buffer, advertised window 稳定大; 应用层: 一次系统调
                // 用搬 4 帧 payload, per-byte 开销降 4×.
                //
                // channel 容量 32 帧 (~512KB) 平衡"生产者不阻塞" vs "内存占用".
                let (tx, mut rx) = tokio::sync::mpsc::channel::<Vec<u8>>(32);
                let mut reader = tunnel_reader;

                let producer = tokio::spawn(async move {
                    loop {
                        match reader.recv_data().await {
                            Ok(data) => {
                                if tx.send(data.to_vec()).await.is_err() { break; }
                            }
                            Err(_) => break,
                        }
                    }
                    reader
                });

                let _ = tokio::time::timeout(std::time::Duration::from_secs(300), async {
                    const BATCH_TARGET: usize = 65536;
                    while let Some(first) = rx.recv().await {
                        let mut batch = first;
                        // 攒足 64KB 或 channel 暂空
                        while batch.len() < BATCH_TARGET {
                            match rx.try_recv() {
                                Ok(more) => batch.extend_from_slice(&more),
                                Err(_) => break,
                            }
                        }
                        if local_write.write_all(&batch).await.is_err() { break; }
                    }
                }).await;

                // consumer 退出 → drop rx → producer 的 tx.send 会返 Err → 循环退出
                drop(rx);
                let mut tunnel_reader = producer.await.unwrap_or_else(|_| {
                    // 极罕见 producer 被外部 panic. 用一个 dummy 结构做兜底不太可能.
                    // 实际实现里 producer body 里的 recv_data 只会返 Ok/Err, 不会
                    // panic. 保留 unwrap_or_else 作静态防御, 生产不会触发.
                    panic!("download producer task panicked unexpectedly");
                });

                // 退出前排空远端发来的残留数据, 确保发给服务端的是 FIN 而不是 RST (核心隐蔽特征)
                let _ = tokio::time::timeout(std::time::Duration::from_millis(500), async {
                    while let Ok(_) = tunnel_reader.recv_data().await {}
                }).await;

                tunnel_reader
            };

            let (tw, tr) = tokio::join!(upload, download);
            drop(_guard);   // ← 先从 set 移除，防止微秒级死 FD 暴露
            drop(tw);
            drop(tr);
            debug!("Mirage connection to {} gracefully closed", target);
        }
        OutboundNode::Direct { .. } => {
            let mut target_stream = match tokio::net::TcpStream::connect(&target).await {
                Ok(s) => s,
                Err(e) => {
                    error!("Direct connection to {} failed: {}", target, e);
                    return;
                }
            };
            
            if !initial_payload.is_empty() {
                if let Err(e) = target_stream.write_all(&initial_payload).await {
                    error!("Failed to send initial payload to direct target: {:?}", e);
                    return;
                }
            }
            
            let mut ebpf_spliced = false;
            if let Some(engine) = ebpf_engine {
                let mut lock = engine.lock().await;
                match lock.register_splice(&local, &target_stream) {
                    Ok(_) => {
                        info!("eBPF TCP Splicing activated for {}. Tokio bypass enabled.", target);
                        ebpf_spliced = true;
                    }
                    Err(e) => {
                        debug!("eBPF splicing failed: {}. Falling back to userspace forwarding.", e);
                    }
                }
            }

            if ebpf_spliced {
                use std::os::unix::io::AsRawFd;
                use tokio::io::unix::AsyncFd;
                
                struct EpollHandle(std::os::unix::io::RawFd);
                impl AsRawFd for EpollHandle {
                    fn as_raw_fd(&self) -> std::os::unix::io::RawFd { self.0 }
                }
                impl Drop for EpollHandle {
                    fn drop(&mut self) { unsafe { libc::close(self.0); } }
                }

                let epfd = unsafe { libc::epoll_create1(libc::EPOLL_CLOEXEC) };
                if epfd >= 0 {
                    let mut ev1 = libc::epoll_event { events: libc::EPOLLRDHUP as u32, u64: 1 };
                    let r1 = unsafe { libc::epoll_ctl(epfd, libc::EPOLL_CTL_ADD, local.as_raw_fd(), &mut ev1) };
                    if r1 < 0 { tracing::warn!("epoll_ctl ADD local failed: {}", std::io::Error::last_os_error()); }
                    
                    let mut ev2 = libc::epoll_event { events: libc::EPOLLRDHUP as u32, u64: 2 };
                    let r2 = unsafe { libc::epoll_ctl(epfd, libc::EPOLL_CTL_ADD, target_stream.as_raw_fd(), &mut ev2) };
                    if r2 < 0 { tracing::warn!("epoll_ctl ADD target failed: {}", std::io::Error::last_os_error()); }

                    if let Ok(async_epoll) = AsyncFd::new(EpollHandle(epfd)) {
                        let _ = tokio::time::timeout(std::time::Duration::from_secs(1800), async {
                            loop {
                                let mut guard = match async_epoll.readable().await {
                                    Ok(g) => g,
                                    Err(_) => break,
                                };
                                let mut events = [libc::epoll_event { events: 0, u64: 0 }; 2];
                                let n = unsafe { libc::epoll_wait(epfd, events.as_mut_ptr(), 2, 0) };
                                if n > 0 {
                                    break;
                                }
                                guard.clear_ready();
                            }
                        }).await;
                    }
                }
                debug!("eBPF connection to {} gracefully closed", target);
                return;
            }

            let (target_read, mut target_write) = target_stream.into_split();
            let (local_read, mut local_write) = local.into_split();

            let mut monitored_local_read = crate::monitor::MonitoredReader::new(local_read, true);
            let mut monitored_target_read = crate::monitor::MonitoredReader::new(target_read, false);

            let upload = async {
                if tokio::io::copy(&mut monitored_local_read, &mut target_write).await.is_err() {
                    return Err::<(), ()>(());
                }
                let _ = target_write.shutdown().await;
                Ok::<(), ()>(())
            };
            let download = async {
                if tokio::io::copy(&mut monitored_target_read, &mut local_write).await.is_err() {
                    return Err::<(), ()>(());
                }
                let _ = local_write.shutdown().await;
                Ok::<(), ()>(())
            };

            let _ = tokio::try_join!(upload, download);
            debug!("Direct connection to {} gracefully closed", target);
        }
        OutboundNode::Block { .. } => {
            debug!("Connection to {} blocked by routing rule", target);
            // Drop connection
        }
        _ => {
            tracing::warn!("Unexpected leaf type {:?} for {}, dropping", leaf.tag(), target);
        }
    }
}
