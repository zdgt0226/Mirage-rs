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
                match &*leaf {
                    OutboundNode::Pyreality { pool, .. } => {
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

pub async fn proxy_tcp_target(
    mut local: TcpStream,
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
    match &*leaf {
        OutboundNode::Pyreality { pool, .. } => {
            let mut tunnel = pool.get().await;

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

            let (mut local_read, mut local_write) = local.into_split();
            let mut tunnel_reader = tunnel.reader;
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
            };

            let download = async {
                let _ = tokio::time::timeout(std::time::Duration::from_secs(300), async {
                    loop {
                        match tunnel_reader.recv_data().await {
                            Ok(data) => {
                                if local_write.write_all(&data).await.is_err() {
                                    break;
                                }
                            }
                            Err(_) => break,
                        }
                    }
                }).await;

                // 退出前排空远端发来的残留数据，确保发给服务端的是 FIN 而不是 RST (核心隐蔽特征)
                let _ = tokio::time::timeout(std::time::Duration::from_millis(500), async {
                    while let Ok(_) = tunnel_reader.recv_data().await {}
                }).await;
            };

            tokio::join!(upload, download);
            debug!("Pyreality connection to {} gracefully closed", target);
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
                if let Ok(mut lock) = engine.try_lock() {
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
            }

            if ebpf_spliced {
                // Keep the connections alive in userspace to prevent dropping the FDs
                // The actual traffic will bypass userspace via eBPF sk_msg sockmap.
                let mut buf1 = [0u8; 1];
                let mut buf2 = [0u8; 1];
                let _ = tokio::select! {
                    _ = local.read(&mut buf1) => {}
                    _ = target_stream.read(&mut buf2) => {}
                };
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
