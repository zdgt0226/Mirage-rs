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

/// Mirage 隧道 relay 的**空闲**超时 (每次 read/recv 无数据满此值才断)。
/// 与服务端 mirage_server/tcp_relay.rs 的 1800s 对齐, 两端一致不互相早关。
/// ⚠️ 必须包在每次 read **内层** —— 包在整个 loop 外层会变成绝对墙钟寿命,
/// 满 300s 无条件斩断 SSH/视频/大下载/长连接 (曾经的 bug)。
const MIRAGE_RELAY_IDLE: std::time::Duration = std::time::Duration::from_secs(1800);

/// 人类可读字节数 (日志用): 1536 → "1.5K", 3145728 → "3.0M"。
pub(crate) fn human_bytes(n: u64) -> String {
    if n >= 1 << 20 {
        format!("{:.1}M", n as f64 / (1 << 20) as f64)
    } else if n >= 1 << 10 {
        format!("{:.1}K", n as f64 / (1 << 10) as f64)
    } else {
        format!("{}B", n)
    }
}

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
                        udp_relay::handle_udp_associate_direct(local).await;
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

            debug!("[TUNNEL] {} 建立 (隧道就绪, 目标头已发)", target);
            let t_start = std::time::Instant::now();

            let (mut local_read, mut local_write) = local.into_split();
            let tunnel_reader = tunnel.reader;
            let mut tunnel_writer = tunnel.writer;

            let upload = async {
                let mut buf = [0u8; 16384];
                let mut up_bytes: u64 = 0;
                loop {
                    // 空闲超时包在每次 read 内层 (非整个 loop 外层, 见 MIRAGE_RELAY_IDLE 注释)
                    match tokio::time::timeout(MIRAGE_RELAY_IDLE, local_read.read(&mut buf)).await {
                        Ok(Ok(0)) => {
                            let _ = tunnel_writer.send_close_notify().await;
                            break;
                        }
                        Ok(Ok(n)) => {
                            if tunnel_writer.send_data(&buf[..n]).await.is_err() {
                                break;
                            }
                            up_bytes += n as u64;
                        }
                        Ok(Err(_)) => {
                            let _ = tunnel_writer.send_close_notify().await;
                            break;
                        }
                        Err(_) => break, // 空闲超时: 双向 1800s 无数据
                    }
                }

                // 退出前排空残留的本地数据，确保发送给本地的是 FIN 而不是 RST
                let _ = tokio::time::timeout(std::time::Duration::from_millis(500), async {
                    let mut discard = [0u8; 8192];
                    while let Ok(n) = local_read.read(&mut discard).await {
                        if n == 0 { break; }
                    }
                }).await;

                (tunnel_writer, up_bytes)
            };

            let download = async {
                // alpha.21 曾尝试 mpsc(32) producer/consumer 批量, 但外部审计
                // 指出 tokio 调度器倾向立刻醒 consumer, `try_recv` 抓空, 批量
                // 失效. alpha.23 撤回改直连: recv_data → write_all 一对一.
                //
                // 真正的批量在两个别的地方发生:
                // 1. 服务端 CryptoWriter 内嵌 BufWriter(64KB), send_data 里
                //    多帧 write_all 自动合成 syscall
                // 2. 服务端 tcp_relay 用 try_read 贪婪收割 upstream
                //
                // 客户端接收侧因为 CryptoReader 的 read_exact 语义无法安全
                // 加 try_recv (中途取消会丢帧半读). 保持一对一直连最稳.
                let mut tunnel_reader = tunnel_reader;
                let mut down_bytes: u64 = 0;

                loop {
                    // 空闲超时包在每次 recv 内层 (非整个 loop 外层)
                    match tokio::time::timeout(MIRAGE_RELAY_IDLE, tunnel_reader.recv_data()).await {
                        Ok(Ok(data)) => {
                            if local_write.write_all(&data).await.is_err() {
                                break;
                            }
                            down_bytes += data.len() as u64;
                        }
                        Ok(Err(_)) => break,
                        Err(_) => break, // 空闲超时
                    }
                }

                // 退出前排空远端发来的残留数据, 确保发给服务端的是 FIN 而不是 RST (核心隐蔽特征)
                let _ = tokio::time::timeout(std::time::Duration::from_millis(500), async {
                    while let Ok(_) = tunnel_reader.recv_data().await {}
                }).await;

                (tunnel_reader, down_bytes)
            };

            let ((tw, up_bytes), (tr, down_bytes)) = tokio::join!(upload, download);
            drop(_guard);   // ← 先从 set 移除，防止微秒级死 FD 暴露
            drop(tw);
            drop(tr);
            debug!(
                "[TUNNEL] {} 关闭 (↑{} ↓{}, 存活 {:.1}s)",
                target,
                human_bytes(up_bytes),
                human_bytes(down_bytes),
                t_start.elapsed().as_secs_f64()
            );
        }
        OutboundNode::Direct { .. } => {
            // v0.4.5-alpha.3: 直连数据面 = splice(2)+pipe 零拷贝 (学 dae/control/tcp_copy_linux.go).
            //
            // 历史: alpha.1/alpha.2 尝试用 sockmap sk_skb/stream_verdict + bpf_sk_redirect_hash
            // 做零拷贝, kernel 6.x 静默丢包 (verdict SK_PASS 但 curl 0 字节). dae 官方在 sk_msg
            // 侧遇到 kernel panic 明确放弃整套 sockmap redirect 家族, 改用 tc-bpf 路由 +
            // splice(2) 数据面. 我们的 SOCKS5 场景不需要 tc-bpf 路由 (客户端主动 opt-in), 只
            // 需要 splice 就够了. sk_psock 家族的整块数据面已删除.
            //
            // splice(2) 是 SPLICE_F_MOVE 只搬 page 引用的 syscall, kernel 3.x 起稳定, 真正的
            // 零拷贝且无 sk_psock 的坑.
            let _ = ebpf_engine; // eBPF 数据面已经不用了; 参数保留为下游兼容, 但这里不用.
            let t_start = std::time::Instant::now();
            let peer_str = local.peer_addr()
                .map(|a| a.to_string())
                .unwrap_or_else(|_| "?".to_string());
            let initial_len = initial_payload.len();

            // v0.4.5-alpha.8: connect_smart = DNS 缓存 + IPv4 优先 + 每尝试超时.
            // 修 musl 无 DNS 缓存导致每连接 getaddrinfo 120ms + 受限 IPv6 hang.
            let mut target_stream = match crate::proxy::resolver::connect_smart(&target).await {
                Ok(s) => s,
                Err(e) => {
                    error!("Direct connect fail: peer={} target={} err='{}'", peer_str, target, e);
                    return;
                }
            };
            let t_connect_ms = t_start.elapsed().as_millis();

            if initial_len > 0 {
                if let Err(e) = target_stream.write_all(&initial_payload).await {
                    error!(
                        "Direct initial_payload write fail: peer={} target={} initial={}B err='{}'",
                        peer_str, target, initial_len, e
                    );
                    return;
                }
            }

            let (pool_hits_pre, pool_misses_pre, _) = crate::proxy::splice::pool_stats();
            debug!(
                "[DIRECT] {} 建立 (peer={} initial={}B connect={}ms pool_hits={} pool_misses={})",
                target, peer_str, initial_len, t_connect_ms, pool_hits_pre, pool_misses_pre
            );

            let relay_start = std::time::Instant::now();
            match crate::proxy::splice::splice_relay(local, target_stream).await {
                Ok((up, down)) => {
                    let (pool_hits, pool_misses, pool_len) = crate::proxy::splice::pool_stats();
                    debug!(
                        "[DIRECT] {} 关闭 (↑{} ↓{}, 存活 {:.1}s, peer={} relay={}ms \
                         pool_hits={} pool_misses={} pool_idle={})",
                        target, human_bytes(up), human_bytes(down), t_start.elapsed().as_secs_f64(),
                        peer_str, relay_start.elapsed().as_millis(),
                        pool_hits, pool_misses, pool_len
                    );
                }
                Err(e) => {
                    let reason = match e.kind() {
                        std::io::ErrorKind::TimedOut => {
                            if e.to_string().contains("idle") { "idle_timeout" } else { "timeout" }
                        }
                        std::io::ErrorKind::ConnectionReset => "conn_reset",
                        std::io::ErrorKind::ConnectionAborted => "conn_aborted",
                        std::io::ErrorKind::UnexpectedEof => "unexpected_eof",
                        std::io::ErrorKind::BrokenPipe => "broken_pipe",
                        std::io::ErrorKind::WriteZero => "write_zero",
                        _ => "other",
                    };
                    debug!(
                        "[DIRECT] {} 出错 (reason={} 存活 {:.1}s peer={} err='{}')",
                        target, reason, t_start.elapsed().as_secs_f64(), peer_str, e
                    );
                }
            }
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
