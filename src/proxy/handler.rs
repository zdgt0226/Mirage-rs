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
use tracing::{debug, error, info, warn};

/// Mirage 隧道 relay 的**空闲**超时: 见 `crate::proxy::relay_idle()` (默认 1800s, env
/// `MIRAGE_RELAY_IDLE` 秒可调; 与服务端 tcp_relay.rs 共用此值, 两端须同设)。
///
/// **双向空闲语义**: 通过 `crate::proxy::IdleClock` 两个方向共享最后活跃时间, 只要任一方向
/// 有数据传输 (如 HTTP/1.1 大下载、只收不发的 SSE/WebSocket), 共享时钟持续 touch 绝不误断;
/// 只有两个方向**共同静默**满 `relay_idle` 时才超时退出。
/// ⚠️ 必须包在每次 read **内层** —— 包在整个 loop 外层会变成绝对墙钟寿命,
/// 满超时无条件斩断 SSH/视频/大下载/长连接 (曾经的 bug)。
#[inline]
fn relay_idle() -> std::time::Duration {
    crate::proxy::relay_idle()
}

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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DownloadEndReason {
    CloseNotify,
    TargetUnreachable, // 服务端报告目标不可达
    PeerError,     // 对端错误结束 (裸 EOF、RST、解密失败)
    IdleTimeout,   // 空闲超时
    LocalWriteErr, // 本地写失败
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RealConnResult {
    Success,
    Failure,
    Ignore,
}

pub(crate) fn classify_real_conn(
    down_bytes: u64,
    end_reason: DownloadEndReason,
    local_eof: bool,
) -> RealConnResult {
    if down_bytes > 0 {
        RealConnResult::Success
    } else if end_reason == DownloadEndReason::PeerError && !local_eof {
        RealConnResult::Failure
    } else {
        RealConnResult::Ignore
    }
}

pub(crate) fn record_real_failure_and_log(
    pool: &crate::proxy::pool::WarmPool,
    target: &str,
    node_tag: &str,
) {
    if pool.stats.write().unwrap_or_else(|e| e.into_inner()).record_real_failure(target) {
        info!(
            "节点 {} 真实连接连续失败 (涉及 {} 个不同目标), urltest 降级 {}s",
            node_tag,
            crate::proxy::pool::PENALIZE_AFTER_FAILURES,
            crate::proxy::pool::PENALTY_DURATION.as_secs()
        );
    }
}

pub(crate) fn record_first_down(
    pool: &crate::proxy::pool::WarmPool,
    target: &str,
    first_up: Option<std::time::Instant>,
    now: std::time::Instant,
    node_tag: &str,
) {
    let mut trigger_probe = false;
    {
        let mut stats = pool.stats.write().unwrap_or_else(|e| e.into_inner());
        stats.record_real_success();
        if let Some(up) = first_up {
            if up <= now {
                let ttfb_ms = now.duration_since(up).as_millis() as u64;
                let baseline_ms = stats.median_latency_ms();
                match crate::proxy::pool::is_slow_ttfb(ttfb_ms, baseline_ms) {
                    Some(true) if stats.record_real_slow(target) => {
                        trigger_probe = true;
                    }
                    Some(true) => {}
                    Some(false) => {
                        stats.record_real_fast();
                    }
                    None => {}
                }
            }
        }
    }
    if trigger_probe {
        pool.trigger_probe();
        info!(
            "节点 {} 真实连接连续明显变慢 (涉及 {} 个不同目标), 触发补测",
            node_tag,
            crate::proxy::pool::SLOW_TRIGGER_COUNT
        );
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
    auth: Option<Arc<crate::config::InboundAuth>>,
    // 本连接来自哪个入站 (供 routing 的 `inbound` 条件用)。
    inbound_tag: Option<Arc<str>>,
) {
    let command = match socks5::handshake(&mut local, auth.as_deref()).await {
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
            // 逐数据报路由 —— 目标写在每个数据报自己的 SOCKS5 头里, ASSOCIATE 时还不知道
            // 要连谁, 所以出站不能在这里定死 (旧实现用 default_outbound 定死, 导致所有
            // UDP 完全绕过路由规则)。
            drop(current_state);
            udp_relay::handle_udp_associate_routed(local, state, inbound_tag).await;
            return;
        }
    };

    proxy_tcp_target(local, target, Vec::new(), state, ebpf_engine, fake_ip_mapper, inbound_tag, false).await;
}

/// 把连接 peer 的 IP 归一成路由用的源 IP。
///
/// 双栈 socket 上一个 IPv4 客户端可能以 v4-mapped v6 (形如 ffff 前缀的 v6) 出现; 不归一则 v4
/// 的 source_ip_cidr 规则匹配不中 → 设备分流对这类连接失效。故把 v4-mapped 折回 v4, 其余原样。
pub(crate) fn normalize_peer_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(IpAddr::V6(v6)),
        v4 => v4,
    }
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
    // 本连接来自哪个入站 (供 routing 的 `inbound` 条件用); None = 调用方未提供。
    inbound_tag: Option<Arc<str>>,
    // 调用方是否**已经嗅过**。transparent 入站自己会先嗅一轮 (它要把域名替换进 target
    // 交服务端在干净网络解析, 抗 DNS 污染), 嗅不到才退回裸 IP —— 那种情况下这里再嗅
    // 一次必然也嗅不到 (同一条流、仍然没数据), 白白再等一个超时。
    already_sniffed: bool,
) {
    let current_state = state.load();
    let mut final_target = target;
    let mut final_host = String::new();
    let mut final_port = 0;
    // 段内 fake-IP 但反查不出域名 (网关重启清表等): 目的地是死的假 IP, 需靠嗅探拿域名, 拿不到则 reset。
    let mut unresolved_fakeip = false;

    let parts: Vec<&str> = final_target.rsplitn(2, ':').collect();
    if parts.len() == 2 {
        let mut host = parts[1];
        if host.starts_with('[') && host.ends_with(']') {
            host = &host[1..host.len()-1];
        }
        if let Ok(port) = parts[0].parse() {
            final_port = port;
            final_host = host.to_string();
            if let Ok(IpAddr::V4(v4)) = host.parse::<IpAddr>() {
                if let Some(mapper) = &fake_ip_mapper {
                    if mapper.is_fake_ip(&v4) {
                        if let Some(domain) = mapper.lookup_domain(&v4) {
                            info!("Fake-IP reverse lookup: {} -> {}", v4, domain);
                            final_host = domain.clone();
                            final_target = format!("{}:{}", domain, port);
                        } else {
                            // 段内 fake-IP 反查 miss → 死地址, 下方嗅到域名则改目的地为域名 (fake-IP 是
                            // 我们合成的、非客户端真实选择, 与"裸真实 IP 不改目的地"规则不同), 嗅不到则 reset。
                            unresolved_fakeip = true;
                        }
                    }
                }
            }
        }
    }

    // 目标仍是**裸 IP** (fake-IP 没还原出域名) 时, 嗅一下 TLS SNI / HTTP Host。
    //
    // 为什么需要: SOCKS5 客户端可以送域名也可以送 IP —— 不少 app 自己做完 DNS 再送 IP。
    // 那种情况下 domain_suffix / geosite 这类规则**全部失效**, 用户看到的是"规则写了不生效"
    // 却查不出原因。嗅到域名后既能正确分流, 也能把域名交给服务端在干净网络解析 (抗污染)。
    //
    // 只在裸 IP 上做: 浏览器等送域名的客户端完全不经过这里, 零成本。
    // 超时取 300ms 而非 transparent 那边的 2s —— 客户端不先说话的协议 (SSH/SMTP 等
    // server-first) 会干等到超时, 这段是白加的延迟, 泛用入站要给得紧。
    // initial_payload 非空表示首包已被读走, peek 看不到, 直接跳过。
    // ⚠️ 嗅到的域名**只用于路由判定, 不改连接目的地**。
    //
    // 客户端明确要连 1.2.3.4:443, 若把目的地换成域名, direct 出站会重新解析 —— 可能落到
    // 另一个 IP (CDN/多 A 记录), 等于擅自改了客户端指定的目的地; 域名解析不出来时更是直接
    // 连不上。sing-box 同样把两者分开 (override_destination 默认关)。
    // TLS 指纹捕获 (armed 时): peek 客户端首包抓 ClientHello。独立于路由 sniff (那个只在裸 IP 时跑),
    // 故 socks5h 送域名也能抓。未 arm 立即返回。
    crate::proxy::tls_capture::maybe_capture(&local).await;

    let mut sniffed_domain: Option<String> = None;
    if !already_sniffed && initial_payload.is_empty() && final_host.parse::<IpAddr>().is_ok() {
        if let Some(sniffed) = crate::proxy::sniff::sniff_with_timeout(
            &local,
            std::time::Duration::from_millis(300),
        )
        .await
        {
            debug!("[SNIFF] 裸 IP {} 嗅到 SNI/Host [{}], 改按域名分流", final_host, sniffed);
            sniffed_domain = Some(sniffed);
        }
    }

    // 未还原的段内 fake-IP: 目的地是死的假 IP。嗅到域名 → 用域名当真实目的地 (fake-IP 必须映射到
    // 真实目标, 与裸真实 IP 不同); 嗅不到 → fail-fast reset, 客户端重解析拿新 fake-IP (勿连死地址)。
    if unresolved_fakeip {
        match &sniffed_domain {
            Some(d) => {
                final_host = d.clone();
                final_target = format!("{}:{}", d, final_port);
            }
            None => {
                warn!("fake-IP {} 反查 miss 且非 HTTP 无法嗅域名 → reset (客户端将重解析)。建议开 advanced_dns.fakeip.persist_path", final_host);
                return;
            }
        }
    }

    info!("Proxying TCP request to {}", final_target);

    // process_name 分流: 仅当有规则用到该维度、且连接来自本机 (loopback) 才查进程名。
    // /proc 扫描是阻塞 IO, 放 spawn_blocking, 不占 tokio worker。非本机/查不到 → None。
    let process_name: Option<String> = if current_state.router.uses_process_name() {
        match local.peer_addr() {
            // is_local_peer: 含双栈 v4-mapped loopback (::ffff:127.0.0.1)。LAN/透明的
            // 远端 peer 不本机 → 不 spawn, 免每连接白跑一次 blocking 任务。
            Ok(peer) if crate::proxy::proc_lookup::is_local_peer(peer.ip()) => {
                tokio::task::spawn_blocking(move || crate::proxy::proc_lookup::process_name_for_peer(peer))
                    .await
                    .ok()
                    .flatten()
            }
            _ => None,
        }
    } else {
        None
    };

    // 源 IP: 透明网关下 = LAN 客户端真实 IP (TPROXY 保留源地址); SOCKS/mixed 下 = 发起方 IP。
    // ⚠️ 语义 = **发起方 IP, 非仅 LAN 设备**: 本机出向 (cgroup/connect4 重定向本机 fake-IP 连接)
    // 走这条时 peer 是 127.0.0.1 → source_ip=127.0.0.1 也参与 source_ip_cidr 匹配。故"非某网段
    // 一律走 X"这类规则会把本机流量也算进去 (本机是发起方之一, 语义自洽; 但与"只想圈 LAN 设备"
    // 的直觉有细微差别, 要精确圈 LAN 就在 cidr 里排除 127.0.0.0/8)。见 brain source-ip-routing。
    // 供 routing 的 `source_ip_cidr` (按设备/网段分流) 匹配。此前恒 None → 设备规则对**透明 TCP
    // 静默不生效** (UDP 已填, 见 transparent_udp), 用户配了按设备分流网页流量却半瘫。
    // v4-mapped v6 (::ffff:a.b.c.d, 双栈 socket 常见) 归一成 v4, 否则 v4 CIDR 规则 contains 不中。
    let source_ip = local.peer_addr().ok().map(|a| normalize_peer_ip(a.ip()));

    // Parse target for router
    let mut routing_req = RoutingRequest {
        domain: None,
        ip: None,
        port: final_port,
        protocol: "tcp",
        source_ip,
        source_mac: None,
        inbound: inbound_tag.as_deref(),
        process_name: process_name.as_deref(),
        user: None,
    };
    
    // 嗅到域名时**同时**带上域名与原始 IP: 域名让 domain_suffix/geosite 生效, IP 让
    // ip_cidr/geoip 仍能匹配 —— 两类规则都不失效。
    if let Ok(ip) = final_host.parse::<IpAddr>() {
        routing_req.ip = Some(ip);
        if let Some(d) = &sniffed_domain {
            routing_req.domain = Some(d);
        }
    } else if !final_host.is_empty() {
        routing_req.domain = Some(&final_host);
    }

    let outbound_tag = current_state.router.route(routing_req);
    
    // Crucial: Use the reversed Fake-IP domain (if any) as the target for proxy and direct connections
    let target = final_target;
    
    info!("Router selected outbound [{}] for target {}", outbound_tag, target);

    // 活跃连接登记 (WebUI 域名连接信息数据源); _conn drop (fn 退出) 时注销并入最近关闭环。
    // 字节数按下面各出站路径累加: Mirage live 累加, splice/WG 关闭时补总量。
    let _conn = crate::monitor::register(
        target.clone(),
        inbound_tag.as_deref().unwrap_or("-").to_string(),
        outbound_tag.to_string(),
        "tcp",
        process_name.clone(),
        source_ip.map(|ip| ip.to_string()), // LAN 设备 IP (WebUI 设备视图)
        None, // 客户端侧无多用户维度
    );

    let outbound = match current_state.outbounds.get(&outbound_tag) {
        Some(o) => o,
        None => {
            error!("Selected outbound {} not found in OutboundManager", outbound_tag);
            return;
        }
    };

    let leaf = outbound.resolve_leaf_active();
    drop(current_state);
    match &*leaf {
        OutboundNode::Mirage { tag: node_tag, pool, .. } => {
            let target_bytes = target.as_bytes();
            if target_bytes.is_empty() || target_bytes.len() > 512 {
                error!(
                    "Mirage: target 长度非法 (须 1..=512 字节): {} 字节",
                    target_bytes.len()
                );
                return;
            }
            // Model X 精简 (transport=quic): 共享连接开一条流, 写 [token(32B)][2B len][host:port]
            // [initial_payload], 之后裸转发 (QUIC 自加密, 无内层 fake-TLS/AEAD)。
            #[cfg(feature = "quic")]
            if pool.is_quic() {
                use tokio::io::AsyncWriteExt;
                let mux = match pool.quic_mux() {
                    Some(m) => m,
                    None => { error!("Mirage QUIC: mux 未初始化 {}", target); return; }
                };
                let (send, recv) = match mux.open_stream().await {
                    Ok(s) => s,
                    Err(e) => {
                        error!("Mirage QUIC open_stream {}: {}", target, e);
                        record_real_failure_and_log(pool, &target, node_tag);
                        return;
                    }
                };
                let token = crate::crypto::hello_auth::make_session_token(
                    pool.password(),
                    crate::crypto::hello_auth::QUIC_LEAN_BIND,
                );
                let mut hdr = Vec::with_capacity(32 + 2 + target_bytes.len());
                hdr.extend_from_slice(&token);
                hdr.extend_from_slice(&(target_bytes.len() as u16).to_be_bytes());
                hdr.extend_from_slice(target_bytes);
                let (mut send, recv) = (send, recv);
                if AsyncWriteExt::write_all(&mut send, &hdr).await.is_err() {
                    mux.check_conn_closed();
                    record_real_failure_and_log(pool, &target, node_tag);
                    return;
                }
                if !initial_payload.is_empty() {
                    if AsyncWriteExt::write_all(&mut send, &initial_payload).await.is_err() {
                        mux.check_conn_closed();
                        record_real_failure_and_log(pool, &target, node_tag);
                        return;
                    }
                    _conn.counter().up(initial_payload.len() as u64);
                }
                // 双向裸转发 (QUIC 加密), 带空闲超时 + 半关闭排空 (DRAIN_IDLE 30s) + 字节计数 (WebUI 统计)。
                // 结束语义: 流 finish (读到 0) = 对端完整结束写, 传 FIN; 流 RESET / 连接断 / 超时 = 异常,
                // 对另一端 RST。QUIC 节点参与真实连接失败降级与变慢补测。
                let local_fd = std::os::fd::AsRawFd::as_raw_fd(&local);
                let local_aborted = std::sync::atomic::AtomicBool::new(false);
                let local_eof = std::sync::atomic::AtomicBool::new(false);
                let (mut lr, lw) = local.into_split();
                let up_c = _conn.counter();
                let dn_c = _conn.counter();
                let clock = Arc::new(crate::proxy::IdleClock::new());
                let up_clock = clock.clone();
                let dn_clock = clock;

                let up_done = crate::proxy::PeerDone::new();
                let dn_done = crate::proxy::PeerDone::new();

                let first_up = std::sync::OnceLock::new();
                let first_down = std::sync::OnceLock::new();
                if !initial_payload.is_empty() {
                    let _ = first_up.set(std::time::Instant::now());
                }

                let upload = async {
                    use tokio::io::AsyncReadExt;
                    let mut send = send;
                    let mut buf = vec![0u8; 65536];
                    let mut local_err = false;
                    loop {
                        match crate::proxy::idle_timeout_drain(&up_clock, relay_idle(), crate::proxy::DRAIN_IDLE, &dn_done, lr.read(&mut buf)).await {
                            Ok(Ok(0)) => {
                                if !local_aborted.load(std::sync::atomic::Ordering::SeqCst) {
                                    local_eof.store(true, std::sync::atomic::Ordering::SeqCst);
                                }
                                break;
                            }
                            Ok(Ok(n)) => {
                                up_clock.touch();
                                if AsyncWriteExt::write_all(&mut send, &buf[..n]).await.is_err() { break; }
                                let _ = first_up.set(std::time::Instant::now());
                                up_c.up(n as u64);
                            }
                            Ok(Err(_)) => {
                                if !local_aborted.load(std::sync::atomic::Ordering::SeqCst) {
                                    local_eof.store(true, std::sync::atomic::Ordering::SeqCst);
                                }
                                local_err = true;
                                break;
                            }
                            Err(_) => {
                                if dn_done.is_set() {
                                    debug!("[QUIC] {} upload drain timeout", target);
                                } else {
                                    debug!("[QUIC] {} upload idle timeout", target);
                                }
                                local_err = true;
                                break;
                            }
                        }
                    }
                    up_clock.touch();
                    up_done.set();
                    if local_err {
                        // 本地应用 RST / 空闲超时 / drain 超时: 上行未正常结束, RESET 流 (服务端据此对目标 RST), 别 finish
                        // 冒充完整结束。
                        let _ = send.reset(quinn::VarInt::from_u32(0));
                    } else {
                        let _ = send.finish(); // 半关上行, 让对端 EOF
                    }
                };
                let download = async {
                    use tokio::io::{AsyncReadExt, AsyncWriteExt as _};
                    let mut recv = recv;
                    let mut lw = lw;
                    let mut buf = vec![0u8; 65536];
                    let mut down_bytes: u64 = 0;
                    let mut truncated = false;
                    let end_reason: DownloadEndReason;
                    loop {
                        match crate::proxy::idle_timeout_drain(&dn_clock, relay_idle(), crate::proxy::DRAIN_IDLE, &up_done, AsyncReadExt::read(&mut recv, &mut buf)).await {
                            Ok(Ok(0)) => {
                                end_reason = DownloadEndReason::CloseNotify;
                                break;
                            }
                            Ok(Ok(n)) => {
                                let now = std::time::Instant::now();
                                if first_down.set(now).is_ok() {
                                    record_first_down(pool, &target, first_up.get().copied(), now, node_tag);
                                }
                                dn_clock.touch();
                                if lw.write_all(&buf[..n]).await.is_err() {
                                    end_reason = DownloadEndReason::LocalWriteErr;
                                    break;
                                }
                                down_bytes += n as u64;
                                dn_c.down(n as u64);
                            }
                            Ok(Err(_)) => {
                                truncated = true;
                                end_reason = DownloadEndReason::PeerError;
                                break;
                            }
                            Err(_) => {
                                truncated = true;
                                end_reason = DownloadEndReason::IdleTimeout;
                                if up_done.is_set() {
                                    debug!("[QUIC] {} download drain timeout", target);
                                } else {
                                    debug!("[QUIC] {} download idle timeout", target);
                                }
                                break;
                            }
                        }
                    }
                    dn_clock.touch();
                    dn_done.set();
                    if truncated {
                        // 同 Model-Y 截断分支: RST 本地并叫醒 upload (读报错 → RESET 上行流, 不 finish),
                        // forget 跳过退回路径下写半程 drop 的 FIN。
                        local_aborted.store(true, std::sync::atomic::Ordering::SeqCst);
                        crate::net_util::abort_socket(local_fd);
                        lw.forget();
                    } else {
                        let _ = lw.shutdown().await;
                    }
                    (down_bytes, end_reason)
                };
                let (_, (down_bytes, end_reason)) = tokio::join!(upload, download);
                mux.check_conn_closed();

                let local_eof_val = local_eof.load(std::sync::atomic::Ordering::SeqCst);
                if classify_real_conn(down_bytes, end_reason, local_eof_val) == RealConnResult::Failure {
                    record_real_failure_and_log(pool, &target, node_tag);
                }
                return;
            }

            let mut target_header = Vec::with_capacity(2 + target_bytes.len());
            target_header.extend_from_slice(&(target_bytes.len() as u16).to_be_bytes());
            target_header.extend_from_slice(target_bytes);

            // 首次写失败重试: get() 的 stale 探测把死隧道挡在派发前, 但探测→派发→使用之间
            // 仍有微秒级竞态 (隧道刚好在这窗口被 RST)。此刻还没开始双向 relay、没给客户端回
            // 任何字节, 重发 target_header + initial_payload 到新隧道是幂等的 —— 首个写
            // (目标头 / 首包) 失败就换一条隧道重试, 闭合 stale 探测留下的竞态窗口。
            const MAX_TUNNEL_ATTEMPTS: usize = 2;
            let mut tunnel = None;
            for attempt in 0..MAX_TUNNEL_ATTEMPTS {
                let mut t = match pool.get().await {
                    Ok(t) => t,
                    Err(e) => {
                        error!("Mirage outbound unavailable for {}: {}", target, e);
                        record_real_failure_and_log(pool, &target, node_tag);
                        return;
                    }
                };
                if let Err(e) = t.writer.send_data(&target_header).await {
                    debug!("[TUNNEL] {} 首写目标头失败 (第 {} 次尝试), 换隧道重试: {:?}", target, attempt + 1, e);
                    continue; // 旧隧道 drop 关闭, 循环取新的
                }
                if !initial_payload.is_empty() {
                    if let Err(e) = t.writer.send_data(&initial_payload).await {
                        debug!("[TUNNEL] {} 首写首包失败 (第 {} 次尝试), 换隧道重试: {:?}", target, attempt + 1, e);
                        continue;
                    }
                }
                tunnel = Some(t);
                break;
            }
            let tunnel = match tunnel {
                Some(t) => t,
                None => {
                    error!("Mirage outbound: {} 尝试 {} 条隧道首写均失败, 放弃", target, MAX_TUNNEL_ATTEMPTS);
                    record_real_failure_and_log(pool, &target, node_tag);
                    return;
                }
            };

            let active_fd = tunnel.get_raw_fd();

            debug!("[TUNNEL] {} 建立 (隧道就绪, 目标头已发)", target);
            let t_start = std::time::Instant::now();

            // 本地 socket fd: 下行被截断时据此对本地应用 RST (见 download 末尾)。两个半程活着期间有效。
            let local_fd = std::os::fd::AsRawFd::as_raw_fd(&local);
            // download 判定截断并 abort 本地 socket 后置位: upload 随后读到的结束 (错误, 或退回路径下的 0)
            // 是 abort 造成的, 不是本地应用写完, 不得向服务端发 close_notify (它表示"客户端完整结束写")。
            let local_aborted = std::sync::atomic::AtomicBool::new(false);
            // upload 读到本地 EOF/错误 (本地应用先结束写) 时置位。之后服务端下行往往不发 close_notify
            // (它的 upload 已退出、SHUT_RDWR 掐断了上游), 这是本地先关的正常收尾, 不算截断, 走 FIN。
            let local_eof = std::sync::atomic::AtomicBool::new(false);
            let (mut local_read, local_write) = local.into_split();
            let tunnel_reader = tunnel.reader;
            let mut tunnel_writer = tunnel.writer;

            // 限速 (device_profiles rate_limit_kbps): 按本连接源 IP (LAN 设备) 取共享桶, 上/下行各整形。
            // 无配置/未命中 → None, 热路径零开销。up_bkt/dn_bkt 各持一份 Arc 供两个泵分别 move。
            let dev_buckets = source_ip.and_then(|ip| state.load().rate_limiter.buckets_for(ip));
            let up_bkt = dev_buckets.clone();

            let clock = Arc::new(crate::proxy::IdleClock::new());
            let up_clock = clock.clone();
            let dn_clock = clock;

            // 方向结束信号: 一方向结束后, 另一方向连续 DRAIN_IDLE 无进展即关 (同 #214 的 WG/SS)
            let up_done = crate::proxy::PeerDone::new();
            let dn_done = crate::proxy::PeerDone::new();

            let first_up = std::sync::OnceLock::new();
            let first_down = std::sync::OnceLock::new();
            if !initial_payload.is_empty() {
                let _ = first_up.set(std::time::Instant::now());
            }

            let up_conn = _conn.counter();
            let upload = async {
                // 64KB 堆 buf (非 16KB 栈): 与服务端 download 对称, 配下方 greedy
                // try_read 一次收割更多本地数据 → 单 send_data → CryptoWriter 的
                // BufWriter(68KB) 合成单 write syscall。高 BDP 上传少碎片。
                let mut buf = vec![0u8; 65536];
                let mut up_bytes: u64 = 0;
                loop {
                    // 空闲超时包在每次 read 内层 (非整个 loop 外层, 见 MIRAGE_RELAY_IDLE 注释)
                    match crate::proxy::idle_timeout_drain(&up_clock, relay_idle(), crate::proxy::DRAIN_IDLE, &dn_done, local_read.read(&mut buf)).await {
                        Ok(Ok(0)) => {
                            if !local_aborted.load(std::sync::atomic::Ordering::SeqCst) {
                                local_eof.store(true, std::sync::atomic::Ordering::SeqCst);
                                let _ = tunnel_writer.send_close_notify().await;
                            }
                            break;
                        }
                        Ok(Ok(n)) => {
                            up_clock.touch();
                            // 贪婪收割: blocking read 拿到第一片后, 非阻塞 try_read 继续填 buf
                            // 剩余空间, kernel 里有多少已到达就装多少, WouldBlock 即止 (不增延迟)。
                            // 对称服务端 tcp_relay download 路径 (local_read 是真 fd 的 OwnedReadHalf)。
                            let mut total = n;
                            while total < buf.len() {
                                match local_read.try_read(&mut buf[total..]) {
                                    Ok(0) => break, // 本地半关闭
                                    Ok(more) => total += more,
                                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                                    Err(_) => break,
                                }
                            }
                            if let Some(b) = &up_bkt {
                                b.up.consume(total).await; // 限速整形: 令牌不足则等 → 停 read → 背压
                            }
                            if tunnel_writer.send_data(&buf[..total]).await.is_err() {
                                break;
                            }
                            let _ = first_up.set(std::time::Instant::now());
                            up_bytes += total as u64;
                            up_conn.up(total as u64);
                        }
                        // 本地读出错 (本地应用 RST 等): 上行不完整, 不发 close_notify (那会让服务端对上游
                        // FIN, 残缺上传被当完整); 改为关隧道写方向 —— 服务端读到裸 EOF 即对上游 RST 并掐断
                        // 下行, 同样不会挂到 relay_idle。嵌套出站 (隧道骑在 MirageStream/SsStream 上, 无物理
                        // fd) 的 poll_shutdown 只 flush 不关底层, 服务端看不到 EOF 会两端挂死 —— 退回发
                        // close_notify (该链路上游看到 FIN, 失去截断区分)。
                        Ok(Err(_)) => {
                            if !local_aborted.load(std::sync::atomic::Ordering::SeqCst) {
                                local_eof.store(true, std::sync::atomic::Ordering::SeqCst);
                                if active_fd.is_some() {
                                    let _ = tunnel_writer.shutdown_transport().await;
                                } else {
                                    let _ = tunnel_writer.send_close_notify().await;
                                }
                            }
                            break;
                        }
                        Err(_) => {
                            if dn_done.is_set() {
                                debug!("[TUNNEL] {} upload drain timeout", target);
                            } else {
                                debug!("[TUNNEL] {} upload idle timeout", target);
                            }
                            break; // 空闲/drain 超时
                        }
                    }
                }
                up_clock.touch();
                up_done.set();

                // 退出前排空残留的本地数据，确保发送给本地的是 FIN 而不是 RST
                let _ = tokio::time::timeout(std::time::Duration::from_millis(500), async {
                    let mut discard = [0u8; 8192];
                    while let Ok(n) = local_read.read(&mut discard).await {
                        if n == 0 { break; }
                    }
                }).await;

                (tunnel_writer, up_bytes)
            };

            let dn_bkt = dev_buckets;
            let dn_conn = _conn.counter();
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
                let mut local_write = local_write; // 移入: 截断分支要 forget() 它
                let mut down_bytes: u64 = 0;
                // 下行是否被截断: 只有收到认证过的 close_notify 才算对端完整结束; 裸 EOF / RST /
                // 解密失败 / 空闲超时都可能是路径注入或服务端异常收尾 (见 aead::PeerCloseNotify)。
                let mut truncated = false;
                let end_reason: DownloadEndReason;

                loop {
                    // 空闲超时包在每次 recv 内层 (非整个 loop 外层)
                    match crate::proxy::idle_timeout_drain(&dn_clock, relay_idle(), crate::proxy::DRAIN_IDLE, &up_done, tunnel_reader.recv_data_borrowed()).await {
                        Ok(Ok(data)) => {
                            let now = std::time::Instant::now();
                            if first_down.set(now).is_ok() {
                                record_first_down(pool, &target, first_up.get().copied(), now, node_tag);
                            }
                            dn_clock.touch();
                            if let Some(b) = &dn_bkt {
                                b.down.consume(data.len()).await; // 限速整形 (下行)
                            }
                            if local_write.write_all(data).await.is_err() {
                                end_reason = DownloadEndReason::LocalWriteErr;
                                break;
                            }
                            down_bytes += data.len() as u64;
                            dn_conn.down(data.len() as u64);
                        }
                        Ok(Err(e)) => {
                            if crate::crypto::aead::is_close_notify(&e) {
                                end_reason = DownloadEndReason::CloseNotify;
                            } else if let Some(reason) = crate::crypto::aead::target_unreachable_reason(&e) {
                                truncated = true;
                                end_reason = DownloadEndReason::TargetUnreachable;
                                debug!("服务端报告目标不可达 {} (reason={})", target, reason);
                            } else {
                                truncated = true;
                                end_reason = DownloadEndReason::PeerError;
                            }
                            break;
                        }
                        Err(_) => {
                            truncated = true; // 空闲/drain超时
                            end_reason = DownloadEndReason::IdleTimeout;
                            if up_done.is_set() {
                                debug!("[TUNNEL] {} download drain timeout", target);
                            } else {
                                debug!("[TUNNEL] {} download idle timeout", target);
                            }
                            break;
                        }
                    }
                }
                dn_clock.touch();
                dn_done.set();

                // 退出前排空远端发来的残留数据, 确保发给服务端的是 FIN 而不是 RST (核心隐蔽特征)
                let _ = tokio::time::timeout(std::time::Duration::from_millis(500), async {
                    while tunnel_reader.recv_data().await.is_ok() {}
                }).await;

                if truncated && !local_eof.load(std::sync::atomic::Ordering::SeqCst) {
                    // 截断: 不能给本地 FIN (以 EOF 定界的明文协议会把残缺数据当完整结果), 改为 RST。
                    // abort_socket 当场发 RST 并叫醒阻塞在 local_read 上的 upload, 避免 join! 挂到 relay_idle。
                    // forget(): 退回路径 (SO_LINGER=0 + SHUT_RD) 下 OwnedWriteHalf 的 drop 会先
                    // shutdown(Write) 发 FIN, 必须跳过, 等读半程 drop 时 fd 关闭才发 RST。
                    local_aborted.store(true, std::sync::atomic::Ordering::SeqCst);
                    crate::net_util::abort_socket(local_fd);
                    local_write.forget();
                } else {
                    // 半关闭传播: 远端已 EOF, 给本地客户端发 FIN (write 端半关), 让守规矩的
                    // 客户端随之关闭 → upload 的 local_read 读到 EOF 自然退出。否则客户端
                    // keep-alive/不发 FIN 时 upload 会干等到 1800s idle, join! 被拖成 30min 僵尸。
                    let _ = local_write.shutdown().await;
                }

                (tunnel_reader, down_bytes, end_reason)
            };

            // ★ guard 必须在 upload/download **之后**声明。这两个 async 块把
            // tunnel_reader/writer **move** 了进去, 所以 fd 的实际关闭时机绑定在它们身上,
            // 而不是上面那两行 let 的作用域。drop 按声明逆序: guard 声明在最后 → 任何退出
            // 路径 (含在下面 join! 处被 cancel, 此时之后的显式 drop 根本不执行) 都是 guard
            // 先析构 (把 fd 移出 active set)、再 drop 两个 future 关 fd。反过来会露出一个
            // "fd 已关但仍在 set 里"的窗口, fd 号被复用后 set 误判活跃。
            //
            // 注: 当前 relay 外无 select!/timeout/abort 包裹, cancel 只发生在进程退出
            // (active_fds 与所有连接一并销毁, 无 fd 复用之虞), 故这是防御性正确而非现存 bug;
            // 但仍以正确顺序声明, 免得日后加了超时/竞速把这个窗口变成真 bug。
            // (早前把 guard 声明在 upload/download 之前, 正常路径靠下面的显式 drop 兜住顺序,
            //  唯独 cancel 路径会先关 fd 再移出 set —— 现已修正。)
            // 物理 TCP 隧道注册 fd 供 brutal 动态调速; 嵌套 (Boxed, 无 fd) 跳过 (无 brutal)。
            let _guard = active_fd.map(|fd| pool.active_fd_guard(fd));

            let ((tw, up_bytes), (tr, down_bytes, end_reason)) = tokio::join!(upload, download);
            drop(_guard);   // 正常路径: 先从 set 移除，防止微秒级死 FD 暴露 (cancel 路径靠声明顺序)
            drop(tw);
            drop(tr);
            debug!(
                "[TUNNEL] {} 关闭 (↑{} ↓{}, 存活 {:.1}s)",
                target,
                human_bytes(up_bytes),
                human_bytes(down_bytes),
                t_start.elapsed().as_secs_f64()
            );

            let local_eof_val = local_eof.load(std::sync::atomic::Ordering::SeqCst);
            // 真实连接成功与 TTFB 判定已在下行首字节时立即记录; 此处仅保留 0 字节错误失败判定。
            if classify_real_conn(down_bytes, end_reason, local_eof_val) == RealConnResult::Failure {
                record_real_failure_and_log(pool, &target, node_tag);
            }
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
                    // splice 只在结束返回总字节, 关闭时补进连接登记 (活跃期间显示 0)。
                    _conn.counter().up(up);
                    _conn.counter().down(down);
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
        OutboundNode::Wireguard { .. } => {
            let t_start = std::time::Instant::now();

            // 隧道懒建立 (首条路由到此出站的连接才真正握手)。
            let tunnel = match leaf.wg_tunnel().await {
                Ok(t) => t,
                Err(e) => {
                    error!("[WG] {} 建立隧道失败: {}", target, e);
                    return;
                }
            };

            // WG 隧道内没有 DNS —— smoltcp 只认 IP。域名先在本机解析, 再把 IP 送进隧道。
            //
            // ⚠️ 这意味着 **DNS 查询不经 WG 出去**, 目标 IP 由本机视角解析得出。对
            // 「只想让某些流量换出口」的用途没问题; 但若指望 WG 出站同时隐藏 DNS 或拿到
            // 对端地区的 CDN 解析结果, 当前实现做不到。隧道内 DNS 属未完成项。
            // target 形如 "host:port"; 从右侧切, 兼容 IPv6 字面量里的冒号。
            let (host, port) = match target.rsplit_once(':').and_then(|(h, p)| {
                p.parse::<u16>().ok().map(|p| (h.trim_matches(['[', ']']), p))
            }) {
                Some(hp) => hp,
                None => {
                    error!("[WG] 目标 `{}` 不是合法的 host:port", target);
                    return;
                }
            };
            let addr = match crate::proxy::wg::resolve_target(&tunnel, host, port).await {
                Ok(a) => a,
                Err(e) => {
                    error!("[WG] {} 解析目标失败: {}", target, e);
                    return;
                }
            };

            let mut remote = match crate::proxy::wg::socket::WgTcpStream::connect(tunnel, addr).await {
                Ok(s) => s,
                Err(e) => {
                    error!("[WG] {} 经隧道连接失败: {}", target, e);
                    return;
                }
            };
            debug!("[WG] {} 已连通 ({}ms)", target, t_start.elapsed().as_millis());

            // 首包 (SOCKS5 早期数据 / HTTP 请求头) 必须先送出去, 否则对端干等。
            if !initial_payload.is_empty() {
                use tokio::io::AsyncWriteExt;
                if let Err(e) = remote.write_all(&initial_payload).await {
                    error!("[WG] {} 首包写入失败: {}", target, e);
                    return;
                }
            }

            // Direct 走 splice(2) 零拷贝, 但 WgTcpStream **不是真 fd** (数据在用户态 smoltcp
            // 里), 无法 splice —— 只能用通用异步拷贝。
            let mut local = local;
            match crate::proxy::copy_bidirectional_with_drain(
                &mut local,
                &mut remote,
                crate::proxy::relay_idle(),
                crate::proxy::DRAIN_IDLE,
            )
            .await
            {
                Ok((up, down)) => {
                    // copy_bidirectional_with_drain 在结束返回总字节, 关闭时补进连接登记。
                    _conn.counter().up(up);
                    _conn.counter().down(down);
                    debug!(
                        "[WG] {} 关闭 (↑{} ↓{}, 存活 {:.1}s)",
                        target, human_bytes(up), human_bytes(down),
                        t_start.elapsed().as_secs_f64()
                    );
                }
                Err(e) => debug!("[WG] {} 出错: {}", target, e),
            }
        }
        OutboundNode::Shadowsocks { tag, .. } => {
            let t_start = std::time::Instant::now();
            let Ok(addr) = crate::proxy::outbound::Address::parse(&target) else {
                error!("[SS:{}] 目标地址非法: {}", tag, target);
                return;
            };
            let mut remote = match leaf.connect(&addr).await {
                Ok(s) => s,
                Err(e) => {
                    error!("[SS:{}] {} 连接失败: {}", tag, target, e);
                    return;
                }
            };
            debug!("[SS:{}] {} 已连通 ({}ms)", tag, target, t_start.elapsed().as_millis());
            if !initial_payload.is_empty() {
                use tokio::io::AsyncWriteExt;
                if let Err(e) = remote.write_all(&initial_payload).await {
                    error!("[SS:{}] {} 首包写入失败: {}", tag, target, e);
                    return;
                }
                _conn.counter().up(initial_payload.len() as u64);
            }
            let mut local = local;
            match crate::proxy::copy_bidirectional_with_drain(
                &mut local,
                &mut remote,
                crate::proxy::relay_idle(),
                crate::proxy::DRAIN_IDLE,
            )
            .await
            {
                Ok((up, down)) => {
                    _conn.counter().up(up);
                    _conn.counter().down(down);
                    debug!(
                        "[SS:{}] {} 关闭 (↑{} ↓{}, 存活 {:.1}s)",
                        tag, target, human_bytes(up), human_bytes(down),
                        t_start.elapsed().as_secs_f64()
                    );
                }
                Err(e) => debug!("[SS:{}] {} 出错: {}", tag, target, e),
            }
        }
        OutboundNode::Block { .. } => {
            debug!("Connection to {} blocked by routing rule", target);
            // Drop connection
        }
        _ => {
            if leaf.is_group() {
                warn!("outbound group `{}` has no available member (all dead), dropping {}", leaf.tag(), target);
            } else {
                tracing::warn!("Unexpected leaf type {:?} for {}, dropping", leaf.tag(), target);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::normalize_peer_ip;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    /// v4-mapped v6 归一成 v4 —— 否则透明 TCP 的双栈客户端匹配不中 v4 source_ip_cidr 设备规则。
    #[test]
    fn v4_mapped_normalized_to_v4() {
        let mapped = IpAddr::V6("::ffff:1.2.3.4".parse::<Ipv6Addr>().unwrap());
        assert_eq!(normalize_peer_ip(mapped), IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)));
    }
    #[test]
    fn plain_v4_unchanged() {
        let v4 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5));
        assert_eq!(normalize_peer_ip(v4), v4);
    }
    #[test]
    fn real_v6_unchanged() {
        let v6 = IpAddr::V6("2001:db8::1".parse::<Ipv6Addr>().unwrap());
        assert_eq!(normalize_peer_ip(v6), v6);
    }

    /// 回归 (审计 D3): 截断时本地应用必须看到 RST 而非 FIN, 且阻塞在本地读上的另一半要被叫醒。
    #[tokio::test]
    async fn abort_socket_wakes_reader_and_resets_peer() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mut app = tokio::net::TcpStream::connect(l.local_addr().unwrap()).await.unwrap();
        let (local, _) = l.accept().await.unwrap();
        let fd = std::os::fd::AsRawFd::as_raw_fd(&local);
        let (mut rd, mut wr) = local.into_split();
        let reader = tokio::spawn(async move {
            let mut b = [0u8; 16];
            let r = rd.read(&mut b).await;
            (rd, r.map(|n| n == 0).unwrap_or(true))
        });
        // app 不读 → 发送缓冲写满, 写阻塞; abort 也必须叫醒它 (旧 SHUT_RD 方案叫不醒)。
        let writer = tokio::spawn(async move {
            let chunk = vec![0u8; 65536];
            loop {
                if wr.write_all(&chunk).await.is_err() {
                    return wr;
                }
            }
        });
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        crate::net_util::abort_socket(fd);
        let (rd, ended) = tokio::time::timeout(std::time::Duration::from_secs(2), reader)
            .await
            .expect("abort 必须叫醒阻塞的读")
            .unwrap();
        assert!(ended);
        let wr = tokio::time::timeout(std::time::Duration::from_secs(2), writer)
            .await
            .expect("abort 必须叫醒卡在满缓冲上的写")
            .unwrap();
        // 两个半程都还活着 (fd 未关): RST 必须已当场发出, 不靠 close。
        let mut b = vec![0u8; 1 << 20];
        let r = loop {
            match app.read(&mut b).await {
                Ok(n) if n > 0 => continue, // 先吐完 RST 前已到达的数据
                other => break other,
            }
        };
        assert!(
            matches!(&r, Err(e) if e.kind() == std::io::ErrorKind::ConnectionReset),
            "本地应用应收到 RST, 实得 {r:?}"
        );
        drop((rd, wr));
    }

    #[test]
    fn test_classify_real_conn() {
        use super::{classify_real_conn, DownloadEndReason, RealConnResult};

        // 成功: down_bytes > 0 (无论结束原因与 local_eof)
        assert_eq!(
            classify_real_conn(1, DownloadEndReason::PeerError, false),
            RealConnResult::Success
        );
        assert_eq!(
            classify_real_conn(1024, DownloadEndReason::CloseNotify, false),
            RealConnResult::Success
        );
        assert_eq!(
            classify_real_conn(50, DownloadEndReason::IdleTimeout, true),
            RealConnResult::Success
        );

        // 失败: down_bytes == 0 且 对端错误结束 且 本地没有先结束
        assert_eq!(
            classify_real_conn(0, DownloadEndReason::PeerError, false),
            RealConnResult::Failure
        );

        // 其它情况均为 Ignore (不记)
        // 0 字节但收到 close_notify
        assert_eq!(
            classify_real_conn(0, DownloadEndReason::CloseNotify, false),
            RealConnResult::Ignore
        );
        // 0 字节但空闲超时
        assert_eq!(
            classify_real_conn(0, DownloadEndReason::IdleTimeout, false),
            RealConnResult::Ignore
        );
        // 0 字节但本地写失败
        assert_eq!(
            classify_real_conn(0, DownloadEndReason::LocalWriteErr, false),
            RealConnResult::Ignore
        );
        // 0 字节且对端错误, 但本地先结束 (local_eof == true)
        assert_eq!(
            classify_real_conn(0, DownloadEndReason::PeerError, true),
            RealConnResult::Ignore
        );
        // 0 字节但服务端报告目标不可达 (Ignore, 不把目标故障当节点故障)
        assert_eq!(
            classify_real_conn(0, DownloadEndReason::TargetUnreachable, false),
            RealConnResult::Ignore
        );
        assert_eq!(
            classify_real_conn(0, DownloadEndReason::TargetUnreachable, true),
            RealConnResult::Ignore
        );
        assert_eq!(
            classify_real_conn(100, DownloadEndReason::TargetUnreachable, false),
            RealConnResult::Success
        );
    }

    #[tokio::test]
    async fn test_record_first_down() {
        let pool = std::sync::Arc::new(crate::proxy::pool::WarmPool::new_with_connect_fn(
            std::sync::Arc::new(crate::proxy::pool::PoolConfig {
                server_host: "127.0.0.1".into(),
                server_port: 8080,
                password: "test_password".into(),
                camouflage_host: "example.com".into(),
                pool_size: 1,
                underlying: None,
                pfs: false,
                transport: crate::config::Transport::Tcp,
                quic_window_mb: 4,
                quic_erasure_cc: true,
                quic_sni: "example.com".into(),
                quic_low_src_port: false,
                quic_pre_packet: false,
                quic_obfs: None,
                quic_pin: None,
            }),
            std::sync::Arc::new(crate::proxy::pool::BrutalState {
                configured_rate: None,
                current_rate: std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0)),
                base_rtt: None,
                active_fds: std::sync::Arc::new(std::sync::Mutex::new(std::collections::HashSet::new())),
            }),
            std::sync::Arc::new(|_, _| Box::pin(async { Err(anyhow::anyhow!("stub")) })),
        ));

        // 先记录一次失败
        pool.stats.write().unwrap().record_real_failure("fail.example.com:443");
        assert_eq!(pool.stats.read().unwrap().real_failures, 1);

        let now = std::time::Instant::now();
        let up = now - std::time::Duration::from_millis(10);
        super::record_first_down(&pool, "example.com:443", Some(up), now, "test-node");

        // 收到首字节后, 真实成功应重置失败计数
        let stats = pool.stats.read().unwrap();
        assert_eq!(stats.real_failures, 0);
    }
}
