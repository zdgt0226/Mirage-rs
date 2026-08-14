//! `start_proxy` 的启动期辅助: 日志初始化 / 运行期配置扫描 / eBPF 引擎与监控任务。
//!
//! 从 `lib.rs::start_proxy` 巨石**逐字抽出**, 零行为变化 —— 仅把内联块换成函数调用。

use std::sync::Arc;
use arc_swap::ArcSwap;
use tracing::{info, warn, error, Level};
use crate::config_watcher::CoreState;

type EbpfEngineHandle = Arc<tokio::sync::Mutex<crate::ebpf::EbpfEngine>>;
type XdpEngineHandle = Arc<crate::ebpf::XdpEngine>;
type TransparentEngineHandle = Arc<tokio::sync::Mutex<crate::ebpf::TransparentEngine>>;

/// 初始化 tracing subscriber (日志级别 / 文件 / 滚动)。
///
/// subscriber 只能 `set_global_default` 一次, 所以必须在任何 `info!`/`error!` 前调用。
/// 早失败 (config 读不到 / 解析错) 用 `eprintln` 输出到 stderr, 不依赖 tracing。
pub(crate) fn init_logging(config_path: &str) {
    use tracing_subscriber::fmt::writer::MakeWriterExt;

    // 早读 config, 取 log_level + log_file 作 subscriber 初始化输入.
    let (log_level_str, log_file_path, log_rotate_mb, log_keep_archives) = {
        let mut level = "info".to_string();
        let mut file: Option<String> = None;
        let mut rotate_mb: Option<u64> = None;
        let mut keep: Option<usize> = None;
        if let Ok(content) = std::fs::read_to_string(config_path) {
            if let Ok(cfg) = serde_json::from_str::<crate::config::Config>(&content) {
                level = cfg.log_level;
                file = cfg.log_file;
                rotate_mb = cfg.log_rotate_mb;
                keep = cfg.log_keep_archives;
            }
        }
        (level, file, rotate_mb, keep)
    };
    let max_level = match log_level_str.to_lowercase().as_str() {
        "trace" => Level::TRACE,
        "debug" => Level::DEBUG,
        "info" => Level::INFO,
        "warn" => Level::WARN,
        "error" => Level::ERROR,
        other => {
            eprintln!(
                "[startup] unknown log_level '{}', falling back to info",
                other
            );
            Level::INFO
        }
    };

    // 打开 log_file (若配置了). 结果放 Option<FileLogger>, 它 Clone 廉价
    // (Arc<Mutex<File>>). subscriber 用 || file_logger.clone() 作 writer.
    // FileLogger 自带按大小滚动 (10MB) + gzip 压缩归档 (保留 10 份)。
    let file_logger_opt: Option<crate::monitor::FileLogger> = match log_file_path.as_deref() {
        Some(path) if !path.is_empty() => {
            match crate::monitor::FileLogger::with_settings(path, log_rotate_mb, log_keep_archives) {
                Ok(fl) => Some(fl),
                Err(e) => {
                    eprintln!(
                        "[startup] cannot open log_file '{}': {}, falling back to stdout only",
                        path, e
                    );
                    None
                }
            }
        }
        _ => None,
    };

    // 组装 subscriber. 两种分支类型不同, 各自 set_global_default. 不用
    // BoxMakeWriter 是因为 closure/GLOBAL_LOGGER.clone() 都需要私有类型.
    // with_ansi(false): 关掉 ANSI 颜色转义码. 同一 formatter 的字节同时写 stdout +
    // GUI MemoryLogger + 文件, 带颜色码的日志在 GUI/文件里渲染成方块 (mojibake).
    // 服务端 daemon 不需要终端颜色, 纯文本全通道干净且 grep 友好.
    if let Some(fl) = file_logger_opt.clone() {
        let subscriber = tracing_subscriber::fmt()
            .with_max_level(max_level)
            .with_ansi(false)
            .with_writer(
                std::io::stdout
                    .and(|| crate::monitor::GLOBAL_LOGGER.clone())
                    .and(move || fl.clone()),
            )
            .finish();
        let _ = tracing::subscriber::set_global_default(subscriber);
    } else {
        let subscriber = tracing_subscriber::fmt()
            .with_max_level(max_level)
            .with_ansi(false)
            .with_writer(std::io::stdout.and(|| crate::monitor::GLOBAL_LOGGER.clone()))
            .finish();
        let _ = tracing::subscriber::set_global_default(subscriber);
    }

    if let Some(ref p) = log_file_path {
        if !p.is_empty() && file_logger_opt.is_some() {
            info!("Logging to file: {}", p);
        }
    }

    info!("Mirage-rs is starting...");
}

/// 运行期配置扫描的产物 (供 start_proxy 后续 updater / watcher / ebpf 使用)。
pub(crate) struct RuntimeScan {
    pub geodata_dir: String,
    pub needs_geo: bool,
    pub ebpf_mode: crate::config::EbpfMode,
    pub geo_sources: Vec<crate::config::GeoSource>,
    pub geo_update_days: u32,
    pub socks_proxy_url: Option<String>,
    pub internal_socks_listener: Option<tokio::net::TcpListener>,
}

/// 一次性扫一遍配置: 校验诊断 + 应用 tuning 全局开关 (cipher agility / tls padding / udp mux /
/// dns-over-tcp) + 取 geo 数据设置 + ebpf_mode + 预绑内部 geo SOCKS 端口。
pub(crate) async fn scan_runtime_config(config_path: &str) -> RuntimeScan {
    let mut geodata_dir = ".geosite".to_string();

    let mut needs_geo = false;
    let mut ebpf_mode = crate::config::EbpfMode::Auto;
    let mut geo_sources: Vec<crate::config::GeoSource> = Vec::new();
    let mut geo_update_days: u32 = 7;
    let mut socks_proxy_url: Option<String> = None;
    // geo via=proxy 用的内部临时 SOCKS: 先绑 (拿 URL), accept 循环等 CoreState 就绪后再起。
    let mut internal_socks_listener: Option<tokio::net::TcpListener> = None;
    if let Ok(content) = std::fs::read_to_string(config_path) {
        // 配置校验: 拼错的键此前被 serde 静默忽略 (用户永远不知道自己配了个寂寞),
        // 引用不存在的 outbound 也不会有任何提示。这里一次性把问题打出来。
        // 刻意**不致命** —— 见 Config::parse_with_diagnostics 的说明。
        match crate::config::Config::parse_with_diagnostics(&content) {
            Ok((_, issues)) if !issues.is_empty() => {
                warn!("配置校验发现 {} 个问题 (不影响启动, 但很可能不是你想要的):", issues.len());
                for issue in &issues {
                    warn!("  · {}", issue);
                }
            }
            Ok(_) => info!("配置校验通过 (无未知字段, 引用完整)"),
            Err(e) => warn!("配置校验跳过 (解析失败: {e})"),
        }

        if let Ok(config) = serde_json::from_str::<crate::config::Config>(&content) {
            if let Some(tuning) = config.tuning {
                // 服务端 cipher agility 开关 (设进全局, control.rs 读)。
                crate::crypto::cipher::set_server_cipher_agility(tuning.cipher_agility);
                // TLS record padding 开关 (设进全局, CryptoWriter::new 读)。收端恒剥零无需开关。
                crate::crypto::cipher::set_tls_padding(tuning.tls_padding);
                if tuning.tls_padding {
                    warn!(
                        "已开启 tls_padding: 要求两端都升到支持剥零的版本。老对端不剥零, 会把填充零\
                         当 content_type 解析失败断连。"
                    );
                }
                // UDP mux 开关 (客户端; 设进全局, transparent_udp 读)。
                crate::proxy::udp_mux::set_udp_mux(tuning.udp_mux, tuning.udp_mux_tunnels);
                if tuning.udp_mux {
                    warn!(
                        "已开启 udp_mux (K={}): 要求服务端也升到支持 mux 的版本。老服务端不认 mux \
                         sentinel, 那些 UDP 流会失败 → 客户端回落 TCP。",
                        tuning.udp_mux_tunnels
                    );
                }
                if tuning.cipher_agility {
                    // 防呆: 开 agility 后 TIME_SYNC 的 proto_ver 变 0x02, 老客户端 (<v0.7.0)
                    // 不认 0x02 → 丢弃 TIME_SYNC 不同步时钟 → 若本机与服务端时钟偏差超容差
                    // (默认 ±60s) 认证直接失败连不上。故必须确保所有客户端 ≥ v0.7.0。
                    warn!(
                        "已开启 cipher_agility: 要求所有客户端升级到 ≥ v0.7.0。\
                         老客户端会丢弃 TIME_SYNC (proto_ver 0x02 不识别) → 时钟不同步 → \
                         若偏差超容差则认证失败连不上。"
                    );
                }
                if let Some(d) = tuning.geodata_dir { geodata_dir = d; }
                if let Some(m) = tuning.ebpf_mode { ebpf_mode = m; }
                geo_sources = tuning.geo_sources;
                if let Some(d) = tuning.geo_update_days {
                    // clamp 下限 1 天. 用户误输 0 会让 updater sleep(0) tight
                    // loop, 每秒往 GitHub 猛拉直接被限流封 IP. 上限不设 (u32
                    // MAX ≈ 4 亿 × 86400 秒, 事实上就是"永不更新").
                    if d == 0 {
                        warn!("tuning.geo_update_days = 0 out of safe range, clamped to 1. Tight-loop pull would flood GitHub and get IP-banned.");
                        geo_update_days = 1;
                    } else {
                        geo_update_days = d;
                    }
                }
                // DNS-over-TCP 解析上游: 设了则所有域名解析走 TCP (UDP 被封的 VPS 做服务端)。
                if let Some(r) = &tuning.dns_tcp_resolver {
                    match crate::config::parse_dns_upstream(r) {
                        Some(addr) => {
                            crate::proxy::resolver::set_tcp_resolver(addr);
                            info!("DNS 解析改走 DNS-over-TCP 上游 {} (系统 getaddrinfo 停用; UDP 被封的 VPS 用)", addr);
                        }
                        None => error!("tuning.dns_tcp_resolver `{}` 非法 (需 ip 或 ip:port), 仍用系统解析器", r),
                    }
                }
            }
            // 仅当 routing.rules 真的引用 geosite / geoip 时才启动 updater
            needs_geo = config.routing.rules.iter().any(|r|
                !r.geosite.is_empty() || !r.geoip.is_empty()
            );

            // geo via=proxy: 起**内部临时 SOCKS** 经隧道下载, 不再自连用户 socks 入站
            // (透明网关无入站时也能用; 免认证免了旧的"自连自认证"auth bug, 见 brain
            // unified-outbound-stream)。先绑端口拿 URL 交给 updater, accept 循环等 CoreState
            // 就绪后再起 (见 watcher 建好之后)。走完整路由 → geo 仍受路由规则控制。
            let has_proxy_source = geo_sources
                .iter()
                .any(|s| matches!(s.via, crate::config::GeoVia::Proxy));
            if needs_geo && has_proxy_source {
                match crate::proxy::internal_socks::bind_loopback().await {
                    Ok((l, url)) => {
                        socks_proxy_url = Some(url);
                        internal_socks_listener = Some(l);
                    }
                    Err(e) => warn!("内部 geo SOCKS 绑定失败: {e}; via=proxy 将回退直连"),
                }
            }
        }
    }

    RuntimeScan {
        geodata_dir,
        needs_geo,
        ebpf_mode,
        geo_sources,
        geo_update_days,
        socks_proxy_url,
        internal_socks_listener,
    }
}

/// eBPF 加载决策: ebpf_mode (auto/force/off) × is_server (来自 CLI 子命令)。
/// 服务端跑 BPF 全部子系统都无价值, auto 模式下服务端自动跳过。Off 任何情况都不加载。
/// Force 调试用, 强制加载。
pub(crate) fn decide_enable_ebpf(ebpf_mode: crate::config::EbpfMode, is_server: bool) -> bool {
    match ebpf_mode {
        crate::config::EbpfMode::Off => {
            info!("eBPF skipped (tuning.ebpf_mode = off).");
            false
        }
        crate::config::EbpfMode::Force => {
            info!("eBPF force-enabled (tuning.ebpf_mode = force).");
            true
        }
        crate::config::EbpfMode::Auto => {
            if is_server {
                info!("eBPF auto-skipped: running in server mode (no client-side workload for sockmap/sockops/XDP/sk_lookup). \
                       Set `tuning.ebpf_mode = \"force\"` to enable for debugging.");
                false
            } else {
                true
            }
        }
    }
}

/// 初始化 eBPF 引擎 (仅当 enable_ebpf 为 true, server-only 模式默认跳过)。
pub(crate) fn init_engines(
    enable_ebpf: bool,
) -> (
    Option<EbpfEngineHandle>,
    Option<XdpEngineHandle>,
    Option<TransparentEngineHandle>,
) {
    if enable_ebpf {
        let ebpf_engine = match crate::ebpf::EbpfEngine::init() {
            Ok(engine) => {
                info!("eBPF acceleration ENABLED");
                Some(Arc::new(tokio::sync::Mutex::new(engine)))
            }
            Err(e) => {
                warn!("eBPF acceleration DISABLED: {}", e);
                None
            }
        };

        let xdp_engine = match crate::ebpf::XdpEngine::init() {
            Ok(engine) => Some(Arc::new(engine)),
            Err(e) => {
                tracing::warn!("XDP DNS acceleration unavailable: {}", e);
                None
            }
        };

        let transparent_engine = match crate::ebpf::TransparentEngine::init() {
            Ok(engine) => Some(Arc::new(tokio::sync::Mutex::new(engine))),
            Err(e) => {
                tracing::warn!("eBPF Transparent proxy unavailable: {}", e);
                None
            }
        };

        (ebpf_engine, xdp_engine, transparent_engine)
    } else {
        (None, None, None)
    }
}

/// eBPF 启用时的两个后台监控任务: ① 每 60s 后台 DNS 解析 (Mirage 出站 server_host → target IP,
/// 喂给 BPF); ② 每 2s RTT 监控 + 动态 Brutal 调速 (采样丢 spawn_blocking, 不占 worker)。
pub(crate) fn spawn_ebpf_monitor_tasks(
    ebpf_engine: &Option<EbpfEngineHandle>,
    state: &Arc<ArcSwap<CoreState>>,
) {
    if let Some(engine_arc) = ebpf_engine {
        // 只在真有 engine 时才 clone state (与抽取前语义一致: clone 在 if let Some 内)。
        let state = state.clone();
        let lock = engine_arc.clone();

        // P1 #3: Decoupled background DNS resolver task (every 60s)
        let dns_state = state.clone();
        let dns_lock = lock.clone();
        tokio::spawn(async move {
            loop {
                let st = dns_state.load();
                let mut futures = Vec::new();

                for node in st.outbounds.outbounds.values() {
                    if let crate::proxy::outbound::OutboundNode::Mirage { server_host, server_port, server_ip, .. } = node.as_ref() {
                        let host = server_host.clone();
                        let port = *server_port;
                        let ip_arc = server_ip.clone();
                        let bpf_lock = dns_lock.clone();

                        futures.push(tokio::spawn(async move {
                            if let Ok(Ok(addrs)) = tokio::time::timeout(
                                std::time::Duration::from_secs(3),
                                tokio::net::lookup_host((host.as_str(), port))
                            ).await {
                                let mut v4 = None;
                                let mut v6 = None;
                                for addr in addrs {
                                    match addr.ip() {
                                        std::net::IpAddr::V4(_) if v4.is_none() => v4 = Some(addr.ip()),
                                        std::net::IpAddr::V6(_) if v6.is_none() => v6 = Some(addr.ip()),
                                        _ => {}
                                    }
                                }
                                if let Some(ip) = v4.or(v6) {
                                    *ip_arc.write().unwrap_or_else(|e| e.into_inner()) = Some(ip);
                                    if let Ok(mut engine) = bpf_lock.try_lock() {
                                        let _ = engine.set_target_ip(ip);
                                    }
                                }
                            }
                        }));
                    }
                }
                for f in futures {
                    let _ = f.await;
                }
                tokio::time::sleep(std::time::Duration::from_secs(60)).await;
            }
        });

        // RTT monitor task (fast polling every 2s)
        let core_state = state.clone();
        let lock_clone = lock.clone();
        tokio::spawn(async move {
            loop {
                let st = core_state.load();
                let engine = lock_clone.clone();
                let outbounds = st.outbounds.clone();
                // 采样是阻塞的 (每个 active fd 一次 getsockopt SO_COOKIE + TCP_INFO 系统调用 +
                // std 锁遍历), 全丢 spawn_blocking, 不占 tokio worker。只把"需要下调/上调的速率"
                // 带回 async 侧 apply (update_brutal_rate 是 async)。调速决策已抽成纯函数
                // decide_brutal_rate (见 proxy::brutal, 有单测), 这里只做 IO + 分发。
                let updates = tokio::task::spawn_blocking(move || {
                    let mut updates: Vec<(std::sync::Arc<crate::proxy::pool::WarmPool>, u64)> = Vec::new();
                    let Ok(lock) = engine.try_lock() else { return updates };
                    for node in outbounds.outbounds.values() {
                        let crate::proxy::outbound::OutboundNode::Mirage {
                            server_ip, rtt_ms, snd_cwnd, total_retrans, total_segs_out, pool, ..
                        } = node.as_ref() else { continue };
                        // server_ip 还没解析出来 = 该出站没建过连接, 无可采样。
                        if server_ip.read().unwrap_or_else(|e| e.into_inner()).is_none() {
                            continue;
                        }
                        let Ok(actives) = pool.brutal_state.active_fds.lock() else { continue };
                        let mut sum_retrans = 0;
                        let mut sum_segs = 0;
                        let mut sum_rtt = 0;
                        let mut max_cwnd = 0;
                        let mut count = 0;
                        for &fd in actives.iter() {
                            if let Ok(cookie) = crate::ebpf::get_socket_cookie(fd) {
                                if let Ok(state) = lock.get_tcp_state_by_cookie(cookie) {
                                    sum_retrans += state.total_retrans as u64;
                                    sum_segs += state.data_segs_out as u64;
                                    sum_rtt += state.srtt_us / 1000;
                                    max_cwnd = max_cwnd.max(state.snd_cwnd as u64);
                                    count += 1;
                                }
                            }
                        }
                        let Some(rtt) = sum_rtt.checked_div(count) else { continue };
                        rtt_ms.store(rtt as u64, std::sync::atomic::Ordering::Relaxed);
                        snd_cwnd.store(max_cwnd, std::sync::atomic::Ordering::Relaxed);
                        let old_retrans = total_retrans.swap(sum_retrans, std::sync::atomic::Ordering::Relaxed);
                        let old_segs = total_segs_out.swap(sum_segs, std::sync::atomic::Ordering::Relaxed);
                        let (delta_retrans, delta_segs) = if old_retrans == u64::MAX || old_segs == u64::MAX {
                            (0i64, 0i64)
                        } else {
                            (sum_retrans as i64 - old_retrans as i64, sum_segs as i64 - old_segs as i64)
                        };
                        // P3.1: 动态 Brutal 调速 (纯函数决策)。
                        if let (Some(base_rate), Some(base_rtt_ms)) =
                            (pool.brutal_state.configured_rate, pool.brutal_state.base_rtt)
                        {
                            let current_rate = pool.brutal_state.current_rate.load(std::sync::atomic::Ordering::Relaxed);
                            if let Some(new_rate) = crate::proxy::brutal::decide_brutal_rate(
                                rtt, base_rtt_ms, max_cwnd, delta_retrans, delta_segs, base_rate, current_rate,
                            ) {
                                updates.push((pool.clone(), new_rate));
                            }
                        }
                    }
                    updates
                })
                .await
                .unwrap_or_default();

                for (p, rate) in updates {
                    p.update_brutal_rate(rate).await;
                }
                tokio::time::sleep(std::time::Duration::from_secs(2)).await;
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::decide_enable_ebpf;
    use crate::config::EbpfMode;

    #[test]
    fn ebpf_decision_matrix() {
        // Off / Force 与 is_server 无关。
        assert!(!decide_enable_ebpf(EbpfMode::Off, false));
        assert!(!decide_enable_ebpf(EbpfMode::Off, true));
        assert!(decide_enable_ebpf(EbpfMode::Force, false));
        assert!(decide_enable_ebpf(EbpfMode::Force, true));
        // Auto: 服务端跳过, 客户端启用。
        assert!(!decide_enable_ebpf(EbpfMode::Auto, true), "Auto+server 应跳过");
        assert!(decide_enable_ebpf(EbpfMode::Auto, false), "Auto+client 应启用");
    }
}
