pub mod crypto;
pub mod proxy;
pub mod router;
pub mod dns;
pub mod config;
pub mod time_sync;
pub mod config_watcher;
pub mod ebpf;
pub mod monitor;
pub mod api;

use anyhow::Result;
use std::sync::Arc;
use tracing::{info, warn, error, Level};

pub async fn start_proxy(config_path: &str, is_server: bool) -> Result<()> {
    use tracing_subscriber::fmt::writer::MakeWriterExt;

    // 早读 config, 取 log_level + log_file 作 subscriber 初始化输入.
    // subscriber 只能 set_global_default 一次, 所以必须在 info!/error! 前.
    // 早失败 (config 读不到 / 解析错) 用 eprintln 输出到 stderr, 不依赖 tracing.
    let (log_level_str, log_file_path) = {
        let mut level = "info".to_string();
        let mut file: Option<String> = None;
        if let Ok(content) = std::fs::read_to_string(config_path) {
            if let Ok(cfg) = serde_json::from_str::<crate::config::Config>(&content) {
                level = cfg.log_level;
                file = cfg.log_file;
            }
        }
        (level, file)
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
    let file_logger_opt: Option<crate::monitor::FileLogger> = match log_file_path.as_deref() {
        Some(path) if !path.is_empty() => {
            match std::fs::OpenOptions::new().create(true).append(true).open(path) {
                Ok(file) => Some(crate::monitor::FileLogger::new(file)),
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
    if let Some(fl) = file_logger_opt.clone() {
        let subscriber = tracing_subscriber::fmt()
            .with_max_level(max_level)
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

    // v0.4 协议: 时间同步从 NTP/HTTP 改为 server 在 handshake 后通过加密 channel
    // 主动下发 (见 src/proxy/mirage_server.rs 和 src/proxy/pool.rs). 这里不再
    // 启动后台 NTP 探测协程.

    // 启动 ConfigWatcher 监控配置热更新
    let mut geodata_dir = ".geosite".to_string();

    // 一次性扫一遍配置: 取 tuning + 判断是否真的需要 geo 数据 + 取 ebpf_mode +
    // 探测本地 socks/mixed inbound 端口 (供 geo_sources via=proxy 使用)
    let mut needs_geo = false;
    let mut ebpf_mode = crate::config::EbpfMode::Auto;
    let mut geo_sources: Vec<crate::config::GeoSource> = Vec::new();
    let mut geo_update_days: u32 = 7;
    let mut socks_proxy_url: Option<String> = None;
    if let Ok(content) = std::fs::read_to_string(config_path) {
        if let Ok(config) = serde_json::from_str::<crate::config::Config>(&content) {
            if let Some(tuning) = config.tuning {
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
            }
            // 仅当 routing.rules 真的引用 geosite / geoip 时才启动 updater
            needs_geo = config.routing.rules.iter().any(|r|
                !r.geosite.is_empty() || !r.geoip.is_empty()
            );

            // 探测本地 socks/mixed inbound 给 geo via=proxy 用. 0.0.0.0 自动改 127.0.0.1
            // (本地自连不能用通配地址).
            for ib in &config.inbounds {
                let (listen, port) = match ib {
                    crate::config::InboundConfig::Socks { listen, port, .. } => (listen, port),
                    crate::config::InboundConfig::Mixed { listen, port, .. } => (listen, port),
                    _ => continue,
                };
                // 0.0.0.0 / :: 通配符改回环 loopback (URL 里指自身). IPv6 主机 (含 ::1 /
                // fd00:: 等) 按 RFC 3986 必须用 [] 包裹, 否则 reqwest::Proxy::all() InvalidUrl.
                let host_raw = if listen == "0.0.0.0" {
                    "127.0.0.1"
                } else if listen == "::" {
                    "::1"
                } else {
                    listen.as_str()
                };
                let host = if host_raw.contains(':') && !host_raw.starts_with('[') {
                    format!("[{}]", host_raw)
                } else {
                    host_raw.to_string()
                };
                socks_proxy_url = Some(format!("socks5://{}:{}", host, port));
                break;
            }
        }
    }

    // eBPF 加载决策: ebpf_mode (auto/force/off) × is_server (来自 CLI 子命令).
    // 服务端跑 BPF 全部子系统都无价值 (详见 TuningConfig::ebpf_mode 注释), auto
    // 模式下服务端自动跳过. Off 任何情况都不加载. Force 调试用, 强制加载.
    let enable_ebpf = match ebpf_mode {
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
    };

    // 无条件建 UpdaterHandle + spawn updater. 冷启动无 sources 时 updater 阻
    // 塞在 wake 上不消耗资源, 热更新加了 sources 后 ConfigWatcher 会 notify
    // 醒它立刻拉一轮. 修 Issue 4 方案 C.
    let updater_handle = crate::router::geo_updater::UpdaterHandle::new(
        crate::router::geo_updater::UpdaterState {
            geodata_dir: geodata_dir.clone(),
            sources: geo_sources,
            update_days: geo_update_days,
            proxy_url: socks_proxy_url,
        },
    );
    crate::router::geo_updater::spawn_updater(updater_handle.clone()).await;
    if needs_geo && updater_handle.state.load().sources.is_empty() {
        warn!("Routing rules reference geosite/geoip but `tuning.geo_sources` is empty. \
               Updater is waiting for hot-reload to add sources.");
    } else if !needs_geo {
        info!("No geosite/geoip rules configured — geo updater running but idle (no sources).");
    }
    
    // 如果 config.json 不存在，我们先写一个基础模板，避免启动直接崩溃
    if !std::path::Path::new(config_path).exists() {
        info!("config.json not found, creating a default template...");
        let default_cfg = r#"{
    "log_level": "info",
    "inbounds": [
        {
            "type": "socks",
            "tag": "socks-in",
            "listen": "127.0.0.1",
            "port": 1080
        }
    ],
    "outbounds": [
        {
            "type": "direct",
            "tag": "direct"
        },
        {
            "type": "block",
            "tag": "block"
        }
    ],
    "routing": {
        "default_outbound": "direct",
        "rules": []
    }
}"#;
        if let Err(e) = std::fs::write(config_path, default_cfg) {
            tracing::error!("Failed to write default config to {}: {}", config_path, e);
            return Err(e.into());
        }
    }
    
    // ConfigWatcher::new() 会立刻解析配置并加载 Router 和 Outbounds，同时启动后台文件监控线程
    let watcher = match crate::config_watcher::ConfigWatcher::new(config_path, &geodata_dir, updater_handle.clone()) {
        Ok(w) => w,
        Err(e) => {
            tracing::error!("Failed to initialize config watcher: {}", e);
            return Err(e);
        }
    };

    // 初始化 eBPF 引擎 (仅当 enable_ebpf 为 true, server-only 模式默认跳过)
    let (ebpf_engine, xdp_engine, transparent_engine) = if enable_ebpf {
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
    };
    
    // Start DNS resolution and RTT monitor loop if eBPF is enabled
    if let Some(engine_arc) = &ebpf_engine {
        let state = watcher.state.clone();
        let lock = engine_arc.clone();
        
        // P1 #3: Decoupled background DNS resolver task (every 60s)
        let dns_state = state.clone();
        let dns_lock = lock.clone();
        tokio::spawn(async move {
            loop {
                let st = dns_state.load();
                let mut futures = Vec::new();
                
                for (_, node) in &st.outbounds.outbounds {
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
                if let Ok(lock) = lock_clone.try_lock() {
                    for (_, node) in &st.outbounds.outbounds {
                        if let crate::proxy::outbound::OutboundNode::Mirage { server_ip, rtt_ms, snd_cwnd, total_retrans, total_segs_out, pool, .. } = node.as_ref() {
                            if let Some(_ip) = *server_ip.read().unwrap_or_else(|e| e.into_inner()) {
                                if let Ok(actives) = pool.brutal_state.active_fds.lock() {
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
                                    
                                    if count > 0 {
                                        let rtt = sum_rtt / count;
                                        rtt_ms.store(rtt as u64, std::sync::atomic::Ordering::Relaxed);
                                        snd_cwnd.store(max_cwnd as u64, std::sync::atomic::Ordering::Relaxed);
                                        let old_retrans = total_retrans.swap(sum_retrans, std::sync::atomic::Ordering::Relaxed);
                                        let old_segs = total_segs_out.swap(sum_segs, std::sync::atomic::Ordering::Relaxed);
                                        
                                        let (delta_retrans, delta_segs) = if old_retrans == u64::MAX || old_segs == u64::MAX {
                                            (0, 0)
                                        } else {
                                            (sum_retrans as i64 - old_retrans as i64, sum_segs as i64 - old_segs as i64)
                                        };

                                    // P3.1: Dynamic Brutal CC adjustment based on true loss rate and BDP
                                    if let (Some(base_rate), Some(base_rtt_ms)) = (pool.brutal_state.configured_rate, pool.brutal_state.base_rtt) {
                                        if rtt > 0 {
                                            let cwnd = max_cwnd; // Packets
                                            let current_rate = pool.brutal_state.current_rate.load(std::sync::atomic::Ordering::Relaxed);
                                            let mut dynamic_rate;

                                            // Calculate loss rate (handle division by zero)
                                            let loss_rate = if delta_segs > 0 { delta_retrans as f64 / delta_segs as f64 } else { 0.0 };

                                            // Congested if RTT > 1.5x base, OR true packet loss rate exceeds 1%
                                            if rtt > (base_rtt_ms as f64 * 1.5) as u32 || loss_rate > 0.01 {
                                                // Congested! Back off to measured BDP bandwidth
                                                // 1 MSS = 1440 bytes
                                                let estimated_bdp_bytes_per_sec = (cwnd as f64 * 1440.0) / (rtt as f64 / 1000.0);
                                                dynamic_rate = (estimated_bdp_bytes_per_sec as u64).max(base_rate / 10);
                                            } else {
                                                // Recover! Increase towards configured rate
                                                dynamic_rate = (current_rate as f64 * 1.1) as u64;
                                            }
                                            
                                            dynamic_rate = dynamic_rate.min(base_rate);
                                            
                                            // Only update if changes are significant (> 5%)
                                            if (dynamic_rate as i64 - current_rate as i64).abs() > (current_rate / 20) as i64 {
                                                let p = pool.clone();
                                                tokio::spawn(async move {
                                                    p.update_brutal_rate(dynamic_rate).await;
                                                });
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                }
                tokio::time::sleep(std::time::Duration::from_secs(2)).await;
            }
        });
    }

    let mut inbounds = Vec::new();
    let mut fake_ip_mapper: Option<Arc<crate::dns::fake_ip::FakeIpMapper>> = None;
    let mut gui_enabled = false;
    let mut gui_listen = "127.0.0.1:9090".to_string();

    if let Ok(content) = std::fs::read_to_string(config_path) {
        if let Ok(config) = serde_json::from_str::<crate::config::Config>(&content) {
            inbounds = config.inbounds;
            if let Some(gui) = config.gui {
                gui_enabled = gui.enabled;
                gui_listen = gui.listen;
            }
            if let Some(adv) = config.advanced_dns {
                if let Some(iface) = &adv.xdp_interface {
                    if let Some(engine) = &xdp_engine {
                        if let Err(e) = engine.attach(iface) {
                            error!("Failed to attach XDP to interface {}: {}", iface, e);
                        } else {
                            engine.attached.store(1, std::sync::atomic::Ordering::Relaxed);
                        }
                    }
                }
                if let Some(fakeip) = adv.fakeip {
                    if fakeip.enabled {
                        if let Ok(mapper) = crate::dns::fake_ip::FakeIpMapper::new(&fakeip.inet4_range) {
                            info!("Fake-IP Mapper initialized with range {}", fakeip.inet4_range);
                            fake_ip_mapper = Some(Arc::new(mapper));
                        } else {
                            error!("Failed to initialize Fake-IP Mapper with range {}", fakeip.inet4_range);
                        }
                    }
                }
            }
        }
    }


    if gui_enabled {
        let gui_state = watcher.state.clone();
        let ebp = ebpf_engine.clone();
        let xdp = xdp_engine.clone();
        let listen = gui_listen.clone();
        let cfg_path = config_path.to_string();
        tokio::spawn(async move {
            crate::api::start_server(&listen, gui_state, ebp, xdp, cfg_path).await;
        });
    }

    if inbounds.is_empty() {
        warn!("No inbounds configured!");
    }

    for inbound in inbounds {
        let state_clone = watcher.state.clone();
        let ebpf_clone = ebpf_engine.clone();
        let fake_mapper_clone = fake_ip_mapper.clone();

        match inbound {
            crate::config::InboundConfig::Socks { listen, port, .. } => {
                let listen_addr = format!("{}:{}", listen, port);
                tokio::spawn(async move {
                    if let Ok(listener) = tokio::net::TcpListener::bind(&listen_addr).await {
                        info!("SOCKS5 listening on {}", listen_addr);
                        while let Ok((stream, _)) = listener.accept().await {
                            let st = state_clone.clone();
                            let ebp = ebpf_clone.clone();
                            let fm = fake_mapper_clone.clone();
                            tokio::spawn(async move {
                                crate::proxy::handler::handle_client(stream, st, ebp, fm).await;
                            });
                        }
                    } else {
                        error!("Failed to bind SOCKS5 on {}", listen_addr);
                    }
                });
            }
            crate::config::InboundConfig::MirageServer { listen, port, password, camouflage_host, brutal_rate_mbps, .. } => {
                let listen_addr = format!("{}:{}", listen, port);
                let cam_host = camouflage_host.unwrap_or_else(|| "www.apple.com".to_string());
                let ebp = ebpf_clone.clone();
                // 0 视为未启用 (兼容旧 install.sh 模板里写 0 表示 "no brutal")
                let brutal_bps = brutal_rate_mbps
                    .filter(|m| *m > 0)
                    .map(|m| m * 125_000);
                tokio::spawn(async move {
                    crate::proxy::mirage_server::start_server(&listen_addr, &password, &cam_host, ebp, brutal_bps).await;
                });
            }
            crate::config::InboundConfig::Mixed { listen, port, .. } => {
                let listen_addr = format!("{}:{}", listen, port);
                tokio::spawn(async move {
                    if let Ok(listener) = tokio::net::TcpListener::bind(&listen_addr).await {
                        tracing::info!("Mixed inbound listening on {}", listen_addr);
                        while let Ok((stream, _)) = listener.accept().await {
                            let st = state_clone.clone();
                            let ebp = ebpf_clone.clone();
                            let fm = fake_mapper_clone.clone();
                            tokio::spawn(async move {
                                crate::proxy::mixed::handle_client(stream, st, ebp, fm).await;
                            });
                        }
                    } else {
                        tracing::error!("Failed to bind Mixed inbound on {}", listen_addr);
                    }
                });
            }
            crate::config::InboundConfig::Transparent { listen, port, .. } => {
                let listen_addr = format!("{}:{}", listen, port);
                let trans_eng = transparent_engine.clone();
                tokio::spawn(async move {
                    if let (Some(te), Some(fm)) = (trans_eng, fake_mapper_clone) {
                        let net = fm.network();
                        let prefix = fm.prefix_len();
                        if let Err(e) = crate::proxy::transparent::start_transparent(
                            &listen_addr, state_clone, ebpf_clone, fm, te, net, prefix
                        ).await {
                            tracing::error!("Transparent proxy listener failed: {}", e);
                        }
                    } else {
                        tracing::error!("Transparent inbound requires fake_ip and eBPF transparent engine to be enabled");
                    }
                });
            }
            crate::config::InboundConfig::Dns { listen, port, .. } => {
                let listen_addr = format!("{}:{}", listen, port);
                let st_for_dns = state_clone.clone();
                let fm_for_dns = fake_mapper_clone.clone();
                let xdp_for_dns = xdp_engine.clone();
                tokio::spawn(async move {
                    if let Ok(addr) = listen_addr.parse() {
                        let _ = crate::dns::server::DnsForwarder::start(
                            addr,
                            st_for_dns,
                            fm_for_dns,
                            xdp_for_dns,
                        ).await;
                    }
                });
            }
        }
    }

    // Keep main thread alive
    match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
        Ok(mut sigterm) => {
            tokio::select! {
                _ = tokio::signal::ctrl_c() => {}
                _ = sigterm.recv() => {}
            }
        }
        Err(_) => {
            let _ = tokio::signal::ctrl_c().await;
        }
    }
    info!("Shutting down Mirage-rs...");
    // 清理透明代理 fake-IP 本地路由 (若装过). best-effort, 失败无害.
    crate::proxy::transparent_net::cleanup().await;
    std::process::exit(0);
}
