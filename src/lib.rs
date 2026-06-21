pub mod crypto;
pub mod proxy;
pub mod router;
pub mod dns;
pub mod config;
pub mod time_sync;
pub mod config_watcher;
pub mod ebpf;
pub mod monitor;
pub mod gui;

use anyhow::Result;
use std::sync::Arc;
use tracing::{info, warn, error, Level};

pub async fn start_proxy(config_path: &str) -> Result<()> {
    use tracing_subscriber::fmt::writer::MakeWriterExt;
    let subscriber = tracing_subscriber::fmt()
        .with_max_level(Level::DEBUG)
        .with_writer(
            std::io::stdout.and(|| crate::monitor::GLOBAL_LOGGER.clone())
        )
        .finish();
    let _ = tracing::subscriber::set_global_default(subscriber);

    info!("Mirage-rs is starting...");

    // v0.4 协议: 时间同步从 NTP/HTTP 改为 server 在 handshake 后通过加密 channel
    // 主动下发 (见 src/proxy/mirage_server.rs 和 src/proxy/pool.rs). 这里不再
    // 启动后台 NTP 探测协程.

    // 启动 ConfigWatcher 监控配置热更新
    let mut geodata_dir = ".geosite".to_string();

    // 默认的社区下载地址
    let mut geosite_url = "https://github.com/v2fly/domain-list-community/releases/latest/download/dlc.dat".to_string();
    let mut geoip_url = "https://github.com/v2fly/geoip/releases/latest/download/geoip.dat".to_string();

    // 一次性扫一遍配置：取 tuning + 判断是否真的需要 geo 数据
    // (服务端典型场景: outbounds=[], routing.rules=[] → geo 数据从不会被读 →
    //  不下载，避免 25MB/天浪费 + 不向 GitHub 暴露指向 v2fly 仓库的可识别流量指纹)
    let mut needs_geo = false;
    if let Ok(content) = std::fs::read_to_string(config_path) {
        if let Ok(config) = serde_json::from_str::<crate::config::Config>(&content) {
            if let Some(tuning) = config.tuning {
                if let Some(d) = tuning.geodata_dir { geodata_dir = d; }
                if let Some(s) = tuning.geosite_url { geosite_url = s; }
                if let Some(i) = tuning.geoip_url { geoip_url = i; }
            }
            // 仅当 routing.rules 真的引用 geosite / geoip 时才启动 updater
            needs_geo = config.routing.rules.iter().any(|r|
                !r.geosite.is_empty() || !r.geoip.is_empty()
            );
        }
    }

    if needs_geo {
        // 启动 Geo 数据库自动下载与热更新任务
        crate::router::geo_updater::spawn_updater(geodata_dir.clone(), geosite_url, geoip_url).await;
    } else {
        info!("No geosite/geoip rules configured — skipping Geo data updater (saves bandwidth + avoids GitHub flow fingerprint).");
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
    let watcher = match crate::config_watcher::ConfigWatcher::new(config_path, &geodata_dir) {
        Ok(w) => w,
        Err(e) => {
            tracing::error!("Failed to initialize config watcher: {}", e);
            return Err(e);
        }
    };

    // 初始化 eBPF 引擎
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
                                    *ip_arc.write().unwrap() = Some(ip);
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
                            if let Some(_ip) = *server_ip.read().unwrap() {
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
            crate::gui::start_server(&listen, gui_state, ebp, xdp, cfg_path).await;
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
            crate::config::InboundConfig::MirageServer { listen, port, password, camouflage_host, .. } => {
                let listen_addr = format!("{}:{}", listen, port);
                let cam_host = camouflage_host.unwrap_or_else(|| "www.apple.com".to_string());
                let ebp = ebpf_clone.clone();
                tokio::spawn(async move {
                    crate::proxy::mirage_server::start_server(&listen_addr, &password, &cam_host, ebp).await;
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
    std::process::exit(0);
}
