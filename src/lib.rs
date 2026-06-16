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

    // 启动全局时间同步
    if let Ok(content) = std::fs::read_to_string(config_path) {
        if let Ok(cfg) = serde_json::from_str::<crate::config::Config>(&content) {
            let mut py_host = None;
            for out in &cfg.outbounds {
                if let crate::config::OutboundConfig::Pyreality { server, .. } = out {
                    py_host = Some(server.clone());
                    break;
                }
            }
            if let Some(host) = py_host {
                tokio::spawn(async move {
                    crate::time_sync::start_time_sync(host).await;
                });
            }
        }
    }
    // 启动 ConfigWatcher 监控配置热更新
    let mut geodata_dir = ".geosite".to_string();

    // 默认的社区下载地址
    let mut geosite_url = "https://github.com/v2fly/domain-list-community/releases/latest/download/dlc.dat".to_string();
    let mut geoip_url = "https://github.com/v2fly/geoip/releases/latest/download/geoip.dat".to_string();
    
    // 尝试读取现有的配置获取自定义参数
    if let Ok(content) = std::fs::read_to_string(config_path) {
        if let Ok(config) = serde_json::from_str::<crate::config::Config>(&content) {
            if let Some(tuning) = config.tuning {
                if let Some(d) = tuning.geodata_dir { geodata_dir = d; }
                if let Some(s) = tuning.geosite_url { geosite_url = s; }
                if let Some(i) = tuning.geoip_url { geoip_url = i; }
            }
        }
    }

    // 启动 Geo 数据库自动下载与热更新任务
    crate::router::geo_updater::spawn_updater(geodata_dir.clone(), geosite_url, geoip_url).await;
    
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
            info!("eBPF Engine loaded successfully.");
            Some(Arc::new(tokio::sync::Mutex::new(engine)))
        }
        Err(e) => {
            tracing::warn!("Failed to load eBPF Engine: {}. Running in userspace-only mode.", e);
            None
        }
    };

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
        let listen = gui_listen.clone();
        let cfg_path = config_path.to_string();
        tokio::spawn(async move {
            crate::gui::start_server(&listen, gui_state, ebp, cfg_path).await;
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
                tokio::spawn(async move {
                    crate::proxy::mirage_server::start_server(&listen_addr, &password, &cam_host).await;
                });
            }
            crate::config::InboundConfig::Mixed { listen, port, .. } => {
                let listen_addr = format!("{}:{}", listen, port);
                tokio::spawn(async move {
                    if let Ok(listener) = tokio::net::TcpListener::bind(&listen_addr).await {
                        info!("Mixed inbound listening on {}", listen_addr);
                        while let Ok((stream, _)) = listener.accept().await {
                            let st = state_clone.clone();
                            let ebp = ebpf_clone.clone();
                            let fm = fake_mapper_clone.clone();
                            tokio::spawn(async move {
                                crate::proxy::mixed::handle_client(stream, st, ebp, fm).await;
                            });
                        }
                    } else {
                        error!("Failed to bind Mixed inbound on {}", listen_addr);
                    }
                });
            }
            crate::config::InboundConfig::Dns { listen, port, .. } => {
                let listen_addr = format!("{}:{}", listen, port);
                let st_for_dns = state_clone.clone();
                let fm_for_dns = fake_mapper_clone.clone();
                tokio::spawn(async move {
                    if let Ok(addr) = listen_addr.parse() {
                        let _ = crate::dns::server::DnsForwarder::start(
                            addr,
                            st_for_dns,
                            fm_for_dns
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
