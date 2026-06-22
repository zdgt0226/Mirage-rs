use crate::config::Config;
use crate::proxy::outbound::OutboundManager;
use crate::router::{RouterEngine, Rule};
use anyhow::Result;
use arc_swap::ArcSwap;
use notify::{Event, RecursiveMode, Watcher};
use std::path::Path;
use std::sync::Arc;
use ipnet::IpNet;
use tracing::{error, info, warn};

pub struct CoreState {
    pub router: Arc<RouterEngine>,
    pub outbounds: Arc<OutboundManager>,
    pub advanced_dns: Option<crate::config::AdvancedDnsConfig>,
}

pub struct ConfigWatcher {
    pub state: Arc<ArcSwap<CoreState>>,
}

impl ConfigWatcher {
    pub fn new(config_path: &str, geodata_dir: &str) -> Result<Self> {
        let state = Self::build_state(config_path, geodata_dir, None)?;
        let arc_state = Arc::new(ArcSwap::from_pointee(state));
        
        let watcher = Self {
            state: arc_state.clone(),
        };

        Self::spawn_watcher(config_path.to_string(), geodata_dir.to_string(), arc_state);

        Ok(watcher)
    }

    fn build_state(config_path: &str, geodata_dir: &str, old_outbounds: Option<Arc<OutboundManager>>) -> Result<CoreState> {
        info!("Loading configuration from {}", config_path);
        let config = Config::load_from_file(config_path)?;
        
        let outbounds = if let Some(old) = old_outbounds {
            info!("Preserving existing outbounds (hot-reload for outbounds is disabled to prevent connection disruption/task leaks).");
            // NOTE: Stateful components like pool/fake_ip_mapper are preserved during reload.
            // If inbounds, outbounds, or fakeip ranges need to be modified, a full restart is required.
            old
        } else {
            Arc::new(OutboundManager::new(&config))
        };
        
        let mut rules = Vec::new();
        for (i, r) in config.routing.rules.into_iter().enumerate() {
            let mut ip_cidr = Vec::new();
            for cidr_str in r.ip_cidr {
                if let Ok(net) = cidr_str.parse() {
                    ip_cidr.push(net);
                }
            }
            
            let mut src_cidrs = Vec::new();
            for src_ip_str in &r.source_ip_cidr {
                if let Ok(net) = src_ip_str.parse::<IpNet>() {
                    src_cidrs.push(net);
                } else if let Ok(ip) = src_ip_str.parse::<std::net::IpAddr>() {
                    src_cidrs.push(IpNet::new(ip, if ip.is_ipv4() { 32 } else { 128 }).unwrap());
                }
            }

            rules.push(Rule {
                id: i,
                mode: r.mode.clone().unwrap_or_else(|| "or".to_string()),
                outbound: r.outbound,
                domain_suffix: r.domain_suffix,
                domain_keyword: r.domain_keyword,
                domain_regex: r.domain_regex,
                geosite: r.geosite,
                ip_cidr,
                geoip: r.geoip,
                source_ip_cidr: src_cidrs,
                source_mac: r.source_mac,
                protocol: r.protocol,
                port: r.port,
            });
        }
        
        let router = RouterEngine::new(
            rules, 
            config.routing.default_outbound, 
            geodata_dir,
            &config.routing.geo_alias,
        )?;
        
        let mut advanced_dns = config.advanced_dns;
        if let Some(adv) = &mut advanced_dns {
            let mut cn_dns = None;
            let mut remote_host = None;
            let mut remote_port = None;
            for r in &adv.resolvers {
                if adv.default.as_ref() == Some(&r.tag) || r.tag == "remote" || r.tag == "proxy" {
                    if r.address.contains(':') {
                        let parts: Vec<&str> = r.address.split(':').collect();
                        remote_host = Some(parts[0].to_string());
                        if let Ok(p) = parts[1].parse() { remote_port = Some(p); }
                    } else {
                        remote_host = Some(r.address.clone());
                    }
                } else if r.tag == "direct" || r.tag == "cn" {
                    if let Ok(addr) = r.address.parse() { cn_dns = Some(addr); }
                }
            }
            adv.cached_cn_dns = cn_dns;
            adv.cached_remote_host = remote_host;
            adv.cached_remote_port = remote_port;
        }

        Ok(CoreState {
            router: Arc::new(router),
            outbounds,
            advanced_dns,
        })
    }

    fn spawn_watcher(config_path: String, geodata_dir: String, state: Arc<ArcSwap<CoreState>>) {
        std::thread::spawn(move || {
            let (tx, rx) = std::sync::mpsc::channel();

            let mut watcher = match notify::recommended_watcher(tx) {
                Ok(w) => w,
                Err(e) => {
                    error!("Failed to initialize config file watcher: {}", e);
                    return;
                }
            };

            // 1. Watch config file
            let config_pathbuf = Path::new(&config_path).to_path_buf();
            if let Err(e) = watcher.watch(&config_pathbuf, RecursiveMode::NonRecursive) {
                error!("Failed to watch config file {}: {}", config_path, e);
                return;
            }
            info!("Started hot-reload watcher on {}", config_path);

            // 2. Watch geodata directory — geo_updater 下载新 .dat 后触发 Router 重建.
            // 修复 bug #2 (启动时序空隙): 之前只 watch config_path, geo_updater 30s
            // 后下载 .dat 落地, 但 ConfigWatcher 不知道, Router 内存里 geo 表始终空,
            // 所有 geosite/geoip 规则 fall back 到 default_outbound. 用户除非手动改
            // config.json 否则永远不会修复.
            //
            // 目录不存在时主动创建 (geo_updater 也会创建, 但 watcher 必须在 .dat 写入
            // 前就 watch 上, 否则 inotify 错过 IN_CREATE 事件).
            let geodir_pathbuf = Path::new(&geodata_dir).to_path_buf();
            if !geodir_pathbuf.exists() {
                if let Err(e) = std::fs::create_dir_all(&geodir_pathbuf) {
                    warn!("Failed to create geodata dir {} (geo hot-reload disabled): {}", geodata_dir, e);
                }
            }
            if geodir_pathbuf.exists() {
                match watcher.watch(&geodir_pathbuf, RecursiveMode::NonRecursive) {
                    Ok(_) => info!("Also watching geodata dir for .dat hot-reload: {}", geodata_dir),
                    Err(e) => warn!(
                        "Failed to watch geodata dir {} (geo downloads after startup will not auto-reload Router; touch config.json to force reload): {}",
                        geodata_dir, e
                    ),
                }
            }

            // 3. Event loop — 过滤事件路径, 只对 config 文件本身或 .dat 文件触发
            // (避免 .tmp 写入 + 其他无关文件抖动). create/modify/rename 都算变更.
            for res in rx {
                match res {
                    Ok(Event { kind, paths, .. }) => {
                        if !(kind.is_modify() || kind.is_create()) {
                            continue;
                        }
                        let trigger = paths.iter().any(|p| {
                            p == &config_pathbuf
                                || p.extension().map_or(false, |e| e == "dat")
                        });
                        if !trigger {
                            continue;
                        }

                        let what = paths.first()
                            .map(|p| p.display().to_string())
                            .unwrap_or_else(|| "<unknown>".to_string());
                        info!("Watched path {} changed. Attempting hot-reload...", what);
                        // Give the writer a moment to finish flushing the file
                        std::thread::sleep(std::time::Duration::from_millis(100));

                        let current_outbounds = state.load().outbounds.clone();
                        match Self::build_state(&config_path, &geodata_dir, Some(current_outbounds)) {
                            Ok(new_state) => {
                                state.store(Arc::new(new_state));
                                info!("Hot-reload successful! New rules and outbounds applied (existing connections uninterrupted).");
                            }
                            Err(e) => {
                                error!("Hot-reload failed! Keeping previous state. Error: {}", e);
                            }
                        }
                    }
                    Err(e) => error!("Watch error: {:?}", e),
                }
            }
        });
    }
}
