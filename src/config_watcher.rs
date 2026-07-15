use crate::config::Config;
use crate::proxy::outbound::OutboundManager;
use crate::router::{RouterEngine, Rule};
use crate::router::geo_updater::{UpdaterHandle, UpdaterState};
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

impl CoreState {
    /// 供 eBPF tc_divert 的 direct_cidr map 用: 直连快路径 v4 CIDR (geoip ∪ 用户
    /// 手动 ip_cidr, 已排除与非直连规则重叠的段)。is_direct 仅认 Direct 类出站 ——
    /// Block/代理都不算 (否则会绕过丢弃/代理)。
    pub fn direct_v4_cidrs(&self) -> Vec<ipnet::Ipv4Net> {
        use crate::proxy::outbound::OutboundNode;
        let outbounds = &self.outbounds.outbounds;
        self.router.direct_v4_cidrs(|tag| {
            matches!(outbounds.get(tag).map(|n| &**n), Some(OutboundNode::Direct { .. }))
        })
    }
}

/// reload 成功后触发的回调 (如刷新 eBPF direct_cidr map)。lib.rs 在 eBPF 引擎
/// 建好后用 set_reload_hook 注入; watcher 线程每次热重载后调用。
type ReloadHook = Box<dyn Fn(&CoreState) + Send + Sync>;

pub struct ConfigWatcher {
    pub state: Arc<ArcSwap<CoreState>>,
    reload_hook: Arc<std::sync::Mutex<Option<ReloadHook>>>,
}

impl ConfigWatcher {
    pub fn new(config_path: &str, geodata_dir: &str, updater_handle: UpdaterHandle) -> Result<Self> {
        let state = Self::build_state(config_path, geodata_dir, None)?;
        let arc_state = Arc::new(ArcSwap::from_pointee(state));
        let reload_hook: Arc<std::sync::Mutex<Option<ReloadHook>>> = Arc::new(std::sync::Mutex::new(None));

        let watcher = Self {
            state: arc_state.clone(),
            reload_hook: reload_hook.clone(),
        };

        Self::spawn_watcher(config_path.to_string(), geodata_dir.to_string(), arc_state, updater_handle, reload_hook);

        Ok(watcher)
    }

    /// 注入 reload 回调 (幂等覆盖)。lib.rs 在 tc_divert 引擎建好后调用, 使热重载
    /// 后 direct_cidr map 随新规则刷新。
    pub fn set_reload_hook(&self, hook: impl Fn(&CoreState) + Send + Sync + 'static) {
        *self.reload_hook.lock().unwrap_or_else(|e| e.into_inner()) = Some(Box::new(hook));
    }

    /// 从 config 文件里抽出 UpdaterState.
    ///
    /// 语义:
    /// - 文件读不到 / JSON 解析错 → None (调用方保留老 state, 不动)
    /// - `tuning` 被删 → 视为空 tuning, 返 `Some(UpdaterState{sources空})` 让
    ///   updater 进 idle. 修 alpha.17 外部审计发现的 "删 tuning updater 仍
    ///   偷偷跑" 纰漏.
    /// - `update_days` 为 0 或缺失 → clamp 到 min 1 (24 小时). 避免 tight
    ///   loop 打满 CPU + 被 GitHub 限流封 IP.
    /// - `proxy_url` + `geodata_dir` 保留 old 值 (跟 inbounds 语义一致, 属
    ///   于 startup-only 字段, 用户改必须 restart).
    fn extract_updater_state(config_path: &str, old: &UpdaterState) -> Option<UpdaterState> {
        const MIN_UPDATE_DAYS: u32 = 1;

        let content = std::fs::read_to_string(config_path).ok()?;
        let config: Config = serde_json::from_str(&content).ok()?;

        let (sources, update_days_raw) = match config.tuning {
            Some(tuning) => (tuning.geo_sources, tuning.geo_update_days.unwrap_or(7)),
            None => (Vec::new(), 7),
        };
        // Clamp: 用户误输 0 或负 clamp 到 1 天, 避免 tight loop.
        // (u32 无负值, 但 0 也是致命 — Duration::from_secs(0) 让 select! 立刻 fire.)
        let update_days = update_days_raw.max(MIN_UPDATE_DAYS);
        if update_days != update_days_raw {
            warn!(
                "tuning.geo_update_days = {} out of safe range, clamped to {}. \
                 Tight-loop pull would flood GitHub and get IP-banned.",
                update_days_raw, update_days
            );
        }

        Some(UpdaterState {
            geodata_dir: old.geodata_dir.clone(),
            sources,
            update_days,
            proxy_url: old.proxy_url.clone(),
        })
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
            let mut cn_dns: Vec<std::net::SocketAddr> = Vec::new();
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
                    // 收集全部 cn/direct 上游 (支持配多个做多上游兜底), 去重。
                    if let Ok(addr) = r.address.parse() {
                        if !cn_dns.contains(&addr) { cn_dns.push(addr); }
                    }
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

    fn spawn_watcher(config_path: String, geodata_dir: String, state: Arc<ArcSwap<CoreState>>, updater_handle: UpdaterHandle, reload_hook: Arc<std::sync::Mutex<Option<ReloadHook>>>) {
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
                        // find 触发路径, 而不是 paths.first(). rename 事件 paths
                        // 里可能 .tmp 在前 .dat 在后, 老 first() 会 log 出误导
                        // 的 .tmp 路径. find 匹配 trigger predicate 保证 log 显
                        // 示的就是真正被认可导致 reload 的那条路径.
                        let trigger_path = paths.iter().find(|p| {
                            *p == &config_pathbuf
                                || p.extension().map_or(false, |e| e == "dat")
                        });
                        let trigger_path = match trigger_path {
                            Some(p) => p,
                            None => continue, // 无路径命中 trigger, skip
                        };

                        info!("Watched path {} changed. Attempting hot-reload...", trigger_path.display());
                        // Give the writer a moment to finish flushing the file
                        std::thread::sleep(std::time::Duration::from_millis(100));

                        let current_outbounds = state.load().outbounds.clone();
                        match Self::build_state(&config_path, &geodata_dir, Some(current_outbounds)) {
                            Ok(new_state) => {
                                state.store(Arc::new(new_state));
                                info!("Hot-reload successful! New rules and outbounds applied (existing connections uninterrupted).");
                                // 刷新 eBPF direct_cidr map (若已注入 hook)
                                if let Some(hook) = reload_hook.lock().unwrap_or_else(|e| e.into_inner()).as_ref() {
                                    hook(&state.load());
                                }
                            }
                            Err(e) => {
                                error!("Hot-reload failed! Keeping previous state. Error: {}", e);
                            }
                        }

                        // 修 Issue 4 方案 C: 也重建 UpdaterState 让 geo_updater
                        // 拿到新 sources / update_days. proxy_url 保留旧值
                        // (inbounds 不热更新, 同步无意义).
                        //
                        // 无脏比较全字段总是 update: GeoSource 字段太多 (name/url/
                        // kind/via), 手写差分容易漏字段 (例如只改 via 从 direct
                        // 到 proxy). update() 幂等 = 一次 Arc swap + notify_one,
                        // 成本很低. 只有 config 文件本身改动才触发 (`.dat` 变化
                        // 不影响 updater 配置).
                        if trigger_path == &config_pathbuf {
                            let old_updater = (**updater_handle.state.load()).clone();
                            if let Some(new_updater) = Self::extract_updater_state(&config_path, &old_updater) {
                                let sources_delta = new_updater.sources.len() as i64
                                    - old_updater.sources.len() as i64;
                                info!(
                                    "Geo updater config reloaded ({} source(s), interval {} days, Δsources={:+}). Notifying updater.",
                                    new_updater.sources.len(),
                                    new_updater.update_days,
                                    sources_delta,
                                );
                                updater_handle.update(new_updater);
                            }
                        }
                    }
                    Err(e) => error!("Watch error: {:?}", e),
                }
            }
        });
    }
}
