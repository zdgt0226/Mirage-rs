use crate::config::Config;
use crate::proxy::outbound::OutboundManager;
use crate::router::{RouterEngine, Rule};
use crate::router::geo_updater::{UpdaterHandle, UpdaterState};
use anyhow::Result;
use arc_swap::ArcSwap;
use notify::{Event, RecursiveMode, Watcher};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use ipnet::IpNet;
use tracing::{error, info, warn};

pub struct CoreState {
    pub router: Arc<RouterEngine>,
    pub outbounds: Arc<OutboundManager>,
    pub advanced_dns: Option<crate::config::AdvancedDnsConfig>,
    /// 未分类域名自适应分类 (auto_classify)。None = 关闭 / geoip 缺失。热重载会重建 (学习缓存重置)。
    pub auto_classify: Option<Arc<crate::dns::server::AutoClassify>>,
    /// 按源 IP 的带宽限速器 (device_profiles 的 rate_limit_kbps)。空 = 无限速 (热路径直接跳过)。
    pub rate_limiter: Arc<crate::proxy::rate_limit::RateLimiter>,
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

    /// 注入 reload 回调 (链式追加)。lib.rs 在 tc_divert/xdp 引擎建好后调用, 使热重载
    /// 后 direct_cidr map 随新规则刷新、XDP DNS 缓存 map 同步清空。
    pub fn set_reload_hook(&self, hook: impl Fn(&CoreState) + Send + Sync + 'static) {
        let mut guard = self.reload_hook.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(prev) = guard.take() {
            *guard = Some(Box::new(move |st| {
                prev(st);
                hook(st);
            }));
        } else {
            *guard = Some(Box::new(hook));
        }
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

    pub(crate) fn build_state(config_path: &str, geodata_dir: &str, old_outbounds: Option<Arc<OutboundManager>>) -> Result<CoreState> {
        info!("Loading configuration from {}", config_path);
        let content = std::fs::read_to_string(config_path)
            .map_err(|e| anyhow::anyhow!("读取配置文件失败: {config_path}: {e}"))?;
        let (config, issues) = Config::parse_with_diagnostics(&content)
            .map_err(|e| anyhow::anyhow!("解析配置 JSON 失败: {config_path}: {e}"))?;
        for issue in &issues {
            // 重复口令会让鉴权命中错误用户 (用量记错人), 用 error 级别醒目提示。
            if issue.contains("password 与") {
                error!("配置校验: {}", issue);
            } else {
                warn!("配置校验: {}", issue);
            }
        }
        
        let is_hot_reload = old_outbounds.is_some();
        let outbounds = if let Some(old) = old_outbounds {
            info!("Preserving existing outbounds (hot-reload for outbounds is disabled to prevent connection disruption/task leaks).");
            // NOTE: Stateful components like pool/fake_ip_mapper are preserved during reload.
            // If inbounds, outbounds, or fakeip ranges need to be modified, a full restart is required.
            old
        } else {
            Arc::new(OutboundManager::new(&config)?)
        };
        
        let mut rules = Vec::new();
        // 「不同用户匹配不同规则」: 展开 device_profiles —— 每个设备分配把其 profile 的规则注入
        // source_ip_cidr(设备网段), 前插到全局规则之前 (设备规则首命中优先; 未命中落全局 → default)。
        let mut all_rule_cfgs: Vec<crate::config::RuleConfig> = Vec::new();
        for dp in &config.routing.device_profiles {
            if let Some(profile_rules) = config.routing.profiles.get(&dp.profile) {
                for pr in profile_rules {
                    let mut rc = pr.clone();
                    rc.source_ip_cidr = dp.source_ip_cidr.clone(); // 注入设备作用域
                    all_rule_cfgs.push(rc);
                }
            }
        }
        all_rule_cfgs.extend(config.routing.rules); // 全局规则在设备规则之后
        for (i, r) in all_rule_cfgs.into_iter().enumerate() {
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
                mode: match r.mode {
                    Some(crate::config::RuleMode::And) => "and",
                    _ => "or",
                }
                .to_string(),
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
                inbound: r.inbound,
                process_name: r.process_name,
            });
        }
        
        let router = RouterEngine::new(
            rules,
            config.routing.default_outbound,
            geodata_dir,
            &config.routing.geo_alias,
        )?;

        // geo .dat 载入自检: geo_updater 只校验它**自己下载**的; 手动放置 / 磁盘损坏 / 半截文件
        // 走 RouterEngine 的宽容 load 会静默返回空表 (规则全 fall back default) 且只在日志翻查才暴露。
        // 这里对 geodata 目录里每个 .dat 数一次分类 (与 updater validate_dat 同源), 0/损坏即 WARN。
        validate_geodata_dir(geodata_dir);

        let mut advanced_dns = config.advanced_dns;
        if let Some(adv) = &mut advanced_dns {
            let mut cn_dns: Vec<(std::net::SocketAddr, crate::config::DnsProtocol)> = Vec::new();
            let mut remote_servers: Vec<(String, u16)> = Vec::new();
            for r in &adv.resolvers {
                if adv.default.as_ref() == Some(&r.tag) || r.tag == "remote" || r.tag == "proxy" {
                    // 剥可选 tcp://|udp:// 前缀 (模板就是这么写的; 旧代码把 "tcp://8.8.8.8:53" 按
                    // split(':') 拆成 host="tcp" 致隧道 DNS 查错目标)。剥后优先按 IP/[v6]:port 精确解析,
                    // 解析不出 (域名) 再退回 host:port 粗拆, IPv6 域名场景极罕见。多个 remote 全收集, failover。
                    let (raw, _proto) = crate::config::strip_dns_scheme(&r.address);
                    let (h, p) = if let Some(sa) = crate::config::parse_dns_upstream(raw) {
                        (sa.ip().to_string(), sa.port())
                    } else if let Some((h, p)) = raw.rsplit_once(':').filter(|(h, p)| !h.is_empty() && p.parse::<u16>().is_ok()) {
                        (h.to_string(), p.parse().unwrap_or(53))
                    } else {
                        (raw.to_string(), 53)
                    };
                    if !remote_servers.iter().any(|(rh, rp)| rh == &h && *rp == p) {
                        remote_servers.push((h, p));
                    }
                } else if r.tag == "direct" || r.tag == "cn" {
                    // 收集全部 cn/direct 上游 (多上游兜底), 带协议; 地址无端口默认 53; 去重。
                    // 同样剥 tcp://|udp:// 前缀; 前缀指定的协议优先于 protocol 字段。
                    let (raw, proto_override) = crate::config::strip_dns_scheme(&r.address);
                    match crate::config::parse_dns_upstream(raw) {
                        Some(addr) => {
                            let entry = (addr, proto_override.unwrap_or(r.protocol));
                            if !cn_dns.contains(&entry) { cn_dns.push(entry); }
                        }
                        None => tracing::warn!("advanced_dns.resolvers: direct 上游地址 `{}` 非法 (需 ip / ip:port, 可带 tcp://|udp:// 前缀), 已跳过", r.address),
                    }
                }
            }
            adv.cached_cn_dns = cn_dns;
            // 首个 remote 作 host/port (兼容 + 附带用途: routing_req.port / 后台校验); 全量供 failover。
            adv.cached_remote_host = remote_servers.first().map(|(h, _)| h.clone());
            adv.cached_remote_port = remote_servers.first().map(|(_, p)| *p);
            adv.cached_remote_servers = remote_servers;

            // 静态解析归一化 (剥尾点+小写, 确定性去重, 长度降序) —— 见 normalize_static_hosts。
            let cached_static = crate::config::normalize_static_hosts(&adv.static_hosts);
            if !cached_static.is_empty() {
                tracing::info!("advanced_dns.static: 已加载 {} 条静态解析 (最长域名优先匹配)", cached_static.len());
            }
            adv.cached_static = cached_static;

            // DNS 规则层预编译: 每条 rule 编 DomainMatcher + 解析 host IP。
            adv.cached_dns_rules = adv
                .rules
                .iter()
                .map(|r| {
                    let host_ips = r
                        .ip
                        .iter()
                        .filter_map(|s| match s.trim().parse::<std::net::IpAddr>() {
                            Ok(ip) => Some(ip),
                            Err(_) => {
                                tracing::warn!("advanced_dns.rules: host IP `{}` 非法, 已跳过", s);
                                None
                            }
                        })
                        .collect();
                    crate::config::CompiledDnsRule {
                        matcher: crate::dns::domain_match::DomainMatcher::from_ruleset(&r.domains),
                        action: r.action,
                        server: r.server,
                        host_ips,
                    }
                })
                .collect();
            if !adv.cached_dns_rules.is_empty() {
                tracing::info!("advanced_dns.rules: 已加载 {} 条 DNS 规则 (首匹配, 选路/host/reject)", adv.cached_dns_rules.len());
            }
        }

        let auto_classify = crate::dns::server::AutoClassify::from_config(
            advanced_dns.as_ref(),
            config.tuning.as_ref(),
            geodata_dir,
        );

        let rate_limiter = Arc::new(
            crate::proxy::rate_limit::RateLimiter::from_device_profiles(&config.routing.device_profiles),
        );
        if !rate_limiter.is_empty() {
            info!("限速: device_profiles 已配置带宽上限 (按源 IP TCP 整形)");
        }
        // 服务端 IP 限速器随热重载更新
        crate::proxy::rate_limit::set_server_limiter(rate_limiter.clone());

        // 多用户凭据与限速/配额热重载 (仅在热重载时应用; 冷启动由 lib.rs 的 init_user_limits + register_creds 负责)
        // watcher 路径在锁内重新读取并解析磁盘文件, 避免并发覆盖 API 的更新。
        //
        // [关于两次读盘的窄窗口与自愈保证]:
        // build_state 顶部首次读取配置 (用于构建路由/DNS/出站), 此处 apply_user_config_from_file
        // 在持有 APPLY_USER_CONFIG_LOCK 期间二次读取磁盘文件以更新凭据。
        // 若在两次读取之间配置文件恰好被外部写入修改，本轮构建出的路由规则与应用的凭据可能会短暂
        // 来自不同版本。但该窄窗口内的外部写入必然会产生新的文件系统事件（或在 30 秒兜底轮询
        // 中比对 mtime/len 时被发现），从而排队触发下一轮 execute_reload / build_state 重载，
        // 最终达到完全一致与收敛。
        if is_hot_reload {
            apply_user_config_from_file(config_path);
        }

        Ok(CoreState {
            router: Arc::new(router),
            outbounds,
            advanced_dns,
            auto_classify,
            rate_limiter,
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

            // 1. 监听配置文件所在的父目录 (NonRecursive), 解决 tmp+rename 覆盖导致的 inode watch 失效
            let config_pathbuf = Path::new(&config_path).to_path_buf();
            let config_file_name = match config_pathbuf.file_name() {
                Some(name) => name.to_os_string(),
                None => {
                    error!("Config path has no file name: {}", config_path);
                    return;
                }
            };
            let config_dir = config_pathbuf
                .parent()
                .filter(|p| !p.as_os_str().is_empty())
                .unwrap_or(Path::new("."));
            let config_dir_canon = config_dir
                .canonicalize()
                .unwrap_or_else(|_| config_dir.to_path_buf());

            if let Err(e) = watcher.watch(config_dir, RecursiveMode::NonRecursive) {
                error!("Failed to watch config dir {}: {}", config_dir.display(), e);
                return;
            }
            info!("Started hot-reload watcher on config dir {} for file {:?}", config_dir.display(), config_file_name);

            // 若配置是软链接 (真实路径与原路径不同), 额外 watch 真实父目录 (与已 watch 目录相同则不重复)
            let mut symlink_state = SymlinkWatchState::new(
                &config_pathbuf,
                &config_dir_canon,
                &config_file_name,
            );

            if let Some(ref r_dir_canon) = symlink_state.real_dir_canon {
                if r_dir_canon != &config_dir_canon {
                    if let Err(e) = watcher.watch(r_dir_canon, RecursiveMode::NonRecursive) {
                        warn!("Failed to watch real config dir {} for symlink target: {}", r_dir_canon.display(), e);
                    } else {
                        info!("Also watching real config dir {} for symlink target {:?}", r_dir_canon.display(), symlink_state.real_file_name);
                    }
                }
            }

            // 2. Watch geodata directory — geo_updater 下载新 .dat 后触发 Router 重建.
            // 修复 bug #2 (启动时序空隙): 之前只 watch config_path, geo_updater 30s
            // 后下载 .dat 落地, 但 ConfigWatcher 不知道, Router 内存里 geo 表始终空,
            // 所有 geosite/geoip 规则 fall back 到 default_outbound. 用户除非手动改
            // config.json 否则永远不会修复.
            //
            // 目录不存在时主动创建 (geo_updater 也会创建, 但 watcher 必须在 .dat 写入
            // 前就 watch 上, 否则 inotify 错过 IN_CREATE 事件).
            // 与配置目录相同时不重复 watch (配置目录已被 watch)。
            let geodir_pathbuf = Path::new(&geodata_dir).to_path_buf();
            if !geodir_pathbuf.exists() {
                if let Err(e) = std::fs::create_dir_all(&geodir_pathbuf) {
                    warn!("Failed to create geodata dir {} (geo hot-reload disabled): {}", geodata_dir, e);
                }
            }
            let geodir_canon = geodir_pathbuf.canonicalize().ok();
            let same_dir = match &geodir_canon {
                Some(g_canon) => g_canon == &config_dir_canon,
                None => geodir_pathbuf == config_dir,
            };

            if !same_dir && geodir_pathbuf.exists() {
                match watcher.watch(&geodir_pathbuf, RecursiveMode::NonRecursive) {
                    Ok(_) => info!("Also watching geodata dir for .dat hot-reload: {}", geodata_dir),
                    Err(e) => warn!(
                        "Failed to watch geodata dir {} (geo downloads after startup will not auto-reload Router; touch config.json to force reload): {}",
                        geodata_dir, e
                    ),
                }
            } else if same_dir {
                info!("Geodata dir is same as config dir; skipping duplicate watch.");
            }

            let inspect_config = |p: &Path| -> Option<(PathBuf, Option<std::time::SystemTime>, u64)> {
                let real = p.canonicalize().ok()?;
                let meta = std::fs::metadata(&real).ok()?;
                let mtime = meta.modified().ok();
                let len = meta.len();
                Some((real, mtime, len))
            };

            let mut last_record = inspect_config(&config_pathbuf);

            // 3. Event loop — 过滤事件路径, 只对 config 文件本身 (含软链接真实目标) 或 .dat 文件触发
            // (避免 .tmp 写入 + 其他无关文件抖动). create/modify/rename 都算变更.
            // 采用 30s 兜底轮询: 事件驱动覆盖一层链接与 K8s ConfigMap, 更深的链接链由 30s 轮询兜底.
            loop {
                let event = match rx.recv_timeout(std::time::Duration::from_secs(30)) {
                    Ok(Ok(event)) => Some(event),
                    Ok(Err(e)) => {
                        error!("Watch error: {:?}", e);
                        continue;
                    }
                    Err(std::sync::mpsc::RecvTimeoutError::Timeout) => None,
                    Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => break,
                };

                let execute_reload = |trigger_path: &Path, symlink_changed: bool, real_target: Option<(&Path, &std::ffi::OsStr)>| {
                    info!("Watched path {} changed. Attempting hot-reload...", trigger_path.display());
                    // Give the writer a moment to finish flushing the file
                    std::thread::sleep(std::time::Duration::from_millis(100));

                    let current_outbounds = state.load().outbounds.clone();
                    match Self::build_state(&config_path, &geodata_dir, Some(current_outbounds)) {
                        Ok(new_state) => {
                            state.store(Arc::new(new_state));
                            info!("Hot-reload successful! New rules and outbounds applied (existing connections kept; sessions of removed/re-keyed users are revoked).");
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
                    // 成本很低. 只有 config 文件本身改动 (含软链接改指向) 才触发
                    // (`.dat` 变化不影响 updater 配置).
                    if symlink_changed || is_config_event(trigger_path, &config_dir_canon, &config_file_name, real_target) {
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
                };

                match event {
                    Some(Event { kind, paths, .. }) => {
                        if !(kind.is_modify() || kind.is_create()) {
                            continue;
                        }
                        // 判定是否可能涉及软链接变更: 文件名以 .. 开头 (K8s)、等于链接名、等于真实目标名或来自真实目录。
                        // 若命中则重新 canonicalize(config_path) 检测软链接指向是否改变。
                        // 这样既能即时响应 ln -sf 与 K8s ..data 切换, 又避免同目录每几秒写一次 stats 的开销。
                        let needs_symlink_check = paths.iter().any(|p| {
                            should_recheck_symlink(
                                p,
                                &config_file_name,
                                symlink_state.real_file_name.as_deref(),
                                symlink_state.real_dir_canon.as_deref(),
                                Some(&config_dir_canon),
                            )
                        });

                        let symlink_action = if needs_symlink_check {
                            symlink_state.update(
                                &config_pathbuf,
                                &config_dir_canon,
                                &config_file_name,
                                geodir_canon.as_deref(),
                            )
                        } else {
                            SymlinkUpdateAction::Unchanged
                        };

                        let symlink_changed = match symlink_action {
                            SymlinkUpdateAction::Unchanged => false,
                            SymlinkUpdateAction::PathChangedOnly => {
                                info!("Config symlink target updated to {}", symlink_state.current_real_path.display());
                                true
                            }
                            SymlinkUpdateAction::DirChanged { old_dir, new_dir } => {
                                if let Some(old) = old_dir {
                                    if let Err(e) = watcher.unwatch(&old) {
                                        warn!("Failed to unwatch old real config dir {}: {}", old.display(), e);
                                    } else {
                                        info!("Unwatched old real config dir {}", old.display());
                                    }
                                }
                                if let Some(new) = new_dir {
                                    if let Err(e) = watcher.watch(&new, RecursiveMode::NonRecursive) {
                                        warn!("Failed to watch new real config dir {}: {}", new.display(), e);
                                    } else {
                                        info!("Watching new real config dir {} for symlink target {:?}", new.display(), symlink_state.real_file_name);
                                    }
                                }
                                true
                            }
                        };

                        let real_target = match (&symlink_state.real_dir_canon, &symlink_state.real_file_name) {
                            (Some(rd), Some(rf)) => Some((rd.as_path(), rf.as_os_str())),
                            _ => None,
                        };
                        // find 触发路径, 而不是 paths.first(). rename 事件 paths
                        // 里可能 .tmp 在前 .dat 在后, 老 first() 会 log 出误导
                        // 的 .tmp 路径. find 匹配 trigger predicate 保证 log 显
                        // 示的就是真正被认可导致 reload 的那条路径.
                        let trigger_path = paths.iter().find(|p| {
                            is_config_event(p, &config_dir_canon, &config_file_name, real_target)
                                || p.extension().is_some_and(|e| e == "dat")
                        });
                        let trigger_path = match trigger_path {
                            Some(p) => p,
                            None if symlink_changed => &config_pathbuf,
                            None => continue, // 无路径命中 trigger, skip
                        };

                        execute_reload(trigger_path, symlink_changed, real_target);
                        last_record = inspect_config(&config_pathbuf);
                    }
                    None => {
                        // 30s 低频兜底轮询: 覆盖深层中间目录链接切换与配置目录链接切换场景
                        let current_record = inspect_config(&config_pathbuf);
                        if current_record.is_some() && current_record != last_record {
                            info!("30s 兜底轮询: 检测到配置文件真实路径/mtime/长度变更, 触发重载...");
                            let symlink_action = symlink_state.update(
                                &config_pathbuf,
                                &config_dir_canon,
                                &config_file_name,
                                geodir_canon.as_deref(),
                            );
                            let symlink_changed = match symlink_action {
                                SymlinkUpdateAction::Unchanged => false,
                                SymlinkUpdateAction::PathChangedOnly => {
                                    info!("Config symlink target updated to {}", symlink_state.current_real_path.display());
                                    true
                                }
                                SymlinkUpdateAction::DirChanged { old_dir, new_dir } => {
                                    if let Some(old) = old_dir {
                                        if let Err(e) = watcher.unwatch(&old) {
                                            warn!("Failed to unwatch old real config dir {}: {}", old.display(), e);
                                        } else {
                                            info!("Unwatched old real config dir {}", old.display());
                                        }
                                    }
                                    if let Some(new) = new_dir {
                                        if let Err(e) = watcher.watch(&new, RecursiveMode::NonRecursive) {
                                            warn!("Failed to watch new real config dir {}: {}", new.display(), e);
                                        } else {
                                            info!("Watching new real config dir {} for symlink target {:?}", new.display(), symlink_state.real_file_name);
                                        }
                                    }
                                    true
                                }
                            };
                            let real_target = match (&symlink_state.real_dir_canon, &symlink_state.real_file_name) {
                                (Some(rd), Some(rf)) => Some((rd.as_path(), rf.as_os_str())),
                                _ => None,
                            };
                            execute_reload(&config_pathbuf, symlink_changed, real_target);
                            last_record = current_record;
                        }
                    }
                }
            }
        });
    }
}

static APPLY_USER_CONFIG_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// 多用户凭据与限速/配额配置应用 (build_state 与 /api/users 共用):
/// 1. 保留既有用量, 重新计算超额
/// 2. 对每个 mirage_server 入站按 tag 重建凭据并原子替换; tag 不存在的跳过
///
/// 限额注册表全进程一张: 汇总所有入站的 users 一次性重建 (逐入站调用会互相覆盖, 见 collect_users)。
/// 全程持一把进程级 Mutex 串行化, 避免 /api/users 与 watcher 观察到交错的注册表状态。
pub fn apply_user_config(inbounds: &[crate::config::InboundConfig]) {
    let _lock = APPLY_USER_CONFIG_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    apply_user_config_locked(inbounds);
}

fn apply_user_config_locked(inbounds: &[crate::config::InboundConfig]) {
    // 5(a) 检查 mirage_server 入站是否存在重复 tag: 存在则拒绝本次应用, error 日志, 保持现有凭据与限额
    let mut seen_tags = std::collections::HashSet::new();
    for ib in inbounds {
        if let crate::config::InboundConfig::MirageServer { tag, .. } = ib {
            if !seen_tags.insert(tag.as_str()) {
                error!("apply_user_config: mirage_server 入站 tag `{tag}` 重复定义, 拒绝本次用户配置应用 (保持现有凭据与限额)");
                return;
            }
        }
    }

    // 5(b) CREDS_REGISTRY 中存在、但新配置里已没有的 mirage_server tag (入站被删除或改名):
    // 对该 tag 快照执行"替换为空凭据列表"(reconcile 吊销全部存量会话, 新握手全部走伪装)
    let current_registered = crate::proxy::mirage_server::registered_creds_tags();
    for registered_tag in current_registered {
        if !seen_tags.contains(registered_tag.as_str()) {
            crate::proxy::mirage_server::reload_creds(&registered_tag, Vec::new());
            warn!("入站 `{registered_tag}` 已从配置移除: 已吊销其全部凭据, 监听端口需重启才会关闭");
        }
    }

    crate::proxy::user_limits::reload_user_limits(&crate::proxy::user_limits::collect_users(inbounds));
    for ib in inbounds {
        if let crate::config::InboundConfig::MirageServer { tag, password, users, .. } = ib {
            let new_creds = crate::proxy::mirage_server::build_creds(password, users);
            if !crate::proxy::mirage_server::reload_creds(tag, new_creds) {
                warn!("入站 `{tag}` 未在运行中注册 (新增或改名的入站需重启才生效, 其凭据变更本次未应用)");
            }
        }
    }
}

/// 从文件重新读取并解析配置文件后再应用用户配置 (watcher 路径专用)。
/// 保证在 APPLY_USER_CONFIG_LOCK 内直接读取磁盘上的最新配置, 避免 watcher 并发时以旧内存配置覆盖 API 刚写的新配置。
pub fn apply_user_config_from_file(config_path: &str) {
    let _lock = APPLY_USER_CONFIG_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let content = match std::fs::read_to_string(config_path) {
        Ok(c) => c,
        Err(e) => {
            warn!("apply_user_config_from_file: 读取配置文件失败 ({config_path}): {e}, 放弃本次用户配置应用");
            return;
        }
    };
    let (config, _) = match Config::parse_with_diagnostics(&content) {
        Ok(cfg) => cfg,
        Err(e) => {
            warn!("apply_user_config_from_file: 解析配置文件失败 ({config_path}): {e}, 放弃本次用户配置应用");
            return;
        }
    };
    apply_user_config_locked(&config.inbounds);
}

/// 软链接监视状态: 追踪配置文件的真实路径及真实目录/文件名。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SymlinkWatchState {
    pub current_real_path: PathBuf,
    pub real_dir_canon: Option<PathBuf>,
    pub real_file_name: Option<std::ffi::OsString>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum SymlinkUpdateAction {
    /// 真实路径未变
    Unchanged,
    /// 真实路径变了, 但真实目录未变 (如指向同目录下的不同文件)
    PathChangedOnly,
    /// 真实路径变了且真实目录发生切换, 需 unwatch 旧真实目录并 watch 新真实目录
    DirChanged {
        old_dir: Option<PathBuf>,
        new_dir: Option<PathBuf>,
    },
}

/// 解析软链接真实目标所在的规范化父目录与目标文件名。
/// 若真实路径与原配置路径一致 (非软链接), 返回 (None, None)。
pub fn resolve_symlink_target(
    real_path: &Path,
    config_path: &Path,
    config_dir_canon: &Path,
    config_file_name: &std::ffi::OsStr,
) -> (Option<PathBuf>, Option<std::ffi::OsString>) {
    if real_path != config_path && real_path != config_dir_canon.join(config_file_name) {
        let r_name = real_path.file_name().map(|n| n.to_os_string());
        let r_dir = real_path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        let r_dir_canon = r_dir.canonicalize().unwrap_or_else(|_| r_dir.to_path_buf());
        (Some(r_dir_canon), r_name)
    } else {
        (None, None)
    }
}

/// 判定是否应当重新解析软链接指向:
/// 1. 事件路径名以 `..` 开头 (如 K8s ConfigMap 原子切换 `..data` 目录或其临时链接 `..data_tmp`)
/// 2. 事件文件名等于配置文件/软链接自身文件名 (如直接 `ln -sf` 覆盖)
/// 3. 事件文件名等于当前记录的真实目标文件名 (如目标文件被就地修改)
/// 4. 事件来自真实目录 (当真实目录 != 配置目录时)
///
/// 其余无关文件事件 (如同目录每几秒写一次的 stats 持久化文件) 跳过重解析以降低开销。
pub fn should_recheck_symlink(
    event_path: &Path,
    config_file_name: &std::ffi::OsStr,
    real_file_name: Option<&std::ffi::OsStr>,
    real_dir_canon: Option<&Path>,
    config_dir_canon: Option<&Path>,
) -> bool {
    if event_path.file_name() == Some(config_file_name) {
        return true;
    }
    if let Some(rf) = real_file_name {
        if event_path.file_name() == Some(rf) {
            return true;
        }
    }
    if let Some(name) = event_path.file_name().and_then(|n| n.to_str()) {
        if name.starts_with("..") {
            return true;
        }
    }
    // 当真实目录与配置目录相同时, 同目录无关写 (如 stats 持久化文件) 不得触发重解析;
    // 仅在真实目录与配置目录不同时, 真实目录下的事件才无条件触发重解析。
    if let (Some(rd), Some(cd)) = (real_dir_canon, config_dir_canon) {
        if rd == cd {
            return false;
        }
    }
    if let Some(rd) = real_dir_canon {
        if let Some(parent) = event_path.parent() {
            if parent == rd || parent.canonicalize().ok().as_deref() == Some(rd) {
                return true;
            }
        }
    }
    false
}

impl SymlinkWatchState {
    pub fn new(
        config_path: &Path,
        config_dir_canon: &Path,
        config_file_name: &std::ffi::OsStr,
    ) -> Self {
        let (real_path, real_dir_canon, real_file_name) = match config_path.canonicalize() {
            Ok(real) => {
                let (d, f) = resolve_symlink_target(&real, config_path, config_dir_canon, config_file_name);
                (real, d, f)
            }
            Err(_) => (config_path.to_path_buf(), None, None),
        };
        Self {
            current_real_path: real_path,
            real_dir_canon,
            real_file_name,
        }
    }

    /// 重新 canonicalize(config_path) 并计算是否需要更新 watch 目录及重新加载配置。
    /// 若 canonicalize 因软链接暂时悬空或原子替换窗口失败, 返回 Unchanged, 保持旧记录, 不 panic。
    pub fn update(
        &mut self,
        config_path: &Path,
        config_dir_canon: &Path,
        config_file_name: &std::ffi::OsStr,
        geodir_canon: Option<&Path>,
    ) -> SymlinkUpdateAction {
        let Ok(new_real) = config_path.canonicalize() else {
            return SymlinkUpdateAction::Unchanged;
        };
        if new_real == self.current_real_path {
            return SymlinkUpdateAction::Unchanged;
        }

        let old_dir = self.real_dir_canon.clone();
        let (new_real_dir_canon, new_real_file_name) = resolve_symlink_target(
            &new_real,
            config_path,
            config_dir_canon,
            config_file_name,
        );

        self.current_real_path = new_real;
        self.real_dir_canon = new_real_dir_canon.clone();
        self.real_file_name = new_real_file_name;

        if new_real_dir_canon != old_dir {
            let should_unwatch = old_dir.as_ref().is_some_and(|d| {
                d != config_dir_canon && Some(d.as_path()) != geodir_canon
            });
            let should_watch_new = new_real_dir_canon.as_ref().is_some_and(|d| {
                d != config_dir_canon && Some(d.as_path()) != geodir_canon
            });

            if should_unwatch || should_watch_new {
                SymlinkUpdateAction::DirChanged {
                    old_dir: if should_unwatch { old_dir } else { None },
                    new_dir: if should_watch_new { new_real_dir_canon } else { None },
                }
            } else {
                SymlinkUpdateAction::PathChangedOnly
            }
        } else {
            SymlinkUpdateAction::PathChangedOnly
        }
    }
}

/// 判定事件路径是否指向配置文件本身 (同时支持软链接自身与真实目标路径)。
///
/// 解决 inotify 监听配置文件本身在 tmp+rename 覆盖后丢失 inode watch 的问题。
/// 监听父目录时, notify 上报该目录下所有变动, 本函数过滤出对目标配置文件的变更:
/// - 比较文件名 (忽略同目录下的 .tmp 临时文件、stats 持久化文件等)
/// - 比较父目录 canonical 路径 (支持相对路径、绝对路径及软链接目录)
/// - 当 real_target 为 Some 时, 额外比对真实目标文件与真实目录 (软链接场景)
pub fn is_config_event(
    path: &Path,
    config_dir_canon: &Path,
    config_file_name: &std::ffi::OsStr,
    real_target: Option<(&Path, &std::ffi::OsStr)>,
) -> bool {
    if is_single_config_event(path, config_dir_canon, config_file_name) {
        return true;
    }
    if let Some((real_dir_canon, real_file_name)) = real_target {
        if is_single_config_event(path, real_dir_canon, real_file_name) {
            return true;
        }
    }
    false
}

fn is_single_config_event(
    path: &Path,
    dir_canon: &Path,
    file_name: &std::ffi::OsStr,
) -> bool {
    if path.file_name() != Some(file_name) {
        return false;
    }
    let p_parent = match path.parent() {
        Some(p) if !p.as_os_str().is_empty() => p,
        _ => Path::new("."),
    };
    if let Ok(canon) = p_parent.canonicalize() {
        canon == dir_canon
    } else {
        p_parent == dir_canon
    }
}

/// geo 数据目录载入自检: 对 `<geodata_dir>/` 的 geo 文件各数一次条目 (与 geo_updater 校验同源)。
/// 覆盖两类格式: **v2ray `.dat`** (geosite/geoip, count_categories 数分类) 与 **sing-box `.json`**
/// (第三方 rule-set, 数 domain/ip_cidr 条目)。0 条目 / 解析失败 = 空壳或损坏 (手动放错 / 半截下载
/// / 磁盘坏), 会让引用它的规则**静默全部 fall back default**。启动 + 每次热重载时 WARN 提示, 避免
/// 只在翻日志时才发现规则失效。best-effort: 目录读不了直接跳过, 不阻断启动。
fn validate_geodata_dir(geodata_dir: &str) {
    let Ok(entries) = std::fs::read_dir(geodata_dir) else { return };
    for entry in entries.flatten() {
        let path = entry.path();
        match path.extension().and_then(|e| e.to_str()) {
            Some("dat") => match crate::router::geo::count_categories(&path) {
                Ok(0) => tracing::warn!(
                    "geo 数据 {:?} 载入 0 个分类 (空壳/损坏/非 v2ray 格式?) — 引用它的 geosite/geoip 规则将全部不匹配, 回落 default 出站。检查文件或删除让 geo_updater 重下。",
                    path
                ),
                Ok(n) => tracing::debug!("geo 数据 {:?} 自检通过 ({} 个分类)", path, n),
                Err(e) => tracing::warn!(
                    "geo 数据 {:?} 解析失败 ({}) — 引用它的规则将不匹配。检查文件或删除重下。",
                    path, e
                ),
            },
            // updater 的元数据文件 (geodata_dir/meta.json), 非 geo 数据, 跳过免误报。
            Some("json") if path.file_name().and_then(|n| n.to_str()) == Some("meta.json") => {}
            // 第三方 sing-box rule-set JSON (RouterEngine 按 .json 后缀走 load_singbox_json)。
            Some("json") => match crate::router::geo::load_singbox_json(&path) {
                Ok((d, c)) if d.is_empty() && c.is_empty() => tracing::warn!(
                    "sing-box geo {:?} 载入 0 条 domain/ip_cidr (空壳/损坏/非 sing-box rule-set 格式?) — 引用它的规则将全部不匹配, 回落 default。检查文件。",
                    path
                ),
                Ok((d, c)) => tracing::debug!("sing-box geo {:?} 自检通过 ({} domain + {} cidr)", path, d.len(), c.len()),
                Err(e) => tracing::warn!(
                    "sing-box geo {:?} 解析失败 ({}) — 引用它的规则将不匹配。检查文件。",
                    path, e
                ),
            },
            _ => {} // 其它文件 (metadata.json 之类由扩展名区分不了的除外) 跳过
        }
    }
}

#[cfg(test)]
mod leak_guard_tests {
    //! §7 抗审查泄漏护甲 (T2 抗 DNS 污染 / T4 fail-closed) —— 进程内驱动真实
    //! config→CoreState→DnsForwarder.resolve_query 路径, 无 netns。见 docs/threat-model.md §7。
    use super::*;
    use crate::dns::fake_ip::FakeIpMapper;
    use crate::dns::server::DnsForwarder;
    use std::io::Write;

    /// 写一个临时 config.json + 空 geodata 目录, 返回 (config_path, geodata_dir)。用后由 caller 删。
    fn write_config(tag: &str, extra_outbounds: &str, rules: &str) -> (String, String) {
        let base = std::env::temp_dir().join(format!(
            "mirage-leak-{}-{}-{}",
            std::process::id(),
            tag,
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&base).unwrap();
        let cfg_path = base.join("config.json");
        let geo_dir = base.join("geo");
        std::fs::create_dir_all(&geo_dir).unwrap();
        let cfg = format!(
            r#"{{
  "schema_version": 1,
  "log_level": "error",
  "inbounds": [],
  "outbounds": [
    {{ "type": "mirage", "tag": "proxy", "server": "127.0.0.1", "server_port": 19999, "password": "x", "camouflage_host": "example.com", "pool_size": 1 }},
    {{ "type": "direct", "tag": "direct" }}{extra_outbounds}
  ],
  "routing": {{
    "default_outbound": "direct",
    "rules": [{rules}]
  }},
  "advanced_dns": {{ "fakeip": {{ "enabled": true, "inet4_range": "198.18.0.0/15" }} }}
}}"#
        );
        std::fs::File::create(&cfg_path)
            .unwrap()
            .write_all(cfg.as_bytes())
            .unwrap();
        (
            cfg_path.to_str().unwrap().to_string(),
            geo_dir.to_str().unwrap().to_string(),
        )
    }

    /// 手搓一个 DNS 查询: [tx=0x1234][flags RD][QD=1] + name(labels) + qtype + QCLASS(IN)。
    fn dns_query(domain: &str, qtype: u16) -> Vec<u8> {
        let mut q = vec![0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
        for label in domain.split('.') {
            q.push(label.len() as u8);
            q.extend_from_slice(label.as_bytes());
        }
        q.push(0);
        q.extend_from_slice(&qtype.to_be_bytes());
        q.extend_from_slice(&[0x00, 0x01]);
        q
    }

    /// 从 DNS 应答取 (ancount, 首个 A 记录 IPv4)。用于断言 fake-IP。
    fn first_a_record(resp: &[u8]) -> (u16, Option<std::net::Ipv4Addr>) {
        let ancount = u16::from_be_bytes([resp[6], resp[7]]);
        // 跳到 answer: header 12 + question (name..0 + 4)
        let mut pos = 12;
        while pos < resp.len() && resp[pos] != 0 {
            pos += 1 + resp[pos] as usize;
        }
        pos += 1 + 4; // root label + qtype + qclass
        if ancount == 0 {
            return (0, None);
        }
        // answer: name(ptr 2B or labels) + type(2) + class(2) + ttl(4) + rdlen(2) + rdata
        // name 压缩指针 0xC0.. → 2B
        if pos < resp.len() && resp[pos] & 0xC0 == 0xC0 {
            pos += 2;
        } else {
            while pos < resp.len() && resp[pos] != 0 {
                pos += 1 + resp[pos] as usize;
            }
            pos += 1;
        }
        let rtype = u16::from_be_bytes([resp[pos], resp[pos + 1]]);
        let rdlen = u16::from_be_bytes([resp[pos + 8], resp[pos + 9]]) as usize;
        pos += 10;
        if rtype == 1 && rdlen == 4 {
            (ancount, Some(std::net::Ipv4Addr::new(resp[pos], resp[pos + 1], resp[pos + 2], resp[pos + 3])))
        } else {
            (ancount, None)
        }
    }

    async fn forwarder_for(cfg: &str, geo: &str, mapper: Option<Arc<FakeIpMapper>>) -> Arc<DnsForwarder> {
        // build_state 会 reload 进程级用户限额注册表, 与 init 注册表的测试串行 (锁只包住这一同步调用)。
        let state = {
            let _reg = crate::proxy::user_limits::REGISTRY_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
            ConfigWatcher::build_state(cfg, geo, None).unwrap()
        };
        let arc = Arc::new(arc_swap::ArcSwap::from_pointee(state));
        DnsForwarder::for_hijack(arc, mapper, None).await.unwrap()
    }

    /// T2: 被代理域名 A 查询 → fake-IP (198.18.0.0/15), 绝不走本地 UDP:53 真解析。
    #[tokio::test]
    async fn t2_proxied_domain_a_query_gets_fakeip() {
        let (cfg, geo) = write_config(
            "t2a",
            "",
            r#"{ "domain_suffix": ["proxied.test"], "outbound": "proxy" }"#,
        );
        let mapper = Arc::new(FakeIpMapper::new("198.18.0.0/15").unwrap());
        let fwd = forwarder_for(&cfg, &geo, Some(mapper.clone())).await;
        let resp = fwd
            .resolve_query(&dns_query("www.proxied.test", 1))
            .await
            .expect("proxied A query 应有应答");
        let (ancount, a) = first_a_record(&resp);
        assert_eq!(ancount, 1, "应有 1 条 A 记录");
        let ip = a.expect("应是 A 记录");
        assert!(mapper.is_fake_ip(&ip), "被代理域名必须解析为 fake-IP (拿到真实 IP = 走了本地解析 = T2 违规); got {ip}");
        let _ = std::fs::remove_dir_all(std::path::Path::new(&cfg).parent().unwrap());
    }

    /// T2: 被代理域名 AAAA 查询 → 空答复 (NODATA), 不走本地 AAAA 真解析。
    #[tokio::test]
    async fn t2_proxied_domain_aaaa_query_returns_empty_not_local() {
        let (cfg, geo) = write_config(
            "t2aaaa",
            "",
            r#"{ "domain_suffix": ["proxied.test"], "outbound": "proxy" }"#,
        );
        let mapper = Arc::new(FakeIpMapper::new("198.18.0.0/15").unwrap());
        let fwd = forwarder_for(&cfg, &geo, Some(mapper)).await;
        let resp = fwd
            .resolve_query(&dns_query("www.proxied.test", 28))
            .await
            .expect("proxied AAAA 应有应答");
        let ancount = u16::from_be_bytes([resp[6], resp[7]]);
        assert_eq!(ancount, 0, "被代理域名 AAAA 必须空答复 (非本地真解析); ancount={ancount}");
        let _ = std::fs::remove_dir_all(std::path::Path::new(&cfg).parent().unwrap());
    }

    /// T4: 被 block 的域名 → NXDOMAIN (rcode=3), 不解析不泄漏。
    #[tokio::test]
    async fn t4_blocked_domain_returns_nxdomain() {
        let (cfg, geo) = write_config(
            "t4blk",
            r#",
    { "type": "block", "tag": "block" }"#,
            r#"{ "domain_suffix": ["blocked.test"], "outbound": "block" }"#,
        );
        let mapper = Arc::new(FakeIpMapper::new("198.18.0.0/15").unwrap());
        let fwd = forwarder_for(&cfg, &geo, Some(mapper)).await;
        let resp = fwd
            .resolve_query(&dns_query("x.blocked.test", 1))
            .await
            .expect("blocked 应有应答");
        let rcode = resp[3] & 0x0F;
        assert_eq!(rcode, 3, "被 block 域名必须 NXDOMAIN (rcode=3); got rcode={rcode}");
        let _ = std::fs::remove_dir_all(std::path::Path::new(&cfg).parent().unwrap());
    }
}

#[cfg(test)]
mod watcher_event_tests {
    use super::*;

    #[test]
    fn test_is_config_event_relative_and_absolute() {
        let temp_dir = std::env::temp_dir().join(format!("mirage_watch_unit_{}_{}", std::process::id(), fastrand::u64(..)));
        std::fs::create_dir_all(&temp_dir).unwrap();
        let canon_dir = temp_dir.canonicalize().unwrap();
        let file_name = std::ffi::OsString::from("config.json");

        // 1. 绝对路径匹配
        let abs_path = canon_dir.join("config.json");
        assert!(is_config_event(&abs_path, &canon_dir, &file_name, None));

        // 2. 相对路径 (以当前工作目录为例)
        let cwd_canon = Path::new(".").canonicalize().unwrap();
        let rel_file = Path::new("config.json");
        let rel_dot_file = Path::new("./config.json");
        assert!(is_config_event(rel_file, &cwd_canon, &file_name, None));
        assert!(is_config_event(rel_dot_file, &cwd_canon, &file_name, None));

        // 3. 其它文件名 (如 .tmp, stats 文件) 不匹配
        let tmp_file = canon_dir.join("config.json.tmp");
        let stats_file = canon_dir.join("stats.json");
        assert!(!is_config_event(&tmp_file, &canon_dir, &file_name, None));
        assert!(!is_config_event(&stats_file, &canon_dir, &file_name, None));

        // 4. 不同目录下的同名文件不匹配
        let other_dir = std::env::temp_dir().join(format!("mirage_other_dir_{}_{}", std::process::id(), fastrand::u64(..)));
        std::fs::create_dir_all(&other_dir).unwrap();
        let other_file = other_dir.join("config.json");
        assert!(!is_config_event(&other_file, &canon_dir, &file_name, None));

        let _ = std::fs::remove_dir_all(&temp_dir);
        let _ = std::fs::remove_dir_all(&other_dir);
    }

    #[test]
    fn test_rename_events_detected_consecutively() {
        let temp_dir = std::env::temp_dir().join(format!("mirage_watch_rename_{}_{}", std::process::id(), fastrand::u64(..)));
        std::fs::create_dir_all(&temp_dir).unwrap();
        let config_dir_canon = temp_dir.canonicalize().unwrap();
        let config_file_name = std::ffi::OsString::from("config.json");
        let config_path = temp_dir.join("config.json");

        // 初始写入 config.json
        std::fs::write(&config_path, b"initial").unwrap();

        let (tx, rx) = std::sync::mpsc::channel();
        let mut watcher = notify::recommended_watcher(tx).expect("watcher create failed");
        watcher.watch(&temp_dir, RecursiveMode::NonRecursive).expect("watcher watch failed");

        // 连续 3 次 tmp+rename 写入覆盖, 每次均须被识别到
        for i in 1..=3 {
            let tmp_path = temp_dir.join(format!("config.json.tmp.{}", i));
            std::fs::write(&tmp_path, format!("version_{}", i)).unwrap();
            std::fs::rename(&tmp_path, &config_path).unwrap();

            // 等待直到收到命中 is_config_event 的事件 (2 秒超时)
            let mut hit = false;
            let timeout = std::time::Instant::now() + std::time::Duration::from_secs(2);
            while std::time::Instant::now() < timeout {
                if let Ok(Ok(Event { kind, paths, .. })) = rx.recv_timeout(std::time::Duration::from_millis(200)) {
                    if (kind.is_modify() || kind.is_create())
                        && paths.iter().any(|p| is_config_event(p, &config_dir_canon, &config_file_name, None))
                    {
                        hit = true;
                        break;
                    }
                }
            }
            assert!(hit, "第 {} 次 tmp+rename 覆盖必须被 watcher 识别到", i);
        }

        // 验证写入同目录无关文件 (.tmp) 不被判定为 config 事件
        let unrelated_path = temp_dir.join("config.json.tmp");
        std::fs::write(&unrelated_path, b"tmp data").unwrap();
        assert!(!is_config_event(&unrelated_path, &config_dir_canon, &config_file_name, None));

        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_is_config_event_with_symlink() {
        let temp_dir = std::env::temp_dir().join(format!("mirage_watch_symlink_{}_{}", std::process::id(), fastrand::u64(..)));
        std::fs::create_dir_all(&temp_dir).unwrap();

        let real_dir = temp_dir.join("real_dir");
        let link_dir = temp_dir.join("link_dir");
        std::fs::create_dir_all(&real_dir).unwrap();
        std::fs::create_dir_all(&link_dir).unwrap();

        let real_path = real_dir.join("real.json");
        std::fs::write(&real_path, b"initial").unwrap();

        let link_path = link_dir.join("link.json");
        #[cfg(unix)]
        std::os::unix::fs::symlink(&real_path, &link_path).unwrap();

        let link_dir_canon = link_dir.canonicalize().unwrap();
        let link_file_name = std::ffi::OsString::from("link.json");
        let real_dir_canon = real_dir.canonicalize().unwrap();
        let real_file_name = std::ffi::OsString::from("real.json");
        let real_target = Some((real_dir_canon.as_path(), real_file_name.as_os_str()));

        // 对 real.json 的路径 (无论是绝对路径还是通过 tmp+rename 写入) 能被识别
        assert!(is_config_event(&real_path, &link_dir_canon, &link_file_name, real_target));

        // 对 link.json 的路径也能被识别
        assert!(is_config_event(&link_path, &link_dir_canon, &link_file_name, real_target));

        // 对 real_dir 下的 tmp 文件不被判定为 config 事件
        let real_tmp = real_dir.join("real.json.tmp");
        assert!(!is_config_event(&real_tmp, &link_dir_canon, &link_file_name, real_target));

        // 对 link_dir 下的 tmp 文件不被判定为 config 事件
        let link_tmp = link_dir.join("link.json.tmp");
        assert!(!is_config_event(&link_tmp, &link_dir_canon, &link_file_name, real_target));

        // 对无关文件不被判定为 config 事件
        let unrelated = real_dir.join("other.json");
        assert!(!is_config_event(&unrelated, &link_dir_canon, &link_file_name, real_target));

        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_symlink_target_retarget_event_recognition() {
        let temp_dir = std::env::temp_dir().join(format!("mirage_retarget_{}_{}", std::process::id(), fastrand::u64(..)));
        std::fs::create_dir_all(&temp_dir).unwrap();

        let a_path = temp_dir.join("a.json");
        let b_path = temp_dir.join("b.json");
        let link_path = temp_dir.join("link.json");

        std::fs::write(&a_path, b"{\"a\": 1}").unwrap();
        std::fs::write(&b_path, b"{\"b\": 2}").unwrap();

        #[cfg(unix)]
        std::os::unix::fs::symlink(&a_path, &link_path).unwrap();

        let link_dir_canon = temp_dir.canonicalize().unwrap();
        let link_file_name = std::ffi::OsString::from("link.json");

        let mut symlink_state = SymlinkWatchState::new(&link_path, &link_dir_canon, &link_file_name);
        assert_eq!(symlink_state.real_file_name.as_deref(), Some(std::ffi::OsStr::new("a.json")));

        // link.json -> a.json 时, 修改 a.json 能匹配, b.json 不匹配
        let real_target1 = match (&symlink_state.real_dir_canon, &symlink_state.real_file_name) {
            (Some(rd), Some(rf)) => Some((rd.as_path(), rf.as_os_str())),
            _ => None,
        };
        assert!(is_config_event(&a_path, &link_dir_canon, &link_file_name, real_target1));
        assert!(!is_config_event(&b_path, &link_dir_canon, &link_file_name, real_target1));

        // 改指向 b.json
        #[cfg(unix)]
        {
            let _ = std::fs::remove_file(&link_path);
            std::os::unix::fs::symlink(&b_path, &link_path).unwrap();
        }

        // 检测指向变更
        let action = symlink_state.update(&link_path, &link_dir_canon, &link_file_name, None);
        assert_eq!(action, SymlinkUpdateAction::PathChangedOnly);
        assert_eq!(symlink_state.real_file_name.as_deref(), Some(std::ffi::OsStr::new("b.json")));

        // 改指向后, 修改 b.json 能被识别为配置事件, 修改 a.json 不再识别
        let real_target2 = match (&symlink_state.real_dir_canon, &symlink_state.real_file_name) {
            (Some(rd), Some(rf)) => Some((rd.as_path(), rf.as_os_str())),
            _ => None,
        };
        assert!(is_config_event(&b_path, &link_dir_canon, &link_file_name, real_target2));
        assert!(!is_config_event(&a_path, &link_dir_canon, &link_file_name, real_target2));

        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_k8s_configmap_atomic_rotation_event_recognition() {
        let temp_dir = std::env::temp_dir().join(format!("mirage_k8s_cm_{}_{}", std::process::id(), fastrand::u64(..)));
        std::fs::create_dir_all(&temp_dir).unwrap();

        let dir_2026_01 = temp_dir.join("..2026_01");
        let dir_2026_02 = temp_dir.join("..2026_02");
        std::fs::create_dir_all(&dir_2026_01).unwrap();
        std::fs::create_dir_all(&dir_2026_02).unwrap();

        let cfg_1 = dir_2026_01.join("config.json");
        let cfg_2 = dir_2026_02.join("config.json");
        std::fs::write(&cfg_1, b"{\"version\": 1}").unwrap();
        std::fs::write(&cfg_2, b"{\"version\": 2}").unwrap();

        let data_link = temp_dir.join("..data");
        let config_link = temp_dir.join("config.json");

        #[cfg(unix)]
        {
            std::os::unix::fs::symlink(&dir_2026_01, &data_link).unwrap();
            std::os::unix::fs::symlink(Path::new("..data/config.json"), &config_link).unwrap();
        }

        let config_dir_canon = temp_dir.canonicalize().unwrap();
        let config_file_name = std::ffi::OsString::from("config.json");

        let mut symlink_state = SymlinkWatchState::new(&config_link, &config_dir_canon, &config_file_name);
        let canon_01 = dir_2026_01.canonicalize().unwrap();
        let canon_02 = dir_2026_02.canonicalize().unwrap();

        assert_eq!(symlink_state.real_dir_canon.as_ref(), Some(&canon_01));
        assert_eq!(symlink_state.real_file_name.as_deref(), Some(std::ffi::OsStr::new("config.json")));

        // 初始状态: ..2026_01/config.json 匹配
        let real_target1 = match (&symlink_state.real_dir_canon, &symlink_state.real_file_name) {
            (Some(rd), Some(rf)) => Some((rd.as_path(), rf.as_os_str())),
            _ => None,
        };
        assert!(is_config_event(&cfg_1, &config_dir_canon, &config_file_name, real_target1));
        assert!(!is_config_event(&cfg_2, &config_dir_canon, &config_file_name, real_target1));

        // K8s 风格原子替换: 创建临时软链接 ..data_tmp 指向 ..2026_02, 然后 rename 覆盖 ..data
        #[cfg(unix)]
        {
            let data_tmp = temp_dir.join("..data_tmp");
            std::os::unix::fs::symlink(&dir_2026_02, &data_tmp).unwrap();
            std::fs::rename(&data_tmp, &data_link).unwrap();
        }

        // 验证 should_recheck_symlink 对 ..data 路径返回 true
        assert!(should_recheck_symlink(&data_link, &config_file_name, symlink_state.real_file_name.as_deref(), symlink_state.real_dir_canon.as_deref(), Some(&config_dir_canon)));

        // 执行 update, 识别目录变更
        let action = symlink_state.update(&config_link, &config_dir_canon, &config_file_name, None);
        assert_eq!(
            action,
            SymlinkUpdateAction::DirChanged {
                old_dir: Some(canon_01),
                new_dir: Some(canon_02.clone()),
            }
        );
        assert_eq!(symlink_state.real_dir_canon.as_ref(), Some(&canon_02));

        // 新版本 ..2026_02/config.json 匹配为配置事件
        let real_target2 = match (&symlink_state.real_dir_canon, &symlink_state.real_file_name) {
            (Some(rd), Some(rf)) => Some((rd.as_path(), rf.as_os_str())),
            _ => None,
        };
        assert!(is_config_event(&cfg_2, &config_dir_canon, &config_file_name, real_target2));
        assert!(!is_config_event(&cfg_1, &config_dir_canon, &config_file_name, real_target2));

        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_should_recheck_symlink_same_dir_filters_unrelated_files() {
        let dir = Path::new("/etc/mirage");
        let cfg_name = std::ffi::OsStr::new("config.json");
        let real_name = std::ffi::OsStr::new("config_v1.json");
        let stats_path = Path::new("/etc/mirage/stats.json");
        let cfg_path = Path::new("/etc/mirage/config.json");
        let real_path = Path::new("/etc/mirage/config_v1.json");
        let k8s_path = Path::new("/etc/mirage/..data");

        // 真实目录 == 配置目录: 只有命中文件名 / .. 前缀才返回 true, 无关文件 (stats.json) 返回 false
        assert!(!should_recheck_symlink(stats_path, cfg_name, Some(real_name), Some(dir), Some(dir)));
        assert!(should_recheck_symlink(cfg_path, cfg_name, Some(real_name), Some(dir), Some(dir)));
        assert!(should_recheck_symlink(real_path, cfg_name, Some(real_name), Some(dir), Some(dir)));
        assert!(should_recheck_symlink(k8s_path, cfg_name, Some(real_name), Some(dir), Some(dir)));

        // 真实目录 != 配置目录: 真实目录下的事件返回 true
        let diff_dir = Path::new("/opt/releases/v1");
        let diff_path = Path::new("/opt/releases/v1/random.json");
        assert!(should_recheck_symlink(diff_path, cfg_name, Some(real_name), Some(diff_dir), Some(dir)));
    }

    #[test]
    fn test_watcher_apply_from_file_does_not_overwrite_api_with_stale() {
        let _lock = crate::proxy::user_limits::REGISTRY_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let temp_dir = std::env::temp_dir().join(format!("mirage_test_p3_task3_{}_{}", std::process::id(), fastrand::u64(..)));
        std::fs::create_dir_all(&temp_dir).unwrap();
        let cfg_path = temp_dir.join("config.json");
        let tag = format!("tag_task3_{}", fastrand::u64(..));

        // 1. 初始向 CREDS_REGISTRY 注册一个初始凭据
        let initial_creds = crate::proxy::mirage_server::build_creds("init_pw", &[]);
        let snapshot = crate::proxy::mirage_server::register_creds(&tag, initial_creds);

        // 2. 模拟 API 更新: 文件中写入了新口令 "api_new_pw"
        let new_cfg_content = format!(
            r#"{{
  "inbounds": [
    {{
      "type": "mirage_server",
      "tag": "{}",
      "listen": "0.0.0.0",
      "port": 443,
      "password": "api_new_pw",
      "users": [{{"name": "alice", "password": "alice_api_pw"}}]
    }}
  ],
  "outbounds": [{{"type": "direct", "tag": "direct"}}],
  "routing": {{"default_outbound": "direct", "rules": []}}
}}"#,
            tag
        );
        std::fs::write(&cfg_path, &new_cfg_content).unwrap();

        // API 路径立即应用新配置
        let (parsed_new, _) = Config::parse_with_diagnostics(&new_cfg_content).unwrap();
        apply_user_config(&parsed_new.inbounds);
        assert_eq!(snapshot.load()[0].password, "api_new_pw");
        assert_eq!(snapshot.load()[1].password, "alice_api_pw");

        // 3. 模拟 watcher: watcher 在锁内重新读取磁盘文件
        apply_user_config_from_file(cfg_path.to_str().unwrap());

        // 验证最终状态依然是磁盘上的最新 API 内容, 没有被旧内存对象覆盖
        assert_eq!(snapshot.load()[0].password, "api_new_pw");
        assert_eq!(snapshot.load()[1].password, "alice_api_pw");

        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_apply_user_config_duplicate_tag_rejected() {
        let _lock = crate::proxy::user_limits::REGISTRY_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let tag = format!("tag_dup_{}", fastrand::u64(..));

        let initial_creds = crate::proxy::mirage_server::build_creds("initial_pw", &[]);
        let snapshot = crate::proxy::mirage_server::register_creds(&tag, initial_creds);

        // 构造含有重复 tag 的配置
        let json_dup = format!(
            r#"{{
  "inbounds": [
    {{ "type": "mirage_server", "tag": "{}", "listen": "0.0.0.0", "port": 443, "password": "new_pw1" }},
    {{ "type": "mirage_server", "tag": "{}", "listen": "0.0.0.0", "port": 444, "password": "new_pw2" }}
  ],
  "outbounds": [{{"type": "direct", "tag": "direct"}}],
  "routing": {{"default_outbound": "direct", "rules": []}}
}}"#,
            tag, tag
        );
        let (cfg, _) = Config::parse_with_diagnostics(&json_dup).unwrap();

        // 应用重复 tag: 应该被拒绝, snapshot 保持原样
        apply_user_config(&cfg.inbounds);
        assert_eq!(snapshot.load()[0].password, "initial_pw");
    }

    #[test]
    fn test_apply_user_config_removed_tag_revoked() {
        let _lock = crate::proxy::user_limits::REGISTRY_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let tag_remove = format!("tag_rem_{}", fastrand::u64(..));
        let tag_keep = format!("tag_keep_{}", fastrand::u64(..));

        let creds_remove = crate::proxy::mirage_server::build_creds("pw_rem", &[]);
        let snapshot_remove = crate::proxy::mirage_server::register_creds(&tag_remove, creds_remove);

        let creds_keep = crate::proxy::mirage_server::build_creds("pw_keep", &[]);
        let snapshot_keep = crate::proxy::mirage_server::register_creds(&tag_keep, creds_keep);

        // 新配置中移除了 tag_remove, 只保留 tag_keep
        let json_new = format!(
            r#"{{
  "inbounds": [
    {{ "type": "mirage_server", "tag": "{}", "listen": "0.0.0.0", "port": 443, "password": "pw_keep_updated" }}
  ],
  "outbounds": [{{"type": "direct", "tag": "direct"}}],
  "routing": {{"default_outbound": "direct", "rules": []}}
}}"#,
            tag_keep
        );
        let (cfg, _) = Config::parse_with_diagnostics(&json_new).unwrap();

        apply_user_config(&cfg.inbounds);

        // 验证 tag_remove 上的凭据已被清空 (且旧条目置 revoked = true)
        assert!(snapshot_remove.load().is_empty());
        // tag_keep 已正常更新
        assert_eq!(snapshot_keep.load()[0].password, "pw_keep_updated");
    }
}

