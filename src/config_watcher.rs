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

    pub(crate) fn build_state(config_path: &str, geodata_dir: &str, old_outbounds: Option<Arc<OutboundManager>>) -> Result<CoreState> {
        info!("Loading configuration from {}", config_path);
        let config = Config::load_from_file(config_path)?;
        
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
        
        let mut advanced_dns = config.advanced_dns;
        if let Some(adv) = &mut advanced_dns {
            let mut cn_dns: Vec<(std::net::SocketAddr, crate::config::DnsProtocol)> = Vec::new();
            let mut remote_host = None;
            let mut remote_port = None;
            for r in &adv.resolvers {
                if adv.default.as_ref() == Some(&r.tag) || r.tag == "remote" || r.tag == "proxy" {
                    // 剥可选 tcp://|udp:// 前缀 (模板就是这么写的; 旧代码把 "tcp://8.8.8.8:53" 按
                    // split(':') 拆成 host="tcp" 致隧道 DNS 查错目标)。剥后优先按 IP/[v6]:port 精确解析,
                    // 解析不出 (域名) 再退回 host:port 粗拆, IPv6 域名场景极罕见。
                    let (raw, _proto) = crate::config::strip_dns_scheme(&r.address);
                    if let Some(sa) = crate::config::parse_dns_upstream(raw) {
                        remote_host = Some(sa.ip().to_string());
                        remote_port = Some(sa.port());
                    } else if let Some((h, p)) = raw.rsplit_once(':').filter(|(h, p)| !h.is_empty() && p.parse::<u16>().is_ok()) {
                        remote_host = Some(h.to_string());
                        remote_port = p.parse().ok();
                    } else {
                        remote_host = Some(raw.to_string());
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
            adv.cached_remote_host = remote_host;
            adv.cached_remote_port = remote_port;

            // 静态解析归一化 (剥尾点+小写, 确定性去重, 长度降序) —— 见 normalize_static_hosts。
            let cached_static = crate::config::normalize_static_hosts(&adv.static_hosts);
            if !cached_static.is_empty() {
                tracing::info!("advanced_dns.static: 已加载 {} 条静态解析 (最长域名优先匹配)", cached_static.len());
            }
            adv.cached_static = cached_static;
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
                                || p.extension().is_some_and(|e| e == "dat")
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
        let state = ConfigWatcher::build_state(cfg, geo, None).unwrap();
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
