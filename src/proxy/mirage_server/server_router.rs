use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, OnceLock};
use arc_swap::ArcSwapOption;
use tracing::info;

#[derive(Clone)]
pub enum ServerOutboundTarget {
    Direct,
    Upstream(Arc<crate::proxy::upstream::UpstreamOutlet>),
    /// `block` 出站, 或路由选到服务端不支持 / 不存在的出站: 拒绝, 绝不回落直连 (回落会悄悄换出口 IP)。
    Reject,
}

#[derive(Clone)]
pub struct ServerRouteDecision {
    pub tag: String,
    pub target: ServerOutboundTarget,
}

pub struct ServerRouterState {
    pub router: Option<Arc<crate::router::RouterEngine>>,
    pub outbounds: HashMap<String, ServerOutboundTarget>,
    pub inbound_upstreams: HashMap<String, Arc<crate::proxy::upstream::UpstreamOutlet>>,
    pub default_outbound: String,
    /// 每个上游出口的配置指纹 (键: 出站 tag / `inbound:<tag>`)。热重载时配置没变的出口复用旧
    /// `UpstreamOutlet`: WG 出口重建会以同一私钥另起会话, 对端漫游到新会话, 旧连接随之断。
    fingerprints: HashMap<String, String>,
    /// 本次构建新建 (非复用) 的 WG 出口, 装表时预热 (见 set_server_router_state)。
    fresh_wg: Vec<Arc<crate::proxy::upstream::UpstreamOutlet>>,
}

static SERVER_ROUTER: OnceLock<ArcSwapOption<ServerRouterState>> = OnceLock::new();

fn slot() -> &'static ArcSwapOption<ServerRouterState> {
    SERVER_ROUTER.get_or_init(|| ArcSwapOption::from(None))
}

/// 首次在 tokio 运行时内装表时记下运行时句柄: 热重载在 std 线程里调本函数, 预热要靠它 spawn。
static RUNTIME: OnceLock<tokio::runtime::Handle> = OnceLock::new();

pub fn set_server_router_state(state: Arc<ServerRouterState>) {
    if let Ok(h) = tokio::runtime::Handle::try_current() {
        let _ = RUNTIME.set(h);
    }
    // 本次新建的 WG 出口立即后台握手: 否则要等第一个请求来才建隧道, 那批请求要排队等握手,
    // 线路抖动时会顶到隧道内建连超时 (15s)。失败不缓存, 请求时还会再试。
    if let Some(h) = RUNTIME.get() {
        for outlet in &state.fresh_wg {
            let outlet = outlet.clone();
            h.spawn(async move {
                if let crate::proxy::upstream::UpstreamOutlet::Wireguard(wg) = &*outlet {
                    if let Err(e) = wg.tunnel().await {
                        tracing::warn!("WG 上游出口预热握手失败 (请求时会重试): {e}");
                    }
                }
            });
        }
    }
    slot().store(Some(state));
}

pub fn current_server_router_state() -> Option<Arc<ServerRouterState>> {
    slot().load_full()
}

impl ServerRouterState {
    pub async fn route(
        &self,
        inbound_tag: Option<&str>,
        target: &str,
        protocol: &str,
        client_ip: Option<IpAddr>,
        user: &str,
    ) -> ServerRouteDecision {
        // 1. 选路优先级：入站自己配了 upstream（旧字段，按接入端口指定）→ 用它，不经路由（向后兼容）
        if let Some(ib) = inbound_tag {
            if let Some(outlet) = self.inbound_upstreams.get(ib) {
                let tag = match &**outlet {
                    crate::proxy::upstream::UpstreamOutlet::Shadowsocks(_) => "ss-upstream",
                    crate::proxy::upstream::UpstreamOutlet::Wireguard(_) => "wg-upstream",
                };
                return ServerRouteDecision {
                    tag: tag.to_string(),
                    target: ServerOutboundTarget::Upstream(outlet.clone()),
                };
            }
        }

        // 2. 没有 routing 段或未配置 router 时等价于全部 direct
        let Some(router) = &self.router else {
            return ServerRouteDecision {
                tag: "direct".to_string(),
                target: ServerOutboundTarget::Direct,
            };
        };

        // 3. 服务端路由规则匹配
        let (host, port) = crate::proxy::resolver::split_host_port(target).unwrap_or((target, 0));
        let ip = host.parse::<IpAddr>().ok();
        let domain = if ip.is_none() { Some(host) } else { None };

        let mut req = crate::router::RoutingRequest {
            domain,
            ip,
            port,
            protocol,
            source_ip: client_ip,
            source_mac: None,
            inbound: inbound_tag,
            process_name: None,
            user: Some(user),
        };

        // 先按域名类规则匹配，只有走到 IP 类规则（ip_cidr / geoip）且目标是域名时才解析
        let tag = match router.route_decision(&req) {
            crate::router::RouteDecision::Matched(t) => t,
            crate::router::RouteDecision::Default(t) => t,
            crate::router::RouteDecision::NeedIp => {
                if let Some(d) = domain {
                    if let Ok(sa) = crate::proxy::resolver::resolve_first(d, port).await {
                        req.ip = Some(sa.ip());
                    }
                }
                router.route(req)
            }
        };

        let target_outlet = match self.outbounds.get(&tag) {
            Some(t) => t.clone(),
            None => {
                warn_unroutable(&tag);
                ServerOutboundTarget::Reject
            }
        };
        ServerRouteDecision {
            tag,
            target: target_outlet,
        }
    }
}

/// 入站上旧 `upstream` 字段对应的出口 (当前路由表里那份; 路由表未建时用监听器启动时的)。
/// 监听器侧的预检要读这里, 才能跟上热重载 (入站 upstream 被改 / 迁移成独立出站后立即生效)。
pub fn current_inbound_upstream(
    inbound_tag: Option<&str>,
    fallback: Option<&Arc<crate::proxy::upstream::UpstreamOutlet>>,
) -> Option<Arc<crate::proxy::upstream::UpstreamOutlet>> {
    match current_server_router_state() {
        Some(st) => inbound_tag.and_then(|t| st.inbound_upstreams.get(t).cloned()),
        None => fallback.cloned(),
    }
}

pub async fn server_route(
    inbound_tag: Option<&str>,
    target: &str,
    protocol: &str,
    client_ip: Option<IpAddr>,
    user: &str,
    fallback_upstream: Option<&Arc<crate::proxy::upstream::UpstreamOutlet>>,
) -> ServerRouteDecision {
    if let Some(state) = current_server_router_state() {
        state.route(inbound_tag, target, protocol, client_ip, user).await
    } else if let Some(up) = fallback_upstream {
        let tag = match &**up {
            crate::proxy::upstream::UpstreamOutlet::Shadowsocks(_) => "ss-upstream",
            crate::proxy::upstream::UpstreamOutlet::Wireguard(_) => "wg-upstream",
        };
        ServerRouteDecision {
            tag: tag.to_string(),
            target: ServerOutboundTarget::Upstream((*up).clone()),
        }
    } else {
        ServerRouteDecision {
            tag: "direct".to_string(),
            target: ServerOutboundTarget::Direct,
        }
    }
}

/// 路由选到服务端没有的出站 (只可能是 check 未拦住的配置) —— 限频告警, 每个 tag 60s 一次。
fn warn_unroutable(tag: &str) {
    static LAST: std::sync::Mutex<Option<HashMap<String, std::time::Instant>>> = std::sync::Mutex::new(None);
    let mut g = LAST.lock().unwrap_or_else(|e| e.into_inner());
    let m = g.get_or_insert_with(HashMap::new);
    let now = std::time::Instant::now();
    if m.get(tag).is_some_and(|t| now.duration_since(*t) < std::time::Duration::from_secs(60)) {
        return;
    }
    if m.len() >= 256 {
        m.clear();
    }
    m.insert(tag.to_string(), now);
    tracing::warn!("服务端路由选到出站 `{tag}`, 但它不是服务端可用的出站 (仅支持 direct / block / shadowsocks / wireguard), 拒绝该连接");
}

/// 配置里是否有服务端入站。只有服务端才建服务端路由表: 纯客户端建它既浪费内存 (再载一份
/// geosite), 同进程内还会把服务端已装好的表覆盖掉。
pub fn has_server_inbound(config: &crate::config::Config) -> bool {
    config
        .inbounds
        .iter()
        .any(|ib| matches!(ib, crate::config::InboundConfig::MirageServer { .. }))
}

/// 上游出口: 指纹与旧表相同则复用旧 outlet, 否则新建。
fn outlet_for(
    key: &str,
    fp: String,
    up_cfg: &crate::config::UpstreamConfig,
    prev: Option<&ServerRouterState>,
    fingerprints: &mut HashMap<String, String>,
    built: &mut HashMap<String, Arc<crate::proxy::upstream::UpstreamOutlet>>,
    fresh_wg: &mut Vec<Arc<crate::proxy::upstream::UpstreamOutlet>>,
) -> anyhow::Result<Option<Arc<crate::proxy::upstream::UpstreamOutlet>>> {
    // 按配置指纹 (而非 tag) 在整张旧表里找: 改 tag、旧入站 upstream 迁移成独立出站时也复用,
    // 不会以同一 WG 私钥另起会话。同一份配置在新表里出现多次时也共用一个实例。
    let lookup = |p: &ServerRouterState, k: &str| match k.strip_prefix("inbound:") {
        Some(ib) => p.inbound_upstreams.get(ib).cloned(),
        None => match p.outbounds.get(k) {
            Some(ServerOutboundTarget::Upstream(o)) => Some(o.clone()),
            _ => None,
        },
    };
    let reused = prev.and_then(|p| {
        p.fingerprints.iter().find(|(_, f)| **f == fp).and_then(|(k, _)| lookup(p, k))
    });
    fingerprints.insert(key.to_string(), fp.clone());
    if let Some(o) = built.get(&fp) {
        return Ok(Some(o.clone()));
    }
    let outlet = match reused {
        Some(o) => Some(o),
        None => {
            let o = crate::build_upstream(Some(up_cfg))?;
            if let Some(o) = o.as_ref().filter(|o| matches!(***o, crate::proxy::upstream::UpstreamOutlet::Wireguard(_))) {
                fresh_wg.push(o.clone());
            }
            o
        }
    };
    if let Some(o) = &outlet {
        built.insert(fp, o.clone());
    }
    Ok(outlet)
}

/// 上游配置指纹 (含口令 / 私钥, 只在内存里比较, 不落日志)。
fn upstream_fingerprint(up: &crate::config::UpstreamConfig) -> String {
    match up {
        crate::config::UpstreamConfig::Shadowsocks { server, server_port, password, method, udp } => {
            format!("ss|{server}|{server_port}|{password}|{method}|{udp:?}")
        }
        crate::config::UpstreamConfig::Wireguard {
            private_key, peer_public_key, preshared_key, endpoint, address, mtu, persistent_keepalive, udp, dns,
        } => format!(
            "wg|{private_key}|{peer_public_key}|{preshared_key:?}|{endpoint}|{address}|{mtu:?}|{persistent_keepalive:?}|{udp:?}|{dns:?}"
        ),
    }
}

/// 由配置构建服务端出站表与路由。`prev` = 热重载前的旧表 (复用配置未变的上游出口)。
pub fn build_server_router_state(
    config: &crate::config::Config,
    geodata_dir: &str,
    prev: Option<&ServerRouterState>,
) -> anyhow::Result<ServerRouterState> {
    let mut fingerprints = HashMap::new();
    let mut built = HashMap::new();
    let mut fresh_wg = Vec::new();
    // 1. 构建入站级旧 upstream 映射表 (按 inbound tag)
    let mut inbound_upstreams = HashMap::new();
    for ib in &config.inbounds {
        if let crate::config::InboundConfig::MirageServer { tag, upstream: Some(up_cfg), .. } = ib {
            let key = format!("inbound:{tag}");
            if let Some(outlet) = outlet_for(&key, upstream_fingerprint(up_cfg), up_cfg, prev, &mut fingerprints, &mut built, &mut fresh_wg)? {
                inbound_upstreams.insert(tag.clone(), outlet);
            }
        }
    }

    // 2. 构建顶层 outbounds 表
    let mut outbounds = HashMap::new();
    for ob in &config.outbounds {
        match ob {
            crate::config::OutboundConfig::Direct { tag } => {
                outbounds.insert(tag.clone(), ServerOutboundTarget::Direct);
            }
            crate::config::OutboundConfig::Block { tag } => {
                outbounds.insert(tag.clone(), ServerOutboundTarget::Reject);
            }
            crate::config::OutboundConfig::Shadowsocks {
                tag,
                server,
                server_port,
                method,
                password,
                udp,
                ..
            } => {
                let up_cfg = crate::config::UpstreamConfig::Shadowsocks {
                    server: server.clone(),
                    server_port: *server_port,
                    password: password.clone(),
                    method: method.clone(),
                    udp: udp.unwrap_or(crate::config::UdpPolicy::Block),
                };
                if let Some(outlet) = outlet_for(tag, upstream_fingerprint(&up_cfg), &up_cfg, prev, &mut fingerprints, &mut built, &mut fresh_wg)? {
                    outbounds.insert(tag.clone(), ServerOutboundTarget::Upstream(outlet));
                }
            }
            crate::config::OutboundConfig::Wireguard {
                tag,
                endpoint,
                address,
                private_key,
                peer_public_key,
                preshared_key,
                mtu,
                persistent_keepalive,
                dns,
                udp,
            } => {
                let up_cfg = crate::config::UpstreamConfig::Wireguard {
                    private_key: private_key.clone(),
                    peer_public_key: peer_public_key.clone(),
                    preshared_key: preshared_key.clone(),
                    endpoint: endpoint.clone(),
                    address: address.clone(),
                    mtu: *mtu,
                    persistent_keepalive: *persistent_keepalive,
                    udp: udp.unwrap_or(crate::config::UdpPolicy::Tunnel),
                    dns: dns.clone(),
                };
                if let Some(outlet) = outlet_for(tag, upstream_fingerprint(&up_cfg), &up_cfg, prev, &mut fingerprints, &mut built, &mut fresh_wg)? {
                    outbounds.insert(tag.clone(), ServerOutboundTarget::Upstream(outlet));
                }
            }
            _ => {}
        }
    }

    // 3. 构建路由引擎。服务端只能用 direct / block / shadowsocks / wireguard 出站 (见 outbounds 表)。
    //    - 混合配置 (同时有客户端入站, 共用一份 routing): 只采用 `inbound` 明确限定到服务端入站的
    //      规则; 默认出站服务端用不了 (如客户端的 proxy) 时按直连 —— 这份 routing 主要是给客户端写的。
    //    - 旧配置 (顶层没有 SS / WG 出站, 从没用过服务端出站): 路由有问题时整体忽略、全部直连,
    //      即 v0.16 之前服务端的行为 (那时服务端不读 routing), 升级不至于突然全拒。
    //    - 其余 (用了服务端出站的配置): 引用未定义 / 服务端用不了的出站、非法 CIDR 都是配置错误,
    //      返回 Err —— 冷启动报错退出, 热重载拒绝并保留旧表 (见 ConfigWatcher::build_state)。
    let server_tags: Vec<&str> = config
        .inbounds
        .iter()
        .filter_map(|ib| match ib {
            crate::config::InboundConfig::MirageServer { tag, .. } => Some(tag.as_str()),
            _ => None,
        })
        .collect();
    let mixed = server_tags.len() < config.inbounds.len();
    let legacy = !outbounds.values().any(|t| matches!(t, ServerOutboundTarget::Upstream(_)));
    let usable = |t: &str| outbounds.contains_key(t);

    let rule_cfgs: Vec<&crate::config::RuleConfig> = config
        .routing
        .rules
        .iter()
        .filter(|r| !mixed || r.inbound.iter().any(|ib| server_tags.contains(&ib.as_str())))
        .collect();
    let mut problems: Vec<String> = Vec::new();
    let default_outbound = if usable(&config.routing.default_outbound) {
        config.routing.default_outbound.clone()
    } else if mixed {
        "direct".to_string()
    } else {
        problems.push(format!(
            "routing.default_outbound = `{}` 不是服务端可用的出站 (未定义, 或不是 direct / block / shadowsocks / wireguard)",
            config.routing.default_outbound
        ));
        "direct".to_string()
    };
    for r in &rule_cfgs {
        if !usable(&r.outbound) {
            problems.push(format!(
                "规则引用的出站 `{}` 不是服务端可用的出站 (未定义, 或不是 direct / block / shadowsocks / wireguard)",
                r.outbound
            ));
        }
    }
    let mut rules = Vec::new();
    for (i, r) in rule_cfgs.iter().enumerate() {
        let ip_cidr = match crate::router::parse_ip_nets(&r.ip_cidr) {
            Ok(v) => v,
            Err(bad) => {
                problems.push(format!("规则 ip_cidr 含非法项 `{bad}`"));
                continue;
            }
        };
        let src_cidrs = match crate::router::parse_ip_nets(&r.source_ip_cidr) {
            Ok(v) => v,
            Err(bad) => {
                problems.push(format!("规则 source_ip_cidr 含非法项 `{bad}`"));
                continue;
            }
        };
        rules.push(crate::router::Rule {
            id: i,
            mode: match r.mode {
                Some(crate::config::RuleMode::And) => "and",
                _ => "or",
            }.to_string(),
            outbound: r.outbound.clone(),
            domain_suffix: r.domain_suffix.clone(),
            domain_keyword: r.domain_keyword.clone(),
            domain_regex: r.domain_regex.clone(),
            geosite: r.geosite.clone(),
            ip_cidr,
            geoip: r.geoip.clone(),
            source_ip_cidr: src_cidrs,
            source_mac: r.source_mac.clone(),
            protocol: r.protocol.clone(),
            port: r.port.clone(),
            inbound: r.inbound.clone(),
            process_name: r.process_name.clone(),
            user: r.user.clone(),
        });
    }

    let router = if !problems.is_empty() {
        if legacy {
            tracing::warn!(
                "服务端路由配置有问题, 且未配置任何上游出站: 按旧版行为忽略 routing、全部直连。问题: {}",
                problems.join("; ")
            );
            None
        } else {
            anyhow::bail!("服务端路由配置无效: {}", problems.join("; "));
        }
    } else if rules.is_empty() && default_outbound == "direct" {
        None // 无规则且默认直连: 不建路由引擎 (省一份 geosite), 全部直连
    } else {
        Some(Arc::new(crate::router::RouterEngine::new(
            rules,
            default_outbound.clone(),
            geodata_dir,
            &config.routing.geo_alias,
        )?))
    };

    info!(
        "服务端出站表构建完成: {} 个出站 (旧 upstream 入站 {} 个), 默认出站 `{}`",
        outbounds.len(),
        inbound_upstreams.len(),
        default_outbound
    );

    Ok(ServerRouterState {
        router,
        outbounds,
        inbound_upstreams,
        default_outbound,
        fingerprints,
        fresh_wg,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;

    #[tokio::test]
    async fn test_mode_one_default_direct_with_rules() {
        let json = r#"{
            "inbounds": [
                { "type": "mirage_server", "tag": "srv", "listen": "127.0.0.1", "port": 1443, "password": "pass123456789012" }
            ],
            "outbounds": [
                { "type": "direct", "tag": "direct" },
                {
                    "type": "shadowsocks",
                    "tag": "ss-out",
                    "server": "192.0.2.1",
                    "server_port": 8388,
                    "method": "chacha20-ietf-poly1305",
                    "password": "sspassword"
                }
            ],
            "routing": {
                "default_outbound": "direct",
                "rules": [
                    { "domain_suffix": ["example.com"], "outbound": "ss-out" }
                ]
            }
        }"#;
        let (cfg, _) = Config::parse_with_diagnostics(json).unwrap();
        let state = build_server_router_state(&cfg, "", None).unwrap();

        // 命中规则 -> ss-out
        let dec1 = state.route(Some("srv"), "example.com:443", "tcp", None, "default").await;
        assert_eq!(dec1.tag, "ss-out");
        assert!(matches!(dec1.target, ServerOutboundTarget::Upstream(_)));

        // 未命中规则 -> direct (默认出站)
        let dec2 = state.route(Some("srv"), "other.test:80", "tcp", None, "default").await;
        assert_eq!(dec2.tag, "direct");
        assert!(matches!(dec2.target, ServerOutboundTarget::Direct));
    }

    #[tokio::test]
    async fn test_mode_two_default_upstream_with_direct_rule() {
        let json = r#"{
            "inbounds": [
                { "type": "mirage_server", "tag": "srv", "listen": "127.0.0.1", "port": 1443, "password": "pass123456789012" }
            ],
            "outbounds": [
                { "type": "direct", "tag": "direct" },
                {
                    "type": "shadowsocks",
                    "tag": "ss-out",
                    "server": "192.0.2.1",
                    "server_port": 8388,
                    "method": "chacha20-ietf-poly1305",
                    "password": "sspassword"
                }
            ],
            "routing": {
                "default_outbound": "ss-out",
                "rules": [
                    { "ip_cidr": ["198.51.100.0/24"], "outbound": "direct" }
                ]
            }
        }"#;
        let (cfg, _) = Config::parse_with_diagnostics(json).unwrap();
        let state = build_server_router_state(&cfg, "", None).unwrap();

        // 命中直连规则 -> direct
        let dec1 = state.route(Some("srv"), "198.51.100.22:443", "tcp", None, "default").await;
        assert_eq!(dec1.tag, "direct");
        assert!(matches!(dec1.target, ServerOutboundTarget::Direct));

        // 未命中规则 -> ss-out (默认出站)
        let dec2 = state.route(Some("srv"), "203.0.113.88:80", "tcp", None, "default").await;
        assert_eq!(dec2.tag, "ss-out");
        assert!(matches!(dec2.target, ServerOutboundTarget::Upstream(_)));
    }

    #[tokio::test]
    async fn test_legacy_inbound_upstream_priority() {
        let json = r#"{
            "inbounds": [
                {
                    "type": "mirage_server",
                    "tag": "legacy-srv",
                    "listen": "127.0.0.1",
                    "port": 1443,
                    "password": "pass123456789012",
                    "upstream": {
                        "type": "shadowsocks",
                        "server": "192.0.2.2",
                        "server_port": 8388,
                        "method": "chacha20-ietf-poly1305",
                        "password": "sspassword"
                    }
                },
                {
                    "type": "mirage_server",
                    "tag": "normal-srv",
                    "listen": "127.0.0.1",
                    "port": 1444,
                    "password": "pass123456789012"
                }
            ],
            "outbounds": [
                { "type": "direct", "tag": "direct" }
            ],
            "routing": {
                "default_outbound": "direct",
                "rules": [
                    { "domain_suffix": ["example.com"], "outbound": "direct" }
                ]
            }
        }"#;
        let (cfg, _) = Config::parse_with_diagnostics(json).unwrap();
        let state = build_server_router_state(&cfg, "", None).unwrap();

        // legacy-srv 入站配置了 upstream: 即使目标匹配了 direct 规则, 也不走路由, 依然走其 legacy upstream
        let dec1 = state.route(Some("legacy-srv"), "example.com:443", "tcp", None, "default").await;
        assert_eq!(dec1.tag, "ss-upstream");
        assert!(matches!(dec1.target, ServerOutboundTarget::Upstream(_)));

        // normal-srv 入站无 upstream: 走常规路由 -> direct
        let dec2 = state.route(Some("normal-srv"), "example.com:443", "tcp", None, "default").await;
        assert_eq!(dec2.tag, "direct");
        assert!(matches!(dec2.target, ServerOutboundTarget::Direct));
    }

    #[tokio::test]
    async fn test_user_routing_rule() {
        let json = r#"{
            "inbounds": [
                {
                    "type": "mirage_server",
                    "tag": "srv",
                    "listen": "127.0.0.1",
                    "port": 1443,
                    "password": "pass123456789012",
                    "users": [
                        { "name": "alice", "password": "alicepassword12345" },
                        { "name": "bob", "password": "bobpassword12345678" }
                    ]
                }
            ],
            "outbounds": [
                { "type": "direct", "tag": "direct" },
                {
                    "type": "shadowsocks",
                    "tag": "ss-vip",
                    "server": "192.0.2.1",
                    "server_port": 8388,
                    "method": "chacha20-ietf-poly1305",
                    "password": "sspassword"
                }
            ],
            "routing": {
                "default_outbound": "direct",
                "rules": [
                    { "user": ["alice"], "outbound": "ss-vip" }
                ]
            }
        }"#;
        let (cfg, _) = Config::parse_with_diagnostics(json).unwrap();
        let state = build_server_router_state(&cfg, "", None).unwrap();

        // alice 走 vip 上游
        let dec_alice = state.route(Some("srv"), "example.com:443", "tcp", None, "alice").await;
        assert_eq!(dec_alice.tag, "ss-vip");

        // bob 走默认 direct
        let dec_bob = state.route(Some("srv"), "example.com:443", "tcp", None, "bob").await;
        assert_eq!(dec_bob.tag, "direct");

        // default 用户走默认 direct
        let dec_def = state.route(Some("srv"), "example.com:443", "tcp", None, "default").await;
        assert_eq!(dec_def.tag, "direct");
    }

    #[tokio::test]
    async fn test_multiple_upstreams_routing() {
        let json = r#"{
            "inbounds": [
                { "type": "mirage_server", "tag": "srv", "listen": "127.0.0.1", "port": 1443, "password": "pass123456789012" }
            ],
            "outbounds": [
                { "type": "direct", "tag": "direct" },
                {
                    "type": "shadowsocks",
                    "tag": "ss-us",
                    "server": "192.0.2.1",
                    "server_port": 8388,
                    "method": "chacha20-ietf-poly1305",
                    "password": "sspassword"
                },
                {
                    "type": "shadowsocks",
                    "tag": "ss-jp",
                    "server": "192.0.2.2",
                    "server_port": 8388,
                    "method": "chacha20-ietf-poly1305",
                    "password": "sspassword"
                }
            ],
            "routing": {
                "default_outbound": "direct",
                "rules": [
                    { "domain_suffix": ["us.example"], "outbound": "ss-us" },
                    { "domain_suffix": ["jp.example"], "outbound": "ss-jp" }
                ]
            }
        }"#;
        let (cfg, _) = Config::parse_with_diagnostics(json).unwrap();
        let state = build_server_router_state(&cfg, "", None).unwrap();

        let dec1 = state.route(Some("srv"), "test.us.example:443", "tcp", None, "default").await;
        assert_eq!(dec1.tag, "ss-us");

        let dec2 = state.route(Some("srv"), "test.jp.example:443", "tcp", None, "default").await;
        assert_eq!(dec2.tag, "ss-jp");

        let dec3 = state.route(Some("srv"), "other.example:443", "tcp", None, "default").await;
        assert_eq!(dec3.tag, "direct");
    }

    #[tokio::test]
    async fn test_no_routing_section_defaults_to_direct() {
        let json = r#"{
            "inbounds": [
                { "type": "mirage_server", "tag": "srv", "listen": "127.0.0.1", "port": 1443, "password": "pass123456789012" }
            ]
        }"#;
        let (cfg, _) = Config::parse_with_diagnostics(json).unwrap();
        let state = build_server_router_state(&cfg, "", None).unwrap();

        let dec = state.route(Some("srv"), "example.com:443", "tcp", None, "default").await;
        assert_eq!(dec.tag, "direct");
        assert!(matches!(dec.target, ServerOutboundTarget::Direct));
    }

    #[tokio::test]
    async fn test_server_router_hot_reload() {
        let json_v1 = r#"{
            "inbounds": [
                { "type": "mirage_server", "tag": "srv", "listen": "127.0.0.1", "port": 1443, "password": "pass123456789012" }
            ],
            "outbounds": [
                { "type": "direct", "tag": "direct" },
                { "type": "shadowsocks", "tag": "ss-up", "server": "192.0.2.1", "server_port": 8388, "method": "aes-128-gcm", "password": "testpassword12345" }
            ],
            "routing": {
                "default_outbound": "direct",
                "rules": [
                    { "domain_suffix": ["example.com"], "outbound": "ss-up" }
                ]
            }
        }"#;
        let (cfg1, _) = Config::parse_with_diagnostics(json_v1).unwrap();
        let state1 = build_server_router_state(&cfg1, "", None).unwrap();
        set_server_router_state(Arc::new(state1));

        let dec1 = server_route(Some("srv"), "example.com:443", "tcp", None, "default", None).await;
        assert_eq!(dec1.tag, "ss-up");

        // 热重载为 v2：default 改为 direct，规则把 example.com 导向 direct
        let json_v2 = r#"{
            "inbounds": [
                { "type": "mirage_server", "tag": "srv", "listen": "127.0.0.1", "port": 1443, "password": "pass123456789012" }
            ],
            "outbounds": [
                { "type": "direct", "tag": "direct" }
            ],
            "routing": {
                "default_outbound": "direct",
                "rules": []
            }
        }"#;
        let (cfg2, _) = Config::parse_with_diagnostics(json_v2).unwrap();
        let state2 = build_server_router_state(&cfg2, "", None).unwrap();
        set_server_router_state(Arc::new(state2));

        let dec2 = server_route(Some("srv"), "example.com:443", "tcp", None, "default", None).await;
        assert_eq!(dec2.tag, "direct");
    }

    #[tokio::test]
    async fn test_server_router_domain_matched_without_dns() {
        let json = r#"{
            "inbounds": [
                { "type": "mirage_server", "tag": "srv", "listen": "127.0.0.1", "port": 1443, "password": "pass123456789012" }
            ],
            "outbounds": [
                { "type": "direct", "tag": "direct" },
                { "type": "shadowsocks", "tag": "ss-up", "server": "192.0.2.1", "server_port": 8388, "method": "aes-128-gcm", "password": "testpassword12345" }
            ],
            "routing": {
                "default_outbound": "direct",
                "rules": [
                    { "domain_suffix": ["nonexistent-domain-test.example"], "outbound": "ss-up" },
                    { "ip_cidr": ["192.0.2.0/24"], "outbound": "ss-up" }
                ]
            }
        }"#;
        let (cfg, _) = Config::parse_with_diagnostics(json).unwrap();
        let state = build_server_router_state(&cfg, "", None).unwrap();

        // 目标为域名，第一条规则是域名后缀规则，即使不存在该域名也不会进行 DNS 解析，直接命中
        let dec = state.route(Some("srv"), "sub.nonexistent-domain-test.example:443", "tcp", None, "default").await;
        assert_eq!(dec.tag, "ss-up");
    }

    fn ss_cfg(pw: &str) -> String {
        format!(r#"{{
            "inbounds": [
                {{ "type": "mirage_server", "tag": "srv", "listen": "127.0.0.1", "port": 1443, "password": "pass123456789012" }}
            ],
            "outbounds": [
                {{ "type": "direct", "tag": "direct" }},
                {{ "type": "block", "tag": "reject" }},
                {{ "type": "shadowsocks", "tag": "ss-up", "server": "192.0.2.1", "server_port": 8388, "method": "aes-128-gcm", "password": "{pw}" }}
            ],
            "routing": {{
                "default_outbound": "direct",
                "rules": [
                    {{ "domain_suffix": ["blocked.example"], "outbound": "reject" }},
                    {{ "ip_cidr": ["198.51.100.7"], "outbound": "ss-up" }}
                ]
            }}
        }}"#)
    }

    fn up_tag(st: &ServerRouterState, tag: &str) -> Arc<crate::proxy::upstream::UpstreamOutlet> {
        match st.outbounds.get(tag) {
            Some(ServerOutboundTarget::Upstream(o)) => o.clone(),
            _ => panic!("{tag} 应是上游出口"),
        }
    }

    #[tokio::test]
    async fn test_block_rejects_and_bare_ip_rule_is_not_match_all() {
        let (cfg, _) = Config::parse_with_diagnostics(&ss_cfg("testpassword12345")).unwrap();
        let state = build_server_router_state(&cfg, "", None).unwrap();
        let d = state.route(Some("srv"), "a.blocked.example:443", "tcp", None, "default").await;
        assert!(matches!(d.target, ServerOutboundTarget::Reject), "block 出站必须拒绝");
        // 裸 IP 规则按 /32: 只命中该 IP, 不能因解析失败退化成"匹配所有"
        let d = state.route(Some("srv"), "198.51.100.7:443", "tcp", None, "default").await;
        assert_eq!(d.tag, "ss-up");
        let d = state.route(Some("srv"), "198.51.100.8:443", "tcp", None, "default").await;
        assert_eq!(d.tag, "direct");
    }

    #[test]
    fn test_invalid_routing_rejected_when_upstreams_configured() {
        let base: serde_json::Value = serde_json::from_str(&ss_cfg("testpassword12345")).unwrap();
        let build = |v: &serde_json::Value| {
            let (cfg, _) = Config::parse_with_diagnostics(&v.to_string()).unwrap();
            build_server_router_state(&cfg, "", None)
        };
        // 引用未定义的出站
        let mut v = base.clone();
        v["routing"]["rules"][1]["outbound"] = serde_json::json!("no-such");
        assert!(build(&v).is_err(), "引用未定义出站应报错 (热重载据此拒绝)");
        // 默认出站服务端用不了 (mirage)
        let mut v = base.clone();
        v["outbounds"].as_array_mut().unwrap().push(serde_json::json!(
            { "type": "mirage", "tag": "m", "server": "192.0.2.9", "server_port": 443, "password": "p", "camouflage_host": "example.com" }));
        v["routing"]["default_outbound"] = serde_json::json!("m");
        assert!(build(&v).is_err(), "默认出站不可用应报错");
        // 非法 CIDR
        let mut v = base.clone();
        v["routing"]["rules"][1]["ip_cidr"] = serde_json::json!(["10.0.0.0/33"]);
        assert!(build(&v).is_err(), "非法 CIDR 应报错, 不能静默丢弃");
    }

    #[tokio::test]
    async fn test_legacy_config_with_bad_routing_stays_direct() {
        // 旧服务端配置 (未配任何上游出站) 里残留从客户端抄来的 routing: 按 v0.16 前行为全部直连
        let json = r#"{
            "inbounds": [ { "type": "mirage_server", "tag": "srv", "listen": "127.0.0.1", "port": 1443, "password": "pass123456789012" } ],
            "outbounds": [ { "type": "direct", "tag": "direct" } ],
            "routing": { "default_outbound": "proxy", "rules": [ { "geosite": ["cn"], "outbound": "direct" } ] }
        }"#;
        let (cfg, _) = Config::parse_with_diagnostics(json).unwrap();
        let state = build_server_router_state(&cfg, "", None).unwrap();
        let d = state.route(Some("srv"), "example.com:443", "tcp", None, "default").await;
        assert!(matches!(d.target, ServerOutboundTarget::Direct));
    }

    #[tokio::test]
    async fn test_mixed_config_only_server_scoped_rules() {
        // 同一进程既是客户端 (socks + mirage 出站) 又是服务端: 共用的 routing 主要给客户端
        let json = r#"{
            "inbounds": [
                { "type": "socks", "tag": "s", "listen": "127.0.0.1", "port": 1080 },
                { "type": "mirage_server", "tag": "srv", "listen": "127.0.0.1", "port": 1443, "password": "pass123456789012" }
            ],
            "outbounds": [
                { "type": "direct", "tag": "direct" },
                { "type": "block", "tag": "reject" },
                { "type": "mirage", "tag": "proxy", "server": "192.0.2.9", "server_port": 443, "password": "p", "camouflage_host": "example.com" },
                { "type": "shadowsocks", "tag": "ss-up", "server": "192.0.2.1", "server_port": 8388, "method": "aes-128-gcm", "password": "testpassword12345" }
            ],
            "routing": { "default_outbound": "proxy", "rules": [
                { "domain_suffix": ["ads.example"], "outbound": "reject" },
                { "inbound": ["srv"], "domain_suffix": ["up.example"], "outbound": "ss-up" }
            ] }
        }"#;
        let (cfg, _) = Config::parse_with_diagnostics(json).unwrap();
        let state = build_server_router_state(&cfg, "", None).unwrap();
        // 限定到服务端入站的规则生效
        assert_eq!(state.route(Some("srv"), "a.up.example:443", "tcp", None, "default").await.tag, "ss-up");
        // 客户端规则 (未限定入站) 不作用于服务端; 客户端默认出站 proxy 服务端用不了 → 直连
        let d = state.route(Some("srv"), "x.ads.example:443", "tcp", None, "default").await;
        assert!(matches!(d.target, ServerOutboundTarget::Direct), "客户端规则不应作用于服务端");
    }

    #[tokio::test]
    async fn test_reload_reuses_unchanged_upstream_outlet() {
        let (c1, _) = Config::parse_with_diagnostics(&ss_cfg("testpassword12345")).unwrap();
        let s1 = build_server_router_state(&c1, "", None).unwrap();
        // 配置未变 → 复用同一 outlet (WG 不会以同一私钥另起会话)
        let s2 = build_server_router_state(&c1, "", Some(&s1)).unwrap();
        assert!(Arc::ptr_eq(&up_tag(&s1, "ss-up"), &up_tag(&s2, "ss-up")), "配置未变的上游出口应复用");
        // 只改 tag (如旧入站 upstream 迁移成独立出站) → 按指纹仍复用
        let renamed = ss_cfg("testpassword12345").replace("ss-up", "ss-renamed");
        let (c3, _) = Config::parse_with_diagnostics(&renamed).unwrap();
        let s3 = build_server_router_state(&c3, "", Some(&s2)).unwrap();
        assert!(Arc::ptr_eq(&up_tag(&s2, "ss-up"), &up_tag(&s3, "ss-renamed")), "改 tag 应按指纹复用");
        // 口令变了 → 新建
        let (c4, _) = Config::parse_with_diagnostics(&ss_cfg("otherpassword6789")).unwrap();
        let s4 = build_server_router_state(&c4, "", Some(&s2)).unwrap();
        assert!(!Arc::ptr_eq(&up_tag(&s2, "ss-up"), &up_tag(&s4, "ss-up")), "配置变化的上游出口应重建");
    }

    #[test]
    fn test_same_upstream_config_built_once() {
        // 入站旧 upstream 与顶层出站是同一份配置: 只建一个实例 (WG 同私钥两会话会互踢)
        let json = r#"{
            "inbounds": [ { "type": "mirage_server", "tag": "srv", "listen": "127.0.0.1", "port": 1443, "password": "pass123456789012",
                "upstream": { "type": "shadowsocks", "server": "192.0.2.1", "server_port": 8388, "method": "aes-128-gcm", "password": "testpassword12345" } } ],
            "outbounds": [ { "type": "direct", "tag": "direct" },
                { "type": "shadowsocks", "tag": "ss-up", "server": "192.0.2.1", "server_port": 8388, "method": "aes-128-gcm", "password": "testpassword12345" } ],
            "routing": { "default_outbound": "direct", "rules": [] }
        }"#;
        let (cfg, _) = Config::parse_with_diagnostics(json).unwrap();
        let st = build_server_router_state(&cfg, "", None).unwrap();
        assert!(Arc::ptr_eq(st.inbound_upstreams.get("srv").unwrap(), &up_tag(&st, "ss-up")));
    }

    #[test]
    fn test_has_server_inbound_only_for_server_configs() {
        let (srv, _) = Config::parse_with_diagnostics(&ss_cfg("testpassword12345")).unwrap();
        assert!(has_server_inbound(&srv));
        let client = r#"{
            "inbounds": [ { "type": "socks", "tag": "s", "listen": "127.0.0.1", "port": 1080 } ],
            "outbounds": [ { "type": "direct", "tag": "direct" } ],
            "routing": { "default_outbound": "direct", "rules": [] }
        }"#;
        let (cli, _) = Config::parse_with_diagnostics(client).unwrap();
        assert!(!has_server_inbound(&cli), "纯客户端配置不应建服务端路由表");
    }
}
