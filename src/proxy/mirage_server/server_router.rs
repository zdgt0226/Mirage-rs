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
}

static SERVER_ROUTER: OnceLock<ArcSwapOption<ServerRouterState>> = OnceLock::new();

fn slot() -> &'static ArcSwapOption<ServerRouterState> {
    SERVER_ROUTER.get_or_init(|| ArcSwapOption::from(None))
}

pub fn set_server_router_state(state: Arc<ServerRouterState>) {
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
) -> anyhow::Result<Option<Arc<crate::proxy::upstream::UpstreamOutlet>>> {
    let reused = prev.and_then(|p| {
        if p.fingerprints.get(key) != Some(&fp) {
            return None;
        }
        match key.strip_prefix("inbound:") {
            Some(ib) => p.inbound_upstreams.get(ib).cloned(),
            None => match p.outbounds.get(key) {
                Some(ServerOutboundTarget::Upstream(o)) => Some(o.clone()),
                _ => None,
            },
        }
    });
    fingerprints.insert(key.to_string(), fp);
    match reused {
        Some(o) => Ok(Some(o)),
        None => crate::build_upstream(Some(up_cfg)),
    }
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
    // 1. 构建入站级旧 upstream 映射表 (按 inbound tag)
    let mut inbound_upstreams = HashMap::new();
    for ib in &config.inbounds {
        if let crate::config::InboundConfig::MirageServer { tag, upstream: Some(up_cfg), .. } = ib {
            let key = format!("inbound:{tag}");
            if let Some(outlet) = outlet_for(&key, upstream_fingerprint(up_cfg), up_cfg, prev, &mut fingerprints)? {
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
                if let Some(outlet) = outlet_for(tag, upstream_fingerprint(&up_cfg), &up_cfg, prev, &mut fingerprints)? {
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
            } => {
                let up_cfg = crate::config::UpstreamConfig::Wireguard {
                    private_key: private_key.clone(),
                    peer_public_key: peer_public_key.clone(),
                    preshared_key: preshared_key.clone(),
                    endpoint: endpoint.clone(),
                    address: address.clone(),
                    mtu: *mtu,
                    persistent_keepalive: *persistent_keepalive,
                    udp: crate::config::UdpPolicy::Tunnel,
                    dns: dns.clone(),
                };
                if let Some(outlet) = outlet_for(tag, upstream_fingerprint(&up_cfg), &up_cfg, prev, &mut fingerprints)? {
                    outbounds.insert(tag.clone(), ServerOutboundTarget::Upstream(outlet));
                }
            }
            _ => {}
        }
    }

    // 3. 构建路由引擎 (若有 outbounds 且配置了 routing)
    let router = if !outbounds.is_empty() || !config.routing.rules.is_empty() || config.routing.default_outbound != "direct" {
        let mut rules = Vec::new();
        for (i, r) in config.routing.rules.iter().enumerate() {
            let mut ip_cidr = Vec::new();
            for c in &r.ip_cidr {
                if let Ok(net) = c.parse() {
                    ip_cidr.push(net);
                }
            }
            let mut src_cidrs = Vec::new();
            for c in &r.source_ip_cidr {
                if let Ok(net) = c.parse() {
                    src_cidrs.push(net);
                }
            }
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
        let engine = crate::router::RouterEngine::new(
            rules,
            config.routing.default_outbound.clone(),
            geodata_dir,
            &config.routing.geo_alias,
        )?;
        Some(Arc::new(engine))
    } else {
        None
    };

    info!(
        "服务端出站表构建完成: {} 个出站 (旧 upstream 入站 {} 个), 默认出站 `{}`",
        outbounds.len(),
        inbound_upstreams.len(),
        config.routing.default_outbound
    );

    Ok(ServerRouterState {
        router,
        outbounds,
        inbound_upstreams,
        default_outbound: config.routing.default_outbound.clone(),
        fingerprints,
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
                {{ "type": "mirage", "tag": "m", "server": "192.0.2.9", "server_port": 443, "password": "p", "camouflage_host": "example.com" }},
                {{ "type": "shadowsocks", "tag": "ss-up", "server": "192.0.2.1", "server_port": 8388, "method": "aes-128-gcm", "password": "{pw}" }}
            ],
            "routing": {{
                "default_outbound": "direct",
                "rules": [
                    {{ "domain_suffix": ["blocked.example"], "outbound": "reject" }},
                    {{ "domain_suffix": ["client-only.example"], "outbound": "m" }},
                    {{ "domain_suffix": ["up.example"], "outbound": "ss-up" }}
                ]
            }}
        }}"#)
    }

    #[tokio::test]
    async fn test_block_and_unusable_outbound_reject_never_direct() {
        let (cfg, _) = Config::parse_with_diagnostics(&ss_cfg("testpassword12345")).unwrap();
        let state = build_server_router_state(&cfg, "", None).unwrap();
        let d = state.route(Some("srv"), "a.blocked.example:443", "tcp", None, "default").await;
        assert!(matches!(d.target, ServerOutboundTarget::Reject), "block 出站必须拒绝");
        // 选到服务端不可用的出站 (mirage): 拒绝, 不能回落直连
        let d = state.route(Some("srv"), "a.client-only.example:443", "tcp", None, "default").await;
        assert!(matches!(d.target, ServerOutboundTarget::Reject), "不可用出站必须拒绝而非直连");
    }

    #[tokio::test]
    async fn test_reload_reuses_unchanged_upstream_outlet() {
        let (c1, _) = Config::parse_with_diagnostics(&ss_cfg("testpassword12345")).unwrap();
        let s1 = build_server_router_state(&c1, "", None).unwrap();
        let o1 = match s1.outbounds.get("ss-up") { Some(ServerOutboundTarget::Upstream(o)) => o.clone(), _ => panic!() };
        // 配置未变 → 复用同一 outlet (WG 不会以同一私钥另起会话)
        let s2 = build_server_router_state(&c1, "", Some(&s1)).unwrap();
        let o2 = match s2.outbounds.get("ss-up") { Some(ServerOutboundTarget::Upstream(o)) => o.clone(), _ => panic!() };
        assert!(Arc::ptr_eq(&o1, &o2), "配置未变的上游出口应复用");
        // 口令变了 → 新建
        let (c3, _) = Config::parse_with_diagnostics(&ss_cfg("otherpassword6789")).unwrap();
        let s3 = build_server_router_state(&c3, "", Some(&s2)).unwrap();
        let o3 = match s3.outbounds.get("ss-up") { Some(ServerOutboundTarget::Upstream(o)) => o.clone(), _ => panic!() };
        assert!(!Arc::ptr_eq(&o2, &o3), "配置变化的上游出口应重建");
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
