use crate::proxy::pool::{WarmPool, PoolConfig};
use std::sync::RwLock;
use std::collections::HashMap;
use std::sync::Arc;
use tracing::info;
use crate::config::{Config, OutboundConfig};

pub enum OutboundNode {
    Mirage {
        tag: String,
        pool: Arc<WarmPool>,
        server_host: String,
        server_port: u16,
        server_ip: Arc<RwLock<Option<std::net::IpAddr>>>,
        rtt_ms: Arc<std::sync::atomic::AtomicU64>,
        snd_cwnd: Arc<std::sync::atomic::AtomicU64>,
        total_retrans: Arc<std::sync::atomic::AtomicU64>,
        total_segs_out: Arc<std::sync::atomic::AtomicU64>,
    },
    /// WireGuard 出站。隧道**懒初始化**: 没流量路由过来就不建, 免得白起一个
    /// pump 任务反复发握手。
    Wireguard {
        tag: String,
        cfg: Arc<crate::proxy::wg::WgConfig>,
        tunnel: tokio::sync::OnceCell<Arc<crate::proxy::wg::tunnel::WgTunnel>>,
    },
    Direct {
        tag: String,
    },
    Block {
        tag: String,
    },
    Urltest {
        tag: String,
        children: Vec<Arc<OutboundNode>>,
        tolerance_ms: u64,
        test_type: String,
        current: Arc<RwLock<Option<Arc<OutboundNode>>>>,
    },
    Fallback {
        tag: String,
        children: Vec<Arc<OutboundNode>>,
    },
    Selector {
        tag: String,
        children: Vec<Arc<OutboundNode>>,
        current: Arc<RwLock<Option<Arc<OutboundNode>>>>,
    },
}

impl OutboundNode {
    pub fn tag(&self) -> &str {
        match self {
            Self::Mirage { tag, .. } => tag,
            Self::Wireguard { tag, .. } => tag,
            Self::Direct { tag } => tag,
            Self::Block { tag } => tag,
            Self::Urltest { tag, .. } => tag,
            Self::Fallback { tag, .. } => tag,
            Self::Selector { tag, .. } => tag,
        }
    }

    /// 取(或首次建立)本出站的 WireGuard 隧道。
    ///
    /// 懒初始化: 第一条路由到此出站的连接才真正建隧道。失败**不缓存** ——
    /// 网络暂时不可达时下一条连接应能重试, 而不是把一次失败钉死到进程结束。
    pub async fn wg_tunnel(&self) -> anyhow::Result<Arc<crate::proxy::wg::tunnel::WgTunnel>> {
        let Self::Wireguard { cfg, tunnel, .. } = self else {
            anyhow::bail!("内部错误: 对非 WireGuard 出站请求隧道");
        };
        tunnel
            .get_or_try_init(|| async {
                crate::proxy::wg::tunnel::WgTunnel::connect(cfg).await.map(Arc::new)
            })
            .await
            .cloned()
    }

    pub fn is_healthy(self: &Arc<Self>) -> bool {
        match &**self {
            Self::Mirage { pool, .. } => pool.stats.read().unwrap_or_else(|e| e.into_inner()).is_healthy(),
            Self::Direct { .. } | Self::Block { .. } | Self::Wireguard { .. } => true,
            Self::Urltest { children, .. } | Self::Fallback { children, .. } | Self::Selector { children, .. } => {
                children.iter().any(|c| c.is_healthy())
            }
        }
    }

    pub fn latency_rtt_ms(self: &Arc<Self>) -> Option<u64> {
        match &**self {
            Self::Mirage { rtt_ms, .. } => {
                let rtt = rtt_ms.load(std::sync::atomic::Ordering::Relaxed);
                if rtt > 0 && rtt != u64::MAX { Some(rtt) } else { None }
            },
            Self::Direct { .. } | Self::Block { .. } | Self::Wireguard { .. } => None,
            Self::Urltest { .. } | Self::Fallback { .. } | Self::Selector { .. } => {
                let leaf = self.resolve_leaf();
                if std::ptr::eq(&*leaf, &**self) { None } else { leaf.latency_rtt_ms() }
            }
        }
    }

    pub fn latency_http_ms(self: &Arc<Self>) -> Option<u64> {
        match &**self {
            Self::Mirage { pool, .. } => pool.stats.read().unwrap_or_else(|e| e.into_inner()).latency_ms(),
            Self::Direct { .. } | Self::Block { .. } | Self::Wireguard { .. } => None,
            Self::Urltest { .. } | Self::Fallback { .. } | Self::Selector { .. } => {
                let leaf = self.resolve_leaf();
                if std::ptr::eq(&*leaf, &**self) { None } else { leaf.latency_http_ms() }
            }
        }
    }

    pub fn latency_ms(self: &Arc<Self>, test_type: &str) -> Option<u64> {
        if test_type == "rtt" {
            self.latency_rtt_ms().or_else(|| self.latency_http_ms())
        } else {
            self.latency_http_ms()
        }
    }

    pub fn resolve_leaf(self: &Arc<Self>) -> Arc<OutboundNode> {
        match &**self {
            Self::Urltest { tag, children, tolerance_ms, test_type, current } => {
                let candidates: Vec<_> = children.iter().filter(|c| c.is_healthy()).collect();
                if candidates.is_empty() {
                    return self.clone();
                }

                let with_lat: Vec<_> = candidates.iter()
                    .filter_map(|c| c.latency_ms(test_type).map(|lat| (c, lat)))
                    .collect();

                if with_lat.is_empty() {
                    let mut curr_guard = current.write().unwrap_or_else(|e| e.into_inner());
                    if let Some(c) = curr_guard.as_ref() {
                        if c.is_healthy() {
                            return c.resolve_leaf();
                        }
                    }
                    *curr_guard = Some(candidates[0].clone());
                    return candidates[0].resolve_leaf();
                }

                let best = with_lat.into_iter()
                    .min_by_key(|&(_, lat)| lat)
                    .unwrap();

                let mut curr_guard = current.write().unwrap_or_else(|e| e.into_inner());
                if let Some(curr) = curr_guard.as_ref() {
                    if let Some(curr_lat) = curr.latency_ms(test_type) {
                        if curr_lat <= best.1 + *tolerance_ms {
                            return curr.resolve_leaf();
                        }
                    }
                }

                info!("Urltest '{}' switched to {}", tag, best.0.tag());
                *curr_guard = Some((*best.0).clone());
                best.0.resolve_leaf()
            }
            Self::Fallback { children, .. } => {
                for c in children {
                    if c.is_healthy() {
                        return c.resolve_leaf();
                    }
                }
                if let Some(first) = children.first() {
                    first.resolve_leaf()
                } else {
                    self.clone()
                }
            }
            Self::Selector { children, current, .. } => {
                let curr_guard = current.read().unwrap_or_else(|e| e.into_inner());
                if let Some(c) = curr_guard.as_ref() {
                    return c.resolve_leaf();
                }
                if let Some(c) = children.first() {
                    return c.resolve_leaf();
                }
                self.clone()
            }
            _ => self.clone(),
        }
    }
}

pub struct OutboundManager {
    pub outbounds: HashMap<String, Arc<OutboundNode>>,
}

impl OutboundManager {
    pub fn new(cfg: &Config) -> Self {
        let mut outbounds = HashMap::new();
        let mut deferred = Vec::new();

        // Pass 1: Leaf nodes
        for oc in &cfg.outbounds {
            match oc {
                OutboundConfig::Mirage { tag, server, server_port, password, camouflage_host, pool_size, brutal_rate_mbps, brutal_base_rtt_ms } => {
                    let pool_cfg = Arc::new(PoolConfig {
                        server_host: server.clone(),
                        server_port: *server_port,
                        password: password.clone(),
                        camouflage_host: camouflage_host.clone(),
                        pool_size: *pool_size,
                    });
                    let bytes_per_sec = brutal_rate_mbps.map(|m| m * 125_000);
                    let brutal_state = Arc::new(crate::proxy::pool::BrutalState {
                        configured_rate: bytes_per_sec,
                        current_rate: Arc::new(std::sync::atomic::AtomicU64::new(bytes_per_sec.unwrap_or(8_000_000))),
                        base_rtt: *brutal_base_rtt_ms,
                        active_fds: Arc::new(std::sync::Mutex::new(std::collections::HashSet::new())),
                    });
                    let pool = Arc::new(WarmPool::new(pool_cfg, brutal_state));
                    outbounds.insert(tag.clone(), Arc::new(OutboundNode::Mirage {
                        tag: tag.clone(),
                        pool,
                        server_host: server.clone(),
                        server_port: *server_port,
                        server_ip: Arc::new(RwLock::new(None)),
                        rtt_ms: Arc::new(std::sync::atomic::AtomicU64::new(u64::MAX)),
                        snd_cwnd: Arc::new(std::sync::atomic::AtomicU64::new(0)),
                        total_retrans: Arc::new(std::sync::atomic::AtomicU64::new(u64::MAX)),
                        total_segs_out: Arc::new(std::sync::atomic::AtomicU64::new(u64::MAX)),
                    }));
                }
                OutboundConfig::Wireguard {
                    tag, private_key, peer_public_key, preshared_key, endpoint, address,
                    mtu, persistent_keepalive,
                } => {
                    // 配置有问题时**降级为 Block, 而不是 Direct**。
                    //
                    // 这是刻意的: 用户配 WG 出站的意图就是流量从 WG 出去, 悄悄改走直连
                    // 意味着本该走隧道的流量从本机 IP 裸奔出去 —— 与 SS 上游的 UDP block
                    // 同一条理由: 安全的失败方式是"不发", 不是"发到别处去"。
                    // (正常路径下 semantic_issues 已在 check/启动阶段拦下这些错配。)
                    let built = (|| -> anyhow::Result<crate::proxy::wg::WgConfig> {
                        Ok(crate::proxy::wg::WgConfig {
                            private_key: crate::proxy::wg::decode_wg_key(private_key, "private_key")?,
                            peer_public_key: crate::proxy::wg::decode_wg_key(peer_public_key, "peer_public_key")?,
                            preshared_key: preshared_key
                                .as_deref()
                                .map(|k| crate::proxy::wg::decode_wg_key(k, "preshared_key"))
                                .transpose()?,
                            endpoint: endpoint.clone(),
                            address: address.parse()?,
                            mtu: *mtu,
                            persistent_keepalive: *persistent_keepalive,
                        })
                    })();
                    match built {
                        Ok(wg) => {
                            info!("出站 `{}`: WireGuard → {} (隧道内地址 {}, MTU {})",
                                  tag, wg.endpoint, wg.address, wg.mtu);
                            outbounds.insert(tag.clone(), Arc::new(OutboundNode::Wireguard {
                                tag: tag.clone(),
                                cfg: Arc::new(wg),
                                tunnel: tokio::sync::OnceCell::new(),
                            }));
                        }
                        Err(e) => {
                            tracing::error!(
                                "出站 `{}` 的 WireGuard 配置有误, 已降级为 block (拒绝连接) \
                                 而非直连 —— 避免本该走隧道的流量从本机 IP 裸奔出去。原因: {}",
                                tag, e
                            );
                            outbounds.insert(tag.clone(), Arc::new(OutboundNode::Block { tag: tag.clone() }));
                        }
                    }
                }
                OutboundConfig::Direct { tag } => {
                    outbounds.insert(tag.clone(), Arc::new(OutboundNode::Direct { tag: tag.clone() }));
                }
                OutboundConfig::Block { tag } => {
                    outbounds.insert(tag.clone(), Arc::new(OutboundNode::Block { tag: tag.clone() }));
                }
                _ => {
                    deferred.push(oc);
                }
            }
        }

        // Auto-add implicit direct and block if not present
        if !outbounds.contains_key("direct") {
            outbounds.insert("direct".to_string(), Arc::new(OutboundNode::Direct { tag: "direct".to_string() }));
        }
        if !outbounds.contains_key("block") {
            outbounds.insert("block".to_string(), Arc::new(OutboundNode::Block { tag: "block".to_string() }));
        }

        // Pass 2: Group nodes (Urltest, Fallback) - simplified fixpoint resolution
        let mut pending = deferred;
        while !pending.is_empty() {
            let mut progress = false;
            let mut next_round = Vec::new();

            for oc in pending {
                let mut hc_url = "".to_string();
                let mut hc_interval = 0;
                let mut hc_test_type = "ping".to_string();
                let (tag, child_tags, otype, _interval, tolerance) = match oc {
                    OutboundConfig::Urltest { tag, outbounds, interval, tolerance, url, test_type } => {
                        hc_url = url.clone();
                        hc_interval = *interval;
                        hc_test_type = test_type.clone();
                        (tag, outbounds, "urltest", *interval, *tolerance)
                    }
                    OutboundConfig::Fallback { tag, outbounds, interval, url } => {
                        hc_url = url.clone();
                        hc_interval = *interval;
                        (tag, outbounds, "fallback", *interval, 0)
                    }
                    OutboundConfig::Selector { tag, outbounds } => {
                        (tag, outbounds, "selector", 0, 0)
                    }
                    _ => unreachable!(),
                };

                let mut children = Vec::new();
                let mut resolved = true;
                for ct in child_tags {
                    if let Some(node) = outbounds.get(ct) {
                        children.push(node.clone());
                    } else {
                        resolved = false;
                        break;
                    }
                }

                if resolved {
                    if hc_interval > 0 && !hc_url.is_empty() {
                        for child in &children {
                            if let OutboundNode::Mirage { .. } = &**child {
                                crate::proxy::healthcheck::start_health_checker(child.clone(), hc_url.clone(), hc_interval);
                            }
                        }
                    }

                    let node = if otype == "urltest" {
                        Arc::new(OutboundNode::Urltest {
                            tag: tag.clone(),
                            children,
                            tolerance_ms: tolerance,
                            test_type: hc_test_type,
                            current: Arc::new(RwLock::new(None)),
                        })
                    } else if otype == "selector" {
                        Arc::new(OutboundNode::Selector {
                            tag: tag.clone(),
                            children,
                            current: Arc::new(RwLock::new(None)),
                        })
                    } else {
                        Arc::new(OutboundNode::Fallback {
                            tag: tag.clone(),
                            children,
                        })
                    };
                    outbounds.insert(tag.clone(), node);
                    progress = true;
                } else {
                    next_round.push(oc);
                }
            }

            if !progress {
                panic!("Unresolved or circular outbound groups: {:?}", next_round);
            }
            pending = next_round;
        }

        Self { outbounds }
    }

    pub fn get(&self, tag: &str) -> Option<Arc<OutboundNode>> {
        self.outbounds.get(tag).cloned()
    }
}

#[cfg(test)]
mod wg_tests {
    use super::*;
    use crate::config::Config;

    fn cfg_with_wg(extra: &str) -> Config {
        let s = format!(r#"{{
          "inbounds": [],
          "outbounds": [
            {{ "type": "direct", "tag": "direct" }},
            {{ "type": "wireguard", "tag": "wg", {extra} }}
          ],
          "routing": {{ "default_outbound": "direct", "rules": [] }}
        }}"#);
        serde_json::from_str(&s).expect("配置应能解析")
    }

    const GOOD_KEYS: &str = r#""private_key": "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=",
        "peer_public_key": "AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=",
        "endpoint": "1.2.3.4:51820", "address": "10.0.0.2""#;

    /// 合法配置应建出 Wireguard 节点 (而非被降级)。
    #[test]
    fn valid_config_builds_wireguard_node() {
        let cfg = cfg_with_wg(GOOD_KEYS);
        assert!(cfg.semantic_issues().is_empty(), "合法配置不该有告警: {:?}", cfg.semantic_issues());
        let m = OutboundManager::new(&cfg);
        let node = m.outbounds.get("wg").expect("应有 wg 出站");
        assert!(matches!(&**node, OutboundNode::Wireguard { .. }), "应是 Wireguard 节点");
    }

    /// 密钥错的 WG 出站必须降级为 **Block**, 绝不能变成 Direct。
    ///
    /// 这是安全契约: 用户配 WG 的意图是流量从 WG 出去; 悄悄改走直连 = 本该走隧道的流量
    /// 从本机 IP 裸奔出去, 且用户毫无察觉。安全的失败方式是"不发"而不是"发到别处去"。
    #[test]
    fn bad_key_degrades_to_block_never_direct() {
        // 16 字节密钥 (WG 要 32)
        let cfg = cfg_with_wg(r#""private_key": "AAAAAAAAAAAAAAAAAAAAAA==",
            "peer_public_key": "AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=",
            "endpoint": "1.2.3.4:51820", "address": "10.0.0.2""#);
        // check 阶段就该报出来
        let issues = cfg.semantic_issues();
        assert!(issues.iter().any(|i| i.contains("private_key")), "应报密钥问题: {issues:?}");

        let m = OutboundManager::new(&cfg);
        match &**m.outbounds.get("wg").expect("wg 出站应存在") {
            OutboundNode::Block { .. } => {}
            OutboundNode::Direct { .. } => {
                panic!("配错的 WG 出站降级成了 Direct —— 流量会从本机 IP 裸奔出去")
            }
            other => panic!("应降级为 Block, 实际 {:?}", other.tag()),
        }
    }

    /// 校验必须拦下这些"不会让进程起不来、但会让每条连接静默失败"的错配。
    #[test]
    fn semantic_issues_catch_common_mistakes() {
        let cases = [
            (r#""private_key": "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=",
              "peer_public_key": "AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=",
              "endpoint": "1.2.3.4", "address": "10.0.0.2""#, "endpoint"),
            (r#""private_key": "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=",
              "peer_public_key": "AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=",
              "endpoint": "1.2.3.4:51820", "address": "10.0.0.2/32""#, "address"),
            (r#""private_key": "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=",
              "peer_public_key": "AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=",
              "endpoint": "1.2.3.4:51820", "address": "10.0.0.2", "mtu": 99999"#, "mtu"),
        ];
        for (extra, want) in cases {
            let issues = cfg_with_wg(extra).semantic_issues();
            assert!(
                issues.iter().any(|i| i.contains(want)),
                "配置含 {want} 错误却没被拦下: {issues:?}"
            );
        }
    }
}
