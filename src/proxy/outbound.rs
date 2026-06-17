use crate::proxy::pool::{WarmPool, PoolConfig};
use std::sync::RwLock;
use std::collections::HashMap;
use std::sync::Arc;
use tracing::info;
use crate::config::{Config, OutboundConfig};

pub enum OutboundNode {
    Pyreality {
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
            Self::Pyreality { tag, .. } => tag,
            Self::Direct { tag } => tag,
            Self::Block { tag } => tag,
            Self::Urltest { tag, .. } => tag,
            Self::Fallback { tag, .. } => tag,
            Self::Selector { tag, .. } => tag,
        }
    }

    pub fn is_healthy(self: &Arc<Self>) -> bool {
        match &**self {
            Self::Pyreality { pool, .. } => pool.stats.read().unwrap().is_healthy(),
            Self::Direct { .. } | Self::Block { .. } => true,
            Self::Urltest { children, .. } | Self::Fallback { children, .. } | Self::Selector { children, .. } => {
                children.iter().any(|c| c.is_healthy())
            }
        }
    }

    pub fn latency_rtt_ms(self: &Arc<Self>) -> Option<u64> {
        match &**self {
            Self::Pyreality { rtt_ms, .. } => {
                let rtt = rtt_ms.load(std::sync::atomic::Ordering::Relaxed);
                if rtt > 0 && rtt != u64::MAX { Some(rtt) } else { None }
            },
            Self::Direct { .. } | Self::Block { .. } => None,
            Self::Urltest { .. } | Self::Fallback { .. } | Self::Selector { .. } => {
                let leaf = self.resolve_leaf();
                if std::ptr::eq(&*leaf, &**self) { None } else { leaf.latency_rtt_ms() }
            }
        }
    }

    pub fn latency_http_ms(self: &Arc<Self>) -> Option<u64> {
        match &**self {
            Self::Pyreality { pool, .. } => pool.stats.read().unwrap().latency_ms(),
            Self::Direct { .. } | Self::Block { .. } => None,
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
                    let mut curr_guard = current.write().unwrap();
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

                let mut curr_guard = current.write().unwrap();
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
                let curr_guard = current.read().unwrap();
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
                OutboundConfig::Pyreality { tag, server, server_port, password, camouflage_host, pool_size, brutal_rate_bytes_per_sec, brutal_base_rtt_ms } => {
                    let pool_cfg = Arc::new(PoolConfig {
                        server_host: server.clone(),
                        server_port: *server_port,
                        password: password.clone(),
                        camouflage_host: camouflage_host.clone(),
                        pool_size: *pool_size,
                    });
                    let brutal_state = Arc::new(crate::proxy::pool::BrutalState {
                        configured_rate: *brutal_rate_bytes_per_sec,
                        current_rate: Arc::new(std::sync::atomic::AtomicU64::new(brutal_rate_bytes_per_sec.unwrap_or(8_000_000))),
                        base_rtt: *brutal_base_rtt_ms,
                        active_fds: Arc::new(std::sync::Mutex::new(std::collections::HashSet::new())),
                    });
                    let pool = Arc::new(WarmPool::new(pool_cfg, brutal_state));
                    outbounds.insert(tag.clone(), Arc::new(OutboundNode::Pyreality {
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
                            if let OutboundNode::Pyreality { .. } = &**child {
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
