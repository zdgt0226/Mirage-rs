use aho_corasick::{AhoCorasick, AhoCorasickBuilder};
use ipnet::{IpNet, Ipv4Net};
use regex::RegexSet;
use std::collections::HashMap;
use std::net::IpAddr;

pub type OutboundTag = String;
pub type RuleId = usize;

/// 两个 v4 CIDR 是否重叠 (较短前缀的一方包含另一方的网络地址即重叠)。
fn cidr_overlaps(a: &Ipv4Net, b: &Ipv4Net) -> bool {
    a.contains(&b.network()) || b.contains(&a.network())
}

#[derive(Clone, Debug, PartialEq)]
pub struct Rule {
    pub id: RuleId,
    pub mode: String,
    pub outbound: OutboundTag,
    pub domain_suffix: Vec<String>,
    pub domain_keyword: Vec<String>,
    pub domain_regex: Vec<String>,
    pub geosite: Vec<String>,
    pub ip_cidr: Vec<IpNet>,
    pub geoip: Vec<String>,
    pub source_ip_cidr: Vec<IpNet>,
    pub source_mac: Vec<String>,
    pub protocol: Vec<String>,
    pub port: Vec<u16>,
    /// 入站 tag 白名单; 空 = 不限。
    pub inbound: Vec<String>,
    /// 进程名白名单 (comm, 精确匹配); 空 = 不限。仅对本机 (loopback) socks/mixed 入站
    /// 连接可判定 —— 透明/LAN 转发的连接进程在别的机器上, 无从取, 此维度不命中。
    pub process_name: Vec<String>,
}

impl Rule {
    pub fn has_domain_filters(&self) -> bool {
        !self.domain_suffix.is_empty()
            || !self.domain_keyword.is_empty()
            || !self.domain_regex.is_empty()
            || !self.geosite.is_empty()
    }

    pub fn has_ip_filters(&self) -> bool {
        !self.ip_cidr.is_empty() || !self.geoip.is_empty()
    }

    pub fn has_network_filters(&self) -> bool {
        self.has_domain_filters() || self.has_ip_filters()
    }

    pub fn matches_port(&self, port: u16) -> bool {
        if self.port.is_empty() {
            true
        } else {
            self.port.contains(&port)
        }
    }

    pub fn matches_extra(&self, req: &RoutingRequest) -> bool {
        if !self.protocol.is_empty() && !self.protocol.contains(&req.protocol.to_string()) {
            return false;
        }
        if !self.source_mac.is_empty() {
            let req_mac = req.source_mac.unwrap_or("");
            if !self.source_mac.contains(&req_mac.to_string()) {
                return false;
            }
        }
        if !self.inbound.is_empty() {
            // 调用方没给入站 tag 时不匹配: 该条件本就是"限定来源", 信息缺失就当不满足,
            // 而不是放宽成"任意入站都算命中" —— 后者会让本该只对某入站生效的规则外溢。
            match req.inbound {
                Some(tag) if self.inbound.iter().any(|t| t == tag) => {}
                _ => return false,
            }
        }
        if !self.source_ip_cidr.is_empty() {
            if let Some(src_ip) = req.source_ip {
                if !self.source_ip_cidr.iter().any(|net| net.contains(&src_ip)) {
                    return false;
                }
            } else {
                return false;
            }
        }
        if !self.process_name.is_empty() {
            // 同 inbound: 进程名未知 (非本机连接 / 查不到) 就不匹配, 不放宽。
            match req.process_name {
                Some(name) if self.process_name.iter().any(|n| n == name) => {}
                _ => return false,
            }
        }
        true
    }
}

#[derive(Default)]
struct DomainTrieNode {
    rule_ids: Vec<RuleId>,
    children: HashMap<String, DomainTrieNode>,
}

#[derive(Default)]
struct DomainTrie {
    root: DomainTrieNode,
}

impl DomainTrie {
    fn insert(&mut self, domain: &str, rule_id: RuleId) {
        let parts: Vec<&str> = domain.split('.').rev().collect();
        let mut curr = &mut self.root;
        for part in parts {
            curr = curr
                .children
                .entry(part.to_string())
                .or_default();
        }
        curr.rule_ids.push(rule_id);
    }

    fn search(&self, domain: &str) -> Vec<RuleId> {
        let parts: Vec<&str> = domain.split('.').rev().collect();
        let mut curr = &self.root;
        let mut matches = Vec::new();

        matches.extend(&curr.rule_ids);

        for part in parts {
            if let Some(next) = curr.children.get(part) {
                curr = next;
                matches.extend(&curr.rule_ids);
            } else {
                break;
            }
        }
        matches
    }
}

#[derive(Default)]
struct IpTrieNode {
    rule_ids: Vec<RuleId>,
    left: Option<Box<IpTrieNode>>,  // 0
    right: Option<Box<IpTrieNode>>, // 1
}

#[derive(Default)]
struct IpTrie {
    root_v4: IpTrieNode,
    root_v6: IpTrieNode,
}

impl IpTrie {
    fn insert(&mut self, net: IpNet, rule_id: RuleId) {
        match net {
            IpNet::V4(v4) => {
                let bits = u32::from(v4.network()).to_be_bytes();
                Self::insert_bits(&mut self.root_v4, &bits, v4.prefix_len(), rule_id);
            }
            IpNet::V6(v6) => {
                let bits = u128::from(v6.network()).to_be_bytes();
                Self::insert_bits(&mut self.root_v6, &bits, v6.prefix_len(), rule_id);
            }
        }
    }

    fn insert_bits(mut node: &mut IpTrieNode, bits: &[u8], prefix_len: u8, rule_id: RuleId) {
        for i in 0..prefix_len {
            let byte_idx = (i / 8) as usize;
            let bit_idx = 7 - (i % 8);
            let bit = (bits[byte_idx] >> bit_idx) & 1;

            node = if bit == 0 {
                node.left.get_or_insert_with(|| Box::new(IpTrieNode::default()))
            } else {
                node.right.get_or_insert_with(|| Box::new(IpTrieNode::default()))
            };
        }
        node.rule_ids.push(rule_id);
    }

    fn search(&self, ip: IpAddr) -> Vec<RuleId> {
        match ip {
            IpAddr::V4(v4) => {
                let bits = u32::from(v4).to_be_bytes();
                Self::search_bits(&self.root_v4, &bits, 32)
            }
            IpAddr::V6(v6) => {
                let bits = u128::from(v6).to_be_bytes();
                Self::search_bits(&self.root_v6, &bits, 128)
            }
        }
    }

    fn search_bits(mut node: &IpTrieNode, bits: &[u8], total_bits: u8) -> Vec<RuleId> {
        let mut matches = Vec::new();
        matches.extend(&node.rule_ids);

        for i in 0..total_bits {
            let byte_idx = (i / 8) as usize;
            let bit_idx = 7 - (i % 8);
            let bit = (bits[byte_idx] >> bit_idx) & 1;

            let next = if bit == 0 { &node.left } else { &node.right };
            if let Some(child) = next {
                node = child.as_ref();
                matches.extend(&node.rule_ids);
            } else {
                break;
            }
        }
        matches
    }
}

pub mod geo;
pub mod geo_updater;

use crate::router::geo::{DomainType, load_geosite_dat, load_geoip_dat, load_singbox_json};
use std::path::Path;

struct KeywordMatcher {
    ac: AhoCorasick,
    pattern_to_rule_id: Vec<RuleId>,
}

struct RegexMatcher {
    set: RegexSet,
    pattern_to_rule_id: Vec<RuleId>,
}

pub struct RouterEngine {
    domain_trie: DomainTrie,
    keyword_matcher: Option<KeywordMatcher>,
    regex_matcher: Option<RegexMatcher>,
    ip_trie: IpTrie,
    
    // Exact domain matches (Type::Full in geosite)
    exact_domain: HashMap<String, Vec<RuleId>>,
    
    // Rules that match any network address (e.g. only port filter)
    any_network_rules: Vec<RuleId>,
    
    pub rule_table: Vec<Rule>,
    pub default_outbound: OutboundTag,

    // 所有解析后的 v4 CIDR 及其所属规则 (ip_cidr 手动 + geoip/geosite 解析统一在此)。
    // 供 eBPF tc_divert direct_cidr map 用, 见 direct_v4_cidrs()。
    all_v4_cidrs: Vec<(Ipv4Net, RuleId)>,
}

pub struct RoutingRequest<'a> {
    pub domain: Option<&'a str>,
    pub ip: Option<IpAddr>,
    pub port: u16,
    pub protocol: &'a str, // "tcp" or "udp"
    pub source_ip: Option<IpAddr>,
    pub source_mac: Option<&'a str>,
    /// 本连接是从哪个入站进来的 (按 tag)。None = 调用方没提供, 此时带 `inbound`
    /// 条件的规则**一律不匹配** —— 宁可不命中, 也不要在信息缺失时猜。
    pub inbound: Option<&'a str>,
    /// 发起连接的本机进程名 (comm)。仅本机 loopback 连接可查到; None = 未知,
    /// 带 `process_name` 条件的规则一律不匹配 (同 inbound 语义)。
    pub process_name: Option<&'a str>,
}

impl RouterEngine {
    pub fn new(
        rules: Vec<Rule>,
        default_outbound: OutboundTag,
        geodata_dir: &str,
        geo_alias: &std::collections::HashMap<String, String>,
    ) -> anyhow::Result<Self> {
        let mut domain_trie = DomainTrie::default();
        let mut exact_domain: HashMap<String, Vec<RuleId>> = HashMap::new();
        let mut patterns = Vec::new();
        let mut pattern_to_rule_id = Vec::new();
        let mut regex_patterns = Vec::new();
        let mut regex_to_rule_id = Vec::new();
        let mut ip_trie = IpTrie::default();
        let mut all_v4_cidrs: Vec<(Ipv4Net, RuleId)> = Vec::new();
        let mut any_network_rules = Vec::new();

        for rule in &rules {
            if !rule.has_network_filters() {
                any_network_rules.push(rule.id);
                continue;
            }

            for cidr in &rule.ip_cidr {
                ip_trie.insert(*cidr, rule.id);
                if let IpNet::V4(v4) = cidr {
                    all_v4_cidrs.push((*v4, rule.id));
                }
            }
            for suffix in &rule.domain_suffix {
                domain_trie.insert(suffix, rule.id);
            }
            for kw in &rule.domain_keyword {
                patterns.push(kw.clone());
                pattern_to_rule_id.push(rule.id);
            }
            for rx in &rule.domain_regex {
                regex_patterns.push(rx.clone());
                regex_to_rule_id.push(rule.id);
            }
            
            for _cidr in &rule.source_ip_cidr {
                // If we want source routing, we need a separate trie, but for now we skip building trie 
                // and rely on matches_extra since source matching is extremely rare and small.
            }
            
            // Process GeoSite
            for site in &rule.geosite {
                let actual_site = geo_alias.get(site).unwrap_or(site);
                
                if actual_site.ends_with(".json") {
                    let path = Path::new(geodata_dir).join(actual_site);
                    match load_singbox_json(&path) {
                        Ok((domains, cidrs)) => {
                            for net in cidrs {
                                ip_trie.insert(net, rule.id);
                                if let IpNet::V4(v4) = net {
                                    all_v4_cidrs.push((v4, rule.id));
                                }
                            }
                            for d in domains {
                                match d.dtype {
                                    DomainType::Plain => {
                                        patterns.push(d.value);
                                        pattern_to_rule_id.push(rule.id);
                                    }
                                    DomainType::Regex => {
                                        regex_patterns.push(d.value);
                                        regex_to_rule_id.push(rule.id);
                                    }
                                    DomainType::RootDomain => {
                                        domain_trie.insert(&d.value, rule.id);
                                    }
                                    DomainType::Full => {
                                        exact_domain.entry(d.value).or_default().push(rule.id);
                                    }
                                }
                            }
                        }
                        Err(e) => tracing::error!(
                            "Router: geosite singbox '{}' load failed from {:?}: {}. Rules referencing this file will match nothing.",
                            actual_site, path, e
                        ),
                    }
                } else if actual_site.contains(':') {
                    // filename.dat:tag
                    let parts: Vec<&str> = actual_site.splitn(2, ':').collect();
                    let path = Path::new(geodata_dir).join(parts[0]);
                    match load_geosite_dat(&path, parts[1]) {
                        Ok(domains) => {
                            for d in domains {
                                match d.dtype {
                                    DomainType::Plain => {
                                        patterns.push(d.value);
                                        pattern_to_rule_id.push(rule.id);
                                    }
                                    DomainType::Regex => {
                                        regex_patterns.push(d.value);
                                        regex_to_rule_id.push(rule.id);
                                    }
                                    DomainType::RootDomain => {
                                        domain_trie.insert(&d.value, rule.id);
                                    }
                                    DomainType::Full => {
                                        exact_domain.entry(d.value).or_default().push(rule.id);
                                    }
                                }
                            }
                        }
                        Err(e) => tracing::error!(
                            "Router: geosite '{}' (path={:?}, tag={}) load failed: {}. Rules referencing this tag will match nothing.",
                            actual_site, path, parts[1], e
                        ),
                    }
                } else {
                    // Standard v2ray geosite.dat
                    let path = Path::new(geodata_dir).join("geosite.dat");
                    match load_geosite_dat(&path, actual_site) {
                        Ok(domains) => {
                            for d in domains {
                                match d.dtype {
                                    DomainType::Plain => {
                                        patterns.push(d.value);
                                        pattern_to_rule_id.push(rule.id);
                                    }
                                    DomainType::Regex => {
                                        regex_patterns.push(d.value);
                                        regex_to_rule_id.push(rule.id);
                                    }
                                    DomainType::RootDomain => {
                                        domain_trie.insert(&d.value, rule.id);
                                    }
                                    DomainType::Full => {
                                        exact_domain.entry(d.value).or_default().push(rule.id);
                                    }
                                }
                            }
                        }
                        Err(e) => tracing::error!(
                            "Router: geosite '{}' load failed from {:?}: {}. Rules referencing this tag will match nothing. Check /etc/mirage-rs/geosite/geosite.dat exists and is valid v2ray format.",
                            actual_site, path, e
                        ),
                    }
                }
            }
            
            // Process GeoIP
            for ip_list in &rule.geoip {
                let actual_ip_list = geo_alias.get(ip_list).unwrap_or(ip_list);
                
                if actual_ip_list.ends_with(".json") {
                    let path = Path::new(geodata_dir).join(actual_ip_list);
                    match load_singbox_json(&path) {
                        Ok((_, cidrs)) => {
                            for net in cidrs {
                                ip_trie.insert(net, rule.id);
                                if let IpNet::V4(v4) = net {
                                    all_v4_cidrs.push((v4, rule.id));
                                }
                            }
                        }
                        Err(e) => tracing::error!(
                            "Router: geoip singbox '{}' load failed from {:?}: {}. Rules referencing this list will match nothing.",
                            actual_ip_list, path, e
                        ),
                    }
                } else if actual_ip_list.contains(':') {
                    // filename.dat:tag
                    let parts: Vec<&str> = actual_ip_list.splitn(2, ':').collect();
                    let path = Path::new(geodata_dir).join(parts[0]);
                    match load_geoip_dat(&path, parts[1]) {
                        Ok(cidrs) => {
                            for net in cidrs {
                                ip_trie.insert(net, rule.id);
                                if let IpNet::V4(v4) = net {
                                    all_v4_cidrs.push((v4, rule.id));
                                }
                            }
                        }
                        Err(e) => tracing::error!(
                            "Router: geoip '{}' (path={:?}, tag={}) load failed: {}. Rules referencing this tag will match nothing.",
                            actual_ip_list, path, parts[1], e
                        ),
                    }
                } else {
                    let path = Path::new(geodata_dir).join("geoip.dat");
                    match load_geoip_dat(&path, actual_ip_list) {
                        Ok(cidrs) => {
                            for net in cidrs {
                                ip_trie.insert(net, rule.id);
                                if let IpNet::V4(v4) = net {
                                    all_v4_cidrs.push((v4, rule.id));
                                }
                            }
                        }
                        Err(e) => tracing::error!(
                            "Router: geoip '{}' load failed from {:?}: {}. Rules referencing this tag will match nothing. Check /etc/mirage-rs/geosite/geoip.dat exists and is valid v2ray format.",
                            actual_ip_list, path, e
                        ),
                    }
                }
            }
        }

        let keyword_matcher = if !patterns.is_empty() {
            Some(KeywordMatcher {
                ac: AhoCorasickBuilder::new().build(&patterns)?,
                pattern_to_rule_id,
            })
        } else {
            None
        };
        
        let regex_matcher = if !regex_patterns.is_empty() {
            Some(RegexMatcher {
                set: RegexSet::new(&regex_patterns)?,
                pattern_to_rule_id: regex_to_rule_id,
            })
        } else {
            None
        };

        Ok(Self {
            domain_trie,
            keyword_matcher,
            regex_matcher,
            ip_trie,
            exact_domain,
            any_network_rules,
            rule_table: rules,
            default_outbound,
            all_v4_cidrs,
        })
    }

    /// 收集会被"直连"的 v4 CIDR 集, 供 eBPF tc_divert 的 direct_cidr map 用作内核
    /// 直连快路径。来源是 new() 已统一解析的 all_v4_cidrs (用户手动 ip_cidr ∪
    /// geoip/geosite), 按规则出站是否直连筛选。
    ///
    /// 安全约束: 若某直连 CIDR 与任一"非直连"规则的 CIDR 重叠, 则排除它 —— 宁可
    /// 该段少走内核快路径、交用户态 router 权威判定, 也绝不能把本该代理的流量误
    /// 直连出去 (泄漏)。因此结果是"绝对直连"的保守子集。
    pub fn direct_v4_cidrs(&self, is_direct: impl Fn(&OutboundTag) -> bool) -> Vec<Ipv4Net> {
        let mut direct = Vec::new();
        let mut nondirect = Vec::new();
        for (cidr, id) in &self.all_v4_cidrs {
            if is_direct(&self.rule_table[*id].outbound) {
                direct.push(*cidr);
            } else {
                nondirect.push(*cidr);
            }
        }
        direct.retain(|c| !nondirect.iter().any(|nd| cidr_overlaps(c, nd)));
        direct.sort_unstable();
        direct.dedup();
        direct
    }

    /// 是否有任何规则带 `process_name` 条件。调用方 (handler) 据此决定是否值得为本机连接
    /// 扫 /proc 查进程名 —— 没人用这维度就完全跳过, 避免每连接的 /proc 开销。
    pub fn uses_process_name(&self) -> bool {
        self.rule_table.iter().any(|r| !r.process_name.is_empty())
    }

    /// 命中即 default 的包装: route_matched 无命中时回落 default_outbound。
    pub fn route(&self, req: RoutingRequest) -> OutboundTag {
        self.route_matched(&req).unwrap_or_else(|| {
            tracing::debug!(
                "[ROUTE] {} :{}/{} → [{}] (默认出口, 无规则命中)",
                req.domain.map(|d| d.to_string()).or_else(|| req.ip.map(|i| i.to_string())).unwrap_or_else(|| "?".into()),
                req.port, req.protocol, self.default_outbound
            );
            self.default_outbound.clone()
        })
    }

    /// 只读的默认出站 tag (供 DNS auto_classify 判定"未命中规则")。
    pub fn default_outbound(&self) -> &str {
        &self.default_outbound
    }

    /// 返回命中的显式规则出站; **无任何规则命中 → None** (由调用方决定回落 default_outbound
    /// 还是走 auto_classify)。语义/顺序与 route() 完全一致, 只是不替调用方兜 default。
    pub fn route_matched(&self, req: &RoutingRequest) -> Option<OutboundTag> {
        let mut candidate_counts: std::collections::HashMap<RuleId, usize> = std::collections::HashMap::new();

        if let Some(domain) = req.domain {
            let mut matched_domain_ids = Vec::new();
            if let Some(ids) = self.exact_domain.get(domain) {
                matched_domain_ids.extend(ids);
            }
            
            matched_domain_ids.extend(self.domain_trie.search(domain));

            if let Some(matcher) = &self.keyword_matcher {
                for mat in matcher.ac.find_iter(domain) {
                    let r_id = matcher.pattern_to_rule_id[mat.pattern().as_usize()];
                    matched_domain_ids.push(r_id);
                }
            }
            
            if let Some(rmatcher) = &self.regex_matcher {
                for mat_idx in rmatcher.set.matches(domain).into_iter() {
                    matched_domain_ids.push(rmatcher.pattern_to_rule_id[mat_idx]);
                }
            }
            
            matched_domain_ids.sort_unstable();
            matched_domain_ids.dedup();
            for id in matched_domain_ids {
                *candidate_counts.entry(id).or_insert(0) += 1;
            }
        }

        if let Some(ip) = req.ip {
            let mut matched_ip_ids = self.ip_trie.search(ip);
            matched_ip_ids.sort_unstable();
            matched_ip_ids.dedup();
            for id in matched_ip_ids {
                *candidate_counts.entry(id).or_insert(0) += 1;
            }
        }

        for id in &self.any_network_rules {
            *candidate_counts.entry(*id).or_insert(0) += 1;
        }

        let mut valid_candidates = Vec::new();
        for (&id, &count) in &candidate_counts {
            let rule = &self.rule_table[id];
            let required = if rule.mode == "and" {
                let mut req_cnt = 0;
                if rule.has_domain_filters() { req_cnt += 1; }
                if rule.has_ip_filters() { req_cnt += 1; }
                if req_cnt == 0 { 1 } else { req_cnt }
            } else {
                1
            };
            
            if count >= required {
                valid_candidates.push(id);
            }
        }

        valid_candidates.sort_unstable();

        for id in valid_candidates {
            let rule = &self.rule_table[id];
            if rule.matches_port(req.port) && rule.matches_extra(req) {
                tracing::debug!(
                    "[ROUTE] {} :{}/{} → [{}] (命中规则 #{})",
                    req.domain
                        .map(|d| d.to_string())
                        .or_else(|| req.ip.map(|i| i.to_string()))
                        .unwrap_or_else(|| "?".into()),
                    req.port,
                    req.protocol,
                    rule.outbound,
                    id
                );
                return Some(rule.outbound.clone());
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn test_router_engine() {
        let rules = vec![
            // Rule 0: block ads
            Rule {
                id: 0,
                mode: "or".to_string(),
                outbound: "block".to_string(),
                domain_suffix: vec!["ads.com".to_string()],
                domain_keyword: vec!["tracker".to_string()],
                domain_regex: vec!["^.*-ad\\..*$".to_string()],
                geosite: vec![],
                ip_cidr: vec!["8.8.8.8/32".parse().unwrap()],
                source_ip_cidr: vec![],
                source_mac: vec![],
                geoip: vec![],
                port: vec![],
                protocol: vec![],
                inbound: vec![],
                process_name: vec![],
            },
            // Rule 1: direct cn
            Rule {
                id: 1,
                mode: "or".to_string(),
                outbound: "direct".to_string(),
                domain_suffix: vec!["cn".to_string(), "baidu.com".to_string()],
                domain_keyword: vec![],
                domain_regex: vec![],
                geosite: vec![],
                ip_cidr: vec!["192.168.0.0/16".parse().unwrap()],
                source_ip_cidr: vec![],
                source_mac: vec![],
                geoip: vec![],
                port: vec![],
                protocol: vec![],
                inbound: vec![],
                process_name: vec![],
            },
            // Rule 2: proxy google
            Rule {
                id: 2,
                mode: "or".to_string(),
                outbound: "proxy".to_string(),
                domain_suffix: vec!["google.com".to_string()],
                domain_keyword: vec![],
                domain_regex: vec![],
                geosite: vec![],
                ip_cidr: vec![],
                source_ip_cidr: vec![],
                source_mac: vec![],
                geoip: vec![],
                port: vec![],
                protocol: vec![],
                inbound: vec![],
                process_name: vec![],
            },
            // Rule 3: proxy specific port
            Rule {
                id: 3,
                mode: "or".to_string(),
                outbound: "proxy_port".to_string(),
                domain_suffix: vec![],
                domain_keyword: vec![],
                domain_regex: vec![],
                geosite: vec![],
                ip_cidr: vec![],
                source_ip_cidr: vec![],
                source_mac: vec![],
                geoip: vec![],
                port: vec![22], // SSH
                protocol: vec![],
                inbound: vec![],
                process_name: vec![],
            },
        ];

        let engine = RouterEngine::new(
            rules, 
            "default".to_string(), 
            ".",
            &std::collections::HashMap::new()
        ).unwrap();

        // 1. match ads.com -> block
        let out = engine.route(RoutingRequest {
            domain: Some("banner.ads.com"),
            ip: None,
            port: 80,
            protocol: "",
            source_ip: None,
            source_mac: None,
            inbound: None,
            process_name: None,
        });
        assert_eq!(out, "block");

        // 2. match tracker keyword -> block
        let out = engine.route(RoutingRequest {
            domain: Some("my-tracker-server.net"),
            ip: None,
            port: 80,
            protocol: "",
            source_ip: None,
            source_mac: None,
            inbound: None,
            process_name: None,
        });
        assert_eq!(out, "block");

        // 3. match baidu.com -> direct
        let out = engine.route(RoutingRequest {
            domain: Some("www.baidu.com"),
            ip: None,
            port: 443,
            protocol: "",
            source_ip: None,
            source_mac: None,
            inbound: None,
            process_name: None,
        });
        assert_eq!(out, "direct");

        // 4. match IP cidr -> direct
        let out = engine.route(RoutingRequest {
            domain: None,
            ip: Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100))),
            port: 80,
            protocol: "",
            source_ip: None,
            source_mac: None,
            inbound: None,
            process_name: None,
        });
        assert_eq!(out, "direct");

        // 5. match default
        let out = engine.route(RoutingRequest {
            domain: Some("unknown.com"),
            ip: Some(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4))),
            port: 80,
            protocol: "",
            source_ip: None,
            source_mac: None,
            inbound: None,
            process_name: None,
        });
        assert_eq!(out, "default");

        // 6. match port 22 -> proxy_port
        let out = engine.route(RoutingRequest {
            domain: Some("unknown.com"),
            ip: None,
            port: 22,
            protocol: "",
            source_ip: None,
            source_mac: None,
            inbound: None,
            process_name: None,
        });
        assert_eq!(out, "proxy_port");

        // 7. priority test
        let out = engine.route(RoutingRequest {
            domain: Some("ads.com"),
            ip: None,
            port: 22,
            protocol: "",
            source_ip: None,
            source_mac: None,
            inbound: None,
            process_name: None,
        });
        assert_eq!(out, "block");

        // 8. match regex -> block
        let out = engine.route(RoutingRequest {
            domain: Some("google-ad.com"),
            ip: None,
            port: 80,
            protocol: "",
            source_ip: None,
            source_mac: None,
            inbound: None,
            process_name: None,
        });
        assert_eq!(out, "block");
    }

    fn ip_rule(id: RuleId, outbound: &str, cidrs: &[&str]) -> Rule {
        Rule {
            id,
            mode: "or".to_string(),
            outbound: outbound.to_string(),
            domain_suffix: vec![],
            domain_keyword: vec![],
            domain_regex: vec![],
            geosite: vec![],
            ip_cidr: cidrs.iter().map(|c| c.parse().unwrap()).collect(),
            source_ip_cidr: vec![],
            source_mac: vec![],
            geoip: vec![],
            port: vec![],
            protocol: vec![],
            inbound: vec![],
            process_name: vec![],
        }
    }

    #[test]
    fn test_direct_v4_cidrs_unify_and_exclude_overlap() {
        // 手动 ip_cidr 与 geoip 走同一条 all_v4_cidrs 汇聚路径, 这里用手动 CIDR 验证
        // "统一收集 + 安全排除重叠"。
        let rules = vec![
            // id0 (高优先级): 1.2.3.0/24 → proxy
            ip_rule(0, "proxy", &["1.2.3.0/24"]),
            // id1: 直连段, 其中 1.2.0.0/16 与上面 proxy 段重叠 → 应被排除
            ip_rule(1, "direct", &["10.0.0.0/8", "1.2.0.0/16"]),
        ];
        let engine = RouterEngine::new(rules, "proxy".to_string(), "/nonexistent", &HashMap::new()).unwrap();

        let direct = engine.direct_v4_cidrs(|t| t == "direct");
        assert!(direct.contains(&"10.0.0.0/8".parse().unwrap()), "纯直连段应保留");
        assert!(
            !direct.contains(&"1.2.0.0/16".parse().unwrap()),
            "与 proxy 段重叠的直连段必须排除, 否则会绕过代理泄漏"
        );
        assert_eq!(direct.len(), 1);
    }

    #[test]
    fn route_matched_none_when_unclassified() {
        let rules = vec![ip_rule(0, "proxy", &["1.2.3.0/24"])];
        let engine = RouterEngine::new(rules, "default".to_string(), "/nonexistent", &HashMap::new()).unwrap();
        let req = |ip: &str| RoutingRequest {
            domain: None,
            ip: Some(ip.parse().unwrap()),
            port: 80,
            protocol: "tcp",
            source_ip: None,
            source_mac: None,
            inbound: None,
            process_name: None,
        };
        // 命中规则 → Some
        assert_eq!(engine.route_matched(&req("1.2.3.5")).as_deref(), Some("proxy"));
        // 未命中 → None (供 auto_classify 介入); route() 才回落 default
        assert!(engine.route_matched(&req("9.9.9.9")).is_none());
        assert_eq!(engine.route(req("9.9.9.9")), "default");
        assert_eq!(engine.default_outbound(), "default");
    }
}

#[cfg(test)]
mod inbound_tests {
    use super::*;

    fn rule_for_inbound(id: RuleId, outbound: &str, inbound: Vec<&str>) -> Rule {
        Rule {
            id,
            mode: "or".to_string(),
            outbound: outbound.to_string(),
            domain_suffix: vec!["example.com".to_string()],
            domain_keyword: vec![],
            domain_regex: vec![],
            geosite: vec![],
            ip_cidr: vec![],
            source_ip_cidr: vec![],
            source_mac: vec![],
            geoip: vec![],
            port: vec![],
            protocol: vec![],
            inbound: inbound.into_iter().map(String::from).collect(),
            process_name: vec![],
        }
    }

    fn engine(rules: Vec<Rule>) -> RouterEngine {
        RouterEngine::new(
            rules,
            "default".to_string(),
            ".",
            &std::collections::HashMap::new(),
        )
        .expect("测试规则应能构建引擎")
    }

    fn req<'a>(domain: &'a str, inbound: Option<&'a str>) -> RoutingRequest<'a> {
        RoutingRequest {
            domain: Some(domain),
            ip: None,
            port: 443,
            protocol: "tcp",
            source_ip: None,
            source_mac: None,
            inbound,
            process_name: None,
        }
    }

    /// 同一个域名, 从不同入站进来要能走不同出口 —— 这就是本特性的全部意义。
    #[test]
    fn same_domain_routes_differently_per_inbound() {
        let e = engine(vec![
            rule_for_inbound(0, "via_a", vec!["in-a"]),
            rule_for_inbound(1, "via_b", vec!["in-b"]),
        ]);
        assert_eq!(e.route(req("example.com", Some("in-a"))), "via_a");
        assert_eq!(e.route(req("example.com", Some("in-b"))), "via_b");
    }

    /// 不带 `inbound` 条件的规则对所有入站生效 (向后兼容: 老配置行为不变)。
    #[test]
    fn rule_without_inbound_matches_any() {
        let e = engine(vec![rule_for_inbound(0, "anywhere", vec![])]);
        assert_eq!(e.route(req("example.com", Some("in-a"))), "anywhere");
        assert_eq!(e.route(req("example.com", None)), "anywhere");
    }

    /// 入站 tag 对不上 → 不命中, 落到默认出口。
    #[test]
    fn non_matching_inbound_falls_through() {
        let e = engine(vec![rule_for_inbound(0, "via_a", vec!["in-a"])]);
        assert_eq!(e.route(req("example.com", Some("in-other"))), "default");
    }

    /// **信息缺失时不猜**: 调用方没提供入站 tag, 带 `inbound` 条件的规则一律不命中。
    ///
    /// 反过来 (缺失就放宽成"任意入站都算") 会让本该只对某入站生效的规则**外溢**到
    /// 所有连接上 —— 例如"家人那条入站走固定落地"的规则会把自己的流量也带过去,
    /// 而且完全无声。宁可不命中。
    #[test]
    fn missing_inbound_never_matches_inbound_scoped_rule() {
        let e = engine(vec![rule_for_inbound(0, "family_exit", vec!["in-family"])]);
        assert_eq!(
            e.route(req("example.com", None)),
            "default",
            "入站信息缺失时命中了限定入站的规则 —— 该规则会外溢到所有连接"
        );
    }

    fn rule_for_proc(id: RuleId, outbound: &str, procs: Vec<&str>) -> Rule {
        let mut r = rule_for_inbound(id, outbound, vec![]);
        r.process_name = procs.into_iter().map(String::from).collect();
        r
    }
    fn req_proc<'a>(domain: &'a str, proc_name: Option<&'a str>) -> RoutingRequest<'a> {
        let mut q = req(domain, None);
        q.process_name = proc_name;
        q
    }

    /// 按进程名分流: Telegram 走代理, 其余落默认。
    #[test]
    fn routes_by_process_name() {
        let e = engine(vec![rule_for_proc(0, "proxy", vec!["telegram", "Telegram"])]);
        assert_eq!(e.route(req_proc("example.com", Some("telegram"))), "proxy");
        assert_eq!(e.route(req_proc("example.com", Some("wechat"))), "default", "其它进程不命中");
    }

    /// 信息缺失不猜: 进程名未知 (非本机连接/查不到), 带 process_name 的规则不命中。
    #[test]
    fn missing_process_name_never_matches() {
        let e = engine(vec![rule_for_proc(0, "proxy", vec!["telegram"])]);
        assert_eq!(e.route(req_proc("example.com", None)), "default");
    }

    /// uses_process_name: 有 process_name 规则才返回 true (handler 据此决定是否扫 /proc)。
    #[test]
    fn uses_process_name_flag() {
        assert!(engine(vec![rule_for_proc(0, "proxy", vec!["x"])]).uses_process_name());
        assert!(!engine(vec![rule_for_inbound(0, "proxy", vec![])]).uses_process_name());
    }
}
