use aho_corasick::{AhoCorasick, AhoCorasickBuilder};
use ipnet::IpNet;
use regex::RegexSet;
use std::collections::HashMap;
use std::net::IpAddr;

pub type OutboundTag = String;
pub type RuleId = usize;

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
        if !self.source_ip_cidr.is_empty() {
            if let Some(src_ip) = req.source_ip {
                if !self.source_ip_cidr.iter().any(|net| net.contains(&src_ip)) {
                    return false;
                }
            } else {
                return false;
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
                .or_insert_with(DomainTrieNode::default);
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
}

pub struct RoutingRequest<'a> {
    pub domain: Option<&'a str>,
    pub ip: Option<IpAddr>,
    pub port: u16,
    pub protocol: &'a str, // "tcp" or "udp"
    pub source_ip: Option<IpAddr>,
    pub source_mac: Option<&'a str>,
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
        let mut any_network_rules = Vec::new();

        for rule in &rules {
            if !rule.has_network_filters() {
                any_network_rules.push(rule.id);
                continue;
            }

            for cidr in &rule.ip_cidr {
                ip_trie.insert(*cidr, rule.id);
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
        })
    }

    pub fn route(&self, req: RoutingRequest) -> OutboundTag {
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
            let rule = &self.rule_table[id as usize];
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
            let rule = &self.rule_table[id as usize];
            if rule.matches_port(req.port) && rule.matches_extra(&req) {
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
                return rule.outbound.clone();
            }
        }

        tracing::debug!(
            "[ROUTE] {} :{}/{} → [{}] (默认出口, 无规则命中)",
            req.domain
                .map(|d| d.to_string())
                .or_else(|| req.ip.map(|i| i.to_string()))
                .unwrap_or_else(|| "?".into()),
            req.port,
            req.protocol,
            self.default_outbound
        );
        self.default_outbound.clone()
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
        });
        assert_eq!(out, "block");
    }
}
