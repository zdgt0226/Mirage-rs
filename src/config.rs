use serde::Deserialize;

#[derive(Debug, Deserialize, Clone)]
pub struct GuiConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_gui_listen")]
    pub listen: String,
}

fn default_gui_listen() -> String {
    "127.0.0.1:9090".to_string()
}

#[derive(Debug, Deserialize)]
pub struct Config {
    #[serde(default = "default_schema_version")]
    pub schema_version: u32,
    #[serde(default = "default_log_level")]
    pub log_level: String,
    pub inbounds: Vec<InboundConfig>,
    pub outbounds: Vec<OutboundConfig>,
    pub routing: RoutingConfig,
    pub advanced_dns: Option<AdvancedDnsConfig>,
    pub api: Option<ApiConfig>,
    pub tuning: Option<TuningConfig>,
    #[serde(default)]
    pub gui: Option<GuiConfig>,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum InboundConfig {
    Socks {
        tag: String,
        listen: String,
        port: u16,
    },
    Dns {
        tag: String,
        listen: String,
        port: u16,
    },
    MirageServer {
        tag: String,
        listen: String,
        port: u16,
        password: String,
        camouflage_host: Option<String>,
    },
    Mixed {
        tag: String,
        listen: String,
        port: u16,
    },
}

#[derive(Debug, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum OutboundConfig {
    Pyreality {
        tag: String,
        server: String,
        server_port: u16,
        password: String,
        camouflage_host: String,
        #[serde(default = "default_pool_size")]
        pool_size: usize,
    },
    Direct {
        tag: String,
    },
    Block {
        tag: String,
    },
    Urltest {
        tag: String,
        outbounds: Vec<String>,
        #[serde(default = "default_probe_url")]
        url: String,
        #[serde(default = "default_urltest_interval")]
        interval: u64,
        #[serde(default = "default_urltest_tolerance")]
        tolerance: u64,
    },
    Fallback {
        tag: String,
        outbounds: Vec<String>,
        #[serde(default = "default_probe_url")]
        url: String,
        #[serde(default = "default_urltest_interval")]
        interval: u64,
    },
    Selector {
        tag: String,
        outbounds: Vec<String>,
    },
}

fn default_probe_url() -> String {
    "http://www.gstatic.com/generate_204".to_string()
}

#[derive(Debug, Deserialize)]
pub struct RoutingConfig {
    pub default_outbound: String,
    #[serde(default)]
    pub geo_alias: std::collections::HashMap<String, String>,
    pub rules: Vec<RuleConfig>,
}

#[derive(Debug, Deserialize, Default)]
pub struct RuleConfig {
    #[serde(default)]
    pub mode: Option<String>,
    pub outbound: String,
    #[serde(default)]
    pub domain_suffix: Vec<String>,
    #[serde(default)]
    pub domain_keyword: Vec<String>,
    #[serde(default)]
    pub domain_regex: Vec<String>,
    #[serde(default)]
    pub geosite: Vec<String>,
    #[serde(default)]
    pub ip_cidr: Vec<String>,
    #[serde(default)]
    pub geoip: Vec<String>,
    #[serde(default)]
    pub source_ip_cidr: Vec<String>,
    #[serde(default)]
    pub source_mac: Vec<String>,
    #[serde(default)]
    pub protocol: Vec<String>,
    #[serde(default)]
    pub port: Vec<u16>,
}

#[derive(Debug, Deserialize)]
pub struct AdvancedDnsConfig {

    #[serde(skip)]
    pub cached_cn_dns: Option<std::net::SocketAddr>,
    #[serde(skip)]
    pub cached_remote_host: Option<String>,
    #[serde(skip)]
    pub cached_remote_port: Option<u16>,
    pub default: Option<String>,
    #[serde(default)]
    pub resolvers: Vec<DnsResolver>,
    #[serde(default)]
    pub rules: Vec<DnsRule>,
    pub fakeip: Option<FakeIpConfig>,
    pub cache: Option<DnsCacheConfig>,
}

#[derive(Debug, Deserialize)]
pub struct DnsResolver {
    pub tag: String,
    pub address: String,
    pub via: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct DnsRule {
    #[serde(rename = "match")]
    pub match_rule: String,
    #[serde(rename = "use")]
    pub use_resolver: String,
}

#[derive(Debug, Deserialize)]
pub struct FakeIpConfig {
    pub enabled: bool,
    pub inet4_range: String,
}

#[derive(Debug, Deserialize)]
pub struct DnsCacheConfig {
    pub enabled: bool,
    #[serde(default = "default_dns_cache_size")]
    pub max_entries: usize,
}

#[derive(Debug, Deserialize)]
pub struct ApiConfig {
    pub listen: String,
    pub secret: String,
}

#[derive(Debug, Deserialize)]
pub struct TuningConfig {
    pub geodata_dir: Option<String>,
    pub geosite_url: Option<String>,
    pub geoip_url: Option<String>,
    pub decision_cache_max_entries: Option<usize>,
    pub tcp_keepalive: Option<u64>,
}

fn default_schema_version() -> u32 {
    1
}

fn default_urltest_interval() -> u64 {
    300
}

fn default_urltest_tolerance() -> u64 {
    50
}

fn default_dns_cache_size() -> usize {
    10000
}

fn default_log_level() -> String {
    "info".to_string()
}

fn default_pool_size() -> usize {
    16
}

impl Config {
    /// Loads configuration from a JSON file.
    pub fn load_from_file(path: &str) -> anyhow::Result<Self> {
        let content = std::fs::read_to_string(path)?;
        let config: Config = serde_json::from_str(&content)?;
        Ok(config)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_json_config() {
        let json = r#"{
            "log_level": "debug",
            "inbounds": [
                {
                    "type": "socks",
                    "tag": "socks-in",
                    "listen": "127.0.0.1",
                    "port": 1080
                }
            ],
            "outbounds": [
                {
                    "type": "pyreality",
                    "tag": "proxy",
                    "server": "1.2.3.4",
                    "server_port": 443,
                    "password": "pass",
                    "camouflage_host": "apple.com"
                },
                {
                    "type": "direct",
                    "tag": "direct"
                }
            ],
            "routing": {
                "default_outbound": "proxy",
                "rules": [
                    {
                        "outbound": "direct",
                        "geosite": ["cn"]
                    }
                ]
            }
        }"#;

        let config: Config = serde_json::from_str(json).unwrap();
        assert_eq!(config.log_level, "debug");
        assert_eq!(config.inbounds.len(), 1);
        
        match &config.inbounds[0] {
            InboundConfig::Socks { port, .. } => assert_eq!(*port, 1080),
            _ => panic!("wrong inbound type"),
        }

        assert_eq!(config.outbounds.len(), 2);
        match &config.outbounds[0] {
            OutboundConfig::Pyreality { tag, pool_size, .. } => {
                assert_eq!(tag, "proxy");
                assert_eq!(*pool_size, 16); // default pool size applied!
            }
            _ => panic!("wrong outbound type"),
        }

        assert_eq!(config.routing.default_outbound, "proxy");
        assert_eq!(config.routing.rules[0].geosite[0], "cn");
        assert!(config.routing.rules[0].domain_suffix.is_empty()); // default empty vec applied!
    }
}
