use serde::Deserialize;

#[derive(Debug, Deserialize, Clone)]
pub struct GuiConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_gui_listen")]
    pub listen: String,
    /// 可选 API 鉴权 token。设了则所有 /api/* 请求必须携带它 (Authorization: Bearer /
    /// mirage_token cookie / ?token= 三选一)。不设 = 不鉴权 —— localhost 默认部署安全,
    /// 但把 listen 改成 0.0.0.0 暴露到公网时**强烈建议**设一个随机 token, 否则任何人可读
    /// 日志/配置、改路由规则。浏览器访问 http://host:9090/?token=XXX 一次即种 cookie。
    #[serde(default)]
    pub token: Option<String>,
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
    /// 可选日志文件路径. 设了就同时写文件 (append 模式) 和 stdout, systemd
    /// journalctl 也仍能抓到 stdout 副本. 不设保持 stdout-only (老行为).
    /// 常见值 "/var/log/mirage-rs/server.log" 或 client.log.
    #[serde(default)]
    pub log_file: Option<String>,
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
        // 服务端 → 客户端 (下载) 方向的 brutal 速率上限, 单位 Mbps.
        // 不设 (或 = 0) 则不启用 brutal, 走系统默认 CC (BBR/Cubic).
        // Note: 服务端这一侧决定下载速度, 比客户端的 brutal 设置重要得多.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        brutal_rate_mbps: Option<u64>,
    },
    Mixed {
        tag: String,
        listen: String,
        port: u16,
    },
    Transparent {
        tag: String,
        listen: String,
        port: u16,
        // 挂 tc_divert 的 LAN 网卡 (纯 eBPF 抓裸-IP 转发流量)。不设则只跑
        // sk_lookup fake-IP 拦截, 不接管裸-IP 转发流量。
        #[serde(default, skip_serializing_if = "Option::is_none")]
        interface: Option<String>,
        // 是否让网关本机自身流量也走代理 (cgroup/connect4 重定向本机出向 fake-IP)。
        // 需本机 DNS 指向 mirage 才能拿到 fake-IP。默认 false (仅转发流量走代理)。
        #[serde(default)]
        proxy_local: bool,
    },
}

#[derive(Debug, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum OutboundConfig {
    #[serde(alias = "pyreality")]
    Mirage {
        tag: String,
        server: String,
        server_port: u16,
        password: String,
        camouflage_host: String,
        #[serde(default = "default_pool_size")]
        pool_size: usize,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        brutal_rate_mbps: Option<u64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        brutal_base_rtt_ms: Option<u64>,
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
        #[serde(default = "default_test_type")]
        test_type: String,
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

    /// 国内/直连域名的上游 DNS 列表 (tag=cn/direct 的 resolver 全部收集)。
    /// udp_query 会向全部并行发 + 重传, 任一先回即用 —— 单上游单发丢一个 UDP 包
    /// 就整体失败, 客户端重传累积 ~11s。空则用默认双公共 DNS 兜底。
    #[serde(skip)]
    pub cached_cn_dns: Vec<std::net::SocketAddr>,
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
    pub xdp_interface: Option<String>,
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
    /// 可选: fake-IP 映射持久化文件路径。设了则启动加载 + 周期/退出落盘, 网关重启后
    /// 客户端仍揣着的旧 fake-IP (≤300s TTL) 还能反查到域名, 避免重启后代理连接断一段。
    /// 不设 = 纯内存 (向后兼容)。install.sh 网关模式默认填 /var/lib/mirage-rs/fakeip.cache。
    #[serde(default)]
    pub persist_path: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct DnsCacheConfig {
    pub enabled: bool,
    #[serde(default = "default_dns_cache_size")]
    pub max_entries: usize,
}

/// ⚠️ **已废弃且从未生效** —— 历史遗留 stub: 本结构解析后**从不被任何代码使用**,
/// `secret` **不提供任何鉴权**。设了它 = 什么都没设(安全 footgun)。
/// **API 鉴权请用 `gui.token`**(见 api/mod.rs::auth_mw)。
/// 字段保留仅为在启动时**检测并警告**设置过它的用户, 未来版本移除。
#[derive(Debug, Deserialize)]
pub struct ApiConfig {
    #[serde(default)]
    pub listen: String,
    #[serde(default)]
    pub secret: String,
}

#[derive(Debug, Deserialize)]
pub struct TuningConfig {
    pub geodata_dir: Option<String>,
    // decision_cache_max_entries + tcp_keepalive 在 alpha.18 删除: 定义但从
    // 未在任何代码路径引用, 保留只会误导用户以为配置生效. serde 遇未知字段
    // 默认忽略, 不会 break 已部署 config 文件.
    /// eBPF 加载策略. 默认 Auto (根据 CLI 子命令决定):
    /// - `auto` (默认): client 模式启用, server 模式跳过. 服务端 BPF 全部子系统
    ///   都没价值 — sockmap splice 要明文流 (服务端入站是加密的, 必须 userspace
    ///   解密), sockops RTT 数据没人消费, XDP DNS 只对本地应用有意义, sk_lookup
    ///   透明代理只劫持本地流量.
    /// - `force`: 不论 client/server 都强制加载 (调试用).
    /// - `off`: 不论 client/server 都跳过.
    #[serde(default)]
    pub ebpf_mode: Option<EbpfMode>,

    /// 多源 Geo 数据下载. 每个 source 独立指定 URL + via (direct/proxy).
    /// 下载后保存为 `<name>.dat`. 路由规则引用形如 `geosite: ["loyalsoldier.dat:cn"]`
    /// 或借助 `routing.geo_alias` 起短名 (例如 `{"ls": "loyalsoldier.dat"}`,
    /// 之后规则写 `geosite: ["ls:cn"]`).
    ///
    /// v0.4.3 起替代旧的 `geosite_url` + `geoip_url` 单 URL 字段.
    #[serde(default)]
    pub geo_sources: Vec<GeoSource>,

    /// Geo 文件更新检查间隔 (天). 默认 7.
    pub geo_update_days: Option<u32>,
}

#[derive(Debug, Deserialize, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum EbpfMode {
    Auto,
    Force,
    Off,
}

#[derive(Debug, Deserialize, Clone)]
pub struct GeoSource {
    /// 文件名 (不含 .dat 后缀, 自动加). 必须在 geo_sources 内唯一.
    pub name: String,
    /// 数据类型: geosite (域名规则) 或 geoip (IP CIDR 规则).
    pub kind: GeoKind,
    /// 下载 URL (通常是 GitHub release).
    pub url: String,
    /// 下载通道: direct (默认, 直连) 或 proxy (走客户端本地 socks/mixed inbound).
    /// 国内服务器拉 GitHub 可设 proxy, 客户端通常 direct 即可 (除非 GitHub 被屏).
    #[serde(default)]
    pub via: GeoVia,
}

#[derive(Debug, Deserialize, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum GeoKind {
    Geosite,
    Geoip,
}

#[derive(Debug, Deserialize, Clone, Copy, PartialEq, Eq, Default)]
#[serde(rename_all = "lowercase")]
pub enum GeoVia {
    #[default]
    Direct,
    Proxy,
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

fn default_test_type() -> String {
    "ping".to_string()
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
                    "type": "mirage",
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
            OutboundConfig::Mirage { tag, pool_size, .. } => {
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
