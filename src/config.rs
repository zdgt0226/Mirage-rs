use serde::Deserialize;

/// 允许路由规则的列表字段既写**单个标量**也写**数组** —— 与 sing-box/Clash 一致。
///
/// 三种形式都接受, 反序列化成 `Vec<T>`:
/// - 缺省(字段不写)  → `[]`(由 `#[serde(default)]` 提供, 不经过本函数)
/// - 单值 `"port": 443` / `"domain_suffix": "cn"` → `[443]` / `["cn"]`
/// - 数组 `"port": [80, 443]` → 原样
///
/// 早前只接受数组, 写单值会**解析失败**(用户实测踩到)。这纯属易用性,
/// 不改变任何匹配语义。
fn one_or_many<'de, D, T>(de: D) -> Result<Vec<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum OneOrMany<T> {
        One(T),
        Many(Vec<T>),
    }
    Ok(match OneOrMany::<T>::deserialize(de)? {
        OneOrMany::One(v) => vec![v],
        OneOrMany::Many(v) => v,
    })
}

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

/// 服务端的**上游出口**配置 —— 配了它, Mirage 服务端就不再直连目标, 而是把流量
/// 再经 Shadowsocks 发往上游 SS 服务器, 即把 Mirage 当作中转站:
///
/// ```text
/// 客户端 ──(Mirage 隧道)──▶ Mirage 服务端 ──(Shadowsocks)──▶ SS 服务器 ──▶ 目标
/// ```
///
/// ⚠️ **仅作用于 TCP**。SS 的 UDP 是另一套包格式, 当前未实现 —— 配了 SS 上游时
/// 服务端的 UDP 中继**仍走直连**, 意味着 TCP 与 UDP 的出口 IP 不同。启动时会 WARN。
#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum UpstreamConfig {
    Shadowsocks {
        server: String,
        server_port: u16,
        password: String,
        /// aes-128-gcm / aes-256-gcm / chacha20-ietf-poly1305。
        /// legacy 流式加密 (aes-256-cfb 等) 无完整性校验、已废弃, 不支持。
        method: String,
        /// 配了上游时 UDP 怎么办。默认 `block`, 理由见 [`UdpPolicy`]。
        #[serde(default)]
        udp: UdpPolicy,
    },
    /// 上游走 WireGuard: 本服务端把流量再经 WG 隧道发往 peer。
    ///
    /// 与 SS 上游同样**目前仅作用于 TCP** —— 服务端的 UDP 中继尚未接到 WG 隧道上,
    /// 故 `udp` 同样默认 `block` (放行会让 UDP 从本机 IP 直连出去, 与 TCP 出口 IP 不一致)。
    Wireguard {
        private_key: String,
        peer_public_key: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        preshared_key: Option<String>,
        endpoint: String,
        address: String,
        #[serde(default = "default_wg_mtu")]
        mtu: usize,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        persistent_keepalive: Option<u16>,
        /// 隧道内 DNS 服务器 (如 `10.0.0.1`), 对齐 wg-quick 的 `DNS =`。
        /// 配了则走本隧道的域名**经隧道解析**; 不配 = 本机解析 (原行为)。
        #[serde(default, skip_serializing_if = "Option::is_none")]
        dns: Option<String>,
        /// 默认 `tunnel` (UDP 也走 WG 隧道, 与 TCP 同出口)。
        #[serde(default = "default_wg_udp")]
        udp: UdpPolicy,
    },
}

/// 配置了上游出口时, 服务端对 UDP 的处理策略。
///
/// **默认 `Block`, 这是刻意的**: SS 的 UDP 尚未实现, 若放行则 UDP 会从 Mirage 服务端
/// **自己的 IP** 直连出去, 而 TCP 从上游出口出去 —— 两者出口 IP 不同。
///
/// 这对中转最典型的用途(落地解锁)不是"不一致"而是**功能性错误**: 流媒体越来越多走
/// QUIC, QUIC 走直连意味着目标看到的是错误的 IP → 区域判定错。而且它**不会**像"UDP 被封"
/// 那样回落 TCP —— QUIC 成功了, 只是从错误的出口成功的, 结果是解锁时灵时不灵且极难排查。
///
/// 你配了中转, 意图就是流量从上游出去。**安全的失败方式是"不发", 而不是"发到别处去"。**
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UdpPolicy {
    /// 拒绝 UDP 中继 (默认)。客户端会立刻收到失败而非静默走错出口;
    /// QUIC 会回落 TCP(页面照常), 但游戏/WebRTC 不可用。
    #[default]
    Block,
    /// 保持旧行为: UDP 从本机直连出去。**出口 IP 与 TCP 不同**, 仅在你确认
    /// 不介意(例如上游只为绕路而非隐藏出口)时才选。
    Direct,
    /// UDP 也走上游隧道, 与 TCP 同一个出口。
    ///
    /// 仅 WireGuard 上游支持 (WG 隧道本就跑 IP 包, UDP 天然可承载); SS 的 UDP 是另一套
    /// 包格式、尚未实现, 给 SS 配这个会在 check 阶段报错而不是静默降级。
    Tunnel,
}

/// WireGuard 上游的 UDP 默认策略 = 走隧道。
///
/// 与 SS 上游默认 `block` 不同, 因为 block 的理由 (UDP 从本机 IP 出去、与 TCP 出口不一致)
/// 在 WG 上**不成立** —— WG 隧道能承载 UDP, 出口与 TCP 完全一致。
fn default_wg_udp() -> UdpPolicy {
    UdpPolicy::Tunnel
}

/// SOCKS5 / HTTP 入站的认证凭据 (可选)。
///
/// **不配 = 不鉴权**(向后兼容既有配置)。但 socks/mixed 入站一旦监听非回环地址而又不配它,
/// 就是一个**开放代理** —— 任何能连到该端口的人都能白嫖隧道, 流量从你的服务端出去,
/// 出口 IP 会被滥用/拉黑。故 `lib.rs` 在这种组合下启动时 WARN。
#[derive(Debug, Clone, Deserialize)]
pub struct InboundAuth {
    pub username: String,
    pub password: String,
}

impl InboundAuth {
    /// 常量时间校验用户名+密码。
    ///
    /// 用非短路的 `&` 且两侧都算完, 避免"用户名错就立刻返回"这类时序差把凭据前缀泄漏出去。
    pub fn verify(&self, username: &[u8], password: &[u8]) -> bool {
        let u = ct_eq(username, self.username.as_bytes());
        let p = ct_eq(password, self.password.as_bytes());
        u & p
    }
}

/// 常量时间字节比较 (长度不同直接 false —— 长度本身不是秘密)。
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

#[derive(Debug, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum InboundConfig {
    Socks {
        tag: String,
        listen: String,
        port: u16,
        /// 可选认证。不设 = 不鉴权 (见 InboundAuth 的开放代理告警)。
        #[serde(default, skip_serializing_if = "Option::is_none")]
        auth: Option<InboundAuth>,
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
        // 握手 token 的时间戳容忍窗口 (秒). 客户端时钟与本机相差超过它 → auth 失败.
        // 默认 60 (见 hello_auth::DEFAULT_AUTH_TS_TOLERANCE_SECS)。别设太小: 首次握手
        // 用未同步的裸系统时钟, TIME_SYNC 卡在这个窗口上无法 bootstrap → 偏差大的机器锁死。
        #[serde(default = "default_auth_ts_tolerance")]
        auth_ts_tolerance_secs: u64,
        /// 可选上游出口: 配了则本服务端作为中转站, 流量再经 SS 发往上游 (仅 TCP)。
        /// 不配 = 直连目标 (原行为)。
        #[serde(default, skip_serializing_if = "Option::is_none")]
        upstream: Option<UpstreamConfig>,
    },
    Mixed {
        tag: String,
        listen: String,
        port: u16,
        /// 可选认证, 同时作用于 SOCKS5 (RFC 1929) 与 HTTP (Proxy-Authorization: Basic)。
        #[serde(default, skip_serializing_if = "Option::is_none")]
        auth: Option<InboundAuth>,
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
    /// WireGuard 出站: 选中的流量经 WG 隧道发往 peer, 不走 Mirage 隧道。
    ///
    /// 密钥都是标准 WireGuard 的 **base64 32 字节 x25519 密钥** (与 `wg genkey`/`wg pubkey`
    /// 一致), 不是任意密码 —— 填错长度会在启动时被拦下, 而不是留到每条连接静默失败。
    Wireguard {
        tag: String,
        /// 本端私钥 (base64)。
        private_key: String,
        /// 对端公钥 (base64)。
        peer_public_key: String,
        /// 可选预共享密钥 (base64)。
        #[serde(default, skip_serializing_if = "Option::is_none")]
        preshared_key: Option<String>,
        /// peer 的 UDP endpoint, `host:port`。
        endpoint: String,
        /// 本端在隧道内的地址, 如 `10.0.0.2`。
        address: String,
        /// 隧道 MTU, 默认 1420。
        #[serde(default = "default_wg_mtu")]
        mtu: usize,
        /// persistent-keepalive 秒数, 穿 NAT 用; 0 = 关。
        #[serde(default, skip_serializing_if = "Option::is_none")]
        persistent_keepalive: Option<u16>,
        /// 隧道内 DNS 服务器 (如 `10.0.0.1`), 对齐 wg-quick 的 `DNS =`。
        /// 配了则走本隧道的域名**经隧道解析**; 不配 = 本机解析 (原行为)。
        #[serde(default, skip_serializing_if = "Option::is_none")]
        dns: Option<String>,
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
    #[serde(default, deserialize_with = "one_or_many")]
    pub domain_suffix: Vec<String>,
    #[serde(default, deserialize_with = "one_or_many")]
    pub domain_keyword: Vec<String>,
    #[serde(default, deserialize_with = "one_or_many")]
    pub domain_regex: Vec<String>,
    #[serde(default, deserialize_with = "one_or_many")]
    pub geosite: Vec<String>,
    #[serde(default, deserialize_with = "one_or_many")]
    pub ip_cidr: Vec<String>,
    #[serde(default, deserialize_with = "one_or_many")]
    pub geoip: Vec<String>,
    #[serde(default, deserialize_with = "one_or_many")]
    pub source_ip_cidr: Vec<String>,
    #[serde(default, deserialize_with = "one_or_many")]
    pub source_mac: Vec<String>,
    #[serde(default, deserialize_with = "one_or_many")]
    pub protocol: Vec<String>,
    #[serde(default, deserialize_with = "one_or_many")]
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

fn default_wg_mtu() -> usize {
    1420
}

fn default_pool_size() -> usize {
    16
}

fn default_auth_ts_tolerance() -> u64 {
    crate::crypto::hello_auth::DEFAULT_AUTH_TS_TOLERANCE_SECS
}

impl Config {
    /// Loads configuration from a JSON file.
    pub fn load_from_file(path: &str) -> anyhow::Result<Self> {
        let content = std::fs::read_to_string(path)?;
        let config: Config = serde_json::from_str(&content)?;
        Ok(config)
    }

    /// 解析配置并**同时**收集校验问题。
    ///
    /// 刻意**不把问题当致命错误**: 配置里多一个字段就让网关起不来, 代价远大于收益
    /// (升级二进制时尤其危险)。校验的价值是"让你看见", 不是"拦住你" —— 与
    /// `api.secret` 那次"保留字段 + WARN"的处理一致。调用方负责把返回的问题打成 WARN。
    ///
    /// 覆盖两类:
    /// 1. **未知字段** —— 拼错的键此前被 serde 静默忽略, 用户永远不知道自己配了个寂寞;
    /// 2. **语义问题** —— 语法合法但逻辑不成立 (引用了不存在的 outbound、tag 重复等)。
    pub fn parse_with_diagnostics(content: &str) -> anyhow::Result<(Self, Vec<String>)> {
        let mut issues = Vec::new();
        let de = &mut serde_json::Deserializer::from_str(content);
        let config: Config = serde_ignored::deserialize(de, |path| {
            issues.push(format!("未知字段 `{}` (拼写错误? 已被忽略, 不会生效)", path));
        })?;
        issues.extend(config.semantic_issues());
        Ok((config, issues))
    }

    /// 语义校验: 语法没问题但逻辑不成立的配置。
    pub fn semantic_issues(&self) -> Vec<String> {
        let mut issues = Vec::new();

        // 收集全部 outbound tag, 顺带查重
        let mut tags: Vec<&str> = Vec::new();
        for ob in &self.outbounds {
            let tag = match ob {
                OutboundConfig::Mirage { tag, .. }
                | OutboundConfig::Wireguard { tag, .. }
                | OutboundConfig::Direct { tag }
                | OutboundConfig::Block { tag }
                | OutboundConfig::Urltest { tag, .. }
                | OutboundConfig::Fallback { tag, .. }
                | OutboundConfig::Selector { tag, .. } => tag.as_str(),
            };
            if tags.contains(&tag) {
                issues.push(format!("outbound tag `{tag}` 重复定义 (后者覆盖前者, 行为不确定)"));
            }
            tags.push(tag);
        }

        // WireGuard 出站: 密钥/地址/endpoint 在这里就验死。
        //
        // 这些错配的共同特征是**不会让进程起不来, 而是让每条连接静默失败** —— 服务看着健康,
        // 却什么都代理不了, 错误信息也指不到根因。所以必须在 check/启动阶段变成明确报错。
        for ob in &self.outbounds {
            if let OutboundConfig::Wireguard {
                tag, private_key, peer_public_key, preshared_key, endpoint, address, mtu, ..
            } = ob
            {
                for (val, what) in [
                    (private_key, "private_key"),
                    (peer_public_key, "peer_public_key"),
                ] {
                    if let Err(e) = crate::proxy::wg::decode_wg_key(val, what) {
                        issues.push(format!("outbound `{tag}`: {e}"));
                    }
                }
                if let Some(psk) = preshared_key {
                    if let Err(e) = crate::proxy::wg::decode_wg_key(psk, "preshared_key") {
                        issues.push(format!("outbound `{tag}`: {e}"));
                    }
                }
                if address.parse::<std::net::IpAddr>().is_err() {
                    issues.push(format!(
                        "outbound `{tag}`: address `{address}` 不是合法 IP \
                         (应是隧道内本端地址, 如 10.0.0.2, 不带掩码)"
                    ));
                }
                // endpoint 必须带端口 —— 少写端口是最常见的手抄错误
                if !endpoint.rsplit(':').next().is_some_and(|p| p.parse::<u16>().is_ok()) {
                    issues.push(format!(
                        "outbound `{tag}`: endpoint `{endpoint}` 缺少端口 (应形如 host:51820)"
                    ));
                }
                if *mtu == 0 || *mtu > 65503 {
                    issues.push(format!(
                        "outbound `{tag}`: mtu {mtu} 非法 (须 1..=65503, 常用 1420)"
                    ));
                }
            }
        }
        let known = |t: &str| tags.contains(&t);

        // 路由默认出站必须存在 —— 不存在则所有未命中规则的流量无处可去
        if !known(&self.routing.default_outbound) {
            issues.push(format!(
                "routing.default_outbound = `{}` 不存在于 outbounds (未命中任何规则的流量将无法路由)",
                self.routing.default_outbound
            ));
        }

        // 每条规则引用的出站必须存在 —— 否则该规则形同虚设, 且是静默的
        for (i, rule) in self.routing.rules.iter().enumerate() {
            if !known(&rule.outbound) {
                issues.push(format!(
                    "routing.rules[{i}].outbound = `{}` 不存在于 outbounds (该规则永远不会正确生效)",
                    rule.outbound
                ));
            }
        }

        // 出站组的成员必须存在, 且组不能为空
        for ob in &self.outbounds {
            let (tag, children, kind) = match ob {
                OutboundConfig::Urltest { tag, outbounds, .. } => (tag, outbounds, "urltest"),
                OutboundConfig::Fallback { tag, outbounds, .. } => (tag, outbounds, "fallback"),
                OutboundConfig::Selector { tag, outbounds, .. } => (tag, outbounds, "selector"),
                _ => continue,
            };
            if children.is_empty() {
                issues.push(format!("{kind} `{tag}` 的 outbounds 为空 (该组不可用)"));
            }
            for child in children {
                if !known(child) {
                    issues.push(format!("{kind} `{tag}` 引用了不存在的成员 `{child}`"));
                }
            }
            if children.iter().any(|c| c == tag) {
                issues.push(format!("{kind} `{tag}` 把自己列为成员 (自引用)"));
            }
        }

        // Mirage 出站的必填项非空
        for ob in &self.outbounds {
            if let OutboundConfig::Mirage { tag, server, server_port, password, .. } = ob {
                if server.trim().is_empty() {
                    issues.push(format!("mirage 出站 `{tag}` 的 server 为空"));
                }
                if *server_port == 0 {
                    issues.push(format!("mirage 出站 `{tag}` 的 server_port 为 0"));
                }
                if password.is_empty() {
                    issues.push(format!("mirage 出站 `{tag}` 的 password 为空 (服务端会认证失败)"));
                }
            }
        }

        // 入站 tag 查重 + 端口 0 + 服务端空密码
        let mut in_tags: Vec<&str> = Vec::new();
        for ib in &self.inbounds {
            let (tag, port) = match ib {
                InboundConfig::Socks { tag, port, .. }
                | InboundConfig::Dns { tag, port, .. }
                | InboundConfig::MirageServer { tag, port, .. }
                | InboundConfig::Mixed { tag, port, .. }
                | InboundConfig::Transparent { tag, port, .. } => (tag.as_str(), *port),
            };
            if in_tags.contains(&tag) {
                issues.push(format!("inbound tag `{tag}` 重复定义"));
            }
            in_tags.push(tag);
            if port == 0 {
                issues.push(format!("inbound `{tag}` 的 port 为 0"));
            }
            if let InboundConfig::MirageServer { tag, password, upstream, .. } = ib {
                if password.is_empty() {
                    issues.push(format!("mirage_server 入站 `{tag}` 的 password 为空 (任何人都能连)"));
                }
                // 上游出口配错会让服务端**拒绝启动**, 必须在 check 阶段就拦住 ——
                // 否则 `check && systemctl restart` 这个闸门对这条路径形同虚设。
                if let Some(UpstreamConfig::Wireguard {
                    private_key, peer_public_key, preshared_key, endpoint, address, mtu, ..
                }) = upstream
                {
                    for (val, what) in [
                        (private_key, "private_key"),
                        (peer_public_key, "peer_public_key"),
                    ] {
                        if let Err(e) = crate::proxy::wg::decode_wg_key(val, what) {
                            issues.push(format!("mirage_server 入站 `{tag}` 的 upstream: {e}"));
                        }
                    }
                    if let Some(psk) = preshared_key {
                        if let Err(e) = crate::proxy::wg::decode_wg_key(psk, "preshared_key") {
                            issues.push(format!("mirage_server 入站 `{tag}` 的 upstream: {e}"));
                        }
                    }
                    if address.parse::<std::net::IpAddr>().is_err() {
                        issues.push(format!(
                            "mirage_server 入站 `{tag}` 的 upstream.address `{address}` 不是合法 IP (不带掩码)"
                        ));
                    }
                    if !endpoint.rsplit(':').next().is_some_and(|p| p.parse::<u16>().is_ok()) {
                        issues.push(format!(
                            "mirage_server 入站 `{tag}` 的 upstream.endpoint `{endpoint}` 缺少端口"
                        ));
                    }
                    if *mtu == 0 || *mtu > 65503 {
                        issues.push(format!("mirage_server 入站 `{tag}` 的 upstream.mtu {mtu} 非法"));
                    }
                }
                if let Some(UpstreamConfig::Shadowsocks { udp, .. }) = upstream {
                    if matches!(udp, UdpPolicy::Tunnel) {
                        issues.push(format!(
                            "mirage_server 入站 `{tag}` 的 upstream.udp 不能是 `tunnel`: \
                             SS 的 UDP 是另一套包格式, 尚未实现。用 `block`(默认) 或 `direct`。"
                        ));
                    }
                }
                if let Some(UpstreamConfig::Shadowsocks {
                    server, server_port, password: ss_pw, method, ..
                }) = upstream
                {
                    match crate::proxy::shadowsocks::Method::parse(method) {
                        Err(e) => issues.push(format!("mirage_server 入站 `{tag}` 的 upstream: {e}")),
                        Ok(m) if m.is_2022() => {
                            // SIP022 的 password 是 base64 密钥且长度固定。写错不会让服务端
                            // 起不来, 而是**每条连接都静默失败** —— 服务看着健康却什么都代理
                            // 不了, 比起不来更难查。必须在这里拦住。
                            if let Err(e) =
                                crate::proxy::shadowsocks::decode_ss2022_psk(ss_pw, m.key_len())
                            {
                                issues.push(format!("mirage_server 入站 `{tag}` 的 upstream: {e}"));
                            }
                        }
                        Ok(_) => {}
                    }
                    if server.trim().is_empty() {
                        issues.push(format!("mirage_server 入站 `{tag}` 的 upstream.server 为空"));
                    }
                    if *server_port == 0 {
                        issues.push(format!("mirage_server 入站 `{tag}` 的 upstream.server_port 为 0"));
                    }
                    if ss_pw.is_empty() {
                        issues.push(format!("mirage_server 入站 `{tag}` 的 upstream.password 为空"));
                    }
                }
            }
        }

        issues
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

#[cfg(test)]
mod validation_tests {
    use super::{Config, RuleConfig};

    /// 一份最小可用配置; 各用例在其上做局部破坏。
    fn base() -> serde_json::Value {
        serde_json::json!({
            "log_level": "info",
            "inbounds": [
                { "type": "mixed", "tag": "in", "listen": "127.0.0.1", "port": 1080 }
            ],
            "outbounds": [
                { "type": "direct", "tag": "direct" },
                { "type": "block",  "tag": "block"  }
            ],
            "routing": { "default_outbound": "direct", "rules": [] }
        })
    }

    fn issues_of(v: &serde_json::Value) -> Vec<String> {
        let (_, issues) = Config::parse_with_diagnostics(&v.to_string()).expect("应能解析");
        issues
    }

    fn has(issues: &[String], needle: &str) -> bool {
        issues.iter().any(|i| i.contains(needle))
    }

    #[test]
    fn rule_port_accepts_scalar_and_array() {
        // 用户反馈: 单端口不该强制写数组 (sing-box/Clash 都允许标量)。
        // 关键是"单值被解成 [值]"而非丢失 —— check 通过只说明能解析, 这里验语义。
        let rule: RuleConfig = serde_json::from_str(
            r#"{"outbound":"direct","port":443}"#).unwrap();
        assert_eq!(rule.port, vec![443], "单端口标量应解成 [443]");

        let rule: RuleConfig = serde_json::from_str(
            r#"{"outbound":"direct","port":[80,443]}"#).unwrap();
        assert_eq!(rule.port, vec![80, 443], "数组应原样");

        // 缺省仍是空
        let rule: RuleConfig = serde_json::from_str(r#"{"outbound":"direct"}"#).unwrap();
        assert!(rule.port.is_empty());
    }

    #[test]
    fn rule_all_list_fields_accept_scalar() {
        // 全部 10 个列表字段都应支持标量, 不只是 port。
        let rule: RuleConfig = serde_json::from_str(r#"{
            "outbound":"direct",
            "domain_suffix":"cn", "domain_keyword":"ads", "domain_regex":"^x$",
            "geosite":"geosite.dat:cn", "ip_cidr":"10.0.0.0/8", "geoip":"geoip.dat:cn",
            "source_ip_cidr":"192.168.1.0/24", "source_mac":"aa:bb:cc:dd:ee:ff",
            "protocol":"tcp", "port":443
        }"#).unwrap();
        assert_eq!(rule.domain_suffix, vec!["cn"]);
        assert_eq!(rule.domain_keyword, vec!["ads"]);
        assert_eq!(rule.domain_regex, vec!["^x$"]);
        assert_eq!(rule.geosite, vec!["geosite.dat:cn"]);
        assert_eq!(rule.ip_cidr, vec!["10.0.0.0/8"]);
        assert_eq!(rule.geoip, vec!["geoip.dat:cn"]);
        assert_eq!(rule.source_ip_cidr, vec!["192.168.1.0/24"]);
        assert_eq!(rule.source_mac, vec!["aa:bb:cc:dd:ee:ff"]);
        assert_eq!(rule.protocol, vec!["tcp"]);
        assert_eq!(rule.port, vec![443]);
    }

    #[test]
    fn clean_config_has_no_issues() {
        assert!(issues_of(&base()).is_empty(), "干净配置不该报问题");
    }

    #[test]
    fn unknown_field_is_reported() {
        let mut v = base();
        // 拼错: log_levle
        v["log_levle"] = serde_json::json!("debug");
        let is = issues_of(&v);
        assert!(has(&is, "log_levle"), "应指出未知字段, 实际: {is:?}");
        assert!(has(&is, "未知字段"));
    }

    #[test]
    fn unknown_nested_field_reports_path() {
        let mut v = base();
        v["routing"]["defalut_outbound"] = serde_json::json!("direct"); // 拼错
        let is = issues_of(&v);
        assert!(has(&is, "routing.defalut_outbound"), "应带嵌套路径, 实际: {is:?}");
    }

    #[test]
    fn rule_referencing_missing_outbound() {
        let mut v = base();
        v["routing"]["rules"] = serde_json::json!([
            { "outbound": "proxy", "domain_suffix": ["example.com"] }
        ]);
        let is = issues_of(&v);
        assert!(has(&is, "rules[0]") && has(&is, "proxy"), "实际: {is:?}");
    }

    #[test]
    fn missing_default_outbound() {
        let mut v = base();
        v["routing"]["default_outbound"] = serde_json::json!("nope");
        assert!(has(&issues_of(&v), "default_outbound"));
    }

    #[test]
    fn duplicate_outbound_tag() {
        let mut v = base();
        v["outbounds"] = serde_json::json!([
            { "type": "direct", "tag": "dup" },
            { "type": "block",  "tag": "dup" }
        ]);
        v["routing"]["default_outbound"] = serde_json::json!("dup");
        assert!(has(&issues_of(&v), "重复定义"));
    }

    #[test]
    fn group_member_and_self_reference() {
        let mut v = base();
        v["outbounds"] = serde_json::json!([
            { "type": "direct", "tag": "direct" },
            { "type": "selector", "tag": "sel", "outbounds": ["ghost", "sel"] }
        ]);
        let is = issues_of(&v);
        assert!(has(&is, "ghost"), "应指出不存在的成员, 实际: {is:?}");
        assert!(has(&is, "自引用"), "应指出自引用, 实际: {is:?}");
    }

    #[test]
    fn empty_group_reported() {
        let mut v = base();
        v["outbounds"] = serde_json::json!([
            { "type": "direct", "tag": "direct" },
            { "type": "urltest", "tag": "ut", "outbounds": [] }
        ]);
        assert!(has(&issues_of(&v), "为空"));
    }

    #[test]
    fn mirage_outbound_required_fields() {
        let mut v = base();
        v["outbounds"] = serde_json::json!([
            { "type": "mirage", "tag": "m", "server": "", "server_port": 0,
              "password": "", "camouflage_host": "x.com" }
        ]);
        v["routing"]["default_outbound"] = serde_json::json!("m");
        let is = issues_of(&v);
        assert!(has(&is, "server 为空") && has(&is, "server_port 为 0") && has(&is, "password 为空"),
                "实际: {is:?}");
    }

    #[test]
    fn ss_upstream_bad_method_is_caught() {
        // 回归: 加密方式写错会让服务端**拒绝启动**, check 必须拦住 ——
        // 否则 `check && systemctl restart` 这个闸门形同虚设。
        let mut v = base();
        v["inbounds"] = serde_json::json!([
            { "type": "mirage_server", "tag": "srv", "listen": "0.0.0.0", "port": 443,
              "password": "pw", "camouflage_host": "x.com",
              "upstream": { "type": "shadowsocks", "server": "1.2.3.4", "server_port": 8388,
                            "password": "sspw", "method": "aes-256-cfb" } }
        ]);
        let is = issues_of(&v);
        assert!(has(&is, "aes-256-cfb"), "应指出不支持的加密方式, 实际: {is:?}");
    }

    #[test]
    fn ss2022_psk_length_is_validated() {
        // 回归: SIP022 密钥长度错**不会**让服务端起不来, 而是每条连接都静默失败 ——
        // 服务看着健康却什么都代理不了。check 必须在重启前就拦住。
        use base64::Engine;
        let short = base64::engine::general_purpose::STANDARD.encode([0u8; 16]);
        let mut v = base();
        v["inbounds"] = serde_json::json!([
            { "type": "mirage_server", "tag": "srv", "listen": "0.0.0.0", "port": 443,
              "password": "pw", "camouflage_host": "x.com",
              "upstream": { "type": "shadowsocks", "server": "1.2.3.4", "server_port": 8388,
                            "password": short, "method": "2022-blake3-aes-256-gcm" } }
        ]);
        let is = issues_of(&v);
        assert!(has(&is, "16 字节") && has(&is, "32 字节"), "实际: {is:?}");

        // 长度正确则放行
        let good = base64::engine::general_purpose::STANDARD.encode([0u8; 32]);
        v["inbounds"][0]["upstream"]["password"] = serde_json::json!(good);
        assert!(issues_of(&v).is_empty(), "合法 PSK 不该报问题: {:?}", issues_of(&v));

        // 非 base64 也要拦
        v["inbounds"][0]["upstream"]["password"] = serde_json::json!("不是base64!!!");
        assert!(has(&issues_of(&v), "base64"), "非 base64 的 PSK 应被拦住");
    }

    #[test]
    fn ss_upstream_empty_fields_are_caught() {
        let mut v = base();
        v["inbounds"] = serde_json::json!([
            { "type": "mirage_server", "tag": "srv", "listen": "0.0.0.0", "port": 443,
              "password": "pw", "camouflage_host": "x.com",
              "upstream": { "type": "shadowsocks", "server": "", "server_port": 0,
                            "password": "", "method": "aes-256-gcm" } }
        ]);
        let is = issues_of(&v);
        assert!(has(&is, "upstream.server 为空"), "实际: {is:?}");
        assert!(has(&is, "upstream.server_port 为 0"), "实际: {is:?}");
        assert!(has(&is, "upstream.password 为空"), "实际: {is:?}");
    }

    #[test]
    fn ss_upstream_valid_passes() {
        let mut v = base();
        v["inbounds"] = serde_json::json!([
            { "type": "mirage_server", "tag": "srv", "listen": "0.0.0.0", "port": 443,
              "password": "pw", "camouflage_host": "x.com",
              "upstream": { "type": "shadowsocks", "server": "1.2.3.4", "server_port": 8388,
                            "password": "sspw", "method": "chacha20-ietf-poly1305" } }
        ]);
        assert!(issues_of(&v).is_empty(), "合法上游配置不该报问题: {:?}", issues_of(&v));
    }

    #[test]
    fn server_inbound_empty_password() {
        let mut v = base();
        v["inbounds"] = serde_json::json!([
            { "type": "mirage_server", "tag": "srv", "listen": "0.0.0.0",
              "port": 443, "password": "" }
        ]);
        assert!(has(&issues_of(&v), "任何人都能连"));
    }

    #[test]
    fn duplicate_inbound_tag_and_zero_port() {
        let mut v = base();
        v["inbounds"] = serde_json::json!([
            { "type": "mixed", "tag": "in", "listen": "127.0.0.1", "port": 1080 },
            { "type": "socks", "tag": "in", "listen": "127.0.0.1", "port": 0 }
        ]);
        let is = issues_of(&v);
        assert!(has(&is, "inbound tag `in` 重复定义"), "实际: {is:?}");
        assert!(has(&is, "port 为 0"), "实际: {is:?}");
    }
}

#[cfg(test)]
mod wg_upstream_tests {
    use super::*;

    const PRIV: &str = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=";
    const PUB: &str = "AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=";

    fn cfg_with_upstream(up: &str) -> Config {
        let s = format!(r#"{{
          "inbounds": [{{ "type": "mirage_server", "tag": "srv", "listen": "0.0.0.0",
                          "port": 443, "password": "pw", "upstream": {up} }}],
          "outbounds": [{{ "type": "direct", "tag": "direct" }}],
          "routing": {{ "default_outbound": "direct", "rules": [] }}
        }}"#);
        serde_json::from_str(&s).expect("配置应能解析")
    }

    /// 配了 WireGuard 上游必须真的建出 WG 出口。
    ///
    /// 这是回归测试: 加 WG 变体时 `build_ss_upstream` 原先的
    /// `let Some(Shadowsocks{..}) = cfg else { return Ok(None) }` 会让 WG 上游**静默
    /// 变成"没配上游"= 直连** —— 用户以为流量从落地机出去, 实际从本服务端 IP 裸奔出去,
    /// 且毫无提示。必须锁死。
    #[test]
    fn wireguard_upstream_is_not_silently_ignored() {
        let cfg = cfg_with_upstream(&format!(
            r#"{{ "type": "wireguard", "private_key": "{PRIV}", "peer_public_key": "{PUB}",
                  "endpoint": "1.2.3.4:51820", "address": "10.0.0.2" }}"#
        ));
        assert!(cfg.semantic_issues().is_empty(), "合法配置不该报错: {:?}", cfg.semantic_issues());

        let InboundConfig::MirageServer { upstream, .. } = &cfg.inbounds[0] else {
            panic!("应是 mirage_server 入站")
        };
        let outlet = crate::build_upstream(upstream.as_ref())
            .expect("构建上游应成功")
            .expect("配了 WG 上游却得到 None —— 会静默走直连, 流量从本机 IP 裸奔出去");
        assert!(
            matches!(&*outlet, crate::proxy::upstream::UpstreamOutlet::Wireguard(_)),
            "应是 WireGuard 出口"
        );
        // WG 上游的 UDP 默认走隧道 —— 与 SS 上游默认 block 不同, 因为 block 的理由
        // (UDP 从本机 IP 出去、与 TCP 出口不一致) 在 WG 上不成立: 隧道能承载 UDP。
        assert_eq!(
            outlet.udp_policy(),
            UdpPolicy::Tunnel,
            "WG 上游的 UDP 默认应为 tunnel (与 TCP 同出口)"
        );
        assert!(!outlet.block_udp(), "默认不该拒绝 UDP");
    }

    /// SS 上游不能配 `udp: "tunnel"` —— SS 的 UDP 是另一套包格式, 尚未实现。
    /// 必须在 check 阶段报错, 而不是静默按某个默认行为跑。
    #[test]
    fn shadowsocks_upstream_rejects_tunnel_udp() {
        let cfg = cfg_with_upstream(
            r#"{ "type": "shadowsocks", "server": "h", "server_port": 8388,
                 "password": "p", "method": "aes-256-gcm", "udp": "tunnel" }"#,
        );
        let issues = cfg.semantic_issues();
        assert!(
            issues.iter().any(|i| i.contains("tunnel")),
            "SS 上游配 udp=tunnel 应被拦下: {issues:?}"
        );
    }

    /// 上游 WG 配错必须在 check 阶段就拦下 (而非留到每条连接静默失败)。
    #[test]
    fn wireguard_upstream_bad_config_is_caught() {
        let cases = [
            (format!(r#"{{ "type": "wireguard", "private_key": "AAAA", "peer_public_key": "{PUB}",
                "endpoint": "1.2.3.4:51820", "address": "10.0.0.2" }}"#), "private_key"),
            (format!(r#"{{ "type": "wireguard", "private_key": "{PRIV}", "peer_public_key": "{PUB}",
                "endpoint": "1.2.3.4", "address": "10.0.0.2" }}"#), "endpoint"),
            (format!(r#"{{ "type": "wireguard", "private_key": "{PRIV}", "peer_public_key": "{PUB}",
                "endpoint": "1.2.3.4:51820", "address": "not-an-ip" }}"#), "address"),
        ];
        for (up, want) in cases {
            let issues = cfg_with_upstream(&up).semantic_issues();
            assert!(
                issues.iter().any(|i| i.contains(want)),
                "含 {want} 错误却没被拦下: {issues:?}"
            );
        }
    }
}
