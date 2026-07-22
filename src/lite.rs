//! 轻量模式: 只做「SOCKS5 进 → 加密隧道出」的最小闭环。
//!
//! 与完整模式的关系: **同一个二进制、同一套协议、同一套加密与伪装**, 只是不加载
//! 分流 / DNS / fake-IP / 透明代理 / Web 看板 / geo 数据 / 配置热重载。
//! 因此轻量客户端可以直连完整版服务端, 反之亦然 —— 协议层完全一致。
//!
//! 设计上刻意**不复制引擎**: 把极简配置在内存里展开成内部 `CoreState`
//! (单个 mirage 出站 + 空规则 + default 指向它), 之后直接复用现成的
//! `proxy_tcp_target` / `mirage_server::start_server`。这样重试、隧道池、
//! 中继、伪装握手等微妙逻辑只有一份实现, 不会与完整版分叉。
//!
//! 「全部转发」是**结构性成立**的: 路由规则为空, 所有流量都落到 default_outbound,
//! 而它就是那唯一的 mirage 出站 —— 不存在"漏了某条规则导致直连泄漏"的可能。
//!
//! 仅 TCP: SOCKS5 UDP ASSOCIATE 会被明确拒绝 (见 `serve_client`)。

use anyhow::{Context, Result};
use serde::Deserialize;
use std::sync::Arc;
use tracing::{error, info, warn};

use crate::config::InboundAuth;

fn d_client_listen() -> String { "127.0.0.1".into() }
fn d_client_port() -> u16 { 1080 }
fn d_server_listen() -> String { "0.0.0.0".into() }
fn d_server_port() -> u16 { 443 }
fn d_sni() -> String { "www.apple.com".into() }
fn d_pool_size() -> usize { 4 }
fn d_log_level() -> String { "info".into() }
fn d_tolerance() -> u64 { crate::crypto::hello_auth::DEFAULT_AUTH_TS_TOLERANCE_SECS }

/// 轻量客户端配置 (平铺, 无 inbounds/outbounds/routing 嵌套)。
#[derive(Debug, Deserialize)]
pub struct LiteClientConfig {
    /// 本地 SOCKS5 监听地址。默认 127.0.0.1 —— 改成 0.0.0.0 而不设 `auth`
    /// 就是开放代理, 启动时会 WARN。
    #[serde(default = "d_client_listen")]
    pub listen: String,
    #[serde(default = "d_client_port")]
    pub port: u16,
    /// 可选 SOCKS5 认证 (RFC 1929)。监听非回环地址时强烈建议设置。
    #[serde(default)]
    pub auth: Option<InboundAuth>,

    pub server: String,
    pub server_port: u16,
    pub password: String,
    /// 伪装 SNI, 必须与服务端一致。
    #[serde(default = "d_sni")]
    pub sni: String,

    #[serde(default = "d_pool_size")]
    pub pool_size: usize,
    #[serde(default)]
    pub brutal_rate_mbps: Option<u64>,
    #[serde(default = "d_log_level")]
    pub log_level: String,
}

/// 轻量服务端配置。
#[derive(Debug, Deserialize)]
pub struct LiteServerConfig {
    #[serde(default = "d_server_listen")]
    pub listen: String,
    #[serde(default = "d_server_port")]
    pub port: u16,
    pub password: String,
    /// 伪装站域名: 认证失败的连接会被转发到它, 使主动探测看到真实站点响应。
    #[serde(default = "d_sni")]
    pub sni: String,
    #[serde(default = "d_tolerance")]
    pub auth_ts_tolerance_secs: u64,
    #[serde(default)]
    pub brutal_rate_mbps: Option<u64>,
    /// 可选上游出口: 配了则本服务端作为中转站, 流量再经 SS 发往上游 (仅 TCP)。
    #[serde(default)]
    pub upstream: Option<crate::config::UpstreamConfig>,
    #[serde(default = "d_log_level")]
    pub log_level: String,
}

/// 轻量模式的日志初始化 (stdout only —— 不带文件滚动/gzip/GUI 内存日志)。
fn init_log(level: &str) {
    let lvl = match level.to_lowercase().as_str() {
        "trace" => tracing::Level::TRACE,
        "debug" => tracing::Level::DEBUG,
        "warn" => tracing::Level::WARN,
        "error" => tracing::Level::ERROR,
        _ => tracing::Level::INFO,
    };
    let sub = tracing_subscriber::fmt().with_max_level(lvl).with_ansi(false).finish();
    let _ = tracing::subscriber::set_global_default(sub);
}

/// 把极简客户端配置展开成内部 `CoreState`。
///
/// 等价于一份"单 mirage 出站 + 零规则"的完整配置, 但全程在内存里, 不落盘、
/// 不需要配置文件, 因此也不会牵扯热重载与看板改配置那套机制。
fn build_core_state(cfg: &LiteClientConfig) -> Result<crate::config_watcher::CoreState> {
    const TAG: &str = "proxy";

    let full = serde_json::json!({
        "inbounds": [],
        "outbounds": [{
            "type": "mirage",
            "tag": TAG,
            "server": cfg.server,
            "server_port": cfg.server_port,
            "password": cfg.password,
            "camouflage_host": cfg.sni,
            "pool_size": cfg.pool_size,
            "brutal_rate_mbps": cfg.brutal_rate_mbps,
        }],
        "routing": { "default_outbound": TAG, "rules": [] },
        "advanced_dns": null, "api": null, "tuning": null, "gui": null,
    });
    let parsed: crate::config::Config =
        serde_json::from_value(full).context("展开轻量配置失败 (内部错误)")?;

    let outbounds = Arc::new(crate::proxy::outbound::OutboundManager::new(&parsed));
    // 空规则 → 一切都落到 default_outbound; geodata_dir 不会被触碰 (没有 geosite/geoip 规则)。
    let router = crate::router::RouterEngine::new(
        Vec::new(),
        TAG.to_string(),
        ".geosite",
        &std::collections::HashMap::new(),
    )?;

    Ok(crate::config_watcher::CoreState {
        router: Arc::new(router),
        outbounds,
        advanced_dns: None,
    })
}

/// 启动轻量客户端: SOCKS5 (仅 TCP) → 隧道。
pub async fn start_client(cfg: LiteClientConfig) -> Result<()> {
    init_log(&cfg.log_level);
    info!(
        "Mirage-rs 轻量模式 (客户端): SOCKS5 {}:{} → {}:{}  [仅 TCP · 全部转发 · 无分流/DNS/看板]",
        cfg.listen, cfg.port, cfg.server, cfg.server_port
    );

    let loopback = cfg.listen.starts_with("127.") || cfg.listen == "::1" || cfg.listen == "localhost";
    if !loopback && cfg.auth.is_none() {
        warn!(
            "⚠️  SOCKS5 监听 {}:{} 且**未配置认证** = 开放代理, 任何能连到该端口的人都能\
             使用你的隧道 (出口 IP 会被滥用/拉黑)。请加 \"auth\": {{\"username\": \"...\", \
             \"password\": \"...\"}}, 或把 listen 改回 127.0.0.1。",
            cfg.listen, cfg.port
        );
    }

    let state = Arc::new(arc_swap::ArcSwap::from_pointee(build_core_state(&cfg)?));
    let auth = cfg.auth.map(Arc::new);
    let addr = format!("{}:{}", cfg.listen, cfg.port);
    let listener = tokio::net::TcpListener::bind(&addr)
        .await
        .with_context(|| format!("SOCKS5 监听 {addr} 失败"))?;
    info!("SOCKS5 listening on {addr}");

    loop {
        let (stream, peer) = match listener.accept().await {
            Ok(v) => v,
            Err(e) => {
                error!("accept 失败: {e}");
                continue;
            }
        };
        let st = state.clone();
        let au = auth.clone();
        tokio::spawn(async move {
            serve_client(stream, st, au, peer).await;
        });
    }
}

/// 单条 SOCKS5 连接。握手后只接受 CONNECT; UDP ASSOCIATE 明确拒绝 (轻量模式仅 TCP)。
async fn serve_client(
    mut stream: tokio::net::TcpStream,
    state: Arc<arc_swap::ArcSwap<crate::config_watcher::CoreState>>,
    auth: Option<Arc<InboundAuth>>,
    peer: std::net::SocketAddr,
) {
    use crate::proxy::socks5::{handshake, SocksCommand};

    match handshake(&mut stream, auth.as_deref()).await {
        Ok(SocksCommand::TcpConnect(target)) => {
            // 复用完整版的转发路径 (含换隧道重试/中继), 不另起一套实现。
            // 无 eBPF、无 fake-IP: 轻量模式不涉及这两者。
            crate::proxy::handler::proxy_tcp_target(stream, target, Vec::new(), state, None, None, None, false)
                .await;
        }
        Ok(SocksCommand::UdpAssociate) => {
            // 轻量模式仅 TCP。回 0x07 (Command not supported) 让客户端明确知道原因,
            // 而不是静默断开导致对端一直等。
            use tokio::io::AsyncWriteExt;
            let _ = stream
                .write_all(&[0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                .await;
            warn!("[LITE] {peer} 请求 UDP ASSOCIATE, 轻量模式仅支持 TCP, 已拒绝");
        }
        Err(e) => {
            tracing::debug!("[LITE] {peer} SOCKS5 握手失败: {e}");
        }
    }
}

/// 启动轻量服务端: 与完整版服务端**完全同一实现**, 只是不带看板/DNS/eBPF。
pub async fn start_server(cfg: LiteServerConfig) -> Result<()> {
    init_log(&cfg.log_level);
    let addr = format!("{}:{}", cfg.listen, cfg.port);
    info!(
        "Mirage-rs 轻量模式 (服务端): 监听 {addr}, 伪装站 {}  [全部转发 · 无看板/DNS/eBPF]",
        cfg.sni
    );
    if cfg.password.is_empty() {
        warn!("⚠️  password 为空 —— 任何人都能连上你的服务端, 请设置一个强密码。");
    }
    let brutal_bps = cfg.brutal_rate_mbps.filter(|m| *m > 0).map(|m| m * 125_000);
    let ss_upstream = crate::build_upstream(cfg.upstream.as_ref())?;

    crate::proxy::mirage_server::start_server(
        &addr,
        &cfg.password,
        &cfg.sni,
        None, // 无 eBPF
        brutal_bps,
        cfg.auth_ts_tolerance_secs,
        ss_upstream,
    )
    .await;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn client_config_minimal_fields() {
        // 只给必填项, 其余全靠默认
        let c: LiteClientConfig = serde_json::from_str(
            r#"{"server":"1.2.3.4","server_port":443,"password":"p"}"#,
        )
        .unwrap();
        assert_eq!(c.listen, "127.0.0.1", "默认应监听回环, 不是 0.0.0.0");
        assert_eq!(c.port, 1080);
        assert_eq!(c.sni, "www.apple.com");
        assert_eq!(c.pool_size, 4);
        assert!(c.auth.is_none());
    }

    #[test]
    fn client_config_with_auth() {
        let c: LiteClientConfig = serde_json::from_str(
            r#"{"server":"h","server_port":1,"password":"p","listen":"0.0.0.0",
                "auth":{"username":"u","password":"pw"}}"#,
        )
        .unwrap();
        let a = c.auth.unwrap();
        assert!(a.verify(b"u", b"pw"));
        assert!(!a.verify(b"u", b"wrong"));
    }

    #[test]
    fn server_config_defaults() {
        let s: LiteServerConfig = serde_json::from_str(r#"{"password":"p"}"#).unwrap();
        assert_eq!(s.listen, "0.0.0.0");
        assert_eq!(s.port, 443);
        assert_eq!(s.auth_ts_tolerance_secs, 60, "应沿用完整版的默认容差");
    }

    #[test]
    fn missing_required_field_is_error() {
        // server/server_port/password 是必填, 缺了必须报错而不是给个空默认
        assert!(serde_json::from_str::<LiteClientConfig>(r#"{"server":"h"}"#).is_err());
        assert!(serde_json::from_str::<LiteServerConfig>(r#"{}"#).is_err());
    }

    // build_core_state → OutboundManager::new → WarmPool::new 内部 tokio::spawn,
    // 必须在运行时上下文里跑 (同步 #[test] 会 panic on no reactor)。
    #[tokio::test]
    async fn core_state_routes_everything_to_tunnel() {
        // 「全部转发」的结构性保证: 零规则 + default 指向唯一的 mirage 出站。
        let cfg: LiteClientConfig = serde_json::from_str(
            r#"{"server":"1.2.3.4","server_port":443,"password":"p"}"#,
        )
        .unwrap();
        let st = build_core_state(&cfg).unwrap();
        assert!(st.outbounds.outbounds.contains_key("proxy"), "应有 mirage 出站");
        assert!(st.advanced_dns.is_none(), "轻量模式不带 DNS");

        // 注意: OutboundManager 会**无条件注入**内置的 direct/block 节点
        // (outbound.rs 里 "if !contains_key 就 insert")。它们的存在不构成泄漏 ——
        // 「全部转发」的保证来自**路由**: 规则为空 + default 指向 proxy, 没有任何
        // 路径能把流量导到 direct。下面的断言正是在守这条线。
        assert!(st.outbounds.outbounds.contains_key("direct"), "内置 direct 确实存在(但不可达)");
        // 任意目标都应路由到 proxy —— 没有任何规则能把它导去别处。
        // 含"通常会被分流成直连"的国内域名与内网/公共 IP: 轻量模式下它们同样走隧道。
        for host in ["example.com", "baidu.cn", "qq.com"] {
            let req = crate::router::RoutingRequest {
                domain: Some(host), ip: None, port: 443,
                protocol: "tcp", source_ip: None, source_mac: None, inbound: None,
            };
            assert_eq!(st.router.route(req), "proxy", "{host} 也必须走隧道");
        }
        for ip in ["10.0.0.1", "1.1.1.1", "114.114.114.114"] {
            let req = crate::router::RoutingRequest {
                domain: None, ip: Some(ip.parse().unwrap()), port: 443,
                protocol: "tcp", source_ip: None, source_mac: None, inbound: None,
            };
            assert_eq!(st.router.route(req), "proxy", "{ip} 也必须走隧道");
        }
    }
}

#[cfg(test)]
mod template_tests {
    use super::*;

    /// 去掉 JSONC 的 `//` 注释。只在**引号之外**才认作注释起点, 否则会误伤
    /// 值里的 `http://...` 之类。
    fn strip_jsonc(src: &str) -> String {
        let mut out = String::with_capacity(src.len());
        for line in src.lines() {
            let (mut in_str, mut esc) = (false, false);
            let b = line.as_bytes();
            let mut cut = line.len();
            for i in 0..b.len() {
                if esc { esc = false; continue; }
                match b[i] {
                    b'\\' if in_str => esc = true,
                    b'"' => in_str = !in_str,
                    b'/' if !in_str && i + 1 < b.len() && b[i + 1] == b'/' => { cut = i; break; }
                    _ => {}
                }
            }
            out.push_str(&line[..cut]);
            out.push('\n');
        }
        out
    }

    /// 仓库里发布的模板必须能被当前代码解析。
    ///
    /// 这条是防**模板腐烂**的: 字段一旦在代码里改名/删除而模板没跟着改, 用户照着模板
    /// 写出来的配置就会解析失败或字段被静默忽略。仓库里那个用旧 schema、连解析都过不了
    /// 的 `transparent_config.json` 就是活例子。
    #[test]
    fn shipped_templates_still_parse() {
        let s = strip_jsonc(&std::fs::read_to_string("templates/lite_server.jsonc").unwrap());
        let srv: LiteServerConfig = serde_json::from_str(&s)
            .expect("templates/lite_server.jsonc 应能解析为 LiteServerConfig");
        assert_eq!(srv.port, 443, "模板应显式给出 port (端口可自定义)");
        assert_eq!(srv.listen, "0.0.0.0");
        assert!(!srv.password.is_empty());

        let c = strip_jsonc(&std::fs::read_to_string("templates/lite_client.jsonc").unwrap());
        let cli: LiteClientConfig = serde_json::from_str(&c)
            .expect("templates/lite_client.jsonc 应能解析为 LiteClientConfig");
        assert_eq!(cli.port, 1080, "模板应显式给出本地监听端口");
        assert_eq!(cli.server_port, 443, "模板应显式给出 server_port");
        assert_eq!(cli.listen, "127.0.0.1", "客户端模板默认应是回环, 不是 0.0.0.0");
    }

    #[test]
    fn strip_jsonc_keeps_urls_in_strings() {
        // 回归: 朴素地按 "//" 切会把 http:// 的值截断
        let s = strip_jsonc(r#"{"u":"http://a.com/x"} // trailing"#);
        let v: serde_json::Value = serde_json::from_str(&s).unwrap();
        assert_eq!(v["u"], "http://a.com/x");
    }
}
