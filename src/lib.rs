// ── 全局 clippy allow: 均为刻意/组织性模式, 非缺陷; 逐条说明理由后翻 -D warnings ──
// while_let_loop: relay/隧道循环刻意用 `loop { match timeout(..).await { Ok(Ok(x)) => body,
//   _ => break } }` 显式表达"任一方向超时/读错 → 拆流", 循环体内还有基于 send 结果的 break,
//   clippy 自己标 MaybeIncorrect(不敢自动改)。改 while-let 会藏起拆流语义且有行为风险。
#![allow(clippy::while_let_loop)]
// items_after_test_module: 少数文件的 #[cfg(test)] mod 后还有非测试项, 纯组织性 lint;
//   为它移动整块 test 模块是无意义的大 churn, 不值当。
#![allow(clippy::items_after_test_module)]
// large_enum_variant: 适配器状态机(MirageStream/SsStream)的 Idle 变体持真实 half(较大),
//   Busy 只是 boxed future; 尺寸差固有。装箱 Idle 反给每次 poll 加一层间接, 每连接一个非热点。
#![allow(clippy::large_enum_variant)]
// too_many_arguments: 数据面入口(proxy_tcp_target / start_transparent)参数多, 但都是独立
//   运行期依赖, 塞进临时结构体只增噪声不增清晰。
#![allow(clippy::too_many_arguments)]

pub mod crypto;
pub mod proxy;
pub mod router;
pub mod dns;
pub mod config;
pub mod time_sync;
pub mod config_watcher;
pub mod ebpf;
pub mod monitor;
pub mod net_monitor;
pub mod net_util;
pub mod node_uri;
pub mod lite;
pub mod api;
mod startup;

use anyhow::Result;
use std::sync::Arc;
use tracing::{info, warn, error};

/// 监听非回环地址却没配 auth = **开放代理**: 任何能连到该端口的人都能白嫖隧道,
/// 流量从你的服务端出去, 出口 IP 会被滥用/拉黑 (对抗审查部署尤其致命 —— 招来注意力)。
/// 不阻止启动 (向后兼容既有配置 + 可信内网仍是合法用法), 但必须让用户看见。
fn warn_if_open_proxy(kind: &str, listen: &str, port: u16, has_auth: bool) {
    if has_auth {
        return;
    }
    let loopback = listen.starts_with("127.") || listen == "::1" || listen == "localhost";
    if loopback {
        return;
    }
    warn!(
        "⚠️  {kind} 入站监听 {listen}:{port} 且**未配置认证** = 开放代理, \
         任何能连到该端口的人都能使用你的隧道 (出口 IP 会被滥用/拉黑)。\
         请在该入站加 \"auth\": {{\"username\": \"...\", \"password\": \"...\"}}, \
         或把 listen 改回 127.0.0.1 仅本机使用。"
    );
}

/// 把配置里的上游出口翻译成运行期的 [`UpstreamOutlet`]。配了就说明本服务端当**中转站**。
///
/// 任何错配都返回 Err 而非静默降级为直连 —— 用户配了中转却悄悄走直连, 意味着出口 IP
/// 与预期完全不同(流量从本服务端 IP 裸奔出去), 属于必须让人立刻知道的错配。
pub(crate) fn build_upstream(
    cfg: Option<&crate::config::UpstreamConfig>,
) -> Result<Option<Arc<crate::proxy::upstream::UpstreamOutlet>>> {
    use crate::config::UpstreamConfig;
    use crate::proxy::upstream::{UpstreamOutlet, WgUpstream};

    let Some(cfg) = cfg else { return Ok(None) };

    // UDP 策略的告警两种上游共用: 原因完全相同 —— UDP 未接到上游通道, 放行就会出口 IP 不一致。
    let warn_udp = |block_udp: bool, why: &str| {
        if block_udp {
            info!(
                "UDP 策略: block (默认) —— {why}, 放行会让 UDP 从本机直连出去 \
                 (出口 IP 与 TCP 不同, 落地解锁场景会判错区域)。故直接拒绝 UDP 中继: \
                 QUIC 将回落 TCP, 游戏/WebRTC 不可用。要保留旧行为请显式设 \"udp\": \"direct\"。"
            );
        } else {
            warn!(
                "⚠️  UDP 策略: direct —— UDP 将从**本机 IP** 直连出去, 与 TCP 的上游出口**不同**。\
                 流媒体走 QUIC 时会被判成本机所在区域 (且不会回落 TCP, 故表现为解锁时灵时不灵)。\
                 除非你确认不介意, 否则建议改回默认的 \"udp\": \"block\"。"
            );
        }
    };

    match cfg {
        UpstreamConfig::Shadowsocks { server, server_port, password, method, udp } => {
            let m = crate::proxy::shadowsocks::Method::parse(method)?;
            // SIP022: 密钥格式/长度错不会让服务起不来, 而是每条连接都静默失败 (服务看着健康却
            // 代理不了任何东西)。在这里提前解一次, 让它变成"拒绝启动 + 明确报错"。
            if m.is_2022() {
                crate::proxy::shadowsocks::decode_ss2022_psk(password, m.key_len())?;
            }
            info!(
                "上游出口: Shadowsocks {}:{} ({}) —— 本服务端作为中转站, TCP 流量将再经 SS 转发",
                server, server_port, method
            );
            let block_udp = matches!(udp, crate::config::UdpPolicy::Block);
            warn_udp(block_udp, "SS 的 UDP 尚未实现");
            Ok(Some(Arc::new(UpstreamOutlet::Shadowsocks(Arc::new(
                crate::proxy::shadowsocks::SsConfig {
                    server: server.clone(),
                    port: *server_port,
                    password: password.clone(),
                    method: m,
                    block_udp,
                },
            )))))
        }
        UpstreamConfig::Wireguard {
            private_key, peer_public_key, preshared_key, endpoint, address, mtu,
            persistent_keepalive, udp, dns,
        } => {
            let wg = crate::proxy::wg::WgConfig {
                private_key: crate::proxy::wg::decode_wg_key(private_key, "private_key")?,
                peer_public_key: crate::proxy::wg::decode_wg_key(peer_public_key, "peer_public_key")?,
                preshared_key: preshared_key
                    .as_deref()
                    .map(|k| crate::proxy::wg::decode_wg_key(k, "preshared_key"))
                    .transpose()?,
                endpoint: endpoint.clone(),
                address: address.parse().map_err(|_| {
                    anyhow::anyhow!("上游 WireGuard: address `{address}` 不是合法 IP (不带掩码, 如 10.0.0.2)")
                })?,
                mtu: *mtu,
                persistent_keepalive: *persistent_keepalive,
                // 隧道内 DNS: 配了则经本隧道解析 (出口与 WG 一致)。非法 IP → 报错不静默。
                dns: dns
                    .as_deref()
                    .map(|s| {
                        s.parse::<std::net::IpAddr>().map_err(|_| {
                            anyhow::anyhow!("上游 WireGuard: dns `{s}` 不是合法 IP")
                        })
                    })
                    .transpose()?,
            };
            info!(
                "上游出口: WireGuard {} (隧道内地址 {}) —— 本服务端作为中转站, TCP 流量将再经 WG 转发",
                wg.endpoint, wg.address
            );
            match udp {
                crate::config::UdpPolicy::Tunnel => info!(
                    "UDP 策略: tunnel (默认) —— UDP 也走 WG 隧道, 与 TCP 同一个出口 IP。"
                ),
                crate::config::UdpPolicy::Block => info!(
                    "UDP 策略: block —— 直接拒绝 UDP 中继。注意 WG 隧道本可承载 UDP \
                     (默认即 tunnel), 除非你刻意要禁用, 否则 block 只会让 QUIC 回落 TCP、\
                     游戏/WebRTC 不可用。"
                ),
                crate::config::UdpPolicy::Direct => warn!(
                    "⚠️  UDP 策略: direct —— UDP 将从**本机 IP** 直连出去, 与 TCP 的 WG 出口\
                     **不同**。WG 隧道本可承载 UDP (默认 tunnel), 除非你确知自己在做什么, \
                     否则建议改回 \"udp\": \"tunnel\"。"
                ),
            }
            Ok(Some(Arc::new(UpstreamOutlet::Wireguard(WgUpstream::new(wg, *udp)))))
        }
    }
}

pub async fn start_proxy(config_path: &str, is_server: bool) -> Result<()> {
    crate::startup::init_logging(config_path);

    // v0.4 协议: 时间同步从 NTP/HTTP 改为 server 在 handshake 后通过加密 channel
    // 主动下发 (见 src/proxy/mirage_server.rs 和 src/proxy/pool.rs). 这里不再
    // 启动后台 NTP 探测协程.

    // 启动 ConfigWatcher 监控配置热更新
    let crate::startup::RuntimeScan {
        geodata_dir,
        needs_geo,
        ebpf_mode,
        geo_sources,
        geo_update_days,
        socks_proxy_url,
        mut internal_socks_listener,
    } = crate::startup::scan_runtime_config(config_path).await;

    // eBPF 加载决策: ebpf_mode (auto/force/off) × is_server (来自 CLI 子命令).
    // 服务端跑 BPF 全部子系统都无价值 (详见 TuningConfig::ebpf_mode 注释), auto
    // 模式下服务端自动跳过. Off 任何情况都不加载. Force 调试用, 强制加载.
    let enable_ebpf = crate::startup::decide_enable_ebpf(ebpf_mode, is_server);

    // 无条件建 UpdaterHandle + spawn updater. 冷启动无 sources 时 updater 阻
    // 塞在 wake 上不消耗资源, 热更新加了 sources 后 ConfigWatcher 会 notify
    // 醒它立刻拉一轮. 修 Issue 4 方案 C.
    let updater_handle = crate::router::geo_updater::UpdaterHandle::new(
        crate::router::geo_updater::UpdaterState {
            geodata_dir: geodata_dir.clone(),
            sources: geo_sources,
            update_days: geo_update_days,
            proxy_url: socks_proxy_url,
        },
    );
    crate::router::geo_updater::spawn_updater(updater_handle.clone()).await;
    if needs_geo && updater_handle.state.load().sources.is_empty() {
        warn!("Routing rules reference geosite/geoip but `tuning.geo_sources` is empty. \
               Updater is waiting for hot-reload to add sources.");
    } else if !needs_geo {
        info!("No geosite/geoip rules configured — geo updater running but idle (no sources).");
    }
    
    // 如果 config.json 不存在，我们先写一个基础模板，避免启动直接崩溃
    if !std::path::Path::new(config_path).exists() {
        info!("config.json not found, creating a default template...");
        let default_cfg = r#"{
    "log_level": "info",
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
            "type": "direct",
            "tag": "direct"
        },
        {
            "type": "block",
            "tag": "block"
        }
    ],
    "routing": {
        "default_outbound": "direct",
        "rules": []
    }
}"#;
        if let Err(e) = std::fs::write(config_path, default_cfg) {
            tracing::error!("Failed to write default config to {}: {}", config_path, e);
            return Err(e.into());
        }
    }
    
    // ConfigWatcher::new() 会立刻解析配置并加载 Router 和 Outbounds，同时启动后台文件监控线程
    let watcher = match crate::config_watcher::ConfigWatcher::new(config_path, &geodata_dir, updater_handle.clone()) {
        Ok(w) => w,
        Err(e) => {
            tracing::error!("Failed to initialize config watcher: {}", e);
            return Err(e);
        }
    };

    // CoreState 就绪, 起内部 geo SOCKS 的 accept 循环 (端口已在上面绑好并给了 updater)。
    if let Some(l) = internal_socks_listener.take() {
        crate::proxy::internal_socks::serve(l, watcher.state.clone());
    }

    // 初始化 eBPF 引擎 (仅当 enable_ebpf 为 true, server-only 模式默认跳过)
    let (ebpf_engine, xdp_engine, transparent_engine) = crate::startup::init_engines(enable_ebpf);
    
    crate::startup::spawn_ebpf_monitor_tasks(&ebpf_engine, &watcher.state);

    let mut inbounds = Vec::new();
    let mut fake_ip_mapper: Option<Arc<crate::dns::fake_ip::FakeIpMapper>> = None;
    let mut gui_enabled = false;
    let mut gui_listen = "127.0.0.1:9090".to_string();
    let mut gui_token: Option<String> = None;

    if let Ok(content) = std::fs::read_to_string(config_path) {
        if let Ok(config) = serde_json::from_str::<crate::config::Config>(&content) {
            inbounds = config.inbounds;
            // 废弃 stub 字段告警: 这些字段解析了但从不被使用, 设了它们的用户会误以为生效。
            if config.api.is_some() {
                warn!(
                    "config 里的 `api` 段已废弃且**从未生效** —— `api.secret` 不提供任何鉴权! \
                     API 鉴权请改用 `gui.token` (见 README)。该字段将在未来版本移除。"
                );
            }
            if let Some(gui) = config.gui {
                gui_enabled = gui.enabled;
                gui_listen = gui.listen;
                gui_token = gui.token;
            }
            if let Some(adv) = config.advanced_dns {
                if let Some(iface) = &adv.xdp_interface {
                    if let Some(engine) = &xdp_engine {
                        if let Err(e) = engine.attach(iface) {
                            error!("Failed to attach XDP to interface {}: {}", iface, e);
                        } else {
                            engine.attached.store(1, std::sync::atomic::Ordering::Relaxed);
                        }
                    }
                }
                if let Some(fakeip) = adv.fakeip {
                    if fakeip.enabled {
                        match crate::dns::fake_ip::FakeIpMapper::with_persist(&fakeip.inet4_range, fakeip.persist_path.clone()) {
                            Ok(mapper) => {
                                info!(
                                    "Fake-IP Mapper initialized with range {} (persist: {})",
                                    fakeip.inet4_range,
                                    fakeip.persist_path.as_deref().unwrap_or("off")
                                );
                                let m = Arc::new(mapper);
                                m.clone().spawn_flusher(); // 持久化启用时周期落盘
                                fake_ip_mapper = Some(m);
                            }
                            Err(e) => error!("Failed to initialize Fake-IP Mapper with range {}: {}", fakeip.inet4_range, e),
                        }
                    }
                }
            }
        }
    }


    if gui_enabled {
        let gui_state = watcher.state.clone();
        let ebp = ebpf_engine.clone();
        let xdp = xdp_engine.clone();
        let listen = gui_listen.clone();
        let cfg_path = config_path.to_string();
        let token = gui_token.clone();
        tokio::spawn(async move {
            crate::api::start_server(&listen, gui_state, ebp, xdp, cfg_path, token).await;
        });
    }

    if inbounds.is_empty() {
        warn!("No inbounds configured!");
    }

    // 退出时要显式摘掉的 tc 过滤器 (见 TcDivertEngine::detach)。
    let mut tc_divert_engine: Option<std::sync::Arc<crate::ebpf::TcDivertEngine>> = None;

    for inbound in inbounds {
        let state_clone = watcher.state.clone();
        let ebpf_clone = ebpf_engine.clone();
        let fake_mapper_clone = fake_ip_mapper.clone();

        match inbound {
            crate::config::InboundConfig::Socks { tag, listen, port, auth } => {
                let listen_addr = crate::net_util::join_host_port(&listen, port);
                let inbound_tag: std::sync::Arc<str> = tag.as_str().into();
                warn_if_open_proxy("socks", &listen, port, auth.is_some());
                let auth = auth.clone().map(std::sync::Arc::new);
                tokio::spawn(async move {
                    if let Ok(listener) = tokio::net::TcpListener::bind(&listen_addr).await {
                        info!("SOCKS5 listening on {}", listen_addr);
                        while let Ok((stream, _)) = listener.accept().await {
                            let st = state_clone.clone();
                            let ebp = ebpf_clone.clone();
                            let fm = fake_mapper_clone.clone();
                            let au = auth.clone();
                            let tg = inbound_tag.clone();
                            tokio::spawn(async move {
                                crate::proxy::handler::handle_client(stream, st, ebp, fm, au, Some(tg)).await;
                            });
                        }
                    } else {
                        error!("Failed to bind SOCKS5 on {}", listen_addr);
                    }
                });
            }
            crate::config::InboundConfig::Shadowsocks { tag, listen, port, method, password } => {
                let listen_addr = crate::net_util::join_host_port(&listen, port);
                let inbound_tag: std::sync::Arc<str> = tag.as_str().into();
                let m = match crate::proxy::shadowsocks::Method::parse(&method) {
                    Ok(m) if m.is_2022() => {
                        error!("SS 入站 `{tag}` method `{method}` 是 SIP022, 入站暂不支持, 未启动");
                        continue;
                    }
                    Ok(m) => m,
                    Err(e) => {
                        error!("SS 入站 `{tag}` method 非法: {e}, 未启动");
                        continue;
                    }
                };
                let pw: std::sync::Arc<str> = password.as_str().into();
                tokio::spawn(async move {
                    if let Ok(listener) = tokio::net::TcpListener::bind(&listen_addr).await {
                        info!("Shadowsocks inbound listening on {} (SIP004 {:?})", listen_addr, m);
                        while let Ok((stream, _)) = listener.accept().await {
                            let st = state_clone.clone();
                            let pwc = pw.clone();
                            let tg = inbound_tag.clone();
                            tokio::spawn(async move {
                                crate::proxy::ss_inbound::handle_ss_client(stream, st, m, pwc, tg).await;
                            });
                        }
                    } else {
                        error!("Failed to bind Shadowsocks inbound on {}", listen_addr);
                    }
                });
            }
            crate::config::InboundConfig::MirageServer { listen, port, password, camouflage_host, brutal_rate_mbps, auth_ts_tolerance_secs, upstream, pfs, .. } => {
                let listen_addr = crate::net_util::join_host_port(&listen, port);
                let cam_host = camouflage_host.unwrap_or_else(|| "www.apple.com".to_string());
                let ebp = ebpf_clone.clone();
                // 0 视为未启用 (兼容旧 install.sh 模板里写 0 表示 "no brutal")
                let brutal_bps = brutal_rate_mbps
                    .filter(|m| *m > 0)
                    .map(|m| m * 125_000);
                let ss_upstream = match build_upstream(upstream.as_ref()) {
                    Ok(v) => v,
                    Err(e) => { error!("上游出口配置无效, 服务端未启动: {e}"); continue; }
                };
                tokio::spawn(async move {
                    crate::proxy::mirage_server::start_server(&listen_addr, &password, &cam_host, ebp, brutal_bps, auth_ts_tolerance_secs, ss_upstream, pfs).await;
                });
            }
            crate::config::InboundConfig::Mixed { tag, listen, port, auth } => {
                let listen_addr = crate::net_util::join_host_port(&listen, port);
                let inbound_tag: std::sync::Arc<str> = tag.as_str().into();
                warn_if_open_proxy("mixed", &listen, port, auth.is_some());
                let auth = auth.clone().map(std::sync::Arc::new);
                tokio::spawn(async move {
                    if let Ok(listener) = tokio::net::TcpListener::bind(&listen_addr).await {
                        tracing::info!("Mixed inbound listening on {}", listen_addr);
                        while let Ok((stream, _)) = listener.accept().await {
                            let st = state_clone.clone();
                            let ebp = ebpf_clone.clone();
                            let fm = fake_mapper_clone.clone();
                            let au = auth.clone();
                            let tg = inbound_tag.clone();
                            tokio::spawn(async move {
                                crate::proxy::mixed::handle_client(stream, st, ebp, fm, au, Some(tg)).await;
                            });
                        }
                    } else {
                        tracing::error!("Failed to bind Mixed inbound on {}", listen_addr);
                    }
                });
            }
            crate::config::InboundConfig::Transparent { tag, listen, port, interface, proxy_local, dns_hijack } => {
                let inbound_tag: std::sync::Arc<str> = tag.as_str().into();
                let listen_addr = crate::net_util::join_host_port(&listen, port);
                // 本机出向重定向 (cgroup/connect4): 开启后网关本机自身 fake-IP 流量也走代理。
                let cgroup_engine = if let (true, true, Some(fm)) = (proxy_local, enable_ebpf, &fake_ip_mapper) {
                    let net = fm.network();
                    let prefix = fm.prefix_len();
                    match crate::ebpf::CgroupConnectEngine::init(port, net, prefix) {
                        Ok(eng) => match eng.attach("/sys/fs/cgroup") {
                            Ok(()) => {
                                info!("cgroup_connect 已接管本机出向 fake-IP 流量 (本机也走代理)");
                                Some(std::sync::Arc::new(eng))
                            }
                            Err(e) => {
                                error!("cgroup_connect attach 失败, 本机流量不走代理: {}", e);
                                None
                            }
                        },
                        Err(e) => {
                            warn!("cgroup_connect 初始化失败, 本机流量不走代理: {}", e);
                            None
                        }
                    }
                } else {
                    None
                };
                // 纯 eBPF 抓裸-IP 转发流量 (与 sk_lookup fake-IP 拦截互补): 配了网卡才挂 tc_divert。
                if let Some(iface) = interface {
                    if enable_ebpf {
                        // MSS clamp 的 mtu: 取该网卡 MTU (PPPoE 会是 1492), 读不到则 1500。
                        let mtu: u32 = std::fs::read_to_string(format!("/sys/class/net/{}/mtu", iface))
                            .ok().and_then(|s| s.trim().parse().ok()).unwrap_or(1500);
                        // fake-IP 段传给 tc_divert 做 ICMP echo 本地反射 (LAN 客户端 ping 代理域名可通)。
                        // fake-ip 未启用 (mapper None) → 传 0.0.0.0/0, mask=0 关闭反射。
                        let (fk_net, fk_prefix) = fake_ip_mapper.as_ref()
                            .map(|fm| (fm.network(), fm.prefix_len()))
                            .unwrap_or((std::net::Ipv4Addr::UNSPECIFIED, 0));
                        match crate::ebpf::TcDivertEngine::init(port, mtu, fk_net, fk_prefix) {
                            Ok(engine) => {
                                let engine = std::sync::Arc::new(engine);
                                let cidrs = watcher.state.load().direct_v4_cidrs();
                                if let Err(e) = engine.sync_direct_cidrs(&cidrs) {
                                    warn!("tc_divert direct_cidr 初始加载失败: {}", e);
                                }
                                match engine.attach(&iface) {
                                    Ok(()) => {
                                        info!("tc_divert 已接管 {} 上的裸-IP 转发流量 ({} 段直连快路径)", iface, cidrs.len());
                                        tc_divert_engine = Some(engine.clone());
                                        // 热重载后按新规则刷新 direct_cidr map
                                        let eng = engine.clone();
                                        watcher.set_reload_hook(move |st| {
                                            if let Err(e) = eng.sync_direct_cidrs(&st.direct_v4_cidrs()) {
                                                warn!("tc_divert direct_cidr 热重载刷新失败: {}", e);
                                            }
                                        });
                                    }
                                    Err(e) => error!("tc_divert attach {} 失败, 裸-IP 转发流量不接管: {}", iface, e),
                                }
                            }
                            Err(e) => warn!("tc_divert 初始化失败, 裸-IP 转发流量不接管: {}", e),
                        }
                    } else {
                        warn!("Transparent interface={} 已配置但 eBPF 未启用, tc_divert 跳过", iface);
                    }
                }
                let trans_eng = transparent_engine.clone();
                // DNS 劫持: 开启时建一个"只处理查询、不 serve"的 forwarder, 与 dns 入站
                // 共用同一个 fake_ip_mapper, 交给透明 UDP/TCP 路径应答 port-53 流量。
                let hijack_state = state_clone.clone();
                let hijack_fm = fake_mapper_clone.clone();
                let hijack_xdp = xdp_engine.clone();
                tokio::spawn(async move {
                    if let (Some(te), Some(fm)) = (trans_eng, fake_mapper_clone) {
                        let dns_hijack_fwd = if dns_hijack {
                            match crate::dns::server::DnsForwarder::for_hijack(
                                hijack_state, hijack_fm, hijack_xdp,
                            ).await {
                                Ok(f) => { info!("DNS 劫持已启用: 流经 LAN 的 53 端口查询将由本机应答"); Some(f) }
                                Err(e) => { error!("DNS 劫持 forwarder 构造失败, 劫持关闭: {}", e); None }
                            }
                        } else { None };
                        let net = fm.network();
                        let prefix = fm.prefix_len();
                        if let Err(e) = crate::proxy::transparent::start_transparent(
                            inbound_tag.clone(), &listen_addr, state_clone, ebpf_clone, fm, te, net, prefix, cgroup_engine, dns_hijack_fwd
                        ).await {
                            tracing::error!("Transparent proxy listener failed: {}", e);
                        }
                    } else {
                        tracing::error!("Transparent inbound requires fake_ip and eBPF transparent engine to be enabled");
                    }
                });
            }
            crate::config::InboundConfig::Dns { tag, listen, port } => {
                let listen_addr = crate::net_util::join_host_port(&listen, port);
                let dns_tag: std::sync::Arc<str> = tag.as_str().into();
                let st_for_dns = state_clone.clone();
                let fm_for_dns = fake_mapper_clone.clone();
                let xdp_for_dns = xdp_engine.clone();
                tokio::spawn(async move {
                    if let Ok(addr) = listen_addr.parse::<std::net::SocketAddr>() {
                        let _ = crate::dns::server::DnsForwarder::start(
                            dns_tag,
                            addr,
                            st_for_dns,
                            fm_for_dns,
                            xdp_for_dns,
                        ).await;
                    }
                });
            }
        }
    }

    // Keep main thread alive
    match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
        Ok(mut sigterm) => {
            tokio::select! {
                _ = tokio::signal::ctrl_c() => {}
                _ = sigterm.recv() => {}
            }
        }
        Err(_) => {
            let _ = tokio::signal::ctrl_c().await;
        }
    }
    info!("Shutting down Mirage-rs...");
    // 退出前最终落盘 fake-IP 映射 (周期 flush 之外, 保住最近 <60s 的新分配)。
    if let Some(m) = &fake_ip_mapper {
        m.flush();
    }
    // 清理透明代理 fake-IP 本地路由 (若装过). best-effort, 失败无害.
    crate::proxy::transparent_net::cleanup().await;
    // 摘掉 tc 过滤器: 下面是 process::exit(0), 析构不跑, 不显式摘就会留在网卡上。
    if let Some(e) = &tc_divert_engine {
        e.detach();
    }
    std::process::exit(0);
}

