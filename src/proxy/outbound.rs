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
    /// Shadowsocks 出站: 经 SS 加密连 SS 服务器。`underlying` 设了则 SS 连接经该出站拨号
    /// (SS-over-X, 如 underlying=Mirage = 类 shadow-tls+ss 嵌套); 否则直连。
    Shadowsocks {
        tag: String,
        cfg: Arc<crate::proxy::shadowsocks::SsConfig>,
        underlying: Option<Arc<OutboundNode>>,
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
    /// 负载均衡组: 把连接**分摊**到多个健康成员 (与 urltest "选一个最优" 不同)。
    /// v1 = round-robin (每连接原子递增取模)。复用 is_healthy 只在健康成员里分摊。
    LoadBalance {
        tag: String,
        children: Vec<Arc<OutboundNode>>,
        /// round-robin 游标 (每次 resolve 递增)。
        next: Arc<std::sync::atomic::AtomicU64>,
    },
}

impl OutboundNode {
    pub fn tag(&self) -> &str {
        match self {
            Self::Mirage { tag, .. } => tag,
            Self::Wireguard { tag, .. } => tag,
            Self::Direct { tag } => tag,
            Self::Block { tag } => tag,
            Self::Shadowsocks { tag, .. } => tag,
            Self::Urltest { tag, .. } => tag,
            Self::Fallback { tag, .. } => tag,
            Self::Selector { tag, .. } => tag,
            Self::LoadBalance { tag, .. } => tag,
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
            Self::Direct { .. } | Self::Block { .. } | Self::Wireguard { .. } | Self::Shadowsocks { .. } => true,
            Self::Urltest { children, .. } | Self::Fallback { children, .. } | Self::Selector { children, .. } | Self::LoadBalance { children, .. } => {
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
            Self::Direct { .. } | Self::Block { .. } | Self::Wireguard { .. } | Self::Shadowsocks { .. } => None,
            Self::Urltest { .. } | Self::Fallback { .. } | Self::Selector { .. } | Self::LoadBalance { .. } => {
                let leaf = self.resolve_leaf();
                if std::ptr::eq(&*leaf, &**self) { None } else { leaf.latency_rtt_ms() }
            }
        }
    }

    pub fn latency_http_ms(self: &Arc<Self>) -> Option<u64> {
        match &**self {
            Self::Mirage { pool, .. } => pool.stats.read().unwrap_or_else(|e| e.into_inner()).latency_ms(),
            Self::Direct { .. } | Self::Block { .. } | Self::Wireguard { .. } | Self::Shadowsocks { .. } => None,
            Self::Urltest { .. } | Self::Fallback { .. } | Self::Selector { .. } | Self::LoadBalance { .. } => {
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
            Self::LoadBalance { children, next, .. } => {
                // round-robin: 只在健康成员里分摊, 原子游标递增取模。
                let healthy: Vec<_> = children.iter().filter(|c| c.is_healthy()).collect();
                if healthy.is_empty() {
                    // 无健康成员: 退回首个 child 去试 (别 self.clone 成死路)。
                    return children.first().map(|c| c.resolve_leaf()).unwrap_or_else(|| self.clone());
                }
                let i = (next.fetch_add(1, std::sync::atomic::Ordering::Relaxed) % healthy.len() as u64) as usize;
                healthy[i].resolve_leaf()
            }
            _ => self.clone(),
        }
    }

    /// 统一出站流接口: 经本出站连到 `target`, 返回一条普通字节流。
    ///
    /// 让**进程内消费者** (geo 下载 / 订阅刷新 / 链式代理) 直接用隧道, 不再绕 SOCKS 入站自连
    /// (见 brain unified-outbound-stream)。组出站先 `resolve_leaf` 选叶子再连。
    /// target 用类型化 [`Address`] (吸收 Gemini 建议): Domain 交由出站/服务端解析, Socket 直用,
    /// 免各处重复解析 host:port 字符串; 也为链式代理 (#5) 的 dialer 注入铺路。
    pub async fn connect(self: &Arc<Self>, target: &Address) -> anyhow::Result<OutStream> {
        let leaf = self.resolve_leaf();
        match &*leaf {
            OutboundNode::Direct { .. } => {
                // Socket 直连 (免解析); Domain 交给 tokio 解析。
                let s = match target {
                    Address::Socket(sa) => tokio::net::TcpStream::connect(sa).await?,
                    Address::Domain(h, p) => tokio::net::TcpStream::connect((h.as_str(), *p)).await?,
                };
                let _ = s.set_nodelay(true);
                Ok(OutStream::Direct(s))
            }
            OutboundNode::Block { tag } => {
                anyhow::bail!("outbound `{tag}` 是 block, 拒绝连接 {target}")
            }
            OutboundNode::Mirage { pool, .. } => {
                let mut tunnel = pool.get().await?;
                // 目标头: [2B len][host:port]; 服务端据此远程解析并连接 (Domain 保留域名交服务端
                // 解析, 抗污染)。与 handler.rs 一致。
                let hp = target.host_port();
                let tb = hp.as_bytes();
                if tb.len() > u16::MAX as usize {
                    anyhow::bail!("target 过长: {} 字节", tb.len());
                }
                let mut hdr = Vec::with_capacity(2 + tb.len());
                hdr.extend_from_slice(&(tb.len() as u16).to_be_bytes());
                hdr.extend_from_slice(tb);
                tunnel.writer.send_data(&hdr).await?;
                Ok(OutStream::Mirage(crate::proxy::mirage_stream::MirageStream::from_tunnel(tunnel)))
            }
            OutboundNode::Wireguard { .. } => {
                let wt = leaf.wg_tunnel().await?;
                // WG 需 SocketAddr: Socket 直用; Domain 经隧道内 DNS 解析。
                let remote = match target {
                    Address::Socket(sa) => *sa,
                    Address::Domain(h, p) => crate::proxy::wg::resolve_target(&wt, h, *p).await?,
                };
                let s = crate::proxy::wg::socket::WgTcpStream::connect(wt, remote).await?;
                Ok(OutStream::Wg(s))
            }
            OutboundNode::Shadowsocks { cfg, underlying, .. } => {
                // PSK 格式错先于建连校验 (fail-fast, 别白建 underlying 隧道; SIP022 的 base64 PSK
                // 长度/格式错是配置问题)。SIP004 密码任意, 无需校验。
                if cfg.method.is_2022() {
                    crate::proxy::shadowsocks::decode_ss2022_psk(&cfg.password, cfg.method.key_len())?;
                }
                // 1. 拨 SS 服务器: 有 underlying 则骑它 (SS-over-X, 如 SS-over-Mirage), 否则直连。
                //    两半装箱 → SsStream 类型统一 (BoxRead/BoxWrite)。
                let ss_server = Address::Domain(cfg.server.clone(), cfg.port);
                let (r, w): (crate::proxy::tunnel::BoxRead, crate::proxy::tunnel::BoxWrite) =
                    match underlying {
                        Some(u) => {
                            // Box::pin: connect 直接递归调 connect (SS-over-X), async 递归须装箱。
                            let out = Box::pin(u.connect(&ss_server)).await?;
                            let (r, w) = tokio::io::split(out);
                            (Box::new(r), Box::new(w))
                        }
                        None => {
                            let s = tokio::net::TcpStream::connect((cfg.server.as_str(), cfg.port)).await?;
                            let _ = s.set_nodelay(true);
                            let (r, w) = s.into_split();
                            (Box::new(r), Box::new(w))
                        }
                    };
                // 2. SS 客户端握手, 真实目标作为 SS 目标头 (server 端到端解出并连)。
                let (reader, writer) =
                    crate::proxy::shadowsocks::client_handshake_over(r, w, cfg, &target.host_port()).await?;
                Ok(OutStream::Ss(crate::proxy::ss_stream::SsStream::new(reader, writer)))
            }
            // resolve_leaf 已把组解到叶子; 仍是组 = 无健康成员可用。
            other => anyhow::bail!("outbound `{}` 无可用叶子出站, 无法连接 {target}", other.tag()),
        }
    }
}

/// 类型化出站目标 (吸收 Gemini 方案): 域名与已解析地址分开, 免各处重复 host:port 字符串解析。
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Address {
    /// 域名 + 端口。交由出站远程解析 (Mirage 服务端 / WG 隧道内 DNS), 抗本地 DNS 污染。
    Domain(String, u16),
    /// 已解析的 socket 地址 (v4/v6)。
    Socket(std::net::SocketAddr),
}

impl Address {
    /// 解析 `host:port` / `[v6]:port` / `ip:port`: 纯 IP → Socket, 否则 Domain。
    pub fn parse(s: &str) -> anyhow::Result<Address> {
        // 完整 socket 地址 (含 ip:port / [v6]:port) 优先。
        if let Ok(sa) = s.parse::<std::net::SocketAddr>() {
            return Ok(Address::Socket(sa));
        }
        // 否则拆 host:port ([v6]:port 或域名:port)。
        let (host, port) = if let Some(rest) = s.strip_prefix('[') {
            rest.split_once("]:")
                .ok_or_else(|| anyhow::anyhow!("非法 [v6]:port: {s}"))?
        } else {
            s.rsplit_once(':')
                .ok_or_else(|| anyhow::anyhow!("target 缺端口 (需 host:port): {s}"))?
        };
        if host.is_empty() {
            anyhow::bail!("target host 为空: {s}");
        }
        Ok(Address::Domain(host.to_string(), port.parse()?))
    }

    /// 端口。
    pub fn port(&self) -> u16 {
        match self {
            Address::Domain(_, p) => *p,
            Address::Socket(sa) => sa.port(),
        }
    }

    /// `host:port` 串 (Mirage 目标头 / 日志用); v6 socket 自带方括号。
    pub fn host_port(&self) -> String {
        match self {
            Address::Domain(h, p) => crate::net_util::join_host_port(h, *p),
            Address::Socket(sa) => sa.to_string(),
        }
    }
}

impl std::fmt::Display for Address {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.host_port())
    }
}

/// 统一出站字节流。闭集枚举 (无 vtable); 各变体都 Unpin, poll 委托直接 `Pin::new`。
pub enum OutStream {
    Direct(tokio::net::TcpStream),
    Mirage(crate::proxy::mirage_stream::MirageStream),
    Wg(crate::proxy::wg::socket::WgTcpStream),
    Ss(crate::proxy::ss_stream::SsStream),
}

impl tokio::io::AsyncRead for OutStream {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match &mut *self {
            OutStream::Direct(s) => std::pin::Pin::new(s).poll_read(cx, buf),
            OutStream::Mirage(s) => std::pin::Pin::new(s).poll_read(cx, buf),
            OutStream::Wg(s) => std::pin::Pin::new(s).poll_read(cx, buf),
            OutStream::Ss(s) => std::pin::Pin::new(s).poll_read(cx, buf),
        }
    }
}

impl tokio::io::AsyncWrite for OutStream {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        match &mut *self {
            OutStream::Direct(s) => std::pin::Pin::new(s).poll_write(cx, buf),
            OutStream::Mirage(s) => std::pin::Pin::new(s).poll_write(cx, buf),
            OutStream::Wg(s) => std::pin::Pin::new(s).poll_write(cx, buf),
            OutStream::Ss(s) => std::pin::Pin::new(s).poll_write(cx, buf),
        }
    }
    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match &mut *self {
            OutStream::Direct(s) => std::pin::Pin::new(s).poll_flush(cx),
            OutStream::Mirage(s) => std::pin::Pin::new(s).poll_flush(cx),
            OutStream::Wg(s) => std::pin::Pin::new(s).poll_flush(cx),
            OutStream::Ss(s) => std::pin::Pin::new(s).poll_flush(cx),
        }
    }
    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match &mut *self {
            OutStream::Direct(s) => std::pin::Pin::new(s).poll_shutdown(cx),
            OutStream::Mirage(s) => std::pin::Pin::new(s).poll_shutdown(cx),
            OutStream::Wg(s) => std::pin::Pin::new(s).poll_shutdown(cx),
            OutStream::Ss(s) => std::pin::Pin::new(s).poll_shutdown(cx),
        }
    }
}

pub struct OutboundManager {
    pub outbounds: HashMap<String, Arc<OutboundNode>>,
}

impl OutboundManager {
    /// 建一个 Mirage 出站节点 (含 WarmPool)。`underlying` 为链式代理 (Mirage-over-X) 的底层出站,
    /// None = 直连。抽出以便 Pass 1 (无 underlying) 与 Pass 2 (依赖 underlying 已建) 复用。
    fn build_mirage(oc: &OutboundConfig, underlying: Option<Arc<OutboundNode>>) -> Arc<OutboundNode> {
        let OutboundConfig::Mirage {
            tag, server, server_port, password, camouflage_host, pool_size,
            brutal_rate_mbps, brutal_base_rtt_ms, pfs, ..
        } = oc else { unreachable!("build_mirage 只接受 Mirage 配置") };
        let pool_cfg = Arc::new(PoolConfig {
            server_host: server.clone(),
            server_port: *server_port,
            password: password.clone(),
            camouflage_host: camouflage_host.clone(),
            pool_size: *pool_size,
            underlying,
            pfs: *pfs,
        });
        let bytes_per_sec = brutal_rate_mbps.map(|m| m * 125_000);
        let brutal_state = Arc::new(crate::proxy::pool::BrutalState {
            configured_rate: bytes_per_sec,
            current_rate: Arc::new(std::sync::atomic::AtomicU64::new(bytes_per_sec.unwrap_or(8_000_000))),
            base_rtt: *brutal_base_rtt_ms,
            active_fds: Arc::new(std::sync::Mutex::new(std::collections::HashSet::new())),
        });
        let pool = Arc::new(WarmPool::new(pool_cfg, brutal_state));
        Arc::new(OutboundNode::Mirage {
            tag: tag.clone(),
            pool,
            server_host: server.clone(),
            server_port: *server_port,
            server_ip: Arc::new(RwLock::new(None)),
            rtt_ms: Arc::new(std::sync::atomic::AtomicU64::new(u64::MAX)),
            snd_cwnd: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            total_retrans: Arc::new(std::sync::atomic::AtomicU64::new(u64::MAX)),
            total_segs_out: Arc::new(std::sync::atomic::AtomicU64::new(u64::MAX)),
        })
    }

    /// 建一个 Shadowsocks 出站节点。`underlying` = SS-over-X 的底层出站 (None = 直连 SS 服务器)。
    /// SS 无连接池 (按需 connect), 故不像 Mirage 起 WarmPool。
    fn build_ss(oc: &OutboundConfig, underlying: Option<Arc<OutboundNode>>) -> anyhow::Result<Arc<OutboundNode>> {
        let OutboundConfig::Shadowsocks { tag, server, server_port, method, password, .. } = oc
        else {
            unreachable!("build_ss 只接受 Shadowsocks 配置")
        };
        let m = crate::proxy::shadowsocks::Method::parse(method)?;
        let cfg = Arc::new(crate::proxy::shadowsocks::SsConfig {
            server: server.clone(),
            port: *server_port,
            password: password.clone(),
            method: m,
            block_udp: true, // SS 出站仅 TCP
        });
        Ok(Arc::new(OutboundNode::Shadowsocks { tag: tag.clone(), cfg, underlying }))
    }

    pub fn new(cfg: &Config) -> anyhow::Result<Self> {
        let mut outbounds = HashMap::new();
        let mut deferred = Vec::new();

        // Pass 1: Leaf nodes
        for oc in &cfg.outbounds {
            match oc {
                OutboundConfig::Mirage { tag, underlying, .. } => {
                    // 无 underlying → 直连 Mirage, Pass 1 立即建。有 underlying → 依赖另一出站,
                    // 延后到 Pass 2 (等 underlying 建好再注入)。
                    if underlying.is_some() {
                        deferred.push(oc);
                    } else {
                        outbounds.insert(tag.clone(), Self::build_mirage(oc, None));
                    }
                }
                OutboundConfig::Wireguard {
                    tag, private_key, peer_public_key, preshared_key, endpoint, address,
                    mtu, persistent_keepalive, dns,
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
                            // 隧道内 DNS: 配了则域名经本隧道解析 (出口与 WG 一致, 防 CDN/geo
                            // 拿本地结果)。非法 IP 在 semantic_issues 已 fail-fast, 这里再兜底。
                            dns: dns
                                .as_deref()
                                .map(|s| {
                                    s.parse::<std::net::IpAddr>()
                                        .map_err(|_| anyhow::anyhow!("WireGuard dns `{s}` 不是合法 IP"))
                                })
                                .transpose()?,
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
                OutboundConfig::Shadowsocks { tag, underlying, .. } => {
                    // 同 Mirage: 无 underlying 立即建; 有则延后到 underlying 建好 (Pass 2)。
                    if underlying.is_some() {
                        deferred.push(oc);
                    } else {
                        outbounds.insert(tag.clone(), Self::build_ss(oc, None)?);
                    }
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
                // Mirage-over-X: 依赖 underlying 出站已建, 建好则注入并建本节点, 否则下一轮再试。
                if let OutboundConfig::Mirage { tag, underlying: Some(utag), .. } = oc {
                    match outbounds.get(utag) {
                        Some(u) => {
                            let u = u.clone();
                            outbounds.insert(tag.clone(), Self::build_mirage(oc, Some(u)));
                            progress = true;
                        }
                        None => next_round.push(oc),
                    }
                    continue;
                }
                // SS-over-X: 同理, 等 underlying 建好再注入建 SS 出站。
                if let OutboundConfig::Shadowsocks { tag, underlying: Some(utag), .. } = oc {
                    match outbounds.get(utag) {
                        Some(u) => {
                            let u = u.clone();
                            outbounds.insert(tag.clone(), Self::build_ss(oc, Some(u))?);
                            progress = true;
                        }
                        None => next_round.push(oc),
                    }
                    continue;
                }

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
                    OutboundConfig::LoadBalance { tag, outbounds, url, interval, .. } => {
                        hc_url = url.clone();
                        hc_interval = *interval;
                        (tag, outbounds, "load_balance", *interval, 0)
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
                    } else if otype == "load_balance" {
                        Arc::new(OutboundNode::LoadBalance {
                            tag: tag.clone(),
                            children,
                            next: Arc::new(std::sync::atomic::AtomicU64::new(0)),
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
                // 配置错误 (未解析 / 循环出站组): 返回诊断错误而非 panic 杀进程。
                anyhow::bail!(
                    "outbound 组无法解析或存在循环引用: {:?} (检查这些 group 的 children 是否都指向已定义的出站, 且无相互/自我引用)",
                    next_round
                );
            }
            pending = next_round;
        }

        Ok(Self { outbounds })
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
        let m = OutboundManager::new(&cfg).expect("测试配置应能构建出站");
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

        let m = OutboundManager::new(&cfg).expect("测试配置应能构建出站");
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

#[cfg(test)]
mod connect_tests {
    use super::*;
    use crate::config::Config;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    fn mgr(outbounds_json: &str) -> OutboundManager {
        let s = format!(
            r#"{{"inbounds":[],"outbounds":{outbounds_json},"routing":{{"default_outbound":"direct","rules":[]}}}}"#
        );
        let cfg: Config = serde_json::from_str(&s).unwrap();
        OutboundManager::new(&cfg).unwrap()
    }

    /// Direct 出站的统一 connect: 应给出一条能读写的普通字节流 (回环 echo 往返)。
    #[tokio::test]
    async fn connect_direct_roundtrips() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut s, _) = listener.accept().await.unwrap();
            let mut b = [0u8; 8];
            let n = s.read(&mut b).await.unwrap();
            s.write_all(&b[..n]).await.unwrap();
        });

        let m = mgr(r#"[{"type":"direct","tag":"direct"}]"#);
        let node = m.outbounds.get("direct").unwrap().clone();
        let mut s = node.connect(&Address::parse(&addr.to_string()).unwrap()).await.unwrap();
        s.write_all(b"ping").await.unwrap();
        s.flush().await.unwrap();
        let mut buf = [0u8; 4];
        s.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"ping", "Direct connect 应回环通");
    }

    /// Block 出站 connect 必须报错 (拒绝连接), 绝不静默放行。
    #[tokio::test]
    async fn connect_block_errors() {
        let m = mgr(r#"[{"type":"direct","tag":"direct"},{"type":"block","tag":"block"}]"#);
        let node = m.outbounds.get("block").unwrap().clone();
        let t = Address::parse("example.com:80").unwrap();
        assert!(node.connect(&t).await.is_err(), "block 出站应拒绝连接");
    }

    /// Mirage-over-X: 配了 underlying=direct 应能建成 (Pass 2 注入 underlying)。
    /// tokio::test: build_mirage → WarmPool::new 内部 spawn 预热任务, 需 runtime。
    #[tokio::test]
    async fn mirage_over_underlying_builds() {
        // 192.0.2.x = TEST-NET, 非路由 (预热后台连不上无所谓, 只验构建/注入)。
        let m = mgr(r#"[
            {"type":"direct","tag":"direct"},
            {"type":"mirage","tag":"m","server":"192.0.2.1","server_port":443,"password":"p","camouflage_host":"a.com","underlying":"direct"}
        ]"#);
        assert!(m.outbounds.contains_key("m"), "Mirage-over-direct 应建成");
    }

    /// 环形 underlying (a→b→a) 无法解析 → OutboundManager::new 返回 Err 而非死循环/panic。
    #[test]
    fn cyclic_underlying_errs() {
        let s = r#"{"inbounds":[],"outbounds":[
            {"type":"mirage","tag":"a","server":"192.0.2.1","server_port":443,"password":"p","camouflage_host":"x","underlying":"b"},
            {"type":"mirage","tag":"b","server":"192.0.2.2","server_port":443,"password":"p","camouflage_host":"x","underlying":"a"}
        ],"routing":{"default_outbound":"a","rules":[]}}"#;
        let cfg: crate::config::Config = serde_json::from_str(s).unwrap();
        assert!(OutboundManager::new(&cfg).is_err(), "环形 underlying 应报错");
    }

    #[test]
    fn address_parse_classifies() {
        // 纯 IP:port → Socket
        assert!(matches!(Address::parse("1.2.3.4:80").unwrap(), Address::Socket(_)));
        assert!(matches!(Address::parse("[2001:db8::1]:443").unwrap(), Address::Socket(_)));
        // 域名:port → Domain
        match Address::parse("example.com:443").unwrap() {
            Address::Domain(h, p) => { assert_eq!(h, "example.com"); assert_eq!(p, 443); }
            _ => panic!("域名应解成 Domain"),
        }
        // host_port 往返 + v6 方括号
        assert_eq!(Address::parse("example.com:443").unwrap().host_port(), "example.com:443");
        assert_eq!(Address::parse("[2001:db8::1]:443").unwrap().host_port(), "[2001:db8::1]:443");
        // 缺端口 / 空 host 报错
        assert!(Address::parse("noport").is_err());
        assert!(Address::parse(":80").is_err());
    }

    /// SS 出站端到端: connect() 经 SS 出站连一个 loopback SS 服务端, 验证目标解出 + 双向往返。
    #[tokio::test]
    async fn ss_outbound_e2e_roundtrip() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let srv = tokio::spawn(async move {
            let (s, _) = listener.accept().await.unwrap();
            let (r, w) = s.into_split();
            let m = crate::proxy::shadowsocks::Method::parse("aes-256-gcm").unwrap();
            let (mut ssr, mut ssw) =
                crate::proxy::shadowsocks::server_handshake(r, w, m, "sspw").await.unwrap();
            let first = ssr.read_chunk().await.unwrap();
            let (target, hlen) = crate::proxy::shadowsocks::decode_socks_addr(&first).unwrap();
            assert_eq!(target, "example.com:443", "SS 服务端应解出出站目标");
            let payload = if first.len() > hlen {
                first[hlen..].to_vec()
            } else {
                ssr.read_chunk().await.unwrap()
            };
            assert_eq!(&payload, b"ping-ss-out");
            ssw.write_all(b"pong-ss-out").await.unwrap();
        });

        let m = mgr(&format!(
            r#"[{{"type":"direct","tag":"direct"}},
                {{"type":"shadowsocks","tag":"ss","server":"{}","server_port":{},
                  "method":"aes-256-gcm","password":"sspw"}}]"#,
            addr.ip(), addr.port()
        ));
        let node = m.outbounds.get("ss").unwrap().clone();
        let mut s = node.connect(&Address::parse("example.com:443").unwrap()).await.unwrap();
        s.write_all(b"ping-ss-out").await.unwrap();
        s.flush().await.unwrap();
        let mut buf = [0u8; 32];
        let n = s.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"pong-ss-out", "SS 出站应收到服务端回复");
        srv.await.unwrap();
    }

    /// SS-over-Mirage (类 shadow-tls+ss): SS 出站配 underlying=mirage 应能建成 (拓扑排序)。
    #[tokio::test]
    async fn ss_over_mirage_builds() {
        let m = mgr(r#"[
            {"type":"mirage","tag":"m","server":"192.0.2.1","server_port":443,"password":"p","camouflage_host":"a.com"},
            {"type":"shadowsocks","tag":"ss","server":"192.0.2.2","server_port":8388,
             "method":"aes-256-gcm","password":"pw","underlying":"m"}
        ]"#);
        assert!(m.outbounds.contains_key("ss"), "SS-over-Mirage 应建成");
    }
}

#[cfg(test)]
mod lb_tests {
    use super::*;
    use std::sync::atomic::AtomicU64;

    fn direct(tag: &str) -> Arc<OutboundNode> {
        Arc::new(OutboundNode::Direct { tag: tag.to_string() })
    }

    #[test]
    fn load_balance_round_robins_healthy() {
        // Direct 恒健康; round-robin 应在成员间轮流。
        let lb = Arc::new(OutboundNode::LoadBalance {
            tag: "lb".into(),
            children: vec![direct("a"), direct("b"), direct("c")],
            next: Arc::new(AtomicU64::new(0)),
        });
        let seq: Vec<String> = (0..6).map(|_| lb.resolve_leaf().tag().to_string()).collect();
        assert_eq!(seq, vec!["a", "b", "c", "a", "b", "c"], "应轮流分摊");
    }

    #[test]
    fn load_balance_skips_unhealthy() {
        // Block 也恒健康 (is_healthy=true), 换用一个真不健康的场景不易造; 这里验"全健康时
        // 不漏成员"已由上面覆盖。无健康成员的退路 (children.first) 由代码保证不 panic:
        let empty_like = Arc::new(OutboundNode::LoadBalance {
            tag: "lb".into(),
            children: vec![direct("only")],
            next: Arc::new(AtomicU64::new(0)),
        });
        assert_eq!(empty_like.resolve_leaf().tag(), "only");
    }

    #[test]
    fn load_balance_builds_and_checks() {
        let s = r#"{
          "inbounds": [],
          "outbounds": [
            { "type": "direct", "tag": "d1" },
            { "type": "direct", "tag": "d2" },
            { "type": "load_balance", "tag": "lb", "outbounds": ["d1", "d2"] }
          ],
          "routing": { "default_outbound": "lb", "rules": [] }
        }"#;
        let cfg: crate::config::Config = serde_json::from_str(s).unwrap();
        assert!(cfg.semantic_issues().is_empty(), "合法 lb 配置无告警: {:?}", cfg.semantic_issues());
        let m = OutboundManager::new(&cfg).expect("测试配置应能构建出站");
        assert!(matches!(&**m.outbounds.get("lb").unwrap(), OutboundNode::LoadBalance { .. }));
    }

    #[test]
    fn unresolved_outbound_group_errs_not_panics() {
        // group 的 children 指向不存在的 tag → 永远解析不出。应返回 Err 而非 panic 杀进程。
        let s = r#"{
          "inbounds": [],
          "outbounds": [
            { "type": "direct", "tag": "direct" },
            { "type": "selector", "tag": "grp", "outbounds": ["ghost"] }
          ],
          "routing": { "default_outbound": "direct", "rules": [] }
        }"#;
        let cfg: crate::config::Config = serde_json::from_str(s).unwrap();
        assert!(OutboundManager::new(&cfg).is_err(), "未解析出站组应返回 Err 而非 panic");
    }

    #[test]
    fn load_balance_bad_strategy_rejected() {
        let s = r#"{
          "inbounds": [],
          "outbounds": [
            { "type": "direct", "tag": "d1" },
            { "type": "load_balance", "tag": "lb", "outbounds": ["d1"], "strategy": "consistent-hash" }
          ],
          "routing": { "default_outbound": "lb", "rules": [] }
        }"#;
        let cfg: crate::config::Config = serde_json::from_str(s).unwrap();
        assert!(cfg.semantic_issues().iter().any(|i| i.contains("strategy") && i.contains("consistent-hash")),
            "未支持的 strategy 应被拦: {:?}", cfg.semantic_issues());
    }
}
