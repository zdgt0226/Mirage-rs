//! QUIC 传输 (实验, `--features quic`)。见 docs/quic-transport-design.md。
//!
//! **Model X (精简)**: 一个共享 QUIC 连接 (QuicMux) 承载多条双向流, 每条 = 一条隧道。每流首部
//! `[token(32B)][2B target_len][host:port]`, 之后裸转发 —— **无 per-stream fake-TLS 握手、无内层
//! AEAD** (QUIC 自己的 TLS1.3 已加密所有流; fake-TLS 在 QUIC 里不可见故抗检测价值为零)。token 为
//! 无状态每流认证 (HMAC 密码+时间), 防开放代理。SNI 用良性 camouflage_host (抗 GFW SNI 封锁, 见 §7)。
//!
//! ⚠️ **不隐蔽**: quinn 默认 QUIC 指纹裸奔, 证书自签+客户端不校验 (机密性靠 QUIC 自身 TLS, 认证靠
//! token; 主动 MITM 弱于密码绑定 AEAD)。勿用于敌对网络。抗审查主力是 TCP fake-TLS 主链路。

use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use anyhow::{Context as _, Result};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// ALPN = `h3` (HTTP/3): QUIC Initial 的 ClientHello 明文可读, 用真 h3 ALPN 混进浏览器 QUIC 人群
/// (P0 曾用 "mirage-p0" 是活靶子)。⚠️ **仅 ALPN 不够** —— rustls 的 ClientHello 扩展顺序/GREASE
/// 仍是 rustls 指纹, JA4-QUIC 可辨。完整仿真 (patch rustls / Rust-uTLS) 是 P1 未竟部分, 见
/// docs/quic-transport-design.md §3.1 + §7。
const ALPN: &[u8] = b"h3";

/// 绑客户端 UDP socket。`low_src_port` 时尝试源端口 ≤ 目标端口 (GFW "仅 src>dst 才查 QUIC" 规避,
/// USENIX Security 2025)。优先非特权范围 [1024, dst_port); dst≤1024 需特权口, 失败回落临时口。
fn bind_client_socket(is_ipv6: bool, dst_port: u16, low_src_port: bool) -> std::io::Result<std::net::UdpSocket> {
    let any = if is_ipv6 { "::" } else { "0.0.0.0" };
    if low_src_port && dst_port > 1 {
        let (lo, hi) = if dst_port > 1024 { (1024u16, dst_port) } else { (1u16, dst_port) };
        for _ in 0..8 {
            let sp = lo + fastrand::u16(0..(hi - lo).max(1));
            if let Ok(s) = std::net::UdpSocket::bind(format!("{any}:{sp}")) {
                tracing::debug!("QUIC: 源端口 {} ≤ 目标 {} (GFW src-port 规避)", sp, dst_port);
                return Ok(s);
            }
        }
        tracing::warn!("QUIC: 无法绑 ≤{} 的源端口 (需 root? 占用?), 回落临时口 —— src-port 规避降级", dst_port);
    }
    std::net::UdpSocket::bind(format!("{any}:0"))
}

/// 建客户端 endpoint (自建 socket, 支持源端口规避 + pre-packet)。`pre_packet` 时在 QUIC 握手前
/// 先发一个随机 UDP 包到 server, desync GFW 的 UDP 四元组追踪 (USENIX Security 2025 规避法之一)。
fn make_client_endpoint(server_addr: SocketAddr, low_src_port: bool, pre_packet: bool, obfs: Option<&str>) -> Result<quinn::Endpoint> {
    let sock = bind_client_socket(server_addr.is_ipv6(), server_addr.port(), low_src_port)
        .context("QUIC: 绑客户端 UDP socket 失败")?;
    if pre_packet {
        // 随机长度 (8~64B) 随机内容, 在同一 4-tuple 上先发, 让 GFW 对该四元组的 QUIC 追踪失准。
        // 到达我们的 QUIC 服务端会被当无效包丢弃, 无副作用。⚠️ obfs 开时这个裸包不混淆, 会被服务端
        // obfs socket 去混淆后丢 (无副作用); 但也别在 obfs 下用 pre_packet (裸包本身反常), 二选一。
        let n = 8 + fastrand::usize(0..=56);
        let junk: Vec<u8> = (0..n).map(|_| fastrand::u8(..)).collect();
        let _ = sock.send_to(&junk, server_addr);
        tracing::debug!("QUIC: 发 {}B pre-packet 到 {} (GFW 四元组 desync)", n, server_addr);
    }
    let runtime = quinn::default_runtime().context("QUIC: 无 tokio runtime")?;
    match obfs {
        Some(pw) => {
            tracing::info!("QUIC: Salamander 混淆已启用 (客户端)");
            let inner = runtime.wrap_udp_socket(sock).context("QUIC: wrap socket 失败")?;
            let obf = crate::proxy::quic_obfs::ObfsSocket::wrap(inner, pw);
            quinn::Endpoint::new_with_abstract_socket(endpoint_config(true), None, obf, runtime)
                .context("QUIC: 建客户端 endpoint (obfs) 失败")
        }
        None => quinn::Endpoint::new(quinn::EndpointConfig::default(), None, sock, runtime)
            .context("QUIC: 建客户端 endpoint 失败"),
    }
}

/// EndpointConfig。obfs 开时缩小 max_udp_payload_size, 让 +8B salt 后的包仍 ≤ MTU 不分片。
fn endpoint_config(obfs: bool) -> quinn::EndpointConfig {
    let mut ec = quinn::EndpointConfig::default();
    if obfs {
        let _ = ec.max_udp_payload_size(crate::proxy::quic_obfs::OBFS_MAX_UDP_PAYLOAD);
    }
    ec
}

/// QUIC 拥塞控制选择。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QuicCc {
    /// quinn 原生 CC。
    Stock,
    /// erasure-aware CC (默认, 见 quic_cc::ErasureConfig)。
    Erasure,
    /// 定速 (brutal 语义, 见 quic_cc::FixedRateConfig), 字节/秒。
    FixedRate(u64),
}

impl QuicCc {
    /// 由配置推出: 配了 `brutal_rate_mbps` (>0) → 定速 (优先); 否则按 `quic_erasure_cc` 选 erasure / 原生。
    pub fn from_config(erasure: bool, brutal_bytes_per_sec: Option<u64>) -> Self {
        match brutal_bytes_per_sec.filter(|r| *r > 0) {
            Some(r) => QuicCc::FixedRate(r),
            None if erasure => QuicCc::Erasure,
            None => QuicCc::Stock,
        }
    }
}

/// QUIC TransportConfig。`window_mb`/`cc` 来自 config, 环境变量 `MIRAGE_QUIC_WND` (MB) /
/// `MIRAGE_QUIC_CC=off|erasure` 优先覆盖 (供真机 A/B 调参; 覆盖时不走定速)。
fn transport_config(window_mb: u64, cc: QuicCc) -> Arc<quinn::TransportConfig> {
    let mut tc = quinn::TransportConfig::default();

    // 流控窗口: quinn 默认偏小 (~1MB 级), 高 BDP 长肥路径上单流被窗口卡死 (实测 JP↔US 111ms 仅
    // ~9MB/s, 而 TCP 自动调窗到 48MB/s)。默认见 config::DEFAULT_QUIC_WINDOW_MB (8MB)。
    // 上游 quinn MAX_CHUNKS=1024 时大窗口在丢包/重排序线路会因乱序 gap 超限被关连接 (真机实证 4MB 仍切、
    // 2MB 稳); 本仓库已补丁到 8192 (third_party/quinn-proto), 8MB 在 20% 丢包下实验室验证不断连, 见
    // quic_cc.rs GAP_SAFE_CHUNKS + docs §5.5 / §5.9。干净长肥路径可调大 (16-64)。过大 (128+) 在并发+丢包下会过冲。
    let wnd_mb: u64 = std::env::var("MIRAGE_QUIC_WND").ok().and_then(|v| v.parse().ok()).unwrap_or(window_mb);
    let stream_wnd = wnd_mb.max(1) * 1024 * 1024;
    let conn_wnd = stream_wnd.saturating_mul(4);
    tc.stream_receive_window(quinn::VarInt::from_u64(stream_wnd).unwrap_or(quinn::VarInt::MAX));
    tc.receive_window(quinn::VarInt::from_u64(conn_wnd).unwrap_or(quinn::VarInt::MAX));
    tc.send_window(conn_wnd);
    // mux 架构: 一个连接承载多条流 (每条=一条隧道), 服务端须允许客户端开足够多的并发双向流
    // (quinn 默认 ~100, 高并发代理不够)。这是对端向本端advertise的上限, 故 client+server 都设。
    tc.max_concurrent_bidi_streams(quinn::VarInt::from_u32(2048));
    tc.max_concurrent_uni_streams(quinn::VarInt::from_u32(0));
    if let Ok(idle) = std::time::Duration::from_secs(60).try_into() {
        tc.max_idle_timeout(Some(idle));
    }

    let cc = match std::env::var("MIRAGE_QUIC_CC").ok().as_deref() {
        Some("off" | "bbr" | "default" | "stock") => QuicCc::Stock,
        Some("erasure" | "on") => QuicCc::Erasure,
        _ => cc,
    };
    match cc {
        QuicCc::FixedRate(bps) => {
            tc.congestion_controller_factory(Arc::new(crate::proxy::quic_cc::FixedRateConfig { bytes_per_sec: bps }));
            tracing::info!("QUIC: 定速 CC 启用 ({} Mbps, 窗口 {}MB)", bps / 125_000, wnd_mb);
        }
        QuicCc::Erasure => {
            tc.congestion_controller_factory(Arc::new(crate::proxy::quic_cc::ErasureConfig::default()));
            tracing::info!("QUIC: erasure-aware CC 启用 (窗口 {}MB)", wnd_mb);
        }
        QuicCc::Stock => tracing::info!("QUIC: CC = quinn 原生 (erasure 关, 窗口 {}MB)", wnd_mb),
    }
    Arc::new(tc)
}

// ───────────────────────── 客户端 ─────────────────────────

/// 拨号失败后的短暂退避窗口: 防止并发或连续新流在网络故障/配置错误时紧密重拨形成风暴。
const DIAL_FAIL_BACKOFF: std::time::Duration = std::time::Duration::from_millis(250);

#[derive(Clone)]
enum DialOutcome {
    Connected(quinn::Connection),
    Failed(String),
    Cancelled,
}
type DialWatchRx = tokio::sync::watch::Receiver<Option<DialOutcome>>;
type DialWatchTx = tokio::sync::watch::Sender<Option<DialOutcome>>;

/// QUIC mux (P4/mux 架构): **一个共享 QUIC 连接承载多条 bi-stream** (每条 = 一条 Mirage 隧道),
/// 取代 P0 的"一隧道一连接"。收益: 服务端每客户端只见一个连接 = 一个 CC = 天然共享瓶颈, 连接级
/// receive_window 封顶聚合在途量 (治多连接过冲/128MB 崩溃); 省 per-conn crypto/CC/UDP-flow 开销。
///
/// endpoint + 当前连接存在内部, 跨 open_stream 复用; 连接死了 (close_reason) 下次 open_stream 重拨。
/// 建连采用单飞 (Singleflight) 状态机: 锁仅保护内存状态切换, 不跨 DNS/握手网络等待。
pub struct QuicMux {
    inner: Arc<std::sync::Mutex<MuxInner>>,
    host: String,
    port: u16,
    /// QUIC ClientHello 里发的 SNI —— **良性域名 (camouflage_host)**, 而非 server 的真 IP/域名。
    /// GFW 解密 QUIC Initial 读 SNI 按黑名单封 (USENIX Security 2025); 用良性 SNI 即使被查也过。
    /// P0 证书不校验, SNI 值不影响握手成败。
    sni: String,
    /// 尝试把源端口绑到 ≤ 目标端口 (GFW "仅 src>dst 才查 QUIC" 规则的规避)。best-effort:
    /// dst≤1024 需特权端口, 无 root 会回落临时口。默认关 (良性 SNI 已是主防御, 低源口本身略反常)。
    low_src_port: bool,
    /// QUIC 握手前先发随机 UDP 包 desync GFW 四元组追踪 (USENIX Security 2025)。默认关。
    pre_packet: bool,
    /// Salamander 混淆密码 (Some = 开混淆, 把 QUIC 藏成随机 UDP; 两端须一致)。默认关。见 quic_obfs。
    obfs: Option<String>,
    window_mb: u64,
    cc: QuicCc,
    pin: Option<String>,
}

#[derive(Default)]
struct MuxInner {
    endpoint: Option<quinn::Endpoint>,
    conn: Option<quinn::Connection>,
    /// 正在进行中的单飞建连广播通道: Follower 订阅此 Receiver 共享同一次建连结果 (含失败结果)。
    dialing: Option<DialWatchRx>,
    /// 最近一次建连失败的时间戳与错误消息 (供 DIAL_FAIL_BACKOFF 退避窗口快速失败)。
    last_failure: Option<(std::time::Instant, String)>,
    /// 当前连接的建立时刻; 连接被观察到关闭并结算后清空 (防同一连接被重复计入拒绝)。
    conn_since: Option<std::time::Instant>,
    /// 连续被服务端拒绝 (刚建连就被应用层 close(0)) 的次数, 驱动 `reject_until` 指数退避。
    reject_streak: u32,
    /// 被服务端拒绝后的冷却截止时刻: 期间 `get_or_dial_conn` 直接快速失败, 不再重做握手。
    reject_until: Option<std::time::Instant>,
}

/// 刚建连就被服务端应用层 close(0) 的判定窗口: 超过它才被关说明会话曾正常工作 (如中途吊销), 不算拒绝。
const REJECT_WINDOW: std::time::Duration = std::time::Duration::from_secs(10);
/// 拒绝退避上限。
const REJECT_BACKOFF_MAX: std::time::Duration = std::time::Duration::from_secs(30);

/// 服务端拒绝类关闭: 应用层 close 且错误码 0 (服务端对 口令/时钟不符、IP 被屏蔽、凭据吊销、
/// 配了上游中继的 lean 路径 都用同一个通用码 0, 以免给主动探测者留下可区分的指纹), 且是刚建连不久。
fn is_server_rejection(reason: &quinn::ConnectionError, lived: std::time::Duration) -> bool {
    matches!(reason, quinn::ConnectionError::ApplicationClosed(ac) if ac.error_code == quinn::VarInt::from_u32(0))
        && lived < REJECT_WINDOW
}

/// 第 `streak` 次连续拒绝后的冷却时长: 1s, 2s, 4s ... 封顶 30s。
fn reject_backoff(streak: u32) -> std::time::Duration {
    let secs = 1u64 << streak.saturating_sub(1).min(5);
    std::time::Duration::from_secs(secs).min(REJECT_BACKOFF_MAX)
}

impl MuxInner {
    /// 连接被观察到已关闭时结算一次: 刚建连即被服务端拒绝 → 连续计数 + 启动冷却; 其它关闭 (空闲超时、
    /// 长会话后被关等) → 清零。
    ///
    /// 为什么需要: 服务端为抗探测把认证失败的 reset 码统一成通用 0 并直接关整条连接, 客户端不再能靠专用
    /// 错误码识别 "口令不符"。若不退避, 口令/时钟配错时每条新流都会重做一次完整 QUIC 握手 (两端都耗 CPU)。
    fn note_conn_closed(&mut self, reason: &quinn::ConnectionError) {
        let Some(since) = self.conn_since.take() else {
            return; // 已结算过
        };
        if is_server_rejection(reason, since.elapsed()) {
            self.reject_streak = self.reject_streak.saturating_add(1);
            let wait = reject_backoff(self.reject_streak);
            self.reject_until = Some(std::time::Instant::now() + wait);
            static WARNED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
            let msg = format!(
                "QUIC: 服务端刚建连就关闭了连接 (连续第 {} 次, {}s 后重试): 常见原因 口令不符 / 时钟偏差超容差 / 本机 IP 被服务端屏蔽 / 凭据已吊销 / 服务端配置了上游中继 (QUIC 暂不支持)",
                self.reject_streak,
                wait.as_secs()
            );
            if !WARNED.swap(true, std::sync::atomic::Ordering::Relaxed) {
                tracing::warn!("{msg}");
            } else {
                tracing::debug!("{msg}");
            }
        } else {
            self.reject_streak = 0;
            self.reject_until = None;
        }
    }
}

/// 单飞建连 Leader 取消守卫: 若发起拨号的任务在 await DNS/握手期间被取消 (drop),
/// 自动清理 `dialing` 槽位并广播 `DialOutcome::Cancelled`, 让等待中的 Follower 自动选出新 Leader 继续建连。
struct DialLeaderGuard<'a> {
    mux: &'a QuicMux,
    tx: Option<DialWatchTx>,
}

impl Drop for DialLeaderGuard<'_> {
    fn drop(&mut self) {
        if let Some(tx) = self.tx.take() {
            let mut g = self.mux.inner.lock().unwrap_or_else(|e| e.into_inner());
            g.dialing = None;
            drop(g);
            let _ = tx.send(Some(DialOutcome::Cancelled));
        }
    }
}

enum MuxAcquireAction {
    Wait(DialWatchRx),
    Dial(DialWatchTx),
}

impl QuicMux {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        host: &str,
        port: u16,
        sni: &str,
        low_src_port: bool,
        pre_packet: bool,
        obfs: Option<String>,
        window_mb: u64,
        cc: QuicCc,
        pin: Option<String>,
    ) -> Arc<Self> {
        Arc::new(Self {
            inner: Arc::new(std::sync::Mutex::new(MuxInner::default())),
            host: host.to_string(),
            port,
            sni: sni.to_string(),
            low_src_port,
            pre_packet,
            obfs,
            window_mb,
            cc,
            pin,
        })
    }

    fn validate_pin(&self) -> Result<&str> {
        match &self.pin {
            Some(p) if crate::config::is_valid_quic_pin(p) => Ok(p.as_str()),
            Some(p) => {
                tracing::error!("QUIC: quic_pin 格式非法 (`{p}`), 拒绝建立连接 (fail-closed)");
                anyhow::bail!("QUIC: quic_pin 格式非法，拒绝建立连接 (fail-closed)");
            }
            None => {
                tracing::error!("QUIC: 未配置 quic_pin (服务端证书 SPKI 指纹必填, fail-closed)");
                anyhow::bail!("QUIC: 未配置 quic_pin，拒绝建立连接 (fail-closed)");
            }
        }
    }

    /// 获取或单飞建立共享 QUIC 连接 (锁仅保护内存状态切换, 不跨网络等待)。
    /// 返回 `(Connection, was_cached)`。
    async fn get_or_dial_conn(&self) -> Result<(quinn::Connection, bool)> {
        loop {
            let action = {
                let mut g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
                let closed = match &g.conn {
                    Some(c) => match c.close_reason() {
                        None => return Ok((c.clone(), true)),
                        Some(r) => Some(r),
                    },
                    None => None,
                };
                if let Some(reason) = closed {
                    g.note_conn_closed(&reason);
                    g.conn = None;
                    g.endpoint = None;
                }
                if let Some(rx) = &g.dialing {
                    MuxAcquireAction::Wait(rx.clone())
                } else {
                    if let Some(until) = g.reject_until {
                        let now = std::time::Instant::now();
                        if now < until {
                            anyhow::bail!(
                                "QUIC: 服务端拒绝了本客户端的连接 (口令不符 / 时钟偏差 / IP 被屏蔽 / 凭据吊销), 冷却中, {}s 后重试",
                                (until - now).as_secs() + 1
                            );
                        }
                        g.reject_until = None;
                    }
                    if let Some((failed_at, err_msg)) = &g.last_failure {
                        if failed_at.elapsed() < DIAL_FAIL_BACKOFF {
                            anyhow::bail!("{err_msg}");
                        }
                        g.last_failure = None;
                    }
                    let (tx, rx) = tokio::sync::watch::channel(None);
                    g.dialing = Some(rx);
                    MuxAcquireAction::Dial(tx)
                }
            };

            match action {
                MuxAcquireAction::Wait(mut rx) => loop {
                    if let Some(outcome) = rx.borrow_and_update().clone() {
                        match outcome {
                            DialOutcome::Connected(conn) => return Ok((conn, false)),
                            DialOutcome::Failed(msg) => anyhow::bail!("{msg}"),
                            DialOutcome::Cancelled => break, // Leader 任务被取消，重新循环竞争新 Leader
                        }
                    }
                    if rx.changed().await.is_err() {
                        break; // 通道关闭，重新循环竞争新 Leader
                    }
                },
                MuxAcquireAction::Dial(tx) => {
                    let mut leader_guard = DialLeaderGuard {
                        mux: self,
                        tx: Some(tx),
                    };

                    let dial_res: Result<(quinn::Endpoint, quinn::Connection)> = async {
                        let pin = self.validate_pin()?;
                        // 单次 DNS 解析: 每次建连按当前解析结果新建 Endpoint (匹配 IPv4/IPv6 地址族、刷新本地源端口四元组并发送 pre-packet)
                        let addr = resolve(&self.host, self.port).await?;
                        let mut ep = make_client_endpoint(
                            addr,
                            self.low_src_port,
                            self.pre_packet,
                            self.obfs.as_deref(),
                        )?;
                        ep.set_default_client_config(client_config(self.window_mb, self.cc, pin)?);
                        let conn = ep
                            .connect(addr, &self.sni) // SNI = 良性 camouflage_host, 非 server 真身
                            .context("QUIC: connect 配置无效")?
                            .await
                            .map_err(classify_quic_handshake_error)?;
                        Ok((ep, conn))
                    }
                    .await;

                    let tx = leader_guard.tx.take().unwrap();
                    return match dial_res {
                        Ok((ep, conn)) => {
                            let mut g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
                            g.endpoint = Some(ep);
                            g.conn = Some(conn.clone());
                            g.conn_since = Some(std::time::Instant::now());
                            g.last_failure = None;
                            g.dialing = None;
                            drop(g);
                            let _ = tx.send(Some(DialOutcome::Connected(conn.clone())));

                            // 后台监控连接关闭: 一旦服务端在首条流认证失败后 close(0), 立即结算拒绝并记录 WARN,
                            // 不必等到客户端发起"下一次"请求调 open_stream 时才感知并报警。
                            let conn_for_watcher = conn.clone();
                            let inner_weak = Arc::downgrade(&self.inner);
                            tokio::spawn(async move {
                                let reason = conn_for_watcher.closed().await;
                                if let Some(inner) = inner_weak.upgrade() {
                                    let mut g = inner.lock().unwrap_or_else(|e| e.into_inner());
                                    if g.conn.as_ref().is_some_and(|c| c.stable_id() == conn_for_watcher.stable_id()) {
                                        g.note_conn_closed(&reason);
                                        g.conn = None;
                                        g.endpoint = None;
                                    }
                                }
                            });

                            Ok((conn, false))
                        }
                        Err(e) => {
                            let msg = format!("{e:#}");
                            let mut g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
                            g.last_failure = Some((std::time::Instant::now(), msg.clone()));
                            g.dialing = None;
                            drop(g);
                            let _ = tx.send(Some(DialOutcome::Failed(msg)));
                            Err(e)
                        }
                    };
                }
            }
        }
    }

    /// 在共享连接上开一条 bi-stream。首次/断线时惰性单飞建 endpoint + 拨号;
    /// 若复用的缓存连接静默失效导致 `open_bi` 报错，自动清理并透明重连重试 1 次。
    pub async fn open_stream(&self) -> Result<(quinn::SendStream, quinn::RecvStream)> {
        for attempt in 0..2 {
            let (conn, was_cached) = self.get_or_dial_conn().await?;
            match conn.open_bi().await {
                Ok(s) => return Ok(s),
                Err(e) => {
                    let mut g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
                    if g.conn.as_ref().is_some_and(|c| c.stable_id() == conn.stable_id()) {
                        if let Some(reason) = conn.close_reason() {
                            g.note_conn_closed(&reason);
                        }
                        g.conn = None;
                        g.endpoint = None;
                    }
                    drop(g);
                    if !was_cached || attempt == 1 {
                        return Err(anyhow::anyhow!("QUIC: open_bi 失败 (连接已断): {e}"));
                    }
                    tracing::debug!("QUIC: 缓存连接已失效 ({e})，自动重连重试...");
                }
            }
        }
        unreachable!()
    }

    /// 检查并结算当前连接的关闭状态 (防首个流在传输期间被服务端关闭连接后延迟结算)。
    pub fn check_conn_closed(&self) {
        let mut g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(c) = &g.conn {
            if let Some(reason) = c.close_reason() {
                g.note_conn_closed(&reason);
                g.conn = None;
                g.endpoint = None;
            }
        }
    }

    /// 连续被服务端拒绝的次数 (供测试与状态断言)。
    pub fn reject_streak(&self) -> u32 {
        self.inner.lock().unwrap_or_else(|e| e.into_inner()).reject_streak
    }

    /// 是否正处于服务端拒绝后的退避冷却期内。
    pub fn is_in_rejection_cooldown(&self) -> bool {
        let g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        match g.reject_until {
            Some(until) => std::time::Instant::now() < until,
            None => false,
        }
    }
}

pub fn client_config(window_mb: u64, cc: QuicCc, pin: &str) -> Result<quinn::ClientConfig> {
    let mut crypto = rustls::ClientConfig::builder_with_provider(
        rustls::crypto::ring::default_provider().into(),
    )
    .with_protocol_versions(&[&rustls::version::TLS13])
    .context("QUIC: rustls 客户端 builder 失败")?
    .dangerous()
    .with_custom_certificate_verifier(Arc::new(PinnedVerifier::new(pin.to_string())))
    .with_no_client_auth();
    crypto.alpn_protocols = vec![ALPN.to_vec()];
    let qcc = quinn::crypto::rustls::QuicClientConfig::try_from(crypto)
        .context("QUIC: rustls→quinn 客户端配置转换失败")?;
    let mut cfg = quinn::ClientConfig::new(Arc::new(qcc));
    cfg.transport_config(transport_config(window_mb, cc));
    Ok(cfg)
}

// ───────────────────────── 证书固定 (SPKI Pinning) ─────────────────────────

/// 计算 SPKI DER 的证书固定指纹: base64url 无填充 (SHA-256(SPKI DER)), 43 字符。
pub fn spki_pin(spki_der: &[u8]) -> String {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;
    use sha2::{Digest, Sha256};

    let digest = Sha256::digest(spki_der);
    URL_SAFE_NO_PAD.encode(digest)
}

/// 以 0600 权限原子写入私钥 (.tmp + rename)。
fn write_key_atomic_0600(path: &std::path::Path, content: &str) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)?;
        }
    }
    let tmp_path = match path.file_name() {
        Some(name) => {
            let mut tmp_name = name.to_os_string();
            tmp_name.push(".tmp");
            path.with_file_name(tmp_name)
        }
        None => std::path::PathBuf::from(format!("{}.tmp", path.display())),
    };

    #[cfg(unix)]
    {
        use std::fs::OpenOptions;
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        use std::os::unix::fs::PermissionsExt;

        let mut f = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&tmp_path)?;
        f.write_all(content.as_bytes())?;
        f.flush()?;
        let _ = f.set_permissions(std::fs::Permissions::from_mode(0o600));
    }
    #[cfg(not(unix))]
    {
        use std::io::Write;
        let mut f = std::fs::File::create(&tmp_path)?;
        f.write_all(content.as_bytes())?;
        f.flush()?;
    }

    std::fs::rename(&tmp_path, path)?;
    Ok(())
}

/// 加载已有的 QUIC 私钥 (PEM), 或新生成一把并以 0600 原子写入。
/// 关键: 若文件已存在但读取/解析失败, 必须返回错误, 绝不静默重新生成!
pub fn load_or_generate_key(path: &std::path::Path) -> Result<rcgen::KeyPair> {
    if path.exists() {
        let pem = std::fs::read_to_string(path)
            .with_context(|| format!("QUIC: 读取私钥文件 `{}` 失败", path.display()))?;
        let key_pair = rcgen::KeyPair::from_pem(&pem)
            .with_context(|| format!("QUIC: 解析私钥文件 `{}` 失败 (PEM 损坏或格式错误)", path.display()))?;
        Ok(key_pair)
    } else {
        let key_pair = rcgen::KeyPair::generate()
            .context("QUIC: 生成 ECDSA P-256 私钥失败")?;
        let pem = key_pair.serialize_pem();
        write_key_atomic_0600(path, &pem)
            .with_context(|| format!("QUIC: 保存私钥至 `{}` 失败", path.display()))?;
        Ok(key_pair)
    }
}

// ───────────────────────── 服务端 ─────────────────────────

/// 建一个 QUIC 服务端 endpoint, 监听 UDP `listen_addr`。
/// 私钥持久化于 `key_path` (默认 "quic_key.pem"), 证书自签并通过 SPKI Pinning 认证。
pub fn server_endpoint(
    listen_addr: SocketAddr,
    window_mb: u64,
    cc: QuicCc,
    obfs: Option<&str>,
    key_path: Option<&str>,
) -> Result<quinn::Endpoint> {
    let key_path_str = key_path.unwrap_or("quic_key.pem");
    let key_pair = load_or_generate_key(std::path::Path::new(key_path_str))?;
    let pin = spki_pin(&key_pair.public_key_der());
    tracing::info!("QUIC 服务端证书指纹 (quic_pin): {pin}");

    let params = rcgen::CertificateParams::new(vec!["localhost".to_string()])
        .context("QUIC: 构造证书参数失败")?;
    let cert = params.self_signed(&key_pair)
        .context("QUIC: 自签证书失败")?;
    let cert_der = cert.der().clone();
    let key_der = rustls::pki_types::PrivatePkcs8KeyDer::from(key_pair.serialize_der());

    let mut crypto = rustls::ServerConfig::builder_with_provider(
        rustls::crypto::ring::default_provider().into(),
    )
    .with_protocol_versions(&[&rustls::version::TLS13])
    .context("QUIC: rustls 服务端 builder 失败")?
    .with_no_client_auth()
    .with_single_cert(vec![cert_der], key_der.into())
    .context("QUIC: 装配自签证书失败")?;
    crypto.alpn_protocols = vec![ALPN.to_vec()];

    let qsc = quinn::crypto::rustls::QuicServerConfig::try_from(crypto)
        .context("QUIC: rustls→quinn 服务端配置转换失败")?;
    let mut server_cfg = quinn::ServerConfig::with_crypto(Arc::new(qsc));
    server_cfg.transport_config(transport_config(window_mb, cc));
    server_cfg.max_incoming(4096);
    match obfs {
        Some(pw) => {
            tracing::info!("QUIC: Salamander 混淆已启用 (服务端)");
            // 混淆开: 自建 socket + 包 ObfsSocket + new_with_abstract_socket。
            let sock = std::net::UdpSocket::bind(listen_addr).context("QUIC: 绑定服务端 UDP socket 失败")?;
            let runtime = quinn::default_runtime().context("QUIC: 无 tokio runtime")?;
            let inner = runtime.wrap_udp_socket(sock).context("QUIC: wrap socket 失败")?;
            let obf = crate::proxy::quic_obfs::ObfsSocket::wrap(inner, pw);
            quinn::Endpoint::new_with_abstract_socket(endpoint_config(true), Some(server_cfg), obf, runtime)
                .context("QUIC: 绑定服务端 endpoint (obfs) 失败")
        }
        None => quinn::Endpoint::server(server_cfg, listen_addr).context("QUIC: 绑定服务端 endpoint 失败"),
    }
}

// ───────────────────────── 双向流适配器 ─────────────────────────

/// 把 QUIC 一条双向流的 (send, recv) 合成单个 AsyncRead+AsyncWrite, 供服务端握手阶段 (读头/体、
/// 写模板、读 tail) 当作一条 "TcpStream 等价物" 用。握手成功后 `into_halves` 拆回两半送 crypto 层。
pub struct QuicBiStream {
    send: quinn::SendStream,
    recv: quinn::RecvStream,
}

impl QuicBiStream {
    pub fn new(send: quinn::SendStream, recv: quinn::RecvStream) -> Self {
        Self { send, recv }
    }
    pub fn into_halves(self) -> (quinn::SendStream, quinn::RecvStream) {
        (self.send, self.recv)
    }
}

impl AsyncRead for QuicBiStream {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.recv).poll_read(cx, buf)
    }
}

impl AsyncWrite for QuicBiStream {
    // quinn SendStream 有同名 inherent poll_write (返 WriteError), 会抢 trait 方法, 故全限定。
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<std::io::Result<usize>> {
        AsyncWrite::poll_write(Pin::new(&mut self.send), cx, buf)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        AsyncWrite::poll_flush(Pin::new(&mut self.send), cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        AsyncWrite::poll_shutdown(Pin::new(&mut self.send), cx)
    }
}

// ───────────────────────── 辅助与验证器 ─────────────────────────

async fn resolve(host: &str, port: u16) -> Result<SocketAddr> {
    use tokio::net::lookup_host;
    lookup_host((host, port))
        .await
        .context("QUIC: DNS 解析失败")?
        .next()
        .with_context(|| format!("QUIC: {host}:{port} 无解析结果"))
}

/// 基于 SPKI 指纹的服务端证书验证器 (替换原 NoVerify)。
///
/// 1. `verify_server_cert`: 仅用 SHA-256(SPKI) 指纹匹配认证服务端 (常数时间比较, 不验证书链/域名/有效期)。
/// 2. `verify_tls13_signature` / `verify_tls12_signature`: 真正验签, 证明服务端持有该 SPKI 对应的私钥 (修复 A1)。
#[derive(Debug)]
pub struct PinnedVerifier {
    pin: String,
}

impl PinnedVerifier {
    pub fn new(pin: String) -> Self {
        Self { pin }
    }
}

impl rustls::client::danger::ServerCertVerifier for PinnedVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        let cert = webpki::EndEntityCert::try_from(end_entity)
            .map_err(|_| rustls::Error::InvalidCertificate(rustls::CertificateError::BadEncoding))?;
        let actual_pin = spki_pin(cert.subject_public_key_info().as_ref());

        use subtle::ConstantTimeEq;
        if actual_pin.len() != self.pin.len()
            || actual_pin.as_bytes().ct_eq(self.pin.as_bytes()).unwrap_u8() != 1
        {
            return Err(rustls::Error::General(format!(
                "quic_pin mismatch: expected {}, got {}",
                self.pin, actual_pin
            )));
        }
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &rustls::crypto::ring::default_provider().signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &rustls::crypto::ring::default_provider().signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// 判定 QUIC 连接失败是否由证书指纹 (SPKI pin) 或签名校验失败引起。
pub fn is_pin_mismatch_error(e: &quinn::ConnectionError) -> bool {
    match e {
        quinn::ConnectionError::TransportError(te) => {
            te.reason.contains("quic_pin mismatch")
                || te.reason.contains("ApplicationVerificationFailure")
                || te.reason.contains("BadSignature")
        }
        _ => {
            let s = e.to_string();
            s.contains("quic_pin mismatch")
                || s.contains("ApplicationVerificationFailure")
                || s.contains("BadSignature")
        }
    }
}

/// 分类 QUIC 握手失败错误: 若为证书指纹 (pin) 不符则给出明确排查指导, 其它情况保留原文案。
pub fn classify_quic_handshake_error(e: quinn::ConnectionError) -> anyhow::Error {
    if is_pin_mismatch_error(&e) {
        anyhow::anyhow!(
            "QUIC: 服务端证书指纹与 quic_pin 不符 (pin 配错, 或服务端换了私钥; 服务端运行 `mirage-rs quic-pin -c <配置>` 获取当前指纹)"
        )
    } else {
        anyhow::Error::new(e).context("QUIC: 握手失败 (对端未监听 QUIC? UDP 被封?)")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quic_cc_from_config() {
        assert_eq!(QuicCc::from_config(true, None), QuicCc::Erasure);
        assert_eq!(QuicCc::from_config(false, None), QuicCc::Stock);
        assert_eq!(QuicCc::from_config(true, Some(0)), QuicCc::Erasure); // 0 = 未启用
        assert_eq!(QuicCc::from_config(true, Some(12_500_000)), QuicCc::FixedRate(12_500_000));
        assert_eq!(QuicCc::from_config(false, Some(12_500_000)), QuicCc::FixedRate(12_500_000));
    }
    use rustls::client::danger::ServerCertVerifier;

    #[test]
    fn test_spki_pin_consistency() {
        // 1. 同一 rcgen 私钥, spki_pin(key.public_key_der()) == 客户端从自签证书经 webpki 解析的 SPKI 指纹
        let key = rcgen::KeyPair::generate().unwrap();
        let server_pin = spki_pin(&key.public_key_der());

        let params = rcgen::CertificateParams::new(vec!["localhost".to_string()]).unwrap();
        let cert = params.self_signed(&key).unwrap();

        let ee = webpki::EndEntityCert::try_from(cert.der()).unwrap();
        let client_pin = spki_pin(ee.subject_public_key_info().as_ref());

        assert_eq!(server_pin, client_pin);
        assert_eq!(server_pin.len(), 43);
    }

    #[test]
    fn test_quic_pin_format_and_config_validation() {
        // 2. 编码 43 字符 base64url; config 对缺 pin / 非法 pin 报语义问题
        let key = rcgen::KeyPair::generate().unwrap();
        let valid_pin = spki_pin(&key.public_key_der());
        assert_eq!(valid_pin.len(), 43);
        assert!(crate::config::is_valid_quic_pin(&valid_pin));

        // 长度不对
        assert!(!crate::config::is_valid_quic_pin("too_short"));
        // 含有非法字符 (+ / =)
        assert!(!crate::config::is_valid_quic_pin("+++++++++++++++++++++++++++++++++++++++++++"));

        // 测试 Config 语义检查: transport=quic 缺 pin 报错
        let cfg_no_pin = r#"{
            "inbounds": [],
            "outbounds": [{
                "type": "mirage",
                "tag": "proxy-quic",
                "server": "1.2.3.4",
                "server_port": 443,
                "password": "secret_password",
                "camouflage_host": "www.apple.com",
                "transport": "quic"
            }],
            "routing": { "default_outbound": "proxy-quic", "rules": [] }
        }"#;
        let (_, issues) = crate::config::Config::parse_with_diagnostics(cfg_no_pin).unwrap();
        assert!(issues.iter().any(|i| i.contains("quic_pin") && i.contains("必填")), "{:?}", issues);

        // transport=quic pin 格式非法报错
        let cfg_bad_pin = r#"{
            "inbounds": [],
            "outbounds": [{
                "type": "mirage",
                "tag": "proxy-quic",
                "server": "1.2.3.4",
                "server_port": 443,
                "password": "secret_password",
                "camouflage_host": "www.apple.com",
                "transport": "quic",
                "quic_pin": "invalid_pin_length"
            }],
            "routing": { "default_outbound": "proxy-quic", "rules": [] }
        }"#;
        let (_, issues) = crate::config::Config::parse_with_diagnostics(cfg_bad_pin).unwrap();
        assert!(issues.iter().any(|i| i.contains("quic_pin") && i.contains("格式非法")), "{:?}", issues);

        // transport=quic pin 正确无报错
        let cfg_good_pin = format!(r#"{{
            "inbounds": [],
            "outbounds": [{{
                "type": "mirage",
                "tag": "proxy-quic",
                "server": "1.2.3.4",
                "server_port": 443,
                "password": "secret_password",
                "camouflage_host": "www.apple.com",
                "transport": "quic",
                "quic_pin": "{valid_pin}"
            }}],
            "routing": {{ "default_outbound": "proxy-quic", "rules": [] }}
        }}"#);
        let (_, issues) = crate::config::Config::parse_with_diagnostics(&cfg_good_pin).unwrap();
        assert!(!issues.iter().any(|i| i.contains("quic_pin")), "{:?}", issues);
    }

    #[test]
    fn test_pinned_verifier_rejects_mismatched_cert() {
        // 3. PinnedVerifier 对指纹不符证书返回错误
        let key_a = rcgen::KeyPair::generate().unwrap();
        let key_b = rcgen::KeyPair::generate().unwrap();

        let pin_a = spki_pin(&key_a.public_key_der());
        let pin_b = spki_pin(&key_b.public_key_der());
        assert_ne!(pin_a, pin_b);

        let params_b = rcgen::CertificateParams::new(vec!["localhost".to_string()]).unwrap();
        let cert_b = params_b.self_signed(&key_b).unwrap();

        let verifier_a = PinnedVerifier::new(pin_a.clone());
        let server_name = rustls::pki_types::ServerName::try_from("localhost").unwrap();
        let now = rustls::pki_types::UnixTime::now();

        // 用 verifier_a 去验 cert_b，必须失败
        let res = verifier_a.verify_server_cert(cert_b.der(), &[], &server_name, &[], now);
        assert!(res.is_err(), "指纹不匹配应被拒绝");

        // 用 verifier_b 去验 cert_b，必须成功
        let verifier_b = PinnedVerifier::new(pin_b);
        let res_ok = verifier_b.verify_server_cert(cert_b.der(), &[], &server_name, &[], now);
        assert!(res_ok.is_ok(), "指纹匹配应通过");
    }

    #[test]
    fn test_signature_verification_regression() {
        // 4. 签名校验回归 (关键): 用证书 A 但以另一把私钥 B 对消息签名构造 DigitallySignedStruct,
        // verify_tls13_signature 必须返回错误; 正确私钥签名必须通过。
        let key_a = rcgen::KeyPair::generate().unwrap();
        let key_b = rcgen::KeyPair::generate().unwrap();

        let params_a = rcgen::CertificateParams::new(vec!["localhost".to_string()]).unwrap();
        let cert_a = params_a.self_signed(&key_a).unwrap();

        let message = b"tls13 handshake signature transcript test message";
        let rng = ring::rand::SystemRandom::new();

        fn make_dss(scheme: rustls::SignatureScheme, sig_bytes: &[u8]) -> rustls::DigitallySignedStruct {
            use rustls::internal::msgs::codec::{Codec, Reader};
            let mut buf = Vec::new();
            scheme.encode(&mut buf);
            (sig_bytes.len() as u16).encode(&mut buf);
            buf.extend_from_slice(sig_bytes);

            let mut reader = Reader::init(&buf);
            rustls::DigitallySignedStruct::read(&mut reader).expect("valid dss")
        }

        // 构造私钥 A 的真实签名
        let ring_key_a = ring::signature::EcdsaKeyPair::from_pkcs8(
            &ring::signature::ECDSA_P256_SHA256_ASN1_SIGNING,
            &key_a.serialize_der(),
            &rng,
        ).unwrap();
        let sig_a = ring_key_a.sign(&rng, message).unwrap();
        let dss_a = make_dss(
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            sig_a.as_ref(),
        );

        // 构造私钥 B 的签名 (冒充者签名)
        let ring_key_b = ring::signature::EcdsaKeyPair::from_pkcs8(
            &ring::signature::ECDSA_P256_SHA256_ASN1_SIGNING,
            &key_b.serialize_der(),
            &rng,
        ).unwrap();
        let sig_b = ring_key_b.sign(&rng, message).unwrap();
        let dss_b = make_dss(
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            sig_b.as_ref(),
        );

        let verifier = PinnedVerifier::new(spki_pin(&key_a.public_key_der()));

        // 正确私钥签名必须通过
        let verify_ok = verifier.verify_tls13_signature(message, cert_a.der(), &dss_a);
        assert!(verify_ok.is_ok(), "正确私钥签名必须验签成功");

        // 冒充私钥 B 的签名必须失败 (修 A1 核心安全漏洞)
        let verify_err = verifier.verify_tls13_signature(message, cert_a.der(), &dss_b);
        assert!(verify_err.is_err(), "错误私钥签名必须验签失败 (拒绝无私钥 MITM)");
    }

    #[tokio::test]
    async fn test_quic_e2e_correct_and_wrong_pin() {
        // 5. 端到端: 进程内起 QUIC 服务端 + 客户端, 正确 pin 能通信, 错误 pin 握手失败。
        let temp_dir = std::env::temp_dir().join(format!("mirage_quic_test_{}", fastrand::u64(..)));
        let _ = std::fs::create_dir_all(&temp_dir);
        let key_path = temp_dir.join("quic_key.pem");
        let key_path_str = key_path.to_str().unwrap();

        let listen_addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let ep_server = server_endpoint(listen_addr, 2, QuicCc::Stock, None, Some(key_path_str)).unwrap();
        let server_addr = ep_server.local_addr().unwrap();

        // 读回服务端的正确 pin
        let server_key = load_or_generate_key(&key_path).unwrap();
        let correct_pin = spki_pin(&server_key.public_key_der());

        // 服务端后台 echo 任务
        let srv_handle = tokio::spawn(async move {
            while let Some(incoming) = ep_server.accept().await {
                tokio::spawn(async move {
                    if let Ok(conn) = incoming.await {
                        if let Ok((mut send, mut recv)) = conn.accept_bi().await {
                            let mut buf = [0u8; 11];
                            if tokio::io::AsyncReadExt::read_exact(&mut recv, &mut buf).await.is_ok() {
                                let _ = tokio::io::AsyncWriteExt::write_all(&mut send, b"pong-quic").await;
                                let _ = tokio::io::AsyncWriteExt::shutdown(&mut send).await;
                                tokio::time::sleep(std::time::Duration::from_millis(500)).await;
                            }
                        }
                    }
                });
            }
        });

        // 1) 正确 pin 客户端: 能握手并读写数据
        let client_cfg = client_config(2, QuicCc::Stock, &correct_pin).unwrap();
        let mut ep_client = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
        ep_client.set_default_client_config(client_cfg);

        let connecting = ep_client.connect(server_addr, "localhost").unwrap();
        let conn = connecting.await.expect("正确 pin 握手应成功");
        let (mut send, mut recv) = conn.open_bi().await.unwrap();
        tokio::io::AsyncWriteExt::write_all(&mut send, b"ping-quic11").await.unwrap();
        tokio::io::AsyncWriteExt::shutdown(&mut send).await.unwrap();
        let mut reply = [0u8; 9];
        tokio::io::AsyncReadExt::read_exact(&mut recv, &mut reply).await.unwrap();
        assert_eq!(&reply, b"pong-quic");

        // 2) 错误 pin 客户端: 握手失败
        let wrong_key = rcgen::KeyPair::generate().unwrap();
        let wrong_pin = spki_pin(&wrong_key.public_key_der());
        let bad_client_cfg = client_config(2, QuicCc::Stock, &wrong_pin).unwrap();
        let mut ep_bad = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
        ep_bad.set_default_client_config(bad_client_cfg);

        let bad_connecting = ep_bad.connect(server_addr, "localhost").unwrap();
        let bad_conn_res = bad_connecting.await;
        assert!(bad_conn_res.is_err(), "错误 pin 握手必须失败 (fail-closed)");
        let err = bad_conn_res.unwrap_err();
        assert!(is_pin_mismatch_error(&err), "错误 pin 必须被识别为 pin mismatch");
        let classified = classify_quic_handshake_error(err);
        assert!(classified.to_string().contains("服务端证书指纹与 quic_pin 不符"));

        srv_handle.abort();
        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_quic_key_persistence_and_file_mode_and_corruption() {
        // 6. 持久化: 两次加载同一路径指纹不变; 文件权限 0600; 损坏的私钥文件 → 返回错误而非重新生成。
        let temp_dir = std::env::temp_dir().join(format!("mirage_key_test_{}", fastrand::u64(..)));
        std::fs::create_dir_all(&temp_dir).unwrap();
        let key_path = temp_dir.join("quic_key.pem");

        // 第一次生成
        let key1 = load_or_generate_key(&key_path).unwrap();
        let pin1 = spki_pin(&key1.public_key_der());

        // 检查权限为 0600
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let meta = std::fs::metadata(&key_path).unwrap();
            let mode = meta.permissions().mode() & 0o777;
            assert_eq!(mode, 0o600, "私钥文件必须是 0600 权限");
        }

        // 第二次加载同一路径: 指纹不变
        let key2 = load_or_generate_key(&key_path).unwrap();
        let pin2 = spki_pin(&key2.public_key_der());
        assert_eq!(pin1, pin2, "两次加载同一私钥指纹必须一致");

        // 损坏测试: 篡改内容为非法垃圾数据
        std::fs::write(&key_path, b"CORRUPTED_GARBAGE_DATA_NOT_A_PEM").unwrap();
        let load_res = load_or_generate_key(&key_path);
        assert!(load_res.is_err(), "损坏的私钥文件必须返回错误 (绝不静默重新生成)");

        // 确认文件没有被静默改写
        let read_back = std::fs::read(&key_path).unwrap();
        assert_eq!(read_back, b"CORRUPTED_GARBAGE_DATA_NOT_A_PEM");

        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_quic_error_classification_unit() {
        let err_pin = quinn::ConnectionError::TransportError(quinn_proto::TransportError {
            code: quinn_proto::TransportErrorCode::crypto(42),
            frame: None,
            reason: "quic_pin mismatch: expected abc, got def".to_string(),
        });
        assert!(is_pin_mismatch_error(&err_pin));
        let classified_pin = classify_quic_handshake_error(err_pin);
        assert!(classified_pin.to_string().contains("服务端证书指纹与 quic_pin 不符"));

        let err_app_fail = quinn::ConnectionError::TransportError(quinn_proto::TransportError {
            code: quinn_proto::TransportErrorCode::crypto(46),
            frame: None,
            reason: "ApplicationVerificationFailure".to_string(),
        });
        assert!(is_pin_mismatch_error(&err_app_fail));

        let err_timeout = quinn::ConnectionError::TimedOut;
        assert!(!is_pin_mismatch_error(&err_timeout));
        let classified_timeout = classify_quic_handshake_error(err_timeout);
        assert!(classified_timeout.to_string().contains("QUIC: 握手失败 (对端未监听 QUIC? UDP 被封?)"));
    }

    #[tokio::test]
    async fn test_quic_mux_singleflight_shares_connection_and_backoff() {
        let temp_dir = std::env::temp_dir().join(format!("mirage_mux_sf_{}", fastrand::u64(..)));
        let _ = std::fs::create_dir_all(&temp_dir);
        let key_path = temp_dir.join("quic_key.pem");
        let key_path_str = key_path.to_str().unwrap();

        let listen_addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let ep_server = server_endpoint(listen_addr, 2, QuicCc::Stock, None, Some(key_path_str)).unwrap();
        let server_addr = ep_server.local_addr().unwrap();
        let server_key = load_or_generate_key(&key_path).unwrap();
        let correct_pin = spki_pin(&server_key.public_key_der());

        // 统计服务端实际接受的 QUIC 连接数: 并发 open_stream 必须只产生 1 条连接
        let accepted_conns = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let accepted_conns_srv = accepted_conns.clone();
        let srv_handle = tokio::spawn(async move {
            while let Some(incoming) = ep_server.accept().await {
                let c_cnt = accepted_conns_srv.clone();
                tokio::spawn(async move {
                    if let Ok(conn) = incoming.await {
                        c_cnt.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                        while let Ok((mut send, _recv)) = conn.accept_bi().await {
                            let _ = tokio::io::AsyncWriteExt::write_all(&mut send, b"ok").await;
                            let _ = tokio::io::AsyncWriteExt::shutdown(&mut send).await;
                        }
                    }
                });
            }
        });

        let mux = QuicMux::new(
            "127.0.0.1",
            server_addr.port(),
            "localhost",
            false,
            false,
            None,
            2,
            QuicCc::Stock,
            Some(correct_pin.clone()),
        );

        // 8 个并发调用同时触发冷启动建连
        let mut tasks = Vec::new();
        for _ in 0..8 {
            let m = mux.clone();
            tasks.push(tokio::spawn(async move {
                let (mut send, mut recv) = m.open_stream().await.expect("并发 open_stream 应成功");
                let _ = tokio::io::AsyncWriteExt::shutdown(&mut send).await;
                let mut out = [0u8; 2];
                tokio::io::AsyncReadExt::read_exact(&mut recv, &mut out).await.unwrap();
                out
            }));
        }
        for t in tasks {
            assert_eq!(&t.await.unwrap(), b"ok");
        }
        assert_eq!(
            accepted_conns.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "并发 open_stream 必须通过单飞共享同一条 QUIC 连接"
        );

        // 验证 Leader 取消接力: 模拟 Leader 在拨号期间被取消 (DialOutcome::Cancelled), 等待中的 Follower 应自动接力完成建连
        let cancel_mux = QuicMux::new(
            "127.0.0.1",
            server_addr.port(),
            "localhost",
            false,
            false,
            None,
            2,
            QuicCc::Stock,
            Some(correct_pin),
        );
        let (tx, rx) = tokio::sync::watch::channel(None);
        cancel_mux.inner.lock().unwrap().dialing = Some(rx);
        let m_wait = cancel_mux.clone();
        let waiter = tokio::spawn(async move {
            let (mut send, mut recv) = m_wait.open_stream().await.expect("Leader 取消后 Follower 应自动接力建连");
            let _ = tokio::io::AsyncWriteExt::shutdown(&mut send).await;
            let mut out = [0u8; 2];
            tokio::io::AsyncReadExt::read_exact(&mut recv, &mut out).await.unwrap();
            out
        });
        for _ in 0..100 {
            if tx.receiver_count() >= 2 {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
        tokio::task::yield_now().await;
        {
            let guard = DialLeaderGuard {
                mux: &cancel_mux,
                tx: Some(tx),
            };
            drop(guard); // 触发 DialOutcome::Cancelled
        }
        assert_eq!(&waiter.await.unwrap(), b"ok");

        // 验证失败退避: 错误 pin 建连失败后, 退避窗口内的紧随调用立即失败且复用错误消息
        let wrong_pin = spki_pin(&rcgen::KeyPair::generate().unwrap().public_key_der());
        let bad_mux = QuicMux::new(
            "127.0.0.1",
            server_addr.port(),
            "localhost",
            false,
            false,
            None,
            2,
            QuicCc::Stock,
            Some(wrong_pin),
        );
        let err1 = bad_mux.open_stream().await.unwrap_err();
        let t0 = std::time::Instant::now();
        let err2 = bad_mux.open_stream().await.unwrap_err();
        assert!(t0.elapsed() < DIAL_FAIL_BACKOFF, "退避窗口内应立即快速失败");
        assert!(err1.to_string().contains("服务端证书指纹与 quic_pin 不符"));
        assert_eq!(err1.to_string(), err2.to_string());

        srv_handle.abort();
        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn rejection_predicate_and_backoff_schedule() {
        use std::time::Duration;
        let app = |code: u32| {
            quinn::ConnectionError::ApplicationClosed(quinn::ApplicationClose {
                error_code: quinn::VarInt::from_u32(code),
                reason: Default::default(),
            })
        };
        assert!(is_server_rejection(&app(0), Duration::from_secs(1)), "刚建连就被 close(0) 算拒绝");
        assert!(!is_server_rejection(&app(0), Duration::from_secs(11)), "长会话后被关不算拒绝");
        assert!(!is_server_rejection(&app(7), Duration::from_secs(1)), "非 0 码不算拒绝");
        assert!(!is_server_rejection(&quinn::ConnectionError::TimedOut, Duration::from_secs(1)), "空闲超时不算拒绝");

        let secs = |n| reject_backoff(n).as_secs();
        assert_eq!((secs(1), secs(2), secs(3), secs(4)), (1, 2, 4, 8));
        assert_eq!((secs(6), secs(7), secs(50)), (30, 30, 30), "封顶 30s");
    }

    #[tokio::test]
    async fn test_quic_mux_backs_off_after_server_rejects_connection() {
        let temp_dir = std::env::temp_dir().join(format!("mirage_mux_rej_{}", fastrand::u64(..)));
        let _ = std::fs::create_dir_all(&temp_dir);
        let key_path = temp_dir.join("quic_key.pem");
        let key_path_str = key_path.to_str().unwrap();

        let listen_addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let ep_server = server_endpoint(listen_addr, 2, QuicCc::Stock, None, Some(key_path_str)).unwrap();
        let server_addr = ep_server.local_addr().unwrap();
        let pin = spki_pin(&load_or_generate_key(&key_path).unwrap().public_key_der());

        // 假服务端: 与真服务端认证失败时一致 —— 收到首条流就用通用码 0 关整条连接。
        let accepted = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let accepted_srv = accepted.clone();
        let srv_handle = tokio::spawn(async move {
            while let Some(incoming) = ep_server.accept().await {
                let cnt = accepted_srv.clone();
                tokio::spawn(async move {
                    if let Ok(conn) = incoming.await {
                        cnt.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                        if conn.accept_bi().await.is_ok() {
                            conn.close(quinn::VarInt::from_u32(0), b"");
                        }
                    }
                });
            }
        });

        let mux = QuicMux::new("127.0.0.1", server_addr.port(), "localhost", false, false, None, 2, QuicCc::Stock, Some(pin));

        let (mut send, mut recv) = mux.open_stream().await.expect("首次建连应成功");
        tokio::io::AsyncWriteExt::write_all(&mut send, b"x").await.unwrap(); // 让服务端看到这条流
        let mut b = [0u8; 1];
        let r = tokio::time::timeout(std::time::Duration::from_secs(2), tokio::io::AsyncReadExt::read(&mut recv, &mut b))
            .await
            .expect("服务端应在 2s 内关闭连接");
        assert!(r.is_err(), "连接被服务端关闭后读取应报错");

        // 冷却窗口内: 立即快速失败, 不再重做 QUIC 握手 (服务端只见过 1 条连接)。
        let t0 = std::time::Instant::now();
        let err = mux.open_stream().await.unwrap_err();
        assert!(t0.elapsed() < std::time::Duration::from_millis(300), "冷却内应立即失败, 实际 {:?}", t0.elapsed());
        assert!(err.to_string().contains("服务端拒绝"), "错误应提示服务端拒绝: {err}");
        assert_eq!(accepted.load(std::sync::atomic::Ordering::SeqCst), 1, "冷却期内不得重新拨号");

        // 冷却 (第 1 次 = 1s) 结束后可以重新建连。
        tokio::time::sleep(std::time::Duration::from_millis(1100)).await;
        let _ = mux.open_stream().await.expect("冷却结束后应能重新建连");
        // 服务端的 accept 计数与客户端握手完成之间有先后差, 轮询等它追上 (上限 1s)。
        for _ in 0..100 {
            if accepted.load(std::sync::atomic::Ordering::SeqCst) >= 2 {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        assert_eq!(accepted.load(std::sync::atomic::Ordering::SeqCst), 2);

        srv_handle.abort();
        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    /// 客户端 QUIC 出站口令错误时，第一次请求失败（如首个流读报错 / 连接被服务端 close(0)）
    /// 必须立即结算拒绝并进入退避冷却期，而无需等到第二次调用 open_stream。
    #[tokio::test]
    async fn test_quic_mux_first_failure_settles_rejection() {
        let temp_dir = std::env::temp_dir().join(format!("mirage_mux_first_rej_{}", fastrand::u64(..)));
        let _ = std::fs::create_dir_all(&temp_dir);
        let key_path = temp_dir.join("quic_key.pem");
        let key_path_str = key_path.to_str().unwrap();

        let listen_addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let ep_server = server_endpoint(listen_addr, 2, QuicCc::Stock, None, Some(key_path_str)).unwrap();
        let server_addr = ep_server.local_addr().unwrap();
        let pin = spki_pin(&load_or_generate_key(&key_path).unwrap().public_key_der());

        let accepted = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let accepted_srv = accepted.clone();
        let srv_handle = tokio::spawn(async move {
            while let Some(incoming) = ep_server.accept().await {
                let cnt = accepted_srv.clone();
                tokio::spawn(async move {
                    if let Ok(conn) = incoming.await {
                        cnt.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                        if conn.accept_bi().await.is_ok() {
                            conn.close(quinn::VarInt::from_u32(0), b"");
                        }
                    }
                });
            }
        });

        let mux = QuicMux::new("127.0.0.1", server_addr.port(), "localhost", false, false, None, 2, QuicCc::Stock, Some(pin));

        // 第一次发起请求: open_stream 建立连接并开出流
        let (mut send, mut recv) = mux.open_stream().await.expect("首条流建连应成功");
        assert_eq!(mux.reject_streak(), 0, "建连成功时 streak 仍为 0");

        // 发送首包触发展示: 服务端认证失败 close(0)
        tokio::io::AsyncWriteExt::write_all(&mut send, b"dummy_bad_token").await.unwrap();
        let mut b = [0u8; 1];
        let r = tokio::time::timeout(std::time::Duration::from_secs(2), tokio::io::AsyncReadExt::read(&mut recv, &mut b))
            .await
            .expect("服务端应在 2s 内关闭连接");
        assert!(r.is_err(), "服务端关闭后读流报错");

        // 模拟 handler 完成后调用 check_conn_closed (或后台 watcher 结算)
        mux.check_conn_closed();

        // 核心验证: 第一次失败即完成拒绝结算, streak 升为 1 且处于冷却中
        assert_eq!(mux.reject_streak(), 1, "第一次失败必须已立即完成结算，streak = 1");
        assert!(mux.is_in_rejection_cooldown(), "第一次失败后必须已处于冷却中");

        // 后续请求在冷却期内直接返回服务端拒绝的明确错误提示
        let err = mux.open_stream().await.unwrap_err();
        assert!(err.to_string().contains("服务端拒绝了本客户端的连接"), "错误提示必须明确指示拒绝: {err}");
        assert_eq!(mux.reject_streak(), 1, "同一连接不得重复累加拒绝计数");
        assert_eq!(accepted.load(std::sync::atomic::Ordering::SeqCst), 1, "冷却期间不得重新发起拨号建连");

        srv_handle.abort();
        let _ = std::fs::remove_dir_all(&temp_dir);
    }
}
