//! QUIC 传输 (P0 实验, `--features quic`)。见 docs/quic-transport-design.md。
//!
//! **Model Y (P0 抄近路)**: QUIC 只做底层字节管道, 上面照跑 Mirage 现有 fake-TLS 握手 + AEAD。
//! 一条 QUIC 连接开一条双向流 (open_bi/accept_bi) 承载一条隧道, 语义等价一条 TCP。
//!
//! ⚠️ P0 **不隐蔽**: quinn 默认 QUIC 指纹裸奔, 且 TLS 证书自签+客户端不校验 (认证靠内层 Mirage
//! 协议, 与 TCP 路径一致)。勿用于敌对网络。指纹仿真是 P1 的活 (path A: patch rustls)。

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
fn make_client_endpoint(server_addr: SocketAddr, low_src_port: bool, pre_packet: bool) -> Result<quinn::Endpoint> {
    let sock = bind_client_socket(server_addr.is_ipv6(), server_addr.port(), low_src_port)
        .context("QUIC: 绑客户端 UDP socket 失败")?;
    if pre_packet {
        // 随机长度 (8~64B) 随机内容, 在同一 4-tuple 上先发, 让 GFW 对该四元组的 QUIC 追踪失准。
        // 到达我们的 QUIC 服务端会被当无效包丢弃, 无副作用。
        let n = 8 + fastrand::usize(0..=56);
        let junk: Vec<u8> = (0..n).map(|_| fastrand::u8(..)).collect();
        let _ = sock.send_to(&junk, server_addr);
        tracing::debug!("QUIC: 发 {}B pre-packet 到 {} (GFW 四元组 desync)", n, server_addr);
    }
    let runtime = quinn::default_runtime().context("QUIC: 无 tokio runtime")?;
    quinn::Endpoint::new(quinn::EndpointConfig::default(), None, sock, runtime)
        .context("QUIC: 建客户端 endpoint 失败")
}

/// QUIC TransportConfig。`window_mb`/`erasure` 来自 config (见 tuning), 环境变量 `MIRAGE_QUIC_WND`
/// (MB) / `MIRAGE_QUIC_CC=off` 优先覆盖 (供真机 A/B 调参)。
fn transport_config(window_mb: u64, erasure: bool) -> Arc<quinn::TransportConfig> {
    let mut tc = quinn::TransportConfig::default();

    // 流控窗口: quinn 默认偏小 (~1MB 级), 高 BDP 长肥路径上单流被窗口卡死 (实测 JP↔US 111ms 仅
    // ~9MB/s, 而 TCP 自动调窗到 48MB/s)。默认 2MB —— ⚠️ 重排序线路 (部分 CN2) 大窗口会因乱序 gap 超
    // quinn MAX_CHUNKS(1024) 被关连接 (真机实证 4MB 仍切、2MB 稳, 见 quic_cc.rs GAP_SAFE_CHUNKS +
    // docs §5.5); 干净长肥路径可调大 (16-64) 榨单流吞吐。过大 (128+) 在并发+丢包下还会过冲。
    let wnd_mb: u64 = std::env::var("MIRAGE_QUIC_WND").ok().and_then(|v| v.parse().ok()).unwrap_or(window_mb);
    let stream_wnd = wnd_mb.max(1) * 1024 * 1024;
    let conn_wnd = stream_wnd.saturating_mul(4);
    tc.stream_receive_window(quinn::VarInt::from_u64(stream_wnd).unwrap_or(quinn::VarInt::MAX));
    tc.receive_window(quinn::VarInt::from_u64(conn_wnd).unwrap_or(quinn::VarInt::MAX));
    tc.send_window(conn_wnd);
    // mux 架构: 一个连接承载多条流 (每条=一条隧道), 服务端须允许客户端开足够多的并发双向流
    // (quinn 默认 ~100, 高并发代理不够)。这是对端向本端advertise的上限, 故 client+server 都设。
    tc.max_concurrent_bidi_streams(quinn::VarInt::from_u32(2048));

    let erasure = match std::env::var("MIRAGE_QUIC_CC").ok().as_deref() {
        Some("off" | "bbr" | "default" | "stock") => false,
        Some("erasure" | "on") => true,
        _ => erasure,
    };
    if erasure {
        tc.congestion_controller_factory(Arc::new(crate::proxy::quic_cc::ErasureConfig::default()));
        tracing::info!("QUIC: erasure-aware CC 启用 (窗口 {}MB)", wnd_mb);
    } else {
        tracing::info!("QUIC: CC = quinn 原生 (erasure 关, 窗口 {}MB)", wnd_mb);
    }
    Arc::new(tc)
}

// ───────────────────────── 客户端 ─────────────────────────

/// QUIC mux (P4/mux 架构): **一个共享 QUIC 连接承载多条 bi-stream** (每条 = 一条 Mirage 隧道),
/// 取代 P0 的"一隧道一连接"。收益: 服务端每客户端只见一个连接 = 一个 CC = 天然共享瓶颈, 连接级
/// receive_window 封顶聚合在途量 (治多连接过冲/128MB 崩溃); 省 per-conn crypto/CC/UDP-flow 开销。
///
/// endpoint + 当前连接存在内部, 跨 open_stream 复用; 连接死了 (close_reason) 下次 open_stream 重拨。
pub struct QuicMux {
    inner: tokio::sync::Mutex<MuxInner>,
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
    window_mb: u64,
    erasure: bool,
}

#[derive(Default)]
struct MuxInner {
    endpoint: Option<quinn::Endpoint>,
    conn: Option<quinn::Connection>,
}

impl QuicMux {
    #[allow(clippy::too_many_arguments)]
    pub fn new(host: &str, port: u16, sni: &str, low_src_port: bool, pre_packet: bool, window_mb: u64, erasure: bool) -> Arc<Self> {
        Arc::new(Self {
            inner: tokio::sync::Mutex::new(MuxInner::default()),
            host: host.to_string(),
            port,
            sni: sni.to_string(),
            low_src_port,
            pre_packet,
            window_mb,
            erasure,
        })
    }

    /// 在共享连接上开一条 bi-stream。首次/断线时惰性建 endpoint + 拨号。
    pub async fn open_stream(&self) -> Result<(quinn::SendStream, quinn::RecvStream)> {
        let conn = {
            let mut g = self.inner.lock().await;
            // 惰性建 endpoint。默认绑通配临时口; low_src_port 时尝试绑 ≤ 目标端口的源口。
            if g.endpoint.is_none() {
                let addr = resolve(&self.host, self.port).await?;
                let mut ep = make_client_endpoint(addr, self.low_src_port, self.pre_packet)?;
                ep.set_default_client_config(client_config(self.window_mb, self.erasure)?);
                g.endpoint = Some(ep);
            }
            // 连接不存在或已关 → 重拨。
            let need_dial = match &g.conn {
                None => true,
                Some(c) => c.close_reason().is_some(),
            };
            if need_dial {
                let addr = resolve(&self.host, self.port).await?;
                let ep = g.endpoint.as_ref().unwrap();
                let conn = ep
                    .connect(addr, &self.sni) // SNI = 良性 camouflage_host, 非 server 真身
                    .context("QUIC: connect 配置无效")?
                    .await
                    .context("QUIC: 握手失败 (对端未监听 QUIC? UDP 被封?)")?;
                g.conn = Some(conn);
            }
            g.conn.as_ref().unwrap().clone() // Connection 是 Arc, clone 廉价
        }; // 释放锁再 await open_bi (可能因对端 MAX_STREAMS 挂起, 不能占锁)

        match conn.open_bi().await {
            Ok(s) => Ok(s),
            Err(e) => {
                // 连接死了 → 清掉, 下次 open_stream 重拨。
                let mut g = self.inner.lock().await;
                if g.conn.as_ref().is_some_and(|c| c.stable_id() == conn.stable_id()) {
                    g.conn = None;
                }
                Err(anyhow::anyhow!("QUIC: open_bi 失败 (连接已断): {e}"))
            }
        }
    }
}

fn client_config(window_mb: u64, erasure: bool) -> Result<quinn::ClientConfig> {
    let mut crypto = rustls::ClientConfig::builder_with_provider(
        rustls::crypto::ring::default_provider().into(),
    )
    .with_protocol_versions(&[&rustls::version::TLS13])
    .context("QUIC: rustls 客户端 builder 失败")?
    .dangerous()
    .with_custom_certificate_verifier(Arc::new(NoVerify))
    .with_no_client_auth();
    crypto.alpn_protocols = vec![ALPN.to_vec()];
    let qcc = quinn::crypto::rustls::QuicClientConfig::try_from(crypto)
        .context("QUIC: rustls→quinn 客户端配置转换失败")?;
    let mut cfg = quinn::ClientConfig::new(Arc::new(qcc));
    cfg.transport_config(transport_config(window_mb, erasure));
    Ok(cfg)
}

// ───────────────────────── 服务端 ─────────────────────────

/// 建一个 QUIC 服务端 endpoint, 监听 UDP `listen_addr`。证书自签 (P0, 认证在内层 Mirage)。
pub fn server_endpoint(listen_addr: SocketAddr, window_mb: u64, erasure: bool) -> Result<quinn::Endpoint> {
    let rcgen::CertifiedKey { cert, key_pair } =
        rcgen::generate_simple_self_signed(vec!["localhost".to_string()])
            .context("QUIC: 生成自签证书失败")?;
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
    server_cfg.transport_config(transport_config(window_mb, erasure));
    quinn::Endpoint::server(server_cfg, listen_addr).context("QUIC: 绑定服务端 endpoint 失败")
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

// ───────────────────────── 辅助 ─────────────────────────

async fn resolve(host: &str, port: u16) -> Result<SocketAddr> {
    use tokio::net::lookup_host;
    lookup_host((host, port))
        .await
        .context("QUIC: DNS 解析失败")?
        .next()
        .with_context(|| format!("QUIC: {host}:{port} 无解析结果"))
}

/// P0 客户端证书验证器: 一律通过。安全性由内层 Mirage 协议 (口令派生 token + AEAD) 保证,
/// 与 TCP fake-TLS 路径同源——QUIC 外层的 TLS 证书在此模型下只是把管道立起来。
#[derive(Debug)]
struct NoVerify;

impl rustls::client::danger::ServerCertVerifier for NoVerify {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }
    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }
    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}
