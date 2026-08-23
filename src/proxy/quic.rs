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

/// P0 占位 ALPN。P1 换成目标浏览器的真 ALPN (h3) 以配合指纹仿真。
const ALPN: &[u8] = b"mirage-p0";

// ───────────────────────── 客户端 ─────────────────────────

/// 建一个 QUIC 客户端 endpoint (绑临时本地 UDP 口) + 拨号 server:port, 开一条双向流。
/// 返回 (send, recv 带 endpoint)。read 半程 `OwnedRecv` 持有 endpoint, 让它活到隧道结束
/// (endpoint 一旦 drop 会关闭其上所有连接; 挂在 read 半程上生命周期与隧道对齐, 不泄漏)。
pub async fn dial(host: &str, port: u16) -> Result<(quinn::SendStream, OwnedRecv)> {
    let addr = resolve(host, port).await?;
    // 绑定与目标同族的通配地址 (v6 目标绑 [::], v4 目标绑 0.0.0.0)。
    let bind: SocketAddr = if addr.is_ipv6() { "[::]:0".parse()? } else { "0.0.0.0:0".parse()? };
    let mut endpoint = quinn::Endpoint::client(bind).context("QUIC: 建客户端 endpoint 失败")?;
    endpoint.set_default_client_config(client_config()?);

    // server_name 用配置的 host (SNI)。P0 证书不校验, 值不影响握手成败。
    let conn = endpoint
        .connect(addr, host)
        .context("QUIC: connect 配置无效")?
        .await
        .context("QUIC: 握手失败 (对端未监听 QUIC? UDP 被封?)")?;
    let (send, recv) = conn.open_bi().await.context("QUIC: open_bi 失败")?;
    Ok((send, OwnedRecv { recv, _endpoint: endpoint }))
}

/// QUIC 客户端读半程 + 持有 endpoint (生命周期锚)。仅委托 AsyncRead。
pub struct OwnedRecv {
    recv: quinn::RecvStream,
    _endpoint: quinn::Endpoint,
}

impl AsyncRead for OwnedRecv {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.recv).poll_read(cx, buf)
    }
}

fn client_config() -> Result<quinn::ClientConfig> {
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
    Ok(quinn::ClientConfig::new(Arc::new(qcc)))
}

// ───────────────────────── 服务端 ─────────────────────────

/// 建一个 QUIC 服务端 endpoint, 监听 UDP `listen_addr`。证书自签 (P0, 认证在内层 Mirage)。
pub fn server_endpoint(listen_addr: SocketAddr) -> Result<quinn::Endpoint> {
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
    let server_cfg = quinn::ServerConfig::with_crypto(Arc::new(qsc));
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
