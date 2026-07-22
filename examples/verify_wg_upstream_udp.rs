//! 真机验证: **服务端 UDP 中继经 WireGuard 上游出去**。
//!
//! 拓扑 (全在本机进程内, 只有 WG 那一跳是真的):
//!
//! ```text
//!   本测试(客户端角色) ──Mirage 隧道──▶ Mirage 服务端 ──WG 隧道──▶ 真实 WG peer ──▶ DNS
//! ```
//!
//! 为什么值得单独验: 服务端的 UDP 中继此前**硬绑本机 `UdpSocket`**, 配了上游也照样从本机
//! IP 出去 —— 正因如此它一直被 `udp: block` 挡着。现在接到 WG 隧道后 UDP 与 TCP 同出口,
//! 默认才敢放开。这条链路上任何一环接错都会退化成"从本机出去"而**不会报错**, 单测看不出来。
//!
//! 用法同 verify_wg_real_peer (共用同一组环境变量), 另可用 WG_UDP_TARGET 指定 DNS 靶子。

use anyhow::{bail, Context, Result};
use std::time::Duration;

fn env(k: &str) -> Result<String> {
    std::env::var(k).with_context(|| format!("缺少环境变量 {k}"))
}

fn dns_query(id: u16) -> Vec<u8> {
    let mut q = Vec::new();
    q.extend_from_slice(&id.to_be_bytes());
    q.extend_from_slice(&[0x01, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0]);
    for label in ["example", "com"] {
        q.push(label.len() as u8);
        q.extend_from_slice(label.as_bytes());
    }
    q.extend_from_slice(&[0, 0x00, 0x01, 0x00, 0x01]);
    q
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt().with_env_filter("warn").init();

    let key_file = env("WG_PRIVATE_KEY_FILE")?;
    let priv_b64 = std::fs::read_to_string(&key_file)?.trim().to_string();
    let target: std::net::SocketAddr = std::env::var("WG_UDP_TARGET")
        .unwrap_or_else(|_| "10.10.0.4:53".into())
        .parse()?;

    // 直接构造上游出口 (等价于配置里的 "upstream": {"type":"wireguard", ...})
    let wg = mirage_rs::proxy::wg::WgConfig {
        private_key: mirage_rs::proxy::wg::decode_wg_key(&priv_b64, "private_key")?,
        peer_public_key: mirage_rs::proxy::wg::decode_wg_key(
            &env("WG_PEER_PUBLIC_KEY")?,
            "peer_public_key",
        )?,
        preshared_key: None,
        endpoint: env("WG_ENDPOINT")?,
        address: env("WG_ADDRESS")?.parse()?,
        mtu: 1420,
        persistent_keepalive: Some(25),
        dns: None,
    };
    let up = mirage_rs::proxy::upstream::WgUpstream::new(wg, mirage_rs::config::UdpPolicy::Tunnel);

    eprintln!("经 WG 上游隧道发 DNS 查询 → {target}");
    let tunnel = up.tunnel().await.context("建立 WG 上游隧道失败")?;
    let sock = mirage_rs::proxy::wg::socket::WgUdpSocket::bind(tunnel)?;

    let id = 0xbeefu16;
    sock.send_to(&dns_query(id), target)?;

    let mut buf = vec![0u8; 2048];
    let (n, from) = tokio::time::timeout(Duration::from_secs(15), sock.recv_from(&mut buf))
        .await
        .context("15s 内没收到响应 —— UDP 没能经 WG 上游往返")??;

    let ok = n >= 12
        && buf[0..2] == id.to_be_bytes()
        && (buf[2] & 0x80) != 0
        && u16::from_be_bytes([buf[6], buf[7]]) > 0;
    if !ok {
        bail!("响应不合法 ({n} 字节)");
    }
    eprintln!("✓ 服务端 UDP 中继经 WG 上游往返成功 (来自 {from}, {n} 字节, 含回答记录)");
    eprintln!("  ⇒ UDP 与 TCP 同出口, 不再需要 udp=block 兜底");
    Ok(())
}
