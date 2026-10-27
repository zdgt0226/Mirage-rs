//! WireGuard 出站/上游支持 (feat/wireguard, 开发中)。
//!
//! WireGuard 与 Shadowsocks 不是一个层级: SS 是 L4 TCP 流, 直接套在字节流上; WG 是 **L3 IP 包**
//! 协议 (Noise IK 握手 + ChaCha20-Poly1305 + 密钥轮换), 隧道里跑的是 IP 包而非 TCP 流。
//!
//! 因此把"某条被代理的 TCP/UDP 连接"送进 WG, 绕不开一个**用户态 TCP/IP 栈**做转换。整体架构:
//!
//! ```text
//!   被代理的 TCP/UDP 连接
//!         │  (smoltcp socket: 应用字节 ↔ IP 包)
//!   ┌─────▼─────┐
//!   │  smoltcp   │  用户态 IP 栈
//!   └─────┬─────┘
//!         │  IP 包
//!   ┌─────▼─────┐
//!   │ WgDevice   │  smoltcp::phy::Device 桥接层
//!   └─────┬─────┘
//!         │  encapsulate / decapsulate
//!   ┌─────▼─────┐
//!   │ boringtun  │  Tunn: Noise 握手 + 加解密
//!   │   Tunn     │
//!   └─────┬─────┘
//!         │  加密 UDP 数据报
//!   ┌─────▼─────┐
//!   │ UdpSocket  │  → WG peer 的 endpoint
//!   └───────────┘
//! ```
//!
//! 实现分阶段 (见 feat/wireguard 分支):
//!   - [x] 阶段1: 配置 + 密钥解码 + Tunn 构造 + 能产出合法 WG 握手包 (本文件 + 测试)
//!   - [x] 阶段2a: WgDevice (smoltcp Device 桥接, 见 device.rs)
//!   - [ ] 阶段2b: 异步 pump (udp↔tunn↔smoltcp + Tunn 定时器)
//!   - [ ] 阶段3: connect_tcp / udp 通过 WG 隧道; 接入 outbound + mirage_server.upstream
//!   - [ ] 阶段4: 真机 e2e 对着真实 WG peer 验证

pub mod device;
pub mod dns;
pub mod socket;
pub mod tunnel;

use anyhow::{anyhow, bail, Result};
use boringtun::x25519::{PublicKey, StaticSecret};

/// WireGuard peer 配置。字段命名对齐标准 wg-quick / sing-box wireguard 出站, 便于用户搬配置。
///
/// 密钥都是标准 WireGuard 的 **base64 编码的 32 字节 x25519 密钥** (与 `wg genkey` / `wg pubkey`
/// 输出一致), **不是**任意密码 —— 填错会连不上。
#[derive(Debug, Clone)]
pub struct WgConfig {
    /// 本端私钥 (`wg genkey` 生成的 base64)。
    pub private_key: [u8; 32],
    /// 对端 (WG 服务器) 公钥 (base64)。
    pub peer_public_key: [u8; 32],
    /// 可选预共享密钥 (`wg genpsk`), 增强抗量子。
    pub preshared_key: Option<[u8; 32]>,
    /// 对端 WG endpoint, `host:port` (UDP)。
    pub endpoint: String,
    /// 本端在隧道内的地址 (如 `10.0.0.2`), smoltcp 接口用它作源 IP。
    pub address: std::net::IpAddr,
    /// 隧道 MTU, 默认 1420 (WG 标准: 1500 - 20 IP - 8 UDP - 32 WG 头 ≈ 1440, 保守取 1420)。
    pub mtu: usize,
    /// persistent-keepalive 秒数, 穿 NAT 用; 0/None = 关。
    pub persistent_keepalive: Option<u16>,
    /// 隧道内 DNS 服务器 (对齐 wg-quick 的 `DNS =`)。
    ///
    /// 配了它, 走本隧道的域名就**经隧道解析** —— 否则在本机解析完再把 IP 送进去,
    /// 意味着 ①查询本身不经隧道, ②拿到的是本机所在地区的解析结果 (CDN/流媒体会因此
    /// 把 WG 出口白配)。不配 = 保持本机解析, 不强加一次额外往返。
    pub dns: Option<std::net::IpAddr>,
}

/// 解码一个标准 WireGuard base64 密钥为 32 字节。
///
/// 长度必须恰好 32 字节 —— WG 密钥格式固定, 填错 (比如误填一段密码) 长度对不上直接报错,
/// 避免"连上但握手永远失败"的难查故障 (与 SIP022 PSK 同类考量)。
pub fn decode_wg_key(b64: &str, what: &str) -> Result<[u8; 32]> {
    use base64::Engine;
    let raw = base64::engine::general_purpose::STANDARD
        .decode(b64.trim())
        .map_err(|e| anyhow!("WireGuard {what} 必须是 base64 编码的密钥: {e}"))?;
    if raw.len() != 32 {
        bail!(
            "WireGuard {what} 长度不对: base64 解码后 {} 字节, 应为 32 字节 \
             (标准 wg genkey/pubkey 输出的密钥)",
            raw.len()
        );
    }
    let mut k = [0u8; 32];
    k.copy_from_slice(&raw);
    Ok(k)
}

/// 标准 base64 编码 WireGuard 32 字节密钥。
pub fn encode_wg_key(key: &[u8; 32]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(key)
}

/// 对 X25519 标量执行 Curve25519 clamping (对齐 RFC 7748 §5 与 WireGuard 规范)。
pub fn clamp_scalar(scalar: &mut [u8; 32]) {
    scalar[0] &= 248;
    scalar[31] &= 127;
    scalar[31] |= 64;
}

/// 生成 WireGuard 密钥对: (私钥, 公钥), 均已完成 clamping 并推导公钥。
pub fn generate_wg_keypair() -> ([u8; 32], [u8; 32]) {
    use rand::RngExt;
    let mut priv_bytes = [0u8; 32];
    rand::rng().fill(&mut priv_bytes);
    clamp_scalar(&mut priv_bytes);
    let pub_bytes = public_key_from_private(&priv_bytes);
    (priv_bytes, pub_bytes)
}

/// 由 32 字节私钥推导 32 字节公钥。
pub fn public_key_from_private(priv_bytes: &[u8; 32]) -> [u8; 32] {
    let secret = StaticSecret::from(*priv_bytes);
    PublicKey::from(&secret).to_bytes()
}

/// 生成 32 字节预共享密钥 (PSK)。
pub fn generate_psk() -> [u8; 32] {
    use rand::RngExt;
    let mut psk = [0u8; 32];
    rand::rng().fill(&mut psk);
    psk
}

impl WgConfig {
    /// 本端公钥 (由私钥推导)。用于日志/排障时和服务端配的 `AllowedIPs`/peer 对照。
    pub fn public_key(&self) -> [u8; 32] {
        PublicKey::from(&StaticSecret::from(self.private_key)).to_bytes()
    }
}

/// 用配置构造 boringtun 的 `Tunn` (单 peer Noise 状态机)。
///
/// `index` 是本端的 sender index (WG 协议里区分多 peer/会话), 单 peer 场景固定给一个值即可;
/// boringtun 内部会 `index << 8`。不设 rate_limiter (仅客户端侧发起, 无需防 DoS 放大)。
pub fn build_tunn(cfg: &WgConfig, index: u32) -> boringtun::noise::Tunn {
    boringtun::noise::Tunn::new(
        StaticSecret::from(cfg.private_key),
        PublicKey::from(cfg.peer_public_key),
        cfg.preshared_key,
        cfg.persistent_keepalive.filter(|k| *k > 0),
        index,
        None,
    )
}

/// 解析目标地址 —— **配了隧道内 DNS 就经隧道解析**, 否则回落到本机解析。
///
/// 回落是刻意的: 不配 `dns` 的用户不该被强加一次额外往返。但要清楚代价 —— 本机解析
/// 意味着查询不经隧道, 且拿到的是本机所在地区的结果 (CDN/流媒体会因此把出口白配)。
pub async fn resolve_target(
    tunnel: &std::sync::Arc<tunnel::WgTunnel>,
    host: &str,
    port: u16,
) -> Result<std::net::SocketAddr> {
    if let Some(dns) = &tunnel.dns {
        return dns.resolve(tunnel.clone(), host, port).await;
    }
    Ok(crate::proxy::resolver::resolve_first(host, port).await?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;

    fn b64(bytes: &[u8]) -> String {
        base64::engine::general_purpose::STANDARD.encode(bytes)
    }

    #[test]
    fn decode_key_enforces_32_bytes() {
        // 合法 32 字节
        let k = b64(&[0x11u8; 32]);
        assert_eq!(decode_wg_key(&k, "private_key").unwrap(), [0x11u8; 32]);
        // 16 字节 (误填短密钥) 必须报错并说明应有长度
        let short = b64(&[0u8; 16]);
        let e = decode_wg_key(&short, "peer_public_key").unwrap_err().to_string();
        assert!(e.contains("16 字节") && e.contains("32 字节"), "实际: {e}");
        // 非 base64
        assert!(decode_wg_key("这不是base64!!", "private_key").is_err());
    }

    #[test]
    fn public_key_derivation_matches_x25519() {
        // 用一个已知私钥, 推导的公钥应与 x25519-dalek 直接算的一致 (证明我们的推导没搞错)。
        let priv_bytes = [0x42u8; 32];
        let cfg = WgConfig {
            private_key: priv_bytes,
            peer_public_key: [0u8; 32],
            preshared_key: None,
            endpoint: "1.2.3.4:51820".into(),
            address: "10.0.0.2".parse().unwrap(),
            mtu: 1420,
            persistent_keepalive: None,
            dns: None,
        };
        let expect = PublicKey::from(&StaticSecret::from(priv_bytes)).to_bytes();
        assert_eq!(cfg.public_key(), expect);
    }

    /// RFC 7748 §6.1 官方测试向量验证公钥推导正确性及 clamping 行为。
    #[test]
    fn test_rfc7748_test_vectors_and_clamping() {
        // Alice
        let alice_priv_hex = "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a";
        let alice_pub_hex = "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a";
        let mut alice_priv = [0u8; 32];
        hex::decode_to_slice(alice_priv_hex, &mut alice_priv).unwrap();
        let mut alice_pub_expected = [0u8; 32];
        hex::decode_to_slice(alice_pub_hex, &mut alice_pub_expected).unwrap();

        let alice_pub_derived = public_key_from_private(&alice_priv);
        assert_eq!(alice_pub_derived, alice_pub_expected, "Alice 公钥推导必须与 RFC 7748 一致");

        // Bob
        let bob_priv_hex = "5dab087e624a8a4b79477010910431d17666461f5048b645162a1494dd4fb82d";
        let bob_pub_hex = "9b5132713d0ade3691a0e7ae89e0071d38e47516b5cb92edaa828e7a91f13a1e";
        let mut bob_priv = [0u8; 32];
        hex::decode_to_slice(bob_priv_hex, &mut bob_priv).unwrap();
        let mut bob_pub_expected = [0u8; 32];
        hex::decode_to_slice(bob_pub_hex, &mut bob_pub_expected).unwrap();

        let bob_pub_derived = public_key_from_private(&bob_priv);
        assert_eq!(bob_pub_derived, bob_pub_expected, "Bob 公钥推导必须与 RFC 7748 一致");

        // 验证生成器符合 clamping 约束
        for _ in 0..50 {
            let (priv_k, pub_k) = generate_wg_keypair();
            // clamp 检验: bit 0, 1, 2 为 0; bit 255 为 0; bit 254 为 1
            assert_eq!(priv_k[0] & 7, 0, "私钥第 0 字节低 3 位必须为 0");
            assert_eq!(priv_k[31] & 128, 0, "私钥最高 bit (bit 255) 必须为 0");
            assert_ne!(priv_k[31] & 64, 0, "私钥次高 bit (bit 254) 必须为 1");

            // 公钥非全零且与公钥推导一致
            assert_ne!(pub_k, [0u8; 32]);
            assert_eq!(public_key_from_private(&priv_k), pub_k);

            // encode 与 decode roundtrip
            let b64 = encode_wg_key(&priv_k);
            let dec = decode_wg_key(&b64, "test_priv").unwrap();
            assert_eq!(dec, priv_k);
        }
    }

    /// 阶段1 里程碑: 用配置构造 Tunn, 驱动它产出**第一个握手包**, 验证它是合法的
    /// WireGuard handshake initiation (type=1, 固定长度 148 字节)。这证明 boringtun
    /// 集成、密钥装载、Noise 状态机启动都对 —— 是整条 WG 链路的第一块地基。
    #[test]
    fn tunn_produces_valid_handshake_initiation() {
        let cfg = WgConfig {
            private_key: [0x01u8; 32],
            peer_public_key: [0x02u8; 32],
            preshared_key: None,
            endpoint: "1.2.3.4:51820".into(),
            address: "10.0.0.2".parse().unwrap(),
            mtu: 1420,
            persistent_keepalive: None,
            dns: None,
        };
        let mut tunn = build_tunn(&cfg, 1);

        // 无数据可发时, encapsulate 空输入会触发握手 initiation。
        let mut out = [0u8; 2048];
        let res = tunn.encapsulate(&[], &mut out);
        match res {
            boringtun::noise::TunnResult::WriteToNetwork(pkt) => {
                // WireGuard handshake initiation: 第 1 字节 message type = 1, 总长 148。
                assert_eq!(pkt[0], 1, "首字节应为 WG handshake-init 类型 1");
                assert_eq!(pkt.len(), 148, "handshake-init 固定 148 字节");
            }
            other => panic!("期望 WriteToNetwork(握手包), 实际 {:?}", std::mem::discriminant(&other)),
        }
    }
}
