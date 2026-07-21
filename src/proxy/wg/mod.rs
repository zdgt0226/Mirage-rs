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
//!   - [ ] 阶段2: WgDevice (smoltcp Device 桥接) + 异步 pump (udp↔tunn↔smoltcp + 定时器)
//!   - [ ] 阶段3: connect_tcp / udp 通过 WG 隧道; 接入 outbound + mirage_server.upstream
//!   - [ ] 阶段4: 真机 e2e 对着真实 WG peer 验证

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
        };
        let expect = PublicKey::from(&StaticSecret::from(priv_bytes)).to_bytes();
        assert_eq!(cfg.public_key(), expect);
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
