//! 前向保密 (PFS): 一次性 X25519 ECDH。
//!
//! 两端各生成一次性 X25519 密钥对, 公钥搭 fake-TLS 的 `random` 字段交换 —— ClientHello.random =
//! 客户端临时公钥, ServerHello.random = 服务端临时公钥。任意 32B 都是合法 X25519 公钥且看起来
//! 均匀随机, 而这俩 random 字段本就每连接随机、明文交换, 故**零指纹变化、无需额外解析**。
//!
//! ECDH 共享秘密混进会话 master (见 [`crate::crypto::aead::create_crypto_pair_pfs`]), 于是即便
//! 口令泄露, 已录流量也无法解密 —— 临时私钥用完即弃、从不上线。认证仍靠口令 token
//! ([`crate::crypto::hello_auth`]), 与加密解耦 (对标 REALITY)。
//!
//! opt-in: 由两端 config `pfs: true` 门控, 默认关。改了 master 派生, 两端必须一致。

use ring::agreement::{self, EphemeralPrivateKey, UnparsedPublicKey};
use ring::rand::SystemRandom;

/// 一次性 X25519 密钥对: 私钥 (用完即弃) + 32B 公钥 (放进 random 字段发出)。
pub struct Ephemeral {
    private: EphemeralPrivateKey,
    /// 32B X25519 公钥, 直接当 ClientHello/ServerHello 的 random 发出。
    pub public: [u8; 32],
}

impl Ephemeral {
    /// 生成一对临时密钥。
    pub fn generate() -> anyhow::Result<Self> {
        let rng = SystemRandom::new();
        let private = EphemeralPrivateKey::generate(&agreement::X25519, &rng)
            .map_err(|_| anyhow::anyhow!("X25519 临时私钥生成失败"))?;
        let pk = private
            .compute_public_key()
            .map_err(|_| anyhow::anyhow!("X25519 公钥计算失败"))?;
        let mut public = [0u8; 32];
        // X25519 公钥恒 32B。
        public.copy_from_slice(pk.as_ref());
        // 抗指纹: X25519 u 坐标 < 2^255-19, 故最高位 (byte[31] & 0x80) **恒为 0**, 而正常 TLS
        // random 该位随机 —— 裸公钥塞进 random 字段会留 1 bit 分布偏差 (审查者多采样可区分)。
        // 随机化该位。RFC 7748 §5 规定收端 scalar mult 前 mask 掉最高位 (见 agree), 故不影响
        // ECDH 结果。这样发出的 random 字段各 bit ~均匀, 与真 TLS random 不可区分。
        if fastrand::bool() {
            public[31] |= 0x80;
        }
        Ok(Self { private, public })
    }

    /// 与对端公钥做 ECDH, 返回 32B 共享秘密。消费自身私钥 (临时密钥一次性用)。
    pub fn agree(self, peer_public: &[u8; 32]) -> anyhow::Result<[u8; 32]> {
        // 收端 mask 最高位再 ECDH (RFC 7748 §5)。对端可能随机化了该 bit 抗指纹 (见 generate),
        // 这里显式清掉, 保证协商用规范 u 坐标、不依赖 ring 内部是否 mask。
        let mut peer = *peer_public;
        peer[31] &= 0x7f;
        let peer = UnparsedPublicKey::new(&agreement::X25519, peer.as_slice());
        agreement::agree_ephemeral(self.private, &peer, |shared| {
            let mut out = [0u8; 32];
            out.copy_from_slice(shared);
            out
        })
        .map_err(|_| anyhow::anyhow!("X25519 ECDH 协商失败"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 两端各生成临时对, 交换公钥后各自 agree, 共享秘密必须一致 (ECDH 对称性)。
    #[test]
    fn ecdh_both_sides_agree() {
        let client = Ephemeral::generate().unwrap();
        let server = Ephemeral::generate().unwrap();
        let client_pub = client.public;
        let server_pub = server.public;
        let s_client = client.agree(&server_pub).unwrap();
        let s_server = server.agree(&client_pub).unwrap();
        assert_eq!(s_client, s_server, "两端 ECDH 共享秘密必须相等");
    }

    /// 不同的对端公钥 → 不同的共享秘密 (基本 sanity: agree 真的用了对端公钥)。
    #[test]
    fn different_peer_yields_different_secret() {
        let a = Ephemeral::generate().unwrap();
        let b = Ephemeral::generate().unwrap();
        let c = Ephemeral::generate().unwrap();
        let b_pub = b.public;
        let c_pub = c.public;
        assert_ne!(a.agree(&b_pub).unwrap(), {
            let a2 = Ephemeral::generate().unwrap();
            a2.agree(&c_pub).unwrap()
        });
    }

    /// 公钥恒 32B。
    #[test]
    fn public_key_is_32_bytes() {
        let e = Ephemeral::generate().unwrap();
        assert_eq!(e.public.len(), 32);
    }

    /// 抗指纹: 发出公钥的最高位 (byte[31] & 0x80) 必须被随机化 —— 多次生成两种取值都出现,
    /// 否则裸 X25519 公钥恒 0 的最高位在 random 字段里是 1 bit 分布指纹。
    #[test]
    fn public_high_bit_is_randomized() {
        let mut saw0 = false;
        let mut saw1 = false;
        for _ in 0..256 {
            let e = Ephemeral::generate().unwrap();
            if e.public[31] & 0x80 == 0 {
                saw0 = true;
            } else {
                saw1 = true;
            }
            if saw0 && saw1 {
                break;
            }
        }
        assert!(saw0 && saw1, "公钥最高位应随机化 (0/1 都出现), 实得 saw0={saw0} saw1={saw1}");
    }

    /// 即便对端随机化了最高位 (或人为设 1), agree 仍应算出与规范公钥相同的共享秘密
    /// (收端 mask 最高位)。防止抗指纹的 bit 翻转破坏 ECDH。
    #[test]
    fn agree_masks_peer_high_bit() {
        let a = Ephemeral::generate().unwrap();
        let b = Ephemeral::generate().unwrap();
        let a_pub = a.public;
        let mut b_pub_flipped = b.public;
        b_pub_flipped[31] ^= 0x80; // 翻转对端公钥最高位
        // a 与"翻转最高位的 b 公钥" agree, 应等于 b 与 a 公钥 agree (b 收端 mask a 的最高位)。
        let s1 = a.agree(&b_pub_flipped).unwrap();
        let s2 = b.agree(&a_pub).unwrap();
        assert_eq!(s1, s2, "最高位翻转不应改变 ECDH 结果 (收端 mask)");
    }
}
