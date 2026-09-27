//! 前向保密 (PFS): 基于 Elligator2 编码的一次性 X25519 ECDH。
//!
//! 两端各生成一次性 X25519 密钥对, 公钥经 Elligator2 编码为均匀随机字节串 (representative),
//! 搭 fake-TLS 的 `random` 字段交换 —— ClientHello.random = 客户端临时 representative,
//! ServerHello.random = 服务端临时 representative。
//!
//! ### 背景与设计
//! 裸 X25519 公钥是 Montgomery 曲线点的 u 坐标, 满足 `u³ + A·u² + u` 恒为平方剩余。审查者对
//! random 字段做单次 Legendre 检验即可将裸公钥与真随机区分 (真随机通过率约 50%, 裸公钥 100%)。
//!
//! 为彻底消除该指纹特征, 本实现采用 Elligator2:
//! 1. **拒绝采样**: 约一半曲线点具有 Elligator2 原像, 生成密钥时循环采样直至命中合法原像;
//! 2. **Torsion-dirty 公钥**: 发布点包含 8 阶低阶挠点分量 (`E_pub = clamp(e)·B + T`), 避免解码后
//!    恒为素数阶子群从而被特征区分; 对端 X25519 标量乘因标量必为 8 的倍数 (`clamp(e)` 保证)
//!    而自动消除 `T` 分量, ECDH 协商不受影响;
//! 3. **高 2 位随机化**: Elligator2 representative 的 bit 254 与 bit 255 原生为 0, 发送端由库
//!    填充真随机比特, 接收端解码时统一 mask, 实现整 32 字节均匀不可区分;
//! 4. **低阶点拒绝 (Fail-Closed)**: 任意 32B 均可经由 `from_representative` 解码为某个曲线点,
//!    若攻击者注入解码为低阶点 (如全 0 等) 的畸变输入, 协商将得到全 0 的非贡献性共享秘密。
//!    本模块严格校验 `SharedSecret::was_contributory()`, 拒绝低阶点输入并返回错误。
//!
//! ### 线上字节 vs 协议内点
//! - 线上发送/接收、TLS random 字段、token bind、HKDF salt 均直接使用 32B 的 representative (即 `public`);
//! - 内部 ECDH 协商时, 通过 `elligator2::from_representative` 将对端 representative 解码为 Montgomery
//!   曲线点的 u 坐标, 再执行 Diffie-Hellman。
//!
//! opt-in: 由两端 config `pfs: true` 门控, 默认关。改了 master 派生, 两端必须一致。

use elligator2::HiddenKey;

/// 一次性 X25519 密钥对: 私钥 (用完即弃, zeroize 保护) + 32B 线上 representative (放进 random 字段发出)。
pub struct Ephemeral {
    hidden: HiddenKey,
    /// 32B Elligator2 representative, 直接当 ClientHello/ServerHello 的 random 发出。
    pub public: [u8; 32],
}

impl Ephemeral {
    /// 生成一对临时密钥。
    ///
    /// 内部调用 `elligator2::generate`, 自动完成拒绝采样、torsion-dirty 构造以及高 2 位随机化。
    pub fn generate() -> anyhow::Result<Self> {
        let mut rng = rand::rng();
        let hidden = elligator2::generate(&mut rng)
            .ok_or_else(|| anyhow::anyhow!("Elligator2 X25519 临时密钥生成失败 (RNG 异常)"))?;
        let public = *hidden.representative();
        Ok(Self { hidden, public })
    }

    /// 与对端 representative 做 ECDH, 返回 32B 共享秘密。消费自身私钥 (临时密钥一次性用)。
    ///
    /// 首先通过 `elligator2::from_representative` 解码对端 representative 得到曲线点的 u 坐标,
    /// 再与自身私钥执行 X25519 协商。协商结果必须满足 `was_contributory()`, 否则返回 Err (拒绝低阶点)。
    pub fn agree(self, peer_public: &[u8; 32]) -> anyhow::Result<[u8; 32]> {
        let peer_point = elligator2::from_representative(peer_public);
        let peer_pk = x25519_dalek::PublicKey::from(peer_point);
        let shared = self.hidden.diffie_hellman(&peer_pk);
        if !shared.was_contributory() {
            anyhow::bail!("X25519 ECDH 协商失败: 共享秘密非 contributory (低阶点拒绝)");
        }
        let mut out = [0u8; 32];
        out.copy_from_slice(shared.as_bytes());
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 两端各生成临时对, 交换 representative 后各自 agree, 共享秘密必须一致 (ECDH 对称性)。
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

    /// 不同的对端 representative → 不同的共享秘密 (基本 sanity: agree 真的用了对端公钥)。
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

    /// 公钥 (representative) 恒 32B。
    #[test]
    fn public_key_is_32_bytes() {
        let e = Ephemeral::generate().unwrap();
        assert_eq!(e.public.len(), 32);
    }

    /// 抗指纹: 发出 representative 的最高 2 位 (byte[31] 的 bit 254 与 bit 255) 必须被随机化 ——
    /// 多次生成中 0/1 均应出现。
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

    /// 即便对端翻转了最高位 (或高 2 位), agree 仍应算出与原始 representative 相同的共享秘密
    /// (from_representative 会自动 mask 掉高 2 位)。
    #[test]
    fn agree_masks_peer_high_bit() {
        let a = Ephemeral::generate().unwrap();
        let b = Ephemeral::generate().unwrap();
        let a_pub = a.public;
        let mut b_pub_flipped = b.public;
        b_pub_flipped[31] ^= 0x80; // 翻转对端 representative 最高位 (bit 255)
        let s1 = a.agree(&b_pub_flipped).unwrap();
        let s2 = b.agree(&a_pub).unwrap();
        assert_eq!(s1, s2, "最高位翻转不应改变 ECDH 结果 (收端 mask)");

        // 进一步验证同时翻转高 2 位 (0xc0 = bit 254 与 bit 255)
        let c = Ephemeral::generate().unwrap();
        let d = Ephemeral::generate().unwrap();
        let c_pub = c.public;
        let mut d_pub_flipped = d.public;
        d_pub_flipped[31] ^= 0xc0;
        let s3 = c.agree(&d_pub_flipped).unwrap();
        let s4 = d.agree(&c_pub).unwrap();
        assert_eq!(s3, s4, "高 2 位翻转不应改变 ECDH 结果 (收端 mask)");
    }

    /// Legendre 分布: 生成 N=2000 个 public, 用 elligator2::is_montgomery_u 统计为 true 的比例,
    /// 断言在 [0.40, 0.60] (裸公钥会是 100%)。另断言 bit 254 与 bit 255 (public[31] 的 0x40 与 0x80)
    /// 各自 0/1 都出现。
    #[test]
    fn legendre_distribution_and_high_bits() {
        const N: usize = 2000;
        let mut montgomery_count = 0;
        let mut saw_bit254_zero = false;
        let mut saw_bit254_one = false;
        let mut saw_bit255_zero = false;
        let mut saw_bit255_one = false;

        for _ in 0..N {
            let e = Ephemeral::generate().expect("generate ephemeral");
            if elligator2::is_montgomery_u(&e.public) {
                montgomery_count += 1;
            }
            if e.public[31] & 0x40 == 0 {
                saw_bit254_zero = true;
            } else {
                saw_bit254_one = true;
            }
            if e.public[31] & 0x80 == 0 {
                saw_bit255_zero = true;
            } else {
                saw_bit255_one = true;
            }
        }

        let ratio = montgomery_count as f64 / N as f64;
        assert!(
            (0.40..=0.60).contains(&ratio),
            "Legendre 检验通过比例应在 [0.40, 0.60], 实际为 {ratio:.4} (裸公钥为 1.0)"
        );

        assert!(saw_bit254_zero, "bit 254 应出现 0");
        assert!(saw_bit254_one, "bit 254 应出现 1");
        assert!(saw_bit255_zero, "bit 255 应出现 0");
        assert!(saw_bit255_one, "bit 255 应出现 1");
    }

    /// 低阶点拒绝: 找一个解码为低阶点的 32B 输入, agree 必须返回 Err。
    #[test]
    fn low_order_point_rejected() {
        let e = Ephemeral::generate().expect("generate ephemeral");

        // 全 0 字节输入作为 representative, 经 from_representative 解码为 u=0 (2 阶低阶点)。
        // 与之协商会产生全 0 / 恒等元共享秘密, was_contributory 返回 false, agree 必须 fail-closed 返回 Err。
        let zero_input = [0u8; 32];
        let decoded = elligator2::from_representative(&zero_input);
        assert_eq!(decoded, [0u8; 32], "全 0 representative 解码应为 u=0 点");
        let res_zero = e.agree(&zero_input);
        assert!(
            res_zero.is_err(),
            "解码为低阶点的 representative (全 0) 协商必须返回 Err"
        );
    }
}
