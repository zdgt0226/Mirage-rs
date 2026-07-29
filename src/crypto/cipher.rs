//! Cipher agility: 隧道 AEAD 算法可协商 (ChaCha20-Poly1305 默认起手, 两端有硬件 AES 加速时
//! 协商切到 AES-256-GCM, 大流量提速 ~2x)。协商见 mirage_server/control.rs + pool.rs。

use ring::aead;

/// 隧道 AEAD 算法。wire 字节: ChaCha20=0x01 (默认/兼容), AES-256-GCM=0x02。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Cipher {
    ChaCha20Poly1305,
    Aes256Gcm,
}

impl Cipher {
    /// wire 字节 (协商帧 / TIME_SYNC 用)。
    pub fn to_wire(self) -> u8 {
        match self {
            Cipher::ChaCha20Poly1305 => 0x01,
            Cipher::Aes256Gcm => 0x02,
        }
    }

    /// 从 wire 字节解析。未知字节 → None (调用方应回落 ChaCha20 或报错)。
    pub fn from_wire(b: u8) -> Option<Cipher> {
        match b {
            0x01 => Some(Cipher::ChaCha20Poly1305),
            0x02 => Some(Cipher::Aes256Gcm),
            _ => None,
        }
    }

    /// 对应的 ring AEAD 算法。
    pub fn ring_algorithm(self) -> &'static aead::Algorithm {
        match self {
            Cipher::ChaCha20Poly1305 => &aead::CHACHA20_POLY1305,
            Cipher::Aes256Gcm => &aead::AES_256_GCM,
        }
    }

    /// HKDF info 后缀 —— 折进密钥派生做**域分隔**: 不同 cipher 派生出不同密钥,
    /// 使 re-key 时 (key,algo) 整体变化, nonce 归零安全 (不复用 (key,nonce))。
    pub fn hkdf_suffix(self) -> &'static [u8] {
        match self {
            Cipher::ChaCha20Poly1305 => b"", // 保持与旧版一致 (info="c2s"/"s2c" 不变, 向后兼容)
            Cipher::Aes256Gcm => b"-aes256gcm",
        }
    }
}

/// 检测本机应优先用哪个 cipher: 有硬件 AES 加速 → AES-256-GCM, 否则 ChaCha20-Poly1305。
/// 保守: 只在**确有加速**时选 AES (无加速时 ChaCha20 更快)。x86/aarch64 分别检测,
/// 其它架构一律 ChaCha20。
pub fn detect_best_cipher() -> Cipher {
    #[cfg(target_arch = "x86_64")]
    {
        if std::is_x86_feature_detected!("aes") && std::is_x86_feature_detected!("pclmulqdq") {
            return Cipher::Aes256Gcm;
        }
    }
    #[cfg(target_arch = "x86")]
    {
        if std::is_x86_feature_detected!("aes") && std::is_x86_feature_detected!("pclmulqdq") {
            return Cipher::Aes256Gcm;
        }
    }
    #[cfg(target_arch = "aarch64")]
    {
        if std::arch::is_aarch64_feature_detected!("aes") {
            return Cipher::Aes256Gcm;
        }
    }
    Cipher::ChaCha20Poly1305
}

/// 本机是否支持硬件加速的 AES (协商时报给对端)。
pub fn local_supports_aes() -> bool {
    detect_best_cipher() == Cipher::Aes256Gcm
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wire_roundtrip() {
        for c in [Cipher::ChaCha20Poly1305, Cipher::Aes256Gcm] {
            assert_eq!(Cipher::from_wire(c.to_wire()), Some(c));
        }
        assert_eq!(Cipher::ChaCha20Poly1305.to_wire(), 0x01, "ChaCha20=0x01 (兼容值)");
        assert_eq!(Cipher::Aes256Gcm.to_wire(), 0x02);
        assert_eq!(Cipher::from_wire(0x00), None);
        assert_eq!(Cipher::from_wire(0xFF), None);
    }

    #[test]
    fn detect_returns_one_of_two() {
        let c = detect_best_cipher();
        assert!(c == Cipher::ChaCha20Poly1305 || c == Cipher::Aes256Gcm);
        assert_eq!(local_supports_aes(), c == Cipher::Aes256Gcm);
    }

    #[test]
    fn hkdf_suffix_differs_per_cipher() {
        // 域分隔: 两 cipher 的 HKDF 后缀必须不同, 否则同 master 派生同 key, re-key 后
        // nonce 归零会复用 (key,nonce) —— 灾难。
        assert_ne!(
            Cipher::ChaCha20Poly1305.hkdf_suffix(),
            Cipher::Aes256Gcm.hkdf_suffix()
        );
    }
}
