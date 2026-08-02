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
        // 需 aes + pmull (GHASH 加速): 缺 pmull 则 AES-GCM 走软件 GHASH, 比 ChaCha20 还慢
        // (性能悬崖)。对称于 x86 的 aes+pclmulqdq。
        if std::arch::is_aarch64_feature_detected!("aes")
            && std::arch::is_aarch64_feature_detected!("pmull")
        {
            return Cipher::Aes256Gcm;
        }
    }
    Cipher::ChaCha20Poly1305
}

/// 本机是否支持硬件加速的 AES (协商时报给对端)。
pub fn local_supports_aes() -> bool {
    detect_best_cipher() == Cipher::Aes256Gcm
}

// ── cipher agility 协商 ──────────────────────────────────────────────────────

use std::sync::atomic::{AtomicBool, Ordering};

/// 服务端 cipher agility 开关 (启动时从 config.tuning.cipher_agility 设一次)。
static SERVER_CIPHER_AGILITY: AtomicBool = AtomicBool::new(false);

pub fn set_server_cipher_agility(on: bool) {
    SERVER_CIPHER_AGILITY.store(on, Ordering::Relaxed);
}
pub fn server_cipher_agility() -> bool {
    SERVER_CIPHER_AGILITY.load(Ordering::Relaxed)
}

/// TLS record padding 开关 (启动时从 config.tuning.tls_padding 设一次)。开启后 CryptoWriter
/// 对握手后前 N 条记录追加 TLS 1.3 原生零填充, 抹掉包长序列指纹。收端**恒剥零**(向后兼容),
/// 故只有发端受此开关控制。**要求对端 ≥ 支持剥零的版本**, 否则老对端会把填充零当 content_type
/// 解析失败 —— 与 cipher_agility 同类约束, 两端同版才开。
static TLS_PADDING: AtomicBool = AtomicBool::new(false);

pub fn set_tls_padding(on: bool) {
    TLS_PADDING.store(on, Ordering::Relaxed);
}
pub fn tls_padding_enabled() -> bool {
    TLS_PADDING.load(Ordering::Relaxed)
}

/// TIME_SYNC 帧 proto_ver: 0x01=仅 ChaCha20 (老/默认), 0x02=支持 agility 协商。
pub const PROTO_VER_LEGACY: u8 = 0x01;
pub const PROTO_VER_AGILITY: u8 = 0x02;

/// 客户端→服务端 CIPHER_NEGO 帧: [0xFF,0xFF,client_aes(0/1)]。前两字节是"不可能的 target_len
/// (65535)"哨兵, 与真 target 帧区分; 老服务端永不收到 (它没发 proto_ver=0x02)。
pub const CIPHER_NEGO_SENTINEL: [u8; 2] = [0xFF, 0xFF];
/// 服务端→客户端 CIPHER_ACK 帧: [0x03, final_cipher_wire]。
pub const CIPHER_ACK_TYPE: u8 = 0x03;

/// 构造 CIPHER_NEGO 帧。
pub fn build_cipher_nego(client_supports_aes: bool) -> [u8; 3] {
    [CIPHER_NEGO_SENTINEL[0], CIPHER_NEGO_SENTINEL[1], client_supports_aes as u8]
}

/// 一帧是否 CIPHER_NEGO (服务端识别客户端首帧)。是则返回 client_supports_aes。
pub fn parse_cipher_nego(frame: &[u8]) -> Option<bool> {
    if frame.len() == 3 && frame[0] == CIPHER_NEGO_SENTINEL[0] && frame[1] == CIPHER_NEGO_SENTINEL[1] {
        Some(frame[2] != 0)
    } else {
        None
    }
}

/// 协商最终 cipher: 仅当**两端都支持** AES 才用 AES, 否则 ChaCha20 (无加速方 AES 反而更慢)。
pub fn negotiate(client_aes: bool, server_aes: bool) -> Cipher {
    if client_aes && server_aes {
        Cipher::Aes256Gcm
    } else {
        Cipher::ChaCha20Poly1305
    }
}

/// 构造 CIPHER_ACK 帧。
pub fn build_cipher_ack(final_cipher: Cipher) -> [u8; 2] {
    [CIPHER_ACK_TYPE, final_cipher.to_wire()]
}

/// 解析 CIPHER_ACK 帧 → 最终 cipher。格式/字节非法 → None。
pub fn parse_cipher_ack(frame: &[u8]) -> Option<Cipher> {
    if frame.len() == 2 && frame[0] == CIPHER_ACK_TYPE {
        Cipher::from_wire(frame[1])
    } else {
        None
    }
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
    fn negotiate_only_aes_when_both() {
        use Cipher::*;
        assert_eq!(negotiate(true, true), Aes256Gcm, "两端都 AES → AES");
        assert_eq!(negotiate(true, false), ChaCha20Poly1305, "一端无 AES → ChaCha20");
        assert_eq!(negotiate(false, true), ChaCha20Poly1305);
        assert_eq!(negotiate(false, false), ChaCha20Poly1305);
    }

    #[test]
    fn nego_frame_roundtrip() {
        assert_eq!(parse_cipher_nego(&build_cipher_nego(true)), Some(true));
        assert_eq!(parse_cipher_nego(&build_cipher_nego(false)), Some(false));
        // 真 target 帧 (非哨兵) 不误判成 NEGO
        assert_eq!(parse_cipher_nego(&[0x00, 0x05, b'h']), None);
        assert_eq!(parse_cipher_nego(&[0xFF, 0xFF]), None, "长度不足 3 不算");
        assert_eq!(parse_cipher_nego(b"\x00\x0aexample.com"), None);
    }

    #[test]
    fn ack_frame_roundtrip() {
        for c in [Cipher::ChaCha20Poly1305, Cipher::Aes256Gcm] {
            assert_eq!(parse_cipher_ack(&build_cipher_ack(c)), Some(c));
        }
        assert_eq!(parse_cipher_ack(&[0x03, 0x00]), None, "非法 cipher 字节");
        assert_eq!(parse_cipher_ack(&[0x01, 0x02]), None, "非 ACK type");
    }

    #[test]
    fn server_agility_flag_global() {
        set_server_cipher_agility(true);
        assert!(server_cipher_agility());
        set_server_cipher_agility(false);
        assert!(!server_cipher_agility());
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
