//! 客户端版本识别 (WebUI 服务端「连接的客户端」显示版本)。
//!
//! **两端 opt-in config 门控** (`tuning.client_info`, 同 pfs/cipher_agility/tls_padding 的模式):
//! 两端同开时, 客户端在握手后 (TIME_SYNC/agility 之后, target 之前) 于**加密信道内**发一帧
//! CLIENT_INFO(版本字符串), 服务端读到即记 `客户端 IP → 版本`。默认关 → 不发不读, 零兼容风险。
//!
//! - **零指纹影响**: 帧在加密信道内, ClientHello 一字不改。
//! - 单边开: 与其它高级特征一致 fail-closed (config 保证两端同开; 见 README 安全声明)。
//! - 内存版: 版本表随进程, 重启清零。

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{LazyLock, Mutex};

/// CLIENT_INFO 帧首字节 sentinel。0xC1 作 first_chunk[0] 不与 UDP(0x00)/mux/合法 target_len
/// 高字节 (目标短, 高字节恒 0) 冲突; 且仅在两端 client_info 开时才发/读, 冲突面为零。
pub const CLIENT_INFO_SENTINEL: u8 = 0xC1;

static ENABLED: AtomicBool = AtomicBool::new(false);

pub fn set_enabled(on: bool) {
    ENABLED.store(on, Ordering::Relaxed);
}
pub fn enabled() -> bool {
    ENABLED.load(Ordering::Relaxed)
}

/// 本机版本字符串 (semver)。客户端据此上报。
pub fn own_version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

/// 构造 CLIENT_INFO 帧: [sentinel][version UTF-8]。
pub fn build_frame(version: &str) -> Vec<u8> {
    let mut f = Vec::with_capacity(1 + version.len());
    f.push(CLIENT_INFO_SENTINEL);
    f.extend_from_slice(version.as_bytes());
    f
}

/// 解析 CLIENT_INFO 帧 → 版本字符串; 非本帧 (首字节非 sentinel / 空 / 非法 UTF-8) → None。
/// 版本长度截断到 32 (防异常客户端灌超长串)。
pub fn parse_frame(frame: &[u8]) -> Option<String> {
    if frame.first() != Some(&CLIENT_INFO_SENTINEL) || frame.len() < 2 {
        return None;
    }
    let raw = &frame[1..frame.len().min(1 + 32)];
    String::from_utf8(raw.to_vec()).ok().map(|s| s.trim().to_string())
}

/// 服务端: 客户端 IP → 版本。
static CLIENT_VERSIONS: LazyLock<Mutex<HashMap<String, String>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

pub fn record_version(client_ip: String, version: String) {
    CLIENT_VERSIONS.lock().unwrap_or_else(|e| e.into_inner()).insert(client_ip, version);
}

pub fn version_of(client_ip: &str) -> Option<String> {
    CLIENT_VERSIONS.lock().unwrap_or_else(|e| e.into_inner()).get(client_ip).cloned()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn frame_roundtrip() {
        let f = build_frame("0.9.6");
        assert_eq!(f[0], CLIENT_INFO_SENTINEL);
        assert_eq!(parse_frame(&f).as_deref(), Some("0.9.6"));
        // 非本帧
        assert_eq!(parse_frame(&[0x00]), None);
        assert_eq!(parse_frame(&[0x16, 0x03]), None);
        assert_eq!(parse_frame(&[CLIENT_INFO_SENTINEL]), None); // 只有 sentinel 无版本
    }
}
