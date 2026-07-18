use mirage_rs::crypto::tls_raw::{self, Profile};
use std::fs;

fn main() {
    let session_id = [0u8; 32];
    let sni = std::env::args().nth(1).unwrap_or_else(|| "www.apple.com".to_string());

    // 每个 profile 生成 3 个样本 (Chrome 每次洗牌; Firefox 固定顺序)。把这些十六进制导入
    // Wireshark / tlsfingerprint.io, 和真实浏览器抓包对 JA4 / 逐字节核对。
    let mut out = String::new();
    for (name, prof) in [("chromium", Profile::Chromium), ("firefox", Profile::Firefox)] {
        for k in 1..=3 {
            let (ch, _) = tls_raw::build_with_profile(prof, &sni, &session_id);
            out.push_str(&format!("{}#{} {}\n", name, k, hex::encode(&ch)));
        }
    }
    let path = "/tmp/rust_tls.hex";
    fs::write(path, &out).unwrap();
    println!("wrote {} ({} lines) sni={}", path, out.lines().count(), sni);
}
