use std::fs;
use mirage_rs::crypto::tls_raw;

fn main() {
    let session_id = [0u8; 32];
    let client_random = [0u8; 32];
    let sni = b"www.apple.com";

    // 生成 3 个 Chromium 150 ClientHello (扩展顺序每次随机洗牌, 验证洗牌 + JA4 稳定).
    let s1 = tls_raw::build_chromium(sni, &session_id, &client_random);
    let s2 = tls_raw::build_chromium(sni, &session_id, &client_random);
    let s3 = tls_raw::build_chromium(sni, &session_id, &client_random);

    let output = format!("{}\n{}\n{}", hex::encode(s1), hex::encode(s2), hex::encode(s3));
    fs::write("/tmp/rust_tls.hex", output).unwrap();
}
