//! ClientHello 指纹对照 harness.
//!
//! 用法:
//!   dump_tls [SNI]              为每个 profile 生成 3 个样本, 打印 JA4 + 十六进制, 写 /tmp/rust_tls.hex
//!   dump_tls --ja4 <hexfile>    读一个抓包的 ClientHello 十六进制 (每行一个), 打印各自 JA4
//!
//! 对照真实抓包: Wireshark 里右键 TLS 层 → Copy as Hex Stream 存文件, `dump_tls --ja4 file`,
//! 把打印的 JA4 和本工具为对应 profile 生成的 JA4 比对; 一致即 mimicry 成立。

use mirage_rs::crypto::tls_raw::{self, Profile};
use std::fs;

fn main() {
    let args: Vec<String> = std::env::args().collect();

    // --ja4 模式: 算抓包文件里每个 ClientHello 的 JA4
    if args.get(1).map(|s| s.as_str()) == Some("--ja4") {
        let path = args.get(2).expect("用法: dump_tls --ja4 <hexfile>");
        let content = fs::read_to_string(path).expect("读文件失败");
        for (n, line) in content.lines().enumerate() {
            let hexs: String = line.split_whitespace().last().unwrap_or("").chars().collect();
            if hexs.len() < 20 {
                continue;
            }
            match hex::decode(&hexs) {
                Ok(ch) => println!("#{} JA4 = {}", n + 1, tls_raw::ja4(&ch)),
                Err(e) => println!("#{} 解析失败: {}", n + 1, e),
            }
        }
        return;
    }

    let session_id = [0u8; 32];
    let sni = args.get(1).cloned().unwrap_or_else(|| "www.apple.com".to_string());

    let mut out = String::new();
    for (name, prof) in [
        ("chromium", Profile::Chromium),
        ("firefox", Profile::Firefox),
        ("okhttp", Profile::OkHttp),
    ] {
        for k in 1..=3 {
            let (ch, _) = tls_raw::build_with_profile(prof, &sni, &session_id);
            if k == 1 {
                println!("{:9} JA4 = {}", name, tls_raw::ja4(&ch));
            }
            out.push_str(&format!("{}#{} {}\n", name, k, hex::encode(&ch)));
        }
    }
    let path = "/tmp/rust_tls.hex";
    fs::write(path, &out).unwrap();
    println!("\nwrote {} ({} lines) sni={}", path, out.lines().count(), sni);
    println!("对照真实抓包: dump_tls --ja4 <你的抓包hex文件>, 比对上面的 JA4");
}
