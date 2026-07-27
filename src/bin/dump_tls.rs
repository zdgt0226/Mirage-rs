//! ClientHello 指纹对照 harness.
//!
//! 用法:
//!   dump_tls [SNI]              为每个 profile 生成 3 个样本, 打印 JA4 + 十六进制, 写 /tmp/rust_tls.hex
//!   dump_tls --ja4 <hexfile>          读抓包 ClientHello 十六进制 (每行一个), 打印各自 JA4
//!   dump_tls --session-ids <hexfile>       抽 session_id, 跨行标注复用 + 多维统计
//!   dump_tls --session-cmp <real> <ours>   两文件的 session_id 统计对照 (真 Chrome vs 我们),
//!                                          论证二者是否可区分 —— TLS resumption 仿真基线
//!
//! 对照真实抓包: Wireshark 里右键 TLS 层 → Copy as Hex Stream 存文件, `dump_tls --ja4 file`,
//! 把打印的 JA4 和本工具为对应 profile 生成的 JA4 比对; 一致即 mimicry 成立。

use mirage_rs::crypto::tls_raw::{self, Profile};
use std::fs;

/// 从抓包 hex 文件抽出所有 session_id 字节串。
fn collect_session_ids(path: &str) -> Vec<Vec<u8>> {
    let content = fs::read_to_string(path).expect("读文件失败");
    let mut out = Vec::new();
    for line in content.lines() {
        let hexs: String = line.split_whitespace().last().unwrap_or("").chars().collect();
        if hexs.len() < 20 { continue; }
        let ch = match hex::decode(&hexs) { Ok(v) => v, Err(_) => continue };
        if ch.len() < 44 { continue; }
        let sid_len = ch[43] as usize;
        if ch.len() < 44 + sid_len || sid_len == 0 { continue; }
        out.push(ch[44..44 + sid_len].to_vec());
    }
    out
}

struct SessStats {
    lengths: std::collections::BTreeMap<usize, usize>,
    entropy: f64,
    pos_means: Vec<f64>, // 每字节位置 (0..32) 的均值
}

/// 打印并返回一组 session_id 的统计量。
fn session_stats(ids: &[Vec<u8>]) -> SessStats {
    let n = ids.len();
    let mut lengths = std::collections::BTreeMap::new();
    for id in ids { *lengths.entry(id.len()).or_insert(0) += 1; }

    // 全局字节直方图 → Shannon 熵 (bit/byte)
    let mut hist = [0u64; 256];
    let mut total = 0u64;
    for id in ids { for &b in id { hist[b as usize] += 1; total += 1; } }
    let entropy = if total == 0 { 0.0 } else {
        hist.iter().filter(|&&c| c > 0).map(|&c| {
            let p = c as f64 / total as f64;
            -p * p.log2()
        }).sum()
    };

    // 逐字节位置均值 (只对 32 字节的样本, 那是绝对主流)
    let width = 32usize;
    let mut sums = vec![0f64; width];
    let mut cnts = vec![0u64; width];
    for id in ids {
        if id.len() != width { continue; }
        for (i, &b) in id.iter().enumerate() { sums[i] += b as f64; cnts[i] += 1; }
    }
    let pos_means: Vec<f64> = sums.iter().zip(&cnts)
        .map(|(s, c)| if *c > 0 { s / *c as f64 } else { 0.0 }).collect();

    println!("  样本数 {}  长度分布 {:?}  字节熵 {:.3} bit/byte (理论 8.0)", n, lengths, entropy);
    SessStats { lengths, entropy, pos_means }
}

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

    // --session-ids: 量化 legacy_session_id 的复用模式 (TLS resumption 仿真基线)。
    //
    // 输入同 --ja4: 每行一个抓包的 ClientHello 十六进制 (带 record 层, 从 16 03 开始)。
    // 抓法: 对**同一个客户端反复连同一服务器**多次, 每次抓 ClientHello 存一行。
    // 输出: 每行的 session_id + 是否与之前某行相同 —— 看真 Chrome 是"每次全新"还是
    // "复用上次" (resumption 时会回显上次 ticket 关联的 id)。
    if args.get(1).map(|s| s.as_str()) == Some("--session-ids") {
        let path = args.get(2).expect("用法: dump_tls --session-ids <hexfile>");
        let content = fs::read_to_string(path).expect("读文件失败");
        let mut seen: Vec<(String, usize)> = Vec::new(); // (sid_hex, 首次出现行号)
        let mut n_total = 0;
        let mut n_reused = 0;
        let mut n_empty = 0;
        for (n, line) in content.lines().enumerate() {
            let hexs: String = line.split_whitespace().last().unwrap_or("").chars().collect();
            if hexs.len() < 20 {
                continue;
            }
            let ch = match hex::decode(&hexs) {
                Ok(v) => v,
                Err(e) => {
                    println!("#{} 解析失败: {}", n + 1, e);
                    continue;
                }
            };
            // session_id: record(5) + hs_header(4) + version(2) + random(32) = 43 起
            if ch.len() < 44 {
                println!("#{} 太短, 跳过", n + 1);
                continue;
            }
            let sid_len = ch[43] as usize;
            if ch.len() < 44 + sid_len {
                println!("#{} 截断, 跳过", n + 1);
                continue;
            }
            n_total += 1;
            let sid = &ch[44..44 + sid_len];
            let sid_hex = hex::encode(sid);
            if sid_len == 0 {
                n_empty += 1;
                println!("#{} session_id = <空> (len=0)", n + 1);
                continue;
            }
            match seen.iter().find(|(h, _)| *h == sid_hex) {
                Some((_, first)) => {
                    n_reused += 1;
                    println!("#{} session_id = {}… (len={}) ← 与 #{} 相同", n + 1, &sid_hex[..sid_hex.len().min(16)], sid_len, first + 1);
                }
                None => {
                    println!("#{} session_id = {}… (len={}) 新", n + 1, &sid_hex[..sid_hex.len().min(16)], sid_len);
                    seen.push((sid_hex, n));
                }
            }
        }
        println!("\n── 汇总 ──");
        println!("总样本: {}  唯一: {}  复用: {}  空 session_id: {}", n_total, seen.len(), n_reused, n_empty);
        if n_total > 0 {
            println!("复用率: {:.0}%  (接近 0 = 真 Chrome 也几乎不复用 session_id, 则我们每次全随机并非异常)",
                     100.0 * n_reused as f64 / n_total as f64);
        }
        return;
    }

    // --session-cmp: 两文件对照, 逐维度看真 Chrome 与我们生成的 session_id 是否可区分。
    if args.get(1).map(|s| s.as_str()) == Some("--session-cmp") {
        let real = args.get(2).expect("用法: dump_tls --session-cmp <real.hex> <ours.hex>");
        let ours = args.get(3).expect("用法: dump_tls --session-cmp <real.hex> <ours.hex>");
        let a = collect_session_ids(real);
        let b = collect_session_ids(ours);
        println!("── {} (真实抓包) ──", real);
        let sa = session_stats(&a);
        println!("── {} (我们生成) ──", ours);
        let sb = session_stats(&b);
        println!("\n── 可区分性判定 ──");
        // 样本太少无法下结论 —— 别把"没数据"误报成"不可区分"。
        let min_n = a.len().min(b.len());
        if min_n < 20 {
            println!("⚠️ 样本不足 (真={} 我们={}), 至少各 20 个才有统计意义, 拒绝下结论。", a.len(), b.len());
            return;
        }
        let mut flags = 0;
        if sa.lengths != sb.lengths {
            println!("🔴 长度分布不同: 真={:?} 我们={:?}", sa.lengths, sb.lengths);
            flags += 1;
        } else {
            println!("✅ 长度分布一致: {:?}", sa.lengths);
        }
        // 字节熵: 均匀随机每字节应 ≈ 8 bit。差 > 0.3 bit 视为可疑。
        if (sa.entropy - sb.entropy).abs() > 0.3 {
            println!("🔴 字节熵差异大: 真={:.2} 我们={:.2} bit/byte", sa.entropy, sb.entropy);
            flags += 1;
        } else {
            println!("✅ 字节熵接近: 真={:.2} 我们={:.2} bit/byte (均匀随机理论值 8.0)", sa.entropy, sb.entropy);
        }
        // 每字节位置的均值: 均匀随机各位置应 ≈ 127.5。某位置系统性偏离 = 有结构。
        let max_pos_dev = sa.pos_means.iter().zip(&sb.pos_means)
            .map(|(x, y)| (x - y).abs()).fold(0.0f64, f64::max);
        if max_pos_dev > 40.0 {
            println!("🔴 某字节位置均值偏差 {:.0} > 40 (可能有固定结构)", max_pos_dev);
            flags += 1;
        } else {
            println!("✅ 各字节位置均值最大偏差 {:.0} (< 40, 无明显固定结构)", max_pos_dev);
        }
        println!("\n{}", if flags == 0 {
            "结论: 在长度/熵/逐位置均值三个维度上**不可区分** —— session_id 层面我们与真 Chrome 一致。"
        } else {
            "结论: 存在可区分维度 (上面 🔴), session_id 可能成为指纹。"
        });
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
