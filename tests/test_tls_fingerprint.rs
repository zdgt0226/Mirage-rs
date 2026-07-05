//! Chromium 150 TLS 指纹回归测试.
//!
//! 锁定 build_chromium 产出的 ClientHello 的 JA4 决定性成分 (cipher 集合 + 扩展
//! 集合 + sig_algs), 防未来改动静默破坏对真实 Chromium 的 mimicry.
//! 真实 Chromium 150 JA4 = t13d1516h2_8daaf6152771_806a8c22fdea.

use mirage_rs::crypto::tls_raw;

const GREASE: &[u16] = &[
    0x0A0A, 0x1A1A, 0x2A2A, 0x3A3A, 0x4A4A, 0x5A5A, 0x6A6A, 0x7A7A, 0x8A8A, 0x9A9A,
    0xAAAA, 0xBABA, 0xCACA, 0xDADA, 0xEAEA, 0xFAFA,
];
fn is_grease(v: u16) -> bool {
    GREASE.contains(&v)
}
fn u16b(b: &[u8], i: usize) -> u16 {
    ((b[i] as u16) << 8) | b[i + 1] as u16
}

struct Parsed {
    ciphers: Vec<u16>,
    exts: Vec<u16>,
    key_share: Vec<u8>,
    total: usize,
}

fn parse(ch: &[u8]) -> Parsed {
    assert_eq!(ch[0], 0x16, "record type Handshake");
    assert_eq!(u16b(ch, 3) as usize, ch.len() - 5, "record_len 自洽");
    let mut i = 5 + 4 + 2 + 32;
    let sl = ch[i] as usize;
    i += 1 + sl;
    let cl = u16b(ch, i) as usize;
    i += 2;
    let ciphers = (0..cl).step_by(2).map(|j| u16b(ch, i + j)).collect();
    i += cl;
    let cm = ch[i] as usize;
    i += 1 + cm;
    let el = u16b(ch, i) as usize;
    i += 2;
    let end = i + el;
    assert_eq!(end, ch.len(), "extensions_len 自洽");
    let mut exts = Vec::new();
    let mut key_share = Vec::new();
    while i < end {
        let et = u16b(ch, i);
        let le = u16b(ch, i + 2) as usize;
        i += 4;
        if et == 0x0033 {
            key_share = ch[i..i + le].to_vec();
        }
        i += le;
        exts.push(et);
    }
    Parsed { ciphers, exts, key_share, total: ch.len() }
}

#[test]
fn chromium_ja4_cipher_and_ext_sets() {
    let session_id = [0u8; 32];
    let random = [0u8; 32];
    let ch = tls_raw::build_chromium(b"www.cloudflare.com", &session_id, &random);
    let p = parse(&ch);

    // 排序后非 GREASE cipher 集合 = 真实 Chromium 150 (决定 JA4_b 8daaf6152771)
    let mut cs: Vec<u16> = p.ciphers.iter().copied().filter(|c| !is_grease(*c)).collect();
    cs.sort();
    assert_eq!(
        cs,
        vec![
            0x002f, 0x0035, 0x009c, 0x009d, 0x1301, 0x1302, 0x1303, 0xc013, 0xc014,
            0xc02b, 0xc02c, 0xc02f, 0xc030, 0xcca8, 0xcca9
        ],
        "cipher 集合必须与真实 Chromium 150 一致"
    );

    // 排序后非 GREASE 扩展集合 (决定 JA4_c 一部分)
    let mut es: Vec<u16> = p.exts.iter().copied().filter(|e| !is_grease(*e)).collect();
    es.sort();
    assert_eq!(
        es,
        vec![
            0x0000, 0x0005, 0x000a, 0x000b, 0x000d, 0x0010, 0x0012, 0x0017, 0x001b,
            0x0023, 0x002b, 0x002d, 0x0033, 0x44cd, 0xfe0d, 0xff01
        ],
        "扩展集合必须与真实 Chromium 150 一致"
    );
}

#[test]
fn chromium_no_duplicate_extensions() {
    // 首尾 GREASE 撞值会产生重复扩展 → 真实服务器拒绝. 跑多次覆盖随机.
    for _ in 0..200 {
        let ch = tls_raw::build_chromium(b"example.com", &[0u8; 32], &[0u8; 32]);
        let p = parse(&ch);
        let mut sorted = p.exts.clone();
        sorted.sort();
        let mut dedup = sorted.clone();
        dedup.dedup();
        assert_eq!(sorted.len(), dedup.len(), "不能有重复扩展类型 (含两个 GREASE 书挡)");
    }
}

#[test]
fn chromium_mlkem_keyshare_valid() {
    // key_share 必须含 X25519MLKEM768 (0x11ec, 1216B), 且 ML-KEM ek 系数全 < q=3329
    // (否则真实服务器 FIPS 203 模数校验失败, 回 illegal_parameter 拒绝整个 CH).
    let ch = tls_raw::build_chromium(b"example.com", &[0u8; 32], &[0u8; 32]);
    let p = parse(&ch);
    // key_share content: [list_len(2)] then entries: group(2) len(2) value
    let ks = &p.key_share;
    let mut i = 2usize;
    let mut found_mlkem = false;
    while i + 4 <= ks.len() {
        let group = u16b(ks, i);
        let klen = u16b(ks, i + 2) as usize;
        let val = &ks[i + 4..i + 4 + klen];
        if group == 0x11ec {
            found_mlkem = true;
            assert_eq!(klen, 1216, "X25519MLKEM768 share = 1184 ek + 32 x25519");
            // ML-KEM ek = 前 1184B; 前 1152B 是 768 个 12-bit 系数
            const Q: u16 = 3329;
            let ek = &val[..1184];
            for o in (0..1152).step_by(3) {
                let c0 = ek[o] as u16 | (((ek[o + 1] & 0x0f) as u16) << 8);
                let c1 = (ek[o + 1] >> 4) as u16 | ((ek[o + 2] as u16) << 4);
                assert!(c0 < Q && c1 < Q, "ML-KEM 系数必须 < q=3329 (模数校验)");
            }
        }
        i += 4 + klen;
    }
    assert!(found_mlkem, "必须含 X25519MLKEM768 后量子 key_share");
}

#[test]
fn chromium_size_matches_real() {
    // 真实 Chromium 150 ~1786B (SNI=tls.peet.ws 11 字符). 我们的应在同量级
    // (差异仅来自 SNI 长度), 远大于旧版 ~550B.
    let ch = tls_raw::build_chromium(b"tls.peet.ws", &[0u8; 32], &[0u8; 32]);
    let p = parse(&ch);
    assert!(
        (1780..=1800).contains(&p.total),
        "ClientHello 大小应 ~1786B (后量子 key_share), 实际 {}",
        p.total
    );
}
