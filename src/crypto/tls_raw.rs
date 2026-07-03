use rand::seq::IndexedRandom;
use rand::RngExt;

const GREASE_VALUES: &[u16] = &[
    0x0A0A, 0x1A1A, 0x2A2A, 0x3A3A, 0x4A4A, 0x5A5A, 0x6A6A, 0x7A7A,
    0x8A8A, 0x9A9A, 0xAAAA, 0xBABA, 0xCACA, 0xDADA, 0xEAEA, 0xFAFA,
];

fn get_grease() -> u16 {
    let mut rng = rand::rng();
    *GREASE_VALUES.choose(&mut rng).unwrap()
}

fn ext(ext_type: u16, data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + data.len());
    out.extend_from_slice(&ext_type.to_be_bytes());
    out.extend_from_slice(&(data.len() as u16).to_be_bytes());
    out.extend_from_slice(data);
    out
}

fn sni_ext(sni_bytes: &[u8]) -> Vec<u8> {
    let mut entry = Vec::with_capacity(3 + sni_bytes.len());
    entry.push(0); // name_type = host_name
    entry.extend_from_slice(&(sni_bytes.len() as u16).to_be_bytes());
    entry.extend_from_slice(sni_bytes);

    let mut data = Vec::with_capacity(2 + entry.len());
    data.extend_from_slice(&(entry.len() as u16).to_be_bytes());
    data.extend_from_slice(&entry);

    ext(0x0000, &data)
}

fn alpn_ext() -> Vec<u8> {
    let protos = b"\x02h2\x08http/1.1";
    let mut data = Vec::with_capacity(2 + protos.len());
    data.extend_from_slice(&(protos.len() as u16).to_be_bytes());
    data.extend_from_slice(protos);
    ext(0x0010, &data)
}

fn key_share_ext(grease_val: Option<u16>) -> Vec<u8> {
    let mut eph_pub = [0u8; 32];
    rand::fill(&mut eph_pub);
    
    let mut x25519_ks = Vec::with_capacity(36);
    x25519_ks.extend_from_slice(&0x001Du16.to_be_bytes());
    x25519_ks.extend_from_slice(&32u16.to_be_bytes());
    x25519_ks.extend_from_slice(&eph_pub);

    let mut ks_list = Vec::new();
    if let Some(gv) = grease_val {
        let mut grease_ks = Vec::with_capacity(5);
        grease_ks.extend_from_slice(&gv.to_be_bytes());
        grease_ks.extend_from_slice(&1u16.to_be_bytes());
        grease_ks.push(0);
        ks_list.extend_from_slice(&grease_ks);
    }
    ks_list.extend_from_slice(&x25519_ks);

    let mut data = Vec::with_capacity(2 + ks_list.len());
    data.extend_from_slice(&(ks_list.len() as u16).to_be_bytes());
    data.extend_from_slice(&ks_list);
    ext(0x0033, &data)
}

fn assemble(session_id: &[u8], client_random: &[u8], cipher_suites: &[u8], extensions: &[u8]) -> Vec<u8> {
    let mut hello_body = Vec::new();
    hello_body.extend_from_slice(b"\x03\x03");
    hello_body.extend_from_slice(client_random);
    hello_body.push(session_id.len() as u8);
    hello_body.extend_from_slice(session_id);
    hello_body.extend_from_slice(&(cipher_suites.len() as u16).to_be_bytes());
    hello_body.extend_from_slice(cipher_suites);
    hello_body.extend_from_slice(b"\x01\x00"); // compression methods
    hello_body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
    hello_body.extend_from_slice(extensions);

    let mut hs = Vec::new();
    hs.push(0x01); // HandshakeType.client_hello
    let body_len = hello_body.len() as u32;
    hs.extend_from_slice(&body_len.to_be_bytes()[1..]); // 24-bit length
    hs.extend_from_slice(&hello_body);

    let mut record = Vec::new();
    record.extend_from_slice(b"\x16\x03\x01"); // Handshake, TLS 1.0
    record.extend_from_slice(&(hs.len() as u16).to_be_bytes());
    record.extend_from_slice(&hs);
    record
}

pub fn build_chrome(sni_bytes: &[u8], session_id: &[u8], client_random: &[u8]) -> Vec<u8> {
    let gv = get_grease();
    let mut ciphers = Vec::new();
    for c in &[gv, 0x1301u16, 0x1302, 0x1303, 0xC02B, 0xC02F, 0xC02C, 0xC030, 0x009C, 0x00FF] {
        ciphers.extend_from_slice(&c.to_be_bytes());
    }
    
    let mut groups = Vec::new();
    for g in &[gv, 0x001Du16, 0x0017, 0x0018] {
        groups.extend_from_slice(&g.to_be_bytes());
    }
    let mut groups_ext = Vec::new();
    groups_ext.extend_from_slice(&(groups.len() as u16).to_be_bytes());
    groups_ext.extend_from_slice(&groups);

    let mut sigalgs = Vec::new();
    for s in &[0x0403u16, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601, 0x0201] {
        sigalgs.extend_from_slice(&s.to_be_bytes());
    }
    let mut sigalgs_ext = Vec::new();
    sigalgs_ext.extend_from_slice(&(sigalgs.len() as u16).to_be_bytes());
    sigalgs_ext.extend_from_slice(&sigalgs);

    let mut exts = Vec::new();
    exts.extend_from_slice(&ext(gv, b"\x00"));
    exts.extend_from_slice(&sni_ext(sni_bytes));
    exts.extend_from_slice(&ext(0x0017, b""));
    exts.extend_from_slice(&ext(0xFF01, b"\x00"));
    exts.extend_from_slice(&ext(0x000A, &groups_ext));
    exts.extend_from_slice(&ext(0x000B, b"\x01\x00"));
    exts.extend_from_slice(&ext(0x0023, b""));
    exts.extend_from_slice(&ext(0x0005, b"\x01\x00\x00\x00\x00"));
    exts.extend_from_slice(&alpn_ext());
    exts.extend_from_slice(&ext(0x000D, &sigalgs_ext));
    exts.extend_from_slice(&key_share_ext(Some(gv)));
    exts.extend_from_slice(&ext(0x002D, b"\x01\x01"));
    exts.extend_from_slice(&ext(0x002B, b"\x04\x03\x04\x03\x03"));
    exts.extend_from_slice(&ext(gv, b"\x00"));

    assemble(session_id, client_random, &ciphers, &exts)
}

pub fn build_firefox(sni_bytes: &[u8], session_id: &[u8], client_random: &[u8]) -> Vec<u8> {
    let mut ciphers = Vec::new();
    for c in &[0x1301u16, 0x1303, 0x1302, 0xC02B, 0xC02F, 0xCCA9, 0xCCA8, 0xC02C, 0xC030, 0xC009, 0xC013, 0x009C] {
        ciphers.extend_from_slice(&c.to_be_bytes());
    }
    
    let mut groups = Vec::new();
    for g in &[0x001Du16, 0x0017, 0x0018, 0x0019, 0x0100, 0x0101] {
        groups.extend_from_slice(&g.to_be_bytes());
    }
    let mut groups_ext = Vec::new();
    groups_ext.extend_from_slice(&(groups.len() as u16).to_be_bytes());
    groups_ext.extend_from_slice(&groups);

    let mut sigalgs = Vec::new();
    for s in &[0x0403u16, 0x0503, 0x0603, 0x0804, 0x0805, 0x0806, 0x0401, 0x0501, 0x0601, 0x0201, 0x0203] {
        sigalgs.extend_from_slice(&s.to_be_bytes());
    }
    let mut sigalgs_ext = Vec::new();
    sigalgs_ext.extend_from_slice(&(sigalgs.len() as u16).to_be_bytes());
    sigalgs_ext.extend_from_slice(&sigalgs);

    let mut exts = Vec::new();
    exts.extend_from_slice(&sni_ext(sni_bytes));
    exts.extend_from_slice(&ext(0x0017, b""));
    exts.extend_from_slice(&ext(0xFF01, b"\x00"));
    exts.extend_from_slice(&ext(0x000A, &groups_ext));
    exts.extend_from_slice(&ext(0x000B, b"\x01\x00"));
    exts.extend_from_slice(&ext(0x0023, b""));
    exts.extend_from_slice(&alpn_ext());
    exts.extend_from_slice(&ext(0x0005, b"\x01\x00\x00\x00\x00"));
    exts.extend_from_slice(&ext(0x000D, &sigalgs_ext));
    exts.extend_from_slice(&key_share_ext(None));
    exts.extend_from_slice(&ext(0x002D, b"\x01\x01"));
    exts.extend_from_slice(&ext(0x002B, b"\x04\x03\x04\x03\x03"));
    exts.extend_from_slice(&ext(0x001B, b"\x02\x00\x02"));
    exts.extend_from_slice(&ext(0x0031, b""));
    exts.extend_from_slice(&ext(0x001C, b"\x40\x01"));

    assemble(session_id, client_random, &ciphers, &exts)
}

pub fn build_safari(sni_bytes: &[u8], session_id: &[u8], client_random: &[u8]) -> Vec<u8> {
    let mut ciphers = Vec::new();
    for c in &[0x1301u16, 0x1302, 0x1303, 0xC02C, 0xC02B, 0xC030, 0xC02F, 0xCCA9, 0xCCA8, 0xC024, 0xC023, 0xC00A, 0xC009, 0x009D, 0x009C] {
        ciphers.extend_from_slice(&c.to_be_bytes());
    }
    
    let mut groups = Vec::new();
    for g in &[0x001Du16, 0x0017, 0x0018, 0x0019] {
        groups.extend_from_slice(&g.to_be_bytes());
    }
    let mut groups_ext = Vec::new();
    groups_ext.extend_from_slice(&(groups.len() as u16).to_be_bytes());
    groups_ext.extend_from_slice(&groups);

    let mut sigalgs = Vec::new();
    for s in &[0x0403u16, 0x0804, 0x0401, 0x0503, 0x0603, 0x0805, 0x0806, 0x0501, 0x0601, 0x0203, 0x0201] {
        sigalgs.extend_from_slice(&s.to_be_bytes());
    }
    let mut sigalgs_ext = Vec::new();
    sigalgs_ext.extend_from_slice(&(sigalgs.len() as u16).to_be_bytes());
    sigalgs_ext.extend_from_slice(&sigalgs);

    let mut exts = Vec::new();
    exts.extend_from_slice(&ext(0xFF01, b"\x00"));
    exts.extend_from_slice(&sni_ext(sni_bytes));
    exts.extend_from_slice(&ext(0x0017, b""));
    exts.extend_from_slice(&ext(0x0023, b""));
    exts.extend_from_slice(&ext(0x000D, &sigalgs_ext));
    exts.extend_from_slice(&ext(0x0005, b"\x01\x00\x00\x00\x00"));
    exts.extend_from_slice(&alpn_ext());
    exts.extend_from_slice(&ext(0x000A, &groups_ext));
    exts.extend_from_slice(&ext(0x000B, b"\x01\x00"));
    exts.extend_from_slice(&ext(0x001B, b"\x04\x00\x01\x00\x02"));
    exts.extend_from_slice(&ext(0x0031, b""));
    exts.extend_from_slice(&key_share_ext(None));
    exts.extend_from_slice(&ext(0x002D, b"\x01\x01"));
    exts.extend_from_slice(&ext(0x002B, b"\x04\x03\x04\x03\x03"));

    assemble(session_id, client_random, &ciphers, &exts)
}

pub fn build_client_hello(server_name: &str, session_id: &[u8; 32]) -> (Vec<u8>, [u8; 32]) {
    let mut client_random = [0u8; 32];
    rand::fill(&mut client_random);
    let sni_bytes = server_name.as_bytes();
    
    let mut rng = rand::rng();
    let r: u8 = rng.random_range(0..3);
    
    let record = match r {
        0 => build_chrome(sni_bytes, session_id, &client_random),
        1 => build_firefox(sni_bytes, session_id, &client_random),
        _ => build_safari(sni_bytes, session_id, &client_random),
    };
    (record, client_random)
}

pub fn build_fake_client_tail() -> Vec<u8> {
    // v0.4.5-alpha.7: 尾巴 body 52 → 53 匹配真实 TLS 1.3 Client Finished 尺寸.
    // ChaCha20-Poly1305 + SHA-256 HMAC 时: 4B handshake header + 32B HMAC digest
    // + 1B content_type + 16B AEAD auth tag = 53B encrypted record body.
    // 老版 52B 差 1 字节, DPI histogram 大样本可识别.
    let ccs = b"\x14\x03\x03\x00\x01\x01";
    let mut finished_body = [0u8; 53];
    rand::fill(&mut finished_body);

    let mut record = Vec::with_capacity(ccs.len() + 5 + finished_body.len());
    record.extend_from_slice(ccs);
    record.extend_from_slice(b"\x17\x03\x03");
    record.extend_from_slice(&(finished_body.len() as u16).to_be_bytes());
    record.extend_from_slice(&finished_body);
    record
}
