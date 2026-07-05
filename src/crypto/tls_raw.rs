//! TLS 1.3 ClientHello 构造 —— byte-exact 模拟真实 Chromium 150 (Chrome/Edge).
//!
//! v0.4.5-alpha.11: 彻底重写. 旧版三浏览器 (Chrome/FF/Safari) 是 2019 年老指纹
//! (缺 ChaCha, 有假 00ff cipher, 缺现代扩展), JA3/JA4 匹配不上任何真实浏览器,
//! 反而成为独有可识别特征. 现按真实抓包 (Edge 150.0.4078 / Chrome 150.0.7871,
//! 均 Chromium 150) 精确复刻:
//!   - 15 cipher (含 cca9/cca8 ChaCha), 无假 00ff
//!   - 后量子 key_share X25519MLKEM768 (0x11ec, 1216B) + X25519 —— 2024+ Chromium
//!     默认, 使 ClientHello 达 ~1786B (旧版才 ~550B, 光大小就能区分)
//!   - ECH GREASE (fe0d) / ALPS (44cd) / cert_compress brotli (001b) / SCT (0012)
//!   - 扩展每连接随机洗牌 (GREASE 首尾固定), 复刻 Chrome 110+ 行为
//!   - 动态字段: client_random / session_id (塞 Poly1305 token) / SNI /
//!     key_share 公钥 / ECH enc / 各槽 GREASE 值 每连接随机
//!
//! 验证: 生成的 ClientHello JA4 = t13d1516h2_8daaf6152771_806a8c22fdea, 跟真实
//! Chromium 150 完全一致 (见 tests / dump_tls).
//!
//! TODO(v2): 增加 Android OkHttp profile (稳定指纹, SNI 灵活) 做多样性.

use rand::RngExt;

const GREASE_VALUES: &[u16] = &[
    0x0A0A, 0x1A1A, 0x2A2A, 0x3A3A, 0x4A4A, 0x5A5A, 0x6A6A, 0x7A7A,
    0x8A8A, 0x9A9A, 0xAAAA, 0xBABA, 0xCACA, 0xDADA, 0xEAEA, 0xFAFA,
];

fn get_grease() -> u16 {
    let mut rng = rand::rng();
    GREASE_VALUES[rng.random_range(0..GREASE_VALUES.len())]
}

// ── Chromium 150 固定参数 (从真实抓包提取) ──────────────────────────────────

/// 15 个 cipher suite (GREASE 在运行时前置). 顺序即真实 Chromium 广播顺序.
const CHROMIUM_CIPHERS: [u16; 15] = [
    0x1301, 0x1302, 0x1303, 0xC02B, 0xC02F, 0xC02C, 0xC030, 0xCCA9, 0xCCA8,
    0xC013, 0xC014, 0x009C, 0x009D, 0x002F, 0x0035,
];

/// supported_groups (0x000a) GREASE 之后的曲线: X25519MLKEM768, X25519, P256, P384.
const CHROMIUM_GROUPS: [u16; 4] = [0x11EC, 0x001D, 0x0017, 0x0018];

/// signature_algorithms (0x000d) 完整内容 (含 2B 列表长度前缀), 11 个算法.
const SIGALGS: &[u8] = &[
    0x00, 0x16, 0x09, 0x04, 0x09, 0x05, 0x09, 0x06, 0x04, 0x03, 0x08, 0x04,
    0x04, 0x01, 0x05, 0x03, 0x08, 0x05, 0x05, 0x01, 0x08, 0x06, 0x06, 0x01,
];

/// ALPN (0x0010): h2, http/1.1.
const ALPN: &[u8] = &[
    0x00, 0x0c, 0x02, b'h', b'2', 0x08, b'h', b't', b't', b'p', b'/', b'1', b'.', b'1',
];

/// application_settings ALPS (0x44cd): h2.
const ALPS: &[u8] = &[0x00, 0x03, 0x02, b'h', b'2'];

/// compress_certificate (0x001b): brotli (0x0002).
const CERT_COMPRESS: &[u8] = &[0x02, 0x00, 0x02];

/// status_request (0x0005): OCSP, 空 responder/extensions.
const STATUS_REQUEST: &[u8] = &[0x01, 0x00, 0x00, 0x00, 0x00];

/// ec_point_formats (0x000b): uncompressed.
const EC_POINT_FORMATS: &[u8] = &[0x01, 0x00];

/// psk_key_exchange_modes (0x002d): psk_dhe_ke.
const PSK_MODES: &[u8] = &[0x01, 0x01];

/// X25519MLKEM768 (0x11ec) 混合 key_share 值长度 = ML-KEM-768 ek (1184) + X25519 (32).
const HYBRID_KEYSHARE_LEN: usize = 1216;
/// ML-KEM-768 encapsulation key 长度.
const MLKEM768_EK_LEN: usize = 1184;

/// 生成一个**结构合法**的 ML-KEM-768 encapsulation key (1184 字节).
///
/// 真实 TLS 服务器 (Chrome camouflage 转发的对端) 会对 ML-KEM ek 做 FIPS 203 §7.2
/// 模数校验: ByteDecode_12 对 12-bit 系数取 mod q (q=3329), 要求 ByteEncode_12∘
/// ByteDecode_12 幂等 —— 即所有系数必须 < q. 纯随机字节约 19%/系数 会 ≥ q 导致
/// round-trip 失败, 服务器回 illegal_parameter 拒绝整个 ClientHello.
///
/// 这里把 768 个系数取在 [0, q) 后按 Kyber 12-bit 小端打包 (2 系数 → 3 字节),
/// 得到通过模数校验的合法 ek. 因为 Mirage 只借 ServerHello 不做真密钥派生, ek
/// 无需对应真实私钥 —— 服务器 encapsulate against 它能成功即可. 每连接新生成
/// (复刻真实 Chrome 每连接新密钥, 避免固定 key 成为指纹).
fn mlkem768_valid_encap_key() -> [u8; MLKEM768_EK_LEN] {
    const Q: u16 = 3329;
    let mut ek = [0u8; MLKEM768_EK_LEN];
    let mut rng = rand::rng();
    // 3 个多项式 × 256 系数 = 768 系数, 12-bit 打包 = 1152 字节
    let mut o = 0;
    for _ in 0..384 {
        let c0 = rng.random_range(0u16..Q);
        let c1 = rng.random_range(0u16..Q);
        ek[o] = (c0 & 0xff) as u8;
        ek[o + 1] = (((c0 >> 8) & 0x0f) as u8) | (((c1 & 0x0f) as u8) << 4);
        ek[o + 2] = ((c1 >> 4) & 0xff) as u8;
        o += 3;
    }
    // 32 字节 rho (任意)
    rand::fill(&mut ek[1152..MLKEM768_EK_LEN]);
    ek
}

// ── 通用序列化 helper ──────────────────────────────────────────────────────

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

// ── Chromium 150 专属扩展构造 ───────────────────────────────────────────────

/// supported_versions (0x002b): [len=6][GREASE][TLS1.3][TLS1.2].
fn supported_versions_ext(grease_val: u16) -> Vec<u8> {
    let mut d = Vec::with_capacity(7);
    d.push(6);
    d.extend_from_slice(&grease_val.to_be_bytes());
    d.extend_from_slice(&0x0304u16.to_be_bytes());
    d.extend_from_slice(&0x0303u16.to_be_bytes());
    ext(0x002b, &d)
}

/// supported_groups (0x000a): GREASE + X25519MLKEM768/X25519/P256/P384.
fn supported_groups_ext(grease_val: u16) -> Vec<u8> {
    let mut g = Vec::new();
    g.extend_from_slice(&grease_val.to_be_bytes());
    for &grp in &CHROMIUM_GROUPS {
        g.extend_from_slice(&grp.to_be_bytes());
    }
    let mut data = Vec::with_capacity(2 + g.len());
    data.extend_from_slice(&(g.len() as u16).to_be_bytes());
    data.extend_from_slice(&g);
    ext(0x000a, &data)
}

/// key_share (0x0033): GREASE(1B) + X25519MLKEM768(1216B 随机) + X25519(32B 随机).
/// 公钥随机 —— Mirage 不做真 TLS 密钥派生, camouflage 转发时对端也只看结构.
fn key_share_ext(grease_val: u16) -> Vec<u8> {
    let mut list = Vec::with_capacity(HYBRID_KEYSHARE_LEN + 64);
    // GREASE 曲线, 1 字节占位 key
    list.extend_from_slice(&grease_val.to_be_bytes());
    list.extend_from_slice(&1u16.to_be_bytes());
    list.push(0x00);
    // X25519MLKEM768 (0x11ec) 混合: ML-KEM-768 ek (1184 合法) || X25519 (32 随机)
    list.extend_from_slice(&0x11ECu16.to_be_bytes());
    list.extend_from_slice(&(HYBRID_KEYSHARE_LEN as u16).to_be_bytes());
    list.extend_from_slice(&mlkem768_valid_encap_key());
    let mut x_hybrid = [0u8; 32];
    rand::fill(&mut x_hybrid);
    list.extend_from_slice(&x_hybrid);
    // 纯 X25519 (0x001d)
    let mut x25519 = [0u8; 32];
    rand::fill(&mut x25519);
    list.extend_from_slice(&0x001Du16.to_be_bytes());
    list.extend_from_slice(&32u16.to_be_bytes());
    list.extend_from_slice(&x25519);

    let mut data = Vec::with_capacity(2 + list.len());
    data.extend_from_slice(&(list.len() as u16).to_be_bytes());
    data.extend_from_slice(&list);
    ext(0x0033, &data)
}

/// encrypted_client_hello GREASE (0xfe0d): type=outer, HKDF-SHA256/AES-128-GCM,
/// 随机 config_id + 32B enc + 208B payload = 250B (匹配真实 Chromium). GREASE ECH
/// 是伪造的, censor 无法校验加密内容, 随机字节即可.
fn ech_grease_ext() -> Vec<u8> {
    let mut c = Vec::with_capacity(250);
    c.push(0x00); // ECHClientHelloType.outer
    c.extend_from_slice(&0x0001u16.to_be_bytes()); // kdf_id = HKDF-SHA256
    c.extend_from_slice(&0x0001u16.to_be_bytes()); // aead_id = AES-128-GCM
    let mut cid = [0u8; 1];
    rand::fill(&mut cid);
    c.push(cid[0]); // config_id 随机
    c.extend_from_slice(&32u16.to_be_bytes()); // enc_len
    let mut enc = [0u8; 32];
    rand::fill(&mut enc);
    c.extend_from_slice(&enc);
    const PAYLOAD_LEN: usize = 208;
    c.extend_from_slice(&(PAYLOAD_LEN as u16).to_be_bytes());
    let mut payload = [0u8; PAYLOAD_LEN];
    rand::fill(&mut payload[..]);
    c.extend_from_slice(&payload);
    ext(0xfe0d, &c)
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
    record.extend_from_slice(b"\x16\x03\x01"); // Handshake, TLS 1.0 (兼容)
    record.extend_from_slice(&(hs.len() as u16).to_be_bytes());
    record.extend_from_slice(&hs);
    record
}

/// 构造 Chromium 150 ClientHello. 扩展中段每连接随机洗牌 (GREASE 首尾固定),
/// 复刻真实 Chrome 110+ 的 per-connection 洗牌行为.
pub fn build_chromium(sni_bytes: &[u8], session_id: &[u8], client_random: &[u8]) -> Vec<u8> {
    // ciphers: GREASE + 15 固定
    let cipher_grease = get_grease();
    let mut ciphers = Vec::with_capacity(32);
    ciphers.extend_from_slice(&cipher_grease.to_be_bytes());
    for &c in &CHROMIUM_CIPHERS {
        ciphers.extend_from_slice(&c.to_be_bytes());
    }

    // 各槽独立随机 GREASE 值 (JA3/JA4 排除 GREASE, 值不影响指纹哈希, 只需合法)
    let g_sv = get_grease();
    let g_groups = get_grease();
    let g_ks = get_grease();

    // 16 个中段扩展 (JA4 计 16 个非 GREASE 扩展)
    let mut middle: Vec<Vec<u8>> = vec![
        supported_versions_ext(g_sv),
        ech_grease_ext(),
        ext(0x000b, EC_POINT_FORMATS),
        ext(0x0017, b""),                 // extended_master_secret
        supported_groups_ext(g_groups),
        ext(0x002d, PSK_MODES),
        ext(0x0023, b""),                 // session_ticket
        ext(0xff01, b"\x00"),             // renegotiation_info
        ext(0x0010, ALPN),
        ext(0x0005, STATUS_REQUEST),
        ext(0x0012, b""),                 // signed_certificate_timestamp
        sni_ext(sni_bytes),
        ext(0x44cd, ALPS),
        ext(0x000d, SIGALGS),
        key_share_ext(g_ks),
        ext(0x001b, CERT_COMPRESS),
    ];

    // Fisher-Yates 洗牌中段 (首尾 GREASE 扩展不参与, 保持 Chrome 的书挡结构)
    let mut rng = rand::rng();
    for i in (1..middle.len()).rev() {
        let j = rng.random_range(0..=i);
        middle.swap(i, j);
    }

    // 首尾 GREASE 扩展的 type 必须不同 —— 否则重复扩展类型, 真实 TLS 服务器会
    // 回 illegal_parameter 拒绝 (真实 Chrome 也用两个不同 GREASE 值做书挡).
    let g_first = get_grease();
    let mut g_last = get_grease();
    while g_last == g_first {
        g_last = get_grease();
    }
    let mut exts = Vec::new();
    exts.extend_from_slice(&ext(g_first, b"")); // 首 GREASE 扩展 (空)
    for m in &middle {
        exts.extend_from_slice(m);
    }
    exts.extend_from_slice(&ext(g_last, b"\x00")); // 尾 GREASE 扩展 (1B)

    assemble(session_id, client_random, &ciphers, &exts)
}

/// 生成 ClientHello + client_random. session_id 携带 Mirage 的 Poly1305 认证
/// token (Chromium 也用 32B session_id, 完美契合).
pub fn build_client_hello(server_name: &str, session_id: &[u8; 32]) -> (Vec<u8>, [u8; 32]) {
    let mut client_random = [0u8; 32];
    rand::fill(&mut client_random);
    let record = build_chromium(server_name.as_bytes(), session_id, &client_random);
    (record, client_random)
}

pub fn build_fake_client_tail() -> Vec<u8> {
    // 尾巴 body 53B 匹配真实 TLS 1.3 Client Finished (ChaCha20-Poly1305 + SHA-256
    // HMAC): 4B handshake header + 32B HMAC digest + 1B content_type + 16B AEAD tag.
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
