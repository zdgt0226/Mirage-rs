//! Shadowsocks 2022 (SIP022) 互通验证。
//!
//! 服务端侧的**加解密**用 `shadowsocks-crypto`(成熟的第三方实现, dev-dependency,
//! 不进发布二进制)。这样密钥派生与 AEAD 这一层是真正独立的 —— 被测代码若把
//! BLAKE3 context、key_material 顺序、nonce 递进任何一处搞错, 这里都解不开。
//!
//! ⚠️ 诚实的边界: 帧结构(定长头/变长头布局)两侧都出自同一份规范解读, 因此本测试
//! **不能**证明帧结构与真实 SS2022 服务器互通, 只能证明"加解密层正确 + 我方收发自洽"。
//! 真正的互通结论需要对着一台真实的 SS2022 服务器验证。

use shadowsocks_crypto::v2::tcp::TcpCipher;
use shadowsocks_crypto::CipherKind;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

const TAG: usize = 16;
const KLEN: usize = 32; // 2022-blake3-aes-256-gcm

/// 读满 n 字节。
async fn rdn(s: &mut tokio::net::TcpStream, n: usize) -> std::io::Result<Vec<u8>> {
    let mut b = vec![0u8; n];
    s.read_exact(&mut b).await?;
    Ok(b)
}

/// 最小 SS2022 服务端。解出目标地址与首段载荷, 回一段下行, 通过 channel 报给测试。
async fn spawn_2022_server(
    psk: Vec<u8>,
    downlink: &'static [u8],
) -> (u16, tokio::sync::oneshot::Receiver<(Vec<u8>, Vec<u8>)>) {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = l.local_addr().unwrap().port();
    let (tx, rx) = tokio::sync::oneshot::channel();

    tokio::spawn(async move {
        let (mut s, _) = l.accept().await.unwrap();
        let kind = CipherKind::AEAD2022_BLAKE3_AES_256_GCM;

        // ── 收请求 ──
        let req_salt = rdn(&mut s, KLEN).await.unwrap();
        // 解密用参考实现的 cipher (独立于被测代码)
        let mut dec = TcpCipher::new(kind, &psk, &req_salt);

        // 定长头: 类型(1) + 时间戳(8) + 变长头长度(2) = 11, 加 tag
        let mut fixed = rdn(&mut s, 11 + TAG).await.unwrap();
        assert!(dec.decrypt_packet(&mut fixed), "定长头解密失败 —— 密钥派生对不上");
        assert_eq!(fixed[0], 0, "请求类型应为 0 (client stream)");
        let ts = u64::from_be_bytes(fixed[1..9].try_into().unwrap());
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
        assert!(now.abs_diff(ts) <= 30, "时间戳应在 ±30s 内, 实际差 {}", now.abs_diff(ts));
        let vlen = u16::from_be_bytes(fixed[9..11].try_into().unwrap()) as usize;

        // 变长头: 目标地址 + padding 长度 + padding + 首段载荷
        let mut var = rdn(&mut s, vlen + TAG).await.unwrap();
        assert!(dec.decrypt_packet(&mut var), "变长头解密失败");
        let var = &var[..vlen];

        // 解地址 (SOCKS5 格式)
        let (addr_bytes, rest) = match var[0] {
            1 => (var[..7].to_vec(), &var[7..]),
            3 => {
                let dl = var[1] as usize;
                (var[..2 + dl + 2].to_vec(), &var[2 + dl + 2..])
            }
            4 => (var[..19].to_vec(), &var[19..]),
            other => panic!("未知 ATYP {other}"),
        };
        let pad_len = u16::from_be_bytes(rest[..2].try_into().unwrap()) as usize;
        let initial = rest[2 + pad_len..].to_vec();

        // ── 回响应 ──
        let resp_salt = vec![0x33u8; KLEN];
        s.write_all(&resp_salt).await.unwrap();
        let mut enc = TcpCipher::new(kind, &psk, &resp_salt);

        // 定长头: 类型=1 + 时间戳 + **回显请求 salt** + 载荷长度
        let mut hdr = Vec::new();
        hdr.push(1u8);
        hdr.extend_from_slice(&now.to_be_bytes());
        hdr.extend_from_slice(&req_salt);
        hdr.extend_from_slice(&(downlink.len() as u16).to_be_bytes());
        hdr.resize(hdr.len() + TAG, 0);
        enc.encrypt_packet(&mut hdr);
        s.write_all(&hdr).await.unwrap();

        let mut body = downlink.to_vec();
        body.resize(body.len() + TAG, 0);
        enc.encrypt_packet(&mut body);
        s.write_all(&body).await.unwrap();
        s.flush().await.unwrap();

        let _ = tx.send((addr_bytes, initial));
        tokio::time::sleep(std::time::Duration::from_secs(5)).await;
    });
    (port, rx)
}

fn psk_b64(psk: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(psk)
}

#[tokio::test]
async fn ss2022_crypto_interops_with_reference_cipher() {
    const DOWN: &[u8] = b"HTTP/1.1 200 OK\r\n\r\nfrom-2022-upstream";
    let psk = vec![0x9Au8; KLEN];
    let (port, rx) = spawn_2022_server(psk.clone(), DOWN).await;

    let cfg = mirage_rs::proxy::shadowsocks::SsConfig {
        server: "127.0.0.1".into(),
        port,
        password: psk_b64(&psk),
        method: mirage_rs::proxy::shadowsocks::Method::parse("2022-blake3-aes-256-gcm").unwrap(),
        block_udp: true,
    };

    let (mut r, _w, _fd) = mirage_rs::proxy::shadowsocks::connect(&cfg, "example.com:443")
        .await
        .expect("SS2022 连接失败");

    // 服务端能解出正确的目标地址 → 说明密钥派生 + 定长/变长头都对
    let (addr, _initial) = tokio::time::timeout(std::time::Duration::from_secs(5), rx)
        .await.expect("等服务端超时").unwrap();
    let mut want = vec![0x03, 11];
    want.extend_from_slice(b"example.com");
    want.extend_from_slice(&443u16.to_be_bytes());
    assert_eq!(addr, want, "目标地址必须正确送达上游");

    // 下行必须能被我方正确解密 (含响应头的 salt 回显校验)
    let got = tokio::time::timeout(std::time::Duration::from_secs(5), r.read_chunk())
        .await.expect("读下行超时").unwrap();
    assert_eq!(got, DOWN, "下行数据必须正确解密");
}

#[tokio::test]
async fn ss2022_wrong_psk_fails() {
    const DOWN: &[u8] = b"secret";
    let (port, _rx) = spawn_2022_server(vec![0x11u8; KLEN], DOWN).await;

    let cfg = mirage_rs::proxy::shadowsocks::SsConfig {
        server: "127.0.0.1".into(),
        port,
        password: psk_b64(&vec![0x22u8; KLEN]), // 与服务端不同
        method: mirage_rs::proxy::shadowsocks::Method::parse("2022-blake3-aes-256-gcm").unwrap(),
        block_udp: true,
    };
    // 连接本身能建立 (TCP 层), 但服务端解不开我们的头 → 我们也读不到有效下行
    match mirage_rs::proxy::shadowsocks::connect(&cfg, "example.com:443").await {
        Ok((mut r, _w, _fd)) => {
            let res = tokio::time::timeout(std::time::Duration::from_secs(3), r.read_chunk()).await;
            if let Ok(Ok(v)) = res {
                assert!(v.is_empty(), "PSK 不匹配却解出了数据: {v:?}");
            }
        }
        Err(_) => {} // 连接阶段就失败也是可接受的拒绝方式
    }
}

#[tokio::test]
async fn ss2022_psk_length_is_enforced() {
    // 16 字节 PSK 配 aes-256 (要求 32) 必须在连接前就报错, 而不是静默截断/补齐 ——
    // 后者会得到两端不一致的密钥, 表现为"连上但全解不开", 错误信息完全指不到根因。
    let cfg = mirage_rs::proxy::shadowsocks::SsConfig {
        server: "127.0.0.1".into(),
        port: 1,
        password: psk_b64(&vec![0u8; 16]),
        method: mirage_rs::proxy::shadowsocks::Method::parse("2022-blake3-aes-256-gcm").unwrap(),
        block_udp: true,
    };
    let e = match mirage_rs::proxy::shadowsocks::connect(&cfg, "h:1").await {
        Err(e) => e.to_string(),
        Ok(_) => panic!("PSK 长度不符必须报错, 却连接成功了"),
    };
    assert!(e.contains("16 字节") && e.contains("32 字节"), "实际: {e}");
}
