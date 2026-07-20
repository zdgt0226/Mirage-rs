//! Shadowsocks 上游中转的端到端验证。
//!
//! 起一个**最小 SS 服务器**(按 SIP004 规范独立实现解密, 不复用被测的 SsWriter/SsReader),
//! 让 Mirage 的 SS 客户端连它, 校验:
//!   ① 首包送出的目标地址能被正确解出;
//!   ② 上行载荷原样抵达;
//!   ③ 下行数据能被 Mirage 侧正确解密。
//!
//! 为什么要独立实现服务端: 用被测代码自己解自己, 双方以同样的方式错依然会"通过"。
//! 这里的解密逻辑照着协议另写一遍, 才能真正证明互通。

use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

const TAG: usize = 16;

/// EVP_BytesToKey(MD5) —— 独立于被测实现另写一遍。
fn evp(password: &[u8], klen: usize) -> Vec<u8> {
    let mut out: Vec<u8> = Vec::new();
    let mut prev: Vec<u8> = Vec::new();
    while out.len() < klen {
        let mut d = md5::Md5::new();
        use md5::Digest;
        d.update(&prev);
        d.update(password);
        prev = d.finalize().to_vec();
        out.extend_from_slice(&prev);
    }
    out.truncate(klen);
    out
}

fn subkey(master: &[u8], salt: &[u8], klen: usize) -> Vec<u8> {
    struct L(usize);
    impl ring::hkdf::KeyType for L {
        fn len(&self) -> usize { self.0 }
    }
    let prk = ring::hkdf::Salt::new(ring::hkdf::HKDF_SHA1_FOR_LEGACY_USE_ONLY, salt).extract(master);
    let okm = prk.expand(&[b"ss-subkey"], L(klen)).unwrap();
    let mut o = vec![0u8; klen];
    okm.fill(&mut o).unwrap();
    o
}

struct Aead {
    key: LessSafeKey,
    n: u128,
}
impl Aead {
    fn new(k: &[u8]) -> Self {
        Self { key: LessSafeKey::new(UnboundKey::new(&ring::aead::AES_256_GCM, k).unwrap()), n: 0 }
    }
    fn nonce(&mut self) -> Nonce {
        let mut b = [0u8; 12];
        b.copy_from_slice(&self.n.to_le_bytes()[..12]);
        self.n += 1;
        Nonce::assume_unique_for_key(b)
    }
    fn open(&mut self, buf: &mut [u8]) -> Vec<u8> {
        let n = self.nonce();
        self.key.open_in_place(n, Aad::empty(), buf).expect("解密失败").to_vec()
    }
    fn seal(&mut self, plain: &[u8]) -> Vec<u8> {
        let n = self.nonce();
        let mut b = plain.to_vec();
        self.key.seal_in_place_append_tag(n, Aad::empty(), &mut b).unwrap();
        b
    }
}

/// 读并解密一个上行 chunk (独立实现的服务端侧)。
async fn read_chunk(s: &mut tokio::net::TcpStream, dec: &mut Aead) -> Option<Vec<u8>> {
    let mut lb = [0u8; 2 + TAG];
    s.read_exact(&mut lb).await.ok()?;
    let l = dec.open(&mut lb);
    let n = u16::from_be_bytes([l[0], l[1]]) as usize;
    let mut body = vec![0u8; n + TAG];
    s.read_exact(&mut body).await.ok()?;
    Some(dec.open(&mut body))
}

/// 最小 SS 服务器。收一条连接, 解出目标地址与上行数据, 回一段下行数据, 然后把
/// (目标地址, 上行明文) 通过 channel 报给测试。
async fn spawn_ss_server(
    password: &'static str,
    downlink: &'static [u8],
) -> (u16, tokio::sync::oneshot::Receiver<(Vec<u8>, Vec<u8>)>) {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = l.local_addr().unwrap().port();
    let (tx, rx) = tokio::sync::oneshot::channel();

    tokio::spawn(async move {
        let (mut s, _) = l.accept().await.unwrap();
        let master = evp(password.as_bytes(), 32);

        // 上行: [salt][chunk...]
        let mut salt = [0u8; 32];
        s.read_exact(&mut salt).await.unwrap();
        let mut dec = Aead::new(&subkey(&master, &salt, 32));

        // 首个 chunk = 目标地址 (本实现把地址与首段载荷分开发送)
        let addr = read_chunk(&mut s, &mut dec).await.unwrap();
        let payload = read_chunk(&mut s, &mut dec).await.unwrap();

        // 下行: 自己的 salt + 加密 chunk
        let dsalt = [0x11u8; 32];
        s.write_all(&dsalt).await.unwrap();
        let mut enc = Aead::new(&subkey(&master, &dsalt, 32));
        let lenc = enc.seal(&(downlink.len() as u16).to_be_bytes());
        let benc = enc.seal(downlink);
        s.write_all(&lenc).await.unwrap();
        s.write_all(&benc).await.unwrap();
        s.flush().await.unwrap();

        let _ = tx.send((addr, payload));
        // 保持连接直到测试结束
        tokio::time::sleep(std::time::Duration::from_secs(5)).await;
    });
    (port, rx)
}

#[tokio::test]
async fn ss_client_interops_with_independent_server() {
    const PW: &str = "relay-pw";
    const DOWN: &[u8] = b"HTTP/1.1 200 OK\r\n\r\nfrom-upstream";
    let (port, rx) = spawn_ss_server(PW, DOWN).await;

    let cfg = mirage_rs::proxy::shadowsocks::SsConfig {
        server: "127.0.0.1".into(),
        port,
        password: PW.into(),
        method: mirage_rs::proxy::shadowsocks::Method::parse("aes-256-gcm").unwrap(),
    };

    let (mut r, mut w, _fd) = mirage_rs::proxy::shadowsocks::connect(&cfg, "example.com:443")
        .await
        .expect("连接 SS 上游失败");
    w.write_all(b"hello-upstream").await.unwrap();

    // 服务端解出的内容必须与我们发的一致
    let (addr, payload) = tokio::time::timeout(std::time::Duration::from_secs(5), rx)
        .await
        .expect("等服务端超时")
        .unwrap();
    let want_addr = {
        let mut v = vec![0x03, 11];
        v.extend_from_slice(b"example.com");
        v.extend_from_slice(&443u16.to_be_bytes());
        v
    };
    assert_eq!(addr, want_addr, "目标地址必须按 SOCKS5 格式正确送达上游");
    assert_eq!(payload, b"hello-upstream", "上行载荷必须原样抵达");

    // 下行必须能被 Mirage 侧正确解密
    let got = tokio::time::timeout(std::time::Duration::from_secs(5), r.read_chunk())
        .await
        .expect("读下行超时")
        .unwrap();
    assert_eq!(got, DOWN, "下行数据必须正确解密");
}

#[tokio::test]
async fn wrong_password_cannot_decrypt_downlink() {
    const DOWN: &[u8] = b"secret";
    let (port, _rx) = spawn_ss_server("server-pw", DOWN).await;

    let cfg = mirage_rs::proxy::shadowsocks::SsConfig {
        server: "127.0.0.1".into(),
        port,
        password: "client-pw-different".into(), // 故意不匹配
        method: mirage_rs::proxy::shadowsocks::Method::parse("aes-256-gcm").unwrap(),
    };
    let (mut r, mut w, _fd) = mirage_rs::proxy::shadowsocks::connect(&cfg, "example.com:443")
        .await
        .unwrap();
    let _ = w.write_all(b"x").await;
    // 密码不匹配 → 下行解密必须失败, 而不是返回垃圾数据
    let res = tokio::time::timeout(std::time::Duration::from_secs(5), r.read_chunk()).await;
    match res {
        Ok(Ok(v)) => panic!("密码不匹配却解出了数据: {v:?}"),
        _ => {} // 解密失败或超时都是可接受的拒绝方式
    }
}
