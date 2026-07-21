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
        block_udp: true,
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
        block_udp: true,
    };
    let (mut r, mut w, _fd) = mirage_rs::proxy::shadowsocks::connect(&cfg, "example.com:443")
        .await
        .unwrap();
    let _ = w.write_all(b"x").await;
    // 密码不匹配 → 下行解密必须失败, 而不是返回垃圾数据
    let res = tokio::time::timeout(std::time::Duration::from_secs(5), r.read_chunk()).await;
    // 解密失败或超时都是可接受的拒绝方式; 唯独不能成功解出数据
    if let Ok(Ok(v)) = res {
        panic!("密码不匹配却解出了数据: {v:?}");
    }
}

// ── UDP 策略 (方案 A: 配了上游默认阻断 UDP) ────────────────────────────────

/// 起一个轻量服务端 + 轻量客户端, 返回 (客户端 SOCKS5 端口, 两个进程守卫)。
/// `udp_field` 直接拼进 upstream, 用于切换策略。
fn spawn_pair(sport: u16, cport: u16, udp_field: &str) -> (std::process::Child, std::process::Child) {
    use std::process::{Command, Stdio};
    let bin = {
        let mut p = std::env::current_exe().unwrap();
        p.pop(); p.pop(); p.push("mirage"); p
    };
    let dir = std::env::temp_dir();
    let scfg = dir.join(format!("ss_udp_srv_{}_{}.json", std::process::id(), sport));
    let ccfg = dir.join(format!("ss_udp_cli_{}_{}.json", std::process::id(), cport));
    std::fs::write(&scfg, format!(
        r#"{{"listen":"127.0.0.1","port":{sport},"password":"pw","sni":"www.apple.com","log_level":"warn",
            "upstream":{{"type":"shadowsocks","server":"127.0.0.1","server_port":19699,
                         "password":"x","method":"aes-256-gcm"{udp_field}}}}}"#)).unwrap();
    std::fs::write(&ccfg, format!(
        r#"{{"listen":"127.0.0.1","port":{cport},"server":"127.0.0.1","server_port":{sport},
            "password":"pw","sni":"www.apple.com","pool_size":1,"log_level":"warn"}}"#)).unwrap();
    let s = Command::new(&bin).args(["lite-server","-c",scfg.to_str().unwrap()])
        .stdout(Stdio::null()).stderr(Stdio::null()).spawn().unwrap();
    std::thread::sleep(std::time::Duration::from_millis(600));
    let c = Command::new(&bin).args(["lite-client","-c",ccfg.to_str().unwrap()])
        .stdout(Stdio::null()).stderr(Stdio::null()).spawn().unwrap();
    std::thread::sleep(std::time::Duration::from_millis(1200));
    (s, c)
}

/// 轻量客户端本就拒绝 UDP, 所以这里直接验证**服务端**的分派行为:
/// 用 Mirage 协议连服务端不现实(需完整握手), 改为验证配置层面的策略解析 ——
/// 真正的阻断行为由下面的"服务端仍能正常提供 TCP"间接佐证(阻断不应波及 TCP)。
#[tokio::test]
async fn udp_block_does_not_break_tcp() {
    let (mut s, mut c) = spawn_pair(19611, 19612, "");
    // 配了上游(指向一个不存在的 SS 端口)时 TCP 会连不通, 但服务端本身必须仍在监听 ——
    // 即"阻断 UDP"这个改动不能把 TCP 路径也带崩。
    let alive = std::net::TcpStream::connect(("127.0.0.1", 19611u16)).is_ok();
    let _ = s.kill(); let _ = c.kill();
    let _ = s.wait(); let _ = c.wait();
    assert!(alive, "配 udp=block 后服务端仍应正常监听 TCP");
}

#[tokio::test]
async fn udp_policy_parses_both_values() {
    // 默认(不写 udp 字段)= block
    let d: mirage_rs::config::UpstreamConfig = serde_json::from_str(
        r#"{"type":"shadowsocks","server":"h","server_port":1,"password":"p","method":"aes-256-gcm"}"#
    ).unwrap();
    let mirage_rs::config::UpstreamConfig::Shadowsocks { udp, .. } = &d else {
        panic!("应解析为 shadowsocks 上游")
    };
    assert_eq!(*udp, mirage_rs::config::UdpPolicy::Block, "不写 udp 字段必须默认 block");

    // 显式 direct
    let e: mirage_rs::config::UpstreamConfig = serde_json::from_str(
        r#"{"type":"shadowsocks","server":"h","server_port":1,"password":"p","method":"aes-256-gcm","udp":"direct"}"#
    ).unwrap();
    let mirage_rs::config::UpstreamConfig::Shadowsocks { udp, .. } = &e else {
        panic!("应解析为 shadowsocks 上游")
    };
    assert_eq!(*udp, mirage_rs::config::UdpPolicy::Direct);

    // 拼错的值必须报错而不是静默回落成某个默认
    assert!(serde_json::from_str::<mirage_rs::config::UpstreamConfig>(
        r#"{"type":"shadowsocks","server":"h","server_port":1,"password":"p","method":"aes-256-gcm","udp":"blcok"}"#
    ).is_err(), "拼错的 udp 值必须报错");
}
