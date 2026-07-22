// Tests for src/proxy/sniff.rs (TLS SNI + HTTP Host extraction).
// Uses a loopback TcpListener so sniff_first_kb can peek real bytes.

use mirage_rs::proxy::sniff::sniff_first_kb;
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream};

/// Build a minimal valid TLS 1.3 ClientHello with given SNI.
/// Layout: [Record header 5B][Handshake header 4B][ClientHello body]
fn build_tls_client_hello(sni: &str) -> Vec<u8> {
    let sni_bytes = sni.as_bytes();

    // SNI extension: type=0, list_len=2+1+2+name, server_name_list=[type=0, len=N, bytes]
    let server_name = {
        let mut v = Vec::new();
        v.push(0u8); // name_type = host_name
        v.extend_from_slice(&(sni_bytes.len() as u16).to_be_bytes());
        v.extend_from_slice(sni_bytes);
        v
    };
    let sni_list = {
        let mut v = Vec::new();
        v.extend_from_slice(&(server_name.len() as u16).to_be_bytes());
        v.extend_from_slice(&server_name);
        v
    };
    let sni_ext = {
        let mut v = Vec::new();
        v.extend_from_slice(&0u16.to_be_bytes()); // extension_type = server_name
        v.extend_from_slice(&(sni_list.len() as u16).to_be_bytes());
        v.extend_from_slice(&sni_list);
        v
    };
    let extensions = {
        let mut v = Vec::new();
        v.extend_from_slice(&(sni_ext.len() as u16).to_be_bytes());
        v.extend_from_slice(&sni_ext);
        v
    };

    let client_hello_body = {
        let mut v = Vec::new();
        v.extend_from_slice(&[0x03, 0x03]); // legacy_version TLS 1.2
        v.extend_from_slice(&[0u8; 32]); // random
        v.push(0); // session_id length
        v.extend_from_slice(&2u16.to_be_bytes()); // cipher_suites length
        v.extend_from_slice(&[0x13, 0x01]); // TLS_AES_128_GCM_SHA256
        v.push(1); // compression_methods length
        v.push(0); // null compression
        v.extend_from_slice(&extensions);
        v
    };

    let handshake = {
        let mut v = vec![0x01]; // handshake_type = ClientHello
        let body_len = client_hello_body.len() as u32;
        v.extend_from_slice(&body_len.to_be_bytes()[1..]); // 24-bit length
        v.extend_from_slice(&client_hello_body);
        v
    };

    let mut record = vec![0x16, 0x03, 0x01]; // content_type=Handshake, version=TLS 1.0
    record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
    record.extend_from_slice(&handshake);
    record
}

/// Helper: spin up a loopback server, send `payload` from client side,
/// run sniff_first_kb on the server-accepted stream.
async fn sniff_with_payload(payload: Vec<u8>) -> Option<String> {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();

    tokio::spawn(async move {
        let mut s = TcpStream::connect(format!("127.0.0.1:{}", port))
            .await
            .unwrap();
        s.write_all(&payload).await.unwrap();
        // Keep client side alive so server can peek
        tokio::time::sleep(std::time::Duration::from_secs(3)).await;
    });

    let (stream, _) = listener.accept().await.unwrap();
    // Give client time to write before peeking
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    sniff_first_kb(&stream).await
}

#[tokio::test]
async fn test_sniff_tls_sni() {
    let hello = build_tls_client_hello("www.example.com");
    let sniffed = sniff_with_payload(hello).await;
    assert_eq!(sniffed, Some("www.example.com".to_string()));
}

#[tokio::test]
async fn test_sniff_tls_sni_long_domain() {
    let domain = "very-long-subdomain-name.deep.tree.example.com";
    let hello = build_tls_client_hello(domain);
    let sniffed = sniff_with_payload(hello).await;
    assert_eq!(sniffed, Some(domain.to_string()));
}

#[tokio::test]
async fn test_sniff_http_get() {
    let req = b"GET / HTTP/1.1\r\nHost: github.com\r\nUser-Agent: curl/8.0\r\n\r\n".to_vec();
    let sniffed = sniff_with_payload(req).await;
    assert_eq!(sniffed, Some("github.com".to_string()));
}

#[tokio::test]
async fn test_sniff_http_host_with_port() {
    // Sniffer should strip port from host header
    let req = b"POST /api HTTP/1.1\r\nHost: api.example.com:8080\r\n\r\n".to_vec();
    let sniffed = sniff_with_payload(req).await;
    assert_eq!(sniffed, Some("api.example.com".to_string()));
}

#[tokio::test]
async fn test_sniff_http_body_with_host_string_ignored() {
    // Regression: HTTP body containing "Host: " line must not be parsed as a header
    // (the sniffer must stop at the \r\n\r\n header/body boundary)
    let req = b"POST /api HTTP/1.1\r\nHost: real.example.com\r\nContent-Type: text/plain\r\n\r\nHost: fake.attacker.com\r\n".to_vec();
    let sniffed = sniff_with_payload(req).await;
    assert_eq!(sniffed, Some("real.example.com".to_string()));
}

#[tokio::test]
async fn test_sniff_timeout_on_slow_client() {
    // A client that connects but sends nothing → sniff should return None within ~2s
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();

    tokio::spawn(async move {
        // Slow client: connect but don't write
        let _s = TcpStream::connect(format!("127.0.0.1:{}", port)).await.unwrap();
        tokio::time::sleep(std::time::Duration::from_secs(10)).await;
    });

    let (stream, _) = listener.accept().await.unwrap();

    let start = std::time::Instant::now();
    let sniffed = sniff_first_kb(&stream).await;
    let elapsed = start.elapsed();

    assert_eq!(sniffed, None);
    assert!(
        elapsed < std::time::Duration::from_secs(3),
        "Sniff should time out within ~2s, took {:?}",
        elapsed
    );
}

#[tokio::test]
async fn test_sniff_unknown_protocol_returns_none() {
    let garbage = b"\x00\x01\x02\x03random binary garbage".to_vec();
    let sniffed = sniff_with_payload(garbage).await;
    assert_eq!(sniffed, None);
}

// ── 裸 IP 目标的嗅探分流 (端到端) ───────────────────────────────────────────
//
// 契约: SOCKS5 客户端把目标写成**裸 IP** 时 (不少 app 自己做完 DNS 再送 IP),
// 仍应嗅出 TLS SNI 并**按域名分流** —— 否则 domain_suffix / geosite 这类规则全部失效,
// 用户看到的是"规则写了不生效"却查不出原因。
//
// 判据设计成二选一的可观测差异: 命中域名规则 → block (连接被丢弃, 读不到回显);
// 未命中 → default direct (echo 正常回显)。两者一眼可分, 不靠日志。

use std::io::{Read as _, Write as _};
use std::process::{Child, Command, Stdio};

struct Kid(Child);
impl Drop for Kid {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn bin() -> std::path::PathBuf {
    let mut p = std::env::current_exe().unwrap();
    p.pop();
    p.pop();
    p.push("mirage");
    p
}

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn wait_port(port: u16) -> bool {
    for _ in 0..50 {
        if std::net::TcpStream::connect(("127.0.0.1", port)).is_ok() {
            return true;
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    false
}

/// echo 服务当"目标站点"。
fn spawn_echo() -> u16 {
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = l.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for s in l.incoming().flatten() {
            std::thread::spawn(move || {
                let mut s = s;
                let mut buf = [0u8; 4096];
                if let Ok(n) = s.read(&mut buf) {
                    let _ = s.write_all(&buf[..n]);
                }
            });
        }
    });
    port
}

/// SOCKS5 CONNECT 到 127.0.0.1:target_port，**用 ATYP=1 送裸 IP**(关键)。
fn socks5_connect_bare_ip(proxy: u16, target_port: u16) -> std::io::Result<std::net::TcpStream> {
    let mut s = std::net::TcpStream::connect(("127.0.0.1", proxy))?;
    s.set_read_timeout(Some(std::time::Duration::from_secs(5)))?;
    s.write_all(&[0x05, 0x01, 0x00])?; // greeting: 无认证
    let mut r = [0u8; 2];
    s.read_exact(&mut r)?;
    let mut req = vec![0x05, 0x01, 0x00, 0x01]; // CONNECT, ATYP=IPv4
    req.extend_from_slice(&[127, 0, 0, 1]);
    req.extend_from_slice(&target_port.to_be_bytes());
    s.write_all(&req)?;
    let mut resp = [0u8; 10];
    s.read_exact(&mut resp)?;
    Ok(s)
}

/// 起一个只有 socks 入站的客户端; `blocked_suffix` 命中则走 block。
fn spawn_proxy(socks_port: u16, blocked_suffix: &str) -> Kid {
    let cfg = format!(
        r#"{{
          "log_level": "warn",
          "inbounds": [{{ "type": "socks", "tag": "in", "listen": "127.0.0.1", "port": {socks_port} }}],
          "outbounds": [{{ "type": "direct", "tag": "direct" }}, {{ "type": "block", "tag": "block" }}],
          "routing": {{
            "default_outbound": "direct",
            "rules": [{{ "domain_suffix": "{blocked_suffix}", "outbound": "block" }}]
          }}
        }}"#
    );
    let p = std::env::temp_dir().join(format!("mirage_sniff_{}.json", std::process::id()));
    std::fs::write(&p, cfg).unwrap();
    Kid(Command::new(bin())
        .args(["client", "-c", p.to_str().unwrap()])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap())
}

#[test]
fn bare_ip_target_is_routed_by_sniffed_sni() {
    let echo = spawn_echo();
    let socks = free_port();
    let _proxy = spawn_proxy(socks, "blocked.example");
    assert!(wait_port(socks), "代理未起来");

    // ① SNI 命中 block 规则 —— 只有"嗅探生效"才可能命中 (SOCKS5 送的是裸 IP)
    let mut s = socks5_connect_bare_ip(socks, echo).expect("SOCKS5 建连失败");
    s.write_all(&build_tls_client_hello("x.blocked.example")).unwrap();
    let mut buf = [0u8; 64];
    let blocked = match s.read(&mut buf) {
        Ok(0) => true,           // 连接被丢弃
        Ok(_) => false,          // 收到回显 = 走了 direct = 嗅探没生效
        Err(_) => true,          // 读超时/重置, 同样视为被拦
    };
    assert!(
        blocked,
        "SOCKS5 送裸 IP 时 SNI 未参与分流 —— domain_suffix 规则形同虚设"
    );

    // ② 对照组: SNI 不命中 → 走 direct → echo 正常回显。
    //    没有这一组, 上面的断言可能只是"连接本来就建不起来"而恒真。
    let mut s2 = socks5_connect_bare_ip(socks, echo).expect("SOCKS5 建连失败(对照)");
    let hello = build_tls_client_hello("x.allowed.example");
    s2.write_all(&hello).unwrap();
    let mut buf2 = vec![0u8; hello.len()];
    s2.read_exact(&mut buf2).expect("对照组应能读到回显");
    assert_eq!(buf2, hello, "对照组回显内容应一致");
}

/// 嗅探超时必须是**紧的**: 客户端不先说话的协议 (SSH/SMTP 等 server-first) 会一直等到
/// 超时才继续, 这段是白加的延迟。若有人把它调回 2s, 这个测试会失败。
#[tokio::test]
async fn sniff_timeout_is_bounded_for_silent_clients() {
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = l.local_addr().unwrap().port();
    tokio::spawn(async move {
        // 客户端连上但**一个字节都不发** (模拟 server-first 协议)
        let _s = tokio::net::TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        tokio::time::sleep(std::time::Duration::from_secs(3)).await;
    });
    let (stream, _) = l.accept().await.unwrap();

    let t0 = std::time::Instant::now();
    let got = mirage_rs::proxy::sniff::sniff_with_timeout(
        &stream,
        std::time::Duration::from_millis(300),
    )
    .await;
    let elapsed = t0.elapsed();

    assert_eq!(got, None, "没数据不该嗅出东西");
    assert!(
        elapsed < std::time::Duration::from_millis(900),
        "静默客户端上耗时 {elapsed:?} —— 超时没生效, server-first 协议会被白加这么多延迟"
    );
}
