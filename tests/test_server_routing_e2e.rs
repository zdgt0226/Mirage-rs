//! 服务端出站路由端到端集成测试 (E2E)。
//!
//! 验证：
//! 1. 模式一：`default_outbound: "direct"`，按规则将流量分流到 Shadowsocks 上游；未命中走直连。
//! 2. 服务端热重载：运行时修改配置文件中的 `outbounds` 与 `routing`，新连接无缝应用新配置。
//! 3. 模式二：`default_outbound: "ss-up"`，默认全部走落地上游，通过规则将指定端口拉回 direct 直连。

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

const TAG: usize = 16;

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
        fn len(&self) -> usize {
            self.0
        }
    }
    let prk = ring::hkdf::Salt::new(ring::hkdf::HKDF_SHA1_FOR_LEGACY_USE_ONLY, salt).extract(master);
    let okm = prk.expand(&[b"ss-subkey"], L(klen)).unwrap();
    let mut o = vec![0u8; klen];
    okm.fill(&mut o).unwrap();
    o
}

struct Aead {
    key: ring::aead::LessSafeKey,
    n: u128,
}

impl Aead {
    fn new(k: &[u8]) -> Self {
        Self {
            key: ring::aead::LessSafeKey::new(
                ring::aead::UnboundKey::new(&ring::aead::AES_256_GCM, k).unwrap(),
            ),
            n: 0,
        }
    }
    fn nonce(&mut self) -> ring::aead::Nonce {
        let mut b = [0u8; 12];
        b.copy_from_slice(&self.n.to_le_bytes()[..12]);
        self.n += 1;
        ring::aead::Nonce::assume_unique_for_key(b)
    }
    fn open(&mut self, buf: &mut [u8]) -> Vec<u8> {
        let n = self.nonce();
        self.key
            .open_in_place(n, ring::aead::Aad::empty(), buf)
            .expect("解密失败")
            .to_vec()
    }
    fn seal(&mut self, plain: &[u8]) -> Vec<u8> {
        let n = self.nonce();
        let mut b = plain.to_vec();
        self.key
            .seal_in_place_append_tag(n, ring::aead::Aad::empty(), &mut b)
            .unwrap();
        b
    }
}

async fn read_chunk(s: &mut TcpStream, dec: &mut Aead) -> Option<Vec<u8>> {
    let mut lb = [0u8; 2 + TAG];
    s.read_exact(&mut lb).await.ok()?;
    let l = dec.open(&mut lb);
    let n = u16::from_be_bytes([l[0], l[1]]) as usize;
    let mut body = vec![0u8; n + TAG];
    s.read_exact(&mut body).await.ok()?;
    Some(dec.open(&mut body))
}

async fn start_echo_server() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut buf = [0u8; 4096];
                while let Ok(n) = stream.read(&mut buf).await {
                    if n == 0 {
                        break;
                    }
                    if stream.write_all(&buf[..n]).await.is_err() {
                        break;
                    }
                }
            });
        }
    });
    port
}

/// 独立实现的最小 SS 服务端（SIP004 AES-256-GCM）。
async fn spawn_ss_upstream(
    password: &'static str,
    downlink_response: &'static [u8],
) -> (u16, tokio::sync::mpsc::Receiver<(String, Vec<u8>)>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let (tx, rx) = tokio::sync::mpsc::channel(16);

    tokio::spawn(async move {
        let master = evp(password.as_bytes(), 32);
        while let Ok((mut s, _)) = listener.accept().await {
            let tx = tx.clone();
            let master = master.clone();
            tokio::spawn(async move {
                let mut salt = [0u8; 32];
                if s.read_exact(&mut salt).await.is_err() {
                    return;
                }
                let mut dec = Aead::new(&subkey(&master, &salt, 32));

                let Some(addr_chunk) = read_chunk(&mut s, &mut dec).await else {
                    return;
                };
                let Ok((target, consumed)) =
                    mirage_rs::proxy::shadowsocks::decode_socks_addr(&addr_chunk)
                else {
                    return;
                };

                let payload = if consumed < addr_chunk.len() {
                    addr_chunk[consumed..].to_vec()
                } else {
                    read_chunk(&mut s, &mut dec).await.unwrap_or_default()
                };

                // 下行：salt + 加密 chunk
                let dsalt = [0x55u8; 32];
                if s.write_all(&dsalt).await.is_err() {
                    return;
                }
                let mut enc = Aead::new(&subkey(&master, &dsalt, 32));
                let lenc = enc.seal(&(downlink_response.len() as u16).to_be_bytes());
                let benc = enc.seal(downlink_response);
                if s.write_all(&lenc).await.is_err() {
                    return;
                }
                if s.write_all(&benc).await.is_err() {
                    return;
                }
                let _ = s.flush().await;

                let _ = tx.send((target, payload)).await;

                // 读剩余流直到断开
                while let Some(chunk) = read_chunk(&mut s, &mut dec).await {
                    if chunk.is_empty() {
                        break;
                    }
                }
            });
        }
    });

    (port, rx)
}

async fn get_free_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    listener.local_addr().unwrap().port()
}

async fn socks5_connect(socks_port: u16, target: &str, port: u16, is_domain: bool) -> TcpStream {
    let mut stream = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        TcpStream::connect(format!("127.0.0.1:{}", socks_port)),
    )
    .await
    .expect("SOCKS5 连接超时")
    .expect("无法连接到 SOCKS5 端口");

    stream.set_nodelay(true).ok();

    // SOCKS5 握手
    stream.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
    let mut auth_resp = [0u8; 2];
    stream.read_exact(&mut auth_resp).await.unwrap();
    assert_eq!(auth_resp, [0x05, 0x00]);

    // SOCKS5 CONNECT 请求
    let mut req = vec![0x05, 0x01, 0x00];
    if is_domain {
        req.push(0x03);
        req.push(target.len() as u8);
        req.extend_from_slice(target.as_bytes());
    } else {
        req.push(0x01);
        let ip: std::net::Ipv4Addr = target.parse().unwrap();
        req.extend_from_slice(&ip.octets());
    }
    req.extend_from_slice(&port.to_be_bytes());

    stream.write_all(&req).await.unwrap();
    let mut resp = [0u8; 10];
    stream.read_exact(&mut resp).await.unwrap();
    assert_eq!(resp[0..4], [0x05, 0x00, 0x00, 0x01]);

    stream
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_server_outbound_routing_and_hot_reload_e2e() {
    const SS_PW: &str = "test-routing-ss-pw-secret";
    const SS_DOWN: &[u8] = b"HTTP/1.1 200 OK\r\n\r\npong-from-ss-upstream";

    let echo_port = start_echo_server().await;
    let (ss_port, mut ss_rx) = spawn_ss_upstream(SS_PW, SS_DOWN).await;
    let server_port = get_free_port().await;
    let socks_port = get_free_port().await;

    let dir = std::env::temp_dir();
    let pid = std::process::id();
    let server_cfg_path = dir.join(format!("mirage_srv_e2e_{}_{}.json", pid, server_port));
    let client_cfg_path = dir.join(format!("mirage_cli_e2e_{}_{}.json", pid, socks_port));

    // ────────────────────────────────────────────────────────────────────────────
    // 阶段一：模式一配置 (default_outbound = "direct", rules 将 *.proxy.example 分流到 ss-up)
    // ────────────────────────────────────────────────────────────────────────────
    let server_config_mode1 = serde_json::json!({
        "inbounds": [{
            "type": "mirage_server",
            "tag": "srv_in",
            "listen": "127.0.0.1",
            "port": server_port,
            "password": "srv-secret-pwd-16B",
            "camouflage_host": "www.apple.com",
            "allow_local_targets": true
        }],
        "outbounds": [
            {
                "type": "direct",
                "tag": "direct"
            },
            {
                "type": "shadowsocks",
                "tag": "ss-up",
                "server": "127.0.0.1",
                "server_port": ss_port,
                "password": SS_PW,
                "method": "aes-256-gcm",
                "udp": "block"
            }
        ],
        "routing": {
            "default_outbound": "direct",
            "rules": [
                {
                    "outbound": "ss-up",
                    "domain_suffix": ["proxy.example"]
                }
            ]
        }
    });

    let client_config = serde_json::json!({
        "inbounds": [{
            "type": "socks",
            "tag": "socks_in",
            "listen": "127.0.0.1",
            "port": socks_port
        }],
        "outbounds": [{
            "type": "pyreality",
            "tag": "proxy",
            "server": "127.0.0.1",
            "server_port": server_port,
            "password": "srv-secret-pwd-16B",
            "camouflage_host": "www.apple.com",
            "pool_size": 1
        }],
        "routing": {
            "default_outbound": "proxy",
            "rules": []
        }
    });

    std::fs::write(&server_cfg_path, serde_json::to_string_pretty(&server_config_mode1).unwrap()).unwrap();
    std::fs::write(&client_cfg_path, serde_json::to_string_pretty(&client_config).unwrap()).unwrap();

    let srv_path_str = server_cfg_path.to_str().unwrap().to_string();
    let cli_path_str = client_cfg_path.to_str().unwrap().to_string();

    tokio::spawn(async move {
        let _ = mirage_rs::start_proxy(&srv_path_str, true).await;
    });

    tokio::spawn(async move {
        let _ = mirage_rs::start_proxy(&cli_path_str, false).await;
    });

    // 等待服务端与客户端完成初始化与连接池就绪
    tokio::time::sleep(tokio::time::Duration::from_millis(800)).await;

    // 1.1 模式一未命中规则：走 direct 直连本地 echo 服务器
    {
        let mut stream = socks5_connect(socks_port, "127.0.0.1", echo_port, false).await;
        let msg = b"ping to direct echo server";
        stream.write_all(msg).await.unwrap();

        let mut buf = [0u8; 1024];
        let n = stream.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], msg, "直连流量必须由 echo 服务器原样返回");

        // SS 上游必须未收到任何连接请求
        assert!(
            ss_rx.try_recv().is_err(),
            "直连流量绝不能被分发到 SS 上游出口"
        );
    }

    // 1.2 模式一命中规则：*.proxy.example 分流到 SS 上游
    {
        let mut stream = socks5_connect(socks_port, "node1.proxy.example", 8443, true).await;
        let msg = b"ping to ss upstream target";
        stream.write_all(msg).await.unwrap();

        let mut buf = [0u8; 1024];
        let n = stream.read(&mut buf).await.unwrap();
        assert_eq!(
            &buf[..n],
            SS_DOWN,
            "命中路由的流量必须收到 SS 上游返回的数据"
        );

        // SS 独立服务端收到了解密后的目标地址与载荷
        let (ss_target, ss_payload) = tokio::time::timeout(
            tokio::time::Duration::from_secs(3),
            ss_rx.recv(),
        )
        .await
        .expect("等待 SS 上游事件超时")
        .expect("SS channel 被关闭");

        assert_eq!(ss_target, "node1.proxy.example:8443");
        assert_eq!(ss_payload, msg);
    }

    // ────────────────────────────────────────────────────────────────────────────
    // 阶段二：热重载切换到模式二 (default_outbound = "ss-up", rules 将 echo_port 拉回 direct)
    // ────────────────────────────────────────────────────────────────────────────
    let server_config_mode2 = serde_json::json!({
        "inbounds": [{
            "type": "mirage_server",
            "tag": "srv_in",
            "listen": "127.0.0.1",
            "port": server_port,
            "password": "srv-secret-pwd-16B",
            "camouflage_host": "www.apple.com",
            "allow_local_targets": true
        }],
        "outbounds": [
            {
                "type": "direct",
                "tag": "direct"
            },
            {
                "type": "shadowsocks",
                "tag": "ss-up",
                "server": "127.0.0.1",
                "server_port": ss_port,
                "password": SS_PW,
                "method": "aes-256-gcm",
                "udp": "block"
            }
        ],
        "routing": {
            "default_outbound": "ss-up",
            "rules": [
                {
                    "outbound": "direct",
                    "port": [echo_port]
                }
            ]
        }
    });

    // 写入新配置触发热重载
    std::fs::write(&server_cfg_path, serde_json::to_string_pretty(&server_config_mode2).unwrap()).unwrap();

    // 等待 ConfigWatcher 触发并在内存原子替换 ServerRouterState
    tokio::time::sleep(tokio::time::Duration::from_millis(800)).await;

    // 2.1 模式二命中 direct 规则：目标端口为 echo_port，拉回 direct 直连
    {
        let mut stream = socks5_connect(socks_port, "127.0.0.1", echo_port, false).await;
        let msg = b"ping direct via mode2 port rule";
        stream.write_all(msg).await.unwrap();

        let mut buf = [0u8; 1024];
        let n = stream.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], msg, "模式二下特定端口仍应拉回 direct 直连");
        assert!(ss_rx.try_recv().is_err(), "拉回 direct 的流量不得流入 SS");
    }

    // 2.2 模式二默认走落地：未匹配规则的任意目标 (如 other.example:9999) 全部默认走 SS 上游
    {
        let mut stream = socks5_connect(socks_port, "other.example", 9999, true).await;
        let msg = b"ping default upstream in mode2";
        stream.write_all(msg).await.unwrap();

        let mut buf = [0u8; 1024];
        let n = stream.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], SS_DOWN);

        let (ss_target, ss_payload) = tokio::time::timeout(
            tokio::time::Duration::from_secs(3),
            ss_rx.recv(),
        )
        .await
        .expect("等待模式二 SS 上游事件超时")
        .expect("SS channel 被关闭");

        assert_eq!(ss_target, "other.example:9999");
        assert_eq!(ss_payload, msg);
    }

    // 清理临时配置文件
    let _ = std::fs::remove_file(&server_cfg_path);
    let _ = std::fs::remove_file(&client_cfg_path);
}
