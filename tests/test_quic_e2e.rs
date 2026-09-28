//! QUIC 传输端到端 (P0, `--features quic`): 起真的 server (mirage_server transport=quic) +
//! client (socks 入站 → mirage 出站 transport=quic), 经 SOCKS5 打通一条真实 TCP 流。
//!
//! 证明: Mirage 的 fake-TLS 握手 + AEAD + TCP relay 完整跑在 QUIC 双向流之上 (Model Y)。
//! 不依赖外网 —— camouflage 用本地残站, 服务端回落合成模板; 目标是本测试自起的 echo。
//!
//! 仅在 `--features quic` 编译时存在 (运行时也需该 feature 的二进制)。
#![cfg(feature = "quic")]

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::process::{Child, Command, Stdio};

fn bin() -> std::path::PathBuf {
    let mut p = std::env::current_exe().unwrap();
    p.pop();
    p.pop();
    p.push("mirage");
    p
}

struct Kid(Child);
impl Drop for Kid {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn write_cfg(name: &str, json: &str) -> std::path::PathBuf {
    let p = std::env::temp_dir().join(format!("mirage_quic_{}_{}", std::process::id(), name));
    std::fs::write(&p, json).unwrap();
    p
}

fn spawn(sub: &str, cfg: &std::path::Path) -> Kid {
    Kid(Command::new(bin())
        .args([sub, "-c", cfg.to_str().unwrap()])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap())
}

fn wait_port(port: u16) -> bool {
    for _ in 0..50 {
        if TcpStream::connect(("127.0.0.1", port)).is_ok() {
            return true;
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    false
}

fn spawn_echo() -> u16 {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = l.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for s in l.incoming().flatten() {
            std::thread::spawn(move || {
                let mut s = s;
                let mut buf = [0u8; 1024];
                if let Ok(n) = s.read(&mut buf) {
                    let _ = s.write_all(&buf[..n]);
                }
            });
        }
    });
    port
}

/// 本地残 camouflage 站 (只回一条不完整 ServerHello), 逼服务端回落合成模板 —— 免外网。
fn spawn_incomplete_camouflage() -> u16 {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = l.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for s in l.incoming().flatten() {
            std::thread::spawn(move || {
                let mut s = s;
                let mut buf = [0u8; 4096];
                let _ = s.read(&mut buf);
                let mut sh = vec![0x16, 0x03, 0x03];
                sh.extend_from_slice(&48u16.to_be_bytes());
                sh.extend(std::iter::repeat_n(0u8, 48));
                let _ = s.write_all(&sh);
                std::thread::sleep(std::time::Duration::from_secs(30));
            });
        }
    });
    port
}

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port()
}

fn socks5_connect(proxy: u16, target_port: u16) -> std::io::Result<TcpStream> {
    let mut s = TcpStream::connect(("127.0.0.1", proxy))?;
    s.set_read_timeout(Some(std::time::Duration::from_secs(3)))?;
    s.write_all(&[5, 1, 0])?;
    let mut r = [0u8; 2];
    s.read_exact(&mut r)?;
    if r != [5, 0] {
        return Err(std::io::Error::other(format!(
            "服务端认证协商失败: {:?}",
            r
        )));
    }
    let p = target_port.to_be_bytes();
    s.write_all(&[5, 1, 0, 1, 127, 0, 0, 1, p[0], p[1]])?;
    let mut rep = [0u8; 10];
    s.read_exact(&mut rep)?;
    if rep[1] != 0 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::ConnectionRefused,
            format!("CONNECT 应成功 (REP=0), 实际 REP={}", rep[1]),
        ));
    }
    Ok(s)
}

/// QUIC 传输打通一条真实 TCP 流 (SOCKS5 → mirage-over-QUIC → direct → echo)。
#[test]
fn quic_transport_tunnels_tcp() {
    struct CleanFile(std::path::PathBuf);
    impl Drop for CleanFile {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
        }
    }

    let echo = spawn_echo();
    let camo = spawn_incomplete_camouflage();
    let sport = free_port(); // 服务端 QUIC 监听 (UDP 用同号)
    let cport = free_port(); // 客户端 SOCKS 入站 (TCP)

    let key_path = std::env::temp_dir().join(format!("mirage_quic_key_{}.pem", std::process::id()));
    let _ = std::fs::remove_file(&key_path);
    let key = mirage_rs::proxy::quic::load_or_generate_key(&key_path).expect("生成测试 QUIC 密钥");
    let pin = mirage_rs::proxy::quic::spki_pin(&key.public_key_der());
    let key_path_str = key_path.to_str().unwrap();

    let _clean_key = CleanFile(key_path.clone());

    let srv = write_cfg("srv", &format!(
        r#"{{"schema_version":1,"log_level":"warn",
            "inbounds":[{{"type":"mirage_server","tag":"m-in","listen":"127.0.0.1","port":{sport},
                          "password":"pw-quic","camouflage_host":"127.0.0.1:{camo}","transport":"quic",
                          "quic_key_path":"{key_path_str}","allow_local_targets":true}}],
            "outbounds":[{{"type":"direct","tag":"direct"}}],
            "routing":{{"default_outbound":"direct","rules":[]}}}}"#
    ));
    let _clean_srv = CleanFile(srv.clone());

    let cli = write_cfg("cli", &format!(
        r#"{{"schema_version":1,"log_level":"warn",
            "inbounds":[{{"type":"socks","tag":"socks-in","listen":"127.0.0.1","port":{cport}}}],
            "outbounds":[{{"type":"mirage","tag":"m-out","server":"127.0.0.1","server_port":{sport},
                            "password":"pw-quic","camouflage_host":"www.apple.com","pool_size":2,"transport":"quic",
                            "quic_pin":"{pin}"}}],
            "routing":{{"default_outbound":"m-out","rules":[]}}}}"#
    ));
    let _clean_cli = CleanFile(cli.clone());

    let _s = spawn("server", &srv);
    let _c = spawn("client", &cli);
    assert!(wait_port(cport), "客户端 SOCKS 入站未就绪");

    // 端到端请求带重试 (最多 10 次、每次间隔 300ms, 替代原先固定 sleep 等待 QUIC 服务端)
    let mut last_err = String::new();
    let mut success = false;
    for _ in 1..=10 {
        match socks5_connect(cport, echo) {
            Ok(mut s) => {
                if s.write_all(b"hello quic").is_ok() {
                    let mut buf = [0u8; 64];
                    if let Ok(n) = s.read(&mut buf) {
                        if &buf[..n] == b"hello quic" {
                            success = true;
                            break;
                        } else {
                            last_err = format!("回显数据不匹配: {:?}", &buf[..n]);
                        }
                    } else {
                        last_err = "从 echo 读取数据失败".to_string();
                    }
                } else {
                    last_err = "向 stream 发送数据失败".to_string();
                }
            }
            Err(e) => {
                last_err = format!("socks5_connect 失败: {e}");
            }
        }
        std::thread::sleep(std::time::Duration::from_millis(300));
    }
    assert!(success, "QUIC 端到端请求重试超限失败: {last_err}");
}
