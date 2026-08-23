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
    s.set_read_timeout(Some(std::time::Duration::from_secs(15)))?;
    s.write_all(&[5, 1, 0])?;
    let mut r = [0u8; 2];
    s.read_exact(&mut r)?;
    assert_eq!(r, [5, 0], "服务端应选无认证");
    let p = target_port.to_be_bytes();
    s.write_all(&[5, 1, 0, 1, 127, 0, 0, 1, p[0], p[1]])?;
    let mut rep = [0u8; 10];
    s.read_exact(&mut rep)?;
    assert_eq!(rep[1], 0, "CONNECT 应成功 (REP=0), 实际 REP={}", rep[1]);
    Ok(s)
}

/// QUIC 传输打通一条真实 TCP 流 (SOCKS5 → mirage-over-QUIC → direct → echo)。
#[test]
fn quic_transport_tunnels_tcp() {
    let echo = spawn_echo();
    let camo = spawn_incomplete_camouflage();
    let sport = free_port(); // 服务端 QUIC 监听 (UDP 用同号)
    let cport = free_port(); // 客户端 SOCKS 入站 (TCP)

    let srv = write_cfg("srv", &format!(
        r#"{{"schema_version":1,"log_level":"warn",
            "inbounds":[{{"type":"mirage_server","tag":"m-in","listen":"127.0.0.1","port":{sport},
                          "password":"pw-quic","camouflage_host":"127.0.0.1:{camo}","transport":"quic"}}],
            "outbounds":[{{"type":"direct","tag":"direct"}}],
            "routing":{{"default_outbound":"direct","rules":[]}}}}"#
    ));
    let cli = write_cfg("cli", &format!(
        r#"{{"schema_version":1,"log_level":"warn",
            "inbounds":[{{"type":"socks","tag":"socks-in","listen":"127.0.0.1","port":{cport}}}],
            "outbounds":[{{"type":"mirage","tag":"m-out","server":"127.0.0.1","server_port":{sport},
                           "password":"pw-quic","camouflage_host":"www.apple.com","pool_size":2,"transport":"quic"}}],
            "routing":{{"default_outbound":"m-out","rules":[]}}}}"#
    ));

    let _s = spawn("server", &srv);
    std::thread::sleep(std::time::Duration::from_millis(1500)); // QUIC 服务端无 TCP 口可探, 等其起
    let _c = spawn("client", &cli);
    assert!(wait_port(cport), "客户端 SOCKS 入站未就绪");
    std::thread::sleep(std::time::Duration::from_millis(500));

    let mut s = socks5_connect(cport, echo).expect("经 QUIC 隧道 SOCKS5 CONNECT 应成功");
    s.write_all(b"hello quic").unwrap();
    let mut buf = [0u8; 64];
    let n = s.read(&mut buf).expect("应从 echo 读回数据");
    assert_eq!(&buf[..n], b"hello quic", "QUIC 隧道回显不匹配");
}
