//! 轻量模式端到端: 起真的 lite-server + lite-client, 经 SOCKS5 打通一条真实 TCP 流。
//!
//! 不依赖外网 —— 目标是本测试自己起的一个 echo 服务, 所以 CI 里也能稳定跑。
//! 覆盖两条核心契约: ①「全部转发」真的走了隧道; ②「仅 TCP」对 UDP ASSOCIATE 明确拒绝。

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

/// 进程守卫: 测试无论怎么结束 (含 panic) 都杀掉子进程, 不留端口占用。
struct Kid(Child);
impl Drop for Kid {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn write_cfg(name: &str, json: &str) -> std::path::PathBuf {
    let p = std::env::temp_dir().join(format!("mirage_lite_{}_{}", std::process::id(), name));
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

/// 等端口可连, 最多 ~5s。
fn wait_port(port: u16) -> bool {
    for _ in 0..50 {
        if TcpStream::connect(("127.0.0.1", port)).is_ok() {
            return true;
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    false
}

/// 起一个最小 echo 服务当"目标站点", 返回其端口。
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

/// 经 SOCKS5 CONNECT 到 127.0.0.1:port, 返回已建立的流。
fn socks5_connect(proxy: u16, target_port: u16) -> std::io::Result<TcpStream> {
    let mut s = TcpStream::connect(("127.0.0.1", proxy))?;
    s.set_read_timeout(Some(std::time::Duration::from_secs(10)))?;
    s.write_all(&[5, 1, 0])?; // greeting: no-auth
    let mut r = [0u8; 2];
    s.read_exact(&mut r)?;
    assert_eq!(r, [5, 0], "服务端应选无认证");

    let p = target_port.to_be_bytes();
    s.write_all(&[5, 1, 0, 1, 127, 0, 0, 1, p[0], p[1]])?; // CONNECT 127.0.0.1:port
    let mut rep = [0u8; 10];
    s.read_exact(&mut rep)?;
    assert_eq!(rep[1], 0, "CONNECT 应成功 (REP=0), 实际 REP={}", rep[1]);
    Ok(s)
}

#[test]
fn lite_tunnel_forwards_tcp_end_to_end() {
    let echo = spawn_echo();
    // 端口取相对不常用的段, 降低与本机既有服务冲突的概率
    let (sport, cport) = (18571, 11571);
    let srv_cfg = write_cfg(
        "srv.json",
        &format!(
            r#"{{"listen":"127.0.0.1","port":{sport},"password":"pw-e2e","sni":"www.apple.com","log_level":"warn"}}"#
        ),
    );
    let cli_cfg = write_cfg(
        "cli.json",
        &format!(
            r#"{{"listen":"127.0.0.1","port":{cport},"server":"127.0.0.1","server_port":{sport},"password":"pw-e2e","sni":"www.apple.com","pool_size":2,"log_level":"warn"}}"#
        ),
    );

    let _s = spawn("lite-server", &srv_cfg);
    assert!(wait_port(sport), "轻量服务端未监听");
    let _c = spawn("lite-client", &cli_cfg);
    assert!(wait_port(cport), "轻量客户端未监听");

    // 经隧道往 echo 服务发一段数据, 应原样回来 —— 证明整条链路 (SOCKS5 → 加密隧道 →
    // 服务端 → 目标) 双向通。
    let mut s = socks5_connect(cport, echo).expect("SOCKS5 CONNECT 失败");
    s.write_all(b"hello-through-lite-tunnel").unwrap();
    let mut buf = [0u8; 64];
    let n = s.read(&mut buf).unwrap();
    assert_eq!(&buf[..n], b"hello-through-lite-tunnel", "回环数据应原样返回");

    std::fs::remove_file(&srv_cfg).ok();
    std::fs::remove_file(&cli_cfg).ok();
}

#[test]
fn lite_client_rejects_udp_associate() {
    let (sport, cport) = (18572, 11572);
    let srv_cfg = write_cfg(
        "srv_udp.json",
        &format!(
            r#"{{"listen":"127.0.0.1","port":{sport},"password":"pw-udp","sni":"www.apple.com","log_level":"warn"}}"#
        ),
    );
    let cli_cfg = write_cfg(
        "cli_udp.json",
        &format!(
            r#"{{"listen":"127.0.0.1","port":{cport},"server":"127.0.0.1","server_port":{sport},"password":"pw-udp","sni":"www.apple.com","pool_size":1,"log_level":"warn"}}"#
        ),
    );
    let _s = spawn("lite-server", &srv_cfg);
    assert!(wait_port(sport));
    let _c = spawn("lite-client", &cli_cfg);
    assert!(wait_port(cport));

    let mut s = TcpStream::connect(("127.0.0.1", cport)).unwrap();
    s.set_read_timeout(Some(std::time::Duration::from_secs(10))).unwrap();
    s.write_all(&[5, 1, 0]).unwrap();
    let mut r = [0u8; 2];
    s.read_exact(&mut r).unwrap();

    s.write_all(&[5, 3, 0, 1, 0, 0, 0, 0, 0, 0]).unwrap(); // UDP ASSOCIATE
    let mut rep = [0u8; 10];
    s.read_exact(&mut rep).unwrap();
    // 必须按 SOCKS5 规范回 0x07 (command not supported), 而不是静默断开让客户端干等
    assert_eq!(rep[1], 0x07, "轻量模式仅 TCP, UDP ASSOCIATE 应回 REP=0x07");

    std::fs::remove_file(&srv_cfg).ok();
    std::fs::remove_file(&cli_cfg).ok();
}

/// 跨模式互通 (契约): **完整模式服务端** (`mirage server`, mirage_server 入站) 必须能被
/// **轻量模式客户端** (`mirage lite-client`) 正常对接 —— 两者共用同一套 Mirage 协议与伪装,
/// 只要 password 一致就该通 (camouflage_host/sni 不同不影响 auth, 仅是伪装 SNI)。
///
/// 真机部署踩过"以为不通"的坑: 实为 password 不一致 / 走了 UDP。这个测试把"能互通"钉成 CI 保证。
#[test]
fn full_server_interops_with_lite_client() {
    let echo = spawn_echo();
    let (sport, cport) = (18573, 11573);
    // 完整模式服务端 config (mirage_server 入站 + direct 出站)。sni 故意与客户端**不同**,
    // 证明只需 password 一致即可互通。
    let srv_cfg = write_cfg(
        "full_srv.json",
        &format!(
            r#"{{"schema_version":1,"log_level":"warn","inbounds":[{{"type":"mirage_server","tag":"mirage-in","listen":"127.0.0.1","port":{sport},"password":"pw-xmode","camouflage_host":"www.cloudflare.com"}}],"outbounds":[{{"type":"direct","tag":"direct"}}],"routing":{{"default_outbound":"direct","rules":[]}}}}"#
        ),
    );
    let cli_cfg = write_cfg(
        "lite_cli.json",
        &format!(
            r#"{{"listen":"127.0.0.1","port":{cport},"server":"127.0.0.1","server_port":{sport},"password":"pw-xmode","sni":"www.apple.com","pool_size":2,"log_level":"warn"}}"#
        ),
    );

    let _s = spawn("server", &srv_cfg);
    assert!(wait_port(sport), "完整模式服务端未监听");
    let _c = spawn("lite-client", &cli_cfg);
    assert!(wait_port(cport), "轻量客户端未监听");

    let mut s = socks5_connect(cport, echo).expect("跨模式 SOCKS5 CONNECT 失败 (完整服务端↔轻量客户端应互通)");
    s.write_all(b"cross-mode-full-server-lite-client").unwrap();
    let mut buf = [0u8; 64];
    let n = s.read(&mut buf).unwrap();
    assert_eq!(&buf[..n], b"cross-mode-full-server-lite-client", "跨模式隧道回环数据应原样返回");

    std::fs::remove_file(&srv_cfg).ok();
    std::fs::remove_file(&cli_cfg).ok();
}
