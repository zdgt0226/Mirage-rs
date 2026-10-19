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

/// 起一个"残 camouflage 站": 只回一条 ServerHello record (缺 CCS 0x14 / 加密 0x17),
/// 然后 hold 住连接。模拟把 flight 拆成多条记录的站 / TLS 1.2 站 —— 服务端 fetch 到这种
/// **不完整模板必须判残、丢弃、回落到恒完整的 fallback_server_hello**, 否则缓存残模板 →
/// 客户端 read_server_handshake 永等不到三型齐 → 不发 tail → 服务端 read_exact tail 超时。
fn spawn_incomplete_camouflage() -> u16 {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = l.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for s in l.incoming().flatten() {
            std::thread::spawn(move || {
                let mut s = s;
                let mut buf = [0u8; 4096];
                let _ = s.read(&mut buf); // 吃掉 ClientHello
                // 只回一条 ServerHello: [0x16][03 03][len=48][48B 全 0]。缺 0x14/0x17。
                let mut sh = vec![0x16, 0x03, 0x03];
                sh.extend_from_slice(&48u16.to_be_bytes());
                sh.extend(std::iter::repeat_n(0u8, 48));
                let _ = s.write_all(&sh);
                std::thread::sleep(std::time::Duration::from_secs(30)); // hold, 让后续读走超时
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
            r#"{{"listen":"127.0.0.1","port":{sport},"password":"pw-e2e","sni":"www.apple.com","allow_local_targets":true,"log_level":"warn"}}"#
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

/// 回归 (fetch 边界): **完整模式服务端**的 camouflage_host 指向一个只回残 ServerHello 的站,
/// **轻量模式客户端**必须仍能打通隧道 —— 服务端得判残模板、丢弃、回落到恒完整的 fallback。
///
/// 这条同时钉两件事: ①跨模式互通 (完整服务端 ↔ 轻量客户端, password 一致即通);
/// ②fetch 完整性门禁 (残模板不毒化 cache)。**修复前**服务端 prewarm 会缓存残模板 → 每条连接
/// 回放残模板 → 客户端永等不到三型齐、不发 tail → SOCKS5 CONNECT 10s 读超时失败。见 commit
/// e309e7e / handshake_cache::template_is_complete。
#[test]
fn server_falls_back_when_camouflage_template_incomplete() {
    let echo = spawn_echo();
    let camo = spawn_incomplete_camouflage();
    let (sport, cport) = (18574, 11574);
    // 完整模式服务端: camouflage_host = 本地残站。fetch 必残 → 弃 → 回落 fallback。
    let srv_cfg = write_cfg(
        "fallback_srv.json",
        &format!(
            r#"{{"schema_version":1,"log_level":"warn","inbounds":[{{"type":"mirage_server","tag":"mirage-in","listen":"127.0.0.1","port":{sport},"password":"pw-fb","camouflage_host":"127.0.0.1:{camo}","allow_local_targets":true}}],"outbounds":[{{"type":"direct","tag":"direct"}}],"routing":{{"default_outbound":"direct","rules":[]}}}}"#
        ),
    );
    let cli_cfg = write_cfg(
        "fallback_cli.json",
        &format!(
            r#"{{"listen":"127.0.0.1","port":{cport},"server":"127.0.0.1","server_port":{sport},"password":"pw-fb","sni":"www.apple.com","pool_size":2,"log_level":"warn"}}"#
        ),
    );

    let _s = spawn("server", &srv_cfg);
    assert!(wait_port(sport), "完整模式服务端未监听");
    let _c = spawn("lite-client", &cli_cfg);
    assert!(wait_port(cport), "轻量客户端未监听");

    let mut s = socks5_connect(cport, echo)
        .expect("残 camouflage 下 SOCKS5 CONNECT 失败: 服务端未回落 fallback (缓存了残模板 → tail 超时)");
    s.write_all(b"incomplete-camouflage-fallback").unwrap();
    let mut buf = [0u8; 64];
    let n = s.read(&mut buf).unwrap();
    assert_eq!(&buf[..n], b"incomplete-camouflage-fallback", "回落 fallback 后隧道回环数据应原样返回");

    std::fs::remove_file(&srv_cfg).ok();
    std::fs::remove_file(&cli_cfg).ok();
}

/// PFS 两端同开 (pfs=true): 握手做 X25519 ECDH, 隧道照常打通 echo 回环。
/// 证明前向保密路径端到端可用 (ClientHello.random=客户端临时公钥, ServerHello.random=
/// 服务端临时公钥, ecdh 混进 master), 且不破坏正常代理。
#[test]
fn pfs_both_ends_tunnel_works() {
    let echo = spawn_echo();
    let (sport, cport) = (18581, 11581);
    let srv_cfg = write_cfg(
        "pfs_srv.json",
        &format!(
            r#"{{"listen":"127.0.0.1","port":{sport},"password":"pw-pfs","sni":"www.apple.com","pfs":true,"allow_local_targets":true,"log_level":"warn"}}"#
        ),
    );
    let cli_cfg = write_cfg(
        "pfs_cli.json",
        &format!(
            r#"{{"listen":"127.0.0.1","port":{cport},"server":"127.0.0.1","server_port":{sport},"password":"pw-pfs","sni":"www.apple.com","pool_size":2,"pfs":true,"log_level":"warn"}}"#
        ),
    );

    let _s = spawn("lite-server", &srv_cfg);
    assert!(wait_port(sport), "PFS 服务端未监听");
    let _c = spawn("lite-client", &cli_cfg);
    assert!(wait_port(cport), "PFS 客户端未监听");

    let mut s = socks5_connect(cport, echo).expect("PFS 两端同开 SOCKS5 CONNECT 应成功");
    s.write_all(b"hello-through-pfs-tunnel").unwrap();
    let mut buf = [0u8; 64];
    let n = s.read(&mut buf).unwrap();
    assert_eq!(&buf[..n], b"hello-through-pfs-tunnel", "PFS 隧道回环数据应原样返回");

    std::fs::remove_file(&srv_cfg).ok();
    std::fs::remove_file(&cli_cfg).ok();
}

/// PFS 失配 (服务端 pfs=true, 客户端 pfs=false): 两端派生的会话 master 不同 (label 域分隔 +
/// 客户端根本没做 ECDH), 加密帧互相解不开 → 隧道回环拿不到数据。钉住"两端必须同开 pfs"
/// 契约 (fail-closed, 不静默出乱数据)。
///
/// 注: SOCKS5 CONNECT 的 REP=0 是乐观提前回的, 失配在**数据中继**阶段才暴露, 故断言整条
/// 回环不成功 (CONNECT 失败 / 无回显 / 回显不符 任一即可)。
#[test]
fn pfs_mismatch_fails_closed() {
    let echo = spawn_echo();
    let (sport, cport) = (18582, 11582);
    let srv_cfg = write_cfg(
        "pfs_mm_srv.json",
        &format!(
            r#"{{"listen":"127.0.0.1","port":{sport},"password":"pw-mm","sni":"www.apple.com","pfs":true,"allow_local_targets":true,"log_level":"warn"}}"#
        ),
    );
    // 客户端不开 pfs (默认 false)。
    let cli_cfg = write_cfg(
        "pfs_mm_cli.json",
        &format!(
            r#"{{"listen":"127.0.0.1","port":{cport},"server":"127.0.0.1","server_port":{sport},"password":"pw-mm","sni":"www.apple.com","pool_size":2,"log_level":"warn"}}"#
        ),
    );

    let _s = spawn("lite-server", &srv_cfg);
    assert!(wait_port(sport), "服务端未监听");
    let _c = spawn("lite-client", &cli_cfg);
    assert!(wait_port(cport), "客户端未监听");

    // master 失配 → 加密中继解不开 → 整条回环不该成功 (CONNECT 失败 / 无回显 / 回显不符)。
    let ok_roundtrip = (|| -> Option<()> {
        let mut s = socks5_connect(cport, echo).ok()?;
        s.write_all(b"pfs-mismatch-probe").ok()?;
        let mut buf = [0u8; 64];
        let n = s.read(&mut buf).ok()?;
        (n > 0 && &buf[..n] == b"pfs-mismatch-probe").then_some(())
    })();
    assert!(ok_roundtrip.is_none(), "PFS 失配下不该有成功的隧道回环 (fail-closed)");

    std::fs::remove_file(&srv_cfg).ok();
    std::fs::remove_file(&cli_cfg).ok();
}

/// PFS 完整模式覆盖: **完整 mirage_server 入站** (走 handshake.rs + control.rs 服务端侧 PFS
/// 路径, 非 lite start_server) + 完整 direct 出站, 对接 lite-client pfs=true。证明 PFS 在
/// 完整服务端握手路径也端到端可用 (lite↔lite 之外的另一条真实路径)。
#[test]
fn pfs_full_server_interops_with_lite_client() {
    let echo = spawn_echo();
    let (sport, cport) = (18583, 11583);
    // 完整模式服务端: mirage_server 入站 + pfs=true + direct 出站。
    let srv_cfg = write_cfg(
        "pfs_full_srv.json",
        &format!(
            r#"{{"schema_version":1,"log_level":"warn","inbounds":[{{"type":"mirage_server","tag":"mirage-in","listen":"127.0.0.1","port":{sport},"password":"pw-pfs-full","camouflage_host":"www.apple.com","pfs":true,"allow_local_targets":true}}],"outbounds":[{{"type":"direct","tag":"direct"}}],"routing":{{"default_outbound":"direct","rules":[]}}}}"#
        ),
    );
    let cli_cfg = write_cfg(
        "pfs_full_cli.json",
        &format!(
            r#"{{"listen":"127.0.0.1","port":{cport},"server":"127.0.0.1","server_port":{sport},"password":"pw-pfs-full","sni":"www.apple.com","pool_size":2,"pfs":true,"log_level":"warn"}}"#
        ),
    );

    let _s = spawn("server", &srv_cfg);
    assert!(wait_port(sport), "完整模式 PFS 服务端未监听");
    let _c = spawn("lite-client", &cli_cfg);
    assert!(wait_port(cport), "PFS 客户端未监听");

    let mut s = socks5_connect(cport, echo)
        .expect("完整服务端 PFS ↔ lite 客户端 PFS 应互通");
    s.write_all(b"pfs-full-server-lite-client").unwrap();
    let mut buf = [0u8; 64];
    let n = s.read(&mut buf).unwrap();
    assert_eq!(&buf[..n], b"pfs-full-server-lite-client", "完整模式 PFS 隧道回环应原样返回");

    std::fs::remove_file(&srv_cfg).ok();
    std::fs::remove_file(&cli_cfg).ok();
}

/// 起完整 mirage_server + lite-client 一对, 返回 (进程守卫, SOCKS 端口)。
fn spawn_pair(name: &str, sport: u16, cport: u16) -> (Kid, Kid, u16) {
    let srv_cfg = write_cfg(
        &format!("{name}_srv.json"),
        &format!(
            r#"{{"schema_version":1,"log_level":"warn","inbounds":[{{"type":"mirage_server","tag":"mirage-in","listen":"127.0.0.1","port":{sport},"password":"pw-close-semantics","camouflage_host":"www.apple.com","allow_local_targets":true}}],"outbounds":[{{"type":"direct","tag":"direct"}}],"routing":{{"default_outbound":"direct","rules":[]}}}}"#
        ),
    );
    let cli_cfg = write_cfg(
        &format!("{name}_cli.json"),
        &format!(
            r#"{{"listen":"127.0.0.1","port":{cport},"server":"127.0.0.1","server_port":{sport},"password":"pw-close-semantics","sni":"www.apple.com","pool_size":2,"log_level":"warn"}}"#
        ),
    );
    let s = spawn("server", &srv_cfg);
    assert!(wait_port(sport), "服务端未监听");
    let c = spawn("lite-client", &cli_cfg);
    assert!(wait_port(cport), "客户端未监听");
    (s, c, cport)
}

/// 起一个目标: 读一次请求后按 `mode` 结束 —— "fin" 回 data 后正常关闭; "rst" 回 data 后 RST;
/// "slow" 等 500ms 再回 data 后关闭。
fn spawn_target(mode: &'static str) -> u16 {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = l.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for s in l.incoming().flatten() {
            std::thread::spawn(move || {
                let mut s = s;
                let mut buf = [0u8; 64];
                let _ = s.read(&mut buf);
                if mode == "slow" {
                    std::thread::sleep(std::time::Duration::from_millis(500));
                }
                let _ = s.write_all(b"data");
                if mode == "rst" {
                    std::thread::sleep(std::time::Duration::from_millis(200));
                    let _ = socket2_free_linger_zero(&s);
                }
            });
        }
    });
    port
}

/// SO_LINGER=0, 随后 drop 即发 RST (测试用, 避免引入 socket2 依赖)。
fn socket2_free_linger_zero(s: &TcpStream) -> std::io::Result<()> {
    use std::os::fd::AsRawFd;
    let linger = libc::linger { l_onoff: 1, l_linger: 0 };
    // SAFETY: s 持有 fd; 参数为栈上 linger 结构体及其大小。
    let rc = unsafe {
        libc::setsockopt(
            s.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_LINGER,
            &linger as *const libc::linger as *const libc::c_void,
            std::mem::size_of::<libc::linger>() as libc::socklen_t,
        )
    };
    if rc == 0 { Ok(()) } else { Err(std::io::Error::last_os_error()) }
}

/// 读到结束: Ok(数据) = 干净 EOF (FIN); Err = 连接被重置 (RST)。
fn read_all_or_reset(s: &mut TcpStream) -> Result<Vec<u8>, std::io::ErrorKind> {
    let mut out = Vec::new();
    let mut buf = [0u8; 256];
    loop {
        match s.read(&mut buf) {
            Ok(0) => return Ok(out),
            Ok(n) => out.extend_from_slice(&buf[..n]),
            Err(e) => return Err(e.kind()),
        }
    }
}

/// 目标正常关闭 → 服务端发 close_notify → 本地应用收到完整数据 + FIN。
#[test]
fn target_clean_close_reaches_app_as_fin() {
    let target = spawn_target("fin");
    let (_s, _c, cport) = spawn_pair("close_fin", 18591, 11591);
    let mut s = socks5_connect(cport, target).expect("SOCKS5 CONNECT");
    s.write_all(b"req").unwrap();
    assert_eq!(read_all_or_reset(&mut s), Ok(b"data".to_vec()), "干净结束应给本地 FIN");
}

/// 回归 (审计 D3): 目标 RST (下行不完整) → 服务端不发 close_notify → 本地应用必须看到 RST,
/// 不能是 FIN (否则以 EOF 定界的协议会把残缺数据当完整)。旧版这里是 FIN。
#[test]
fn target_reset_reaches_app_as_reset() {
    let target = spawn_target("rst");
    let (_s, _c, cport) = spawn_pair("close_rst", 18592, 11592);
    let mut s = socks5_connect(cport, target).expect("SOCKS5 CONNECT");
    s.write_all(b"req").unwrap();
    assert_eq!(read_all_or_reset(&mut s), Err(std::io::ErrorKind::ConnectionReset), "截断应给本地 RST");
}

/// 本地应用先结束写 (半关闭) 是正常收尾: 不支持半关闭 (服务端掐掉下行, 见 tcp_relay.rs 头注释),
/// 但本地应看到 FIN 而不是 RST —— 本地先关不能被误判为截断 (审计第 3 轮)。
#[test]
fn app_half_close_first_gets_fin_not_reset() {
    let target = spawn_target("slow");
    let (_s, _c, cport) = spawn_pair("close_half", 18593, 11593);
    let mut s = socks5_connect(cport, target).expect("SOCKS5 CONNECT");
    s.write_all(b"req").unwrap();
    std::thread::sleep(std::time::Duration::from_millis(100));
    s.shutdown(std::net::Shutdown::Write).unwrap();
    assert!(read_all_or_reset(&mut s).is_ok(), "本地先关应收 FIN, 不应被 RST");
}
