//! 部署验证: sk_lookup UDP 透明代理的两个内核行为分水岭。
//!
//! 用**真实的 transparent.elf** 在隔离 netns 里跑完整路径, 回答:
//!   ① sk_lookup 的 bpf_sk_assign 把 UDP 包投给我们的 socket 后,
//!      IP_RECVORIGDSTADDR/recvmsg 能否报出**原始 fake-IP 目的地**?
//!   ② 收包 socket 是否**必须** IP_TRANSPARENT 才能收到重定向包?
//!
//! 运行 (需 root + kernel≥5.9 + CAP_BPF/NET_ADMIN, 在新 netns 内):
//!   unshare -n bash -c '
//!     ip link set lo up
//!     ip route add local 198.18.0.0/16 dev lo
//!     ./target/debug/examples/verify_udp_transparent
//!   '

use aya::maps::{Array, SockMap};
use aya::programs::SkLookup;
use aya::Ebpf;
use std::net::{Ipv4Addr, SocketAddrV4};
use std::os::fd::{AsRawFd, FromRawFd, IntoRawFd, RawFd};

use nix::sys::socket::{
    bind, recvmsg, setsockopt, socket, sockopt, AddressFamily, ControlMessageOwned, MsgFlags,
    SockFlag, SockType, SockaddrIn,
};

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct FakeIpCfg {
    net: u32,
    mask: u32,
}
unsafe impl aya::Pod for FakeIpCfg {}

/// 建 UDP socket, 可选 IP_TRANSPARENT。始终开 IP_RECVORIGDSTADDR。
/// 返回 std blocking socket (2s recv 超时, 免 hang)。
fn build_udp_socket(bind_addr: SocketAddrV4, transparent: bool) -> anyhow::Result<std::net::UdpSocket> {
    let fd = socket(
        AddressFamily::Inet,
        SockType::Datagram,
        SockFlag::empty(),
        None,
    )?;
    setsockopt(&fd, sockopt::ReuseAddr, &true)?;
    if transparent {
        setsockopt(&fd, sockopt::IpTransparent, &true)?;
    }
    setsockopt(&fd, sockopt::Ipv4OrigDstAddr, &true)?; // IP_RECVORIGDSTADDR
    // 2s recv 超时
    let tv = nix::sys::time::TimeVal::new(2, 0);
    setsockopt(&fd, sockopt::ReceiveTimeout, &tv)?;
    bind(fd.as_raw_fd(), &SockaddrIn::from(bind_addr))?;
    Ok(unsafe { std::net::UdpSocket::from_raw_fd(fd.into_raw_fd()) })
}

/// 一次 recvmsg, 取 (字节数, 客户端源, 原始目的)。origdst 缺失返回 None。
fn recv_origdst(fd: RawFd, buf: &mut [u8]) -> nix::Result<(usize, SocketAddrV4, Option<SocketAddrV4>)> {
    let mut iov = [std::io::IoSliceMut::new(buf)];
    let mut cmsg = nix::cmsg_space!(libc::sockaddr_in);
    let msg = recvmsg::<SockaddrIn>(fd, &mut iov, Some(&mut cmsg), MsgFlags::empty())?;
    let client = msg.address.ok_or(nix::errno::Errno::EINVAL)?;
    let client = SocketAddrV4::new(Ipv4Addr::from(client.ip()), client.port());
    let mut orig = None;
    for c in msg.cmsgs()? {
        if let ControlMessageOwned::Ipv4OrigDstAddr(sa) = c {
            orig = Some(SocketAddrV4::new(
                Ipv4Addr::from(u32::from_be(sa.sin_addr.s_addr)),
                u16::from_be(sa.sin_port),
            ));
        }
    }
    Ok((msg.bytes, client, orig))
}

/// 加载 + 配置 + attach transparent.elf 的 sk_lookup 到当前 netns。返回 Ebpf (须持有以维持 attach)。
fn load_and_attach() -> anyhow::Result<Ebpf> {
    static ELF: &[u8] = aya::include_bytes_aligned!(env!("BPF_TRANSPARENT_ELF"));
    let mut bpf = Ebpf::load(ELF)?;

    // fake-IP 网段 198.18.0.0/16 (RFC 2544 benchmark 段, 不冲突)
    let mut cfg_map = Array::<_, FakeIpCfg>::try_from(bpf.map_mut("mirage_fakeip_cfg").unwrap())?;
    let net = u32::from(Ipv4Addr::new(198, 18, 0, 0)).to_be();
    let mask = (!0u32 << (32 - 16)).to_be();
    cfg_map.set(0, FakeIpCfg { net: net & mask, mask }, 0)?;

    let netns = std::fs::File::open("/proc/self/ns/net")?;
    let prog: &mut SkLookup = bpf.program_mut("mirage_sk_lookup").unwrap().try_into()?;
    prog.load()?;
    prog.attach(netns)?;
    println!("  [setup] transparent.elf loaded, sk_lookup attached, fake-IP=198.18.0.0/16");
    Ok(bpf)
}

/// 返回本 case 是否达成预期 (origdst 正确报出 fake-IP)。调用方决定它是"必须通过"还是"对照观察"。
fn run_case(bpf: &mut Ebpf, transparent: bool, bind_port: u16, target: SocketAddrV4) -> anyhow::Result<bool> {
    let label = if transparent { "IP_TRANSPARENT=on" } else { "IP_TRANSPARENT=off" };
    println!("\n=== case: {} → 目标 fake-IP {} ===", label, target);

    let sock = build_udp_socket(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, bind_port), transparent)?;
    // 注册进 udp sockmap
    {
        let mut udpmap = SockMap::try_from(bpf.map_mut("mirage_udp_sk").unwrap())?;
        udpmap.set(0, &sock, 0)?;
    }

    // 从独立 socket 往 fake-IP 发 UDP
    let sender = std::net::UdpSocket::bind("0.0.0.0:0")?;
    let payload = b"verify-origdst";
    sender.send_to(payload, target)?;
    println!("  [send] {} bytes → {}", payload.len(), target);

    let mut buf = [0u8; 2048];
    let ok = match recv_origdst(sock.as_raw_fd(), &mut buf) {
        Ok((n, client, orig)) => {
            println!("  [recv] {} bytes, client={}, origdst={:?}", n, client, orig);
            let data_ok = &buf[..n] == payload;
            match orig {
                Some(od) if od == target && data_ok => {
                    println!("  ✅ PASS: sk_assign 后 IP_ORIGDSTADDR 正确报出 fake-IP {}", od);
                    true
                }
                Some(od) => {
                    println!("  ⚠️  origdst={} 与目标 {} 不一致 (data_ok={})", od, target, data_ok);
                    false
                }
                None => {
                    println!("  ⚠️  收到包但 origdst cmsg 缺失 —— IP_RECVORIGDSTADDR 未生效?");
                    false
                }
            }
        }
        Err(nix::errno::Errno::EAGAIN) => {
            println!("  ❌ 2s 内未收到包 —— sk_lookup 未把 UDP 投给本 socket (transparent={})", transparent);
            false
        }
        Err(e) => {
            println!("  ❌ recvmsg 错误: {}", e);
            false
        }
    };
    Ok(ok)
}

/// ③ 回包源地址伪造: reply socket 用 IP_TRANSPARENT+IP_FREEBIND 绑到**非本地**
/// 地址, send 时源地址应是该绑定地址 (client 会看到回包来自 fake-IP:port)。
fn run_reply_spoof() -> anyhow::Result<bool> {
    println!("\n=== case: reply socket 源地址伪造 (IP_TRANSPARENT+IP_FREEBIND) ===");
    // 监听方 (模拟客户端)
    let listener = std::net::UdpSocket::bind("127.0.0.1:0")?;
    listener.set_read_timeout(Some(std::time::Duration::from_secs(2)))?;
    let listener_addr = listener.local_addr()?;

    // 非本地伪造源 (无任何接口/路由持有它 → 绑定必须 FREEBIND)
    let spoof_src = SocketAddrV4::new(Ipv4Addr::new(10, 77, 88, 99), 443);
    let fd = socket(AddressFamily::Inet, SockType::Datagram, SockFlag::empty(), None)?;
    setsockopt(&fd, sockopt::ReuseAddr, &true)?;
    setsockopt(&fd, sockopt::IpTransparent, &true)?;
    setsockopt(&fd, sockopt::IpFreebind, &true)?;
    match bind(fd.as_raw_fd(), &SockaddrIn::from(spoof_src)) {
        Ok(_) => println!("  [bind] IP_TRANSPARENT+FREEBIND 绑非本地 {} 成功", spoof_src),
        Err(e) => {
            println!("  ❌ 绑非本地 {} 失败: {} (FREEBIND 未生效?)", spoof_src, e);
            return Ok(false);
        }
    }
    let reply_sock = unsafe { std::net::UdpSocket::from_raw_fd(fd.into_raw_fd()) };

    reply_sock.send_to(b"reply-spoof", listener_addr)?;
    println!("  [send] 从伪造源 {} → {}", spoof_src, listener_addr);

    let mut buf = [0u8; 128];
    let ok = match listener.recv_from(&mut buf) {
        Ok((n, src)) => {
            println!("  [recv] listener 收到 {} 字节, 源={}", n, src);
            if src == std::net::SocketAddr::V4(spoof_src) {
                println!("  ✅ PASS: 回包源被伪造成 {} (客户端会认为回包来自 fake-IP:port)", spoof_src);
                true
            } else {
                println!("  ⚠️  源={} 不是伪造的 {} —— 源伪造未生效", src, spoof_src);
                false
            }
        }
        Err(e) => {
            println!("  ❌ listener 2s 未收到 (源伪造包被丢?): {}", e);
            false
        }
    };
    Ok(ok)
}

fn main() -> anyhow::Result<()> {
    println!("== sk_lookup UDP 透明代理内核行为验证 ==");
    let mut bpf = load_and_attach()?;

    // ① 主验证: IP_TRANSPARENT 开, 看 origdst 是否报出 fake-IP —— **必须通过**
    let case1 = run_case(&mut bpf, true, 19999, SocketAddrV4::new(Ipv4Addr::new(198, 18, 0, 7), 12345))?;

    // ② 对照实验: IP_TRANSPARENT 关, 看是否还能收到重定向包 (判断该选项是否必须)。
    //    **两种结果都只是信息, 不参与成败判定** —— 收不到恰恰说明 IP_TRANSPARENT 是必需的。
    let case2 = run_case(&mut bpf, false, 19998, SocketAddrV4::new(Ipv4Addr::new(198, 18, 0, 8), 12345))?;

    // ③ 回包源伪造 (IP_TRANSPARENT+FREEBIND) —— **必须通过**
    let case3 = run_reply_spoof()?;

    println!("\n== 汇总 ==");
    println!("  ① origdst 报出 fake-IP (必须通过): {}", if case1 { "✅ PASS" } else { "❌ FAIL" });
    println!("  ② 对照 IP_TRANSPARENT=off 能否收到 (仅信息): {}", if case2 { "收到了" } else { "收不到 (即该选项必需)" });
    println!("  ③ 回包源伪造 (必须通过): {}", if case3 { "✅ PASS" } else { "❌ FAIL" });

    // ⚠️ 用退出码表达结论: 本验证器在 CI 里跑, 只 println 的话失败也是绿灯 (假信心)。
    if !case1 || !case3 {
        eprintln!("\n❌ 关键 case 未通过 → 退出码 1");
        std::process::exit(1);
    }
    println!("\n✅ 全部关键 case 通过");
    Ok(())
}
