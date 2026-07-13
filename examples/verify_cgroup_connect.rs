//! 验证 cgroup/connect4 本机出向透明重定向机制:
//!   本机进程 connect(198.18.0.13:443) → connect4 改写为 127.0.0.1:19999 +
//!   存 origdst → sockops re-key srcport→origdst → listener accept 后按 peer 端口
//!   查回原始目的 198.18.0.13:443。这是"本机流量走代理"的机制分水岭 (对应
//!   tc_divert 那次的 sk_assign 验证)。
//!
//! cgroup 由 verify_cgroup_connect.sh 建好并经 MIRAGE_CG 传入; client 由脚本放进
//! 该 cgroup 后 connect (本进程 listener 不在该 cgroup, 不受改写影响)。

use aya::maps::{Array, HashMap};
use aya::programs::{CgroupAttachMode, CgroupSockAddr, SockOps};
use aya::Ebpf;
use std::net::{Ipv4Addr, TcpListener};
use std::os::fd::{AsRawFd, FromRawFd, IntoRawFd};

use nix::sys::socket::{
    bind, listen, setsockopt, socket, sockopt, AddressFamily, Backlog, SockFlag, SockType,
    SockaddrIn,
};

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct ConnectCfg {
    listen_ip: u32,    // 网络序
    listen_port: u32,  // host 序
    fakeip_net: u32,   // 网络序
    fakeip_mask: u32,  // 网络序
}
unsafe impl aya::Pod for ConnectCfg {}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct OrigDst {
    ip: u32,   // 网络序
    port: u32, // host 序
}
unsafe impl aya::Pod for OrigDst {}

const LPORT: u16 = 19999;
const FOREIGN: &str = "198.18.0.13"; // 模拟 fake-IP 目的
const FOREIGN_PORT: u16 = 443;

fn build_listener() -> anyhow::Result<TcpListener> {
    let fd = socket(AddressFamily::Inet, SockType::Stream, SockFlag::empty(), None)?;
    setsockopt(&fd, sockopt::ReuseAddr, &true)?;
    setsockopt(&fd, sockopt::ReceiveTimeout, &nix::sys::time::TimeVal::new(5, 0))?;
    bind(fd.as_raw_fd(), &SockaddrIn::from(std::net::SocketAddrV4::new(Ipv4Addr::LOCALHOST, LPORT)))?;
    listen(&fd, Backlog::new(128)?)?;
    Ok(unsafe { TcpListener::from_raw_fd(fd.into_raw_fd()) })
}

fn main() -> anyhow::Result<()> {
    println!("== cgroup/connect4 本机出向透明重定向验证 ==");
    let cg_path = std::env::var("MIRAGE_CG").unwrap_or_else(|_| "/sys/fs/cgroup/mirage_test".into());

    static ELF: &[u8] = aya::include_bytes_aligned!(env!("BPF_CGROUP_CONNECT_ELF"));
    let mut bpf = Ebpf::load(ELF)?;
    {
        let mut cfg = Array::<_, ConnectCfg>::try_from(bpf.map_mut("cc_cfg").unwrap())?;
        cfg.set(
            0,
            ConnectCfg {
                listen_ip: u32::from(Ipv4Addr::LOCALHOST).to_be(),
                listen_port: LPORT as u32,
                // fake-IP 段 198.18.0.0/15
                fakeip_net: u32::from(Ipv4Addr::new(198, 18, 0, 0)).to_be(),
                fakeip_mask: (!0u32 << (32 - 15)).to_be(),
            },
            0,
        )?;
    }

    let cg = std::fs::File::open(&cg_path)?;
    {
        let p: &mut CgroupSockAddr = bpf.program_mut("cc_connect4").unwrap().try_into()?;
        p.load()?;
        p.attach(&cg, CgroupAttachMode::Single)?;
    }
    {
        let p: &mut SockOps = bpf.program_mut("cc_sockops").unwrap().try_into()?;
        p.load()?;
        p.attach(&cg, CgroupAttachMode::Single)?;
    }
    println!("  [setup] connect4 + sockops attached @ {}", cg_path);

    let listener = build_listener()?;
    let expect_ip: Ipv4Addr = FOREIGN.parse().unwrap();
    println!("  [ready] 等 client connect {}:{} (被改写进 127.0.0.1:{}, 5s)...", expect_ip, FOREIGN_PORT, LPORT);

    match listener.accept() {
        Ok((_stream, peer)) => {
            let sport = peer.port() as u32; // 客户端源端口 (host)
            let ports = HashMap::<_, u32, OrigDst>::try_from(bpf.map("cc_port").unwrap())?;
            match ports.get(&sport, 0) {
                Ok(od) => {
                    let ip = Ipv4Addr::from(u32::from_be(od.ip));
                    println!("  [accept] peer={} → 查回 origdst {}:{}", peer, ip, od.port);
                    if ip == expect_ip && od.port == FOREIGN_PORT as u32 {
                        println!("  ✅ PASS: connect4 改写 + sockops re-key 还原原始目的 {}:{}", ip, od.port);
                    } else {
                        println!("  ❌ FAIL: origdst {}:{} != {}:{}", ip, od.port, expect_ip, FOREIGN_PORT);
                    }
                }
                Err(_) => println!("  ❌ FAIL: cc_port[{}] 无记录 (sockops re-key 没生效?)", sport),
            }
        }
        Err(e) => println!("  ❌ FAIL: 5s 未 accept (connect4 改写没生效?): {}", e),
    }
    Ok(())
}
