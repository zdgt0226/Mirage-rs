//! 验证 tc_divert 的 **TCP 分水岭**: sk_assign 偷来的外网-IP TCP SYN, 经
//! IP_TRANSPARENT listener 完成握手后, accept 出的 socket 的 local_addr() 是否
//! == 原始 foreign 目的 (而非 127.0.0.1 / 网关 IP)。这是透明 TCP 能否成立的关键。
//!
//! 网关侧 (本进程, 在 ns_gw 跑): 挂 tc_divert + IP_TRANSPARENT listener + accept。
//! client 侧 (ns_cli, 由 verify_tc_divert_tcp.sh 发起): TCP connect 8.8.8.8:9999。

use aya::maps::Array;
use aya::programs::{tc, SchedClassifier, TcAttachType};
use aya::Ebpf;
use std::io::Read;
use std::net::{Ipv4Addr, SocketAddrV4, TcpListener};
use std::os::fd::{AsRawFd, FromRawFd, IntoRawFd};

use nix::sys::socket::{
    bind, listen, setsockopt, socket, sockopt, AddressFamily, Backlog, SockFlag, SockType,
    SockaddrIn,
};

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct DivertCfg {
    listen_port: u32,
}
unsafe impl aya::Pod for DivertCfg {}

const IFACE: &str = "veth1";
const LPORT: u16 = 19999;
const FOREIGN: &str = "8.8.8.8";
const FOREIGN_PORT: u16 = 9999;

fn build_transparent_listener(bind_addr: SocketAddrV4) -> anyhow::Result<TcpListener> {
    let fd = socket(AddressFamily::Inet, SockType::Stream, SockFlag::empty(), None)?;
    setsockopt(&fd, sockopt::ReuseAddr, &true)?;
    setsockopt(&fd, sockopt::IpTransparent, &true)?;
    // accept 超时: 5s 没连接就放弃 (SO_RCVTIMEO 对 listen socket 的 accept 生效)
    setsockopt(&fd, sockopt::ReceiveTimeout, &nix::sys::time::TimeVal::new(5, 0))?;
    bind(fd.as_raw_fd(), &SockaddrIn::from(bind_addr))?;
    listen(&fd, Backlog::new(128)?)?;
    Ok(unsafe { TcpListener::from_raw_fd(fd.into_raw_fd()) })
}

fn main() -> anyhow::Result<()> {
    println!("== tc-bpf + sk_assign 透明 TCP 分水岭验证 (local_addr 保原始目的) ==");

    static ELF: &[u8] = aya::include_bytes_aligned!(env!("BPF_TC_DIVERT_ELF"));
    let mut bpf = Ebpf::load(ELF)?;
    {
        let mut cfg = Array::<_, DivertCfg>::try_from(bpf.map_mut("tc_divert_cfg").unwrap())?;
        cfg.set(0, DivertCfg { listen_port: LPORT as u32 }, 0)?;
    }
    let _ = tc::qdisc_add_clsact(IFACE);
    let prog: &mut SchedClassifier = bpf.program_mut("tc_divert").unwrap().try_into()?;
    prog.load()?;
    prog.attach(IFACE, TcAttachType::Ingress)?;
    println!("  [setup] tc_divert @ {} ingress, listen_port={}", IFACE, LPORT);

    let listener = build_transparent_listener(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, LPORT))?;
    let expect = SocketAddrV4::new(FOREIGN.parse().unwrap(), FOREIGN_PORT);
    println!("  [ready] 等 client TCP connect → {} (5s)...", expect);

    match listener.accept() {
        Ok((mut stream, peer)) => {
            let local = stream.local_addr()?;
            let mut buf = [0u8; 64];
            let n = stream.read(&mut buf).unwrap_or(0);
            println!("  [accept] peer={} local_addr={} 收到 {} 字节", peer, local, n);
            match local {
                std::net::SocketAddr::V4(l) if l == expect => {
                    println!("  ✅ PASS: local_addr()={} == 原始 foreign 目的, 透明 TCP 成立", l);
                }
                other => {
                    println!("  ❌ FAIL: local_addr()={} != 原始目的 {} (IP_TRANSPARENT 未生效?)", other, expect);
                }
            }
        }
        Err(e) => {
            println!("  ❌ FAIL: 5s 未 accept 到连接: {} (sk_assign/握手断?)", e);
        }
    }
    Ok(())
}
