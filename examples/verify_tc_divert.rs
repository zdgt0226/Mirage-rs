//! 部署验证: tc-bpf + bpf_sk_assign 能否把转发的裸-IP 流量"偷"进本地
//! IP_TRANSPARENT socket, 并保留原始目的地 (IP_ORIGDSTADDR)。
//!
//! 这是 sk_assign 分流方案的机制分水岭 (对应 sk_lookup 那次的 origdst 验证)。
//! 用真实 tc_divert.elf, 在隔离 netns 里跑通:
//!   client → 8.8.8.8:9999 (裸-IP, 无 DNS) → 路由出 veth0 → veth1 ingress →
//!   tc_divert sk_assign → 本地透明 UDP socket 收到, origdst = 8.8.8.8:9999。
//!
//! 运行 (需 root + CAP_BPF/NET_ADMIN, 在新 netns 内, veth 已建好):
//!   见 verify_tc_divert.sh 或本文件尾注释。

use aya::maps::Array;
use aya::programs::{tc, SchedClassifier, TcAttachType};
use aya::Ebpf;
use std::net::{Ipv4Addr, SocketAddrV4};
use std::os::fd::{AsRawFd, FromRawFd, IntoRawFd, RawFd};

use nix::sys::socket::{
    bind, recvmsg, setsockopt, socket, sockopt, AddressFamily, ControlMessageOwned, MsgFlags,
    SockFlag, SockType, SockaddrIn,
};

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct DivertCfg {
    listen_port: u32,
}
unsafe impl aya::Pod for DivertCfg {}

const IFACE: &str = "veth1"; // tc ingress 挂这里 (client 发的包从 veth0 出 → veth1 入)
const LPORT: u16 = 19999; // 透明监听端口
const FOREIGN: &str = "8.8.8.8"; // 裸 foreign IP (路由出 veth0)
const FOREIGN_PORT: u16 = 9999; // foreign 服务端口 (应作为 origdst 保留)

fn build_transparent_udp(bind_addr: SocketAddrV4) -> anyhow::Result<std::net::UdpSocket> {
    let fd = socket(AddressFamily::Inet, SockType::Datagram, SockFlag::empty(), None)?;
    setsockopt(&fd, sockopt::ReuseAddr, &true)?;
    setsockopt(&fd, sockopt::IpTransparent, &true)?;
    setsockopt(&fd, sockopt::Ipv4OrigDstAddr, &true)?;
    let tv = nix::sys::time::TimeVal::new(3, 0);
    setsockopt(&fd, sockopt::ReceiveTimeout, &tv)?;
    bind(fd.as_raw_fd(), &SockaddrIn::from(bind_addr))?;
    Ok(unsafe { std::net::UdpSocket::from_raw_fd(fd.into_raw_fd()) })
}

fn recv_origdst(
    fd: RawFd,
    buf: &mut [u8],
) -> nix::Result<(usize, SocketAddrV4, Option<SocketAddrV4>)> {
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

fn main() -> anyhow::Result<()> {
    println!("== tc-bpf + bpf_sk_assign 裸-IP 拦截验证 ==");

    // 1. 加载 tc_divert.elf, 配置监听端口
    static ELF: &[u8] = aya::include_bytes_aligned!(env!("BPF_TC_DIVERT_ELF"));
    let mut bpf = Ebpf::load(ELF)?;
    {
        let mut cfg = Array::<_, DivertCfg>::try_from(bpf.map_mut("tc_divert_cfg").unwrap())?;
        cfg.set(0, DivertCfg { listen_port: LPORT as u32 }, 0)?;
    }

    // 2. veth1 ingress 挂 clsact + tc_divert
    let _ = tc::qdisc_add_clsact(IFACE);
    let prog: &mut SchedClassifier = bpf.program_mut("tc_divert").unwrap().try_into()?;
    prog.load()?;
    prog.attach(IFACE, TcAttachType::Ingress)?;
    println!("  [setup] tc_divert attached @ {} ingress, listen_port={}", IFACE, LPORT);

    // 3. 透明监听 socket (网关侧)。裸-IP 包由**另一个 netns 的 client** 发来
    //    (双 netns 拓扑, ARP 正常), 目的 8.8.8.8:9999。
    let sock = build_transparent_udp(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, LPORT))?;
    let target = SocketAddrV4::new(FOREIGN.parse().unwrap(), FOREIGN_PORT);
    println!("  [ready] 等 client 发裸-IP UDP → {} (5s)...", target);

    // 4. 透明 socket 应收到, origdst = 8.8.8.8:9999
    let mut buf = [0u8; 2048];
    match recv_origdst(sock.as_raw_fd(), &mut buf) {
        Ok((n, client, orig)) => {
            println!("  [recv] {} 字节, client={}, origdst={:?}", n, client, orig);
            match orig {
                Some(od) if od == target => {
                    println!("  ✅ PASS: tc sk_assign 把裸-IP 包偷进本地 socket, origdst={} 保留", od);
                }
                Some(od) => println!("  ⚠️  origdst={} 与目标 {} 不符", od, target),
                None => println!("  ⚠️  收到包但无 origdst cmsg"),
            }
        }
        Err(nix::errno::Errno::EAGAIN) => {
            println!("  ❌ 3s 未收到 —— tc_divert 未把包 sk_assign 进本地 socket");
            println!("     (可能: verifier 拒绝 / sk_lookup 没找到监听 / rp_filter 丢包)");
        }
        Err(e) => println!("  ❌ recvmsg 错误: {}", e),
    }
    Ok(())
}
