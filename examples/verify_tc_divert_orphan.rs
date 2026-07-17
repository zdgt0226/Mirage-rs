//! 部署验证: tc_divert 的**孤儿过滤器**安全网 —— 透明 listener 不在时, 已建流的
//! TCP 包不该被打 fwmark (否则配合 fwmark→local 的 ip rule 会黑洞掉 LAN 的非直连
//! TCP; 详见 tc_divert.c 已建流分支注释)。
//!
//! ⚠️ 为什么用**真实连接**而非合成裸 ACK (v0.5.0-alpha.6 之后重写):
//!   最初 case ① 用 raw socket 造一个凭空的 TCP ACK 打已建流分支。它在本机内核 6.1
//!   稳定, 但在 CI 的 5.15 上恒失败 —— 合成 ACK 无 conntrack 态 (INVALID)、skb 线性
//!   布局也可能不同, 早于 sk_lookup 的边界/校验处理在不同内核不一致。而
//!   bpf_sk_lookup_tcp 只认传入的 tuple、不认包内容, 且 SYN/已建两分支 tuple 字节一致;
//!   verify_tc_divert_tcp 用真实握手在 5.15 上跑通了同一段门控 (它路由 mark-gated,
//!   3rd ACK 能投递即证明门控在 5.15 找得到 listener)。故病灶在合成包, 不在产品。
//!   重写为真实流: 建真连接 → 杀 listener → 后续包 (客户端重传) 打已建流分支 → 门控
//!   查不到 listener → 不打 mark。全程只用内核自然产生的包。
//!
//! 三个模式 (由 verify_tc_divert_orphan.sh 驱动, 结论看 nft mark 计数器):
//!   attach —— 挂 tc_divert 到 veth1 后 mem::forget(bpf) 再退出。aya 靠 Drop 摘 link,
//!             forget 掉就让过滤器在进程退出后仍挂着 (孤儿态的物理基础)。
//!   listen —— IP_TRANSPARENT listener, accept 后 hold 住并持续 drain。收到 drop_flag
//!             文件后**只关掉 LISTEN socket、保留已 accept 的 child**: 门控查的是
//!             LISTEN socket (127.0.0.1:lport), 关掉它就让 sk_lookup 返回 null (复现
//!             "listener 没了"), 而 child (8.8.8.8:9999) 还在 → 客户端的流不被 RST,
//!             继续发包 —— 这样修复版/有 bug 版都持续有已建流包可测, 结论干净。

use aya::maps::lpm_trie::{Key, LpmTrie};
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
    mtu: u32,
}
unsafe impl aya::Pod for DivertCfg {}

const IFACE: &str = "veth1";
const LPORT: u16 = 19999;
const DIRECT_CIDR: &str = "1.1.1.0";

fn do_attach() -> anyhow::Result<()> {
    static ELF: &[u8] = aya::include_bytes_aligned!(env!("BPF_TC_DIVERT_ELF"));
    let mut bpf = Ebpf::load(ELF)?;
    {
        let mut cfg = Array::<_, DivertCfg>::try_from(bpf.map_mut("tc_divert_cfg").unwrap())?;
        cfg.set(0, DivertCfg { listen_port: LPORT as u32, mtu: 0 }, 0)?;
    }
    {
        let mut trie = LpmTrie::<_, u32, u8>::try_from(bpf.map_mut("direct_cidr").unwrap())?;
        let net: u32 = u32::from(DIRECT_CIDR.parse::<Ipv4Addr>().unwrap()).to_be();
        trie.insert(&Key::new(24, net), 1u8, 0)?;
    }
    let _ = tc::qdisc_add_clsact(IFACE);
    let prog: &mut SchedClassifier = bpf.program_mut("tc_divert").unwrap().try_into()?;
    prog.load()?;
    prog.attach(IFACE, TcAttachType::Ingress)?;
    println!("  [attach] tc_divert @ {} ingress, listen_port={}", IFACE, LPORT);

    // ★ 泄漏 Ebpf, 让 aya 不在 Drop 里摘 link → 进程退出后过滤器仍挂在网卡上。
    std::mem::forget(bpf);
    println!("  [attach] 已 mem::forget(bpf) → 退出后过滤器留在网卡上 (孤儿态物理基础)");
    Ok(())
}

fn do_listen() -> anyhow::Result<()> {
    // 第二个参数 = drop_flag 路径: 该文件一出现就关掉 LISTEN socket (保留 child)。
    let drop_flag = std::env::args().nth(2).unwrap_or_default();

    // IP_TRANSPARENT: sk_assign 偷来的外网-IP SYN 要靠透明 listener 才能完成握手
    // (绑非本地 foreign 目的)。plain listener 会握手悬死。
    let fd = socket(AddressFamily::Inet, SockType::Stream, SockFlag::empty(), None)?;
    setsockopt(&fd, sockopt::ReuseAddr, &true)?;
    setsockopt(&fd, sockopt::IpTransparent, &true)?;
    // accept 超时 200ms: 让 accept 周期性返回, 好在两次之间检查 drop_flag。
    setsockopt(&fd, sockopt::ReceiveTimeout, &nix::sys::time::TimeVal::new(0, 200_000))?;
    bind(fd.as_raw_fd(), &SockaddrIn::from(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, LPORT)))?;
    listen(&fd, Backlog::MAXCONN)?;
    let l = unsafe { TcpListener::from_raw_fd(fd.into_raw_fd()) };
    println!("  [listen] IP_TRANSPARENT listener @ 0.0.0.0:{} 就绪", LPORT);

    // accept 循环放主线程 (持有唯一 LISTEN fd); child 各起线程 drain, 持有自己的 fd。
    loop {
        if !drop_flag.is_empty() && std::path::Path::new(&drop_flag).exists() {
            break; // 只 drop LISTEN socket, child 线程继续存活
        }
        match l.accept() {
            Ok((mut s, _)) => {
                std::thread::spawn(move || {
                    let mut buf = [0u8; 1024];
                    while let Ok(n) = s.read(&mut buf) {
                        if n == 0 {
                            break;
                        }
                    }
                });
            }
            Err(_) => continue, // accept 超时 (WouldBlock) 或瞬时错误 → 回去查 flag
        }
    }
    drop(l); // 关掉 LISTEN socket: sk_lookup(127.0.0.1:lport) 从此返回 null
    println!("  [listen] LISTEN socket 已关 (child 保留); sk_lookup 应查不到 listener");
    // hold 住进程 (维持 child 线程/连接), 等 shell 在 cleanup 里杀。
    loop {
        std::thread::sleep(std::time::Duration::from_secs(3600));
    }
}

fn main() -> anyhow::Result<()> {
    match std::env::args().nth(1).as_deref() {
        Some("attach") => do_attach(),
        Some("listen") => do_listen(),
        _ => {
            eprintln!("usage: verify_tc_divert_orphan {{attach|listen}}");
            std::process::exit(2);
        }
    }
}
