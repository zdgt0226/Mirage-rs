//! 部署验证: tc_divert 的**孤儿过滤器**安全网 —— 透明 listener 不在时, 已建流的
//! TCP 包不该被打 fwmark。
//!
//! 为什么需要这个验证器 (v0.5.0):
//!   tc 过滤器自己持有 prog 引用, **不随进程消失**; 而 fwmark→local 路由表的 ip rule
//!   由独立的 mirage-gw-nat.service 装、只在卸载时删。进程被 SIGKILL 后两者叠加, 会把
//!   LAN 每个已建流的包引到 local 表却无 socket 可收 → 整段非直连 TCP 黑洞。
//!   tc_divert.c 的已建流路径因此加了 sk_lookup 门控: listener 不在就不打 mark。
//!   verify_tc_divert.sh 只覆盖 UDP sk_assign, 覆盖不到这条 TCP 已建流语义。
//!
//! 两个模式 (由 verify_tc_divert_orphan.sh 驱动, 结论看 nft 计数器):
//!   attach —— 挂 tc_divert 到 veth1 后 mem::forget(bpf) 再退出。aya 靠 Drop 摘 link,
//!             forget 掉就精确复现"进程没了、过滤器还挂着、listener 不存在"的孤儿态。
//!   listen —— 在 LPORT 上起 listener 并 hold 住 (对照组: listener 活着时 mark 必须照打,
//!             证明门控没把正常路径也一起掐了)。

use aya::maps::lpm_trie::{Key, LpmTrie};
use aya::maps::Array;
use aya::programs::{tc, SchedClassifier, TcAttachType};
use aya::Ebpf;
use std::net::{Ipv4Addr, TcpListener};

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

    // ★ 关键: 泄漏 Ebpf, 让 aya 不在 Drop 里摘 link → 进程退出后过滤器仍挂在网卡上,
    //   且没有任何 listener。这就是 SIGKILL 之后的真实状态。
    std::mem::forget(bpf);
    println!("  [attach] 已 mem::forget(bpf) → 退出后过滤器留在网卡上 (孤儿态)");
    Ok(())
}

fn do_listen() -> anyhow::Result<()> {
    let l = TcpListener::bind(("0.0.0.0", LPORT))?;
    println!("  [listen] listener @ 0.0.0.0:{} 已就绪", LPORT);
    // hold 住直到被杀; accept 不会真的等到连接 (测试只发裸 ACK)。
    for _ in l.incoming() {}
    Ok(())
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
