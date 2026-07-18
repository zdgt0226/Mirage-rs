//! 部署验证: XDP 极速 DNS (dns_xdp.c) 端到端功能 + **哈希一致性**。
//!
//! 为什么需要 (v0.5.0-alpha.8): dns_xdp 曾在内核 ≥6.1 上加载被拒 (符号扩展/BPF-to-BPF
//! call/嵌套 unroll 状态爆炸), 重写 hash_domain 修复后仅验了"能加载 + 读双方实现核对哈希",
//! 没做端到端。本验证器补上: 用户态按**域名字符串** DJB2 灌 map, BPF 从**wire 查询**算哈希
//! 查表 —— 命中才回 fake-IP。两个哈希只要有一字节不一致, 这里就 miss → 测试失败。所以它
//! 同时证明: ①XDP 收包→改包→XDP_TX 回包整条通; ②BPF/用户态哈希逐字节一致。
//!
//! serve 模式 (由 verify_dns_xdp.sh 在 ns_srv 跑): 灌 map + attach XDP 到 veth1, hold 住。
//! 客户端 (ns_cli) 发 test.mirage 的 A 查询, 期望收到 198.18.0.99。

use aya::maps::HashMap as AyaHashMap;
use aya::programs::{Xdp, XdpFlags};
use aya::Ebpf;
use std::net::Ipv4Addr;

const IFACE: &str = "veth1";
const DOMAIN: &str = "test.mirage";
const FAKE_IP: Ipv4Addr = Ipv4Addr::new(198, 18, 0, 99);

/// DJB2, 与用户态 src/ebpf/mod.rs::update_dns_cache 完全一致 (逐 label 字符/跳点/小写)。
/// 复制而非调用, 是为了让本验证器独立于 XdpEngine, 直接操作 map。
fn djb2_domain(domain: &str) -> u64 {
    let mut hash: u64 = 5381;
    for part in domain.split('.') {
        for &c in part.as_bytes() {
            let mut b = c;
            if b.is_ascii_uppercase() {
                b += 32;
            }
            hash = (hash << 5).wrapping_add(hash).wrapping_add(b as u64);
        }
    }
    hash
}

fn main() -> anyhow::Result<()> {
    match std::env::args().nth(1).as_deref() {
        Some("serve") => {}
        _ => {
            eprintln!("usage: verify_dns_xdp serve");
            std::process::exit(2);
        }
    }

    static ELF: &[u8] = aya::include_bytes_aligned!(env!("BPF_DNS_XDP_ELF"));
    let mut bpf = Ebpf::load(ELF)?;

    // 1. 灌 map: hash(域名字符串) → fake-IP (网络序 u32, 与 update_dns_cache 一致)。
    {
        let mut cache =
            AyaHashMap::<_, u64, u32>::try_from(bpf.map_mut("mirage_dns_cache").unwrap())?;
        let key = djb2_domain(DOMAIN);
        let val = u32::from(FAKE_IP).to_be();
        cache.insert(key, val, 0)?;
        println!("  [serve] map 灌入 hash({})={:#x} → {}", DOMAIN, key, FAKE_IP);
    }

    // 2. attach XDP 到 veth1。**强制 SKB/generic 模式**: veth 上原生(DRV)XDP_TX 有已知怪癖
    //    (改包后 TX 不回对端), generic 走常规栈路径可靠。生产挂真实网卡用 DRV 无此问题,
    //    本验证器只为验逻辑/哈希, 用 SKB 即可。
    let prog: &mut Xdp = bpf.program_mut("mirage_xdp_dns").unwrap().try_into()?;
    prog.load()?;
    prog.attach(IFACE, XdpFlags::SKB_MODE)?;
    println!("  [serve] dns_xdp attached @ {} (等客户端发 {} 的 A 查询)", IFACE, DOMAIN);

    // hold 住 (维持 attach + map), 等 .sh 在测完后杀。
    loop {
        std::thread::sleep(std::time::Duration::from_secs(3600));
    }
}
