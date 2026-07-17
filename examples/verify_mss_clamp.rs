//! 验证 TC MSS clamp: loopback 上挂 mss_clamp (mtu=1400 → max_mss=1360), 做一次
//! 127.0.0.1 TCP 握手。lo ingress 会钳制 SYN/SYN-ACK 的 MSS 选项, accepted socket
//! 的 TCP_MAXSEG 应从 loopback 默认 ~65495 被钳到 ≤1360。
//!
//! 在独立 netns 里跑 (见 verify_mss_clamp.sh), 免动宿主 lo 的 clsact。

use aya::maps::Array;
use aya::programs::{tc, SchedClassifier, TcAttachType};
use aya::Ebpf;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::os::fd::AsRawFd;

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct MssCfg {
    mtu: u32,
}
unsafe impl aya::Pod for MssCfg {}

const MTU: u32 = 1400; // → max_mss = 1360

fn tcp_maxseg(fd: i32) -> i32 {
    let mut mss: libc::c_int = 0;
    let mut len = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
    unsafe {
        libc::getsockopt(
            fd,
            libc::IPPROTO_TCP,
            libc::TCP_MAXSEG,
            &mut mss as *mut _ as *mut libc::c_void,
            &mut len,
        );
    }
    mss
}

fn main() -> anyhow::Result<()> {
    println!("== TC MSS clamp 验证 (loopback, mtu={} → max_mss={}) ==", MTU, MTU - 40);

    static ELF: &[u8] = aya::include_bytes_aligned!(env!("BPF_MSS_CLAMP_ELF"));
    let mut bpf = Ebpf::load(ELF)?;
    {
        let mut cfg = Array::<_, MssCfg>::try_from(bpf.map_mut("mss_cfg").unwrap())?;
        cfg.set(0, MssCfg { mtu: MTU }, 0)?;
    }
    let _ = tc::qdisc_add_clsact("lo");
    let prog: &mut SchedClassifier = bpf.program_mut("mss_clamp").unwrap().try_into()?;
    prog.load()?;
    prog.attach("lo", TcAttachType::Ingress)?;
    println!("  [setup] mss_clamp @ lo ingress");

    let listener = TcpListener::bind("127.0.0.1:0")?;
    let addr = listener.local_addr()?;

    let cli = std::thread::spawn(move || {
        let mut s = TcpStream::connect(addr).unwrap();
        let _ = s.write_all(b"hi");
        let mut b = [0u8; 4];
        let _ = s.read(&mut b);
    });

    let (mut server, _peer) = listener.accept()?;
    let mss = tcp_maxseg(server.as_raw_fd());
    let _ = server.write_all(b"ok");
    let mut b = [0u8; 4];
    let _ = server.read(&mut b);
    let _ = cli.join();

    println!("  [recv] accepted socket TCP_MAXSEG = {}", mss);
    if mss > 0 && mss <= (MTU - 40) as i32 {
        println!("  ✅ PASS: MSS 被钳制到 {} ≤ {} (loopback 默认 ~65495)", mss, MTU - 40);
    } else {
        // ⚠️ 退出码表达结论 (CI 里跑, 只 println 失败也绿灯)
        println!("  ❌ FAIL: MSS={} 未被钳制 (期望 ≤{})", mss, MTU - 40);
        std::process::exit(1);
    }
    Ok(())
}
