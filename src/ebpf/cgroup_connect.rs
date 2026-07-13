//! cgroup/connect4 本机出向透明重定向引擎 (纯 eBPF, 无 sockmap/iptables)。
//!
//! tc_divert(ingress) 只抓转发流量; 本机自身流量走本地出向、碰不到 ingress。
//! 本引擎在进程 connect() 时把落在 fake-IP 段的目的改写为本地透明 listener,
//! 让网关本机自己的流量也能进代理。机制与 netns 实测见 ebpf-src/cgroup_connect.c
//! 与 examples/verify_cgroup_connect.{rs,sh}。
//!
//! origdst 恢复: connect4 存 cookie→origdst, sockops 存 srcport→origdst, listener
//! accept 后按 peer 端口查回原始 fake-IP (lookup_origdst)。

#[cfg(all(feature = "ebpf", target_os = "linux"))]
mod sys {
    use anyhow::{Context, Result};
    use aya::maps::{Array, HashMap};
    use aya::programs::{CgroupAttachMode, CgroupSockAddr, SockOps};
    use aya::Ebpf;
    use std::net::Ipv4Addr;
    use std::sync::Mutex;
    use tracing::info;

    #[repr(C)]
    #[derive(Clone, Copy, Default)]
    struct ConnectCfg {
        listen_ip: u32,   // 网络序
        listen_port: u32, // host 序
        fakeip_net: u32,  // 网络序
        fakeip_mask: u32, // 网络序
    }
    unsafe impl aya::Pod for ConnectCfg {}

    #[repr(C)]
    #[derive(Clone, Copy, Default)]
    struct OrigDst {
        ip: u32,   // 网络序
        port: u32, // host 序
    }
    unsafe impl aya::Pod for OrigDst {}

    pub struct CgroupConnectEngine {
        bpf: Mutex<Ebpf>,
    }

    impl CgroupConnectEngine {
        pub fn init(listen_port: u16, fakeip_net: Ipv4Addr, prefix_len: u8) -> Result<Self> {
            static ELF: &[u8] = aya::include_bytes_aligned!(env!("BPF_CGROUP_CONNECT_ELF"));
            let mut bpf = Ebpf::load(ELF).context("Failed to load cgroup_connect.elf")?;
            let mask: u32 = if prefix_len == 0 { 0 } else { !0u32 << (32 - prefix_len) };
            {
                let mut cfg = Array::<_, ConnectCfg>::try_from(
                    bpf.map_mut("cc_cfg").context("cc_cfg map missing")?,
                )?;
                cfg.set(
                    0,
                    ConnectCfg {
                        listen_ip: u32::from(Ipv4Addr::LOCALHOST).to_be(),
                        listen_port: listen_port as u32,
                        fakeip_net: (u32::from(fakeip_net) & mask).to_be(),
                        fakeip_mask: mask.to_be(),
                    },
                    0,
                )?;
            }
            info!("eBPF cgroup_connect engine initialized (listen_port={}, fake-IP={}/{})", listen_port, fakeip_net, prefix_len);
            Ok(Self { bpf: Mutex::new(bpf) })
        }

        /// attach connect4 + sockops 到指定 cgroup (通常根 cgroup /sys/fs/cgroup)。
        pub fn attach(&self, cgroup_path: &str) -> Result<()> {
            let cg = std::fs::File::open(cgroup_path)
                .with_context(|| format!("open cgroup {}", cgroup_path))?;
            let mut bpf = self.bpf.lock().unwrap_or_else(|e| e.into_inner());
            {
                let p: &mut CgroupSockAddr =
                    bpf.program_mut("cc_connect4").context("cc_connect4 missing")?.try_into()?;
                p.load()?;
                p.attach(&cg, CgroupAttachMode::Single).context("attach cc_connect4")?;
            }
            {
                let p: &mut SockOps =
                    bpf.program_mut("cc_sockops").context("cc_sockops missing")?.try_into()?;
                p.load()?;
                p.attach(&cg, CgroupAttachMode::Single).context("attach cc_sockops")?;
            }
            info!("eBPF cgroup_connect attached to {} (本机出向 fake-IP 重定向)", cgroup_path);
            Ok(())
        }

        /// listener accept 后按 peer(客户端)源端口查回原始 fake-IP:port。查到即消费删除。
        pub fn lookup_origdst(&self, src_port: u16) -> Option<(Ipv4Addr, u16)> {
            let mut bpf = self.bpf.lock().unwrap_or_else(|e| e.into_inner());
            let mut map = HashMap::<_, u32, OrigDst>::try_from(bpf.map_mut("cc_port")?).ok()?;
            let key = src_port as u32;
            let od = map.get(&key, 0).ok()?;
            let _ = map.remove(&key);
            Some((Ipv4Addr::from(u32::from_be(od.ip)), od.port as u16))
        }
    }
}

#[cfg(not(all(feature = "ebpf", target_os = "linux")))]
mod sys {
    use anyhow::Result;
    use std::net::Ipv4Addr;

    pub struct CgroupConnectEngine {}

    impl CgroupConnectEngine {
        pub fn init(_listen_port: u16, _fakeip_net: Ipv4Addr, _prefix_len: u8) -> Result<Self> {
            Err(anyhow::anyhow!("eBPF disabled"))
        }
        pub fn attach(&self, _cgroup_path: &str) -> Result<()> {
            Ok(())
        }
        pub fn lookup_origdst(&self, _src_port: u16) -> Option<(Ipv4Addr, u16)> {
            None
        }
    }
}

pub use sys::CgroupConnectEngine;
