#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct TcpState {
    pub srtt_us: u32,
    pub snd_cwnd: u32,
    pub total_retrans: u32,
    pub data_segs_out: u32,
}

#[cfg(all(feature = "ebpf", target_os = "linux"))]
unsafe impl aya::Pod for TcpState {}

#[cfg(all(feature = "ebpf", target_os = "linux"))]
mod sys {
    use anyhow::Result;
    use aya::{Ebpf, programs::{SkSkb, SockOps, CgroupAttachMode, Xdp, XdpFlags}};
    use aya::maps::{SockHash, PerCpuArray, HashMap};
    use std::os::unix::io::AsRawFd;
    
    pub fn ip_to_key(ip: std::net::IpAddr) -> [u32; 5] {
        match ip {
            std::net::IpAddr::V4(v4) => [2, 0, 0, 0, u32::from(v4).to_be()],
            std::net::IpAddr::V6(v6) => {
                let b = v6.octets();
                [
                    10,
                    u32::from_ne_bytes(b[0..4].try_into().unwrap()),
                    u32::from_ne_bytes(b[4..8].try_into().unwrap()),
                    u32::from_ne_bytes(b[8..12].try_into().unwrap()),
                    u32::from_ne_bytes(b[12..16].try_into().unwrap()),
                ]
            }
        }
    }
    use tokio::net::TcpStream;
    use tracing::info;

    pub struct EbpfEngine {
        bpf: Ebpf,
    }

    pub struct XdpEngine {
        bpf: std::sync::Mutex<Ebpf>,
        pub attached: std::sync::atomic::AtomicU8,
    }

    impl EbpfEngine {
        pub fn init() -> Result<Self> {
            static SOCKMAP_ELF: &[u8] = aya::include_bytes_aligned!(env!("BPF_SOCKMAP_ELF"));
            let mut bpf = Ebpf::load(SOCKMAP_ELF)?;
            
            let sockmap_fd = {
                let map = bpf.map("mirage_sockmap").unwrap();
                let sock_map = SockHash::<_, u64>::try_from(map)?;
                sock_map.fd().try_clone()?.try_into()?
            };
            
            let program: &mut SkSkb = bpf.program_mut("mirage_stream_verdict").unwrap().try_into()?;
            program.load()?;
            program.attach(&sockmap_fd)?;
            
            // Try attaching sockops for RTT monitoring
            let mut sockops_attached = false;
            if let Some(prog) = bpf.program_mut("mirage_sockops") {
                if let Ok(sockops) = TryInto::<&mut SockOps>::try_into(prog) {
                    if sockops.load().is_ok() {
                        let mut cgroup_paths = vec![];
                        if let Ok(content) = std::fs::read_to_string("/proc/self/cgroup") {
                            if let Some(line) = content.lines().find(|l| l.starts_with("0::")) {
                                if let Some(rel) = line.strip_prefix("0::") {
                                    cgroup_paths.push(format!("/sys/fs/cgroup{}", rel.trim()));
                                }
                            }
                        }
                        cgroup_paths.push("/sys/fs/cgroup".to_string());
                        cgroup_paths.push("/sys/fs/cgroup/unified".to_string());
                        
                        for path in cgroup_paths {
                            if let Ok(cg) = std::fs::File::open(&path) {
                                match sockops.attach(cg, CgroupAttachMode::Single) {
                                    Ok(_) => {
                                        info!("eBPF SockOps attached to {}", path);
                                        sockops_attached = true;
                                        break;
                                    }
                                    Err(e) => tracing::warn!("eBPF SockOps attach to {} failed: {}", path, e),
                                }
                            }
                        }
                    }
                }
            }
            if !sockops_attached {
                tracing::warn!("RTT monitoring unavailable: cgroup attach failed on all paths. Verify cgroup v2 mount and CAP_NET_ADMIN.");
            }
            
            info!("eBPF Engine initialized! Waiting for registrations.");
            Ok(Self { bpf })
        }

        pub fn register_splice(&mut self, local: &TcpStream, remote: &TcpStream) -> Result<()> {
            let mut map = SockHash::<_, u64>::try_from(self.bpf.map_mut("mirage_sockmap").unwrap())?;
            
            let local_cookie = get_socket_cookie(local.as_raw_fd())?;
            let remote_cookie = get_socket_cookie(remote.as_raw_fd())?;
            
            let local_fd = local.as_raw_fd();
            let remote_fd = remote.as_raw_fd();
            
            map.insert(local_cookie, remote_fd, 0)?;
            map.insert(remote_cookie, local_fd, 0)?;
            
            info!("eBPF SockMap: spliced local_cookie={} <-> remote_cookie={} (Zero-copy bypass activated)", local_cookie, remote_cookie);
            Ok(())
        }
        pub fn get_stats(&self) -> Result<(u64, u64)> {
            let map = self.bpf.map("mirage_bpf_stats").unwrap();
            let hash = PerCpuArray::<_, u64>::try_from(map)?;
            let sum_up = hash.get(&0, 0)?.iter().copied().sum();
            let sum_down = hash.get(&2, 0)?.iter().copied().sum();
            Ok((sum_up, sum_down))
        }
        
        /**
         * [读取底层 TCP 状态]
         * 通过 Socket 的唯一 Cookie，从内核 LRU Cache 中提取 RTT 和丢包指标。
         * 这比传统的 getsockopt(TCP_INFO) 快，并且完全规避了用户态锁竞争。
         */
        pub fn get_tcp_state_by_cookie(&self, cookie: u64) -> Result<crate::ebpf::TcpState> {
            let map = self.bpf.map("mirage_rtt_map").unwrap();
            let hash = HashMap::<_, u64, crate::ebpf::TcpState>::try_from(map)?;
            hash.get(&cookie, 0).map_err(|e| e.into())
        }
        
        /**
         * [添加监控白名单]
         * 只有被登记到此 Map 的 IP，底层的 bpf_sockops 程序才会收集它的 TCP 信息。
         */
        pub fn set_target_ip(&mut self, ip: std::net::IpAddr) -> Result<()> {
            let map = self.bpf.map_mut("mirage_target_ips").unwrap();
            let mut hash = HashMap::<_, [u32; 5], u8>::try_from(map)?;
            let key = ip_to_key(ip);
            hash.insert(key, 1, 0)?;
            Ok(())
        }
    }



    impl XdpEngine {
        pub fn init() -> Result<Self> {
            static DNS_XDP_ELF: &[u8] = aya::include_bytes_aligned!(env!("BPF_DNS_XDP_ELF"));
            let xdp_bpf = Ebpf::load(DNS_XDP_ELF)?;
            Ok(Self { 
                bpf: std::sync::Mutex::new(xdp_bpf),
                attached: std::sync::atomic::AtomicU8::new(0),
            })
        }
        
        pub fn attach(&self, iface: &str) -> Result<()> {
            let mut bpf = self.bpf.lock().unwrap();
            let program: &mut Xdp = bpf.program_mut("mirage_xdp_dns").unwrap().try_into()?;
            program.load()?;
            if program.attach(iface, XdpFlags::DRV_MODE).is_err() {
                program.attach(iface, XdpFlags::SKB_MODE)?;
            }
            info!("eBPF XDP DNS Accelerator attached to interface: {}", iface);
            Ok(())
        }
        
        /**
         * [推送 Fake-IP 到 XDP 层]
         * 当用户态解析到一个域名并分配了伪装 IP 后，将其同步给网卡层。
         * 此后该域名的 DNS 查询包将由硬件直接拦截并伪装打回，实现纳秒级响应。
         */
        pub fn update_dns_cache(&self, domain: &str, fake_ip: std::net::Ipv4Addr) -> Result<()> {
            let mut bpf = self.bpf.lock().unwrap();
            let map = bpf.map_mut("mirage_dns_cache").unwrap();
            let mut lru = aya::maps::HashMap::<_, u64, u32>::try_from(map)?;
            
            // DJB2 hash of the domain name
            let mut hash: u64 = 5381;
            for part in domain.split('.') {
                for &c in part.as_bytes() {
                    let mut b = c;
                    if b >= b'A' && b <= b'Z' { b += 32; }
                    hash = ((hash << 5) + hash).wrapping_add(b as u64);
                }
            }
            
            let ip_u32 = u32::from(fake_ip).to_be(); // Net endian
            lru.insert(hash, ip_u32, 0)?;
            Ok(())
        }
    }

    pub fn get_socket_cookie(fd: std::os::unix::io::RawFd) -> Result<u64> {
        let mut cookie: u64 = 0;
        let mut len = std::mem::size_of::<u64>() as libc::socklen_t;
        let res = unsafe {
            libc::getsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_COOKIE,
                &mut cookie as *mut _ as *mut libc::c_void,
                &mut len,
            )
        };
        if res < 0 {
            return Err(anyhow::anyhow!("Failed to get socket cookie"));
        }
        Ok(cookie)
    }
}

#[cfg(not(all(feature = "ebpf", target_os = "linux")))]
mod sys {
    use anyhow::Result;
    use tokio::net::TcpStream;
    use tracing::info;

    pub struct EbpfEngine {}

    impl EbpfEngine {
        pub fn init() -> Result<Self> {
            info!("eBPF Engine is disabled (Requires feature 'ebpf' and Linux OS). Falling back to Tokio userspace forwarding.");
            Ok(Self {})
        }

        pub fn register_splice(&mut self, _local: &TcpStream, _remote: &TcpStream) -> Result<()> {
            // No-op. Tokio io::copy will take over.
            Ok(())
        }
        
        pub fn get_stats(&self) -> Result<(u64, u64)> {
            Ok((0, 0))
        }
        
        pub fn get_tcp_state_by_cookie(&self, _cookie: u64) -> Result<crate::ebpf::TcpState> {
            Err(anyhow::anyhow!("eBPF disabled"))
        }
        
        pub fn set_target_ip(&mut self, _ip: std::net::IpAddr) -> Result<()> {
            Ok(())
        }
    }
        
    pub struct XdpEngine {
        pub attached: std::sync::atomic::AtomicU8,
    }
    
    impl XdpEngine {
        pub fn init() -> Result<Self> {
            Err(anyhow::anyhow!("eBPF disabled"))
        }
        pub fn update_dns_cache(&self, _domain: &str, _fake_ip: std::net::Ipv4Addr) -> Result<()> {
            Ok(())
        }
        pub fn attach(&self, _iface: &str) -> Result<()> {
            Ok(())
        }
    }
    
    pub fn get_socket_cookie(_fd: i32) -> Result<u64> {
        Ok(0)
    }
}

pub use sys::EbpfEngine;
pub use sys::XdpEngine;
pub use sys::get_socket_cookie;

pub mod transparent;
pub use transparent::TransparentEngine;
