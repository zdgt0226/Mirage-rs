#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct TcpState {
    pub srtt_us: u32,
    pub snd_cwnd: u32,
    pub total_retrans: u32,
    pub padding: u32,
}

#[cfg(all(feature = "ebpf", target_os = "linux"))]
unsafe impl aya::Pod for TcpState {}

#[cfg(all(feature = "ebpf", target_os = "linux"))]
mod sys {
    use anyhow::Result;
    use aya::{Ebpf, programs::{SkSkb, SockOps, CgroupAttachMode}};
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

    impl EbpfEngine {
        pub fn init() -> Result<Self> {
            static SOCKMAP_ELF: &[u8] = include_bytes!("../../ebpf-src/sockmap.elf");
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
        
        pub fn get_tcp_state(&self, ip: std::net::IpAddr) -> Result<crate::ebpf::TcpState> {
            let map = self.bpf.map("mirage_rtt_map").unwrap();
            let hash = HashMap::<_, [u32; 5], crate::ebpf::TcpState>::try_from(map)?;
            let key = ip_to_key(ip);
            let state = hash.get(&key, 0)?;
            Ok(state)
        }
        
        pub fn set_target_ip(&mut self, ip: std::net::IpAddr) -> Result<()> {
            let map = self.bpf.map_mut("mirage_target_ips").unwrap();
            let mut hash = HashMap::<_, [u32; 5], u8>::try_from(map)?;
            let key = ip_to_key(ip);
            hash.insert(key, 1, 0)?;
            Ok(())
        }
    }

    fn get_socket_cookie(fd: std::os::unix::io::RawFd) -> Result<u64> {
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
        
        pub fn get_tcp_state(&self, _ip: std::net::IpAddr) -> Result<crate::ebpf::TcpState> {
            Err(anyhow::anyhow!("eBPF disabled"))
        }
        
        pub fn set_target_ip(&mut self, _ip: std::net::IpAddr) -> Result<()> {
            Ok(())
        }
    }
}

pub use sys::EbpfEngine;
