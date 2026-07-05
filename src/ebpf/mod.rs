/// Per-tunnel TCP 指标 + 远端 endpoint, 必须跟 ebpf-src/sockmap.c::tcp_state
/// 字段顺序/大小严格一致 (size_of=36, 自然对齐 4). 改动时两边同步.
///
/// `family`: 2=AF_INET, 10=AF_INET6, 其他=未知.
/// `remote_ip`: IPv4 在 [0] (network byte order), IPv6 全部 4 个 u32.
/// `remote_port`: host byte order.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct TcpState {
    pub srtt_us: u32,
    pub snd_cwnd: u32,
    pub total_retrans: u32,
    pub data_segs_out: u32,
    pub remote_ip: [u32; 4],
    pub remote_port: u16,
    pub family: u16,
}

#[cfg(all(feature = "ebpf", target_os = "linux"))]
unsafe impl aya::Pod for TcpState {}

#[cfg(all(feature = "ebpf", target_os = "linux"))]
mod sys {
    use anyhow::Result;
    use aya::{Ebpf, programs::{SockOps, CgroupAttachMode, Xdp, XdpFlags}};
    use aya::maps::HashMap;
    
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

            // v0.4.5-alpha.3: sk_skb/stream_verdict + sockhash 数据面已彻底删除 (kernel 6.x
            // sockmap redirect 家族静默丢包, 参考 dae 结论). 客户端直连零拷贝改用
            // splice(2)+pipe (见 src/proxy/splice.rs). ELF 里 sockmap.c 只剩 sockops +
            // mirage_rtt_map + mirage_target_ips, 用于 brutal CC 的 RTT 反馈.

            // Try attaching sockops for RTT monitoring — report the actual failure step.
            // 非 root + 无 CAP_BPF 的常见场景 (用户自己跑客户端) 失败是预期, 降级为 INFO
            // 不刷 WARN; 真正 root 还失败才用 WARN.
            let is_root = unsafe { libc::geteuid() } == 0;
            let mut sockops_attached = false;
            let sockops_diag: String = match bpf.program_mut("mirage_sockops") {
                None => "program `mirage_sockops` not found in BPF ELF (section name mismatch?)".to_string(),
                Some(prog) => match TryInto::<&mut SockOps>::try_into(prog) {
                    Err(e) => format!("type cast to SockOps failed: {e}"),
                    Ok(sockops) => match sockops.load() {
                        Err(e) => format!("sockops.load() rejected by kernel verifier: {e}"),
                        Ok(()) => {
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

                            let mut attach_errors = vec![];
                            for path in &cgroup_paths {
                                match std::fs::File::open(path) {
                                    Err(e) => attach_errors.push(format!("open({path}): {e}")),
                                    Ok(cg) => match sockops.attach(cg, CgroupAttachMode::Single) {
                                        Ok(_) => {
                                            info!("eBPF SockOps attached to {}", path);
                                            sockops_attached = true;
                                            break;
                                        }
                                        Err(e) => attach_errors.push(format!("attach({path}): {e}")),
                                    },
                                }
                            }
                            if sockops_attached {
                                String::new()
                            } else {
                                format!("all cgroup attach paths failed: [{}]", attach_errors.join("; "))
                            }
                        }
                    },
                },
            };
            if !sockops_attached {
                if is_root {
                    tracing::warn!("RTT monitoring unavailable: {}", sockops_diag);
                } else {
                    tracing::info!(
                        "RTT monitoring disabled (non-root): {}. Brutal CC will run in static-rate mode. \
                         Run as root or `sudo setcap cap_bpf,cap_net_admin+ep <binary>` to enable.",
                        sockops_diag
                    );
                }
            }
            
            info!("eBPF Engine initialized! Waiting for registrations.");
            Ok(Self { bpf })
        }

        // v0.4.5-alpha.3: register_splice 删除, 直连零拷贝走 splice(2)+pipe.
        // get_stats 保留签名返回 0, 兼容 sampler.rs / GUI 拿 BPF hit 数的调用点.
        // BPF fast-path counter 语义在新架构下没了意义, GUI 图会稳定显示 0.
        pub fn get_stats(&self) -> Result<(u64, u64)> {
            Ok((0, 0))
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

        // 遍历 mirage_rtt_map 所有 cookie → 用于 GUI Active Tunnels 面板.
        // LRU 淘汰过的 cookie 自动不会出现, 上层不用清理.
        pub fn get_all_tunnel_stats(&self) -> Result<Vec<(u64, crate::ebpf::TcpState)>> {
            let map = self.bpf.map("mirage_rtt_map").unwrap();
            let hash = HashMap::<_, u64, crate::ebpf::TcpState>::try_from(map)?;
            let mut out = Vec::new();
            for entry in hash.iter() {
                if let Ok((cookie, state)) = entry {
                    out.push((cookie, state));
                }
            }
            Ok(out)
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
            let mut bpf = self.bpf.lock().unwrap_or_else(|e| e.into_inner());
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
            let mut bpf = self.bpf.lock().unwrap_or_else(|e| e.into_inner());
            let map = bpf.map_mut("mirage_dns_cache").unwrap();
            let mut lru = aya::maps::HashMap::<_, u64, u32>::try_from(map)?;
            
            // DJB2 hash of the domain name.
            // ★ 全部用 wrapping_* — Rust debug build 默认 overflow-checks=true,
            // 任何 + 一旦 u64 溢出就 panic. C 端 (dns_xdp.c) 的 u64 + 天然 2's
            // complement 截断, 必须显式 wrapping 对齐才能哈希一致. 之前只在
            // 末尾 wrapping_add(b) 而 (hash << 5) + hash 的 + 没保护, 长域名
            // 攻击会精准 panic 用户态. 见 commit:bug1 修复.
            let mut hash: u64 = 5381;
            for part in domain.split('.') {
                for &c in part.as_bytes() {
                    let mut b = c;
                    if b >= b'A' && b <= b'Z' { b += 32; }
                    hash = (hash << 5).wrapping_add(hash).wrapping_add(b as u64);
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
    use tracing::info;

    pub struct EbpfEngine {}

    impl EbpfEngine {
        pub fn init() -> Result<Self> {
            info!("eBPF Engine is disabled (Requires feature 'ebpf' and Linux OS). Falling back to userspace forwarding.");
            Ok(Self {})
        }

        pub fn get_stats(&self) -> Result<(u64, u64)> {
            Ok((0, 0))
        }
        
        pub fn get_tcp_state_by_cookie(&self, _cookie: u64) -> Result<crate::ebpf::TcpState> {
            Err(anyhow::anyhow!("eBPF disabled"))
        }

        pub fn get_all_tunnel_stats(&self) -> Result<Vec<(u64, crate::ebpf::TcpState)>> {
            Ok(Vec::new())
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
