/// DNS 域名哈希 —— **必须与 `ebpf-src/dns_xdp.c::hash_domain` 逐字节一致**。
///
/// ⚠️ 修复 (2026-07-23): 旧实现只对字符字节做 DJB2, **点分隔符/长度字节不进哈希** ——
/// 于是 `foo.bar.com` 与 `foobar.com` 哈希相同, DNS 缓存串扰把流量劫持到错 IP。
///
/// XDP 侧看到的是 DNS wire format 的 QNAME: `[3]foo[3]bar[3]com[0]` —— 每个 label 前有
/// 一个长度字节, 它就是"点"的等价物。把长度字节也算进哈希, 碰撞即消除:
///   `foo.bar.com` → 3,f,o,o,3,b,a,r,3,c,o,m
///   `foobar.com`  → 6,f,o,o,b,a,r,3,c,o,m   (首字节 6≠3, 哈希不同)
///
/// 本函数在**字符串**上重建 wire format 的哈希序列: 逐 label, 先哈希其长度, 再哈希其字符
/// (小写)。空 label (末尾的点 / 连续点) 跳过, 与 wire format 不产生 0 长度 label 对齐。
pub fn hash_domain(domain: &str) -> u64 {
    let mut hash: u64 = 5381;
    for label in domain.split('.') {
        if label.is_empty() {
            continue; // 末尾点等: wire format 里不会出现 0 长度中间 label
        }
        // 长度字节 (label 的字节数, 与 wire format 的长度前缀一致)
        let len = label.len() as u64;
        hash = (hash << 5).wrapping_add(hash).wrapping_add(len);
        for &c in label.as_bytes() {
            let mut b = c;
            if b.is_ascii_uppercase() { b += 32; }
            hash = (hash << 5).wrapping_add(hash).wrapping_add(b as u64);
        }
    }
    hash
}

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
    
    /// 构造 mirage_target_ips 的 key [family, ...ip]。**字节序必须与 BPF 端
    /// sockmap.c::extract_ip 一致 = 网络序** (skops->remote_ip4 / remote_ip6[]
    /// 都是网络序)。已核对: 两分支写法不同但都产出网络序内存布局, 匹配 BPF 端:
    ///   - IPv4 `u32::from(v4).to_be()`   → 内存 [a,b,c,d] 网络序;
    ///   - IPv6 `from_ne_bytes(网络序octets)` → 内存原样网络序。
    /// (等价于都用 from_ne_bytes(octets); 写法虽不对称但**非 bug**, 勿"修")。
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
            
            // wire-format 一致的哈希 (含长度字节, 防 foo.bar.com / foobar.com 碰撞)。
            // 全 wrapping_*: debug build overflow-checks=true 下裸 + 溢出会 panic,
            // 而 C 端 u64 + 天然 2's complement 截断, 必须对齐。见 super::hash_domain。
            let hash = super::hash_domain(domain);
            
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

pub mod tc_divert;
pub use tc_divert::TcDivertEngine;

pub mod cgroup_connect;
pub use cgroup_connect::CgroupConnectEngine;

#[cfg(test)]
mod hash_tests {
    use super::hash_domain;

    /// C 侧 (dns_xdp.c) 的 hash_domain 参考实现: 在**真实 DNS wire format 字节**上跑,
    /// 与 C 逐字节等价 —— 读长度字节 b (进哈希), 再读 b 个字符 (小写后进哈希)。
    /// 这是"另一份独立实现", 用来钉死 Rust 字符串版与 C wire 版必须产出同一个 u64。
    fn hash_wire(domain: &str) -> u64 {
        // 构造 wire format QNAME: 每 label [len][bytes...], 末尾 [0]
        let mut wire = Vec::new();
        for label in domain.split('.') {
            if label.is_empty() { continue; }
            wire.push(label.len() as u8);
            wire.extend_from_slice(label.as_bytes());
        }
        wire.push(0);

        // 逐字节跑 C 的状态机
        let mut hash: u64 = 5381;
        let mut remaining = 0u32;
        for &b in &wire {
            if remaining == 0 {
                if b == 0 { break; }
                if b > 63 { break; }
                remaining = b as u32;
                hash = (hash << 5).wrapping_add(hash).wrapping_add(b as u64); // 长度字节进哈希
            } else {
                let mut c = b;
                if c.is_ascii_uppercase() { c += 32; }
                hash = (hash << 5).wrapping_add(hash).wrapping_add(c as u64);
                remaining -= 1;
            }
        }
        hash
    }

    /// 核心 bug 回归: 点位置不同、字符相同的域名**必须**哈希不同。
    #[test]
    fn dot_position_changes_hash() {
        assert_ne!(hash_domain("foo.bar.com"), hash_domain("foobar.com"),
                   "foo.bar.com 与 foobar.com 哈希相同 —— 碰撞未消除, DNS 缓存会串扰");
        assert_ne!(hash_domain("ex.ample.com"), hash_domain("example.com"));
        assert_ne!(hash_domain("a.bc.d"), hash_domain("ab.c.d"));
    }

    /// 跨端一致性护栏: Rust 字符串版必须与 C wire-format 版逐字节产出同一哈希。
    /// 任一端改了哈希逻辑, 这个测试会红 —— 防"改完两端对不上、缓存全 miss"。
    #[test]
    fn rust_matches_c_wire_format() {
        for d in [
            "foo.bar.com", "foobar.com", "example.com", "www.example.com",
            "a.b.c.d.e", "xn--fiqs8s.cn", "UPPER.Case.COM", "single",
        ] {
            assert_eq!(hash_domain(d), hash_wire(d),
                       "域名 {d}: Rust 字符串哈希 != C wire 哈希");
        }
    }

    /// 大小写不敏感 (DNS 语义): 同域名不同大小写哈希一致。
    #[test]
    fn case_insensitive() {
        assert_eq!(hash_domain("Example.COM"), hash_domain("example.com"));
    }
}
