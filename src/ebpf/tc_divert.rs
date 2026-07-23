//! tc-bpf 透明分流引擎: 把转发的裸-IP 流量 sk_assign 进本地透明监听 socket
//! (纯 eBPF, 无 iptables/nftables)。与 sk_lookup 的 fake-IP 拦截互补 ——
//! sk_lookup 只在本地投递触发, 抓不到转发的裸-IP 流量, 本引擎补上。
//!
//! 机制细节与 netns 实测见 ebpf-src/tc_divert.c、examples/verify_tc_divert.{rs,sh}。
//! 部署侧还需 (install.sh 网关模式已配): ip rule fwmark 1 lookup 100 +
//! ip route add local default dev lo table 100, 否则 sk_assign 的包走转发不投本地。

#[cfg(all(feature = "ebpf", target_os = "linux"))]
mod sys {
    use anyhow::{Context, Result};
    use aya::maps::lpm_trie::{Key, LpmTrie};
    use aya::maps::Array;
    use aya::programs::tc::SchedClassifierLinkId;
    use aya::programs::{tc, SchedClassifier, TcAttachType};
    use aya::Ebpf;
    use ipnet::Ipv4Net;
    use std::collections::HashSet;
    use std::sync::Mutex;
    use tracing::{info, warn};

    #[repr(C)]
    #[derive(Clone, Copy, Default)]
    struct DivertCfg {
        listen_port: u32,
        mtu: u32, // MSS clamp: max_mss=mtu-40; 0 关闭
    }
    unsafe impl aya::Pod for DivertCfg {}

    pub struct TcDivertEngine {
        bpf: Mutex<Ebpf>,
        // 当前 direct_cidr map 里的 (网络序 u32, 前缀长度), 供热重载差量增删。
        loaded: Mutex<HashSet<(u32, u8)>>,
        // attach 后的 tc 过滤器 link, 供退出时显式摘除 (见 detach)。
        link: Mutex<Option<SchedClassifierLinkId>>,
    }

    impl TcDivertEngine {
        pub fn init(listen_port: u16, mtu: u32) -> Result<Self> {
            static TC_DIVERT_ELF: &[u8] = aya::include_bytes_aligned!(env!("BPF_TC_DIVERT_ELF"));
            let mut bpf = Ebpf::load(TC_DIVERT_ELF).context("Failed to load tc_divert.elf")?;
            {
                let mut cfg = Array::<_, DivertCfg>::try_from(
                    bpf.map_mut("tc_divert_cfg").context("tc_divert_cfg map missing")?,
                )?;
                cfg.set(0, DivertCfg { listen_port: listen_port as u32, mtu }, 0)?;
            }
            info!("eBPF tc_divert engine initialized (listen_port={}, mss_clamp mtu={}).", listen_port, mtu);
            Ok(Self {
                bpf: Mutex::new(bpf),
                loaded: Mutex::new(HashSet::new()),
                link: Mutex::new(None),
            })
        }

        /// 挂到 LAN 网卡 ingress (clsact)。
        pub fn attach(&self, iface: &str) -> Result<()> {
            let mut bpf = self.bpf.lock().unwrap_or_else(|e| e.into_inner());
            // clsact 可能已存在, 忽略错误。
            let _ = tc::qdisc_add_clsact(iface);
            let prog: &mut SchedClassifier = bpf
                .program_mut("tc_divert")
                .context("tc_divert program missing")?
                .try_into()?;
            prog.load()?;
            let link_id = prog
                .attach(iface, TcAttachType::Ingress)
                .with_context(|| format!("tc_divert attach to {} ingress failed", iface))?;
            *self.link.lock().unwrap_or_else(|e| e.into_inner()) = Some(link_id);
            info!("eBPF tc_divert attached to {} ingress.", iface);
            Ok(())
        }

        /// 退出前显式摘掉 tc 过滤器。
        ///
        /// tc 过滤器自己持有 prog 引用, 不随进程 fd 关闭消失; 而本进程走
        /// std::process::exit(0), 析构一个都不跑 → aya 的 Ebpf 永远不 Drop, 连优雅停止
        /// 都会把过滤器留在网卡上。留下的过滤器配合 mirage-gw-nat 装的 fwmark→local
        /// ip rule 会黑洞掉 LAN 的非直连 TCP。BPF 侧已有 sk_lookup 兜底 (listener 没了
        /// 就不打 mark), 这里是第二道保险: 正常退出路径直接把过滤器摘干净。
        pub fn detach(&self) {
            let Some(link_id) = self.link.lock().unwrap_or_else(|e| e.into_inner()).take() else {
                return;
            };
            let mut bpf = self.bpf.lock().unwrap_or_else(|e| e.into_inner());
            let Some(prog) = bpf.program_mut("tc_divert") else { return };
            let prog: Result<&mut SchedClassifier, _> = prog.try_into();
            match prog.map(|p| p.detach(link_id)) {
                Ok(Ok(())) => info!("eBPF tc_divert 已从网卡摘除。"),
                Ok(Err(e)) => warn!("tc_divert detach 失败 (过滤器可能残留): {}", e),
                Err(e) => warn!("tc_divert detach 取程序失败: {}", e),
            }
        }

        /// 全量同步 direct_cidr map 到给定直连集 (增删差量, 支持热重载)。
        /// key.addr = 网络序 u32 (与 BPF __be32 同布局); 用 to_be() 令 LE 原生字节==网络序。
        pub fn sync_direct_cidrs(&self, cidrs: &[Ipv4Net]) -> Result<()> {
            let want: HashSet<(u32, u8)> = cidrs
                .iter()
                .map(|c| (u32::from(c.network()).to_be(), c.prefix_len()))
                .collect();

            let mut bpf = self.bpf.lock().unwrap_or_else(|e| e.into_inner());
            let mut trie = LpmTrie::<_, u32, u8>::try_from(
                bpf.map_mut("direct_cidr").context("direct_cidr map missing")?,
            )?;
            let mut loaded = self.loaded.lock().unwrap_or_else(|e| e.into_inner());

            // ⚠️ 外部审计 #3: LPM map 更新非事务原子, 差量增删期间若 SYN 首包撞上"半更新"
            // 状态会走错分流。真原子切换 (ARRAY_OF_MAPS 双缓冲) 需换 map 类型 + 裸 syscall,
            // 对一个 P3 竞态性价比太低。改用**先加后删**几乎消除风险:
            //
            //   1. 先 insert 全部新增段 —— 此刻 map = 旧 ∪ 新, 是超集, **绝不会漏判**
            //      (本该直连的段一定在, 不会被误当代理)。
            //   2. 再 remove 过时段。
            //
            // 唯一残留: 一个刚"不再直连"的段, 在 remove 前几微秒仍被当直连 —— 但它上一秒
            // 本就是直连, 方向无害 (顶多晚一个包切走, 下个包正常; TCP 会重传)。审计真正担心
            // 的"直连流量被误代理"那个方向 (漏判) 被彻底消除。
            for (net, plen) in want.iter() {
                if !loaded.contains(&(*net, *plen)) {
                    trie.insert(&Key::new(*plen as u32, *net), 1u8, 0)?;
                }
            }
            for (net, plen) in loaded.iter() {
                if !want.contains(&(*net, *plen)) {
                    let _ = trie.remove(&Key::new(*plen as u32, *net));
                }
            }
            let n = want.len();
            *loaded = want;
            info!("eBPF tc_divert direct_cidr synced: {} 段直连快路径", n);
            Ok(())
        }
    }
}

#[cfg(not(all(feature = "ebpf", target_os = "linux")))]
mod sys {
    use anyhow::Result;
    use ipnet::Ipv4Net;

    pub struct TcDivertEngine {}

    impl TcDivertEngine {
        pub fn init(_listen_port: u16, _mtu: u32) -> Result<Self> {
            Err(anyhow::anyhow!("eBPF disabled"))
        }
        pub fn attach(&self, _iface: &str) -> Result<()> {
            Ok(())
        }
        pub fn detach(&self) {}
        pub fn sync_direct_cidrs(&self, _cidrs: &[Ipv4Net]) -> Result<()> {
            Ok(())
        }
    }
}

pub use sys::TcDivertEngine;
