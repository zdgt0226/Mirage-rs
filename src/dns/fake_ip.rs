use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, RwLock};

pub struct FakeIpMapper {
    network: u32,
    mask: u32,
    prefix_len: u8,
    next_ip: RwLock<u32>,
    domain_to_ip: RwLock<HashMap<String, Ipv4Addr>>,
    ip_to_domain: RwLock<HashMap<Ipv4Addr, String>>,
    /// 持久化文件路径 (None = 纯内存)。
    persist_path: Option<PathBuf>,
    /// 有新分配就置 true; flush 后清。避免无变化时空写盘。
    dirty: AtomicBool,
}

impl FakeIpMapper {
    pub fn new(cidr: &str) -> anyhow::Result<Self> {
        Self::with_persist(cidr, None)
    }

    /// 带持久化: persist_path 设了则启动尝试加载已有映射 (缺失/损坏则空启动)。
    pub fn with_persist(cidr: &str, persist_path: Option<String>) -> anyhow::Result<Self> {
        // Simple CIDR parsing like "198.18.0.0/16"
        let parts: Vec<&str> = cidr.split('/').collect();
        if parts.len() != 2 {
            return Err(anyhow::anyhow!("Invalid CIDR format"));
        }
        let ip: Ipv4Addr = parts[0].parse()?;
        let prefix: u32 = parts[1].parse()?;

        if prefix > 32 {
            return Err(anyhow::anyhow!("Invalid CIDR prefix"));
        }

        let mask = if prefix == 0 { 0u32 } else { !0u32 << (32 - prefix) };
        let network = u32::from(ip) & mask;

        let mapper = Self {
            network,
            mask,
            prefix_len: prefix as u8,
            next_ip: RwLock::new(network + 2), // Start at .2
            domain_to_ip: RwLock::new(HashMap::new()),
            ip_to_domain: RwLock::new(HashMap::new()),
            persist_path: persist_path.map(PathBuf::from),
            dirty: AtomicBool::new(false),
        };

        if let Some(p) = &mapper.persist_path {
            if p.exists() {
                if let Err(e) = mapper.load(p) {
                    tracing::warn!("[FAKEIP] 加载持久化缓存 {} 失败 ({}), 空启动", p.display(), e);
                }
            }
        }
        Ok(mapper)
    }

    /// 从持久化文件恢复映射 + next_ip。行格式: `next_ip=<u32>` 或 `<ip> <domain>`。
    /// 只接受落在本 range 的 IP (换过 fakeip 网段的旧缓存自动丢弃)。best-effort 解析。
    fn load(&self, path: &Path) -> anyhow::Result<()> {
        let content = std::fs::read_to_string(path)?;
        let mut d2i = self.domain_to_ip.write().unwrap_or_else(|e| e.into_inner());
        let mut i2d = self.ip_to_domain.write().unwrap_or_else(|e| e.into_inner());
        let mut loaded_next: Option<u32> = None;
        let mut count = 0usize;
        for line in content.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            if let Some(v) = line.strip_prefix("next_ip=") {
                loaded_next = v.trim().parse().ok();
                continue;
            }
            let mut it = line.splitn(2, ' ');
            let (ip_s, dom) = match (it.next(), it.next()) {
                (Some(a), Some(b)) if !b.is_empty() => (a, b),
                _ => continue,
            };
            let ip: Ipv4Addr = match ip_s.parse() {
                Ok(i) => i,
                Err(_) => continue,
            };
            if (u32::from(ip) & self.mask) != self.network {
                continue; // 不在本 range, 丢弃 (换过网段)
            }
            let dom = dom.to_lowercase();
            d2i.insert(dom.clone(), ip);
            i2d.insert(ip, dom);
            count += 1;
        }
        if let Some(n) = loaded_next {
            // next_ip 必须落在 range 内且非广播, 否则保留默认 network+2
            if (n & self.mask) == self.network && (n & !self.mask) != !self.mask {
                *self.next_ip.write().unwrap_or_else(|e| e.into_inner()) = n;
            }
        }
        tracing::info!("[FAKEIP] 从 {} 恢复 {} 条映射", path.display(), count);
        Ok(())
    }

    /// 落盘 (仅 dirty 时)。先写 .tmp 再原子 rename。best-effort, 失败恢复 dirty 下轮重试。
    pub fn flush(&self) {
        let Some(path) = &self.persist_path else {
            return;
        };
        if !self.dirty.swap(false, Ordering::SeqCst) {
            return;
        }
        // 短暂持读锁快照 (域名, IP), 出锁再格式化 —— 不长时间阻塞新分配。
        let snapshot: Vec<(String, Ipv4Addr)> = {
            let d2i = self.domain_to_ip.read().unwrap_or_else(|e| e.into_inner());
            d2i.iter().map(|(d, ip)| (d.clone(), *ip)).collect()
        };
        let next = *self.next_ip.read().unwrap_or_else(|e| e.into_inner());

        let mut out = String::with_capacity(snapshot.len() * 32 + 64);
        out.push_str("# mirage-rs fake-ip persist v1\n");
        out.push_str(&format!("next_ip={}\n", next));
        for (dom, ip) in &snapshot {
            out.push_str(&format!("{} {}\n", ip, dom));
        }

        if let Some(parent) = path.parent() {
            let _ = std::fs::create_dir_all(parent); // 目录不存在则建 (best-effort)
        }
        let tmp = path.with_extension("tmp");
        if let Err(e) = std::fs::write(&tmp, out.as_bytes()) {
            tracing::warn!("[FAKEIP] 写临时缓存 {} 失败: {}", tmp.display(), e);
            self.dirty.store(true, Ordering::SeqCst); // 恢复 dirty
            return;
        }
        if let Err(e) = std::fs::rename(&tmp, path) {
            tracing::warn!("[FAKEIP] rename 缓存 {} 失败: {}", path.display(), e);
            let _ = std::fs::remove_file(&tmp);
            self.dirty.store(true, Ordering::SeqCst);
            return;
        }
        tracing::debug!("[FAKEIP] 持久化 {} 条映射 → {}", snapshot.len(), path.display());
    }

    /// 启动周期落盘后台任务 (每 60s, 仅 dirty 才写)。持久化未启用则 no-op。
    pub fn spawn_flusher(self: Arc<Self>) {
        if self.persist_path.is_none() {
            return;
        }
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(std::time::Duration::from_secs(60)).await;
                self.flush();
            }
        });
    }

    pub fn network(&self) -> Ipv4Addr {
        Ipv4Addr::from(self.network)
    }

    pub fn prefix_len(&self) -> u8 {
        self.prefix_len
    }

    pub fn lookup_or_assign(&self, domain: &str) -> Ipv4Addr {
        let domain = domain.to_lowercase();

        // 1. 快路径: 读锁命中 (常见).
        if let Some(&ip) = self
            .domain_to_ip
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .get(&domain)
        {
            return ip;
        }

        // 2. 慢路径: 分配新 IP. 持 domain_to_ip 写锁全程, 双检防两个并发同域名各占
        //    一个 IP. round-robin 推进 next_ip: range 满后复用最老槽位的 IP, 并
        //    **淘汰其旧域名的正向映射** —— 否则 domain_to_ip 每个唯一域名永久留存,
        //    长跑网关 (代理海量广告/CDN 域名) 无界增长吃内存. 复用后两个 map 都封顶
        //    在 range 容量 (/16 = 65534), 淘汰的是 65534 次分配前的最老域名 (几乎
        //    不可能仍活跃).
        let mut d2i = self.domain_to_ip.write().unwrap_or_else(|e| e.into_inner());
        if let Some(&ip) = d2i.get(&domain) {
            return ip; // 双检: 慢路径拿锁期间别的线程已分配
        }

        let ip_u32 = {
            let mut next = self.next_ip.write().unwrap_or_else(|e| e.into_inner());
            let cur = *next;
            let mut n = cur + 1;
            // 主机位全 1 (广播) 时回绕到 network+2, 跳过 .0/.1/broadcast
            if (n & !self.mask) == !self.mask {
                n = self.network + 2;
            }
            *next = n;
            cur
        };
        let ip = Ipv4Addr::from(ip_u32);

        let mut i2d = self.ip_to_domain.write().unwrap_or_else(|e| e.into_inner());
        // 占用该 IP; 若之前被别的域名占着 (round-robin 复用), 删掉旧域名的正向映射.
        if let Some(old_domain) = i2d.insert(ip, domain.clone()) {
            if old_domain != domain {
                d2i.remove(&old_domain);
                tracing::debug!("[FAKEIP] {} 槽位复用 → 淘汰旧域名 [{}]", ip, old_domain);
            }
        }
        tracing::debug!("[FAKEIP] assign [{}] → {} (已用 {}/~{})", domain, ip, d2i.len() + 1, !self.mask);
        d2i.insert(domain, ip);
        self.dirty.store(true, Ordering::Relaxed); // 新分配 → 待落盘

        ip
    }

    pub fn lookup_domain(&self, ip: &Ipv4Addr) -> Option<String> {
        self.ip_to_domain.read().unwrap_or_else(|e| e.into_inner()).get(ip).cloned()
    }

    pub fn is_fake_ip(&self, ip: &Ipv4Addr) -> bool {
        let ip_u32 = u32::from(*ip);
        (ip_u32 & self.mask) == self.network
    }
}

#[cfg(test)]
mod bounded_tests {
    use super::*;

    #[test]
    fn round_robin_bounds_both_maps_and_evicts_oldest() {
        // /29: 主机位 3, 可用 .2 .3 .4 .5 .6 (5 个, .7 广播回绕到 .2)
        let m = FakeIpMapper::new("10.0.0.0/29").unwrap();
        for i in 0..100 {
            m.lookup_or_assign(&format!("d{i}.example.com"));
        }
        let d2i = m.domain_to_ip.read().unwrap().len();
        let i2d = m.ip_to_domain.read().unwrap().len();
        // 两 map 都封顶在 range 容量 (5), 绝不是 100
        assert!(d2i <= 5, "domain_to_ip 必须有界 (round-robin 淘汰), 实际 {d2i}");
        assert_eq!(d2i, i2d, "两 map 一致 (无 stale 正向映射)");
        // 最老域名 d0 应已被淘汰
        assert!(
            m.domain_to_ip.read().unwrap().get("d0.example.com").is_none(),
            "最老域名 d0 应被 round-robin 淘汰"
        );
        // 最近域名 d99 应仍在, 且反查一致
        let ip99 = *m.domain_to_ip.read().unwrap().get("d99.example.com").unwrap();
        assert_eq!(
            m.lookup_domain(&ip99).as_deref(),
            Some("d99.example.com"),
            "最近域名正反映射一致"
        );
    }

    #[test]
    fn same_domain_stable_ip() {
        let m = FakeIpMapper::new("198.18.0.0/16").unwrap();
        let a = m.lookup_or_assign("stable.com");
        let b = m.lookup_or_assign("stable.com");
        assert_eq!(a, b, "同域名多次查询返回同一 fake-IP");
    }
}

#[cfg(test)]
mod persist_tests {
    use super::*;

    fn tmp_path(name: &str) -> std::path::PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!("mirage_fakeip_{}_{}", nanos, name))
    }

    #[test]
    fn roundtrip_restores_mappings_and_next_ip() {
        let path = tmp_path("rt");
        let ps = path.to_str().unwrap().to_string();
        let (ip_a, ip_b);
        {
            let m = FakeIpMapper::with_persist("198.18.0.0/16", Some(ps.clone())).unwrap();
            ip_a = m.lookup_or_assign("a.com");
            ip_b = m.lookup_or_assign("b.com");
            assert_ne!(ip_a, ip_b);
            m.flush();
        }
        // 新 mapper 从同路径恢复
        let m2 = FakeIpMapper::with_persist("198.18.0.0/16", Some(ps)).unwrap();
        assert_eq!(m2.lookup_or_assign("a.com"), ip_a, "恢复后 a.com 应同 IP");
        assert_eq!(m2.lookup_domain(&ip_a).as_deref(), Some("a.com"), "反查恢复");
        // next_ip 恢复 → 新域名不撞已恢复的 IP
        let ip_c = m2.lookup_or_assign("c.com");
        assert_ne!(ip_c, ip_a);
        assert_ne!(ip_c, ip_b);
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn out_of_range_entries_dropped_on_load() {
        let path = tmp_path("range");
        // 10.0.0.5 不在 198.18/16, 应丢弃; 198.18.0.9 保留
        std::fs::write(&path, "# hdr\nnext_ip=999\n10.0.0.5 x.com\n198.18.0.9 y.com\n").unwrap();
        let m = FakeIpMapper::with_persist("198.18.0.0/16", Some(path.to_str().unwrap().to_string())).unwrap();
        assert_eq!(m.lookup_domain(&"198.18.0.9".parse().unwrap()).as_deref(), Some("y.com"), "range 内保留");
        assert!(m.lookup_domain(&"10.0.0.5".parse().unwrap()).is_none(), "range 外丢弃");
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn corrupt_file_does_not_panic() {
        let path = tmp_path("corrupt");
        std::fs::write(&path, b"not\xffutf8 garbage\nnext_ip=abc\n\n").unwrap();
        // 损坏 (非法 UTF-8) → load Err → warn 但 with_persist 返回 Ok (空启动)
        let m = FakeIpMapper::with_persist("198.18.0.0/16", Some(path.to_str().unwrap().to_string()));
        assert!(m.is_ok(), "损坏文件不应致 panic/失败");
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn no_persist_path_is_pure_memory() {
        let m = FakeIpMapper::with_persist("198.18.0.0/16", None).unwrap();
        m.lookup_or_assign("x.com");
        m.flush(); // 无路径 → no-op, 不 panic
    }
}
