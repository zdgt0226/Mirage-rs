use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::RwLock;

pub struct FakeIpMapper {
    network: u32,
    mask: u32,
    prefix_len: u8,
    next_ip: RwLock<u32>,
    domain_to_ip: RwLock<HashMap<String, Ipv4Addr>>,
    ip_to_domain: RwLock<HashMap<Ipv4Addr, String>>,
}

impl FakeIpMapper {
    pub fn new(cidr: &str) -> anyhow::Result<Self> {
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
        
        Ok(Self {
            network,
            mask,
            prefix_len: prefix as u8,
            next_ip: RwLock::new(network + 2), // Start at .2
            domain_to_ip: RwLock::new(HashMap::new()),
            ip_to_domain: RwLock::new(HashMap::new()),
        })
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
            }
        }
        d2i.insert(domain, ip);

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
