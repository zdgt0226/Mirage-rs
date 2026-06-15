use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::RwLock;

pub struct FakeIpMapper {
    network: u32,
    mask: u32,
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
        
        let network = u32::from(ip) & (!0 << (32 - prefix));
        let mask = !0 << (32 - prefix);
        
        Ok(Self {
            network,
            mask,
            next_ip: RwLock::new(network + 2), // Start at .2
            domain_to_ip: RwLock::new(HashMap::new()),
            ip_to_domain: RwLock::new(HashMap::new()),
        })
    }

    pub fn lookup_or_assign(&self, domain: &str) -> Ipv4Addr {
        let domain = domain.to_lowercase();
        
        // 1. Check if already mapped
        {
            let map = self.domain_to_ip.read().unwrap();
            if let Some(&ip) = map.get(&domain) {
                return ip;
            }
        }
        
        // 2. Assign new IP
        let mut next_guard = self.next_ip.write().unwrap();
        let ip_u32 = *next_guard;
        *next_guard += 1;
        
        // Check overflow (wrap around)
        if (*next_guard & !self.mask) == (!self.mask) {
            *next_guard = self.network + 2;
        }
        
        let ip = Ipv4Addr::from(ip_u32);
        
        self.domain_to_ip.write().unwrap().insert(domain.clone(), ip);
        self.ip_to_domain.write().unwrap().insert(ip, domain);
        
        ip
    }

    pub fn lookup_domain(&self, ip: &Ipv4Addr) -> Option<String> {
        self.ip_to_domain.read().unwrap().get(ip).cloned()
    }

    pub fn is_fake_ip(&self, ip: &Ipv4Addr) -> bool {
        let ip_u32 = u32::from(*ip);
        (ip_u32 & self.mask) == self.network
    }
}
