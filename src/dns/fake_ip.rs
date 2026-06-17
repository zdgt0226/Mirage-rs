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
        
        // 1. Check if already mapped
        {
            let map = self.domain_to_ip.read().unwrap();
            if let Some(&ip) = map.get(&domain) {
                return ip;
            }
        }
        
        // 2. Assign new IP
        let mut next_guard = self.next_ip.write().unwrap();
        let mut ip_u32 = *next_guard;
        *next_guard += 1;
        
        // Check overflow (wrap around)
        if (*next_guard & !self.mask) == (!self.mask) {
            *next_guard = self.network + 2;
        }
        
        let mut ip = Ipv4Addr::from(ip_u32);
        
        let max_attempts = !self.mask as usize;
        let mut attempts = 0;
        
        // Conflict resolution: skip already mapped IPs if wrapped around
        while self.ip_to_domain.read().unwrap().contains_key(&ip) {
            attempts += 1;
            if attempts >= max_attempts {
                tracing::warn!("Fake-IP range {} exhausted", self.network);
                break;
            }
            ip_u32 = *next_guard;
            *next_guard += 1;
            if (*next_guard & !self.mask) == (!self.mask) {
                *next_guard = self.network + 2;
            }
            ip = Ipv4Addr::from(ip_u32);
        }
        
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
