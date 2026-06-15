use std::fs;
use std::path::Path;
use anyhow::{anyhow, Result};
use ipnet::IpNet;
use std::net::{Ipv4Addr, Ipv6Addr};

#[derive(Debug, Clone, PartialEq)]
pub enum DomainType {
    Plain,
    Regex,
    RootDomain,
    Full,
}

#[derive(Debug, Clone)]
pub struct GeoDomain {
    pub dtype: DomainType,
    pub value: String,
}

fn read_varint(data: &[u8], pos: &mut usize) -> Result<u64> {
    let mut n: u64 = 0;
    let mut shift = 0;
    while *pos < data.len() {
        let b = data[*pos];
        *pos += 1;
        n |= ((b & 0x7f) as u64) << shift;
        if b & 0x80 == 0 {
            return Ok(n);
        }
        shift += 7;
    }
    Err(anyhow!("Truncated varint"))
}

fn read_len_delim<'a>(data: &'a [u8], pos: &mut usize) -> Result<&'a [u8]> {
    let length = read_varint(data, pos)? as usize;
    if *pos + length > data.len() {
        return Err(anyhow!("Truncated length delimited data"));
    }
    let res = &data[*pos..*pos + length];
    *pos += length;
    Ok(res)
}

fn parse_domain_msg(data: &[u8]) -> Result<Option<GeoDomain>> {
    let mut pos = 0;
    let mut dtype = DomainType::Plain;
    let mut value = String::new();

    while pos < data.len() {
        let tag = read_varint(data, &mut pos)?;
        let fn_num = tag >> 3;
        let wt = tag & 7;

        if wt == 0 {
            let v = read_varint(data, &mut pos)?;
            if fn_num == 1 {
                dtype = match v {
                    0 => DomainType::Plain,
                    1 => DomainType::Regex,
                    2 => DomainType::RootDomain,
                    3 => DomainType::Full,
                    _ => DomainType::Plain, // Fallback
                };
            }
        } else if wt == 2 {
            let content = read_len_delim(data, &mut pos)?;
            if fn_num == 2 {
                value = String::from_utf8_lossy(content).to_string();
            }
        } else {
            break;
        }
    }

    if !value.is_empty() {
        Ok(Some(GeoDomain { dtype, value }))
    } else {
        Ok(None)
    }
}

pub fn load_geosite_dat(path: &Path, target_code: &str) -> Result<Vec<GeoDomain>> {
    let data = fs::read(path)?;
    let mut pos = 0;
    let target_upper = target_code.to_uppercase();

    while pos < data.len() {
        let tag = read_varint(&data, &mut pos)?;
        let fn_num = tag >> 3;
        let wt = tag & 7;

        if wt == 2 {
            let content = read_len_delim(&data, &mut pos)?;
            // fn_num 1 is repeated GeoSite
            if fn_num == 1 {
                let mut cpos = 0;
                let mut code = String::new();
                let mut domains = Vec::new();

                while cpos < content.len() {
                    let ctag = read_varint(content, &mut cpos)?;
                    let cfn = ctag >> 3;
                    let cwt = ctag & 7;

                    if cwt == 2 {
                        let inner = read_len_delim(content, &mut cpos)?;
                        if cfn == 1 {
                            code = String::from_utf8_lossy(inner).to_uppercase();
                        } else if cfn == 2 {
                            if code == target_upper {
                                if let Ok(Some(d)) = parse_domain_msg(inner) {
                                    domains.push(d);
                                }
                            }
                        }
                    } else if cwt == 0 {
                        read_varint(content, &mut cpos)?;
                    } else {
                        break;
                    }
                }
                
                if code == target_upper {
                    return Ok(domains);
                }
            }
        } else if wt == 0 {
            read_varint(&data, &mut pos)?;
        } else {
            break;
        }
    }
    
    Ok(Vec::new())
}

fn parse_cidr_msg(data: &[u8]) -> Result<Option<IpNet>> {
    let mut pos = 0;
    let mut ip_bytes = Vec::new();
    let mut prefix = 0;

    while pos < data.len() {
        let tag = read_varint(data, &mut pos)?;
        let fn_num = tag >> 3;
        let wt = tag & 7;

        if wt == 2 {
            let content = read_len_delim(data, &mut pos)?;
            if fn_num == 1 {
                ip_bytes = content.to_vec();
            }
        } else if wt == 0 {
            let v = read_varint(data, &mut pos)?;
            if fn_num == 2 {
                prefix = v as u8;
            }
        } else {
            break;
        }
    }

    if ip_bytes.len() == 4 {
        let addr = Ipv4Addr::new(ip_bytes[0], ip_bytes[1], ip_bytes[2], ip_bytes[3]);
        Ok(Some(IpNet::V4(ipnet::Ipv4Net::new(addr, prefix)?)))
    } else if ip_bytes.len() == 16 {
        let mut b = [0u8; 16];
        b.copy_from_slice(&ip_bytes);
        let addr = Ipv6Addr::from(b);
        Ok(Some(IpNet::V6(ipnet::Ipv6Net::new(addr, prefix)?)))
    } else {
        Ok(None)
    }
}

pub fn load_geoip_dat(path: &Path, target_code: &str) -> Result<Vec<IpNet>> {
    let data = fs::read(path)?;
    let mut pos = 0;
    let target_upper = target_code.to_uppercase();

    while pos < data.len() {
        let tag = read_varint(&data, &mut pos)?;
        let fn_num = tag >> 3;
        let wt = tag & 7;

        if wt == 2 {
            let content = read_len_delim(&data, &mut pos)?;
            if fn_num == 1 {
                let mut cpos = 0;
                let mut code = String::new();
                let mut cidrs = Vec::new();

                while cpos < content.len() {
                    let ctag = read_varint(content, &mut cpos)?;
                    let cfn = ctag >> 3;
                    let cwt = ctag & 7;

                    if cwt == 2 {
                        let inner = read_len_delim(content, &mut cpos)?;
                        if cfn == 1 {
                            code = String::from_utf8_lossy(inner).to_uppercase();
                        } else if cfn == 2 {
                            if code == target_upper {
                                if let Ok(Some(net)) = parse_cidr_msg(inner) {
                                    cidrs.push(net);
                                }
                            }
                        }
                    } else if cwt == 0 {
                        read_varint(content, &mut cpos)?;
                    } else {
                        break;
                    }
                }
                
                if code == target_upper {
                    return Ok(cidrs);
                }
            }
        } else if wt == 0 {
            read_varint(&data, &mut pos)?;
        } else {
            break;
        }
    }
    
    Ok(Vec::new())
}

// ==========================================
// Sing-box SRS / JSON compatibility layer
// ==========================================
use serde_json::Value;

pub fn load_singbox_json(path: &Path) -> Result<(Vec<GeoDomain>, Vec<IpNet>)> {
    let data = fs::read_to_string(path)?;
    let parsed: Value = serde_json::from_str(&data)?;
    
    let mut domains = Vec::new();
    let mut cidrs = Vec::new();
    
    if let Some(rules) = parsed.get("rules").and_then(|r| r.as_array()) {
        for rule in rules {
            if let Some(domain_suffix) = rule.get("domain_suffix").and_then(|d| d.as_array()) {
                for d in domain_suffix {
                    if let Some(s) = d.as_str() {
                        domains.push(GeoDomain { dtype: DomainType::RootDomain, value: s.to_string() });
                    }
                }
            }
            if let Some(domain_keyword) = rule.get("domain_keyword").and_then(|d| d.as_array()) {
                for d in domain_keyword {
                    if let Some(s) = d.as_str() {
                        domains.push(GeoDomain { dtype: DomainType::Plain, value: s.to_string() });
                    }
                }
            }
            if let Some(domain_regex) = rule.get("domain_regex").and_then(|d| d.as_array()) {
                for d in domain_regex {
                    if let Some(s) = d.as_str() {
                        domains.push(GeoDomain { dtype: DomainType::Regex, value: s.to_string() });
                    }
                }
            }
            if let Some(domain) = rule.get("domain").and_then(|d| d.as_array()) {
                for d in domain {
                    if let Some(s) = d.as_str() {
                        domains.push(GeoDomain { dtype: DomainType::Full, value: s.to_string() });
                    }
                }
            }
            if let Some(ip_cidr) = rule.get("ip_cidr").and_then(|d| d.as_array()) {
                for ip in ip_cidr {
                    if let Some(s) = ip.as_str() {
                        if let Ok(net) = s.parse::<IpNet>() {
                            cidrs.push(net);
                        }
                    }
                }
            }
        }
    }
    
    Ok((domains, cidrs))
}
