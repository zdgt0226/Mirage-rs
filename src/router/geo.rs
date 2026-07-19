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
        // shift ≥ 64 时 `<< shift` 是溢出 (debug panic / release 掩码得垃圾值)。
        // 合法 protobuf varint 最多 10 字节 (64/7), 超过即畸形, 返 Err 拒绝。
        if shift >= 64 {
            return Err(anyhow!("Varint too long (overflow)"));
        }
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
    // `*pos + length` 直接相加会在 length 接近 usize::MAX 时回绕, 使检查失效 →
    // 后面 &data[*pos..*pos+length] start>end 而 panic。用减法比较避免溢出
    // (*pos ≤ data.len() 由 read_varint 保证)。
    if length > data.len().saturating_sub(*pos) {
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
                // 先收集所有 entry(cfn==2)payload, 延后解析: protobuf 字段序**任意**
                // (标准不保证 code 在 entries 前)。原代码只在 code 已知时才解析 entry,
                // 若某 .dat 把 entries 排在 code 前, 整个国家的规则会被静默丢弃。
                let mut entries: Vec<&[u8]> = Vec::new();

                while cpos < content.len() {
                    let ctag = read_varint(content, &mut cpos)?;
                    let cfn = ctag >> 3;
                    let cwt = ctag & 7;

                    if cwt == 2 {
                        let inner = read_len_delim(content, &mut cpos)?;
                        if cfn == 1 {
                            code = String::from_utf8_lossy(inner).to_uppercase();
                        } else if cfn == 2 {
                            entries.push(inner);
                        }
                    } else if cwt == 0 {
                        let _ = read_varint(content, &mut cpos)?;
                    } else if cwt == 1 {
                        cpos += 8;
                    } else if cwt == 5 {
                        cpos += 4;
                    } else {
                        break;
                    }
                }

                // code 与 entries 收齐后再判定 (与字段序无关)
                if code == target_upper {
                    let mut domains = Vec::new();
                    for inner in entries {
                        if let Ok(Some(d)) = parse_domain_msg(inner) {
                            domains.push(d);
                        }
                    }
                    return Ok(domains);
                }
            }
        } else if wt == 0 {
            let _ = read_varint(&data, &mut pos)?;
        } else if wt == 1 {
            pos += 8;
        } else if wt == 5 {
            pos += 4;
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
                // 先收集 entry(cfn==2), 延后解析: protobuf 字段序任意 (见 load_geosite_dat 同款修复)。
                let mut entries: Vec<&[u8]> = Vec::new();

                while cpos < content.len() {
                    let ctag = read_varint(content, &mut cpos)?;
                    let cfn = ctag >> 3;
                    let cwt = ctag & 7;

                    if cwt == 2 {
                        let inner = read_len_delim(content, &mut cpos)?;
                        if cfn == 1 {
                            code = String::from_utf8_lossy(inner).to_uppercase();
                        } else if cfn == 2 {
                            entries.push(inner);
                        }
                    } else if cwt == 0 {
                        let _ = read_varint(content, &mut cpos)?;
                    } else if cwt == 1 {
                        cpos += 8;
                    } else if cwt == 5 {
                        cpos += 4;
                    } else {
                        break;
                    }
                }

                if code == target_upper {
                    let mut cidrs = Vec::new();
                    for inner in entries {
                        if let Ok(Some(net)) = parse_cidr_msg(inner) {
                            cidrs.push(net);
                        }
                    }
                    return Ok(cidrs);
                }
            }
        } else if wt == 0 {
            let _ = read_varint(&data, &mut pos)?;
        } else if wt == 1 {
            pos += 8;
        } else if wt == 5 {
            pos += 4;
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

#[cfg(test)]
mod tests {
    use super::{read_len_delim, read_varint};

    #[test]
    fn varint_roundtrip() {
        let data = [0xAC, 0x02]; // 300
        let mut pos = 0;
        assert_eq!(read_varint(&data, &mut pos).unwrap(), 300);
        assert_eq!(pos, 2);
    }

    #[test]
    fn varint_overlong_rejected_no_panic() {
        // 回归 F7: 11+ 字节全 0x80 的 varint 曾使 shift≥64 溢出 panic。现应返 Err。
        let data = [0x80u8; 16];
        let mut pos = 0;
        assert!(read_varint(&data, &mut pos).is_err());
    }

    #[test]
    fn len_delim_huge_length_no_overflow_panic() {
        // 回归 F7: length 近 usize::MAX 时 `*pos+length` 回绕曾使检查失效 →
        // &data[..] start>end panic。构造一个声明超大长度的 varint。
        // varint 0xFF*9,0x01 ≈ 巨大值; 后跟少量数据。应返 Err, 不 panic。
        let mut data = vec![0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x7F];
        data.extend_from_slice(b"short");
        let mut pos = 0;
        assert!(read_len_delim(&data, &mut pos).is_err());
    }

    #[test]
    fn len_delim_valid() {
        let mut data = vec![0x03]; // length = 3
        data.extend_from_slice(b"abc");
        let mut pos = 0;
        assert_eq!(read_len_delim(&data, &mut pos).unwrap(), b"abc");
        assert_eq!(pos, 4);
    }

    // ── protobuf 编码 helper (仅测试用) ──
    fn varint(mut v: u64) -> Vec<u8> {
        let mut out = vec![];
        loop {
            let b = (v & 0x7f) as u8;
            v >>= 7;
            if v != 0 {
                out.push(b | 0x80);
            } else {
                out.push(b);
                break;
            }
        }
        out
    }
    fn ld(field: u64, data: &[u8]) -> Vec<u8> {
        let mut out = varint((field << 3) | 2);
        out.extend(varint(data.len() as u64));
        out.extend_from_slice(data);
        out
    }
    // wire-type 1 (fixed64) / 5 (fixed32) 字段编码 (仅测试用)。
    fn fixed64(field: u64, val: u64) -> Vec<u8> {
        let mut out = varint((field << 3) | 1);
        out.extend_from_slice(&val.to_le_bytes());
        out
    }
    fn fixed32(field: u64, val: u32) -> Vec<u8> {
        let mut out = varint((field << 3) | 5);
        out.extend_from_slice(&val.to_le_bytes());
        out
    }

    #[test]
    fn geosite_field_order_independent() {
        // 回归 #3: protobuf 字段序任意。构造 GeoSite 里 domain(field 2) **排在** code(field 1)
        // **之前** 的 .dat —— 原代码会因"处理 domain 时 code 还空"把整个国家规则静默丢弃。
        let domain_msg = ld(2, b"example.com"); // Domain{ value(field2)="example.com" } (type 默认 Plain)
        // GeoSite: 反序 —— 先 domain(field 2), 再 code(field 1)="CN"
        let mut geosite = Vec::new();
        geosite.extend(ld(2, &domain_msg)); // domain 在前
        geosite.extend(ld(1, b"CN")); // code 在后
        let dat = ld(1, &geosite); // GeoSiteList: field 1 = GeoSite

        let dir = std::env::temp_dir();
        let path = dir.join(format!("mirage_geo_test_{}.dat", std::process::id()));
        std::fs::write(&path, &dat).unwrap();

        let got = super::load_geosite_dat(&path, "CN").unwrap();
        std::fs::remove_file(&path).ok();

        assert_eq!(got.len(), 1, "反序 .dat 也应解析出 1 条域名 (原 bug 会得 0)");
        assert_eq!(got[0].value, "example.com");
    }

    #[test]
    fn geosite_normal_order_and_miss() {
        // 正序仍正常, 且非目标国不误匹配。
        let domain_msg = ld(2, b"a.cn");
        let mut geosite = Vec::new();
        geosite.extend(ld(1, b"CN")); // 正序: code 先
        geosite.extend(ld(2, &domain_msg));
        let dat = ld(1, &geosite);

        let path = std::env::temp_dir().join(format!("mirage_geo_test2_{}.dat", std::process::id()));
        std::fs::write(&path, &dat).unwrap();
        assert_eq!(super::load_geosite_dat(&path, "CN").unwrap().len(), 1, "正序命中");
        assert_eq!(super::load_geosite_dat(&path, "US").unwrap().len(), 0, "非目标国不匹配");
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn geosite_skips_fixed32_64_fields() {
        // GeoSite 内混入未知的 fixed64(wt1)/fixed32(wt5) 字段 (未来 schema 扩展)。
        // 原代码遇非 0/2 wire-type 直接 break → 截断内层循环, 丢掉其后的 domain。
        // 修复后应跳 8/4 字节继续, 仍解析出域名。
        let domain_msg = ld(2, b"example.com");
        let mut geosite = Vec::new();
        geosite.extend(ld(1, b"CN")); // code
        geosite.extend(fixed64(3, 0xDEAD_BEEF)); // 假 fixed64 字段
        geosite.extend(fixed32(4, 0x1234)); // 假 fixed32 字段
        geosite.extend(ld(2, &domain_msg)); // domain 排在 fixed 字段之后
        let dat = ld(1, &geosite);

        let path = std::env::temp_dir().join(format!("mirage_geo_test3_{}.dat", std::process::id()));
        std::fs::write(&path, &dat).unwrap();
        let got = super::load_geosite_dat(&path, "CN").unwrap();
        std::fs::remove_file(&path).ok();

        assert_eq!(got.len(), 1, "fixed 字段应被跳过, domain 仍解析 (原 break 会得 0)");
        assert_eq!(got[0].value, "example.com");
    }
}
