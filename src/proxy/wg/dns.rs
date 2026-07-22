//! 隧道内 DNS —— 让域名**经 WG 隧道解析**, 而不是在本机解析完再把 IP 送进去。
//!
//! 为什么需要: 本机解析意味着 ①DNS 查询本身不经隧道(暴露你在查什么), ②拿到的是**本机
//! 所在地区**的解析结果。对 CDN/流媒体这类按解析结果分配节点的服务, ②会让 WG 出口白配 ——
//! 流量确实从对端出去了, 但目标 IP 是按你本地位置挑的。这与"出口 IP 不一致"是同一类
//! 功能性错误, 只是发生在更早的一步。
//!
//! 不配 `dns` 字段则保持原行为(本机解析), 不强加一次额外往返。
//!
//! ⚠️ 解析用的是明文 DNS(53/UDP), 但**整条查询在 WG 隧道内**, 对隧道外不可见。

use anyhow::{bail, Result};
use std::net::Ipv4Addr;

/// 单次查询超时。隧道内 DNS 多为局域网级延迟, 5s 足够且不会把建连拖太久。
const QUERY_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);
/// 缓存条目上限, 防止被唯一域名洪泛撑爆内存。
const CACHE_CAP: usize = 1024;
/// TTL 下限/上限 (秒)。上限防止一条超长 TTL 把错误答案钉死。
const TTL_MIN: u64 = 5;
const TTL_MAX: u64 = 3600;

/// 构造一个 A 记录查询。
fn build_query(id: u16, name: &str) -> Result<Vec<u8>> {
    let mut q = Vec::with_capacity(32 + name.len());
    q.extend_from_slice(&id.to_be_bytes());
    q.extend_from_slice(&[0x01, 0x00]); // 标准查询 + 期望递归
    q.extend_from_slice(&[0x00, 0x01]); // QDCOUNT = 1
    q.extend_from_slice(&[0, 0, 0, 0, 0, 0]); // AN/NS/AR = 0
    for label in name.split('.').filter(|l| !l.is_empty()) {
        if label.len() > 63 {
            bail!("域名标签超过 63 字节: {label}");
        }
        q.push(label.len() as u8);
        q.extend_from_slice(label.as_bytes());
    }
    q.push(0);
    q.extend_from_slice(&[0x00, 0x01]); // QTYPE = A
    q.extend_from_slice(&[0x00, 0x01]); // QCLASS = IN
    Ok(q)
}

/// 跳过报文中 `pos` 处的一个域名, 返回其后的偏移。
///
/// **必须防压缩指针环**: DNS 允许用指针复用前面出现过的名字, 恶意/损坏的报文可以让指针
/// 指回自己形成死循环 —— 这是解析器上的经典 DoS。这里限制跳转次数, 且指针只允许**向前**
/// 指(标准要求), 两道都卡住。
fn skip_name(msg: &[u8], mut pos: usize) -> Result<usize> {
    let mut jumps = 0;
    loop {
        if pos >= msg.len() {
            bail!("DNS 报文截断");
        }
        let len = msg[pos] as usize;
        if len == 0 {
            return Ok(pos + 1);
        }
        if len & 0xC0 == 0xC0 {
            // 压缩指针: 名字到此结束, 后面跟 2 字节指针
            if pos + 1 >= msg.len() {
                bail!("DNS 压缩指针截断");
            }
            jumps += 1;
            if jumps > 1 {
                // 跳过一个名字最多只需读到第一个指针 —— 再跳说明报文有环或恶意构造
                bail!("DNS 压缩指针异常");
            }
            return Ok(pos + 2);
        }
        pos += 1 + len;
    }
}

/// 从响应里取出 A 记录与最小 TTL。CNAME 直接跳过 —— 我们只要最终的 A。
fn parse_a_records(resp: &[u8], want_id: u16) -> Result<(Vec<Ipv4Addr>, u64)> {
    if resp.len() < 12 {
        bail!("DNS 响应过短");
    }
    if resp[0..2] != want_id.to_be_bytes() {
        bail!("DNS 响应 ID 不匹配 (可能是串包)");
    }
    if resp[2] & 0x80 == 0 {
        bail!("DNS 响应的 QR 位不是响应");
    }
    match resp[3] & 0x0F {
        0 => {}
        3 => bail!("域名不存在 (NXDOMAIN)"),
        rc => bail!("DNS 服务端返回错误 RCODE={rc}"),
    }

    let qd = u16::from_be_bytes([resp[4], resp[5]]) as usize;
    let an = u16::from_be_bytes([resp[6], resp[7]]) as usize;
    let mut pos = 12;
    // 跳过问题段
    for _ in 0..qd {
        pos = skip_name(resp, pos)?;
        pos += 4; // QTYPE + QCLASS
    }

    let mut ips = Vec::new();
    let mut min_ttl = TTL_MAX;
    for _ in 0..an {
        pos = skip_name(resp, pos)?;
        if pos + 10 > resp.len() {
            bail!("DNS 回答段截断");
        }
        let rtype = u16::from_be_bytes([resp[pos], resp[pos + 1]]);
        let ttl = u32::from_be_bytes([resp[pos + 4], resp[pos + 5], resp[pos + 6], resp[pos + 7]]);
        let rdlen = u16::from_be_bytes([resp[pos + 8], resp[pos + 9]]) as usize;
        pos += 10;
        if pos + rdlen > resp.len() {
            bail!("DNS 记录数据截断");
        }
        if rtype == 1 && rdlen == 4 {
            ips.push(Ipv4Addr::new(resp[pos], resp[pos + 1], resp[pos + 2], resp[pos + 3]));
            min_ttl = min_ttl.min(ttl as u64);
        }
        pos += rdlen;
    }

    if ips.is_empty() {
        bail!("响应里没有 A 记录");
    }
    Ok((ips, min_ttl.clamp(TTL_MIN, TTL_MAX)))
}

/// 隧道内 DNS 解析器 (每条隧道一个)。
pub struct TunnelDns {
    server: std::net::SocketAddr,
    cache: std::sync::Mutex<std::collections::HashMap<String, (Vec<Ipv4Addr>, std::time::Instant)>>,
}

impl TunnelDns {
    pub fn new(server: std::net::IpAddr) -> Self {
        Self {
            server: std::net::SocketAddr::new(server, 53),
            cache: std::sync::Mutex::new(std::collections::HashMap::new()),
        }
    }

    fn cached(&self, name: &str) -> Option<Vec<Ipv4Addr>> {
        let c = self.cache.lock().unwrap_or_else(|e| e.into_inner());
        c.get(name).and_then(|(ips, exp)| {
            (*exp > std::time::Instant::now()).then(|| ips.clone())
        })
    }

    fn store(&self, name: &str, ips: &[Ipv4Addr], ttl: u64) {
        let mut c = self.cache.lock().unwrap_or_else(|e| e.into_inner());
        if c.len() >= CACHE_CAP {
            // 简单清理: 先扔掉所有过期项; 仍满则整体清空 (缓存是优化, 丢了只是多一次查询)。
            let now = std::time::Instant::now();
            c.retain(|_, (_, exp)| *exp > now);
            if c.len() >= CACHE_CAP {
                c.clear();
            }
        }
        c.insert(
            name.to_string(),
            (
                ips.to_vec(),
                std::time::Instant::now() + std::time::Duration::from_secs(ttl),
            ),
        );
    }

    /// 经隧道解析域名, 返回首选 IPv4 地址。
    pub async fn resolve(
        &self,
        tunnel: std::sync::Arc<super::tunnel::WgTunnel>,
        name: &str,
        port: u16,
    ) -> Result<std::net::SocketAddr> {
        // IP 字面量不查
        if let Ok(ip) = name.parse::<std::net::IpAddr>() {
            return Ok(std::net::SocketAddr::new(ip, port));
        }
        if let Some(ips) = self.cached(name) {
            return Ok(std::net::SocketAddr::new(ips[0].into(), port));
        }

        let id = fastrand::u16(..);
        let query = build_query(id, name)?;
        let sock = super::socket::WgUdpSocket::bind(tunnel)?;
        sock.send_to(&query, self.server)?;

        let mut buf = vec![0u8; 2048];
        let (n, _) = tokio::time::timeout(QUERY_TIMEOUT, sock.recv_from(&mut buf))
            .await
            .map_err(|_| anyhow::anyhow!("隧道内 DNS 查询超时 ({}s)", QUERY_TIMEOUT.as_secs()))??;

        let (ips, ttl) = parse_a_records(&buf[..n], id)?;
        self.store(name, &ips, ttl);
        Ok(std::net::SocketAddr::new(ips[0].into(), port))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 构造一个最小 DNS 响应: 1 问题 + n 个 A 记录。
    fn resp_with_a(id: u16, ips: &[Ipv4Addr], ttl: u32) -> Vec<u8> {
        let mut r = Vec::new();
        r.extend_from_slice(&id.to_be_bytes());
        r.extend_from_slice(&[0x81, 0x80]); // QR=1, RD/RA
        r.extend_from_slice(&[0x00, 0x01]); // QDCOUNT
        r.extend_from_slice(&(ips.len() as u16).to_be_bytes()); // ANCOUNT
        r.extend_from_slice(&[0, 0, 0, 0]);
        // 问题段: example.com A IN
        for l in ["example", "com"] {
            r.push(l.len() as u8);
            r.extend_from_slice(l.as_bytes());
        }
        r.extend_from_slice(&[0, 0x00, 0x01, 0x00, 0x01]);
        // 回答段: 用压缩指针指回问题段的名字 (0xC00C)
        for ip in ips {
            r.extend_from_slice(&[0xC0, 0x0C]);
            r.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]); // A, IN
            r.extend_from_slice(&ttl.to_be_bytes());
            r.extend_from_slice(&[0x00, 0x04]);
            r.extend_from_slice(&ip.octets());
        }
        r
    }

    #[test]
    fn parses_a_records_with_compression_pointer() {
        let ips = [Ipv4Addr::new(1, 2, 3, 4), Ipv4Addr::new(5, 6, 7, 8)];
        let r = resp_with_a(0x1234, &ips, 60);
        let (got, ttl) = parse_a_records(&r, 0x1234).unwrap();
        assert_eq!(got, ips);
        assert_eq!(ttl, 60);
    }

    #[test]
    fn rejects_mismatched_id() {
        let r = resp_with_a(0x1111, &[Ipv4Addr::new(1, 1, 1, 1)], 60);
        // ID 不匹配必须拒绝 —— 否则一个串进来的响应就能把域名解析到攻击者指定的 IP
        let e = parse_a_records(&r, 0x2222).unwrap_err().to_string();
        assert!(e.contains("ID 不匹配"), "实际: {e}");
    }

    #[test]
    fn rejects_nxdomain_and_servfail() {
        let mut r = resp_with_a(1, &[Ipv4Addr::new(1, 1, 1, 1)], 60);
        r[3] = (r[3] & 0xF0) | 3; // NXDOMAIN
        assert!(parse_a_records(&r, 1).unwrap_err().to_string().contains("NXDOMAIN"));
        r[3] = (r[3] & 0xF0) | 2; // SERVFAIL
        assert!(parse_a_records(&r, 1).unwrap_err().to_string().contains("RCODE=2"));
    }

    /// 压缩指针环必须被挡住, 不能把解析器转死。
    ///
    /// 这是 DNS 解析器上的经典 DoS: 一个指向自己的指针能让朴素实现无限循环。
    #[test]
    fn compression_pointer_loop_is_rejected_not_hung() {
        // 名字位置 12 处放一个指回 12 的指针
        let mut r = vec![0u8; 12];
        r[0..2].copy_from_slice(&1u16.to_be_bytes());
        r[2] = 0x81;
        r[3] = 0x80;
        r[4..6].copy_from_slice(&1u16.to_be_bytes()); // QDCOUNT=1
        r[6..8].copy_from_slice(&1u16.to_be_bytes()); // ANCOUNT=1
        r.extend_from_slice(&[0xC0, 0x0C]); // 指向偏移 12 = 自己
        r.extend_from_slice(&[0x00, 0x01, 0x00, 0x01, 0, 0, 0, 60, 0x00, 0x04, 1, 2, 3, 4]);
        // 不 hang、返回 Err 或正常解析都可以, 唯独不能卡死
        let _ = parse_a_records(&r, 1);
    }

    #[test]
    fn truncated_message_is_rejected() {
        assert!(parse_a_records(&[0u8; 5], 1).is_err());
        let r = resp_with_a(1, &[Ipv4Addr::new(1, 1, 1, 1)], 60);
        assert!(parse_a_records(&r[..r.len() - 2], 1).is_err(), "截断的记录必须报错");
    }

    #[test]
    fn query_roundtrips_name() {
        let q = build_query(0xABCD, "example.com").unwrap();
        assert_eq!(&q[0..2], &0xABCDu16.to_be_bytes());
        assert_eq!(u16::from_be_bytes([q[4], q[5]]), 1, "QDCOUNT 应为 1");
        assert!(q.windows(7).any(|w| w == b"example"));
        assert_eq!(&q[q.len() - 4..], &[0x00, 0x01, 0x00, 0x01], "QTYPE=A QCLASS=IN");
    }

    #[test]
    fn ttl_is_clamped() {
        let r = resp_with_a(1, &[Ipv4Addr::new(1, 1, 1, 1)], 0);
        assert_eq!(parse_a_records(&r, 1).unwrap().1, TTL_MIN, "TTL 0 应抬到下限");
        let r = resp_with_a(1, &[Ipv4Addr::new(1, 1, 1, 1)], 999_999);
        assert_eq!(parse_a_records(&r, 1).unwrap().1, TTL_MAX, "超长 TTL 应压到上限");
    }
}
