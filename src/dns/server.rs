use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::time::timeout;
use tracing::{debug, error, info};

use crate::proxy::pool::WarmPool;
use crate::proxy::outbound::OutboundNode;
use crate::router::RoutingRequest;

const TCP_TIMEOUT: Duration = Duration::from_secs(5);
/// DNS 上游查询重传轮数。每轮向所有上游各发一份, 无匹配响应则重传。
const DNS_QUERY_ROUNDS: u32 = 3;
/// 每轮等待上限。上游正常时响应几十毫秒即返回, 这只是丢包后重传前的最大等待。
/// 3 × 800ms = 2.4s 总上限, 远低于 Windows DNS 客户端 ~11s 重传超时。
const DNS_RETRANSMIT_INTERVAL: Duration = Duration::from_millis(800);
/// TCP 上游单次查询 (连接+收发) 超时。TCP 无 UDP 的丢包问题, 故按上游顺序 failover 而非
/// 并行重传; 3s 宽于正常 TCP DNS 往返, 又能在上游 SYN 被丢时较快切下一个。
const DNS_TCP_TIMEOUT: Duration = Duration::from_secs(3);

fn extract_domain(data: &[u8]) -> Option<String> {
    if data.len() < 12 {
        return None;
    }
    let mut offset = 12;
    let mut labels = Vec::new();
    while offset < data.len() {
        let n = data[offset] as usize;
        offset += 1;
        if n == 0 {
            break;
        }
        if n & 0xC0 != 0 {
            break; // pointer compression not expected in question
        }
        if offset + n > data.len() {
            break;
        }
        if let Ok(label) = std::str::from_utf8(&data[offset..offset + n]) {
            labels.push(label.to_lowercase());
        } else {
            return None;
        }
        offset += n;
    }
    if labels.is_empty() {
        None
    } else {
        Some(labels.join("."))
    }
}

fn question_end(data: &[u8]) -> usize {
    if data.len() < 12 {
        return data.len();
    }
    let qdcount = u16::from_be_bytes([data[4], data[5]]) as usize;
    let mut pos = 12;
    for _ in 0..qdcount {
        while pos < data.len() {
            let n = data[pos] as usize;
            if n == 0 {
                pos += 1;
                break;
            }
            if n & 0xC0 != 0 {
                pos += 2;
                break;
            }
            pos += 1 + n;
        }
        pos += 4; // QTYPE + QCLASS
        if pos > data.len() {
            return data.len();
        }
    }
    pos
}

fn make_nxdomain(query: &[u8]) -> Vec<u8> {
    if query.len() < 12 {
        return query.to_vec();
    }
    let end = question_end(query);
    let mut header = query[..12].to_vec();
    header[2] |= 0x80; // QR=1
    header[3] = (header[3] & 0xF0) | 0x03; // RCODE=NXDOMAIN
    header[6] = 0;
    header[7] = 0; // ANCOUNT
    header[8] = 0;
    header[9] = 0; // NSCOUNT
    header[10] = 0;
    header[11] = 0; // ARCOUNT

    let mut result = header;
    result.extend_from_slice(&query[12..end]);
    result
}

fn pack_address(host: &str, port: u16) -> Vec<u8> {
    let mut buf = Vec::new();
    if let Ok(ip) = host.parse::<IpAddr>() {
        match ip {
            IpAddr::V4(v4) => {
                buf.push(0x01);
                buf.extend_from_slice(&v4.octets());
            }
            IpAddr::V6(v6) => {
                buf.push(0x04);
                buf.extend_from_slice(&v6.octets());
            }
        }
    } else {
        buf.push(0x03);
        buf.push(host.len() as u8);
        buf.extend_from_slice(host.as_bytes());
    }
    buf.extend_from_slice(&port.to_be_bytes());
    buf
}

fn get_qtype(data: &[u8]) -> Option<u16> {
    let end = question_end(data);
    if end > data.len() || end < 4 {
        return None;
    }
    Some(u16::from_be_bytes([data[end - 4], data[end - 3]]))
}

fn make_fake_ip_response(query: &[u8], ip: std::net::Ipv4Addr) -> Option<Vec<u8>> {
    let end = question_end(query);
    // end<=12 = 没有真实问题段: 此时 0xC00C 压缩指针会指向 answer 自身 (自引用环)。
    // process_query 已在上游拦畸形查询, 这里是第二道防线 (也便于单测)。
    if end <= 12 || end > query.len() || query.len() < 12 { return None; }

    let mut header = query[..12].to_vec();
    header[2] |= 0x80; // QR=1
    header[3] &= 0x0F; // No error
    
    // ANCOUNT = 1
    header[6] = 0;
    header[7] = 1;
    // NSCOUNT = 0
    header[8] = 0;
    header[9] = 0;
    // ARCOUNT = 0
    header[10] = 0;
    header[11] = 0;

    let mut result = header;
    result.extend_from_slice(&query[12..end]);
    
    // Answer: Name ptr(0xc00c) Type A(1) Class IN(1) TTL RDLength(4) RData(ip)。
    // TTL=300s: fake-IP 映射稳定 (一个域名的 fake-IP 不变, 池 131071 淘汰极罕见), 之前
    // TTL=1s 让客户端几乎每个请求都重新查网关 DNS → 查询量放大数百倍 → DNS 被打爆偶发
    // 丢包 → Windows 重传 11s 卡顿。300s 大幅降低查询频率, 陈旧风险≤5min 可接受。
    result.extend_from_slice(&[0xC0, 0x0C, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x01, 0x2C, 0x00, 0x04]);
    result.extend_from_slice(&ip.octets());
    
    Some(result)
}

/// 单条 AAAA 记录响应 (静态解析的 IPv6)。结构同 make_fake_ip_response, 仅 Type=AAAA(28)
/// + RDLENGTH=16 + 16B 地址。TTL=300s (静态映射稳定)。
fn make_aaaa_response(query: &[u8], ip: std::net::Ipv6Addr) -> Option<Vec<u8>> {
    let end = question_end(query);
    if end <= 12 || end > query.len() || query.len() < 12 { return None; }
    let mut header = query[..12].to_vec();
    header[2] |= 0x80; // QR=1
    header[3] &= 0x0F; // No error
    header[6] = 0; header[7] = 1; // ANCOUNT=1
    header[8] = 0; header[9] = 0; // NSCOUNT=0
    header[10] = 0; header[11] = 0; // ARCOUNT=0
    let mut result = header;
    result.extend_from_slice(&query[12..end]);
    // Name ptr(0xC00C) Type AAAA(28) Class IN(1) TTL(300) RDLength(16) RData(ip)
    result.extend_from_slice(&[0xC0, 0x0C, 0x00, 0x1C, 0x00, 0x01, 0x00, 0x00, 0x01, 0x2C, 0x00, 0x10]);
    result.extend_from_slice(&ip.octets());
    Some(result)
}

/// 静态解析域名匹配 (dnsmasq 语义): 精确相等, 或 dq 是 key 的子域 (dq 以 `.key` 结尾)。
/// 两侧均应已小写。`test.local` 命中 `test.local` / `api.test.local`, 不命中 `xtest.local`。
fn static_domain_matches(dq: &str, key: &str) -> bool {
    dq == key
        || (dq.len() > key.len() + 1
            && dq.ends_with(key)
            && dq.as_bytes()[dq.len() - key.len() - 1] == b'.')
}

/// IP 版本策略是否把该查询抑制成 NODATA。
/// - `Ipv4Only`: 抑制 AAAA(28)。 `Ipv6Only`: 抑制 A(1)。 (硬模式, 与 has_* 无关)
/// - `PreferIpv4`: 该名字**有 v4** 时抑制 AAAA (逼 v4)。 `PreferIpv6`: 有 v6 时抑制 A。
/// direct/上游无法探测另一族存在与否 → 传 has_v4=has_v6=false, 使 prefer 恒不抑制 (=Dual);
/// static 已知全部族 → 传真实值, prefer 完全生效。非 A/AAAA (其他 qtype) 一律不抑制。
fn ip_strategy_suppresses(strategy: crate::config::IpStrategy, qtype: u16, has_v4: bool, has_v6: bool) -> bool {
    use crate::config::IpStrategy::*;
    match (strategy, qtype) {
        (Ipv4Only, 28) => true,
        (Ipv6Only, 1) => true,
        (PreferIpv4, 28) => has_v4,
        (PreferIpv6, 1) => has_v6,
        _ => false,
    }
}

/// 静态命中后按查询类型 + IP 策略构造答复。A(1)/AAAA(28) 未被策略抑制且有对应家族 IP
/// 则回该记录; 该域名被静态接管, 被抑制 / 无对应家族 / 其他类型一律回 NODATA
/// (**不放行上游**, 防拿到真实记录泄漏)。
fn static_answer(req: &[u8], qtype: u16, ips: &[std::net::IpAddr], strategy: crate::config::IpStrategy) -> Option<Vec<u8>> {
    let nodata = || make_empty_response(req).or_else(|| Some(make_nxdomain(req)));
    let has_v4 = ips.iter().any(|ip| ip.is_ipv4());
    let has_v6 = ips.iter().any(|ip| ip.is_ipv6());
    if ip_strategy_suppresses(strategy, qtype, has_v4, has_v6) {
        return nodata();
    }
    match qtype {
        1 => ips.iter().find_map(|ip| match ip { IpAddr::V4(v4) => Some(*v4), _ => None })
            .and_then(|v4| make_fake_ip_response(req, v4))
            .or_else(nodata),
        28 => ips.iter().find_map(|ip| match ip { IpAddr::V6(v6) => Some(*v6), _ => None })
            .and_then(|v6| make_aaaa_response(req, v6))
            .or_else(nodata),
        _ => nodata(),
    }
}

fn make_empty_response(query: &[u8]) -> Option<Vec<u8>> {
    let end = question_end(query);
    if end > query.len() || query.len() < 12 { return None; }

    let mut header = query[..12].to_vec();
    header[2] |= 0x80; // QR=1
    header[3] &= 0x0F; // No error

    header[6] = 0; header[7] = 0;   // ANCOUNT=0
    header[8] = 0; header[9] = 1;   // NSCOUNT=1 (authority 段带 SOA, 供负缓存)
    header[10] = 0; header[11] = 0; // ARCOUNT=0

    let mut result = header;
    result.extend_from_slice(&query[12..end]);

    // RFC 2308 负缓存: NODATA 空答复必须在 authority 段带一条 SOA, 否则 Windows 等
    // stub resolver 不缓存该 (qname, qtype) → getaddrinfo 每次都重查 AAAA/type65
    // → 自造查询风暴 + 偶发丢包致 11s 卡顿。合成一条最小 SOA, owner/MNAME/RNAME 均用
    // 压缩指针 0xC00C 指向问题名 (RFC 1035 §4.1.4 允许 SOA RDATA 压缩)。负缓存 TTL
    // = min(SOA.TTL, SOA.MINIMUM) = 300s, 与 fake-IP A 记录 TTL 对齐。
    result.extend_from_slice(&[
        0xC0, 0x0C,             // Name → ptr 问题名
        0x00, 0x06,             // Type = SOA
        0x00, 0x01,             // Class = IN
        0x00, 0x00, 0x01, 0x2C, // TTL = 300
        0x00, 0x18,             // RDLENGTH = 24 (MNAME 2 + RNAME 2 + 5×u32 20)
        0xC0, 0x0C,             // MNAME → ptr 问题名
        0xC0, 0x0C,             // RNAME → ptr 问题名
        0x00, 0x00, 0x00, 0x01, // SERIAL  = 1
        0x00, 0x00, 0x0E, 0x10, // REFRESH = 3600
        0x00, 0x00, 0x02, 0x58, // RETRY   = 600
        0x00, 0x01, 0x51, 0x80, // EXPIRE  = 86400
        0x00, 0x00, 0x01, 0x2C, // MINIMUM = 300 (负缓存 TTL)
    ]);
    Some(result)
}

/// DNS 上游查询: 多上游并行 + 重传。
///
/// 旧实现单上游单发不重传: 上游丢一个 UDP 包(114 等公共 DNS 高峰期偶发/限速)就返回
/// None → 网关不回包 → 客户端(Windows)靠自身重传累积 ~11s 才成功。这里每轮向**所有**
/// 上游各发一份, 等 DNS_RETRANSMIT_INTERVAL, 无匹配响应则重传, 最多 DNS_QUERY_ROUNDS 轮。
/// 任一上游先回且 tx_id 匹配即返回 —— 上游健康时几十毫秒返回(recv 一到就醒, 不等满
/// interval), 只有真丢包才触发重传/换上游。
async fn udp_query(req: &[u8], upstreams: &[SocketAddr]) -> Option<Vec<u8>> {
    if upstreams.is_empty() || req.len() < 2 {
        return None;
    }
    let sock = UdpSocket::bind("0.0.0.0:0").await.ok()?;
    let mut buf = vec![0u8; 1500];

    for _round in 0..DNS_QUERY_ROUNDS {
        // 本轮向所有上游各发一份 (并行竞速 + 单上游丢包由其他上游兜底)
        for up in upstreams {
            let _ = sock.send_to(req, up).await;
        }
        // 本轮内循环收包, 丢弃 tx_id 不匹配的串扰/迟到响应, 直到匹配或本轮超时
        let deadline = tokio::time::Instant::now() + DNS_RETRANSMIT_INTERVAL;
        loop {
            match tokio::time::timeout_at(deadline, sock.recv_from(&mut buf)).await {
                // 合法 DNS 响应: ≥12B 头 + tx_id 与查询一致 + QR=1
                Ok(Ok((size, _)))
                    if size >= 12 && buf[0] == req[0] && buf[1] == req[1] && (buf[2] & 0x80) != 0 =>
                {
                    return Some(buf[..size].to_vec());
                }
                Ok(Ok(_)) => continue, // 不匹配/畸形, 本轮继续等
                _ => break,            // 本轮超时或 socket 错 → 下一轮重传
            }
        }
    }
    None
}

/// 直连上游解析: 按每个上游的传输协议分派。UDP 上游走 udp_query (并行 + 重传), TCP 上游
/// 走 tcp_query (顺序 failover)。两者都配则并发跑、取先返回的正响应 (混配少见但支持)。
async fn direct_query(req: &[u8], upstreams: &[(SocketAddr, crate::config::DnsProtocol)]) -> Option<Vec<u8>> {
    use crate::config::DnsProtocol::{Tcp, Udp};
    let udp: Vec<SocketAddr> = upstreams.iter().filter(|(_, p)| *p == Udp).map(|(a, _)| *a).collect();
    let tcp: Vec<SocketAddr> = upstreams.iter().filter(|(_, p)| *p == Tcp).map(|(a, _)| *a).collect();
    match (udp.is_empty(), tcp.is_empty()) {
        (false, true) => udp_query(req, &udp).await,
        (true, false) => tcp_query(req, &tcp).await,
        (true, true) => None,
        (false, false) => {
            // 并发竞速: 先返回 Some 者胜; 若先完成的是 None 则 await 另一个 (pin 复用, 不重跑)。
            let u = udp_query(req, &udp);
            let t = tcp_query(req, &tcp);
            tokio::pin!(u);
            tokio::pin!(t);
            tokio::select! {
                r = &mut u => if r.is_some() { r } else { t.await },
                r = &mut t => if r.is_some() { r } else { u.await },
            }
        }
    }
}

/// TCP 上游解析: 按顺序试各上游, 首个成功即返回。TCP 无丢包问题, 故 failover 而非并行重传。
async fn tcp_query(req: &[u8], upstreams: &[SocketAddr]) -> Option<Vec<u8>> {
    for up in upstreams {
        if let Some(r) = tcp_query_one(req, *up).await {
            return Some(r);
        }
    }
    None
}

/// 单个 TCP 上游一次查询: 连接 → 写 [2B 长度][报文] → 读 [2B 长度][响应] (RFC 7766),
/// 校验 tx_id + QR。整体 DNS_TCP_TIMEOUT 超时。任何一步失败/超时 → None (交上层 failover)。
async fn tcp_query_one(req: &[u8], up: SocketAddr) -> Option<Vec<u8>> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let attempt = async {
        let mut s = tokio::net::TcpStream::connect(up).await.ok()?;
        let mut framed = Vec::with_capacity(2 + req.len());
        framed.extend_from_slice(&(req.len() as u16).to_be_bytes());
        framed.extend_from_slice(req);
        s.write_all(&framed).await.ok()?;
        let mut len_buf = [0u8; 2];
        s.read_exact(&mut len_buf).await.ok()?;
        let n = u16::from_be_bytes(len_buf) as usize;
        if n < 12 {
            return None;
        }
        let mut buf = vec![0u8; n];
        s.read_exact(&mut buf).await.ok()?;
        // 合法响应: tx_id 与查询一致 + QR=1 (req 已在 process_query 上游保证 ≥12B)。
        if buf[0] == req[0] && buf[1] == req[1] && (buf[2] & 0x80) != 0 {
            Some(buf)
        } else {
            None
        }
    };
    tokio::time::timeout(DNS_TCP_TIMEOUT, attempt).await.ok().flatten()
}

// ── DNS 响应缓存 (honoring TTL) ──────────────────────────────────────────────
// 接上 advanced_dns.cache (原为 stub 未实现)。缓存直连(udp_query)+ 隧道(tcp_over_tunnel)
// 的上游响应, 按 answer 段最小 TTL 过期。价值: 直连域名不再每查打 114/223; **非 fake-IP /
// 罕见 qtype 的隧道-DNS 不再每次消耗一条 WarmPool 隧道**。fake-IP 路径本地无需缓存。

struct CacheEntry {
    response: Vec<u8>,
    expiry: std::time::Instant,
}

/// TTL-aware DNS 响应缓存。key=(小写域名, qtype), 只缓存有 answer 的正响应。
struct DnsCache {
    map: std::sync::Mutex<std::collections::HashMap<(String, u16), CacheEntry>>,
    max_entries: usize,
}

impl DnsCache {
    fn new(max_entries: usize) -> Self {
        Self {
            map: std::sync::Mutex::new(std::collections::HashMap::new()),
            max_entries: max_entries.max(1),
        }
    }

    /// 命中且未过期 → 返回按当前 query patch 好的响应 (tx_id + question 段, 兼容 0x20 大小写
    /// 随机 + id; 保留响应头/flags/答案不变)。
    fn get(&self, domain: &str, qtype: u16, query: &[u8]) -> Option<Vec<u8>> {
        let mut m = self.map.lock().unwrap_or_else(|e| e.into_inner());
        let key = (domain.to_string(), qtype);
        let e = m.get(&key)?;
        if e.expiry <= std::time::Instant::now() {
            m.remove(&key);
            return None;
        }
        let mut resp = e.response.clone();
        let q_end = question_end(query);
        if q_end >= 12 && resp.len() >= q_end && query.len() >= q_end {
            resp[0] = query[0];
            resp[1] = query[1];
            resp[12..q_end].copy_from_slice(&query[12..q_end]);
        }
        Some(resp)
    }

    /// 存入 (仅有 answer 的正响应)。NODATA/NXDOMAIN 不缓存 (客户端 SOA 负缓存已兜 AAAA)。
    fn put(&self, domain: &str, qtype: u16, response: &[u8]) {
        let ttl = match min_answer_ttl(response) {
            Some(t) => t.clamp(1, 3600),
            None => return,
        };
        let key = (domain.to_string(), qtype);
        let mut m = self.map.lock().unwrap_or_else(|e| e.into_inner());
        if m.len() >= self.max_entries && !m.contains_key(&key) {
            let now = std::time::Instant::now();
            m.retain(|_, e| e.expiry > now); // 先清过期
            if m.len() >= self.max_entries {
                if let Some(k) = m.keys().next().cloned() {
                    m.remove(&k); // 仍满则弹一个 (非严格 LRU, 缓存策略不影响正确性)
                }
            }
        }
        m.insert(
            key,
            CacheEntry {
                response: response.to_vec(),
                expiry: std::time::Instant::now() + Duration::from_secs(ttl as u64),
            },
        );
    }
}

/// 跳过一个 DNS 域名 (处理压缩指针), 返回其后偏移。
fn skip_name(data: &[u8], mut pos: usize) -> Option<usize> {
    loop {
        let len = *data.get(pos)?;
        if len == 0 {
            return Some(pos + 1);
        }
        if len & 0xC0 == 0xC0 {
            return Some(pos + 2); // 压缩指针 (2B, name 到此为止)
        }
        if len & 0xC0 != 0 {
            return None; // 非法长度字节
        }
        pos += 1 + len as usize;
    }
}

/// 从响应 answer 段取最小 TTL (缓存过期用)。无 answer 返回 None (不缓存)。
fn min_answer_ttl(resp: &[u8]) -> Option<u32> {
    if resp.len() < 12 {
        return None;
    }
    let ancount = u16::from_be_bytes([resp[6], resp[7]]);
    if ancount == 0 {
        return None;
    }
    let mut pos = question_end(resp);
    let mut min: Option<u32> = None;
    for _ in 0..ancount {
        pos = skip_name(resp, pos)?;
        if pos + 10 > resp.len() {
            break;
        }
        let ttl = u32::from_be_bytes([resp[pos + 4], resp[pos + 5], resp[pos + 6], resp[pos + 7]]);
        let rdlen = u16::from_be_bytes([resp[pos + 8], resp[pos + 9]]) as usize;
        min = Some(min.map_or(ttl, |m| m.min(ttl)));
        pos += 10 + rdlen;
    }
    min
}

pub struct DnsForwarder {
    socket: Arc<UdpSocket>,
    state: Arc<arc_swap::ArcSwap<crate::config_watcher::CoreState>>,
    fake_ip_mapper: Option<Arc<crate::dns::fake_ip::FakeIpMapper>>,
    xdp_engine: Option<Arc<crate::ebpf::XdpEngine>>,
    cache: Option<DnsCache>,
    /// 本 DNS 入站的 tag, 供路由的 `inbound` 条件用。
    ///
    /// ⚠️ 语义要看清: DNS 查询是从 **dns 入站**进来的, 所以这里带的是 dns 的 tag。
    /// 一条 `{"inbound": "tproxy", ...}` 的规则**不会**影响 DNS/fake-IP 决策 ——
    /// 那条查询并非来自 tproxy。这不是遗漏, 是"决策发生在另一个入站上"的固有结果。
    inbound_tag: Arc<str>,
}

impl DnsForwarder {
    /// 构造一个**只处理查询、不 serve** 的实例, 供透明代理的 DNS 劫持复用。
    ///
    /// 与 `start` 的区别: 不绑监听 socket、不起收发 loop —— 劫持路径的收发由 transparent_udp
    /// 的透明 socket 负责, 这里只借 `process_query` 的 fake-IP 分配 + 上游解析能力。
    /// 共用同一个 `fake_ip_mapper`, 所以劫持路径分配的 fake-IP 与 dns 入站完全一致。
    ///
    /// socket 字段填一个未绑定的占位 (0.0.0.0:0), 因为 process_query 从不碰它 (只 serve loop 用)。
    pub async fn for_hijack(
        state: Arc<arc_swap::ArcSwap<crate::config_watcher::CoreState>>,
        fake_ip_mapper: Option<Arc<crate::dns::fake_ip::FakeIpMapper>>,
        xdp_engine: Option<Arc<crate::ebpf::XdpEngine>>,
    ) -> anyhow::Result<Arc<Self>> {
        let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await?); // 占位, 不用于收发
        let cache = state
            .load()
            .advanced_dns
            .as_ref()
            .and_then(|adv| adv.cache.as_ref())
            .filter(|c| c.enabled)
            .map(|c| DnsCache::new(c.max_entries));
        Ok(Arc::new(Self {
            socket,
            state,
            fake_ip_mapper,
            xdp_engine,
            cache,
            inbound_tag: crate::config::DNS_HIJACK_INBOUND_TAG.into(),
        }))
    }

    /// 处理一个 DNS 查询字节, 返回应答字节 (供 DNS 劫持路径调用)。None = 无法应答, 应放行。
    pub async fn resolve_query(&self, req: &[u8]) -> Option<Vec<u8>> {
        self.process_query(req).await
    }

    pub async fn start(
        inbound_tag: Arc<str>,
        listen_addr: SocketAddr,
        state: Arc<arc_swap::ArcSwap<crate::config_watcher::CoreState>>,
        fake_ip_mapper: Option<Arc<crate::dns::fake_ip::FakeIpMapper>>,
        xdp_engine: Option<Arc<crate::ebpf::XdpEngine>>,
    ) -> anyhow::Result<Arc<Self>> {
        let socket = Arc::new(UdpSocket::bind(listen_addr).await?);

        // 接上 advanced_dns.cache (enabled + max_entries)。启动时读初始配置; 缓存开关不热重载。
        let cache = state
            .load()
            .advanced_dns
            .as_ref()
            .and_then(|adv| adv.cache.as_ref())
            .filter(|c| c.enabled)
            .map(|c| DnsCache::new(c.max_entries));

        info!(
            "DNS Forwarder listening on {} (dynamic upstream, fake-ip: {}, cache: {})",
            listen_addr,
            fake_ip_mapper.is_some(),
            if cache.is_some() { "on" } else { "off" }
        );

        let forwarder = Arc::new(Self {
            socket,
            state,
            fake_ip_mapper,
            xdp_engine,
            cache,
            inbound_tag,
        });

        // Start worker task
        let f = forwarder.clone();
        tokio::spawn(async move {
            f.run_loop().await;
        });

        Ok(forwarder)
    }

    async fn run_loop(self: Arc<Self>) {
        let mut buf = vec![0u8; 1500];
        loop {
            match self.socket.recv_from(&mut buf).await {
                Ok((size, addr)) => {
                    let req = buf[..size].to_vec();
                    let f = self.clone();
                    tokio::spawn(async move {
                        if let Some(resp) = f.process_query(&req).await {
                            let _ = f.socket.send_to(&resp, addr).await;
                        }
                    });
                }
                Err(e) => {
                    error!("DNS server recv error: {}", e);
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
            }
        }
    }

    async fn process_query(&self, req: &[u8]) -> Option<Vec<u8>> {
        // 拒畸形查询: 必须有真实问题段。否则 question_end 停在 12, 而 extract_domain 只从
        // offset 12 起读 (不看 QDCOUNT) 仍可能返回域名 → get_qtype 把报头的 NSCOUNT 错当 qtype、
        // make_fake_ip_response 生成指向自身的 0xC00C 压缩指针 (自引用环, 畸形响应)。
        // QDCOUNT>=1 且 question_end>12 才算有合法问题名。
        if req.len() < 12
            || u16::from_be_bytes([req[4], req[5]]) == 0
            || question_end(req) <= 12
        {
            return None;
        }
        let domain = extract_domain(req)?;
        let qtype = get_qtype(req).unwrap_or(0);
        let _req_port = 53; // DNS
        let st = self.state.load();
        // IP 版本策略 (Copy, 在 drop(st) 前取出供后续 direct 分支用)。缺省 Dual。
        let ip_strategy = st.advanced_dns.as_ref().map(|a| a.ip_strategy).unwrap_or_default();

        // 静态解析优先 (最高优先级): 命中即直接回 A/AAAA, 绕过 fake-IP / 路由 / 上游 ——
        // 该域名完全由本地接管。最长键优先 (cached_static 已按域名长度降序)。命中但查询
        // 类型无对应 IP 家族 (如只配 v4 却查 AAAA) → NODATA 空答复: 该域名既然被静态接管,
        // 就**不**放行到上游, 否则会拿到真实 AAAA 泄漏。非 A/AAAA 查询同理回 NODATA。
        if let Some(adv) = &st.advanced_dns {
            if !adv.cached_static.is_empty() {
                let dq = domain.to_lowercase();
                if let Some((key, ips)) = adv.cached_static.iter().find(|(k, _)| static_domain_matches(&dq, k)) {
                    debug!("[DNS] static  [{}] → 匹配 `{}` {:?} (qtype {}, strategy {:?})", domain, key, ips, qtype, ip_strategy);
                    return static_answer(req, qtype, ips, ip_strategy);
                }
            }
        }
        // 用户配了 cn/direct resolver 就用其全部 (尊重配置, 不掺公共 DNS 免污染内网视图);
        // 没配则默认双公共 DNS 兜底 (114 电信/联通 + 223 阿里)。
        let mut cn_dns: Vec<(SocketAddr, crate::config::DnsProtocol)> = Vec::new();
        let mut remote_dns_host = "8.8.8.8".to_string();
        let mut remote_dns_port = 53;

        if let Some(adv) = &st.advanced_dns {
            if !adv.cached_cn_dns.is_empty() { cn_dns = adv.cached_cn_dns.clone(); }
            if let Some(cached) = &adv.cached_remote_host { remote_dns_host = cached.clone(); }
            if let Some(cached) = &adv.cached_remote_port { remote_dns_port = *cached; }
        }
        if cn_dns.is_empty() {
            use crate::config::DnsProtocol::Udp;
            cn_dns = vec![
                ("114.114.114.114:53".parse().unwrap(), Udp),
                ("223.5.5.5:53".parse().unwrap(), Udp),
            ];
        }

        let routing_req = RoutingRequest {
            domain: Some(&domain),
            ip: None,
            port: remote_dns_port,
            protocol: "udp",
            source_ip: None,
            source_mac: None,
            inbound: Some(&self.inbound_tag),
        };

        let action = st.router.route(routing_req);
        
        let node = st.outbounds.get(action.as_str()).map(|n| n.resolve_leaf());
        drop(st);
        
        if let Some(n) = node {
            match &*n {
                OutboundNode::Block { .. } => {
                    debug!("[DNS] block   [{}] → NXDOMAIN", domain);
                    Some(make_nxdomain(req))
                }
                OutboundNode::Direct { .. } => {
                    // IP 策略 (direct 只做硬抑制: prefer 无法探测另一族, 降为 Dual)。
                    // has_v4/has_v6 传 false → ip_strategy_suppresses 里 prefer 分支恒不抑制。
                    if ip_strategy_suppresses(ip_strategy, qtype, false, false) {
                        debug!("[DNS] direct  [{}] → qtype {} 被 IP 策略 {:?} 抑制 (NODATA)", domain, qtype, ip_strategy);
                        return make_empty_response(req).or_else(|| Some(make_nxdomain(req)));
                    }
                    let dk = domain.to_lowercase();
                    if let Some(cache) = &self.cache {
                        if let Some(hit) = cache.get(&dk, qtype, req) {
                            debug!("[DNS] direct  [{}] → cache hit", domain);
                            return Some(hit);
                        }
                    }
                    debug!("[DNS] direct  [{}] → 真实解析 via {:?}", domain, cn_dns);
                    let resp = direct_query(req, &cn_dns).await;
                    if let (Some(cache), Some(r)) = (&self.cache, &resp) {
                        cache.put(&dk, qtype, r);
                    }
                    resp
                }
                OutboundNode::Mirage { pool, .. } => {
                    if let Some(mapper) = &self.fake_ip_mapper {
                        if qtype == 1 { // A
                            let fake_ip = mapper.lookup_or_assign(&domain);
                            debug!("[DNS] proxy   [{}] → fake-IP {} (A)", domain, fake_ip);
                            if let Some(engine) = &self.xdp_engine {
                                let _ = engine.update_dns_cache(&domain, fake_ip);
                            }
                            return make_fake_ip_response(req, fake_ip);
                        } else if qtype == 28 || qtype == 65 { // AAAA / HTTPS(SVCB, type 65)
                            // fake-IP 模式下非 A 记录无需真解析: 客户端用 A 的 fake-IP
                            // 连接、代理按域名建连。尤其 type 65 (HTTPS RR) 现代浏览器
                            // 对每个域名都发, 若逐个走 tcp_over_tunnel 会各消耗+销毁一条
                            // 预热隧道 → 开页面 20-30 域名瞬间打空 WarmPool。返回 NODATA
                            // 空答复 (同 AAAA), 客户端回落 A 记录 fake-IP 连接, 功能无损。
                            debug!("[DNS] proxy   [{}] → qtype {} 空答复 (fake-IP 免隧道)", domain, qtype);
                            return make_empty_response(req);
                        }
                    }
                    // 隧道-DNS 是最贵的路径 (每查耗一条 WarmPool 隧道), 缓存收益最大。
                    let dk = domain.to_lowercase();
                    if let Some(cache) = &self.cache {
                        if let Some(hit) = cache.get(&dk, qtype, req) {
                            debug!("[DNS] proxy   [{}] → cache hit (免隧道)", domain);
                            return Some(hit);
                        }
                    }
                    debug!("[DNS] proxy   [{}] → 隧道查 {}:{} via {}", domain, remote_dns_host, remote_dns_port, n.tag());
                    let resp = self.tcp_over_tunnel(req, pool, &remote_dns_host, remote_dns_port).await;
                    if let (Some(cache), Some(r)) = (&self.cache, &resp) {
                        cache.put(&dk, qtype, r);
                    }
                    Some(resp.unwrap_or_else(|| make_nxdomain(req)))
                }
                _ => Some(make_nxdomain(req)),
            }
        } else {
            Some(make_nxdomain(req))
        }
    }

    async fn tcp_over_tunnel(&self, req: &[u8], pool: &WarmPool, remote_host: &str, remote_port: u16) -> Option<Vec<u8>> {
        let mut tunnel = match pool.get().await {
            Ok(t) => t,
            Err(e) => {
                tracing::warn!("DNS over tunnel: pool unavailable for {}:{} ({}). Query will fail.", remote_host, remote_port, e);
                return None;
            }
        };

        let target_addr = pack_address(remote_host, remote_port);
        let mut payload = Vec::new();
        payload.extend_from_slice(&target_addr);
        payload.extend_from_slice(&(req.len() as u16).to_be_bytes());
        payload.extend_from_slice(req);
        
        tunnel.writer.send_data(&payload).await.ok()?;
        
        // Read response block
        let resp_payload = timeout(TCP_TIMEOUT, tunnel.reader.recv_data()).await.ok()?.ok()?;
        
        if resp_payload.len() < 2 { return None; }
        
        let mut resp_buf = resp_payload[2..].to_vec();
        
        // Override tx_id just in case
        if resp_buf.len() >= 2 && req.len() >= 2 {
            resp_buf[0] = req[0];
            resp_buf[1] = req[1];
        }
        
        Some(resp_buf)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // 构造 "x.com" AAAA 查询: header(12) + name(3"x"..1"com"..0) + QTYPE(28) + QCLASS(1)
    fn aaaa_query() -> Vec<u8> {
        let mut q = vec![0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
        q.push(1); q.push(b'x');
        q.push(3); q.extend_from_slice(b"com");
        q.push(0);
        q.extend_from_slice(&[0x00, 0x1C]); // QTYPE = AAAA(28)
        q.extend_from_slice(&[0x00, 0x01]); // QCLASS = IN
        q
    }

    #[test]
    fn fake_ip_rejects_malformed_no_question() {
        let ip = "198.18.0.5".parse().unwrap();
        // 纯 12B 报头, QDCOUNT=0 → 无问题段, question_end=12 → 必须拒 (否则 0xC00C 自引用)。
        let hdr_only = vec![0x12, 0x34, 0x01, 0x00, 0, 0, 0, 0, 0, 0, 0, 0];
        assert!(make_fake_ip_response(&hdr_only, ip).is_none(), "纯报头应拒");
        // 构造包: QDCOUNT=0 但 offset 12 塞 label 字节 (骗过 extract_domain), NSCOUNT=0x0001
        // (让 get_qtype 误读成 qtype=1)。question_end 仍=12 (QDCOUNT=0) → 必须拒。
        let mut crafted = vec![0x12, 0x34, 0x01, 0x00, 0, 0, 0, 0, 0, 1, 0, 0];
        crafted.push(1); crafted.push(b'a'); // 伪 label
        assert_eq!(question_end(&crafted), 12, "QDCOUNT=0 → question_end 停在 12");
        assert!(make_fake_ip_response(&crafted, ip).is_none(), "构造的空问询包应拒, 不生成自引用 0xC00C");
        // 正常查询仍应正常出响应。
        assert!(make_fake_ip_response(&aaaa_query(), ip).is_some(), "合法查询正常");
    }

    #[test]
    fn static_domain_matching_semantics() {
        // 精确
        assert!(static_domain_matches("test.local", "test.local"));
        // 子域 (任意深度)
        assert!(static_domain_matches("api.test.local", "test.local"));
        assert!(static_domain_matches("a.b.test.local", "test.local"));
        // 不是子域: 前缀粘连 (xtest.local) 不该命中
        assert!(!static_domain_matches("xtest.local", "test.local"));
        // 不同域不命中
        assert!(!static_domain_matches("test.example", "test.local"));
        // key 比 dq 长不命中
        assert!(!static_domain_matches("local", "test.local"));
    }

    #[test]
    fn make_aaaa_response_structure() {
        let ip: std::net::Ipv6Addr = "fd00::1".parse().unwrap();
        let resp = make_aaaa_response(&aaaa_query(), ip).unwrap();
        assert_eq!(resp[2] & 0x80, 0x80, "QR");
        assert_eq!(u16::from_be_bytes([resp[6], resp[7]]), 1, "ANCOUNT=1");
        let ans = &resp[question_end(&aaaa_query())..];
        assert_eq!([ans[0], ans[1]], [0xC0, 0x0C], "name ptr");
        assert_eq!(u16::from_be_bytes([ans[2], ans[3]]), 28, "TYPE=AAAA");
        assert_eq!(u16::from_be_bytes([ans[10], ans[11]]), 16, "RDLENGTH=16");
        assert_eq!(&ans[12..28], &ip.octets(), "RDATA=IPv6");
    }

    #[test]
    fn static_answer_family_selection() {
        use crate::config::IpStrategy::Dual;
        let v4: std::net::IpAddr = "10.0.0.5".parse().unwrap();
        let v6: std::net::IpAddr = "fd00::1".parse().unwrap();

        // A 查询 + 有 v4 → A 记录 (ANCOUNT=1, TYPE=A, 正确 IP)
        let r = static_answer(&a_query(), 1, &[v4], Dual).unwrap();
        assert_eq!(u16::from_be_bytes([r[6], r[7]]), 1, "A: ANCOUNT=1");
        let ans = &r[question_end(&a_query())..];
        assert_eq!(u16::from_be_bytes([ans[2], ans[3]]), 1, "TYPE=A");
        assert_eq!(&ans[12..16], &[10, 0, 0, 5]);

        // A 查询但只配了 v6 → NODATA (ANCOUNT=0 + SOA), 绝不放行上游
        let r = static_answer(&a_query(), 1, &[v6], Dual).unwrap();
        assert_eq!(u16::from_be_bytes([r[6], r[7]]), 0, "只 v6 时 A 查询应 NODATA");
        assert_eq!(u16::from_be_bytes([r[8], r[9]]), 1, "NODATA 带 SOA");

        // AAAA 查询 + 有 v6 → AAAA 记录
        let r = static_answer(&aaaa_query(), 28, &[v6], Dual).unwrap();
        assert_eq!(u16::from_be_bytes([r[6], r[7]]), 1, "AAAA: ANCOUNT=1");
        let ans = &r[question_end(&aaaa_query())..];
        assert_eq!(u16::from_be_bytes([ans[2], ans[3]]), 28, "TYPE=AAAA");

        // AAAA 查询但只配 v4 → NODATA
        let r = static_answer(&aaaa_query(), 28, &[v4], Dual).unwrap();
        assert_eq!(u16::from_be_bytes([r[6], r[7]]), 0, "只 v4 时 AAAA 查询应 NODATA");

        // 其他类型 (MX=15) → NODATA (静态只服务 A/AAAA, 但仍接管该域名)
        let r = static_answer(&a_query(), 15, &[v4, v6], Dual).unwrap();
        assert_eq!(u16::from_be_bytes([r[6], r[7]]), 0, "非 A/AAAA 应 NODATA");
    }

    #[test]
    fn ip_strategy_suppression_matrix() {
        use crate::config::IpStrategy::*;
        // A=1, AAAA=28。has_v4/has_v6 只在 prefer 分支起作用。
        // Dual: 都不抑制
        assert!(!ip_strategy_suppresses(Dual, 1, true, true));
        assert!(!ip_strategy_suppresses(Dual, 28, true, true));
        // Ipv4Only: 抑制 AAAA, 不抑制 A (与 has_* 无关)
        assert!(ip_strategy_suppresses(Ipv4Only, 28, false, false));
        assert!(!ip_strategy_suppresses(Ipv4Only, 1, false, false));
        // Ipv6Only: 抑制 A, 不抑制 AAAA
        assert!(ip_strategy_suppresses(Ipv6Only, 1, false, false));
        assert!(!ip_strategy_suppresses(Ipv6Only, 28, false, false));
        // PreferIpv4: 有 v4 才抑制 AAAA; 无 v4 不抑制 (让 v6 通过)
        assert!(ip_strategy_suppresses(PreferIpv4, 28, true, true));
        assert!(!ip_strategy_suppresses(PreferIpv4, 28, false, true));
        assert!(!ip_strategy_suppresses(PreferIpv4, 1, true, true), "prefer_ipv4 绝不抑制 A");
        // PreferIpv6: 有 v6 才抑制 A
        assert!(ip_strategy_suppresses(PreferIpv6, 1, true, true));
        assert!(!ip_strategy_suppresses(PreferIpv6, 1, true, false));
        assert!(!ip_strategy_suppresses(PreferIpv6, 28, true, true), "prefer_ipv6 绝不抑制 AAAA");
        // direct 语义: has_v4=has_v6=false → prefer 恒不抑制 (降为 Dual), only 仍生效
        assert!(!ip_strategy_suppresses(PreferIpv4, 28, false, false), "direct: prefer 降 Dual");
        assert!(ip_strategy_suppresses(Ipv6Only, 1, false, false), "direct: only 仍生效");
    }

    #[test]
    fn static_answer_honors_prefer_and_only() {
        use crate::config::IpStrategy::*;
        let v4: std::net::IpAddr = "10.0.0.5".parse().unwrap();
        let v6: std::net::IpAddr = "fd00::1".parse().unwrap();
        let both = [v4, v6];

        // prefer_ipv4 + 双族: A 查询正常回 v4, AAAA 查询被抑制 (NODATA)
        let r = static_answer(&a_query(), 1, &both, PreferIpv4).unwrap();
        assert_eq!(u16::from_be_bytes([r[6], r[7]]), 1, "prefer_ipv4: A 正常");
        let r = static_answer(&aaaa_query(), 28, &both, PreferIpv4).unwrap();
        assert_eq!(u16::from_be_bytes([r[6], r[7]]), 0, "prefer_ipv4: AAAA 抑制");

        // prefer_ipv4 但条目只有 v6: AAAA 不抑制 (无 v4 可逼), 正常回 v6
        let r = static_answer(&aaaa_query(), 28, &[v6], PreferIpv4).unwrap();
        assert_eq!(u16::from_be_bytes([r[6], r[7]]), 1, "prefer_ipv4 但只有 v6: AAAA 放行");

        // ipv6_only + 双族: A 查询被硬抑制
        let r = static_answer(&a_query(), 1, &both, Ipv6Only).unwrap();
        assert_eq!(u16::from_be_bytes([r[6], r[7]]), 0, "ipv6_only: A 抑制");
    }

    #[test]
    fn empty_response_carries_soa_for_negative_caching() {
        let resp = make_empty_response(&aaaa_query()).unwrap();
        // header: QR=1, RCODE=0, ANCOUNT=0, NSCOUNT=1, ARCOUNT=0
        assert_eq!(resp[2] & 0x80, 0x80, "QR bit");
        assert_eq!(resp[3] & 0x0F, 0, "RCODE=NOERROR (NODATA, 非 NXDOMAIN)");
        assert_eq!(u16::from_be_bytes([resp[6], resp[7]]), 0, "ANCOUNT=0");
        assert_eq!(u16::from_be_bytes([resp[8], resp[9]]), 1, "NSCOUNT=1 (SOA)");
        assert_eq!(u16::from_be_bytes([resp[10], resp[11]]), 0, "ARCOUNT=0");

        // authority 段: 紧跟问题之后。定位 SOA RR。
        let soa = &resp[question_end(&aaaa_query())..];
        assert_eq!([soa[0], soa[1]], [0xC0, 0x0C], "owner = ptr 问题名");
        assert_eq!(u16::from_be_bytes([soa[2], soa[3]]), 6, "TYPE=SOA");
        let ttl = u32::from_be_bytes([soa[6], soa[7], soa[8], soa[9]]);
        assert_eq!(ttl, 300, "SOA TTL=300");
        let rdlen = u16::from_be_bytes([soa[10], soa[11]]) as usize;
        assert_eq!(rdlen, 24, "RDLENGTH=24");
        // RDATA 末 4 字节 = MINIMUM (负缓存 TTL)
        let rdata = &soa[12..12 + rdlen];
        let minimum = u32::from_be_bytes([rdata[20], rdata[21], rdata[22], rdata[23]]);
        assert_eq!(minimum, 300, "SOA MINIMUM=300 (负缓存 TTL)");
        // 整包长度精确 = header + question + SOA RR
        assert_eq!(resp.len(), question_end(&aaaa_query()) + 12 + rdlen, "无多余/截断字节");
    }

    // 最小 A 查询 (tx_id=0x1234)
    fn a_query() -> Vec<u8> {
        let mut q = vec![0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
        q.push(1); q.push(b'x');
        q.push(3); q.extend_from_slice(b"com");
        q.push(0);
        q.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]); // A IN
        q
    }

    /// 起一个假上游: `respond_from` 之前的包全丢, 之后的回一个合法响应 (QR=1, tx_id 回显)。
    /// 返回其地址。用于验证重传。
    async fn fake_upstream(respond_from: usize) -> SocketAddr {
        let up = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = up.local_addr().unwrap();
        tokio::spawn(async move {
            let mut b = vec![0u8; 1500];
            let mut count = 0usize;
            loop {
                let (n, from) = match up.recv_from(&mut b).await { Ok(v) => v, Err(_) => break };
                count += 1;
                if count < respond_from { continue; } // 丢前 N 个
                let mut resp = b[..n].to_vec();
                resp[2] |= 0x80; // QR=1
                let _ = up.send_to(&resp, from).await;
            }
        });
        addr
    }

    #[tokio::test]
    async fn udp_query_happy_path() {
        let up = fake_upstream(1).await; // 第 1 个包就回
        let resp = udp_query(&a_query(), &[up]).await.expect("应得到响应");
        assert_eq!(&resp[0..2], &[0x12, 0x34], "tx_id 回显");
        assert_eq!(resp[2] & 0x80, 0x80, "QR=1");
    }

    #[tokio::test]
    async fn udp_query_retransmits_after_loss() {
        // 上游丢掉第 1 个包, 第 2 个 (重传) 才回 → 单发不重传会失败, 重传应成功。
        let up = fake_upstream(2).await;
        let resp = udp_query(&a_query(), &[up]).await;
        assert!(resp.is_some(), "丢首包后应靠重传拿到响应");
    }

    #[tokio::test]
    async fn udp_query_second_upstream_failover() {
        // 上游 A 永不回 (127.0.0.1:1 通常无监听/被拒), 上游 B 立即回 → 并行发应从 B 拿到。
        let dead: SocketAddr = "127.0.0.1:1".parse().unwrap();
        let alive = fake_upstream(1).await;
        let resp = udp_query(&a_query(), &[dead, alive]).await;
        assert!(resp.is_some(), "首上游死时应由第二上游兜底");
    }

    #[tokio::test]
    async fn udp_query_all_dead_returns_none() {
        // 所有上游都不回 → 3 轮重传后返回 None (不挂死)。
        let dead: SocketAddr = "127.0.0.1:1".parse().unwrap();
        let resp = udp_query(&a_query(), &[dead]).await;
        assert!(resp.is_none(), "全上游无响应应返回 None");
    }

    #[tokio::test]
    async fn udp_query_empty_upstreams_none() {
        assert!(udp_query(&a_query(), &[]).await.is_none());
    }

    #[test]
    fn parse_dns_upstream_defaults_port_53() {
        use crate::config::parse_dns_upstream as p;
        // 裸 IPv4 → :53
        assert_eq!(p("223.5.5.5").unwrap(), "223.5.5.5:53".parse().unwrap());
        // 显式端口保留
        assert_eq!(p("223.5.5.5:5353").unwrap(), "223.5.5.5:5353".parse().unwrap());
        // 裸 IPv6 → :53
        assert_eq!(p("2001:4860:4860::8888").unwrap(),
                   "[2001:4860:4860::8888]:53".parse().unwrap());
        // 带方括号+端口的 IPv6
        assert_eq!(p("[2001:4860:4860::8888]:53").unwrap(),
                   "[2001:4860:4860::8888]:53".parse().unwrap());
        // 非法
        assert!(p("not-an-ip").is_none());
        assert!(p("").is_none());
    }

    /// 假 TCP DNS 上游: accept 一条, 读 [2B 长度][查询], 回 [2B 长度][查询+QR置位]。
    async fn fake_tcp_upstream() -> SocketAddr {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        tokio::spawn(async move {
            if let Ok((mut s, _)) = l.accept().await {
                let mut lb = [0u8; 2];
                if s.read_exact(&mut lb).await.is_err() { return; }
                let n = u16::from_be_bytes(lb) as usize;
                let mut q = vec![0u8; n];
                if s.read_exact(&mut q).await.is_err() { return; }
                q[2] |= 0x80; // QR=1
                let mut out = (q.len() as u16).to_be_bytes().to_vec();
                out.extend_from_slice(&q);
                let _ = s.write_all(&out).await;
            }
        });
        addr
    }

    #[tokio::test]
    async fn tcp_query_one_happy_path() {
        let up = fake_tcp_upstream().await;
        let resp = tcp_query_one(&a_query(), up).await.expect("TCP 上游应返回响应");
        assert_eq!([resp[0], resp[1]], [a_query()[0], a_query()[1]], "tx_id 回显");
        assert_eq!(resp[2] & 0x80, 0x80, "QR=1");
    }

    #[tokio::test]
    async fn tcp_query_failover_to_second() {
        // 首个上游是死端口 (connect 立刻 ECONNREFUSED) → failover 到活的
        let dead: SocketAddr = "127.0.0.1:1".parse().unwrap();
        let good = fake_tcp_upstream().await;
        let resp = tcp_query(&a_query(), &[dead, good]).await;
        assert!(resp.is_some(), "首个死上游应 failover 到第二个");
    }

    #[tokio::test]
    async fn direct_query_dispatches_by_protocol() {
        use crate::config::DnsProtocol::{Tcp, Udp};
        // 只配 TCP 上游 → 走 tcp 路径
        let tcp_up = fake_tcp_upstream().await;
        assert!(direct_query(&a_query(), &[(tcp_up, Tcp)]).await.is_some(), "纯 TCP 上游");
        // 混配: 死 UDP + 活 TCP → 竞速取活的 (UDP 3 轮 2.4s 内 TCP 先回)
        let dead_udp: SocketAddr = "127.0.0.1:1".parse().unwrap();
        let tcp_up2 = fake_tcp_upstream().await;
        assert!(direct_query(&a_query(), &[(dead_udp, Udp), (tcp_up2, Tcp)]).await.is_some(), "混配竞速");
        // 空 → None
        assert!(direct_query(&a_query(), &[]).await.is_none());
    }

    // ── DNS 响应缓存测试 ──
    // x.com A 响应: header(QR=1,an=1) + question + answer(ptr, A, IN, ttl, rdlen=4, ip)
    fn cache_a_response(tx: [u8; 2], ttl: u32) -> Vec<u8> {
        let mut r = vec![tx[0], tx[1], 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0];
        r.push(1); r.push(b'x');
        r.push(3); r.extend_from_slice(b"com");
        r.push(0);
        r.extend_from_slice(&[0, 1, 0, 1]); // A IN
        r.extend_from_slice(&[0xc0, 0x0c, 0, 1, 0, 1]); // ptr, A, IN
        r.extend_from_slice(&ttl.to_be_bytes());
        r.extend_from_slice(&[0, 4, 1, 2, 3, 4]); // rdlen=4, 1.2.3.4
        r
    }
    fn cache_a_query(tx: [u8; 2]) -> Vec<u8> {
        let mut q = vec![tx[0], tx[1], 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
        q.push(1); q.push(b'x');
        q.push(3); q.extend_from_slice(b"com");
        q.push(0);
        q.extend_from_slice(&[0, 1, 0, 1]);
        q
    }

    #[test]
    fn min_ttl_reads_answer() {
        assert_eq!(min_answer_ttl(&cache_a_response([0x12, 0x34], 120)), Some(120));
        // ancount=0 → None
        let mut r = cache_a_response([0, 0], 100);
        r[6] = 0; r[7] = 0;
        assert_eq!(min_answer_ttl(&r), None);
    }

    #[test]
    fn cache_hit_patches_txid_and_question() {
        let cache = DnsCache::new(10);
        cache.put("x.com", 1, &cache_a_response([0xAA, 0xBB], 300));
        let q = cache_a_query([0x99, 0x88]);
        let hit = cache.get("x.com", 1, &q).expect("应命中");
        assert_eq!(&hit[0..2], &[0x99, 0x88], "tx_id 应 patch 成 query 的");
        assert_eq!(hit[2], 0x81, "响应 flags (QR=1) 保留");
        // answer 段仍在 (响应比查询长)
        assert!(hit.len() > q.len(), "命中响应应含 answer 段");
        // 不同 qtype / 域名 → miss
        assert!(cache.get("x.com", 28, &q).is_none(), "不同 qtype miss");
        assert!(cache.get("y.com", 1, &q).is_none(), "不同域名 miss");
    }

    #[test]
    fn cache_skips_no_answer_response() {
        let cache = DnsCache::new(10);
        let mut r = cache_a_response([0, 0], 100);
        r[6] = 0; r[7] = 0; // ancount=0 (NODATA/NXDOMAIN)
        cache.put("x.com", 1, &r);
        assert!(cache.get("x.com", 1, &cache_a_query([1, 2])).is_none(), "无 answer 不缓存");
    }
}
