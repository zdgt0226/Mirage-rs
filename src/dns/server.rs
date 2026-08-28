use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::time::timeout;
use tracing::{debug, error, info, warn};

use crate::proxy::pool::WarmPool;
use crate::proxy::outbound::OutboundNode;
use crate::router::RoutingRequest;

const TCP_TIMEOUT: Duration = Duration::from_secs(5);
/// DNS 上游查询重传轮数。每轮向所有上游各发一份, 无匹配响应则重传。
const DNS_QUERY_ROUNDS: u32 = 3;
/// 每轮等待上限。上游正常时响应几十毫秒即返回, 这只是丢包后重传前的最大等待。
/// 3 × 800ms = 2.4s 总上限, 远低于 Windows DNS 客户端 ~11s 重传超时。
const DNS_RETRANSMIT_INTERVAL: Duration = Duration::from_millis(800);
/// TCP 上游查询超时: 既是单个 tcp_query_one 的上限, 也是 tcp_query 并行竞速的整体上限。
/// 3s 宽于正常 TCP DNS 往返; 并行竞速故总延迟与上游数无关 (不像顺序 failover 会堆叠)。
const DNS_TCP_TIMEOUT: Duration = Duration::from_secs(3);
// 隧道 DNS 响应重组的总时限: 逐帧各 TCP_TIMEOUT 时最坏 5s×64 帧, 恶意对端可拖住任务, 用整体封顶。
const DNS_TUNNEL_REASSEMBLE_TIMEOUT: Duration = Duration::from_secs(10);

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

/// 从 DNS 响应里取**首个 A 记录**的 IPv4 (供 auto_classify 判归属)。无 A / 越界 → None。
fn first_a_record(resp: &[u8]) -> Option<std::net::Ipv4Addr> {
    if resp.len() < 12 {
        return None;
    }
    let ancount = u16::from_be_bytes([resp[6], resp[7]]) as usize;
    let mut pos = question_end(resp);
    for _ in 0..ancount {
        // 跳过 answer 的 name (0xC0 压缩指针 2 字节, 或 label 序列到 0x00)
        while pos < resp.len() {
            let n = resp[pos] as usize;
            if n == 0 {
                pos += 1;
                break;
            }
            if n & 0xC0 == 0xC0 {
                pos += 2;
                break;
            }
            pos += 1 + n;
        }
        if pos + 10 > resp.len() {
            return None;
        }
        let rtype = u16::from_be_bytes([resp[pos], resp[pos + 1]]);
        let rdlen = u16::from_be_bytes([resp[pos + 8], resp[pos + 9]]) as usize;
        let rdata = pos + 10;
        if rdata + rdlen > resp.len() {
            return None;
        }
        if rtype == 1 && rdlen == 4 {
            return Some(std::net::Ipv4Addr::new(
                resp[rdata], resp[rdata + 1], resp[rdata + 2], resp[rdata + 3],
            ));
        }
        pos = rdata + rdlen;
    }
    None
}

/// 未分类域名的自适应分类状态: CN 段集 (判 IP 归属) + 学习到的"海外"域名 TTL 缓存。
/// 见 config::AutoClassifyConfig。构造经 `from_config` (geoip cn 段为空则返 None = 禁用)。
pub struct AutoClassify {
    ttl: std::time::Duration,
    cn_cidrs: Vec<ipnet::IpNet>,
    foreign: std::sync::Mutex<ForeignCache>,
    /// 国内判 CN 时后台隧道交叉校验 (非阻塞, 污染则标记海外供下次)。
    verify_async: bool,
}

struct ForeignCache {
    map: std::collections::HashMap<String, std::time::Instant>, // domain(小写) → 过期时刻
    cap: usize,
}

impl AutoClassify {
    /// 从配置构造。auto_classify.enabled 且 geoip.dat 的 cn 段非空才返 Some; 否则 None (禁用)。
    pub(crate) fn from_config(
        advanced_dns: Option<&crate::config::AdvancedDnsConfig>,
        tuning: Option<&crate::config::TuningConfig>,
        geodata_dir: &str,
    ) -> Option<std::sync::Arc<Self>> {
        let ac = advanced_dns?.auto_classify.as_ref()?;
        if !ac.enabled {
            return None;
        }
        // geoip.dat 路径: geodata_dir + geo_sources 里 kind=geoip 的 name (默认 geoip)
        let name = tuning
            .and_then(|t| t.geo_sources.iter().find(|s| s.kind == crate::config::GeoKind::Geoip))
            .map(|s| s.name.as_str())
            .unwrap_or("geoip");
        let path = std::path::Path::new(geodata_dir).join(format!("{name}.dat"));
        match crate::router::geo::load_geoip_dat(&path, "cn") {
            Ok(cn) if !cn.is_empty() => {
                info!(
                    "auto_classify 启用: 载入 CN 段 {} 条 (ttl {}s, cap {})",
                    cn.len(),
                    ac.ttl,
                    ac.max_entries
                );
                Some(std::sync::Arc::new(Self {
                    ttl: std::time::Duration::from_secs(ac.ttl),
                    cn_cidrs: cn,
                    foreign: std::sync::Mutex::new(ForeignCache {
                        map: std::collections::HashMap::new(),
                        cap: ac.max_entries.max(1),
                    }),
                    verify_async: ac.verify_cn == crate::config::VerifyCn::Async,
                }))
            }
            Ok(_) => {
                warn!("auto_classify 开启但 geoip.dat 的 cn 段为空 ({}) — 已禁用", path.display());
                None
            }
            Err(e) => {
                warn!("auto_classify 开启但读 geoip cn 段失败 ({}): {} — 已禁用", path.display(), e);
                None
            }
        }
    }

    /// IP 是否属 CN (在 geoip cn 段内)。cn_cidrs 恒非空 (构造保证)。
    fn is_cn(&self, ip: std::net::IpAddr) -> bool {
        self.cn_cidrs.iter().any(|c| c.contains(&ip))
    }

    /// 域名是否已学习为海外且未过 TTL (过期条目顺手清掉)。
    fn is_foreign_cached(&self, domain: &str) -> bool {
        let mut g = self.foreign.lock().unwrap_or_else(|e| e.into_inner());
        match g.map.get(domain) {
            Some(&exp) if exp > std::time::Instant::now() => true,
            Some(_) => {
                g.map.remove(domain);
                false
            }
            None => false,
        }
    }

    /// 学习标记域名为海外 (带 TTL)。超容量先清过期, 仍满则移除任意一条 (软上限)。
    fn mark_foreign(&self, domain: &str) {
        let now = std::time::Instant::now();
        let mut g = self.foreign.lock().unwrap_or_else(|e| e.into_inner());
        if g.map.len() >= g.cap {
            g.map.retain(|_, exp| *exp > now);
            if g.map.len() >= g.cap {
                if let Some(k) = g.map.keys().next().cloned() {
                    g.map.remove(&k);
                }
            }
        }
        g.map.insert(domain.to_string(), now + self.ttl);
    }
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

/// 隧道目标头: [2B len][host:port 字符串]。必须与服务端 control.rs TCP 分派 / outbound.rs::connect
/// 解析一致。历史上此处曾发 SOCKS5 ATYP 头, 服务端把 ATYP 首字节当 target_len 高位 →
/// first_chunk too short 丢弃 → 隧道 DNS 全静默失败 (无测试覆盖)。本 helper + 单测锁死格式。
fn tunnel_target_header(host: &str, port: u16) -> Vec<u8> {
    let target = format!("{host}:{port}");
    let mut buf = Vec::with_capacity(2 + target.len());
    buf.extend_from_slice(&(target.len() as u16).to_be_bytes());
    buf.extend_from_slice(target.as_bytes());
    buf
}

/// 隧道 DNS 响应重组状态: 从累积字节按 TCP-DNS 帧 `[2B len][报文体]` 判定。抽成纯函数便于
/// 单测覆盖各分支 (前缀单独成帧 / 跨帧大响应 / len 非法 / 超上限), 免逐帧逻辑只有代码审查兜底。
#[derive(Debug, PartialEq)]
enum Reassembled {
    Need,        // 还需更多帧
    Done(usize), // 报文体完整, 长度 = usize (报文体在 acc[2..2+len])
    Malformed,   // len 不合理 / 超上限
}

fn reassemble_tcp_dns(acc: &[u8]) -> Reassembled {
    if acc.len() < 2 {
        return Reassembled::Need;
    }
    let want = u16::from_be_bytes([acc[0], acc[1]]) as usize;
    if want < 12 {
        return Reassembled::Malformed; // DNS 报文至少 12B 报头, 更短不合理
    }
    if acc.len() >= 2 + want {
        return Reassembled::Done(want);
    }
    if acc.len() > 2 + u16::MAX as usize {
        return Reassembled::Malformed; // 理论不可达
    }
    Reassembled::Need
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
///
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

/// TCP 上游解析: **并行竞速**所有上游, 首个成功即返回。整体 DNS_TCP_TIMEOUT 封顶。
/// 不用顺序 failover: 一个 SYN 被黑洞 (非 RST) 的上游会占满自身 3s 超时, 顺序试 N 个
/// 就堆到 3s×N, 远超 UDP 路径固定 2.4s。并行则总延迟 = min(最快成功, 3s), 与上游数无关。
async fn tcp_query(req: &[u8], upstreams: &[SocketAddr]) -> Option<Vec<u8>> {
    if upstreams.is_empty() {
        return None;
    }
    let mut set = tokio::task::JoinSet::new();
    for up in upstreams {
        let up = *up;
        let req = req.to_vec(); // 'static: 每个任务拿一份查询字节
        set.spawn(async move { tcp_query_one(&req, up).await });
    }
    // 首个 Some 即返回 (JoinSet drop 时中止其余任务, 关掉悬挂连接)。
    let race = async {
        while let Some(res) = set.join_next().await {
            if let Ok(Some(resp)) = res {
                return Some(resp);
            }
        }
        None
    };
    tokio::time::timeout(DNS_TCP_TIMEOUT, race).await.ok().flatten()
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

    /// 返回 fakeip 应答 (auto_classify 判为海外时用): A → fake-IP, AAAA/HTTPS → 空答复。
    /// 未配 fakeip mapper 则退空答复 (auto_classify 无法代理, 但也不泄露真实 IP)。
    fn answer_fakeip(&self, req: &[u8], domain: &str, qtype: u16) -> Option<Vec<u8>> {
        if let Some(mapper) = &self.fake_ip_mapper {
            if qtype == 1 {
                let fake_ip = mapper.lookup_or_assign(domain);
                if let Some(engine) = &self.xdp_engine {
                    let _ = engine.update_dns_cache(domain, fake_ip);
                }
                return make_fake_ip_response(req, fake_ip);
            }
            if qtype == 28 || qtype == 65 {
                return make_empty_response(req);
            }
        }
        make_empty_response(req).or_else(|| Some(make_nxdomain(req)))
    }

    /// 后台 (非阻塞) 交叉校验: 经隧道可信解析 `query` 的域名; 若首个 A 判为**海外** (即国内那次
    /// 判 CN 是污染) → `mark_foreign`, 下次该域名走 fakeip。leaf 非 Mirage / 隧道失败 → 静默不动。
    fn spawn_cn_verify(
        leaf: Arc<crate::proxy::outbound::OutboundNode>,
        ac: Arc<AutoClassify>,
        domain: String,
        query: Vec<u8>,
        host: String,
        port: u16,
    ) {
        tokio::spawn(async move {
            if let crate::proxy::outbound::OutboundNode::Mirage { pool, .. } = &*leaf {
                if let Some(resp) = Self::dns_over_tunnel(&query, pool, &host, port).await {
                    if let Some(ip) = first_a_record(&resp) {
                        if !ac.is_cn(ip.into()) {
                            debug!("[DNS] auto-verify [{}] 国内判CN但可信判海外 {} → 疑污染, 标记海外", domain, ip);
                            ac.mark_foreign(&domain);
                        }
                    }
                }
            }
        });
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
            // 故意 None: 按**源设备/网段分流 DNS 查询** (每主机 DNS 策略) 尚未实现, 非疏漏。
            // 要做时把 run_loop `recv_from` 拿到的 `from` 一路传进 process_query 填这里即可
            // (成本极低)。填了会让 source_ip_cidr 规则开始作用于 DNS 解析路由 —— 属行为新增,
            // 需明确是想要的产品行为再开。见 [[source-ip-routing]]。
            source_ip: None,
            source_mac: None,
            inbound: Some(&self.inbound_tag),
            process_name: None, // DNS 查询: 无本机进程名维度
        };

        let matched = st.router.route_matched(&routing_req);

        // 未命中任何显式规则 + auto_classify 开 → 按解析 IP 归属自适应分类 (见 AutoClassify)。
        if matched.is_none() {
            if let Some(ac) = st.auto_classify.clone() {
                // 后台交叉校验 (verify_async) 需一条隧道: 抓 default 出站解析出的叶子 (drop(st) 前)。
                let verify_leaf = if ac.verify_async {
                    st.outbounds.get(st.router.default_outbound()).map(|n| n.resolve_leaf())
                } else {
                    None
                };
                drop(st);
                let dk = domain.to_lowercase();
                let known_foreign = ac.is_foreign_cached(&dk);
                if !known_foreign && qtype == 1 {
                    // A 查询: 国内解析探首个 A 归属 (先查 DNS cache 省一次上游)
                    if let Some(cache) = &self.cache {
                        if let Some(hit) = cache.get(&dk, qtype, req) {
                            debug!("[DNS] auto    [{}] → cache hit", domain);
                            return Some(hit);
                        }
                    }
                    let probe = direct_query(req, &cn_dns).await;
                    match probe.as_deref().and_then(first_a_record) {
                        Some(ip) if ac.is_cn(ip.into()) => {
                            debug!("[DNS] auto    [{}] → 首个A {} 属CN → 直连返回", domain, ip);
                            if let (Some(cache), Some(r)) = (&self.cache, &probe) {
                                cache.put(&dk, qtype, r);
                            }
                            // 非阻塞交叉校验: 国内判 CN, 后台经隧道可信解析确认; 可信判海外 → 疑污染,
                            // 标记海外供**下次** (本次已返回, 不受保护 —— 非阻塞的固有取舍)。
                            // 仅 DNS cache 开时才校验: cache 开则同域名每 TTL 只探测一次 (spawn 天然
                            // 有界); cache 关会每次查询都重探测, 再逐次 spawn 隧道会刷爆 WarmPool。
                            if let (Some(leaf), true) = (verify_leaf, self.cache.is_some()) {
                                Self::spawn_cn_verify(
                                    leaf, ac.clone(), dk.clone(), req.to_vec(),
                                    remote_dns_host.clone(), remote_dns_port,
                                );
                            }
                            return probe;
                        }
                        Some(ip) => {
                            debug!("[DNS] auto    [{}] → 首个A {} 属海外 → 学习标记 + fakeip", domain, ip);
                            ac.mark_foreign(&dk);
                            return self.answer_fakeip(req, &domain, qtype);
                        }
                        None => {
                            debug!("[DNS] auto    [{}] → 无A/解析失败 → 国内结果兜底", domain);
                            return probe.or_else(|| Some(make_nxdomain(req)));
                        }
                    }
                }
                // 已学习海外 (任意 qtype) → fakeip
                if known_foreign {
                    return self.answer_fakeip(req, &domain, qtype);
                }
                // 未分类的非 A 查询: 还没探测。AAAA/HTTPS 回空答复逼客户端用 A (与 fakeip v4-only 一致);
                // 其它类型 (MX/TXT…) 走国内解析兜底。
                if qtype == 28 || qtype == 65 {
                    return make_empty_response(req);
                }
                return direct_query(req, &cn_dns).await.or_else(|| Some(make_nxdomain(req)));
            }
        }

        // 命中规则用其出站; 未命中且 auto_classify 关 → 回落 default_outbound (原行为)。
        let action = matched.unwrap_or_else(|| st.router.default_outbound().to_string());
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
                    let resp = Self::dns_over_tunnel(req, pool, &remote_dns_host, remote_dns_port).await;
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

    /// 经隧道向服务端上游 DNS 发一次查询取应答 (不依赖 self, 供 auto_classify 后台校验复用)。
    async fn dns_over_tunnel(req: &[u8], pool: &WarmPool, remote_host: &str, remote_port: u16) -> Option<Vec<u8>> {
        let mut tunnel = match pool.get().await {
            Ok(t) => t,
            Err(e) => {
                tracing::warn!("DNS over tunnel: pool unavailable for {}:{} ({}). Query will fail.", remote_host, remote_port, e);
                return None;
            }
        };

        // u16 长度守卫 (对齐 outbound.rs): host:port 超 u16::MAX 会静默截断长度字段。DNS 上游
        // 主机名远短于此 (≤253), 实际不可达, 仅防配置怪值 + 与主线一致。
        if remote_host.len() >= u16::MAX as usize { return None; }

        let mut payload = tunnel_target_header(remote_host, remote_port);
        payload.extend_from_slice(&(req.len() as u16).to_be_bytes());
        payload.extend_from_slice(req);

        tunnel.writer.send_data(&payload).await.ok()?;

        // TCP-DNS 响应 = [2B len][报文体]。服务端逐 read 逐帧转发, 上游可能把长度前缀与体分成
        // 两个 TCP 段 → 客户端收到两条加密帧。必须循环 recv_data 重组到 2+len 字节, 别只读一帧:
        // 只读一帧时首帧可能仅含 2B 前缀 → resp[2..] 空 → 空响应; 大响应 (DNSSEC/EDNS) 跨帧同理。
        let deadline = std::time::Instant::now() + DNS_TUNNEL_REASSEMBLE_TIMEOUT;
        let mut acc = Vec::new();
        let mut frames = 0u32;
        let dns_len = loop {
            let remaining = deadline.saturating_duration_since(std::time::Instant::now());
            if remaining.is_zero() { return None; } // 总时限到, 别再逐帧等
            let chunk = timeout(remaining.min(TCP_TIMEOUT), tunnel.reader.recv_data()).await.ok()?.ok()?;
            frames += 1;
            if frames > 64 { return None; } // 防碎片流跑飞
            acc.extend_from_slice(&chunk);
            match reassemble_tcp_dns(&acc) {
                Reassembled::Done(len) => break len,
                Reassembled::Malformed => return None,
                Reassembled::Need => {}
            }
        };

        let mut resp_buf = acc[2..2 + dns_len].to_vec();
        
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

    // 回归: 客户端隧道目标头必须能被服务端**真解析函数**认出 (直接调 control::parse_tcp_target,
    // 非内联复述 —— 改了分派逻辑这测试才会跟着红)。曾用 SOCKS5 ATYP → 服务端把首字节当 target_len
    // 高位 → 丢弃 → 隧道 DNS 全失败。
    #[test]
    fn tunnel_target_header_matches_server_parse() {
        use crate::proxy::mirage_server::parse_tcp_target;
        for (host, port, want) in [
            ("8.8.8.8", 53u16, "8.8.8.8:53"),
            ("dns.google", 53, "dns.google:53"),
        ] {
            let mut hdr = tunnel_target_header(host, port);
            // 追加一段假 piggyback body, 验证服务端 target/payload 切分也对
            hdr.extend_from_slice(&[0xAB, 0xCD]);
            let (target, payload) = parse_tcp_target(&hdr).expect("服务端应能解析客户端目标头");
            assert_eq!(target, want);
            assert_eq!(payload.as_deref(), Some(&[0xAB, 0xCD][..]), "piggyback payload 切分错");
            // ATYP 回归护栏: 首字节不得是 SOCKS5 ATYP IPv4(0x01) 被误当长度高位
            assert_ne!(hdr[0], 0x01, "首字节像 SOCKS5 ATYP IPv4 = 回归");
        }
    }

    // 隧道 DNS 响应重组: 覆盖前缀单独成帧 / 跨帧大响应 / len 非法 / 多余尾字节。
    #[test]
    fn reassemble_tcp_dns_states() {
        // 不足 2B 前缀 → Need
        assert_eq!(reassemble_tcp_dns(&[]), Reassembled::Need);
        assert_eq!(reassemble_tcp_dns(&[0x00]), Reassembled::Need);
        // len<12 → Malformed (DNS 报文至少 12B 报头)
        assert_eq!(reassemble_tcp_dns(&[0x00, 0x00]), Reassembled::Malformed);
        assert_eq!(reassemble_tcp_dns(&[0x00, 0x0B]), Reassembled::Malformed);
        // 前缀单独成帧 (want=12, 体未到) → Need
        assert_eq!(reassemble_tcp_dns(&[0x00, 0x0C]), Reassembled::Need);
        // 跨帧: 前缀 + 部分体 → Need; 补齐 → Done(12)
        let mut acc = vec![0x00, 0x0C];
        acc.extend_from_slice(&[0u8; 5]);
        assert_eq!(reassemble_tcp_dns(&acc), Reassembled::Need);
        acc.extend_from_slice(&[0u8; 7]);
        assert_eq!(reassemble_tcp_dns(&acc), Reassembled::Done(12));
        // 一帧到齐 + 多余尾字节 → Done(12) 精确, 尾字节不计入
        let mut one = vec![0x00, 0x0C];
        one.extend_from_slice(&[0xAA; 12]);
        one.extend_from_slice(&[0xFF, 0xFF]);
        assert_eq!(reassemble_tcp_dns(&one), Reassembled::Done(12));
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
    async fn tcp_query_races_dead_and_live() {
        // 并行竞速: 死端口任务返回 None, 活上游返回 Some → 整体 Some (不被死上游拖住)
        let dead: SocketAddr = "127.0.0.1:1".parse().unwrap();
        let good = fake_tcp_upstream().await;
        let resp = tcp_query(&a_query(), &[dead, good]).await;
        assert!(resp.is_some(), "死+活上游并行竞速应取活的");
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

    #[test]
    fn first_a_record_extracts_first_ipv4() {
        let r = cache_a_response([0, 0], 100); // A 1.2.3.4
        assert_eq!(first_a_record(&r), Some(std::net::Ipv4Addr::new(1, 2, 3, 4)));
        let mut na = cache_a_response([0, 0], 100);
        na[6] = 0; na[7] = 0; // ancount=0
        assert_eq!(first_a_record(&na), None, "无 answer → None");
    }

    fn mk_auto(ttl_ms: u64, cap: usize, cn: &[&str]) -> AutoClassify {
        AutoClassify {
            ttl: std::time::Duration::from_millis(ttl_ms),
            cn_cidrs: cn.iter().map(|c| c.parse().unwrap()).collect(),
            foreign: std::sync::Mutex::new(ForeignCache {
                map: std::collections::HashMap::new(),
                cap,
            }),
            verify_async: false,
        }
    }

    #[test]
    fn verify_cn_config_parses() {
        use crate::config::{AutoClassifyConfig, VerifyCn};
        let off: AutoClassifyConfig =
            serde_json::from_str(r#"{"enabled":true}"#).unwrap();
        assert_eq!(off.verify_cn, VerifyCn::Off, "缺省 off");
        let a: AutoClassifyConfig =
            serde_json::from_str(r#"{"enabled":true,"verify_cn":"async"}"#).unwrap();
        assert_eq!(a.verify_cn, VerifyCn::Async);
        assert!(serde_json::from_str::<AutoClassifyConfig>(r#"{"enabled":true,"verify_cn":"bogus"}"#).is_err(), "非法值拒绝");
    }

    #[test]
    fn auto_classify_is_cn() {
        let ac = mk_auto(1000, 8, &["1.2.3.0/24"]);
        assert!(ac.is_cn("1.2.3.9".parse().unwrap()));
        assert!(!ac.is_cn("8.8.8.8".parse().unwrap()));
    }

    #[test]
    fn auto_classify_foreign_cache_ttl() {
        let ac = mk_auto(60, 8, &["1.2.3.0/24"]);
        assert!(!ac.is_foreign_cached("x.com"));
        ac.mark_foreign("x.com");
        assert!(ac.is_foreign_cached("x.com"), "刚标记应命中");
        std::thread::sleep(std::time::Duration::from_millis(90));
        assert!(!ac.is_foreign_cached("x.com"), "过 TTL 应失效");
    }

    #[test]
    fn auto_classify_cache_cap_bounded() {
        let ac = mk_auto(60_000, 3, &["1.0.0.0/8"]);
        for i in 0..20 {
            ac.mark_foreign(&format!("d{i}.com"));
        }
        assert!(ac.foreign.lock().unwrap().map.len() <= 3, "容量应封顶 (软上限)");
    }
}
