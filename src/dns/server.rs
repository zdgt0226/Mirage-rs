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
    if end > query.len() || query.len() < 12 { return None; }
    
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

pub struct DnsForwarder {
    socket: Arc<UdpSocket>,
    state: Arc<arc_swap::ArcSwap<crate::config_watcher::CoreState>>,
    fake_ip_mapper: Option<Arc<crate::dns::fake_ip::FakeIpMapper>>,
    xdp_engine: Option<Arc<crate::ebpf::XdpEngine>>,
}

impl DnsForwarder {
    pub async fn start(
        listen_addr: SocketAddr,
        state: Arc<arc_swap::ArcSwap<crate::config_watcher::CoreState>>,
        fake_ip_mapper: Option<Arc<crate::dns::fake_ip::FakeIpMapper>>,
        xdp_engine: Option<Arc<crate::ebpf::XdpEngine>>,
    ) -> anyhow::Result<Arc<Self>> {
        let socket = Arc::new(UdpSocket::bind(listen_addr).await?);
        info!(
            "DNS Forwarder listening on {} (dynamic upstream, fake-ip: {})",
            listen_addr, fake_ip_mapper.is_some()
        );

        let forwarder = Arc::new(Self {
            socket,
            state,
            fake_ip_mapper,
            xdp_engine,
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
        let domain = extract_domain(req)?;
        let qtype = get_qtype(req).unwrap_or(0);
        let _req_port = 53; // DNS
        let st = self.state.load();
        // 用户配了 cn/direct resolver 就用其全部 (尊重配置, 不掺公共 DNS 免污染内网视图);
        // 没配则默认双公共 DNS 兜底 (114 电信/联通 + 223 阿里)。
        let mut cn_dns: Vec<SocketAddr> = Vec::new();
        let mut remote_dns_host = "8.8.8.8".to_string();
        let mut remote_dns_port = 53;

        if let Some(adv) = &st.advanced_dns {
            if !adv.cached_cn_dns.is_empty() { cn_dns = adv.cached_cn_dns.clone(); }
            if let Some(cached) = &adv.cached_remote_host { remote_dns_host = cached.clone(); }
            if let Some(cached) = &adv.cached_remote_port { remote_dns_port = *cached; }
        }
        if cn_dns.is_empty() {
            cn_dns = vec![
                "114.114.114.114:53".parse().unwrap(),
                "223.5.5.5:53".parse().unwrap(),
            ];
        }

        let routing_req = RoutingRequest {
            domain: Some(&domain),
            ip: None,
            port: remote_dns_port,
            protocol: "udp",
            source_ip: None,
            source_mac: None,
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
                    debug!("[DNS] direct  [{}] → 真实解析 via {:?}", domain, cn_dns);
                    udp_query(req, &cn_dns).await
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
                    debug!("[DNS] proxy   [{}] → 隧道查 {}:{} via {}", domain, remote_dns_host, remote_dns_port, n.tag());
                    self.tcp_over_tunnel(req, &pool, &remote_dns_host, remote_dns_port).await.unwrap_or_else(|| make_nxdomain(req)).into()
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
}
