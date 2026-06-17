use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::time::timeout;
use tracing::{debug, error, info};

use crate::proxy::pool::WarmPool;
use crate::proxy::outbound::OutboundNode;
use crate::router::RoutingRequest;

const UDP_TIMEOUT: Duration = Duration::from_secs(5);
const TCP_TIMEOUT: Duration = Duration::from_secs(5);

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
    
    // Answer: Name pointer (0xc00c), Type A (1), Class IN (1), TTL (1), RDLength (4), RData (ip)
    result.extend_from_slice(&[0xC0, 0x0C, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x04]);
    result.extend_from_slice(&ip.octets());
    
    Some(result)
}

fn make_empty_response(query: &[u8]) -> Option<Vec<u8>> {
    let end = question_end(query);
    if end > query.len() || query.len() < 12 { return None; }
    
    let mut header = query[..12].to_vec();
    header[2] |= 0x80; // QR=1
    header[3] &= 0x0F; // No error
    
    header[6] = 0; header[7] = 0;
    header[8] = 0; header[9] = 0;
    header[10] = 0; header[11] = 0;
    
    let mut result = header;
    result.extend_from_slice(&query[12..end]);
    Some(result)
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
        let mut cn_dns: SocketAddr = "114.114.114.114:53".parse().unwrap();
        let mut remote_dns_host = "8.8.8.8".to_string();
        let mut remote_dns_port = 53;
        
        if let Some(adv) = &st.advanced_dns {
            if let Some(cached) = &adv.cached_cn_dns { cn_dns = *cached; }
            if let Some(cached) = &adv.cached_remote_host { remote_dns_host = cached.clone(); }
            if let Some(cached) = &adv.cached_remote_port { remote_dns_port = *cached; }
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
        if let Some(n) = node {
            match &*n {
                OutboundNode::Block { .. } => {
                    debug!("DNS block   {}", domain);
                    Some(make_nxdomain(req))
                }
                OutboundNode::Direct { .. } => {
                    debug!("DNS direct  {} -> {}", domain, cn_dns);
                    self.udp_query(req, cn_dns).await
                }
                OutboundNode::Pyreality { pool, .. } => {
                    if let Some(mapper) = &self.fake_ip_mapper {
                        if qtype == 1 { // A
                            let fake_ip = mapper.lookup_or_assign(&domain);
                            debug!("DNS Fake-IP {} -> {}", domain, fake_ip);
                            if let Some(engine) = &self.xdp_engine {
                                let _ = engine.update_dns_cache(&domain, fake_ip);
                            }
                            return make_fake_ip_response(req, fake_ip);
                        } else if qtype == 28 { // AAAA
                            debug!("DNS Fake-IP {} -> AAAA empty", domain);
                            return make_empty_response(req);
                        }
                    }
                    debug!("DNS proxy {} -> {}:{} via {}", domain, remote_dns_host, remote_dns_port, n.tag());
                    self.tcp_over_tunnel(req, &pool, &remote_dns_host, remote_dns_port).await.unwrap_or_else(|| make_nxdomain(req)).into()
                }
                _ => Some(make_nxdomain(req)),
            }
        } else {
            Some(make_nxdomain(req))
        }
    }

    async fn udp_query(&self, req: &[u8], addr: SocketAddr) -> Option<Vec<u8>> {
        let sock = UdpSocket::bind("0.0.0.0:0").await.ok()?;
        sock.send_to(req, addr).await.ok()?;
        
        let mut buf = vec![0u8; 1500];
        match timeout(UDP_TIMEOUT, sock.recv_from(&mut buf)).await {
            Ok(Ok((size, _))) => Some(buf[..size].to_vec()),
            _ => None,
        }
    }

    async fn tcp_over_tunnel(&self, req: &[u8], pool: &WarmPool, remote_host: &str, remote_port: u16) -> Option<Vec<u8>> {
        let mut tunnel = pool.get().await;
        
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
