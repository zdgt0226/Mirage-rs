use tokio::net::TcpStream;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tracing::{debug, error};
use std::sync::Arc;
use crate::config_watcher::CoreState;
use arc_swap::ArcSwap;

pub async fn handle_client(
    mut stream: TcpStream,
    state: Arc<ArcSwap<CoreState>>,
    ebpf_engine: Option<Arc<tokio::sync::Mutex<crate::ebpf::EbpfEngine>>>,
    fake_ip_mapper: Option<Arc<crate::dns::fake_ip::FakeIpMapper>>,
) {
    let mut buf = [0u8; 1];
    
    // Peek 1 byte to determine protocol
    let peek_len = match stream.peek(&mut buf).await {
        Ok(n) => n,
        Err(e) => {
            error!("Mixed inbound peek failed: {}", e);
            return;
        }
    };

    if peek_len == 0 {
        return;
    }

    if buf[0] == 0x05 {
        // SOCKS5
        debug!("Mixed inbound sniffed SOCKS5");
        crate::proxy::handler::handle_client(stream, state, ebpf_engine, fake_ip_mapper).await;
    } else {
        // HTTP
        debug!("Mixed inbound sniffed HTTP (first byte: {})", buf[0]);
        
        let mut header_buf = Vec::new();
        let mut temp = [0u8; 1024];

        loop {
            match stream.read(&mut temp).await {
                Ok(0) => return,
                Ok(n) => {
                    header_buf.extend_from_slice(&temp[..n]);
                    if header_buf.windows(4).any(|w| w == b"\r\n\r\n") {
                        break;
                    }
                    if header_buf.len() > 8192 { return; } // Too large
                }
                Err(_) => return,
            }
        }

        // 精确按 \r\n\r\n 切出 header 段与被同包多读进来的 body/ClientHello,
        // 只对 header 段做 lossy (纯 ASCII 安全), body 原始字节零破坏。
        let hdr_end = match header_buf.windows(4).position(|w| w == b"\r\n\r\n") {
            Some(p) => p + 4,
            None => return,
        };
        let body_extra = header_buf[hdr_end..].to_vec();
        let header_str = String::from_utf8_lossy(&header_buf[..hdr_end]);
        let mut lines = header_str.lines();
        let first_line = match lines.next() {
            Some(l) => l,
            None => return,
        };

        let parts: Vec<&str> = first_line.split_whitespace().collect();
        if parts.len() < 3 { return; }

        let method = parts[0];
        let uri = parts[1];

        let target;
        let mut initial_payload = None;
        let is_connect = method == "CONNECT";

        if is_connect {
            target = uri.to_string();
            // CONNECT 后若客户端同包带了 TLS ClientHello (\r\n\r\n 之后), 原样作首包转发, 别丢。
            if !body_extra.is_empty() {
                initial_payload = Some(body_extra);
            }
        } else {
            if uri.starts_with("http://") {
                let without_scheme = &uri[7..];
                let host_end = without_scheme.find('/').unwrap_or(without_scheme.len());
                let host_part = &without_scheme[..host_end];
                
                let actual_host = match host_part.rfind('@') {
                    Some(at_idx) => &host_part[at_idx + 1..],
                    None => host_part,
                };
                
                if actual_host.contains(':') {
                    target = actual_host.to_string();
                } else {
                    target = format!("{}:80", actual_host);
                }
                
                let new_uri = if host_end == without_scheme.len() { "/" } else { &without_scheme[host_end..] };
                let new_first_line = format!("{} {} {}", method, new_uri, parts[2]);
                
                let mut new_req = new_first_line.into_bytes();
                new_req.extend_from_slice(b"\r\n");
                // 首行之后的一切 (剩余 header + 可能的二进制 body) 原样拼接, 不经 lossy 破坏。
                let fl_end = header_buf
                    .windows(2)
                    .position(|w| w == b"\r\n")
                    .map(|p| p + 2)
                    .unwrap_or(hdr_end);
                new_req.extend_from_slice(&header_buf[fl_end..]);
                initial_payload = Some(new_req);
            } else {
                let mut host = None;
                for line in lines {
                    if line.trim().is_empty() {
                        break;
                    }
                    if let Some((k, v)) = line.split_once(':') {
                        if k.eq_ignore_ascii_case("host") {
                            host = Some(v.trim().to_string());
                            break;
                        }
                    }
                }
                let host = match host {
                    Some(h) => h,
                    None => return,
                };
                if host.contains(':') {
                    target = host;
                } else {
                    target = format!("{}:80", host);
                }
                initial_payload = Some(header_buf.clone());
            }
        }

        if is_connect {
            if stream.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n").await.is_err() {
                return;
            }
        }

        crate::proxy::handler::proxy_tcp_target(
            stream,
            target,
            initial_payload.unwrap_or_default(),
            state,
            ebpf_engine,
            fake_ip_mapper
        ).await;
    }
}
