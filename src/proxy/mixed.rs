use tokio::net::TcpStream;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tracing::{debug, error};
use std::sync::Arc;
use crate::config_watcher::CoreState;
use arc_swap::ArcSwap;

/// 解 base64 (标准字母表, 容忍尾部 '='), 失败返回 None。
/// 只为 HTTP `Proxy-Authorization: Basic` 一处需要, 手写 ~20 行免得为此引入依赖。
fn b64_decode(s: &str) -> Option<Vec<u8>> {
    fn val(c: u8) -> Option<u8> {
        match c {
            b'A'..=b'Z' => Some(c - b'A'),
            b'a'..=b'z' => Some(c - b'a' + 26),
            b'0'..=b'9' => Some(c - b'0' + 52),
            b'+' => Some(62),
            b'/' => Some(63),
            _ => None,
        }
    }
    let src: Vec<u8> = s.bytes().filter(|b| !b.is_ascii_whitespace() && *b != b'=').collect();
    let mut out = Vec::with_capacity(src.len() * 3 / 4);
    for chunk in src.chunks(4) {
        if chunk.len() < 2 {
            return None; // 单字符尾块非法
        }
        let mut acc = 0u32;
        for (i, &c) in chunk.iter().enumerate() {
            acc |= (val(c)? as u32) << (18 - 6 * i);
        }
        out.push((acc >> 16) as u8);
        if chunk.len() >= 3 {
            out.push((acc >> 8) as u8);
        }
        if chunk.len() == 4 {
            out.push(acc as u8);
        }
    }
    Some(out)
}

/// 从 header 段找 `Proxy-Authorization: Basic <b64>` 并校验。
/// header 名大小写不敏感 (RFC 7230)。
fn http_auth_ok(header_str: &str, cred: &crate::config::InboundAuth) -> bool {
    for line in header_str.lines() {
        let Some((name, value)) = line.split_once(':') else { continue };
        if !name.trim().eq_ignore_ascii_case("proxy-authorization") {
            continue;
        }
        let value = value.trim();
        let Some(b64) = value.strip_prefix("Basic ").or_else(|| value.strip_prefix("basic ")) else {
            continue;
        };
        let Some(raw) = b64_decode(b64.trim()) else { continue };
        // 只按**第一个**冒号切分: 密码里允许含冒号。
        let Some(pos) = raw.iter().position(|&b| b == b':') else { continue };
        if cred.verify(&raw[..pos], &raw[pos + 1..]) {
            return true;
        }
    }
    false
}

pub async fn handle_client(
    mut stream: TcpStream,
    state: Arc<ArcSwap<CoreState>>,
    ebpf_engine: Option<Arc<tokio::sync::Mutex<crate::ebpf::EbpfEngine>>>,
    fake_ip_mapper: Option<Arc<crate::dns::fake_ip::FakeIpMapper>>,
    auth: Option<Arc<crate::config::InboundAuth>>,
    inbound_tag: Option<Arc<str>>,
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
        // SOCKS5 (鉴权在 socks5::handshake 里按 RFC 1929 做)
        debug!("Mixed inbound sniffed SOCKS5");
        crate::proxy::handler::handle_client(stream, state, ebpf_engine, fake_ip_mapper, auth, inbound_tag).await;
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

        // HTTP 代理鉴权 (配了 auth 才检查)。未通过 → 407 + Proxy-Authenticate, 让浏览器/
        // curl 能弹凭据重试; 不能静默断开, 否则客户端只看到连接被重置无从判断。
        if let Some(cred) = auth.as_deref() {
            if !http_auth_ok(&header_str, cred) {
                debug!("Mixed inbound HTTP: proxy auth required/failed");
                let _ = stream
                    .write_all(
                        b"HTTP/1.1 407 Proxy Authentication Required\r\n\
                          Proxy-Authenticate: Basic realm=\"mirage\"\r\n\
                          Content-Length: 0\r\n\
                          Connection: close\r\n\r\n",
                    )
                    .await;
                return;
            }
        }

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
            fake_ip_mapper,
            inbound_tag,
        ).await;
    }
}

#[cfg(test)]
mod auth_tests {
    use super::{b64_decode, http_auth_ok};
    use crate::config::InboundAuth;

    fn cred(u: &str, p: &str) -> InboundAuth {
        InboundAuth { username: u.into(), password: p.into() }
    }

    #[test]
    fn b64_known_vectors() {
        assert_eq!(b64_decode("YWxhZGRpbjpvcGVuc2VzYW1l").unwrap(), b"aladdin:opensesame");
        assert_eq!(b64_decode("YQ==").unwrap(), b"a");       // 2 字符尾块
        assert_eq!(b64_decode("YWI=").unwrap(), b"ab");      // 3 字符尾块
        assert_eq!(b64_decode("YWJj").unwrap(), b"abc");     // 满块
        assert_eq!(b64_decode("").unwrap(), b"");
        assert!(b64_decode("!!!!").is_none());               // 非法字符
    }

    #[test]
    fn accepts_valid_basic() {
        // "u:p" → dTpw
        let h = "CONNECT x:443 HTTP/1.1\r\nProxy-Authorization: Basic dTpw\r\n\r\n";
        assert!(http_auth_ok(h, &cred("u", "p")));
    }

    #[test]
    fn rejects_wrong_or_missing() {
        let good = "CONNECT x:443 HTTP/1.1\r\nProxy-Authorization: Basic dTpw\r\n\r\n";
        assert!(!http_auth_ok(good, &cred("u", "WRONG")), "密码错应拒");
        assert!(!http_auth_ok(good, &cred("WRONG", "p")), "用户名错应拒");
        assert!(!http_auth_ok("CONNECT x:443 HTTP/1.1\r\n\r\n", &cred("u", "p")), "缺头应拒");
        // 用 Authorization 而非 Proxy-Authorization 不算数
        let wrong_header = "CONNECT x:443 HTTP/1.1\r\nAuthorization: Basic dTpw\r\n\r\n";
        assert!(!http_auth_ok(wrong_header, &cred("u", "p")));
    }

    #[test]
    fn header_name_case_insensitive() {
        // RFC 7230: header 名大小写不敏感
        let h = "CONNECT x:443 HTTP/1.1\r\nPROXY-AUTHORIZATION: Basic dTpw\r\n\r\n";
        assert!(http_auth_ok(h, &cred("u", "p")));
    }

    #[test]
    fn password_may_contain_colon() {
        // "u:a:b" → dTphOmI= ; 只按第一个冒号切分
        let h = "CONNECT x:443 HTTP/1.1\r\nProxy-Authorization: Basic dTphOmI=\r\n\r\n";
        assert!(http_auth_ok(h, &cred("u", "a:b")));
    }
}
