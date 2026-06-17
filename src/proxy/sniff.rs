use tokio::net::TcpStream;
use tracing::debug;

/**
 * [协议嗅探核心]
 * 窥探流的首个 KB 数据，尝试提取 TLS ClientHello 中的 SNI 或者 HTTP 的 Host 头。
 * 注意，窥探必须使用 peek，不能消费（读走）数据，以免破坏代理后的握手流程。
 */
pub async fn sniff_first_kb(stream: &TcpStream) -> Option<String> {
    let mut buf = [0u8; 1024];
    
    // 使用 peek 查看数据，不从流中移除它，并加上 2 秒超时防止慢速 DoS 攻击
    let n = match tokio::time::timeout(std::time::Duration::from_secs(2), stream.peek(&mut buf)).await {
        Ok(Ok(n)) if n > 0 => n,
        _ => return None,
    };
    
    let data = &buf[..n];

    // 1. 尝试解析 TLS 1.2/1.3 ClientHello -> SNI
    if data[0] == 0x16 && data.len() > 5 {
        return parse_tls_sni(data);
    }

    // 2. 尝试解析 HTTP/1.x -> Host header
    if data.starts_with(b"GET ") || data.starts_with(b"POST ") ||
       data.starts_with(b"CONNECT ") || data.starts_with(b"PUT ") ||
       data.starts_with(b"HEAD ") || data.starts_with(b"OPTIONS ") {
        return parse_http_host(data);
    }

    None
}

/// 解析 TLS ClientHello 以提取 SNI (Server Name Indication)
fn parse_tls_sni(data: &[u8]) -> Option<String> {
    // 这个解析非常基础，跳过了 Record Header (5) + Handshake Header (4) + ClientHello 版本等
    // 为了防止数组越界，我们用非常保守的截断。
    if data.len() < 43 { return None; }
    
    // 检查 Handshake Type = 1 (ClientHello)
    if data[5] != 0x01 { return None; }
    
    let session_id_len = data[43] as usize;
    let mut offset = 44 + session_id_len;
    
    if offset + 2 > data.len() { return None; }
    let cipher_suites_len = ((data[offset] as usize) << 8) | (data[offset + 1] as usize);
    offset += 2 + cipher_suites_len;
    
    if offset + 1 > data.len() { return None; }
    let compression_methods_len = data[offset] as usize;
    offset += 1 + compression_methods_len;
    
    if offset + 2 > data.len() { return None; }
    let ext_total_len = ((data[offset] as usize) << 8) | (data[offset + 1] as usize);
    offset += 2;
    
    let ext_end = offset + ext_total_len;
    if ext_end > data.len() { return None; }
    
    // 遍历 Extensions
    while offset + 4 <= ext_end {
        let ext_type = ((data[offset] as usize) << 8) | (data[offset + 1] as usize);
        let ext_len = ((data[offset + 2] as usize) << 8) | (data[offset + 3] as usize);
        offset += 4;
        
        // SNI Extension Type = 0
        if ext_type == 0 {
            if offset + 2 > ext_end { return None; }
            let _list_len = ((data[offset] as usize) << 8) | (data[offset + 1] as usize);
            offset += 2;
            
            if offset + 3 > ext_end { return None; }
            let name_type = data[offset];
            let name_len = ((data[offset + 1] as usize) << 8) | (data[offset + 2] as usize);
            offset += 3;
            
            if name_type == 0 && offset + name_len <= ext_end {
                let name_bytes = &data[offset..offset + name_len];
                if let Ok(s) = std::str::from_utf8(name_bytes) {
                    debug!("Sniffed TLS SNI: {}", s);
                    return Some(s.to_string());
                }
            }
            break;
        }
        offset += ext_len;
    }
    None
}

/// 解析 HTTP 请求头以提取 Host
fn parse_http_host(data: &[u8]) -> Option<String> {
    if let Ok(text) = std::str::from_utf8(data) {
        for line in text.lines() {
            if line.trim().is_empty() { break; } // Header end
            if line.to_lowercase().starts_with("host:") {
                let host = line[5..].trim().to_string();
                // 剔除可能的端口号
                let host_only = host.split(':').next().unwrap_or(&host).to_string();
                debug!("Sniffed HTTP Host: {}", host_only);
                return Some(host_only);
            }
        }
    }
    None
}
