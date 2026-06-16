use std::sync::atomic::{AtomicI64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::time::timeout;
use tracing::{debug, info, warn};

// 全局时钟偏移 (秒)：ServerTime = LocalTime + TIME_OFFSET
static TIME_OFFSET: AtomicI64 = AtomicI64::new(0);

const NTP_EPOCH_OFFSET: u64 = 2_208_988_800; // 1900-01-01 to 1970-01-01

/// 获取经过校正的当前 Unix 秒时间戳
pub fn now_sec() -> u64 {
    let local = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let offset = TIME_OFFSET.load(Ordering::Relaxed);
    (local + offset) as u64
}

/// 启动后台校时循环
pub async fn start_time_sync(server_host: String) {
    tokio::spawn(async move {
        // 启动时立刻执行一次强制同步（阻塞直到成功或兜底）
        let mut first = true;
        loop {
            let success = sync_once(&server_host).await;
            if success {
                if first {
                    first = false;
                    info!("Initial time sync completed.");
                }
                // 成功后，1小时同步一次
                tokio::time::sleep(Duration::from_secs(3600)).await;
            } else {
                // 失败后，1分钟重试一次
                tokio::time::sleep(Duration::from_secs(60)).await;
            }
        }
    });
}

async fn sync_once(host: &str) -> bool {
    // 优先级 1：UDP NTP (Port 123)
    if let Some(server_time) = query_ntp_udp(host).await {
        apply_offset(server_time, "UDP NTP");
        return true;
    }

    // 优先级 2：TCP HTTP Date (Port 80/443 fallback)
    if let Some(server_time) = query_http_tcp(host).await {
        apply_offset(server_time, "TCP HTTP Date");
        return true;
    }

    warn!("Time sync failed for both UDP and TCP against {}", host);
    false
}

fn apply_offset(server_time: u64, source: &str) {
    let local = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let offset = (server_time as i64) - local;
    
    // 净化逻辑：防止异常的时间跨度（如超过1天视为劫持）
    if offset.abs() > 86400 {
        warn!("Calculated offset {}s is too large (>1 day). Ignored.", offset);
        return;
    }

    let old = TIME_OFFSET.swap(offset, Ordering::Relaxed);
    if old != offset {
        info!("Time offset updated via {}: {}s -> {}s (Δ{}s)", source, old, offset, offset - old);
    } else {
        debug!("Time offset maintained via {}: {}s", source, offset);
    }
}

async fn query_ntp_udp(host: &str) -> Option<u64> {
    let socket = UdpSocket::bind("0.0.0.0:0").await.ok()?;
    let addr = format!("{}:123", host);
    
    // NTPv3 Client packet (48 bytes)
    let mut pkt = [0u8; 48];
    pkt[0] = 0x1B; // LI=0, VN=3, Mode=3 (Client)

    if timeout(Duration::from_secs(3), socket.send_to(&pkt, &addr))
        .await
        .is_err()
    {
        return None;
    }

    let mut buf = [0u8; 64];
    if let Ok(Ok((size, _))) = timeout(Duration::from_secs(3), socket.recv_from(&mut buf)).await {
        if size >= 48 {
            let secs = u32::from_be_bytes([buf[40], buf[41], buf[42], buf[43]]) as u64;
            if secs >= NTP_EPOCH_OFFSET {
                return Some(secs - NTP_EPOCH_OFFSET);
            }
        }
    }
    None
}

async fn query_http_tcp(host: &str) -> Option<u64> {
    // 尝试连接 80 端口发送 HEAD
    let addr = format!("{}:80", host);
    let mut stream = match timeout(Duration::from_secs(3), TcpStream::connect(&addr)).await {
        Ok(Ok(s)) => s,
        _ => return None,
    };

    let req = format!("HEAD / HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n", host);
    if timeout(Duration::from_secs(2), stream.write_all(req.as_bytes())).await.is_err() {
        return None;
    }

    let mut buf = Vec::new();
    let mut temp = [0u8; 1024];
    while let Ok(Ok(n)) = timeout(Duration::from_secs(3), stream.read(&mut temp)).await {
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&temp[..n]);
        if buf.len() > 4096 || buf.windows(4).any(|w| w == b"\r\n\r\n") {
            break;
        }
    }

    let header_str = String::from_utf8_lossy(&buf);
    for line in header_str.lines() {
        if line.to_lowercase().starts_with("date:") {
            if let Some((_, v)) = line.split_once(':') {
                let date_str = v.trim();
                // Parse RFC2822 date
                if let Ok(parsed_time) = chrono::DateTime::parse_from_rfc2822(date_str) {
                    return Some(parsed_time.timestamp() as u64);
                }
            }
        }
    }

    None
}
