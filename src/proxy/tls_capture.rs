//! TLS 指纹捕获: 抓本机真浏览器的 ClientHello 当 fake-TLS 指纹模板。**不 phone-home** ——
//! 用的是用户真浏览器经本代理 (SOCKS5/透明) 访问 HTTPS 时的实时握手, 非联网拉取。
//!
//! 两种触发 (不走 config):
//! - CLI `mirage tls-capture --listen --out`: 起一次性 SOCKS 抓取代理, 抓到即退 (`wait_captured`)。
//! - API `POST /api/v1/tls/capture`: 给已运行的透明网关免重启 arm; `GET` 取回模板 (base64)。
//!
//! 机制: relay 入口 (`handler.rs` SOCKS/mixed + `transparent.rs` 透明) 各调 `maybe_capture`; armed 时
//! peek 客户端首包, 是合法 TLS 1.3 ClientHello (带 32B session_id, Mirage 认证 token 塞此) 就抓一次。

use std::sync::{LazyLock, Mutex};
use tokio::sync::Notify;
use tracing::{info, warn};

#[derive(Default)]
struct State {
    armed: bool,
    out: Option<String>,
    last: Option<Captured>,
}

/// 抓取结果: 原始 ClientHello 字节 + 关键字段偏移 (供回放 B 替换 session_id/random/SNI)。
#[derive(Clone)]
pub struct Captured {
    pub bytes: Vec<u8>,
    pub record_len: usize,
    pub sni_host: Option<String>,
    pub sni_host_offset: Option<usize>,
    pub sni_host_len: Option<usize>,
}

static CAP: Mutex<State> = Mutex::new(State { armed: false, out: None, last: None });
static NOTIFY: LazyLock<Notify> = LazyLock::new(Notify::new);

fn lock() -> std::sync::MutexGuard<'static, State> {
    CAP.lock().unwrap_or_else(|e| e.into_inner())
}

/// arm 一次性抓取。`out`=Some 时抓到同时写该文件 (+ `.json`); None 时仅存内存供 API 取回。
pub fn arm(out: Option<String>) {
    let mut s = lock();
    s.armed = true;
    s.out = out;
    info!("[TLS-CAPTURE] 已武装: 下一个经过的浏览器 ClientHello 将被抓为指纹模板");
}

/// 是否 armed (供 API status)。
pub fn is_armed() -> bool {
    lock().armed
}

/// 最近抓取结果 (供 API GET 取回)。
pub fn last() -> Option<Captured> {
    lock().last.clone()
}

/// 等待抓到一次 (CLI 用: 抓到即返回, 好退出)。
pub async fn wait_captured() {
    NOTIFY.notified().await;
}

/// relay 入口调用 (SOCKS5/mixed + 透明两路): armed 时 peek 客户端首包, 是 TLS 就抓。未 arm 立即
/// 返回 (不 peek, 零开销), 故不受路由是否需要 sniff 的影响 —— socks5h 送域名 / fake-IP 命中也能抓。
pub async fn maybe_capture(stream: &tokio::net::TcpStream) {
    if !is_armed() {
        return;
    }
    let mut buf = [0u8; 4096];
    if let Ok(Ok(n)) =
        tokio::time::timeout(std::time::Duration::from_millis(500), stream.peek(&mut buf)).await
    {
        if n > 5 && buf[0] == 0x16 {
            try_capture(&buf[..n]);
        }
    }
}

/// 校验+原子抓一次: 只有一个连接成功 take 掉 armed, 保证只抓一次。
fn try_capture(data: &[u8]) {
    let Some(cap) = parse_for_capture(data) else {
        return;
    };
    let out = {
        let mut s = lock();
        if !s.armed {
            return;
        }
        s.armed = false;
        s.last = Some(cap.clone());
        s.out.take()
    };
    if let Some(path) = &out {
        if let Err(e) = write_files(path, &cap) {
            warn!("[TLS-CAPTURE] 写 {} 失败: {} —— 重新武装, 可再试", path, e);
            let mut s = lock();
            s.armed = true;
            s.out = out;
            return;
        }
    }
    info!(
        "[TLS-CAPTURE] 已抓取 ClientHello ({} 字节, SNI={}){}",
        cap.record_len,
        cap.sni_host.as_deref().unwrap_or("?"),
        out.as_ref().map(|p| format!(" → {p} (+ .json)")).unwrap_or_default()
    );
    NOTIFY.notify_waiters();
}

/// 校验是否**完整合法**的 TLS 1.3 ClientHello (带 32B session_id) 并解析偏移。
fn parse_for_capture(data: &[u8]) -> Option<Captured> {
    if data.len() < 44 || data[0] != 0x16 || data[5] != 0x01 {
        return None;
    }
    let record_len = 5 + (((data[3] as usize) << 8) | (data[4] as usize));
    if record_len > data.len() {
        return None;
    }
    if data[43] as usize != 32 {
        return None;
    }
    let (sni_host, sni_host_offset, sni_host_len) = parse_sni(data, record_len);
    Some(Captured {
        bytes: data[..record_len].to_vec(),
        record_len,
        sni_host,
        sni_host_offset,
        sni_host_len,
    })
}

/// 解析 SNI host 及其字节偏移/长度 (供 B 变长替换 camouflage_host)。
fn parse_sni(data: &[u8], end: usize) -> (Option<String>, Option<usize>, Option<usize>) {
    let mut offset = 44 + data[43] as usize;
    if offset + 2 > end {
        return (None, None, None);
    }
    offset += 2 + (((data[offset] as usize) << 8) | (data[offset + 1] as usize));
    if offset + 1 > end {
        return (None, None, None);
    }
    offset += 1 + data[offset] as usize;
    if offset + 2 > end {
        return (None, None, None);
    }
    let ext_total = ((data[offset] as usize) << 8) | (data[offset + 1] as usize);
    offset += 2;
    let ext_end = std::cmp::min(offset + ext_total, end);
    while offset + 4 <= ext_end {
        let ext_type = ((data[offset] as usize) << 8) | (data[offset + 1] as usize);
        let ext_len = ((data[offset + 2] as usize) << 8) | (data[offset + 3] as usize);
        offset += 4;
        if ext_type == 0 {
            if offset + 5 > ext_end {
                return (None, None, None);
            }
            let name_len = ((data[offset + 3] as usize) << 8) | (data[offset + 4] as usize);
            let host_off = offset + 5;
            if data[offset + 2] == 0 && host_off + name_len <= ext_end {
                let host = std::str::from_utf8(&data[host_off..host_off + name_len])
                    .ok()
                    .map(str::to_string);
                return (host, Some(host_off), Some(name_len));
            }
            return (None, None, None);
        }
        offset += ext_len;
    }
    (None, None, None)
}

/// 原子写: <path> = 原始 ClientHello; <path>.json = 偏移 sidecar。
fn write_files(path: &str, cap: &Captured) -> std::io::Result<()> {
    if let Some(parent) = std::path::Path::new(path).parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let tmp = format!("{path}.tmp");
    std::fs::write(&tmp, &cap.bytes)?;
    std::fs::rename(&tmp, path)?;
    std::fs::write(format!("{path}.json"), serde_json::to_vec_pretty(&sidecar(cap))?)?;
    Ok(())
}

/// 偏移 sidecar JSON (session_id/random 固定偏移; SNI 变长)。
pub fn sidecar(cap: &Captured) -> serde_json::Value {
    serde_json::json!({
        "note": "Mirage fake-TLS 指纹模板 (真浏览器 ClientHello). 回放时替换 session_id/random/SNI。",
        "record_len": cap.record_len,
        "session_id_offset": 44,
        "random_offset": 11,
        "sni_host": cap.sni_host,
        "sni_host_offset": cap.sni_host_offset,
        "sni_host_len": cap.sni_host_len,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn craft_ch() -> Vec<u8> {
        let host = b"ex.com";
        let mut sni = vec![0u8, 0];
        let inner = 2 + 1 + 2 + host.len();
        sni.extend_from_slice(&(inner as u16).to_be_bytes());
        sni.extend_from_slice(&((1 + 2 + host.len()) as u16).to_be_bytes());
        sni.push(0);
        sni.extend_from_slice(&(host.len() as u16).to_be_bytes());
        sni.extend_from_slice(host);
        let mut body = vec![0x03, 0x03];
        body.extend_from_slice(&[0u8; 32]);
        body.push(32);
        body.extend_from_slice(&[0u8; 32]);
        body.extend_from_slice(&[0x00, 0x02, 0x13, 0x01]);
        body.extend_from_slice(&[0x01, 0x00]);
        body.extend_from_slice(&(sni.len() as u16).to_be_bytes());
        body.extend_from_slice(&sni);
        let mut hs = vec![0x01];
        hs.extend_from_slice(&(body.len() as u32).to_be_bytes()[1..]);
        hs.extend_from_slice(&body);
        let mut rec = vec![0x16, 0x03, 0x01];
        rec.extend_from_slice(&(hs.len() as u16).to_be_bytes());
        rec.extend_from_slice(&hs);
        rec
    }

    #[test]
    fn parse_extracts_sni_and_offsets() {
        let ch = craft_ch();
        let c = parse_for_capture(&ch).expect("合法 ClientHello");
        assert_eq!(c.record_len, ch.len());
        assert_eq!(c.sni_host.as_deref(), Some("ex.com"));
        assert_eq!(c.sni_host_offset, Some(93));
        assert_eq!(c.sni_host_len, Some(6));
    }

    #[test]
    fn rejects_truncated_and_non_ch() {
        assert!(parse_for_capture(&[0x16, 0x03, 0x01]).is_none());
        let mut ch = craft_ch();
        ch.truncate(ch.len() - 3);
        assert!(parse_for_capture(&ch).is_none());
    }
}
