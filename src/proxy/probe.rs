//! 节点可用性探测: 对一个 mirage 出站做一次**完整握手 + 认证验证**, 报 RTT。
//!
//! 为什么不是裸 TCP connect: mirage 的伪装前置是真站点, `:443` 本来就通, 连上 ≠ 节点
//! 能用。真正的可用 = 完成 TLS 伪装握手后, 用密码派生的会话密钥**成功解开**服务端下发的
//! 首帧 (TIME_SYNC)。认证没过时服务端会把连接转发给伪装站, 我们用会话密钥去解伪装站的
//! 真 TLS 流量必然失败 —— 这正是"密码不符 / 非 Mirage 服务端"的确定信号。
//!
//! 复用客户端握手原语 (pool::connect_upstream 的同一套), 但判定更严: 必须解密成功。

use std::time::{Duration, Instant};

use anyhow::anyhow;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tokio::time::timeout;

/// 探测结果。RTT 单位毫秒。
pub enum ProbeOutcome {
    /// 握手 + 认证均通过。tcp_ms = TCP 建连往返; handshake_ms = 建连后到认证确认的往返;
    /// http_ms = 可选的穿隧道 HTTP 端到端往返 (含 VPS 出口), None = 未测或探测失败。
    Ok { tcp_ms: u64, handshake_ms: u64, http_ms: Option<u64> },
    /// TCP + TLS 伪装握手可达, 但没收到可解密的首帧确认认证 (旧服务端不下发 TIME_SYNC?)。
    /// 可达但认证未确认 —— 不算失败, 也不能保证密码正确。
    Unconfirmed { tcp_ms: u64, note: String },
    /// 不可用。原因: 连接失败/超时、握手失败、认证解密失败等。
    Fail(String),
}

/// 对一个 mirage 节点做一次探测。永不返回 Err —— 所有错误折叠进 `ProbeOutcome::Fail`,
/// 便于调用方 (CLI / import --test) 直接按结果分支。
///
/// `http_probe`: Some(url) 则在认证确认后额外做一次**穿隧道 HTTP 探测** (拉 url, 计端到端
/// 往返, 含 VPS 出口质量); None 则只做握手+认证 (不产生出口流量, import --test 用)。
/// 探测本身失败不影响可用性判定 (节点仍 Ok, 只是 http_ms=None)。
pub async fn probe_mirage(
    server: &str,
    port: u16,
    password: &str,
    camouflage_host: &str,
    timeout_secs: u64,
    http_probe: Option<&str>,
) -> ProbeOutcome {
    match probe_inner(server, port, password, camouflage_host, timeout_secs, http_probe).await {
        Ok(o) => o,
        Err(e) => ProbeOutcome::Fail(e.to_string()),
    }
}

async fn probe_inner(
    server: &str,
    port: u16,
    password: &str,
    camouflage_host: &str,
    timeout_secs: u64,
    http_probe: Option<&str>,
) -> anyhow::Result<ProbeOutcome> {
    let dl = Duration::from_secs(timeout_secs);
    let addr = format!("{server}:{port}");

    // 1. TCP 建连 (计 RTT)。黑洞路由下会挂到内核 syn_retries, 故必须带超时。
    let t0 = Instant::now();
    let stream = timeout(dl, TcpStream::connect(&addr))
        .await
        .map_err(|_| anyhow!("TCP 连接 {addr} 超时 ({timeout_secs}s, 黑洞路由/端口不通?)"))?
        .map_err(|e| anyhow!("TCP 连接 {addr} 失败: {e}"))?;
    let tcp_ms = t0.elapsed().as_millis() as u64;
    let _ = stream.set_nodelay(true);
    let (mut read_half, mut write_half) = stream.into_split();

    let t1 = Instant::now();

    // 2. 发带 token 的伪装 ClientHello, 读服务端握手 flight, 回假 Finished tail —— 与
    //    pool::connect_upstream 完全同一套原语。整段包一个总超时。
    let hs = async {
        let token = crate::crypto::hello_auth::make_session_token(password);
        let (hello, client_random) =
            crate::crypto::tls_raw::build_client_hello(camouflage_host, &token);
        write_half.write_all(&hello).await?;
        write_half.flush().await?;
        crate::proxy::pool::read_server_handshake(&mut read_half).await?;
        let tail = crate::crypto::tls_raw::build_fake_client_tail();
        write_half.write_all(&tail).await?;
        write_half.flush().await?;
        Ok::<_, anyhow::Error>(client_random)
    };
    // 握手阶段超时**下限 15s**: read_server_handshake 本身对真实慢链路容忍到 ~10-14s
    // (CCS 前), 若用外层 8s 总超时去卡它, 慢但可用的服务端会被误判 Fail (--require-live
    // 就会拒掉一个其实能用的节点)。故握手取 max(用户超时, 15s), 不低于协议自身容忍。
    let hs_dl = dl.max(Duration::from_secs(15));
    let client_random = timeout(hs_dl, hs)
        .await
        .map_err(|_| anyhow!("TLS 伪装握手超时 ({}s)", hs_dl.as_secs()))?
        .map_err(|e| anyhow!("TLS 伪装握手失败: {e}"))?;

    // 3. 派生会话密钥, 尝试解服务端首帧。解密成功 = 密钥正确 = 密码对且是真 Mirage 服务端。
    let (mut reader, mut writer) = crate::crypto::aead::create_crypto_pair(
        read_half,
        write_half,
        password,
        &client_random,
        true, // is_initiator
    );
    // 认证确认单独一个较短超时 (对齐 connect_upstream 的 3s TIME_SYNC 等待, 不超过总超时)。
    let auth_wait = dl.min(Duration::from_secs(3));
    match timeout(auth_wait, reader.recv_data()).await {
        // 解密成功 (任意帧): 会话密钥正确 → 认证通过。
        Ok(Ok(_data)) => {
            let handshake_ms = t1.elapsed().as_millis() as u64;
            // 认证已确认。可选: 穿隧道 HTTP 探测端到端质量 (探测失败不影响可用判定)。
            let http_ms = match http_probe {
                Some(url) => fetch_via_tunnel(&mut reader, &mut writer, url, dl).await.ok(),
                None => None,
            };
            Ok(ProbeOutcome::Ok { tcp_ms, handshake_ms, http_ms })
        }
        // 首帧接收/解密失败: 最常见是服务端拒认证、把连接转给伪装站, 会话密钥解不开其真
        // TLS。也可能是服务端解密后提前关连接 (close_notify/空帧)。措辞不武断指向密码。
        Ok(Err(e)) => Ok(ProbeOutcome::Fail(format!(
            "认证/首帧失败: 会话数据接收或解密错 (多为密码不符 / 非 Mirage 服务端 / 时钟偏差; \
             也可能服务端提前关连接): {e}"
        ))),
        // 超时未收到首帧: TLS 握手过了但没确认认证 (旧服务端不下发 TIME_SYNC?)。
        Err(_) => Ok(ProbeOutcome::Unconfirmed {
            tcp_ms,
            note: "TLS 握手可达但未收到认证确认帧 (旧服务端?)".to_string(),
        }),
    }
}

/// 解析明文 HTTP 探测 URL → (host, port, path)。只支持 `http://` (穿隧道到目标是裸 TCP,
/// 拉 HTTP/80 免去对目标再套 TLS)。无端口默认 80, 无路径默认 `/`。方括号 IPv6 字面量
/// (`http://[::1]:80/x` 或 `http://[::1]/x`) 也支持 —— host 保留方括号供 host:port 目标头。
fn parse_http_probe_url(url: &str) -> Option<(String, u16, String)> {
    let rest = url.strip_prefix("http://")?;
    let (authority, path) = match rest.find('/') {
        Some(i) => (&rest[..i], rest[i..].to_string()),
        None => (rest, "/".to_string()),
    };
    let (host, port) = if let Some(inner) = authority.strip_prefix('[') {
        // 方括号 IPv6: [addr] 可选 :port。不能用 rsplit_once(':') —— 地址内部全是冒号。
        let close = inner.find(']')?;
        let addr = &inner[..close];
        if addr.is_empty() {
            return None;
        }
        let after = &inner[close + 1..];
        let port = match after.strip_prefix(':') {
            Some(p) => p.parse().ok()?,
            None if after.is_empty() => 80,
            None => return None, // ']' 后有杂字符
        };
        (format!("[{addr}]"), port)
    } else {
        match authority.rsplit_once(':') {
            Some((h, p)) => (h.to_string(), p.parse().ok()?),
            None => (authority.to_string(), 80),
        }
    };
    if host.is_empty() {
        return None;
    }
    Some((host, port, path))
}

/// 认证确认后, 借已建好的隧道拉一次 HTTP, 计端到端往返 (ms)。协议: 先发目标头
/// `[2B len][host:port]` (与 handler.rs 客户端一致), 再发 `GET`, 收首个响应即计时。
/// 计时从发目标头到收到响应 —— 含 VPS 连目标 + 拉取 + 回程, 即出口质量。
async fn fetch_via_tunnel<R, W>(
    reader: &mut crate::crypto::aead::CryptoReader<R>,
    writer: &mut crate::crypto::aead::CryptoWriter<W>,
    url: &str,
    dl: Duration,
) -> anyhow::Result<u64>
where
    R: tokio::io::AsyncRead + Unpin,
    W: tokio::io::AsyncWrite + Unpin,
{
    let (host, port, path) = parse_http_probe_url(url)
        .ok_or_else(|| anyhow!("探测 URL 非法 (需 http://host[:port]/path): {url}"))?;
    let target = format!("{host}:{port}");
    let mut header = Vec::with_capacity(2 + target.len());
    header.extend_from_slice(&(target.len() as u16).to_be_bytes());
    header.extend_from_slice(target.as_bytes());
    let req = format!(
        "GET {path} HTTP/1.0\r\nHost: {host}\r\nUser-Agent: mirage-probe\r\nConnection: close\r\n\r\n"
    );

    let t = Instant::now();
    // 全部 IO (两次写 + 一次读) 包一个 dl 超时: 写侧 stall (server 不读/发缓冲满) 也不会
    // 永久挂死, 否则单个坏节点会卡住整个 test。
    let io = async {
        writer.send_data(&header).await?;
        writer.send_data(req.as_bytes()).await?;
        reader.recv_data().await
    };
    let resp = timeout(dl, io)
        .await
        .map_err(|_| anyhow!("穿隧道 HTTP 探测超时"))??;
    // 收到像样的 HTTP 响应即算出口通 (非 HTTP 头 = 出口异常/被劫持)。
    if resp.starts_with(b"HTTP/") {
        Ok(t.elapsed().as_millis() as u64)
    } else {
        Err(anyhow!("穿隧道响应非 HTTP (出口异常?)"))
    }
}

#[cfg(test)]
mod tests {
    use super::parse_http_probe_url;

    #[test]
    fn parse_probe_url_variants() {
        assert_eq!(
            parse_http_probe_url("http://www.gstatic.com/generate_204"),
            Some(("www.gstatic.com".into(), 80, "/generate_204".into()))
        );
        // 带端口
        assert_eq!(
            parse_http_probe_url("http://example.com:8080/x"),
            Some(("example.com".into(), 8080, "/x".into()))
        );
        // 无路径 → /
        assert_eq!(
            parse_http_probe_url("http://example.com"),
            Some(("example.com".into(), 80, "/".into()))
        );
        // 非 http:// (https / 缺 scheme / 空) → None
        assert!(parse_http_probe_url("https://example.com/").is_none());
        assert!(parse_http_probe_url("example.com/x").is_none());
        assert!(parse_http_probe_url("http:///path").is_none()); // 空 host
        // 方括号 IPv6: 带端口 / 无端口(默认80) / 空地址
        assert_eq!(
            parse_http_probe_url("http://[::1]:8080/x"),
            Some(("[::1]".into(), 8080, "/x".into()))
        );
        assert_eq!(
            parse_http_probe_url("http://[2001:db8::1]/"),
            Some(("[2001:db8::1]".into(), 80, "/".into()))
        );
        assert!(parse_http_probe_url("http://[]/x").is_none()); // 空 IPv6
    }
}
