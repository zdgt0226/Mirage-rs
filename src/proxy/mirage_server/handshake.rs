//! Mirage 协议握手: 解析 TLS ClientHello + Poly1305 token 校验 + ServerHello
//! 模拟回放 + 64B fake Client Finished tail 消费.
//!
//! 通过的连接继续走 `control::dispatch_authenticated` 建立加密 channel.
//! 失败的连接走 `camouflage::run_camouflage_forward` 伪装成正常 TLS 转发.
//!
//! v0.4.5-alpha.7: ClientHello 读取从 "read 1024 max" 改为精确 5B header +
//! body read_exact, 修 iOS Safari / Chrome 带完整 PSK/ECH 扩展 (1200-1400B)
//! 被截断误判 auth-fail 的问题. TLS 记录 length 上限 2^14 (RFC 8446 §5.1)
//! 硬 cap 16384. Fake tail 从 63 (52B body) 改为 64 (53B body) 匹配真实
//! TLS 1.3 Client Finished 尺寸.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::Ordering;
use std::sync::{Arc, LazyLock, Mutex};
use std::time::{Duration, Instant};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tracing::warn;

use super::camouflage;
use super::control;
use super::CamouflagePool;
use super::{IpSlotGuard, GLOBAL_UNAUTH, UNAUTH_CONNS};

const TLS_RECORD_HEADER_LEN: usize = 5;
const TLS_RECORD_MAX_BODY: usize = 16384; // 2^14, RFC 8446 §5.1

/// UNAUTH 限流 key: IPv6 归一到 /64 前缀 (清零低 64 位), 防攻击者用一个 /64
/// 段造 2^64 个"独立 IP" 逃逸限流. IPv4 原样返回 (单地址已是最细粒度).
fn rate_limit_key(ip: std::net::IpAddr) -> std::net::IpAddr {
    match ip {
        std::net::IpAddr::V4(_) => ip,
        std::net::IpAddr::V6(v6) => {
            let mut octets = v6.octets();
            for b in &mut octets[8..] {
                *b = 0;
            }
            std::net::IpAddr::V6(std::net::Ipv6Addr::from(octets))
        }
    }
}

// 反射 flood 速率守卫: 已有并发上限 (UNAUTH_CONNS 100/IP + GLOBAL_UNAUTH 5000) 只挡"同时挂着"
// 的反射, 挡不住"快速开-失败-关"的高频反射 (每条短命 → 并发低但反复砸 camouflage_host, 让本机
// IP 惹 abuse)。按源 IP(/64) 补窗口速率上限: 阈值远超 GFW 低频主动探测 (探测一次一两条), 只掐
// flood 滥用。超限直接 drop (与并发超限的 return None 行为一致)。
const UNAUTH_RATE_WINDOW: Duration = Duration::from_secs(10);
const UNAUTH_RATE_MAX: u32 = 30; // 每源 IP(/64) 每窗口最多反射次数
const UNAUTH_RATE_MAP_CAP: usize = 8192; // 表上限, 满淘汰窗口最旧的一条 (有界)
static UNAUTH_RATE: LazyLock<Mutex<HashMap<IpAddr, (Instant, u32)>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

/// 认证失败反射的按源 IP 窗口速率: 超 `UNAUTH_RATE_MAX`/`UNAUTH_RATE_WINDOW` 返 true (该丢)。
fn unauth_reflect_rate_exceeded(ip: IpAddr) -> bool {
    let now = Instant::now();
    let mut m = match UNAUTH_RATE.lock() {
        Ok(g) => g,
        Err(p) => p.into_inner(),
    };
    if !m.contains_key(&ip) && m.len() >= UNAUTH_RATE_MAP_CAP {
        // 满 + 新 IP: 淘汰窗口起点最旧的一条, 防表无界增长。
        if let Some(k) = m.iter().min_by_key(|(_, (t, _))| *t).map(|(k, _)| *k) {
            m.remove(&k);
        }
    }
    let e = m.entry(ip).or_insert((now, 0));
    if now.duration_since(e.0) > UNAUTH_RATE_WINDOW {
        *e = (now, 0); // 窗口过期, 重置
    }
    e.1 += 1;
    e.1 > UNAUTH_RATE_MAX
}

/// 传输无关的服务端握手核心 (ClientHello 鉴权 + 模板回放 + tail 消费)。返回 `Some((stream,
/// client_random, ecdh))` 表示鉴权通过、可进 dispatch; `None` = 已按 auth-fail 走 camouflage
/// 或出错 (调用方直接结束)。TCP/QUIC 各自的 `handle_connection*` 包一层做 split + dispatch。
async fn run_handshake<S>(
    mut stream: S,
    peer_addr: SocketAddr,
    password: &str,
    camouflage_host: &str,
    cam_pool: &Arc<CamouflagePool>,
    auth_ts_tolerance_secs: u64,
    pfs: bool,
) -> Option<(S, [u8; 32], Option<[u8; 32]>)>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    // 1. Read TLS record header (5 bytes exact)
    let mut header = [0u8; TLS_RECORD_HEADER_LEN];
    if tokio::time::timeout(Duration::from_secs(5), stream.read_exact(&mut header))
        .await
        .map(|r| r.is_err())
        .unwrap_or(true)
    {
        return None;
    }

    let content_type = header[0];
    let record_len = u16::from_be_bytes([header[3], header[4]]) as usize;

    // Malformed / oversized record: 静默丢. 不走 camouflage 是因为攻击者发的
    // 前 5B 已经不像 TLS, 转到 camouflage_host:443 只会浪费对面的连接.
    if record_len == 0 || record_len > TLS_RECORD_MAX_BODY {
        return None;
    }

    // 2. Read record body exact
    let mut body = vec![0u8; record_len];
    match tokio::time::timeout(Duration::from_secs(5), stream.read_exact(&mut body)).await {
        Ok(Ok(_)) => {}
        _ => return None,
    }

    // Reconstruct full ClientHello record for camouflage forwarding
    let mut client_hello = Vec::with_capacity(TLS_RECORD_HEADER_LEN + record_len);
    client_hello.extend_from_slice(&header);
    client_hello.extend_from_slice(&body);

    // 3. Authenticate by searching for the token in session_id field.
    //
    // ClientHello body layout (RFC 8446 §4.1.2):
    //   body[0]        HandshakeType (0x01 = ClientHello)
    //   body[1..4]     uint24 body length
    //   body[4..6]     ProtocolVersion (0x0303 = TLS 1.2)
    //   body[6..38]    Random (32 bytes) ← client_random
    //   body[38]       legacy_session_id.length (1 byte)
    //   body[39..]     legacy_session_id (32 bytes for Mirage) ← token here
    let mut authenticated = false;
    let mut client_random = [0u8; 32];

    if content_type == 0x16 && body.len() >= 39 && body[0] == 0x01 {
        let sid_len = body[38] as usize;
        if sid_len == 32 && body.len() >= 39 + sid_len {
            let session_id = &body[39..39 + sid_len];
            let mut sid_array = [0u8; 32];
            sid_array.copy_from_slice(session_id);
            if crate::crypto::hello_auth::verify_session_token(password, &sid_array, auth_ts_tolerance_secs) {
                authenticated = true;
                client_random.copy_from_slice(&body[6..38]);
            }
        }
    }

    if !authenticated {
        warn!("Mirage Server auth failed from {}", peer_addr);

        let global_count = GLOBAL_UNAUTH.fetch_add(1, Ordering::SeqCst);
        if global_count >= 5000 {
            GLOBAL_UNAUTH.fetch_sub(1, Ordering::SeqCst);
            return None;
        }

        // v0.4.5-alpha.10: 限流 key 用 /64 归一后的 IP, 防攻击者用 /64 段造
        // 2^64 独立 IPv6 地址逃逸限流. IPv4 保持单地址 (已是最细粒度).
        let ip = rate_limit_key(peer_addr.ip());

        // 反射速率守卫 (补并发上限盲区: 快速开-失败-关的高频反射)。超限直接 drop, 不再反射砸
        // camouflage_host —— GFW 低频探测远达不到阈值, 只掐滥用 flood。
        if unauth_reflect_rate_exceeded(ip) {
            GLOBAL_UNAUTH.fetch_sub(1, Ordering::SeqCst);
            return None;
        }

        let _slot_guard = {
            // 锁中毒容忍 (into_inner), 不 unwrap panic —— 跟 IpSlotGuard::drop 同锁
            // 同原则. HashMap 数据没被破坏 (临界区无 panic 源).
            let mut map = match UNAUTH_CONNS.get_or_init(|| Mutex::new(HashMap::new())).lock() {
                Ok(g) => g,
                Err(poisoned) => poisoned.into_inner(),
            };
            let count = map.entry(ip).or_insert(0);
            if *count >= 100 {
                GLOBAL_UNAUTH.fetch_sub(1, Ordering::SeqCst);
                return None;
            }
            *count += 1;
            IpSlotGuard(ip)
        };

        camouflage::run_camouflage_forward(stream, &client_hello, camouflage_host, cam_pool)
            .await;

        return None;
    }

    // PFS: 生成服务端一次性 X25519 对。公钥注入回放模板的 ServerHello.random 发给客户端,
    // 私钥留着与 client_random (= 客户端临时公钥) 做 ECDH。见 crypto::pfs。
    let server_ephemeral = if pfs {
        match crate::crypto::pfs::Ephemeral::generate() {
            Ok(e) => Some(e),
            Err(e) => {
                tracing::error!("Mirage Server: PFS 临时密钥生成失败: {e}");
                return None;
            }
        }
    } else {
        None
    };

    // 2.5 Send ServerHello template back to satisfy Mirage Client's TLS state machine
    let template = crate::crypto::handshake_cache::get_server_hello_pfs(
        camouflage_host,
        &client_hello,
        server_ephemeral.as_ref().map(|e| &e.public),
    )
    .await;

    // v0.4.5-alpha.13: 消除 auth-succ vs auth-fail 时序侧信道.
    // auth-fail 走 camouflage 转发有 ~1 RTT 延迟 (探针→server→camouflage→回),
    // auth-succ 本地模板回放 ~0ms. 差异让 GFW 关联"真实用户秒回、探针慢回"识破
    // 差别对待 = 暴露 Reality 式代理. auth-fail 无法变快 (探针要真实 TLS 握手必须
    // 转发真站), 故在 auth-succ 注入等量抖动延迟对齐. RTT 由 CamouflagePool 实测,
    // ±25% 抖动模拟网络方差 (固定延迟太规整反而是特征). WarmPool 预建吸收此延迟,
    // 用户无感.
    let rtt = cam_pool.rtt_us();
    if rtt > 0 {
        let jitter_num = 75 + fastrand::u64(0..=50); // 75%~125%
        let delay_us = rtt.saturating_mul(jitter_num) / 100;
        tokio::time::sleep(Duration::from_micros(delay_us)).await;
    }

    if let Err(e) = stream.write_all(&template).await {
        tracing::error!("Mirage Server: write_all template failed: {}", e);
        return None;
    }

    // 2.7 Consume Fake Client Tail (64 bytes: 6B CCS + 5B record header + 53B fake finished body)
    let mut tail = [0u8; 64];
    match tokio::time::timeout(Duration::from_secs(5), stream.read_exact(&mut tail)).await {
        Ok(Err(e)) => {
            tracing::error!("Mirage Server: read_exact tail failed: {}", e);
            return None;
        }
        Err(_) => {
            tracing::error!("Mirage Server: read_exact tail timed out!");
            return None;
        }
        Ok(Ok(_)) => {
            tracing::info!("Mirage Server: Successfully consumed 64 bytes tail");
        }
    }

    // PFS: 与 client_random (= 客户端临时公钥) 做 ECDH 得共享秘密, 混进会话 master。
    let ecdh = match server_ephemeral {
        Some(e) => match e.agree(&client_random) {
            Ok(s) => Some(s),
            Err(err) => {
                tracing::error!("Mirage Server: PFS ECDH 协商失败: {err}");
                return None;
            }
        },
        None => None,
    };

    // Hand off to control plane (crypto setup + TIME_SYNC + dispatch)
    Some((stream, client_random, ecdh))
}

/// TCP 传输入口: 握手 → into_split (Tcp 变体, 保留静态分发 + 无锁) → dispatch。
pub(super) async fn handle_connection(
    stream: TcpStream,
    peer_addr: SocketAddr,
    password: String,
    camouflage_host: String,
    cam_pool: Arc<CamouflagePool>,
    auth_ts_tolerance_secs: u64,
    upstream: Option<std::sync::Arc<crate::proxy::upstream::UpstreamOutlet>>,
    pfs: bool,
) {
    stream.set_nodelay(true).unwrap_or_default();
    let client_ip = peer_addr.ip();
    if let Some((stream, client_random, ecdh)) = run_handshake(
        stream, peer_addr, &password, &camouflage_host, &cam_pool, auth_ts_tolerance_secs, pfs,
    )
    .await
    {
        let (rh, wh) = stream.into_split();
        control::dispatch_authenticated(
            crate::proxy::tunnel::TunnelRead::Tcp(rh),
            crate::proxy::tunnel::TunnelWrite::Tcp(wh),
            Some(client_ip),
            password,
            client_random,
            upstream,
            ecdh,
        )
        .await;
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unauth_reflect_rate_trips_after_max() {
        // 测试专用 IP, 免与其它测试共享 static 状态干扰。
        let ip: IpAddr = "203.0.113.77".parse().unwrap();
        for i in 1..=UNAUTH_RATE_MAX {
            assert!(!unauth_reflect_rate_exceeded(ip), "第 {i} 次不该超限");
        }
        assert!(unauth_reflect_rate_exceeded(ip), "超过 MAX 应触发丢弃");
    }

    #[test]
    fn reflect_rate_key_normalizes_ipv6_to_64() {
        // 同 /64 段不同低位 → 归一为同一限流 key, 共享速率窗口 (防 /64 造 2^64 IP 逃逸)。
        let a = rate_limit_key("2001:db8::1".parse().unwrap());
        let b = rate_limit_key("2001:db8::dead:beef".parse().unwrap());
        assert_eq!(a, b, "同 /64 应归一为同 key");
    }
}
