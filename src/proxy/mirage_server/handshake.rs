//! Mirage 协议握手: 解析 TLS ClientHello + Poly1305 token 校验 + ServerHello
//! 模拟回放 + 64B fake Client Finished tail 消费.
//!
//! 通过的连接继续走 `control::dispatch_authenticated` 建立加密 channel.
//! 失败的连接以及认证前读取异常 (非 TLS/超长/超时/不完整) 均走
//! `camouflage::run_camouflage_forward` 伪装成正常 TLS 反向代理转发.
//!
//! v0.4.5-alpha.7: ClientHello 读取从 "read 1024 max" 改为精确 5B header +
//! body read_exact, 修 iOS Safari / Chrome 带完整 PSK/ECH 扩展 (1200-1400B)
//! 被截断误判 auth-fail 的问题. TLS 记录 length 上限 2^14 (RFC 8446 §5.1)
//! 硬 cap 16384. Fake tail 从 63 (52B body) 改为 64 (53B body) 匹配真实
//! TLS 1.3 Client Finished 尺寸.
//!
//! 2026-09-27 审计修补: 认证前读取改为单一 5s 截止时间的增量缓冲读取。
//! 任何异常 (buf[0] != 0x16 首字节非 TLS、record_len == 0 或 > 16384、
//! 记录体或记录头读取超时/EOF读不全) 不再静默断开, 而是将已收到的原始字节
//! 原样透传给真实伪装站, 消除主动明文探测 (如 HTTP GET 探针秒断/静默丢)
//! 与真实站点的行为差异; 对端未发字节即关闭时安全释放。所有转发统一受
//! GLOBAL_UNAUTH、UNAUTH_RATE 速率守卫及 UNAUTH_CONNS 槽位保护。

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

/// 校验 token 是否匹配有效 (且未超额) 凭据。
/// 超额用户按认证失败处理 (None), 走与 token 校验失败完全相同的伪装站转发路径。
pub(crate) fn verify_creds_and_quota<F>(
    creds: &[(String, String)],
    token: &[u8; 32],
    client_random: &[u8; 32],
    auth_ts_tolerance_secs: u64,
    is_exhausted: F,
) -> Option<usize>
where
    F: Fn(&str) -> bool,
{
    let idx = creds.iter().position(|(_, pw)| {
        crate::crypto::hello_auth::verify_session_token(pw, token, client_random, auth_ts_tolerance_secs)
    })?;
    let username = &creds[idx].0;
    if is_exhausted(username) {
        return None;
    }
    Some(idx)
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum ClientHelloReadResult {
    /// 完整读取到了 TLS ClientHello 记录 (buf.len() == 5 + record_len)
    Complete(Vec<u8>),
    /// 异常读取需回落到伪装站透传 (附带已收到的全部原始字节, 包含 0 字节超时)
    Fallback(Vec<u8>),
    /// 对端未发送任何字节即关闭/报错, 连接已死直接丢弃
    Close,
}

/// 增量读取 ClientHello (单一截止时间保持 5s 总体语义)。
/// 循环 `read` 追加, 任何时刻都知道已读到的全部字节。
/// 异常时 (首字节非 0x16、record_len==0 或 >16384、读取超时、读不全 EOF)
/// 返回 Fallback 附带已读字节; 仅当 0 字节 EOF/报错时返回 Close。
pub(crate) async fn read_client_hello<S>(
    stream: &mut S,
    timeout_dur: Duration,
) -> ClientHelloReadResult
where
    S: AsyncRead + Unpin,
{
    let deadline = Instant::now() + timeout_dur;
    let mut buf = Vec::with_capacity(1024);
    let mut tmp = [0u8; 1024];

    loop {
        let now = Instant::now();
        if now >= deadline {
            return ClientHelloReadResult::Fallback(buf);
        }
        let remaining_time = deadline.saturating_duration_since(now);

        // 单次读取上限: 头未齐只读到 5B, 头齐后只读到记录末尾 —— 绝不越过首个 record,
        // 否则其后的字节 (管道化数据) 会被吞进 buf 丢失或误判。
        let target_len = if buf.len() >= TLS_RECORD_HEADER_LEN {
            TLS_RECORD_HEADER_LEN + u16::from_be_bytes([buf[3], buf[4]]) as usize
        } else {
            TLS_RECORD_HEADER_LEN
        };
        let to_read = (target_len - buf.len()).min(tmp.len());

        match tokio::time::timeout(remaining_time, stream.read(&mut tmp[..to_read])).await {
            Ok(Ok(0)) => {
                // EOF
                if buf.is_empty() {
                    return ClientHelloReadResult::Close;
                } else {
                    return ClientHelloReadResult::Fallback(buf);
                }
            }
            Ok(Ok(n)) => {
                buf.extend_from_slice(&tmp[..n]);

                // 规则 3: 一旦首字节非 0x16, 立即回落, 不等满 5B (HTTP 明文探测秒判)
                if buf[0] != 0x16 {
                    return ClientHelloReadResult::Fallback(buf);
                }

                // 首字节是 0x16, 检查是否已收齐 5B 记录头
                if buf.len() >= TLS_RECORD_HEADER_LEN {
                    let record_len = u16::from_be_bytes([buf[3], buf[4]]) as usize;
                    // 规则 2: record_len == 0 或 > 16384 异常回落
                    // (不再静默丢弃, 而是原样透传给伪装站以消除探测与真站差异)
                    if record_len == 0 || record_len > TLS_RECORD_MAX_BODY {
                        return ClientHelloReadResult::Fallback(buf);
                    }
                    if buf.len() == TLS_RECORD_HEADER_LEN + record_len {
                        return ClientHelloReadResult::Complete(buf);
                    }
                }
            }
            Ok(Err(_)) => {
                // 读取报错
                if buf.is_empty() {
                    return ClientHelloReadResult::Close;
                } else {
                    return ClientHelloReadResult::Fallback(buf);
                }
            }
            Err(_) => {
                // 超时 (交出已读部分, 哪怕 0 字节 —— 让伪装站超时接管)
                return ClientHelloReadResult::Fallback(buf);
            }
        }
    }
}

/// 将客户端连接与已接收字节反射给伪装站 (camouflage_host:443) 并双向透传。
/// 认证失败与各种读取异常回落共用此 helper, 统一受并发门禁 (GLOBAL_UNAUTH 5000)、
/// 源 IP 速率守卫 (UNAUTH_RATE) 及每 IP 并发限制 (UNAUTH_CONNS 100) 保护。
async fn reflect_to_camouflage<S>(
    stream: S,
    peer_addr: SocketAddr,
    bytes: &[u8],
    camouflage_host: &str,
    cam_pool: &Arc<CamouflagePool>,
) where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let global_count = GLOBAL_UNAUTH.fetch_add(1, Ordering::SeqCst);
    if global_count >= 5000 {
        GLOBAL_UNAUTH.fetch_sub(1, Ordering::SeqCst);
        return;
    }

    // v0.4.5-alpha.10: 限流 key 用 /64 归一后的 IP, 防攻击者用 /64 段造
    // 2^64 独立 IPv6 地址逃逸限流. IPv4 保持单地址 (已是最细粒度).
    let ip = rate_limit_key(peer_addr.ip());

    // 反射速率守卫 (补并发上限盲区: 快速开-失败-关的高频反射)。超限直接 drop, 不再反射砸
    // camouflage_host —— GFW 低频探测远达不到阈值, 只掐滥用 flood。
    if unauth_reflect_rate_exceeded(ip) {
        GLOBAL_UNAUTH.fetch_sub(1, Ordering::SeqCst);
        return;
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
            return;
        }
        *count += 1;
        IpSlotGuard(ip)
    };

    camouflage::run_camouflage_forward(stream, bytes, camouflage_host, cam_pool).await;
}

/// 传输无关的服务端握手核心 (ClientHello 鉴权 + 模板回放 + tail 消费)。返回 `Some((stream,
/// client_random, ecdh))` 表示鉴权通过、可进 dispatch; `None` = 已按 auth-fail 走 camouflage
/// 或出错 (调用方直接结束)。TCP/QUIC 各自的 `handle_connection*` 包一层做 split + dispatch。
async fn run_handshake<S>(
    mut stream: S,
    peer_addr: SocketAddr,
    creds: &[(String, String)],
    camouflage_host: &str,
    cam_pool: &Arc<CamouflagePool>,
    auth_ts_tolerance_secs: u64,
    pfs: bool,
) -> Option<(S, [u8; 32], [u8; 32], Option<[u8; 32]>, usize)>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    // 1 & 2. 增量读取 ClientHello (单一 5s 截止时间)
    let client_hello = match read_client_hello(&mut stream, Duration::from_secs(5)).await {
        ClientHelloReadResult::Complete(ch) => ch,
        ClientHelloReadResult::Fallback(bytes) => {
            warn!(
                "Mirage Server: abnormal pre-auth read from {} ({} bytes), reflecting to camouflage",
                peer_addr,
                bytes.len()
            );
            reflect_to_camouflage(stream, peer_addr, &bytes, camouflage_host, cam_pool).await;
            return None;
        }
        ClientHelloReadResult::Close => {
            // 对端在发送任何字节前就 EOF/报错关闭, 连接已死直接退出
            return None;
        }
    };

    let content_type = client_hello[0];
    let body = &client_hello[TLS_RECORD_HEADER_LEN..];

    // 3. Authenticate by searching for the token in session_id field.
    //
    // ClientHello body layout (RFC 8446 §4.1.2):
    //   body[0]        HandshakeType (0x01 = ClientHello)
    //   body[1..4]     uint24 body length
    //   body[4..6]     ProtocolVersion (0x0303 = TLS 1.2)
    //   body[6..38]    Random (32 bytes) ← client_random
    //   body[38]       legacy_session_id.length (1 byte)
    //   body[39..]     legacy_session_id (32 bytes for Mirage) ← token here
    // 多用户: token 对每个凭据试, 命中即认出是哪个用户 (matched_idx)。非匹配在 tag 比对处即返回
    // false 不碰 replay, 故 replay 对同一 token 仍单插 (见 hello_auth::identify_session_token)。
    let mut matched_idx: Option<usize> = None;
    let mut client_random = [0u8; 32];

    if content_type == 0x16 && body.len() >= 39 && body[0] == 0x01 {
        let sid_len = body[38] as usize;
        if sid_len == 32 && body.len() >= 39 + sid_len {
            client_random.copy_from_slice(&body[6..38]);
            let session_id = &body[39..39 + sid_len];
            let mut sid_array = [0u8; 32];
            sid_array.copy_from_slice(session_id);
            matched_idx = verify_creds_and_quota(
                creds,
                &sid_array,
                &client_random,
                auth_ts_tolerance_secs,
                crate::proxy::user_limits::is_user_exhausted,
            );
        }
    }
    let authenticated = matched_idx.is_some();

    if !authenticated {
        warn!("Mirage Server auth failed from {}", peer_addr);
        reflect_to_camouflage(stream, peer_addr, &client_hello, camouflage_host, cam_pool).await;
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
    let (template, server_random) = crate::crypto::handshake_cache::get_server_hello_pfs(
        camouflage_host,
        &client_hello,
        server_ephemeral.as_ref().map(|e| &e.public),
    )
    .await;
    // v0.15: server_random 参与会话密钥派生 (服务端新鲜性的唯一来源)。全 0 = 回放模板异常没写进
    // random —— 此时派生退化为只依赖 client_random, 重放防护失效。客户端遇全 0 会自行断开, 但攻击者
    // 扮演客户端时不会, 故服务端也必须 fail-closed。正常路径 (apply_server_random) 恒写入随机值。
    if server_random == [0u8; 32] {
        warn!("Mirage Server: ServerHello 模板未携带 random (全 0), 拒绝该连接 (fail-closed) from {}", peer_addr);
        return None;
    }

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

    // Hand off to control plane (crypto setup + TIME_SYNC + dispatch)。matched_idx 此处必 Some
    // (上方 !authenticated 已 return None), 即命中的凭据下标, 供调用方取用户名/派生密钥的 password。
    Some((stream, client_random, server_random, ecdh, matched_idx.expect("authenticated ⇒ matched_idx")))
}

/// TCP 传输入口: 握手 → into_split (Tcp 变体, 保留静态分发 + 无锁) → dispatch。
pub(super) async fn handle_connection(
    stream: TcpStream,
    peer_addr: SocketAddr,
    creds: super::CredsSnapshot,
    camouflage_host: String,
    cam_pool: Arc<CamouflagePool>,
    auth_ts_tolerance_secs: u64,
    upstream: Option<std::sync::Arc<crate::proxy::upstream::UpstreamOutlet>>,
    pfs: bool,
    allow_local_targets: bool,
) {
    stream.set_nodelay(true).unwrap_or_default();
    let client_ip = peer_addr.ip();
    let creds_snapshot = creds.load_full();
    if let Some((stream, client_random, server_random, ecdh, idx)) = run_handshake(
        stream, peer_addr, &creds_snapshot, &camouflage_host, &cam_pool, auth_ts_tolerance_secs, pfs,
    )
    .await
    {
        let (user, password) = creds_snapshot[idx].clone(); // 命中的凭据: 用户名 + 派生会话密钥的 password
        let (rh, wh) = stream.into_split();
        control::dispatch_authenticated(
            crate::proxy::tunnel::TunnelRead::Tcp(rh),
            crate::proxy::tunnel::TunnelWrite::Tcp(wh),
            Some(client_ip),
            password,
            user,
            client_random,
            server_random,
            upstream,
            ecdh,
            allow_local_targets,
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

    #[test]
    fn test_verify_creds_and_quota_exhausted_treated_as_auth_failed() {
        let creds = vec![
            ("alice".to_string(), "pwd_alice".to_string()),
            ("bob".to_string(), "pwd_bob".to_string()),
        ];
        let client_random = [42u8; 32];
        let token = crate::crypto::hello_auth::make_session_token("pwd_alice", &client_random);

        // 1. 未超额 -> 认证成功, 返回 Some(0)
        let res = verify_creds_and_quota(&creds, &token, &client_random, 60, |_| false);
        assert_eq!(res, Some(0));

        // 2. 超额 -> 返回 None (当作认证失败)
        let res_exh = verify_creds_and_quota(&creds, &token, &client_random, 60, |user| user == "alice");
        assert_eq!(res_exh, None);
    }

    #[test]
    fn test_creds_registry_hot_reload_reflects_changes() {
        let tag = "test_tag_hot_reload";
        let initial_creds = vec![
            ("default".to_string(), "main_pwd".to_string()),
            ("alice".to_string(), "alice_pwd".to_string()),
            ("bob".to_string(), "bob_pwd".to_string()),
        ];
        let store = super::super::register_creds(tag, initial_creds);

        let client_random = [11u8; 32];
        let token_alice = crate::crypto::hello_auth::make_session_token("alice_pwd", &client_random);
        let token_bob = crate::crypto::hello_auth::make_session_token("bob_pwd", &client_random);

        // 初始状态: alice 与 bob 均能通过
        let snap1 = store.load();
        assert_eq!(verify_creds_and_quota(&snap1, &token_alice, &client_random, 60, |_| false), Some(1));
        assert_eq!(verify_creds_and_quota(&snap1, &token_bob, &client_random, 60, |_| false), Some(2));

        // 热重载: 删掉 bob, 修改 alice 密码, 增加 charlie
        let new_creds = vec![
            ("default".to_string(), "main_pwd".to_string()),
            ("alice".to_string(), "alice_pwd_new".to_string()),
            ("charlie".to_string(), "charlie_pwd".to_string()),
        ];
        let updated = super::super::reload_creds(tag, new_creds);
        assert!(updated, "已注册 tag 热重载应返回 true");

        // 新快照立即生效
        let snap2 = store.load();

        // 1. 被删掉的 bob token 不再通过
        assert_eq!(
            verify_creds_and_quota(&snap2, &token_bob, &client_random, 60, |_| false),
            None,
            "删掉的用户 token 不应再通过"
        );

        // 2. alice 旧密码 token 不再通过
        assert_eq!(
            verify_creds_and_quota(&snap2, &token_alice, &client_random, 60, |_| false),
            None,
            "旧密码 token 不应再通过"
        );

        // 3. alice 新密码 token 通过
        let token_alice_new = crate::crypto::hello_auth::make_session_token("alice_pwd_new", &client_random);
        assert_eq!(
            verify_creds_and_quota(&snap2, &token_alice_new, &client_random, 60, |_| false),
            Some(1)
        );

        // 4. 新用户 charlie token 通过
        let token_charlie = crate::crypto::hello_auth::make_session_token("charlie_pwd", &client_random);
        assert_eq!(
            verify_creds_and_quota(&snap2, &token_charlie, &client_random, 60, |_| false),
            Some(2)
        );
    }

    #[tokio::test]
    async fn test_read_client_hello_http_probe_immediate_fallback() {
        let (mut client, mut server) = tokio::io::duplex(1024);
        let probe = b"GET / HTTP/1.1\r\n\r\n";
        client.write_all(probe).await.unwrap();

        let start = Instant::now();
        let res = read_client_hello(&mut server, Duration::from_secs(5)).await;
        let elapsed = start.elapsed();

        // 必须立即判定, 不等 5s 超时或后续字节
        assert!(elapsed < Duration::from_millis(500), "HTTP 探测必须立即判定回落, 实际耗时 {:?}", elapsed);
        match res {
            ClientHelloReadResult::Fallback(bytes) => {
                // 只读到判定所需的前缀, 余下字节留在流里由 camouflage 双向透传原样送达伪装站。
                assert!(probe.starts_with(&bytes) && !bytes.is_empty(), "回落字节必须是探针前缀");
                let mut rest = vec![0u8; probe.len() - bytes.len()];
                server.read_exact(&mut rest).await.unwrap();
                assert_eq!([bytes, rest].concat(), probe, "回落字节 + 流中剩余 == 探针原文, 一字不丢");
            }
            other => panic!("expected Fallback, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn test_read_client_hello_oversized_record_len_fallback() {
        let (mut client, mut server) = tokio::io::duplex(1024);
        // TLS record header: 0x16, 0x03, 0x03, len = 20000 (> 16384)
        let header = [0x16, 0x03, 0x03, 0x4e, 0x20];
        client.write_all(&header).await.unwrap();

        let res = read_client_hello(&mut server, Duration::from_secs(5)).await;
        match res {
            ClientHelloReadResult::Fallback(bytes) => {
                assert_eq!(bytes, header, "超长 record_len 必须回落且包含已读字节");
            }
            other => panic!("expected Fallback, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn test_read_client_hello_zero_record_len_fallback() {
        let (mut client, mut server) = tokio::io::duplex(1024);
        // TLS record header: 0x16, 0x03, 0x03, len = 0
        let header = [0x16, 0x03, 0x03, 0x00, 0x00];
        client.write_all(&header).await.unwrap();

        let res = read_client_hello(&mut server, Duration::from_secs(5)).await;
        match res {
            ClientHelloReadResult::Fallback(bytes) => {
                assert_eq!(bytes, header, "record_len == 0 必须回落且包含已读字节");
            }
            other => panic!("expected Fallback, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn test_read_client_hello_partial_body_timeout_fallback() {
        let (mut client, mut server) = tokio::io::duplex(1024);
        // header: 0x16, 0x03, 0x03, len = 100
        let mut data = vec![0x16, 0x03, 0x03, 0x00, 0x64];
        // body 发 40 字节 (不足 100 字节), client 停顿保持连接开启
        data.extend(vec![0xAA; 40]);
        client.write_all(&data).await.unwrap();

        let res = read_client_hello(&mut server, Duration::from_millis(50)).await;
        match res {
            ClientHelloReadResult::Fallback(bytes) => {
                assert_eq!(bytes, data, "超时后回落字节必须 == 已发送的全部字节 (头+半个体)");
            }
            other => panic!("expected Fallback, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn test_read_client_hello_legitimate_complete() {
        let (mut client, mut server) = tokio::io::duplex(1024);
        // header: 0x16, 0x03, 0x01, len = 150
        let mut ch = vec![0x16, 0x03, 0x01, 0x00, 0x96];
        ch.extend(vec![0xBB; 150]);
        client.write_all(&ch).await.unwrap();

        let res = read_client_hello(&mut server, Duration::from_secs(5)).await;
        match res {
            ClientHelloReadResult::Complete(bytes) => {
                assert_eq!(bytes, ch, "合法 ClientHello 必须完整读出且返回 Complete");
            }
            other => panic!("expected Complete, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn test_read_client_hello_does_not_overread_past_record() {
        let (mut client, mut server) = tokio::io::duplex(1024);
        let mut ch = vec![0x16, 0x03, 0x01, 0x00, 0x10];
        ch.extend(vec![0xBB; 16]);
        let mut sent = ch.clone();
        sent.extend_from_slice(b"TRAILING"); // 紧随其后的管道化字节
        client.write_all(&sent).await.unwrap();

        let res = read_client_hello(&mut server, Duration::from_secs(5)).await;
        assert_eq!(res, ClientHelloReadResult::Complete(ch), "只读首个 record, 不吞后续字节");
        let mut rest = [0u8; 8];
        server.read_exact(&mut rest).await.unwrap();
        assert_eq!(&rest, b"TRAILING", "后续字节必须留在流里");
    }

    #[tokio::test]
    async fn test_read_client_hello_zero_bytes_eof_closes() {
        let (client, mut server) = tokio::io::duplex(1024);
        drop(client); // 0 字节立即断开
        let res = read_client_hello(&mut server, Duration::from_secs(5)).await;
        assert_eq!(res, ClientHelloReadResult::Close, "未发送任何字节即 EOF 应返回 Close");
    }

    #[tokio::test]
    async fn test_read_client_hello_zero_bytes_timeout_fallback() {
        let (_client, mut server) = tokio::io::duplex(1024);
        // 0 字节连接挂起超时
        let res = read_client_hello(&mut server, Duration::from_millis(50)).await;
        match res {
            ClientHelloReadResult::Fallback(bytes) => {
                assert!(bytes.is_empty(), "0 字节超时应交出空字节交由伪装站超时接管");
            }
            other => panic!("expected Fallback, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn test_run_handshake_authenticated_success_over_duplex() {
        let (mut client, server) = tokio::io::duplex(8192);
        let password = "test_handshake_pwd";
        let creds = vec![("default".to_string(), password.to_string())];
        let peer_addr: SocketAddr = "127.0.0.1:12345".parse().unwrap();
        let pool = CamouflagePool::new("example.com".to_string());

        let client_random = [0x55u8; 32];
        let token = crate::crypto::hello_auth::make_session_token(password, &client_random);

        // 构造能够通过认证的合法 ClientHello
        let mut hs = vec![0x01, 0x00, 0x00, 0x00]; // type ClientHello + 3B len
        hs.extend_from_slice(&[0x03, 0x03]); // version
        hs.extend_from_slice(&client_random); // random
        hs.push(32); // sid_len
        hs.extend_from_slice(&token); // session_id
        hs.extend_from_slice(&2u16.to_be_bytes()); // cipher_len
        hs.extend_from_slice(&[0x13, 0x01]); // cipher
        hs.extend_from_slice(&[0x01, 0x00]); // compression
        hs.extend_from_slice(&[0x00, 0x00]); // extensions len = 0
        let body_len = (hs.len() - 4) as u32;
        hs[1..4].copy_from_slice(&body_len.to_be_bytes()[1..4]);

        let mut ch_record = vec![0x16, 0x03, 0x01];
        ch_record.extend_from_slice(&(hs.len() as u16).to_be_bytes());
        ch_record.extend_from_slice(&hs);

        let server_task = tokio::spawn(async move {
            run_handshake(server, peer_addr, &creds, "example.com", &pool, 60, false).await
        });

        // 客户端发送 ClientHello
        client.write_all(&ch_record).await.unwrap();

        // 客户端读取服务端回显模板 (直到集齐 0x16, 0x14, 0x17)
        let mut resp_buf = vec![0u8; 4096];
        let n = client.read(&mut resp_buf).await.unwrap();
        assert!(n > 0, "服务端必须返回 ServerHello 模板");

        // 客户端发送 64B fake client finished tail
        let tail = [0xAAu8; 64];
        client.write_all(&tail).await.unwrap();

        let handshake_res = server_task.await.unwrap();
        assert!(handshake_res.is_some(), "合法 ClientHello 必须握手成功");
        let (_stream, c_rand, s_rand, _ecdh, idx) = handshake_res.unwrap();
        assert_eq!(idx, 0, "命中的凭据下标为 0");
        assert_eq!(c_rand, client_random);
        assert_ne!(s_rand, [0u8; 32], "server_random 必须有效写入");
    }
}
