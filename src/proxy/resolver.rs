//! 直连目标的智能连接: DNS 缓存 + prefer-IPv4 + 每尝试超时.
//!
//! v0.4.5-alpha.8: 修国内直连延迟. 客户端常跑在 musl libc (Alpine) 环境, 无
//! nscd/systemd-resolved DNS 缓存, `TcpStream::connect(域名)` 每次连接都走一次
//! 完整 getaddrinfo (实测 ~120ms, GSLB/CDN 域名更慢). 一个页面 200 子请求累积
//! 秒级延迟. 且 tokio connect 顺序试地址无 Happy-Eyeballs, IPv6 受限网络会 hang
//! 在 v6 尝试上.
//!
//! 修法:
//! - 域名解析结果按 TTL 缓存 (60s), 重复访问 0 解析开销
//! - IPv4 优先排序, 受限 IPv6 网络不会 hang 在 v6
//! - 每个候选地址独立 3s 连接超时, 单个坏地址不拖垮整体
//! - target 本身就是 IP 时直接连, 不碰缓存/解析

use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::atomic::{AtomicU16, Ordering};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

const DNS_CACHE_TTL: Duration = Duration::from_secs(60);
const PER_ATTEMPT_TIMEOUT: Duration = Duration::from_secs(3);
/// 缓存容量上限. 超过时清理过期项; 仍超过则整体清空 (粗暴但有界, 家用/网关
/// 域名基数不会持续爆这个数).
const CACHE_MAX_ENTRIES: usize = 8192;
/// 全局并发 DNS 解析上限. tokio lookup_host 走 spawn_blocking 阻塞池 (默认 512
/// 线程). UDP 转发场景若遭唯一域名洪泛 (每包不同随机域名, 缓存无效), 会瞬间打满
/// 阻塞池饿死其他任务 (文件 IO / 其他 TCP 解析). 用信号量把并发解析封顶 128,
/// 洪泛时新解析排队等待而非无限 spawn, 给阻塞池留 384 线程给别的活.
const DNS_MAX_CONCURRENT: usize = 128;

/// DNS-over-TCP 探测超时 (连接 + 收发)。
const DNS_TCP_TIMEOUT: Duration = Duration::from_secs(5);

/// 可选的 DNS-over-TCP 上游。设了 (服务端 `tuning.dns_tcp_resolver`) 则**所有域名解析走
/// 它、经 TCP:53 查**, 不再用系统 getaddrinfo (glibc 默认 UDP)。用于 UDP 出向被封的 VPS ——
/// 否则 getaddrinfo 用 UDP 查 DNS, 封 UDP 就解析不了代理目标域名。启动时 set 一次, 不热重载。
static TCP_RESOLVER: OnceLock<SocketAddr> = OnceLock::new();

/// 设置 DNS-over-TCP 上游 (启动时调用一次)。已设过则忽略 (返回 false)。
pub fn set_tcp_resolver(addr: SocketAddr) -> bool {
    TCP_RESOLVER.set(addr).is_ok()
}

fn tcp_resolver() -> Option<SocketAddr> {
    TCP_RESOLVER.get().copied()
}

struct CacheEntry {
    ips: Vec<IpAddr>,
    expiry: Instant,
}

fn dns_cache() -> &'static Mutex<HashMap<String, CacheEntry>> {
    static CACHE: OnceLock<Mutex<HashMap<String, CacheEntry>>> = OnceLock::new();
    CACHE.get_or_init(|| Mutex::new(HashMap::new()))
}

fn dns_semaphore() -> &'static tokio::sync::Semaphore {
    static SEM: OnceLock<tokio::sync::Semaphore> = OnceLock::new();
    SEM.get_or_init(|| tokio::sync::Semaphore::new(DNS_MAX_CONCURRENT))
}

/// 解析 host → Vec<IpAddr>, 命中缓存则 0 网络开销. 返回的 Vec 已经 IPv4 优先排序.
async fn resolve_cached(host: &str, port: u16) -> io::Result<Vec<IpAddr>> {
    // 1. 查缓存
    if let Ok(cache) = dns_cache().lock() {
        if let Some(entry) = cache.get(host) {
            if entry.expiry > Instant::now() {
                return Ok(entry.ips.clone());
            }
        }
    }

    // 2. miss / 过期 → 解析. 先拿信号量封顶并发, 防洪泛打满阻塞池. permit 解析完即释放.
    //    配了 dns_tcp_resolver 则走 DNS-over-TCP (UDP 被封的 VPS 用); 否则系统 getaddrinfo.
    let _permit = dns_semaphore().acquire().await.ok();
    let mut ips: Vec<IpAddr> = match tcp_resolver() {
        Some(upstream) => resolve_via_tcp(host, upstream).await?,
        None => tokio::net::lookup_host((host, port))
            .await?
            .map(|sa| sa.ip())
            .collect(),
    };

    if ips.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("no addresses resolved for {host}"),
        ));
    }

    // 3. IPv4 优先 (受限 IPv6 网络不 hang 在 v6). stable sort 保留同族内原顺序.
    ips.sort_by_key(|ip| if ip.is_ipv4() { 0 } else { 1 });

    // 4. 写缓存
    if let Ok(mut cache) = dns_cache().lock() {
        if cache.len() >= CACHE_MAX_ENTRIES {
            let now = Instant::now();
            cache.retain(|_, e| e.expiry > now);
            if cache.len() >= CACHE_MAX_ENTRIES {
                cache.clear();
            }
        }
        cache.insert(
            host.to_string(),
            CacheEntry {
                ips: ips.clone(),
                expiry: Instant::now() + DNS_CACHE_TTL,
            },
        );
    }

    Ok(ips)
}

/// 解析 "host:port" 为 (host, port). 支持 IPv6 字面量 "[::1]:443".
fn split_host_port(target: &str) -> Option<(&str, u16)> {
    let parts: Vec<&str> = target.rsplitn(2, ':').collect();
    if parts.len() != 2 {
        return None;
    }
    let port: u16 = parts[0].parse().ok()?;
    let mut host = parts[1];
    if host.starts_with('[') && host.ends_with(']') {
        host = &host[1..host.len() - 1];
    }
    Some((host, port))
}

/// 解析 host+port 为**首选** SocketAddr (IPv4 优先). host 是 IP 字面量则直接构造
/// 不解析; 是域名则走 60s 缓存 + 并发限流. 供无连接场景 (UDP 转发) 用 —— 让服务端
/// UDP relay 遇域名也享受缓存 + 洪泛防护, 不再每包裸调 lookup_host 打满阻塞池.
pub(crate) async fn resolve_first(host: &str, port: u16) -> io::Result<SocketAddr> {
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Ok(SocketAddr::new(ip, port));
    }
    let ips = resolve_cached(host, port).await?;
    ips.into_iter()
        .next()
        .map(|ip| SocketAddr::new(ip, port))
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, format!("no address for {host}")))
}

/// 智能连接 "host:port". host 是 IP 字面量则直连; 是域名则走缓存解析 +
/// IPv4 优先 + 每尝试超时. 返回首个连上的 TcpStream.
pub async fn connect_smart(target: &str) -> io::Result<TcpStream> {
    let (host, port) = split_host_port(target).ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidInput, format!("bad target: {target}"))
    })?;

    // host 已是 IP → 直连, 不解析不缓存 (对应日志里 target=180.101.49.44:443, connect 6ms)
    // 超时和域名路径一致: 少了这个就只能等内核的 TCP 重传超时 (~130s), 被墙/黑洞的
    // 裸 IP 目的地会把这条连接吊死两分钟。
    if let Ok(ip) = host.parse::<IpAddr>() {
        let addr = SocketAddr::new(ip, port);
        return match tokio::time::timeout(PER_ATTEMPT_TIMEOUT, TcpStream::connect(addr)).await {
            Ok(r) => r,
            Err(_) => Err(io::Error::new(
                io::ErrorKind::TimedOut,
                format!("connect {addr} timed out after {}s", PER_ATTEMPT_TIMEOUT.as_secs()),
            )),
        };
    }

    // 域名 → 缓存解析 + 候选逐一试
    let ips = resolve_cached(host, port).await?;
    let mut last_err: Option<io::Error> = None;
    for ip in ips {
        let addr = SocketAddr::new(ip, port);
        match tokio::time::timeout(PER_ATTEMPT_TIMEOUT, TcpStream::connect(addr)).await {
            Ok(Ok(s)) => return Ok(s),
            Ok(Err(e)) => last_err = Some(e),
            Err(_) => {
                last_err = Some(io::Error::new(
                    io::ErrorKind::TimedOut,
                    format!("connect {addr} timed out after {}s", PER_ATTEMPT_TIMEOUT.as_secs()),
                ))
            }
        }
    }
    Err(last_err.unwrap_or_else(|| {
        io::Error::new(io::ErrorKind::AddrNotAvailable, format!("all addresses failed for {host}"))
    }))
}

// ── DNS-over-TCP 解析 (tuning.dns_tcp_resolver, UDP 被封的 VPS 用) ─────────────

/// 经 TCP 向 upstream 查 host 的 A + AAAA, 合并返回。与 getaddrinfo 双栈行为对齐
/// (后续 resolve_cached 会 IPv4 优先排序)。两族并发查, 任一有结果即可用。
async fn resolve_via_tcp(host: &str, upstream: SocketAddr) -> io::Result<Vec<IpAddr>> {
    let (ra, raaaa) = tokio::join!(
        query_one(host, 1, upstream),   // A
        query_one(host, 28, upstream),  // AAAA
    );
    let mut ips = Vec::new();
    // 保留真实错误: 两族都失败时 (超时/连不上/域名非法) 把最后一个真错误抛出, 便于诊断
    // 死/错配的 dns_tcp_resolver, 而非一律吞成通用 NotFound。
    let mut last_err = None;
    match ra {
        Ok(v) => ips.extend(v),
        Err(e) => last_err = Some(e),
    }
    match raaaa {
        Ok(v) => ips.extend(v),
        Err(e) => last_err = Some(e),
    }
    if ips.is_empty() {
        return Err(last_err.unwrap_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                format!("DNS-over-TCP: {host} 无 A/AAAA 记录 (上游 {upstream})"),
            )
        }));
    }
    Ok(ips)
}

/// 一次 DNS-over-TCP 查询 (RFC 7766: 连接 → [2B 长度][报文] → 收 [2B 长度][响应])。
async fn query_one(host: &str, qtype: u16, upstream: SocketAddr) -> io::Result<Vec<IpAddr>> {
    let query = build_dns_query(host, qtype)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, format!("非法域名: {host}")))?;
    // TXID 在 query 头 2 字节 (build_dns_query 生成), 收响应时用它校验 ID 防串号/注入。
    let tx = u16::from_be_bytes([query[0], query[1]]);
    let fut = async {
        let mut s = TcpStream::connect(upstream).await?;
        let mut framed = (query.len() as u16).to_be_bytes().to_vec();
        framed.extend_from_slice(&query);
        s.write_all(&framed).await?;
        let mut len_buf = [0u8; 2];
        s.read_exact(&mut len_buf).await?;
        let n = u16::from_be_bytes(len_buf) as usize;
        let mut resp = vec![0u8; n];
        s.read_exact(&mut resp).await?;
        Ok::<_, io::Error>(parse_answer_ips(&resp, tx))
    };
    tokio::time::timeout(DNS_TCP_TIMEOUT, fut)
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, format!("DNS-over-TCP {upstream} 超时")))?
}

/// 构造一个标准 DNS 查询报文 (RD=1, QDCOUNT=1, 单问题)。域名 label 空或 >63 → None。
fn build_dns_query(host: &str, qtype: u16) -> Option<Vec<u8>> {
    static TXID: AtomicU16 = AtomicU16::new(1);
    let tx = TXID.fetch_add(1, Ordering::Relaxed);
    let mut q = Vec::with_capacity(host.len() + 18);
    q.extend_from_slice(&tx.to_be_bytes());
    q.extend_from_slice(&[0x01, 0x00]); // flags: RD=1
    q.extend_from_slice(&[0x00, 0x01]); // QDCOUNT=1
    q.extend_from_slice(&[0, 0, 0, 0, 0, 0]); // AN/NS/AR=0
    for label in host.trim_end_matches('.').split('.') {
        if label.is_empty() || label.len() > 63 {
            return None;
        }
        q.push(label.len() as u8);
        q.extend_from_slice(label.as_bytes());
    }
    q.push(0); // root label
    q.extend_from_slice(&qtype.to_be_bytes());
    q.extend_from_slice(&[0x00, 0x01]); // QCLASS=IN
    // TCP DNS 长度前缀是 u16: 报文超 65535 则前缀会截断、与实际字节错位。真实域名远不及此,
    // 但畸形超长 host 得拦住, 否则帧错位。
    if q.len() > u16::MAX as usize {
        return None;
    }
    Some(q)
}

/// 从 DNS 响应的 answer 段抽出 A/AAAA 记录的 IP。畸形/截断即尽力而止 (返回已解出的)。
/// 名字压缩指针只跳过不追 (取 rdata 不需要解名), 故不会有指针环。
///
/// `expect_tx` = 发出查询时的 TXID。响应 ID 不匹配、或 QR 位非响应 → 视为伪造/串号,
/// 返回空 (不缓存)。防注入响应把别的域名的 A 记录污进本域名 (对齐 dns/server.rs、
/// wg/dns.rs 的校验; 这条最常用的 UDP-relay 解析路径此前漏检)。
fn parse_answer_ips(resp: &[u8], expect_tx: u16) -> Vec<IpAddr> {
    let mut ips = Vec::new();
    if resp.len() < 12 {
        return ips;
    }
    // TXID 必须与查询一致, 且 QR=1 (bit 15 of flags) 是响应。
    if u16::from_be_bytes([resp[0], resp[1]]) != expect_tx || (resp[2] & 0x80) == 0 {
        return ips;
    }
    let qd = u16::from_be_bytes([resp[4], resp[5]]) as usize;
    let an = u16::from_be_bytes([resp[6], resp[7]]) as usize;
    let mut pos = 12;
    for _ in 0..qd {
        pos = skip_name(resp, pos);
        pos += 4; // QTYPE + QCLASS
    }
    for _ in 0..an {
        pos = skip_name(resp, pos);
        if pos + 10 > resp.len() {
            break;
        }
        let rtype = u16::from_be_bytes([resp[pos], resp[pos + 1]]);
        let rdlen = u16::from_be_bytes([resp[pos + 8], resp[pos + 9]]) as usize;
        pos += 10;
        if pos + rdlen > resp.len() {
            break;
        }
        match (rtype, rdlen) {
            (1, 4) => ips.push(IpAddr::V4(Ipv4Addr::new(
                resp[pos], resp[pos + 1], resp[pos + 2], resp[pos + 3],
            ))),
            (28, 16) => {
                let mut o = [0u8; 16];
                o.copy_from_slice(&resp[pos..pos + 16]);
                ips.push(IpAddr::V6(Ipv6Addr::from(o)));
            }
            _ => {}
        }
        pos += rdlen;
    }
    ips
}

/// 跳过一个 DNS 名字, 返回其后位置。压缩指针 (0xC0) = 2 字节即止, 不追 (只求跳过)。
fn skip_name(buf: &[u8], mut pos: usize) -> usize {
    while pos < buf.len() {
        let len = buf[pos];
        if len == 0 {
            return pos + 1;
        }
        if len & 0xC0 == 0xC0 {
            return pos + 2; // 指针占 2 字节, 名字到此结束
        }
        pos += 1 + len as usize;
    }
    pos
}

#[cfg(test)]
mod dns_tcp_tests {
    use super::*;

    #[test]
    fn build_query_shape() {
        let q = build_dns_query("example.com", 1).unwrap();
        // header 12B: flags RD=1, QDCOUNT=1
        assert_eq!(&q[2..4], &[0x01, 0x00]);
        assert_eq!(&q[4..6], &[0x00, 0x01]);
        // question: 7"example" 3"com" 0 + QTYPE(A=1) + QCLASS(IN=1)
        assert_eq!(q[12], 7);
        assert_eq!(&q[13..20], b"example");
        assert_eq!(q[20], 3);
        assert_eq!(&q[21..24], b"com");
        assert_eq!(q[24], 0);
        assert_eq!(&q[25..29], &[0x00, 0x01, 0x00, 0x01]);
        // 非法域名
        assert!(build_dns_query("", 1).is_none());
        assert!(build_dns_query(&"x".repeat(64), 1).is_none());
    }

    #[test]
    fn parse_answers_a_and_aaaa() {
        // header: tx=0x1234, QR=1, QD=1, AN=2
        let mut r = vec![0x12, 0x34, 0x81, 0x80, 0, 1, 0, 2, 0, 0, 0, 0];
        // question: 1"a" 3"com" 0 A IN
        r.push(1); r.push(b'a'); r.push(3); r.extend_from_slice(b"com"); r.push(0);
        r.extend_from_slice(&[0, 1, 0, 1]);
        // answer 1: name ptr(0xC00C) A IN ttl rdlen=4 1.2.3.4
        r.extend_from_slice(&[0xC0, 0x0C, 0x00, 0x01, 0x00, 0x01, 0, 0, 1, 44, 0, 4, 1, 2, 3, 4]);
        // answer 2: name ptr AAAA rdlen=16 ::1
        r.extend_from_slice(&[0xC0, 0x0C, 0x00, 0x1C, 0x00, 0x01, 0, 0, 1, 44, 0, 16]);
        r.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        let ips = parse_answer_ips(&r, 0x1234);
        assert_eq!(ips.len(), 2);
        assert_eq!(ips[0], "1.2.3.4".parse::<IpAddr>().unwrap());
        assert_eq!(ips[1], "::1".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn parse_rejects_txid_mismatch() {
        // 与上同报文 (tx=0x1234, 含合法 A/AAAA), 但期望 tx=0x9999 → 视为注入/串号, 返回空。
        let mut r = vec![0x12, 0x34, 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0];
        r.push(1); r.push(b'a'); r.push(3); r.extend_from_slice(b"com"); r.push(0);
        r.extend_from_slice(&[0, 1, 0, 1]);
        r.extend_from_slice(&[0xC0, 0x0C, 0x00, 0x01, 0x00, 0x01, 0, 0, 1, 44, 0, 4, 1, 2, 3, 4]);
        assert!(parse_answer_ips(&r, 0x9999).is_empty()); // ID 不匹配
        assert_eq!(parse_answer_ips(&r, 0x1234).len(), 1); // ID 匹配则正常解出
    }

    #[test]
    fn parse_rejects_non_response_qr() {
        // tx 匹配但 QR=0 (查询而非响应, flags 高位 0) → 拒。
        let mut r = vec![0x12, 0x34, 0x01, 0x00, 0, 1, 0, 1, 0, 0, 0, 0];
        r.push(1); r.push(b'a'); r.push(3); r.extend_from_slice(b"com"); r.push(0);
        r.extend_from_slice(&[0, 1, 0, 1]);
        r.extend_from_slice(&[0xC0, 0x0C, 0x00, 0x01, 0x00, 0x01, 0, 0, 1, 44, 0, 4, 1, 2, 3, 4]);
        assert!(parse_answer_ips(&r, 0x1234).is_empty());
    }

    #[test]
    fn parse_ignores_cname_and_truncation() {
        // AN=1 但 rdata 截断 → 尽力而止, 不 panic, 返回空。tx=0 匹配 + QR=1。
        let mut r = vec![0, 0, 0x81, 0x80, 0, 0, 0, 1, 0, 0, 0, 0];
        r.extend_from_slice(&[0xC0, 0x0C, 0x00, 0x01, 0x00, 0x01, 0, 0, 1, 44, 0, 4, 1, 2]); // rdlen=4 但只剩 2B
        assert!(parse_answer_ips(&r, 0).is_empty());
    }

    // 真实网络: DNS-over-TCP 对 1.1.1.1 解析已知域名。默认 ignore (CI 无出口时不挂),
    // 手动跑: cargo test --lib resolver::dns_tcp_tests::real -- --ignored --nocapture
    #[tokio::test]
    #[ignore]
    async fn real_resolve_via_tcp_1111() {
        let up = "1.1.1.1:53".parse().unwrap();
        let ips = resolve_via_tcp("example.com", up).await.expect("应解出 IP");
        println!("example.com via TCP 1.1.1.1 → {ips:?}");
        assert!(ips.iter().any(|ip| ip.is_ipv4()), "至少一个 A 记录");
    }
}

#[cfg(test)]
mod prop_tests {
    //! 模糊/属性测试: 任意字节 + 任意 TXID 喂给 DNS 应答解析器, **绝不 panic**
    //! (偏移遍历 / name 压缩指针 / rdlen 全部要边界安全)。
    use super::parse_answer_ips;
    use proptest::prelude::*;

    proptest! {
        // 纯随机字节 (浅层)。
        #[test]
        fn parse_answer_ips_raw_never_panics(data: Vec<u8>, tx: u16) {
            let _ = parse_answer_ips(&data, tx);
        }

        // 构造合规 12B 头 (匹配 tx + QR=1) + 小 QD/AN 计数 + 随机 rdata, 钻进 question/answer
        // 循环 (skip_name 压缩指针 / rtype / rdlen 偏移全部要边界安全)。
        #[test]
        fn parse_answer_ips_structured_never_panics(
            tx: u16,
            qd in 0u8..3,
            an in 0u8..8,
            rest in prop::collection::vec(any::<u8>(), 0..200),
        ) {
            let mut msg = Vec::new();
            msg.extend_from_slice(&tx.to_be_bytes());
            msg.extend_from_slice(&[0x81, 0x80]); // flags: QR=1
            msg.extend_from_slice(&(qd as u16).to_be_bytes());
            msg.extend_from_slice(&(an as u16).to_be_bytes());
            msg.extend_from_slice(&[0, 0, 0, 0]); // NS/AR = 0
            msg.extend_from_slice(&rest);
            let _ = parse_answer_ips(&msg, tx);
        }
    }
}
