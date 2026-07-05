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
use std::net::{IpAddr, SocketAddr};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};
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

    // 2. miss / 过期 → getaddrinfo (tokio 阻塞池). 先拿信号量封顶并发, 防洪泛
    //    打满阻塞池. permit 在解析完成即释放.
    let _permit = dns_semaphore().acquire().await.ok();
    let mut ips: Vec<IpAddr> = tokio::net::lookup_host((host, port))
        .await?
        .map(|sa| sa.ip())
        .collect();

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
    if let Ok(ip) = host.parse::<IpAddr>() {
        return TcpStream::connect(SocketAddr::new(ip, port)).await;
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
