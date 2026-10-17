//! 用户态流量整形 (token bucket) —— 按源 IP 限 TCP relay 字节流带宽。
//!
//! 客户端侧 = 按 LAN 设备 (源 IP) 限速; 服务端侧 = 按连接的客户端 (其源 IP) 限速。两侧共用
//! `routing.device_profiles` 的 `source_ip_cidr` + `rate_limit_kbps` 配置 (服务端的"设备"= 连来的
//! 客户端)。**整形非丢包**: 令牌不足就 `await` 到够, 靠 TCP 背压自然把发送端拖慢 (对 relay 上/下行
//! 各一个独立桶, 同一源 IP 的全部连接**共享**该 IP 的桶 = 聚合限速)。仅 TCP (UDP 后续)。

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use ipnet::IpNet;

/// 单向令牌桶 (字节)。`rate` = 限速 (bytes/s), `burst` = 桶容量 (突发上限)。
pub struct TokenBucket {
    inner: Mutex<BucketState>,
    pub rate: f64,
    pub burst: f64,
}

struct BucketState {
    tokens: f64,
    last: Instant,
}

impl TokenBucket {
    pub fn new(rate_bytes_per_sec: u64) -> Self {
        let rate = rate_bytes_per_sec.max(1) as f64;
        // burst = 0.5s 的量 (下限 64KB): 太小会让单个 64KB relay 块每次都要等、吞吐抖动; 太大突发穿透。
        let burst = (rate * 0.5).max(65536.0);
        Self {
            inner: Mutex::new(BucketState { tokens: burst, last: Instant::now() }),
            rate,
            burst,
        }
    }

    /// 消费 `n` 字节: 令牌不足则算出需等多久, sleep 后重试, 直到扣够。整形式 (调用方在 relay 泵里
    /// await 它 → 停止 read/recv → TCP 背压减速)。`n` 可大于 burst (多睡几轮)。
    pub async fn consume(&self, n: usize) {
        let mut need = n as f64;
        loop {
            let wait = {
                let mut s = self.inner.lock().unwrap_or_else(|e| e.into_inner());
                let now = Instant::now();
                let elapsed = now.duration_since(s.last).as_secs_f64();
                s.last = now;
                s.tokens = (s.tokens + elapsed * self.rate).min(self.burst);
                if s.tokens >= need {
                    s.tokens -= need;
                    return;
                }
                let deficit = need - s.tokens;
                s.tokens = 0.0;
                need = deficit;
                Duration::from_secs_f64(deficit / self.rate)
            };
            tokio::time::sleep(wait).await;
        }
    }

    /// 非阻塞消费 (policing): 令牌够则扣掉返 true; 不够**不扣**返 false (调用方丢包)。
    /// 用于 UDP —— UDP 无背压, 不能 await 整形 (会加延迟/乱序), 只能超速即丢 (同 tc police)。
    /// 单个 UDP 报文 ≤ 64KB ≤ burst, 不会因"包比桶大"永久丢。
    pub fn try_consume(&self, n: usize) -> bool {
        let mut s = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let now = Instant::now();
        let elapsed = now.duration_since(s.last).as_secs_f64();
        s.last = now;
        s.tokens = (s.tokens + elapsed * self.rate).min(self.burst);
        if s.tokens >= n as f64 {
            s.tokens -= n as f64;
            true
        } else {
            false
        }
    }
}

/// 某源 IP 或用户的上/下行桶对 (跨该 IP 或该用户全部连接共享)。
pub struct DeviceBuckets {
    pub up: TokenBucket,
    pub down: TokenBucket,
}

impl DeviceBuckets {
    pub fn new(rate_bytes_per_sec: u64) -> Self {
        Self {
            up: TokenBucket::new(rate_bytes_per_sec),
            down: TokenBucket::new(rate_bytes_per_sec),
        }
    }
}

/// 同时消费两对桶中的单侧 (如客户端 IP 桶 + 用户桶)。
/// 只有当两个存在的桶都有足够令牌时才同时扣除 (取更严, 互不泄露)。
/// 若其中任一桶令牌不足, 返回 false 且不扣除任何一桶的令牌。
pub fn try_consume_two(b1: Option<&TokenBucket>, b2: Option<&TokenBucket>, n: usize) -> bool {
    match (b1, b2) {
        (None, None) => true,
        (Some(b), None) | (None, Some(b)) => b.try_consume(n),
        (Some(b1), Some(b2)) => {
            let mut s1 = b1.inner.lock().unwrap_or_else(|e| e.into_inner());
            let mut s2 = b2.inner.lock().unwrap_or_else(|e| e.into_inner());
            let now = Instant::now();

            let elapsed1 = now.duration_since(s1.last).as_secs_f64();
            s1.last = now;
            s1.tokens = (s1.tokens + elapsed1 * b1.rate).min(b1.burst);

            let elapsed2 = now.duration_since(s2.last).as_secs_f64();
            s2.last = now;
            s2.tokens = (s2.tokens + elapsed2 * b2.rate).min(b2.burst);

            let need = n as f64;
            if s1.tokens >= need && s2.tokens >= need {
                s1.tokens -= need;
                s2.tokens -= need;
                true
            } else {
                false
            }
        }
    }
}

/// live 表最大容量 (源 IP 桶数上限, 与 monitor.rs 风格一致)。
const RATE_LIMIT_CAP: usize = 4096;

struct LiveBucketEntry {
    buckets: Arc<DeviceBuckets>,
    last: Instant,
}

/// 按源 IP 限速器。从 `device_profiles` 建 (CIDR 网段 → 限速 bytes/s), 运行时按源 IP 懒建共享桶。
pub struct RateLimiter {
    /// (网段, bytes/s)。**首命中**生效 (对齐 device_profiles 首命中语义)。空 = 全局不限速。
    cidrs: Vec<(IpNet, u64)>,
    /// 源 IP → 共享桶 (懒建)。
    live: Mutex<HashMap<IpAddr, LiveBucketEntry>>,
    /// 表满且所有条目都有活跃连接时, 新 IP 按命中网段共用的溢出桶 (速率 = 该网段限速)。
    /// 不挤掉别人的活跃条目: 否则被挤掉的 IP 下个连接拿新桶, 与旧连接的旧桶各算各的 → 速率翻倍。
    overflow: Mutex<HashMap<IpNet, Arc<DeviceBuckets>>>,
}

impl RateLimiter {
    /// 从 device_profiles 的 (source_ip_cidr, rate_limit_kbps) 建。裸 IP 自动补 /32÷/128
    /// (对齐 config_watcher 里 source_ip_cidr 的解析)。kbps→bytes/s = ×1000÷8 = ×125。
    pub fn from_device_profiles(dps: &[crate::config::DeviceProfile]) -> Self {
        let mut cidrs = Vec::new();
        for dp in dps {
            let Some(kbps) = dp.rate_limit_kbps.filter(|&k| k > 0) else { continue };
            let bytes_per_sec = kbps.saturating_mul(125);
            for s in &dp.source_ip_cidr {
                let net = s.parse::<IpNet>().ok().or_else(|| {
                    s.parse::<IpAddr>()
                        .ok()
                        .and_then(|ip| IpNet::new(ip, if ip.is_ipv4() { 32 } else { 128 }).ok())
                });
                if let Some(net) = net {
                    cidrs.push((net, bytes_per_sec));
                }
            }
        }
        Self { cidrs, live: Mutex::new(HashMap::new()), overflow: Mutex::new(HashMap::new()) }
    }

    /// 热重载用: 按新配置建, 并沿用旧限速器里**限速未变**的活跃桶 (与用户配额热重载同理)。
    ///
    /// 桶在连接建立时取得; 若热重载换成全新的表, 已有连接留着旧桶、新连接拿新桶, 同一 IP 两个桶各自放行
    /// → 速率翻倍, 且每次热重载再叠一代。限速变了的 IP 才换新桶 (其已有连接按旧速率跑到断开)。
    pub fn rebuild_from(dps: &[crate::config::DeviceProfile], old: Option<&RateLimiter>) -> Self {
        let new = Self::from_device_profiles(dps);
        let Some(old) = old else { return new };
        {
            let old_live = old.live.lock().unwrap_or_else(|e| e.into_inner());
            let mut live = new.live.lock().unwrap_or_else(|e| e.into_inner());
            for (ip, e) in old_live.iter() {
                if new.resolve(*ip).is_some_and(|(_, r)| e.buckets.up.rate as u64 == r) {
                    live.insert(*ip, LiveBucketEntry { buckets: e.buckets.clone(), last: e.last });
                }
            }
        }
        {
            let old_of = old.overflow.lock().unwrap_or_else(|e| e.into_inner());
            let mut of = new.overflow.lock().unwrap_or_else(|e| e.into_inner());
            for (net, b) in old_of.iter() {
                if new.cidrs.iter().any(|(n, r)| n == net && b.up.rate as u64 == *r) {
                    of.insert(*net, b.clone());
                }
            }
        }
        new
    }

    /// 全局无任何限速配置 → 可在热路径上直接跳过。
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.cidrs.is_empty()
    }

    /// 源 IP 命中的 (网段, 限速 bytes/s); 未命中 → None。首个匹配网段生效。
    fn resolve(&self, ip: IpAddr) -> Option<(IpNet, u64)> {
        self.cidrs.iter().find(|(net, _)| net.contains(&ip)).copied()
    }

    /// 取某源 IP 的共享桶对; 该 IP 无限速配置 → None (调用方跳过整形)。
    pub fn buckets_for(&self, ip: IpAddr) -> Option<Arc<DeviceBuckets>> {
        if self.cidrs.is_empty() {
            return None;
        }
        let (net, rate) = self.resolve(ip)?;
        let mut live = self.live.lock().unwrap_or_else(|e| e.into_inner());
        let now = Instant::now();

        if let Some(entry) = live.get_mut(&ip) {
            entry.last = now;
            return Some(entry.buckets.clone());
        }

        if live.len() >= RATE_LIMIT_CAP {
            // 满 + 新 IP: 只淘汰无活跃连接 (strong_count <= 1, 仅表本身持有) 中最久未活跃的一条。
            // 全部都有活跃连接时不挤掉任何条目, 新 IP 改用该网段的溢出共享桶 (偏严: 只会更慢, 不会超限)。
            let evict_key = live
                .iter()
                .filter(|(_, e)| Arc::strong_count(&e.buckets) <= 1)
                .min_by_key(|(_, e)| e.last)
                .map(|(k, _)| *k);
            match evict_key {
                Some(k) => {
                    live.remove(&k);
                }
                None => {
                    drop(live);
                    let mut of = self.overflow.lock().unwrap_or_else(|e| e.into_inner());
                    return Some(of.entry(net).or_insert_with(|| Arc::new(DeviceBuckets::new(rate))).clone());
                }
            }
        }

        let buckets = Arc::new(DeviceBuckets {
            up: TokenBucket::new(rate),
            down: TokenBucket::new(rate),
        });
        live.insert(
            ip,
            LiveBucketEntry {
                buckets: buckets.clone(),
                last: now,
            },
        );
        Some(buckets)
    }
}

// ───────────────────────── 服务端进程级 limiter ─────────────────────────
// 客户端侧限速器挂在 CoreState (随 ArcSwap<CoreState> 热重载)。服务端 relay 路径不经 CoreState,
// 故用一个进程级全局 (仿 blocklist/monitor 的全局模式), server 启动时按 config.routing 装, relay
// 泵按 client_ip 直接读。arc-swap 可热更 (config 热重载时重装)。

static SERVER_LIMITER: std::sync::OnceLock<arc_swap::ArcSwapOption<RateLimiter>> =
    std::sync::OnceLock::new();

fn server_slot() -> &'static arc_swap::ArcSwapOption<RateLimiter> {
    SERVER_LIMITER.get_or_init(|| arc_swap::ArcSwapOption::from(None))
}

/// server 启动/热重载时装入按 config.routing.device_profiles 建的 limiter。
pub fn set_server_limiter(rl: Arc<RateLimiter>) {
    server_slot().store(Some(rl));
}

/// 当前装着的服务端 limiter (热重载时作为 `rebuild_from` 的旧表)。
pub fn current_server_limiter() -> Option<Arc<RateLimiter>> {
    server_slot().load_full()
}

/// 服务端 relay 泵按客户端 IP 取共享桶; 未装/未命中 → None (跳过整形)。
pub fn server_buckets_for(ip: IpAddr) -> Option<Arc<DeviceBuckets>> {
    server_slot().load_full().and_then(|rl| rl.buckets_for(ip))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test(start_paused = true)]
    async fn token_bucket_shapes_to_rate() {
        // 1000 B/s, burst 默认 ≥64KB。先耗掉 burst, 再验稳态限速。
        let tb = TokenBucket::new(1000);
        // 消费 64KB (burst) 应几乎立即 (start_paused 下不推进时间)。
        tb.consume(65536).await;
        // 再消费 1000B: 桶已空, 需等 ~1s。start_paused 下 sleep 自动推进虚拟时钟。
        let t0 = tokio::time::Instant::now();
        tb.consume(1000).await;
        assert!(t0.elapsed() >= Duration::from_millis(900), "限速未生效: {:?}", t0.elapsed());
    }

    #[test]
    fn resolve_first_match_and_kbps_conversion() {
        let dps = vec![crate::config::DeviceProfile {
            source_ip_cidr: vec!["192.168.1.0/24".into()],
            profile: "kids".into(),
            name: None,
            rate_limit_kbps: Some(8000), // 8000 kbps = 1 MB/s
        }];
        let rl = RateLimiter::from_device_profiles(&dps);
        assert_eq!(rl.resolve("192.168.1.50".parse().unwrap()).map(|(_, r)| r), Some(1_000_000));
        assert_eq!(rl.resolve("10.0.0.1".parse().unwrap()), None);
        assert!(rl.buckets_for("192.168.1.50".parse().unwrap()).is_some());
        assert!(rl.buckets_for("10.0.0.1".parse().unwrap()).is_none());
    }

    #[test]
    fn try_consume_polices_drops_over_rate() {
        // try_consume 用 std::Instant, 与 tokio 虚拟时钟无关, 故做确定性测试: 耗掉 burst 后桶空,
        // 超速立即返 false (丢)。两次调用间只过 µs 级真实时间, 回补远 < 1000, 故稳定丢。
        let tb = TokenBucket::new(1000); // burst = max(0.5*1000, 65536) = 65536
        assert!(tb.try_consume(65536), "burst 内应放行");
        assert!(!tb.try_consume(1000), "桶空后超速应丢 (false)");
        assert!(!tb.try_consume(1000), "仍空仍丢");
        // 回补验证: 真实等 50ms 补 ~50 tokens, 仍 < 1000 丢; 等足量 (rate 拉高) 才放 —— 见下高速率桶。
        let fast = TokenBucket::new(10_000_000); // burst 5MB
        assert!(fast.try_consume(5_000_000), "高速桶 burst 内放行");
    }

    #[test]
    fn empty_when_no_rate_configured() {
        let dps = vec![crate::config::DeviceProfile {
            source_ip_cidr: vec!["192.168.1.0/24".into()],
            profile: "kids".into(),
            name: None,
            rate_limit_kbps: None,
        }];
        assert!(RateLimiter::from_device_profiles(&dps).is_empty());
    }

    #[test]
    fn rate_limiter_live_capped() {
        let dps = vec![crate::config::DeviceProfile {
            source_ip_cidr: vec!["0.0.0.0/0".into()],
            profile: "default".into(),
            name: None,
            rate_limit_kbps: Some(1000),
        }];
        let rl = RateLimiter::from_device_profiles(&dps);
        for i in 0..(RATE_LIMIT_CAP + 50) as u32 {
            let ip = std::net::Ipv4Addr::from(0x0a000000 + i);
            assert!(rl.buckets_for(std::net::IpAddr::V4(ip)).is_some());
        }
        let live = rl.live.lock().unwrap();
        assert_eq!(live.len(), RATE_LIMIT_CAP, "超出容量后 live 长度应严格封顶在 RATE_LIMIT_CAP");
    }

    fn dp(cidr: &str, kbps: u64) -> crate::config::DeviceProfile {
        crate::config::DeviceProfile {
            source_ip_cidr: vec![cidr.into()],
            profile: "p".into(),
            name: None,
            rate_limit_kbps: Some(kbps),
        }
    }

    /// 表满且全部有活跃连接: 不挤掉活跃条目, 新 IP 共用溢出桶 (同一个 Arc)。
    #[test]
    fn full_table_with_active_entries_uses_overflow_bucket() {
        let rl = RateLimiter::from_device_profiles(&[dp("10.0.0.0/8", 1000)]);
        // 填满并持有全部桶 (模拟活跃连接)
        let held: Vec<_> = (0..RATE_LIMIT_CAP as u32)
            .map(|i| rl.buckets_for(IpAddr::V4(std::net::Ipv4Addr::from(0x0a000000 + i))).unwrap())
            .collect();
        let first_ip = IpAddr::V4(std::net::Ipv4Addr::from(0x0a000000));
        let a = rl.buckets_for(IpAddr::V4(std::net::Ipv4Addr::new(10, 200, 0, 1))).unwrap();
        let b = rl.buckets_for(IpAddr::V4(std::net::Ipv4Addr::new(10, 200, 0, 2))).unwrap();
        assert!(Arc::ptr_eq(&a, &b), "溢出的新 IP 应共用同一个桶");
        // 原有活跃条目没被挤掉: 同一 IP 再取仍是原桶
        assert!(Arc::ptr_eq(&rl.buckets_for(first_ip).unwrap(), &held[0]));
        assert_eq!(rl.live.lock().unwrap().len(), RATE_LIMIT_CAP);
        drop(held);
        // 有空闲条目后, 新 IP 回到独立桶
        let c = rl.buckets_for(IpAddr::V4(std::net::Ipv4Addr::new(10, 200, 0, 3))).unwrap();
        assert!(!Arc::ptr_eq(&c, &a));
    }

    /// 热重载沿用限速未变的桶; 限速变了换新桶; 网段被删则不再限速。
    #[test]
    fn rebuild_keeps_buckets_when_rate_unchanged() {
        let ip_a: IpAddr = "10.1.0.1".parse().unwrap();
        let ip_b: IpAddr = "192.168.5.5".parse().unwrap();
        let old = RateLimiter::from_device_profiles(&[dp("10.0.0.0/8", 1000), dp("192.168.0.0/16", 2000)]);
        let ba = old.buckets_for(ip_a).unwrap();
        let bb = old.buckets_for(ip_b).unwrap();

        // 无关改动 (限速都不变): 两个都沿用
        let same = RateLimiter::rebuild_from(&[dp("10.0.0.0/8", 1000), dp("192.168.0.0/16", 2000)], Some(&old));
        assert!(Arc::ptr_eq(&same.buckets_for(ip_a).unwrap(), &ba));
        assert!(Arc::ptr_eq(&same.buckets_for(ip_b).unwrap(), &bb));

        // 改了 192.168/16 的限速: A 沿用, B 换新桶且速率是新值
        let changed = RateLimiter::rebuild_from(&[dp("10.0.0.0/8", 1000), dp("192.168.0.0/16", 4000)], Some(&old));
        assert!(Arc::ptr_eq(&changed.buckets_for(ip_a).unwrap(), &ba));
        let nb = changed.buckets_for(ip_b).unwrap();
        assert!(!Arc::ptr_eq(&nb, &bb));
        assert_eq!(nb.up.rate as u64, 4000 * 125);

        // 删掉 10/8: A 不再限速
        let removed = RateLimiter::rebuild_from(&[dp("192.168.0.0/16", 2000)], Some(&old));
        assert!(removed.buckets_for(ip_a).is_none());
    }
}
