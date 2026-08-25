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
    rate: f64,
    burst: f64,
}

struct BucketState {
    tokens: f64,
    last: Instant,
}

impl TokenBucket {
    fn new(rate_bytes_per_sec: u64) -> Self {
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
}

/// 某源 IP 的上/下行桶对 (跨该 IP 全部连接共享)。
pub struct DeviceBuckets {
    pub up: TokenBucket,
    pub down: TokenBucket,
}

/// 按源 IP 限速器。从 `device_profiles` 建 (CIDR 网段 → 限速 bytes/s), 运行时按源 IP 懒建共享桶。
pub struct RateLimiter {
    /// (网段, bytes/s)。**首命中**生效 (对齐 device_profiles 首命中语义)。空 = 全局不限速。
    cidrs: Vec<(IpNet, u64)>,
    /// 源 IP → 共享桶 (懒建)。
    live: Mutex<HashMap<IpAddr, Arc<DeviceBuckets>>>,
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
        Self { cidrs, live: Mutex::new(HashMap::new()) }
    }

    /// 全局无任何限速配置 → 可在热路径上直接跳过。
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.cidrs.is_empty()
    }

    /// 源 IP 命中的限速 (bytes/s); 未命中 → None。首个匹配网段生效。
    fn resolve(&self, ip: IpAddr) -> Option<u64> {
        self.cidrs.iter().find(|(net, _)| net.contains(&ip)).map(|(_, r)| *r)
    }

    /// 取某源 IP 的共享桶对; 该 IP 无限速配置 → None (调用方跳过整形)。
    pub fn buckets_for(&self, ip: IpAddr) -> Option<Arc<DeviceBuckets>> {
        if self.cidrs.is_empty() {
            return None;
        }
        let rate = self.resolve(ip)?;
        let mut live = self.live.lock().unwrap_or_else(|e| e.into_inner());
        Some(
            live.entry(ip)
                .or_insert_with(|| {
                    Arc::new(DeviceBuckets { up: TokenBucket::new(rate), down: TokenBucket::new(rate) })
                })
                .clone(),
        )
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
        assert_eq!(rl.resolve("192.168.1.50".parse().unwrap()), Some(1_000_000));
        assert_eq!(rl.resolve("10.0.0.1".parse().unwrap()), None);
        assert!(rl.buckets_for("192.168.1.50".parse().unwrap()).is_some());
        assert!(rl.buckets_for("10.0.0.1".parse().unwrap()).is_none());
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
}
