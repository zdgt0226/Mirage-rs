pub mod brutal;
#[cfg(feature = "quic")]
pub mod quic;
#[cfg(feature = "quic")]
pub mod quic_cc;
#[cfg(feature = "quic")]
pub mod quic_obfs;
pub mod pool;
pub mod tunnel;
pub mod tls_capture;
pub mod mirage_stream;
pub mod internal_socks;
pub mod ss_inbound;
pub mod ss_stream;
pub mod socks5;
pub mod handler;
pub mod udp_relay;
pub mod outbound;
pub mod mirage_server;
pub mod mixed;
pub mod healthcheck;
pub mod transparent;
pub mod transparent_udp;
pub mod udp_mux;
pub mod sniff;
pub mod splice;
pub mod resolver;
pub mod shadowsocks;
pub mod upstream;
pub mod wg;
pub mod transparent_net;
pub mod probe;
pub mod proc_lookup;
pub mod rate_limit;
pub mod user_limits;

/// Mirage **TCP 隧道 relay 的空闲超时** (双向共同静默满此值才断, 非单向亦非绝对寿命)。
/// 默认 1800s (30min, 给 SSH/视频/大下载/长连接留余量), 可用环境变量 `MIRAGE_RELAY_IDLE` (秒)
/// 覆盖。资源受限或高频短连接场景 (软路由 / 低配 VPS / 移动端) 可调小防僵尸连接钉住 task+缓冲
/// (移动端实测 300s 更稳)。客户端 (`handler`) 与服务端 (`mirage_server::tcp_relay`) 共用此值 ——
/// **两端须同设**才保持"一致不互相早关"。解析失败/非数字回落 1800; 下限 5s (防病态 0 无限斩断)。
/// 进程内只读一次 env (缓存)。
pub(crate) fn relay_idle() -> std::time::Duration {
    use std::sync::OnceLock;
    static V: OnceLock<std::time::Duration> = OnceLock::new();
    *V.get_or_init(|| {
        let secs = std::env::var("MIRAGE_RELAY_IDLE")
            .ok()
            .and_then(|s| s.trim().parse::<u64>().ok())
            .map(|s| s.max(5))
            .unwrap_or(1800);
        std::time::Duration::from_secs(secs)
    })
}

/// 一条 relay 两个方向共享的最后活跃时间。
pub(crate) struct IdleClock {
    base: tokio::time::Instant,
    last_active_ms: std::sync::atomic::AtomicU64,
}

impl IdleClock {
    pub(crate) fn new() -> Self {
        Self {
            base: tokio::time::Instant::now(),
            last_active_ms: std::sync::atomic::AtomicU64::new(0),
        }
    }

    /// 任一方向有数据时调用
    #[inline]
    pub(crate) fn touch(&self) {
        let ms = tokio::time::Instant::now().saturating_duration_since(self.base).as_millis() as u64;
        self.last_active_ms.fetch_max(ms, std::sync::atomic::Ordering::Relaxed);
    }

    #[inline]
    pub(crate) fn elapsed_since_active(&self) -> std::time::Duration {
        let now_ms = tokio::time::Instant::now().saturating_duration_since(self.base).as_millis() as u64;
        let last_ms = self.last_active_ms.load(std::sync::atomic::Ordering::Relaxed);
        std::time::Duration::from_millis(now_ms.saturating_sub(last_ms))
    }
}

/// `idle_timeout` 到期 (两个方向共同静默达 idle)。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct IdleElapsed;

/// 等 fut 完成; 仅当两个方向共同静默达 idle 时返回 Err。
/// 本方向等待中若另一方向 touch 过, 按剩余时间继续等 (不是重新计满 idle), 保证总空闲上界 = idle。
pub(crate) async fn idle_timeout<F: std::future::Future>(
    clock: &IdleClock,
    idle: std::time::Duration,
    fut: F,
) -> Result<F::Output, IdleElapsed> {
    tokio::pin!(fut);
    loop {
        let idle_so_far = clock.elapsed_since_active();
        let remaining = match idle.checked_sub(idle_so_far) {
            Some(rem) if !rem.is_zero() => rem,
            // 到期前再 poll 一次: 本方向可能刚从长时间写阻塞 / 限速中回来, 缓冲里已有数据。
            _ => {
                return tokio::select! {
                    biased;
                    res = &mut fut => Ok(res),
                    _ = std::future::ready(()) => Err(IdleElapsed),
                };
            }
        };
        tokio::select! {
            biased;
            res = &mut fut => return Ok(res),
            _ = tokio::time::sleep(remaining) => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::time::Duration;

    #[tokio::test(start_paused = true)]
    async fn test_idle_timeout_sustained_by_other_direction() {
        let clock = Arc::new(IdleClock::new());
        let idle = Duration::from_secs(10);
        let other_clock = clock.clone();

        // 另一方向持续 touch: 每 idle/2 (5s) 一次, 共持续 35s (> 3 * idle)
        tokio::spawn(async move {
            for _ in 0..7 {
                tokio::time::sleep(Duration::from_secs(5)).await;
                other_clock.touch();
            }
        });

        // 本方向 fut 在 35s 后完成
        let fut = async {
            tokio::time::sleep(Duration::from_secs(35)).await;
            42
        };

        let start = tokio::time::Instant::now();
        let res = idle_timeout(&clock, idle, fut).await;
        let elapsed = start.elapsed();

        assert_eq!(res, Ok(42));
        assert_eq!(elapsed, Duration::from_secs(35));
    }

    #[tokio::test(start_paused = true)]
    async fn test_idle_timeout_both_silent() {
        let clock = IdleClock::new();
        let idle = Duration::from_secs(10);

        // 两边都静默, fut 远长于 idle (100s)
        let fut = async {
            tokio::time::sleep(Duration::from_secs(100)).await;
            42
        };

        let start = tokio::time::Instant::now();
        let res = idle_timeout(&clock, idle, fut).await;
        let elapsed = start.elapsed();

        assert_eq!(res, Err(IdleElapsed));
        assert_eq!(elapsed, Duration::from_secs(10));
    }

    #[tokio::test(start_paused = true)]
    async fn test_idle_timeout_touch_once_remaining_wait() {
        let clock = Arc::new(IdleClock::new());
        let idle = Duration::from_secs(10);
        let other_clock = clock.clone();

        // 另一方向在 t = idle - 1s (9s) touch 一次后静默
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_secs(9)).await;
            other_clock.touch();
        });

        let fut = async {
            tokio::time::sleep(Duration::from_secs(100)).await;
            42
        };

        let start = tokio::time::Instant::now();
        let res = idle_timeout(&clock, idle, fut).await;
        let elapsed = start.elapsed();

        assert_eq!(res, Err(IdleElapsed));
        let expected = 2 * idle - Duration::from_secs(1); // 19s
        assert_eq!(elapsed, expected);
    }
}
