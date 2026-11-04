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
pub mod selector_state;

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

/// TCP relay drain 阶段的空闲超时 (单侧半关闭后, 剩余方向连续无字节进展满此值即两端都关)。
/// 生产环境 30s (给慢速下载/大传输留余量, 同时防止对端崩溃/丢状态导致 CLOSE-WAIT 协程泄漏);
/// 测试环境下缩短为 500ms (同 honk 写法)。
pub(crate) const DRAIN_IDLE: std::time::Duration = if cfg!(test) {
    std::time::Duration::from_millis(500)
} else {
    std::time::Duration::from_secs(30)
};

/// 拷贝单方向运行结果
#[derive(Debug)]
pub(crate) enum CopyResult {
    Finished(u64),
    Idle,
    Err(std::io::Error),
}

/// 等待幸存方向在排空阶段完成。
/// 仅当连续 `drain` 时长无任何字节进展时才终止并返回已转发的字节数 (不当作错误)。
/// 若幸存方向在此期间有字节流动, 则重置无进展计时器。
pub(crate) async fn drain_wait<F>(
    mut fut: F,
    progress: &std::sync::atomic::AtomicU64,
    drain: std::time::Duration,
) -> std::io::Result<u64>
where
    F: std::future::Future<Output = CopyResult> + Unpin,
{
    let check = std::time::Duration::from_millis(100)
        .min(drain / 10)
        .max(std::time::Duration::from_millis(1));
    let mut last = progress.load(std::sync::atomic::Ordering::Relaxed);
    let mut stalled = std::time::Duration::ZERO;
    loop {
        tokio::select! {
            r = &mut fut => match r {
                CopyResult::Finished(n) => return Ok(n),
                CopyResult::Idle => {
                    tracing::debug!("relay drain idle timeout; closing survivor");
                    return Ok(progress.load(std::sync::atomic::Ordering::Relaxed));
                }
                CopyResult::Err(e) => return Err(e),
            },
            _ = tokio::time::sleep(check) => {
                let now = progress.load(std::sync::atomic::Ordering::Relaxed);
                if now != last {
                    last = now;
                    stalled = std::time::Duration::ZERO;
                } else {
                    stalled += check;
                    if stalled >= drain {
                        tracing::debug!("relay drain stalled ({:?}); closing survivor", drain);
                        return Ok(now);
                    }
                }
            }
        }
    }
}

async fn copy_one_direction<R, W>(
    mut rd: R,
    mut wr: W,
    clock: &IdleClock,
    idle: std::time::Duration,
    progress: &std::sync::atomic::AtomicU64,
) -> CopyResult
where
    R: tokio::io::AsyncRead + Unpin,
    W: tokio::io::AsyncWrite + Unpin,
{
    use std::sync::atomic::Ordering;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let res = idle_timeout(clock, idle, async {
        let mut buf = vec![0u8; 16384];
        loop {
            let n = rd.read(&mut buf).await?;
            if n == 0 {
                break;
            }
            wr.write_all(&buf[..n]).await?;
            clock.touch();
            progress.fetch_add(n as u64, Ordering::Relaxed);
        }
        wr.flush().await?;
        wr.shutdown().await?;
        Ok::<(), std::io::Error>(())
    })
    .await;

    match res {
        Ok(Ok(())) => CopyResult::Finished(progress.load(Ordering::Relaxed)),
        Ok(Err(e)) => CopyResult::Err(e),
        Err(IdleElapsed) => CopyResult::Idle,
    }
}

/// 双向异步拷贝并带超时防护与半关闭排空守望:
/// - 整体空闲超时 `idle`: 双向共同静默达 `idle` 结束 (不当作错误, 返回 Ok 和实际转发字节数)。
/// - 半关闭传递: 一侧读到 EOF (0 字节) 后, 先 flush + shutdown 对端写半程, 然后进入 drain 守望。
/// - 排空超时 `drain`: 剩余方向若连续 `drain` 时长无任何字节进展即关闭 (不当作错误, 返回 Ok 和实际转发字节数);
///   若有数据持续流动则重置计时器, 不打断慢速大传输。
/// - 任一方向发生 I/O 错误则立即返回 Err (语义对齐 tokio `copy_bidirectional`)。
pub(crate) async fn copy_bidirectional_with_drain<A, B>(
    a: &mut A,
    b: &mut B,
    idle: std::time::Duration,
    drain: std::time::Duration,
) -> std::io::Result<(u64, u64)>
where
    A: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
    B: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    use std::sync::atomic::{AtomicU64, Ordering};

    let (mut a_r, mut a_w) = tokio::io::split(a);
    let (mut b_r, mut b_w) = tokio::io::split(b);

    let clock = IdleClock::new();
    let a2b_progress = AtomicU64::new(0);
    let b2a_progress = AtomicU64::new(0);

    let a2b = copy_one_direction(&mut a_r, &mut b_w, &clock, idle, &a2b_progress);
    let b2a = copy_one_direction(&mut b_r, &mut a_w, &clock, idle, &b2a_progress);

    tokio::pin!(a2b);
    tokio::pin!(b2a);

    tokio::select! {
        r = &mut a2b => match r {
            CopyResult::Err(e) => Err(e),
            CopyResult::Idle => {
                tracing::debug!("relay idle timeout ({:?}); closing both directions", idle);
                Ok((a2b_progress.load(Ordering::Relaxed), b2a_progress.load(Ordering::Relaxed)))
            }
            CopyResult::Finished(a_n) => {
                let b_n = drain_wait(&mut b2a, &b2a_progress, drain).await?;
                Ok((a_n, b_n))
            }
        },
        r = &mut b2a => match r {
            CopyResult::Err(e) => Err(e),
            CopyResult::Idle => {
                tracing::debug!("relay idle timeout ({:?}); closing both directions", idle);
                Ok((a2b_progress.load(Ordering::Relaxed), b2a_progress.load(Ordering::Relaxed)))
            }
            CopyResult::Finished(b_n) => {
                let a_n = drain_wait(&mut a2b, &a2b_progress, drain).await?;
                Ok((a_n, b_n))
            }
        },
    }
}

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

    #[tokio::test]
    async fn test_copy_bidirectional_with_drain_normal() {
        let (mut client_user, mut client_relay) = tokio::io::duplex(64);
        let (mut remote_relay, mut remote_user) = tokio::io::duplex(64);

        let relay = tokio::spawn(async move {
            copy_bidirectional_with_drain(
                &mut client_relay,
                &mut remote_relay,
                Duration::from_secs(10),
                DRAIN_IDLE,
            )
            .await
        });

        let client_task = tokio::spawn(async move {
            use tokio::io::{AsyncReadExt, AsyncWriteExt};
            client_user.write_all(b"ping from client").await.unwrap();
            client_user.shutdown().await.unwrap();
            let mut resp = Vec::new();
            client_user.read_to_end(&mut resp).await.unwrap();
            resp
        });

        let remote_task = tokio::spawn(async move {
            use tokio::io::{AsyncReadExt, AsyncWriteExt};
            let mut req = Vec::new();
            let mut buf = vec![0u8; 32];
            loop {
                let n = remote_user.read(&mut buf).await.unwrap();
                if n == 0 {
                    break;
                }
                req.extend_from_slice(&buf[..n]);
            }
            remote_user.write_all(b"pong from remote").await.unwrap();
            remote_user.shutdown().await.unwrap();
            req
        });

        let (c_res, r_res) = tokio::join!(client_task, remote_task);
        assert_eq!(r_res.unwrap(), b"ping from client");
        assert_eq!(c_res.unwrap(), b"pong from remote");

        let (up, down) = relay.await.unwrap().unwrap();
        assert_eq!(up, b"ping from client".len() as u64);
        assert_eq!(down, b"pong from remote".len() as u64);
    }

    #[tokio::test]
    async fn test_copy_bidirectional_with_drain_slow_survivor_not_interrupted() {
        let (mut client_user, mut client_relay) = tokio::io::duplex(1024);
        let (mut remote_relay, mut remote_user) = tokio::io::duplex(1024);

        let drain = DRAIN_IDLE; // 500ms in test
        let relay = tokio::spawn(async move {
            copy_bidirectional_with_drain(
                &mut client_relay,
                &mut remote_relay,
                Duration::from_secs(10),
                drain,
            )
            .await
        });

        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        client_user.write_all(b"client hello").await.unwrap();
        client_user.shutdown().await.unwrap();

        let mut req = [0u8; 16];
        let n = remote_user.read(&mut req).await.unwrap();
        assert_eq!(&req[..n], b"client hello");
        let n_eof = remote_user.read(&mut req).await.unwrap();
        assert_eq!(n_eof, 0);

        let total_chunks = 18;
        let chunk = b"chunk_data_";
        let mut expected_bytes = Vec::new();
        let remote_writer = tokio::spawn(async move {
            for _ in 0..total_chunks {
                tokio::time::sleep(Duration::from_millis(100)).await;
                remote_user.write_all(chunk).await.unwrap();
            }
            remote_user.shutdown().await.unwrap();
        });

        let client_reader = tokio::spawn(async move {
            let mut all = Vec::new();
            client_user.read_to_end(&mut all).await.unwrap();
            all
        });

        remote_writer.await.unwrap();
        let received = client_reader.await.unwrap();
        for _ in 0..total_chunks {
            expected_bytes.extend_from_slice(chunk);
        }
        assert_eq!(received, expected_bytes);

        let (up, down) = relay.await.unwrap().unwrap();
        assert_eq!(up, b"client hello".len() as u64);
        assert_eq!(down, expected_bytes.len() as u64);
    }

    #[tokio::test]
    async fn test_copy_bidirectional_with_drain_survivor_stalled_closes_after_drain() {
        let (mut client_user, mut client_relay) = tokio::io::duplex(64);
        let (mut remote_relay, mut remote_user) = tokio::io::duplex(64);

        let drain = DRAIN_IDLE; // 500ms in test
        let start = tokio::time::Instant::now();
        let relay = tokio::spawn(async move {
            copy_bidirectional_with_drain(
                &mut client_relay,
                &mut remote_relay,
                Duration::from_secs(10),
                drain,
            )
            .await
        });

        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        client_user.shutdown().await.unwrap();

        let mut buf = [0u8; 8];
        let n = remote_user.read(&mut buf).await.unwrap();
        assert_eq!(n, 0);

        let res = tokio::time::timeout(Duration::from_secs(5), relay).await;
        assert!(res.is_ok(), "relay did not finish within 5s");
        let (up, down) = res.unwrap().unwrap().unwrap();
        let elapsed = start.elapsed();
        assert_eq!(up, 0);
        assert_eq!(down, 0);
        assert!(elapsed >= Duration::from_millis(450), "elapsed {:?} should be around drain (500ms)", elapsed);
        assert!(elapsed < Duration::from_secs(2), "elapsed {:?} should not be stalled indefinitely", elapsed);
    }

    #[tokio::test]
    async fn test_copy_bidirectional_with_drain_both_silent_returns_on_idle() {
        let (_client_user, mut client_relay) = tokio::io::duplex(64);
        let (_remote_relay_user, mut remote_relay) = tokio::io::duplex(64);

        let idle = Duration::from_millis(300);
        let drain = Duration::from_millis(500);
        let start = tokio::time::Instant::now();

        let res = copy_bidirectional_with_drain(
            &mut client_relay,
            &mut remote_relay,
            idle,
            drain,
        )
        .await;

        let elapsed = start.elapsed();
        let (up, down) = res.unwrap();
        assert_eq!(up, 0);
        assert_eq!(down, 0);
        assert!(elapsed >= Duration::from_millis(270), "elapsed {:?} should be >= idle (300ms)", elapsed);
        assert!(elapsed < Duration::from_millis(600), "elapsed {:?} should be around idle (300ms)", elapsed);
    }

    #[tokio::test]
    async fn test_copy_bidirectional_with_drain_half_close_propagated() {
        let (mut client_user, mut client_relay) = tokio::io::duplex(64);
        let (mut remote_relay, mut remote_user) = tokio::io::duplex(64);

        let relay = tokio::spawn(async move {
            copy_bidirectional_with_drain(
                &mut client_relay,
                &mut remote_relay,
                Duration::from_secs(10),
                DRAIN_IDLE,
            )
            .await
        });

        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        client_user.write_all(b"half close test").await.unwrap();
        client_user.shutdown().await.unwrap();

        let mut buf = vec![0u8; 32];
        let n = remote_user.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"half close test");
        let eof = remote_user.read(&mut buf).await.unwrap();
        assert_eq!(eof, 0, "remote_user must observe EOF after client half-closes");

        remote_user.write_all(b"ack").await.unwrap();
        remote_user.shutdown().await.unwrap();

        let mut resp = Vec::new();
        client_user.read_to_end(&mut resp).await.unwrap();
        assert_eq!(resp, b"ack");

        let (up, down) = relay.await.unwrap().unwrap();
        assert_eq!(up, b"half close test".len() as u64);
        assert_eq!(down, b"ack".len() as u64);
    }
}
