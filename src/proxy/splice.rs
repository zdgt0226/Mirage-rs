//! 直连 TCP 零拷贝转发 — 学 dae/control/tcp_copy_linux.go
//!
//! 用 splice(2) + pipe 做真正的 kernel 零拷贝 (SPLICE_F_MOVE 只搬 page 引用,
//! 数据一字节不进 userspace). 每方向一个 256KB pipe, 双向并行 tokio::try_join.
//!
//! 为什么不用 sockmap: kernel 6.x 的 sk_skb/stream_verdict + bpf_sk_redirect_hash
//! 组合会静默丢包 (dae 团队也在 sk_msg 侧遇到 kernel panic, 明确放弃整套
//! sockmap redirect). splice(2) 从 kernel 3.x 稳定, 无 sk_psock 家族的坑.
//!
//! Idle timeout (alpha.4): 双向共享 ActivityTracker, 15 分钟双向都静默 →
//! watchdog 报 TimedOut 关连接.
//!
//! Pipe pool (alpha.5): 64 容量 pool 复用 pipe (学 dae relaySplicePipePool).
//! 避免每连接一次 pipe2()+F_SETPIPE_SZ() 两次 syscall. 出错 pipe 走 Drop 关 fd,
//! 成功归池 (成功路径 in_pipe 保证为 0, 无残留).
//!
//! Byte accounting: 每次 splice→dst 成功后 counter(m) 立即更新 GLOBAL_UP/DOWN,
//! 出错也保留 partial 已传输字节 (alpha.4 是函数末尾统一 add 会丢 partial).

use std::collections::VecDeque;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};
use tokio::io::Interest;
use tokio::net::TcpStream;

const PIPE_SIZE: usize = 256 * 1024;
const SPLICE_FLAGS: libc::c_uint =
    (libc::SPLICE_F_MOVE | libc::SPLICE_F_MORE | libc::SPLICE_F_NONBLOCK) as libc::c_uint;

/// 双向共享的 idle 阈值. 网关场景下 15 分钟静默即回收连接.
/// 长连接 SSE/WebSocket 通常有 30s-5min 心跳, 不会碰这个上限.
const IDLE_TIMEOUT: Duration = Duration::from_secs(15 * 60);
/// watchdog 检查频率. IDLE_TIMEOUT / 30 = 30s, 单条连接每 15 分钟最多多活半分钟.
const IDLE_CHECK_INTERVAL: Duration = Duration::from_secs(30);

/// pipe pool 容量. dae 也是 64. 高并发瞬时开新 pipe 是 fallback, 无上限阻塞.
const POOL_CAPACITY: usize = 64;

pub(crate) struct Pipe {
    pub(crate) r: OwnedFd,
    pub(crate) w: OwnedFd,
}

impl Pipe {
    fn new() -> io::Result<Self> {
        let mut fds = [0i32; 2];
        let ret = unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC | libc::O_NONBLOCK) };
        if ret < 0 {
            return Err(io::Error::last_os_error());
        }
        // F_SETPIPE_SZ 是 best-effort: 拿不到 CAP_SYS_RESOURCE 或超过 /proc/sys/fs/pipe-max-size
        // 会失败, 但 pipe 仍能用默认 64KB 跑, 不影响正确性只影响吞吐.
        unsafe {
            libc::fcntl(fds[0], libc::F_SETPIPE_SZ, PIPE_SIZE as libc::c_int);
        }
        Ok(Self {
            r: unsafe { OwnedFd::from_raw_fd(fds[0]) },
            w: unsafe { OwnedFd::from_raw_fd(fds[1]) },
        })
    }
}

fn pipe_pool() -> &'static Mutex<VecDeque<Pipe>> {
    // TODO(perf): 若火焰图显示 Mutex::lock 占 CPU > 1% (估计需 50K+ conn/sec 且
    // 32+ 核并发), 换 crossbeam_queue::ArrayQueue 无锁池化. 当前锁持有 ~30ns vs
    // 工作时间 ms 级, 竞争概率 ≈ 0, 家用/SOHO/SME 网关不换也罢. dae 用 Go
    // buffered channel (底层 mutex+condvar) 生产验证过不是瓶颈.
    static POOL: OnceLock<Mutex<VecDeque<Pipe>>> = OnceLock::new();
    POOL.get_or_init(|| Mutex::new(VecDeque::with_capacity(POOL_CAPACITY)))
}

static POOL_HITS: AtomicU64 = AtomicU64::new(0);
static POOL_MISSES: AtomicU64 = AtomicU64::new(0);

fn acquire_pipe() -> io::Result<Pipe> {
    if let Ok(mut pool) = pipe_pool().lock() {
        if let Some(pipe) = pool.pop_front() {
            POOL_HITS.fetch_add(1, Ordering::Relaxed);
            return Ok(pipe);
        }
    }
    POOL_MISSES.fetch_add(1, Ordering::Relaxed);
    Pipe::new()
}

fn release_pipe(pipe: Pipe) {
    if let Ok(mut pool) = pipe_pool().lock() {
        if pool.len() < POOL_CAPACITY {
            pool.push_back(pipe);
            return;
        }
    }
    // pool 满 / lock poisoned — pipe 走 Drop, OwnedFd 关 fd, 无泄漏.
    drop(pipe);
}

/// 当前 (hits, misses, in_use_estimate) 供 debug/GUI 用. in_use 是启动至今
/// misses - hits + pool_len 的粗略估计 (不精确, 但足够 debug).
pub fn pool_stats() -> (u64, u64, usize) {
    let hits = POOL_HITS.load(Ordering::Relaxed);
    let misses = POOL_MISSES.load(Ordering::Relaxed);
    let pool_len = pipe_pool().lock().map(|p| p.len()).unwrap_or(0);
    (hits, misses, pool_len)
}

/// 双向共享的活动时间戳. 任一方向 splice 成功就 touch(), watchdog 只读它判断
/// 是否 idle. 用 AtomicU64 (自进程启动后单调递增秒) 而不是 Mutex<Instant>,
/// 因为热路径 (每次 splice 后) 会 touch, 无锁最省事.
///
/// alpha.6: 从 SystemTime epoch 换成 Instant 单调时钟 (Linux CLOCK_MONOTONIC).
/// 免疫 NTP 前跳误杀 — 之前用 SystemTime, 虚拟机 RTC 不准 + NTP 突然 +30 min
/// 会让所有连接瞬间被 watchdog 报 idle. Instant 是单调时钟不会前跳.
/// (副作用: Linux CLOCK_MONOTONIC 不计 suspend 时长, VM 从 suspend 恢复后
/// 连接被视为"刚活跃过", 第一个请求正常, 之后 15 min 才淘汰. 合理.)
struct ActivityTracker(AtomicU64);

impl ActivityTracker {
    fn new() -> Self {
        Self(AtomicU64::new(monotonic_secs()))
    }
    fn touch(&self) {
        self.0.store(monotonic_secs(), Ordering::Relaxed);
    }
    fn idle_secs(&self) -> u64 {
        monotonic_secs().saturating_sub(self.0.load(Ordering::Relaxed))
    }
}

/// 自进程启动 (首次调用 monotonic_secs) 起的单调递增秒数. OnceLock 保证
/// ORIGIN 只被第一次调用初始化一次, 之后所有调用都读 elapsed(). Instant
/// 底层是 CLOCK_MONOTONIC, 免疫 NTP 前后跳.
fn monotonic_secs() -> u64 {
    static ORIGIN: OnceLock<Instant> = OnceLock::new();
    ORIGIN.get_or_init(Instant::now).elapsed().as_secs()
}

/// RAII: 成功走 release_pipe (归池), 出错走 Drop (关 fd).
/// 通过 finish() 显式转移 pipe 到 pool; 如 finish 未调用 (提前 return / panic),
/// Drop 兜底关 fd.
struct PipeGuard(Option<Pipe>);

impl PipeGuard {
    fn new(pipe: Pipe) -> Self {
        Self(Some(pipe))
    }
    fn as_fds(&self) -> (RawFd, RawFd) {
        let pipe = self.0.as_ref().unwrap();
        (pipe.r.as_raw_fd(), pipe.w.as_raw_fd())
    }
    fn finish(mut self) {
        if let Some(pipe) = self.0.take() {
            release_pipe(pipe);
        }
    }
}

/// 单方向 splice: src socket → pipe → dst socket 循环, 直到 src EOF.
/// src EOF 后主动 shutdown(dst, SHUT_WR) 让对端知道我方已关.
///
/// counter: 每次 pipe→dst 成功后调用, 用于 GLOBAL_UP/DOWN 计数. 出错也保留
/// 已传输的 partial bytes 到 counter (调用点已经加过).
async fn splice_one_way(
    src: &TcpStream,
    dst: &TcpStream,
    tracker: &ActivityTracker,
    counter: fn(u64),
) -> io::Result<u64> {
    let pipe_guard = PipeGuard::new(acquire_pipe()?);
    let (pipe_r, pipe_w) = pipe_guard.as_fds();
    let src_fd = src.as_raw_fd();
    let dst_fd = dst.as_raw_fd();

    let mut total: u64 = 0;
    let mut in_pipe: usize = 0;

    loop {
        if in_pipe == 0 {
            let n = src
                .async_io(Interest::READABLE, || {
                    let r = unsafe {
                        libc::splice(
                            src_fd,
                            std::ptr::null_mut(),
                            pipe_w,
                            std::ptr::null_mut(),
                            PIPE_SIZE,
                            SPLICE_FLAGS,
                        )
                    };
                    if r < 0 {
                        let err = io::Error::last_os_error();
                        // EINTR 也当 WouldBlock 让 async_io 重试
                        if err.raw_os_error() == Some(libc::EINTR) {
                            return Err(io::Error::new(io::ErrorKind::WouldBlock, "EINTR"));
                        }
                        return Err(err);
                    }
                    Ok(r as usize)
                })
                .await?;

            if n == 0 {
                // src 半关. 通知 dst 我方已经不再发数据.
                unsafe {
                    libc::shutdown(dst_fd, libc::SHUT_WR);
                }
                break;
            }
            in_pipe = n;
            tracker.touch();
        }

        while in_pipe > 0 {
            let m = dst
                .async_io(Interest::WRITABLE, || {
                    let r = unsafe {
                        libc::splice(
                            pipe_r,
                            std::ptr::null_mut(),
                            dst_fd,
                            std::ptr::null_mut(),
                            in_pipe,
                            SPLICE_FLAGS,
                        )
                    };
                    if r < 0 {
                        let err = io::Error::last_os_error();
                        if err.raw_os_error() == Some(libc::EINTR) {
                            return Err(io::Error::new(io::ErrorKind::WouldBlock, "EINTR"));
                        }
                        return Err(err);
                    }
                    Ok(r as usize)
                })
                .await?;

            if m == 0 {
                return Err(io::Error::new(io::ErrorKind::WriteZero, "splice returned 0"));
            }
            in_pipe -= m;
            total += m as u64;
            counter(m as u64);
            tracker.touch();
        }
    }

    // 成功路径: in_pipe == 0 (loop 出口条件), pipe 无残留, 归池复用.
    pipe_guard.finish();
    Ok(total)
}

/// idle 守望: 每 IDLE_CHECK_INTERVAL 秒读一次 tracker, 累计静默 > IDLE_TIMEOUT
/// 就返回 TimedOut error. tokio::select! 拿到 error 后取消双向 splice, sockets
/// 走 Drop, kernel 侧 fd 释放.
async fn idle_watchdog(tracker: &ActivityTracker) -> io::Error {
    loop {
        tokio::time::sleep(IDLE_CHECK_INTERVAL).await;
        if tracker.idle_secs() > IDLE_TIMEOUT.as_secs() {
            return io::Error::new(
                io::ErrorKind::TimedOut,
                format!("splice relay idle > {}s", IDLE_TIMEOUT.as_secs()),
            );
        }
    }
}

/// 双向零拷贝 relay. 返回 (up_bytes, down_bytes).
///
/// 半关行为: 客户端 FIN → up 方向 splice 返回 0 → shutdown(target, WR), 但
/// target 可能仍在发数据, down 方向照跑到 target FIN 后才结束. 此时 up_fut
/// 已 Ok, try_join! 会等 down_fut 一起完成.
///
/// 错误行为: 任一方向报错 (ECONNRESET/ETIMEDOUT/Idle Watchdog TimedOut) → 立刻
/// 取消另一方向 Future 并返回 Err → sockets Drop → kernel fd 释放, 无泄漏.
/// partial 字节数已通过 counter 上报到 GLOBAL_UP/DOWN, 不丢.
///
/// idle 语义: 见文件头注释. 15 分钟双向都静默 → watchdog 报 TimedOut 强关.
pub async fn splice_relay(local: TcpStream, target: TcpStream) -> io::Result<(u64, u64)> {
    let tracker = ActivityTracker::new();

    let up_fut = splice_one_way(&local, &target, &tracker, crate::monitor::add_up);
    let down_fut = splice_one_way(&target, &local, &tracker, crate::monitor::add_down);
    let watchdog_fut = idle_watchdog(&tracker);

    tokio::select! {
        r = async { tokio::try_join!(up_fut, down_fut) } => r,
        e = watchdog_fut => Err(e),
    }
}
