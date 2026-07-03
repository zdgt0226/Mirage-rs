//! 直连 TCP 零拷贝转发 — 学 dae/control/tcp_copy_linux.go
//!
//! 用 splice(2) + pipe 做真正的 kernel 零拷贝 (SPLICE_F_MOVE 只搬 page 引用,
//! 数据一字节不进 userspace). 每方向一个 256KB pipe, 双向并行 tokio::try_join.
//!
//! 为什么不用 sockmap: kernel 6.x 的 sk_skb/stream_verdict + bpf_sk_redirect_hash
//! 组合会静默丢包 (dae 团队也在 sk_msg 侧遇到 kernel panic, 明确放弃整套
//! sockmap redirect). splice(2) 从 kernel 3.x 稳定, 无 sk_psock 家族的坑.
//!
//! Idle timeout 语义 (v0.4.5-alpha.4): 双向共享 ActivityTracker, 任一方向有数据
//! 流通就 touch(). watchdog 每 30 秒检查, 双向都静默 > 15 分钟 → 报 TimedOut
//! 关连接. 网关场景防僵尸连接堆积占 fd, 同时兼顾长连接 (SSE/WebSocket 只要
//! 应用层心跳 < 15 分钟就不会误杀).

use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
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

struct Pipe {
    r: OwnedFd,
    w: OwnedFd,
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

/// 双向共享的活动时间戳. 任一方向 splice 成功就 touch(), watchdog 只读它判断
/// 是否 idle. 用 AtomicU64 (epoch 秒) 而不是 Mutex<Instant>, 因为热路径 (每次
/// splice 后) 会 touch, 无锁最省事.
struct ActivityTracker(AtomicU64);

impl ActivityTracker {
    fn new() -> Self {
        Self(AtomicU64::new(now_epoch_secs()))
    }
    fn touch(&self) {
        self.0.store(now_epoch_secs(), Ordering::Relaxed);
    }
    fn idle_secs(&self) -> u64 {
        now_epoch_secs().saturating_sub(self.0.load(Ordering::Relaxed))
    }
}

fn now_epoch_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// 单方向 splice: src socket → pipe → dst socket 循环, 直到 src EOF.
/// src EOF 后主动 shutdown(dst, SHUT_WR) 让对端知道我方已关.
async fn splice_one_way(
    src: &TcpStream,
    dst: &TcpStream,
    tracker: &ActivityTracker,
) -> io::Result<u64> {
    let pipe = Pipe::new()?;
    let src_fd = src.as_raw_fd();
    let dst_fd = dst.as_raw_fd();
    let pipe_r: RawFd = pipe.r.as_raw_fd();
    let pipe_w: RawFd = pipe.w.as_raw_fd();

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
            tracker.touch();
        }
    }

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
///
/// idle 语义: 见文件头注释. 15 分钟双向都静默 → watchdog 报 TimedOut 强关.
pub async fn splice_relay(local: TcpStream, target: TcpStream) -> io::Result<(u64, u64)> {
    let tracker = ActivityTracker::new();

    let up_fut = async {
        let n = splice_one_way(&local, &target, &tracker).await?;
        crate::monitor::add_up(n);
        io::Result::Ok(n)
    };
    let down_fut = async {
        let n = splice_one_way(&target, &local, &tracker).await?;
        crate::monitor::add_down(n);
        io::Result::Ok(n)
    };
    let watchdog_fut = idle_watchdog(&tracker);

    tokio::select! {
        r = async { tokio::try_join!(up_fut, down_fut) } => r,
        e = watchdog_fut => Err(e),
    }
}
