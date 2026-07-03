//! 直连 TCP 零拷贝转发 — 学 dae/control/tcp_copy_linux.go
//!
//! 用 splice(2) + pipe 做真正的 kernel 零拷贝 (SPLICE_F_MOVE 只搬 page 引用,
//! 数据一字节不进 userspace). 每方向一个 256KB pipe, 双向并行 tokio::try_join.
//!
//! 为什么不用 sockmap: kernel 6.x 的 sk_skb/stream_verdict + bpf_sk_redirect_hash
//! 组合会静默丢包 (dae 团队也在 sk_msg 侧遇到 kernel panic, 明确放弃整套
//! sockmap redirect). splice(2) 从 kernel 3.x 稳定, 无 sk_psock 家族的坑.

use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use tokio::io::Interest;
use tokio::net::TcpStream;

const PIPE_SIZE: usize = 256 * 1024;
const SPLICE_FLAGS: libc::c_uint =
    (libc::SPLICE_F_MOVE | libc::SPLICE_F_MORE | libc::SPLICE_F_NONBLOCK) as libc::c_uint;

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

/// 单方向 splice: src socket → pipe → dst socket 循环, 直到 src EOF.
/// src EOF 后主动 shutdown(dst, SHUT_WR) 让对端知道我方已关.
async fn splice_one_way(src: &TcpStream, dst: &TcpStream) -> io::Result<u64> {
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
        }
    }

    Ok(total)
}

/// 双向零拷贝 relay. 返回 (up_bytes, down_bytes).
///
/// 一方向出错/EOF 不影响另一方向 — try_join 遇错才会一起取消. 正常 TCP 半关
/// 流程: 客户端 FIN → up 方向 splice 返回 0 → shutdown(target, WR), 但 target
/// 可能仍在发数据, down 方向照跑到 target FIN 后才结束.
pub async fn splice_relay(local: TcpStream, target: TcpStream) -> io::Result<(u64, u64)> {
    let up_fut = async {
        let n = splice_one_way(&local, &target).await?;
        crate::monitor::add_up(n);
        Ok::<u64, io::Error>(n)
    };
    let down_fut = async {
        let n = splice_one_way(&target, &local).await?;
        crate::monitor::add_down(n);
        Ok::<u64, io::Error>(n)
    };

    tokio::try_join!(up_fut, down_fut)
}
