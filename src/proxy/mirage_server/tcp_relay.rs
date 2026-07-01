//! 服务端 TCP 上游转发. 收到 target 后建立 TCP 连接, 双向 copy.
//!
//! 1800s = 30min 双向超时 - 给长连接 (WebSocket / 大文件下载) 留余量.
//!
//! 半关闭联动 (修 bug: 30 分钟僵尸泄露):
//! 单纯 `join!(upload, download)` 在一方先 Err 后会让另一方挂在阻塞读上
//! 直到 1800s 超时. 客户端断网/锁屏频繁的弱网场景下, 服务端会泄露海量
//! 无头连接 + tokio 协程, 耗尽 FD/内存.
//!
//! 修复策略: 两方共享 upstream 的 FD, 任一方退出立即 libc::shutdown(SHUT_RDWR)
//! 强制关闭整个 upstream socket. 另一方的 read/write 立即返回 Err, 退出循环.
//! 不用 tokio select! abort 是为了避免 cancel mid-write 导致协议层 AEAD 写入
//! 半截后又写 close_notify, 客户端 bad record mac (见 udp_relay 同样的考量).

use std::os::unix::io::AsRawFd;
use std::sync::Arc;
use std::sync::atomic::{AtomicI32, Ordering};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tracing::{debug, warn};

pub(super) async fn handle_tcp_relay(
    target: String,
    initial_payload: Option<Vec<u8>>,
    mut reader: crate::crypto::aead::CryptoReader<tokio::net::tcp::OwnedReadHalf>,
    mut writer: crate::crypto::aead::CryptoWriter<tokio::net::tcp::OwnedWriteHalf>
) {
    debug!("Mirage Server: Connecting to TCP target {}", target);
    let mut upstream = match tokio::net::TcpStream::connect(&target).await {
        Ok(s) => s,
        Err(e) => {
            warn!("Mirage Server failed to connect to {}: {}", target, e);
            return;
        }
    };

    // 在 split 前抓 FD: split 后两个 OwnedHalf 不再共享 as_raw_fd 接口
    let upstream_fd = upstream.as_raw_fd();

    // 显式设 SO_SNDBUF + SO_RCVBUF = 8MB. 老版本靠 kernel auto-tune, 长
    // BDP 链路 (200ms RTT × 40Mbps ≈ 1MB) 起手 buffer 太小会导致 rwnd_limited
    // 卡住 server → client 转发. 手动置大值 kernel 会 disable auto-tune,
    // 直接用固定 buffer. 上限由 install.sh 的 optimize_sysctl 设的
    // net.core.{rmem,wmem}_max=8388608 决定, 到不了 8MB 就 warn 一次.
    unsafe {
        let val: libc::c_int = 8 * 1024 * 1024;
        libc::setsockopt(upstream_fd, libc::SOL_SOCKET, libc::SO_SNDBUF,
            &val as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t);
        libc::setsockopt(upstream_fd, libc::SOL_SOCKET, libc::SO_RCVBUF,
            &val as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t);
    }

    if let Some(payload) = initial_payload {
        if !payload.is_empty() {
            let _ = upstream.write_all(&payload).await;
        }
    }
    let (mut up_read, mut up_write) = upstream.into_split();

    // 共享 atomic: 第一个 swap 到 -1 的 task 负责 shutdown, 另一方自然 break.
    // SUM_RDWR 让两个方向都立刻报 EOF/Err, 双向同时退出.
    let stop_fd = Arc::new(AtomicI32::new(upstream_fd));
    let stop_fd_up = stop_fd.clone();
    let stop_fd_down = stop_fd.clone();

    let shutdown_upstream = |stop: Arc<AtomicI32>| {
        let fd = stop.swap(-1, Ordering::SeqCst);
        if fd >= 0 {
            // SHUT_RDWR forces both directions to fail; idempotent — second
            // caller hits -1 swap and skips.
            unsafe { libc::shutdown(fd, libc::SHUT_RDWR); }
        }
    };

    let upload = async move {
        loop {
            match tokio::time::timeout(std::time::Duration::from_secs(1800), reader.recv_data()).await {
                Ok(Ok(data)) => {
                    if up_write.write_all(&data).await.is_err() {
                        break;
                    }
                }
                _ => break,
            }
        }
        // upload 退出 (客户端 reader 报错或超时) → 强制 shutdown upstream,
        // 让 download 卡在 up_read.read() 上的阻塞立刻返回, 不再 hang 1800s
        shutdown_upstream(stop_fd_up);
    };

    let download = async move {
        // 老 16KB 太小: 长 BDP 链路一次 syscall 只搬 4 帧, 频繁 poll wait 增加
        // per-byte 开销. 加大到 64KB 后一次系统调用能吃掉 4 倍数据, 减少
        // context switch, 上游 (YouTube 等) 有大量待读数据时能一口气吃干净.
        // 用 vec! 而非 [_;N] 数组是为了避免栈上 64KB 大对象 (tokio task stack
        // 不大, 有大 buf 时用堆更稳).
        let mut buf = vec![0u8; 65536];
        loop {
            match tokio::time::timeout(std::time::Duration::from_secs(1800), up_read.read(&mut buf)).await {
                Ok(Ok(0)) => break,
                Ok(Ok(n)) => {
                    if writer.send_data(&buf[..n]).await.is_err() {
                        break;
                    }
                }
                _ => break,
            }
        }
        // 优雅通知客户端我们这边结束写 (走加密 close_notify alert).
        // 此时 upload 协程还在 reader.recv_data 上, 客户端收到 close_notify
        // 会优雅断开自己的 tunnel writer, upload 那边 recv_data 报错退出.
        let _ = writer.send_close_notify().await;
        // 同时强制 shutdown upstream (上游已 EOF, 再 shutdown 是 idempotent),
        // 主要意义是: 若客户端忽视 close_notify 不断连接, upload 在 reader
        // 上仍阻塞, 此处再无能为力 (1800s 兜底). 但 upload 若是正在写 upstream,
        // 我们这一刀让它立刻报错退出.
        shutdown_upstream(stop_fd_down);
    };

    tokio::join!(upload, download);
}
