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
    mut writer: crate::crypto::aead::CryptoWriter<tokio::net::tcp::OwnedWriteHalf>,
    upstream_cfg: Option<Arc<crate::proxy::upstream::UpstreamOutlet>>,
) {
    // 配了上游 → 本服务端作中转站, 流量再经上游出口发出, 而非直连目标。
    if let Some(outlet) = upstream_cfg {
        match &*outlet {
            crate::proxy::upstream::UpstreamOutlet::Shadowsocks(ss) => {
                relay_via_shadowsocks(target, initial_payload, reader, writer, ss).await;
            }
            crate::proxy::upstream::UpstreamOutlet::Wireguard(wg) => {
                relay_via_wireguard(target, initial_payload, reader, writer, wg).await;
            }
        }
        return;
    }
    debug!("Mirage Server: Connecting to TCP target {}", target);
    // connect_smart: 60s DNS 缓存 + IP 字面量零解析快车道 + **多候选 IP 逐一带超时** ——
    // 既有缓存(免每连接重解析), 又保证首个 IP 丢包时跳到下一个, 不会卡死内核 connect 超时。
    // (eb322b9 曾误用 resolve_first+裸connect, 只取第一个 IP 无 failover, 已回退。)
    let mut upstream = match crate::proxy::resolver::connect_smart(&target).await {
        Ok(s) => s,
        Err(e) => {
            warn!("Mirage Server failed to connect to {}: {}", target, e);
            return;
        }
    };

    // 在 split 前抓 FD: split 后两个 OwnedHalf 不再共享 as_raw_fd 接口
    let upstream_fd = upstream.as_raw_fd();

    // alpha.25 撤回 alpha.21 的显式 SO_SNDBUF/SO_RCVBUF setsockopt:
    // 手动设 buffer size 会 disable Linux TCP window auto-tuning, 固定
    // 8MB 窗口在高丢包链路上反而造成 bufferbloat (8MB in-flight → loss
    // 后大量重传排队 → 拖垮吞吐). 用户实测 alpha.22 就慢, 定位到这段
    // sockopt 是元凶. 让 kernel auto-tune 自己按 BDP + 丢包动态调节.

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
        // 老 16KB 太小 (alpha.21 加大到 64KB), 但仅仅加大 buf 只解决"能装多少",
        // 没解决"实际每次装了多少": tokio 的 read() 返回 kernel recv buffer 里
        // 现成的数据 (可能只有 8KB), 剩余到达的数据只能靠下一轮 poll 才拿到.
        //
        // 方向二 (greedy try_read): blocking read 拿到第一片后, 立刻 try_read
        // 非阻塞收割 kernel 里更多已到达的数据, 一次填到 64KB 或没更多为止.
        // 一次 send_data 送出大批 → CryptoWriter 里 BufWriter (alpha.23 加的)
        // 把多帧 syscall 合成一个大 write. 打破"读一片写一片"串行的碎片.
        let mut buf = vec![0u8; 65536];
        loop {
            match tokio::time::timeout(std::time::Duration::from_secs(1800), up_read.read(&mut buf)).await {
                Ok(Ok(0)) => break,
                Ok(Ok(n)) => {
                    let mut total = n;
                    // 贪婪收割: 非阻塞 try_read 继续填 buf 剩余空间, kernel 里有
                    // 多少数据就装多少, WouldBlock (E_AGAIN) 时立即退出. 不会
                    // 因为等 kernel 而增加延迟.
                    while total < buf.len() {
                        match up_read.try_read(&mut buf[total..]) {
                            Ok(0) => break,   // upstream 半关闭
                            Ok(more) => total += more,
                            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                            Err(_) => break,
                        }
                    }
                    if writer.send_data(&buf[..total]).await.is_err() {
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

/// 经 Shadowsocks 上游中转的 TCP 转发。
///
/// 结构与直连路径一致(共享 fd + 任一方退出即 `shutdown(SHUT_RDWR)` 唤醒另一方),
/// 差别只在: 上游是 SS 加密流, 因此下行按**整块解密**读取, 用不上直连路径那个
/// 基于 `try_read` 的贪婪收割(SS 已按 ≤16KB 分块, 半块数据没有意义)。
async fn relay_via_shadowsocks(
    target: String,
    initial_payload: Option<Vec<u8>>,
    mut reader: crate::crypto::aead::CryptoReader<tokio::net::tcp::OwnedReadHalf>,
    mut writer: crate::crypto::aead::CryptoWriter<tokio::net::tcp::OwnedWriteHalf>,
    ss: &crate::proxy::shadowsocks::SsConfig,
) {
    debug!("Mirage Server: 经 SS 上游 {} 转发到 {}", ss.addr(), target);
    let (mut up_read, mut up_write, up_fd) =
        match crate::proxy::shadowsocks::connect(ss, &target).await {
            Ok(v) => v,
            Err(e) => {
                warn!("Mirage Server: 连接 SS 上游 {} 失败 ({}): {}", ss.addr(), target, e);
                return;
            }
        };

    if let Some(payload) = initial_payload {
        if !payload.is_empty() && up_write.write_all(&payload).await.is_err() {
            return;
        }
    }

    let stop_fd = Arc::new(AtomicI32::new(up_fd));
    let (stop_up, stop_down) = (stop_fd.clone(), stop_fd.clone());
    let shutdown_upstream = |stop: Arc<AtomicI32>| {
        let fd = stop.swap(-1, Ordering::SeqCst);
        if fd >= 0 {
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
        shutdown_upstream(stop_up);
    };

    let download = async move {
        loop {
            match tokio::time::timeout(std::time::Duration::from_secs(1800), up_read.read_chunk()).await {
                Ok(Ok(chunk)) if chunk.is_empty() => break, // 上游 EOF
                Ok(Ok(chunk)) => {
                    if writer.send_data(&chunk).await.is_err() {
                        break;
                    }
                }
                _ => break,
            }
        }
        let _ = writer.send_close_notify().await;
        shutdown_upstream(stop_down);
    };

    tokio::join!(upload, download);
}

/// 经 WireGuard 上游中转。
///
/// 与 SS 上游的结构差异: SS 那边有真 fd, 靠共享 fd + `libc::shutdown(SHUT_RDWR)` 让对侧
/// 循环立刻退出; `WgTcpStream` **没有真 fd**(连接活在用户态 smoltcp 里)。
///
/// ⚠️ 曾经的写法是 `tokio::io::split` + "一方结束就 drop 自己那半, 另一半自然结束" ——
/// **那是错的**: `tokio::io::split` 把 stream 放进 `Arc<Mutex<_>>`, drop 掉一半只是减引用
/// 计数, 底层 stream 的 `Drop` 要**两半都 drop 了**才跑。结果是上行结束后下行仍阻塞在
/// 读上, 一直挂到 1800s 超时, 每条这样的连接钉住一个 task + 128KB 缓冲 —— 正是本文件
/// 头部注释里说的"僵尸泄漏"那一类。
///
/// 现在用 [`WgStreamCloser`] 显式中止: smoltcp 的 `set_state` 会 wake rx/tx waker,
/// 所以另一个任务里阻塞的读会立刻醒来退出。这是 `libc::shutdown` 的等价物。
async fn relay_via_wireguard(
    target: String,
    initial_payload: Option<Vec<u8>>,
    mut reader: crate::crypto::aead::CryptoReader<tokio::net::tcp::OwnedReadHalf>,
    mut writer: crate::crypto::aead::CryptoWriter<tokio::net::tcp::OwnedWriteHalf>,
    wg: &crate::proxy::upstream::WgUpstream,
) {
    debug!("Mirage Server: 经 WireGuard 上游 {} 转发到 {}", wg.cfg.endpoint, target);

    let tunnel = match wg.tunnel().await {
        Ok(t) => t,
        Err(e) => {
            warn!("Mirage Server: 建立 WireGuard 上游隧道失败: {}", e);
            return;
        }
    };

    // 隧道内没有 DNS —— 域名在本服务端解析后, 只把 IP 送进隧道。
    let (host, port) = match target.rsplit_once(':').and_then(|(h, p)| {
        p.parse::<u16>().ok().map(|p| (h.trim_matches(['[', ']']), p))
    }) {
        Some(hp) => hp,
        None => {
            warn!("Mirage Server: 目标 `{}` 不是合法 host:port", target);
            return;
        }
    };
    let addr = match crate::proxy::wg::resolve_target(&tunnel, host, port).await {
        Ok(a) => a,
        Err(e) => {
            warn!("Mirage Server: 解析 {} 失败: {}", target, e);
            return;
        }
    };

    let stream = match crate::proxy::wg::socket::WgTcpStream::connect(tunnel, addr).await {
        Ok(s) => s,
        Err(e) => {
            warn!("Mirage Server: 经 WG 隧道连接 {} 失败: {}", target, e);
            return;
        }
    };
    let closer = stream.closer();
    let (mut up_read, mut up_write) = tokio::io::split(stream);
    let (stop_up, stop_down) = (closer.clone(), closer);

    if let Some(payload) = initial_payload {
        if !payload.is_empty() && up_write.write_all(&payload).await.is_err() {
            return;
        }
    }

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
        // 中止整条连接, 叫醒可能正阻塞在读上的 download。
        stop_up.abort();
    };

    let download = async move {
        let mut buf = vec![0u8; 32 * 1024];
        loop {
            match tokio::time::timeout(
                std::time::Duration::from_secs(1800),
                up_read.read(&mut buf),
            )
            .await
            {
                Ok(Ok(0)) => break, // 上游 EOF
                Ok(Ok(n)) => {
                    if writer.send_data(&buf[..n]).await.is_err() {
                        break;
                    }
                }
                _ => break,
            }
        }
        let _ = writer.send_close_notify().await;
        stop_down.abort();
    };

    tokio::join!(upload, download);
}
