//! 服务端 TCP 上游转发. 收到 target 后建立 TCP 连接, 双向 copy.
//!
//! 空闲超时默认 1800s = 30min 双向共享 - 给长连接 (WebSocket / 大文件下载) 留余量; 由
//! `crate::proxy::relay_idle()` 提供 (env `MIRAGE_RELAY_IDLE` 秒可调, 与客户端 handler 共用,
//! 两端须同设). 两个方向通过 `IdleClock` 共享活跃时间, 仅两向共同静默达 `relay_idle` 才断开.
//! 资源受限/高频短连接可调小防僵尸连接泄露.
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
//!
//! 代价: **不支持应用层 TCP 半关闭**。客户端本地 `read()==0` 分不清"半关闭等响应"
//! (`nc -N`、HTTP/1.0 式) 与"全关闭"(绝大多数), 收到 close_notify 后若只 SHUT_WR
//! 继续下行, 全关闭 + 上游不主动关的连接会两端挂到 relay_idle —— 正是上面修掉的僵尸。
//!
//! close_notify 语义: 服务端只在上游干净 EOF 时发 (下行完整); 上游出错/超额/吊销/
//! 空闲超时直接结束, 客户端读到裸 EOF 即判截断、对本地应用 RST 而非 FIN。
//! 上行对称: 只有 upload 收到客户端 close_notify、或 download 读到上游自身干净 EOF 时才对上游
//! FIN; 任一方向异常结束 (裸 EOF / 解密失败 / 超时 / 超额 / 吊销 / 读写失败) 都让上游看到 RST
//! (直连路径到目标; SS 路径只到 SS 服务端, 它对最终目标如何收尾不由我们决定)。WG 路径无论
//! 哪种都 `abort()` (smoltcp 发 RST), 干净结束也是 RST —— 既有行为, 未改。

use std::os::unix::io::AsRawFd;
use std::sync::Arc;
use std::sync::atomic::{AtomicI32, Ordering};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tracing::{debug, warn};

pub(super) async fn handle_tcp_relay(
    target: String,
    initial_payload: Option<Vec<u8>>,
    mut reader: crate::crypto::aead::CryptoReader<crate::proxy::tunnel::TunnelRead>,
    mut writer: crate::crypto::aead::CryptoWriter<crate::proxy::tunnel::TunnelWrite>,
    upstream_cfg: Option<Arc<crate::proxy::upstream::UpstreamOutlet>>,
    client_ip: Option<std::net::IpAddr>,
    user: String, // 命中的用户名 (多用户统计); 单用户恒 "default"
    session_auth: super::SessionAuth,
    allow_local_targets: bool,
    inbound_tag: Option<Arc<str>>,
) {
    let decision = super::server_router::server_route(
        inbound_tag.as_deref(),
        &target,
        "tcp",
        client_ip,
        &user,
        upstream_cfg.as_ref(),
    )
    .await;

    // WebUI 服务端连接登记 (T1: 域名排行 / 服务端 Connections 视图)。覆盖 direct + ss/wg 全路径
    let outbound_label = &decision.tag;
    let inbound_label = client_ip.map(|ip| ip.to_string()).unwrap_or_else(|| "client".into());
    let _conn = crate::monitor::register(
        target.clone(),
        inbound_label,
        outbound_label.clone(),
        "tcp",
        None,
        client_ip.map(|ip| ip.to_string()),
        Some(user.clone()),
    );

    // 配了上游或路由选到上游 → 本服务端作中转站, 流量再经上游出口发出, 而非直连目标。
    if let super::server_router::ServerOutboundTarget::Upstream(outlet) = decision.target {
        // 中转路径同样受限速/配额/吊销约束 (客户端 IP 桶 + 用户桶 + 凭据令牌), 否则配了上游即可绕过。
        let limits = UpstreamLimits {
            ip: client_ip.and_then(crate::proxy::rate_limit::server_buckets_for),
            auth: session_auth.clone(),
        };
        match &*outlet {
            crate::proxy::upstream::UpstreamOutlet::Shadowsocks(ss) => {
                relay_via_shadowsocks(target, initial_payload, reader, writer, ss, limits).await;
            }
            crate::proxy::upstream::UpstreamOutlet::Wireguard(wg) => {
                relay_via_wireguard(target, initial_payload, reader, writer, wg, limits).await;
            }
        }
        return;
    }
    debug!("Mirage Server: Connecting to TCP target {}", target);
    // connect_smart_filtered: 60s DNS 缓存 + IP 字面量零解析快车道 + 多候选 IP 逐一带超时 + 出站 SSRF 白名单过滤 ——
    // 既有缓存(免每连接重解析), 又保证首个 IP 丢包时跳到下一个, 且拒绝内网/链路本地/云元数据目标。
    let mut upstream = match crate::proxy::resolver::connect_smart_filtered(&target, |ip| {
        crate::net_util::egress_allowed(ip, allow_local_targets)
    }).await {
        Ok(s) => s,
        Err(e) => {
            if e.kind() == std::io::ErrorKind::PermissionDenied {
                super::warn_egress_blocked("Mirage Server TCP", &user, &target);
            } else {
                warn!("Mirage Server failed to connect to {}: {}", target, e);
            }
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

    // 限速 (device_profiles rate_limit_kbps): 服务端按连接的客户端 IP 取共享桶, 上/下行各整形。
    // 全局 limiter (server_buckets_for, 见 rate_limit.rs) 在 server 启动时按 config.routing 装。
    let dev_buckets = client_ip.and_then(crate::proxy::rate_limit::server_buckets_for);
    // 用户级限速与配额及凭据吊销已在分发时一次性获取 (避免与 connect 期间存在 TOCTOU 导致删除后放行)

    if let Some(payload) = initial_payload {
        if !payload.is_empty() {
            if let Some(b) = &dev_buckets {
                b.up.consume(payload.len()).await;
            }
            if session_auth.charge(payload.len(), true).await {
                return;
            }
            if upstream.write_all(&payload).await.is_err() {
                return;
            }
            _conn.counter().up(payload.len() as u64);
        }
    }
    let (mut up_read, mut up_write) = upstream.into_split();

    // 共享 atomic: 第一个 swap 到 -1 的 task 负责 shutdown, 另一方自然 break.
    // SUM_RDWR 让两个方向都立刻报 EOF/Err, 双向同时退出.
    // 第一个 swap(-1) 的任务调用 shutdown 时其自身半句柄仍存活, 第二个任务看到 -1 直接跳过, 故不存在 fd 复用窗口。
    let stop_fd = Arc::new(AtomicI32::new(upstream_fd));
    let stop_fd_up = stop_fd.clone();
    let stop_fd_down = stop_fd.clone();

    let shutdown_upstream = |stop: Arc<AtomicI32>| {
        let fd = stop.swap(-1, Ordering::SeqCst);
        if fd >= 0 {
            // SHUT_RDWR forces both directions to fail; idempotent — second
            // caller hits -1 swap and skips.
            unsafe {
                libc::shutdown(fd, libc::SHUT_RDWR);
            }
        }
    };
    // 同 shutdown_upstream 的抢占约定, 但以 RST 收尾 (异常结束时用)。
    let abort_upstream = |stop: Arc<AtomicI32>| {
        let fd = stop.swap(-1, Ordering::SeqCst);
        if fd >= 0 {
            crate::net_util::abort_socket(fd);
        }
    };

    let up_bkt = dev_buckets.clone();
    let dn_bkt = dev_buckets;

    let up_auth = session_auth.clone();
    let dn_auth = session_auth;

    let clock = Arc::new(crate::proxy::IdleClock::new());
    let up_clock = clock.clone();
    let dn_clock = clock;

    let up_conn = _conn.counter();
    let upload = async move {
        let mut clean_end = false;
        let mut write_failed = false;
        loop {
            if up_auth.should_stop() {
                break;
            }
            match crate::proxy::idle_timeout(&up_clock, crate::proxy::relay_idle(), reader.recv_data_borrowed()).await {
                Ok(Ok(data)) => {
                    up_clock.touch();
                    // 限速叠加: 客户端 IP 桶与用户桶同时扣 (取更严)
                    if let Some(b) = &up_bkt {
                        b.up.consume(data.len()).await; // 客户端上行限速整形
                    }
                    // 用户上行限速 + 配额计数; 越过配额或凭据吊销即断开
                    if up_auth.charge(data.len(), true).await {
                        break;
                    }
                    if up_write.write_all(data).await.is_err() {
                        write_failed = true;
                        break;
                    }
                    up_conn.up(data.len() as u64);
                }
                Ok(Err(e)) => {
                    clean_end = crate::crypto::aead::is_close_notify(&e);
                    break;
                }
                Err(_) => break,
            }
        }
        // upload 退出 (客户端 reader 报错或超时) → 强制 shutdown upstream,
        // 让 download 卡在 up_read.read() 上的阻塞立刻返回, 不再 hang 1800s。
        // 只有收到 close_notify (客户端完整结束写) 才让上游看到 FIN; 裸 EOF / 解密失败 / 超时 /
        // 超额 / 吊销都可能是路径注入的截断或异常收尾, 让上游看到 RST, 别把残缺上传当完整。
        // 写上游失败 = 上游已断, RST 无新信息, 且 abort 会清空接收队列, 丢掉上游已发出的早期
        // 响应 (如 413 后关闭); 走 SHUT_RDWR 保留队列, 让 download 把它转完 (随后仍按截断收尾)。
        if clean_end || write_failed {
            shutdown_upstream(stop_fd_up);
        } else {
            abort_upstream(stop_fd_up);
        }
        // 无条件 forget: 抢到 fd 的一方已安排好 FIN (SHUT_RDWR) 或 RST, 写半程 drop 补的
        // shutdown(Write) 永远多余 —— 且 download 刚抢到 fd、尚未 abort 时它会抢先发出 FIN。
        // fd 由读半程 drop 时关闭。
        up_write.forget();
    };

    let dn_conn = _conn.counter();
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
        let mut clean_eof = false;
        loop {
            if dn_auth.should_stop() {
                break;
            }
            match crate::proxy::idle_timeout(&dn_clock, crate::proxy::relay_idle(), up_read.read(&mut buf)).await {
                Ok(Ok(0)) => {
                    // 上游自己 EOF 才算干净结束; fd 已被 upload 置 -1 说明这个 0 是 upload 退出
                    // 时 SHUT_RDWR 造成的 (隧道上行被断/截断), 下行同样不完整。
                    clean_eof = stop_fd_down.load(Ordering::SeqCst) >= 0;
                    break;
                }
                Ok(Ok(n)) => {
                    dn_clock.touch();
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
                    // 限速叠加: 客户端 IP 桶与用户桶同时扣 (取更严)
                    if let Some(b) = &dn_bkt {
                        b.down.consume(total).await; // 客户端下行限速整形
                    }
                    // 用户下行限速 + 配额计数; 越过配额或凭据吊销即断开
                    if dn_auth.charge(total, false).await {
                        break;
                    }
                    if writer.send_data(&buf[..total]).await.is_err() {
                        break;
                    }
                    dn_conn.down(total as u64);
                }
                _ => break,
            }
        }
        // 只有上游干净 EOF 才发加密 close_notify —— 它是客户端判断"下行完整"的唯一依据
        // (客户端据此给本地应用 FIN, 否则 RST)。上游出错 / 超额 / 吊销 / 空闲超时直接结束:
        // writer 随本 future 结束而 drop, 隧道 TCP 写半关 (FIN), 客户端读到裸 EOF 即知被截断。
        // 此时 upload 协程还在 reader.recv_data 上, 客户端断开后 upload 那边 recv_data 报错退出.
        if clean_eof {
            let _ = writer.send_close_notify().await;
            // 同时强制 shutdown upstream (上游已 EOF, 再 shutdown 是 idempotent),
            // 主要意义是: 若客户端忽视 close_notify 不断连接, upload 在 reader
            // 上仍阻塞, 此处再无能为力 (1800s 兜底). 但 upload 若是正在写 upstream,
            // 我们这一刀让它立刻报错退出.
            shutdown_upstream(stop_fd_down);
        } else {
            // 下行异常先退出 (超额 / 吊销 / 写隧道失败 / 超时 / 上游出错): upload 可能还没收完,
            // 对上游 RST 而非 FIN, 别把残缺上传当完整。
            abort_upstream(stop_fd_down);
        }
    };

    tokio::join!(upload, download);
}

/// 经 Shadowsocks 上游中转的 TCP 转发。
///
/// 结构与直连路径一致(共享 fd + 任一方退出即 `shutdown(SHUT_RDWR)` 唤醒另一方),
/// 差别只在: 上游是 SS 加密流, 因此下行按**整块解密**读取, 用不上直连路径那个
/// 基于 `try_read` 的贪婪收割(SS 已按 ≤16KB 分块, 半块数据没有意义)。
/// 上游中转路径的限速/配额/吊销上下文 (客户端 IP 桶 + 用户桶 + 凭据令牌, 两桶都扣)。
#[derive(Clone)]
struct UpstreamLimits {
    ip: Option<Arc<crate::proxy::rate_limit::DeviceBuckets>>,
    auth: super::SessionAuth,
}

impl UpstreamLimits {
    /// 扣限速 + 计配额; 返回 true = 用户已超额或凭据已吊销, 调用方断开。
    async fn charge(&self, n: usize, up: bool) -> bool {
        if let Some(b) = &self.ip {
            if up { b.up.consume(n).await } else { b.down.consume(n).await }
        }
        self.auth.charge(n, up).await
    }

    fn exhausted(&self) -> bool {
        self.auth.should_stop()
    }
}

async fn relay_via_shadowsocks(
    target: String,
    initial_payload: Option<Vec<u8>>,
    mut reader: crate::crypto::aead::CryptoReader<crate::proxy::tunnel::TunnelRead>,
    mut writer: crate::crypto::aead::CryptoWriter<crate::proxy::tunnel::TunnelWrite>,
    ss: &crate::proxy::shadowsocks::SsConfig,
    limits: UpstreamLimits,
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
        if !payload.is_empty() {
            if limits.charge(payload.len(), true).await {
                return;
            }
            if up_write.write_all(&payload).await.is_err() {
                return;
            }
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

    let abort_upstream = |stop: Arc<AtomicI32>| {
        let fd = stop.swap(-1, Ordering::SeqCst);
        if fd >= 0 {
            crate::net_util::abort_socket(fd);
        }
    };

    let clock = Arc::new(crate::proxy::IdleClock::new());
    let up_clock = clock.clone();
    let dn_clock = clock;

    let up_lim = limits.clone();
    let upload = async move {
        let mut clean_end = false;
        let mut write_failed = false;
        loop {
            if up_lim.exhausted() {
                break;
            }
            match crate::proxy::idle_timeout(&up_clock, crate::proxy::relay_idle(), reader.recv_data_borrowed()).await {
                Ok(Ok(data)) => {
                    up_clock.touch();
                    if up_lim.charge(data.len(), true).await {
                        break; // 越过配额即断开
                    }
                    if up_write.write_all(data).await.is_err() {
                        write_failed = true;
                        break;
                    }
                }
                Ok(Err(e)) => {
                    clean_end = crate::crypto::aead::is_close_notify(&e);
                    break;
                }
                Err(_) => break,
            }
        }
        // 只有 close_notify 才对 SS 上游 FIN, 否则 RST; 写上游失败保留接收队列 (见直连路径)。
        if clean_end || write_failed {
            shutdown_upstream(stop_up);
        } else {
            abort_upstream(stop_up);
        }
        up_write.into_inner().forget(); // 无条件, 见直连路径
    };

    let download = async move {
        let mut clean_eof = false;
        loop {
            if limits.exhausted() {
                break;
            }
            match crate::proxy::idle_timeout(&dn_clock, crate::proxy::relay_idle(), up_read.read_chunk()).await {
                Ok(Ok(chunk)) if chunk.is_empty() => {
                    // 上游 EOF; fd 已被 upload 置 -1 则是 upload 退出时的 SHUT_RDWR 所致, 不算干净 (同直连路径)。
                    clean_eof = stop_down.load(Ordering::SeqCst) >= 0;
                    break;
                }
                Ok(Ok(chunk)) => {
                    dn_clock.touch();
                    if limits.charge(chunk.len(), false).await {
                        break; // 越过配额即断开
                    }
                    if writer.send_data(&chunk).await.is_err() {
                        break;
                    }
                }
                _ => break,
            }
        }
        if clean_eof {
            let _ = writer.send_close_notify().await; // 只在干净 EOF 时发, 见直连路径
            shutdown_upstream(stop_down);
        } else {
            abort_upstream(stop_down); // 下行异常先退出, 见直连路径
        }
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
    mut reader: crate::crypto::aead::CryptoReader<crate::proxy::tunnel::TunnelRead>,
    mut writer: crate::crypto::aead::CryptoWriter<crate::proxy::tunnel::TunnelWrite>,
    wg: &crate::proxy::upstream::WgUpstream,
    limits: UpstreamLimits,
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
    // upload 已退出 (随后 abort 整条连接) → download 读到的 EOF 不是上游自己的结束, 不算干净。
    let upload_done = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let upload_done_dn = upload_done.clone();

    if let Some(payload) = initial_payload {
        if !payload.is_empty() {
            if limits.charge(payload.len(), true).await {
                return;
            }
            if up_write.write_all(&payload).await.is_err() {
                return;
            }
        }
    }

    let clock = Arc::new(crate::proxy::IdleClock::new());
    let up_clock = clock.clone();
    let dn_clock = clock;

    let up_lim = limits.clone();
    let upload = async move {
        loop {
            if up_lim.exhausted() {
                break;
            }
            match crate::proxy::idle_timeout(&up_clock, crate::proxy::relay_idle(), reader.recv_data_borrowed()).await {
                Ok(Ok(data)) => {
                    up_clock.touch();
                    if up_lim.charge(data.len(), true).await {
                        break; // 越过配额即断开
                    }
                    if up_write.write_all(data).await.is_err() {
                        break;
                    }
                }
                _ => break,
            }
        }
        // 中止整条连接, 叫醒可能正阻塞在读上的 download。
        upload_done.store(true, Ordering::SeqCst);
        stop_up.abort();
    };

    let download = async move {
        let mut buf = vec![0u8; 32 * 1024];
        let mut clean_eof = false;
        loop {
            if limits.exhausted() {
                break;
            }
            match crate::proxy::idle_timeout(
                &dn_clock,
                crate::proxy::relay_idle(),
                up_read.read(&mut buf),
            )
            .await
            {
                Ok(Ok(0)) => {
                    clean_eof = !upload_done_dn.load(Ordering::SeqCst); // 上游 EOF
                    break;
                }
                Ok(Ok(n)) => {
                    dn_clock.touch();
                    if limits.charge(n, false).await {
                        break; // 越过配额即断开
                    }
                    if writer.send_data(&buf[..n]).await.is_err() {
                        break;
                    }
                }
                _ => break,
            }
        }
        if clean_eof {
            let _ = writer.send_close_notify().await; // 只在干净 EOF 时发, 见直连路径
        }
        stop_down.abort();
    };

    tokio::join!(upload, download);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::aead::{is_close_notify, CryptoReader, CryptoWriter};
    use std::os::fd::AsRawFd;
    use crate::proxy::tunnel::{TunnelRead, TunnelWrite};
    use std::time::Duration;
    use tokio::net::{TcpListener, TcpStream};

    /// 起直连中继: 返回客户端侧的加密读端 + 裸写半程 (服务端侧跑 handle_tcp_relay 到真上游 `target`)。
    async fn spawn_relay(
        target: String,
    ) -> (CryptoReader<tokio::net::tcp::OwnedReadHalf>, tokio::net::tcp::OwnedWriteHalf, tokio::task::JoinHandle<()>) {
        spawn_relay_with_auth(target, super::super::SessionAuth::unlimited()).await
    }

    async fn spawn_relay_with_auth(
        target: String,
        auth: super::super::SessionAuth,
    ) -> (CryptoReader<tokio::net::tcp::OwnedReadHalf>, tokio::net::tcp::OwnedWriteHalf, tokio::task::JoinHandle<()>) {
        let master = [0x42u8; 32];
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        let relay = tokio::spawn(async move {
            let (s, _) = l.accept().await.unwrap();
            let (r, w) = s.into_split();
            let reader = CryptoReader::new(TunnelRead::Tcp(r), &master, false);
            let writer = CryptoWriter::new(TunnelWrite::Tcp(w), &master, false);
            handle_tcp_relay(target, None, reader, writer, None, None, "default".into(), auth, true, None).await;
        });
        let c = TcpStream::connect(addr).await.unwrap();
        let (r, w) = c.into_split();
        (CryptoReader::new(r, &master, true), w, relay)
    }

    /// 读到结束, 返回 (收到的数据, 结束是否为 close_notify)。
    async fn read_until_end(r: &mut CryptoReader<tokio::net::tcp::OwnedReadHalf>) -> (Vec<u8>, bool) {
        let mut got = Vec::new();
        loop {
            match tokio::time::timeout(Duration::from_secs(5), r.recv_data()).await.expect("中继不应挂死") {
                Ok(d) => got.extend_from_slice(&d),
                Err(e) => return (got, is_close_notify(&e)),
            }
        }
    }

    #[tokio::test]
    async fn upstream_clean_eof_sends_close_notify() {
        let up = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target = up.local_addr().unwrap().to_string();
        tokio::spawn(async move {
            let (mut s, _) = up.accept().await.unwrap();
            s.write_all(b"hello").await.unwrap();
            // drop = FIN, 上游干净结束
        });
        let (mut cr, _cw, _relay) = spawn_relay(target).await;
        let (got, clean) = read_until_end(&mut cr).await;
        assert_eq!(got, b"hello");
        assert!(clean, "上游干净 EOF 时服务端必须发 close_notify");
    }

    #[tokio::test]
    async fn upstream_reset_does_not_send_close_notify() {
        let up = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target = up.local_addr().unwrap().to_string();
        tokio::spawn(async move {
            let (mut s, _) = up.accept().await.unwrap();
            s.write_all(b"hello").await.unwrap();
            tokio::time::sleep(Duration::from_millis(100)).await;
            let linger = libc::linger { l_onoff: 1, l_linger: 0 };
            // SAFETY: s 持有该 fd; 参数为栈上 linger 结构体及其大小。
            unsafe {
                libc::setsockopt(
                    s.as_raw_fd(),
                    libc::SOL_SOCKET,
                    libc::SO_LINGER,
                    &linger as *const libc::linger as *const libc::c_void,
                    std::mem::size_of::<libc::linger>() as libc::socklen_t,
                );
            }
            drop(s); // SO_LINGER=0 → RST
        });
        let (mut cr, _cw, _relay) = spawn_relay(target).await;
        let (got, clean) = read_until_end(&mut cr).await;
        assert_eq!(got, b"hello");
        assert!(!clean, "上游 RST 不是完整结束, 不得发 close_notify");
    }

    /// 隧道上行被截断 (客户端侧裸 FIN, 无 close_notify) → upload 退出 SHUT_RDWR 掐断下行;
    /// 下行读到的 0 是自己造成的, 不能当上游干净 EOF 发 close_notify。
    #[tokio::test]
    async fn tunnel_upload_truncation_does_not_send_close_notify() {
        let up = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target = up.local_addr().unwrap().to_string();
        tokio::spawn(async move {
            let (s, _) = up.accept().await.unwrap();
            tokio::time::sleep(Duration::from_secs(10)).await; // 上游保持打开不说话
            drop(s);
        });
        let (mut cr, mut cw, _relay) = spawn_relay(target).await;
        tokio::time::sleep(Duration::from_millis(100)).await; // 等中继连上上游
        cw.shutdown().await.unwrap(); // 裸 FIN, 无 close_notify
        let (got, clean) = read_until_end(&mut cr).await;
        assert!(got.is_empty());
        assert!(!clean, "上行被截断时服务端不得发 close_notify");
    }

    /// 隧道上行干净结束 (客户端发 close_notify) → upload 让上游看到 FIN (Ok(0))。
    #[tokio::test]
    async fn tunnel_upload_clean_close_reaches_upstream_as_fin() {
        let up = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target = up.local_addr().unwrap().to_string();
        let up_task = tokio::spawn(async move {
            let (mut s, _) = up.accept().await.unwrap();
            let mut buf = [0u8; 64];
            let n = s.read(&mut buf).await.unwrap();
            assert_eq!(&buf[..n], b"complete data");
            let mut end_buf = [0u8; 16];
            let n_end = s.read(&mut end_buf).await.unwrap();
            assert_eq!(n_end, 0, "客户端发送 close_notify 后上游应收到 FIN (Ok(0))");
        });
        let (_cr, w, _relay) = spawn_relay(target).await;
        let mut cw = CryptoWriter::new(w, &[0x42u8; 32], true);
        cw.send_data(b"complete data").await.unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;
        cw.send_close_notify().await.unwrap();
        tokio::time::timeout(Duration::from_secs(5), up_task)
            .await
            .expect("上游不应挂死")
            .unwrap();
    }

    /// 隧道上行被截断 (客户端侧裸 FIN, 无 close_notify) → upload 必须让上游看到 RST 而非 FIN。
    #[tokio::test]
    async fn tunnel_upload_truncation_reaches_upstream_as_reset() {
        let up = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target = up.local_addr().unwrap().to_string();
        let up_task = tokio::spawn(async move {
            let (mut s, _) = up.accept().await.unwrap();
            let mut buf = [0u8; 64];
            let n = s.read(&mut buf).await.unwrap();
            assert_eq!(&buf[..n], b"partial data");
            // 接下来读到结束: 截断时必须是 RST, 不能是 Ok(0)
            let mut end_buf = [0u8; 16];
            s.read(&mut end_buf).await
        });
        let (_cr, w, _relay) = spawn_relay(target).await;
        let mut cw = CryptoWriter::new(w, &[0x42u8; 32], true);
        cw.send_data(b"partial data").await.unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;
        drop(cw); // 裸 FIN, 无 close_notify
        let res = tokio::time::timeout(Duration::from_secs(5), up_task)
            .await
            .expect("上游不应挂死")
            .unwrap();
        assert!(
            matches!(&res, Err(e) if e.kind() == std::io::ErrorKind::ConnectionReset),
            "上行被截断时上游必须收到 RST, 实得: {res:?}"
        );
    }

    /// 下行异常先退出 (此处: 凭据吊销后上游再来数据) 时 upload 可能还没收完 → 上游必须看到 RST,
    /// 不能是 FIN。旧版 download 退出一律 SHUT_RDWR, 上游看到 FIN。
    #[tokio::test]
    async fn download_abnormal_exit_reaches_upstream_as_reset() {
        let up = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target = up.local_addr().unwrap().to_string();
        let (go_tx, go_rx) = tokio::sync::oneshot::channel::<()>();
        let up_task = tokio::spawn(async move {
            let (mut s, _) = up.accept().await.unwrap();
            let mut buf = [0u8; 64];
            let n = s.read(&mut buf).await.unwrap();
            assert_eq!(&buf[..n], b"partial");
            go_rx.await.unwrap();
            s.write_all(b"x").await.unwrap(); // 叫醒 download, 它发现已吊销即退出
            s.read(&mut buf).await
        });
        let revoked = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let auth = super::super::SessionAuth::new(None, revoked.clone());
        let (_cr, w, _relay) = spawn_relay_with_auth(target, auth).await;
        let mut cw = CryptoWriter::new(w, &[0x42u8; 32], true);
        cw.send_data(b"partial").await.unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;
        revoked.store(true, Ordering::SeqCst);
        go_tx.send(()).unwrap();
        let res = tokio::time::timeout(Duration::from_secs(5), up_task)
            .await
            .expect("上游不应挂死")
            .unwrap();
        assert!(
            matches!(&res, Err(e) if e.kind() == std::io::ErrorKind::ConnectionReset),
            "下行异常退出时上游必须收到 RST, 实得: {res:?}"
        );
    }
}
