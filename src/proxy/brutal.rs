//! Brutal CC per-socket setup helper.
//!
//! TCP_CONGESTION 是 per-socket per-direction 的内核机制 — setsockopt 只控
//! 制这个 socket 的"发送方向". 代理场景里:
//!
//!   - 服务端在 accept 的 socket 上设 brutal → 控制 server→client 速率
//!     (即客户端的下载速度, 大多数代理用户最关心的方向)
//!   - 客户端在 outbound socket 上设 brutal → 控制 client→server 速率
//!     (上传速度)
//!
//! 两端各自管自己, 无需任何协议层协商. 一端没装 tcp_brutal 内核模块
//! 只影响这一端的发送方向, 自动回退到 BBR/Cubic, 不影响对端.
//!
//! 当前 helper 只做静态 setsockopt; 客户端的动态速率调节 (基于 BPF RTT
//! 反馈) 仍在 src/proxy/pool.rs 里独立维护.

use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

// 自适应回落参数. 服务端默认启用 brutal, 但部分链路 (国内访问跨洲 CDN 等)
// 实际丢包率高, brutal 死磕设定速率会引爆重传, 净吞吐反不如 BBR. 设计:
// 每条 brutal-enabled 连接起一个 monitor task, 周期性读 TCP_INFO, 重传率
// 超阈值 → setsockopt TCP_CONGESTION=bbr 切回, 让 kernel 自适应.
const MONITOR_INTERVAL: Duration = Duration::from_secs(10);
const MIN_SEGS_PER_WINDOW: u32 = 500;        // 不到 500 包不评估 (流量太少噪声大)
const RETRANS_THRESHOLD_PCT: f64 = 5.0;      // 单窗口 retrans 比 > 5% 判定不适合
const MAX_MONITOR_CHECKS: usize = 18;        // 3 分钟 (18 × 10s) 后停止监测
const STABLE_OK_CHECKS: usize = 6;           // 连续 6 个窗口正常即认定该链路稳定

/// 仅在 LISTENER fd 上设 TCP_CONGESTION = "brutal", accept 出来的子 socket
/// 自动继承算法名. 这样子 socket 从 SYN-ACK 起就是 brutal, kernel pacing
/// 状态干净, 避免中途从 BBR/cubic 切换到 brutal 时 pacing 状态过渡不一致
/// 导致的吞吐塌方 (alpha.5/alpha.6 的根因, 跟 Python POC 实测对比发现).
///
/// 必须在 bind 后, 第一次 accept 前调用一次.
pub fn set_brutal_on_listener(fd: i32) {
    static CC_WARNED: AtomicBool = AtomicBool::new(false);
    unsafe {
        let brutal = b"brutal\0";
        let ret = libc::setsockopt(
            fd,
            libc::IPPROTO_TCP,
            libc::TCP_CONGESTION,
            brutal.as_ptr() as *const libc::c_void,
            7,
        );
        if ret < 0 {
            let err = std::io::Error::last_os_error();
            if !CC_WARNED.swap(true, Ordering::Relaxed) {
                tracing::warn!(
                    "brutal CC unavailable on listener ({}). Install tcp-brutal kernel module \
                     or remove brutal_rate_mbps from config.",
                    err
                );
            }
        } else {
            tracing::info!("Brutal CC pre-set on listener fd={} (will be inherited by accepted sockets)", fd);
        }
    }
}

/// 在已 accept 的 TCP socket 上只设 TCP_BRUTAL_PARAMS (速率 + cwnd_gain).
/// 不再重设 TCP_CONGESTION — 算法名通过 listener 继承.
///
/// `rate_bytes_per_sec` = config 里 `brutal_rate_mbps * 125_000`.
pub fn set_brutal_rate(fd: i32, rate_bytes_per_sec: u64) {
    static PARAMS_WARNED: AtomicBool = AtomicBool::new(false);
    unsafe {
        const TCP_BRUTAL_PARAMS: libc::c_int = 23301;
        #[repr(C, packed)]
        struct BrutalParams {
            rate: u64,
            cwnd_gain: u32,
        }
        const CWND_GAIN_X10: u32 = 20;
        let params = BrutalParams {
            rate: rate_bytes_per_sec,
            cwnd_gain: CWND_GAIN_X10,
        };
        let pret = libc::setsockopt(
            fd,
            libc::IPPROTO_TCP,
            TCP_BRUTAL_PARAMS,
            &params as *const _ as *const libc::c_void,
            std::mem::size_of::<BrutalParams>() as libc::socklen_t,
        );
        if pret < 0 {
            let err = std::io::Error::last_os_error();
            if !PARAMS_WARNED.swap(true, Ordering::Relaxed) {
                tracing::warn!(
                    "brutal TCP_BRUTAL_PARAMS failed ({}). Possible tcp-brutal \
                     module version mismatch.",
                    err
                );
            }
        }
    }
}

/// 给已建立的 TCP socket 应用 Brutal CC + 速率.
///
/// `rate_bytes_per_sec` = config 里 `brutal_rate_mbps * 125_000`.
///
/// 失败 (内核模块没装等) 仅 WARN 一次 (per-process), socket 仍可用
/// (内核自动回退到默认 CC). 不返回错误是故意的 — Brutal 是优化项不是必需项.
///
/// 注: 服务端入站建议改用 set_brutal_on_listener + set_brutal_rate 组合,
/// 避免中途从默认 CC 切换到 brutal 导致 kernel pacing 状态过渡问题.
/// 本函数仅给客户端出站 (pool.rs) 用 — 客户端 outbound 是主动 connect,
/// 没有可继承的 listener, 只能在 connect 后 apply.
pub fn apply_brutal(fd: i32, rate_bytes_per_sec: u64) {
    static CC_WARNED: AtomicBool = AtomicBool::new(false);
    static PARAMS_WARNED: AtomicBool = AtomicBool::new(false);

    unsafe {
        // 1. TCP_CONGESTION = "brutal"
        let brutal = b"brutal\0";
        let ret = libc::setsockopt(
            fd,
            libc::IPPROTO_TCP,
            libc::TCP_CONGESTION,
            brutal.as_ptr() as *const libc::c_void,
            7,
        );
        if ret < 0 {
            let err = std::io::Error::last_os_error();
            if !CC_WARNED.swap(true, Ordering::Relaxed) {
                tracing::warn!(
                    "brutal CC unavailable ({}). Install hysteria-tcp-brutal-dkms \
                     or remove brutal_rate_mbps from config.",
                    err
                );
            }
            return;
        }

        // 2. TCP_BRUTAL_PARAMS — 注意两件事:
        //
        // (a) 常量值 = 23301, 不是 23. 23 是 Linux 标准 TCP_FASTOPEN, 内核协议
        //     栈会先吃掉这个 opt, 我们的 brutal 模块根本看不到. TCP_FASTOPEN
        //     在 ESTABLISHED 状态下直接返 -EINVAL → 之前 v0.x 的 brutal CC
        //     全部 100% 静默失败. apernet/tcp-brutal 官方源码定义为 23301
        //     以避开冲突. 实测验证 https://github.com/apernet/tcp-brutal.
        //
        // (b) struct 必须 #[repr(C, packed)] (12 字节, 不是 16). 内核源码
        //     struct brutal_params { u64 rate; u32 cwnd_gain; } __packed;
        //     sizeof = 12. 我们这边 Rust 也要 packed 才完全对齐. 之前
        //     v0.4.1-alpha.1 把 packed 去掉是基于第三方分析的误判, 实测
        //     拿 brutal.c 上游源码确认内核确实 __packed.
        const TCP_BRUTAL_PARAMS: libc::c_int = 23301;
        #[repr(C, packed)]
        struct BrutalParams {
            rate: u64,
            cwnd_gain: u32,
        }
        // X10 编码: 20 = 2.0× BDP. 匹配 apernet/tcp-brutal 内核默认值.
        // 之前用 15 (= 1.5× BDP) 在低 RTT 链路上 cwnd 偏紧, ACK 没回 cwnd 就满,
        // 实测吞吐 < 设定 rate (E rate=20 ≈ F rate=50 的根因).
        const CWND_GAIN_X10: u32 = 20;
        let params = BrutalParams {
            rate: rate_bytes_per_sec,
            cwnd_gain: CWND_GAIN_X10,
        };
        let pret = libc::setsockopt(
            fd,
            libc::IPPROTO_TCP,
            TCP_BRUTAL_PARAMS,
            &params as *const _ as *const libc::c_void,
            std::mem::size_of::<BrutalParams>() as libc::socklen_t,
        );
        if pret < 0 {
            let err = std::io::Error::last_os_error();
            if !PARAMS_WARNED.swap(true, Ordering::Relaxed) {
                tracing::warn!(
                    "brutal TCP_BRUTAL_PARAMS failed ({}). Possible tcp-brutal \
                     module version mismatch.",
                    err
                );
            }
        }
    }
}

// ── 自适应回落 ──────────────────────────────────────────────────────

// libc 0.2.186 的 tcp_info 只到 tcpi_total_retrans (2.6.27 时代字段).
// 我们要 tcpi_segs_out 来算 retrans 率, 自定义完整 struct (匹配 Linux
// 上游 include/uapi/linux/tcp.h, 是 append-only ABI 稳定). 不引新依赖.
// kernel 返回长度小于本 struct 时尾部字段保留 0, 老内核场景下 segs_out=0
// 自然就跳过判断 (MIN_SEGS_PER_WINDOW 检查兜底), 安全降级.
#[repr(C)]
#[derive(Default, Clone, Copy)]
struct TcpInfoExt {
    state: u8,
    ca_state: u8,
    retransmits: u8,
    probes: u8,
    backoff: u8,
    options: u8,
    wscale: u8,
    delivery_flags: u8,
    rto: u32,
    ato: u32,
    snd_mss: u32,
    rcv_mss: u32,
    unacked: u32,
    sacked: u32,
    lost: u32,
    retrans: u32,
    fackets: u32,
    last_data_sent: u32,
    last_ack_sent: u32,
    last_data_recv: u32,
    last_ack_recv: u32,
    pmtu: u32,
    rcv_ssthresh: u32,
    rtt: u32,
    rttvar: u32,
    snd_ssthresh: u32,
    snd_cwnd: u32,
    advmss: u32,
    reordering: u32,
    rcv_rtt: u32,
    rcv_space: u32,
    total_retrans: u32,
    // Linux 3.15+ extensions
    pacing_rate: u64,
    max_pacing_rate: u64,
    bytes_acked: u64,
    bytes_received: u64,
    segs_out: u32,
    segs_in: u32,
}

fn get_tcp_info(fd: i32) -> std::io::Result<TcpInfoExt> {
    let mut info = TcpInfoExt::default();
    let mut len: libc::socklen_t = std::mem::size_of::<TcpInfoExt>() as _;
    let ret = unsafe {
        libc::getsockopt(
            fd,
            libc::IPPROTO_TCP,
            libc::TCP_INFO,
            &mut info as *mut _ as *mut libc::c_void,
            &mut len,
        )
    };
    if ret < 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(info)
    }
}

fn get_socket_cookie(fd: i32) -> std::io::Result<u64> {
    let mut cookie: u64 = 0;
    let mut len: libc::socklen_t = std::mem::size_of::<u64>() as _;
    let ret = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_COOKIE,
            &mut cookie as *mut _ as *mut libc::c_void,
            &mut len,
        )
    };
    if ret < 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(cookie)
    }
}

fn switch_to_bbr(fd: i32) -> std::io::Result<()> {
    let bbr = b"bbr\0";
    let ret = unsafe {
        libc::setsockopt(
            fd,
            libc::IPPROTO_TCP,
            libc::TCP_CONGESTION,
            bbr.as_ptr() as *const libc::c_void,
            4,
        )
    };
    if ret < 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(())
    }
}

/// 监测 brutal-enabled 连接的 retrans 率, 超阈值自动 setsockopt 切回 BBR.
///
/// 用 SO_COOKIE 防 fd 复用错认 (socket 被回收后内核可能复用同一 fd 给新连接,
/// 仅靠 fd 监测会误操作无关 socket). cookie 不变才继续判断.
///
/// 连续 STABLE_OK_CHECKS 个窗口正常 (1 分钟) 或 MAX_MONITOR_CHECKS 次后停止,
/// 避免长连接永远轮询.
pub fn spawn_fallback_monitor(fd: i32) {
    let initial_cookie = match get_socket_cookie(fd) {
        Ok(c) => c,
        Err(_) => return, // 拿不到 cookie 就放弃监测 (内核太旧 / fd 已无效)
    };

    tokio::spawn(async move {
        let mut prev_retrans: u32 = 0;
        let mut prev_segs: u32 = 0;
        let mut consecutive_ok: usize = 0;
        let mut first_sample = true;

        for _check_idx in 0..MAX_MONITOR_CHECKS {
            tokio::time::sleep(MONITOR_INTERVAL).await;

            // 防 fd 复用: cookie 变了说明原 socket 已死, 新 fd 不归我们管.
            match get_socket_cookie(fd) {
                Ok(c) if c == initial_cookie => {}
                _ => return,
            }

            let info = match get_tcp_info(fd) {
                Ok(i) => i,
                Err(_) => return, // socket 关闭
            };

            let cur_retrans = info.total_retrans;
            let cur_segs = info.segs_out;

            if first_sample {
                prev_retrans = cur_retrans;
                prev_segs = cur_segs;
                first_sample = false;
                continue;
            }

            let delta_retrans = cur_retrans.saturating_sub(prev_retrans);
            let delta_segs = cur_segs.saturating_sub(prev_segs);
            prev_retrans = cur_retrans;
            prev_segs = cur_segs;

            // 流量不够无法判断
            if delta_segs < MIN_SEGS_PER_WINDOW {
                continue;
            }

            let retrans_pct = (delta_retrans as f64 / delta_segs as f64) * 100.0;

            if retrans_pct > RETRANS_THRESHOLD_PCT {
                // 不适合 brutal — 切回 BBR
                match switch_to_bbr(fd) {
                    Ok(_) => tracing::warn!(
                        "Brutal CC unsuitable for this link (fd={}, retrans {:.1}% in 10s window). \
                         Auto-fallback to BBR.",
                        fd, retrans_pct
                    ),
                    Err(e) => tracing::warn!(
                        "Brutal CC retrans high ({:.1}%) but BBR fallback failed: {}",
                        retrans_pct, e
                    ),
                }
                return;
            }

            consecutive_ok += 1;
            if consecutive_ok >= STABLE_OK_CHECKS {
                // 链路稳定, 不必再监测
                tracing::debug!(
                    "Brutal CC stable on fd={} ({} OK windows), stopping monitor",
                    fd, consecutive_ok
                );
                return;
            }
        }
    });
}
