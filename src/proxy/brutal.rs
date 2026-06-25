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

/// 给已建立的 TCP socket 应用 Brutal CC + 速率.
///
/// `rate_bytes_per_sec` = config 里 `brutal_rate_mbps * 125_000`.
///
/// 失败 (内核模块没装等) 仅 WARN 一次 (per-process), socket 仍可用
/// (内核自动回退到默认 CC). 不返回错误是故意的 — Brutal 是优化项不是必需项.
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
