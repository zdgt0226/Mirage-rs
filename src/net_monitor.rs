//! 链路自愈: netlink 监听内核路由/地址/接口变更。
//!
//! 物理网络路径切换 (Wi-Fi↔蜂窝、宽带 IP 续租、载波 up/down、DHCP 重新分配) 后, WarmPool
//! 里预建的隧道全部绑在旧源地址/旧路由上, 已经静默失效。旧行为要等下一次 `pool.get()` 的
//! stale 探测或发送失败逐条发现, 期间用户前几个请求卡顿。
//!
//! 本模块开一个 netlink 路由 socket 订阅 LINK/ADDR/ROUTE 组播, 网络一变就广播一个递增
//! epoch (`tokio::watch`)。每个 WarmPool 订阅它, 变更即**清空整池**, builder 用新路径并发
//! 重建 —— 毫秒级切换而非等超时。
//!
//! 设计取舍: 只要收到任何 LINK/ADDR/ROUTE 通知就触发 (不细分是不是默认路由/出口源地址),
//! 靠 500ms 去抖把一次网络切换产生的十几条消息合并成一次 flush。flush = 重建连接池, 成本低
//! (几百 ms 补货), 对目标部署 (客户端/家用网关, 网络变更本就罕见) 完全够用。未来可解析
//! RTM_* 只对默认路由/出口源地址变化触发, 降低 route 频繁抖动机器上的误 flush。

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::OnceLock;
use tokio::sync::watch;

/// 全局网络变更 epoch。netlink 监听线程每次检测到变更就 +1; WarmPool 订阅 changed()。
static EPOCH_TX: OnceLock<watch::Sender<u64>> = OnceLock::new();
static MONITOR_STARTED: AtomicBool = AtomicBool::new(false);

fn sender() -> &'static watch::Sender<u64> {
    EPOCH_TX.get_or_init(|| watch::channel(0u64).0)
}

/// WarmPool 订阅网络变更。subscribe 后只对**未来**的变更触发 changed() (不含订阅时的当前值),
/// 故启动瞬间不会误 flush。
pub fn subscribe() -> watch::Receiver<u64> {
    sender().subscribe()
}

/// 广播一次网络变更 (epoch +1)。可从任意线程调 (watch::Sender 线程安全)。
fn bump() {
    sender().send_modify(|v| *v = v.wrapping_add(1));
}

/// 启动 netlink 监听 (幂等, 全局只一个)。由 WarmPool::new 调 —— 仅客户端/网关 (有连接池)
/// 才需要, 服务端无 WarmPool 自然不会启动这个线程。
pub fn spawn_monitor() {
    if MONITOR_STARTED.swap(true, Ordering::SeqCst) {
        return;
    }
    #[cfg(target_os = "linux")]
    imp::spawn();
}

#[cfg(target_os = "linux")]
mod imp {
    use super::bump;
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    use std::time::Duration;
    use tracing::{info, warn};

    // rtnetlink 组播组 (旧式 nl_groups 位掩码)。订阅接口/地址/路由的增删改。
    const RTMGRP_LINK: u32 = 0x1;
    const RTMGRP_IPV4_IFADDR: u32 = 0x10;
    const RTMGRP_IPV4_ROUTE: u32 = 0x40;
    const RTMGRP_IPV6_IFADDR: u32 = 0x100;
    const RTMGRP_IPV6_ROUTE: u32 = 0x400;
    /// 一次网络切换会连发十几条 netlink 消息, 去抖合并成一次 flush。
    const DEBOUNCE: Duration = Duration::from_millis(500);

    pub(super) fn spawn() {
        let fd = match open_netlink() {
            Ok(fd) => fd,
            Err(e) => {
                warn!("链路自愈 netlink 启动失败 ({e}); 降级为仅靠 get() stale 探测 + 首写重试");
                return;
            }
        };
        let _ = std::thread::Builder::new()
            .name("mirage-net-monitor".into())
            .spawn(move || run(fd));
        info!("链路自愈: netlink 网络变更监听已启动 (Wi-Fi↔蜂窝 / 宽带续租 / 载波变化 → 清空重建连接池)");
    }

    fn open_netlink() -> std::io::Result<OwnedFd> {
        let fd = unsafe {
            libc::socket(
                libc::AF_NETLINK,
                libc::SOCK_RAW | libc::SOCK_CLOEXEC,
                libc::NETLINK_ROUTE,
            )
        };
        if fd < 0 {
            return Err(std::io::Error::last_os_error());
        }
        // 立即 OwnedFd 接管, 后续任何 early-return 都会关 fd。
        let owned = unsafe { OwnedFd::from_raw_fd(fd) };

        let mut sa: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
        sa.nl_family = libc::AF_NETLINK as u16;
        sa.nl_groups = RTMGRP_LINK
            | RTMGRP_IPV4_IFADDR
            | RTMGRP_IPV4_ROUTE
            | RTMGRP_IPV6_IFADDR
            | RTMGRP_IPV6_ROUTE;
        let ret = unsafe {
            libc::bind(
                owned.as_raw_fd(),
                &sa as *const _ as *const libc::sockaddr,
                std::mem::size_of::<libc::sockaddr_nl>() as libc::socklen_t,
            )
        };
        if ret < 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(owned)
    }

    /// 阻塞收 netlink 通知的循环 (独立 OS 线程, 大部分时间阻塞在 recv)。收到一条变更就
    /// 排空当前 burst + 去抖 + 再排空, 然后 bump 一次 epoch。
    fn run(fd: OwnedFd) {
        let raw = fd.as_raw_fd();
        let mut buf = [0u8; 8192];
        loop {
            // 阻塞等下一条变更 (无变更时线程休眠, 不占 CPU)
            let n = unsafe { libc::recv(raw, buf.as_mut_ptr() as *mut _, buf.len(), 0) };
            if n < 0 {
                let err = std::io::Error::last_os_error();
                match err.raw_os_error() {
                    Some(libc::EINTR) => continue,
                    // 缓冲溢出 = 短时间大量变更, 照样视为"网络变了"
                    Some(libc::ENOBUFS) => {}
                    _ => {
                        warn!("链路自愈 netlink recv 错误 ({err}); 监听退出, 降级为 stale 探测/重试");
                        return;
                    }
                }
            }
            // 合并一个 burst: 排空 → 去抖 500ms → 再排空, 只 bump 一次
            drain(raw, &mut buf);
            std::thread::sleep(DEBOUNCE);
            drain(raw, &mut buf);
            bump();
        }
    }

    /// 非阻塞排空 socket 里已到达的剩余消息 (合并 burst 用)。
    fn drain(fd: i32, buf: &mut [u8]) {
        loop {
            let n = unsafe {
                libc::recv(fd, buf.as_mut_ptr() as *mut _, buf.len(), libc::MSG_DONTWAIT)
            };
            if n <= 0 {
                break;
            }
        }
    }

    #[cfg(test)]
    mod tests {
        use std::os::fd::AsRawFd;

        #[test]
        fn netlink_socket_opens_and_binds() {
            // 验证 AF_NETLINK/SOCK_RAW/NETLINK_ROUTE + bind 组播组的系统调用序列在本内核
            // 成功 (常量值 / sockaddr_nl 布局正确)。订阅 rtnetlink 组播不需 root。
            // 沙箱可能禁 netlink —— EPERM/EAFNOSUPPORT 时跳过而非误报失败。
            match super::open_netlink() {
                Ok(fd) => assert!(fd.as_raw_fd() >= 0),
                Err(e) => match e.raw_os_error() {
                    Some(libc::EPERM) | Some(libc::EAFNOSUPPORT) | Some(libc::EACCES) => {
                        eprintln!("skip: netlink 在此环境不可用 ({e}) —— 沙箱限制, 非代码问题");
                    }
                    _ => panic!("netlink socket open/bind 失败 (非权限原因): {e}"),
                },
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // EPOCH_TX 是 process-global; 并行测试会互相 bump 干扰。串行化独占。
    static TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    #[tokio::test]
    async fn subscribe_only_sees_future_bumps() {
        let _g = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let mut rx = subscribe();
        // 订阅后立刻 changed() 不应就绪 (无未来变更)
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(50), rx.changed())
                .await
                .is_err(),
            "订阅时的当前值不算变更, changed() 不应立即就绪"
        );
        // 一次 bump → changed() 就绪
        bump();
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(200), rx.changed())
                .await
                .is_ok(),
            "bump 后 changed() 应就绪"
        );
    }

    #[tokio::test]
    async fn bump_advances_epoch() {
        let _g = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let rx = subscribe();
        let before = *rx.borrow();
        bump();
        bump();
        assert_eq!(*rx.borrow(), before.wrapping_add(2), "两次 bump epoch +2");
    }
}
