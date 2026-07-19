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
//! 设计取舍: 解析 RTM_* 消息类型, 对 LINK (载波 up/down)、ADDR (源地址增删/续租)、以及
//! **默认路由**变化触发, 只滤掉忙机上的非默认路由抖动噪声 (BGP/具体 /32·/24 增删)。再靠
//! 500ms 去抖把一次网络切换产生的十几条消息合并成一次 flush。flush = 重建连接池, 成本低
//! (几百 ms 补货), 对目标部署 (客户端/家用网关) 完全够用。判据见 imp::should_bump。

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

    /// 扫一个 netlink 缓冲里的所有消息, 判断是否值得清空重建连接池。
    /// 只滤掉一种高频噪声: 忙机上的**非默认路由**抖动 (BGP/具体 /32·/24 路由增删)。
    /// 载波 up/down (LINK)、源地址增删续租 (ADDR)、默认路由变化 (ROUTE dst_len==0)
    /// 都是真网络切换 → 触发。任一消息值得触发即返回 true。
    fn should_bump(buf: &[u8]) -> bool {
        let mut pos = 0;
        while pos + 16 <= buf.len() {
            let nlmsg_len = u32::from_ne_bytes(buf[pos..pos + 4].try_into().unwrap()) as usize;
            let nlmsg_type = u16::from_ne_bytes(buf[pos + 4..pos + 6].try_into().unwrap());

            if nlmsg_len < 16 || pos + nlmsg_len > buf.len() {
                break;
            }

            match nlmsg_type {
                // RTM_NEWLINK=16 / RTM_DELLINK=17 (载波 up/down),
                // RTM_NEWADDR=20 / RTM_DELADDR=21 (源地址增删/DHCP 续租) —— 均为真变更。
                16 | 17 | 20 | 21 => return true,
                // RTM_NEWROUTE=24 / RTM_DELROUTE=25 —— 只认默认路由 (rtmsg.rtm_dst_len==0,
                // 即 0.0.0.0/0 或 ::/0), 过滤具体路由抖动噪声。rtm_dst_len 在 rtmsg offset 1。
                24 | 25 => {
                    if pos + 16 + 2 <= buf.len() && buf[pos + 16 + 1] == 0 {
                        return true;
                    }
                }
                _ => {}
            }
            pos = (pos + nlmsg_len + 3) & !3; // NLMSG_ALIGN
        }
        false
    }

    /// 阻塞收 netlink 通知的循环 (独立 OS 线程, 大部分时间阻塞在 recv)。收到一批变更就
    /// 判定是否值得触发, 值得则排空当前 burst + 去抖 + 再排空, 然后 bump 一次 epoch。
    fn run(fd: OwnedFd) {
        let raw = fd.as_raw_fd();
        let mut buf = [0u8; 8192];
        loop {
            // 阻塞等下一条变更 (无变更时线程休眠, 不占 CPU)
            let n = unsafe { libc::recv(raw, buf.as_mut_ptr() as *mut _, buf.len(), 0) };

            let changed = if n < 0 {
                let err = std::io::Error::last_os_error();
                match err.raw_os_error() {
                    Some(libc::EINTR) => continue,
                    // 缓冲溢出 = 短时间大量变更, 无法解析内容, 保守视为"网络变了"
                    Some(libc::ENOBUFS) => true,
                    _ => {
                        warn!("链路自愈 netlink recv 错误 ({err}); 监听退出, 降级为 stale 探测/重试");
                        return;
                    }
                }
            } else {
                should_bump(&buf[..n as usize])
            };

            if !changed {
                continue;
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
        use super::should_bump;
        use std::os::fd::AsRawFd;

        /// 造一条 netlink 消息: [len u32][type u16][flags u16][seq u32][pid u32][payload], 4B 对齐。
        fn nlmsg(nlmsg_type: u16, payload: &[u8]) -> Vec<u8> {
            let len = 16 + payload.len();
            let mut m = Vec::new();
            m.extend_from_slice(&(len as u32).to_ne_bytes());
            m.extend_from_slice(&nlmsg_type.to_ne_bytes());
            m.extend_from_slice(&0u16.to_ne_bytes()); // flags
            m.extend_from_slice(&0u32.to_ne_bytes()); // seq
            m.extend_from_slice(&0u32.to_ne_bytes()); // pid
            m.extend_from_slice(payload);
            while m.len() % 4 != 0 {
                m.push(0); // NLMSG_ALIGN
            }
            m
        }

        /// rtmsg payload (12B): family, dst_len, src_len, tos, table, proto, scope, type, flags(4B)。
        fn rtmsg(dst_len: u8) -> Vec<u8> {
            let mut p = vec![0u8; 12];
            p[1] = dst_len; // rtm_dst_len
            p
        }

        #[test]
        fn default_route_triggers() {
            // RTM_NEWROUTE(24) dst_len=0 = 默认路由 → true
            assert!(should_bump(&nlmsg(24, &rtmsg(0))));
            // RTM_DELROUTE(25) dst_len=0 → true
            assert!(should_bump(&nlmsg(25, &rtmsg(0))));
        }

        #[test]
        fn specific_route_noise_ignored() {
            // 具体路由 (dst_len=24/32) 抖动 = 噪声 → false
            assert!(!should_bump(&nlmsg(24, &rtmsg(24))));
            assert!(!should_bump(&nlmsg(25, &rtmsg(32))));
            // 一堆非默认路由拼一起仍 false
            let mut buf = nlmsg(24, &rtmsg(24));
            buf.extend(nlmsg(25, &rtmsg(32)));
            buf.extend(nlmsg(24, &rtmsg(16)));
            assert!(!should_bump(&buf));
        }

        #[test]
        fn link_and_addr_always_trigger() {
            // 这些是本 WIP 早期漏掉的: 载波与源地址变化必须触发 (换源 IP 但网关不变的场景)
            for t in [16u16, 17, 20, 21] {
                // ADDR/LINK 消息带各自结构体, 内容无关紧要, 给 8B 占位
                assert!(should_bump(&nlmsg(t, &[0u8; 8])), "nlmsg_type {t} 应触发");
            }
        }

        #[test]
        fn mixed_burst_default_route_wins() {
            // 一次切换的 burst: 具体路由噪声 + 中间夹一条默认路由 → true
            let mut buf = nlmsg(24, &rtmsg(24));
            buf.extend(nlmsg(24, &rtmsg(0))); // 默认路由
            buf.extend(nlmsg(25, &rtmsg(32)));
            assert!(should_bump(&buf));
        }

        #[test]
        fn garbage_and_truncation_no_panic() {
            assert!(!should_bump(&[])); // 空
            assert!(!should_bump(&[1, 2, 3])); // 不足一个头
            // 声明 len=999 但 buf 不够 → 越界守卫 break, 不 panic, 返回 false
            let mut m = 999u32.to_ne_bytes().to_vec();
            m.extend_from_slice(&24u16.to_ne_bytes());
            m.extend_from_slice(&[0u8; 10]);
            assert!(!should_bump(&m));
            // nlmsg_len < 16 (畸形) → break
            let mut bad = 8u32.to_ne_bytes().to_vec();
            bad.extend_from_slice(&[0u8; 12]);
            assert!(!should_bump(&bad));
        }

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
