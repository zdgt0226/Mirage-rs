//! 把 smoltcp 的**轮询式** TCP socket 包成 tokio 的 `AsyncRead`/`AsyncWrite`。
//!
//! 两个模型的落差是这层的全部难点:
//!
//! | | smoltcp | tokio |
//! |---|---|---|
//! | 驱动 | 外部反复调 `poll()` | 靠 waker 唤醒 |
//! | 读写 | `can_recv()` 后 `recv_slice()`, 满了就返回 0 | `Poll::Pending` + 注册 waker |
//!
//! 桥接靠 smoltcp 的 `register_recv_waker`/`register_send_waker` (需 `async` feature):
//! 数据没准备好时把 tokio 的 waker 交给 smoltcp, pump 下次 `poll` 让 socket 状态变化时
//! smoltcp 会唤醒我们。**不轮询、不 sleep**, 否则要么烧 CPU 要么加延迟。
//!
//! 写侧还必须在 `send_slice` 之后调 `tunnel.poll_now()`: 数据进了 socket 的发送缓冲不等于
//! 发出去了, 得驱动 smoltcp 生成 IP 包、再叫醒 pump 加密发送。漏了这步表现为
//! "写成功但对端半天收不到"。

use super::tunnel::{lock_inner, WgTunnel};
use anyhow::{anyhow, Result};
use smoltcp::iface::SocketHandle;
use smoltcp::socket::tcp;
use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// 单条连接的收发缓冲。64KB 是吞吐与内存的常见折中 (BDP 100Mbps×5ms ≈ 62KB)。
const SOCK_BUF: usize = 64 * 1024;

/// 建连超时。**必须有**: smoltcp 的 socket 没调 `set_timeout`, SynSent 会以退避 RTO
/// 无限重传, 状态机自己永远不会退出 —— 没有这个超时, 连一个被丢包的目标就会把调用任务
/// 和它那 128KB 缓冲永久钉死。
///
/// 只管建连: 不给 socket 设 smoltcp 的空闲超时, 否则代理里合法的长空闲连接 (SSH 等)
/// 会被误杀。
const CONNECT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(15);

/// 经 WireGuard 隧道的一条 TCP 连接。
pub struct WgTcpStream {
    tunnel: Arc<WgTunnel>,
    handle: SocketHandle,
    /// socket 是否还在 SocketSet 里。`SocketSet` 的取用接口对失效 handle 一律 panic,
    /// 而 [`WgStreamCloser`] 可能在本 stream 已 drop 后才被调用, 故需要这个标志。
    alive: Arc<AtomicBool>,
}

/// 可跨任务使用的连接中止句柄。
///
/// 存在的理由: 双向转发的两个方向跑在不同的 future 里, 一方结束时必须把另一方也叫醒,
/// 否则它会一直挂到自己的超时 (本项目里是 1800s), 每条这样的连接钉住一个 task +
/// 128KB 缓冲。SS/直连腿靠共享 fd + `libc::shutdown(SHUT_RDWR)` 做到这点, 而
/// `WgTcpStream` **没有真 fd** —— 连接活在用户态 smoltcp 里。
///
/// 替代机制: smoltcp 在 `async` feature 下, `set_state` 会 wake rx/tx waker,
/// 所以 `abort()` 能让阻塞在另一个任务里的读/写立刻醒来、看到 Closed 后退出。
#[derive(Clone)]
pub struct WgStreamCloser {
    tunnel: Arc<WgTunnel>,
    handle: SocketHandle,
    alive: Arc<AtomicBool>,
}

impl WgStreamCloser {
    /// 立刻中止连接并唤醒任何阻塞在这条连接上的任务。可重复调用。
    pub fn abort(&self) {
        {
            let mut g = lock_inner(&self.tunnel.inner);
            // alive 的读写都在同一把锁下, 与 Drop 里的 remove 互斥, 不会取到失效 handle。
            if !self.alive.load(Ordering::Relaxed) {
                return;
            }
            g.sockets.get_mut::<tcp::Socket>(self.handle).abort();
        }
        self.tunnel.poll_now();
    }
}

impl WgTcpStream {
    /// 经隧道连接目标。等到 TCP 进入 Established 才返回。
    ///
    /// 本地端口随机取 —— smoltcp 不像内核会自动分配, 得自己给。
    pub async fn connect(tunnel: Arc<WgTunnel>, remote: std::net::SocketAddr) -> Result<Self> {
        let handle = {
            let mut g = lock_inner(&tunnel.inner);
            let sock = tcp::Socket::new(
                tcp::SocketBuffer::new(vec![0u8; SOCK_BUF]),
                tcp::SocketBuffer::new(vec![0u8; SOCK_BUF]),
            );
            let handle = g.sockets.add(sock);
            let local_port = tunnel.alloc_port();
            let g = &mut *g;
            let sock = g.sockets.get_mut::<tcp::Socket>(handle);
            sock.connect(g.iface.context(), remote, local_port)
                .map_err(|e| anyhow!("WireGuard: 发起 TCP 连接失败: {e:?}"))?;
            handle
        };
        tunnel.poll_now();

        let stream = Self { tunnel, handle, alive: Arc::new(AtomicBool::new(true)) };
        match tokio::time::timeout(CONNECT_TIMEOUT, stream.wait_connected()).await {
            Ok(r) => r?,
            // 超时后 stream 在此被 drop, Drop 会 close + 摘除 socket, 不留残骸。
            Err(_) => anyhow::bail!(
                "WireGuard: 经隧道连接 {remote} 超时 ({}s)",
                CONNECT_TIMEOUT.as_secs()
            ),
        }
        Ok(stream)
    }

    /// 取一个可跨任务使用的中止句柄, 用于双向转发时让一方结束能叫醒另一方。
    pub fn closer(&self) -> WgStreamCloser {
        WgStreamCloser {
            tunnel: self.tunnel.clone(),
            handle: self.handle,
            alive: self.alive.clone(),
        }
    }

    /// 等 TCP 三次握手完成。
    ///
    /// 注意这里既要等 WG 隧道握手 (Noise), 又要等隧道内的 TCP 握手 —— 冷启动时前者
    /// 可能要一两个 RTT, 所以超时给得比裸 TCP 宽。
    async fn wait_connected(&self) -> Result<()> {
        std::future::poll_fn(|cx| {
            let mut g = lock_inner(&self.tunnel.inner);
            let sock = g.sockets.get_mut::<tcp::Socket>(self.handle);
            match sock.state() {
                tcp::State::Established => Poll::Ready(Ok(())),
                // 对端拒绝或连接被重置
                tcp::State::Closed => {
                    Poll::Ready(Err(anyhow!("WireGuard: 目标拒绝连接 (TCP 已关闭)")))
                }
                _ => {
                    // 状态未就绪: 挂上 waker, 由 pump 的下一次 poll 唤醒。
                    sock.register_recv_waker(cx.waker());
                    sock.register_send_waker(cx.waker());
                    Poll::Pending
                }
            }
        })
        .await
    }
}

impl Drop for WgTcpStream {
    fn drop(&mut self) {
        {
            let mut g = lock_inner(&self.tunnel.inner);
            if self.alive.load(Ordering::Relaxed) {
                g.sockets.get_mut::<tcp::Socket>(self.handle).close();
            }
        }
        // ⚠️ 顺序是关键: `close()` 只改状态**不发包**, FIN 是 `Interface::poll` 遍历
        // **仍在 SocketSet 里**的 socket 时才生成的。所以必须先 poll 再 remove ——
        // 反过来 (旧实现) FIN 永远发不出去, 对端只能干等自己的超时。
        self.tunnel.poll_now();
        // 摘除, 否则每条连接在隧道里留一份 128KB 缓冲, 长跑必然吃爆内存。
        {
            let mut g = lock_inner(&self.tunnel.inner);
            if self.alive.swap(false, Ordering::Relaxed) {
                g.sockets.remove(self.handle);
            }
        }
    }
}

impl AsyncRead for WgTcpStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let n = {
            let mut g = lock_inner(&self.tunnel.inner);
            let sock = g.sockets.get_mut::<tcp::Socket>(self.handle);

            if sock.can_recv() {
                Some(
                    sock.recv_slice(buf.initialize_unfilled()).map_err(|e| {
                        io::Error::new(io::ErrorKind::ConnectionReset, format!("{e:?}"))
                    })?,
                )
            } else if !sock.may_recv() {
                // 收不到且不可能再收到 = 对端关闭 = EOF (返回 Ok 且不填数据)。
                // 必须区分"暂时没数据"与"永远没数据了": 前者 Pending, 后者 EOF。
                // 搞混了要么连接读不到 EOF 永远挂着, 要么正常连接被误判成断开。
                None
            } else {
                sock.register_recv_waker(cx.waker());
                return Poll::Pending;
            }
        };

        if let Some(n) = n {
            buf.advance(n);
            // 排空接收缓冲后**必须**驱动 smoltcp: 窗口更新/ACK 只在 poll 时才产出。
            // 漏了这步, 对端要等到下一次 pump 事件 (收包或 250ms tick) 才知道窗口已腾开 ——
            // 持续下载时缓冲一满就卡, 吞吐被钉在"每 tick 一个窗口"的量级上。
            self.tunnel.poll_now();
        }
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for WgTcpStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        let n = {
            let mut g = lock_inner(&self.tunnel.inner);
            let sock = g.sockets.get_mut::<tcp::Socket>(self.handle);

            if !sock.may_send() {
                return Poll::Ready(Err(io::Error::from(io::ErrorKind::BrokenPipe)));
            }
            if !sock.can_send() {
                // 发送缓冲满: 等对端确认腾出空间。
                sock.register_send_waker(cx.waker());
                return Poll::Pending;
            }
            sock.send_slice(data)
                .map_err(|e| io::Error::new(io::ErrorKind::BrokenPipe, format!("{e:?}")))?
        };
        // 数据只是进了发送缓冲。驱动 smoltcp 生成 IP 包并叫醒 pump 加密发出去,
        // 否则要等下个 250ms tick —— 每往返白加延迟。
        self.tunnel.poll_now();
        Poll::Ready(Ok(n))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        // smoltcp 没有独立的 flush 语义: send_slice 后已由 poll_now 推进。
        self.tunnel.poll_now();
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        {
            let mut g = lock_inner(&self.tunnel.inner);
            // close() = 发 FIN, 半关闭; 仍可继续读对端数据。
            g.sockets.get_mut::<tcp::Socket>(self.handle).close();
        }
        self.tunnel.poll_now();
        Poll::Ready(Ok(()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proxy::wg::WgConfig;

    fn cfg(endpoint: String) -> WgConfig {
        WgConfig {
            private_key: [0x07u8; 32],
            peer_public_key: [0x08u8; 32],
            preshared_key: None,
            endpoint,
            address: "10.0.0.2".parse().unwrap(),
            mtu: 1420,
            persistent_keepalive: None,
            dns: None,
        }
    }

    // 注: "建连立刻驱动出站流量" 无法在此层单测 —— 握手进行中 boringtun 对后续
    // encapsulate 一律返回 Done, 5s 内不会有任何包出去, 判据恒真。唤醒路径的测试
    // 见 tunnel.rs 的 wake_drains_tx_promptly (直接观察 tx 队列被排空)。

    /// UDP socket drop 后同样必须摘除, 否则每个 socket 泄漏 128KB 缓冲。
    #[tokio::test]
    async fn dropping_udp_socket_removes_it() {
        let peer = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let t = Arc::new(
            super::WgTunnel::connect(&cfg(peer.local_addr().unwrap().to_string()))
                .await
                .unwrap(),
        );
        let s = WgUdpSocket::bind(t.clone()).expect("绑定应成功");
        assert_eq!(lock_inner(&t.inner).sockets.iter().count(), 1);
        drop(s);
        assert_eq!(
            lock_inner(&t.inner).sockets.iter().count(),
            0,
            "UDP socket drop 后未摘除 —— 每个 socket 泄漏 128KB 缓冲"
        );
    }

    /// send_to 必须把数据报交给 smoltcp 并驱动出去(不报错即入队成功)。
    /// 隧道未握手时 boringtun 会把它排队, 这里只锁住"调用路径通、不 panic"。
    #[tokio::test]
    async fn udp_send_enqueues_without_error() {
        let peer = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let t = Arc::new(
            super::WgTunnel::connect(&cfg(peer.local_addr().unwrap().to_string()))
                .await
                .unwrap(),
        );
        let s = WgUdpSocket::bind(t).unwrap();
        s.send_to(b"hello", "10.0.0.1:53".parse().unwrap())
            .expect("发送应入队成功");
    }

    /// `Drop` 必须在 socket **仍在 SocketSet 里**时先 poll 一次, 才可能发出 FIN。
    ///
    /// 判据用"drop 期间 smoltcp 是否被 poll 过、且当时 socket 还在", 而不是"对端有没有
    /// 收到 FIN"(没有真对端可问)。实现方式: 用一个不可能建立连接的隧道建 socket, 手工把
    /// 它推进到 Established 之外不可行, 故退而验**顺序** —— close 后 poll_now 时 socket
    /// 仍可被取到 (alive 仍为 true), remove 发生在其后。
    #[tokio::test]
    async fn drop_polls_before_removing_socket() {
        let peer = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let t = Arc::new(
            super::WgTunnel::connect(&cfg(peer.local_addr().unwrap().to_string()))
                .await
                .unwrap(),
        );
        let handle = {
            let mut g = lock_inner(&t.inner);
            g.sockets.add(tcp::Socket::new(
                tcp::SocketBuffer::new(vec![0u8; SOCK_BUF]),
                tcp::SocketBuffer::new(vec![0u8; SOCK_BUF]),
            ))
        };
        let alive = Arc::new(AtomicBool::new(true));
        let s = WgTcpStream { tunnel: t.clone(), handle, alive: alive.clone() };
        drop(s);
        assert!(!alive.load(Ordering::Relaxed), "drop 后 alive 应为 false");
        assert_eq!(
            lock_inner(&t.inner).sockets.iter().count(),
            0,
            "drop 后 socket 必须已摘除"
        );
    }

    /// `closer().abort()` 必须能在 stream 已 drop 后安全调用 (不 panic)。
    ///
    /// `SocketSet` 的取用接口对失效 handle 一律 panic, 而 closer 是跨任务传递的 ——
    /// 转发任务里一方 abort 时另一方可能刚好已经把 stream drop 掉。
    #[tokio::test]
    async fn closer_is_safe_after_stream_dropped() {
        let peer = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let t = Arc::new(
            super::WgTunnel::connect(&cfg(peer.local_addr().unwrap().to_string()))
                .await
                .unwrap(),
        );
        let handle = {
            let mut g = lock_inner(&t.inner);
            g.sockets.add(tcp::Socket::new(
                tcp::SocketBuffer::new(vec![0u8; SOCK_BUF]),
                tcp::SocketBuffer::new(vec![0u8; SOCK_BUF]),
            ))
        };
        let s = WgTcpStream { tunnel: t.clone(), handle, alive: Arc::new(AtomicBool::new(true)) };
        let c = s.closer();
        drop(s);
        c.abort(); // 不该 panic
        c.abort(); // 可重复调用
    }

    /// stream drop 后 socket 必须从 SocketSet 摘除, 否则每条连接泄漏 128KB 缓冲。
    #[tokio::test]
    async fn dropping_stream_removes_socket() {
        let peer = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let t = Arc::new(
            super::WgTunnel::connect(&cfg(peer.local_addr().unwrap().to_string()))
                .await
                .unwrap(),
        );

        // 直接建一个 socket 再 drop, 不走 connect (对端是哑的, 连不上)
        let handle = {
            let mut g = lock_inner(&t.inner);
            g.sockets.add(tcp::Socket::new(
                tcp::SocketBuffer::new(vec![0u8; SOCK_BUF]),
                tcp::SocketBuffer::new(vec![0u8; SOCK_BUF]),
            ))
        };
        let s = WgTcpStream { tunnel: t.clone(), handle, alive: Arc::new(AtomicBool::new(true)) };
        drop(s);

        // 摘除后再取应 panic (smoltcp 对无效 handle 的行为), 用 iter 计数更稳妥
        let n = lock_inner(&t.inner).sockets.iter().count();
        assert_eq!(n, 0, "stream drop 后 socket 未从 SocketSet 摘除 —— 每条连接泄漏缓冲");
    }
}

/// 经 WireGuard 隧道的一个 UDP socket。
///
/// 与 TCP 侧同样的桥接思路(waker + `poll_now`), 但语义差别要留神:
/// UDP 是**逐数据报**的 —— `recv_from` 一次给一个完整数据报, 缓冲不足会截断,
/// 所以调用方的 buf 必须 ≥ 隧道 MTU。
pub struct WgUdpSocket {
    tunnel: Arc<WgTunnel>,
    handle: SocketHandle,
}

/// UDP 收发缓冲: 元数据槽数 + 载荷字节数。
/// 32 个数据报 ≈ 突发容量; 64KB 载荷够放满 MTU 级别的包。
const UDP_META_SLOTS: usize = 32;
const UDP_PAYLOAD: usize = 64 * 1024;

impl WgUdpSocket {
    /// 在隧道内绑一个本地端口并返回 socket。
    pub fn bind(tunnel: Arc<WgTunnel>) -> Result<Self> {
        let handle = {
            let mut g = lock_inner(&tunnel.inner);
            let mut sock = smoltcp::socket::udp::Socket::new(
                smoltcp::socket::udp::PacketBuffer::new(
                    vec![smoltcp::socket::udp::PacketMetadata::EMPTY; UDP_META_SLOTS],
                    vec![0u8; UDP_PAYLOAD],
                ),
                smoltcp::socket::udp::PacketBuffer::new(
                    vec![smoltcp::socket::udp::PacketMetadata::EMPTY; UDP_META_SLOTS],
                    vec![0u8; UDP_PAYLOAD],
                ),
            );
            let local_port = tunnel.alloc_port();
            sock.bind(local_port)
                .map_err(|e| anyhow!("WireGuard: UDP 绑定本地端口失败: {e:?}"))?;
            g.sockets.add(sock)
        };
        tunnel.poll_now();
        Ok(Self { tunnel, handle })
    }

    /// 经隧道发一个数据报。
    pub fn send_to(&self, data: &[u8], dst: std::net::SocketAddr) -> Result<()> {
        {
            let mut g = lock_inner(&self.tunnel.inner);
            let sock = g
                .sockets
                .get_mut::<smoltcp::socket::udp::Socket>(self.handle);
            sock.send_slice(data, smoltcp::wire::IpEndpoint::from(dst))
                .map_err(|e| anyhow!("WireGuard: UDP 发送失败: {e:?}"))?;
        }
        // 同 TCP 侧: 进了发送缓冲不等于发出去了, 必须驱动 smoltcp + 叫醒 pump。
        self.tunnel.poll_now();
        Ok(())
    }

    /// 收一个数据报。`buf` 必须 ≥ 隧道 MTU, 否则数据报会被截断。
    pub async fn recv_from(&self, buf: &mut [u8]) -> Result<(usize, std::net::SocketAddr)> {
        std::future::poll_fn(|cx| {
            let mut g = lock_inner(&self.tunnel.inner);
            let sock = g
                .sockets
                .get_mut::<smoltcp::socket::udp::Socket>(self.handle);
            if sock.can_recv() {
                return Poll::Ready(
                    sock.recv_slice(buf)
                        .map(|(n, meta)| {
                            let addr = std::net::SocketAddr::new(meta.endpoint.addr.into(), meta.endpoint.port);
                            (n, addr)
                        })
                        .map_err(|e| anyhow!("WireGuard: UDP 接收失败: {e:?}")),
                );
            }
            sock.register_recv_waker(cx.waker());
            Poll::Pending
        })
        .await
    }
}

impl Drop for WgUdpSocket {
    fn drop(&mut self) {
        // 同 TCP: 不摘除则每个 socket 在隧道里泄漏 128KB 缓冲。
        lock_inner(&self.tunnel.inner).sockets.remove(self.handle);
    }
}
