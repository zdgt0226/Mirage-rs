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
use std::sync::Arc;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// 单条连接的收发缓冲。64KB 是吞吐与内存的常见折中 (BDP 100Mbps×5ms ≈ 62KB)。
const SOCK_BUF: usize = 64 * 1024;

/// 经 WireGuard 隧道的一条 TCP 连接。
pub struct WgTcpStream {
    tunnel: Arc<WgTunnel>,
    handle: SocketHandle,
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
            let local_port = 1024 + (fastrand::u16(..) % (u16::MAX - 1024));
            let g = &mut *g;
            let sock = g.sockets.get_mut::<tcp::Socket>(handle);
            sock.connect(g.iface.context(), remote, local_port)
                .map_err(|e| anyhow!("WireGuard: 发起 TCP 连接失败: {e:?}"))?;
            handle
        };
        tunnel.poll_now();

        let stream = Self { tunnel, handle };
        stream.wait_connected().await?;
        Ok(stream)
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
        // 必须把 socket 从 SocketSet 里摘掉, 否则每条连接都在隧道里留一份 128KB 缓冲,
        // 长跑必然吃爆内存。close 让对端收到 FIN 而非干等超时。
        {
            let mut g = lock_inner(&self.tunnel.inner);
            g.sockets.get_mut::<tcp::Socket>(self.handle).close();
            g.sockets.remove(self.handle);
        }
        self.tunnel.poll_now();
    }
}

impl AsyncRead for WgTcpStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let mut g = lock_inner(&self.tunnel.inner);
        let sock = g.sockets.get_mut::<tcp::Socket>(self.handle);

        if sock.can_recv() {
            let n = sock
                .recv_slice(buf.initialize_unfilled())
                .map_err(|e| io::Error::new(io::ErrorKind::ConnectionReset, format!("{e:?}")))?;
            buf.advance(n);
            return Poll::Ready(Ok(()));
        }
        // 收不到且不可能再收到 = 对端关闭 = EOF (返回 Ok 且不填数据)。
        // 这里必须区分"暂时没数据"与"永远没数据了": 前者 Pending, 后者 EOF。
        // 搞混了要么连接读不到 EOF 永远挂着, 要么正常连接被误判成断开。
        if !sock.may_recv() {
            return Poll::Ready(Ok(()));
        }
        sock.register_recv_waker(cx.waker());
        Poll::Pending
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
        }
    }

    // 注: "建连立刻驱动出站流量" 无法在此层单测 —— 握手进行中 boringtun 对后续
    // encapsulate 一律返回 Done, 5s 内不会有任何包出去, 判据恒真。唤醒路径的测试
    // 见 tunnel.rs 的 wake_drains_tx_promptly (直接观察 tx 队列被排空)。

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
        let s = WgTcpStream { tunnel: t.clone(), handle };
        drop(s);

        // 摘除后再取应 panic (smoltcp 对无效 handle 的行为), 用 iter 计数更稳妥
        let n = lock_inner(&t.inner).sockets.iter().count();
        assert_eq!(n, 0, "stream drop 后 socket 未从 SocketSet 摘除 —— 每条连接泄漏缓冲");
    }
}
