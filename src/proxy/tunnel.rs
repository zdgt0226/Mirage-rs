use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};

use crate::crypto::aead::{CryptoReader, CryptoWriter};

/// 类型擦除的**任意**字节流半程 (用于 Mirage-over-X 嵌套: 隧道骑另一个出站的 OutStream)。
pub type BoxRead = Box<dyn AsyncRead + Unpin + Send>;
pub type BoxWrite = Box<dyn AsyncWrite + Unpin + Send>;

/// 隧道底层读半程。**保留 TCP 快路径** (Tcp 变体直接持 OwnedReadHalf, 可 try_read 探活 / 取
/// 裸 fd 调 brutal); Boxed 变体用于 Mirage-over-X 嵌套 (骑另一出站的流, 无裸 fd)。
/// 早先硬绑 OwnedReadHalf, 只能骑物理 TCP; 现改 enum 以支持链式代理, 且不牺牲 TCP 路径。
pub enum TunnelRead {
    Tcp(OwnedReadHalf),
    Boxed(BoxRead),
}

pub enum TunnelWrite {
    Tcp(OwnedWriteHalf),
    Boxed(BoxWrite),
}

impl TunnelRead {
    /// 非阻塞探活 (仅 TCP 变体真探; 嵌套无裸 fd → 返 WouldBlock 让 is_stale 判健康, 靠 recv 检测死)。
    fn try_read_probe(&self) -> std::io::Result<usize> {
        match self {
            TunnelRead::Tcp(s) => {
                let mut probe = [0u8; 1];
                s.try_read(&mut probe)
            }
            TunnelRead::Boxed(_) => Err(std::io::Error::from(std::io::ErrorKind::WouldBlock)),
        }
    }

    /// 裸 fd (仅 TCP 变体有; 嵌套返 None)。
    fn raw_fd(&self) -> Option<std::os::unix::io::RawFd> {
        use std::os::unix::io::AsRawFd;
        match self {
            // OwnedReadHalf 无 as_raw_fd, 经 as_ref() 取 &TcpStream。
            TunnelRead::Tcp(s) => Some(s.as_ref().as_raw_fd()),
            TunnelRead::Boxed(_) => None,
        }
    }
}

impl AsyncRead for TunnelRead {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            TunnelRead::Tcp(s) => Pin::new(s).poll_read(cx, buf),
            TunnelRead::Boxed(s) => Pin::new(s).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for TunnelWrite {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<std::io::Result<usize>> {
        match self.get_mut() {
            TunnelWrite::Tcp(s) => Pin::new(s).poll_write(cx, buf),
            TunnelWrite::Boxed(s) => Pin::new(s).poll_write(cx, buf),
        }
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            TunnelWrite::Tcp(s) => Pin::new(s).poll_flush(cx),
            TunnelWrite::Boxed(s) => Pin::new(s).poll_flush(cx),
        }
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            TunnelWrite::Tcp(s) => Pin::new(s).poll_shutdown(cx),
            TunnelWrite::Boxed(s) => Pin::new(s).poll_shutdown(cx),
        }
    }
}

/// 抽象出的加密信道。
/// 拆分为 reader 和 writer，彻底解耦底层传输的收发，避免加锁。
pub struct Tunnel {
    pub reader: CryptoReader<TunnelRead>,
    pub writer: CryptoWriter<TunnelWrite>,
    pub created_at: std::time::Instant,
    pub max_age_sec: u64,
}

impl Tunnel {
    pub fn new(reader: CryptoReader<TunnelRead>, writer: CryptoWriter<TunnelWrite>) -> Self {
        Self {
            reader,
            writer,
            created_at: std::time::Instant::now(),
            // 30 ~ 50s 随机抖动, 必须 < 服务端 first_chunk 超时 60s, 否则
            // pool 会发出"服务端已 reap 但客户端以为还活着"的死 tunnel,
            // 触发 handler 5 分钟级 read timeout (用户实测过).
            // 抖动是为了避免大量 warmup 同时刷新冲垮服务端.
            max_age_sec: 30 + fastrand::u64(0..20),
        }
    }

    /// 裸 fd。仅物理 TCP 隧道有; Mirage-over-X 嵌套隧道返 None (无裸 fd → 调用方跳过
    /// brutal / fd 级 shutdown)。
    pub fn get_raw_fd(&self) -> Option<std::os::unix::io::RawFd> {
        self.reader.inner().raw_fd()
    }

    /// 非阻塞探测隧道是否已死/半开 (stale)。
    ///
    /// 空闲池内隧道的服务端在协议上应保持**静默** —— TIME_SYNC 帧已在 connect_upstream
    /// 建连时消费掉, 之后服务端阻塞等 first_chunk, 不主动发任何字节。故对读半边做一次
    /// **非阻塞** try_read:
    ///   - `Err(WouldBlock)` 无数据无 EOF → 健康 (唯一保留条件)
    ///   - `Ok(0)`            对端已 FIN (idle 关闭 / reap) → 死
    ///   - `Ok(n>0)`          意外数据 (远端脏/RST 前的残留) → 不可用
    ///   - 其他 `Err`         RST / 错误 → 死
    ///
    /// 非健康一律判 stale, 不派发。**嵌套 (Boxed) 隧道也进 WarmPool**, 但无裸 fd 可探活 →
    /// try_read_probe 恒返 WouldBlock 判健康, 故 sweeper 不会主动清掉死的嵌套隧道; 它们靠
    /// max_age (30~50s) 过期回收 + handler 首写失败时的换隧道重试兜底 (代价: 偶尔浪费一条)。
    pub fn is_stale(&self) -> bool {
        !matches!(
            self.reader.inner().try_read_probe(),
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::{TcpListener, TcpStream};

    /// 建一对 loopback TCP, 包成 Tunnel (is_stale 只读裸 socket 就绪态, 不需真握手)。
    async fn make_tunnel() -> (Tunnel, TcpStream) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let client = TcpStream::connect(addr).await.unwrap();
        let (server, _) = listener.accept().await.unwrap();
        let (cr, cw) = client.into_split();
        let (reader, writer) = crate::crypto::aead::create_crypto_pair(
            TunnelRead::Tcp(cr),
            TunnelWrite::Tcp(cw),
            "pw",
            &[0u8; 32],
            true,
        );
        (Tunnel::new(reader, writer), server)
    }

    #[tokio::test]
    async fn healthy_tunnel_not_stale() {
        let (tunnel, _server) = make_tunnel().await; // server 持有不发数据 = 健康静默
        assert!(!tunnel.is_stale(), "静默健康隧道不应判 stale");
    }

    #[tokio::test]
    async fn peer_fin_is_stale() {
        let (tunnel, server) = make_tunnel().await;
        drop(server); // 服务端关闭 → 客户端收 FIN
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        assert!(tunnel.is_stale(), "对端 FIN 后应判 stale");
    }

    #[tokio::test]
    async fn peer_sends_data_is_stale() {
        use tokio::io::AsyncWriteExt;
        let (tunnel, mut server) = make_tunnel().await;
        server.write_all(b"unexpected").await.unwrap();
        server.flush().await.unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        assert!(tunnel.is_stale(), "收到意外数据的隧道应判 stale");
    }
}
