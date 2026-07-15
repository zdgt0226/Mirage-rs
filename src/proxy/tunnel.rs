use crate::crypto::aead::{CryptoReader, CryptoWriter};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};

/// 抽象出的加密信道。
/// 拆分为 reader 和 writer，彻底解耦 TCP 的收发，避免加锁。
pub struct Tunnel {
    pub reader: CryptoReader<OwnedReadHalf>,
    pub writer: CryptoWriter<OwnedWriteHalf>,
    pub created_at: std::time::Instant,
    pub max_age_sec: u64,
}

impl Tunnel {
    pub fn new(reader: CryptoReader<OwnedReadHalf>, writer: CryptoWriter<OwnedWriteHalf>) -> Self {
        Self { 
            reader, 
            writer, 
            created_at: std::time::Instant::now(),
            // 30 ~ 50s 随机抖动, 必须 < 服务端 first_chunk 超时 60s, 否则
            // pool 会发出"服务端已 reap 但客户端以为还活着"的死 tunnel,
            // 触发 handler 5 分钟级 read timeout (用户实测过).
            // 抖动是为了避免大量 warmup 同时刷新冲垮服务端.
            max_age_sec: 30 + fastrand::u64(0..20)
        }
    }

    pub fn get_raw_fd(&self) -> std::os::unix::io::RawFd {
        use std::os::unix::io::AsRawFd;
        self.reader.inner().as_ref().as_raw_fd()
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
    /// 非健康一律判 stale, 不派发。对齐 camouflage_pool::is_alive 的做法 (非阻塞、
    /// 任何可读事件即丢弃, 消费与否无所谓因为脏隧道不保留)。
    ///
    /// 已知边角: 若 connect_upstream 读 TIME_SYNC 超时 (3s) 而帧迟到滞留缓冲, 这里会把
    /// 该健康隧道误判 stale 丢弃 (罕见, builder 会补, 不致命)。
    pub fn is_stale(&self) -> bool {
        let mut probe = [0u8; 1];
        !matches!(
            self.reader.inner().try_read(&mut probe),
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
        let (reader, writer) =
            crate::crypto::aead::create_crypto_pair(cr, cw, "pw", &[0u8; 32], true);
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
