//! `MirageStream`: 把 Mirage 隧道的**帧式 async 接口** (`CryptoWriter::send_data` /
//! `CryptoReader::recv_data`) 适配成字节流 `AsyncRead + AsyncWrite`。
//!
//! 为什么需要: 统一出站流接口 (`OutboundNode::connect(target) -> stream`) 要求每种出站都能
//! 给出一条普通字节流, 好让**进程内消费者** (geo 下载 / 未来订阅刷新 / 链式代理) 直接用隧道,
//! 不再绕 SOCKS 入站自连 (见 brain unified-outbound-stream)。WireGuard 的 `WgTcpStream` 早已
//! 是这个形状, Mirage 出站此前没跟上 —— 建连逻辑缠在 handler.rs 里、不返回流。
//!
//! 适配手法: `send_data`/`recv_data` 是 `&mut self` 的 async 方法, 无法在 `poll_*` 里直接持有
//! 借用自身的 future (自引用)。改用"**把半程 move 进 future, 完成后再交还**"模式: 每个方向持
//! 一个拥有该半程所有权的 `BoxFuture`, 就绪时把半程取回置回 Idle。OwnedReadHalf/OwnedWriteHalf
//! 都是 Send+'static, 故 future 可 box 成 'static。全程安全, 无 unsafe。

use std::future::Future;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::crypto::aead::{CryptoReader, CryptoWriter};
use crate::proxy::tunnel::{Tunnel, TunnelRead, TunnelWrite};

type Reader = CryptoReader<TunnelRead>;
type Writer = CryptoWriter<TunnelWrite>;
/// `Ok(None)` = 对端 close_notify (EOF); `Ok(Some(v))` = 一帧明文 (可能为空内容记录, 不是 EOF)。
type ReadFut = Pin<Box<dyn Future<Output = (Reader, io::Result<Option<Vec<u8>>>)> + Send>>;
type WriteFut = Pin<Box<dyn Future<Output = (Writer, io::Result<()>)> + Send>>;

enum ReadState {
    Idle(Reader),
    Busy(ReadFut),
    /// 转移所有权的瞬态 (mem::replace 占位), 正常不会在 poll 边界停留。
    Poisoned,
}

enum WriteState {
    Idle(Writer),
    Busy(WriteFut),
    Poisoned,
}

/// Mirage 隧道字节流。由 [`crate::proxy::outbound::OutboundNode::connect`] 在发完 target 头后交出。
pub struct MirageStream {
    read: ReadState,
    write: WriteState,
    /// recv_data 一次收一整帧, 可能大于本次 poll_read 的 buf, 余下暂存这里。
    read_buf: Vec<u8>,
    read_pos: usize,
    /// poll_read 顺带驱动在途写时遇到的写错误, 留到下次 poll_write/poll_flush 报出。
    write_err: Option<io::Error>,
    /// 最近一次在 poll_write/poll_flush 处 Pending 的写方 waker。drive_write 用读方的 cx 推进写
    /// future 会顶掉 socket 上登记的写方 waker; 读写分在两个 task 时, 写 future 在读路径完成后
    /// 须由这里叫醒写方, 否则它会一直 Pending。
    write_waker: Option<std::task::Waker>,
}

impl MirageStream {
    /// 用已建好、且**已发送 target 头**的隧道包一条流。target 头由调用方 (connect) 先写。
    pub fn from_tunnel(tunnel: Tunnel) -> Self {
        Self {
            read: ReadState::Idle(tunnel.reader),
            write: WriteState::Idle(tunnel.writer),
            read_buf: Vec::new(),
            read_pos: 0,
            write_err: None,
            write_waker: None,
        }
    }

    /// 推进在途写 future 一步 (不阻塞): 完成则交还 writer, 错误暂存到 `write_err`。
    ///
    /// poll_write 接受数据后即返回 Ready (单槽缓冲, 同 tokio `BufWriter`), 之后必须有人继续
    /// poll 那个 future 数据才会落网。调用方 `write_all` 后不 flush 就转去读 (如 SS 入站发首包后
    /// 进 `copy_bidirectional`) 时, 只有读路径会被 poll —— 故读路径也要顺带驱动写, 否则首包永远
    /// 不发, 两端互等到空闲超时。
    fn drive_write(&mut self, cx: &mut Context<'_>) {
        if let WriteState::Busy(fut) = &mut self.write {
            if let Poll::Ready((writer, res)) = fut.as_mut().poll(cx) {
                self.write = WriteState::Idle(writer);
                if let Err(e) = res {
                    self.write_err = Some(e);
                }
                if let Some(w) = self.write_waker.take() {
                    w.wake();
                }
            }
        }
    }
}

/// recv_data 的 Err: 只有认证过的 close_notify 视为流结束 (EOF); 其余 (含裸 TCP EOF) 是真错误,
/// 不能当 EOF —— 否则路径注入的 FIN/RST 会把截断伪装成完整结束。
fn recv_err_to_eof_or_io(e: anyhow::Error) -> io::Result<Option<Vec<u8>>> {
    if crate::crypto::aead::is_close_notify(&e) {
        Ok(None)
    } else {
        Err(io::Error::other(e.to_string()))
    }
}

impl AsyncRead for MirageStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let me = &mut *self;
        me.drive_write(cx);
        loop {
            // 1. 先把上一帧的余量吐给 buf。
            if me.read_pos < me.read_buf.len() {
                let remaining = &me.read_buf[me.read_pos..];
                let n = remaining.len().min(buf.remaining());
                buf.put_slice(&remaining[..n]);
                me.read_pos += n;
                return Poll::Ready(Ok(()));
            }
            // 2. 余量吐完, 驱动下一帧。
            match std::mem::replace(&mut me.read, ReadState::Poisoned) {
                ReadState::Idle(mut reader) => {
                    let fut: ReadFut = Box::pin(async move {
                        let r = reader.recv_data().await;
                        let mapped = match r {
                            Ok(v) => Ok(Some(v)),
                            Err(e) => recv_err_to_eof_or_io(e),
                        };
                        (reader, mapped)
                    });
                    me.read = ReadState::Busy(fut);
                }
                ReadState::Busy(mut fut) => match fut.as_mut().poll(cx) {
                    Poll::Ready((reader, res)) => {
                        me.read = ReadState::Idle(reader);
                        match res {
                            Ok(None) => return Poll::Ready(Ok(())), // close_notify = EOF
                            // 空内容记录 (padding 方案某条 target=1 时发端可能发出) 不是 EOF, 继续读下一帧。
                            Ok(Some(v)) if v.is_empty() => {}
                            Ok(Some(v)) => {
                                me.read_buf = v;
                                me.read_pos = 0;
                                // 回到循环顶把新帧吐给 buf。
                            }
                            Err(e) => return Poll::Ready(Err(e)),
                        }
                    }
                    Poll::Pending => {
                        me.read = ReadState::Busy(fut);
                        return Poll::Pending;
                    }
                },
                ReadState::Poisoned => unreachable!("MirageStream read state poisoned"),
            }
        }
    }
}

impl AsyncWrite for MirageStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let me = &mut *self;
        if let Some(e) = me.write_err.take() {
            return Poll::Ready(Err(e));
        }
        loop {
            match std::mem::replace(&mut me.write, WriteState::Poisoned) {
                WriteState::Idle(mut writer) => {
                    // 单槽缓冲: 把整个 buf 交给一次 send_data, 完成前不接受新写。
                    let data = buf.to_vec();
                    let n = data.len();
                    let mut fut: WriteFut = Box::pin(async move {
                        let r = writer.send_data(&data).await;
                        (writer, r.map_err(|e| io::Error::other(e.to_string())))
                    });
                    // 立即推进一次: 多数情况 socket 可写, 本次就落网; 否则留在 Busy, 由后续
                    // poll_write / poll_flush / poll_read (见 drive_write) 继续驱动。
                    match fut.as_mut().poll(cx) {
                        Poll::Ready((writer, res)) => {
                            me.write = WriteState::Idle(writer);
                            res?;
                        }
                        Poll::Pending => me.write = WriteState::Busy(fut),
                    }
                    return Poll::Ready(Ok(n));
                }
                WriteState::Busy(mut fut) => match fut.as_mut().poll(cx) {
                    Poll::Ready((writer, res)) => {
                        me.write = WriteState::Idle(writer);
                        me.write_waker = None;
                        if let Err(e) = res {
                            return Poll::Ready(Err(e));
                        }
                        // 上一次写完成, 回循环顶接受本次 buf。
                    }
                    Poll::Pending => {
                        me.write = WriteState::Busy(fut);
                        me.write_waker = Some(cx.waker().clone());
                        return Poll::Pending;
                    }
                },
                WriteState::Poisoned => unreachable!("MirageStream write state poisoned"),
            }
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let me = &mut *self;
        if let Some(e) = me.write_err.take() {
            return Poll::Ready(Err(e));
        }
        // 把在途的 send_data 驱动到完成 (send_data 内部已 flush BufWriter)。
        match std::mem::replace(&mut me.write, WriteState::Poisoned) {
            WriteState::Idle(writer) => {
                me.write = WriteState::Idle(writer);
                Poll::Ready(Ok(()))
            }
            WriteState::Busy(mut fut) => match fut.as_mut().poll(cx) {
                Poll::Ready((writer, res)) => {
                    me.write = WriteState::Idle(writer);
                    me.write_waker = None;
                    Poll::Ready(res)
                }
                Poll::Pending => {
                    me.write = WriteState::Busy(fut);
                    me.write_waker = Some(cx.waker().clone());
                    Poll::Pending
                }
            },
            WriteState::Poisoned => unreachable!("MirageStream write state poisoned"),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        // 先把在途写刷完; close_notify 交由 Drop/上层, 这里只保证数据落网。
        self.poll_flush(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};

    // 真 TCP 回环建一对 mirage 加密端 (共享 master)。客户端包成 MirageStream 当字节流用,
    // 服务端用裸 CryptoReader/Writer 收发, 验证适配器双向字节流往返正确 (含大于单帧的数据)。
    #[tokio::test]
    async fn mirage_stream_roundtrip() {
        let master = [5u8; 32];
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let srv = tokio::spawn(async move {
            let (s, _) = listener.accept().await.unwrap();
            let (r, w) = s.into_split();
            let mut sr = CryptoReader::new(r, &master, false); // 非发起端: 读 c2s
            let mut sw = CryptoWriter::new(w, &master, false); // 非发起端: 写 s2c
            let got = sr.recv_data().await.unwrap();
            assert_eq!(&got, b"hello from stream", "服务端应收到客户端字节流写入");
            sw.send_data(b"world back").await.unwrap();
        });

        let cs = TcpStream::connect(addr).await.unwrap();
        let (r, w) = cs.into_split();
        let reader = CryptoReader::new(TunnelRead::Tcp(r), &master, true); // 发起端: 读 s2c
        let writer = CryptoWriter::new(TunnelWrite::Tcp(w), &master, true); // 发起端: 写 c2s
        let mut ms = MirageStream::from_tunnel(Tunnel::new(reader, writer));

        ms.write_all(b"hello from stream").await.unwrap();
        ms.flush().await.unwrap();

        let mut buf = vec![0u8; 64];
        let n = ms.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"world back", "MirageStream 应把隧道回包当字节流读出");

        srv.await.unwrap();
    }

    /// 回归 (审计 D2): `write_all` 后**不 flush** 直接读响应 (SS 入站首包后进 copy_bidirectional
    /// 的形状)。旧实现 poll_write 只建 future 不 poll, 请求永远不发, 两端互等 → 此处超时。
    #[tokio::test]
    async fn write_without_flush_then_read_does_not_hang() {
        let master = [6u8; 32];
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let srv = tokio::spawn(async move {
            let (s, _) = listener.accept().await.unwrap();
            let (r, w) = s.into_split();
            let mut sr = CryptoReader::new(r, &master, false);
            let mut sw = CryptoWriter::new(w, &master, false);
            let got = sr.recv_data().await.unwrap();
            assert_eq!(&got, b"request");
            sw.send_data(b"response").await.unwrap();
        });

        let cs = TcpStream::connect(addr).await.unwrap();
        let (r, w) = cs.into_split();
        let reader = CryptoReader::new(TunnelRead::Tcp(r), &master, true);
        let writer = CryptoWriter::new(TunnelWrite::Tcp(w), &master, true);
        let mut ms = MirageStream::from_tunnel(Tunnel::new(reader, writer));

        ms.write_all(b"request").await.unwrap(); // 刻意不 flush
        let mut buf = vec![0u8; 64];
        let n = tokio::time::timeout(std::time::Duration::from_secs(5), ms.read(&mut buf))
            .await
            .expect("write_all 后未 flush 的数据必须仍会发出, 不能挂死")
            .unwrap();
        assert_eq!(&buf[..n], b"response");
        srv.await.unwrap();
    }

    /// 回归 (审计 D5): 空内容记录 (padding 方案 target=1 时发端会发) 不是 EOF; 只有 close_notify 是。
    #[tokio::test]
    async fn empty_record_is_not_eof_but_close_notify_is() {
        let master = [8u8; 32];
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let srv = tokio::spawn(async move {
            let (s, _) = listener.accept().await.unwrap();
            let (_r, w) = s.into_split();
            let mut sw = {
                // 方案前两条 target=1 → 前两条记录只有 inner type, 内容为空; 之后才带数据。
                let _g = crate::crypto::cipher::PAD_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
                crate::crypto::cipher::set_padding_scheme(vec![(1, 1), (1, 1)]);
                let mut sw = CryptoWriter::new(w, &master, false);
                crate::crypto::cipher::set_padding_scheme(vec![]);
                sw.set_padding(true);
                sw
            };
            sw.send_data(b"payload").await.unwrap();
            sw.send_close_notify().await.unwrap();
        });

        let cs = TcpStream::connect(addr).await.unwrap();
        let (r, w) = cs.into_split();
        let reader = CryptoReader::new(TunnelRead::Tcp(r), &master, true);
        let writer = CryptoWriter::new(TunnelWrite::Tcp(w), &master, true);
        let mut ms = MirageStream::from_tunnel(Tunnel::new(reader, writer));

        let mut got = Vec::new();
        ms.read_to_end(&mut got).await.unwrap();
        assert_eq!(&got, b"payload", "空内容记录须被跳过, close_notify 才是 EOF");
        srv.await.unwrap();
    }

    /// 裸 TCP EOF (无 close_notify) 是截断, 必须报错而非 EOF (审计 D3)。
    #[tokio::test]
    async fn bare_tcp_eof_is_error_not_eof() {
        let master = [9u8; 32];
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let srv = tokio::spawn(async move {
            let (s, _) = listener.accept().await.unwrap();
            let (_r, w) = s.into_split();
            let mut sw = CryptoWriter::new(w, &master, false);
            sw.send_data(b"partial").await.unwrap();
            // 不发 close_notify 直接关
        });

        let cs = TcpStream::connect(addr).await.unwrap();
        let (r, w) = cs.into_split();
        let reader = CryptoReader::new(TunnelRead::Tcp(r), &master, true);
        let writer = CryptoWriter::new(TunnelWrite::Tcp(w), &master, true);
        let mut ms = MirageStream::from_tunnel(Tunnel::new(reader, writer));
        srv.await.unwrap();

        let mut got = Vec::new();
        assert!(ms.read_to_end(&mut got).await.is_err(), "无 close_notify 的结束必须报错");
        assert_eq!(&got, b"partial");
    }
}
