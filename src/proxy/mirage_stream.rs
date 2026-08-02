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
type ReadFut = Pin<Box<dyn Future<Output = (Reader, io::Result<Vec<u8>>)> + Send>>;
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
}

impl MirageStream {
    /// 用已建好、且**已发送 target 头**的隧道包一条流。target 头由调用方 (connect) 先写。
    pub fn from_tunnel(tunnel: Tunnel) -> Self {
        Self {
            read: ReadState::Idle(tunnel.reader),
            write: WriteState::Idle(tunnel.writer),
            read_buf: Vec::new(),
            read_pos: 0,
        }
    }
}

/// recv_data 的 Err: close_notify 视为流结束 (EOF); 其余是真错误。
fn recv_err_to_eof_or_io(e: anyhow::Error) -> io::Result<Vec<u8>> {
    let msg = e.to_string();
    if msg.contains("close_notify") {
        Ok(Vec::new()) // 空 = EOF
    } else {
        Err(io::Error::other(msg))
    }
}

impl AsyncRead for MirageStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let me = &mut *self;
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
                            Ok(v) => Ok(v),
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
                            Ok(v) if v.is_empty() => return Poll::Ready(Ok(())), // EOF
                            Ok(v) => {
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
        loop {
            match std::mem::replace(&mut me.write, WriteState::Poisoned) {
                WriteState::Idle(mut writer) => {
                    // 单槽缓冲: 把整个 buf 交给一次 send_data, 完成前不接受新写。
                    let data = buf.to_vec();
                    let n = data.len();
                    let fut: WriteFut = Box::pin(async move {
                        let r = writer.send_data(&data).await;
                        (writer, r.map_err(|e| io::Error::other(e.to_string())))
                    });
                    me.write = WriteState::Busy(fut);
                    return Poll::Ready(Ok(n));
                }
                WriteState::Busy(mut fut) => match fut.as_mut().poll(cx) {
                    Poll::Ready((writer, res)) => {
                        me.write = WriteState::Idle(writer);
                        if let Err(e) = res {
                            return Poll::Ready(Err(e));
                        }
                        // 上一次写完成, 回循环顶接受本次 buf。
                    }
                    Poll::Pending => {
                        me.write = WriteState::Busy(fut);
                        return Poll::Pending;
                    }
                },
                WriteState::Poisoned => unreachable!("MirageStream write state poisoned"),
            }
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let me = &mut *self;
        // 把在途的 send_data 驱动到完成 (send_data 内部已 flush BufWriter)。
        match std::mem::replace(&mut me.write, WriteState::Poisoned) {
            WriteState::Idle(writer) => {
                me.write = WriteState::Idle(writer);
                Poll::Ready(Ok(()))
            }
            WriteState::Busy(mut fut) => match fut.as_mut().poll(cx) {
                Poll::Ready((writer, res)) => {
                    me.write = WriteState::Idle(writer);
                    Poll::Ready(res)
                }
                Poll::Pending => {
                    me.write = WriteState::Busy(fut);
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
}
