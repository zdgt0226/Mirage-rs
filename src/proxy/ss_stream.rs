//! `SsStream`: 把 Shadowsocks **客户端** 的帧式接口 (`SsReader::read_chunk` / `SsWriter::write_all`)
//! 适配成字节流 `AsyncRead + AsyncWrite`, 供 SS 出站 (`OutboundNode::Shadowsocks`) 交给统一
//! 出站接口。底层半程装箱 (BoxRead/BoxWrite) → SS 既能直连 SS 服务器, 也能骑另一出站的
//! OutStream (SS-over-Mirage, 类 shadow-tls+ss)。手法同 [`crate::proxy::mirage_stream`]。

use std::future::Future;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::proxy::shadowsocks::{SsReader, SsWriter};
use crate::proxy::tunnel::{BoxRead, BoxWrite};

type Reader = SsReader<BoxRead>;
type Writer = SsWriter<BoxWrite>;
type ReadFut = Pin<Box<dyn Future<Output = (Reader, io::Result<Vec<u8>>)> + Send>>;
type WriteFut = Pin<Box<dyn Future<Output = (Writer, io::Result<()>)> + Send>>;

enum ReadState {
    Idle(Reader),
    Busy(ReadFut),
    Poisoned,
}
enum WriteState {
    Idle(Writer),
    Busy(WriteFut),
    Poisoned,
}

pub struct SsStream {
    read: ReadState,
    write: WriteState,
    read_buf: Vec<u8>,
    read_pos: usize,
    /// poll_read 顺带驱动在途写时遇到的写错误, 留到下次 poll_write/poll_flush 报出。
    write_err: Option<io::Error>,
    /// 最近一次在 poll_write/poll_flush 处 Pending 的写方 waker。drive_write 用读方的 cx 推进写
    /// future 会顶掉 socket 上登记的写方 waker; 读写分在两个 task 时, 写 future 在读路径完成后
    /// 须由这里叫醒写方, 否则它会一直 Pending。
    write_waker: Option<std::task::Waker>,
    /// 是否已对底层写半程执行过 shutdown (幂等保证)。
    shutdown_done: bool,
}

impl SsStream {
    /// 用已握手完成的 SS 读/写半程 (底层已装箱) 包一条字节流。
    pub fn new(reader: Reader, writer: Writer) -> Self {
        Self {
            read: ReadState::Idle(reader),
            write: WriteState::Idle(writer),
            read_buf: Vec::new(),
            read_pos: 0,
            write_err: None,
            write_waker: None,
            shutdown_done: false,
        }
    }

    /// 推进在途写 future 一步, 同 [`crate::proxy::mirage_stream`] 的 drive_write:
    /// write_all 后不 flush 就转去读的调用方, 只有读路径会被 poll, 由它顺带把写推下去。
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

impl AsyncRead for SsStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let me = &mut *self;
        me.drive_write(cx);
        loop {
            if me.read_pos < me.read_buf.len() {
                let remaining = &me.read_buf[me.read_pos..];
                let n = remaining.len().min(buf.remaining());
                buf.put_slice(&remaining[..n]);
                me.read_pos += n;
                return Poll::Ready(Ok(()));
            }
            match std::mem::replace(&mut me.read, ReadState::Poisoned) {
                ReadState::Idle(mut reader) => {
                    let fut: ReadFut = Box::pin(async move {
                        let r = reader.read_chunk().await;
                        (reader, r)
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
                            }
                            Err(e) => return Poll::Ready(Err(e)),
                        }
                    }
                    Poll::Pending => {
                        me.read = ReadState::Busy(fut);
                        return Poll::Pending;
                    }
                },
                ReadState::Poisoned => unreachable!("SsStream read state poisoned"),
            }
        }
    }
}

impl AsyncWrite for SsStream {
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
                    let data = buf.to_vec();
                    let n = data.len();
                    let mut fut: WriteFut = Box::pin(async move {
                        let r = writer.write_all(&data).await;
                        (writer, r)
                    });
                    // 立即推进一次; 未完成则留在 Busy, 由后续 poll_write / poll_flush / poll_read 驱动。
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
                    }
                    Poll::Pending => {
                        me.write = WriteState::Busy(fut);
                        me.write_waker = Some(cx.waker().clone());
                        return Poll::Pending;
                    }
                },
                WriteState::Poisoned => unreachable!("SsStream write state poisoned"),
            }
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let me = &mut *self;
        if let Some(e) = me.write_err.take() {
            return Poll::Ready(Err(e));
        }
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
            WriteState::Poisoned => unreachable!("SsStream write state poisoned"),
        }
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let me = &mut *self;
        if me.shutdown_done {
            return Poll::Ready(Ok(()));
        }
        if let Some(e) = me.write_err.take() {
            return Poll::Ready(Err(e));
        }
        loop {
            match std::mem::replace(&mut me.write, WriteState::Poisoned) {
                WriteState::Idle(mut writer) => {
                    let res = writer.poll_shutdown(cx);
                    me.write = WriteState::Idle(writer);
                    if let Poll::Ready(Ok(())) = &res {
                        me.shutdown_done = true;
                    }
                    return res;
                }
                WriteState::Busy(mut fut) => match fut.as_mut().poll(cx) {
                    Poll::Ready((writer, res)) => {
                        me.write = WriteState::Idle(writer);
                        me.write_waker = None;
                        if let Err(e) = res {
                            return Poll::Ready(Err(e));
                        }
                    }
                    Poll::Pending => {
                        me.write = WriteState::Busy(fut);
                        me.write_waker = Some(cx.waker().clone());
                        return Poll::Pending;
                    }
                },
                WriteState::Poisoned => unreachable!("SsStream write state poisoned"),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncWriteExt;
    use crate::proxy::shadowsocks::{Method, client_handshake_over, server_handshake, SsConfig};

    #[tokio::test]
    async fn test_ss_stream_shutdown_sends_eof_to_peer() {
        let cfg = SsConfig {
            server: "192.0.2.1".into(),
            port: 8388,
            password: "test-password-ss".into(),
            method: Method::Chacha20IetfPoly1305,
            block_udp: true,
        };

        let (client_io, server_io) = tokio::io::duplex(65536);
        let (cr, cw) = tokio::io::split(client_io);
        let (sr, sw) = tokio::io::split(server_io);

        let (c_reader, c_writer) = client_handshake_over(
            Box::new(cr) as BoxRead,
            Box::new(cw) as BoxWrite,
            &cfg,
            "example.com:443",
        ).await.unwrap();

        let (mut s_reader, _s_writer) = server_handshake(
            sr,
            sw,
            cfg.method,
            &cfg.password,
        ).await.unwrap();

        let mut stream = SsStream::new(c_reader, c_writer);

        // 写数据
        stream.write_all(b"hello via ss stream").await.unwrap();
        // 关写端 (FIN)
        stream.shutdown().await.unwrap();
        // 再次 shutdown 保证幂等
        stream.shutdown().await.unwrap();

        // 对端读首块 (握手时客户端发的 target 目标头)
        let first_chunk = s_reader.read_chunk().await.unwrap();
        assert!(!first_chunk.is_empty(), "首块应包含目标头");
        let (target, hlen) = crate::proxy::shadowsocks::decode_socks_addr(&first_chunk).unwrap();
        assert_eq!(target, "example.com:443");
        assert_eq!(&first_chunk[hlen..], b"");

        // 对端读第 2 块 (stream.write_all 写入的数据)
        let data_chunk = s_reader.read_chunk().await.unwrap();
        assert_eq!(data_chunk, b"hello via ss stream");

        // 对端读到 EOF (空 Vec)
        let eof_chunk = s_reader.read_chunk().await.unwrap();
        assert!(eof_chunk.is_empty(), "对端在 shutdown 后必须读到 EOF");
    }
}
