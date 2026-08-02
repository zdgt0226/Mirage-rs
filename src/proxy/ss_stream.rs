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
}

impl SsStream {
    /// 用已握手完成的 SS 读/写半程 (底层已装箱) 包一条字节流。
    pub fn new(reader: Reader, writer: Writer) -> Self {
        Self {
            read: ReadState::Idle(reader),
            write: WriteState::Idle(writer),
            read_buf: Vec::new(),
            read_pos: 0,
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
        loop {
            match std::mem::replace(&mut me.write, WriteState::Poisoned) {
                WriteState::Idle(mut writer) => {
                    let data = buf.to_vec();
                    let n = data.len();
                    let fut: WriteFut = Box::pin(async move {
                        let r = writer.write_all(&data).await;
                        (writer, r)
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
                    }
                    Poll::Pending => {
                        me.write = WriteState::Busy(fut);
                        return Poll::Pending;
                    }
                },
                WriteState::Poisoned => unreachable!("SsStream write state poisoned"),
            }
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let me = &mut *self;
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
            WriteState::Poisoned => unreachable!("SsStream write state poisoned"),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.poll_flush(cx)
    }
}
