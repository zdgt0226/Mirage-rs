use std::io::Write;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::collections::VecDeque;

pub static GLOBAL_UP: AtomicU64 = AtomicU64::new(0);
pub static GLOBAL_DOWN: AtomicU64 = AtomicU64::new(0);

pub fn add_up(bytes: u64) {
    GLOBAL_UP.fetch_add(bytes, Ordering::Relaxed);
}

pub fn add_down(bytes: u64) {
    GLOBAL_DOWN.fetch_add(bytes, Ordering::Relaxed);
}

#[derive(Clone)]
pub struct MemoryWriter {
    buffer: Arc<Mutex<VecDeque<String>>>,
}

impl MemoryWriter {
    pub fn new() -> Self {
        Self {
            buffer: Arc::new(Mutex::new(VecDeque::with_capacity(500))),
        }
    }

    pub fn get_logs(&self) -> Vec<String> {
        let q = self.buffer.lock().unwrap();
        q.iter().cloned().collect()
    }
}

impl Write for MemoryWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let s = String::from_utf8_lossy(buf).to_string();
        if s.trim().is_empty() {
            return Ok(buf.len());
        }
        
        let mut q = self.buffer.lock().unwrap();
        if q.len() >= 500 {
            q.pop_front();
        }
        q.push_back(s);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

lazy_static::lazy_static! {
    pub static ref GLOBAL_LOGGER: MemoryWriter = MemoryWriter::new();
}

use tokio::io::{AsyncRead, ReadBuf};
use std::pin::Pin;
use std::task::{Context, Poll};

pub struct MonitoredReader<R> {
    inner: R,
    is_up: bool,
}

impl<R> MonitoredReader<R> {
    pub fn new(inner: R, is_up: bool) -> Self {
        Self { inner, is_up }
    }
}

impl<R: AsyncRead + Unpin> AsyncRead for MonitoredReader<R> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let before = buf.filled().len();
        let res = Pin::new(&mut self.inner).poll_read(cx, buf);
        let after = buf.filled().len();
        
        let read_bytes = (after - before) as u64;
        if read_bytes > 0 {
            if self.is_up {
                add_up(read_bytes);
            } else {
                add_down(read_bytes);
            }
        }
        res
    }
}
