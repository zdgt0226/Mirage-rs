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
            max_age_sec: 120 + fastrand::u64(0..60)
        }
    }

    pub fn get_raw_fd(&self) -> std::os::unix::io::RawFd {
        use std::os::unix::io::AsRawFd;
        self.reader.inner().as_ref().as_raw_fd()
    }
}
