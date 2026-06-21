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
}
