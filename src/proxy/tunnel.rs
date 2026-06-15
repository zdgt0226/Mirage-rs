use crate::crypto::aead::{CryptoReader, CryptoWriter};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};

/// 抽象出的加密信道。
/// 拆分为 reader 和 writer，彻底解耦 TCP 的收发，避免加锁。
pub struct Tunnel {
    pub reader: CryptoReader<OwnedReadHalf>,
    pub writer: CryptoWriter<OwnedWriteHalf>,
}

impl Tunnel {
    pub fn new(reader: CryptoReader<OwnedReadHalf>, writer: CryptoWriter<OwnedWriteHalf>) -> Self {
        Self { reader, writer }
    }
}
