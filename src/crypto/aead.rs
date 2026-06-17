use anyhow::{anyhow, Result};
use ring::aead::{self, LessSafeKey, UnboundKey, Nonce as RingNonce};
use hkdf::Hkdf;
use sha2::Sha256;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

pub const NONCE_SIZE: usize = 12;
pub const TAG_SIZE: usize = 16;
pub const MAX_RECORD_SIZE: usize = 16384;

/// 生成会话主密钥 (Session Master Key)
fn derive_master(password: &str, salt: &[u8]) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(Some(salt), password.as_bytes());
    let mut okm = [0u8; 32];
    hk.expand(b"pyrealiy-session", &mut okm).unwrap();
    okm
}

fn expand_key(master: &[u8; 32], info: &[u8]) -> LessSafeKey {
    let hk = Hkdf::<Sha256>::from_prk(master).unwrap();
    let mut okm = [0u8; 32];
    hk.expand(info, &mut okm).unwrap();
    let unbound = UnboundKey::new(&aead::CHACHA20_POLY1305, &okm).unwrap();
    LessSafeKey::new(unbound)
}

#[inline]
fn format_nonce(n: u64) -> RingNonce {
    let mut buf = [0u8; NONCE_SIZE];
    buf[4..12].copy_from_slice(&n.to_be_bytes());
    RingNonce::assume_unique_for_key(buf)
}

// ============================================================================
// CryptoWriter (发送端)
// ============================================================================

pub struct CryptoWriter<W> {
    writer: W,
    cipher: LessSafeKey,
    nonce: u64,
    buffer: Vec<u8>,
    is_initiator: bool,
    rng: fastrand::Rng,
}

impl<W: AsyncWrite + Unpin> CryptoWriter<W> {
    pub fn new(writer: W, master_key: &[u8; 32], is_initiator: bool) -> Self {
        let info = if is_initiator { b"c2s" } else { b"s2c" };
        let cipher = expand_key(master_key, info);
        Self {
            writer,
            cipher,
            nonce: 0,
            // 预分配最大容量，杜绝运行时内存分配开销
            buffer: Vec::with_capacity(MAX_RECORD_SIZE + TAG_SIZE),
            is_initiator,
            rng: fastrand::Rng::new(),
        }
    }

    /// 发送 TLS 1.3 格式的加密数据块
    pub async fn send_data(&mut self, plaintext: &[u8]) -> Result<()> {
        let plaintext_len = plaintext.len();
        if self.is_initiator {
            crate::monitor::add_up(plaintext_len as u64);
        } else {
            crate::monitor::add_down(plaintext_len as u64);
        }

        let mut offset = 0;

        while offset < plaintext.len() {
            // 分桶随机化帧大小，模拟真实 HTTPS 碎片特征
            let r: f64 = self.rng.f64();
            let limit = if r <= 0.50 {
                16384
            } else if r <= 0.85 {
                8192
            } else {
                4096
            };

            let end = std::cmp::min(offset + limit, plaintext.len());
            let chunk = &plaintext[offset..end];
            offset = end;

            // 复用 Buffer，零分配 (Zero-Allocation)
            self.buffer.clear();
            self.buffer.extend_from_slice(chunk);
            self.buffer.push(0x17); // inner content type = application_data

            let nonce_bytes = format_nonce(self.nonce);
            self.nonce += 1;

            self.cipher
                .seal_in_place_append_tag(nonce_bytes, aead::Aad::empty(), &mut self.buffer)
                .map_err(|e| anyhow!("encryption failed: {:?}", e))?;

            // 构造 5 字节 TLS Header: [0x17, 0x03, 0x03, len_hi, len_lo]
            let mut header = [0x17, 0x03, 0x03, 0x00, 0x00];
            let len = self.buffer.len() as u16;
            header[3..5].copy_from_slice(&len.to_be_bytes());

            self.writer.write_all(&header).await?;
            self.writer.write_all(&self.buffer).await?;
        }
        // 显式 flush 保证数据推向 OS 网络层
        self.writer.flush().await?;
        Ok(())
    }

    /// 发送 TLS 1.3 close_notify 警告，优雅关闭连接
    pub async fn send_close_notify(&mut self) -> Result<()> {
        self.buffer.clear();
        self.buffer.extend_from_slice(b"\x01\x00"); // Alert: warning(1), close_notify(0)
        self.buffer.push(0x15); // inner content type = alert (21)

        let nonce_bytes = format_nonce(self.nonce);
        self.nonce += 1;

        self.cipher
            .seal_in_place_append_tag(nonce_bytes, aead::Aad::empty(), &mut self.buffer)
            .map_err(|e| anyhow!("encryption failed: {:?}", e))?;

        let mut header = [0x17, 0x03, 0x03, 0x00, 0x00];
        let len = self.buffer.len() as u16;
        header[3..5].copy_from_slice(&len.to_be_bytes());

        self.writer.write_all(&header).await?;
        self.writer.write_all(&self.buffer).await?;
        self.writer.flush().await?;
        Ok(())
    }
}

// ============================================================================
// CryptoReader (接收端)
// ============================================================================

pub struct CryptoReader<R> {
    reader: R,
    cipher: LessSafeKey,
    nonce: u64,
    is_initiator: bool,
}

impl<R: AsyncRead + Unpin> CryptoReader<R> {
    pub fn new(reader: R, master_key: &[u8; 32], is_initiator: bool) -> Self {
        let info = if is_initiator { b"s2c" } else { b"c2s" };
        let cipher = expand_key(master_key, info);
        Self {
            reader,
            cipher,
            nonce: 0,
            is_initiator,
        }
    }

    pub fn inner(&self) -> &R {
        &self.reader
    }

    /// 接收并解密 TLS 1.3 格式的加密数据块
    pub async fn recv_data(&mut self) -> Result<Vec<u8>> {
        let mut header = [0u8; 5];
        self.reader.read_exact(&mut header).await?;

        // 虽然伪装成了 TLS 1.3 Application Data，我们还是简单断言一下
        if header[0] != 0x17 || header[1] != 0x03 || header[2] != 0x03 {
            return Err(anyhow!("invalid TLS header magic bytes"));
        }

        let len = u16::from_be_bytes([header[3], header[4]]) as usize;
        if len > MAX_RECORD_SIZE + 1 + TAG_SIZE {
            return Err(anyhow!("TLS record exceeds max size"));
        }

        // 读取密文
        let mut buffer = vec![0u8; len];
        self.reader.read_exact(&mut buffer).await?;

        let nonce_bytes = format_nonce(self.nonce);
        self.nonce += 1;

        // In-place 极速解密
        let plaintext_slice = self.cipher
            .open_in_place(nonce_bytes, aead::Aad::empty(), &mut buffer)
            .map_err(|e| anyhow!("decryption failed: {:?}", e))?;
        
        let plaintext_len = plaintext_slice.len();
        buffer.truncate(plaintext_len);

        if buffer.is_empty() {
            return Err(anyhow!("empty plaintext received"));
        }

        // 提取 inner_content_type
        let inner_type = buffer.pop().unwrap();
        
        let payload_len = buffer.len() as u64;
        if self.is_initiator {
            crate::monitor::add_down(payload_len);
        } else {
            crate::monitor::add_up(payload_len);
        }

        if inner_type == 0x17 {
            Ok(buffer)
        } else if inner_type == 0x15 {
            Err(anyhow!("peer sent TLS alert (close_notify)"))
        } else {
            Err(anyhow!("unknown TLS inner content type {:#x}", inner_type))
        }
    }
}

// ============================================================================
// 便捷构造工厂
// ============================================================================

pub fn create_crypto_pair<R: AsyncRead + Unpin, W: AsyncWrite + Unpin>(
    reader: R,
    writer: W,
    password: &str,
    salt: &[u8],
    is_initiator: bool,
) -> (CryptoReader<R>, CryptoWriter<W>) {
    let master = derive_master(password, salt);
    (
        CryptoReader::new(reader, &master, is_initiator),
        CryptoWriter::new(writer, &master, is_initiator),
    )
}
