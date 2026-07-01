use anyhow::{anyhow, Result};
use ring::aead::{self, LessSafeKey, UnboundKey, Nonce as RingNonce};
use hkdf::Hkdf;
use sha2::Sha256;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufWriter};

/// CryptoWriter 内嵌 BufWriter 容量 (方向一 Part 2). 64KB = 4× MAX_RECORD_SIZE:
/// send_data 处理 64KB plaintext 时内部拆 4 个 16KB 帧, 4× write_all 全部
/// 攒在 BufWriter 里, 最后 flush() 一次 syscall 送出 64KB. 老代码是 4 次
/// 独立 syscall + TCP_NODELAY 各自成小段. 视频下载单方向 4× syscall 缩减.
const WRITER_BUF_CAPACITY: usize = 65536;

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

pub struct CryptoWriter<W: AsyncWrite + Unpin> {
    /// 内嵌 BufWriter(64KB): 多帧写入自动 coalesce 为一次 syscall (方向一 Part 2).
    /// send_data 尾部的 flush() 会主动 drain BufWriter, 契约与 alpha.22 完全
    /// 一致 — 所有 caller (healthcheck / dns / control / handler 等) 无需改.
    writer: BufWriter<W>,
    cipher: LessSafeKey,
    nonce: u64,
    /// 加密临时区: [chunk_bytes, content_type=0x17] → seal_in_place 后附 tag
    buffer: Vec<u8>,
    /// 出线组帧区: [5B TLS header, encrypted_buffer]. 单次 write_all 送出,
    /// 修 alpha.21 之前的两次 write_all + flush 碎片化问题.
    framed: Vec<u8>,
    is_initiator: bool,
    rng: fastrand::Rng,
}

impl<W: AsyncWrite + Unpin> CryptoWriter<W> {
    pub fn new(writer: W, master_key: &[u8; 32], is_initiator: bool) -> Self {
        let info = if is_initiator { b"c2s" } else { b"s2c" };
        let cipher = expand_key(master_key, info);
        Self {
            writer: BufWriter::with_capacity(WRITER_BUF_CAPACITY, writer),
            cipher,
            nonce: 0,
            // 预分配最大容量，杜绝运行时内存分配开销
            buffer: Vec::with_capacity(MAX_RECORD_SIZE + TAG_SIZE),
            framed: Vec::with_capacity(5 + MAX_RECORD_SIZE + TAG_SIZE),
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

            // 单次 write_all 送出 [5B header + encrypted body], 避免:
            // - 分成两次 write_all 每次都在 TCP_NODELAY=on 下变成独立小包
            // - 帧间 flush 让 kernel 立刻 send 每一小片, 网络碎片化
            // 老代码 (alpha.21 之前) 每帧 3 次 syscall (header/body/flush),
            // 新代码 1 次 write_all, syscall 数量 3× 降.
            let body_len = self.buffer.len() as u16;
            self.framed.clear();
            self.framed.extend_from_slice(&[0x17, 0x03, 0x03]);
            self.framed.extend_from_slice(&body_len.to_be_bytes());
            self.framed.extend_from_slice(&self.buffer);
            self.writer.write_all(&self.framed).await?;
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

        // 单次 write_all + flush (关闭是终态, 必须立即刷到网络层保证对端 EOF)
        let body_len = self.buffer.len() as u16;
        self.framed.clear();
        self.framed.extend_from_slice(&[0x17, 0x03, 0x03]);
        self.framed.extend_from_slice(&body_len.to_be_bytes());
        self.framed.extend_from_slice(&self.buffer);
        self.writer.write_all(&self.framed).await?;
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
