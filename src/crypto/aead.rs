use anyhow::{anyhow, Result};
use ring::aead::{self, LessSafeKey, UnboundKey, Nonce as RingNonce};
use crate::crypto::cipher::Cipher;
use hkdf::Hkdf;
use sha2::Sha256;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufWriter};

/// CryptoWriter 内嵌 BufWriter 容量 (方向一 Part 2).
///
/// 上游 tcp_relay `buf = vec![0u8; 65536]` 是本 CryptoWriter 单次 send_data
/// 接收的最大 plaintext. 加密封装单帧开销 = 5B TLS header + 1B inner
/// content type + 16B Poly1305 tag = 22 字节.
///
/// alpha.23 曾用 64KB (65536), **漏算了这 22 字节 × N 帧 overhead**, 满载
/// 时最后一帧塞不进导致 2 次 syscall (外部审计发现). 精确计算 worst case:
///
/// - alpha.23 帧 size 分桶 rng (50%=16384, 35%=8192, 15%=4096)
/// - 65536 plaintext 全 4KB chunk → 16 帧, 16 × 4118 = **65888 bytes**
/// - 65536 plaintext 全 16KB chunk → 4 帧, 4 × 16406 = 65624 bytes
///
/// 68 KB = 69632 覆盖 worst case (65888) 还有 3744 headroom, 未来提高 tcp_relay
/// buf size 也有小 buffer 缓冲.
const WRITER_BUF_CAPACITY: usize = 68 * 1024;

pub const NONCE_SIZE: usize = 12;
pub const TAG_SIZE: usize = 16;
pub const MAX_RECORD_SIZE: usize = 16384;

/// 生成会话主密钥 (Session Master Key)
fn derive_master(password: &str, salt: &[u8]) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(Some(salt), password.as_bytes());
    let mut okm = [0u8; 32];
    // ⚠️ 协议冻结常量: "pyrealiy" 是 "pyreality" 的历史拼写错误。**切勿"修正"** ——
    // 客户端/服务端必须用完全相同的 info 字节才能派生同一密钥, 改了会让新旧版本
    // 密钥不兼容、静默解密失败。要动必须两端同步 + bump 协议版本。
    hk.expand(b"pyrealiy-session", &mut okm).unwrap();
    okm
}

/// 从 master + 方向 info + cipher 派生 AEAD 密钥。cipher 折进 HKDF info 做**域分隔**:
/// 不同 cipher 得不同 key, 使 re-key 时 (key,algo) 整体变化, nonce 归零安全。
/// ChaCha20 的后缀为空 → info 与旧版一致 → bootstrap 密钥**字节兼容**老协议。
fn expand_key(master: &[u8; 32], info: &[u8], cipher: Cipher) -> LessSafeKey {
    let hk = Hkdf::<Sha256>::from_prk(master).unwrap();
    let mut full_info = Vec::with_capacity(info.len() + 10);
    full_info.extend_from_slice(info);
    full_info.extend_from_slice(cipher.hkdf_suffix());
    let mut okm = [0u8; 32];
    hk.expand(&full_info, &mut okm).unwrap();
    let unbound = UnboundKey::new(cipher.ring_algorithm(), &okm).unwrap();
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
    /// 保存 master + cipher_kind 供 re-key (cipher agility) 重派生密钥。
    master: [u8; 32],
    cipher_kind: Cipher,
    /// 加密临时区: [chunk_bytes, content_type=0x17] → seal_in_place 后附 tag
    buffer: Vec<u8>,
    /// 出线组帧区: [5B TLS header, encrypted_buffer]. 单次 write_all 送出,
    /// 修 alpha.21 之前的两次 write_all + flush 碎片化问题.
    framed: Vec<u8>,
    is_initiator: bool,
    rng: fastrand::Rng,
    /// TLS record padding 开关 (从全局 cipher::tls_padding_enabled() 取)。
    padding: bool,
    /// 已发记录数, 用于只填握手后前 PAD_FIRST_N 条 (跨 rekey 不重置, 表流内位置)。
    records_sent: u32,
}

/// TLS padding: 只填握手后前 N 条记录 (GFW ML 主要认前几包长度序列)。
const PAD_FIRST_N: u32 = 4;
/// 每条最多追加的零字节数 (均匀随机 [0, PAD_MAX])。
const PAD_MAX: usize = 256;

impl<W: AsyncWrite + Unpin> CryptoWriter<W> {
    pub fn new(writer: W, master_key: &[u8; 32], is_initiator: bool) -> Self {
        // bootstrap 恒 ChaCha20 (与老协议字节兼容); 协商成功后由 rekey 切 AES。
        let info: &[u8] = if is_initiator { b"c2s" } else { b"s2c" };
        let cipher = expand_key(master_key, info, Cipher::ChaCha20Poly1305);
        Self {
            writer: BufWriter::with_capacity(WRITER_BUF_CAPACITY, writer),
            cipher,
            nonce: 0,
            master: *master_key,
            cipher_kind: Cipher::ChaCha20Poly1305,
            // 预分配最大容量，杜绝运行时内存分配开销
            buffer: Vec::with_capacity(MAX_RECORD_SIZE + TAG_SIZE),
            framed: Vec::with_capacity(5 + MAX_RECORD_SIZE + TAG_SIZE),
            is_initiator,
            rng: fastrand::Rng::new(),
            padding: crate::crypto::cipher::tls_padding_enabled(),
            records_sent: 0,
        }
    }

    /// 显式设置 padding (测试/需要绕过全局开关时用; 生产由 new() 从全局取)。
    #[cfg(test)]
    pub fn set_padding(&mut self, on: bool) {
        self.padding = on;
    }

    /// 切换 AEAD 算法 (cipher agility 协商后)。重派生该 cipher 的密钥 + **nonce 归零**
    /// (新 (key,algo) 组合, 归零不复用)。只应在协商确定后调一次。
    pub fn rekey(&mut self, cipher: Cipher) {
        let info: &[u8] = if self.is_initiator { b"c2s" } else { b"s2c" };
        self.cipher = expand_key(&self.master, info, cipher);
        self.cipher_kind = cipher;
        self.nonce = 0;
    }

    /// 当前 cipher (供协商/调试)。
    pub fn cipher(&self) -> Cipher {
        self.cipher_kind
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

            // TLS 1.3 原生零填充: 握手后前 N 条记录在 content_type 之后追加随机数量的零,
            // 抹掉包长序列指纹。收端恒剥零 (见 recv_data)。content 自身尾零在 0x17 之前不受影响。
            if self.padding && self.records_sent < PAD_FIRST_N {
                // 保证 chunk + 0x17 + pad ≤ MAX_RECORD_SIZE (buffer 此刻 = chunk+1)。
                let room = MAX_RECORD_SIZE.saturating_sub(self.buffer.len());
                let cap = PAD_MAX.min(room);
                if cap > 0 {
                    let pad = self.rng.usize(0..=cap);
                    self.buffer.resize(self.buffer.len() + pad, 0);
                }
            }
            self.records_sent = self.records_sent.saturating_add(1);

            // nonce 用尽即断: (key,nonce) 复用会毁掉 AEAD 安全。2^64 帧物理不可达,
            // 但显式拦住比依赖"到不了"稳妥 (溢出在 debug 会 panic, release 会回绕)。
            if self.nonce == u64::MAX {
                return Err(anyhow!("AEAD nonce 耗尽, 拒绝复用"));
            }
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
    master: [u8; 32],
    cipher_kind: Cipher,
    is_initiator: bool,
}

impl<R: AsyncRead + Unpin> CryptoReader<R> {
    pub fn new(reader: R, master_key: &[u8; 32], is_initiator: bool) -> Self {
        let info: &[u8] = if is_initiator { b"s2c" } else { b"c2s" };
        let cipher = expand_key(master_key, info, Cipher::ChaCha20Poly1305);
        Self {
            reader,
            cipher,
            nonce: 0,
            master: *master_key,
            cipher_kind: Cipher::ChaCha20Poly1305,
            is_initiator,
        }
    }

    pub fn inner(&self) -> &R {
        &self.reader
    }

    /// 切换 AEAD 算法 (cipher agility 协商后, 与对端 writer 的 rekey 同步)。重派生密钥 + nonce 归零。
    pub fn rekey(&mut self, cipher: Cipher) {
        let info: &[u8] = if self.is_initiator { b"s2c" } else { b"c2s" };
        self.cipher = expand_key(&self.master, info, cipher);
        self.cipher_kind = cipher;
        self.nonce = 0;
    }

    /// 当前 cipher (供协商/调试)。
    pub fn cipher(&self) -> Cipher {
        self.cipher_kind
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

        if self.nonce == u64::MAX {
            return Err(anyhow!("AEAD nonce 耗尽, 拒绝复用"));
        }
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

        // TLS 1.3 原生 padding: content_type 后可能跟任意数量的零填充。从尾剥零, 第一个非零
        // 字节即 content_type。content 自身的尾零在 content_type **之前**, 不会被误剥。
        // 收端恒剥零 (与是否开启发端 padding 无关) —— 这是两阶段上线的兼容基座: 老发端不发零,
        // 剥零对其无影响; 新发端发零, 老收端(无此逻辑)才会解析失败, 故收端须先普及。
        while buffer.last() == Some(&0) {
            buffer.pop();
        }
        // 剥零后若空 = 整帧全零, 畸形。
        if buffer.is_empty() {
            return Err(anyhow!("padding-only record (no content type)"));
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

/// 前向保密 (PFS) master: 在口令派生的基础上**混入临时 X25519 ECDH 共享秘密**。
///
/// - salt 仍是 client_random (= 客户端临时公钥, 见 crypto::pfs)。
/// - IKM = password || ecdh —— ecdh 是一次性的, 私钥用完即弃, 故口令泄露也解不了已录流量。
/// - **新 info label `pyrealiy-session-pfs`**: 刻意与非 PFS 的 `pyrealiy-session` 域分隔 →
///   pfs 与非 pfs 两端派生出不同密钥, 一端开一端没开会解密失败 (两端必须同开 pfs)。
fn derive_master_pfs(password: &str, salt: &[u8], ecdh: &[u8; 32]) -> [u8; 32] {
    let mut ikm = Vec::with_capacity(password.len() + 32);
    ikm.extend_from_slice(password.as_bytes());
    ikm.extend_from_slice(ecdh);
    let hk = Hkdf::<Sha256>::new(Some(salt), &ikm);
    let mut okm = [0u8; 32];
    hk.expand(b"pyrealiy-session-pfs", &mut okm).unwrap();
    okm
}

/// 同 `create_crypto_pair`, 但走 PFS master 派生 (混入 ecdh 共享秘密)。仅 pfs 两端调用。
pub fn create_crypto_pair_pfs<R: AsyncRead + Unpin, W: AsyncWrite + Unpin>(
    reader: R,
    writer: W,
    password: &str,
    salt: &[u8],
    ecdh: &[u8; 32],
    is_initiator: bool,
) -> (CryptoReader<R>, CryptoWriter<W>) {
    let master = derive_master_pfs(password, salt, ecdh);
    (
        CryptoReader::new(reader, &master, is_initiator),
        CryptoWriter::new(writer, &master, is_initiator),
    )
}

#[cfg(test)]
mod rekey_tests {
    use super::*;
    use tokio::io::duplex;

    /// writer(c2s, initiator) ↔ reader(c2s, 非 initiator) 一对; 可选先 rekey 到某 cipher。
    async fn roundtrip(rekey_to: Option<Cipher>) {
        let (a, b) = duplex(64 * 1024);
        let master = [7u8; 32];
        let mut w = CryptoWriter::new(a, &master, true);
        let mut r = CryptoReader::new(b, &master, false);
        if let Some(c) = rekey_to {
            w.rekey(c);
            r.rekey(c);
        }
        let msg = b"hello cipher agility 1234567890 payload";
        w.send_data(msg).await.unwrap();
        assert_eq!(&r.recv_data().await.unwrap(), msg);
    }

    #[tokio::test]
    async fn roundtrip_default_chacha() {
        roundtrip(None).await;
    }
    #[tokio::test]
    async fn roundtrip_rekey_aes() {
        roundtrip(Some(Cipher::Aes256Gcm)).await;
    }
    #[tokio::test]
    async fn roundtrip_rekey_chacha() {
        roundtrip(Some(Cipher::ChaCha20Poly1305)).await;
    }

    #[tokio::test]
    async fn mismatched_cipher_fails_closed() {
        // writer 切 AES, reader 留 ChaCha20 → 解密必失败 (fail-closed, 不静默出乱数据)。
        let (a, b) = duplex(64 * 1024);
        let master = [9u8; 32];
        let mut w = CryptoWriter::new(a, &master, true);
        let mut r = CryptoReader::new(b, &master, false);
        w.rekey(Cipher::Aes256Gcm);
        w.send_data(b"boom").await.unwrap();
        assert!(r.recv_data().await.is_err(), "cipher 不同步必须解密失败");
    }

    #[tokio::test]
    async fn rekey_resets_nonce_and_keeps_stream() {
        // 发 5 帧推进 nonce → rekey → nonce 归零 + 新 cipher 端到端仍通。
        let (a, b) = duplex(64 * 1024);
        let master = [3u8; 32];
        let mut w = CryptoWriter::new(a, &master, true);
        let mut r = CryptoReader::new(b, &master, false);
        for _ in 0..5 {
            w.send_data(b"x").await.unwrap();
            r.recv_data().await.unwrap();
        }
        assert_eq!(w.nonce, 5);
        assert_eq!(r.nonce, 5);
        w.rekey(Cipher::Aes256Gcm);
        r.rekey(Cipher::Aes256Gcm);
        assert_eq!(w.nonce, 0, "rekey 后 writer nonce 归零");
        assert_eq!(r.nonce, 0, "rekey 后 reader nonce 归零");
        w.send_data(b"post-rekey-payload").await.unwrap();
        assert_eq!(&r.recv_data().await.unwrap(), b"post-rekey-payload");
    }

    #[test]
    fn chacha_key_bytes_match_legacy() {
        // 向后兼容硬约束: ChaCha20 (后缀空) 派生的密钥必须与"折 cipher 前"完全一致。
        let master = [42u8; 32];
        let k_new = expand_key(&master, b"c2s", Cipher::ChaCha20Poly1305);
        let hk = Hkdf::<Sha256>::from_prk(&master).unwrap();
        let mut okm = [0u8; 32];
        hk.expand(b"c2s", &mut okm).unwrap();
        let k_old = LessSafeKey::new(UnboundKey::new(&aead::CHACHA20_POLY1305, &okm).unwrap());
        let mut b1 = b"legacy-compat".to_vec();
        let mut b2 = b1.clone();
        k_new.seal_in_place_append_tag(format_nonce(0), aead::Aad::empty(), &mut b1).unwrap();
        k_old.seal_in_place_append_tag(format_nonce(0), aead::Aad::empty(), &mut b2).unwrap();
        assert_eq!(b1, b2, "ChaCha20 密钥必须与旧版字节一致 (向后兼容)");
    }

    #[test]
    fn pfs_master_deterministic_and_domain_separated() {
        let salt = [1u8; 32];
        let ecdh = [2u8; 32];
        // 确定性: 同输入同密钥 (两端才能派同一 master)。
        assert_eq!(
            derive_master_pfs("pw", &salt, &ecdh),
            derive_master_pfs("pw", &salt, &ecdh),
        );
        // 域分隔: PFS master 必须 != 非 PFS master (label 不同 → 一端开一端没开会解密失败)。
        assert_ne!(
            derive_master_pfs("pw", &salt, &ecdh),
            derive_master("pw", &salt),
            "PFS master 必须与非 PFS 域分隔",
        );
        // ecdh 变 → master 变 (ecdh 真的进了派生; 这是 PFS 的根)。
        assert_ne!(
            derive_master_pfs("pw", &salt, &ecdh),
            derive_master_pfs("pw", &salt, &[9u8; 32]),
            "不同 ecdh 必须派生不同 master",
        );
    }

    #[tokio::test]
    async fn pfs_pair_roundtrips() {
        // 两端同 (password, salt, ecdh) → create_crypto_pair_pfs 端到端解密通。
        let (a, b) = duplex(64 * 1024);
        let salt = [7u8; 32];
        let ecdh = [8u8; 32];
        let (_ra, mut wa) = create_crypto_pair_pfs(tokio::io::empty(), a, "pw", &salt, &ecdh, true);
        let (mut rb, _wb) = create_crypto_pair_pfs(b, tokio::io::sink(), "pw", &salt, &ecdh, false);
        let msg = b"pfs payload 0123456789";
        wa.send_data(msg).await.unwrap();
        assert_eq!(&rb.recv_data().await.unwrap(), msg);
    }

    #[tokio::test]
    async fn pfs_mismatched_ecdh_fails_closed() {
        // 一端 ecdh 不同 (模拟 pfs 失配) → master 不同 → 解密必失败, 不静默出乱数据。
        let (a, b) = duplex(64 * 1024);
        let salt = [7u8; 32];
        let (_ra, mut wa) = create_crypto_pair_pfs(tokio::io::empty(), a, "pw", &salt, &[8u8; 32], true);
        let (mut rb, _wb) = create_crypto_pair_pfs(b, tokio::io::sink(), "pw", &salt, &[9u8; 32], false);
        wa.send_data(b"boom").await.unwrap();
        assert!(rb.recv_data().await.is_err(), "ecdh 不一致必须解密失败 (fail-closed)");
    }
}

#[cfg(test)]
mod cipher_bench {
    use ring::aead::{self, Aad, LessSafeKey, Nonce, UnboundKey};
    use std::time::Instant;

    fn bench(alg: &'static aead::Algorithm, name: &str) -> f64 {
        let key = LessSafeKey::new(UnboundKey::new(alg, &[0x42u8; 32]).unwrap());
        let mut buf = vec![0u8; 16384 + 16]; // 16KB record + tag 空间
        let iters = 200_000u64; // 200k × 16KB ≈ 3.1 GB
        let t = Instant::now();
        for i in 0..iters {
            let mut nb = [0u8; 12];
            nb[4..12].copy_from_slice(&i.to_be_bytes());
            buf.truncate(16384);
            key.seal_in_place_append_tag(Nonce::assume_unique_for_key(nb), Aad::empty(), &mut buf).unwrap();
        }
        let secs = t.elapsed().as_secs_f64();
        let gb = (iters * 16384) as f64 / 1e9;
        let gbps = gb / secs;
        println!("  {name:22} {gbps:6.2} GB/s  ({gb:.1} GB in {secs:.2}s)");
        gbps
    }

    #[test]
    #[ignore]
    fn compare_chacha_vs_aesgcm() {
        println!("\n== AEAD seal 吞吐 (16KB record, 本 CPU) ==");
        let cc = bench(&aead::CHACHA20_POLY1305, "ChaCha20-Poly1305");
        let aes = bench(&aead::AES_256_GCM, "AES-256-GCM");
        println!("  → AES-256-GCM / ChaCha20 = {:.2}x", aes / cc);
    }
}

#[cfg(test)]
mod padding_tests {
    use super::*;
    use tokio::io::duplex;

    async fn roundtrip_with_padding(payloads: &[&[u8]]) {
        let (a, b) = duplex(256 * 1024);
        let master = [9u8; 32];
        let mut w = CryptoWriter::new(a, &master, true);
        let mut r = CryptoReader::new(b, &master, false);
        w.set_padding(true);
        for p in payloads {
            w.send_data(p).await.unwrap();
            assert_eq!(
                &r.recv_data().await.unwrap(),
                p,
                "开 padding 的往返必须精确还原原文"
            );
        }
    }

    /// 前 4 条被填充、之后不填, 全部必须精确还原。
    #[tokio::test]
    async fn padding_roundtrip_exact() {
        roundtrip_with_padding(&[b"first", b"second", b"third", b"fourth", b"fifth-nopad", b"sixth"]).await;
    }

    /// 关键安全性: content **自身尾部的零字节**不得被剥零逻辑误删 (它们在 content_type 之前)。
    #[tokio::test]
    async fn padding_preserves_content_trailing_zeros() {
        roundtrip_with_padding(&[b"data\x00\x00\x00", b"\x00", b"x\x00y\x00\x00"]).await;
    }

    /// 收端恒剥零, 但发端不填时无零可剥, 尾零内容照样原样还原 (向后兼容基座)。
    #[tokio::test]
    async fn recv_strip_is_noop_when_sender_unpadded() {
        let (a, b) = duplex(64 * 1024);
        let master = [3u8; 32];
        let mut w = CryptoWriter::new(a, &master, true); // padding 默认 off
        let mut r = CryptoReader::new(b, &master, false);
        let msg = b"no padding here\x00";
        w.send_data(msg).await.unwrap();
        assert_eq!(&r.recv_data().await.unwrap(), msg);
    }
}
