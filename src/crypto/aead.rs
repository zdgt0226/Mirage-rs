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
    /// 已发记录数, 用于只整形握手后前 scheme.len() 条 (跨 rekey 不重置, 表流内位置)。
    records_sent: u32,
    /// 本连接生效的填充整形方案 (new() 时从全局快照; config 换方案对新连接生效)。
    scheme: std::sync::Arc<Vec<(usize, usize)>>,
}

// 填充整形方案 (paddingScheme, 借鉴 AnyTLS / XTLS Vision): 握手后前 N 条记录的目标 plaintext
// 大小取自对应区间, 把一大条 inner TLS 握手记录切分+填充成一串定长小记录, 抹掉封装 TLS 握手的
// burst 长度序列 (USENIX Sec 2024 Xue et al. 主检测向量)。第 N 条后回落吞吐分桶、不填充。收端恒剥
// 尾零 + 逐记录重组, 故纯发端生效、wire 向后兼容。默认方案见 cipher::DEFAULT_PAD_SCHEME; B' 起可由
// config `tls_padding_scheme` 覆盖 + 热重载 (CryptoWriter::new 快照 cipher::padding_scheme())。

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
            scheme: crate::crypto::cipher::padding_scheme(),
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
            let remaining = plaintext.len() - offset;
            self.buffer.clear(); // 复用 Buffer, 零分配

            let scheme_idx = self.records_sent as usize;
            if self.padding && scheme_idx < self.scheme.len() {
                // paddingScheme 整形: 本记录 plaintext (含 content_type + 零填充) 定长 = rng[lo,hi]。
                // 取 target-1 字节数据 (留 1B content_type), 不足则纯零填充补满 → 记录大小恒 = target,
                // 与真实数据量无关, 切断 inner TLS 握手 burst 的长度关联。
                let (lo, hi) = self.scheme[scheme_idx];
                let target = self.rng.usize(lo..=hi);
                let take = target.saturating_sub(1).min(remaining);
                self.buffer.extend_from_slice(&plaintext[offset..offset + take]);
                offset += take;
                self.buffer.push(0x17); // inner content type = application_data
                if self.buffer.len() < target {
                    self.buffer.resize(target, 0); // 零填充补满至 target (收端恒剥尾零)
                }
            } else {
                // 第 N 条之后 (或未开 padding): 吞吐分桶随机化帧大小, 不填充。
                let r: f64 = self.rng.f64();
                let limit = if r <= 0.50 {
                    16384
                } else if r <= 0.85 {
                    8192
                } else {
                    4096
                };
                let end = std::cmp::min(offset + limit, plaintext.len());
                self.buffer.extend_from_slice(&plaintext[offset..end]);
                offset = end;
                self.buffer.push(0x17); // inner content type = application_data
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

        // nonce 用尽守卫 (与 send_data 一致): (key,nonce) 复用会毁 AEAD 安全。2^64 帧物理不可达,
        // 仅一致性 —— 关闭帧也不例外。
        if self.nonce == u64::MAX {
            return Err(anyhow!("AEAD nonce 耗尽, 拒绝复用"));
        }
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

    /// crypto **相对吞吐哨兵** (`#[ignore]`, 仅 CI 显式跑: `cargo test --release -- --ignored`)。
    ///
    /// 用**比值** (非绝对 GB/s) 当门 —— 两个 cipher 同机同条件跑, 比值抵消大部分绝对计时噪声。
    /// AES-NI 机器上 AES-256-GCM 实测 ~2× ChaCha20 (cipher agility 选 AES 的前提)。设宽松下限
    /// 1.3× 抗噪, 但 AES 回归到 ChaCha 水平 (没走 AES-NI / ring 算法配错 / 硬件加速丢失) 会跌破。
    /// 仅在检测到 AES-NI 时断言 (无 AES-NI 的 arm 等平台只打印不断言, ChaCha 本就更快)。
    #[test]
    #[ignore]
    fn aes_chacha_throughput_ratio_sentinel() {
        println!("\n== AEAD seal 吞吐 (16KB record, 本 CPU) ==");
        let cc = bench(&aead::CHACHA20_POLY1305, "ChaCha20-Poly1305");
        let aes = bench(&aead::AES_256_GCM, "AES-256-GCM");
        let ratio = aes / cc;
        println!("  → AES-256-GCM / ChaCha20 = {ratio:.2}x");
        #[cfg(target_arch = "x86_64")]
        if std::is_x86_feature_detected!("aes") && std::is_x86_feature_detected!("pclmulqdq") {
            assert!(
                ratio >= 1.3,
                "AES/ChaCha 吞吐比 {ratio:.2}x < 1.3 哨兵下限 —— AES-NI 机器上 AES 该显著更快; \
                 cipher agility 选 AES 的前提崩了 (没走 AES-NI / ring 算法配错)?"
            );
        }
    }
}

#[cfg(test)]
mod padding_tests {
    use super::*;
    use tokio::io::{duplex, AsyncReadExt};

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

    /// 大 payload (跨 paddingScheme 整形段 + 之后吞吐分桶) 必须逐记录重组后精确还原。
    #[tokio::test]
    async fn padding_large_payload_reassembles_exact() {
        let (a, b) = duplex(512 * 1024);
        let master = [11u8; 32];
        let mut w = CryptoWriter::new(a, &master, true);
        let mut r = CryptoReader::new(b, &master, false);
        w.set_padding(true);
        let big: Vec<u8> = (0..40_000u32).map(|i| (i * 7 + 3) as u8).collect();
        w.send_data(&big).await.unwrap();
        let mut got = Vec::new();
        while got.len() < big.len() {
            got.extend_from_slice(&r.recv_data().await.unwrap());
        }
        assert_eq!(got, big, "大 payload 逐记录重组必须精确还原");
    }

    /// paddingScheme: 前 N 条记录被**定长整形** (body ∈ 区间+tag) 且大 payload 被**切分**
    /// 成小记录 (远小于原始 40KB), 抹掉 inner TLS 握手 burst 长度序列。
    #[tokio::test]
    async fn scheme_shapes_first_records_and_splits() {
        let (a, mut b) = duplex(512 * 1024);
        let master = [12u8; 32];
        // 锁只护 "设默认 + new() 快照" (不跨 await); writer 快照后与全局解耦, 故读取阶段可释锁。
        let mut w = {
            let _g = crate::crypto::cipher::PAD_TEST_LOCK.lock().unwrap();
            crate::crypto::cipher::set_padding_scheme(crate::crypto::cipher::DEFAULT_PAD_SCHEME.to_vec());
            CryptoWriter::new(a, &master, true)
        };
        w.set_padding(true);
        let big = vec![0xABu8; 40_000];
        w.send_data(&big).await.unwrap();
        // 原始读前 3 条记录头, 断言定长整形 + 切分 (每条 ≤ 区间上限+tag, 远小于 40000)。
        for (i, &(lo, hi)) in crate::crypto::cipher::DEFAULT_PAD_SCHEME.iter().take(3).enumerate() {
            let mut h = [0u8; 5];
            b.read_exact(&mut h).await.unwrap();
            assert_eq!([h[0], h[1], h[2]], [0x17, 0x03, 0x03]);
            let body = u16::from_be_bytes([h[3], h[4]]) as usize;
            assert!(
                body >= lo + TAG_SIZE && body <= hi + TAG_SIZE,
                "记录 {i} body {body} 不在方案 [{lo},{hi}]+tag 内"
            );
            let mut skip = vec![0u8; body];
            b.read_exact(&mut skip).await.unwrap(); // 跳到下一条头
        }
    }
}
