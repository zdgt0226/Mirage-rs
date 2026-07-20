//! Shadowsocks AEAD (SIP004) 客户端 —— 让 Mirage **服务端**能把流量再经 SS 发往上游出口,
//! 即把 Mirage 当作中转站:
//!
//! ```text
//! 客户端 ──(Mirage 加密隧道)──▶ Mirage 服务端 ──(Shadowsocks)──▶ SS 服务器 ──▶ 目标
//! ```
//!
//! 只实现**客户端侧的 TCP**(SIP004 AEAD)。协议要点:
//!
//! - 主密钥由密码经 OpenSSL 的 `EVP_BytesToKey`(MD5 链)派生 —— 这是 SS 的历史约定,
//!   所有现存服务器都这么算, 不能换成别的 KDF, 否则连不上。
//! - 每条连接每个方向各自随机一个 salt(长度 = 密钥长度), 用
//!   `HKDF-SHA1(主密钥, salt, "ss-subkey")` 派生该方向的会话子密钥。
//! - 流格式: `[salt][chunk][chunk]...`, 每个 chunk 是
//!   `[加密长度(2B)+tag][加密载荷+tag]`, 长度上限 0x3FFF。
//! - nonce 是 12 字节**小端**计数器, **每次加密后 +1** —— 长度和载荷各消耗一个 nonce。
//! - 首个载荷是 SOCKS5 格式的目标地址 `[ATYP][ADDR][PORT_BE]`。
//!
//! **不实现 UDP**: SS 的 UDP 是另一套包格式 (每包独立 salt, 无分块)。当前配了 SS 上游时
//! 服务端的 UDP 中继仍走直连, 详见 `handle_tcp_relay` 调用处的说明与启动告警。

use anyhow::{anyhow, bail, Result};
use md5::{Digest, Md5};
use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// SS 单个 chunk 的载荷长度上限 (协议规定 11 位 + 掩码, 实际 0x3FFF)。
const MAX_CHUNK: usize = 0x3FFF;
const TAG_LEN: usize = 16;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Method {
    Aes128Gcm,
    Aes256Gcm,
    Chacha20IetfPoly1305,
}

impl Method {
    pub fn parse(s: &str) -> Result<Self> {
        match s.to_ascii_lowercase().as_str() {
            "aes-128-gcm" => Ok(Self::Aes128Gcm),
            "aes-256-gcm" => Ok(Self::Aes256Gcm),
            // 两种写法在生态里都常见, 都认
            "chacha20-ietf-poly1305" | "chacha20-poly1305" => Ok(Self::Chacha20IetfPoly1305),
            other => bail!(
                "不支持的 Shadowsocks 加密方式 `{other}`。支持: aes-128-gcm / aes-256-gcm / \
                 chacha20-ietf-poly1305。(legacy 流式加密如 aes-256-cfb 无完整性校验、已废弃, 不支持)"
            ),
        }
    }

    /// 密钥长度。salt 长度与之相同 (SIP004)。
    pub fn key_len(&self) -> usize {
        match self {
            Self::Aes128Gcm => 16,
            Self::Aes256Gcm | Self::Chacha20IetfPoly1305 => 32,
        }
    }

    fn algorithm(&self) -> &'static ring::aead::Algorithm {
        match self {
            Self::Aes128Gcm => &ring::aead::AES_128_GCM,
            Self::Aes256Gcm => &ring::aead::AES_256_GCM,
            Self::Chacha20IetfPoly1305 => &ring::aead::CHACHA20_POLY1305,
        }
    }
}

/// 上游 SS 服务器配置。
#[derive(Debug, Clone)]
pub struct SsConfig {
    pub server: String,
    pub port: u16,
    pub password: String,
    pub method: Method,
}

impl SsConfig {
    pub fn addr(&self) -> String {
        // IPv6 字面量需方括号
        if self.server.contains(':') && !self.server.starts_with('[') {
            format!("[{}]:{}", self.server, self.port)
        } else {
            format!("{}:{}", self.server, self.port)
        }
    }
}

/// OpenSSL `EVP_BytesToKey(md5, salt=NULL, iter=1)` —— SS 的密码→主密钥派生。
///
/// `d_0 = ""`, `d_i = MD5(d_{i-1} || password)`, `key = (d_1||d_2||...)[..key_len]`。
/// 这是历史约定而非安全选择; 换成任何"更好"的 KDF 都会导致连不上现存服务器。
pub fn evp_bytes_to_key(password: &str, key_len: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(key_len + 16);
    let mut prev: Vec<u8> = Vec::new();
    while out.len() < key_len {
        let mut h = Md5::new();
        h.update(&prev);
        h.update(password.as_bytes());
        prev = h.finalize().to_vec();
        out.extend_from_slice(&prev);
    }
    out.truncate(key_len);
    out
}

/// `HKDF-SHA1(ikm=主密钥, salt, info="ss-subkey")` → 该方向的会话子密钥。
fn hkdf_subkey(master: &[u8], salt: &[u8], key_len: usize) -> Vec<u8> {
    struct Len(usize);
    impl ring::hkdf::KeyType for Len {
        fn len(&self) -> usize {
            self.0
        }
    }
    let prk = ring::hkdf::Salt::new(ring::hkdf::HKDF_SHA1_FOR_LEGACY_USE_ONLY, salt).extract(master);
    let okm = prk
        .expand(&[b"ss-subkey"], Len(key_len))
        .expect("hkdf expand 长度合法");
    let mut out = vec![0u8; key_len];
    okm.fill(&mut out).expect("hkdf fill");
    out
}

/// 单方向的 AEAD 状态: 密钥固定, nonce 是每次加/解密后自增的小端计数器。
struct Crypter {
    key: LessSafeKey,
    nonce: [u8; 12],
}

impl Crypter {
    fn new(method: Method, subkey: &[u8]) -> Self {
        let unbound = UnboundKey::new(method.algorithm(), subkey).expect("子密钥长度匹配算法");
        Self { key: LessSafeKey::new(unbound), nonce: [0u8; 12] }
    }

    /// 小端 96 位计数器 +1 (SIP004 规定)。
    fn bump(&mut self) {
        for b in self.nonce.iter_mut() {
            *b = b.wrapping_add(1);
            if *b != 0 {
                break;
            }
        }
    }

    /// 原地加密并追加 tag。
    fn seal(&mut self, buf: &mut Vec<u8>) -> Result<()> {
        let n = Nonce::assume_unique_for_key(self.nonce);
        self.key
            .seal_in_place_append_tag(n, Aad::empty(), buf)
            .map_err(|_| anyhow!("shadowsocks 加密失败"))?;
        self.bump();
        Ok(())
    }

    /// 原地解密 (buf 含 tag), 返回明文长度。
    fn open(&mut self, buf: &mut [u8]) -> Result<usize> {
        let n = Nonce::assume_unique_for_key(self.nonce);
        let plain = self
            .key
            .open_in_place(n, Aad::empty(), buf)
            .map_err(|_| anyhow!("shadowsocks 解密失败 (密码或加密方式不匹配?)"))?;
        let len = plain.len();
        self.bump();
        Ok(len)
    }
}

/// 把 `host:port` 编成 SOCKS5 地址格式 `[ATYP][ADDR][PORT_BE]`。
pub fn encode_socks_addr(target: &str) -> Result<Vec<u8>> {
    let (host, port_s) = target
        .rsplit_once(':')
        .ok_or_else(|| anyhow!("目标缺少端口: {target}"))?;
    let port: u16 = port_s.parse().map_err(|_| anyhow!("端口非法: {port_s}"))?;
    // 去掉 IPv6 字面量的方括号
    let host = host.trim_start_matches('[').trim_end_matches(']');

    let mut out = Vec::with_capacity(1 + host.len() + 3);
    if let Ok(v4) = host.parse::<std::net::Ipv4Addr>() {
        out.push(0x01);
        out.extend_from_slice(&v4.octets());
    } else if let Ok(v6) = host.parse::<std::net::Ipv6Addr>() {
        out.push(0x04);
        out.extend_from_slice(&v6.octets());
    } else {
        if host.is_empty() || host.len() > 255 {
            bail!("域名长度非法: {host:?}");
        }
        out.push(0x03);
        out.push(host.len() as u8);
        out.extend_from_slice(host.as_bytes());
    }
    out.extend_from_slice(&port.to_be_bytes());
    Ok(out)
}

// ────────────────────────────────────────────────────────────────────────────
// 读写半边
// ────────────────────────────────────────────────────────────────────────────

pub struct SsWriter<W> {
    inner: W,
    crypter: Crypter,
    buf: Vec<u8>,
}

impl<W: AsyncWriteExt + Unpin> SsWriter<W> {
    /// 写入明文, 内部按 MAX_CHUNK 切块并逐块加密。
    pub async fn write_all(&mut self, data: &[u8]) -> std::io::Result<()> {
        for chunk in data.chunks(MAX_CHUNK) {
            self.buf.clear();
            // [加密长度+tag]
            self.buf.extend_from_slice(&(chunk.len() as u16).to_be_bytes());
            self.crypter
                .seal(&mut self.buf)
                .map_err(|e| std::io::Error::other(e.to_string()))?;
            // [加密载荷+tag]
            let mut body = Vec::with_capacity(chunk.len() + TAG_LEN);
            body.extend_from_slice(chunk);
            self.crypter
                .seal(&mut body)
                .map_err(|e| std::io::Error::other(e.to_string()))?;
            self.buf.extend_from_slice(&body);
            // 一次 write_all 送出整个 chunk, 避免长度与载荷分成两个小包
            self.inner.write_all(&self.buf).await?;
        }
        self.inner.flush().await
    }
}

/// 用给定 salt 构造一个写半边 —— 仅供测试与交叉验证 (需要可复现的 salt)。
/// 生产路径请用 `connect`, 它每条连接随机 salt。
#[doc(hidden)]
pub fn test_writer<W: AsyncWriteExt + Unpin>(
    inner: W,
    method: Method,
    master: &[u8],
    salt: &[u8],
) -> SsWriter<W> {
    let subkey = hkdf_subkey(master, salt, method.key_len());
    SsWriter { inner, crypter: Crypter::new(method, &subkey), buf: Vec::new() }
}

pub struct SsReader<R> {
    inner: R,
    crypter: Option<Crypter>, // 首次读到 salt 后才建立
    method: Method,
    master: Vec<u8>,
}

impl<R: AsyncReadExt + Unpin> SsReader<R> {
    /// 读并解密一个 chunk。返回空 Vec 表示对端正常 EOF。
    pub async fn read_chunk(&mut self) -> std::io::Result<Vec<u8>> {
        // 首个 chunk 之前先收下行 salt
        if self.crypter.is_none() {
            let mut salt = vec![0u8; self.method.key_len()];
            match self.inner.read_exact(&mut salt).await {
                Ok(_) => {}
                Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(Vec::new()),
                Err(e) => return Err(e),
            }
            let subkey = hkdf_subkey(&self.master, &salt, self.method.key_len());
            self.crypter = Some(Crypter::new(self.method, &subkey));
        }
        let c = self.crypter.as_mut().unwrap();

        // [加密长度(2)+tag]
        let mut lenbuf = [0u8; 2 + TAG_LEN];
        match self.inner.read_exact(&mut lenbuf).await {
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(Vec::new()),
            Err(e) => return Err(e),
        }
        c.open(&mut lenbuf)
            .map_err(|e| std::io::Error::other(e.to_string()))?;
        let n = u16::from_be_bytes([lenbuf[0], lenbuf[1]]) as usize;
        if n == 0 || n > MAX_CHUNK {
            return Err(std::io::Error::other(format!(
                "shadowsocks chunk 长度非法: {n}"
            )));
        }

        // [加密载荷+tag]
        let mut body = vec![0u8; n + TAG_LEN];
        self.inner.read_exact(&mut body).await?;
        let plen = c
            .open(&mut body)
            .map_err(|e| std::io::Error::other(e.to_string()))?;
        body.truncate(plen);
        Ok(body)
    }
}

/// 连接上游 SS 服务器并完成"首包送目标地址"。
///
/// 返回 (读半边, 写半边, 底层 TCP 的裸 fd) —— fd 供调用方沿用既有的
/// `shutdown(SHUT_RDWR)` 双向唤醒机制。
#[allow(clippy::type_complexity)]
pub async fn connect(
    cfg: &SsConfig,
    target: &str,
) -> Result<(
    SsReader<tokio::net::tcp::OwnedReadHalf>,
    SsWriter<tokio::net::tcp::OwnedWriteHalf>,
    std::os::fd::RawFd,
)> {
    use std::os::fd::AsRawFd;

    let stream = TcpStream::connect(cfg.addr()).await?;
    stream.set_nodelay(true).ok();
    let fd = stream.as_raw_fd();
    let (r, w) = stream.into_split();

    let key_len = cfg.method.key_len();
    let master = evp_bytes_to_key(&cfg.password, key_len);

    // 上行 salt: 每连接随机
    let mut salt = vec![0u8; key_len];
    ring::rand::SecureRandom::fill(&ring::rand::SystemRandom::new(), &mut salt)
        .map_err(|_| anyhow!("生成 salt 失败"))?;
    let subkey = hkdf_subkey(&master, &salt, key_len);

    let mut writer = SsWriter {
        inner: w,
        crypter: Crypter::new(cfg.method, &subkey),
        buf: Vec::with_capacity(MAX_CHUNK + 2 * TAG_LEN + 2),
    };
    // salt 是明文前缀, 不经加密直接送出
    writer.inner.write_all(&salt).await?;

    // 首个载荷 = 目标地址
    let addr = encode_socks_addr(target)?;
    writer.write_all(&addr).await?;

    let reader = SsReader { inner: r, crypter: None, method: cfg.method, master };
    Ok((reader, writer, fd))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn evp_bytes_to_key_known_vectors() {
        // EVP_BytesToKey(MD5, "foobar") —— d1 = MD5("foobar"), d2 = MD5(d1||"foobar")
        // MD5("foobar") = 3858f62230ac3c915f300c664312c63f
        let k16 = evp_bytes_to_key("foobar", 16);
        assert_eq!(hex::encode(&k16), "3858f62230ac3c915f300c664312c63f");
        // 32 字节 = d1 || d2, 前 16 字节必须与上面一致 (链式派生)
        let k32 = evp_bytes_to_key("foobar", 32);
        assert_eq!(&k32[..16], &k16[..]);
        assert_eq!(k32.len(), 32);
        // 不同密码必须得到不同密钥
        assert_ne!(evp_bytes_to_key("other", 32), k32);
    }

    #[test]
    fn method_parse_and_lengths() {
        assert_eq!(Method::parse("aes-128-gcm").unwrap().key_len(), 16);
        assert_eq!(Method::parse("AES-256-GCM").unwrap().key_len(), 32);
        assert_eq!(Method::parse("chacha20-ietf-poly1305").unwrap().key_len(), 32);
        assert_eq!(Method::parse("chacha20-poly1305").unwrap().key_len(), 32);
        // legacy 流式加密必须明确拒绝, 且错误信息要解释原因
        let e = Method::parse("aes-256-cfb").unwrap_err().to_string();
        assert!(e.contains("aes-256-cfb") && e.contains("废弃"), "实际: {e}");
    }

    #[test]
    fn nonce_is_little_endian_counter() {
        let mut c = Crypter::new(Method::Aes256Gcm, &[7u8; 32]);
        assert_eq!(c.nonce[0], 0);
        c.bump();
        assert_eq!(c.nonce[0], 1, "应从低位字节开始自增 (小端)");
        // 低位溢出应进位到下一字节
        c.nonce = [0xff, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        c.bump();
        assert_eq!(&c.nonce[..2], &[0x00, 0x01], "0xff+1 应进位");
    }

    #[test]
    fn socks_addr_encoding() {
        assert_eq!(encode_socks_addr("1.2.3.4:443").unwrap(),
                   vec![0x01, 1, 2, 3, 4, 0x01, 0xbb]);
        let d = encode_socks_addr("example.com:80").unwrap();
        assert_eq!(d[0], 0x03);
        assert_eq!(d[1], 11);
        assert_eq!(&d[2..13], b"example.com");
        assert_eq!(&d[13..], &[0x00, 0x50]);
        let v6 = encode_socks_addr("[::1]:443").unwrap();
        assert_eq!(v6[0], 0x04);
        assert_eq!(v6.len(), 1 + 16 + 2);
        // 畸形输入
        assert!(encode_socks_addr("noport").is_err());
        assert!(encode_socks_addr("host:notaport").is_err());
    }

    #[test]
    fn hkdf_subkey_is_salt_dependent() {
        let master = evp_bytes_to_key("pw", 32);
        let a = hkdf_subkey(&master, &[1u8; 32], 32);
        let b = hkdf_subkey(&master, &[2u8; 32], 32);
        assert_ne!(a, b, "不同 salt 必须派生出不同子密钥");
        assert_eq!(a.len(), 32);
        // 同 salt 必须可复现 (否则两端对不上)
        assert_eq!(a, hkdf_subkey(&master, &[1u8; 32], 32));
    }

    /// **互通性黄金向量**。
    ///
    /// 下面这串字节是本实现产出的真实上行流(password="test-password",
    /// aes-256-gcm, salt 固定 0x5A×32, 载荷 = 地址 example.com:443 + "hi"),
    /// 并已用**独立实现**(Python `cryptography` 按 SIP004 规范另写一遍服务端解密)
    /// 验证过能正确解出。
    ///
    /// 为什么需要它: 自洽回环测试(writer→reader)证明不了互通 —— 两边可以以同样的方式
    /// 错而依然对得上。锁死这串字节, 等于锁死 EVP_BytesToKey、HKDF 子密钥、分块格式、
    /// 小端 nonce 递进、地址编码这一整套**对外契约**; 任何一处改动都会让它变红。
    #[tokio::test]
    async fn golden_vector_interop() {
        const GOLDEN: &str = "5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a\
                              b0e16a5dceed77b0fea00d5e6ecd971a6c5939cd1dc66594a807c9298737205d\
                              1517bf21efb2134f646d613f8afddbed4a7d05656d1a9961a2afe1fecb79fe74\
                              aa82c2cb6da24c3c49aded518cec7bbf4b3efc8bfc";
        let method = Method::Aes256Gcm;
        let master = evp_bytes_to_key("test-password", 32);
        let salt = vec![0x5Au8; 32];

        let mut wire: Vec<u8> = Vec::new();
        wire.extend_from_slice(&salt);
        {
            let mut w = test_writer(&mut wire, method, &master, &salt);
            w.write_all(&encode_socks_addr("example.com:443").unwrap()).await.unwrap();
            w.write_all(b"hi").await.unwrap();
        }
        assert_eq!(
            hex::encode(&wire),
            GOLDEN.replace(['\n', ' '], ""),
            "线格式发生了变化 —— 这会破坏与真实 SS 服务器的互通, 除非你确认新格式仍符合 SIP004"
        );
    }

    /// 自洽回环: 用 SsWriter 加密的字节流, 能被 SsReader 原样解回来。
    /// 这同时验证了分块、nonce 递进、salt 协商三者一致。
    #[tokio::test]
    async fn writer_reader_roundtrip() {
        let method = Method::Chacha20IetfPoly1305;
        let master = evp_bytes_to_key("secret", method.key_len());
        let salt = vec![9u8; method.key_len()];
        let subkey = hkdf_subkey(&master, &salt, method.key_len());

        let mut wire: Vec<u8> = Vec::new();
        wire.extend_from_slice(&salt); // reader 先吃 salt
        {
            let mut w = SsWriter {
                inner: &mut wire,
                crypter: Crypter::new(method, &subkey),
                buf: Vec::new(),
            };
            w.write_all(b"hello").await.unwrap();
            w.write_all(&vec![0xABu8; 40000]).await.unwrap(); // 跨多个 chunk
        }

        let mut r = SsReader {
            inner: &wire[..],
            crypter: None,
            method,
            master: master.clone(),
        };
        let mut got = Vec::new();
        loop {
            let c = r.read_chunk().await.unwrap();
            if c.is_empty() {
                break;
            }
            got.extend_from_slice(&c);
        }
        let mut want = b"hello".to_vec();
        want.extend_from_slice(&vec![0xABu8; 40000]);
        assert_eq!(got, want, "回环数据必须原样还原 (含跨 chunk 情形)");
    }

    #[tokio::test]
    async fn wrong_password_fails_to_decrypt() {
        let method = Method::Aes256Gcm;
        let salt = vec![3u8; method.key_len()];
        let good = evp_bytes_to_key("right", method.key_len());
        let subkey = hkdf_subkey(&good, &salt, method.key_len());

        let mut wire: Vec<u8> = Vec::new();
        wire.extend_from_slice(&salt);
        {
            let mut w = SsWriter {
                inner: &mut wire,
                crypter: Crypter::new(method, &subkey),
                buf: Vec::new(),
            };
            w.write_all(b"payload").await.unwrap();
        }
        // 用错密码解 → 必须失败而不是返回垃圾
        let mut r = SsReader {
            inner: &wire[..],
            crypter: None,
            method,
            master: evp_bytes_to_key("wrong", method.key_len()),
        };
        assert!(r.read_chunk().await.is_err(), "密码不匹配必须解密失败");
    }
}
