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
    // ── SIP004 AEAD (经典) ──
    Aes128Gcm,
    Aes256Gcm,
    Chacha20IetfPoly1305,
    // ── SIP022 (Shadowsocks 2022) ──
    Ss2022Aes128Gcm,
    Ss2022Aes256Gcm,
    Ss2022Chacha20Poly1305,
}

impl Method {
    pub fn parse(s: &str) -> Result<Self> {
        match s.to_ascii_lowercase().as_str() {
            "aes-128-gcm" => Ok(Self::Aes128Gcm),
            "aes-256-gcm" => Ok(Self::Aes256Gcm),
            // 两种写法在生态里都常见, 都认
            "chacha20-ietf-poly1305" | "chacha20-poly1305" => Ok(Self::Chacha20IetfPoly1305),
            "2022-blake3-aes-128-gcm" => Ok(Self::Ss2022Aes128Gcm),
            "2022-blake3-aes-256-gcm" => Ok(Self::Ss2022Aes256Gcm),
            "2022-blake3-chacha20-poly1305" => Ok(Self::Ss2022Chacha20Poly1305),
            other => bail!(
                "不支持的 Shadowsocks 加密方式 `{other}`。支持: \
                 aes-128-gcm / aes-256-gcm / chacha20-ietf-poly1305 (SIP004), \
                 2022-blake3-aes-128-gcm / 2022-blake3-aes-256-gcm / \
                 2022-blake3-chacha20-poly1305 (SIP022)。\
                 (legacy 流式加密如 aes-256-cfb 无完整性校验、已废弃, 不支持)"
            ),
        }
    }

    /// 是否为 Shadowsocks 2022 (SIP022)。两代在**密钥来源**与**帧结构**上都不同, 不可混用。
    pub fn is_2022(&self) -> bool {
        matches!(
            self,
            Self::Ss2022Aes128Gcm | Self::Ss2022Aes256Gcm | Self::Ss2022Chacha20Poly1305
        )
    }

    /// 密钥长度。salt 长度与之相同 (两代皆然)。
    pub fn key_len(&self) -> usize {
        match self {
            Self::Aes128Gcm | Self::Ss2022Aes128Gcm => 16,
            Self::Aes256Gcm
            | Self::Chacha20IetfPoly1305
            | Self::Ss2022Aes256Gcm
            | Self::Ss2022Chacha20Poly1305 => 32,
        }
    }

    fn algorithm(&self) -> &'static ring::aead::Algorithm {
        match self {
            Self::Aes128Gcm | Self::Ss2022Aes128Gcm => &ring::aead::AES_128_GCM,
            Self::Aes256Gcm | Self::Ss2022Aes256Gcm => &ring::aead::AES_256_GCM,
            Self::Chacha20IetfPoly1305 | Self::Ss2022Chacha20Poly1305 => {
                &ring::aead::CHACHA20_POLY1305
            }
        }
    }
}

/// SIP022 的 BLAKE3 KDF context。**必须逐字一致**, 差一个字符就得出完全不同的密钥,
/// 表现为"能连上但握手后对不上", 极难排查。
const SS2022_KDF_CONTEXT: &str = "shadowsocks 2022 session subkey";

/// SIP022 会话子密钥: `BLAKE3::derive_key(context, PSK || salt)`, 取 key_len 字节。
///
/// 注意 key_material 的顺序是 **PSK 在前、salt 在后**, 与 SIP004 的 HKDF(ikm=主密钥,
/// salt=salt) 是完全不同的构造 —— 两者不能互相套用。
fn ss2022_session_key(psk: &[u8], salt: &[u8], key_len: usize) -> Vec<u8> {
    let mut hasher = blake3::Hasher::new_derive_key(SS2022_KDF_CONTEXT);
    hasher.update(psk);
    hasher.update(salt);
    let mut out = vec![0u8; key_len];
    hasher.finalize_xof().fill(&mut out);
    out
}

/// SIP022 的 PSK 在配置里是 **base64 编码**的, 且解码后长度必须等于 key_len。
///
/// 这与 SIP004 的"任意密码经 EVP_BytesToKey 派生"完全不同 —— 2022 不做密码拉伸,
/// 配置里那串就是密钥本身。长度不对必须直接报错: 若容忍并截断/补齐, 会得到一个
/// 双方不一致的密钥, 表现为连上后解密全失败, 而错误信息完全指不到根因。
pub fn decode_ss2022_psk(b64: &str, key_len: usize) -> Result<Vec<u8>> {
    use base64::Engine;
    let psk = base64::engine::general_purpose::STANDARD
        .decode(b64.trim())
        .map_err(|e| anyhow!("SIP022 的 password 必须是 base64 编码的密钥: {e}"))?;
    if psk.len() != key_len {
        bail!(
            "SIP022 密钥长度不对: base64 解码后 {} 字节, 该加密方式要求 {} 字节。\
             (可用 `openssl rand -base64 {}` 生成)",
            psk.len(), key_len, key_len
        );
    }
    Ok(psk)
}

/// 上游 SS 服务器配置。
///
/// `block_udp` 严格说不属于"如何连 SS", 但它恰好在**存在上游时**才有意义, 且本结构
/// 已被一路传到 control.rs 的分派点 —— 让它搭个便车比另开一条管线更简单也更不易漏。
#[derive(Debug, Clone)]
pub struct SsConfig {
    pub server: String,
    pub port: u16,
    pub password: String,
    pub method: Method,
    /// true = 拒绝 UDP 中继 (默认)。见 config::UdpPolicy 的说明。
    pub block_udp: bool,
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
// SIP022 (Shadowsocks 2022) 帧结构
// ────────────────────────────────────────────────────────────────────────────
//
// 与 SIP004 完全不同, 不能套用:
//
//   请求 (客户端→服务端):
//     [salt: key_len]
//     [AEAD(定长头): 11 + tag]      类型(1)=0 | 时间戳(8, u64 BE) | 变长头长度(2, u16 BE)
//     [AEAD(变长头): 上述长度 + tag] 目标地址 | padding 长度(2) | padding | 首段载荷
//     [后续 chunk: 与 SIP004 同构]
//
//   响应 (服务端→客户端):
//     [salt: key_len]
//     [AEAD(定长头): 1+8+key_len+2 + tag]  类型(1)=1 | 时间戳(8) | **请求 salt** | 载荷长度(2)
//     [AEAD(载荷): 上述长度 + tag]
//     [后续 chunk]
//
// 两个 SIP004 没有的安全要素:
//   · **时间戳**: 双方校验 ±30s, 用于抗重放。这也意味着两端时钟偏差过大会直接连不上
//     (与 Mirage 自己的握手容差是同类问题, 见 auth_ts_tolerance_secs)。
//   · **请求 salt 回显**: 服务端必须在响应头里回显客户端的 salt, 把响应绑定到本次请求。
//     不校验它, 攻击者就能把另一会话的响应重放给你。

const SS2022_TYPE_CLIENT: u8 = 0;
const SS2022_TYPE_SERVER: u8 = 1;
/// 时间戳容差 (秒)。协议规定 30s。
const SS2022_TS_TOLERANCE: u64 = 30;

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// 构造 SIP022 请求的定长头与变长头明文。
///
/// `initial_payload` 为空时塞一段随机 padding —— 协议如此规定, 目的是让"只建连不发数据"
/// 的请求不至于呈现固定长度特征。有首段载荷时 padding 长度写 0。
fn build_2022_request(target: &str, initial_payload: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
    let addr = encode_socks_addr(target)?;

    let mut var = Vec::with_capacity(addr.len() + 2 + 64 + initial_payload.len());
    var.extend_from_slice(&addr);
    if initial_payload.is_empty() {
        // 0..=64 的随机 padding (协议允许 0..=900, 取小段即可打散长度特征)
        let pad_len = fastrand::usize(..65);
        var.extend_from_slice(&(pad_len as u16).to_be_bytes());
        var.extend(std::iter::repeat_n(0u8, pad_len).map(|_| fastrand::u8(..)));
    } else {
        var.extend_from_slice(&0u16.to_be_bytes());
        var.extend_from_slice(initial_payload);
    }

    if var.len() > u16::MAX as usize {
        bail!("SIP022 变长头过长: {} 字节", var.len());
    }
    let mut fixed = Vec::with_capacity(11);
    fixed.push(SS2022_TYPE_CLIENT);
    fixed.extend_from_slice(&now_unix().to_be_bytes());
    fixed.extend_from_slice(&(var.len() as u16).to_be_bytes());

    Ok((fixed, var))
}

/// 校验服务端响应的定长头。返回随后那段载荷的长度。
///
/// 三项都必须查: 类型 / 时间戳 / **请求 salt 回显**。少查任何一项都会留下重放面。
fn parse_2022_response_header(plain: &[u8], our_salt: &[u8]) -> Result<usize> {
    let klen = our_salt.len();
    if plain.len() != 1 + 8 + klen + 2 {
        bail!("SIP022 响应定长头长度异常: {}", plain.len());
    }
    if plain[0] != SS2022_TYPE_SERVER {
        bail!("SIP022 响应头类型应为 {SS2022_TYPE_SERVER}, 实际 {}", plain[0]);
    }
    let ts = u64::from_be_bytes(plain[1..9].try_into().unwrap());
    let now = now_unix();
    if now.abs_diff(ts) > SS2022_TS_TOLERANCE {
        bail!(
            "SIP022 响应时间戳超出 ±{SS2022_TS_TOLERANCE}s (对端 {ts}, 本机 {now}) —— \
             两端时钟不同步, 或是重放的旧响应"
        );
    }
    if &plain[9..9 + klen] != our_salt {
        bail!("SIP022 响应未回显本次请求的 salt —— 可能是重放的其它会话响应");
    }
    Ok(u16::from_be_bytes(plain[9 + klen..].try_into().unwrap()) as usize)
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

    /// 把整块明文密封后直接送出 —— **不套** chunk 的长度前缀。
    /// SIP022 的定长头/变长头就是这样发的: 它们自身已带长度语义, 再套一层就错了。
    async fn write_raw_sealed(&mut self, plain: &[u8]) -> std::io::Result<()> {
        let mut b = plain.to_vec();
        self.crypter
            .seal(&mut b)
            .map_err(|e| std::io::Error::other(e.to_string()))?;
        self.inner.write_all(&b).await?;
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
    /// SIP004: EVP_BytesToKey 出的主密钥; SIP022: base64 解码出的 PSK。
    master: Vec<u8>,
    /// 本次请求用的上行 salt。SIP022 必须拿它校验服务端响应头里的回显, 防重放。
    req_salt: Vec<u8>,
    /// SIP022 首个 chunk 混在响应定长头之后, 与后续 chunk 结构不同, 需单独处理一次。
    ss2022_first_done: bool,
}

impl<R: AsyncReadExt + Unpin> SsReader<R> {
    /// 读并解密一个 chunk。返回空 Vec 表示对端正常 EOF。
    pub async fn read_chunk(&mut self) -> std::io::Result<Vec<u8>> {
        // 首个 chunk 之前先收下行 salt
        if self.crypter.is_none() {
            let klen = self.method.key_len();
            let mut salt = vec![0u8; klen];
            match self.inner.read_exact(&mut salt).await {
                Ok(_) => {}
                Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(Vec::new()),
                Err(e) => return Err(e),
            }
            let subkey = if self.method.is_2022() {
                ss2022_session_key(&self.master, &salt, klen)
            } else {
                hkdf_subkey(&self.master, &salt, klen)
            };
            self.crypter = Some(Crypter::new(self.method, &subkey));
        }

        // SIP022: salt 之后是定长响应头 (含请求 salt 回显), 其后那段载荷的长度由它给出。
        // 这一步每条连接只做一次, 之后回到与 SIP004 同构的 chunk 循环。
        if self.method.is_2022() && !self.ss2022_first_done {
            self.ss2022_first_done = true;
            let klen = self.method.key_len();
            let hdr_len = 1 + 8 + klen + 2;
            let mut hdr = vec![0u8; hdr_len + TAG_LEN];
            match self.inner.read_exact(&mut hdr).await {
                Ok(_) => {}
                Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(Vec::new()),
                Err(e) => return Err(e),
            }
            let c = self.crypter.as_mut().unwrap();
            let n = c.open(&mut hdr).map_err(|e| std::io::Error::other(e.to_string()))?;
            let plen = parse_2022_response_header(&hdr[..n], &self.req_salt)
                .map_err(|e| std::io::Error::other(e.to_string()))?;
            if plen == 0 {
                return Ok(Vec::new());
            }
            let mut body = vec![0u8; plen + TAG_LEN];
            self.inner.read_exact(&mut body).await?;
            let c = self.crypter.as_mut().unwrap();
            let bl = c.open(&mut body).map_err(|e| std::io::Error::other(e.to_string()))?;
            body.truncate(bl);
            return Ok(body);
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

    let key_len = cfg.method.key_len();
    // 两代的"密钥来源"完全不同: SIP004 把任意密码经 EVP_BytesToKey 拉伸;
    // SIP022 不做拉伸, 配置里那串 base64 解码后**就是**密钥本身。
    //
    // 这一步刻意放在 **connect 之前**: PSK 格式/长度错是配置问题, 若先建连,
    // 网络错误 (Connection refused / 超时) 会把真正的原因盖住, 用户对着
    // "连接被拒" 根本查不到是密钥写错了。
    let master = if cfg.method.is_2022() {
        decode_ss2022_psk(&cfg.password, key_len)?
    } else {
        evp_bytes_to_key(&cfg.password, key_len)
    };

    let stream = TcpStream::connect(cfg.addr()).await?;
    stream.set_nodelay(true).ok();
    let fd = stream.as_raw_fd();
    let (r, w) = stream.into_split();

    // 上行 salt: 每连接随机
    let mut salt = vec![0u8; key_len];
    ring::rand::SecureRandom::fill(&ring::rand::SystemRandom::new(), &mut salt)
        .map_err(|_| anyhow!("生成 salt 失败"))?;
    let subkey = if cfg.method.is_2022() {
        ss2022_session_key(&master, &salt, key_len)
    } else {
        hkdf_subkey(&master, &salt, key_len)
    };

    let mut writer = SsWriter {
        inner: w,
        crypter: Crypter::new(cfg.method, &subkey),
        buf: Vec::with_capacity(MAX_CHUNK + 2 * TAG_LEN + 2),
    };
    // salt 是明文前缀, 不经加密直接送出 (两代皆然)
    writer.inner.write_all(&salt).await?;

    if cfg.method.is_2022() {
        // SIP022: 定长头 + 变长头 (目标地址在变长头里, 不是普通 chunk)
        let (fixed, var) = build_2022_request(target, &[])?;
        writer.write_raw_sealed(&fixed).await?;
        writer.write_raw_sealed(&var).await?;
    } else {
        // SIP004: 首个 chunk 就是目标地址
        let addr = encode_socks_addr(target)?;
        writer.write_all(&addr).await?;
    }

    let reader = SsReader {
        inner: r,
        crypter: None,
        method: cfg.method,
        master,
        req_salt: salt,
        ss2022_first_done: false,
    };
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
            req_salt: salt.clone(),
            ss2022_first_done: false,
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
            req_salt: salt.clone(),
            ss2022_first_done: false,
        };
        assert!(r.read_chunk().await.is_err(), "密码不匹配必须解密失败");
    }
}

#[cfg(test)]
mod ss2022_crypto_tests {
    use super::*;

    /// **对照验证**: 会话子密钥派生必须与成熟实现 `shadowsocks-crypto` 逐字节一致。
    ///
    /// 这是 SIP022 最容易搞错、错了又最难排查的一步 (context 字符串差一个字符、
    /// key_material 拼接顺序反了, 都会得出完全不同的密钥, 表现为"连上但解不开")。
    /// shadowsocks-crypto 是 dev-dependency, 不进发布二进制。
    #[test]
    fn session_key_matches_reference_impl() {
        use shadowsocks_crypto::v2::BLAKE3_KEY_DERIVE_CONTEXT;
        // 先确认双方用的是同一个 context 字符串
        assert_eq!(SS2022_KDF_CONTEXT, BLAKE3_KEY_DERIVE_CONTEXT,
                   "BLAKE3 KDF context 必须与参考实现完全一致");

        for (klen, label) in [(16usize, "aes-128"), (32usize, "aes-256")] {
            let psk = vec![0xABu8; klen];
            let salt = vec![0x5Cu8; klen];

            // 参考实现的派生方式 (照搬 shadowsocks-crypto TcpCipher::new 的算法)
            let key_material = [&psk[..], &salt[..]].concat();
            let mut h = blake3::Hasher::new_derive_key(BLAKE3_KEY_DERIVE_CONTEXT);
            h.update(&key_material);
            let mut expect = vec![0u8; klen];
            h.finalize_xof().fill(&mut expect);

            let got = ss2022_session_key(&psk, &salt, klen);
            assert_eq!(got, expect, "{label} 的会话子密钥与参考实现不一致");
        }
    }

    /// 我们用两次 update 喂 (psk, salt), 参考实现用一次 update 喂拼接结果。
    /// BLAKE3 是流式哈希, 两者必须等价 —— 这条测试把这个假设钉死。
    #[test]
    fn streaming_update_equals_concat() {
        let psk = b"0123456789abcdef";
        let salt = b"fedcba9876543210";
        let mut a = blake3::Hasher::new_derive_key(SS2022_KDF_CONTEXT);
        a.update(psk);
        a.update(salt);
        let mut ka = [0u8; 32];
        a.finalize_xof().fill(&mut ka);

        let mut b = blake3::Hasher::new_derive_key(SS2022_KDF_CONTEXT);
        b.update(&[&psk[..], &salt[..]].concat());
        let mut kb = [0u8; 32];
        b.finalize_xof().fill(&mut kb);

        assert_eq!(ka, kb, "分次 update 必须等价于拼接后一次 update");
    }

    #[test]
    fn psk_must_be_base64_of_exact_length() {
        use base64::Engine;
        let ok = base64::engine::general_purpose::STANDARD.encode([7u8; 32]);
        assert_eq!(decode_ss2022_psk(&ok, 32).unwrap(), vec![7u8; 32]);

        // 长度不匹配必须报错 (静默截断/补齐会造成两端密钥不一致)
        let short = base64::engine::general_purpose::STANDARD.encode([7u8; 16]);
        let e = decode_ss2022_psk(&short, 32).unwrap_err().to_string();
        assert!(e.contains("16 字节") && e.contains("32 字节"), "实际: {e}");

        // 非 base64 必须报错
        assert!(decode_ss2022_psk("不是base64!!!", 32).is_err());
    }

    #[test]
    fn method_parse_2022() {
        let m = Method::parse("2022-blake3-aes-256-gcm").unwrap();
        assert!(m.is_2022());
        assert_eq!(m.key_len(), 32);
        let m = Method::parse("2022-blake3-aes-128-gcm").unwrap();
        assert!(m.is_2022());
        assert_eq!(m.key_len(), 16);
        // SIP004 的不能被误判成 2022
        assert!(!Method::parse("aes-256-gcm").unwrap().is_2022());
        let m = Method::parse("2022-blake3-chacha20-poly1305").unwrap();
        assert!(m.is_2022());
        assert_eq!(m.key_len(), 32);
        // 仍未实现的变体要明确报错而非静默接受
        assert!(Method::parse("2022-blake3-chacha8-poly1305").is_err());
    }
}
