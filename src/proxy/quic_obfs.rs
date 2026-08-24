//! QUIC Salamander 式混淆 (抗审查, `--features quic`)。见 docs/quic-transport-design.md §7。
//!
//! 参考 Hysteria2 的 Salamander: 在 **UDP socket 层**对每个 QUIC 包做 XOR 混淆 —— 把 QUIC **藏成
//! 随机 UDP**, GFW 连"这是 QUIC"都认不出, 更读不到 Initial 里的 SNI (直接废掉 GFW 基于 SNI 的 QUIC
//! 封锁, USENIX Security 2025)。**不碰 rustls/quinn 内部、不加重依赖** —— 靠 quinn 的自定义
//! `AsyncUdpSocket` (`Endpoint::new_with_abstract_socket`)。
//!
//! 每包线格式: `[salt(8B 随机)][ 原 QUIC 包 XOR keystream(blake3-XOF(key, salt)) ]`。key = blake3(obfs 密码)。
//! 两端 obfs 密码须一致。⚠️ 关 GSO/GRO (每报文单独混淆, 见 max_*_segments=1)。混淆非加密 (QUIC 自己已
//! 加密), 只为反 DPI; "随机 UDP"无掩护人群 (全加密流量检测风险), 配端口跳跃缓解 (后续)。

use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use quinn::udp::{RecvMeta, Transmit};
use quinn::{AsyncUdpSocket, UdpPoller};

const SALT_LEN: usize = 8;
/// 混淆开时 QUIC 包最大值 —— 留 SALT_LEN 头余量, 保证 obfs 包 (+8B) 仍 ≤ 常见 1500 MTU 不分片。
pub const OBFS_MAX_UDP_PAYLOAD: u16 = 1444;

/// 混淆 socket: 包一层真 socket, 出向 salt+XOR、入向去混淆。
pub struct ObfsSocket {
    inner: Arc<dyn AsyncUdpSocket>,
    key: [u8; 32],
}

impl std::fmt::Debug for ObfsSocket {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ObfsSocket").finish()
    }
}

impl ObfsSocket {
    pub fn wrap(inner: Arc<dyn AsyncUdpSocket>, obfs_password: &str) -> Arc<Self> {
        Arc::new(Self {
            inner,
            key: *blake3::hash(obfs_password.as_bytes()).as_bytes(),
        })
    }
}

/// keystream(blake3-XOF(key, salt)) 就地 XOR data。
fn xor_keystream(key: &[u8; 32], salt: &[u8], data: &mut [u8]) {
    let mut hasher = blake3::Hasher::new_keyed(key);
    hasher.update(salt);
    let mut xof = hasher.finalize_xof();
    let mut ks = [0u8; 1024];
    let mut off = 0;
    while off < data.len() {
        xof.fill(&mut ks);
        let n = (data.len() - off).min(ks.len());
        for i in 0..n {
            data[off + i] ^= ks[i];
        }
        off += n;
    }
}

impl AsyncUdpSocket for ObfsSocket {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        self.inner.clone().create_io_poller()
    }

    fn try_send(&self, transmit: &Transmit) -> io::Result<()> {
        // 单报文 (GSO 已关 → segment_size 恒 None)。salt(8) || (contents XOR keystream)。
        let mut buf = Vec::with_capacity(SALT_LEN + transmit.contents.len());
        buf.resize(SALT_LEN, 0);
        for b in buf.iter_mut().take(SALT_LEN) {
            *b = fastrand::u8(..);
        }
        buf.extend_from_slice(transmit.contents);
        let salt = {
            let mut s = [0u8; SALT_LEN];
            s.copy_from_slice(&buf[..SALT_LEN]);
            s
        };
        xor_keystream(&self.key, &salt, &mut buf[SALT_LEN..]);
        let obf = Transmit {
            destination: transmit.destination,
            ecn: transmit.ecn,
            contents: &buf,
            segment_size: None,
            src_ip: transmit.src_ip,
        };
        self.inner.try_send(&obf)
    }

    fn poll_recv(
        &self,
        cx: &mut Context,
        bufs: &mut [io::IoSliceMut<'_>],
        meta: &mut [RecvMeta],
    ) -> Poll<io::Result<usize>> {
        let n = match self.inner.poll_recv(cx, bufs, meta) {
            Poll::Ready(Ok(n)) => n,
            other => return other,
        };
        for i in 0..n {
            let len = meta[i].len;
            if len < SALT_LEN {
                meta[i].len = 0; // 太短, 非我们的包 → 丢
                continue;
            }
            let mut salt = [0u8; SALT_LEN];
            salt.copy_from_slice(&bufs[i][..SALT_LEN]);
            let plen = len - SALT_LEN;
            xor_keystream(&self.key, &salt, &mut bufs[i][SALT_LEN..len]);
            bufs[i].copy_within(SALT_LEN..len, 0); // 去掉 salt 头, QUIC 包移到 buf 起始
            meta[i].len = plen;
            meta[i].stride = plen;
        }
        Poll::Ready(Ok(n))
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.inner.local_addr()
    }
    fn max_transmit_segments(&self) -> usize {
        1 // 关 GSO: 每报文单独混淆
    }
    fn max_receive_segments(&self) -> usize {
        1 // 关 GRO
    }
    fn may_fragment(&self) -> bool {
        self.inner.may_fragment()
    }
}
