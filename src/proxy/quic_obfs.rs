//! QUIC Salamander 式混淆 (抗审查, `--features quic`)。见 docs/quic-transport-design.md §7。
//!
//! 参考 Hysteria2 的 Salamander: 在 **UDP socket 层**对每个 QUIC 包做 XOR 混淆 —— 把 QUIC **藏成
//! 随机 UDP**, GFW 连"这是 QUIC"都认不出, 更读不到 Initial 里的 SNI (直接废掉 GFW 基于 SNI 的 QUIC
//! 封锁, USENIX Security 2025)。**不碰 rustls/quinn 内部、不加重依赖** —— 靠 quinn 的自定义
//! `AsyncUdpSocket` (`Endpoint::new_with_abstract_socket`)。
//!
//! 每包线格式: `[salt(8B 随机)][ 原 QUIC 包 XOR keystream(blake3-XOF(key, salt)) ]`。key = blake3(obfs 密码)。
//! 两端 obfs 密码须一致。发端关 GSO (`max_transmit_segments=1`, 每报文单独 salt); 收端 inner socket 的
//! UDP_GRO 无法关, 故 poll_recv **GRO-aware 逐段解** (合并 buffer 按 stride 拆, 每段用各自 salt)。混淆非加密 (QUIC 自己已
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

/// GRO-aware 逐段去混淆 (就地)。
///
/// `buf[..len]` 是 inner socket 收到的、可能被 UDP_GRO 合并的多段: 每段 `stride` 字节 (末段可能更短),
/// 各段是**独立 salt+XOR** 混淆的。逐段用各自的 salt 解、剥掉 8B salt 前移压实, 返回压实后的有效长度。
/// 段 < `SALT_LEN` 视为非法直接丢弃 (不计入输出)。`stride` 由调用方解析 (0 → 单段, 见 poll_recv)。
fn deobfs_datagram(key: &[u8; 32], buf: &mut [u8], len: usize, stride: usize) -> usize {
    let mut read = 0usize;
    let mut write = 0usize;
    while read < len {
        let seg = stride.min(len - read);
        if seg < SALT_LEN {
            read += seg; // 太短, 非合法段 → 丢
            continue;
        }
        let mut salt = [0u8; SALT_LEN];
        salt.copy_from_slice(&buf[read..read + SALT_LEN]);
        xor_keystream(key, &salt, &mut buf[read + SALT_LEN..read + seg]);
        buf.copy_within(read + SALT_LEN..read + seg, write); // 剥 salt, 前移压实
        write += seg - SALT_LEN;
        read += seg;
    }
    write
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
            if len == 0 {
                continue;
            }
            // ⚠️ inner socket 开了 UDP_GRO (quinn-udp 恒开), 会把多个独立 datagram 合并进一个 buffer:
            // len = 合并总字节, stride = 每段大小 (末段可能更短)。每段是**独立 salt+XOR** 混淆的, 必须
            // 逐段用各自的 salt 解 —— 不能整块用首段 salt (否则首段之后全腐化, 小包如 ACK 大面积合并
            // → CC 饿死, 真机实测 ~15-40x 崩)。单 datagram 时 stride==len, 循环只跑一次。
            let stride = if meta[i].stride == 0 { len } else { meta[i].stride };
            let write = deobfs_datagram(&self.key, &mut bufs[i], len, stride);
            meta[i].len = write; // write==0 (全丢) → quinn 忽略
            meta[i].stride = stride.saturating_sub(SALT_LEN); // 每段少 8B, 新 stride 一致 (末段短 quinn 自处理)
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
        // ⚠️ 必须 ≥2: quinn 按 max_udp_payload_size(1444) × 本值 定 recv buffer 尺寸。obfs 线上包 =
        // QUIC(≤1444) + salt(8) = 最多 1452 > 1444 → 若 buffer=1444 会**截断尾 8B**, 解出腐化 QUIC 包被
        // 丢 → bulk 下载大面积丢包 (真机实测吞吐 ~7x 崩)。返 2 → buffer 2888 容得下 1452。GRO 合并由
        // poll_recv 逐段解处理。
        2
    }
    fn may_fragment(&self) -> bool {
        self.inner.may_fragment()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(pw: &str) -> [u8; 32] {
        *blake3::hash(pw.as_bytes()).as_bytes()
    }

    /// 按 try_send 的线格式造一段: salt(8) || (payload XOR keystream(key,salt))。
    fn obf_seg(k: &[u8; 32], salt: [u8; SALT_LEN], payload: &[u8]) -> Vec<u8> {
        let mut seg = salt.to_vec();
        let mut body = payload.to_vec();
        xor_keystream(k, &salt, &mut body);
        seg.extend_from_slice(&body);
        seg
    }

    #[test]
    fn xor_keystream_is_involution() {
        let k = key("pw");
        let salt = [9u8; SALT_LEN];
        let orig = b"the quick brown fox jumps over the lazy dog x2 for >1KB block boundary";
        let mut data = orig.to_vec();
        xor_keystream(&k, &salt, &mut data);
        assert_ne!(&data, orig, "XOR 一次必须改变内容");
        xor_keystream(&k, &salt, &mut data);
        assert_eq!(&data, orig, "XOR 两次 (同 key+salt) 必还原");
    }

    #[test]
    fn xor_crosses_1kb_keystream_block() {
        // keystream 内部按 1024B 块填充; 跨块必须连续正确。
        let k = key("pw");
        let salt = [3u8; SALT_LEN];
        let orig = vec![0xA5u8; 3000];
        let mut data = orig.clone();
        xor_keystream(&k, &salt, &mut data);
        xor_keystream(&k, &salt, &mut data);
        assert_eq!(data, orig);
    }

    #[test]
    fn deobfs_single_datagram_roundtrip() {
        let k = key("pw");
        let payload = b"one quic packet payload";
        let seg = obf_seg(&k, [1u8; SALT_LEN], payload);
        let mut buf = seg.clone();
        // 单 datagram: stride == len。
        let n = deobfs_datagram(&k, &mut buf, seg.len(), seg.len());
        assert_eq!(&buf[..n], payload, "单段去混淆应还原原 payload");
    }

    #[test]
    fn deobfs_gro_multi_segment() {
        // 模拟 UDP_GRO 把 3 个独立 datagram 合并: 每段各自 salt, 等长 → stride 统一。
        let k = key("pw");
        let p0 = b"aaaaaaaaaaaaaaaaaaaa"; // 各 20B, 段长 28
        let p1 = b"bbbbbbbbbbbbbbbbbbbb";
        let p2 = b"cccccccccccccccccccc";
        let stride = SALT_LEN + p0.len();
        let mut buf = Vec::new();
        buf.extend_from_slice(&obf_seg(&k, [10u8; SALT_LEN], p0));
        buf.extend_from_slice(&obf_seg(&k, [20u8; SALT_LEN], p1));
        buf.extend_from_slice(&obf_seg(&k, [30u8; SALT_LEN], p2));
        let len = buf.len();
        let n = deobfs_datagram(&k, &mut buf, len, stride);
        let mut want = Vec::new();
        want.extend_from_slice(p0);
        want.extend_from_slice(p1);
        want.extend_from_slice(p2);
        assert_eq!(&buf[..n], &want[..], "GRO 多段应逐段各自 salt 解、压实拼接");
    }

    #[test]
    fn deobfs_drops_undersized_trailing_segment() {
        // 一整段 + 末尾 <SALT_LEN 的残段 (非法) → 残段丢弃, 只出第一段。
        let k = key("pw");
        let payload = b"first-full-segment!!";
        let seg = obf_seg(&k, [7u8; SALT_LEN], payload);
        let stride = seg.len();
        let mut buf = seg.clone();
        buf.extend_from_slice(&[0xFF; 5]); // 5 < SALT_LEN(8) 残段
        let len = buf.len();
        let n = deobfs_datagram(&k, &mut buf, len, stride);
        assert_eq!(&buf[..n], payload, "残段应被丢弃, 只还原完整段");
    }

    #[test]
    fn deobfs_wrong_key_corrupts() {
        let payload = b"secret quic bytes";
        let seg = obf_seg(&key("right-pw"), [5u8; SALT_LEN], payload);
        let mut buf = seg.clone();
        let n = deobfs_datagram(&key("wrong-pw"), &mut buf, seg.len(), seg.len());
        assert_ne!(&buf[..n], payload, "错 key 解出必为腐化数据 (QUIC 层随后丢弃)");
    }
}
