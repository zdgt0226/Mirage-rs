//! UDP 多路复用 (session-id over shared Mirage tunnel)。
//!
//! 帧格式 (双向, 紧接 [0x01] mux sentinel 之后):
//!   [2B frameLen][4B sid][1B ATYP][ADDR][2B port][payload]
//! frameLen = 2B 长度字段之后的字节数 = 4 + 1 + addrlen + 2 + payloadlen。
//! ATYP: 1=IPv4, 3=Domain, 4=IPv6 (与 legacy udp_relay 帧一致, 仅在 frameLen 后插 4B sid)。
//! sid: u32, 客户端在一条共享隧道内唯一分配。上行=目标地址; 下行=回包源地址
//! (客户端忽略地址, 按 sid 分流)。

use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicUsize, Ordering};
use std::sync::{Arc, LazyLock, Mutex as StdMutex};
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tokio::time::{timeout, Duration};

use crate::proxy::pool::WarmPool;

/// mux 模式 sentinel: 客户端在共享隧道上首个 send_data 发此单字节。
/// 服务端 control 分派: len==1 && [0]==0x01 → mux relay。
pub const MUX_SENTINEL: u8 = 0x01;

// ── 全局门控 (启动时由 config.tuning 设定, 仿 tls_padding) ──────────────────
static UDP_MUX_ENABLED: AtomicBool = AtomicBool::new(false);
static UDP_MUX_TUNNELS: AtomicUsize = AtomicUsize::new(4);

pub fn set_udp_mux(enabled: bool, tunnels: usize) {
    UDP_MUX_ENABLED.store(enabled, Ordering::Relaxed);
    UDP_MUX_TUNNELS.store(tunnels.max(1), Ordering::Relaxed);
}
pub fn udp_mux_enabled() -> bool {
    UDP_MUX_ENABLED.load(Ordering::Relaxed)
}
fn udp_mux_tunnels() -> usize {
    UDP_MUX_TUNNELS.load(Ordering::Relaxed)
}

/// 帧体在 sid 之后、ATYP 之前的固定前缀: 4B sid。
/// body_len 上限 = u16::MAX; 超出封帧返回 None。
fn wrap_frame(sid: u32, atyp_and_addr: &[u8], port: u16, payload: &[u8]) -> Option<Vec<u8>> {
    let body_len = 4 + atyp_and_addr.len() + 2 + payload.len();
    if body_len > u16::MAX as usize {
        return None;
    }
    let mut f = Vec::with_capacity(2 + body_len);
    f.extend_from_slice(&(body_len as u16).to_be_bytes());
    f.extend_from_slice(&sid.to_be_bytes());
    f.extend_from_slice(atyp_and_addr);
    f.extend_from_slice(&port.to_be_bytes());
    f.extend_from_slice(payload);
    Some(f)
}

/// 封上行 mux 帧 (域名目标)。域名 >255 或超 u16 帧长返回 None (真实 UDP 极少 >60KB)。
/// 不截断: 截断会静默打到错误主机, 宁可 fail loud 让调用方处理。
pub fn frame_mux_domain(sid: u32, domain: &str, port: u16, payload: &[u8]) -> Option<Vec<u8>> {
    if domain.len() > 255 {
        return None;
    }
    let mut a = Vec::with_capacity(2 + domain.len());
    a.push(0x03);
    a.push(domain.len() as u8);
    a.extend_from_slice(domain.as_bytes());
    wrap_frame(sid, &a, port, payload)
}

/// 封上行 mux 帧 (裸 IPv4 目标)。
pub fn frame_mux_ipv4(sid: u32, ip: &Ipv4Addr, port: u16, payload: &[u8]) -> Option<Vec<u8>> {
    let mut a = Vec::with_capacity(5);
    a.push(0x01);
    a.extend_from_slice(&ip.octets());
    wrap_frame(sid, &a, port, payload)
}

/// 封下行 mux 帧 (服务端: 回包源地址, v4/v6 自适应 ATYP)。
pub fn frame_mux_addr(sid: u32, addr: SocketAddr, payload: &[u8]) -> Option<Vec<u8>> {
    let mut a = Vec::new();
    match addr.ip() {
        std::net::IpAddr::V4(ip) => {
            a.push(0x01);
            a.extend_from_slice(&ip.octets());
        }
        std::net::IpAddr::V6(ip) => {
            a.push(0x04);
            a.extend_from_slice(&ip.octets());
        }
    }
    wrap_frame(sid, &a, addr.port(), payload)
}

/// 从累积 buffer 解一帧 mux, 返回 (sid, payload, 消费字节数)。不完整返回 None。
/// 畸形内层 (帧太短放不下 sid / 坏 ATYP / 越界) 仍消费整帧以重同步, payload 空、
/// sid 尽力取 (放不下时 0)。
pub fn parse_mux_frame(buf: &[u8]) -> Option<(u32, Vec<u8>, usize)> {
    if buf.len() < 2 {
        return None;
    }
    let flen = u16::from_be_bytes([buf[0], buf[1]]) as usize;
    let total = 2 + flen;
    if buf.len() < total {
        return None; // 帧未收全
    }
    let frame = &buf[2..total];
    // 帧太短放不下 4B sid → 消费整帧重同步
    if frame.len() < 4 {
        return Some((0, Vec::new(), total));
    }
    let sid = u32::from_be_bytes([frame[0], frame[1], frame[2], frame[3]]);
    let empty = (sid, Vec::new(), total);
    let inner = &frame[4..]; // ATYP..
    if inner.is_empty() {
        return Some(empty);
    }
    let mut off = 1usize; // 跳 ATYP
    match inner[0] {
        1 => off += 4,
        4 => off += 16,
        3 => {
            if inner.len() < off + 1 {
                return Some(empty);
            }
            let dl = inner[off] as usize;
            off += 1 + dl;
        }
        _ => return Some(empty),
    }
    off += 2; // port
    if off > inner.len() {
        return Some(empty);
    }
    Some((sid, inner[off..].to_vec(), total))
}

/// 服务端上行解析: 与 [`parse_mux_frame`] 同帧, 但额外解出目标 (域名/IP 字面量) 与端口,
/// 供服务端 resolve + 转发。返回 (消费字节数, Some(帧) | None=畸形跳过)。外层 None=未收全。
/// target 为 ATYP 对应的字符串 (域名原样 / IP 的 to_string), 交 resolver::resolve_first 处理。
pub struct UplinkFrame {
    pub sid: u32,
    pub target: String,
    pub port: u16,
    pub payload: Vec<u8>,
}

pub fn parse_mux_uplink(buf: &[u8]) -> Option<(usize, Option<UplinkFrame>)> {
    if buf.len() < 2 {
        return None;
    }
    let flen = u16::from_be_bytes([buf[0], buf[1]]) as usize;
    let total = 2 + flen;
    if buf.len() < total {
        return None; // 未收全
    }
    let frame = &buf[2..total];
    if frame.len() < 4 {
        return Some((total, None)); // 放不下 sid, 跳
    }
    let sid = u32::from_be_bytes([frame[0], frame[1], frame[2], frame[3]]);
    let inner = &frame[4..];
    if inner.is_empty() {
        return Some((total, None));
    }
    let mut off = 1usize;
    let target = match inner[0] {
        1 => {
            if inner.len() < off + 4 {
                return Some((total, None));
            }
            let s = Ipv4Addr::new(inner[off], inner[off + 1], inner[off + 2], inner[off + 3])
                .to_string();
            off += 4;
            s
        }
        3 => {
            if inner.len() < off + 1 {
                return Some((total, None));
            }
            let dl = inner[off] as usize;
            off += 1;
            if inner.len() < off + dl {
                return Some((total, None));
            }
            let s = String::from_utf8_lossy(&inner[off..off + dl]).to_string();
            off += dl;
            s
        }
        4 => {
            if inner.len() < off + 16 {
                return Some((total, None));
            }
            let mut o = [0u8; 16];
            o.copy_from_slice(&inner[off..off + 16]);
            let s = std::net::Ipv6Addr::from(o).to_string();
            off += 16;
            s
        }
        _ => return Some((total, None)),
    };
    if inner.len() < off + 2 {
        return Some((total, None));
    }
    let port = u16::from_be_bytes([inner[off], inner[off + 1]]);
    off += 2;
    let payload = inner[off..].to_vec();
    Some((total, Some(UplinkFrame { sid, target, port, payload })))
}

// ── 客户端: K 条共享 mux 隧道 ────────────────────────────────────────────────

const MUX_IDLE_TIMEOUT: Duration = Duration::from_secs(60);
/// 共享 writer 泵一次 send_data 前榨干队列的合帧上限 (跨流合并, 抗长度指纹, 近零延迟)。
const MUX_UPLINK_COALESCE_CAP: usize = 16 * 1024;

type FlowKey = (SocketAddrV4, SocketAddrV4);

struct FlowEntry {
    reply: Arc<UdpSocket>,
    client: SocketAddrV4,
}

/// 客户端一条共享 mux 隧道。多条 UDP 流按 sid 复用: 上行经共享 writer 泵合帧发出,
/// 下行由单一 demux 泵按 sid 路由到各流的 reply socket。
pub struct MuxTunnel {
    uplink_tx: mpsc::Sender<Vec<u8>>, // 预封帧字节 → 共享 writer 泵
    flows: Arc<StdMutex<HashMap<u32, FlowEntry>>>,
    next_sid: AtomicU32,
    alive: Arc<AtomicBool>,
}

impl MuxTunnel {
    /// 从 pool 取一条隧道, 发 MUX_SENTINEL, spawn 共享 writer + demux 泵。
    async fn create(pool: &Arc<WarmPool>) -> anyhow::Result<Arc<MuxTunnel>> {
        let mut tunnel = pool.get().await?;
        tunnel.writer.send_data(&[MUX_SENTINEL]).await?;
        Ok(Self::from_tunnel(tunnel))
    }

    /// 用一条已就绪 (sentinel 已发) 的隧道 spawn 共享 writer + demux 泵。
    fn from_tunnel(tunnel: crate::proxy::tunnel::Tunnel) -> Arc<MuxTunnel> {
        let (uplink_tx, mut uplink_rx) = mpsc::channel::<Vec<u8>>(1024);
        let flows: Arc<StdMutex<HashMap<u32, FlowEntry>>> = Default::default();
        let alive = Arc::new(AtomicBool::new(true));

        // writer 泵: 唯一 AEAD 写点。合帧后 send_data。
        let mut writer = tunnel.writer;
        let alive_w = alive.clone();
        tokio::spawn(async move {
            while let Some(first) = uplink_rx.recv().await {
                let mut batch = first;
                while batch.len() < MUX_UPLINK_COALESCE_CAP {
                    match uplink_rx.try_recv() {
                        Ok(b) => batch.extend_from_slice(&b),
                        Err(_) => break,
                    }
                }
                if writer.send_data(&batch).await.is_err() {
                    break;
                }
            }
            alive_w.store(false, Ordering::Relaxed);
        });

        // demux 泵: read → parse_mux_frame → 按 sid 找 flow → reply.send_to。
        let mut reader = tunnel.reader;
        let flows_d = flows.clone();
        let alive_d = alive.clone();
        tokio::spawn(async move {
            let mut acc: Vec<u8> = Vec::new();
            loop {
                let chunk = match timeout(MUX_IDLE_TIMEOUT, reader.recv_data()).await {
                    Ok(Ok(c)) => c,
                    _ => break,
                };
                acc.extend_from_slice(&chunk);
                while let Some((sid, payload, consumed)) = parse_mux_frame(&acc) {
                    if !payload.is_empty() {
                        let entry = flows_d
                            .lock()
                            .unwrap_or_else(|e| e.into_inner())
                            .get(&sid)
                            .map(|e| (e.reply.clone(), e.client));
                        if let Some((reply, client)) = entry {
                            let _ = reply.send_to(&payload, SocketAddr::V4(client)).await;
                        }
                    }
                    acc.drain(0..consumed);
                }
                if acc.len() > 65536 * 2 {
                    break;
                }
            }
            alive_d.store(false, Ordering::Relaxed);
        });

        Arc::new(MuxTunnel {
            uplink_tx,
            flows,
            next_sid: AtomicU32::new(1),
            alive,
        })
    }

    fn is_alive(&self) -> bool {
        self.alive.load(Ordering::Relaxed)
    }
    pub fn alloc_sid(&self) -> u32 {
        self.next_sid.fetch_add(1, Ordering::Relaxed)
    }
    fn unregister(&self, sid: u32) {
        self.flows
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&sid);
    }
    /// 注册 sid → (reply, client) 并返回 RAII 守卫: 守卫 drop 时**保证**注销 (含 panic/
    /// early-return), 与 FlowGuard 的"保证清理"契约对齐, 防 sid 泄漏吊住 reply socket。
    pub fn register(self: &Arc<Self>, sid: u32, reply: Arc<UdpSocket>, client: SocketAddrV4) -> SidGuard {
        self.flows
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(sid, FlowEntry { reply, client });
        SidGuard { mtun: self.clone(), sid }
    }
    /// 共享上行发送端: per-flow 上行泵把封好 sid 的帧推进来, 由 writer 泵合帧发出。
    pub fn uplink(&self) -> mpsc::Sender<Vec<u8>> {
        self.uplink_tx.clone()
    }
}

/// sid 注册的 RAII 守卫: drop 即从 MuxTunnel.flows 注销该 sid。
pub struct SidGuard {
    mtun: Arc<MuxTunnel>,
    sid: u32,
}
impl Drop for SidGuard {
    fn drop(&mut self) {
        self.mtun.unregister(self.sid);
    }
}

/// K 条共享 mux 隧道。按 flowkey 散列选隧道 (HoL 分摊); 懒创建; 死则重建。
/// 持 pool 的 **Weak** 引用 —— 不吊住 pool 生命 (配置热重载丢弃旧 outbound → 旧 pool
/// 应能被 drop); pool 没了 (upgrade 失败) 说明这套 MuxSet 已作废, 由 REGISTRY 剪除。
pub struct MuxSet {
    pool: std::sync::Weak<WarmPool>,
    slots: Vec<tokio::sync::Mutex<Option<Arc<MuxTunnel>>>>,
}

impl MuxSet {
    fn new(pool: &Arc<WarmPool>, k: usize) -> Self {
        let k = k.max(1);
        MuxSet {
            pool: Arc::downgrade(pool),
            slots: (0..k).map(|_| tokio::sync::Mutex::new(None)).collect(),
        }
    }
    fn slot_for(&self, key: &FlowKey) -> usize {
        use std::hash::{Hash, Hasher};
        let mut h = std::collections::hash_map::DefaultHasher::new();
        key.hash(&mut h);
        (h.finish() as usize) % self.slots.len()
    }
    async fn get(&self, key: &FlowKey) -> anyhow::Result<Arc<MuxTunnel>> {
        let pool = self
            .pool
            .upgrade()
            .ok_or_else(|| anyhow::anyhow!("mux: 底层 pool 已释放 (配置重载?)"))?;
        let idx = self.slot_for(key);
        let mut slot = self.slots[idx].lock().await;
        if let Some(t) = slot.as_ref() {
            if t.is_alive() {
                return Ok(t.clone());
            }
        }
        let t = MuxTunnel::create(&pool).await?;
        *slot = Some(t.clone());
        Ok(t)
    }
}

/// pool 指针 → 该 pool 的 MuxSet (每 Mirage outbound 一套共享隧道)。
static REGISTRY: LazyLock<StdMutex<HashMap<usize, Arc<MuxSet>>>> =
    LazyLock::new(|| StdMutex::new(HashMap::new()));

/// 取 (或懒建/重建) 给定 pool + flowkey 对应的共享 mux 隧道。
pub async fn get_mux_tunnel(
    pool: &Arc<WarmPool>,
    key: &FlowKey,
) -> anyhow::Result<Arc<MuxTunnel>> {
    let ptr = Arc::as_ptr(pool) as usize;
    let set = {
        let mut reg = REGISTRY.lock().unwrap_or_else(|e| e.into_inner());
        // 剪除 pool 已释放的死条目 (配置热重载会换新 pool Arc → 旧条目作废)。**先剪再插**:
        // 顺带堵住旧 pool 释放后新 pool 复用同地址 (ptr) 撞进旧 MuxSet 的隐患。
        reg.retain(|_, set| set.pool.strong_count() > 0);
        reg.entry(ptr)
            .or_insert_with(|| Arc::new(MuxSet::new(pool, udp_mux_tunnels())))
            .clone()
    };
    set.get(key).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv6Addr, SocketAddrV6};

    #[test]
    fn parse_mux_uplink_domain() {
        let f = frame_mux_domain(5, "ex.com", 443, b"hi").unwrap();
        let (consumed, uf) = parse_mux_uplink(&f).unwrap();
        let uf = uf.unwrap();
        assert_eq!(consumed, f.len());
        assert_eq!(uf.sid, 5);
        assert_eq!(uf.target, "ex.com");
        assert_eq!(uf.port, 443);
        assert_eq!(uf.payload, b"hi");
    }

    #[test]
    fn parse_mux_uplink_ipv4() {
        let f = frame_mux_ipv4(9, &"8.8.8.8".parse().unwrap(), 53, b"dns").unwrap();
        let (_, uf) = parse_mux_uplink(&f).unwrap();
        let uf = uf.unwrap();
        assert_eq!(uf.sid, 9);
        assert_eq!(uf.target, "8.8.8.8");
        assert_eq!(uf.port, 53);
        assert_eq!(uf.payload, b"dns");
    }

    #[test]
    fn parse_mux_uplink_malformed_skips() {
        // 坏 ATYP → Some((consumed, None))
        let buf = [0x00, 0x05, 0x01, 0x02, 0x03, 0x04, 0x09];
        let (consumed, uf) = parse_mux_uplink(&buf).unwrap();
        assert_eq!(consumed, 7);
        assert!(uf.is_none());
    }

    #[test]
    fn parse_mux_uplink_incomplete_none() {
        let f = frame_mux_ipv4(1, &"1.1.1.1".parse().unwrap(), 53, b"xx").unwrap();
        assert!(parse_mux_uplink(&f[..f.len() - 1]).is_none());
    }

    /// 客户端全链路: MuxTunnel (from_tunnel) 上行 → 服务端 mux relay → 下行 demux
    /// 按 sid 路由到正确 reply socket。验证客户端 uplink 泵 + demux 泵 + 服务端 relay 打通。
    #[tokio::test]
    async fn client_roundtrip_demux_by_sid() {
        use tokio::net::{TcpListener, TcpStream, UdpSocket};

        // UDP echo
        let echo = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let echo_addr = echo.local_addr().unwrap();
        let echo_ip = match echo_addr.ip() {
            std::net::IpAddr::V4(v) => v,
            _ => unreachable!(),
        };
        tokio::spawn(async move {
            let mut b = [0u8; 2048];
            loop {
                if let Ok((n, from)) = echo.recv_from(&mut b).await {
                    let _ = echo.send_to(&b[..n], from).await;
                }
            }
        });

        // TCP loopback 对
        let lis = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = lis.local_addr().unwrap();
        let cli = TcpStream::connect(addr).await.unwrap();
        let (srv, _) = lis.accept().await.unwrap();

        // 服务端: OwnedReadHalf/WriteHalf crypto (非 initiator) → handle_udp_mux_relay
        let (sr, sw) = {
            let (r, w) = srv.into_split();
            crate::crypto::aead::create_crypto_pair(r, w, "pw", b"salt1234", false)
        };
        let server = tokio::spawn(async move {
            crate::proxy::mirage_server::udp_relay::handle_udp_mux_relay(sr, sw, None).await;
        });

        // 客户端: Boxed crypto (initiator) 组 Tunnel → from_tunnel (不发 sentinel, 对端直接 relay)
        let (cr, cw) = {
            let (r, w) = cli.into_split();
            crate::crypto::aead::create_crypto_pair(
                crate::proxy::tunnel::TunnelRead::Boxed(Box::new(r)),
                crate::proxy::tunnel::TunnelWrite::Boxed(Box::new(w)),
                "pw",
                b"salt1234",
                true,
            )
        };
        let tunnel = crate::proxy::tunnel::Tunnel::new(cr, cw);
        let mtun = MuxTunnel::from_tunnel(tunnel);

        // 注册 sid=1: 回包出口 reply → 打到 catcher, client=catcher 地址
        let catcher = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let catcher_v4 = match catcher.local_addr().unwrap() {
            SocketAddr::V4(a) => a,
            _ => unreachable!(),
        };
        let reply = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let _sid_guard = mtun.register(1, reply, catcher_v4);

        // 上行: 经共享 uplink 泵发 sid=1 帧到 echo
        mtun.uplink()
            .send(frame_mux_ipv4(1, &echo_ip, echo_addr.port(), b"PING").unwrap())
            .await
            .unwrap();

        // catcher 应收到 demux 回来的 PING
        let mut b = [0u8; 64];
        let n = tokio::time::timeout(std::time::Duration::from_secs(5), catcher.recv(&mut b))
            .await
            .expect("demux 回包超时")
            .unwrap();
        assert_eq!(&b[..n], b"PING");
        server.abort();
    }

    #[test]
    fn frame_mux_domain_over_255_returns_none() {
        // 域名 >255 不截断 (静默打错主机), 而是 None 让调用方 fail loud。
        let long = "a".repeat(256);
        assert!(frame_mux_domain(1, &long, 443, b"x").is_none());
        // 恰好 255 仍成功
        let ok = "b".repeat(255);
        assert!(frame_mux_domain(1, &ok, 443, b"x").is_some());
    }

    #[test]
    fn frame_mux_domain_roundtrip() {
        let f = frame_mux_domain(0xDEADBEEF, "ex.com", 443, b"hello").unwrap();
        // [2B len][4B sid][ATYP=3][1B dlen][domain][2B port][payload]
        let body_len = 4 + 1 + 1 + 6 + 2 + 5;
        assert_eq!(u16::from_be_bytes([f[0], f[1]]) as usize, body_len);
        assert_eq!(f.len(), 2 + body_len);
        let (sid, payload, consumed) = parse_mux_frame(&f).unwrap();
        assert_eq!(sid, 0xDEADBEEF);
        assert_eq!(payload, b"hello");
        assert_eq!(consumed, f.len());
    }

    #[test]
    fn frame_mux_ipv4_roundtrip() {
        let ip: Ipv4Addr = "8.8.8.8".parse().unwrap();
        let f = frame_mux_ipv4(7, &ip, 53, b"dns").unwrap();
        let body_len = 4 + 1 + 4 + 2 + 3;
        assert_eq!(u16::from_be_bytes([f[0], f[1]]) as usize, body_len);
        assert_eq!(f[6], 0x01); // ATYP=1 after 2B len + 4B sid
        let (sid, payload, consumed) = parse_mux_frame(&f).unwrap();
        assert_eq!(sid, 7);
        assert_eq!(payload, b"dns");
        assert_eq!(consumed, f.len());
    }

    #[test]
    fn frame_mux_addr_v4_roundtrip() {
        let addr = SocketAddr::V4(SocketAddrV4::new("1.2.3.4".parse().unwrap(), 9999));
        let f = frame_mux_addr(42, addr, b"reply").unwrap();
        assert_eq!(f[6], 0x01); // ATYP=1
        let (sid, payload, consumed) = parse_mux_frame(&f).unwrap();
        assert_eq!(sid, 42);
        assert_eq!(payload, b"reply");
        assert_eq!(consumed, f.len());
    }

    #[test]
    fn frame_mux_addr_v6_roundtrip() {
        let v6: Ipv6Addr = "2001:db8::1".parse().unwrap();
        let addr = SocketAddr::V6(SocketAddrV6::new(v6, 443, 0, 0));
        let f = frame_mux_addr(99, addr, b"quic").unwrap();
        assert_eq!(f[6], 0x04); // ATYP=4
        let (sid, payload, consumed) = parse_mux_frame(&f).unwrap();
        assert_eq!(sid, 99);
        assert_eq!(payload, b"quic");
        assert_eq!(consumed, f.len());
    }

    #[test]
    fn multi_frame_coalesced_demux() {
        let mut buf = Vec::new();
        buf.extend_from_slice(&frame_mux_ipv4(1, &"1.1.1.1".parse().unwrap(), 53, b"a").unwrap());
        buf.extend_from_slice(&frame_mux_domain(2, "b.io", 80, b"bb").unwrap());
        buf.extend_from_slice(&frame_mux_ipv4(3, &"2.2.2.2".parse().unwrap(), 443, b"ccc").unwrap());
        let mut acc = &buf[..];
        let mut got = Vec::new();
        while let Some((sid, payload, consumed)) = parse_mux_frame(acc) {
            got.push((sid, payload));
            acc = &acc[consumed..];
        }
        assert_eq!(got, vec![
            (1u32, b"a".to_vec()),
            (2u32, b"bb".to_vec()),
            (3u32, b"ccc".to_vec()),
        ]);
    }

    #[test]
    fn incomplete_frame_returns_none() {
        let f = frame_mux_ipv4(1, &"1.1.1.1".parse().unwrap(), 53, b"payload").unwrap();
        // 只喂前半截 → None, 不消费
        assert!(parse_mux_frame(&f[..f.len() - 2]).is_none());
        assert!(parse_mux_frame(&[0x00]).is_none()); // 不足 2B 长度
    }

    #[test]
    fn malformed_inner_consumes_frame_empty_payload() {
        // frameLen=5, sid=0x01020304, 然后 ATYP=0x09 (非法) → 消费整帧, payload 空, sid 取出
        let buf = [0x00, 0x05, 0x01, 0x02, 0x03, 0x04, 0x09];
        let (sid, payload, consumed) = parse_mux_frame(&buf).unwrap();
        assert_eq!(sid, 0x01020304);
        assert!(payload.is_empty());
        assert_eq!(consumed, 7);
    }

    #[test]
    fn frame_too_short_for_sid_consumes_empty() {
        // frameLen=2 (放不下 4B sid) → 消费整帧, sid=0, payload 空
        let buf = [0x00, 0x02, 0xAA, 0xBB];
        let (sid, payload, consumed) = parse_mux_frame(&buf).unwrap();
        assert_eq!(sid, 0);
        assert!(payload.is_empty());
        assert_eq!(consumed, 4);
    }

    #[test]
    fn frame_len_three_no_panic() {
        // frameLen=3 (仍放不下 4B sid) —— 边界: 守卫必须挡在读 frame[0..4] 之前, 否则越界 panic。
        let buf = [0x00, 0x03, 0xAA, 0xBB, 0xCC];
        let (sid, payload, consumed) = parse_mux_frame(&buf).unwrap();
        assert_eq!(sid, 0);
        assert!(payload.is_empty());
        assert_eq!(consumed, 5);
    }
}
