//! eBPF 透明 UDP 代理 (sk_lookup + IP_TRANSPARENT)
//!
//! 与 TCP 透明并行. sk_lookup 按 protocol 把命中 fake-IP 的 UDP 数据报 assign
//! 到本模块注册的主 socket. UDP 无 accept, 因此:
//!   - 主 socket 设 IP_TRANSPARENT + IP_RECVORIGDSTADDR, recvmsg 逐包取
//!     (client_src, orig_dst=fake-IP:port)
//!   - 回包必须从 fake-IP:port 伪造源发回: 每个 orig_dst 建一个 IP_TRANSPARENT
//!     + IP_FREEBIND 绑定到该地址的 reply socket (源 IP+端口都对)
//!   - 出口用普通 egress socket 跟真目标收发
//!
//! v1: Direct/Block 完整; Mirage 路由的 UDP 记日志丢弃 (客户端 QUIC 回落到已
//! 透明的 TCP); 仅 IPv4. 需部署验证 (CAP_NET_ADMIN + 内核 ≥5.9).

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4};
use std::os::fd::OwnedFd;
use std::os::unix::io::{AsRawFd, FromRawFd, IntoRawFd, RawFd};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::Duration;

use arc_swap::ArcSwap;
use nix::sys::socket::{
    bind, recvmsg, setsockopt, socket, sockopt, AddressFamily, ControlMessageOwned, MsgFlags,
    SockFlag, SockType, SockaddrIn,
};
use tokio::io::Interest;
use tokio::net::UdpSocket;
use tokio::sync::Mutex;
use tracing::{debug, error, info, warn};

use crate::config_watcher::CoreState;
use crate::dns::fake_ip::FakeIpMapper;
use crate::ebpf::TransparentEngine;
use crate::proxy::outbound::OutboundNode;
use crate::router::RoutingRequest;

const IDLE_TIMEOUT: Duration = Duration::from_secs(60);
const UDP_BUF: usize = 65536;
/// 并发透明 UDP 流上限。每流 ≈ 1 出口 socket FD + 1 task + 64KB downlink buf
/// (+ 共享 reply socket)。透明 UDP 仅跑在 64 位网关 (内核≥5.9+CAP_NET_ADMIN),
/// 内存充裕; 家用/小企业合法峰值数百~低千, 4096 留足余量, 同时给恶意 LAN
/// 客户端狂建流封一个天花板 (最坏 ~256MB downlink buf + ~4-8K FD)。
const MAX_FLOWS: usize = 4096;

/// 到顶丢包累计计数, 用于限流打印 (每 1000 次告警一次, 免刷屏)。
static CAP_DROPS: AtomicU64 = AtomicU64::new(0);

type FlowKey = (SocketAddrV4, SocketAddrV4); // (client, orig_dst)

/// 递增 flow id, 供 teardown 守卫辨认"是不是自己那条"(两种 sink 通用, 取代
/// 仅对 UDP socket 有效的 Arc::ptr_eq)。
static NEXT_FLOW_ID: AtomicU64 = AtomicU64::new(1);

/// 流的上行出口. Direct = 直发 UDP socket; Mirage = 送进 per-flow 隧道任务的
/// channel (任务负责封帧 + 走加密隧道)。
#[derive(Clone)]
enum FlowSink {
    Direct(Arc<UdpSocket>),
    Mirage(tokio::sync::mpsc::Sender<Vec<u8>>),
}

/// 会话槽. Setting = setup_flow 正在建流 (占位, 防突发包重复 spawn);
/// Ready = 出口就绪, 主循环快路径按 sink 分发。id 供守卫辨认。
enum FlowSlot {
    Setting,
    Ready { id: u64, sink: FlowSink },
}

/// 回包 socket + 引用计数 (同 orig_dst 的多客户端 flow 共享一个)。refs 归 0
/// 即从表移除 → drop → 关 FD, 防句柄泄漏。
struct ReplyEntry {
    sock: Arc<UdpSocket>,
    refs: usize,
}

type Sessions = Arc<StdMutex<HashMap<FlowKey, FlowSlot>>>;
type Replies = Arc<StdMutex<HashMap<SocketAddrV4, ReplyEntry>>>;

fn lock_sessions(s: &Sessions) -> std::sync::MutexGuard<'_, HashMap<FlowKey, FlowSlot>> {
    s.lock().unwrap_or_else(|e| e.into_inner())
}
fn lock_replies(r: &Replies) -> std::sync::MutexGuard<'_, HashMap<SocketAddrV4, ReplyEntry>> {
    r.lock().unwrap_or_else(|e| e.into_inner())
}

/// flow 生命周期的 RAII 清理, **保证执行**(含 panic 展开 / 任何 early-return):
///   - committed_id=None (未 commit): 移除主循环占位的 Setting 槽, 否则该 key
///     永久卡 Setting → 后续包被当"建流中"丢弃 → 目标黑洞。
///   - committed_id=Some(id) (已 commit): 若槽仍是本流 (id 匹配) 则移除 (防误删
///     被替换的会话) + reply refs-- 归 0 移除关 FD。
/// 关键: 清理内联在收发循环后会被 panic/未来 early-return 跳过 → 泄漏, 故收进
/// Drop 强制保证 (同 reply-socket FD 泄漏那次的教训)。
struct FlowGuard {
    key: FlowKey,
    orig_dst: SocketAddrV4,
    sessions: Sessions,
    replies: Replies,
    committed_id: Option<u64>,
}
impl Drop for FlowGuard {
    fn drop(&mut self) {
        match self.committed_id {
            None => {
                let mut s = lock_sessions(&self.sessions);
                if matches!(s.get(&self.key), Some(FlowSlot::Setting)) {
                    s.remove(&self.key);
                }
            }
            Some(id) => {
                {
                    let mut s = lock_sessions(&self.sessions);
                    if matches!(s.get(&self.key), Some(FlowSlot::Ready { id: cur, .. }) if *cur == id)
                    {
                        s.remove(&self.key);
                    }
                }
                let mut r = lock_replies(&self.replies);
                if let Some(e) = r.get_mut(&self.orig_dst) {
                    e.refs = e.refs.saturating_sub(1);
                    if e.refs == 0 {
                        r.remove(&self.orig_dst);
                    }
                }
            }
        }
    }
}

fn new_dgram_fd() -> anyhow::Result<OwnedFd> {
    Ok(socket(
        AddressFamily::Inet,
        SockType::Datagram,
        SockFlag::SOCK_NONBLOCK,
        None,
    )?)
}

/// 主收包 socket: 透明 + 记录原始目的地.
fn build_main_socket(bind_addr: SocketAddrV4) -> anyhow::Result<UdpSocket> {
    let fd = new_dgram_fd()?;
    setsockopt(&fd, sockopt::ReuseAddr, &true)?;
    setsockopt(&fd, sockopt::IpTransparent, &true)?;
    setsockopt(&fd, sockopt::Ipv4OrigDstAddr, &true)?; // IP_RECVORIGDSTADDR
    bind(fd.as_raw_fd(), &SockaddrIn::from(bind_addr))?;
    let std_sock = unsafe { std::net::UdpSocket::from_raw_fd(fd.into_raw_fd()) };
    std_sock.set_nonblocking(true)?;
    Ok(UdpSocket::from_std(std_sock)?)
}

/// 回包 socket: 绑定到 fake-IP:port (非本地地址, 需 FREEBIND), 透明发源.
fn build_reply_socket(orig_dst: SocketAddrV4) -> anyhow::Result<UdpSocket> {
    let fd = new_dgram_fd()?;
    setsockopt(&fd, sockopt::ReuseAddr, &true)?;
    setsockopt(&fd, sockopt::IpTransparent, &true)?;
    setsockopt(&fd, sockopt::IpFreebind, &true)?;
    bind(fd.as_raw_fd(), &SockaddrIn::from(orig_dst))?;
    let std_sock = unsafe { std::net::UdpSocket::from_raw_fd(fd.into_raw_fd()) };
    std_sock.set_nonblocking(true)?;
    Ok(UdpSocket::from_std(std_sock)?)
}

/// recvmsg 一次, 取 (字节数, 客户端源, 原始目的 fake-IP:port).
fn recv_with_origdst(fd: RawFd, buf: &mut [u8]) -> nix::Result<(usize, SocketAddrV4, SocketAddrV4)> {
    let mut iov = [std::io::IoSliceMut::new(buf)];
    let mut cmsg = nix::cmsg_space!(libc::sockaddr_in);
    let msg = recvmsg::<SockaddrIn>(fd, &mut iov, Some(&mut cmsg), MsgFlags::empty())?;

    let client = msg.address.ok_or(nix::errno::Errno::EINVAL)?;
    let client = SocketAddrV4::new(Ipv4Addr::from(client.ip()), client.port());

    let mut orig = None;
    for c in msg.cmsgs()? {
        if let ControlMessageOwned::Ipv4OrigDstAddr(sa) = c {
            let ip = Ipv4Addr::from(u32::from_be(sa.sin_addr.s_addr));
            let port = u16::from_be(sa.sin_port);
            orig = Some(SocketAddrV4::new(ip, port));
        }
    }
    Ok((msg.bytes, client, orig.ok_or(nix::errno::Errno::ENOMSG)?))
}

fn nix_to_io(e: nix::errno::Errno) -> std::io::Error {
    std::io::Error::from_raw_os_error(e as i32)
}

/// 取/建 orig_dst 的回包 socket 并 refs++。**调用方须紧接 commit**(中间无早退),
/// 以保证与 FlowGuard teardown 的 refs-- 配平。None = build 失败。
fn acquire_reply(replies: &Replies, orig_dst: SocketAddrV4) -> Option<Arc<UdpSocket>> {
    let mut r = lock_replies(replies);
    if let Some(e) = r.get_mut(&orig_dst) {
        e.refs += 1;
        Some(e.sock.clone())
    } else {
        match build_reply_socket(orig_dst) {
            Ok(rs) => {
                let rs = Arc::new(rs);
                r.insert(orig_dst, ReplyEntry { sock: rs.clone(), refs: 1 });
                Some(rs)
            }
            Err(e) => {
                error!("udp-t: reply socket for {} failed: {}", orig_dst, e);
                None
            }
        }
    }
}

/// 封 Mirage UDP 隧道帧: [2B bodyLen][ATYP=3][1B dlen][domain][2B port][payload]。
/// 与服务端 mirage_server::udp_relay 的解码格式一致。调用方须保证 domain≤255、
/// 4+dlen+payload ≤ u16::MAX。
fn frame_udp_domain(domain: &str, port: u16, payload: &[u8]) -> Vec<u8> {
    let dlen = domain.len().min(255);
    let body_len = 1 + 1 + dlen + 2 + payload.len();
    let mut f = Vec::with_capacity(2 + body_len);
    f.extend_from_slice(&(body_len as u16).to_be_bytes());
    f.push(0x03);
    f.push(dlen as u8);
    f.extend_from_slice(&domain.as_bytes()[..dlen]);
    f.extend_from_slice(&port.to_be_bytes());
    f.extend_from_slice(payload);
    f
}

/// 从累积 buffer 解一帧回程 [2B len][ATYP][ADDR][2B port][payload], 返回
/// (payload, 消费字节数=2+len)。不完整返回 None。源地址被忽略 —— 透明回包一律从
/// orig_dst 发回客户端。畸形内层(坏 ATYP/越界)仍消费整帧以重同步, payload 空。
fn parse_udp_frame_payload(buf: &[u8]) -> Option<(Vec<u8>, usize)> {
    if buf.len() < 2 {
        return None;
    }
    let flen = u16::from_be_bytes([buf[0], buf[1]]) as usize;
    let total = 2 + flen;
    if buf.len() < total {
        return None; // 帧未收全
    }
    let frame = &buf[2..total];
    let empty = (Vec::new(), total);
    if frame.is_empty() {
        return Some(empty);
    }
    let mut off = 1usize;
    match frame[0] {
        1 => off += 4,
        4 => off += 16,
        3 => {
            if frame.len() < off + 1 {
                return Some(empty);
            }
            let dl = frame[off] as usize;
            off += 1 + dl;
        }
        _ => return Some(empty),
    }
    off += 2; // port
    if off > frame.len() {
        return Some(empty);
    }
    Some((frame[off..].to_vec(), total))
}

pub async fn start_transparent_udp(
    listen_addr: SocketAddrV4,
    state: Arc<ArcSwap<CoreState>>,
    fake_ip_mapper: Arc<FakeIpMapper>,
    transparent_engine: Arc<Mutex<TransparentEngine>>,
) -> anyhow::Result<()> {
    let main = Arc::new(build_main_socket(listen_addr)?);
    transparent_engine
        .lock()
        .await
        .register_udp_listener(&main)?;
    info!(
        "Transparent UDP proxy on {} (sk_lookup UDP map registered)",
        listen_addr
    );

    // (client, orig_dst) → 会话槽; orig_dst → 回包 socket (引用计数)
    let sessions: Sessions = Arc::new(StdMutex::new(HashMap::new()));
    let replies: Replies = Arc::new(StdMutex::new(HashMap::new()));

    let fd = main.as_raw_fd();
    let mut buf = vec![0u8; UDP_BUF];
    loop {
        let recv = main
            .async_io(Interest::READABLE, || {
                recv_with_origdst(fd, &mut buf).map_err(nix_to_io)
            })
            .await;
        let (size, client, orig_dst) = match recv {
            Ok(v) => v,
            Err(e) => {
                error!("udp-t recv error: {}", e);
                continue;
            }
        };

        // 单锁内决策 (原子): Ready→取出 socket; Setting→建流中丢包; None→占位并建流。
        // 关键: 只在锁内取 Arc, 出锁再 await send —— 不把锁跨越 .await (原实现把
        // sessions 锁持有到 send().await 期间, 阻塞其他锁者)。
        let key = (client, orig_dst);
        let mut do_setup = false;
        let mut at_cap = false;
        let forward = {
            let mut s = lock_sessions(&sessions);
            match s.get(&key) {
                Some(FlowSlot::Ready { sink, .. }) => Some(sink.clone()),
                Some(FlowSlot::Setting) => None, // 建流中, 丢本包 (UDP 可丢, 应用会重传)
                None if s.len() >= MAX_FLOWS => {
                    // 并发流到顶: 丢新流的包, 防恶意 LAN 客户端狂建流耗尽 FD/内存。
                    at_cap = true;
                    None
                }
                None => {
                    s.insert(key, FlowSlot::Setting);
                    do_setup = true;
                    None
                }
            }
        };

        if at_cap {
            // 出锁后再记 (不在锁内 format/写日志)。限流打印, 免刷屏。
            let n = CAP_DROPS.fetch_add(1, Ordering::Relaxed);
            if n % 1000 == 0 {
                warn!(
                    "udp-t: 并发流到上限 {} , 丢弃新流 (累计丢 {})",
                    MAX_FLOWS,
                    n + 1
                );
            }
            continue;
        }

        if let Some(sink) = forward {
            match sink {
                FlowSink::Direct(out) => {
                    let _ = out.send(&buf[..size]).await;
                }
                // 非阻塞: channel 满即丢本包 (UDP 可丢), 不阻塞收包循环。
                FlowSink::Mirage(tx) => {
                    let _ = tx.try_send(buf[..size].to_vec());
                }
            }
        } else if do_setup {
            let payload = buf[..size].to_vec();
            let st = state.clone();
            let fm = fake_ip_mapper.clone();
            let sessions = sessions.clone();
            let replies = replies.clone();
            tokio::spawn(async move {
                setup_flow(client, orig_dst, payload, st, fm, sessions, replies).await;
            });
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn setup_flow(
    client: SocketAddrV4,
    orig_dst: SocketAddrV4,
    first_payload: Vec<u8>,
    state: Arc<ArcSwap<CoreState>>,
    fake_ip_mapper: Arc<FakeIpMapper>,
    sessions: Sessions,
    replies: Replies,
) {
    let key = (client, orig_dst);
    // RAII 清理: 早退清占位, commit 后清完整会话。始终保证执行 (含 panic)。
    let mut guard = FlowGuard {
        key,
        orig_dst,
        sessions: sessions.clone(),
        replies: replies.clone(),
        committed_id: None,
    };
    let fake_ip = *orig_dst.ip();
    let port = orig_dst.port();
    let domain = fake_ip_mapper.lookup_domain(&fake_ip);

    // 路由决策
    let snapshot = state.load();
    let mut req = RoutingRequest {
        domain: None,
        ip: None,
        port,
        protocol: "udp",
        source_ip: Some(IpAddr::V4(*client.ip())),
        source_mac: None,
    };
    match &domain {
        Some(d) => req.domain = Some(d.as_str()),
        None => req.ip = Some(IpAddr::V4(fake_ip)),
    }
    let tag = snapshot.router.route(req);
    let outbound = match snapshot.outbounds.get(&tag) {
        Some(o) => o.clone(),
        None => {
            warn!("udp-t: outbound [{}] not found, dropping", tag);
            return;
        }
    };
    // leaf 是独立 Arc (不借 snapshot)。提取路由类型, Mirage 需要 pool。
    let leaf = outbound.resolve_leaf();
    enum Route {
        Direct,
        Mirage(Arc<crate::proxy::pool::WarmPool>),
    }
    let route = match &*leaf {
        OutboundNode::Direct { .. } => Route::Direct,
        OutboundNode::Block { .. } => {
            debug!("udp-t: blocked {:?}", domain);
            return;
        }
        OutboundNode::Mirage { pool, .. } => Route::Mirage(pool.clone()),
        other => {
            warn!("udp-t: unsupported outbound leaf {:?}, dropping", other.tag());
            return;
        }
    };
    drop(snapshot);

    let flow_id = NEXT_FLOW_ID.fetch_add(1, Ordering::Relaxed);

    match route {
        // ── Direct 腿: 本地解析 + 直发 UDP socket ──
        Route::Direct => {
            let real: SocketAddr = match &domain {
                Some(d) => match crate::proxy::resolver::resolve_first(d, port).await {
                    Ok(sa) => sa,
                    Err(_) => {
                        debug!("udp-t: resolve {} failed", d);
                        return;
                    }
                },
                None => {
                    warn!("udp-t: no domain for fake-ip {}, dropping", fake_ip);
                    return;
                }
            };
            if real.is_ipv6() {
                warn!("udp-t: IPv6 target {} unsupported in v1, dropping", real);
                return;
            }
            let out = match UdpSocket::bind("0.0.0.0:0").await {
                Ok(s) => Arc::new(s),
                Err(e) => {
                    error!("udp-t: bind outbound failed: {}", e);
                    return;
                }
            };
            if out.connect(real).await.is_err() {
                return;
            }
            // reply refs++ 紧接 commit (中间无早退, 保证与 teardown 的 refs-- 配平)。
            let reply = match acquire_reply(&replies, orig_dst) {
                Some(r) => r,
                None => return,
            };
            lock_sessions(&sessions).insert(
                key,
                FlowSlot::Ready { id: flow_id, sink: FlowSink::Direct(out.clone()) },
            );
            guard.committed_id = Some(flow_id);
            debug!("udp-t: new Direct flow {} → {} (real {})", client, domain.as_deref().unwrap_or("?"), real);

            let _ = out.send(&first_payload).await;
            let mut dbuf = vec![0u8; UDP_BUF];
            loop {
                match tokio::time::timeout(IDLE_TIMEOUT, out.recv(&mut dbuf)).await {
                    Ok(Ok(n)) => {
                        let _ = reply.send_to(&dbuf[..n], SocketAddr::V4(client)).await;
                    }
                    _ => break,
                }
            }
        }

        // ── Mirage 腿: 走加密隧道, 目标发**域名**让服务端远程解析 ──
        Route::Mirage(pool) => {
            let domain = match &domain {
                Some(d) if d.len() <= 255 => d.clone(),
                _ => {
                    warn!("udp-t: Mirage flow needs domain (fake-ip {}), dropping", fake_ip);
                    return;
                }
            };
            let mut tunnel = match pool.get().await {
                Ok(t) => t,
                Err(e) => {
                    error!("udp-t: Mirage pool unavailable: {}", e);
                    return;
                }
            };
            // UDP 模式 sentinel
            if tunnel.writer.send_data(&[0x00]).await.is_err() {
                return;
            }
            let reply = match acquire_reply(&replies, orig_dst) {
                Some(r) => r,
                None => return,
            };
            let (tx, mut rx) = tokio::sync::mpsc::channel::<Vec<u8>>(256);
            lock_sessions(&sessions).insert(
                key,
                FlowSlot::Ready { id: flow_id, sink: FlowSink::Mirage(tx.clone()) },
            );
            guard.committed_id = Some(flow_id);
            debug!("udp-t: new Mirage flow {} → {} (via tunnel)", client, domain);

            // 首包入 channel, 由 uplink 统一封帧
            let _ = tx.try_send(first_payload);

            let mut writer = tunnel.writer;
            let mut reader = tunnel.reader;
            let domain_up = domain.clone();

            // uplink: channel → 封帧 [len][ATYP=3][domain][port][payload] → 隧道
            let uplink = async move {
                loop {
                    let pkt = match tokio::time::timeout(IDLE_TIMEOUT, rx.recv()).await {
                        Ok(Some(p)) => p,
                        _ => break, // idle / channel 关
                    };
                    // 超大包无法用 u16 帧长表示, 丢 (真实 UDP 极少 >60KB)
                    if 4 + domain_up.len() + pkt.len() > u16::MAX as usize {
                        continue;
                    }
                    let frame = frame_udp_domain(&domain_up, port, &pkt);
                    if writer.send_data(&frame).await.is_err() {
                        break;
                    }
                }
            };

            // downlink: 隧道 → 解帧取 payload → reply_socket 发回客户端 (伪源 orig_dst)
            let downlink = async move {
                let mut acc: Vec<u8> = Vec::new();
                loop {
                    let chunk = match tokio::time::timeout(IDLE_TIMEOUT, reader.recv_data()).await {
                        Ok(Ok(c)) => c,
                        _ => break,
                    };
                    acc.extend_from_slice(&chunk);
                    while let Some((payload, consumed)) = parse_udp_frame_payload(&acc) {
                        if !payload.is_empty() {
                            let _ = reply.send_to(&payload, SocketAddr::V4(client)).await;
                        }
                        acc.drain(0..consumed);
                    }
                    if acc.len() > UDP_BUF * 2 {
                        break; // 防异常累积
                    }
                }
            };

            tokio::select! {
                _ = uplink => {},
                _ = downlink => {},
            }
        }
    }

    // teardown (session 移除 + reply refs--) 由 FlowGuard::drop 保证执行。
    debug!("udp-t: flow {:?} closed", key);
}

#[cfg(test)]
mod tests {
    use super::{frame_udp_domain, parse_udp_frame_payload};

    #[test]
    fn frame_domain_bytes() {
        // ATYP=3 "ab.com":443 payload "hi"; body=1+1+6+2+2=12
        let f = frame_udp_domain("ab.com", 443, b"hi");
        assert_eq!(&f[0..2], &[0x00, 0x0C]); // bodyLen=12
        assert_eq!(f[2], 0x03); // ATYP domain
        assert_eq!(f[3], 6); // dlen
        assert_eq!(&f[4..10], b"ab.com");
        assert_eq!(&f[10..12], &[0x01, 0xBB]); // 443
        assert_eq!(&f[12..14], b"hi");
    }

    #[test]
    fn parse_ipv4_reply_frame() {
        // 服务端回程帧 ATYP=1 1.2.3.4:53 payload "resp"; body=1+4+2+4=11
        let mut buf = vec![0x00, 0x0B, 0x01, 1, 2, 3, 4, 0x00, 0x35];
        buf.extend_from_slice(b"resp");
        let (payload, consumed) = parse_udp_frame_payload(&buf).unwrap();
        assert_eq!(payload, b"resp");
        assert_eq!(consumed, buf.len());
    }

    #[test]
    fn parse_domain_frame_roundtrip() {
        // frame_udp_domain 产出的帧, parse 应能取回 payload (ATYP=3 也解析)
        let f = frame_udp_domain("x.io", 8080, b"PING");
        let (payload, consumed) = parse_udp_frame_payload(&f).unwrap();
        assert_eq!(payload, b"PING");
        assert_eq!(consumed, f.len());
    }

    #[test]
    fn parse_incomplete_returns_none() {
        assert!(parse_udp_frame_payload(&[0x00]).is_none()); // 不足 2B 长度
        // 声明 body=11 但只给 5B
        assert!(parse_udp_frame_payload(&[0x00, 0x0B, 0x01, 1, 2]).is_none());
    }

    #[test]
    fn parse_malformed_consumes_frame_empty_payload() {
        // 坏 ATYP=9, body=3: 消费整帧, payload 空 (重同步)
        let (payload, consumed) = parse_udp_frame_payload(&[0x00, 0x03, 0x09, 0xAA, 0xBB]).unwrap();
        assert!(payload.is_empty());
        assert_eq!(consumed, 5);
    }

    #[test]
    fn parse_two_frames_in_buffer() {
        // 一次 recv 收到两帧, 逐帧解析
        let mut buf = frame_udp_domain("a.b", 1, b"one");
        buf.extend(frame_udp_domain("c.d", 2, b"two"));
        let (p1, c1) = parse_udp_frame_payload(&buf).unwrap();
        assert_eq!(p1, b"one");
        let (p2, _) = parse_udp_frame_payload(&buf[c1..]).unwrap();
        assert_eq!(p2, b"two");
    }
}
