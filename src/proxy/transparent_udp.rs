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

/// 会话槽. Setting = setup_flow 正在建流 (占位, 防突发包重复 spawn);
/// Ready = 出口 socket 就绪, 主循环快路径直接转发。
enum FlowSlot {
    Setting,
    Ready(Arc<UdpSocket>),
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
///   - out=None (未 commit): 移除主循环占位的 Setting 槽, 否则该 key 永久卡
///     Setting → 后续包被当"建流中"丢弃 → 目标黑洞。
///   - out=Some (已 commit): 守卫移除 Ready 槽 (Arc::ptr_eq 防误删被替换的会话)
///     + reply refs-- 归 0 移除关 FD。
/// 关键: 清理内联在 downlink 循环后会被 panic/未来 early-return 跳过 → 泄漏,
/// 故收进 Drop 强制保证 (同 reply-socket FD 泄漏那次的教训)。
struct FlowGuard {
    key: FlowKey,
    orig_dst: SocketAddrV4,
    sessions: Sessions,
    replies: Replies,
    out: Option<Arc<UdpSocket>>,
}
impl Drop for FlowGuard {
    fn drop(&mut self) {
        match &self.out {
            None => {
                let mut s = lock_sessions(&self.sessions);
                if matches!(s.get(&self.key), Some(FlowSlot::Setting)) {
                    s.remove(&self.key);
                }
            }
            Some(out) => {
                {
                    let mut s = lock_sessions(&self.sessions);
                    if let Some(FlowSlot::Ready(cur)) = s.get(&self.key) {
                        if Arc::ptr_eq(cur, out) {
                            s.remove(&self.key);
                        }
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
                Some(FlowSlot::Ready(out)) => Some(out.clone()),
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

        if let Some(out) = forward {
            let _ = out.send(&buf[..size]).await;
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
        out: None,
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
    let leaf = outbound.resolve_leaf();
    match &*leaf {
        OutboundNode::Direct { .. } => {} // 继续直发
        OutboundNode::Block { .. } => {
            debug!("udp-t: blocked {:?}", domain);
            return;
        }
        OutboundNode::Mirage { .. } => {
            warn!(
                "udp-t: Mirage-routed UDP to {} 暂未接入 (v1), 丢弃 → 客户端回落 TCP",
                domain.as_deref().unwrap_or("?")
            );
            return;
        }
        other => {
            warn!("udp-t: unsupported outbound leaf {:?}, dropping", other.tag());
            return;
        }
    }
    drop(snapshot);

    // 解析真目标 (fake-IP 必须有域名映射; 无则丢)
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

    // 出口 socket (普通 egress), 连到真目标
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

    // 回包 socket (按 orig_dst 复用, refs++)。build 失败 → 早退 (guard 清占位)。
    let reply = {
        let mut r = lock_replies(&replies);
        if let Some(e) = r.get_mut(&orig_dst) {
            e.refs += 1;
            e.sock.clone()
        } else {
            match build_reply_socket(orig_dst) {
                Ok(rs) => {
                    let rs = Arc::new(rs);
                    r.insert(orig_dst, ReplyEntry { sock: rs.clone(), refs: 1 });
                    rs
                }
                Err(e) => {
                    error!("udp-t: reply socket for {} failed: {}", orig_dst, e);
                    return;
                }
            }
        }
    };

    // commit: Setting → Ready, guard 转入"已建流"模式 (drop 时做完整 teardown)。
    lock_sessions(&sessions).insert(key, FlowSlot::Ready(out.clone()));
    guard.out = Some(out.clone());
    debug!(
        "udp-t: new flow {} → {} (fake {} → real {})",
        client,
        domain.as_deref().unwrap_or("?"),
        fake_ip,
        real
    );

    // 首包
    let _ = out.send(&first_payload).await;

    // downlink: 真目标 → 客户端 (经透明回包 socket, 伪源 = fake-IP:port)
    let mut buf = vec![0u8; UDP_BUF];
    loop {
        match tokio::time::timeout(IDLE_TIMEOUT, out.recv(&mut buf)).await {
            Ok(Ok(n)) => {
                let _ = reply.send_to(&buf[..n], SocketAddr::V4(client)).await;
            }
            _ => break, // 空闲超时或出错
        }
    }

    // teardown (session 移除 + reply refs--) 由 FlowGuard::drop 保证执行,
    // 即使 downlink 循环里 panic 也不泄漏。
    debug!("udp-t: flow {:?} closed", key);
}
