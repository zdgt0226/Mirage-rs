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
use std::sync::Arc;
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

type FlowKey = (SocketAddrV4, SocketAddrV4); // (client, orig_dst)

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

    // (client, orig_dst) → 出口 socket; orig_dst → 回包 socket
    let sessions: Arc<Mutex<HashMap<FlowKey, Arc<UdpSocket>>>> = Arc::new(Mutex::new(HashMap::new()));
    let replies: Arc<Mutex<HashMap<SocketAddrV4, Arc<UdpSocket>>>> =
        Arc::new(Mutex::new(HashMap::new()));

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

        // 已有会话 → 快路径直接转发
        let key = (client, orig_dst);
        if let Some(out) = sessions.lock().await.get(&key).cloned() {
            let _ = out.send(&buf[..size]).await;
            continue;
        }

        // 新流 → 反查/路由/建 socket (异步, 不阻塞收包循环)
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

#[allow(clippy::too_many_arguments)]
async fn setup_flow(
    client: SocketAddrV4,
    orig_dst: SocketAddrV4,
    first_payload: Vec<u8>,
    state: Arc<ArcSwap<CoreState>>,
    fake_ip_mapper: Arc<FakeIpMapper>,
    sessions: Arc<Mutex<HashMap<FlowKey, Arc<UdpSocket>>>>,
    replies: Arc<Mutex<HashMap<SocketAddrV4, Arc<UdpSocket>>>>,
) {
    let key = (client, orig_dst);
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

    // 回包 socket (按 orig_dst 复用)
    let reply = {
        let mut r = replies.lock().await;
        if let Some(rs) = r.get(&orig_dst) {
            rs.clone()
        } else {
            match build_reply_socket(orig_dst) {
                Ok(rs) => {
                    let rs = Arc::new(rs);
                    r.insert(orig_dst, rs.clone());
                    rs
                }
                Err(e) => {
                    error!("udp-t: reply socket for {} failed: {}", orig_dst, e);
                    return;
                }
            }
        }
    };

    sessions.lock().await.insert(key, out.clone());
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
    let sessions_gc = sessions.clone();
    let mut buf = vec![0u8; UDP_BUF];
    loop {
        match tokio::time::timeout(IDLE_TIMEOUT, out.recv(&mut buf)).await {
            Ok(Ok(n)) => {
                let _ = reply.send_to(&buf[..n], SocketAddr::V4(client)).await;
            }
            _ => break, // 空闲超时或出错
        }
    }
    sessions_gc.lock().await.remove(&key);
    debug!("udp-t: flow {:?} closed", key);
}
