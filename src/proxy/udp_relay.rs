use crate::proxy::pool::WarmPool;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tracing::{debug, error, info, warn};

// ── Direct 出口 UDP 转发 (SOCKS5 UDP ASSOCIATE, 不走隧道) ──
// 复用 handle_udp_associate 的 SOCKS5-UDP 封装语义, 但把"隧道收发"换成
// 直发 socket 收发. v1: outbound 绑 v4, IPv6 目标显式告警丢弃 (非静默).

/// SOCKS5 UDP ASSOCIATE 的**逐数据报路由**转发。
///
/// ⚠️ 为什么必须逐包路由: ASSOCIATE 建立时**还没有任何数据报**, 目标是未知的 —— 目标写在
/// 每个数据报自己的 SOCKS5 头里 (`[RSV][FRAG][ATYP][ADDR][PORT][PAYLOAD]`)。旧实现在
/// ASSOCIATE 那一刻就用 `default_outbound` 定死出站, 于是**所有 UDP 完全绕过路由规则**:
/// 默认直连时, 本该走隧道的域名从本机 IP 裸奔出去; 写了 `block` 的域名照发不误。
///
/// 会话按**出站 tag** 建, 不按目标建 —— 这是本实现比 transparent_udp 简单的原因:
/// - Mirage 隧道本身就多路复用目标 (每帧自带地址, 服务端逐帧解析), 一条隧道够用;
/// - 直连 socket 可以 `send_to` 任意目标, 一个 socket 够用。
///
/// 同一个关联里不同数据报**可以走不同出站** —— 这正是修复的意义所在。
pub async fn handle_udp_associate_routed(
    mut local_tcp: TcpStream,
    state: Arc<arc_swap::ArcSwap<crate::config_watcher::CoreState>>,
    inbound_tag: Option<Arc<str>>,
) {
    let client_socket = match UdpSocket::bind("0.0.0.0:0").await {
        Ok(s) => Arc::new(s),
        Err(e) => {
            error!("UDP relay: 绑客户端侧 socket 失败: {}", e);
            return;
        }
    };
    let port = match client_socket.local_addr() {
        Ok(a) => a.port(),
        Err(_) => return,
    };

    let mut reply = vec![0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0];
    reply.extend_from_slice(&port.to_be_bytes());
    if local_tcp.write_all(&reply).await.is_err() {
        return;
    }
    info!("UDP Relay (逐包路由) started on port {}", port);

    // 每个出站 tag 一个 sink; 懒创建。
    let mut sinks: HashMap<String, Sink> = HashMap::new();
    // 各 sink 的下行任务, 关联结束时统一 abort (drop JoinHandle 不会 abort)。
    let mut downlinks: Vec<tokio::task::AbortHandle> = Vec::new();
    let mut dns_cache: HashMap<(String, u16), SocketAddr> = HashMap::new();

    let uplink_sock = client_socket.clone();
    let relay = async {
        let mut buf = vec![0u8; 65536];
        let mut client_addr: Option<SocketAddr> = None;

        loop {
            let (size, from) = match uplink_sock.recv_from(&mut buf).await {
                Ok(v) => v,
                Err(_) => break,
            };
            // 只认第一个来源, 之后固定 —— 防别的主机往这个 relay 端口灌包。
            let client = *client_addr.get_or_insert(from);
            if from != client {
                continue;
            }

            let data = &buf[..size];
            // [2B RSV][1B FRAG][1B ATYP]...; FRAG != 0 不支持
            if data.len() < 4 || data[0] != 0 || data[1] != 0 || data[2] != 0 {
                continue;
            }
            let rest = &data[3..];
            let (target, off) = match parse_socks_udp_addr(rest) {
                Some(v) => v,
                None => continue,
            };
            let payload = &rest[off..];

            // ── 逐包路由 ──
            let snap = state.load();
            let (host_for_log, req_domain, req_ip, dport) = match &target {
                UdpTarget::Domain(d, p) => (d.clone(), Some(d.clone()), None, *p),
                UdpTarget::Ip(sa) => (sa.ip().to_string(), None, Some(sa.ip()), sa.port()),
            };
            let tag = snap.router.route(crate::router::RoutingRequest {
                domain: req_domain.as_deref(),
                ip: req_ip,
                port: dport,
                protocol: "udp",
                source_ip: Some(client.ip()),
                source_mac: None,
                inbound: inbound_tag.as_deref(),
            });

            // ── 取或建该出站的 sink ──
            if !sinks.contains_key(&tag) {
                let node = match snap.outbounds.get(&tag) {
                    Some(o) => o.resolve_leaf(),
                    None => {
                        warn!("[SOCKS-UDP] 出站 [{}] 不存在, 丢弃", tag);
                        continue;
                    }
                };
                drop(snap);
                match build_sink(&node, client_socket.clone(), client).await {
                    Some((sink, ah)) => {
                        if let Some(ah) = ah {
                            downlinks.push(ah);
                        }
                        debug!("[SOCKS-UDP] 为出站 [{}] 建立 sink", tag);
                        sinks.insert(tag.clone(), sink);
                    }
                    None => {
                        warn!("[SOCKS-UDP] 出站 [{}] 无法建立 sink, 丢弃", tag);
                        continue;
                    }
                }
            } else {
                drop(snap);
            }

            match sinks.get(&tag) {
                Some(Sink::Block) => {
                    debug!("[SOCKS-UDP] {} 命中 block 规则, 丢弃", host_for_log);
                }
                Some(Sink::Direct { out }) => {
                    let dst = match &target {
                        UdpTarget::Ip(sa) => *sa,
                        UdpTarget::Domain(d, p) => {
                            match dns_cache.get(&(d.clone(), *p)) {
                                Some(sa) => *sa,
                                None => match crate::proxy::resolver::resolve_first(d, *p).await {
                                    Ok(sa) => {
                                        dns_cache.insert((d.clone(), *p), sa);
                                        sa
                                    }
                                    Err(_) => continue,
                                },
                            }
                        }
                    };
                    if dst.is_ipv6() {
                        warn!("[SOCKS-UDP] IPv6 目标 {} 暂不支持, 丢弃", dst);
                        continue;
                    }
                    let _ = out.send_to(payload, dst).await;
                }
                Some(Sink::Mirage { writer }) => {
                    // 隧道帧: [2B len][ATYP..][PORT][PAYLOAD] —— 地址原样透传,
                    // 由服务端逐帧解析目标, 所以一条隧道能服务所有目标。
                    let body = &rest[..off + payload.len()];
                    let mut frame = Vec::with_capacity(2 + body.len());
                    frame.extend_from_slice(&(body.len() as u16).to_be_bytes());
                    frame.extend_from_slice(body);
                    if writer.lock().await.send_data(&frame).await.is_err() {
                        // 隧道断了: 摘掉这个 sink, 下个包会重建
                        sinks.remove(&tag);
                    }
                }
                None => {}
            }
        }
    };

    // SOCKS5 标准: 控制 TCP 关闭即结束 UDP 关联
    let tcp_watcher = async move {
        let mut b = [0u8; 1];
        let _ = local_tcp.read(&mut b).await;
    };

    tokio::select! {
        _ = relay => {},
        _ = tcp_watcher => {},
    }

    // 各 sink 的下行是 spawn 出去的, 必须显式 abort —— drop JoinHandle 不会停任务,
    // 否则每个关联都会留下永久阻塞在 recv 的僵尸 (连带泄漏 socket / 隧道)。
    for ah in downlinks {
        ah.abort();
    }
    debug!("UDP Relay closed for port {}", port);
}

/// 一个出站对应的 UDP 出口。
enum Sink {
    /// 直连: 一个出向 socket, `send_to` 任意目标。
    Direct { out: Arc<UdpSocket> },
    /// 经 Mirage 隧道: 一条隧道多路复用所有目标。
    Mirage {
        writer: Arc<tokio::sync::Mutex<crate::crypto::aead::CryptoWriter<tokio::net::tcp::OwnedWriteHalf>>>,
    },
    /// 命中 block 规则: 逐包丢弃 (而不是拒绝整个关联)。
    Block,
}

/// 按出站类型建 sink, 并起对应的下行任务 (Block 无下行)。
async fn build_sink(
    node: &Arc<crate::proxy::outbound::OutboundNode>,
    client_socket: Arc<UdpSocket>,
    client: SocketAddr,
) -> Option<(Sink, Option<tokio::task::AbortHandle>)> {
    use crate::proxy::outbound::OutboundNode;
    match &**node {
        OutboundNode::Block { .. } => Some((Sink::Block, None)),
        OutboundNode::Direct { .. } => {
            let out = Arc::new(UdpSocket::bind("0.0.0.0:0").await.ok()?);
            let dn_out = out.clone();
            let h = tokio::spawn(async move {
                let mut buf = vec![0u8; 65536];
                loop {
                    let (n, src) = match dn_out.recv_from(&mut buf).await {
                        Ok(v) => v,
                        Err(_) => break,
                    };
                    let mut resp = vec![0u8, 0, 0]; // RSV + FRAG
                    resp.extend_from_slice(&encode_socks_udp_addr(src));
                    resp.extend_from_slice(&buf[..n]);
                    let _ = client_socket.send_to(&resp, client).await;
                }
            });
            Some((Sink::Direct { out }, Some(h.abort_handle())))
        }
        OutboundNode::Mirage { pool, .. } => {
            let mut tunnel = pool.get().await.ok()?;
            // UDP 模式哨兵
            tunnel.writer.send_data(&[0x00]).await.ok()?;
            let mut reader = tunnel.reader;
            let writer = Arc::new(tokio::sync::Mutex::new(tunnel.writer));
            let h = tokio::spawn(async move {
                let mut buffer = Vec::new();
                loop {
                    let chunk = match reader.recv_data().await {
                        Ok(c) => c,
                        Err(_) => break,
                    };
                    buffer.extend_from_slice(&chunk);
                    while buffer.len() >= 2 {
                        let flen = u16::from_be_bytes([buffer[0], buffer[1]]) as usize;
                        if buffer.len() < 2 + flen {
                            break;
                        }
                        let mut resp = vec![0u8, 0, 0]; // RSV + FRAG
                        resp.extend_from_slice(&buffer[2..2 + flen]);
                        let _ = client_socket.send_to(&resp, client).await;
                        buffer.drain(0..2 + flen);
                    }
                }
            });
            Some((Sink::Mirage { writer }, Some(h.abort_handle())))
        }
        other => {
            warn!("[SOCKS-UDP] 不支持的出站类型 {:?}", other.tag());
            None
        }
    }
}

/// SOCKS5 UDP 请求头里的目标地址.
enum UdpTarget {
    Ip(SocketAddr),
    Domain(String, u16),
}

/// 解析从 ATYP 开始的 SOCKS5 地址. 返回 (目标, payload 相对偏移).
fn parse_socks_udp_addr(b: &[u8]) -> Option<(UdpTarget, usize)> {
    match b.first()? {
        0x01 => {
            if b.len() < 1 + 4 + 2 {
                return None;
            }
            let ip = std::net::Ipv4Addr::new(b[1], b[2], b[3], b[4]);
            let port = u16::from_be_bytes([b[5], b[6]]);
            Some((UdpTarget::Ip(SocketAddr::from((ip, port))), 7))
        }
        0x04 => {
            if b.len() < 1 + 16 + 2 {
                return None;
            }
            let mut o = [0u8; 16];
            o.copy_from_slice(&b[1..17]);
            let ip = std::net::Ipv6Addr::from(o);
            let port = u16::from_be_bytes([b[17], b[18]]);
            Some((UdpTarget::Ip(SocketAddr::from((ip, port))), 19))
        }
        0x03 => {
            let len = *b.get(1)? as usize;
            if b.len() < 2 + len + 2 {
                return None;
            }
            let host = std::str::from_utf8(&b[2..2 + len]).ok()?.to_string();
            let port = u16::from_be_bytes([b[2 + len], b[3 + len]]);
            Some((UdpTarget::Domain(host, port), 2 + len + 2))
        }
        _ => None,
    }
}

/// 把回程源地址编码成 SOCKS5 UDP 头的 [ATYP][ADDR][PORT] 部分.
fn encode_socks_udp_addr(addr: SocketAddr) -> Vec<u8> {
    let mut out = Vec::with_capacity(19);
    match addr {
        SocketAddr::V4(a) => {
            out.push(0x01);
            out.extend_from_slice(&a.ip().octets());
        }
        SocketAddr::V6(a) => {
            out.push(0x04);
            out.extend_from_slice(&a.ip().octets());
        }
    }
    out.extend_from_slice(&addr.port().to_be_bytes());
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::SocketAddr;
    use std::time::Duration;
    use tokio::net::TcpListener;

    #[test]
    fn parse_v4_addr() {
        // ATYP=1, 1.2.3.4:443, payload "hi"
        let b = [0x01, 1, 2, 3, 4, 0x01, 0xBB, b'h', b'i'];
        let (t, off) = parse_socks_udp_addr(&b).unwrap();
        assert_eq!(off, 7);
        assert!(matches!(t, UdpTarget::Ip(sa) if sa == "1.2.3.4:443".parse().unwrap()));
        assert_eq!(&b[off..], b"hi");
    }

    #[test]
    fn parse_domain_addr() {
        // ATYP=3, len=3 "abc", :80, payload "x"
        let b = [0x03, 3, b'a', b'b', b'c', 0x00, 0x50, b'x'];
        let (t, off) = parse_socks_udp_addr(&b).unwrap();
        assert_eq!(off, 7);
        match t {
            UdpTarget::Domain(h, p) => {
                assert_eq!(h, "abc");
                assert_eq!(p, 80);
            }
            _ => panic!("expected domain"),
        }
    }

    #[test]
    fn parse_truncated_returns_none() {
        assert!(parse_socks_udp_addr(&[]).is_none());
        assert!(parse_socks_udp_addr(&[0x01, 1, 2]).is_none()); // v4 too short
        assert!(parse_socks_udp_addr(&[0x03, 5, b'a']).is_none()); // domain len exceeds
        assert!(parse_socks_udp_addr(&[0x02, 0, 0]).is_none()); // bad ATYP
    }

    #[test]
    fn encode_v4_roundtrip() {
        let sa: SocketAddr = "9.8.7.6:1234".parse().unwrap();
        let enc = encode_socks_udp_addr(sa);
        assert_eq!(enc, vec![0x01, 9, 8, 7, 6, 0x04, 0xD2]);
    }

    /// 造一个只有 direct/block 出站的最小 CoreState。
    /// `blocked_ports` 里的**目标端口**会被路由到 block 出站。
    ///
    /// 用端口而非 IP 段区分, 是为了让被 block 的目标也能是一个**真在监听**的 echo ——
    /// 否则"收不到回程"在没有路由的情况下也成立, 判据恒真 (本测试初版就是这么错的)。
    fn test_state(
        blocked_ports: Vec<u16>,
    ) -> Arc<arc_swap::ArcSwap<crate::config_watcher::CoreState>> {
        let rules: Vec<crate::router::Rule> = blocked_ports
            .iter()
            .enumerate()
            .map(|(i, p)| crate::router::Rule {
                id: i,
                mode: "or".into(),
                outbound: "block".into(),
                domain_suffix: vec![],
                domain_keyword: vec![],
                domain_regex: vec![],
                geosite: vec![],
                ip_cidr: vec![],
                source_ip_cidr: vec![],
                source_mac: vec![],
                geoip: vec![],
                port: vec![*p],
                protocol: vec![],
                inbound: vec![],
            })
            .collect();
        let router = crate::router::RouterEngine::new(
            rules,
            "direct".into(),
            ".",
            &std::collections::HashMap::new(),
        )
        .expect("引擎应能构建");
        let cfg: crate::config::Config = serde_json::from_str(
            r#"{"inbounds":[],"outbounds":[{"type":"direct","tag":"direct"},{"type":"block","tag":"block"}],"routing":{"default_outbound":"direct","rules":[]}}"#,
        )
        .unwrap();
        Arc::new(arc_swap::ArcSwap::from_pointee(
            crate::config_watcher::CoreState {
                router: Arc::new(router),
                outbounds: Arc::new(crate::proxy::outbound::OutboundManager::new(&cfg)),
                advanced_dns: None,
            },
        ))
    }

    /// **逐数据报路由**的回归测试 —— 这是本次修复的核心契约。
    ///
    /// 旧实现在 ASSOCIATE 时就用 `default_outbound` 定死出站, 于是所有 UDP 完全绕过路由:
    /// 写了 `block` 的目标照发不误。这里在**同一个 ASSOCIATE 里**往两个目标各发一包,
    /// 一个命中 block 规则、一个不命中, 断言前者收不到回程、后者能。
    #[tokio::test]
    async fn per_datagram_routing_applies_block_rule() {
        async fn spawn_echo() -> SocketAddr {
            let s = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let a = s.local_addr().unwrap();
            tokio::spawn(async move {
                let mut b = vec![0u8; 1500];
                while let Ok((n, from)) = s.recv_from(&mut b).await {
                    let _ = s.send_to(&b[..n], from).await;
                }
            });
            a
        }
        fn pkt(dst: SocketAddr, body: &[u8]) -> Vec<u8> {
            let mut p = vec![0u8, 0, 0, 0x01];
            if let SocketAddr::V4(v4) = dst {
                p.extend_from_slice(&v4.ip().octets());
                p.extend_from_slice(&v4.port().to_be_bytes());
            }
            p.extend_from_slice(body);
            p
        }

        // ⚠️ 两个 echo **都真在监听** —— 被 block 的那个如果没人监听, "收不到回程"
        // 在完全没有路由的情况下也成立, 判据就恒真了 (初版正是这么错的, 变异测试拆穿)。
        let echo_ok = spawn_echo().await;
        let echo_blocked = spawn_echo().await;
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let laddr = listener.local_addr().unwrap();
        let mut client_tcp = TcpStream::connect(laddr).await.unwrap();
        let (server_tcp, _) = listener.accept().await.unwrap();
        tokio::spawn(handle_udp_associate_routed(
            server_tcp,
            test_state(vec![echo_blocked.port()]),
            None,
        ));

        let mut reply = [0u8; 10];
        client_tcp.read_exact(&mut reply).await.unwrap();
        let relay: SocketAddr =
            ([127, 0, 0, 1], u16::from_be_bytes([reply[8], reply[9]])).into();

        let cli = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let mut rbuf = vec![0u8; 1500];

        // ① 未命中 block → 应有回程 (证明链路本身是通的)
        cli.send_to(&pkt(echo_ok, b"ok"), relay).await.unwrap();
        let got = tokio::time::timeout(Duration::from_secs(2), cli.recv_from(&mut rbuf)).await;
        assert!(got.is_ok(), "未命中 block 的目标应能收到回程");

        // ② 命中 block → 不该有回程。注意这个 echo **是在监听的**, 所以唯一能解释
        //    "收不到"的原因就是路由把它拦了。
        cli.send_to(&pkt(echo_blocked, b"nope"), relay).await.unwrap();
        let after = tokio::time::timeout(Duration::from_millis(700), cli.recv_from(&mut rbuf)).await;
        assert!(
            after.is_err(),
            "命中 block 规则的目标仍收到了回程 —— UDP 绕过了路由规则"
        );
    }

    // 端到端: 本地 echo UDP server + 走 Direct relay 打一发, 验证回程封装正确
    #[tokio::test]
    async fn direct_udp_echo_roundtrip() {
        // echo server
        let echo = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let echo_addr = echo.local_addr().unwrap();
        tokio::spawn(async move {
            let mut b = vec![0u8; 1500];
            loop {
                match echo.recv_from(&mut b).await {
                    Ok((n, from)) => {
                        let _ = echo.send_to(&b[..n], from).await;
                    }
                    Err(_) => break,
                }
            }
        });

        // 控制 TCP (loopback)
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let laddr = listener.local_addr().unwrap();
        let mut client_tcp = TcpStream::connect(laddr).await.unwrap();
        let (server_tcp, _) = listener.accept().await.unwrap();

        let state = test_state(vec![]);
        tokio::spawn(handle_udp_associate_routed(server_tcp, state, None));

        // 读 SOCKS5 reply 拿 relay UDP 端口
        let mut reply = [0u8; 10];
        client_tcp.read_exact(&mut reply).await.unwrap();
        let relay_port = u16::from_be_bytes([reply[8], reply[9]]);
        let relay_addr: SocketAddr = ([127, 0, 0, 1], relay_port).into();

        // 构造 SOCKS5-UDP 包发到 relay: RSV+FRAG+ATYP(v4)+IP+PORT+"hello"
        let cli = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let mut pkt = vec![0u8, 0, 0, 0x01];
        if let SocketAddr::V4(v4) = echo_addr {
            pkt.extend_from_slice(&v4.ip().octets());
            pkt.extend_from_slice(&v4.port().to_be_bytes());
        }
        pkt.extend_from_slice(b"hello");
        cli.send_to(&pkt, relay_addr).await.unwrap();

        // 收回程
        let mut rbuf = vec![0u8; 1500];
        let n = tokio::time::timeout(Duration::from_secs(2), cli.recv_from(&mut rbuf))
            .await
            .expect("timed out waiting for echo")
            .unwrap()
            .0;
        // 回程 = RSV(2)+FRAG(1)+ATYP(1)+IP(4)+PORT(2)+"hello"
        assert_eq!(rbuf[0], 0);
        assert_eq!(rbuf[3], 0x01); // v4 ATYP
        assert_eq!(&rbuf[n - 5..n], b"hello");
    }
}
