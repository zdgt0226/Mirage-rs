use std::sync::Arc;
use tokio::net::TcpListener;
use tracing::{error, info, debug, warn};

use crate::config_watcher::CoreState;
use crate::dns::fake_ip::FakeIpMapper;
use crate::ebpf::TransparentEngine;
use arc_swap::ArcSwap;

// 引入嗅探器
use crate::proxy::sniff::sniff_first_kb;

/// 构造带 IP_TRANSPARENT 的 TCP listener (v4)。与 transparent_udp.rs 的
/// build_main_socket 同范式 (nix socket + setsockopt + from_std)。
/// 构建透明 listener, 保证成功: 先试 IP_TRANSPARENT 路径 (raw-IP 分流需要), 任何
/// 一步失败就回落普通 TcpListener::bind (fake-IP 靠 local 路由已是本地、完全够用,
/// 只损 raw-IP 直连分流)。绝不因 setsockopt/listen EINVAL 而让整个透明代理起不来。
fn build_transparent_listener(listen_addr: &str) -> anyhow::Result<TcpListener> {
    match build_transparent_listener_inner(listen_addr) {
        Ok(l) => Ok(l),
        Err(e) => {
            warn!("IP_TRANSPARENT listener 构建失败 ({}); 回落普通 listener —— fake-IP 转发可用, raw-IP 直连分流受限", e);
            let std_l = std::net::TcpListener::bind(listen_addr)?;
            std_l.set_nonblocking(true)?;
            Ok(TcpListener::from_std(std_l)?)
        }
    }
}

fn build_transparent_listener_inner(listen_addr: &str) -> anyhow::Result<TcpListener> {
    use anyhow::Context;
    use nix::sys::socket::{
        bind, listen, setsockopt, socket, sockopt, AddressFamily, Backlog, SockFlag, SockType,
        SockaddrIn,
    };
    use std::os::fd::{AsRawFd, FromRawFd, IntoRawFd};

    let addr: std::net::SocketAddrV4 = listen_addr
        .parse()
        .map_err(|e| anyhow::anyhow!("透明 TCP listen 地址非 IPv4 ({}): {}", listen_addr, e))?;
    let fd = socket(AddressFamily::Inet, SockType::Stream, SockFlag::SOCK_NONBLOCK, None)
        .context("socket(AF_INET, SOCK_STREAM)")?;
    setsockopt(&fd, sockopt::ReuseAddr, &true).context("setsockopt SO_REUSEADDR")?;
    // IP_TRANSPARENT 非致命: 仅 tc_divert 的 raw-IP 路径需要 (以非本地目的完成握手);
    // fake-IP 路径靠 `ip route add local` 已是本地地址, 普通 listener 即可 accept。
    // 某些内核/受限环境 setsockopt 会 EINVAL —— 失败则降级为普通 listener, fake-IP
    // 转发照常, 只有 raw-IP 直连分流受限。绝不能因它 drop 掉整个 listener。
    if let Err(e) = setsockopt(&fd, sockopt::IpTransparent, &true) {
        warn!("透明 listener IP_TRANSPARENT 设置失败 ({}); fake-IP 仍可用, raw-IP 分流受限", e);
    }
    bind(fd.as_raw_fd(), &SockaddrIn::from(addr)).with_context(|| format!("bind {}", addr))?;
    // Backlog::MAXCONN (=SOMAXCONN) 恒合法; 早前 Backlog::new(1024) 在 SOMAXCONN=128
    // 的内核上直接 EINVAL (nix 校验 val < SOMAXCONN), 是真机 listener 起不来的真凶。
    listen(&fd, Backlog::MAXCONN).context("listen")?;
    let std_listener = unsafe { std::net::TcpListener::from_raw_fd(fd.into_raw_fd()) };
    std_listener.set_nonblocking(true)?;
    Ok(TcpListener::from_std(std_listener)?)
}

/**
 * [eBPF 透明代理监听服务]
 * 这个服务会绑定到一个本地端口，并通过 eBPF sk_lookup 截获所有针对 fake_ip 的流量。
 */
pub async fn start_transparent(
    inbound_tag: Arc<str>,
    listen_addr: &str,
    state: Arc<ArcSwap<CoreState>>,
    ebpf_engine: Option<Arc<tokio::sync::Mutex<crate::ebpf::EbpfEngine>>>,
    fake_ip_mapper: Arc<FakeIpMapper>,
    transparent_engine: Arc<tokio::sync::Mutex<TransparentEngine>>,
    fake_ip_net: std::net::Ipv4Addr,
    fake_ip_prefix: u8,
    // 本机出向重定向引擎: cgroup/connect4 把本机 fake-IP 连接改写进本 listener,
    // local_addr() 变成 127.0.0.1:lport, 需按 peer 端口查回原始 fake-IP。
    cgroup_engine: Option<Arc<crate::ebpf::CgroupConnectEngine>>,
) -> anyhow::Result<()> {
    // IP_TRANSPARENT listener: tc_divert 用 sk_assign 把外网-IP 的 TCP SYN 偷进来后,
    // listener 必须透明才能以非本地目的地址完成三次握手, accept 出的 socket 的
    // local_addr() = 原始 foreign 目的 (裸-IP 分流的分水岭)。fake-IP 路径靠本地
    // 路由已是"本地"、不依赖此选项, 但开着无害且统一。
    let listener = build_transparent_listener(listen_addr)?;
    info!("Transparent proxy listener bound to {} (IP_TRANSPARENT)", listen_addr);

    // 1./2. sk_lookup 旧路径 (sockmap + attach netns): 非致命。tc_divert 已用内核
    // bpf_sk_lookup_tcp 直接在 socket 表找本 listener 并 sk_assign, 不依赖 sockmap。
    // 而 register_listener 把 TCP_LISTEN socket 塞进 SOCKMAP 在多数内核返回 EINVAL ——
    // 若此处 `?` 硬失败会连累整个 start_transparent 返回 Err、把 listener socket 也
    // drop 掉, 导致 tc_divert 无 socket 可 assign、fake-IP TCP 全部放行转发被墙。
    // 故降级为 warn: sk_lookup 能装则装 (覆盖本机 local 流量), 装不上也不影响
    // tc_divert 对转发流量的接管。
    {
        let engine = transparent_engine.lock().await;
        if let Err(e) = engine.register_listener(&listener) {
            warn!("sk_lookup register_listener 失败 (不影响 tc_divert 转发拦截): {}", e);
        }
    }
    {
        let mut engine = transparent_engine.lock().await;
        if let Err(e) = engine.attach_to_netns(fake_ip_net, fake_ip_prefix) {
            warn!("sk_lookup attach_to_netns 失败 (不影响 tc_divert 转发拦截): {}", e);
        }
    }

    // 2.5 装 fake-IP 本地路由: sk_lookup 只在本地投递路径触发, 不加这条路由
    // fake-IP 会被内核判为转发/默认路由发出, 拦截静默失效. 自动装, 退出清理,
    // 用户无感. 见 transparent_net.rs 顶注释.
    crate::proxy::transparent_net::install(fake_ip_net, fake_ip_prefix).await;

    // UDP 透明代理: 与 TCP 并行. sk_lookup 按 protocol 把 UDP 分流到 udp sockmap.
    // (QUIC/HTTP3/DNS-over-UDP 的网关支持)
    if let Ok(std::net::SocketAddr::V4(udp_bind)) = listen_addr.parse::<std::net::SocketAddr>() {
        let st = state.clone();
        let fm = fake_ip_mapper.clone();
        let te = transparent_engine.clone();
        let udp_tag = inbound_tag.clone();
        tokio::spawn(async move {
            if let Err(e) =
                crate::proxy::transparent_udp::start_transparent_udp(udp_tag, udp_bind, st, fm, te).await
            {
                error!("Transparent UDP proxy failed: {}", e);
            }
        });
    } else {
        warn!("Transparent UDP proxy skipped: listen addr {} is not IPv4", listen_addr);
    }

    info!("Transparent proxy pipeline fully initialized and attached.");

    // 本 listener 的实际端口, 用于拦截"目标 == 自己监听端口"的自连 (见下面 spawn 内)。
    let listen_port = listener.local_addr().map(|a| a.port()).unwrap_or(0);

    loop {
        match listener.accept().await {
            Ok((stream, peer_addr)) => {
                let state_clone = state.clone();
                let fake_ip_mapper_clone = fake_ip_mapper.clone();
                let ebpf_clone = ebpf_engine.clone();
                let tag_clone = inbound_tag.clone();
                let cgroup_clone = cgroup_engine.clone();
                let lport = listen_port;

                tokio::spawn(async move {
                    // 原始目的: tc_divert 路径下 local_addr() 即 fake-IP; cgroup/connect4
                    // 路径下被改写成 127.0.0.1:lport, 需按 peer 源端口查回原始 fake-IP。
                    let dst = stream.local_addr();
                    if let Ok(mut dst_addr) = dst {
                        if dst_addr.ip().is_loopback() {
                            match cgroup_clone.as_ref().and_then(|eng| eng.lookup_origdst(peer_addr.port())) {
                                Some((ip, port)) => dst_addr = std::net::SocketAddr::from((ip, port)),
                                None => {
                                    // ⚠️ 外部审计 #2: cgroup/connect4 是异步的 —— TCP_CONNECT_CB 写
                                    // cc_port map 与用户态 accept 存在竞态, accept 抢在 map 写入前时
                                    // lookup 落空。此刻 dst 仍是 127.0.0.1:lport, **绝不能拿它当目标**:
                                    // 那会让代理连回自己 (至少是一次注定失败的自连, 表现为偶发卡顿)。
                                    // 直接丢弃 —— 客户端 TCP 会重传, 届时 map 多半已同步。
                                    debug!(
                                        "[TPROXY] {} origdst 查询落空 (cgroup map 竞态), 丢弃以防自连 127.0.0.1:{}",
                                        peer_addr, dst_addr.port()
                                    );
                                    return;
                                }
                            }
                        }
                        // 双保险: 无论走哪条路径, 目标若恰是本 listener 端口 = 自连, 丢弃。
                        if dst_addr.ip().is_loopback() && dst_addr.port() == lport {
                            debug!("[TPROXY] {} 目标为自身监听端口 127.0.0.1:{}, 丢弃防死循环", peer_addr, lport);
                            return;
                        }
                        if let std::net::IpAddr::V4(dst_v4) = dst_addr.ip() {

                            // 从 fake-ip mapper 反查真实域名。
                            // 优化: fake-IP 已反查到域名的 —— 客户端连的就是它、SNI 必与之
                            // 一致, 直接用, **不再阻塞 sniff**(省掉每条网页连接的一次嗅探)。
                            // sniff 只对**裸-IP**(无 fake-IP 映射)才做: 嗅 SNI 拿域名交服务端
                            // 在干净网络解析(抗污染), 拿不到才退回裸 IP。
                            let target_host = match fake_ip_mapper_clone.lookup_domain(&dst_v4) {
                                Some(d) => format!("{}:{}", d, dst_addr.port()),
                                None => match sniff_first_kb(&stream).await {
                                    Some(sniffed) => {
                                        debug!("[TPROXY] TCP {} 裸-IP 嗅探到 SNI/Host [{}]", peer_addr, sniffed);
                                        format!("{}:{}", sniffed, dst_addr.port())
                                    }
                                    None => format!("{}:{}", dst_v4, dst_addr.port()),
                                },
                            };

                            debug!("[TPROXY] TCP {} → {} → [{}]", peer_addr, dst_addr, target_host);

                            // 复用现有的 TCP 处理逻辑，根据 rule_engine 进行路由分发
                            crate::proxy::handler::proxy_tcp_target(
                                stream,
                                target_host,
                                vec![],
                                state_clone,
                                ebpf_clone,
                                Some(fake_ip_mapper_clone),
                                Some(tag_clone),
                                // transparent 上面已经嗅过一轮, 别再重复等一个超时
                                true,
                            ).await;
                        }
                    }
                });
            }
            Err(e) => {
                error!("Transparent proxy listener accept error: {}", e);
            }
        }
    }
}
