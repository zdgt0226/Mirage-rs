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
fn build_transparent_listener(listen_addr: &str) -> anyhow::Result<TcpListener> {
    use nix::sys::socket::{
        bind, listen, setsockopt, socket, sockopt, AddressFamily, Backlog, SockFlag, SockType,
        SockaddrIn,
    };
    use std::os::fd::{AsRawFd, FromRawFd, IntoRawFd};

    let addr: std::net::SocketAddrV4 = listen_addr
        .parse()
        .map_err(|e| anyhow::anyhow!("透明 TCP listen 地址非 IPv4 ({}): {}", listen_addr, e))?;
    let fd = socket(AddressFamily::Inet, SockType::Stream, SockFlag::SOCK_NONBLOCK, None)?;
    setsockopt(&fd, sockopt::ReuseAddr, &true)?;
    setsockopt(&fd, sockopt::IpTransparent, &true)?;
    bind(fd.as_raw_fd(), &SockaddrIn::from(addr))?;
    listen(&fd, Backlog::new(1024)?)?;
    let std_listener = unsafe { std::net::TcpListener::from_raw_fd(fd.into_raw_fd()) };
    std_listener.set_nonblocking(true)?;
    Ok(TcpListener::from_std(std_listener)?)
}

/**
 * [eBPF 透明代理监听服务]
 * 这个服务会绑定到一个本地端口，并通过 eBPF sk_lookup 截获所有针对 fake_ip 的流量。
 */
pub async fn start_transparent(
    listen_addr: &str,
    state: Arc<ArcSwap<CoreState>>,
    ebpf_engine: Option<Arc<tokio::sync::Mutex<crate::ebpf::EbpfEngine>>>,
    fake_ip_mapper: Arc<FakeIpMapper>,
    transparent_engine: Arc<tokio::sync::Mutex<TransparentEngine>>,
    fake_ip_net: std::net::Ipv4Addr,
    fake_ip_prefix: u8,
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
        tokio::spawn(async move {
            if let Err(e) =
                crate::proxy::transparent_udp::start_transparent_udp(udp_bind, st, fm, te).await
            {
                error!("Transparent UDP proxy failed: {}", e);
            }
        });
    } else {
        warn!("Transparent UDP proxy skipped: listen addr {} is not IPv4", listen_addr);
    }

    info!("Transparent proxy pipeline fully initialized and attached.");

    loop {
        match listener.accept().await {
            Ok((stream, peer_addr)) => {
                let state_clone = state.clone();
                let fake_ip_mapper_clone = fake_ip_mapper.clone();
                let ebpf_clone = ebpf_engine.clone();

                tokio::spawn(async move {
                    // 获取连接原本想要访问的真实目标 IP (也就是 fake-ip)
                    let dst = stream.local_addr();
                    if let Ok(dst_addr) = dst {
                        if let std::net::IpAddr::V4(dst_v4) = dst_addr.ip() {
                            
                            // 1. 从 fake-ip mapper 中反查真实域名
                            let domain_opt = fake_ip_mapper_clone.lookup_domain(&dst_v4);
                            
                            let mut target_host = match domain_opt {
                                Some(d) => format!("{}:{}", d, dst_addr.port()),
                                None => format!("{}:{}", dst_v4, dst_addr.port()),
                            };
                            
                            debug!("[TPROXY] TCP {} → fake-IP {} → 反查 [{}]", peer_addr, dst_addr, target_host);

                            // 2. 为了精准路由，我们再嗅探一下协议特征 (TLS SNI 或 HTTP Host)
                            // 比如某些情况并不是通过 fake-ip 查询的，而是直接透明劫持了纯 IP 的请求
                            let sniffed_domain = sniff_first_kb(&stream).await;
                            if let Some(sniffed) = sniffed_domain {
                                debug!("[TPROXY] TCP 嗅探到 SNI/Host [{}] (纠偏目标)", sniffed);
                                // 如果嗅探到了域名，我们就优先使用嗅探到的域名作为目标
                                target_host = format!("{}:{}", sniffed, dst_addr.port());
                            }
                            
                            // 3. 复用现有的 TCP 处理逻辑，根据 rule_engine 进行路由分发
                            crate::proxy::handler::proxy_tcp_target(
                                stream,
                                target_host,
                                vec![],
                                state_clone,
                                ebpf_clone,
                                Some(fake_ip_mapper_clone),
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
