use std::sync::Arc;
use tokio::net::TcpListener;
use tracing::{error, info, debug};

use crate::config_watcher::CoreState;
use crate::dns::fake_ip::FakeIpMapper;
use crate::ebpf::TransparentEngine;
use arc_swap::ArcSwap;

// 引入嗅探器
use crate::proxy::sniff::sniff_first_kb;

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
    let listener = TcpListener::bind(listen_addr).await?;
    info!("Transparent proxy listener bound to {}", listen_addr);

    // 1. 注册 listener socket 到 eBPF map 中，告知内核将流量抛给哪个 Socket
    {
        let engine = transparent_engine.lock().await;
        engine.register_listener(&listener)?;
    }

    // 2. 将 sk_lookup 程序 attach 到当前 Network Namespace，并下发 fake_ip 规则
    {
        let mut engine = transparent_engine.lock().await;
        engine.attach_to_netns(fake_ip_net, fake_ip_prefix)?;
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
                            
                            debug!("Transparent connection from {} aimed at fake_ip {} -> resolved to {}", peer_addr, dst_addr, target_host);

                            // 2. 为了精准路由，我们再嗅探一下协议特征 (TLS SNI 或 HTTP Host)
                            // 比如某些情况并不是通过 fake-ip 查询的，而是直接透明劫持了纯 IP 的请求
                            let sniffed_domain = sniff_first_kb(&stream).await;
                            if let Some(sniffed) = sniffed_domain {
                                debug!("Sniffed domain {} from transparent connection", sniffed);
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
