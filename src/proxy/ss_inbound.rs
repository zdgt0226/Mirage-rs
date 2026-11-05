//! Shadowsocks 入站 (链式代理 ②): 网关接受 SS 客户端连接, 解出目标, 经**统一出站接口**
//! (`OutboundNode::connect`) 走路由/隧道出。仅 SIP004 AEAD (SIP022 服务端未实现)。
//!
//! 这是 `connect()` 统一出站流在**数据面**的首个消费者: SS 入 → router 选出站 → connect →
//! 双向 relay。配合 routing 的 `inbound` 条件, 即可实现"SS 入 X → 出站 Y"任意编排。

use std::sync::Arc;

use arc_swap::ArcSwap;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tracing::{debug, warn};

use crate::config_watcher::CoreState;
use crate::proxy::outbound::Address;
use crate::proxy::shadowsocks::{decode_socks_addr, server_handshake, Method};
use crate::router::RoutingRequest;

/// 处理一条 SS 入站连接。免认证由 SS 协议本身的密钥保证 (解不开 = 拒)。
pub async fn handle_ss_client(
    conn: TcpStream,
    state: Arc<ArcSwap<CoreState>>,
    method: Method,
    password: Arc<str>,
    inbound_tag: Arc<str>,
) {
    let peer = conn.peer_addr().ok();
    conn.set_nodelay(true).ok();
    let (r, w) = conn.into_split();

    // 1. SS 服务端握手 (发下行 salt; 读端懒读客户端上行 salt)。
    let (mut ssr, mut ssw) = match server_handshake(r, w, method, &password).await {
        Ok(x) => x,
        Err(e) => {
            warn!("SS 入站握手失败 (peer={peer:?}): {e}");
            return;
        }
    };

    // 2. 首个解密 chunk 前缀 = SOCKS 目标头, 其后可能附带初始载荷。
    let first = match ssr.read_chunk().await {
        Ok(c) if !c.is_empty() => c,
        Ok(_) => return, // EOF
        Err(e) => {
            warn!("SS 入站读目标头失败 (peer={peer:?}, 多为密钥不符): {e}");
            return;
        }
    };
    let (target, hlen) = match decode_socks_addr(&first) {
        Ok(x) => x,
        Err(e) => {
            warn!("SS 入站目标头非法 (peer={peer:?}): {e}");
            return;
        }
    };
    let initial = first[hlen..].to_vec();

    // 3. 路由 → 选出站。
    let addr = match Address::parse(&target) {
        Ok(a) => a,
        Err(e) => {
            warn!("SS 入站目标 `{target}` 非法: {e}");
            return;
        }
    };
    let st = state.load();
    let (dom, ipopt) = match &addr {
        Address::Domain(h, _) => (Some(h.as_str()), None),
        Address::Socket(sa) => (None, Some(sa.ip())),
    };
    let req = RoutingRequest {
        domain: dom,
        ip: ipopt,
        port: addr.port(),
        protocol: "tcp",
        source_ip: None,
        source_mac: None,
        inbound: Some(&inbound_tag),
        process_name: None,
        user: None,
    };
    let outbound_tag = st.router.route(req);
    let outbound = match st.outbounds.get(&outbound_tag) {
        Some(o) => o.clone(),
        None => {
            warn!("SS 入站: 选中出站 `{outbound_tag}` 不存在");
            return;
        }
    };
    drop(st);
    debug!("SS 入站 {target} → 出站 [{outbound_tag}]");

    // 4. 经统一出站接口连目标 (connect_active: 真实流量标活跃, 保活底层组)。
    let out = match outbound.connect_active(&addr).await {
        Ok(s) => s,
        Err(e) => {
            warn!("SS 入站经出站 [{outbound_tag}] 连 {target} 失败: {e}");
            return;
        }
    };
    let (mut out_r, mut out_w) = tokio::io::split(out);

    // 首块附带的初始载荷 (我们的 SS 客户端 addr 单独成块 → 通常空; 通用客户端可能带)。
    if !initial.is_empty() && out_w.write_all(&initial).await.is_err() {
        return;
    }

    // 5. 双向 relay: 客户端(解密) ↔ 目标(明文)。
    use std::sync::atomic::{AtomicU64, Ordering};
    use crate::proxy::{idle_timeout, relay_idle, CopyResult, IdleClock, IdleElapsed, DRAIN_IDLE};

    let clock = IdleClock::new();
    let idle = relay_idle();
    let up_progress = AtomicU64::new(initial.len() as u64);
    let down_progress = AtomicU64::new(0);

    let up = async {
        let res = idle_timeout(&clock, idle, async {
            loop {
                match ssr.read_chunk().await {
                    Ok(b) if !b.is_empty() => {
                        out_w.write_all(&b).await?;
                        clock.touch();
                        up_progress.fetch_add(b.len() as u64, Ordering::Relaxed);
                    }
                    Ok(_) => break, // EOF
                    Err(e) => return Err(e),
                }
            }
            out_w.flush().await?;
            out_w.shutdown().await?;
            Ok::<(), std::io::Error>(())
        })
        .await;

        match res {
            Ok(Ok(())) => CopyResult::Finished(up_progress.load(Ordering::Relaxed)),
            Ok(Err(e)) => CopyResult::Err(e),
            Err(IdleElapsed) => CopyResult::Idle,
        }
    };

    let down = async {
        let res = idle_timeout(&clock, idle, async {
            let mut buf = vec![0u8; 16384];
            loop {
                match out_r.read(&mut buf).await {
                    Ok(0) => break,
                    Ok(n) => {
                        ssw.write_all(&buf[..n]).await?;
                        clock.touch();
                        down_progress.fetch_add(n as u64, Ordering::Relaxed);
                    }
                    Err(e) => return Err(e),
                }
            }
            // SsWriter 本身无 shutdown 方法, 取出底层写半程对其 shutdown, 向客户端传递半关闭 (FIN)。
            let mut raw_w = ssw.into_inner();
            raw_w.flush().await?;
            raw_w.shutdown().await?;
            Ok::<(), std::io::Error>(())
        })
        .await;

        match res {
            Ok(Ok(())) => CopyResult::Finished(down_progress.load(Ordering::Relaxed)),
            Ok(Err(e)) => CopyResult::Err(e),
            Err(IdleElapsed) => CopyResult::Idle,
        }
    };

    tokio::pin!(up);
    tokio::pin!(down);

    tokio::select! {
        r = &mut up => match r {
            CopyResult::Err(e) => {
                debug!("SS 入站 [{inbound_tag}] 上行出错: {e}");
            }
            CopyResult::Idle => {
                debug!("SS 入站 [{inbound_tag}] relay 空闲超时 ({}s)", idle.as_secs_f64());
            }
            CopyResult::Finished(up_n) => {
                if let Err(e) = crate::proxy::drain_wait(&mut down, &down_progress, DRAIN_IDLE).await {
                    debug!("SS 入站 [{inbound_tag}] 下行排空出错: {e}");
                }
                let down_n = down_progress.load(Ordering::Relaxed);
                debug!("SS 入站 [{inbound_tag}] relay 完成 (↑{up_n} ↓{down_n})");
            }
        },
        r = &mut down => match r {
            CopyResult::Err(e) => {
                debug!("SS 入站 [{inbound_tag}] 下行出错: {e}");
            }
            CopyResult::Idle => {
                debug!("SS 入站 [{inbound_tag}] relay 空闲超时 ({}s)", idle.as_secs_f64());
            }
            CopyResult::Finished(down_n) => {
                if let Err(e) = crate::proxy::drain_wait(&mut up, &up_progress, DRAIN_IDLE).await {
                    debug!("SS 入站 [{inbound_tag}] 上行排空出错: {e}");
                }
                let up_n = up_progress.load(Ordering::Relaxed);
                debug!("SS 入站 [{inbound_tag}] relay 完成 (↑{up_n} ↓{down_n})");
            }
        },
    }
}
