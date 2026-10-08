//! Auth 失败 / 读取异常时的伪装路径: 把已收到的原始字节原样转发到真实
//! `camouflage_host:443`, 表现得完全像普通 TLS 反向代理. GFW 探测打过来的
//! "任何 ClientHello" 都会得到一个来自真实站点的 ServerHello, 无识别特征.
//!
//! **对齐靠预连、容错靠判定期限** (见 `docs/client-hello-timing-design.md`):
//! - 正常路径: 服务端在 accept 后延迟 `preconnect_delay` 仍未见完整 ClientHello 时, 已在后台
//!   **推测性预连**一条伪装站连接 (`handshake.rs::Preconnect`)。真站的空闲计时从它 accept 起算,
//!   故探测者看到的关闭时间与"直连真站"只差一个预连触发延迟 (数十~数百 ms), 而非旧预热池的 8~14s。
//! - 这里优先使用那条预连 socket; 不可用 (或未预连) 才按需即时建连。
//! - 降级链: 预连/新连接 (写失败换一条重试一次, 覆盖 TOCTOU 死连接) → `HandshakeCache` 合成模板。
//!   写失败绝不能把 RST 暴露给探针 (与真实站点行为不一致 → 暴露 camouflage)。

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tracing::{debug, warn};

use super::CamouflageRtt;

/// 伪装站默认端口 (配置的 host 未带端口时)。
const CAMOUFLAGE_PORT: u16 = 443;
/// 单次 connect 尝试上限 (多候选 IP 逐个试)。
const CONNECT_ATTEMPT_TIMEOUT: Duration = Duration::from_secs(3);
/// 解析 + 连接的总预算 (与旧版单次 5s 超时同量级, 避免多候选叠加成十几秒)。
const CONNECT_TOTAL_TIMEOUT: Duration = Duration::from_secs(5);
/// 最多尝试几个候选 IP (CDN 常有多个 A 记录; IPv4 已由 resolver 排在前)。
const MAX_CANDIDATES: usize = 3;

/// 连一条伪装站连接 (推测性预连与按需转发共用)。
///
/// - **解析**走 `proxy::resolver` 的 60s 缓存 (并尊重 `tuning.dns_tcp_resolver`), 且**排在计时
///   之外**; 于是 `observe_connect` 收到的是**纯 TCP connect RTT** —— auth-succ 的时序注入量
///   (`2 × cam_RTT`) 才准。旧实现每次 `TcpStream::connect(host:443)` 都走 `getaddrinfo`(无 nscd
///   时不缓存), 既把 DNS 塞进探测转发的关键路径, 又把 DNS 耗时混进了 RTT 样本。
/// - 返回 None = 解析失败 / 所有候选连接失败 (调用方回落合成模板)。
pub(super) async fn connect_camouflage(
    host: &str,
    cam_rtt: &Arc<CamouflageRtt>,
) -> Option<TcpStream> {
    let (h, port) = crate::proxy::resolver::split_host_port(host).unwrap_or((host, CAMOUFLAGE_PORT));

    let candidates: Vec<IpAddr> = match h.parse::<IpAddr>() {
        Ok(ip) => vec![ip], // IP 字面量: 无需解析
        Err(_) => match crate::proxy::resolver::resolve_cached(h, port).await {
            Ok(v) if !v.is_empty() => v,
            Ok(_) => {
                warn!("camouflage_host `{h}` 解析结果为空");
                return None;
            }
            Err(e) => {
                warn!("camouflage_host `{h}` 解析失败: {e}");
                return None;
            }
        },
    };

    let deadline = Instant::now() + CONNECT_TOTAL_TIMEOUT;
    for ip in candidates.into_iter().take(MAX_CANDIDATES) {
        let remain = deadline.saturating_duration_since(Instant::now());
        if remain.is_zero() {
            break;
        }
        let sa = SocketAddr::new(ip, port);
        let t0 = Instant::now();
        match tokio::time::timeout(remain.min(CONNECT_ATTEMPT_TIMEOUT), TcpStream::connect(sa)).await
        {
            Ok(Ok(s)) => {
                // 只测 TCP connect (解析在计时之外) → RTT 样本纯净。
                cam_rtt.observe_connect(t0.elapsed());
                return Some(s);
            }
            Ok(Err(e)) => debug!("camouflage connect {sa} failed: {e}"),
            Err(_) => debug!("camouflage connect {sa} timed out"),
        }
    }
    warn!("camouflage_host `{h}` 所有候选均未能建连 (预算 {CONNECT_TOTAL_TIMEOUT:?})");
    None
}

/// 尝试用一条 camouflage 连接转发探针握手. 成功发出 client_hello (证明连接活着)
/// 就显式读取真站返回的首块数据, 记录首字节往返时延 F (仅当 t_start.is_some(), 即 preconnect==0 时采样),
/// 再将首块写回并双向透传到底.
/// probe 泛型 (TCP=TcpStream, QUIC=QuicBiStream): auth 失败路径对任意传输一致伪装。
async fn try_forward<S>(
    probe: &mut S,
    mut cam: TcpStream,
    client_hello: &[u8],
    cam_rtt: &Arc<CamouflageRtt>,
    t_start: Option<Instant>,
) -> Result<(), ()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    if cam.write_all(client_hello).await.is_err() {
        return Err(());
    }

    // 显式读取伪装站的首块数据: 得到首字节确切到达时刻 T1 (F = T1 - T0)
    let mut first_buf = [0u8; 4096];
    let n = match cam.read(&mut first_buf).await {
        Ok(n) if n > 0 => n,
        _ => return Err(()),
    };

    // 关键设计: 仅当 preconnect==0 (即时建连, 无池) 时采样, 避免混采预连连接导致两档漂移
    if let Some(t0) = t_start {
        let elapsed_us = t0.elapsed().as_micros() as u64;
        cam_rtt.observe_fail_forward(elapsed_us);
    }

    if probe.write_all(&first_buf[..n]).await.is_err() {
        return Err(());
    }

    let _ = tokio::time::timeout(
        std::time::Duration::from_secs(300),
        tokio::io::copy_bidirectional(probe, &mut cam),
    )
    .await;
    Ok(())
}

pub(super) async fn run_camouflage_forward<S>(
    mut stream: S,
    client_hello: &[u8],
    camouflage_host: &str,
    cam_rtt: &Arc<CamouflageRtt>,
    preconnected: Option<TcpStream>,
) where
    S: AsyncRead + AsyncWrite + Unpin,
{
    // 1. 推测性预连的 socket 优先 —— 它的 connect 时刻 ≈ 探测者连上 + 预连触发延迟, 于是真站的
    //    空闲计时起点与"直连真站"基本一致 (**对齐**)。写失败 (TOCTOU 死连接) 才换按需建连。
    //
    //    至多两次"取连接 → 转发": 首次用预连(或按需), 写失败则再建一条重试; 都失败落合成模板。
    //    (connect 失败本身不重试: 多候选 IP 已在 connect_camouflage 内逐个试过, 立刻重试无益且会
    //     叠加超时 —— 此时快速回落模板更贴近"伪装站不可达"的真实行为。)
    let mut cam = preconnected;
    for attempt in 0..2 {
        let is_on_demand = cam.is_none();
        // 仅在即时建连 (preconnect==0) 时记录 T0, 供首字节到达 T1 采样 F
        let t_start = if is_on_demand { Some(Instant::now()) } else { None };
        let sock = match cam.take() {
            Some(s) => s,
            None => match connect_camouflage(camouflage_host, cam_rtt).await {
                Some(s) => s,
                None => break, // 伪装站不可达 → 合成模板兜底
            },
        };
        if try_forward(&mut stream, sock, client_hello, cam_rtt, t_start).await.is_ok() {
            return;
        }
        debug!(
            "Mirage Server: camouflage forward write failed (attempt {}/2), 换一条新连接重试",
            attempt + 1
        );
    }

    // 2. camouflage_host 不可达, 回落 HandshakeCache 合成模板。仅当探针发来的像 TLS 握手
    //    (首字节 0x16) 才回 ServerHello; 明文探测 / 0 字节超时回 ServerHello 反成特征, 直接断开。
    if client_hello.first() != Some(&0x16) {
        return;
    }
    let template =
        crate::crypto::handshake_cache::get_server_hello(camouflage_host, client_hello).await;
    let _ = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        stream.write_all(&template),
    )
    .await;
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tokio::io::AsyncReadExt;
    use tokio::net::TcpListener;

    /// 核心行为: **按需即时建连** —— 触发转发前不产生任何到伪装站的连接 (旧预热池会后台
    /// 持续建连), 触发后恰好新建一条。这是消除 T2/T3 "池龄传导给真站 idle-timeout"
    /// 侧信道的机制断言 (确定性: 只看连接数, 不依赖壁钟时序)。
    #[tokio::test]
    async fn forward_connects_on_demand_not_before() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let conns = Arc::new(AtomicUsize::new(0));
        let c = conns.clone();
        tokio::spawn(async move {
            while let Ok((mut sock, _)) = listener.accept().await {
                c.fetch_add(1, Ordering::SeqCst);
                tokio::spawn(async move {
                    let mut b = [0u8; 64];
                    let _ = sock.read(&mut b).await;
                    let _ = sock.write_all(b"ok").await;
                    tokio::time::sleep(Duration::from_secs(2)).await; // hold
                });
            }
        });

        let cam_rtt = CamouflageRtt::new();
        // 触发前静置: 不得有任何连接 (旧池此处会有后台预连 churn)。
        tokio::time::sleep(Duration::from_millis(400)).await;
        assert_eq!(conns.load(Ordering::SeqCst), 0, "触发转发前不得有后台预连 (旧池行为)");

        // 触发一次转发 (probe 用 duplex 的 server 端当被转发方; 未预连 → 走按需建连)。
        let (_probe_peer, probe) = tokio::io::duplex(1024);
        let host = addr.to_string();
        let rtt = cam_rtt.clone();
        let h = tokio::spawn(async move {
            run_camouflage_forward(probe, b"\x16\x03\x01\x00\x05hello", &host, &rtt, None).await;
        });

        for _ in 0..50 {
            if conns.load(Ordering::SeqCst) > 0 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert_eq!(conns.load(Ordering::SeqCst), 1, "触发转发后应恰好新建一条连接");
        assert!(cam_rtt.rtt_us() > 0, "即时建连应更新 RTT 估计 (供 auth-succ 时序对齐)");
        h.abort();
    }

    /// 预连 socket 优先: 传入已建好的 socket 时**不得**再新建连接 (对齐依赖它)。
    #[tokio::test]
    async fn preconnected_socket_is_used_without_new_connect() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let conns = Arc::new(AtomicUsize::new(0));
        let c = conns.clone();
        tokio::spawn(async move {
            while let Ok((mut sock, _)) = listener.accept().await {
                c.fetch_add(1, Ordering::SeqCst);
                tokio::spawn(async move {
                    let mut b = [0u8; 64];
                    let _ = sock.read(&mut b).await;
                    let _ = sock.write_all(b"ok").await;
                    tokio::time::sleep(Duration::from_secs(2)).await;
                });
            }
        });

        // 先手工建一条 (模拟预连), 再交给 run_camouflage_forward。
        let cam_rtt = CamouflageRtt::new();
        let pre = connect_camouflage(&addr.to_string(), &cam_rtt).await.expect("预连应成功");
        // accept 侧是异步的, 等它计数 (不直接断言, 否则是测试竞态)。
        for _ in 0..50 {
            if conns.load(Ordering::SeqCst) > 0 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert_eq!(conns.load(Ordering::SeqCst), 1, "预连应恰好一条");
        let before_rtt = cam_rtt.rtt_us();
        assert!(before_rtt > 0, "预连自身就是 RTT 样本");

        let (_probe_peer, probe) = tokio::io::duplex(1024);
        let host = addr.to_string();
        let rtt = cam_rtt.clone();
        let h = tokio::spawn(async move {
            run_camouflage_forward(probe, b"\x16\x03\x01\x00\x05hello", &host, &rtt, Some(pre)).await;
        });
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert_eq!(conns.load(Ordering::SeqCst), 1, "已有预连时不得再新建连接");
        h.abort();
    }
}
