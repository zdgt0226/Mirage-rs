//! Auth 失败 / 读取异常时的伪装路径: 把已收到的原始字节原样转发到真实
//! `camouflage_host:443`, 表现得完全像普通 TLS 反向代理. GFW 探测打过来的
//! "任何 ClientHello" 都会得到一个来自真实站点的 ServerHello, 无识别特征.
//!
//! **延迟预连 (取代预热池)**: 旧实现优先从后台 `CamouflagePool` 取 pre-warmed 连接,
//! 但池中连接的**已存在时长**会被真站的 idle-timeout 继承 —— 探测者看到的关闭时间
//! = 真站超时 − 池龄, 实测提前 8~14s (T2/T3 可区分)。现在在**判定要转发的这一刻**
//! 即时建连: 真站 idle 计时起点与探测者连上的时刻只差一个服务器→伪装站 RTT, 偏差
//! 落回亚秒级; 且不再有后台常驻连接打伪装站。见 `camouflage_rtt.rs` 顶注释。
//!
//! 降级链: 即时建连 (失败重试一次, 覆盖 TOCTOU 死连接) → `HandshakeCache` 合成模板。
//! 写失败绝不能把 RST 暴露给探针 (与真实站点行为不一致 → 暴露 camouflage)。

use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;

use super::CamouflageRtt;

/// 尝试用一条 camouflage 连接转发探针握手. 成功发出 client_hello (证明连接活着)
/// 就接着双向转发到底, 返回 Ok; 发送即失败 (死连接) 返回 Err 让上层重试.
/// probe 泛型 (TCP=TcpStream, QUIC=QuicBiStream): auth 失败路径对任意传输一致伪装。
async fn try_forward<S>(probe: &mut S, mut cam: TcpStream, client_hello: &[u8]) -> Result<(), ()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    if cam.write_all(client_hello).await.is_err() {
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
) where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let addr = crate::net_util::host_with_default_port(camouflage_host, 443);

    // 1. 判定要转发的此刻即时建连 (无池龄)。失败重试一次覆盖伪装站瞬时抖动 / 写前死连接。
    //    建连耗时 ≈ 1 RTT, 喂给 EWMA 供 auth-succ 时序对齐 (仅真实转发时才有样本)。
    for attempt in 0..2 {
        let t0 = Instant::now();
        match tokio::time::timeout(Duration::from_secs(5), TcpStream::connect(&addr)).await {
            Ok(Ok(cam)) => {
                cam_rtt.observe_connect(t0.elapsed());
                if try_forward(&mut stream, cam, client_hello).await.is_ok() {
                    return;
                }
                tracing::debug!(
                    "Mirage Server: camouflage forward write failed (attempt {}/2), retrying",
                    attempt + 1
                );
            }
            Ok(Err(e)) => {
                tracing::warn!("Mirage Server: camouflage connect {} failed: {}", addr, e);
                break;
            }
            Err(_) => {
                tracing::warn!("Mirage Server: camouflage connect {} timeout", addr);
                break;
            }
        }
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

        // 触发一次转发 (probe 用 duplex 的 server 端当被转发方)。
        let (_probe_peer, probe) = tokio::io::duplex(1024);
        let host = addr.to_string();
        let rtt = cam_rtt.clone();
        let h = tokio::spawn(async move {
            run_camouflage_forward(probe, b"\x16\x03\x01\x00\x05hello", &host, &rtt).await;
        });

        // 等 connect 完成 (触发后才建)。
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
}
