//! Auth 失败时的伪装路径: 把请求原样转发到真实 camouflage_host:443, 表现得
//! 完全像普通 TLS 反向代理. GFW 探测打过来的"任何 ClientHello" 都会得到一个
//! 来自真实站点的 ServerHello, 无任何识别特征.
//!
//! v0.4.5-alpha.7: 优先从 CamouflagePool 拿 pre-warmed TCP 连接 (省一个 TCP
//! 3-way RTT, 消除跟 auth-succ 分支的时序侧信道). 池空 → 降级到即时 connect
//! (跟老版行为一致). 连 connect 都失败 → 降级到 HandshakeCache 模板回应.

use std::sync::Arc;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;

use super::CamouflagePool;

pub(super) async fn run_camouflage_forward(
    mut stream: TcpStream,
    client_hello: &[u8],
    camouflage_host: &str,
    cam_pool: &Arc<CamouflagePool>,
) {
    // Fast path: pool 里有 pre-warmed 连接就直接用, 省 TCP 3-way RTT.
    let pooled = cam_pool.acquire().await;

    let cam_stream: Option<TcpStream> = if let Some(s) = pooled {
        Some(s)
    } else {
        // Fallback: 即时 connect
        tokio::time::timeout(
            std::time::Duration::from_secs(5),
            TcpStream::connect(&format!("{}:443", camouflage_host)),
        )
        .await
        .ok()
        .and_then(|r| r.ok())
    };

    if let Some(mut cam_stream) = cam_stream {
        let _ = cam_stream.write_all(client_hello).await;
        let _ = tokio::time::timeout(
            std::time::Duration::from_secs(300),
            tokio::io::copy_bidirectional(&mut stream, &mut cam_stream),
        )
        .await;
    } else {
        // camouflage_host is unreachable, fallback to HandshakeCache
        let template =
            crate::crypto::handshake_cache::get_server_hello(camouflage_host, client_hello).await;
        let _ = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            stream.write_all(&template),
        )
        .await;
    }
}
