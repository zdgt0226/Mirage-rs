//! Auth 失败时的伪装路径: 把请求原样转发到真实 camouflage_host:443, 表现得
//! 完全像普通 TLS 反向代理. GFW 探测打过来的"任何 ClientHello" 都会得到一个
//! 来自真实站点的 ServerHello, 无任何识别特征.
//!
//! v0.4.5-alpha.7: 优先从 CamouflagePool 拿 pre-warmed TCP 连接 (省一个 TCP
//! 3-way RTT, 消除跟 auth-succ 分支的时序侧信道).
//!
//! v0.4.5-alpha.12: 三级降级 + 写失败探测. 池的 acquire 已探活跳过死连接, 但仍
//! 有微秒级 TOCTOU 竞态 (拿到时活, 写入前对端刚关). 若转发写入 ClientHello 即
//! 失败, 决不能把 RST 暴露给探针 (与真实站点行为不一致 → 暴露 camouflage), 而是
//! 换一条即时新建的连接重试; 都不行才回落 HandshakeCache 合成模板.

use std::sync::Arc;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;

use super::CamouflagePool;

/// 尝试用一条 camouflage 连接转发探针握手. 成功发出 client_hello (证明连接活着)
/// 就接着双向转发到底, 返回 Ok; 发送即失败 (死连接) 返回 Err 让上层换连接.
async fn try_forward(probe: &mut TcpStream, mut cam: TcpStream, client_hello: &[u8]) -> Result<(), ()> {
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

pub(super) async fn run_camouflage_forward(
    mut stream: TcpStream,
    client_hello: &[u8],
    camouflage_host: &str,
    cam_pool: &Arc<CamouflagePool>,
) {
    // 1. Fast path: pool 里的 pre-warmed 连接 (已探活). 写失败 (TOCTOU 死连接)
    //    则 fall through 换即时新建.
    if let Some(cam) = cam_pool.acquire().await {
        if try_forward(&mut stream, cam, client_hello).await.is_ok() {
            return;
        }
    }

    // 2. 即时 connect camouflage_host:443
    if let Ok(Ok(cam)) = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        TcpStream::connect(&format!("{}:443", camouflage_host)),
    )
    .await
    {
        if try_forward(&mut stream, cam, client_hello).await.is_ok() {
            return;
        }
    }

    // 3. camouflage_host 不可达, 回落 HandshakeCache 合成模板
    let template =
        crate::crypto::handshake_cache::get_server_hello(camouflage_host, client_hello).await;
    let _ = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        stream.write_all(&template),
    )
    .await;
}
