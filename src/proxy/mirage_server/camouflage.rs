//! Auth 失败时的伪装路径: 把请求原样转发到真实 camouflage_host:443, 表现得
//! 完全像普通 TLS 反向代理. GFW 探测打过来的"任何 ClientHello" 都会得到一个
//! 来自真实站点的 ServerHello, 无任何识别特征.
//!
//! 不可达时退回 HandshakeCache (启动时预取的真实 ServerHello 模板).

use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;

pub(super) async fn run_camouflage_forward(
    mut stream: TcpStream,
    client_hello: &[u8],
    camouflage_host: &str,
) {
    if let Ok(mut cam_stream) = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        TcpStream::connect(&format!("{}:443", camouflage_host))
    ).await.unwrap_or(Err(std::io::Error::new(std::io::ErrorKind::TimedOut, "Camouflage connect timeout"))) {
        let _ = cam_stream.write_all(client_hello).await;
        let _ = tokio::time::timeout(
            std::time::Duration::from_secs(300),
            tokio::io::copy_bidirectional(&mut stream, &mut cam_stream)
        ).await;
    } else {
        // camouflage_host is unreachable, fallback to HandshakeCache
        let template = crate::crypto::handshake_cache::get_server_hello(camouflage_host, client_hello).await;
        let _ = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            stream.write_all(&template)
        ).await;
    }
}
