//! 服务端 TCP 上游转发. 收到 target 后建立 TCP 连接, 双向 copy.
//!
//! 1800s = 30min 双向超时 - 给长连接 (WebSocket / 大文件下载) 留余量.

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tracing::{debug, warn};

pub(super) async fn handle_tcp_relay(
    target: String,
    initial_payload: Option<Vec<u8>>,
    mut reader: crate::crypto::aead::CryptoReader<tokio::net::tcp::OwnedReadHalf>,
    mut writer: crate::crypto::aead::CryptoWriter<tokio::net::tcp::OwnedWriteHalf>
) {
    debug!("Mirage Server: Connecting to TCP target {}", target);
    let mut upstream = match tokio::net::TcpStream::connect(&target).await {
        Ok(s) => s,
        Err(e) => {
            warn!("Mirage Server failed to connect to {}: {}", target, e);
            return;
        }
    };

    if let Some(payload) = initial_payload {
        if !payload.is_empty() {
            let _ = upstream.write_all(&payload).await;
        }
    }

    let (mut up_read, mut up_write) = upstream.into_split();

    let upload = async {
        loop {
            match tokio::time::timeout(std::time::Duration::from_secs(1800), reader.recv_data()).await {
                Ok(Ok(data)) => {
                    if up_write.write_all(&data).await.is_err() {
                        break;
                    }
                }
                _ => break,
            }
        }
    };

    let download = async {
        let mut buf = [0u8; 16384];
        loop {
            match tokio::time::timeout(std::time::Duration::from_secs(1800), up_read.read(&mut buf)).await {
                Ok(Ok(0)) => break,
                Ok(Ok(n)) => {
                    if writer.send_data(&buf[..n]).await.is_err() {
                        break;
                    }
                }
                _ => break,
            }
        }
        let _ = writer.send_close_notify().await;
    };

    tokio::join!(upload, download);
}
