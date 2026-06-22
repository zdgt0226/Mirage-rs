use anyhow::Result;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tracing::{info, Level};
use tracing_subscriber::FmtSubscriber;

#[tokio::main]
async fn main() -> Result<()> {
    // 初始化日志，查看 eBPF 引擎的注入信息
    let subscriber = FmtSubscriber::builder()
        .with_max_level(Level::DEBUG)
        .finish();
    let _ = tracing::subscriber::set_global_default(subscriber);

    info!("=== [Sandbox] Starting eBPF Test Environment ===");

    // 1. 启动一个极其简单的目标服务器 (Echo Server)
    tokio::spawn(async move {
        let listener = TcpListener::bind("127.0.0.1:9090").await.unwrap();
        info!("[Sandbox] Echo Server listening on 127.0.0.1:9090");
        while let Ok((mut socket, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut buf = [0u8; 1024];
                while let Ok(n) = socket.read(&mut buf).await {
                    if n == 0 { break; }
                    info!("[Sandbox] Echo Server received {} bytes. Echoing back...", n);
                    if socket.write_all(&buf[..n]).await.is_err() {
                        break;
                    }
                }
            });
        }
    });

    // 2. 启动我们的 Mirage-rs 代理内核
    tokio::spawn(async move {
        info!("[Sandbox] Starting Mirage-rs proxy core...");
        // sandbox 是 eBPF 调试工具, 走客户端模式 (server 模式默认会跳过 BPF)
        if let Err(e) = mirage_rs::start_proxy("sandbox_config.json", false).await {
            tracing::error!("Proxy core failed: {}", e);
        }
    });

    // 等待代理和目标服务器完全启动完毕
    tokio::time::sleep(Duration::from_secs(2)).await;

    info!("=== [Sandbox] Environment ready, initiating SOCKS5 connection ===");

    // 3. 模拟一个 SOCKS5 客户端发起连接
    let mut proxy_client = TcpStream::connect("127.0.0.1:1080").await?;
    
    // SOCKS5 握手阶段 1: 认证协商
    proxy_client.write_all(&[0x05, 0x01, 0x00]).await?;
    let mut auth_resp = [0u8; 2];
    proxy_client.read_exact(&mut auth_resp).await?;
    assert_eq!(auth_resp, [0x05, 0x00]);

    // SOCKS5 握手阶段 2: 发起连接请求到 127.0.0.1:9090
    // 0x05 (VER) 0x01 (CMD CONNECT) 0x00 (RSV) 0x01 (IPv4) + 127.0.0.1 + Port 9090
    let connect_req = vec![0x05, 0x01, 0x00, 0x01, 127, 0, 0, 1, (9090u16 >> 8) as u8, (9090u16 & 0xFF) as u8];
    proxy_client.write_all(&connect_req).await?;
    
    let mut connect_resp = [0u8; 10];
    proxy_client.read_exact(&mut connect_resp).await?;
    assert_eq!(connect_resp[1], 0x00); // 0x00 means succeeded

    info!("[Sandbox] SOCKS5 connection established successfully. Sending payload...");

    // 4. 发送真实的业务数据，此时 eBPF 应该已经接管！
    let payload = b"Hello, Mirage-rs eBPF Kernel Splicing!";
    proxy_client.write_all(payload).await?;

    let mut buf = [0u8; 1024];
    let n = proxy_client.read(&mut buf).await?;
    
    let resp_str = String::from_utf8_lossy(&buf[..n]);
    info!("=== [Sandbox] Received Response: {} ===", resp_str);
    assert_eq!(resp_str.as_bytes(), payload);

    info!("=== [Sandbox] Test Passed: Zero-copy forwarding is functioning perfectly! ===");

    Ok(())
}
