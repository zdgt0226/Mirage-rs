mod common;

use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

async fn start_echo_server() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();

    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut buf = [0u8; 1024];
                if let Ok(n) = stream.read(&mut buf).await {
                    let _ = stream.write_all(&buf[..n]).await;
                }
            });
        }
    });

    port
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_echo_server_baseline() {
    let port = start_echo_server().await;
    let mut stream = TcpStream::connect(format!("127.0.0.1:{}", port)).await.unwrap();

    stream.write_all(b"hello world").await.unwrap();
    let mut buf = [0u8; 1024];
    let n = stream.read(&mut buf).await.unwrap();

    assert_eq!(&buf[..n], b"hello world");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_full_e2e_proxy() {
    let echo_port = start_echo_server().await;
    let ports = common::free_ports(2);
    let server_port = ports[0];
    let socks_port = ports[1];

    let server_config = serde_json::json!({
        "inbounds": [{
            "type": "mirage_server",
            "tag": "server_in",
            "listen": "127.0.0.1",
            "port": server_port,
            "password": "test_password",
            "camouflage_host": common::TEST_CAMOUFLAGE_HOST,
            "allow_local_targets": true
        }],
        "outbounds": [{
            "type": "direct",
            "tag": "direct"
        }],
        "routing": {
            "default_outbound": "direct",
            "rules": []
        }
    });

    let client_config = serde_json::json!({
        "inbounds": [{
            "type": "socks",
            "tag": "socks_in",
            "listen": "127.0.0.1",
            "port": socks_port
        }],
        "outbounds": [{
            "type": "pyreality",
            "tag": "proxy",
            "server": "127.0.0.1",
            "server_port": server_port,
            "password": "test_password",
            "camouflage_host": common::TEST_CAMOUFLAGE_HOST,
            "pool_size": 1
        }],
        "routing": {
            "default_outbound": "proxy",
            "rules": []
        }
    });

    let tmp = common::TempTestDir::new("integration");
    let server_cfg = tmp.write_file("server_config.json", &serde_json::to_string_pretty(&server_config).unwrap());
    let client_cfg = tmp.write_file("client_config.json", &serde_json::to_string_pretty(&client_config).unwrap());

    let srv_str = server_cfg.to_str().unwrap().to_string();
    let cli_str = client_cfg.to_str().unwrap().to_string();

    tokio::spawn(async move {
        let _ = mirage_rs::start_proxy(&srv_str, true).await;
    });

    tokio::spawn(async move {
        let _ = mirage_rs::start_proxy(&cli_str, false).await;
    });

    assert!(
        common::wait_tcp_ready_async(&format!("127.0.0.1:{}", server_port), Duration::from_secs(10)).await,
        "Mirage server listening timed out"
    );
    assert!(
        common::wait_tcp_ready_async(&format!("127.0.0.1:{}", socks_port), Duration::from_secs(10)).await,
        "SOCKS client listening timed out"
    );

    println!("Connecting to SOCKS5 client...");
    let mut stream = tokio::time::timeout(tokio::time::Duration::from_secs(5), TcpStream::connect(format!("127.0.0.1:{}", socks_port))).await.unwrap().unwrap();

    println!("Sending SOCKS5 Handshake...");
    // SOCKS5 Handshake
    tokio::time::timeout(tokio::time::Duration::from_secs(5), stream.write_all(&[0x05, 0x01, 0x00])).await.unwrap().unwrap();
    let mut auth_resp = [0u8; 2];
    tokio::time::timeout(tokio::time::Duration::from_secs(5), stream.read_exact(&mut auth_resp)).await.unwrap().unwrap();
    assert_eq!(auth_resp, [0x05, 0x00]);

    println!("Sending SOCKS5 Connect Request...");
    // SOCKS5 Connect Request to Echo Server
    let mut req = vec![0x05, 0x01, 0x00, 0x01, 127, 0, 0, 1];
    req.extend_from_slice(&echo_port.to_be_bytes());
    tokio::time::timeout(tokio::time::Duration::from_secs(5), stream.write_all(&req)).await.unwrap().unwrap();

    println!("Waiting for SOCKS5 Connect Response...");
    let mut resp = [0u8; 10];
    tokio::time::timeout(tokio::time::Duration::from_secs(5), stream.read_exact(&mut resp)).await.unwrap().unwrap();
    assert_eq!(resp[0..4], [0x05, 0x00, 0x00, 0x01]);

    println!("Sending payload...");
    // Send payload
    let payload = b"hello full e2e proxy through mirage!";
    tokio::time::timeout(tokio::time::Duration::from_secs(5), stream.write_all(payload)).await.unwrap().unwrap();

    println!("Reading payload...");
    // Read payload
    let mut buf = [0u8; 1024];
    let n = tokio::time::timeout(tokio::time::Duration::from_secs(5), stream.read(&mut buf)).await.unwrap().unwrap();
    assert_eq!(&buf[..n], payload);

    println!("Test complete!");
}
