// Tests for src/proxy/sniff.rs (TLS SNI + HTTP Host extraction).
// Uses a loopback TcpListener so sniff_first_kb can peek real bytes.

use mirage_rs::proxy::sniff::sniff_first_kb;
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream};

/// Build a minimal valid TLS 1.3 ClientHello with given SNI.
/// Layout: [Record header 5B][Handshake header 4B][ClientHello body]
fn build_tls_client_hello(sni: &str) -> Vec<u8> {
    let sni_bytes = sni.as_bytes();

    // SNI extension: type=0, list_len=2+1+2+name, server_name_list=[type=0, len=N, bytes]
    let server_name = {
        let mut v = Vec::new();
        v.push(0u8); // name_type = host_name
        v.extend_from_slice(&(sni_bytes.len() as u16).to_be_bytes());
        v.extend_from_slice(sni_bytes);
        v
    };
    let sni_list = {
        let mut v = Vec::new();
        v.extend_from_slice(&(server_name.len() as u16).to_be_bytes());
        v.extend_from_slice(&server_name);
        v
    };
    let sni_ext = {
        let mut v = Vec::new();
        v.extend_from_slice(&0u16.to_be_bytes()); // extension_type = server_name
        v.extend_from_slice(&(sni_list.len() as u16).to_be_bytes());
        v.extend_from_slice(&sni_list);
        v
    };
    let extensions = {
        let mut v = Vec::new();
        v.extend_from_slice(&(sni_ext.len() as u16).to_be_bytes());
        v.extend_from_slice(&sni_ext);
        v
    };

    let client_hello_body = {
        let mut v = Vec::new();
        v.extend_from_slice(&[0x03, 0x03]); // legacy_version TLS 1.2
        v.extend_from_slice(&[0u8; 32]); // random
        v.push(0); // session_id length
        v.extend_from_slice(&2u16.to_be_bytes()); // cipher_suites length
        v.extend_from_slice(&[0x13, 0x01]); // TLS_AES_128_GCM_SHA256
        v.push(1); // compression_methods length
        v.push(0); // null compression
        v.extend_from_slice(&extensions);
        v
    };

    let handshake = {
        let mut v = vec![0x01]; // handshake_type = ClientHello
        let body_len = client_hello_body.len() as u32;
        v.extend_from_slice(&body_len.to_be_bytes()[1..]); // 24-bit length
        v.extend_from_slice(&client_hello_body);
        v
    };

    let mut record = vec![0x16, 0x03, 0x01]; // content_type=Handshake, version=TLS 1.0
    record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
    record.extend_from_slice(&handshake);
    record
}

/// Helper: spin up a loopback server, send `payload` from client side,
/// run sniff_first_kb on the server-accepted stream.
async fn sniff_with_payload(payload: Vec<u8>) -> Option<String> {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();

    tokio::spawn(async move {
        let mut s = TcpStream::connect(format!("127.0.0.1:{}", port))
            .await
            .unwrap();
        s.write_all(&payload).await.unwrap();
        // Keep client side alive so server can peek
        tokio::time::sleep(std::time::Duration::from_secs(3)).await;
    });

    let (stream, _) = listener.accept().await.unwrap();
    // Give client time to write before peeking
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    sniff_first_kb(&stream).await
}

#[tokio::test]
async fn test_sniff_tls_sni() {
    let hello = build_tls_client_hello("www.example.com");
    let sniffed = sniff_with_payload(hello).await;
    assert_eq!(sniffed, Some("www.example.com".to_string()));
}

#[tokio::test]
async fn test_sniff_tls_sni_long_domain() {
    let domain = "very-long-subdomain-name.deep.tree.example.com";
    let hello = build_tls_client_hello(domain);
    let sniffed = sniff_with_payload(hello).await;
    assert_eq!(sniffed, Some(domain.to_string()));
}

#[tokio::test]
async fn test_sniff_http_get() {
    let req = b"GET / HTTP/1.1\r\nHost: github.com\r\nUser-Agent: curl/8.0\r\n\r\n".to_vec();
    let sniffed = sniff_with_payload(req).await;
    assert_eq!(sniffed, Some("github.com".to_string()));
}

#[tokio::test]
async fn test_sniff_http_host_with_port() {
    // Sniffer should strip port from host header
    let req = b"POST /api HTTP/1.1\r\nHost: api.example.com:8080\r\n\r\n".to_vec();
    let sniffed = sniff_with_payload(req).await;
    assert_eq!(sniffed, Some("api.example.com".to_string()));
}

#[tokio::test]
async fn test_sniff_http_body_with_host_string_ignored() {
    // Regression: HTTP body containing "Host: " line must not be parsed as a header
    // (the sniffer must stop at the \r\n\r\n header/body boundary)
    let req = b"POST /api HTTP/1.1\r\nHost: real.example.com\r\nContent-Type: text/plain\r\n\r\nHost: fake.attacker.com\r\n".to_vec();
    let sniffed = sniff_with_payload(req).await;
    assert_eq!(sniffed, Some("real.example.com".to_string()));
}

#[tokio::test]
async fn test_sniff_timeout_on_slow_client() {
    // A client that connects but sends nothing → sniff should return None within ~2s
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();

    tokio::spawn(async move {
        // Slow client: connect but don't write
        let _s = TcpStream::connect(format!("127.0.0.1:{}", port)).await.unwrap();
        tokio::time::sleep(std::time::Duration::from_secs(10)).await;
    });

    let (stream, _) = listener.accept().await.unwrap();

    let start = std::time::Instant::now();
    let sniffed = sniff_first_kb(&stream).await;
    let elapsed = start.elapsed();

    assert_eq!(sniffed, None);
    assert!(
        elapsed < std::time::Duration::from_secs(3),
        "Sniff should time out within ~2s, took {:?}",
        elapsed
    );
}

#[tokio::test]
async fn test_sniff_unknown_protocol_returns_none() {
    let garbage = b"\x00\x01\x02\x03random binary garbage".to_vec();
    let sniffed = sniff_with_payload(garbage).await;
    assert_eq!(sniffed, None);
}
