//! Mirage 协议握手: 解析 TLS ClientHello + Poly1305 token 校验 + ServerHello
//! 模拟回放 + 63B fake Client Finished tail 消费.
//!
//! 通过的连接继续走 `control::dispatch_authenticated` 建立加密 channel.
//! 失败的连接走 `camouflage::run_camouflage_forward` 伪装成正常 TLS 转发.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::Ordering;
use std::sync::Mutex;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tracing::warn;

use super::camouflage;
use super::control;
use super::{IpSlotGuard, GLOBAL_UNAUTH, UNAUTH_CONNS};

pub(super) async fn handle_connection(
    mut stream: TcpStream,
    peer_addr: SocketAddr,
    password: String,
    camouflage_host: String,
) {
    stream.set_nodelay(true).unwrap_or_default();

    // 1. Parse ClientHello
    let mut hello_buf = vec![0u8; 1024];
    let n = match tokio::time::timeout(std::time::Duration::from_secs(5), stream.read(&mut hello_buf)).await {
        Ok(Ok(n)) if n > 0 => n,
        _ => return,
    };
    let client_hello = &hello_buf[..n];

    // Authenticate by searching for the token
    let mut authenticated = false;
    let mut client_random = [0u8; 32];

    if client_hello.len() >= 43 && client_hello[0] == 0x16 && client_hello[5] == 0x01 {
        let sid_len = client_hello[43] as usize;
        if client_hello.len() >= 44 + sid_len {
            let session_id = &client_hello[44..44+sid_len];
            if session_id.len() == 32 {
                let mut sid_array = [0u8; 32];
                sid_array.copy_from_slice(session_id);
                if crate::crypto::hello_auth::verify_session_token(&password, &sid_array) {
                    authenticated = true;
                    client_random.copy_from_slice(&client_hello[11..43]);
                }
            }
        }
    }

    if !authenticated {
        warn!("Mirage Server auth failed from {}", peer_addr);

        let global_count = GLOBAL_UNAUTH.fetch_add(1, Ordering::SeqCst);
        if global_count >= 5000 {
            GLOBAL_UNAUTH.fetch_sub(1, Ordering::SeqCst);
            return;
        }

        let ip = peer_addr.ip();
        let _slot_guard = {
            let mut map = UNAUTH_CONNS.get_or_init(|| Mutex::new(HashMap::new())).lock().unwrap();
            let count = map.entry(ip).or_insert(0);
            if *count >= 100 {
                GLOBAL_UNAUTH.fetch_sub(1, Ordering::SeqCst);
                return;
            }
            *count += 1;
            IpSlotGuard(ip)
        };

        camouflage::run_camouflage_forward(stream, client_hello, &camouflage_host).await;

        return;
    }

    // 2.5 Send ServerHello template back to satisfy Mirage Client's TLS state machine
    let template = crate::crypto::handshake_cache::get_server_hello(&camouflage_host, client_hello).await;
    if let Err(e) = stream.write_all(&template).await {
        tracing::error!("Mirage Server: write_all template failed: {}", e);
        return;
    }

    // 2.7 Consume Fake Client Tail (63 bytes)
    let mut tail = [0u8; 63];
    match tokio::time::timeout(std::time::Duration::from_secs(5), stream.read_exact(&mut tail)).await {
        Ok(Err(e)) => {
            tracing::error!("Mirage Server: read_exact tail failed: {}", e);
            return;
        }
        Err(_) => {
            tracing::error!("Mirage Server: read_exact tail timed out!");
            return;
        }
        Ok(Ok(_)) => {
            tracing::info!("Mirage Server: Successfully consumed 63 bytes tail");
        }
    }

    // Hand off to control plane (crypto setup + TIME_SYNC + dispatch)
    control::dispatch_authenticated(stream, password, client_random).await;
}
