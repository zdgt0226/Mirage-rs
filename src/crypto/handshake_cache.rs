use std::sync::OnceLock;
use std::sync::atomic::{AtomicBool, Ordering};
use tokio::sync::Mutex;
use tokio::net::TcpStream;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tracing::{error, info};
use rand::RngExt;

static HANDSHAKE_CACHE: OnceLock<Mutex<Vec<Vec<u8>>>> = OnceLock::new();
static WARMING_UP: AtomicBool = AtomicBool::new(false);

struct WarmGuard;
impl Drop for WarmGuard {
    fn drop(&mut self) {
        WARMING_UP.store(false, Ordering::SeqCst);
    }
}

pub async fn get_server_hello(camouflage_host: &str, client_hello: &[u8]) -> Vec<u8> {
    let client_session_id = get_session_id(client_hello).unwrap_or(&[]);
    
    let cache = HANDSHAKE_CACHE.get_or_init(|| Mutex::new(Vec::new()));
    let mut cache_guard = cache.lock().await;

    if cache_guard.is_empty() {
        if !WARMING_UP.swap(true, Ordering::SeqCst) {
            drop(cache_guard);
            let _guard = WarmGuard;
            info!("Fetching real ServerHello from {} to warm up HandshakeCache", camouflage_host);
            let mut set = tokio::task::JoinSet::new();
            for _ in 0..5 {
                let host = camouflage_host.to_string();
                set.spawn(async move {
                    fetch_real_server_hello(&host).await
                });
            }
            let mut new_templates = Vec::new();
            while let Some(res) = set.join_next().await {
                if let Ok(Ok(template)) = res {
                    new_templates.push(template);
                }
            }
            
            let mut guard = cache.lock().await;
            if !new_templates.is_empty() {
                guard.extend(new_templates);
            } else {
                error!("Failed to fetch any templates from {}. Using fallback.", camouflage_host);
                guard.push(fallback_server_hello(client_session_id));
            }
            cache_guard = guard;

            // Spawn background task to refresh cache every 30 minutes
            let host_bg = camouflage_host.to_string();
            tokio::spawn(async move {
                loop {
                    tokio::time::sleep(std::time::Duration::from_secs(1800)).await;
                    let mut set = tokio::task::JoinSet::new();
                    for _ in 0..5 {
                        let h = host_bg.clone();
                        set.spawn(async move { fetch_real_server_hello(&h).await });
                    }
                    let mut templates = Vec::new();
                    while let Some(res) = set.join_next().await {
                        if let Ok(Ok(template)) = res {
                            templates.push(template);
                        }
                    }
                    if !templates.is_empty() {
                        let cache = HANDSHAKE_CACHE.get().unwrap();
                        let mut guard = cache.lock().await;
                        *guard = templates;
                    }
                }
            });
        } else {
            drop(cache_guard);
            let mut attempts = 0;
            while WARMING_UP.load(Ordering::SeqCst) && attempts < 50 {
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                attempts += 1;
            }
            cache_guard = cache.lock().await;
            if cache_guard.is_empty() {
                return fallback_server_hello(client_session_id);
            }
        }
    }

    let mut rng = rand::rng();
    let template_idx = rng.random_range(0..cache_guard.len());
    let response = cache_guard[template_idx].clone();

    patch_server_hello(&response, client_session_id)
}

async fn fetch_real_server_hello(host: &str) -> anyhow::Result<Vec<u8>> {
    let target = if host.contains(':') {
        host.to_string()
    } else {
        format!("{}:443", host)
    };

    let mut stream = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        TcpStream::connect(&target)
    ).await??;

    let mut session_id = [0u8; 32];
    rand::fill(&mut session_id);
    let hostname = host.split(':').next().unwrap_or(host);
    let (ch, _) = crate::crypto::tls_raw::build_client_hello(hostname, &session_id);

    stream.write_all(&ch).await?;

    let mut buf = Vec::new();


    if buf.is_empty() {
        return Err(anyhow::anyhow!("Connection closed by server"));
    }

    Ok(buf)
}

fn patch_server_hello(flight: &[u8], client_session_id: &[u8]) -> Vec<u8> {
    if flight.len() < 44 || flight[0] != 0x16 {
        return flight.to_vec();
    }
    
    let sid_len = flight[43] as usize;
    if flight.len() < 44 + sid_len {
        return flight.to_vec();
    }
    
    let mut result = Vec::with_capacity(flight.len() + client_session_id.len());
    result.extend_from_slice(&flight[..43]);
    result.push(client_session_id.len() as u8);
    result.extend_from_slice(client_session_id);
    result.extend_from_slice(&flight[44 + sid_len..]);
    
    // Server Random
    let mut new_random = [0u8; 32];
    rand::fill(&mut new_random);
    result[11..43].copy_from_slice(&new_random);
    
    let new_len = result.len() - 5;
    result[3] = (new_len >> 8) as u8;
    result[4] = (new_len & 0xFF) as u8;
    
    let hs_len = new_len - 4;
    result[6] = (hs_len >> 16) as u8;
    result[7] = (hs_len >> 8) as u8;
    result[8] = (hs_len & 0xFF) as u8;
    
    result
}

fn get_session_id(client_hello: &[u8]) -> Option<&[u8]> {
    if client_hello.len() < 44 { return None; }
    let sid_len = client_hello[43] as usize;
    if client_hello.len() >= 44 + sid_len {
        Some(&client_hello[44..44+sid_len])
    } else {
        None
    }
}

fn fallback_server_hello(client_session_id: &[u8]) -> Vec<u8> {
    let mut hs_body = vec![0x03, 0x03]; // Version
    let mut rnd = [0u8; 32];
    rand::fill(&mut rnd);
    hs_body.extend_from_slice(&rnd);
    hs_body.push(client_session_id.len() as u8);
    hs_body.extend_from_slice(client_session_id);
    hs_body.extend_from_slice(&[
        0x13, 0x01, // Cipher Suite
        0x00, // Compression
        0x00, 0x0e, // Extensions Length
        0x00, 0x2b, 0x00, 0x02, 0x03, 0x04, // Supported Versions (TLS 1.3)
        0x00, 0x33, 0x00, 0x04, 0x00, 0x1d, 0x00, 0x17, // Key Share
    ]);

    let mut server_hello = vec![0x16, 0x03, 0x03]; // ServerHello Record
    let record_len = (4 + hs_body.len()) as u16;
    server_hello.extend_from_slice(&record_len.to_be_bytes());
    server_hello.push(0x02); // Handshake: ServerHello
    let hs_len = hs_body.len() as u32;
    server_hello.extend_from_slice(&hs_len.to_be_bytes()[1..4]);
    server_hello.extend_from_slice(&hs_body);

    // ChangeCipherSpec & ApplicationData
    server_hello.extend_from_slice(&[
        0x14, 0x03, 0x03, 0x00, 0x01, 0x01, // ChangeCipherSpec
        0x17, 0x03, 0x03, 0x00, 0x15, // Application Data
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    ]);
    server_hello
}
