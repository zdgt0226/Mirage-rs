use crate::proxy::outbound::OutboundNode;
use std::sync::Arc;
use tokio::time::{sleep, Duration, Instant, timeout};
use tracing::debug;

pub fn start_health_checker(node: Arc<OutboundNode>, url: String, interval: u64) {
    if interval == 0 {
        return;
    }

    tokio::spawn(async move {
        // Wait a bit before starting the first check to avoid thundering herd
        sleep(Duration::from_secs(2)).await;

        loop {
            if let OutboundNode::Pyreality { pool, tag, .. } = &*node {
                let start = Instant::now();
                
                // Parse target from url
                let target = if url.contains("cloudflare.com") {
                    "cp.cloudflare.com:80"
                } else if url.contains("firefox.com") {
                    "detectportal.firefox.com:80"
                } else {
                    "www.gstatic.com:80" // default
                };

                let path = if url.contains("cloudflare.com") || url.contains("gstatic.com") {
                    "/generate_204"
                } else {
                    "/success.txt"
                };

                // Acquire a tunnel
                let tunnel_res = timeout(Duration::from_secs(5), async {
                    pool.get().await
                }).await;

                if let Ok(mut tunnel) = tunnel_res {
                    // Send connection target header
                    let target_bytes = target.as_bytes();
                    let mut target_header = Vec::with_capacity(2 + target_bytes.len());
                    target_header.extend_from_slice(&(target_bytes.len() as u16).to_be_bytes());
                    target_header.extend_from_slice(target_bytes);
                    
                    if tunnel.writer.send_data(&target_header).await.is_ok() {
                        let req = format!("GET {} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n", path, target.split(':').next().unwrap_or(""));
                        if tunnel.writer.send_data(req.as_bytes()).await.is_ok() {
                            let _buf = [0u8; 1024];
                            if let Ok(Ok(data)) = timeout(Duration::from_secs(5), tunnel.reader.recv_data()).await {
                                let resp = String::from_utf8_lossy(&data);
                                if resp.contains("HTTP/1.1 204") || resp.contains("HTTP/1.1 200") {
                                    let rtt = start.elapsed().as_millis() as u64;
                                    pool.stats.write().unwrap().record_latency(rtt);
                                    debug!("HealthCheck [{}] ok: {}ms", tag, rtt);
                                } else {
                                    pool.stats.write().unwrap().record_failure();
                                    debug!("HealthCheck [{}] failed (bad status)", tag);
                                }
                            } else {
                                pool.stats.write().unwrap().record_failure();
                                debug!("HealthCheck [{}] failed (recv timeout/err)", tag);
                            }
                        } else {
                            pool.stats.write().unwrap().record_failure();
                        }
                    } else {
                        pool.stats.write().unwrap().record_failure();
                    }
                } else {
                    pool.stats.write().unwrap().record_failure();
                    debug!("HealthCheck [{}] failed (pool get timeout/err)", tag);
                }
            }
            sleep(Duration::from_secs(interval)).await;
        }
    });
}
