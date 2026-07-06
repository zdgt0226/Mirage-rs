//! GET /api/bpf/tunnels — 列出当前 BPF 跟踪的所有活跃 TCP tunnel.
//!
//! cookie 为内核 SO_COOKIE, 唯一标识一条 socket; 字段为 sockmap.c::tcp_state.
//! srtt_us 已折算成毫秒返回; LRU 淘汰的 cookie 自动从列表消失.
//!
//! `remote` 字段是字符串化的远端地址 (host:port). v0.4.4+ 起 BPF 端在 tcp_state
//! 里塞了 remote_ip / port / family, 这里只做格式化. 注意当前 BPF 白名单只跟踪
//! 客户端→服务端的 tunnel 连接 (mirage 服务器 IP) 或服务端←客户端的入站连接,
//! 不跟踪上游业务连接 (github.com 等). 因此 remote 一般是 mirage 服务器 IP /
//! 客户端 IP, 不是用户访问的目标网站.

use axum::{extract::State, Json};
use serde_json::{json, Value};

use super::super::state::AppState;

/// 把 BPF tcp_state 里的 remote_ip / port / family 格式化成 "host:port" 字符串.
/// IPv4: "192.0.2.5:443"; IPv6: "[2001:db8::1]:443"; 未知 family: "?:?".
fn format_remote(remote_ip: [u32; 4], port: u16, family: u16) -> String {
    match family {
        2 => {
            // AF_INET. remote_ip[0] 是 network byte order, 转回主机字节序后取
            // 各字节构造点分十进制. (network byte order u32: 高字节=最高位)
            let raw = remote_ip[0];
            let b0 = (raw & 0xff) as u8;
            let b1 = ((raw >> 8) & 0xff) as u8;
            let b2 = ((raw >> 16) & 0xff) as u8;
            let b3 = ((raw >> 24) & 0xff) as u8;
            format!("{}.{}.{}.{}:{}", b0, b1, b2, b3, port)
        }
        10 => {
            // AF_INET6. 4 个 u32 拼成 16 字节 IPv6 地址.
            let mut octets = [0u8; 16];
            for i in 0..4 {
                let raw = remote_ip[i];
                octets[i * 4] = (raw & 0xff) as u8;
                octets[i * 4 + 1] = ((raw >> 8) & 0xff) as u8;
                octets[i * 4 + 2] = ((raw >> 16) & 0xff) as u8;
                octets[i * 4 + 3] = ((raw >> 24) & 0xff) as u8;
            }
            format!("[{}]:{}", std::net::Ipv6Addr::from(octets), port)
        }
        _ => "?:?".to_string(),
    }
}

pub async fn get_bpf_tunnels(State(state): State<AppState>) -> Json<Value> {
    let mut tunnels: Vec<Value> = Vec::new();
    if let Some(engine) = state.ebpf_engine {
        // lock().await 而非 try_lock: 避免锁被短暂占用那帧返回空列表导致面板闪烁.
        let lock = engine.lock().await;
        {
            if let Ok(entries) = lock.get_all_tunnel_stats() {
                tunnels = entries.into_iter().map(|(cookie, s)| {
                    json!({
                        // 序列化为字符串避免 JSON Number 在 JS 端的 2^53 精度上限.
                        // 实际触发要 SO_COOKIE > 9e15, 物理不可能, 但 belt-and-suspenders
                        // 让前端用 BigInt(string) 完整接收 u64.
                        "cookie": cookie.to_string(),
                        "remote": format_remote(s.remote_ip, s.remote_port, s.family),
                        "rtt_ms": s.srtt_us as f64 / 1000.0,
                        "cwnd": s.snd_cwnd,
                        "retrans": s.total_retrans,
                        "data_segs": s.data_segs_out,
                    })
                }).collect();
            }
        }
    }
    Json(json!({ "tunnels": tunnels }))
}
