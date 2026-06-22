//! GET /api/bpf/tunnels — 列出当前 BPF 跟踪的所有活跃 TCP tunnel.
//!
//! cookie 为内核 SO_COOKIE, 唯一标识一条 socket; 字段为 sockmap.c::tcp_state.
//! srtt_us 已折算成毫秒返回; LRU 淘汰的 cookie 自动从列表消失.

use axum::{extract::State, Json};
use serde_json::{json, Value};

use super::super::state::AppState;

pub async fn get_bpf_tunnels(State(state): State<AppState>) -> Json<Value> {
    let mut tunnels: Vec<Value> = Vec::new();
    if let Some(engine) = state.ebpf_engine {
        if let Ok(lock) = engine.try_lock() {
            if let Ok(entries) = lock.get_all_tunnel_stats() {
                tunnels = entries.into_iter().map(|(cookie, s)| {
                    json!({
                        "cookie": cookie,
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
