//! GET /api/history — 过去 120 秒的滑动窗口数据 (上行/下行字节速率 + BPF
//! 命中数速率). 由 sampler 后台 task 每秒采样累加.

use axum::{extract::State, Json};
use serde_json::{json, Value};

use super::super::state::AppState;

pub async fn get_history(State(state): State<AppState>) -> Json<Value> {
    if let Ok(h) = state.history.read() {
        Json(json!({
            "up": h.up,
            "down": h.down,
            "bpf_success": h.bpf,
        }))
    } else {
        Json(json!({}))
    }
}
