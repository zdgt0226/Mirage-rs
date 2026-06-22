//! GET /api/logs — 当前内存日志缓冲 (供 Dashboard "Terminal" 面板展示).

use axum::Json;
use serde_json::{json, Value};

use crate::monitor::GLOBAL_LOGGER;

pub async fn get_logs() -> Json<Value> {
    let logs = GLOBAL_LOGGER.get_logs();
    Json(json!({
        "logs": logs
    }))
}
