//! GET /api/devices — 按发起方 IP 聚合的设备/来源统计。
//! 客户端: LAN 设备 (透明入站的源 IP); 服务端: 连接的客户端 IP。
//! 供 WebUI 客户端 Devices 视图 / 服务端 Clients 视图。

use axum::Json;
use serde_json::{json, Value};

pub async fn get_devices() -> Json<Value> {
    Json(json!({ "devices": serde_json::to_value(crate::monitor::device_stats()).unwrap_or(Value::Null) }))
}
