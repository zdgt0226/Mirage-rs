//! GET /api/connections — 活跃连接 + 最近关闭 (WebUI「域名连接信息」数据源)。
//!
//! 全用户态连接登记表 (见 crate::monitor), 与 eBPF 无关: lite / 网关模式都有数据,
//! 区别于仅 eBPF sockops 才有的 `/api/bpf/tunnels` (那个是 IP 级 TCP 栈指标)。
//! 每条含: 域名/IP 目标、入站、路由选中出站、协议、进程名、时长、上下行字节。

use axum::Json;
use serde_json::{json, Value};

pub async fn get_connections() -> Json<Value> {
    let (active, recent_closed) = crate::monitor::conn_snapshots();
    Json(json!({
        "active": serde_json::to_value(active).unwrap_or(Value::Null),
        "recent_closed": serde_json::to_value(recent_closed).unwrap_or(Value::Null),
    }))
}
