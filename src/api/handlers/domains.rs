//! GET /api/domains — 域名排行 (top-N by 累计上下行流量), WebUI 服务端 Admin「Top domains」。
//!
//! 源: monitor 连接登记表的 per-域名聚合 (register 计连接数, 断连补字节)。服务端 relay 已登记
//! (T1), 故服务端上此表反映所有客户端经本机访问过的目标域名/IP。客户端上则是本机自己的访问。

use axum::Json;
use serde_json::{json, Value};

pub async fn get_domains() -> Json<Value> {
    let top = crate::monitor::domain_stats(30);
    Json(json!({ "domains": serde_json::to_value(top).unwrap_or(Value::Null) }))
}
