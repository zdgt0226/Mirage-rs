//! 服务端「连接的客户端」管理 (WebUI 服务端 Admin/Clients)。
//! - GET  /api/clients — 客户端列表 (device_stats, 源=客户端 IP) + 屏蔽标记 + 当前屏蔽名单。
//! - POST /api/clients/block — 屏蔽 / 解除屏蔽一个客户端 IP (鉴权+CSRF 在 auth_mw)。
//!
//! 仅服务端有意义 (客户端模式下 device_stats 是 LAN 设备, 屏蔽在此对客户端无用途)。

use axum::Json;
use serde::Deserialize;
use serde_json::{json, Value};

pub async fn get_clients() -> Json<Value> {
    let blocked_set: std::collections::HashSet<String> = crate::blocklist::list().into_iter().collect();
    let clients: Vec<Value> = crate::monitor::device_stats().into_iter().map(|d| json!({
        "ip": d.ip,
        "conns": d.conns,
        "up": d.up,
        "down": d.down,
        "idle_ms": d.idle_ms,
        "blocked": blocked_set.contains(&d.ip),
        // 客户端上报的版本 (两端 client_info 同开才有; 否则 null = 未知/未上报)。
        "version": crate::client_info::version_of(&d.ip),
    })).collect();
    Json(json!({ "clients": clients, "blocked": crate::blocklist::list() }))
}

#[derive(Deserialize)]
pub struct BlockReq {
    pub ip: String,
    pub blocked: bool,
}

pub async fn post_block(Json(req): Json<BlockReq>) -> axum::response::Response {
    use axum::response::IntoResponse;
    match req.ip.parse::<std::net::IpAddr>() {
        Ok(ip) => {
            if req.blocked {
                crate::blocklist::block(ip);
            } else {
                crate::blocklist::unblock(&ip);
            }
            Json(json!({"status": "success", "ip": req.ip, "blocked": req.blocked})).into_response()
        }
        Err(_) => super::super::err_resp(
            axum::http::StatusCode::BAD_REQUEST,
            "invalid_ip",
            "IP 地址格式非法",
            vec![],
        ),
    }
}
