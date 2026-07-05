//! GET /api/proxies — 列出 Selector / Urltest 组及其子节点 + 当前选择
//! POST /api/proxies/select — 手动切换 Selector 组的当前节点 (含 CSRF 校验)

use axum::{extract::State, http::HeaderMap, Json};
use serde::Deserialize;
use serde_json::{json, Value};

use crate::proxy::outbound::OutboundNode;
use super::super::state::AppState;

pub async fn get_proxies(State(app_state): State<AppState>) -> Json<Value> {
    let st = app_state.state.load();
    let mut proxies = Vec::new();

    for (tag, node) in &st.outbounds.outbounds {
        match node.as_ref() {
            OutboundNode::Selector { children, current, .. } | OutboundNode::Urltest { children, current, .. } => {
                let mut child_info = Vec::new();
                for c in children {
                    child_info.push(json!({
                        "tag": c.tag(),
                        "latency_rtt_ms": c.latency_rtt_ms(),
                        "latency_http_ms": c.latency_http_ms(),
                    }));
                }

                let selected = current.read().unwrap_or_else(|e| e.into_inner()).as_ref().map(|n| n.tag().to_string()).unwrap_or_default();
                let node_type = if matches!(node.as_ref(), OutboundNode::Selector { .. }) { "Selector" } else { "UrlTest" };

                proxies.push(json!({
                    "tag": tag,
                    "type": node_type,
                    "children": child_info,
                    "selected": selected,
                }));
            }
            _ => {}
        }
    }

    Json(json!({ "proxies": proxies }))
}

#[derive(Deserialize)]
pub struct SelectReq {
    pub group: String,
    pub target: String,
}

pub async fn select_proxy(State(app_state): State<AppState>, headers: HeaderMap, Json(req): Json<SelectReq>) -> Json<Value> {
    let is_xhr = headers.get("x-requested-with").and_then(|h| h.to_str().ok()).unwrap_or("") == "XMLHttpRequest";
    let is_cli = headers.get("user-agent").map_or(false, |v| v.as_bytes().starts_with(b"curl/"));

    if !is_xhr && !is_cli {
        let host = headers.get("host").and_then(|h| h.to_str().ok()).unwrap_or("");
        if let Some(origin) = headers.get("origin").and_then(|h| h.to_str().ok()) {
            let expected = format!("//{}", host);
            if !origin.ends_with(&expected) {
                return Json(json!({"status": "error", "message": "CSRF check failed"}));
            }
        } else {
            return Json(json!({"status": "error", "message": "CSRF check failed: Missing Origin or X-Requested-With"}));
        }
    }

    let st = app_state.state.load();

    if let Some(group_node) = st.outbounds.outbounds.get(&req.group) {
        if let OutboundNode::Selector { children, current, .. } = group_node.as_ref() {
            if let Some(target_node) = children.iter().find(|c| c.tag() == req.target) {
                let mut curr = current.write().unwrap_or_else(|e| e.into_inner());
                *curr = Some(target_node.clone());
                return Json(json!({"status": "success", "message": format!("Switched {} to {}", req.group, req.target)}));
            }
        }
    }

    Json(json!({"status": "error", "message": "Group or target not found"}))
}
