//! GET /api/rules — 读 config 里 routing.rules 部分
//! POST /api/rules — 写回 routing.rules (CSRF 校验), 触发 config 热更新

use axum::{extract::State, http::HeaderMap, Json};
use serde::Deserialize;
use serde_json::{json, Value};

use super::super::state::AppState;

pub async fn get_rules(State(app_state): State<AppState>) -> Json<Value> {
    if let Ok(content) = tokio::fs::read_to_string(&app_state.config_path).await {
        if let Ok(v) = serde_json::from_str::<Value>(&content) {
            if let Some(rules) = v.get("routing").and_then(|r| r.get("rules")) {
                return Json(json!({"status": "success", "rules": rules}));
            }
        }
    }
    Json(json!({"status": "error", "message": "Could not read rules from config"}))
}

#[derive(Deserialize)]
pub struct UpdateRulesReq {
    pub rules: Value,
}

pub async fn update_rules(State(app_state): State<AppState>, headers: HeaderMap, Json(req): Json<UpdateRulesReq>) -> Json<Value> {
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

    if let Ok(content) = tokio::fs::read_to_string(&app_state.config_path).await {
        if let Ok(mut v) = serde_json::from_str::<Value>(&content) {
            if let Some(routing) = v.get_mut("routing").and_then(|r| r.as_object_mut()) {
                routing.insert("rules".to_string(), req.rules);
                if let Ok(new_content) = serde_json::to_string_pretty(&v) {
                    if tokio::fs::write(&app_state.config_path, new_content).await.is_ok() {
                        return Json(json!({"status": "success"}));
                    }
                }
            }
        }
    }
    Json(json!({"status": "error", "message": "Failed to write rules to config file"}))
}
