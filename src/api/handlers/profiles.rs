//! 用户策略 (profiles) + 设备分配 (device_profiles) 的读写 —— 「不同用户匹配不同规则」。
//! - GET  /api/profiles — 读 config 的 routing.profiles + routing.device_profiles + 出站标签。
//! - POST /api/profiles — 校验 → (可 dry-run) → 原子写回, 触发热重载。鉴权+CSRF 在 auth_mw。
//!
//! 与 /api/rules 同款校验+dry_run+原子写模式 (整份候选 config 结构+语义校验, 拒绝会写坏的提交)。

use axum::{extract::{Query, State}, Json};
use serde::Deserialize;
use serde_json::{json, Value};

use super::super::state::AppState;

pub async fn get_profiles(State(app_state): State<AppState>) -> Json<Value> {
    if let Ok(content) = tokio::fs::read_to_string(&app_state.config_path).await {
        if let Ok(v) = serde_json::from_str::<Value>(&content) {
            let routing = v.get("routing");
            let profiles = routing.and_then(|r| r.get("profiles")).cloned().unwrap_or_else(|| json!({}));
            let device_profiles = routing.and_then(|r| r.get("device_profiles")).cloned().unwrap_or_else(|| json!([]));
            let outbounds: Vec<&str> = v.get("outbounds")
                .and_then(|o| o.as_array())
                .map(|arr| arr.iter().filter_map(|o| o.get("tag").and_then(|t| t.as_str())).collect())
                .unwrap_or_default();
            return Json(json!({
                "status": "success",
                "profiles": profiles,
                "device_profiles": device_profiles,
                "outbounds": outbounds,
            }));
        }
    }
    Json(json!({"status": "error", "message": "无法读取配置"}))
}

#[derive(Deserialize)]
pub struct UpdateReq {
    pub profiles: Value,
    pub device_profiles: Value,
}

#[derive(Deserialize, Default)]
pub struct DryQuery {
    #[serde(default, deserialize_with = "super::rules::de_flexible_bool")]
    pub dry_run: bool,
}

pub async fn update_profiles(
    State(app_state): State<AppState>,
    Query(q): Query<DryQuery>,
    Json(req): Json<UpdateReq>,
) -> Json<Value> {
    let Ok(content) = tokio::fs::read_to_string(&app_state.config_path).await else {
        return Json(json!({"status": "error", "stage": "read", "message": "无法读取当前配置文件"}));
    };
    let Ok(mut v) = serde_json::from_str::<Value>(&content) else {
        return Json(json!({"status": "error", "stage": "read", "message": "当前配置文件非合法 JSON"}));
    };
    let Some(routing) = v.get_mut("routing").and_then(|r| r.as_object_mut()) else {
        return Json(json!({"status": "error", "stage": "read", "message": "当前配置缺少 routing 段"}));
    };
    routing.insert("profiles".to_string(), req.profiles);
    routing.insert("device_profiles".to_string(), req.device_profiles);
    let Ok(candidate) = serde_json::to_string_pretty(&v) else {
        return Json(json!({"status": "error", "stage": "serialize", "message": "候选配置序列化失败"}));
    };

    let (cfg, mut issues) = match crate::config::Config::parse_with_diagnostics(&candidate) {
        Ok(pair) => pair,
        Err(e) => {
            return Json(json!({
                "status": "error", "stage": "validate",
                "message": format!("候选配置结构非法, 已拒绝 (未写入): {e}")
            }));
        }
    };
    issues.extend(cfg.semantic_issues());

    if q.dry_run {
        return Json(json!({"status": "success", "dry_run": true, "written": false, "issues": issues}));
    }

    let tmp = format!("{}.tmp", app_state.config_path);
    if tokio::fs::write(&tmp, &candidate).await.is_ok()
        && tokio::fs::rename(&tmp, &app_state.config_path).await.is_ok()
    {
        return Json(json!({"status": "success", "written": true, "issues": issues}));
    }
    let _ = tokio::fs::remove_file(&tmp).await;
    Json(json!({"status": "error", "stage": "write", "message": "写入配置失败 (原文件未改动)"}))
}
