//! 用户策略 (profiles) + 设备分配 (device_profiles) 的读写 —— 「不同用户匹配不同规则」。
//! - GET  /api/profiles — 读 config 的 routing.profiles + routing.device_profiles + 出站标签 (+ version)。
//! - POST /api/profiles — 校验 → (可 dry-run) → 原子写回, 触发热重载。鉴权+CSRF 在 auth_mw。
//!
//! 与 /api/rules 同款: 结构+语义校验、dry_run、原子写、version 乐观锁 (409, 契约 §07)。

use axum::{
    extract::{Query, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde::Deserialize;
use serde_json::{json, Value};

use super::super::state::AppState;
use super::super::{config_version, err_resp};

pub async fn get_profiles(State(app_state): State<AppState>) -> Response {
    let content = match tokio::fs::read_to_string(&app_state.config_path).await {
        Ok(c) => c,
        Err(_) => return err_resp(StatusCode::INTERNAL_SERVER_ERROR, "io_error", "无法读取配置文件", vec![]),
    };
    let Ok(v) = serde_json::from_str::<Value>(&content) else {
        return err_resp(StatusCode::INTERNAL_SERVER_ERROR, "corrupt_config", "配置文件非合法 JSON", vec![]);
    };
    let routing = v.get("routing");
    let profiles = routing.and_then(|r| r.get("profiles")).cloned().unwrap_or_else(|| json!({}));
    let device_profiles = routing.and_then(|r| r.get("device_profiles")).cloned().unwrap_or_else(|| json!([]));
    let outbounds: Vec<&str> = v
        .get("outbounds")
        .and_then(|o| o.as_array())
        .map(|arr| arr.iter().filter_map(|o| o.get("tag").and_then(|t| t.as_str())).collect())
        .unwrap_or_default();
    Json(json!({
        "status": "success",
        "version": config_version(&content),
        "profiles": profiles,
        "device_profiles": device_profiles,
        "outbounds": outbounds,
    }))
    .into_response()
}

#[derive(Deserialize)]
pub struct UpdateReq {
    pub profiles: Value,
    pub device_profiles: Value,
    /// 乐观锁: 带上且与当前配置不符 → 409 stale_version。不带 = 不检查 (兼容)。
    #[serde(default)]
    pub version: Option<String>,
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
) -> Response {
    // 读改写全程持锁, 与 rules 端点串行 (共用 config.json + .tmp), 防撕裂/丢更新。
    let _wlock = super::CONFIG_WRITE_LOCK.lock().await;

    let Ok(content) = tokio::fs::read_to_string(&app_state.config_path).await else {
        return err_resp(StatusCode::INTERNAL_SERVER_ERROR, "io_error", "无法读取当前配置文件", vec![]);
    };
    if let Some(client_ver) = &req.version {
        if client_ver != &config_version(&content) {
            return err_resp(StatusCode::CONFLICT, "stale_version", "配置已被他处修改, 请刷新后重试", vec![]);
        }
    }
    let Ok(mut v) = serde_json::from_str::<Value>(&content) else {
        return err_resp(StatusCode::INTERNAL_SERVER_ERROR, "corrupt_config", "当前配置文件非合法 JSON", vec![]);
    };
    let Some(routing) = v.get_mut("routing").and_then(|r| r.as_object_mut()) else {
        return err_resp(StatusCode::INTERNAL_SERVER_ERROR, "corrupt_config", "当前配置缺少 routing 段", vec![]);
    };
    routing.insert("profiles".to_string(), req.profiles);
    routing.insert("device_profiles".to_string(), req.device_profiles);
    let Ok(candidate) = serde_json::to_string_pretty(&v) else {
        return err_resp(StatusCode::INTERNAL_SERVER_ERROR, "serialize_error", "候选配置序列化失败", vec![]);
    };

    let (cfg, mut issues) = match crate::config::Config::parse_with_diagnostics(&candidate) {
        Ok(pair) => pair,
        Err(e) => {
            return err_resp(
                StatusCode::UNPROCESSABLE_ENTITY,
                "invalid_config",
                format!("策略内容非法, 已拒绝 (未写入): {e}"),
                vec![],
            );
        }
    };
    issues.extend(cfg.semantic_issues());

    if q.dry_run {
        return Json(json!({"status": "success", "dry_run": true, "written": false, "issues": issues})).into_response();
    }

    let tmp = format!("{}.tmp", app_state.config_path);
    if tokio::fs::write(&tmp, &candidate).await.is_ok()
        && tokio::fs::rename(&tmp, &app_state.config_path).await.is_ok()
    {
        return Json(json!({
            "status": "success", "written": true, "issues": issues,
            "version": config_version(&candidate),
        }))
        .into_response();
    }
    let _ = tokio::fs::remove_file(&tmp).await;
    err_resp(StatusCode::INTERNAL_SERVER_ERROR, "write_error", "写入配置失败 (原文件未改动)", vec![])
}
