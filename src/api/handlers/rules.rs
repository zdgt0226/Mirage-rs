//! GET /api/rules — 读 config 里 routing.rules 部分 (+ 配置版本指纹 version, 供乐观锁)。
//! POST /api/rules — 校验 → (可 dry-run) → 原子写回 routing.rules, 触发 config 热更新。
//! 鉴权+CSRF 在 auth_mw 中间件。写前先把候选整份 config 结构化校验 (解析 + 语义), 拒绝
//! 会把配置写坏的提交; `?dry_run=1` 只校验不写。带 version 且与当前不符 → 409 (契约 §07)。

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

pub async fn get_rules(State(app_state): State<AppState>) -> Response {
    let content = match tokio::fs::read_to_string(&app_state.config_path).await {
        Ok(c) => c,
        Err(_) => return err_resp(StatusCode::INTERNAL_SERVER_ERROR, "io_error", "无法读取配置文件", vec![]),
    };
    let Ok(v) = serde_json::from_str::<Value>(&content) else {
        return err_resp(StatusCode::INTERNAL_SERVER_ERROR, "corrupt_config", "配置文件非合法 JSON", vec![]);
    };
    let Some(rules) = v.get("routing").and_then(|r| r.get("rules")) else {
        return err_resp(StatusCode::INTERNAL_SERVER_ERROR, "corrupt_config", "配置缺少 routing 段", vec![]);
    };
    // 出站 tag 列表 (供前端 outbound 下拉建议); 从 config.outbounds[].tag 取, 与规则同源 authoritative。
    let outbounds: Vec<&str> = v
        .get("outbounds")
        .and_then(|o| o.as_array())
        .map(|arr| arr.iter().filter_map(|o| o.get("tag").and_then(|t| t.as_str())).collect())
        .unwrap_or_default();
    Json(json!({
        "status": "success",
        "version": config_version(&content),
        "rules": rules,
        "outbounds": outbounds,
    }))
    .into_response()
}

#[derive(Deserialize)]
pub struct UpdateRulesReq {
    pub rules: Value,
    /// 乐观锁: GET 时拿到的 version。带上且与当前配置不符 → 409 stale_version。不带 = 不检查 (兼容)。
    #[serde(default)]
    pub version: Option<String>,
}

#[derive(Deserialize, Default)]
pub struct UpdateRulesQuery {
    /// `?dry_run=1`: 只校验候选配置, 不落盘 (前端"保存前预检")。
    /// axum 的 Query 对裸 `bool` 只认 `true`/`false`, 但本参数文档契约是 `=1` ——
    /// 用 flexible 反序列化同时吃 `1`/`true`/`yes`/`on`, 否则 `?dry_run=1` 会 400。
    #[serde(default, deserialize_with = "de_flexible_bool")]
    pub dry_run: bool,
}

pub(crate) fn de_flexible_bool<'de, D>(d: D) -> Result<bool, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let s = String::deserialize(d)?;
    Ok(matches!(s.as_str(), "1" | "true" | "yes" | "on"))
}

pub async fn update_rules(
    State(app_state): State<AppState>,
    Query(q): Query<UpdateRulesQuery>,
    Json(req): Json<UpdateRulesReq>,
) -> Response {
    // 鉴权 + CSRF 由 auth_mw 中间件统一处理 (方案 B), 此处不再重复启发式检查。

    // 读改写全程持锁, 与 profiles 端点串行 (共用 config.json + .tmp), 防撕裂/丢更新。
    let _wlock = super::CONFIG_WRITE_LOCK.lock().await;

    // 1. 读当前配置。
    let Ok(content) = tokio::fs::read_to_string(&app_state.config_path).await else {
        return err_resp(StatusCode::INTERNAL_SERVER_ERROR, "io_error", "无法读取当前配置文件", vec![]);
    };
    // 乐观锁: 带了 version 且与当前不符 → 配置已被他处修改。
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
    routing.insert("rules".to_string(), req.rules);
    let Ok(candidate) = serde_json::to_string_pretty(&v) else {
        return err_resp(StatusCode::INTERNAL_SERVER_ERROR, "serialize_error", "候选配置序列化失败", vec![]);
    };

    // 2. 结构化校验: 整份候选必须能解析成 Config (schema); 再收语义告警。解析失败 = 会写坏 → 422 拒绝。
    let (cfg, mut issues) = match crate::config::Config::parse_with_diagnostics(&candidate) {
        Ok(pair) => pair,
        Err(e) => {
            return err_resp(
                StatusCode::UNPROCESSABLE_ENTITY,
                "invalid_config",
                format!("规则内容非法, 已拒绝 (未写入): {e}"),
                vec![],
            );
        }
    };
    issues.extend(cfg.semantic_issues());

    // 3. dry-run: 只回校验结果, 不写。issues 是非阻断告警。
    if q.dry_run {
        return Json(json!({"status": "success", "dry_run": true, "written": false, "issues": issues})).into_response();
    }

    // 4. 原子写: 先写 .tmp 再 rename。裸 fs::write 原地覆写中途崩溃/并发会把 config 截断变砖。
    let tmp = format!("{}.tmp", app_state.config_path);
    if tokio::fs::write(&tmp, &candidate).await.is_ok()
        && tokio::fs::rename(&tmp, &app_state.config_path).await.is_ok()
    {
        // 新 version = 落盘后内容指纹, 前端更新本地锁值 (免下次立刻 stale)。
        return Json(json!({
            "status": "success", "written": true, "issues": issues,
            "version": config_version(&candidate),
        }))
        .into_response();
    }
    let _ = tokio::fs::remove_file(&tmp).await;
    err_resp(StatusCode::INTERNAL_SERVER_ERROR, "write_error", "写入配置失败 (原文件未改动)", vec![])
}
