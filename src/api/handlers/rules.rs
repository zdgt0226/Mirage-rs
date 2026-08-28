//! GET /api/rules — 读 config 里 routing.rules 部分
//! POST /api/rules — 校验 → (可 dry-run) → 原子写回 routing.rules, 触发 config 热更新。
//! 鉴权+CSRF 在 auth_mw 中间件。写前先把候选整份 config 结构化校验 (解析 + 语义), 拒绝
//! 会把配置写坏的提交; `?dry_run=1` 只校验不写。

use axum::{extract::{Query, State}, Json};
use serde::Deserialize;
use serde_json::{json, Value};

use super::super::state::AppState;

pub async fn get_rules(State(app_state): State<AppState>) -> Json<Value> {
    if let Ok(content) = tokio::fs::read_to_string(&app_state.config_path).await {
        if let Ok(v) = serde_json::from_str::<Value>(&content) {
            if let Some(rules) = v.get("routing").and_then(|r| r.get("rules")) {
                // 出站 tag 列表 (供前端 outbound 下拉建议); 从 config.outbounds[].tag 取, 与规则同源 authoritative。
                let outbounds: Vec<&str> = v.get("outbounds")
                    .and_then(|o| o.as_array())
                    .map(|arr| arr.iter().filter_map(|o| o.get("tag").and_then(|t| t.as_str())).collect())
                    .unwrap_or_default();
                return Json(json!({"status": "success", "rules": rules, "outbounds": outbounds}));
            }
        }
    }
    Json(json!({"status": "error", "message": "Could not read rules from config"}))
}

#[derive(Deserialize)]
pub struct UpdateRulesReq {
    pub rules: Value,
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
) -> Json<Value> {
    // 鉴权 + CSRF 由 auth_mw 中间件统一处理 (方案 B), 此处不再重复启发式检查。

    // 读改写全程持锁, 与 profiles 端点串行 (共用 config.json + .tmp), 防撕裂/丢更新。
    let _wlock = super::CONFIG_WRITE_LOCK.lock().await;

    // 1. 读当前配置, 把新 rules 拼进 routing.rules 得到候选整份 config。
    let Ok(content) = tokio::fs::read_to_string(&app_state.config_path).await else {
        return Json(json!({"status": "error", "stage": "read", "message": "无法读取当前配置文件"}));
    };
    let Ok(mut v) = serde_json::from_str::<Value>(&content) else {
        return Json(json!({"status": "error", "stage": "read", "message": "当前配置文件非合法 JSON"}));
    };
    let Some(routing) = v.get_mut("routing").and_then(|r| r.as_object_mut()) else {
        return Json(json!({"status": "error", "stage": "read", "message": "当前配置缺少 routing 段"}));
    };
    routing.insert("rules".to_string(), req.rules);
    let Ok(candidate) = serde_json::to_string_pretty(&v) else {
        return Json(json!({"status": "error", "stage": "serialize", "message": "候选配置序列化失败"}));
    };

    // 2. 结构化校验: 整份候选必须能解析成 Config (schema); 再收语义告警 (如规则引用不存在的出站)。
    //    解析失败 = 会把配置写坏 → 拒绝, 绝不落盘。
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

    // 3. dry-run: 只回校验结果, 不写。
    if q.dry_run {
        return Json(json!({"status": "success", "dry_run": true, "written": false, "issues": issues}));
    }

    // 4. 原子写: 先写 .tmp 再 rename 替换。裸 fs::write 原地覆写不安全 —— 中途崩溃/OOM/并发
    //    保存会把 config.json 截成半截 JSON 或空文件, 下次重启核心引擎解析失败直接变砖。
    let tmp = format!("{}.tmp", app_state.config_path);
    if tokio::fs::write(&tmp, &candidate).await.is_ok()
        && tokio::fs::rename(&tmp, &app_state.config_path).await.is_ok()
    {
        // config_watcher 监听文件变化异步热重载; 候选已通过同一套校验, 故此处返回的 issues
        // 即热重载会看到的告警 (reload 结果预期)。
        return Json(json!({"status": "success", "written": true, "issues": issues}));
    }
    // 写或 rename 失败: 清掉可能残留的半截 .tmp, 原 config.json 未被触碰。
    let _ = tokio::fs::remove_file(&tmp).await;
    Json(json!({"status": "error", "stage": "write", "message": "写入配置失败 (原文件未改动)"}))
}
