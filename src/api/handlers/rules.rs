//! GET /api/rules — 读 config 里 routing.rules 部分
//! POST /api/rules — 写回 routing.rules (鉴权+CSRF 在 auth_mw 中间件), 触发 config 热更新

use axum::{extract::State, Json};
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

pub async fn update_rules(State(app_state): State<AppState>, Json(req): Json<UpdateRulesReq>) -> Json<Value> {
    // 鉴权 + CSRF 由 auth_mw 中间件统一处理 (方案 B), 此处不再重复启发式检查。
    if let Ok(content) = tokio::fs::read_to_string(&app_state.config_path).await {
        if let Ok(mut v) = serde_json::from_str::<Value>(&content) {
            if let Some(routing) = v.get_mut("routing").and_then(|r| r.as_object_mut()) {
                routing.insert("rules".to_string(), req.rules);
                if let Ok(new_content) = serde_json::to_string_pretty(&v) {
                    // 原子写: 先写 .tmp 再 rename 替换。裸 fs::write 原地覆写不安全 ——
                    // 中途崩溃/OOM/并发保存会把 config.json 截成半截 JSON 或空文件, 下次
                    // 重启核心引擎解析失败直接变砖, 得人工 SSH 救。fake_ip 落盘早已用此范式,
                    // 唯独这里的全局配置写漏了。rename 同目录同 FS, 原子。
                    let tmp = format!("{}.tmp", app_state.config_path);
                    if tokio::fs::write(&tmp, &new_content).await.is_ok()
                        && tokio::fs::rename(&tmp, &app_state.config_path).await.is_ok()
                    {
                        return Json(json!({"status": "success"}));
                    }
                    // 写或 rename 失败: 清掉可能残留的半截 .tmp, 原 config.json 未被触碰。
                    let _ = tokio::fs::remove_file(&tmp).await;
                }
            }
        }
    }
    Json(json!({"status": "error", "message": "Failed to write rules to config file"}))
}
