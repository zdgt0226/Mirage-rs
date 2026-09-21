//! 多用户凭据管理 (P1) —— 供 Mirage-console 操作。
//! - GET  /api/users — 列用户 (name + per-user 用量: conns/up/down/active)。**绝不返 password**。
//! - POST /api/users — 设 mirage_server 入站的 `users[]` (增删/改密), 校验 → 原子写 → 热重载。
//!
//! 与 /api/profiles 同款: version 乐观锁 (409)、parse+semantic 校验、dry_run、原子写。
//! 安全: GET 只出 name+用量; password 仅经 POST 进 config, 不回显、不进日志。

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
use super::profiles::DryQuery;

/// 找第一个 type=mirage_server 的入站 (下标)。多用户凭据挂在服务端入站上。
fn find_mirage_server(inbounds: &[Value]) -> Option<usize> {
    inbounds.iter().position(|ib| ib.get("type").and_then(|t| t.as_str()) == Some("mirage_server"))
}

pub async fn get_users(State(app_state): State<AppState>) -> Response {
    let content = match tokio::fs::read_to_string(&app_state.config_path).await {
        Ok(c) => c,
        Err(_) => return err_resp(StatusCode::INTERNAL_SERVER_ERROR, "io_error", "无法读取配置文件", vec![]),
    };
    let Ok(v) = serde_json::from_str::<Value>(&content) else {
        return err_resp(StatusCode::INTERNAL_SERVER_ERROR, "corrupt_config", "配置文件非合法 JSON", vec![]);
    };

    // 配置里的用户名: "default" (主密码) + mirage_server.users[].name。**不取 password**。
    let mut names: Vec<String> = vec!["default".to_string()];
    if let Some(arr) = v.get("inbounds").and_then(|i| i.as_array()) {
        if let Some(idx) = find_mirage_server(arr) {
            if let Some(users) = arr[idx].get("users").and_then(|u| u.as_array()) {
                for u in users {
                    if let Some(n) = u.get("name").and_then(|n| n.as_str()) {
                        names.push(n.to_string());
                    }
                }
            }
        }
    }

    // 用量 (per-user 统计) → 按 name 索引。
    let usage: std::collections::HashMap<String, crate::monitor::UserStat> =
        crate::monitor::user_stats().into_iter().map(|s| (s.name.clone(), s)).collect();

    // 合并: 配置里的每个用户 (含 0 流量) + 有流量但已从配置删掉的历史用户 (标 orphan)。
    let mut seen = std::collections::HashSet::new();
    let mut out: Vec<Value> = Vec::new();
    for name in &names {
        seen.insert(name.clone());
        let (conns, up, down, active) = usage.get(name)
            .map(|s| (s.conns, s.up, s.down, s.active)).unwrap_or((0, 0, 0, 0));
        out.push(json!({"name": name, "conns": conns, "up": up, "down": down, "active": active, "in_config": true}));
    }
    for (name, s) in &usage {
        if !seen.contains(name) {
            out.push(json!({"name": name, "conns": s.conns, "up": s.up, "down": s.down, "active": s.active, "in_config": false}));
        }
    }

    Json(json!({
        "status": "success",
        "version": config_version(&content),
        "users": out,
    }))
    .into_response()
}

/// 一条用户操作。**op-based (增量) 而非整表替换** —— 因为 GET 不回显 password, 前端拿不到
/// 既有用户的密码, 无法做整表替换 (会把未改用户的密码清空)。故只发变更: 增/改密/删。
#[derive(Deserialize)]
pub struct UserOp {
    /// "upsert" (增或改密, 需 password) | "remove" (删, 忽略 password)。
    pub action: String,
    pub name: String,
    #[serde(default)]
    pub password: Option<String>,
}

#[derive(Deserialize)]
pub struct UpdateReq {
    /// 要应用的操作 (增量)。保留名 "default" (主密码) 不由此管理。
    pub ops: Vec<UserOp>,
    #[serde(default)]
    pub version: Option<String>,
}

/// 对当前 users 数组应用增量操作。纯函数 (无 IO), 便于单测。Err = (错误码, 消息)。
/// 保留名 "default" (主密码) 拒绝; upsert 需非空 password (存在则改密, 否则新增); remove 按名删。
/// 结果的 name 唯一/非空/密码非空由上层 semantic_issues 兜底校验 (此处只挡明显的 op 级错误)。
fn apply_ops(mut users: Vec<Value>, ops: &[UserOp]) -> Result<Vec<Value>, (&'static str, String)> {
    for op in ops {
        if op.name == "default" {
            return Err(("reserved_name", "保留名 `default` 是主密码, 不通过 /api/users 管理".into()));
        }
        match op.action.as_str() {
            "upsert" => {
                let pw = op.password.clone().unwrap_or_default();
                if pw.is_empty() {
                    return Err(("empty_password", format!("user `{}` 的 password 为空", op.name)));
                }
                match users.iter_mut().find(|u| u.get("name").and_then(|n| n.as_str()) == Some(op.name.as_str())) {
                    Some(u) => { u["password"] = Value::String(pw); }
                    None => users.push(json!({"name": op.name, "password": pw})),
                }
            }
            "remove" => users.retain(|u| u.get("name").and_then(|n| n.as_str()) != Some(op.name.as_str())),
            other => return Err(("bad_op", format!("未知操作 `{other}` (仅 upsert/remove)"))),
        }
    }
    Ok(users)
}

pub async fn update_users(
    State(app_state): State<AppState>,
    Query(q): Query<DryQuery>,
    Json(req): Json<UpdateReq>,
) -> Response {
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
    let Some(inbounds) = v.get_mut("inbounds").and_then(|i| i.as_array_mut()) else {
        return err_resp(StatusCode::INTERNAL_SERVER_ERROR, "corrupt_config", "当前配置缺少 inbounds", vec![]);
    };
    let Some(idx) = find_mirage_server(inbounds) else {
        return err_resp(StatusCode::UNPROCESSABLE_ENTITY, "no_mirage_server", "当前配置无 mirage_server 入站, 无处挂多用户凭据", vec![]);
    };
    let Some(ib) = inbounds[idx].as_object_mut() else {
        return err_resp(StatusCode::INTERNAL_SERVER_ERROR, "corrupt_config", "mirage_server 入站非对象", vec![]);
    };

    // 取当前 users 数组 (缺则空), 应用增量操作 —— 不需要既有密码。
    let cur: Vec<Value> = ib.get("users").and_then(|u| u.as_array()).cloned().unwrap_or_default();
    let users = match apply_ops(cur, &req.ops) {
        Ok(u) => u,
        Err((code, msg)) => return err_resp(StatusCode::UNPROCESSABLE_ENTITY, code, msg, vec![]),
    };
    ib.insert("users".to_string(), Value::Array(users));

    let Ok(candidate) = serde_json::to_string_pretty(&v) else {
        return err_resp(StatusCode::INTERNAL_SERVER_ERROR, "serialize_error", "候选配置序列化失败", vec![]);
    };

    // parse (挡未知字段/类型错) + semantic_issues (挡空名/重名/空密码)。issues 里凡提 user 的均视为硬错拒写。
    let (cfg, issues) = match crate::config::Config::parse_with_diagnostics(&candidate) {
        Ok(pair) => pair,
        Err(e) => return err_resp(StatusCode::UNPROCESSABLE_ENTITY, "invalid_config", format!("用户列表非法, 已拒绝 (未写入): {e}"), vec![]),
    };
    let sem = cfg.semantic_issues();
    let user_errs: Vec<String> = sem.iter().filter(|s| s.contains("user")).cloned().collect();
    if !user_errs.is_empty() {
        return err_resp(StatusCode::UNPROCESSABLE_ENTITY, "invalid_users", format!("凭据校验失败, 已拒绝 (未写入): {}", user_errs.join("; ")), user_errs);
    }

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

#[cfg(test)]
mod tests {
    use super::*;

    fn op(action: &str, name: &str, pw: Option<&str>) -> UserOp {
        UserOp { action: action.into(), name: name.into(), password: pw.map(|s| s.into()) }
    }
    fn names(v: &[Value]) -> Vec<String> {
        v.iter().filter_map(|u| u.get("name").and_then(|n| n.as_str()).map(String::from)).collect()
    }

    #[test]
    fn upsert_adds_then_changes_password() {
        let u = apply_ops(vec![], &[op("upsert", "alice", Some("p1"))]).unwrap();
        assert_eq!(names(&u), vec!["alice"]);
        assert_eq!(u[0]["password"], "p1");
        // 再 upsert 同名 = 改密, 不新增。
        let u2 = apply_ops(u, &[op("upsert", "alice", Some("p2"))]).unwrap();
        assert_eq!(u2.len(), 1);
        assert_eq!(u2[0]["password"], "p2");
    }

    #[test]
    fn remove_deletes_by_name_untouched_kept() {
        let start = vec![json!({"name":"a","password":"x"}), json!({"name":"b","password":"y"})];
        let u = apply_ops(start, &[op("remove", "a", None)]).unwrap();
        assert_eq!(names(&u), vec!["b"]);
        assert_eq!(u[0]["password"], "y", "未动用户密码保留 (op-based 不需回传既有密码)");
    }

    #[test]
    fn reserved_default_and_empty_pw_and_bad_op_rejected() {
        assert_eq!(apply_ops(vec![], &[op("upsert", "default", Some("p"))]).unwrap_err().0, "reserved_name");
        assert_eq!(apply_ops(vec![], &[op("upsert", "u", Some(""))]).unwrap_err().0, "empty_password");
        assert_eq!(apply_ops(vec![], &[op("upsert", "u", None)]).unwrap_err().0, "empty_password");
        assert_eq!(apply_ops(vec![], &[op("frobnicate", "u", None)]).unwrap_err().0, "bad_op");
    }
}
