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

#[derive(Default, Clone, Copy)]
struct UserConfigLimits {
    rate_limit_kbps: Option<u64>,
    quota_gb: Option<f64>,
    quota_reset_day: Option<u8>,
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
    let mut config_limits: std::collections::HashMap<String, UserConfigLimits> = std::collections::HashMap::new();
    if let Some(arr) = v.get("inbounds").and_then(|i| i.as_array()) {
        if let Some(idx) = find_mirage_server(arr) {
            if let Some(users) = arr[idx].get("users").and_then(|u| u.as_array()) {
                for u in users {
                    if let Some(n) = u.get("name").and_then(|n| n.as_str()) {
                        names.push(n.to_string());
                        let kbps = u.get("rate_limit_kbps").and_then(|x| x.as_u64());
                        let quota = u.get("quota_gb").and_then(|x| x.as_f64());
                        let rday = u.get("quota_reset_day").and_then(|x| x.as_u64()).map(|d| d as u8);
                        config_limits.insert(n.to_string(), UserConfigLimits {
                            rate_limit_kbps: kbps,
                            quota_gb: quota,
                            quota_reset_day: rday,
                        });
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
        let limits = config_limits.get(name).copied().unwrap_or_default();
        let (period_used_bytes, period_start, exhausted) = if name == "default" {
            (0, 0, false)
        } else {
            crate::proxy::user_limits::get_user_period_stats(name)
        };
        out.push(json!({
            "name": name,
            "conns": conns,
            "up": up,
            "down": down,
            "active": active,
            "in_config": true,
            "rate_limit_kbps": limits.rate_limit_kbps,
            "quota_gb": limits.quota_gb,
            "quota_reset_day": limits.quota_reset_day,
            "period_used_bytes": period_used_bytes,
            "period_start": period_start,
            "exhausted": exhausted,
        }));
    }
    for (name, s) in &usage {
        if !seen.contains(name) {
            let (period_used_bytes, period_start, exhausted) = crate::proxy::user_limits::get_user_period_stats(name);
            out.push(json!({
                "name": name,
                "conns": s.conns,
                "up": s.up,
                "down": s.down,
                "active": s.active,
                "in_config": false,
                "rate_limit_kbps": None::<u64>,
                "quota_gb": None::<f64>,
                "quota_reset_day": None::<u8>,
                "period_used_bytes": period_used_bytes,
                "period_start": period_start,
                "exhausted": exhausted,
            }));
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
/// 既有用户的密码, 无法做整表替换 (会把未改用户的密码清空)。故只发变更: 增/改密/删/改限额/清配额。
#[derive(Deserialize)]
pub struct UserOp {
    /// "upsert" (增或改密, 需 password) | "remove" (删, 忽略 password) | "set_limits" (设限速/配额) | "reset_quota" (清本周期用量)
    pub action: String,
    pub name: String,
    #[serde(default)]
    pub password: Option<String>,
    #[serde(default)]
    pub rate_limit_kbps: Option<Value>,
    #[serde(default)]
    pub quota_gb: Option<Value>,
    #[serde(default)]
    pub quota_reset_day: Option<Value>,
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
/// set_limits 设置或清空限额与配额; reset_quota 仅校验用户存在, 不改 config 中的 users 数组。
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
            "set_limits" => {
                let Some(user_obj) = users.iter_mut().find(|u| u.get("name").and_then(|n| n.as_str()) == Some(op.name.as_str())) else {
                    return Err(("user_not_found", format!("user `{}` 不存在", op.name)));
                };
                let map = user_obj.as_object_mut().ok_or(("invalid_user", "用户结构非 JSON 对象".into()))?;

                // rate_limit_kbps: None 或 Null 则清空; 数字 > 0 则更新; <= 0 或非数字则报错
                match &op.rate_limit_kbps {
                    None | Some(Value::Null) => {
                        map.remove("rate_limit_kbps");
                    }
                    Some(Value::Number(n)) => {
                        if let Some(v) = n.as_u64() {
                            if v == 0 {
                                return Err(("invalid_limit", format!("user `{}` 的 rate_limit_kbps 必须大于 0", op.name)));
                            }
                            map.insert("rate_limit_kbps".into(), json!(v));
                        } else {
                            return Err(("invalid_limit", format!("user `{}` 的 rate_limit_kbps 非法", op.name)));
                        }
                    }
                    Some(_) => return Err(("invalid_limit", format!("user `{}` 的 rate_limit_kbps 非法", op.name))),
                }

                // quota_gb: None 或 Null 则清空; 数字 > 0 则更新; <= 0 或非数字则报错
                match &op.quota_gb {
                    None | Some(Value::Null) => {
                        map.remove("quota_gb");
                    }
                    Some(Value::Number(n)) => {
                        if let Some(v) = n.as_f64() {
                            if !v.is_finite() || v <= 0.0 {
                                return Err(("invalid_limit", format!("user `{}` 的 quota_gb 必须为有效正数 (>0)", op.name)));
                            }
                            map.insert("quota_gb".into(), json!(v));
                        } else {
                            return Err(("invalid_limit", format!("user `{}` 的 quota_gb 非法", op.name)));
                        }
                    }
                    Some(_) => return Err(("invalid_limit", format!("user `{}` 的 quota_gb 非法", op.name))),
                }

                // quota_reset_day: None 或 Null 则清空; 1..=28 则更新; 其它则报错
                match &op.quota_reset_day {
                    None | Some(Value::Null) => {
                        map.remove("quota_reset_day");
                    }
                    Some(Value::Number(n)) => {
                        if let Some(v) = n.as_u64() {
                            if !(1..=28).contains(&v) {
                                return Err(("invalid_limit", format!("user `{}` 的 quota_reset_day 必须在 1..=28 范围内", op.name)));
                            }
                            map.insert("quota_reset_day".into(), json!(v));
                        } else {
                            return Err(("invalid_limit", format!("user `{}` 的 quota_reset_day 非法", op.name)));
                        }
                    }
                    Some(_) => return Err(("invalid_limit", format!("user `{}` 的 quota_reset_day 非法", op.name))),
                }
            }
            "reset_quota" => {
                if !users.iter().any(|u| u.get("name").and_then(|n| n.as_str()) == Some(op.name.as_str())) {
                    return Err(("user_not_found", format!("user `{}` 不存在", op.name)));
                }
            }
            other => return Err(("bad_op", format!("未知操作 `{other}` (仅 upsert/remove/set_limits/reset_quota)"))),
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

    // 处理 reset_quota: 仅清零运行时用量与超额标志并立即落盘 (不改 config)
    let has_reset_quota = req.ops.iter().any(|op| op.action == "reset_quota");
    if has_reset_quota && !q.dry_run {
        for op in &req.ops {
            if op.action == "reset_quota" {
                crate::proxy::user_limits::reset_user_quota(&op.name);
            }
        }
        crate::monitor::flush_current();
    }

    if q.dry_run {
        return Json(json!({"status": "success", "dry_run": true, "written": false, "issues": issues})).into_response();
    }

    // 若配置未发生改动 (如仅 reset_quota 操作), 无需落盘配置
    if candidate == content {
        return Json(json!({
            "status": "success", "written": false, "issues": issues,
            "version": config_version(&candidate),
        }))
        .into_response();
    }

    if super::atomic_write_config(&app_state.config_path, &candidate).await.is_ok() {
        return Json(json!({
            "status": "success", "written": true, "issues": issues,
            "version": config_version(&candidate),
        }))
        .into_response();
    }
    err_resp(StatusCode::INTERNAL_SERVER_ERROR, "write_error", "写入配置失败 (原文件未改动)", vec![])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn op(action: &str, name: &str, pw: Option<&str>) -> UserOp {
        UserOp {
            action: action.into(),
            name: name.into(),
            password: pw.map(|s| s.into()),
            rate_limit_kbps: None,
            quota_gb: None,
            quota_reset_day: None,
        }
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

    #[test]
    fn set_limits_sets_and_clears_fields() {
        let start = vec![json!({"name":"alice","password":"p"})];
        // 设置三项限额
        let op_set = UserOp {
            action: "set_limits".into(),
            name: "alice".into(),
            password: None,
            rate_limit_kbps: Some(json!(1000)),
            quota_gb: Some(json!(50.5)),
            quota_reset_day: Some(json!(15)),
        };
        let u = apply_ops(start, &[op_set]).unwrap();
        assert_eq!(u[0]["rate_limit_kbps"], 1000);
        assert_eq!(u[0]["quota_gb"], 50.5);
        assert_eq!(u[0]["quota_reset_day"], 15);

        // 清空
        let op_clear = UserOp {
            action: "set_limits".into(),
            name: "alice".into(),
            password: None,
            rate_limit_kbps: Some(Value::Null),
            quota_gb: None,
            quota_reset_day: Some(Value::Null),
        };
        let u2 = apply_ops(u, &[op_clear]).unwrap();
        assert!(u2[0].get("rate_limit_kbps").is_none());
        assert!(u2[0].get("quota_gb").is_none());
        assert!(u2[0].get("quota_reset_day").is_none());
    }

    #[test]
    fn set_limits_and_reset_quota_reject_default_and_nonexistent() {
        // default 拒绝
        let op_def = UserOp {
            action: "set_limits".into(),
            name: "default".into(),
            password: None,
            rate_limit_kbps: Some(json!(100)),
            quota_gb: None,
            quota_reset_day: None,
        };
        assert_eq!(apply_ops(vec![], &[op_def]).unwrap_err().0, "reserved_name");

        let op_rq_def = UserOp {
            action: "reset_quota".into(),
            name: "default".into(),
            password: None,
            rate_limit_kbps: None,
            quota_gb: None,
            quota_reset_day: None,
        };
        assert_eq!(apply_ops(vec![], &[op_rq_def]).unwrap_err().0, "reserved_name");

        // 不存在用户
        let op_no = UserOp {
            action: "set_limits".into(),
            name: "ghost".into(),
            password: None,
            rate_limit_kbps: Some(json!(100)),
            quota_gb: None,
            quota_reset_day: None,
        };
        assert_eq!(apply_ops(vec![], &[op_no]).unwrap_err().0, "user_not_found");

        let op_rq_no = UserOp {
            action: "reset_quota".into(),
            name: "ghost".into(),
            password: None,
            rate_limit_kbps: None,
            quota_gb: None,
            quota_reset_day: None,
        };
        assert_eq!(apply_ops(vec![], &[op_rq_no]).unwrap_err().0, "user_not_found");
    }

    #[test]
    fn set_limits_rejects_invalid_values() {
        let start = vec![json!({"name":"alice","password":"p"})];

        // rate_limit_kbps = 0
        let op_zero_kbps = UserOp {
            action: "set_limits".into(),
            name: "alice".into(),
            password: None,
            rate_limit_kbps: Some(json!(0)),
            quota_gb: None,
            quota_reset_day: None,
        };
        assert_eq!(apply_ops(start.clone(), &[op_zero_kbps]).unwrap_err().0, "invalid_limit");

        // quota_gb = 0
        let op_zero_q = UserOp {
            action: "set_limits".into(),
            name: "alice".into(),
            password: None,
            rate_limit_kbps: None,
            quota_gb: Some(json!(0.0)),
            quota_reset_day: None,
        };
        assert_eq!(apply_ops(start.clone(), &[op_zero_q]).unwrap_err().0, "invalid_limit");

        // quota_reset_day = 29
        let op_bad_day = UserOp {
            action: "set_limits".into(),
            name: "alice".into(),
            password: None,
            rate_limit_kbps: None,
            quota_gb: None,
            quota_reset_day: Some(json!(29)),
        };
        assert_eq!(apply_ops(start.clone(), &[op_bad_day]).unwrap_err().0, "invalid_limit");
    }

    #[test]
    fn reset_quota_valid_leaves_config_untouched() {
        let start = vec![json!({"name":"alice","password":"p","quota_gb":10.0})];
        let op_rq = UserOp {
            action: "reset_quota".into(),
            name: "alice".into(),
            password: None,
            rate_limit_kbps: None,
            quota_gb: None,
            quota_reset_day: None,
        };
        let u = apply_ops(start.clone(), &[op_rq]).unwrap();
        assert_eq!(u, start, "reset_quota 不修改 config 中的 users 结构");
    }
}
