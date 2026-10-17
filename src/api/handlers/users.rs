//! 多用户凭据管理 (P1) —— 供 Mirage-console 操作。
//! - GET  /api/users — 列用户 (name + per-user 用量: conns/up/down/active)。**绝不返 password**。
//! - POST /api/users — 设 mirage_server 入站的 `users[]` (增删/改密), 校验 → 原子写 → 热重载。
//!   热重载即时生效: 凭据快照按入站 tag 原子替换 (新连接/新流立即生效, 已建连接不受影响), 限额与用量同步重载。
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

/// 全部 type=mirage_server 入站的下标。多用户凭据挂在服务端入站上, 每个入站各自认证,
/// 所以用户管理必须覆盖全部入站 —— 只改第一个时, 删用户 / 改口令在其他入站上不生效。
fn mirage_server_indices(inbounds: &[Value]) -> Vec<usize> {
    inbounds
        .iter()
        .enumerate()
        .filter(|(_, ib)| ib.get("type").and_then(|t| t.as_str()) == Some("mirage_server"))
        .map(|(i, _)| i)
        .collect()
}

fn inbound_tag(ib: &Value) -> &str {
    ib.get("tag").and_then(|t| t.as_str()).unwrap_or("")
}

fn user_named<'a>(users: &'a [Value], name: &str) -> Option<&'a Value> {
    users.iter().find(|u| u.get("name").and_then(|n| n.as_str()) == Some(name))
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
    // 跨全部 mirage_server 入站合并: 按首次出现排序; 限额取首个出现处 (与限额注册表的"先出现者为准"一致);
    // 记下每个用户所在的入站 tag。
    let mut user_inbounds: std::collections::HashMap<String, Vec<String>> = std::collections::HashMap::new();
    let mut all_tags: Vec<String> = Vec::new();
    if let Some(arr) = v.get("inbounds").and_then(|i| i.as_array()) {
        for idx in mirage_server_indices(arr) {
            let tag = inbound_tag(&arr[idx]).to_string();
            all_tags.push(tag.clone());
            let Some(users) = arr[idx].get("users").and_then(|u| u.as_array()) else { continue };
            for u in users {
                let Some(n) = u.get("name").and_then(|n| n.as_str()) else { continue };
                user_inbounds.entry(n.to_string()).or_default().push(tag.clone());
                if config_limits.contains_key(n) {
                    continue;
                }
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
    user_inbounds.insert("default".to_string(), all_tags);

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
            "inbounds": user_inbounds.get(name).cloned().unwrap_or_default(),
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
                "inbounds": Vec::<String>::new(),
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
#[derive(Deserialize, Clone, Default)]
pub struct UserOp {
    /// "upsert" (增或改密, 需 password) | "remove" (删, 忽略 password) | "set_limits" (设限速/配额) | "reset_quota" (清本周期用量)
    pub action: String,
    pub name: String,
    #[serde(default)]
    pub password: Option<String>,
    /// 限额字段: `None` = 请求里没出现 (set_limits 保留原值); `Some(Null)` = 显式 null (清空);
    /// `Some(数字)` = 设置。用 `present` 反序列化, 否则 serde 会把 null 也读成 None, 两者无法区分。
    #[serde(default, deserialize_with = "present")]
    pub rate_limit_kbps: Option<Value>,
    #[serde(default, deserialize_with = "present")]
    pub quota_gb: Option<Value>,
    #[serde(default, deserialize_with = "present")]
    pub quota_reset_day: Option<Value>,
    /// 只作用于该 tag 的 mirage_server 入站; 不传 = 作用于全部 mirage_server 入站。
    #[serde(default)]
    pub inbound: Option<String>,
}

/// 字段出现即 `Some(值)` (含 `Some(Null)`); 缺省由 `#[serde(default)]` 给 `None`。
fn present<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Option<Value>, D::Error> {
    Value::deserialize(d).map(Some)
}

impl UserOp {
    fn has_limit_fields(&self) -> bool {
        self.rate_limit_kbps.is_some() || self.quota_gb.is_some() || self.quota_reset_day.is_some()
    }
}

#[derive(Deserialize, Clone)]
pub struct UpdateReq {
    /// 要应用的操作 (增量)。保留名 "default" (主密码) 不由此管理。
    pub ops: Vec<UserOp>,
    #[serde(default)]
    pub version: Option<String>,
}

/// 对当前 users 数组应用增量操作。纯函数 (无 IO), 便于单测。Err = (错误码, 消息)。
/// 保留名 "default" (主密码) 拒绝; upsert 需非空 password (存在则改密, 否则新增); remove 按名删。
/// set_limits 局部更新限额 (未传保留 / null 清空); upsert 带限额字段报错; reset_quota 仅校验用户存在, 不改 config。
/// 结果的 name 唯一/非空/密码非空由上层 semantic_issues 兜底校验 (此处只挡明显的 op 级错误)。
fn apply_ops(mut users: Vec<Value>, ops: &[UserOp]) -> Result<Vec<Value>, (&'static str, String)> {
    for op in ops {
        if op.name == "default" {
            return Err(("reserved_name", "保留名 `default` 是主密码, 不通过 /api/users 管理".into()));
        }
        match op.action.as_str() {
            "upsert" => {
                if op.has_limit_fields() {
                    return Err((
                        "limits_not_allowed",
                        format!("upsert 只设置口令; 用户 `{}` 的限速/配额请用 set_limits 设置 (可放在同一请求的后一个 op)", op.name),
                    ));
                }
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

                // 局部更新: 未传保留; null 清空; 数字 > 0 则更新; <= 0 或非数字则报错
                match &op.rate_limit_kbps {
                    None => {} // 未传: 保留原值
                    Some(Value::Null) => {
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

                // quota_gb: 未传保留; null 清空; 有限正数则更新; 其它报错
                match &op.quota_gb {
                    None => {} // 未传: 保留原值
                    Some(Value::Null) => {
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

                // quota_reset_day: 未传保留; null 清空; 1..=28 则更新; 其它报错
                match &op.quota_reset_day {
                    None => {} // 未传: 保留原值
                    Some(Value::Null) => {
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

/// 把 ops 应用到 mirage_server 入站的 `users[]` (纯函数, 便于单测)。
/// - `op.inbound` 不传 = 全部 mirage_server 入站; 传了 = 只该 tag 的入站 (不存在 → `unknown_inbound`)。
/// - upsert / remove: 对每个目标入站都生效, 保证口令与成员在各入站一致。
/// - set_limits / reset_quota: 只作用于含该用户的目标入站; 都不含 → `user_not_found`。
/// - 某入站结果未变 (如对没有 users 的入站执行 remove) 时不写入, 避免凭空加 `"users": []`。
fn apply_ops_inbounds(inbounds: &mut [Value], ops: &[UserOp]) -> Result<(), (&'static str, String)> {
    let idxs = mirage_server_indices(inbounds);
    if idxs.is_empty() {
        return Err(("no_mirage_server", "当前配置无 mirage_server 入站, 无处挂多用户凭据".into()));
    }
    for op in ops {
        if op.name == "default" {
            return Err(("reserved_name", "保留名 `default` 是主密码, 不通过 /api/users 管理".into()));
        }
        if !matches!(op.action.as_str(), "upsert" | "remove" | "set_limits" | "reset_quota") {
            return Err(("bad_op", format!("未知操作 `{}` (仅 upsert/remove/set_limits/reset_quota)", op.action)));
        }
        let targets: Vec<usize> = match &op.inbound {
            None => idxs.clone(),
            Some(t) => {
                let v: Vec<usize> = idxs.iter().copied().filter(|&i| inbound_tag(&inbounds[i]) == t).collect();
                if v.is_empty() {
                    return Err(("unknown_inbound", format!("不存在 tag 为 `{t}` 的 mirage_server 入站")));
                }
                v
            }
        };
        let needs_user = matches!(op.action.as_str(), "set_limits" | "reset_quota");
        let mut applied = false;
        for i in targets {
            let ib = inbounds[i]
                .as_object_mut()
                .ok_or(("corrupt_config", "mirage_server 入站非对象".to_string()))?;
            let cur: Vec<Value> = ib.get("users").and_then(|u| u.as_array()).cloned().unwrap_or_default();
            if needs_user && user_named(&cur, &op.name).is_none() {
                continue;
            }
            let next = apply_ops(cur.clone(), std::slice::from_ref(op))?;
            applied = true;
            if next != cur {
                ib.insert("users".to_string(), Value::Array(next));
            }
        }
        if needs_user && !applied {
            return Err(("user_not_found", format!("user `{}` 不存在", op.name)));
        }
    }
    Ok(())
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
    // 对全部 mirage_server 入站应用增量操作 —— 不需要既有密码。
    if let Err((code, msg)) = apply_ops_inbounds(inbounds, &req.ops) {
        let status = if code == "corrupt_config" { StatusCode::INTERNAL_SERVER_ERROR } else { StatusCode::UNPROCESSABLE_ENTITY };
        return err_resp(status, code, msg, vec![]);
    }

    let Ok(candidate) = serde_json::to_string_pretty(&v) else {
        return err_resp(StatusCode::INTERNAL_SERVER_ERROR, "serialize_error", "候选配置序列化失败", vec![]);
    };

    // parse (挡未知字段/类型错) + user_hard_errors (挡空名/重名/空密码/重复口令硬错拒写)。
    // 跨入站限额不一致等普通提示在 issues 里返回, 不阻断写入。
    let (cfg, issues) = match crate::config::Config::parse_with_diagnostics(&candidate) {
        Ok(pair) => pair,
        Err(e) => return err_resp(StatusCode::UNPROCESSABLE_ENTITY, "invalid_config", format!("用户列表非法, 已拒绝 (未写入): {e}"), vec![]),
    };
    // parse (挡未知字段/类型错) + user_hard_errors (挡空名/重名/空密码/重复口令) 视为硬错拒写;
    // 其余语义提示 (如跨入站同名用户限额不一致) 只随响应 issues 返回, 不拦写入。
    let user_errs = cfg.user_hard_errors();
    if !user_errs.is_empty() {
        return err_resp(StatusCode::UNPROCESSABLE_ENTITY, "invalid_users", format!("凭据校验失败, 已拒绝 (未写入): {}", user_errs.join("; ")), user_errs);
    }

    if q.dry_run {
        return Json(json!({"status": "success", "dry_run": true, "written": false, "issues": issues})).into_response();
    }

    // 处理 reset_quota: 仅清零运行时用量与超额标志并立即落盘 (不改 config)。
    // 挪至成功路径执行 (配置未改动直接返回 / atomic_write_config 成功), 写失败则不执行。
    let apply_reset_quota = || {
        let has_reset_quota = req.ops.iter().any(|op| op.action == "reset_quota");
        if has_reset_quota {
            for op in &req.ops {
                if op.action == "reset_quota" {
                    crate::proxy::user_limits::reset_user_quota(&op.name);
                }
            }
            crate::monitor::flush_current();
        }
    };

    // 若配置未发生改动 (如仅 reset_quota 操作), 无需落盘配置。比较解析后的 JSON 而非原文:
    // 原文件缩进/格式与 to_string_pretty 不同时, 不应被当成改动而重写配置、触发热重载。
    let unchanged = serde_json::from_str::<Value>(&content).ok().as_ref() == Some(&v);
    if unchanged {
        apply_reset_quota();
        return Json(json!({
            "status": "success", "written": false, "issues": issues,
            "version": config_version(&candidate),
        }))
        .into_response();
    }

    if super::atomic_write_config(&app_state.config_path, &candidate).await.is_ok() {
        crate::config_watcher::apply_user_config(&cfg.inbounds);
        apply_reset_quota();
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
    use std::sync::Arc;

    fn op(action: &str, name: &str, pw: Option<&str>) -> UserOp {
        UserOp {
            action: action.into(),
            name: name.into(),
            password: pw.map(|s| s.into()),
            rate_limit_kbps: None,
            quota_gb: None,
            quota_reset_day: None,
            inbound: None,
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
            inbound: None,
        };
        let u = apply_ops(start, &[op_set]).unwrap();
        assert_eq!(u[0]["rate_limit_kbps"], 1000);
        assert_eq!(u[0]["quota_gb"], 50.5);
        assert_eq!(u[0]["quota_reset_day"], 15);

        // 局部: 显式 null 清空, 未传保留
        let op_partial = UserOp {
            action: "set_limits".into(),
            name: "alice".into(),
            rate_limit_kbps: Some(Value::Null),
            quota_reset_day: Some(Value::Null),
            ..Default::default()
        };
        let u2 = apply_ops(u, &[op_partial]).unwrap();
        assert!(u2[0].get("rate_limit_kbps").is_none(), "null 应清空");
        assert!(u2[0].get("quota_reset_day").is_none(), "null 应清空");
        assert_eq!(u2[0]["quota_gb"], 50.5, "未传的字段应保留原值");

        // 只改一项, 其余保留
        let op_one = UserOp {
            action: "set_limits".into(),
            name: "alice".into(),
            quota_gb: Some(json!(80)),
            ..Default::default()
        };
        let u3 = apply_ops(u2, &[op_one]).unwrap();
        assert_eq!(u3[0]["quota_gb"], 80.0);
        assert!(u3[0].get("rate_limit_kbps").is_none());
    }

    #[test]
    fn op_json_distinguishes_missing_and_null() {
        let a: UserOp = serde_json::from_str(r#"{"action":"set_limits","name":"x","quota_gb":null}"#).unwrap();
        assert_eq!(a.quota_gb, Some(Value::Null), "显式 null 应保留为 Some(Null)");
        assert_eq!(a.rate_limit_kbps, None, "未传应为 None");
    }

    #[test]
    fn upsert_with_limit_fields_rejected() {
        let op_bad = UserOp {
            action: "upsert".into(),
            name: "alice".into(),
            password: Some("p".into()),
            quota_gb: Some(json!(10)),
            ..Default::default()
        };
        assert_eq!(apply_ops(vec![], &[op_bad]).unwrap_err().0, "limits_not_allowed");
        // 显式 null 也算"带了"限额字段
        let op_null: UserOp = serde_json::from_str(r#"{"action":"upsert","name":"a","password":"p","rate_limit_kbps":null}"#).unwrap();
        assert_eq!(apply_ops(vec![], &[op_null]).unwrap_err().0, "limits_not_allowed");
    }

    fn two_inbounds() -> Vec<Value> {
        vec![
            json!({"type":"mirage_server","tag":"tcp","users":[{"name":"alice","password":"pa"}]}),
            json!({"type":"mixed","tag":"m"}),
            json!({"type":"mirage_server","tag":"quic","users":[{"name":"alice","password":"pa"},{"name":"bob","password":"pb"}]}),
        ]
    }
    fn users_of(ibs: &[Value], i: usize) -> Vec<String> {
        ibs[i].get("users").and_then(|u| u.as_array()).map(|a| names(a)).unwrap_or_default()
    }

    #[test]
    fn ops_apply_to_all_mirage_server_inbounds_by_default() {
        // 改口令: 两个入站都改
        let mut ibs = two_inbounds();
        apply_ops_inbounds(&mut ibs, &[op("upsert", "alice", Some("new"))]).unwrap();
        assert_eq!(ibs[0]["users"][0]["password"], "new");
        assert_eq!(ibs[2]["users"][0]["password"], "new");
        assert!(ibs[1].get("users").is_none(), "非 mirage_server 入站不动");

        // 删用户: 两个入站都删
        apply_ops_inbounds(&mut ibs, &[op("remove", "alice", None)]).unwrap();
        assert_eq!(users_of(&ibs, 0), Vec::<String>::new());
        assert_eq!(users_of(&ibs, 2), vec!["bob"]);

        // 新增: 两个入站都加
        apply_ops_inbounds(&mut ibs, &[op("upsert", "carol", Some("pc"))]).unwrap();
        assert_eq!(users_of(&ibs, 0), vec!["carol"]);
        assert_eq!(users_of(&ibs, 2), vec!["bob", "carol"]);
    }

    #[test]
    fn ops_with_inbound_tag_and_partial_presence() {
        // 指定入站: 只改该入站
        let mut ibs = two_inbounds();
        let mut o = op("upsert", "dave", Some("pd"));
        o.inbound = Some("quic".into());
        apply_ops_inbounds(&mut ibs, &[o]).unwrap();
        assert_eq!(users_of(&ibs, 0), vec!["alice"]);
        assert_eq!(users_of(&ibs, 2), vec!["alice", "bob", "dave"]);

        // 不存在的 tag
        let mut o = op("remove", "alice", None);
        o.inbound = Some("nope".into());
        assert_eq!(apply_ops_inbounds(&mut ibs, &[o]).unwrap_err().0, "unknown_inbound");

        // set_limits 只作用于含该用户的入站 (bob 只在 quic)
        let lim = UserOp { action: "set_limits".into(), name: "bob".into(), quota_gb: Some(json!(5)), ..Default::default() };
        apply_ops_inbounds(&mut ibs, &[lim]).unwrap();
        assert_eq!(ibs[2]["users"][1]["quota_gb"], 5.0);
        assert!(user_named(ibs[0]["users"].as_array().unwrap(), "bob").is_none(), "不应在 tcp 入站凭空建出 bob");

        // 所有入站都没有该用户 → user_not_found
        let lim = UserOp { action: "set_limits".into(), name: "ghost".into(), quota_gb: Some(json!(5)), ..Default::default() };
        assert_eq!(apply_ops_inbounds(&mut ibs, &[lim]).unwrap_err().0, "user_not_found");

        // 对没有 users 键的入站执行 remove 不写入空数组
        let mut ibs2 = vec![json!({"type":"mirage_server","tag":"a"})];
        apply_ops_inbounds(&mut ibs2, &[op("remove", "x", None)]).unwrap();
        assert!(ibs2[0].get("users").is_none());

        // 无 mirage_server 入站
        let mut none = vec![json!({"type":"mixed","tag":"m"})];
        assert_eq!(apply_ops_inbounds(&mut none, &[op("remove", "x", None)]).unwrap_err().0, "no_mirage_server");
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
            inbound: None,
        };
        assert_eq!(apply_ops(vec![], &[op_def]).unwrap_err().0, "reserved_name");

        let op_rq_def = UserOp {
            action: "reset_quota".into(),
            name: "default".into(),
            password: None,
            rate_limit_kbps: None,
            quota_gb: None,
            quota_reset_day: None,
            inbound: None,
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
            inbound: None,
        };
        assert_eq!(apply_ops(vec![], &[op_no]).unwrap_err().0, "user_not_found");

        let op_rq_no = UserOp {
            action: "reset_quota".into(),
            name: "ghost".into(),
            password: None,
            rate_limit_kbps: None,
            quota_gb: None,
            quota_reset_day: None,
            inbound: None,
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
            inbound: None,
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
            inbound: None,
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
            inbound: None,
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
            inbound: None,
        };
        let u = apply_ops(start.clone(), &[op_rq]).unwrap();
        assert_eq!(u, start, "reset_quota 不修改 config 中的 users 结构");
    }

    #[tokio::test]
    #[allow(clippy::await_holding_lock)]
    async fn test_reset_quota_only_executes_on_success() {
        use std::sync::atomic::Ordering;
        use std::sync::Arc;

        let temp_dir = std::env::temp_dir().join(format!("mirage_test_users_{}", fastrand::u64(..)));
        tokio::fs::create_dir_all(&temp_dir).await.unwrap();
        let cfg_file = temp_dir.join("config.json");
        let initial_cfg = r#"{
            "schema_version": 1,
            "inbounds": [{
                "type": "mirage_server",
                "tag": "in",
                "listen": "0.0.0.0",
                "port": 443,
                "password": "mainpw",
                "users": [{"name": "alice", "password": "p", "quota_gb": 1.0}]
            }],
            "outbounds": [{"type": "direct", "tag": "direct"}],
            "routing": {"default_outbound": "direct", "rules": []}
        }"#;
        tokio::fs::write(&cfg_file, initial_cfg).await.unwrap();

        let user = crate::config::MirageUser {
            name: "alice".to_string(),
            password: "p".to_string(),
            rate_limit_kbps: None,
            quota_gb: Some(1.0),
            quota_reset_day: Some(1),
        };
        // 跨 await 持 std 锁: 仅为与其它 init 注册表的测试串行 (current_thread 运行时, 无死锁风险)。
        let _reg = crate::proxy::user_limits::REGISTRY_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        crate::proxy::user_limits::init_user_limits(&[user]);
        let h = crate::proxy::user_limits::get_user_limit("alice").unwrap();
        h.record_bytes(1000);
        assert_eq!(h.period_used.load(Ordering::SeqCst), 1000);

        let cfg_parsed: crate::config::Config = serde_json::from_str(initial_cfg).unwrap();
        let router = crate::router::RouterEngine::new(
            Vec::new(),
            "direct".into(),
            ".",
            &std::collections::HashMap::new(),
        )
        .unwrap();
        let dummy_core = Arc::new(arc_swap::ArcSwap::from_pointee(crate::config_watcher::CoreState {
            router: Arc::new(router),
            outbounds: Arc::new(crate::proxy::outbound::OutboundManager::new(&cfg_parsed).unwrap()),
            advanced_dns: None,
            auto_classify: None,
            rate_limiter: Arc::new(crate::proxy::rate_limit::RateLimiter::from_device_profiles(&[])),
        }));

        let app_state = AppState {
            state: dummy_core,
            ebpf_engine: None,
            xdp_engine: None,
            config_path: cfg_file.to_str().unwrap().to_string(),
            history: Arc::new(std::sync::RwLock::new(crate::api::state::HistoryData {
                up: std::collections::VecDeque::new(),
                down: std::collections::VecDeque::new(),
                bpf: std::collections::VecDeque::new(),
            })),
            gui_token: None,
            rate_limiter: Arc::new(std::sync::Mutex::new(crate::api::ratelimit::RateLimiter::new())),
            is_server: true,
            gui_listen_ip: None,
        };

        // 1. dry_run = true 时, reset_quota 不执行
        let q_dry = DryQuery { dry_run: true };
        let req_reset = UpdateReq {
            version: None,
            ops: vec![UserOp {
                action: "reset_quota".into(),
                name: "alice".into(),
                password: None,
                rate_limit_kbps: None,
                quota_gb: None,
                quota_reset_day: None,
                inbound: None,
            }],
        };
        let resp = update_users(State(app_state.clone()), Query(q_dry), Json(req_reset.clone())).await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(h.period_used.load(Ordering::SeqCst), 1000, "dry_run 不应清零配额");

        // 2. 真实成功执行 reset_quota (配置无改动直接返回路径): 配额清零
        let q_real = DryQuery { dry_run: false };
        let resp2 = update_users(State(app_state.clone()), Query(q_real), Json(req_reset)).await;
        assert_eq!(resp2.status(), StatusCode::OK);
        assert_eq!(h.period_used.load(Ordering::SeqCst), 0, "成功路径应清零配额");

        let _ = tokio::fs::remove_dir_all(&temp_dir).await;
    }

    #[tokio::test]
    #[allow(clippy::await_holding_lock)] // 仅测试串行锁, current_thread 运行时无死锁
    async fn test_cross_inbound_limit_inconsistency_allows_user_ops_but_warns() {
        // update_users 写盘成功后 apply_user_config 会替换进程级限额注册表, 与其它 init 注册表的测试串行。
        let _reg = crate::proxy::user_limits::REGISTRY_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let temp_dir = std::env::temp_dir().join(format!("mirage_user_api_test_{}_{}", std::process::id(), fastrand::u64(..)));
        std::fs::create_dir_all(&temp_dir).unwrap();
        let cfg_file = temp_dir.join("config.json");

        let initial_cfg = r#"{
            "schema_version": 1,
            "inbounds": [
                {
                    "type": "mirage_server",
                    "tag": "srv1",
                    "listen": "0.0.0.0",
                    "port": 443,
                    "password": "pass1",
                    "users": [{"name": "alice", "password": "pa", "rate_limit_kbps": 1000}]
                },
                {
                    "type": "mirage_server",
                    "tag": "srv2",
                    "listen": "0.0.0.0",
                    "port": 8443,
                    "password": "pass2",
                    "users": [{"name": "alice", "password": "pa", "rate_limit_kbps": 2000}]
                }
            ],
            "outbounds": [{"type": "direct", "tag": "direct"}],
            "routing": {"default_outbound": "direct", "rules": []}
        }"#;
        std::fs::write(&cfg_file, initial_cfg).unwrap();

        let cfg_parsed: crate::config::Config = serde_json::from_str(initial_cfg).unwrap();
        let router = crate::router::RouterEngine::new(
            Vec::new(),
            "direct".into(),
            ".",
            &std::collections::HashMap::new(),
        )
        .unwrap();
        let dummy_core = Arc::new(arc_swap::ArcSwap::from_pointee(crate::config_watcher::CoreState {
            router: Arc::new(router),
            outbounds: Arc::new(crate::proxy::outbound::OutboundManager::new(&cfg_parsed).unwrap()),
            advanced_dns: None,
            auto_classify: None,
            rate_limiter: Arc::new(crate::proxy::rate_limit::RateLimiter::from_device_profiles(&[])),
        }));

        let app_state = AppState {
            state: dummy_core,
            ebpf_engine: None,
            xdp_engine: None,
            config_path: cfg_file.to_str().unwrap().to_string(),
            history: Arc::new(std::sync::RwLock::new(crate::api::state::HistoryData {
                up: std::collections::VecDeque::new(),
                down: std::collections::VecDeque::new(),
                bpf: std::collections::VecDeque::new(),
            })),
            gui_token: None,
            rate_limiter: Arc::new(std::sync::Mutex::new(crate::api::ratelimit::RateLimiter::new())),
            is_server: true,
            gui_listen_ip: None,
        };

        // 1. 只改 srv1 的 alice 限额 (指定入站): 两入站限额不一致, 仍应成功 (200), 且 issues 含提示
        let req_set = UpdateReq {
            version: None,
            ops: vec![UserOp {
                action: "set_limits".into(),
                name: "alice".into(),
                password: None,
                rate_limit_kbps: Some(serde_json::json!(5000)),
                quota_gb: None,
                quota_reset_day: None,
                inbound: Some("srv1".into()),
            }],
        };
        let resp = update_users(State(app_state.clone()), Query(DryQuery { dry_run: false }), Json(req_set)).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body_bytes = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let body: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
        let issues = body.get("issues").and_then(|i| i.as_array()).unwrap();
        assert!(issues.iter().any(|i| i.as_str().unwrap_or("").contains("限额配置与入站")), "issues 应包含跨入站不一致提示: {:?}", issues);

        // 2. upsert 添加同口令用户 (撞 srv1 default 密码 pass1): 应被硬错拒写 (422)
        let req_dup_pw = UpdateReq {
            version: None,
            ops: vec![UserOp {
                action: "upsert".into(),
                name: "bob".into(),
                password: Some("pass1".into()),
                rate_limit_kbps: None,
                quota_gb: None,
                quota_reset_day: None,
                inbound: None,
            }],
        };
        let resp_dup = update_users(State(app_state.clone()), Query(DryQuery { dry_run: false }), Json(req_dup_pw)).await;
        assert_eq!(resp_dup.status(), StatusCode::UNPROCESSABLE_ENTITY, "重复口令应返回 422");

        // 3. 不指定入站的 set_limits 同步到两个入站 → 限额一致, 不再有不一致提示
        let req_all = UpdateReq {
            version: None,
            ops: vec![UserOp {
                action: "set_limits".into(),
                name: "alice".into(),
                rate_limit_kbps: Some(serde_json::json!(3000)),
                ..Default::default()
            }],
        };
        let resp = update_users(State(app_state.clone()), Query(DryQuery { dry_run: false }), Json(req_all)).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body: serde_json::Value =
            serde_json::from_slice(&axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap()).unwrap();
        let issues = body.get("issues").and_then(|i| i.as_array()).cloned().unwrap_or_default();
        assert!(!issues.iter().any(|i| i.as_str().unwrap_or("").contains("限额配置与入站")), "同步后不应再不一致: {issues:?}");
        let written: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(&cfg_file).unwrap()).unwrap();
        assert_eq!(written["inbounds"][0]["users"][0]["rate_limit_kbps"], 3000);
        assert_eq!(written["inbounds"][1]["users"][0]["rate_limit_kbps"], 3000);

        // 4. GET 合并两个入站, 并标出 alice 所在入站
        let resp = get_users(State(app_state.clone())).await;
        let body: serde_json::Value =
            serde_json::from_slice(&axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap()).unwrap();
        let users = body["users"].as_array().unwrap();
        let alice: Vec<&serde_json::Value> = users.iter().filter(|u| u["name"] == "alice").collect();
        assert_eq!(alice.len(), 1, "跨入站同名用户只列一次");
        assert_eq!(alice[0]["inbounds"], serde_json::json!(["srv1", "srv2"]));

        let _ = tokio::fs::remove_dir_all(&temp_dir).await;
    }
}
