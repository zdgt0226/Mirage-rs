//! GET /api/logs — 当前内存日志缓冲 (供 Dashboard "Terminal" 面板展示).
//!
//! 支持游标增量 (契约 §10 P2): `?after=<cursor>&limit=<n>` 只拉 seq > cursor 的新行,
//! 返回 `{ logs, cursor }`。首次不带 after (=0) 即拿最近全量; 之后带上一次的 cursor 增量拉。
//! 不带 query 时向后兼容: after=0, limit=500。

use axum::{extract::Query, Json};
use serde::Deserialize;
use serde_json::{json, Value};

use crate::monitor::GLOBAL_LOGGER;

#[derive(Deserialize, Default)]
pub struct LogsQuery {
    #[serde(default)]
    pub after: u64,
    pub limit: Option<usize>,
}

pub async fn get_logs(Query(q): Query<LogsQuery>) -> Json<Value> {
    let limit = q.limit.unwrap_or(500).clamp(1, 1000);
    let (logs, cursor) = GLOBAL_LOGGER.get_logs_after(q.after, limit);
    Json(json!({ "logs": logs, "cursor": cursor }))
}
