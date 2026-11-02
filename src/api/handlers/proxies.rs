//! GET /api/proxies — 列出出站组 (Selector / UrlTest / Fallback / LoadBalance) 及其子节点 + 当前选择 + 默认出站
//! POST /api/proxies/select — 手动切换 Selector 组的当前节点 (鉴权+CSRF 在 auth_mw 中间件)

use axum::{extract::State, Json};
use std::sync::{Arc, RwLock};

use serde::Deserialize;
use serde_json::{json, Value};

use crate::proxy::outbound::OutboundNode;
use super::super::state::AppState;

pub async fn get_proxies(State(app_state): State<AppState>) -> Json<Value> {
    let st = app_state.state.load();
    // HashMap 迭代顺序不定, 按 tag 排序免得前端轮询时组卡片乱跳
    let mut tags: Vec<&String> = st.outbounds.outbounds.keys().collect();
    tags.sort();
    let proxies: Vec<Value> = tags
        .into_iter()
        .filter_map(|tag| group_json(tag, &st.outbounds.outbounds[tag]))
        .collect();

    Json(json!({ "default": st.router.default_outbound(), "proxies": proxies }))
}

/// 出站组 → JSON; 非组返回 None。`selected` 为当前生效的直接子成员 (load_balance 轮询无固定选择, 给空串)。
fn group_json(tag: &str, node: &Arc<OutboundNode>) -> Option<Value> {
    let (node_type, children, selected) = match node.as_ref() {
        OutboundNode::Selector { children, current, .. } => ("Selector", children, read_current(current)),
        OutboundNode::Urltest { children, current, .. } => ("UrlTest", children, read_current(current)),
        OutboundNode::Fallback { children, .. } => {
            // 与 resolve_leaf 同规则: 第一个健康成员, 全不健康取第一个
            let pick = children.iter().find(|c| c.is_healthy()).or_else(|| children.first());
            ("Fallback", children, pick.map(|c| c.tag().to_string()).unwrap_or_default())
        }
        OutboundNode::LoadBalance { children, .. } => ("LoadBalance", children, String::new()),
        _ => return None,
    };
    let child_info: Vec<Value> = children
        .iter()
        .map(|c| {
            json!({
                "tag": c.tag(),
                "latency_rtt_ms": c.latency_rtt_ms(),
                "latency_http_ms": c.latency_http_ms(),
                "healthy": c.is_healthy(),
            })
        })
        .collect();
    Some(json!({
        "tag": tag,
        "type": node_type,
        "children": child_info,
        "selected": selected,
    }))
}

fn read_current(current: &RwLock<Option<Arc<OutboundNode>>>) -> String {
    current.read().unwrap_or_else(|e| e.into_inner()).as_ref().map(|n| n.tag().to_string()).unwrap_or_default()
}

#[derive(Deserialize)]
pub struct SelectReq {
    pub group: String,
    pub target: String,
}

pub async fn select_proxy(State(app_state): State<AppState>, Json(req): Json<SelectReq>) -> axum::response::Response {
    use axum::response::IntoResponse;
    // 鉴权 + CSRF 由 auth_mw 中间件统一处理 (方案 B), 此处不再重复启发式检查。
    let st = app_state.state.load();

    if let Some(group_node) = st.outbounds.outbounds.get(&req.group) {
        if let OutboundNode::Selector { children, current, .. } = group_node.as_ref() {
            if let Some(target_node) = children.iter().find(|c| c.tag() == req.target) {
                // 写锁只罩住切换本身; 落盘 (含 fsync) 放到阻塞线程池, 不卡选路也不占 tokio worker
                *current.write().unwrap_or_else(|e| e.into_inner()) = Some(target_node.clone());
                let (path, group, current) =
                    (st.outbounds.selector_persist_path.clone(), req.group.clone(), current.clone());
                tokio::task::spawn_blocking(move || {
                    // 锁内读内存最新值再写: 连切时落盘顺序乱了也不会把旧选择写成最终结果
                    crate::proxy::selector_state::save_selector_current(&path, &group, || {
                        current.read().unwrap_or_else(|e| e.into_inner()).as_ref().map(|n| n.tag().to_string())
                    })
                });
                return Json(json!({"status": "success", "message": format!("Switched {} to {}", req.group, req.target)})).into_response();
            }
        }
    }

    super::super::err_resp(
        axum::http::StatusCode::NOT_FOUND,
        "not_found",
        "找不到该出站组或目标节点",
        vec![],
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn leaf(tag: &str) -> Arc<OutboundNode> {
        Arc::new(OutboundNode::Direct { tag: tag.into() })
    }

    #[test]
    fn group_json_covers_all_group_types() {
        let a = leaf("a");
        let b = leaf("b");
        let sel = Arc::new(OutboundNode::Selector {
            tag: "sel".into(),
            children: vec![a.clone(), b.clone()],
            current: Arc::new(RwLock::new(Some(b.clone()))),
        });
        let v = group_json("sel", &sel).unwrap();
        assert_eq!(v["type"], "Selector");
        assert_eq!(v["selected"], "b");
        assert_eq!(v["children"][0]["healthy"], true);
        assert!(v["children"][0]["latency_rtt_ms"].is_null());

        let fb = Arc::new(OutboundNode::Fallback { tag: "fb".into(), children: vec![a.clone(), b.clone()] });
        let v = group_json("fb", &fb).unwrap();
        assert_eq!(v["type"], "Fallback");
        assert_eq!(v["selected"], "a");

        let lb = Arc::new(OutboundNode::LoadBalance {
            tag: "lb".into(),
            children: vec![a.clone(), b],
            next: Arc::new(std::sync::atomic::AtomicU64::new(0)),
        });
        let v = group_json("lb", &lb).unwrap();
        assert_eq!(v["type"], "LoadBalance");
        assert_eq!(v["selected"], "");

        assert!(group_json("a", &a).is_none());
    }
}
