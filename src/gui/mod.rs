use axum::{
    routing::{get, post},
    response::Html,
    Json, Router,
    extract::State,
    http::HeaderMap,
};
use std::net::SocketAddr;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use serde_json::{json, Value};
use serde::Deserialize;
use arc_swap::ArcSwap;
use crate::monitor::{GLOBAL_UP, GLOBAL_DOWN, GLOBAL_LOGGER};
use crate::config_watcher::CoreState;
use crate::proxy::outbound::OutboundNode;

#[derive(Clone)]
pub struct AppState {
    pub state: Arc<ArcSwap<CoreState>>,
    pub ebpf_engine: Option<Arc<tokio::sync::Mutex<crate::ebpf::EbpfEngine>>>,
    pub xdp_engine: Option<Arc<crate::ebpf::XdpEngine>>,
    pub config_path: String,
}

pub async fn start_server(listen_addr: &str, state: Arc<ArcSwap<CoreState>>, ebpf_engine: Option<Arc<tokio::sync::Mutex<crate::ebpf::EbpfEngine>>>, xdp_engine: Option<Arc<crate::ebpf::XdpEngine>>, config_path: String) {
    let app_state = AppState { state, ebpf_engine, xdp_engine, config_path };
    
    let app = Router::new()
        .route("/api/overview", get(get_overview))
        .route("/api/logs", get(get_logs))
        .route("/api/proxies", get(get_proxies))
        .route("/api/proxies/select", post(select_proxy))
        .route("/api/rules", get(get_rules).post(update_rules))
        .route("/", get(|| async { Html(include_str!("index.html")) }))
        .with_state(app_state);

    let addr: SocketAddr = listen_addr.parse().expect("Invalid GUI listen address");
    tracing::info!("GUI Server listening on http://{}", addr);

    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}

async fn get_overview(State(state): State<AppState>) -> Json<Value> {
    let up = GLOBAL_UP.load(Ordering::Relaxed);
    let down = GLOBAL_DOWN.load(Ordering::Relaxed);
    
    let mut bpf_success = 0;
    let mut bpf_fallback = 0;
    if let Some(engine) = state.ebpf_engine {
        if let Ok(lock) = engine.try_lock() {
            if let Ok((s, f)) = lock.get_stats() {
                bpf_success = s;
                bpf_fallback = f;
            }
        }
    }
    
    let xdp_attached = state.xdp_engine.as_ref().map(|e| e.attached.load(Ordering::Relaxed)).unwrap_or(0);
    
    Json(json!({
        "up": up,
        "down": down,
        "connections": 0,
        "bpf_success": bpf_success,
        "bpf_fallback": bpf_fallback,
        "xdp_attached": xdp_attached
    }))
}

async fn get_logs() -> Json<Value> {
    let logs = GLOBAL_LOGGER.get_logs();
    Json(json!({
        "logs": logs
    }))
}

async fn get_proxies(State(app_state): State<AppState>) -> Json<Value> {
    let st = app_state.state.load();
    let mut proxies = Vec::new();
    
    for (tag, node) in &st.outbounds.outbounds {
        match node.as_ref() {
            OutboundNode::Selector { children, current, .. } | OutboundNode::Urltest { children, current, .. } => {
                let mut child_info = Vec::new();
                for c in children {
                    child_info.push(json!({
                        "tag": c.tag(),
                        "latency_rtt_ms": c.latency_rtt_ms(),
                        "latency_http_ms": c.latency_http_ms(),
                    }));
                }
                
                let selected = current.read().unwrap().as_ref().map(|n| n.tag().to_string()).unwrap_or_default();
                let node_type = if matches!(node.as_ref(), OutboundNode::Selector { .. }) { "Selector" } else { "UrlTest" };
                
                proxies.push(json!({
                    "tag": tag,
                    "type": node_type,
                    "children": child_info,
                    "selected": selected,
                }));
            }
            _ => {}
        }
    }
    
    Json(json!({ "proxies": proxies }))
}

#[derive(Deserialize)]
struct SelectReq {
    group: String,
    target: String,
}

async fn select_proxy(State(app_state): State<AppState>, headers: HeaderMap, Json(req): Json<SelectReq>) -> Json<Value> {
    let is_xhr = headers.get("x-requested-with").and_then(|h| h.to_str().ok()).unwrap_or("") == "XMLHttpRequest";
    let is_cli = headers.get("user-agent").map_or(false, |v| v.as_bytes().starts_with(b"curl/"));
    
    if !is_xhr && !is_cli {
        let host = headers.get("host").and_then(|h| h.to_str().ok()).unwrap_or("");
        if let Some(origin) = headers.get("origin").and_then(|h| h.to_str().ok()) {
            let expected = format!("//{}", host);
            if !origin.ends_with(&expected) {
                return Json(json!({"status": "error", "message": "CSRF check failed"}));
            }
        } else {
            return Json(json!({"status": "error", "message": "CSRF check failed: Missing Origin or X-Requested-With"}));
        }
    }

    let st = app_state.state.load();
    
    if let Some(group_node) = st.outbounds.outbounds.get(&req.group) {
        if let OutboundNode::Selector { children, current, .. } = group_node.as_ref() {
            if let Some(target_node) = children.iter().find(|c| c.tag() == req.target) {
                let mut curr = current.write().unwrap();
                *curr = Some(target_node.clone());
                return Json(json!({"status": "success", "message": format!("Switched {} to {}", req.group, req.target)}));
            }
        }
    }
    
    Json(json!({"status": "error", "message": "Group or target not found"}))
}

async fn get_rules(State(app_state): State<AppState>) -> Json<Value> {
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
struct UpdateRulesReq {
    rules: Value,
}

async fn update_rules(State(app_state): State<AppState>, headers: HeaderMap, Json(req): Json<UpdateRulesReq>) -> Json<Value> {
    let is_xhr = headers.get("x-requested-with").and_then(|h| h.to_str().ok()).unwrap_or("") == "XMLHttpRequest";
    let is_cli = headers.get("user-agent").map_or(false, |v| v.as_bytes().starts_with(b"curl/"));
    
    if !is_xhr && !is_cli {
        let host = headers.get("host").and_then(|h| h.to_str().ok()).unwrap_or("");
        if let Some(origin) = headers.get("origin").and_then(|h| h.to_str().ok()) {
            let expected = format!("//{}", host);
            if !origin.ends_with(&expected) {
                return Json(json!({"status": "error", "message": "CSRF check failed"}));
            }
        } else {
            return Json(json!({"status": "error", "message": "CSRF check failed: Missing Origin or X-Requested-With"}));
        }
    }

    if let Ok(content) = tokio::fs::read_to_string(&app_state.config_path).await {
        if let Ok(mut v) = serde_json::from_str::<Value>(&content) {
            if let Some(routing) = v.get_mut("routing").and_then(|r| r.as_object_mut()) {
                routing.insert("rules".to_string(), req.rules);
                if let Ok(new_content) = serde_json::to_string_pretty(&v) {
                    if tokio::fs::write(&app_state.config_path, new_content).await.is_ok() {
                        return Json(json!({"status": "success"}));
                    }
                }
            }
        }
    }
    Json(json!({"status": "error", "message": "Failed to write rules to config file"}))
}
