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

// 历史流量与拦截数据记录器
// 使用高性能的 VecDeque (双端队列) 维持一个固定长度的滑动窗口
pub struct HistoryData {
    // 记录每秒钟增加的上行流量 (Bytes)
    pub up: std::collections::VecDeque<u64>,
    // 记录每秒钟增加的下行流量 (Bytes)
    pub down: std::collections::VecDeque<u64>,
    // 记录每秒钟 eBPF 成功在内核层拦截/处理的包数
    pub bpf: std::collections::VecDeque<u64>,
}

#[derive(Clone)]
pub struct AppState {
    pub state: Arc<ArcSwap<CoreState>>,
    pub ebpf_engine: Option<Arc<tokio::sync::Mutex<crate::ebpf::EbpfEngine>>>,
    pub xdp_engine: Option<Arc<crate::ebpf::XdpEngine>>,
    pub config_path: String,
    pub history: Arc<std::sync::RwLock<HistoryData>>,
}

pub async fn start_server(listen_addr: &str, state: Arc<ArcSwap<CoreState>>, ebpf_engine: Option<Arc<tokio::sync::Mutex<crate::ebpf::EbpfEngine>>>, xdp_engine: Option<Arc<crate::ebpf::XdpEngine>>, config_path: String) {
    // 1. 初始化历史数据结构，窗口大小设定为 120 (即记录过去 120 秒 / 2分钟 的数据)
    // 预先填充 0 以避免前端在数据不足时渲染异常
    let history = Arc::new(std::sync::RwLock::new(HistoryData {
        up: { let mut v = std::collections::VecDeque::new(); v.resize(120, 0); v },
        down: { let mut v = std::collections::VecDeque::new(); v.resize(120, 0); v },
        bpf: { let mut v = std::collections::VecDeque::new(); v.resize(120, 0); v },
    }));
    
    let app_state = AppState { state, ebpf_engine, xdp_engine, config_path, history: history.clone() };
    
    // 2. 启动一个常驻的后台监控协程 (Daemon Task)
    // 目的：每秒钟醒来一次，计算过去一秒内各项指标的 Delta 差值 (即流速)，并压入历史队列
    let bg_state = app_state.clone();
    tokio::spawn(async move {
        // 获取循环开始前的初始绝对数值
        let mut last_up = crate::monitor::GLOBAL_UP.load(Ordering::Relaxed);
        let mut last_down = crate::monitor::GLOBAL_DOWN.load(Ordering::Relaxed);
        let mut last_bpf = 0;
        
        loop {
            // 精确睡眠 1 秒
            tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
            
            // 采样当前时刻的绝对数值
            let up = crate::monitor::GLOBAL_UP.load(Ordering::Relaxed);
            let down = crate::monitor::GLOBAL_DOWN.load(Ordering::Relaxed);
            let mut bpf_success = 0;
            
            // 尝试获取 eBPF 引擎的统计信息
            if let Some(engine) = &bg_state.ebpf_engine {
                if let Ok(lock) = engine.try_lock() {
                    if let Ok((s, _)) = lock.get_stats() {
                        bpf_success = s;
                    }
                }
            }
            
            // 计算 Delta (流速) = 当前总数 - 上一秒总数
            // saturating_sub 用于防止特殊情况下数值溢出导致 panic
            let up_diff = up.saturating_sub(last_up);
            let down_diff = down.saturating_sub(last_down);
            let bpf_diff = bpf_success.saturating_sub(last_bpf);
            
            // 更新 last 值供下一轮使用
            last_up = up;
            last_down = down;
            last_bpf = bpf_success;
            
            // 将计算出的流速数据压入双端队列，并剔除最老的数据，保持队列长度为 120
            if let Ok(mut h) = bg_state.history.write() {
                h.up.pop_front(); h.up.push_back(up_diff);
                h.down.pop_front(); h.down.push_back(down_diff);
                h.bpf.pop_front(); h.bpf.push_back(bpf_diff);
            }
        }
    });

    let app = Router::new()
        .route("/api/overview", get(get_overview))
        .route("/api/history", get(get_history))
        .route("/api/logs", get(get_logs))
        .route("/api/proxies", get(get_proxies))
        .route("/api/proxies/select", post(select_proxy))
        .route("/api/rules", get(get_rules).post(update_rules))
        .route("/api/bpf/tunnels", get(get_bpf_tunnels))
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
    let mut tunnel_count = 0usize;
    let mut brutal_cc_active = false;
    // engine_online = sockmap/sockops 子系统在内核加载成功. 服务端没 XDP 但有 sockmap,
    // 客户端两者都有. 之前 GUI 只看 xdp_attached 导致服务端永远 OFFLINE 误导用户.
    let mut engine_online = false;
    if let Some(engine) = state.ebpf_engine {
        if let Ok(lock) = engine.try_lock() {
            if let Ok((s, f)) = lock.get_stats() {
                bpf_success = s;
                bpf_fallback = f;
                engine_online = true; // get_stats 成功 = mirage_bpf_stats map 可读 = BPF 加载成功
            }
            if let Ok(tunnels) = lock.get_all_tunnel_stats() {
                tunnel_count = tunnels.len();
                // 任何一条 tunnel 有 srtt_us > 0 即说明 RTT_CB 已生效, Brutal CC 拿得到反馈
                brutal_cc_active = tunnels.iter().any(|(_, s)| s.srtt_us > 0);
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
        "xdp_attached": xdp_attached,
        "engine_online": engine_online,
        "tunnel_count": tunnel_count,
        "brutal_cc_active": brutal_cc_active,
    }))
}

// 列出当前 BPF 跟踪的所有活跃 TCP tunnel.
// cookie 为内核 SO_COOKIE, 唯一标识一条 socket; 字段为 sockmap.c::tcp_state.
// srtt_us 已折算成毫秒返回; LRU 淘汰的 cookie 自动从列表消失.
async fn get_bpf_tunnels(State(state): State<AppState>) -> Json<Value> {
    let mut tunnels: Vec<Value> = Vec::new();
    if let Some(engine) = state.ebpf_engine {
        if let Ok(lock) = engine.try_lock() {
            if let Ok(entries) = lock.get_all_tunnel_stats() {
                tunnels = entries.into_iter().map(|(cookie, s)| {
                    json!({
                        "cookie": cookie,
                        "rtt_ms": s.srtt_us as f64 / 1000.0,
                        "cwnd": s.snd_cwnd,
                        "retrans": s.total_retrans,
                        "data_segs": s.data_segs_out,
                    })
                }).collect();
            }
        }
    }
    Json(json!({ "tunnels": tunnels }))
}

async fn get_history(State(state): State<AppState>) -> Json<Value> {
    if let Ok(h) = state.history.read() {
        Json(json!({
            "up": h.up,
            "down": h.down,
            "bpf_success": h.bpf,
        }))
    } else {
        Json(json!({}))
    }
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
