//! Mirage-rs Web API (Neon Dashboard 后端 + 配置管理 endpoint).
//!
//! 模块拓扑 (v0.4.2 重组, 从 src/gui/ 改名):
//! - `state`: AppState 共享应用状态 + HistoryData 流量历史滑动窗口
//! - `sampler`: 后台 task, 每秒采样上下行流量 / BPF 命中数 Delta 压入 history
//! - `handlers/`: 每个 endpoint 一个文件
//!   - overview: GET /api/overview (Dashboard 顶部汇总)
//!   - bpf_tunnels: GET /api/bpf/tunnels (per-tunnel BPF 数据)
//!   - history: GET /api/history (120s 滑动窗口数据)
//!   - logs: GET /api/logs (内存日志)
//!   - proxies: GET /api/proxies + POST /api/proxies/select
//!   - rules: GET + POST /api/rules
//!
//! 设计原则: 自有 API 路径, 不做 Clash 兼容 (见 architecture_decisions).

mod state;
mod sampler;
mod handlers;

use axum::{
    routing::{get, post},
    response::{Html, IntoResponse, Response},
    http::{header, HeaderMap, StatusCode, Uri},
    middleware::{self, Next},
    extract::{Request, State},
    Router,
};
use std::collections::VecDeque;
use std::net::SocketAddr;
use std::sync::Arc;
use arc_swap::ArcSwap;
use crate::config_watcher::CoreState;

pub use state::AppState;

/// 常量时间比较, 防 token 校验的时序侧信道 (长度不同直接不等; 长度本身不敏感)。
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for i in 0..a.len() {
        diff |= a[i] ^ b[i];
    }
    diff == 0
}

/// 从请求里按优先级提取 token: Authorization: Bearer <t> → mirage_token cookie → ?token=<t>。
fn extract_token(headers: &HeaderMap, uri: &Uri) -> Option<String> {
    // 1. Authorization: Bearer <t> (CLI / 脚本首选)
    if let Some(v) = headers.get(header::AUTHORIZATION).and_then(|h| h.to_str().ok()) {
        if let Some(t) = v.strip_prefix("Bearer ") {
            return Some(t.trim().to_string());
        }
    }
    // 2. Cookie: mirage_token=<t> (浏览器种一次即自动带)
    if let Some(c) = headers.get(header::COOKIE).and_then(|h| h.to_str().ok()) {
        for kv in c.split(';') {
            if let Some(t) = kv.trim().strip_prefix("mirage_token=") {
                return Some(t.to_string());
            }
        }
    }
    // 3. ?token=<t> (浏览器首次访问 /?token=XXX 用; 假设 token 为 url-safe)
    if let Some(q) = uri.query() {
        for kv in q.split('&') {
            if let Some(t) = kv.strip_prefix("token=") {
                return Some(t.to_string());
            }
        }
    }
    None
}

/// 鉴权中间件: gui.token 设了才拦。校验 Authorization/cookie/query 三者任一。
/// 未配 token → 直接放行 (向后兼容, localhost 默认部署)。
async fn auth_mw(State(app): State<AppState>, req: Request, next: Next) -> Response {
    let Some(expected) = app.gui_token.as_ref() else {
        return next.run(req).await; // 未启用鉴权
    };
    match extract_token(req.headers(), req.uri()) {
        Some(t) if ct_eq(t.as_bytes(), expected.as_bytes()) => next.run(req).await,
        _ => (
            StatusCode::UNAUTHORIZED,
            "unauthorized: missing/invalid API token (set Authorization: Bearer, mirage_token cookie, or ?token=)",
        )
            .into_response(),
    }
}

/// 根路由: 服务 SPA。若带合法 ?token= 则顺手种 HttpOnly cookie, 之后 SPA 的 fetch 自动带,
/// 无需改前端。(能走到这里说明 auth_mw 已放行, 即 token 合法或未启用鉴权。)
async fn serve_root(State(app): State<AppState>, uri: Uri) -> Response {
    let html = Html(include_str!("index.html"));
    if let (Some(expected), Some(q)) = (app.gui_token.as_ref(), uri.query()) {
        for kv in q.split('&') {
            if let Some(t) = kv.strip_prefix("token=") {
                if ct_eq(t.as_bytes(), expected.as_bytes()) {
                    // SameSite=Strict + HttpOnly: 防 CSRF 自动带 cookie 到跨站 + 防 JS 读取。
                    let cookie = format!("mirage_token={t}; HttpOnly; SameSite=Strict; Path=/");
                    return ([(header::SET_COOKIE, cookie)], html).into_response();
                }
            }
        }
    }
    html.into_response()
}

pub async fn start_server(
    listen_addr: &str,
    state: Arc<ArcSwap<CoreState>>,
    ebpf_engine: Option<Arc<tokio::sync::Mutex<crate::ebpf::EbpfEngine>>>,
    xdp_engine: Option<Arc<crate::ebpf::XdpEngine>>,
    config_path: String,
    token: Option<String>,
) {
    // 1. 初始化历史数据结构，窗口大小设定为 120 (即记录过去 120 秒 / 2分钟 的数据)
    // 预先填充 0 以避免前端在数据不足时渲染异常
    let history = Arc::new(std::sync::RwLock::new(state::HistoryData {
        up: { let mut v = VecDeque::new(); v.resize(120, 0); v },
        down: { let mut v = VecDeque::new(); v.resize(120, 0); v },
        bpf: { let mut v = VecDeque::new(); v.resize(120, 0); v },
    }));

    let gui_token = token.filter(|t| !t.is_empty()).map(Arc::new);
    let auth_enabled = gui_token.is_some();
    let app_state = AppState {
        state,
        ebpf_engine,
        xdp_engine,
        config_path,
        history: history.clone(),
        gui_token,
    };

    // 2. 启动 1Hz 采样后台 task
    sampler::spawn(app_state.clone());

    // 3. 装配 axum 路由 + 鉴权中间件 (route_layer: 只对已匹配路由跑, 不含 404)
    let app = Router::new()
        .route("/api/overview", get(handlers::overview::get_overview))
        .route("/api/history", get(handlers::history::get_history))
        .route("/api/logs", get(handlers::logs::get_logs))
        .route("/api/proxies", get(handlers::proxies::get_proxies))
        .route("/api/proxies/select", post(handlers::proxies::select_proxy))
        .route("/api/rules", get(handlers::rules::get_rules).post(handlers::rules::update_rules))
        .route("/api/bpf/tunnels", get(handlers::bpf_tunnels::get_bpf_tunnels))
        .route("/", get(serve_root))
        .route_layer(middleware::from_fn_with_state(app_state.clone(), auth_mw))
        .with_state(app_state);

    let addr: SocketAddr = match listen_addr.parse() {
        Ok(a) => a,
        Err(e) => {
            tracing::error!("GUI listen addr '{}' 非法 ({}); GUI 未启动", listen_addr, e);
            return;
        }
    };

    if auth_enabled {
        tracing::info!("GUI Server listening on http://{} (API 鉴权已启用; 浏览器用 /?token=XXX 访问)", addr);
    } else if !addr.ip().is_loopback() {
        tracing::warn!(
            "GUI Server listening on http://{} 且**未设 gui.token** —— 非 localhost 暴露, 任何可达者可读日志/配置+改路由规则! 请设 gui.token 或外挂 nginx 鉴权",
            addr
        );
    } else {
        tracing::info!("GUI Server listening on http://{} (localhost, 未设 token)", addr);
    }

    let listener = match tokio::net::TcpListener::bind(addr).await {
        Ok(l) => l,
        Err(e) => {
            tracing::error!("GUI 绑定 {} 失败 ({}); GUI 未启动 (端口占用?)", addr, e);
            return;
        }
    };
    if let Err(e) = axum::serve(listener, app).await {
        tracing::error!("GUI serve 退出: {}", e);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ct_eq_basic() {
        assert!(ct_eq(b"secret", b"secret"));
        assert!(!ct_eq(b"secret", b"secreT"));
        assert!(!ct_eq(b"secret", b"secre"));   // 长度不同
        assert!(!ct_eq(b"", b"x"));
        assert!(ct_eq(b"", b""));
    }

    fn headers_with(name: header::HeaderName, val: &str) -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert(name, val.parse().unwrap());
        h
    }

    #[test]
    fn extract_from_bearer() {
        let h = headers_with(header::AUTHORIZATION, "Bearer abc123");
        let uri: Uri = "/api/x".parse().unwrap();
        assert_eq!(extract_token(&h, &uri).as_deref(), Some("abc123"));
    }

    #[test]
    fn extract_from_cookie() {
        let h = headers_with(header::COOKIE, "foo=1; mirage_token=tok42; bar=2");
        let uri: Uri = "/api/x".parse().unwrap();
        assert_eq!(extract_token(&h, &uri).as_deref(), Some("tok42"));
    }

    #[test]
    fn extract_from_query() {
        let h = HeaderMap::new();
        let uri: Uri = "/?a=1&token=qtok&b=2".parse().unwrap();
        assert_eq!(extract_token(&h, &uri).as_deref(), Some("qtok"));
    }

    #[test]
    fn extract_precedence_bearer_over_cookie() {
        let mut h = HeaderMap::new();
        h.insert(header::AUTHORIZATION, "Bearer bearer_tok".parse().unwrap());
        h.insert(header::COOKIE, "mirage_token=cookie_tok".parse().unwrap());
        let uri: Uri = "/".parse().unwrap();
        assert_eq!(extract_token(&h, &uri).as_deref(), Some("bearer_tok"));
    }

    #[test]
    fn extract_none_when_absent() {
        let h = HeaderMap::new();
        let uri: Uri = "/api/x".parse().unwrap();
        assert_eq!(extract_token(&h, &uri), None);
    }
}
