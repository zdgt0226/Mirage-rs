//! Mirage-rs Web API (Neon Dashboard 后端 + 配置管理 endpoint).
//!
//! 模块拓扑 (v0.4.2 重组, 从 src/gui/ 改名):
//! - `state`: AppState 共享应用状态 + HistoryData 流量历史滑动窗口
//! - `sampler`: 后台 task, 每秒采样上下行流量 / BPF 命中数 Delta 压入 history
//! - `handlers/`: 每个 endpoint 一个文件
//!   - overview: GET /api/overview (Dashboard 顶部汇总)
//!   - connections: GET /api/connections (活跃连接 + 最近关闭, 域名连接信息)
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
mod ratelimit;

use axum::{
    routing::{get, post},
    response::{Html, IntoResponse, Response},
    http::{header, HeaderMap, Method, StatusCode, Uri},
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
///
/// 用 `subtle::ConstantTimeEq` 而非手写累加器 —— 手写 `diff |= a[i]^b[i]` 虽是正确惯用法, 但
/// Rust/LLVM **不保证**不会在优化时插入短路/向量化破坏常数时间; subtle 带优化屏障。
/// (原用 `ring::constant_time::verify_slices_are_equal`, 已被 ring 标记 deprecated 待移除,
/// 换 subtle 统一全仓常量时间比较。)
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    use subtle::ConstantTimeEq;
    a.ct_eq(b).into()
}

/// token 来源。CSRF 判定要用: **Bearer header 天然抗 CSRF** (跨站页面发不出自定义
/// Authorization header, 除非 CORS 预检而服务端不放行); Cookie 会被浏览器跨站自动带, 需防护。
#[derive(Clone, Copy, PartialEq)]
enum TokenSrc {
    Bearer,
    Cookie,
    Query,
}

/// 从请求里按优先级提取 token + 来源: Authorization: Bearer → mirage_token cookie → ?token=。
/// `allow_query`: 是否接受 URL `?token=`。仅根路径 `/` 传 true (首访种 cookie 用); `/api/*`
/// 传 false —— token 出现在 URL 会进浏览器历史/Referer/反代日志, 不该作为 API 的长期认证入口。
fn extract_token_src(headers: &HeaderMap, uri: &Uri, allow_query: bool) -> Option<(String, TokenSrc)> {
    // 1. Authorization: Bearer <t> (CLI / 脚本首选)
    if let Some(v) = headers.get(header::AUTHORIZATION).and_then(|h| h.to_str().ok()) {
        if let Some(t) = v.strip_prefix("Bearer ") {
            return Some((t.trim().to_string(), TokenSrc::Bearer));
        }
    }
    // 2. Cookie: mirage_token=<t> (浏览器种一次即自动带)
    if let Some(c) = headers.get(header::COOKIE).and_then(|h| h.to_str().ok()) {
        for kv in c.split(';') {
            if let Some(t) = kv.trim().strip_prefix("mirage_token=") {
                return Some((t.to_string(), TokenSrc::Cookie));
            }
        }
    }
    // 3. ?token=<t> —— 仅根路径 (allow_query) 接受, 供浏览器首访 /?token=XXX 种 cookie。
    if allow_query {
        if let Some(q) = uri.query() {
            for kv in q.split('&') {
                if let Some(t) = kv.strip_prefix("token=") {
                    return Some((t.to_string(), TokenSrc::Query));
                }
            }
        }
    }
    None
}

#[cfg(test)]
fn extract_token(headers: &HeaderMap, uri: &Uri, allow_query: bool) -> Option<String> {
    extract_token_src(headers, uri, allow_query).map(|(t, _)| t)
}

/// 同源判定 (CSRF 防护): Origin (优先) 或 Referer 的 authority 是否等于 Host header。
/// 变更请求两者都无 → 判为非同源 (保守: 合法浏览器同源 POST 会带 Origin)。
fn same_origin(headers: &HeaderMap) -> bool {
    let Some(host) = headers.get(header::HOST).and_then(|h| h.to_str().ok()) else {
        return false;
    };
    let authority_of = |url: &str| -> Option<String> {
        url.split_once("://").map(|(_, rest)| rest.split('/').next().unwrap_or("").to_string())
    };
    if let Some(o) = headers.get(header::ORIGIN).and_then(|h| h.to_str().ok()) {
        return authority_of(o).as_deref() == Some(host);
    }
    if let Some(r) = headers.get(header::REFERER).and_then(|h| h.to_str().ok()) {
        return authority_of(r).as_deref() == Some(host);
    }
    false
}

/// 鉴权 + CSRF 中间件。
/// - **鉴权**: gui.token 设了才拦, 校验 Authorization/cookie/query 任一; 未配 → 放行 (localhost 默认)。
/// - **CSRF** (方案 B): 变更方法 (POST/PUT/DELETE/PATCH) 且**非 Bearer-header 认证**时, 要求同源
///   (Origin/Referer 匹配 Host)。理由: Bearer header 跨站发不出 → 抗 CSRF, 直接放行; cookie 会被
///   浏览器跨站自动带, 必须同源防护; 未启用 token 的 localhost 写接口也靠这层挡恶意网页/DNS-rebinding。
async fn auth_mw(
    State(app): State<AppState>,
    axum::extract::ConnectInfo(peer): axum::extract::ConnectInfo<SocketAddr>,
    req: Request,
    next: Next,
) -> Response {
    // 1. 鉴权 (若配了 token), 记录认证来源供 CSRF 判定。
    let auth_src: Option<TokenSrc> = match app.gui_token.as_ref() {
        None => None, // 未启用鉴权 (无 token = 无暴力面, 不限流)
        Some(expected) => {
            let ip = peer.ip();
            let now = std::time::Instant::now();
            // 先看该 IP 是否已因反复失败被锁定 → 429, 挡在 token 比较之前 (省 CPU + 明确信号)。
            if app
                .rate_limiter
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .is_locked(ip, now)
            {
                return (
                    StatusCode::TOO_MANY_REQUESTS,
                    "too many failed auth attempts; this IP is temporarily locked out",
                )
                    .into_response();
            }
            // ?token= 仅根路径认 (首访种 cookie); /api/* 只认 header/cookie, 避免 token 进 URL 日志。
            let allow_query = req.uri().path() == "/";
            match extract_token_src(req.headers(), req.uri(), allow_query) {
                Some((t, src)) if ct_eq(t.as_bytes(), expected.as_bytes()) => {
                    // 认证成功 → 清该 IP 失败记录。
                    app.rate_limiter
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .note_success(ip);
                    Some(src)
                }
                _ => {
                    // 认证失败 → 记一次, 累计超阈后续请求会被上面的 is_locked 拦成 429。
                    app.rate_limiter
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .note_failure(ip, now);
                    return (
                        StatusCode::UNAUTHORIZED,
                        "unauthorized: missing/invalid API token (set Authorization: Bearer, mirage_token cookie, or ?token=)",
                    )
                        .into_response();
                }
            }
        }
    };

    // 2. CSRF: 变更方法 + 非 Bearer 认证 → 要求同源。Bearer header 抗 CSRF, 免检。
    let mutating = matches!(*req.method(), Method::POST | Method::PUT | Method::DELETE | Method::PATCH);
    if mutating && auth_src != Some(TokenSrc::Bearer) && !same_origin(req.headers()) {
        return (
            StatusCode::FORBIDDEN,
            "csrf: cross-origin state-changing request rejected (use Authorization: Bearer for automation, or same-origin browser request)",
        )
            .into_response();
    }

    next.run(req).await
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
    is_server: bool,
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
        rate_limiter: Arc::new(std::sync::Mutex::new(ratelimit::RateLimiter::new())),
        is_server,
    };

    // 2. 启动 1Hz 采样后台 task
    sampler::spawn(app_state.clone());

    // 3. 装配 axum 路由 + 鉴权中间件 (route_layer: 只对已匹配路由跑, 不含 404)
    let app = Router::new()
        .route("/api/overview", get(handlers::overview::get_overview))
        .route("/api/connections", get(handlers::connections::get_connections))
        .route("/api/stats", get(handlers::stats::get_stats))
        .route("/api/domains", get(handlers::domains::get_domains))
        .route("/api/devices", get(handlers::devices::get_devices))
        .route("/api/clients", get(handlers::clients::get_clients))
        .route("/api/clients/block", post(handlers::clients::post_block))
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
    // into_make_service_with_connect_info: 让 auth_mw 能拿到 TCP peer IP (per-IP 限流用)。
    let app = app.into_make_service_with_connect_info::<SocketAddr>();
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
        assert_eq!(extract_token(&h, &uri, false).as_deref(), Some("abc123"));
    }

    #[test]
    fn extract_from_cookie() {
        let h = headers_with(header::COOKIE, "foo=1; mirage_token=tok42; bar=2");
        let uri: Uri = "/api/x".parse().unwrap();
        assert_eq!(extract_token(&h, &uri, false).as_deref(), Some("tok42"));
    }

    #[test]
    fn extract_from_query_only_when_allowed() {
        let h = HeaderMap::new();
        let uri: Uri = "/?a=1&token=qtok&b=2".parse().unwrap();
        // 根路径放行 query token (首访种 cookie)
        assert_eq!(extract_token(&h, &uri, true).as_deref(), Some("qtok"));
        // /api/* 不放行 query token —— 防 token 进 URL 日志
        assert_eq!(extract_token(&h, &uri, false), None);
    }

    #[test]
    fn extract_precedence_bearer_over_cookie() {
        let mut h = HeaderMap::new();
        h.insert(header::AUTHORIZATION, "Bearer bearer_tok".parse().unwrap());
        h.insert(header::COOKIE, "mirage_token=cookie_tok".parse().unwrap());
        let uri: Uri = "/".parse().unwrap();
        assert_eq!(extract_token(&h, &uri, true).as_deref(), Some("bearer_tok"));
    }

    #[test]
    fn extract_none_when_absent() {
        let h = HeaderMap::new();
        let uri: Uri = "/api/x".parse().unwrap();
        assert_eq!(extract_token(&h, &uri, false), None);
    }

    #[test]
    fn ct_eq_semantics() {
        assert!(ct_eq(b"secret-token", b"secret-token"), "相等应 true");
        assert!(!ct_eq(b"secret-token", b"secret-toXen"), "有差异应 false");
        assert!(!ct_eq(b"short", b"short-longer"), "长度不同应 false");
        assert!(ct_eq(b"", b""), "空 == 空");
    }

    #[test]
    fn token_source_classified() {
        let uri: Uri = "/".parse().unwrap();
        let h = headers_with(header::AUTHORIZATION, "Bearer b");
        assert!(matches!(extract_token_src(&h, &uri, true), Some((_, TokenSrc::Bearer))));
        let h = headers_with(header::COOKIE, "mirage_token=c");
        assert!(matches!(extract_token_src(&h, &uri, true), Some((_, TokenSrc::Cookie))));
        let uri_q: Uri = "/?token=q".parse().unwrap();
        assert!(matches!(extract_token_src(&HeaderMap::new(), &uri_q, true), Some((_, TokenSrc::Query))));
    }

    #[test]
    fn same_origin_checks() {
        // Origin authority 匹配 Host → 同源
        let mut h = HeaderMap::new();
        h.insert(header::HOST, "1.2.3.4:9090".parse().unwrap());
        h.insert(header::ORIGIN, "http://1.2.3.4:9090".parse().unwrap());
        assert!(same_origin(&h));
        // Origin 不匹配 → 非同源
        let mut h = HeaderMap::new();
        h.insert(header::HOST, "1.2.3.4:9090".parse().unwrap());
        h.insert(header::ORIGIN, "http://evil.example".parse().unwrap());
        assert!(!same_origin(&h));
        // 无 Origin 无 Referer → 保守判非同源
        let mut h = HeaderMap::new();
        h.insert(header::HOST, "1.2.3.4:9090".parse().unwrap());
        assert!(!same_origin(&h));
        // 退回 Referer 匹配
        let mut h = HeaderMap::new();
        h.insert(header::HOST, "host:80".parse().unwrap());
        h.insert(header::REFERER, "http://host:80/page".parse().unwrap());
        assert!(same_origin(&h));
    }
}
