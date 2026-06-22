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
    response::Html,
    Router,
};
use std::collections::VecDeque;
use std::net::SocketAddr;
use std::sync::Arc;
use arc_swap::ArcSwap;
use crate::config_watcher::CoreState;

pub use state::AppState;

pub async fn start_server(
    listen_addr: &str,
    state: Arc<ArcSwap<CoreState>>,
    ebpf_engine: Option<Arc<tokio::sync::Mutex<crate::ebpf::EbpfEngine>>>,
    xdp_engine: Option<Arc<crate::ebpf::XdpEngine>>,
    config_path: String,
) {
    // 1. 初始化历史数据结构，窗口大小设定为 120 (即记录过去 120 秒 / 2分钟 的数据)
    // 预先填充 0 以避免前端在数据不足时渲染异常
    let history = Arc::new(std::sync::RwLock::new(state::HistoryData {
        up: { let mut v = VecDeque::new(); v.resize(120, 0); v },
        down: { let mut v = VecDeque::new(); v.resize(120, 0); v },
        bpf: { let mut v = VecDeque::new(); v.resize(120, 0); v },
    }));

    let app_state = AppState { state, ebpf_engine, xdp_engine, config_path, history: history.clone() };

    // 2. 启动 1Hz 采样后台 task
    sampler::spawn(app_state.clone());

    // 3. 装配 axum 路由
    let app = Router::new()
        .route("/api/overview", get(handlers::overview::get_overview))
        .route("/api/history", get(handlers::history::get_history))
        .route("/api/logs", get(handlers::logs::get_logs))
        .route("/api/proxies", get(handlers::proxies::get_proxies))
        .route("/api/proxies/select", post(handlers::proxies::select_proxy))
        .route("/api/rules", get(handlers::rules::get_rules).post(handlers::rules::update_rules))
        .route("/api/bpf/tunnels", get(handlers::bpf_tunnels::get_bpf_tunnels))
        .route("/", get(|| async { Html(include_str!("index.html")) }))
        .with_state(app_state);

    let addr: SocketAddr = listen_addr.parse().expect("Invalid GUI listen address");
    tracing::info!("GUI Server listening on http://{}", addr);

    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
