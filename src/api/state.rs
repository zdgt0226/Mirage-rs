//! API 共享的应用状态. handlers + sampler 都通过 AppState 访问.
//!
//! AppState 是 axum 路由的 State<>, handlers 拿到 `State(AppState)` 参数.

use arc_swap::ArcSwap;
use std::sync::Arc;
use std::collections::VecDeque;
use crate::config_watcher::CoreState;

// 历史流量与拦截数据记录器
// 使用高性能的 VecDeque (双端队列) 维持一个固定长度的滑动窗口
pub struct HistoryData {
    // 记录每秒钟增加的上行流量 (Bytes)
    pub up: VecDeque<u64>,
    // 记录每秒钟增加的下行流量 (Bytes)
    pub down: VecDeque<u64>,
    // 记录每秒钟 eBPF 成功在内核层拦截/处理的包数
    pub bpf: VecDeque<u64>,
}

#[derive(Clone)]
pub struct AppState {
    pub state: Arc<ArcSwap<CoreState>>,
    pub ebpf_engine: Option<Arc<tokio::sync::Mutex<crate::ebpf::EbpfEngine>>>,
    pub xdp_engine: Option<Arc<crate::ebpf::XdpEngine>>,
    pub config_path: String,
    pub history: Arc<std::sync::RwLock<HistoryData>>,
    /// 可选 API 鉴权 token (gui.token)。None = 不鉴权。auth 中间件按它校验所有请求。
    pub gui_token: Option<Arc<String>>,
    /// 认证失败限流 (per-IP 锁定, 防 token 暴力猜解)。仅在配了 gui_token 时生效。
    pub rate_limiter: Arc<std::sync::Mutex<super::ratelimit::RateLimiter>>,
    /// 运行模式: true=服务端 (mirage server), false=客户端/网关。WebUI 按此分视图 + 决定
    /// 服务端专属功能 (域名排行/连接历史/客户端管理) vs 客户端专属 (LAN 设备规则)。
    pub is_server: bool,
}
