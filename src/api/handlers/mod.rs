//! Web API handlers. 每个 endpoint 一个文件 (或几个相关 endpoint 一组).
//!
//! 所有 handler 函数都接收 `State<AppState>` 作为 axum 路由参数.

pub mod overview;
pub mod bpf_tunnels;
pub mod history;
pub mod logs;
pub mod proxies;
pub mod rules;
