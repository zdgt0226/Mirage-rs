//! Web API handlers. 每个 endpoint 一个文件 (或几个相关 endpoint 一组).
//!
//! 所有 handler 函数都接收 `State<AppState>` 作为 axum 路由参数.

/// 串行化配置文件 RMW: rules / profiles 两个写端点共用 config.json + 同名 `.tmp`。无锁时
/// 并发 (或两端点交错) POST 会撕裂 `.tmp`, 或"读旧→各自改→后写覆盖前写"丢更新。整段读改写
/// 在此锁下串行。
pub(crate) static CONFIG_WRITE_LOCK: std::sync::LazyLock<tokio::sync::Mutex<()>> =
    std::sync::LazyLock::new(|| tokio::sync::Mutex::new(()));

pub mod overview;
pub mod connections;
pub mod stats;
pub mod domains;
pub mod devices;
pub mod clients;
pub mod profiles;
pub mod tls_capture;
pub mod bpf_tunnels;
pub mod history;
pub mod logs;
pub mod proxies;
pub mod rules;
