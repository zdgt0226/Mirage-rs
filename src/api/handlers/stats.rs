//! GET /api/stats — per-出站分流量/连接数 + per-规则命中统计 (WebUI Phase 4)。
//!
//! - outbounds: 每个出站的累计上下行字节 + 累计连接数 + 当前活跃数 (源: monitor 连接登记表)。
//! - rules: 每条路由规则的命中次数 (索引 = config routing.rules 顺序; 源: router hit 计数,
//!   随配置热重载重建 engine 归零)。default = 无规则命中走默认出口的次数。

use axum::{extract::State, Json};
use serde_json::{json, Value};

use super::super::state::AppState;

pub async fn get_stats(State(app_state): State<AppState>) -> Json<Value> {
    let outbounds = crate::monitor::outbound_stats();
    let st = app_state.state.load();
    // 纯服务端配置下客户端 RouterEngine 规则为空 (避免 geosite 内存翻倍), 命中统计读服务端路由表
    let (rules, (default_outbound, default_hits)) = if st.router.rules_count() == 0 {
        if let Some(srv_state) = crate::proxy::mirage_server::server_router::current_server_router_state() {
            if let Some(srv_router) = &srv_state.router {
                srv_router.hit_stats()
            } else {
                st.router.hit_stats()
            }
        } else {
            st.router.hit_stats()
        }
    } else {
        st.router.hit_stats()
    };
    let rules_json: Vec<Value> = rules
        .into_iter()
        .map(|(index, outbound, hits)| json!({"index": index, "outbound": outbound, "hits": hits}))
        .collect();
    Json(json!({
        "outbounds": serde_json::to_value(outbounds).unwrap_or(Value::Null),
        "rules": rules_json,
        "default": {"outbound": default_outbound, "hits": default_hits},
    }))
}
