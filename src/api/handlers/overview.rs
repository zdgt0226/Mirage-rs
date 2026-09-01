//! GET /api/overview — Dashboard 顶部汇总卡片的全部数字 (上下行总流量, BPF
//! 命中数, XDP 状态, 活跃 tunnel 数, Brutal CC 状态).

use axum::{extract::State, Json};
use serde_json::{json, Value};
use std::sync::atomic::Ordering;

use crate::monitor::{GLOBAL_UP, GLOBAL_DOWN};
use super::super::state::AppState;

pub async fn get_overview(State(state): State<AppState>) -> Json<Value> {
    Json(build_overview(&state).await)
}

/// 构造 overview 数据体。抽出来供 GET /overview 与 SSE /events 复用 (契约 §08)。
pub async fn build_overview(state: &AppState) -> Value {
    let up = GLOBAL_UP.load(Ordering::Relaxed);
    let down = GLOBAL_DOWN.load(Ordering::Relaxed);

    let mut bpf_success = 0;
    let mut bpf_fallback = 0;
    let mut tunnel_count = 0usize;
    let mut brutal_cc_active = false;
    // engine_online = sockmap/sockops 子系统在内核加载成功. 服务端没 XDP 但有 sockmap,
    // 客户端两者都有. 之前 GUI 只看 xdp_attached 导致服务端永远 OFFLINE 误导用户.
    let mut engine_online = false;
    if let Some(engine) = &state.ebpf_engine {
        // lock().await 而非 try_lock: 锁被 sampler/brutal 短暂占用那一帧 try_lock 会
        // 失败 → engine_online/tunnel_count/brutal_cc 全归零 → GUI 面板闪烁 (时有时无).
        // 锁只被持有 ~µs (读 BPF map), await 等一下即可, 消除闪烁.
        let lock = engine.lock().await;
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

    // 契约 §10 P2: 返回 bool (是否 attach), 而非计数 —— 前端只关心"XDP 挂没挂"。
    let xdp_attached = state.xdp_engine.as_ref().map(|e| e.attached.load(Ordering::Relaxed)).unwrap_or(0) > 0;

    json!({
        "up": up,
        "down": down,
        "connections": crate::monitor::live_conn_count(),
        "bpf_success": bpf_success,
        "bpf_fallback": bpf_fallback,
        "xdp_attached": xdp_attached,
        "engine_online": engine_online,
        "tunnel_count": tunnel_count,
        "brutal_cc_active": brutal_cc_active,
        // 运行模式, 供 WebUI 分服务端/客户端视图 + 「特定入口」Admin 区决定展示哪些功能。
        "mode": if state.is_server { "server" } else { "client" },
    })
}
