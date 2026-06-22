//! 每秒采样的后台 Daemon: 计算过去 1 秒内上下行流量 + BPF 命中数的 Delta,
//! 压入 AppState::history 双端队列 (滑动窗口 120 秒).
//!
//! GUI /api/history endpoint 读取这个 history.

use std::sync::atomic::Ordering;

use super::state::AppState;

/// spawn 后台采样 task. 调用一次, task 会持续到进程退出.
pub fn spawn(app_state: AppState) {
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
            if let Some(engine) = &app_state.ebpf_engine {
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
            if let Ok(mut h) = app_state.history.write() {
                h.up.pop_front(); h.up.push_back(up_diff);
                h.down.pop_front(); h.down.push_back(down_diff);
                h.bpf.pop_front(); h.bpf.push_back(bpf_diff);
            }
        }
    });
}
