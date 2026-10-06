//! Camouflage 站 RTT 估计 (原 `CamouflagePool` 的替代)。
//!
//! **历史与动机**: v0.4.5-alpha.7 引入 `CamouflagePool` —— 后台常驻 8 条到
//! `camouflage_host` 的预连 TCP, 供 auth-fail / 读取异常路径即时取用, 消除"临时建连
//! 多一个 3-way RTT"的时延侧信道。但它把**池中连接的已存在时长**继承给了真站的
//! idle-timeout 计时: 探测者看到的关闭时间 = 真站超时 − 池龄, 实测提前 8~14 秒, 可区分
//! (见 `docs/active-probing-assessment-2026-10.md` T2/T3); 且后台 ~0.32 conn/s 的持续
//! churn 对伪装站表现为 bot 式定时连接。
//!
//! **现在 (延迟预连)**: 转发路径改为"判定要转发的那一刻即时建连"(`camouflage.rs`),
//! 池龄恒 ≈ 0, 真站 idle 计时起点与探测者连上的时刻只差一个服务器→伪装站 RTT。
//! 本模块只保留 **RTT 估计** —— auth-succ 分支仍需按"服务器→伪装站 RTT"注入等价抖动,
//! 对齐 auth-fail 的时延 (T5 无时序侧信道)。样本由每次即时建连测量
//! (`connect` 耗时 ≈ 1 RTT) 更新 EWMA; 无样本时 `rtt_us() == 0`, 调用方不注入
//! (与旧行为一致)。
//!
//! **有意的副作用**: 不再有后台常驻流量打伪装站 —— 只有真实探测 / 异常才产生连接。

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

/// RTT EWMA 上限, 防测量毛刺注入荒谬延迟 (远 camouflage 是坏部署, 另行建议就近选)。
const RTT_MAX_US: u64 = 1_000_000;

pub struct CamouflageRtt {
    /// 到 camouflage_host 的 RTT EWMA (微秒, 0 = 未知 / 尚无样本)。
    rtt_us: AtomicU64,
}

impl CamouflageRtt {
    /// 构造 (无后台任务; 与旧 `CamouflagePool::new` 同形状返回 `Arc` 以便调用点不变)。
    pub fn new() -> Arc<Self> {
        Arc::new(Self { rtt_us: AtomicU64::new(0) })
    }

    /// 用一次即时建连的耗时 (≈ 1 RTT) 更新 EWMA (1/8 新样本), 上限防毛刺。
    /// 只在真正发生转发 (auth-fail / 读取异常) 时被调用 —— 无探测即无样本, 无后台流量。
    pub fn observe_connect(&self, elapsed: Duration) {
        let rtt = (elapsed.as_micros() as u64).min(RTT_MAX_US);
        let prev = self.rtt_us.load(Ordering::Relaxed);
        let ewma = if prev == 0 { rtt } else { (prev * 7 + rtt) / 8 };
        self.rtt_us.store(ewma, Ordering::Relaxed);
    }

    /// 当前估计的 camouflage_host RTT (微秒, 0 = 尚未测到)。供 auth-succ 时序对齐用。
    pub fn rtt_us(&self) -> u64 {
        self.rtt_us.load(Ordering::Relaxed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_sample_returns_zero() {
        let r = CamouflageRtt::new();
        assert_eq!(r.rtt_us(), 0, "无样本应为 0 (调用方据此跳过注入)");
    }

    #[test]
    fn first_sample_seeds_ewma() {
        let r = CamouflageRtt::new();
        r.observe_connect(Duration::from_millis(10));
        assert_eq!(r.rtt_us(), 10_000, "首样本直接作为 EWMA 初值 (微秒)");
    }

    #[test]
    fn ewma_smooths_and_stays_positive() {
        let r = CamouflageRtt::new();
        r.observe_connect(Duration::from_millis(10));
        // 第 2 个样本 20ms: ewma = (10000*7 + 20000)/8 = 11250
        r.observe_connect(Duration::from_millis(20));
        assert_eq!(r.rtt_us(), 11_250);
    }

    #[test]
    fn spike_is_capped() {
        let r = CamouflageRtt::new();
        // 5 秒毛刺 → 截到 RTT_MAX_US
        r.observe_connect(Duration::from_secs(5));
        assert_eq!(r.rtt_us(), RTT_MAX_US, "毛刺应被上限截断");
    }
}
