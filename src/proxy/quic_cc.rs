//! erasure-aware 拥塞控制 (P3, `--features quic`)。吸收 queqiao ErasureSender 思想, 落在 quinn
//! 的窗口制 `Controller` 上: 包一层内置 BBR, 做两处修正 —— 见 docs/quic-transport-design.md §2.1。
//!
//! 背景 (P0 真机实测): china-us 路径 27% **独立** erasure 丢包 (RTT 极稳=非拥塞), quinn 默认 CC
//! 把 erasure 当拥塞退避 → 环路自我归零 (~20KB/s vs TCP 2MB/s)。
//!
//! 本控制器:
//! 1. **测 erasure floor** = 丢包率 p 的下包络 (降速也不减的那部分)。纯 erasure (p≈floor) 的
//!    congestion event **吞掉不传给 BBR** —— 不让信道底噪触发退避。真拥塞 (p 超 floor+margin) 照传。
//! 2. **窗口按 1/(1-floor) 补偿** —— BBR 的带宽估计是送达速率 (=发送×(1-p)), 抵消 erasure 损耗,
//!    使 goodput 收敛到瓶颈而非零。floor 补偿封顶 (FLOOR_CAP) 防太烂的路径硬推爆缓冲。
//!
//! 校准前 (样本不足) 一律透传 + 不补偿 = 纯 BBR (未测路径行为不臆断)。

use std::any::Any;
use std::sync::Arc;
use std::time::{Duration, Instant};

use quinn::congestion::{BbrConfig, Controller, ControllerFactory};
use quinn_proto::RttEstimator;

const MIN_SAMPLES: u32 = 20; // 校准前透传 (≈20 个 RTT 间隔, china-us ~3s)
const ALPHA: f64 = 0.25; // p 的 EWMA 系数
const LEAK: f64 = 0.003; // floor 每间隔的上漏 (路径变好时慢慢遗忘旧低点)
const MARGIN: f64 = 0.05; // p 超 floor 多少才算真拥塞
const FLOOR_CAP: f64 = 0.7; // 补偿封顶 (1/(1-0.7)=3.3x)。真机 27% 丢包 75x 靠此激进补偿, 勿降
                            // (过冲防护交给下面的 damping, 纯 erasure 路径不受影响)
const MIN_INTERVAL: Duration = Duration::from_millis(20);
// P4a 抗过冲 (加法安全, 不改纯 erasure 路径): 拥塞信号 (excess = p-floor) 出现时把窗口补偿从满
// inflation 收敛回 1x (纯 BBR)。纯 erasure (excess≈0, 如 china-us 27% 独立丢包) 满补偿不变、75x 保住;
// 队列建立 (excess>0) 时退补偿, 减少单控制器过冲。
// ⚠️ 不解决超大窗口 (128MB+) 的崩溃 —— 那是巨大流控窗口本身在 CC 反应前就允许远超 BDP 的在途量
// (真机实测 128MB×10 流仍崩), 治本靠"别设超大窗口"(默认 16, 荐 ≤64) + 未来 mux 架构 (多流骑一连接、
// 一个 CC)。真正的跨连接共享瓶颈 (queqiao PathModel) 受 quinn Controller API 无 peer 上下文所限,
// 也需 mux 才能干净实现。
const CONGEST_KNEE: f64 = 0.10; // excess 达此值, inflation 完全退回 1x

/// erasure-aware CC 工厂。挂到 quinn `TransportConfig::congestion_controller_factory`。
#[derive(Debug, Default)]
pub struct ErasureConfig {
    bbr: Arc<BbrConfig>,
}

impl ControllerFactory for ErasureConfig {
    fn build(self: Arc<Self>, now: Instant, current_mtu: u16) -> Box<dyn Controller> {
        Box::new(ErasureController {
            inner: self.bbr.clone().build(now, current_mtu),
            p_ewma: 0.0,
            floor: 1.0, // 未知: 先高, 由首批下包络拉下来
            recent_excess: 0.0,
            samples: 0,
            acked_acc: 0,
            lost_acc: 0,
            interval_start: now,
            last_rtt: Duration::from_millis(100),
        })
    }
}

struct ErasureController {
    inner: Box<dyn Controller>,
    p_ewma: f64,
    floor: f64,
    recent_excess: f64, // EWMA of max(p-floor,0): 拥塞压力信号, 抑制过冲
    samples: u32,
    acked_acc: u64,
    lost_acc: u64,
    interval_start: Instant,
    last_rtt: Duration,
}

impl ErasureController {
    /// 一个测量间隔 (≈1 RTT) 结束: 算 p、更新 EWMA + floor 下包络。
    fn maybe_finalize(&mut self, now: Instant) {
        let interval = self.last_rtt.max(MIN_INTERVAL);
        if now.duration_since(self.interval_start) < interval {
            return;
        }
        let total = self.acked_acc + self.lost_acc;
        if total > 0 {
            let p = self.lost_acc as f64 / total as f64;
            self.p_ewma = if self.samples == 0 { p } else { (1.0 - ALPHA) * self.p_ewma + ALPHA * p };
            // 下包络: 遇新低立即抓; 否则慢慢上漏, 但不超当前 p。
            if self.p_ewma < self.floor {
                self.floor = self.p_ewma;
            } else {
                self.floor = (self.floor + LEAK).min(self.p_ewma);
            }
            // 拥塞压力 = 超出 floor 的丢包 (纯 erasure 时≈0, 队列建立时>0)。EWMA 平滑。
            let excess = (self.p_ewma - self.floor).max(0.0);
            self.recent_excess = (1.0 - ALPHA) * self.recent_excess + ALPHA * excess;
            self.samples = self.samples.saturating_add(1);
        }
        self.acked_acc = 0;
        self.lost_acc = 0;
        self.interval_start = now;
    }

    fn calibrated(&self) -> bool {
        self.samples >= MIN_SAMPLES
    }
}

impl Controller for ErasureController {
    fn on_sent(&mut self, now: Instant, bytes: u64, last_packet_number: u64) {
        self.inner.on_sent(now, bytes, last_packet_number);
    }

    fn on_ack(&mut self, now: Instant, sent: Instant, bytes: u64, app_limited: bool, rtt: &RttEstimator) {
        self.last_rtt = rtt.get();
        self.acked_acc += bytes;
        self.maybe_finalize(now);
        self.inner.on_ack(now, sent, bytes, app_limited, rtt);
    }

    fn on_end_acks(&mut self, now: Instant, in_flight: u64, app_limited: bool, largest_packet_num_acked: Option<u64>) {
        self.inner.on_end_acks(now, in_flight, app_limited, largest_packet_num_acked);
    }

    fn on_congestion_event(&mut self, now: Instant, sent: Instant, is_persistent_congestion: bool, lost_bytes: u64) {
        self.lost_acc += lost_bytes;
        self.maybe_finalize(now);

        // 持续拥塞 (真) 或未校准 → 照常传给 BBR。纯 erasure (p 未超 floor+margin) → 吞掉。
        let excess = self.p_ewma - self.floor;
        let real_congestion = is_persistent_congestion || !self.calibrated() || excess > MARGIN;
        if real_congestion {
            self.inner.on_congestion_event(now, sent, is_persistent_congestion, lost_bytes);
        }
        // else: 信道 erasure, 不让它触发 BBR 退避。
    }

    fn on_mtu_update(&mut self, new_mtu: u16) {
        self.inner.on_mtu_update(new_mtu);
    }

    fn window(&self) -> u64 {
        let w = self.inner.window();
        if self.calibrated() {
            let f = self.floor.min(FLOOR_CAP);
            let full_inflation = 1.0 / (1.0 - f); // 纯 erasure 时的满补偿
            // 抗过冲: 拥塞压力越大, 越收敛回 1x (纯 BBR)。excess 达 CONGEST_KNEE 时完全不补偿。
            let damp = (1.0 - (self.recent_excess / CONGEST_KNEE).min(1.0)).max(0.0);
            let inflation = 1.0 + (full_inflation - 1.0) * damp;
            ((w as f64) * inflation) as u64
        } else {
            w
        }
    }

    fn clone_box(&self) -> Box<dyn Controller> {
        Box::new(ErasureController {
            inner: self.inner.clone_box(),
            p_ewma: self.p_ewma,
            floor: self.floor,
            recent_excess: self.recent_excess,
            samples: self.samples,
            acked_acc: self.acked_acc,
            lost_acc: self.lost_acc,
            interval_start: self.interval_start,
            last_rtt: self.last_rtt,
        })
    }

    fn initial_window(&self) -> u64 {
        self.inner.initial_window()
    }

    fn into_any(self: Box<Self>) -> Box<dyn Any> {
        self
    }
}
