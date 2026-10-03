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
// gap-safety: quinn-proto 0.11.17 (RUSTSEC-2026-0185 修复) 给乱序流重组加了 MAX_CHUNKS=1024 硬界,
// 超了就关连接 ("too many gaps in stream buffer")。在途包 × 丢包率 ≈ 待补 gap 数, 故按测到的丢包率
// 封顶 cwnd 使 gap 稳在界下 (真机实证: 16MB 窗口 ×13% 丢包 → gap 超限 ~1MB 就断; 加此封顶后下完)。
const GAP_SAFE_CHUNKS: f64 = 800.0; // MAX_CHUNKS=1024 的安全余量

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
            mtu: current_mtu.max(1200) as u64,
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
    mtu: u64, // 当前 MTU, 用于 gap-safety 封顶换算包数
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
        self.mtu = (new_mtu as u64).max(1200);
        self.inner.on_mtu_update(new_mtu);
    }

    fn window(&self) -> u64 {
        let mut w = self.inner.window();
        // erasure 补偿 (校准后): 无视纯 erasure、按 1/(1-floor) 补窗口, 拥塞压力 damp。
        if self.calibrated() {
            let f = self.floor.min(FLOOR_CAP);
            let full_inflation = 1.0 / (1.0 - f);
            let damp = (1.0 - (self.recent_excess / CONGEST_KNEE).min(1.0)).max(0.0);
            let inflation = 1.0 + (full_inflation - 1.0) * damp;
            w = ((w as f64) * inflation) as u64;
        }
        // gap-safety 封顶: 按测到的丢包率封顶在途, 使接收端乱序 gap < quinn MAX_CHUNKS(1024)。
        // 干净路径 (p≈0) 无封顶; 丢包路径自动收窄防"too many gaps"关连接。见 GAP_SAFE_CHUNKS 注释。
        if self.samples > 0 && self.p_ewma > 0.02 {
            w = w.min(gap_safe_cap(self.mtu, self.p_ewma));
        }
        w
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
            mtu: self.mtu,
        })
    }

    fn initial_window(&self) -> u64 {
        self.inner.initial_window()
    }

    fn into_any(self: Box<Self>) -> Box<dyn Any> {
        self
    }
}

/// gap-safety 封顶 (见 GAP_SAFE_CHUNKS): 丢包率 `p` 下在途字节上限, 使接收端乱序 gap 稳在 quinn
/// MAX_CHUNKS 之下; 不低于 8 个 MTU 的最小窗口。调用方只在 p > 0.02 时施加。
fn gap_safe_cap(mtu: u64, p: f64) -> u64 {
    let gap_cap = (GAP_SAFE_CHUNKS * mtu as f64 / p) as u64;
    gap_cap.max(mtu * 8)
}

// ───────────────────────── 定速模式 (brutal 语义) ─────────────────────────
//
// 实测 (docs/benchmark-2026-09.md §3.3): erasure CC 仍随链路自适应降速, 晚间同线路 51 Mbps vs
// hysteria2 定速 81 Mbps。定速模式按配置速率发送、遇丢包不退让 (同 tcp-brutal / hysteria2 brutal):
//   目标发送速率 = rate / ack_rate   (ack_rate = 最近 ACK_SLOTS 秒的送达率, 下限 MIN_ACK_RATE)
//   窗口 = 目标发送速率 × smoothed RTT / ack_rate × CWND_GAIN
// 第二个 / ack_rate: 丢失的包在被判定丢失前 (≈1 RTT) 仍占着窗口, 能发新数据的窗口只剩约 ack_rate 比例,
// 不补这一项则高丢包下实际发送速率达不到目标 (真机 15-25% 丢包: 只补一次 63-70 Mbps, 补两次后接近
// hysteria2)。无丢包时两项都是 1, 不会超发; 两项各受 MIN_ACK_RATE 下限, 合计最多 1/0.64 ≈ 1.56 倍。
// quinn 的 pacer 按 1.25 × window / srtt 放行、在途受 window 封顶, 故窗口即决定实际发送速率。
// ⚠️ 与 TCP brutal 相同的风险: rate 高于实际可用带宽会自己灌满线路、重传放大 —— rate 须取客户端
// 实际能跑到的带宽。gap-safety 封顶照常生效 (按原始丢包率), 防乱序 gap 超限被关连接。

/// 送达率统计窗口: ACK_SLOTS 个 1 秒槽 (同 hysteria2 brutal 的 5 秒)。
const ACK_SLOTS: usize = 5;
/// 送达率下限: 最多补偿 1/0.8 = 1.25 倍, 烂链路上不无限放大 (同 hysteria2 minAckRate)。
const MIN_ACK_RATE: f64 = 0.8;
/// 样本不足 (ack+lost 字节 < 该值个 MTU) 时视为无丢包, 不补偿。
const MIN_SAMPLE_PACKETS: u64 = 50;
/// 窗口 = 速率 × RTT × 该增益。pacer 已有 1.25 倍突发余量, 取 1.0 使稳态发送速率 ≈ 目标。
const CWND_GAIN: f64 = 1.0;
/// 首个 RTT 样本前的假定 RTT (只影响初始窗口)。
const INITIAL_RTT: Duration = Duration::from_millis(100);

/// 定速 CC 工厂。`bytes_per_sec` = `brutal_rate_mbps × 125_000`。
#[derive(Debug)]
pub struct FixedRateConfig {
    pub bytes_per_sec: u64,
}

impl ControllerFactory for FixedRateConfig {
    fn build(self: Arc<Self>, now: Instant, current_mtu: u16) -> Box<dyn Controller> {
        Box::new(FixedRateController {
            rate: self.bytes_per_sec.max(1),
            rtt: INITIAL_RTT,
            mtu: current_mtu.max(1200) as u64,
            stats: AckStats::new(now),
        })
    }
}

/// 最近 ACK_SLOTS 秒的 ack / lost 字节, 按秒分槽滚动。
#[derive(Clone, Debug)]
struct AckStats {
    start: Instant,
    last: Instant,                       // 最近一次 ack / lost 记账时刻 (window() 无 now, 以此为参照)
    slots: [(u64, u64, u64); ACK_SLOTS], // (秒序号, acked, lost)
}

impl AckStats {
    fn new(start: Instant) -> Self {
        Self { start, last: start, slots: [(u64::MAX, 0, 0); ACK_SLOTS] }
    }

    fn slot(&mut self, now: Instant) -> &mut (u64, u64, u64) {
        self.last = self.last.max(now);
        let sec = now.saturating_duration_since(self.start).as_secs();
        let slot = &mut self.slots[(sec % ACK_SLOTS as u64) as usize];
        if slot.0 != sec {
            *slot = (sec, 0, 0);
        }
        slot
    }

    fn on_ack(&mut self, now: Instant, bytes: u64) {
        self.slot(now).1 += bytes;
    }

    fn on_lost(&mut self, now: Instant, bytes: u64) {
        self.slot(now).2 += bytes;
    }

    /// 最近 ACK_SLOTS 秒内的 (acked, lost) 合计 (过期槽不计)。
    fn totals(&self, now: Instant) -> (u64, u64) {
        let sec = now.saturating_duration_since(self.start).as_secs();
        self.slots
            .iter()
            .filter(|s| s.0 != u64::MAX && s.0 + ACK_SLOTS as u64 > sec)
            .fold((0, 0), |(a, l), s| (a + s.1, l + s.2))
    }
}

/// 由 (acked, lost) 字节得 (用于补偿的 ack_rate ∈ [MIN_ACK_RATE, 1], 原始丢包率 p)。样本不足 → (1, 0)。
fn ack_rate_of(acked: u64, lost: u64, mtu: u64) -> (f64, f64) {
    let total = acked + lost;
    if total < MIN_SAMPLE_PACKETS * mtu {
        return (1.0, 0.0);
    }
    let raw = acked as f64 / total as f64;
    (raw.max(MIN_ACK_RATE), 1.0 - raw)
}

/// 定速窗口 (纯函数, 便于单测): rate × rtt / ack_rate² × CWND_GAIN (见上方说明), 丢包 > 2% 时叠
/// gap-safety 封顶, 不低于 4 个 MTU。
fn fixed_rate_window(rate: u64, rtt: Duration, ack_rate: f64, p: f64, mtu: u64) -> u64 {
    let w = (rate as f64 * rtt.as_secs_f64() / (ack_rate * ack_rate) * CWND_GAIN) as u64;
    let w = if p > 0.02 { w.min(gap_safe_cap(mtu, p)) } else { w };
    w.max(mtu * 4)
}

struct FixedRateController {
    rate: u64,
    rtt: Duration,
    mtu: u64,
    stats: AckStats,
}

impl Controller for FixedRateController {
    fn on_ack(&mut self, now: Instant, _sent: Instant, bytes: u64, _app_limited: bool, rtt: &RttEstimator) {
        self.rtt = rtt.get();
        self.stats.on_ack(now, bytes);
    }

    fn on_congestion_event(&mut self, now: Instant, _sent: Instant, _is_persistent_congestion: bool, lost_bytes: u64) {
        // 只记账, 不退让 (定速语义)。
        self.stats.on_lost(now, lost_bytes);
    }

    fn on_mtu_update(&mut self, new_mtu: u16) {
        self.mtu = (new_mtu as u64).max(1200);
    }

    fn window(&self) -> u64 {
        // Controller::window 无 now 参数: 以最近一次 ack / lost 记账时刻为参照。
        let (acked, lost) = self.stats.totals(self.stats.last);
        let (ack_rate, p) = ack_rate_of(acked, lost, self.mtu);
        fixed_rate_window(self.rate, self.rtt, ack_rate, p, self.mtu)
    }

    fn clone_box(&self) -> Box<dyn Controller> {
        Box::new(FixedRateController { rate: self.rate, rtt: self.rtt, mtu: self.mtu, stats: self.stats.clone() })
    }

    fn initial_window(&self) -> u64 {
        fixed_rate_window(self.rate, INITIAL_RTT, 1.0, 0.0, self.mtu)
    }

    fn into_any(self: Box<Self>) -> Box<dyn Any> {
        self
    }
}

#[cfg(test)]
mod fixed_rate_tests {
    use super::*;

    const MTU: u64 = 1200;
    const RATE: u64 = 12_500_000; // 100 Mbps

    #[test]
    fn window_is_rate_times_rtt_without_loss() {
        let w = fixed_rate_window(RATE, Duration::from_millis(180), 1.0, 0.0, MTU);
        assert_eq!(w, 2_250_000); // 12.5 MB/s × 0.18 s
    }

    #[test]
    fn window_compensates_by_ack_rate_squared() {
        let near = |w: u64, want: u64| w.abs_diff(want) <= 1; // 浮点取整误差
        let w = fixed_rate_window(RATE, Duration::from_millis(100), 0.8, 0.0, MTU);
        assert!(near(w, 1_953_125), "{w}"); // 1.25 MB / 0.8², 即最大补偿 ≈ 1.56 倍
        let w = fixed_rate_window(RATE, Duration::from_millis(100), 0.9, 0.0, MTU);
        assert!(near(w, 1_543_209), "{w}"); // 1.25 MB / 0.81
    }

    #[test]
    fn window_respects_gap_cap_and_floor() {
        // 30% 丢包: gap 封顶 = 800 × 1200 / 0.3 = 3.2 MB, 低于 rate × 1s / 0.8
        let w = fixed_rate_window(RATE, Duration::from_secs(1), 0.8, 0.3, MTU);
        assert_eq!(w, gap_safe_cap(MTU, 0.3));
        // 极小 RTT: 不低于 4 个 MTU
        let w = fixed_rate_window(RATE, Duration::from_micros(10), 1.0, 0.0, MTU);
        assert_eq!(w, 4 * MTU);
    }

    #[test]
    fn ack_rate_needs_samples_and_is_floored() {
        assert_eq!(ack_rate_of(10 * MTU, 10 * MTU, MTU), (1.0, 0.0)); // 样本不足 → 不补偿
        let (r, p) = ack_rate_of(90 * MTU, 10 * MTU, MTU);
        assert!((r - 0.9).abs() < 1e-9 && (p - 0.1).abs() < 1e-9);
        let (r, p) = ack_rate_of(50 * MTU, 50 * MTU, MTU); // 50% 丢包: 补偿封顶 0.8, p 保留原值
        assert_eq!(r, MIN_ACK_RATE);
        assert!((p - 0.5).abs() < 1e-9);
    }

    #[test]
    fn ack_stats_slots_expire() {
        let t0 = Instant::now();
        let mut s = AckStats::new(t0);
        s.on_ack(t0, 1000);
        s.on_lost(t0 + Duration::from_millis(500), 100);
        assert_eq!(s.totals(t0 + Duration::from_secs(1)), (1000, 100));
        s.on_ack(t0 + Duration::from_secs(3), 500);
        assert_eq!(s.totals(t0 + Duration::from_secs(3)), (1500, 100));
        // 第 0 秒的槽在第 5 秒起过期
        assert_eq!(s.totals(t0 + Duration::from_secs(5)), (500, 0));
        // 同一槽位被新的一秒复用时清零
        s.on_ack(t0 + Duration::from_secs(8), 7); // 8 % 5 == 3, 覆盖第 3 秒的槽
        assert_eq!(s.totals(t0 + Duration::from_secs(8)), (7, 0));
        assert_eq!(s.last, t0 + Duration::from_secs(8));
    }
}
