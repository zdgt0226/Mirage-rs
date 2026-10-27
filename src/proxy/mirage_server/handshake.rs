//! Mirage 协议握手: 解析 TLS ClientHello + Poly1305 token 校验 + ServerHello
//! 模拟回放 + 64B fake Client Finished tail 消费.
//!
//! 通过的连接继续走 `control::dispatch_authenticated` 建立加密 channel.
//! 失败的连接以及认证前读取异常 (非 TLS/超长/超时/不完整) 均走
//! `camouflage::run_camouflage_forward` 伪装成正常 TLS 反向代理转发.
//!
//! v0.4.5-alpha.7: ClientHello 读取从 "read 1024 max" 改为精确 5B header +
//! body read_exact, 修 iOS Safari / Chrome 带完整 PSK/ECH 扩展 (1200-1400B)
//! 被截断误判 auth-fail 的问题. TLS 记录 length 上限 2^14 (RFC 8446 §5.1)
//! 硬 cap 16384. Fake tail 从 63 (52B body) 改为 64 (53B body) 匹配真实
//! TLS 1.3 Client Finished 尺寸.
//!
//! 2026-09-27 审计修补: 认证前读取不再静默断开。任何异常 (buf[0] != 0x16 首字节非
//! TLS、record_len == 0 或 > 16384、读取超时/EOF 读不全) 都将已收到的原始字节原样
//! 透传给真实伪装站, 消除主动明文探测 (如 HTTP GET 探针秒断/静默丢) 与真实站点的
//! 行为差异; 对端未发字节即关闭时安全释放。所有转发统一受 GLOBAL_UNAUTH、
//! UNAUTH_RATE 速率守卫及 UNAUTH_CONNS 槽位保护。
//!
//! 2026-10 对齐/容错分离 (见 `docs/client-hello-timing-design.md`): 转发路径不再取后台预热
//! 连接池而是**推测性预连**(accept 后延迟 ① 仍未见完整 CH 才后台连一条, 不用则关) —— 消除旧池
//! 把"连接已存在时长"传导给真站 idle-timeout 导致的 8~14s 关闭时间侧信道 (T2/T3)。
//! 认证前读取的判定依据是 ② 静默间隔 (`judge_silence_ms`, 默认 1s —— 必须大于 TCP 重传退避,
//! 否则丢段的合法客户端会被误判), ③ `hard_deadline` 作 slowloris 总兜底。
//! 详见 `read_client_hello` / `Preconnect` / `preconnect_delay_for`。

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, LazyLock, Mutex};
use std::time::{Duration, Instant};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tracing::warn;

use super::camouflage;
use super::control;
use super::CamouflageRtt;
use super::{IpSlotGuard, GLOBAL_UNAUTH, UNAUTH_CONNS};

const TLS_RECORD_HEADER_LEN: usize = 5;
const TLS_RECORD_MAX_BODY: usize = 16384; // 2^14, RFC 8446 §5.1

/// UNAUTH 限流 key: IPv6 归一到 /64 前缀 (清零低 64 位), 防攻击者用一个 /64
/// 段造 2^64 个"独立 IP" 逃逸限流. IPv4 原样返回 (单地址已是最细粒度).
pub(crate) fn rate_limit_key(ip: std::net::IpAddr) -> std::net::IpAddr {
    // 双栈监听 (`[::]`) 下 IPv4 客户端以 `::ffff:a.b.c.d` 出现; 不先还原为 v4, 下面的 /64 归一
    // 会把所有 v4 来源清零成同一个 `::` 桶 —— 限流/限额对它们变成 "全体共享一个额度"。
    let ip = ip.to_canonical();
    match ip {
        std::net::IpAddr::V4(_) => ip,
        std::net::IpAddr::V6(v6) => {
            let mut octets = v6.octets();
            for b in &mut octets[8..] {
                *b = 0;
            }
            std::net::IpAddr::V6(std::net::Ipv6Addr::from(octets))
        }
    }
}

// 反射 flood 速率守卫: 已有并发上限 (UNAUTH_CONNS 100/IP + GLOBAL_UNAUTH 5000) 只挡"同时挂着"
// 的反射, 挡不住"快速开-失败-关"的高频反射 (每条短命 → 并发低但反复砸 camouflage_host, 让本机
// IP 惹 abuse)。按源 IP(/64) 补窗口速率上限: 阈值远超 GFW 低频主动探测 (探测一次一两条), 只掐
// flood 滥用。超限直接 drop (与并发超限的 return None 行为一致)。
const UNAUTH_RATE_WINDOW: Duration = Duration::from_secs(10);
const UNAUTH_RATE_MAX: u32 = 30; // 每源 IP(/64) 每窗口最多反射次数
const UNAUTH_RATE_MAP_CAP: usize = 8192; // 表上限, 满淘汰窗口最旧的一条 (有界)
static UNAUTH_RATE: LazyLock<Mutex<HashMap<IpAddr, (Instant, u32)>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

/// 认证失败反射的按源 IP 窗口速率: 超 `UNAUTH_RATE_MAX`/`UNAUTH_RATE_WINDOW` 返 true (该丢)。
fn unauth_reflect_rate_exceeded(ip: IpAddr) -> bool {
    let now = Instant::now();
    let mut m = match UNAUTH_RATE.lock() {
        Ok(g) => g,
        Err(p) => p.into_inner(),
    };
    if !m.contains_key(&ip) && m.len() >= UNAUTH_RATE_MAP_CAP {
        // 满 + 新 IP: 淘汰窗口起点最旧的一条, 防表无界增长。
        if let Some(k) = m.iter().min_by_key(|(_, (t, _))| *t).map(|(k, _)| *k) {
            m.remove(&k);
        }
    }
    let e = m.entry(ip).or_insert((now, 0));
    if now.duration_since(e.0) > UNAUTH_RATE_WINDOW {
        *e = (now, 0); // 窗口过期, 重置
    }
    e.1 += 1;
    e.1 > UNAUTH_RATE_MAX
}

/// 校验 token 是否匹配有效 (且未超额) 凭据。
/// 超额用户按认证失败处理 (None), 走与 token 校验失败完全相同的伪装站转发路径。
pub(crate) fn verify_creds_and_quota<F>(
    creds: &[super::CredEntry],
    token: &[u8; 32],
    client_random: &[u8; 32],
    auth_ts_tolerance_secs: u64,
    is_exhausted: F,
) -> Option<usize>
where
    F: Fn(&str) -> bool,
{
    let idx = creds.iter().position(|entry| {
        crate::crypto::hello_auth::verify_session_token(&entry.password, token, client_random, auth_ts_tolerance_secs)
    })?;
    let username = &creds[idx].name;
    if is_exhausted(username) {
        return None;
    }
    Some(idx)
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum ClientHelloReadResult {
    /// 完整读取到了 TLS ClientHello 记录 (buf.len() == 5 + record_len)
    Complete(Vec<u8>),
    /// 异常读取需回落到伪装站透传 (附带已收到的全部原始字节, 包含 0 字节超时)
    Fallback(Vec<u8>),
    /// 对端未发送任何字节即关闭/报错, 连接已死直接丢弃
    Close,
}

/// 读取过程中的计时画像（供 A3 标定与"丢包误杀"检测，见 `docs/client-hello-timing-design.md` §5）。
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ReadTiming {
    /// 从进入 `read_client_hello` 到返回的总耗时。
    pub total_us: u64,
    /// **两次数据到达之间**的最大间隔 —— 不含"末尾那段触发判定的静默"。
    /// 合法客户端丢段后靠 TLP/RTO 重传会出现 ≥200ms 的这种间隔；一次性发完就停的探测者没有。
    pub max_internal_gap_us: u64,
    /// 已读到的字节数。
    pub bytes: usize,
}

/// 增量读取 ClientHello。
///
/// 判定量纲是"**最后一次收到数据后的静默时长**"（`judge_silence`），而非总时长：
/// - 探测者（空连接 / 半截）发完就停 → 静默 `judge_silence` 后返回 `Fallback` 交伪装站接管。
///   **窗口不必再为"对齐"让步** —— 对齐由 `Preconnect` 的推测性预连负责（它让真站的空闲计时
///   起点 ≈ 探测者连上的时刻），所以这里可以给足重传时间。
/// - 合法客户端丢段后靠 TLP/RTO 重传（≥ 200ms，退避可达 800ms+）：只要 `judge_silence` 大于它，
///   数据会补上来 → 读到完整即 `Complete`，**不会被误判**。
///   （旧实现的缺陷：把 `2×RTT`（下限 100ms）同时当成了"触发转发的时刻"与"判定期限"，
///   于是丢一个段就扛不住 RTO。）
/// - `hard_deadline` 是总时限兜底，防"每 judge_silence−ε 滴一个字节"的 slowloris。
///
/// 其余语义不变：首字节非 0x16 / record_len 非法**立即** Fallback（不等超时）；只读首个
/// record 不越过（管道化字节留在流里）；EOF 时分已读非空 → Fallback，空 → Close。
pub(crate) async fn read_client_hello<S>(
    stream: &mut S,
    judge_silence: Duration,
    hard_deadline: Duration,
) -> (ClientHelloReadResult, ReadTiming)
where
    S: AsyncRead + Unpin,
{
    let start = Instant::now();
    let hard_at = start + hard_deadline;
    let mut buf = Vec::with_capacity(1024);
    let mut tmp = [0u8; 1024];
    let mut last_arrival: Option<Instant> = None;
    let mut max_gap = Duration::ZERO;

    loop {
        let now = Instant::now();
        let hard_remaining = hard_at.saturating_duration_since(now);
        if hard_remaining.is_zero() {
            // 总时限到 (slowloris 兜底)
            let t = ReadTiming {
                total_us: start.elapsed().as_micros() as u64,
                max_internal_gap_us: max_gap.as_micros() as u64,
                bytes: buf.len(),
            };
            return (ClientHelloReadResult::Fallback(buf), t);
        }
        // 单次读取等 min(判定期限, 距总时限余量): 每次读到数据后此窗口重新起算，
        // 等价于"最后一次数据后静默 judge_silence 即判异常"。
        let wait = judge_silence.min(hard_remaining);

        // 单次读取上限: 头未齐只读到 5B, 头齐后只读到记录末尾 —— 绝不越过首个 record,
        // 否则其后的字节 (管道化数据) 会被吞进 buf 丢失或误判。
        let target_len = if buf.len() >= TLS_RECORD_HEADER_LEN {
            TLS_RECORD_HEADER_LEN + u16::from_be_bytes([buf[3], buf[4]]) as usize
        } else {
            TLS_RECORD_HEADER_LEN
        };
        let to_read = (target_len - buf.len()).min(tmp.len());

        match tokio::time::timeout(wait, stream.read(&mut tmp[..to_read])).await {
            Ok(Ok(0)) => {
                // EOF
                let t = ReadTiming {
                    total_us: start.elapsed().as_micros() as u64,
                    max_internal_gap_us: max_gap.as_micros() as u64,
                    bytes: buf.len(),
                };
                if buf.is_empty() {
                    return (ClientHelloReadResult::Close, t);
                } else {
                    return (ClientHelloReadResult::Fallback(buf), t);
                }
            }
            Ok(Ok(n)) => {
                let now = Instant::now();
                if let Some(prev) = last_arrival {
                    max_gap = max_gap.max(now.saturating_duration_since(prev));
                }
                last_arrival = Some(now);
                buf.extend_from_slice(&tmp[..n]);

                // 规则 3: 一旦首字节非 0x16, 立即回落, 不等静默窗口 (HTTP 明文探测秒判)
                if buf[0] != 0x16 {
                    let t = ReadTiming {
                        total_us: start.elapsed().as_micros() as u64,
                        max_internal_gap_us: max_gap.as_micros() as u64,
                        bytes: buf.len(),
                    };
                    return (ClientHelloReadResult::Fallback(buf), t);
                }

                // 首字节是 0x16, 检查是否已收齐 5B 记录头
                if buf.len() >= TLS_RECORD_HEADER_LEN {
                    let record_len = u16::from_be_bytes([buf[3], buf[4]]) as usize;
                    // 规则 2: record_len == 0 或 > 16384 异常回落
                    // (不再静默丢弃, 而是原样透传给伪装站以消除探测与真站差异)
                    if record_len == 0 || record_len > TLS_RECORD_MAX_BODY {
                        let t = ReadTiming {
                            total_us: start.elapsed().as_micros() as u64,
                            max_internal_gap_us: max_gap.as_micros() as u64,
                            bytes: buf.len(),
                        };
                        return (ClientHelloReadResult::Fallback(buf), t);
                    }
                    if buf.len() == TLS_RECORD_HEADER_LEN + record_len {
                        let t = ReadTiming {
                            total_us: start.elapsed().as_micros() as u64,
                            max_internal_gap_us: max_gap.as_micros() as u64,
                            bytes: buf.len(),
                        };
                        return (ClientHelloReadResult::Complete(buf), t);
                    }
                }
            }
            Ok(Err(_)) => {
                // 读取报错
                let t = ReadTiming {
                    total_us: start.elapsed().as_micros() as u64,
                    max_internal_gap_us: max_gap.as_micros() as u64,
                    bytes: buf.len(),
                };
                if buf.is_empty() {
                    return (ClientHelloReadResult::Close, t);
                } else {
                    return (ClientHelloReadResult::Fallback(buf), t);
                }
            }
            Err(_) => {
                // 静默窗口耗尽 (或总时限到) — 交出已读部分 (哪怕 0 字节) 让伪装站接管
                let t = ReadTiming {
                    total_us: start.elapsed().as_micros() as u64,
                    max_internal_gap_us: max_gap.as_micros() as u64,
                    bytes: buf.len(),
                };
                return (ClientHelloReadResult::Fallback(buf), t);
            }
        }
    }
}

// ── ClientHello 计时/判定参数 (启动时从 tuning.client_hello_guard 设一次; env 可覆盖) ──
// 三个时钟分离, 见 docs/client-hello-timing-design.md §2:
// ① 预连触发 (对齐) ② 判定期限 (容错) ③ 总时限 (slowloris 兜底)。
static PC_MULT: AtomicU32 = AtomicU32::new(1);
static PC_MIN_US: AtomicU64 = AtomicU64::new(50_000);
static PC_MAX_US: AtomicU64 = AtomicU64::new(200_000);
static JUDGE_SILENCE_US: AtomicU64 = AtomicU64::new(1_000_000);
static HARD_DEADLINE_US: AtomicU64 = AtomicU64::new(5_000_000);
/// auth-succ 时序注入: `(mult_x10/10 × cam_RTT + offset_us) × jitter`。见 `auth_succ_delay_us`。
static AUTH_MULT_X10: AtomicU32 = AtomicU32::new(20);
static AUTH_OFFSET_US: AtomicU64 = AtomicU64::new(0);
static AUTO_CALIBRATE: AtomicBool = AtomicBool::new(true);

/// env 覆盖 (优先于 config)。**0 视为无效** → 回落: 0 长度的窗口会让所有连接被判异常。
fn env_ms(name: &str) -> Option<u64> {
    std::env::var(name).ok().and_then(|v| v.parse::<u64>().ok()).filter(|v| *v > 0)
}
fn env_u32(name: &str) -> Option<u32> {
    std::env::var(name).ok().and_then(|v| v.parse::<u32>().ok()).filter(|v| *v > 0)
}
fn env_bool(name: &str) -> Option<bool> {
    std::env::var(name).ok().and_then(|v| {
        match v.to_ascii_lowercase().trim() {
            "1" | "true" | "on" | "yes" => Some(true),
            "0" | "false" | "off" | "no" => Some(false),
            _ => None,
        }
    })
}
/// 环境变量优先取新名, 再回落到旧名 (真机 A/B 脚本用过 `MIRAGE_DELAY_*`, 兼容不破坏)。
fn env_u32_alias(new: &str, old: &str) -> Option<u32> {
    env_u32(new).or_else(|| env_u32(old))
}

/// 设置 ClientHello 计时/判定参数 (启动时一次)。环境变量 `MIRAGE_CH_PRECONNECT_MULT` /
/// `MIRAGE_CH_PRECONNECT_MIN_MS` / `MIRAGE_CH_PRECONNECT_MAX_MS` / `MIRAGE_CH_JUDGE_MS` /
/// `MIRAGE_CH_HARD_MS` / `MIRAGE_CH_AUTH_MULT_X10` / `MIRAGE_CH_AUTH_OFFSET_MS` / `MIRAGE_CH_AUTO_CALIBRATE` 优先覆盖
/// (供真机 A/B 调参; 旧名 `MIRAGE_DELAY_MULT_TENTHS` / `MIRAGE_DELAY_OFFSET_MS` 仍兼容)。
/// min/max 反转自动纠正。
pub fn set_client_hello_guard(
    preconnect_mult: u32,
    preconnect_min: Duration,
    preconnect_max: Duration,
    judge_silence: Duration,
    hard_deadline: Duration,
    auth_succ_mult_x10: u32,
    auth_succ_offset: Duration,
    auto_calibrate: bool,
) {
    let mult = env_u32("MIRAGE_CH_PRECONNECT_MULT").unwrap_or(preconnect_mult.max(1));
    let mut pc_min =
        env_ms("MIRAGE_CH_PRECONNECT_MIN_MS").unwrap_or(preconnect_min.as_millis() as u64);
    let mut pc_max =
        env_ms("MIRAGE_CH_PRECONNECT_MAX_MS").unwrap_or(preconnect_max.as_millis() as u64);
    if pc_min > pc_max {
        std::mem::swap(&mut pc_min, &mut pc_max);
    }
    let judge = env_ms("MIRAGE_CH_JUDGE_MS").unwrap_or(judge_silence.as_millis() as u64);
    // 总时限不得短于判定期限 (否则后者永远不会生效)。
    let hard = env_ms("MIRAGE_CH_HARD_MS")
        .unwrap_or(hard_deadline.as_millis() as u64)
        .max(judge);
    let auth_mult = env_u32_alias("MIRAGE_CH_AUTH_MULT_X10", "MIRAGE_DELAY_MULT_TENTHS")
        .unwrap_or(auth_succ_mult_x10.max(1));
    // 偏置允许为 0 (纯倍率模式), 故用 env_u32 (不套 >0 过滤), 但旧名以 ms 计量。
    let auth_off_ms = std::env::var("MIRAGE_CH_AUTH_OFFSET_MS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .or_else(|| {
            std::env::var("MIRAGE_DELAY_OFFSET_MS")
                .ok()
                .and_then(|v| v.parse::<u64>().ok())
        })
        .unwrap_or(auth_succ_offset.as_millis() as u64);
    let auto = env_bool("MIRAGE_CH_AUTO_CALIBRATE").unwrap_or(auto_calibrate);

    PC_MULT.store(mult, Ordering::Relaxed);
    PC_MIN_US.store(pc_min.saturating_mul(1000), Ordering::Relaxed);
    PC_MAX_US.store(pc_max.saturating_mul(1000), Ordering::Relaxed);
    JUDGE_SILENCE_US.store(judge.saturating_mul(1000), Ordering::Relaxed);
    HARD_DEADLINE_US.store(hard.saturating_mul(1000), Ordering::Relaxed);
    AUTH_MULT_X10.store(auth_mult, Ordering::Relaxed);
    AUTH_OFFSET_US.store(auth_off_ms.saturating_mul(1000), Ordering::Relaxed);
    AUTO_CALIBRATE.store(auto, Ordering::Relaxed);
}

/// auth-succ 时序注入基准 (微秒, 未含抖动): `(mult_x10/10 × cam_RTT) + offset`。
///
/// **时延对齐依据** (见 Phase-6 验证与 `docs/plan-phase6-dns-optimization.md`):
/// 伪装站常青保活排除 DNS 耗时后，实测 Fastly 边缘处理底限 `P_edge ≈ 1~4ms` (S1 4.2ms, S3 1.4ms)。
/// 故默认 offset = 0ms，纯 2.0× 倍率即可将残差控制在 ~1.5ms 安全网络噪声内；
/// 当 `auto_calibrate = true` 时，则直接由实测 auth-fail 时延 F 的 EWMA 自校准。
pub(crate) fn auth_succ_delay_us(mult_x10: u32, offset_us: u64, cam_rtt_us: u64) -> u64 {
    if cam_rtt_us == 0 {
        // 伪装站未连通 / 不可达 (回落合成模板 F ≈ 0): 不注入固定 offset, 避免反向不对称
        return 0;
    }
    cam_rtt_us
        .saturating_mul(mult_x10 as u64)
        .saturating_div(10)
        .saturating_add(offset_us)
}

/// 自校准注入上限护栏 (500ms): 避免异常网络抖动或保活失效导致合法连接等待过久。
pub(crate) const MAX_AUTH_SUCC_INJECTION_US: u64 = 500_000;

/// 选 auth-succ 注入基准 (微秒, 未含抖动):
///
/// 1. 伪装站未连通 / 不可达 (cam_rtt_us == 0): 恒为 0 (避免反向不对称);
/// 2. auto_calibrate 开启且已有 F 样本: 采用实测的 F(EWMA), 若 F > 500ms 护栏则回落静态公式;
/// 3. auto_calibrate 开启但尚无 F 样本 (冷启动): 纯倍率 `mult×cam_RTT`, **不叠加固定 offset**
///    —— 实测 `F ≈ 2×cam_RTT + P` 且 `P` 远小于 offset, 叠加会凭空引入 ~100ms 虚高
///    (见 `docs/phase4-real-machine-verification-report.md` §8);
/// 4. auto_calibrate 关闭: 静态公式 `(mult_x10/10 × cam_RTT) + offset` (此时 `offset` 才生效)。
///
/// 最终注入值封顶 500ms 护栏。
pub(crate) fn injection_base_us(
    auto_calibrate: bool,
    fail_us: u64,
    mult_x10: u32,
    offset_us: u64,
    cam_rtt_us: u64,
) -> u64 {
    if cam_rtt_us == 0 {
        return 0;
    }
    let base = if auto_calibrate {
        if fail_us > 0 {
            if fail_us > MAX_AUTH_SUCC_INJECTION_US {
                tracing::warn!(
                    "自校准 F 样本异常过大 ({}ms > {}ms 上限), 回落静态公式避免合法握手延迟失控",
                    fail_us / 1000,
                    MAX_AUTH_SUCC_INJECTION_US / 1000
                );
                auth_succ_delay_us(mult_x10, offset_us, cam_rtt_us)
            } else {
                fail_us
            }
        } else {
            auth_succ_delay_us(mult_x10, 0, cam_rtt_us)
        }
    } else {
        auth_succ_delay_us(mult_x10, offset_us, cam_rtt_us)
    };
    base.min(MAX_AUTH_SUCC_INJECTION_US)
}

/// 当前生效的参数 —— 启动日志用。
pub fn client_hello_guard_params() -> (u32, u64, u64, u64, u64, u32, u64, bool) {
    (
        PC_MULT.load(Ordering::Relaxed),
        PC_MIN_US.load(Ordering::Relaxed) / 1000,
        PC_MAX_US.load(Ordering::Relaxed) / 1000,
        JUDGE_SILENCE_US.load(Ordering::Relaxed) / 1000,
        HARD_DEADLINE_US.load(Ordering::Relaxed) / 1000,
        AUTH_MULT_X10.load(Ordering::Relaxed),
        AUTH_OFFSET_US.load(Ordering::Relaxed) / 1000,
        AUTO_CALIBRATE.load(Ordering::Relaxed),
    )
}

/// ① 预连触发延迟 = `clamp(mult × RTT, min, max)`；RTT 未知/0 → **上限**（无 RTT 信息时偏保守）。
/// min/max 反转自动纠正。纯函数, 便于单测。
///
/// 取值依据: 真实 Chromium ClientHello ~1786B（> MSS）在 IW10 下**背靠背**发出, 正常间隔 ≈ 0,
/// 所以这个延迟主要是“高 RTT 链路留余量” + “不让快客户端触发预连”; 它**不再**承担容错职责。
pub(crate) fn preconnect_delay(
    mult: u32,
    min: Duration,
    max: Duration,
    client_rtt: Option<Duration>,
) -> Duration {
    let (floor, ceil) = if min <= max { (min, max) } else { (max, min) };
    match client_rtt {
        Some(rtt) if !rtt.is_zero() => (rtt * mult.max(1)).clamp(floor, ceil),
        _ => ceil,
    }
}

pub(crate) fn preconnect_delay_for(client_rtt: Option<Duration>) -> Duration {
    preconnect_delay(
        PC_MULT.load(Ordering::Relaxed),
        Duration::from_micros(PC_MIN_US.load(Ordering::Relaxed)),
        Duration::from_micros(PC_MAX_US.load(Ordering::Relaxed)),
        client_rtt,
    )
}

/// ② 静默判定期限。
fn judge_silence() -> Duration {
    Duration::from_micros(JUDGE_SILENCE_US.load(Ordering::Relaxed))
}
/// ③ 未认证连接总时限。
fn hard_deadline() -> Duration {
    Duration::from_micros(HARD_DEADLINE_US.load(Ordering::Relaxed))
}

// ── A3 标定度量 / 丢包误杀检测 ────────────────────────────────────────────────────
/// env `MIRAGE_CH_MEASURE=1` 时逐条输出判定画像（含 Fallback 样本 —— 旧版只记“读完整”的,
/// 被误杀的合法客户端根本不会出现在数据里, 幸存者偏差使度量无法证伪窗口）。
static CH_MEASURE: LazyLock<bool> =
    LazyLock::new(|| matches!(std::env::var("MIRAGE_CH_MEASURE").as_deref(), Ok("1") | Ok("true")));
/// 首次“疑似丢包误杀”的详细告警只打一次（之后降 debug, 免被滴发探测刷日志）。
static KILL_WARNED: AtomicBool = AtomicBool::new(false);
/// “到达之间”≥ 此值视为可能发生了 TCP 重传（TLP/RTO ≥ 200ms）。
const LOSS_SUSPECT_GAP_US: u64 = 150_000;

/// 记录一次 ClientHello 判定（度量行 + 误杀检测）。`preconnect`: "0"=未预连 "1"=用了预连 "2a"=建连前abort "2b"=建连后丢弃。
fn log_ch_guard(
    outcome: &str,
    authed: Option<bool>,
    bytes: &[u8],
    timing: &ReadTiming,
    judge: Duration,
    client_rtt: Option<Duration>,
    preconnect: &'static str,
    cam_rtt: &CamouflageRtt,
    inj_us: u64,
    pc_fire_us: u64,
    pc_ready_us: u64,
) {
    let pre_tls = bytes.first() == Some(&0x16);
    if *CH_MEASURE {
        tracing::info!(
            "[CH-GUARD] outcome={} ch_read_us={} bytes={} max_gap_us={} pre_tls={} authed={} \
             judge_us={} preconnect={} rtt_us={} fail_us={} inj_us={} pc_fire_us={} pc_ready_us={} \
             cam_rtt_us={} resolve_us={}",
            outcome,
            timing.total_us,
            timing.bytes,
            timing.max_internal_gap_us,
            pre_tls as u8,
            authed.map(|a| if a { "1" } else { "0" }).unwrap_or("-"),
            judge.as_micros(),
            preconnect,
            client_rtt.map(|r| r.as_micros()).unwrap_or(0),
            cam_rtt.fail_latency_us(),
            inj_us,
            pc_fire_us,
            pc_ready_us,
            cam_rtt.rtt_us(),
            cam_rtt.resolve_us(),
        );
    }
    // 丢包误杀检测: 已收到 TLS 记录头, 且“到达之间”出现过 ≥150ms 间隔 —— 合法客户端丢段后
    // 靠 TLP/RTO 重传正是这个形态; 一次性发完就停的探测者不会有这种**内部**间隔。
    if outcome == "fallback" && pre_tls && timing.max_internal_gap_us >= LOSS_SUSPECT_GAP_US {
        if !KILL_WARNED.swap(true, Ordering::Relaxed) {
            tracing::warn!(
                "Mirage Server: 疑似丢包误杀合法客户端 ({} 字节, 到达间隔 {}ms >= {}ms)。\
                 judge_silence_ms={} 可能小于 TCP 重传退避 (RTO 可退到 800ms+): \
                 调大 MIRAGE_CH_JUDGE_MS 或核对 docs/real-machine-verification.md A1/A3。\
                 (本告警只打一次; 开 MIRAGE_CH_MEASURE=1 可逐条统计)",
                timing.bytes,
                timing.max_internal_gap_us / 1000,
                LOSS_SUSPECT_GAP_US / 1000,
                judge.as_millis()
            );
        } else {
            tracing::debug!(
                "Mirage Server: 疑似丢包误杀 ({} 字节, 间隔 {}ms)",
                timing.bytes,
                timing.max_internal_gap_us / 1000
            );
        }
    }
}

// ── 推测性预连 (对齐) ─────────────────────────────────────────────────────────────
/// 预连预算: 全在途上限 + 全局发起速率上限。**独立于反射守卫** —— 预连可能随后因认证成功
/// 被关掉 (不是反射), 用 `UNAUTH_*` 给它计数会惩罚“触发预连的合法慢客户端”; 但它毕竟是
/// “由未认证输入触发的出向连接”, 必须自带上限, 否则一次空连接扫描就能让本机对伪装站
/// 狂开连接 (正是旧预热池被谪病的问题, 且这里可被攻击者放大)。
/// 预连并发上限。**这是真正的保护**: 尚未认证的连接可能对伪装站发起出向连接, 必须自带上限,
/// 否则一次空连接扫描就能让本机对伪装站狂开连接。
///
/// 注: 曾经的 `PRECONNECT_RATE_PER_SEC`(30/s) 已移除 —— 它并**不能减少**对伪装站的总连接数
/// (被限速的空/半截探测在判定期 ② 仍会按需建连一次), 只把建连从 ① 推迟到 ②, 结果是
/// 探测者看到的关闭偏差从 ~① 变成 ~②(约 1s), 反而**更容易被区分** (见 docs/codebase-audit-2026-10.md A1)。
/// 保留在途上限 + 有界等待后, 过载时只会降级“部分对齐”而不是“完全不对齐”。
const PRECONNECT_MAX_INFLIGHT: usize = 128;
/// 判定时等待“已 armed 的预连”就绪的上限。
const PRECONNECT_TAKE_WAIT: Duration = Duration::from_millis(800);

static PRECONNECT_INFLIGHT: LazyLock<Arc<tokio::sync::Semaphore>> =
    LazyLock::new(|| Arc::new(tokio::sync::Semaphore::new(PRECONNECT_MAX_INFLIGHT)));
/// 预连因预算耗尽而降级的次数 (可观测: 非 0 即说明该节点探测速率超过预算)。
static PRECONNECT_DEGRADED: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// 取一个预连名额: 先 try, 再在 `budget` 内等待 (名额由先完成的预连释放)。
/// 等不到 → None (调用方记降级并放弃对齐, 判定时按需建连)。
async fn preconnect_permit(
    budget: Duration,
) -> Option<tokio::sync::OwnedSemaphorePermit> {
    match PRECONNECT_INFLIGHT.clone().try_acquire_owned() {
        Ok(p) => Some(p),
        Err(_) => {
            let permit = tokio::time::timeout(budget, PRECONNECT_INFLIGHT.clone().acquire_owned())
                .await
                .ok()
                .and_then(|r| r.ok());
            // 只有等满预算仍没拿到才算降级 (预算内排到名额的不计, 否则突发时指标与告警虚高)。
            if permit.is_none() {
                let n = PRECONNECT_DEGRADED.fetch_add(1, Ordering::Relaxed) + 1;
                // 采样告警: 避免扫描时刷满日志
                if n % 500 == 1 {
                    tracing::warn!(
                        "预连预算耗尽, 第 {n} 次降级 (在途上限 {PRECONNECT_MAX_INFLIGHT}); \
                         该连接将退回判定时按需建连 ⇒ 关闭时间对齐变差"
                    );
                }
            }
            permit
        }
    }
}

/// 推测性预连: accept 后延迟 `delay` 仍未见完整 ClientHello 就后台连一条伪装站连接备用 ——
/// 让真站的空闲计时起点 ≈ 探测者连上的时刻 (**对齐**), 而判定期限可以宽容 (**容错**)。
/// 合法快客户端在 delay 前就读完 → 任务被 abort → **零**预连。
struct Preconnect {
    handle: Option<tokio::task::JoinHandle<()>>,
    rx: Option<tokio::sync::oneshot::Receiver<Option<TcpStream>>>,
    has_connected: Arc<AtomicBool>,
    fire_us: Arc<AtomicU64>,
    ready_us: Arc<AtomicU64>,
}

impl Preconnect {
    fn armed(&self) -> bool {
        self.rx.is_some()
    }
    fn was_connected(&self) -> bool {
        self.has_connected.load(Ordering::Acquire)
    }
    fn fire_us(&self) -> u64 {
        self.fire_us.load(Ordering::Relaxed)
    }
    fn ready_us(&self) -> u64 {
        self.ready_us.load(Ordering::Acquire)
    }
    /// 预算不足 → 降级 (只损失对齐, 不影响可用性: 判定时退回按需即时建连)。
    fn arm(delay: Duration, host: &str, cam_rtt: &Arc<CamouflageRtt>) -> Self {
        let (tx, rx) = tokio::sync::oneshot::channel();
        let host = host.to_string();
        let rtt = cam_rtt.clone();
        let has_connected = Arc::new(AtomicBool::new(false));
        let hc = has_connected.clone();
        let fire_us = Arc::new(AtomicU64::new(0));
        let fu = fire_us.clone();
        let ready_us = Arc::new(AtomicU64::new(0));
        let ru = ready_us.clone();
        let t_arm = Instant::now();
        let handle = tokio::spawn(async move {
            tokio::time::sleep(delay).await;
            fu.store(t_arm.elapsed().as_micros() as u64, Ordering::Relaxed);
            // 预算: 允许排到“判定后仍能被取用”的时刻 (delay + take_wait), 于是过载时只是
            // “晚一点连”而不是“完全不连” —— 保留部分对齐 (见 PRECONNECT_MAX_INFLIGHT 注释)。
            let Some(_permit) = preconnect_permit(PRECONNECT_TAKE_WAIT).await else {
                return;
            };
            let sock = camouflage::connect_camouflage(&host, &rtt).await;
            if sock.is_some() {
                ru.store(t_arm.elapsed().as_micros() as u64, Ordering::Release);
                hc.store(true, Ordering::Release);
            }
            let _ = tx.send(sock); // 接收端已 drop → socket 随之关闭, 不泄漏到伪装站
        });
        Self { handle: Some(handle), rx: Some(rx), has_connected, fire_us, ready_us }
    }
    /// 判定为异常时取用预连连接: 已 armed 则等它就绪 (有界), 否则 None (调用方按需建连)。
    async fn take_socket(&mut self) -> Option<TcpStream> {
        let rx = self.rx.take()?;
        match tokio::time::timeout(PRECONNECT_TAKE_WAIT, rx).await {
            Ok(Ok(sock)) => sock,
            _ => None,
        }
    }
    /// 非阻塞尝试取用已就绪的预连连接 (CH 秒到时预连仍在 delay 中 → 立即返回 None 以便即时建连并精确采样 F)
    fn take_ready_socket(&mut self) -> Option<TcpStream> {
        let mut rx = self.rx.take()?;
        match rx.try_recv() {
            Ok(sock) => sock,
            Err(tokio::sync::oneshot::error::TryRecvError::Empty) => {
                self.rx = Some(rx);
                None
            }
            Err(tokio::sync::oneshot::error::TryRecvError::Closed) => None,
        }
    }
}

impl Drop for Preconnect {
    fn drop(&mut self) {
        // 未触发 → 定时器任务被 abort (不会连); 已连好 → 接收端 drop, socket 随之关闭。
        if let Some(h) = self.handle.take() {
            h.abort();
        }
    }
}

/// `preconnect` 度量值:
/// - "0": 未预连
/// - "1": 用了预连 (真站 idle 计时与直连一致)
/// - "2a": 预连已 armed 但在建连前被 abort (对伪装站 0 连接损耗)
/// - "2b": 预连已建立 TCP 连接, 但随后因合法认证成功被关闭释放 (1 次上游连接损耗)
fn preconnect_status(armed: bool, used: bool, connected: bool) -> &'static str {
    if used {
        "1"
    } else if armed {
        if connected { "2b" } else { "2a" }
    } else {
        "0"
    }
}

/// 从已建立的 TCP 连接读内核 RTT 估计 (`TCP_INFO.tcpi_rtt`, 微秒)。零成本 (不发包, TCP
/// 握手后即有 SRTT)。失败 / 为 0 → None (调用方回落默认窗口)。
#[cfg(target_os = "linux")]
fn tcp_info_rtt(stream: &TcpStream) -> Option<Duration> {
    use std::os::unix::io::AsRawFd;
    let fd = stream.as_raw_fd();
    let mut info: libc::tcp_info = unsafe { std::mem::zeroed() };
    let mut len = std::mem::size_of::<libc::tcp_info>() as libc::socklen_t;
    let r = unsafe {
        libc::getsockopt(
            fd,
            libc::IPPROTO_TCP,
            libc::TCP_INFO,
            &mut info as *mut _ as *mut libc::c_void,
            &mut len,
        )
    };
    if r != 0 {
        return None;
    }
    let us = info.tcpi_rtt as u64;
    if us == 0 {
        return None;
    }
    Some(Duration::from_micros(us))
}

/// 非 Linux 无 TCP_INFO (项目实际只跑 Linux, 此分支仅为编译健全性)。
#[cfg(not(target_os = "linux"))]
fn tcp_info_rtt(_stream: &TcpStream) -> Option<Duration> {
    None
}

/// 将客户端连接与已接收字节反射给伪装站 (camouflage_host:443) 并双向透传。
/// 认证失败与各种读取异常回落共用此 helper, 统一受并发门禁 (GLOBAL_UNAUTH 5000)、
/// 源 IP 速率守卫 (UNAUTH_RATE) 及每 IP 并发限制 (UNAUTH_CONNS 100) 保护。
async fn reflect_to_camouflage<S>(
    stream: S,
    peer_addr: SocketAddr,
    bytes: &[u8],
    camouflage_host: &str,
    cam_rtt: &Arc<CamouflageRtt>,
    preconnected: Option<TcpStream>,
) where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let global_count = GLOBAL_UNAUTH.fetch_add(1, Ordering::SeqCst);
    if global_count >= 5000 {
        GLOBAL_UNAUTH.fetch_sub(1, Ordering::SeqCst);
        return;
    }

    // v0.4.5-alpha.10: 限流 key 用 /64 归一后的 IP, 防攻击者用 /64 段造
    // 2^64 独立 IPv6 地址逃逸限流. IPv4 保持单地址 (已是最细粒度).
    let ip = rate_limit_key(peer_addr.ip());

    // 反射速率守卫 (补并发上限盲区: 快速开-失败-关的高频反射)。超限直接 drop, 不再反射砸
    // camouflage_host —— GFW 低频探测远达不到阈值, 只掐滥用 flood。
    if unauth_reflect_rate_exceeded(ip) {
        GLOBAL_UNAUTH.fetch_sub(1, Ordering::SeqCst);
        return;
    }

    let _slot_guard = {
        // 锁中毒容忍 (into_inner), 不 unwrap panic —— 跟 IpSlotGuard::drop 同锁
        // 同原则. HashMap 数据没被破坏 (临界区无 panic 源).
        let mut map = match UNAUTH_CONNS.get_or_init(|| Mutex::new(HashMap::new())).lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };
        let count = map.entry(ip).or_insert(0);
        if *count >= 100 {
            GLOBAL_UNAUTH.fetch_sub(1, Ordering::SeqCst);
            return;
        }
        *count += 1;
        IpSlotGuard(ip)
    };

    camouflage::run_camouflage_forward(stream, bytes, camouflage_host, cam_rtt, preconnected).await;
}

/// 结构化消费 Fake Client Finished Tail:
/// 1. 6B 必须是 CCS `14 03 03 00 01 01`
/// 2. 5B 记录头 (类型 0x17, 版本 0x03 0x03)
/// 3. 体长只接受 53 (0x1301/0x1303) 或 69 (0x1302)
///
/// 读体丢弃，任何不符返回错误。
pub(crate) async fn consume_fake_client_tail<S: AsyncRead + Unpin>(
    stream: &mut S,
) -> anyhow::Result<usize> {
    let mut ccs = [0u8; 6];
    stream.read_exact(&mut ccs).await?;
    if ccs != [0x14, 0x03, 0x03, 0x00, 0x01, 0x01] {
        return Err(anyhow::anyhow!("invalid CCS in client tail: {:02x?}", ccs));
    }

    let mut rec_hdr = [0u8; 5];
    stream.read_exact(&mut rec_hdr).await?;
    if rec_hdr[0] != 0x17 || rec_hdr[1] != 0x03 || rec_hdr[2] != 0x03 {
        return Err(anyhow::anyhow!(
            "invalid record header in client tail: {:02x?}",
            rec_hdr
        ));
    }

    let body_len = u16::from_be_bytes([rec_hdr[3], rec_hdr[4]]) as usize;
    if body_len != 53 && body_len != 69 {
        return Err(anyhow::anyhow!(
            "invalid finished body length in client tail: {}",
            body_len
        ));
    }

    let mut body = [0u8; 69];
    stream.read_exact(&mut body[..body_len]).await?;
    Ok(body_len)
}

/// 传输无关的服务端握手核心 (ClientHello 鉴权 + 模板回放 + tail 消费)。返回 `Some((stream,
/// client_random, ecdh))` 表示鉴权通过、可进 dispatch; `None` = 已按 auth-fail 走 camouflage
/// 或出错 (调用方直接结束)。TCP/QUIC 各自的 `handle_connection*` 包一层做 split + dispatch。
pub(super) async fn run_handshake<S>(
    mut stream: S,
    peer_addr: SocketAddr,
    creds: &[super::CredEntry],
    camouflage_host: &str,
    cam_rtt: &Arc<CamouflageRtt>,
    auth_ts_tolerance_secs: u64,
    pfs: bool,
    client_rtt: Option<Duration>,
) -> Option<(S, [u8; 32], [u8; 32], Option<[u8; 32]>, usize)>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    // ① 推测性预连 (对齐): accept 后延迟 `preconnect_delay` 仍未见完整 ClientHello 就后台连一条
    //    伪装站连接备用。合法快客户端在此之前就读完 → 任务被 abort → **零**预连。
    //    预算不足 (PRECONNECT_MAX_INFLIGHT / 速率) 自动退化为不预连, 只损失对齐。
    let mut pre = Preconnect::arm(preconnect_delay_for(client_rtt), camouflage_host, cam_rtt);
    let judge = judge_silence();

    // ② 读取: 判定依据是"最后一次数据后的静默 >= judge", 而不再是旧的 `2×RTT` 窗口 ——
    //    窗口不必再为对齐让步, 所以可以给丢包重传留足时间 (修复: 丢段的合法客户端被误杀)。
    let (ch_res, timing) = read_client_hello(&mut stream, judge, hard_deadline()).await;
    let client_hello = match ch_res {
        ClientHelloReadResult::Complete(ch) => ch,
        ClientHelloReadResult::Fallback(bytes) => {
            warn!(
                "Mirage Server: abnormal pre-auth read from {} ({} bytes), reflecting to camouflage",
                peer_addr,
                bytes.len()
            );
            let armed = pre.armed();
            let fire_us = pre.fire_us();
            let sock = pre.take_socket().await;
            let used = sock.is_some();
            let connected = pre.was_connected();
            let ready_us = if connected { pre.ready_us() } else { 0 };
            log_ch_guard(
                "fallback",
                None,
                &bytes,
                &timing,
                judge,
                client_rtt,
                preconnect_status(armed, used, connected),
                cam_rtt,
                0,
                fire_us,
                ready_us,
            );
            reflect_to_camouflage(stream, peer_addr, &bytes, camouflage_host, cam_rtt, sock).await;
            return None;
        }
        ClientHelloReadResult::Close => {
            // 对端在发送任何字节前就 EOF/报错关闭, 连接已死直接退出 (pre drop → 定时器 abort)
            let armed = pre.armed();
            let connected = pre.was_connected();
            let fire_us = pre.fire_us();
            let ready_us = if connected { pre.ready_us() } else { 0 };
            log_ch_guard(
                "close",
                None,
                &[],
                &timing,
                judge,
                client_rtt,
                preconnect_status(armed, false, connected),
                cam_rtt,
                0,
                fire_us,
                ready_us,
            );
            return None;
        }
    };

    let content_type = client_hello[0];
    let body = &client_hello[TLS_RECORD_HEADER_LEN..];

    // 3. Authenticate by searching for the token in session_id field.
    //
    // ClientHello body layout (RFC 8446 §4.1.2):
    //   body[0]        HandshakeType (0x01 = ClientHello)
    //   body[1..4]     uint24 body length
    //   body[4..6]     ProtocolVersion (0x0303 = TLS 1.2)
    //   body[6..38]    Random (32 bytes) ← client_random
    //   body[38]       legacy_session_id.length (1 byte)
    //   body[39..]     legacy_session_id (32 bytes for Mirage) ← token here
    // 多用户: token 对每个凭据试, 命中即认出是哪个用户 (matched_idx)。非匹配在 tag 比对处即返回
    // false 不碰 replay, 故 replay 对同一 token 仍单插 (见 hello_auth::identify_session_token)。
    let mut matched_idx: Option<usize> = None;
    let mut client_random = [0u8; 32];

    if content_type == 0x16 && body.len() >= 39 && body[0] == 0x01 {
        let sid_len = body[38] as usize;
        if sid_len == 32 && body.len() >= 39 + sid_len {
            client_random.copy_from_slice(&body[6..38]);
            let session_id = &body[39..39 + sid_len];
            let mut sid_array = [0u8; 32];
            sid_array.copy_from_slice(session_id);
            matched_idx = verify_creds_and_quota(
                creds,
                &sid_array,
                &client_random,
                auth_ts_tolerance_secs,
                crate::proxy::user_limits::is_user_exhausted,
            );
        }
    }
    let authenticated = matched_idx.is_some();

    if !authenticated {
        warn!("Mirage Server auth failed from {}", peer_addr);
        // 完整 CH 但认证失败: 若预连已经连好则直接用; 若仍在延时中则不白等 (即时建连 preconnect=0, 采样 F 并消除人为附加延迟)
        let fire_us = pre.fire_us();
        let sock = pre.take_ready_socket();
        let used = sock.is_some();
        let connected = pre.was_connected();
        let ready_us = if connected { pre.ready_us() } else { 0 };
        if !used {
            drop(pre);
        }
        log_ch_guard(
            "complete",
            Some(false),
            &client_hello,
            &timing,
            judge,
            client_rtt,
            if used { "1" } else { "0" },
            cam_rtt,
            0,
            fire_us,
            ready_us,
        );
        reflect_to_camouflage(stream, peer_addr, &client_hello, camouflage_host, cam_rtt, sock).await;
        return None;
    }

    // 认证成功: 关掉推测性预连 (任务 abort / socket drop = 关闭)。这正是"合法客户端零额外
    // 开销"的落点 —— 绝大多数连接在预连触发前就读完了, 从未向伪装站发出过连接。
    let was_armed = pre.armed();
    let was_connected = pre.was_connected();
    let fire_us = pre.fire_us();
    let ready_us = if was_connected { pre.ready_us() } else { 0 };
    drop(pre);

    let mult_x10 = AUTH_MULT_X10.load(Ordering::Relaxed);
    let offset_us = AUTH_OFFSET_US.load(Ordering::Relaxed);
    let auto_calib = AUTO_CALIBRATE.load(Ordering::Relaxed);
    let inj_us = injection_base_us(
        auto_calib,
        cam_rtt.fail_latency_us(),
        mult_x10,
        offset_us,
        cam_rtt.rtt_us(),
    );

    log_ch_guard(
        "complete",
        Some(true),
        &client_hello,
        &timing,
        judge,
        client_rtt,
        preconnect_status(was_armed, false, was_connected),
        cam_rtt,
        inj_us,
        fire_us,
        ready_us,
    );

    // PFS: 生成服务端一次性 X25519 对。公钥注入回放模板的 ServerHello.random 发给客户端,
    // 私钥留着与 client_random (= 客户端临时公钥) 做 ECDH。见 crypto::pfs。
    let server_ephemeral = if pfs {
        match crate::crypto::pfs::Ephemeral::generate() {
            Ok(e) => Some(e),
            Err(e) => {
                tracing::error!("Mirage Server: PFS 临时密钥生成失败: {e}");
                return None;
            }
        }
    } else {
        None
    };

    // 2.5 Send ServerHello template back to satisfy Mirage Client's TLS state machine
    let (template, server_random) = crate::crypto::handshake_cache::get_server_hello_pfs(
        camouflage_host,
        &client_hello,
        server_ephemeral.as_ref().map(|e| &e.public),
    )
    .await;
    // v0.15: server_random 参与会话密钥派生 (服务端新鲜性的唯一来源)。全 0 = 回放模板异常没写进
    // random —— 此时派生退化为只依赖 client_random, 重放防护失效。客户端遇全 0 会自行断开, 但攻击者
    // 扮演客户端时不会, 故服务端也必须 fail-closed。正常路径 (apply_server_random) 恒写入随机值。
    if server_random == [0u8; 32] {
        warn!("Mirage Server: ServerHello 模板未携带 random (全 0), 拒绝该连接 (fail-closed) from {}", peer_addr);
        return None;
    }

    // v0.4.5-alpha.13: 消除 auth-succ vs auth-fail 时序侧信道.
    // 注入由 injection_base_us 统一决定的延迟基准 (含 ±25% 抖动模拟网络方差).
    if inj_us > 0 {
        let jitter_num = 75 + fastrand::u64(0..=50); // 75%~125%
        let delay_us = inj_us.saturating_mul(jitter_num) / 100;
        tokio::time::sleep(Duration::from_micros(delay_us)).await;
    }

    if let Err(e) = stream.write_all(&template).await {
        tracing::debug!("Mirage Server: write_all template failed: {}", e);
        return None;
    }

    // 2.7 Consume Fake Client Tail (按结构读取: 6B CCS + 5B record header + 53B/69B body)
    match tokio::time::timeout(Duration::from_secs(5), consume_fake_client_tail(&mut stream)).await {
        Ok(Err(e)) => {
            tracing::debug!("Mirage Server: consume tail failed: {}", e);
            return None;
        }
        Err(_) => {
            tracing::debug!("Mirage Server: consume tail timed out!");
            return None;
        }
        Ok(Ok(body_len)) => {
            tracing::debug!(
                "Mirage Server: Successfully consumed {} bytes tail (body {}B)",
                6 + 5 + body_len,
                body_len
            );
        }
    }

    // PFS: 与 client_random (= 客户端临时公钥) 做 ECDH 得共享秘密, 混进会话 master。
    let ecdh = match server_ephemeral {
        Some(e) => match e.agree(&client_random) {
            Ok(s) => Some(s),
            Err(err) => {
                tracing::error!("Mirage Server: PFS ECDH 协商失败: {err}");
                return None;
            }
        },
        None => None,
    };

    // Hand off to control plane (crypto setup + TIME_SYNC + dispatch)。matched_idx 此处必 Some
    // (上方 !authenticated 已 return None), 即命中的凭据下标, 供调用方取用户名/派生密钥的 password。
    Some((stream, client_random, server_random, ecdh, matched_idx.expect("authenticated ⇒ matched_idx")))
}

/// TCP 传输入口: 握手 → into_split (Tcp 变体, 保留静态分发 + 无锁) → dispatch。
pub(super) async fn handle_connection(
    stream: TcpStream,
    peer_addr: SocketAddr,
    ip_guard: super::ConnIpGuard,
    creds: super::CredsSnapshot,
    camouflage_host: String,
    cam_rtt: Arc<CamouflageRtt>,
    auth_ts_tolerance_secs: u64,
    upstream: Option<std::sync::Arc<crate::proxy::upstream::UpstreamOutlet>>,
    pfs: bool,
    allow_local_targets: bool,
    inbound_tag: Option<Arc<str>>,
) {
    stream.set_nodelay(true).unwrap_or_default();
    let client_ip = peer_addr.ip();
    // 客户端 RTT (TCP_INFO, 零成本) → 预连触发延迟 (见 `preconnect_delay_for`)。
    let client_rtt = tcp_info_rtt(&stream);
    let creds_snapshot = creds.load_full();
    if let Some((stream, client_random, server_random, ecdh, idx)) = run_handshake(
        stream, peer_addr, &creds_snapshot, &camouflage_host, &cam_rtt, auth_ts_tolerance_secs, pfs, client_rtt,
    )
    .await
    {
        // 认证通过: 归还单来源未认证名额 (失败路径要转发伪装站, 名额持到连接结束)。
        drop(ip_guard);
        // 命中的凭据: 用户名 + 派生会话密钥的 password + 该凭据的吊销令牌 (改口令/删用户时置位)
        let entry = &creds_snapshot[idx];
        let user = entry.name.clone();
        let password = entry.password.clone();
        let cred_revoked = entry.revoked.clone();
        let (rh, wh) = stream.into_split();
        control::dispatch_authenticated(
            crate::proxy::tunnel::TunnelRead::Tcp(rh),
            crate::proxy::tunnel::TunnelWrite::Tcp(wh),
            Some(client_ip),
            password,
            user,
            cred_revoked,
            client_random,
            server_random,
            upstream,
            ecdh,
            allow_local_targets,
            inbound_tag,
        )
        .await;
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    use crate::proxy::mirage_server::CredEntry;

    #[test]
    fn unauth_reflect_rate_trips_after_max() {
        // 测试专用 IP, 免与其它测试共享 static 状态干扰。
        let ip: IpAddr = "203.0.113.77".parse().unwrap();
        for i in 1..=UNAUTH_RATE_MAX {
            assert!(!unauth_reflect_rate_exceeded(ip), "第 {i} 次不该超限");
        }
        assert!(unauth_reflect_rate_exceeded(ip), "超过 MAX 应触发丢弃");
    }

    #[test]
    fn reflect_rate_key_normalizes_ipv6_to_64() {
        // 同 /64 段不同低位 → 归一为同一限流 key, 共享速率窗口 (防 /64 造 2^64 IP 逃逸)。
        let a = rate_limit_key("2001:db8::1".parse().unwrap());
        let b = rate_limit_key("2001:db8::dead:beef".parse().unwrap());
        assert_eq!(a, b, "同 /64 应归一为同 key");
    }

    #[test]
    fn rate_limit_key_unmaps_ipv4_mapped_addresses() {
        // 双栈监听下 v4 客户端是 ::ffff:a.b.c.d: 必须还原成各自的 v4 key, 不能塌成同一个 `::`。
        let a = rate_limit_key("::ffff:192.0.2.1".parse().unwrap());
        let b = rate_limit_key("::ffff:192.0.2.2".parse().unwrap());
        assert_ne!(a, b, "不同 v4 来源不得共享同一桶");
        assert_eq!(a, "192.0.2.1".parse::<std::net::IpAddr>().unwrap());
    }

    #[test]
    fn test_verify_creds_and_quota_exhausted_treated_as_auth_failed() {
        // 串行: 生成 token 读全局 TIME_OFFSET, 与会改 offset 的测试 (time_sync / 服务端时钟隔离) 并行会超容差。
        let _t = crate::time_sync::tests::TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let creds = vec![
            CredEntry::new("alice", "pwd_alice"),
            CredEntry::new("bob", "pwd_bob"),
        ];
        let client_random = [42u8; 32];
        let token = crate::crypto::hello_auth::make_session_token("pwd_alice", &client_random);

        // 1. 未超额 -> 认证成功, 返回 Some(0)
        let res = verify_creds_and_quota(&creds, &token, &client_random, 60, |_| false);
        assert_eq!(res, Some(0));

        // 2. 超额 -> 返回 None (当作认证失败)
        let res_exh = verify_creds_and_quota(&creds, &token, &client_random, 60, |user| user == "alice");
        assert_eq!(res_exh, None);
    }

    #[test]
    fn test_creds_registry_hot_reload_reflects_changes() {
        // 串行: config_watcher 的 apply_user_config 测试会吊销注册表中"不在其配置里"的所有 tag。
        let _creds_serial = crate::proxy::user_limits::REGISTRY_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        // 串行: 生成 token 读全局 TIME_OFFSET, 与会改 offset 的测试 (time_sync / 服务端时钟隔离) 并行会超容差。
        let _t = crate::time_sync::tests::TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let tag = "test_tag_hot_reload";
        let initial_creds = vec![
            super::super::CredEntry::new("default", "main_pwd"),
            super::super::CredEntry::new("alice", "alice_pwd"),
            super::super::CredEntry::new("bob", "bob_pwd"),
        ];
        let store = super::super::register_creds(tag, initial_creds);

        let client_random = [11u8; 32];
        let token_alice = crate::crypto::hello_auth::make_session_token("alice_pwd", &client_random);
        let token_bob = crate::crypto::hello_auth::make_session_token("bob_pwd", &client_random);

        // 初始状态: alice 与 bob 均能通过
        let snap1 = store.load();
        assert_eq!(verify_creds_and_quota(&snap1, &token_alice, &client_random, 60, |_| false), Some(1));
        assert_eq!(verify_creds_and_quota(&snap1, &token_bob, &client_random, 60, |_| false), Some(2));

        // 热重载: 删掉 bob, 修改 alice 密码, 增加 charlie
        let new_creds = vec![
            super::super::CredEntry::new("default", "main_pwd"),
            super::super::CredEntry::new("alice", "alice_pwd_new"),
            super::super::CredEntry::new("charlie", "charlie_pwd"),
        ];
        let updated = super::super::reload_creds(tag, new_creds);
        assert!(updated, "已注册 tag 热重载应返回 true");

        // 新快照立即生效
        let snap2 = store.load();

        // 1. 被删掉的 bob token 不再通过
        assert_eq!(
            verify_creds_and_quota(&snap2, &token_bob, &client_random, 60, |_| false),
            None,
            "删掉的用户 token 不应再通过"
        );

        // 2. alice 旧密码 token 不再通过
        assert_eq!(
            verify_creds_and_quota(&snap2, &token_alice, &client_random, 60, |_| false),
            None,
            "旧密码 token 不应再通过"
        );

        // 3. alice 新密码 token 通过
        let token_alice_new = crate::crypto::hello_auth::make_session_token("alice_pwd_new", &client_random);
        assert_eq!(
            verify_creds_and_quota(&snap2, &token_alice_new, &client_random, 60, |_| false),
            Some(1)
        );

        // 4. 新用户 charlie token 通过
        let token_charlie = crate::crypto::hello_auth::make_session_token("charlie_pwd", &client_random);
        assert_eq!(
            verify_creds_and_quota(&snap2, &token_charlie, &client_random, 60, |_| false),
            Some(2)
        );
    }

    #[tokio::test]
    async fn test_read_client_hello_http_probe_immediate_fallback() {
        let (mut client, mut server) = tokio::io::duplex(1024);
        let probe = b"GET / HTTP/1.1\r\n\r\n";
        client.write_all(probe).await.unwrap();

        let start = Instant::now();
        let (res, _t) =
            read_client_hello(&mut server, Duration::from_secs(5), Duration::from_secs(10)).await;
        let elapsed = start.elapsed();

        // 必须立即判定, 不等超时或后续字节
        assert!(elapsed < Duration::from_millis(500), "HTTP 探测必须立即判定回落, 实际耗时 {:?}", elapsed);
        match res {
            ClientHelloReadResult::Fallback(bytes) => {
                // 只读到判定所需的前缀, 余下字节留在流里由 camouflage 双向透传原样送达伪装站。
                assert!(probe.starts_with(&bytes) && !bytes.is_empty(), "回落字节必须是探针前缀");
                let mut rest = vec![0u8; probe.len() - bytes.len()];
                server.read_exact(&mut rest).await.unwrap();
                assert_eq!([bytes, rest].concat(), probe, "回落字节 + 流中剩余 == 探针原文, 一字不丢");
            }
            other => panic!("expected Fallback, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn test_read_client_hello_oversized_record_len_fallback() {
        let (mut client, mut server) = tokio::io::duplex(1024);
        // TLS record header: 0x16, 0x03, 0x03, len = 20000 (> 16384)
        let header = [0x16, 0x03, 0x03, 0x4e, 0x20];
        client.write_all(&header).await.unwrap();

        let (res, _t) =
            read_client_hello(&mut server, Duration::from_secs(5), Duration::from_secs(10)).await;
        match res {
            ClientHelloReadResult::Fallback(bytes) => {
                assert_eq!(bytes, header, "超长 record_len 必须回落且包含已读字节");
            }
            other => panic!("expected Fallback, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn test_read_client_hello_zero_record_len_fallback() {
        let (mut client, mut server) = tokio::io::duplex(1024);
        // TLS record header: 0x16, 0x03, 0x03, len = 0
        let header = [0x16, 0x03, 0x03, 0x00, 0x00];
        client.write_all(&header).await.unwrap();

        let (res, _t) =
            read_client_hello(&mut server, Duration::from_secs(5), Duration::from_secs(10)).await;
        match res {
            ClientHelloReadResult::Fallback(bytes) => {
                assert_eq!(bytes, header, "record_len == 0 必须回落且包含已读字节");
            }
            other => panic!("expected Fallback, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn test_read_client_hello_partial_body_timeout_fallback() {
        let (mut client, mut server) = tokio::io::duplex(1024);
        // header: 0x16, 0x03, 0x03, len = 100
        let mut data = vec![0x16, 0x03, 0x03, 0x00, 0x64];
        // body 发 40 字节 (不足 100 字节), client 停顿保持连接开启
        data.extend(vec![0xAA; 40]);
        client.write_all(&data).await.unwrap();

        let (res, _t) =
            read_client_hello(&mut server, Duration::from_millis(50), Duration::from_secs(5)).await;
        match res {
            ClientHelloReadResult::Fallback(bytes) => {
                assert_eq!(bytes, data, "超时后回落字节必须 == 已发送的全部字节 (头+半个体)");
            }
            other => panic!("expected Fallback, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn test_read_client_hello_legitimate_complete() {
        let (mut client, mut server) = tokio::io::duplex(1024);
        // header: 0x16, 0x03, 0x01, len = 150
        let mut ch = vec![0x16, 0x03, 0x01, 0x00, 0x96];
        ch.extend(vec![0xBB; 150]);
        client.write_all(&ch).await.unwrap();

        let (res, _t) =
            read_client_hello(&mut server, Duration::from_secs(5), Duration::from_secs(10)).await;
        match res {
            ClientHelloReadResult::Complete(bytes) => {
                assert_eq!(bytes, ch, "合法 ClientHello 必须完整读出且返回 Complete");
            }
            other => panic!("expected Complete, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn test_read_client_hello_does_not_overread_past_record() {
        let (mut client, mut server) = tokio::io::duplex(1024);
        let mut ch = vec![0x16, 0x03, 0x01, 0x00, 0x10];
        ch.extend(vec![0xBB; 16]);
        let mut sent = ch.clone();
        sent.extend_from_slice(b"TRAILING"); // 紧随其后的管道化字节
        client.write_all(&sent).await.unwrap();

        let (res, _t) =
            read_client_hello(&mut server, Duration::from_secs(5), Duration::from_secs(10)).await;
        assert_eq!(res, ClientHelloReadResult::Complete(ch), "只读首个 record, 不吞后续字节");
        let mut rest = [0u8; 8];
        server.read_exact(&mut rest).await.unwrap();
        assert_eq!(&rest, b"TRAILING", "后续字节必须留在流里");
    }

    #[tokio::test]
    async fn test_read_client_hello_zero_bytes_eof_closes() {
        let (client, mut server) = tokio::io::duplex(1024);
        drop(client); // 0 字节立即断开
        let (res, _t) =
            read_client_hello(&mut server, Duration::from_secs(5), Duration::from_secs(10)).await;
        assert_eq!(res, ClientHelloReadResult::Close, "未发送任何字节即 EOF 应返回 Close");
    }

    #[tokio::test]
    async fn test_read_client_hello_zero_bytes_timeout_fallback() {
        let (_client, mut server) = tokio::io::duplex(1024);
        // 0 字节连接挂起超时
        let (res, _t) =
            read_client_hello(&mut server, Duration::from_millis(50), Duration::from_secs(5)).await;
        match res {
            ClientHelloReadResult::Fallback(bytes) => {
                assert!(bytes.is_empty(), "0 字节超时应交出空字节交由伪装站超时接管");
            }
            other => panic!("expected Fallback, got {:?}", other),
        }
    }

    /// auth-succ 注入 = `(mult_x10/10 × cam_RTT) + offset`。
    /// 实测依据: auth-fail 含伪装站/CDN 对 ClientHello 的固有处理底限 P (~100ms, 与 RTT 无关)
    /// —— 只按 `2×cam_RTT` 注入时 auth-succ 比 auth-fail 快 118~125ms (S1/S2)。
    #[test]
    fn auth_succ_delay_is_mult_plus_offset() {
        // 默认档: 2.0× + 100ms
        assert_eq!(auth_succ_delay_us(20, 100_000, 180_000), 460_000);
        // 纯倍率 (offset=0)
        assert_eq!(auth_succ_delay_us(20, 0, 180_000), 360_000);
        // 半整倍率 (2.5× → x10=25)
        assert_eq!(auth_succ_delay_us(25, 0, 180_000), 450_000);
        // 伪装站未连通 / 不可达 (回落合成模板 F ≈ 0) 时不注入固定偏置, 避免反向不对称 (合法变慢 100ms)
        assert_eq!(auth_succ_delay_us(20, 100_000, 0), 0);
        // 饱和不溢出
        assert_eq!(auth_succ_delay_us(100, u64::MAX, u64::MAX), u64::MAX);
    }

    /// ① 预连触发延迟: `clamp(mult×RTT, min, max)`, RTT 未知 → 上限。
    /// （它只负责**对齐**；容错由 ②`judge_silence` 负责。）
    #[test]
    fn preconnect_delay_adapts_to_rtt() {
        let (m, lo, hi) = (2u32, Duration::from_millis(100), Duration::from_millis(500));
        // 低延迟: 2×20ms=40ms → 下限 100ms
        assert_eq!(preconnect_delay(m, lo, hi, Some(Duration::from_millis(20))), Duration::from_millis(100));
        // 中延迟: 2×80ms=160ms
        assert_eq!(preconnect_delay(m, lo, hi, Some(Duration::from_millis(80))), Duration::from_millis(160));
        // 高延迟: 2×300ms=600ms → 上限 500ms
        assert_eq!(preconnect_delay(m, lo, hi, Some(Duration::from_millis(300))), Duration::from_millis(500));
        // RTT 未知 / 0 → 上限 (保守)
        assert_eq!(preconnect_delay(m, lo, hi, None), Duration::from_millis(500));
        assert_eq!(preconnect_delay(m, lo, hi, Some(Duration::ZERO)), Duration::from_millis(500));
        // 可配: 3×RTT / clamp 50~2000ms
        let (m2, lo2, hi2) = (3u32, Duration::from_millis(50), Duration::from_millis(2000));
        assert_eq!(preconnect_delay(m2, lo2, hi2, Some(Duration::from_millis(20))), Duration::from_millis(60));
        assert_eq!(preconnect_delay(m2, lo2, hi2, Some(Duration::from_millis(500))), Duration::from_millis(1500));
        // min/max 反转自动纠正
        assert_eq!(
            preconnect_delay(2, Duration::from_millis(500), Duration::from_millis(100), Some(Duration::from_millis(1000))),
            Duration::from_millis(500)
        );
    }

    /// **P1 回归（本设计的核心不变量）**: 合法客户端丢段后靠 TCP 重传补上 (到达间隔 ≈ RTO 200ms)。
    /// 只要间隔小于判定期限, 就必须读到完整、**不得**被判成探测转发去真站。
    /// 旧实现把 `2×RTT` (下限 100ms) 当作判定期限, 丢一个段就误杀。
    #[tokio::test]
    async fn retransmit_gap_within_judge_is_tolerated() {
        let (mut client, mut server) = tokio::io::duplex(4096);
        let ch: Vec<u8> = {
            let mut v = vec![0x16, 0x03, 0x01, 0x00, 0x20]; // len = 32
            v.extend(vec![0xAA; 32]);
            v
        };
        let first = ch[..5].to_vec(); // 只到记录头 (等效第 2 段丢失)
        let second = ch[5..].to_vec(); // RTO 后重传补上
        let w = tokio::spawn(async move {
            client.write_all(&first).await.unwrap();
            tokio::time::sleep(Duration::from_millis(200)).await; // ≈ Linux 最小 RTO
            client.write_all(&second).await.unwrap();
            client // 保持连接开到自己读完
        });

        let (res, t) =
            read_client_hello(&mut server, Duration::from_millis(1000), Duration::from_secs(5)).await;
        assert_eq!(res, ClientHelloReadResult::Complete(ch), "重传间隔 < 判定期限时必须读完, 不得误判");
        assert!(t.max_internal_gap_us >= 150_000, "应记下 >=150ms 的内部间隔: {}", t.max_internal_gap_us);
        let _hold = w.await;
    }

    /// 对照锚点: 判定期限小于重传间隔时, 半截被交出转真站 —— 这正是旧缺陷的行为, 也说明
    /// “判定期限必须大于 TCP 重传退避”。注意此形态与真实探测**不可区分** (内部间隔为 0),
    /// 故靠度量计数只能看到“内部间隔 ≥150ms 的误杀”, 这类要靠 A1 关掉时间对比才能发现。
    #[tokio::test]
    async fn retransmit_gap_beyond_judge_is_forwarded() {
        let (mut client, mut server) = tokio::io::duplex(4096);
        let ch: Vec<u8> = {
            let mut v = vec![0x16, 0x03, 0x01, 0x00, 0x20];
            v.extend(vec![0xAA; 32]);
            v
        };
        let first = ch[..5].to_vec();
        let first_copy = first.clone();
        let second = ch[5..].to_vec();
        let w = tokio::spawn(async move {
            client.write_all(&first).await.unwrap();
            tokio::time::sleep(Duration::from_millis(300)).await; // > 判定期限
            let _ = client.write_all(&second).await;
            client
        });

        let (res, t) =
            read_client_hello(&mut server, Duration::from_millis(100), Duration::from_secs(5)).await;
        match res {
            ClientHelloReadResult::Fallback(bytes) => {
                assert_eq!(bytes, first_copy, "期限小于重传间隔时只交出已收到的半截");
                assert_eq!(t.max_internal_gap_us, 0, "只有一个到达, 内部无间隔 (与真探测同形)");
            }
            other => panic!("expected Fallback, got {other:?}"),
        }
        w.abort();
    }

    /// `ReadTiming.max_internal_gap_us` 只统计**到达之间**的间隔, 不含末尾那段触发判定的静默 ——
    /// 否则“探测者发完就停”也会被误记成丢包误杀, 度量就失去意义。
    #[tokio::test]
    async fn read_timing_excludes_trailing_silence() {
        let (mut client, mut server) = tokio::io::duplex(4096);
        let data = {
            let mut v = vec![0x16, 0x03, 0x03, 0x00, 0x64]; // 声称 100B
            v.extend(vec![0xAA; 40]);
            v
        };
        client.write_all(&data).await.unwrap();

        let (res, t) =
            read_client_hello(&mut server, Duration::from_millis(80), Duration::from_secs(5)).await;
        assert!(matches!(res, ClientHelloReadResult::Fallback(_)));
        // 关键语义: 末尾那 80ms 静默**不算**内部间隔, 度量才不会被“单次发完就停”的探测者误触。
        // (一次 write 在 duplex 上可能被拆成多次 read → 允许 µs 级内部间隔, 但远小于 50ms。)
        assert!(
            t.max_internal_gap_us < 50_000,
            "末尾静默不应被计入内部间隔, 实得 {}us",
            t.max_internal_gap_us
        );
        assert_eq!(t.bytes, data.len());
        assert!(t.total_us >= 80_000, "总耗时含末尾静默: {}", t.total_us);
    }

    /// 核心不变量: 数据分段到达且段间隔 < 静默窗口时, **不得**误判为探测 ——
    /// 分段到达但间隔小于判定期限 → 读到完整 (与 `retransmit_gap_within_judge_is_tolerated` 同族,
    /// 这里验的是普通两段紧接到达的情形)。
    #[tokio::test]
    async fn test_read_client_hello_interval_data_not_treated_as_quiet() {
        let (mut client, mut server) = tokio::io::duplex(4096);
        let ch: Vec<u8> = {
            let mut v = vec![0x16, 0x03, 0x01, 0x00, 0x20]; // len = 32
            v.extend(vec![0xAA; 32]);
            v
        };
        let first = ch[..10].to_vec();
        let second = ch[10..].to_vec();

        let writer = tokio::spawn(async move {
            client.write_all(&first).await.unwrap();
            // 间隔远小于判定期限 (10× 裕量): 在负载重的 CI 上也不致因调度延迟偶发失败。
            tokio::time::sleep(Duration::from_millis(200)).await;
            client.write_all(&second).await.unwrap();
            client // 保持连接开启直到读完
        });

        let (res, _t) =
            read_client_hello(&mut server, Duration::from_secs(2), Duration::from_secs(5)).await;
        assert_eq!(res, ClientHelloReadResult::Complete(ch), "持续有数据到达就不该触发静默判定");
        let _hold = writer.await;
    }

    /// slowloris 兜底: 以 < quiet 的间隔持续滴发但总时长超 hard → hard deadline 强制回落。
    #[tokio::test]
    async fn test_read_client_hello_drip_feed_hits_hard_deadline() {
        let (mut client, mut server) = tokio::io::duplex(4096);
        let header = vec![0x16, 0x03, 0x03, 0x03, 0xE8]; // 声称 body 1000B
        let writer = tokio::spawn(async move {
            if client.write_all(&header).await.is_err() { return; }
            for _ in 0..100 {
                if client.write_all(&[0xAA]).await.is_err() { return; }
                tokio::time::sleep(Duration::from_millis(20)).await; // < quiet(50ms)
            }
        });

        let start = Instant::now();
        let (res, _t) =
            read_client_hello(&mut server, Duration::from_millis(50), Duration::from_millis(300)).await;
        let elapsed = start.elapsed();
        assert!(matches!(res, ClientHelloReadResult::Fallback(_)), "滴发应被 hard deadline 兜底, 实际 {:?}", res);
        assert!(elapsed >= Duration::from_millis(250), "应在 hard deadline 附近返回, 实际 {:?}", elapsed);
        writer.abort();
    }

    #[tokio::test]
    #[allow(clippy::await_holding_lock)] // 仅测试串行锁, current_thread 运行时无死锁
    async fn test_run_handshake_authenticated_success_over_duplex() {
        // 串行: 生成 token 读全局 TIME_OFFSET, 与会改 offset 的测试 (time_sync / 服务端时钟隔离) 并行会超容差。
        let _t = crate::time_sync::tests::TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let (mut client, server) = tokio::io::duplex(8192);
        let password = "test_handshake_pwd";
        let creds = vec![super::super::CredEntry::new("default", password)];
        let peer_addr: SocketAddr = "127.0.0.1:12345".parse().unwrap();
        let cam_rtt = CamouflageRtt::new();

        let client_random = [0x55u8; 32];
        let token = crate::crypto::hello_auth::make_session_token(password, &client_random);

        // 构造能够通过认证的合法 ClientHello
        let mut hs = vec![0x01, 0x00, 0x00, 0x00]; // type ClientHello + 3B len
        hs.extend_from_slice(&[0x03, 0x03]); // version
        hs.extend_from_slice(&client_random); // random
        hs.push(32); // sid_len
        hs.extend_from_slice(&token); // session_id
        hs.extend_from_slice(&2u16.to_be_bytes()); // cipher_len
        hs.extend_from_slice(&[0x13, 0x01]); // cipher
        hs.extend_from_slice(&[0x01, 0x00]); // compression
        hs.extend_from_slice(&[0x00, 0x00]); // extensions len = 0
        let body_len = (hs.len() - 4) as u32;
        hs[1..4].copy_from_slice(&body_len.to_be_bytes()[1..4]);

        let mut ch_record = vec![0x16, 0x03, 0x01];
        ch_record.extend_from_slice(&(hs.len() as u16).to_be_bytes());
        ch_record.extend_from_slice(&hs);

        let server_task = tokio::spawn(async move {
            run_handshake(server, peer_addr, &creds, "example.com", &cam_rtt, 60, false, None).await
        });

        // 客户端发送 ClientHello
        client.write_all(&ch_record).await.unwrap();

        // 客户端读取服务端回显模板 (直到集齐 0x16, 0x14, 0x17)
        let mut resp_buf = vec![0u8; 4096];
        let n = client.read(&mut resp_buf).await.unwrap();
        assert!(n > 0, "服务端必须返回 ServerHello 模板");

        // 客户端发送 fake client finished tail (0x1301 -> 53B body, 总长 64B)
        let tail = crate::crypto::tls_raw::build_fake_client_tail(0x1301);
        client.write_all(&tail).await.unwrap();

        let handshake_res = server_task.await.unwrap();
        assert!(handshake_res.is_some(), "合法 ClientHello 必须握手成功");
        let (_stream, c_rand, s_rand, _ecdh, idx) = handshake_res.unwrap();
        assert_eq!(idx, 0, "命中的凭据下标为 0");
        assert_eq!(c_rand, client_random);
        assert_ne!(s_rand, [0u8; 32], "server_random 必须有效写入");
    }

    #[tokio::test]
    async fn test_consume_fake_client_tail_53_and_69_and_no_overread() {
        use std::io::Cursor;
        use tokio::io::AsyncReadExt;

        // 1. 53B body tail + 额外载荷: 正确消费 64B, 额外字节不被多读
        let tail_53 = crate::crypto::tls_raw::build_fake_client_tail(0x1301);
        assert_eq!(tail_53.len(), 64);
        let mut stream_data = tail_53;
        stream_data.extend_from_slice(b"EXTRA_STREAM_PAYLOAD_53");
        let mut cursor = Cursor::new(stream_data);

        let consumed = consume_fake_client_tail(&mut cursor).await.unwrap();
        assert_eq!(consumed, 53);
        let mut remaining = Vec::new();
        cursor.read_to_end(&mut remaining).await.unwrap();
        assert_eq!(remaining, b"EXTRA_STREAM_PAYLOAD_53");

        // 2. 69B body tail + 额外载荷: 正确消费 80B, 额外字节不被多读
        let tail_69 = crate::crypto::tls_raw::build_fake_client_tail(0x1302);
        assert_eq!(tail_69.len(), 80);
        let mut stream_data_69 = tail_69;
        stream_data_69.extend_from_slice(b"EXTRA_STREAM_PAYLOAD_69");
        let mut cursor_69 = Cursor::new(stream_data_69);

        let consumed_69 = consume_fake_client_tail(&mut cursor_69).await.unwrap();
        assert_eq!(consumed_69, 69);
        let mut remaining_69 = Vec::new();
        cursor_69.read_to_end(&mut remaining_69).await.unwrap();
        assert_eq!(remaining_69, b"EXTRA_STREAM_PAYLOAD_69");
    }

    #[tokio::test]
    async fn test_consume_fake_client_tail_rejects_invalid() {
        use std::io::Cursor;

        // 非法 CCS
        let mut bad_ccs = crate::crypto::tls_raw::build_fake_client_tail(0x1301);
        bad_ccs[0] = 0x15;
        let res = consume_fake_client_tail(&mut Cursor::new(bad_ccs)).await;
        assert!(res.is_err(), "非法 CCS 应被拒绝");

        // 非法 record type (非 0x17)
        let mut bad_type = crate::crypto::tls_raw::build_fake_client_tail(0x1301);
        bad_type[6] = 0x16;
        let res = consume_fake_client_tail(&mut Cursor::new(bad_type)).await;
        assert!(res.is_err(), "非法 record type 应被拒绝");

        // 非法体长 (例如 64B 体长, 或 52B)
        let mut bad_len = crate::crypto::tls_raw::build_fake_client_tail(0x1301);
        bad_len[9] = 0x00;
        bad_len[10] = 52; // 52B != 53 && != 69
        let res = consume_fake_client_tail(&mut Cursor::new(bad_len)).await;
        assert!(res.is_err(), "非法体长应被拒绝");
    }

    #[test]
    fn test_injection_base_selection() {
        // 1. auto 开且已有 F 样本 → 采用实测的 F(EWMA)
        assert_eq!(injection_base_us(true, 460_000, 20, 100_000, 180_000), 460_000);
        // 2. auto 开但无 F 样本 (冷启动) → **纯倍率**, 忽略 offset (实测 P ≪ offset, 叠加即虚高)
        assert_eq!(injection_base_us(true, 0, 20, 100_000, 180_000), 360_000);
        assert_eq!(injection_base_us(true, 0, 20, 999_000, 180_000), 360_000);
        // 3. auto 关 → 静态公式 (即使已有 F), offset 生效
        assert_eq!(injection_base_us(false, 460_000, 20, 100_000, 180_000), 460_000);
        // 4. 关键安全守卫: 伪装站不可达 (cam_rtt_us == 0) → 恒为 0 (绝不注入, 避免反向时延不对称)
        assert_eq!(injection_base_us(true, 460_000, 20, 100_000, 0), 0);
        assert_eq!(injection_base_us(false, 0, 20, 100_000, 0), 0);
        // 5. 护栏: auto 开但 F 样本超限 (> 500ms) → 回落静态公式
        assert_eq!(injection_base_us(true, 600_000, 20, 100_000, 180_000), 460_000);
        // 6. 护栏: 无论静态还是自校准, 最终注入封顶 500ms
        assert_eq!(injection_base_us(false, 0, 30, 200_000, 200_000), 500_000);
    }

    #[test]
    fn test_config_startup_defaults_consistency() {
        assert_eq!(crate::config::default_preconnect_mult(), 1);
        assert_eq!(crate::config::default_preconnect_min_ms(), 50);
        assert_eq!(crate::config::default_preconnect_max_ms(), 200);
        assert_eq!(crate::config::default_auth_succ_offset_ms(), 0);
        assert!(crate::config::default_auto_calibrate());
    }

    #[test]
    fn test_tier_b_implicit_vs_explicit_config_identical() {
        let implicit: crate::config::ClientHelloGuardConfig = serde_json::from_str("{}").unwrap();
        let explicit: crate::config::ClientHelloGuardConfig = serde_json::from_str(
            r#"{
                "preconnect_mult": 1,
                "preconnect_min_ms": 50,
                "preconnect_max_ms": 200,
                "auth_succ_offset_ms": 0,
                "auto_calibrate": true
            }"#,
        )
        .unwrap();

        assert_eq!(implicit.preconnect_mult, explicit.preconnect_mult);
        assert_eq!(implicit.preconnect_min_ms, explicit.preconnect_min_ms);
        assert_eq!(implicit.preconnect_max_ms, explicit.preconnect_max_ms);
        assert_eq!(implicit.auth_succ_offset_ms, explicit.auth_succ_offset_ms);
        assert_eq!(implicit.auto_calibrate, explicit.auto_calibrate);
    }
}
