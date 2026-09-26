//! 多用户限速与按月流量配额 (v2)。
//!
//! 支持每个用户独立配置:
//! - `rate_limit_kbps`: 上行 + 下行限速 (该用户全部连接共享同一对令牌桶)。
//! - `quota_gb`: 月度流量配额 (上行+下行合计, 越额切断)。
//! - `quota_reset_day`: 账单日 1..=28 (默认 1, 按 UTC 计算周期起点)。
//!
//! 超额处理:
//! 1. 新连接握手时直接作为认证失败 (与 token 校验失败走同一条伪装站转发路径)。
//! 2. 活跃连接在跨过额度时立刻退出。

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicU8, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::info;

use super::rate_limit::DeviceBuckets;

/// 1 GB (GiB) = 1024 * 1024 * 1024 字节
pub const BYTES_PER_GB: f64 = 1024.0 * 1024.0 * 1024.0;

/// 将 GB 配额转为字节数
pub fn quota_gb_to_bytes(gb: f64) -> u64 {
    if !gb.is_finite() || gb <= 0.0 {
        0
    } else {
        (gb * BYTES_PER_GB).round() as u64
    }
}

/// 获取当前 UTC 时间戳 (秒)
pub fn current_unix_time() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

// ───────────────────────── 公历日历数学 (UTC) ─────────────────────────

/// 根据公历 (年, 月 1..=12, 日 1..=31) 计算自 1970-01-01 起的天数 (Howard Hinnant 算法)
pub fn days_from_civil(y: i64, m: u32, d: u32) -> i64 {
    let y = y - if m <= 2 { 1 } else { 0 };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = (y - era * 400) as u32;
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146097 + doe as i64 - 719468
}

/// 根据自 1970-01-01 起的天数计算公历 (年, 月 1..=12, 日 1..=31)
pub fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = (z - era * 146097) as u32;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = (yoe as i64) + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = y + if m <= 2 { 1 } else { 0 };
    (y, m, d)
}

/// 计算以 reset_day (1..=28) 为账单日、包含 now_secs (UTC unix timestamp) 的周期起点 (UTC unix timestamp).
pub fn compute_period_start(now_secs: u64, reset_day: u8) -> u64 {
    let reset_day = reset_day.clamp(1, 28) as u32;
    let days = (now_secs / 86400) as i64;
    let (y, m, d) = civil_from_days(days);
    let (start_y, start_m) = if d >= reset_day {
        (y, m)
    } else if m == 1 {
        (y - 1, 12)
    } else {
        (y, m - 1)
    };
    let start_days = days_from_civil(start_y, start_m, reset_day);
    (start_days as u64) * 86400
}

// ───────────────────────── 用户限速与配额句柄 ─────────────────────────

/// 单个用户的运行时限额与用量句柄 (跨该用户全部连接共享)。
///
/// **身份跨热重载保持不变**: 连接建立时拿到的是这个 Arc, 之后一直往它累加用量、查它的 exhausted。
/// 若热重载新建 handle, 在用连接的字节会记到被丢弃的旧 handle 上 (新 handle 看不到 → 长连接绕过配额),
/// 故限额字段都做成可原地更新 (`ArcSwapOption` / 原子量), 热重载只改字段不换 Arc (见 build_registry)。
pub struct UserLimitHandle {
    pub name: String,
    /// 可选限速桶对 (该用户所有连接共享); 热重载改速率时原地换桶。
    buckets: arc_swap::ArcSwapOption<DeviceBuckets>,
    /// 配额字节数, 0 = 不设限 (config 校验保证配额 > 0)。
    quota_bytes: AtomicU64,
    /// 账单重置日 (1..=28)
    reset_day: AtomicU8,
    /// 当前周期起点 (UTC unix 秒)
    pub period_start: AtomicU64,
    /// 本周期已用字节数 (上下行合计, 实时原子累加)
    pub period_used: AtomicU64,
    /// 是否已超额
    pub exhausted: AtomicBool,
}

impl UserLimitHandle {
    fn new(name: &str, buckets: Option<Arc<DeviceBuckets>>, quota: Option<u64>, reset_day: u8, period_start: u64, period_used: u64) -> Self {
        let h = Self {
            name: name.to_string(),
            buckets: arc_swap::ArcSwapOption::new(buckets),
            quota_bytes: AtomicU64::new(quota.unwrap_or(0)),
            reset_day: AtomicU8::new(reset_day),
            period_start: AtomicU64::new(period_start),
            period_used: AtomicU64::new(period_used),
            exhausted: AtomicBool::new(false),
        };
        h.reevaluate_exhausted();
        h
    }

    /// 当前限速桶 (热路径每块数据 load 一次, 无锁)。
    pub fn buckets(&self) -> Option<Arc<DeviceBuckets>> {
        self.buckets.load_full()
    }

    /// 配额字节数 (None = 不设限)。
    pub fn quota_bytes(&self) -> Option<u64> {
        match self.quota_bytes.load(Ordering::Relaxed) {
            0 => None,
            q => Some(q),
        }
    }

    /// 账单重置日 (1..=28)。
    pub fn reset_day(&self) -> u8 {
        self.reset_day.load(Ordering::Relaxed)
    }

    /// 按当前配额与用量重算 exhausted (限额被调高/取消时解除超额)。
    fn reevaluate_exhausted(&self) {
        let used = self.period_used.load(Ordering::Relaxed);
        let exh = self.quota_bytes().is_some_and(|q| used >= q);
        self.exhausted.store(exh, Ordering::SeqCst);
    }

    /// 实时累加用量; 若越过配额则置 exhausted=true 并返回 true (表示超额需中断连接)
    pub fn record_bytes(&self, n: usize) -> bool {
        if let Some(quota) = self.quota_bytes() {
            let prev = self.period_used.fetch_add(n as u64, Ordering::Relaxed);
            let current = prev.saturating_add(n as u64);
            if current >= quota {
                self.exhausted.store(true, Ordering::SeqCst);
                return true;
            }
        }
        self.exhausted.load(Ordering::Relaxed)
    }

    /// 查询该用户是否已超额
    pub fn is_exhausted(&self) -> bool {
        self.exhausted.load(Ordering::Relaxed)
    }
}

/// relay 每块数据的用户级门控 (TCP 直连 / SS·WG 上游中转 / QUIC lean 共用): 先扣用户限速桶
/// (`up` = 上行, 否则下行), 再计入本周期用量。返回 true = 已超额, 调用方应断开连接。
/// `user` 为 None (default 用户 / 未配限额) 时零开销直接放行。
pub async fn charge(user: Option<&UserLimitHandle>, n: usize, up: bool) -> bool {
    let Some(u) = user else { return false };
    if let Some(b) = u.buckets() {
        if up { b.up.consume(n).await } else { b.down.consume(n).await }
    }
    u.record_bytes(n)
}

// ───────────────────────── 持久化数据结构 ─────────────────────────

/// 周期配额状态持久化结构
#[derive(serde::Serialize, serde::Deserialize, Clone, Default, Debug, PartialEq, Eq)]
pub struct UserQuotaPersist {
    pub period_bytes: u64,
    pub period_start: u64,
}

// ───────────────────────── 注册表与全局状态 ─────────────────────────

pub struct UserLimitsRegistry {
    pub users: HashMap<String, Arc<UserLimitHandle>>,
}

static USER_LIMITS: OnceLock<arc_swap::ArcSwap<UserLimitsRegistry>> = OnceLock::new();
static RESTORED_QUOTAS: OnceLock<Mutex<HashMap<String, UserQuotaPersist>>> = OnceLock::new();

fn registry_slot() -> &'static arc_swap::ArcSwap<UserLimitsRegistry> {
    USER_LIMITS.get_or_init(|| {
        arc_swap::ArcSwap::from_pointee(UserLimitsRegistry {
            users: HashMap::new(),
        })
    })
}

fn restored_slot() -> &'static Mutex<HashMap<String, UserQuotaPersist>> {
    RESTORED_QUOTAS.get_or_init(|| Mutex::new(HashMap::new()))
}

/// 根据配置和可选旧状态构建 UserLimitsRegistry。
///
/// 热重载 (`old_registry` = Some) 时**复用同名用户的旧 handle** 并原地更新限额 —— 保证在用连接持有的
/// Arc 与注册表里的是同一个, 用量不丢、超额即断仍生效 (见 UserLimitHandle 文档)。
pub fn build_registry(
    users: &[crate::config::MirageUser],
    old_registry: Option<&UserLimitsRegistry>,
    now_secs: u64,
) -> UserLimitsRegistry {
    let mut map = HashMap::new();
    let restored = restored_slot().lock().unwrap_or_else(|e| e.into_inner());

    for u in users {
        if u.name == "default" {
            continue; // 保留名 default 不设限
        }
        let rate_bytes = u.rate_limit_kbps.filter(|&k| k > 0).map(|k| k.saturating_mul(125));
        let quota_bytes = u.quota_gb.filter(|&q| q.is_finite() && q > 0.0).map(quota_gb_to_bytes);
        let reset_day = u.quota_reset_day.unwrap_or(1).clamp(1, 28);
        let expected_start = compute_period_start(now_secs, reset_day);

        if let Some(old_h) = old_registry.and_then(|r| r.users.get(&u.name)) {
            // 限速: 速率没变就留原桶 (令牌状态连续), 变了才换; 取消限速则清空。
            let keep = matches!((old_h.buckets(), rate_bytes), (Some(b), Some(r)) if (b.up.rate as u64) == r);
            if !keep {
                old_h.buckets.store(rate_bytes.map(|r| Arc::new(DeviceBuckets::new(r))));
            }
            old_h.quota_bytes.store(quota_bytes.unwrap_or(0), Ordering::SeqCst);
            old_h.reset_day.store(reset_day, Ordering::SeqCst);
            // 账单日改动导致周期起点变化 → 按新周期从 0 计; 否则保留本周期用量。
            if old_h.period_start.load(Ordering::Relaxed) != expected_start {
                old_h.period_start.store(expected_start, Ordering::SeqCst);
                old_h.period_used.store(0, Ordering::SeqCst);
            }
            old_h.reevaluate_exhausted();
            map.insert(u.name.clone(), old_h.clone());
            continue;
        }

        // 新用户 (或启动): 若刚从持久化文件恢复过同周期用量则沿用。
        let period_used = match restored.get(&u.name) {
            Some(p) if p.period_start == expected_start => p.period_bytes,
            _ => 0,
        };
        let buckets = rate_bytes.map(|r| Arc::new(DeviceBuckets::new(r)));
        let handle = Arc::new(UserLimitHandle::new(&u.name, buckets, quota_bytes, reset_day, expected_start, period_used));
        map.insert(u.name.clone(), handle);
    }

    UserLimitsRegistry { users: map }
}

/// 初始化全局用户限制 (启动时调用)
pub fn init_user_limits(users: &[crate::config::MirageUser]) {
    let now = current_unix_time();
    let reg = build_registry(users, None, now);
    registry_slot().store(Arc::new(reg));
}

/// 配置热重载时更新用户限制 (保留已用流量)
pub fn reload_user_limits(users: &[crate::config::MirageUser]) {
    let now = current_unix_time();
    let old = registry_slot().load();
    let reg = build_registry(users, Some(&old), now);
    let count = reg.users.len();
    registry_slot().store(Arc::new(reg));
    info!("[USER_LIMITS] 热重载完成, 已更新 {} 位用户限速与配额", count);
}

/// 重置指定用户的本周期配额与超额状态 (不改 config)
pub fn reset_user_quota(name: &str) {
    let reg = registry_slot().load();
    if let Some(h) = reg.users.get(name) {
        h.period_used.store(0, Ordering::SeqCst);
        h.exhausted.store(false, Ordering::SeqCst);
        info!("[USER_LIMITS] 用户 `{}` 本周期配额已重置为 0", name);
    }
    let mut restored = restored_slot().lock().unwrap_or_else(|e| e.into_inner());
    if let Some(p) = restored.get_mut(name) {
        p.period_bytes = 0;
    }
}

/// 导出所有用户周期状态供持久化
pub fn export_persisted_quotas() -> HashMap<String, UserQuotaPersist> {
    let reg = registry_slot().load();
    let mut out = HashMap::new();
    for (name, handle) in &reg.users {
        out.insert(name.clone(), UserQuotaPersist {
            period_bytes: handle.period_used.load(Ordering::Relaxed),
            period_start: handle.period_start.load(Ordering::Relaxed),
        });
    }
    out
}

/// 从持久化文件恢复用户周期状态
pub fn restore_persisted_quotas(data: HashMap<String, UserQuotaPersist>) {
    let now = current_unix_time();
    let reg = registry_slot().load();
    for (name, p) in &data {
        if let Some(h) = reg.users.get(name) {
            let expected_start = compute_period_start(now, h.reset_day());
            if p.period_start == expected_start {
                h.period_start.store(p.period_start, Ordering::SeqCst);
                h.period_used.store(p.period_bytes, Ordering::SeqCst);
                h.reevaluate_exhausted();
            }
        }
    }
    let mut restored = restored_slot().lock().unwrap_or_else(|e| e.into_inner());
    *restored = data;
}

/// 周期滚动检查: 进入新周期则清零已用量与 exhausted
pub fn check_period_rollover() {
    let now = current_unix_time();
    let reg = registry_slot().load();
    for (name, h) in &reg.users {
        let expected_start = compute_period_start(now, h.reset_day());
        let cur_start = h.period_start.load(Ordering::Relaxed);
        if expected_start != cur_start {
            h.period_start.store(expected_start, Ordering::SeqCst);
            h.period_used.store(0, Ordering::SeqCst);
            h.exhausted.store(false, Ordering::SeqCst);
            info!("[USER_LIMITS] 用户 `{}` 滚动进入新配额周期 (起点 {}), 用量已清零", name, expected_start);
        }
    }
}

/// 启动每 10 分钟一次的配额周期滚动定时检查任务
pub fn start_rollover_task() {
    tokio::spawn(async {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(600));
        loop {
            interval.tick().await;
            check_period_rollover();
        }
    });
}

/// 获取指定用户的限速与配额句柄 (连接建立时查询一次)
pub fn get_user_limit(name: &str) -> Option<Arc<UserLimitHandle>> {
    registry_slot().load().users.get(name).cloned()
}

/// 判定指定用户当前是否已超额 (握手鉴权快速门控)
pub fn is_user_exhausted(name: &str) -> bool {
    if name == "default" {
        return false;
    }
    registry_slot().load().users.get(name).is_some_and(|h| h.is_exhausted())
}

/// 获取用户本周期统计 (供 API 查询): (已用字节, 周期起点, 是否超额)
pub fn get_user_period_stats(name: &str) -> (u64, u64, bool) {
    if let Some(h) = registry_slot().load().users.get(name) {
        (
            h.period_used.load(Ordering::Relaxed),
            h.period_start.load(Ordering::Relaxed),
            h.is_exhausted(),
        )
    } else {
        (0, 0, false)
    }
}

// ───────────────────────── 单元测试 ─────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::MirageUser;

    #[test]
    fn test_civil_calendar_conversions() {
        // 1970-01-01
        assert_eq!(days_from_civil(1970, 1, 1), 0);
        assert_eq!(civil_from_days(0), (1970, 1, 1));

        // 2026-09-26
        let days = days_from_civil(2026, 9, 26);
        assert_eq!(civil_from_days(days), (2026, 9, 26));

        // 闰年: 2024-02-29
        let leap_days = days_from_civil(2024, 2, 29);
        assert_eq!(civil_from_days(leap_days), (2024, 2, 29));
    }

    #[test]
    fn test_period_start_calculation() {
        // 2026-09-26 15:30:00 UTC (1790436600)
        let ts_2026_09_26 = days_from_civil(2026, 9, 26) as u64 * 86400 + 15 * 3600 + 1800;

        // reset_day = 1: 当月 1 号
        let start_1 = compute_period_start(ts_2026_09_26, 1);
        let expected_1 = days_from_civil(2026, 9, 1) as u64 * 86400;
        assert_eq!(start_1, expected_1);

        // reset_day = 26 (今天): 今天 0 点
        let start_26 = compute_period_start(ts_2026_09_26, 26);
        let expected_26 = days_from_civil(2026, 9, 26) as u64 * 86400;
        assert_eq!(start_26, expected_26);

        // reset_day = 28 (在今天之后): 上月 28 号 (2026-08-28)
        let start_28 = compute_period_start(ts_2026_09_26, 28);
        let expected_28 = days_from_civil(2026, 8, 28) as u64 * 86400;
        assert_eq!(start_28, expected_28);

        // 跨年测试: 2026-01-10, reset_day = 20 -> 2025-12-20
        let ts_2026_01_10 = days_from_civil(2026, 1, 10) as u64 * 86400;
        let start_jan = compute_period_start(ts_2026_01_10, 20);
        let expected_dec = days_from_civil(2025, 12, 20) as u64 * 86400;
        assert_eq!(start_jan, expected_dec);
    }

    /// 统一门控 charge(): 无句柄零开销放行; 有配额时跨过额度返回 true (调用方断开连接)。
    #[tokio::test]
    async fn charge_gate_passes_without_handle_and_trips_on_quota() {
        assert!(!charge(None, 1 << 30, true).await, "无句柄 (default/未设限) 必须放行");
        let h = UserLimitHandle::new("q", None, Some(1000), 1, 0, 0);
        assert!(!charge(Some(&h), 600, true).await);
        assert!(charge(Some(&h), 500, false).await, "上下行合计跨过 1000B 必须判超额");
        assert!(h.is_exhausted());
    }

    #[test]
    fn test_quota_accumulation_and_exhaustion() {
        let handle = UserLimitHandle::new("bob", None, Some(1000), 1, 100, 0);

        assert!(!handle.is_exhausted());
        // 第一次传 600B
        let over = handle.record_bytes(600);
        assert!(!over);
        assert!(!handle.is_exhausted());
        assert_eq!(handle.period_used.load(Ordering::Relaxed), 600);

        // 第二次传 500B (合计 1100B >= 1000B)
        let over = handle.record_bytes(500);
        assert!(over);
        assert!(handle.is_exhausted());
        assert_eq!(handle.period_used.load(Ordering::Relaxed), 1100);

        // 之后继续记录依然返回 true
        assert!(handle.record_bytes(50));
    }

    #[test]
    fn test_shared_buckets_for_same_user() {
        let user = MirageUser {
            name: "carol".to_string(),
            password: "pwd".to_string(),
            rate_limit_kbps: Some(500),
            quota_gb: Some(1.0),
            quota_reset_day: Some(1),
        };
        let reg = build_registry(&[user], None, 1790436600);
        let u1 = reg.users.get("carol").unwrap();
        let u2 = reg.users.get("carol").unwrap();
        assert!(Arc::ptr_eq(u1, u2));
        assert!(Arc::ptr_eq(
            &u1.buckets().unwrap(),
            &u2.buckets().unwrap()
        ));
    }

    #[test]
    fn test_hot_reload_preserves_usage_and_reevaluates_exhausted() {
        let user_v1 = MirageUser {
            name: "dave".to_string(),
            password: "pwd".to_string(),
            rate_limit_kbps: Some(500),
            quota_gb: Some(1.0), // 1 GB
            quota_reset_day: Some(1),
        };
        let now = 1790436600;
        let reg1 = build_registry(&[user_v1], None, now);
        let h1 = reg1.users.get("dave").unwrap();
        // 记录 1.5 GB 用量 (超额)
        let used_bytes = (1.5 * BYTES_PER_GB) as usize;
        assert!(h1.record_bytes(used_bytes));
        assert!(h1.is_exhausted());

        // 热重载: 管理员将 quota 调大为 2.0 GB
        let user_v2 = MirageUser {
            name: "dave".to_string(),
            password: "pwd".to_string(),
            rate_limit_kbps: Some(1000), // 顺便提速
            quota_gb: Some(2.0),
            quota_reset_day: Some(1),
        };
        let reg2 = build_registry(&[user_v2], Some(&reg1), now);
        let h2 = reg2.users.get("dave").unwrap();
        // 用量保留为 1.5 GB
        assert_eq!(h2.period_used.load(Ordering::Relaxed), used_bytes as u64);
        // 新配额为 2.0 GB, 不再超额!
        assert!(!h2.is_exhausted());
        // 身份保持: 热重载复用同一个 handle, 在用连接 (持 h1) 之后的字节必须记到注册表里的 handle 上,
        // 否则长连接可绕过配额 (旧实现新建 handle 的回归)。
        assert!(Arc::ptr_eq(h1, h2), "热重载必须复用同一 handle");
        assert!(h1.record_bytes((0.6 * BYTES_PER_GB) as usize), "在用连接跨过新配额 2GB 必须判超额");
        assert!(h2.is_exhausted(), "注册表中的 handle 看得到在用连接的用量");
        // 限速变了 → 桶原地换成新速率 (1000 kbps = 125000 B/s)
        assert_eq!(h2.buckets().unwrap().up.rate as u64, 125_000);
    }

    #[test]
    fn test_reset_user_quota() {
        let user = MirageUser {
            name: "eve".to_string(),
            password: "pwd".to_string(),
            rate_limit_kbps: None,
            quota_gb: Some(1.0),
            quota_reset_day: Some(1),
        };
        init_user_limits(&[user]);
        let h = get_user_limit("eve").unwrap();
        h.record_bytes((1.5 * BYTES_PER_GB) as usize);
        assert!(h.is_exhausted());

        reset_user_quota("eve");
        assert_eq!(h.period_used.load(Ordering::Relaxed), 0);
        assert!(!h.is_exhausted());
    }

    #[test]
    fn test_persisted_quota_roundtrip() {
        let user = MirageUser {
            name: "frank".to_string(),
            password: "pwd".to_string(),
            rate_limit_kbps: None,
            quota_gb: Some(10.0),
            quota_reset_day: Some(5),
        };
        init_user_limits(&[user]);
        let h = get_user_limit("frank").unwrap();
        h.record_bytes(4096);

        let exported = export_persisted_quotas();
        assert_eq!(exported.get("frank").unwrap().period_bytes, 4096);

        // 清空后再恢复
        h.period_used.store(0, Ordering::Relaxed);
        assert_eq!(h.period_used.load(Ordering::Relaxed), 0);

        restore_persisted_quotas(exported);
        assert_eq!(h.period_used.load(Ordering::Relaxed), 4096);
    }
}
