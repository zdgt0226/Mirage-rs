//! 看板 API 认证失败限流 (防 token 字典暴力猜解)。
//!
//! 按**客户端 IP** 计失败次数: 窗口内失败超阈 → 锁定该 IP 一段冷却期 (期间一律 429),
//! 成功认证清零。IP 来自 TCP 连接 (ConnectInfo), 不可伪造, 故 per-IP 无"伪造源把合法用户
//! 锁死"的 DoS 隐患。map 有容量上限, 满时清理过期条目防无界增长。
//!
//! token 本身已是常量时间比较 (见 `ct_eq`), 挡住时序侧信道; 本限流补上"字典/暴力面"。

use std::collections::HashMap;
use std::net::IpAddr;
use std::time::{Duration, Instant};

/// 窗口内允许的最大认证失败次数, 超过即锁定。
pub const MAX_FAILURES: u32 = 10;
/// 失败计数窗口: 超过此时长无新失败则计数重置。
pub const WINDOW: Duration = Duration::from_secs(60);
/// 锁定冷却期: 触发锁定后此时长内该 IP 一律拒绝。
pub const LOCKOUT: Duration = Duration::from_secs(300);
/// map 条目上限, 满时清理过期条目 (防恶意海量源 IP 撑爆内存)。
pub const MAP_CAP: usize = 10_000;

#[derive(Clone)]
struct FailRecord {
    fails: u32,
    /// 当前计数窗口起点 (首次失败或窗口重置时)。
    window_start: Instant,
    /// 锁定到期时刻; None = 未锁定。
    locked_until: Option<Instant>,
}

/// 认证失败限流状态表 (per-IP)。放进 AppState, 全局共享。
#[derive(Default)]
pub struct RateLimiter {
    map: HashMap<IpAddr, FailRecord>,
}

impl RateLimiter {
    pub fn new() -> Self {
        Self::default()
    }

    /// 认证**前**调用: 该 IP 当前是否处于锁定期。
    pub fn is_locked(&mut self, ip: IpAddr, now: Instant) -> bool {
        match self.map.get(&ip) {
            Some(r) => r.locked_until.is_some_and(|until| now < until),
            None => false,
        }
    }

    /// 认证**失败**后调用: 记一次失败; 窗口内累计超阈则设置锁定。
    pub fn note_failure(&mut self, ip: IpAddr, now: Instant) {
        // 插入新 IP 前若已到上限, 硬封顶: 先清过期, 仍满则淘汰窗口最旧的一条。
        if !self.map.contains_key(&ip) && self.map.len() >= MAP_CAP {
            self.evict(now);
        }
        let rec = self.map.entry(ip).or_insert(FailRecord {
            fails: 0,
            window_start: now,
            locked_until: None,
        });
        // 窗口过期 → 计数从头开始 (跨窗口的累计不叠加)。
        if now.duration_since(rec.window_start) > WINDOW {
            rec.fails = 0;
            rec.window_start = now;
            rec.locked_until = None;
        }
        rec.fails += 1;
        if rec.fails >= MAX_FAILURES {
            rec.locked_until = Some(now + LOCKOUT);
        }
    }

    /// 认证**成功**后调用: 清除该 IP 的失败记录。
    pub fn note_success(&mut self, ip: IpAddr) {
        self.map.remove(&ip);
    }

    /// 硬封顶: 先删所有已完全过期的条目 (锁定期与窗口都已过); 若仍达上限, 淘汰
    /// window_start 最旧的一条 (最可能已不活跃)。保证 map.len() 不超过 MAP_CAP。
    fn evict(&mut self, now: Instant) {
        self.map.retain(|_, r| {
            let lock_active = r.locked_until.is_some_and(|until| now < until);
            let window_active = now.duration_since(r.window_start) <= WINDOW;
            lock_active || window_active
        });
        while self.map.len() >= MAP_CAP {
            if let Some(oldest) = self
                .map
                .iter()
                .min_by_key(|(_, r)| r.window_start)
                .map(|(ip, _)| *ip)
            {
                self.map.remove(&oldest);
            } else {
                break;
            }
        }
    }

    /// 当前记录条目数 (测试/诊断用)。
    pub fn len(&self) -> usize {
        self.map.len()
    }

    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(n: u8) -> IpAddr {
        IpAddr::from([10, 0, 0, n])
    }

    #[test]
    fn under_threshold_not_locked() {
        let mut rl = RateLimiter::new();
        let t = Instant::now();
        for _ in 0..(MAX_FAILURES - 1) {
            rl.note_failure(ip(1), t);
        }
        assert!(!rl.is_locked(ip(1), t), "未到阈值不应锁定");
    }

    #[test]
    fn reaching_threshold_locks() {
        let mut rl = RateLimiter::new();
        let t = Instant::now();
        for _ in 0..MAX_FAILURES {
            rl.note_failure(ip(1), t);
        }
        assert!(rl.is_locked(ip(1), t), "达到阈值应锁定");
    }

    #[test]
    fn lockout_expires_after_cooldown() {
        let mut rl = RateLimiter::new();
        let t = Instant::now();
        for _ in 0..MAX_FAILURES {
            rl.note_failure(ip(1), t);
        }
        assert!(rl.is_locked(ip(1), t));
        // 冷却期后解锁
        let later = t + LOCKOUT + Duration::from_secs(1);
        assert!(!rl.is_locked(ip(1), later), "冷却期过应解锁");
    }

    #[test]
    fn success_resets_counter() {
        let mut rl = RateLimiter::new();
        let t = Instant::now();
        for _ in 0..(MAX_FAILURES - 1) {
            rl.note_failure(ip(1), t);
        }
        rl.note_success(ip(1));
        // 重置后再来一次失败不应锁定
        rl.note_failure(ip(1), t);
        assert!(!rl.is_locked(ip(1), t), "成功清零后单次失败不该锁定");
    }

    #[test]
    fn window_expiry_resets_before_locking() {
        let mut rl = RateLimiter::new();
        let t = Instant::now();
        // 差一次到阈值
        for _ in 0..(MAX_FAILURES - 1) {
            rl.note_failure(ip(1), t);
        }
        // 窗口过后再失败一次 → 计数应从窗口过期重置, 不触发锁定
        let later = t + WINDOW + Duration::from_secs(1);
        rl.note_failure(ip(1), later);
        assert!(!rl.is_locked(ip(1), later), "窗口过期后计数重置, 不应因累计跨窗口锁定");
    }

    #[test]
    fn independent_ips_dont_interfere() {
        let mut rl = RateLimiter::new();
        let t = Instant::now();
        for _ in 0..MAX_FAILURES {
            rl.note_failure(ip(1), t);
        }
        assert!(rl.is_locked(ip(1), t));
        assert!(!rl.is_locked(ip(2), t), "另一个 IP 不受牵连");
    }

    #[test]
    fn map_capacity_bounded_under_flood() {
        let mut rl = RateLimiter::new();
        let t = Instant::now();
        // 插入远超上限数量的**存活**不同源 IP (模拟大规模分布式暴力), 强制淘汰:
        // len 必须始终 <= MAP_CAP, 即便这些条目都没过期 (靠淘汰最旧, 非只清过期)。
        let total = MAP_CAP as u32 + 500;
        for i in 0..total {
            let o = i.to_be_bytes();
            rl.note_failure(IpAddr::from([o[0], o[1], o[2], o[3]]), t);
        }
        assert!(rl.len() <= MAP_CAP, "map 必须硬封顶 <= MAP_CAP (当前 {})", rl.len());
    }
}
