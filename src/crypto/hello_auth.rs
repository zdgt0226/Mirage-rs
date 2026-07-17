use hmac::{Hmac, Mac};
use poly1305::{Poly1305, universal_hash::KeyInit};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::sync::{Mutex, OnceLock};

type HmacSha256 = Hmac<Sha256>;

fn ts_mask(password: &str, random_prefix: &[u8; 8]) -> [u8; 8] {
    let pw_key = Sha256::digest(password.as_bytes());
    let mut mac = HmacSha256::new_from_slice(&pw_key).expect("HMAC can take key of any size");
    mac.update(random_prefix);
    let result = mac.finalize().into_bytes();
    let mut mask = [0u8; 8];
    mask.copy_from_slice(&result[..8]);
    mask
}

fn poly1305_tag(password_bytes: &[u8], ts_bytes: &[u8; 8], random_prefix: &[u8; 8]) -> [u8; 16] {
    let mut hasher = Sha256::new();
    hasher.update(password_bytes);
    hasher.update(ts_bytes);
    hasher.update(random_prefix);
    let one_time_key = hasher.finalize();

    let poly = Poly1305::new(&one_time_key.into());
    let tag = poly.compute_unpadded(ts_bytes);
    let mut out = [0u8; 16];
    out.copy_from_slice(&tag);
    out
}

pub fn make_session_token(password: &str) -> [u8; 32] {
    let mut random_prefix = [0u8; 8];
    rand::fill(&mut random_prefix);
    
    let ts = crate::time_sync::now_sec();
    let ts_bytes = ts.to_be_bytes();
    
    let mask = ts_mask(password, &random_prefix);
    let mut hidden_ts = [0u8; 8];
    for i in 0..8 {
        hidden_ts[i] = ts_bytes[i] ^ mask[i];
    }
    
    let tag = poly1305_tag(password.as_bytes(), &ts_bytes, &random_prefix);
    
    let mut token = [0u8; 32];
    token[0..8].copy_from_slice(&random_prefix);
    token[8..16].copy_from_slice(&hidden_ts);
    token[16..32].copy_from_slice(&tag);
    token
}

/// Token 时间戳容忍窗口默认值 (秒). 服务端可经 config `auth_ts_tolerance_secs` 覆盖.
///
/// 为什么不能太小 (曾是 10s, 实测坑): 首次握手用的是客户端**未经 TIME_SYNC 校正**的裸
/// 系统时钟 (TIME_OFFSET 初始 0), 而 TIME_SYNC 帧只在 auth 成功后才下发 —— auth 卡在这个
/// 窗口上 → TIME_SYNC 永远 bootstrap 不了 → 时钟偏差 > 窗口的机器被永久锁死。auth 失败又
/// 必须转发伪装站 (不能回时间提示, 否则破坏抗探测), 所以这个窗口是首次握手唯一的容错。
/// 60s 容日常漂移; 更大的偏差应靠 NTP 压住 (且 NTP 不能走本代理, 否则死循环), 不靠拉宽窗口。
pub const DEFAULT_AUTH_TS_TOLERANCE_SECS: u64 = 60;

/// ReplayCache 桶大小 (秒). 保留桶数由容差自动推导 (见 verify_session_token), 二者始终一致.
const REPLAY_BUCKET_SECS: u64 = 10;

pub struct TokenReplayCache {
    /// (high-water-mark bucket, 各桶已见 token 集)。淘汰参考用**单调递增的 hwm**
    /// 而非当前 token 桶 —— 否则重放一个旧 token 会把参考拉回、"复活"已淘汰的桶,
    /// 使其 own 桶被当空桶重建 → 重放漏检 (F1)。hwm 只增不减, 保证淘汰单向前进。
    seen: Mutex<(u64, HashMap<u64, HashSet<Vec<u8>>>)>,
}

impl TokenReplayCache {
    pub fn new() -> Self {
        Self {
            seen: Mutex::new((0, HashMap::new())),
        }
    }

    /// retain_buckets: 保留最近多少个桶 (由容差推导, 见 verify_session_token)。必须覆盖
    /// 整个 ±容差窗口, 否则窗口内的旧 token 被过早淘汰 → 重放漏检。
    pub fn check_and_insert(&self, ts: u64, token: &[u8], retain_buckets: u64) -> bool {
        let current_bucket = ts / REPLAY_BUCKET_SECS;
        let mut guard = self.seen.lock().unwrap_or_else(|e| e.into_inner());
        let (hwm, cache) = &mut *guard;

        // hwm = 已见的最高桶 (单调)。ts 容忍窗口 ±tol + 桶量化 → 一个仍有效的 token 桶
        // 最低可到 hwm - 2*tol/bucket (未来向 token 可把 hwm 推到 now_bucket + tol/bucket)。
        // retain_buckets 已按此推导。参考用 hwm 而非 current_bucket, 旧 token 重放不会把
        // 参考拉回复活已淘汰桶。
        *hwm = (*hwm).max(current_bucket);
        let hwm_val = *hwm;
        cache.retain(|&k, _| hwm_val.saturating_sub(k) <= retain_buckets);

        let bucket = cache.entry(current_bucket).or_default();
        if bucket.len() > 100_000 {
            // v0.4.5-alpha.7: fail-closed. 老版满桶时 return true (放行) 是"避免误
            // 杀合法请求"取舍, 但攻击者可以 DDoS 拉满桶后无限重放合法 token, 让
            // 重放防护完全失效. 现在满桶 → return false (拒绝) → 桶满期间合法 token
            // 也会被误判重放, 但同时攻击者的重放也被拦, 保守安全大于可用性.
            // 100k 桶 = 60 秒内 10 万个不同 token, 正常业务达不到这个量级,
            // 只有 DDoS 才可能触发, 拒绝是对的.
            tracing::warn!("ReplayCache bucket saturated at {} entries, denying (fail-closed)", bucket.len());
            return false;
        }

        bucket.insert(token.to_vec())
    }
}

/// token 时间戳是否落在 ±tolerance 窗口内 (双向对称: 客户端可能快也可能慢)。
fn ts_within_tolerance(ts: u64, now: u64, tolerance_secs: u64) -> bool {
    now <= ts + tolerance_secs && ts <= now + tolerance_secs
}

static REPLAY_CACHE: OnceLock<TokenReplayCache> = OnceLock::new();

pub fn verify_session_token(password: &str, token: &[u8; 32], tolerance_secs: u64) -> bool {
    let mut random_prefix = [0u8; 8];
    random_prefix.copy_from_slice(&token[0..8]);
    
    let mut hidden_ts = [0u8; 8];
    hidden_ts.copy_from_slice(&token[8..16]);
    
    let mask = ts_mask(password, &random_prefix);
    let mut ts_bytes = [0u8; 8];
    for i in 0..8 {
        ts_bytes[i] = hidden_ts[i] ^ mask[i];
    }
    
    let expected_tag = poly1305_tag(password.as_bytes(), &ts_bytes, &random_prefix);
    let mut diff = 0u8;
    for i in 0..16 {
        diff |= expected_tag[i] ^ token[16 + i];
    }
    if diff != 0 {
        return false;
    }
    
    let ts = u64::from_be_bytes(ts_bytes);
    let now = crate::time_sync::now_sec();

    if !ts_within_tolerance(ts, now, tolerance_secs) {
        return false;
    }

    // 保留桶数覆盖整个 ±容差窗口: 最旧有效 token 桶 = (now-tol)/bucket, hwm 最高可被未来
    // 向 token 推到 (now+tol)/bucket → 需保留 2*tol/bucket 个桶, +2 余量抗桶边界量化。
    let retain_buckets = 2 * tolerance_secs / REPLAY_BUCKET_SECS + 2;
    let cache = REPLAY_CACHE.get_or_init(TokenReplayCache::new);
    if !cache.check_and_insert(ts, token, retain_buckets) {
        return false; // Replay detected
    }

    true
}

#[cfg(test)]
mod tolerance_tests {
    use super::ts_within_tolerance;

    #[test]
    fn within_and_beyond_window_both_directions() {
        let now = 1_000_000u64;
        let tol = 60;
        // 窗口内 (含边界)
        assert!(ts_within_tolerance(now, now, tol), "ts==now");
        assert!(ts_within_tolerance(now - 60, now, tol), "客户端慢 60s (边界)");
        assert!(ts_within_tolerance(now + 60, now, tol), "客户端快 60s (边界)");
        assert!(ts_within_tolerance(now - 59, now, tol));
        // 窗口外, 两个方向都要拒
        assert!(!ts_within_tolerance(now - 61, now, tol), "客户端慢 61s 应拒");
        assert!(!ts_within_tolerance(now + 61, now, tol), "客户端快 61s 应拒");
        // 更小的容差更严
        assert!(!ts_within_tolerance(now - 11, now, 10), "±10s: 慢 11s 应拒");
        assert!(ts_within_tolerance(now - 9, now, 10), "±10s: 慢 9s 应过");
    }
}

#[cfg(test)]
mod replay_tests {
    use super::TokenReplayCache;

    #[test]
    fn first_seen_ok_replay_denied() {
        let c = TokenReplayCache::new();
        assert!(c.check_and_insert(1000, b"tok-a", 2), "首见应放行");
        assert!(!c.check_and_insert(1000, b"tok-a", 2), "重放同 token 应拒绝");
        // 不同 token 同桶各自独立
        assert!(c.check_and_insert(1000, b"tok-b", 2));
    }

    #[test]
    fn replay_survives_advancing_buckets_f1() {
        // 回归 F1: token1(桶100) 存入后, 一个更高桶的 token 推进 hwm, 旧 token 重放
        // 仍须被检出 (旧实现会因桶被淘汰而漏检)。
        let c = TokenReplayCache::new();
        assert!(c.check_and_insert(1009, b"old", 2), "token1 首见");
        // ts=1020 → 桶 102, 把 hwm 推到 102 (旧代码此刻淘汰桶 100)
        assert!(c.check_and_insert(1020, b"mid", 2));
        // token1 重放: 现在必须仍被检出为重放
        assert!(
            !c.check_and_insert(1009, b"old", 2),
            "F1: 桶推进后旧 token 重放必须仍被检出"
        );
    }

    #[test]
    fn far_past_bucket_evicted() {
        // 超出 3 桶窗口的旧桶应被淘汰 (内存有界)。这类 token 早已被 ts 容忍窗口拒绝,
        // 淘汰后即便"重放"也无所谓 (ts 校验在 check_and_insert 之前已挡下)。
        let c = TokenReplayCache::new();
        assert!(c.check_and_insert(1000, b"ancient", 2)); // 桶 100
        // hwm 推到 130 (桶 130), 桶 100 早已 < hwm-2 被淘汰
        assert!(c.check_and_insert(1300, b"now", 2));
        // 桶 100 已淘汰, 这里返回 true 只是证明桶确实被清 (内存有界); 真实场景 ts 校验已挡
        assert!(c.check_and_insert(1000, b"ancient", 2));
    }
}
