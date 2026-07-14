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

/// Token 时间戳容忍窗口 (秒). v0.4 协议有内嵌时间同步, 不再需要 60s 的宽容窗口.
/// ±10s 既能容忍 handshake 抖动 (RTT 几百毫秒), 又显著缩小重放攻击窗口.
const TOKEN_TS_TOLERANCE_SECS: u64 = 10;

/// ReplayCache 桶大小 (秒). 配合 TOKEN_TS_TOLERANCE_SECS 设置.
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

    pub fn check_and_insert(&self, ts: u64, token: &[u8]) -> bool {
        let current_bucket = ts / REPLAY_BUCKET_SECS;
        let mut guard = self.seen.lock().unwrap_or_else(|e| e.into_inner());
        let (hwm, cache) = &mut *guard;

        // hwm = 已见的最高桶 (单调)。ts 容忍窗口 ±10s + 桶量化 → 一个仍有效的 token
        // 桶最低可到 hwm-2 (未来向 token 可把 hwm 推到 now_bucket+1)。保留 hwm-2..hwm
        // 共 3 桶 (30s), 覆盖整个容忍窗口。参考用 hwm 而非 current_bucket, 旧 token 重放
        // 不会把参考拉回复活已淘汰桶。
        *hwm = (*hwm).max(current_bucket);
        let hwm_val = *hwm;
        cache.retain(|&k, _| hwm_val.saturating_sub(k) <= 2);

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

static REPLAY_CACHE: OnceLock<TokenReplayCache> = OnceLock::new();

pub fn verify_session_token(password: &str, token: &[u8; 32]) -> bool {
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

    if now > ts + TOKEN_TS_TOLERANCE_SECS || ts > now + TOKEN_TS_TOLERANCE_SECS {
        return false;
    }
    
    let cache = REPLAY_CACHE.get_or_init(TokenReplayCache::new);
    if !cache.check_and_insert(ts, token) {
        return false; // Replay detected
    }

    true
}

#[cfg(test)]
mod replay_tests {
    use super::TokenReplayCache;

    #[test]
    fn first_seen_ok_replay_denied() {
        let c = TokenReplayCache::new();
        assert!(c.check_and_insert(1000, b"tok-a"), "首见应放行");
        assert!(!c.check_and_insert(1000, b"tok-a"), "重放同 token 应拒绝");
        // 不同 token 同桶各自独立
        assert!(c.check_and_insert(1000, b"tok-b"));
    }

    #[test]
    fn replay_survives_advancing_buckets_f1() {
        // 回归 F1: token1(桶100) 存入后, 一个更高桶的 token 推进 hwm, 旧 token 重放
        // 仍须被检出 (旧实现会因桶被淘汰而漏检)。
        let c = TokenReplayCache::new();
        assert!(c.check_and_insert(1009, b"old"), "token1 首见");
        // ts=1020 → 桶 102, 把 hwm 推到 102 (旧代码此刻淘汰桶 100)
        assert!(c.check_and_insert(1020, b"mid"));
        // token1 重放: 现在必须仍被检出为重放
        assert!(
            !c.check_and_insert(1009, b"old"),
            "F1: 桶推进后旧 token 重放必须仍被检出"
        );
    }

    #[test]
    fn far_past_bucket_evicted() {
        // 超出 3 桶窗口的旧桶应被淘汰 (内存有界)。这类 token 早已被 ts 容忍窗口拒绝,
        // 淘汰后即便"重放"也无所谓 (ts 校验在 check_and_insert 之前已挡下)。
        let c = TokenReplayCache::new();
        assert!(c.check_and_insert(1000, b"ancient")); // 桶 100
        // hwm 推到 130 (桶 130), 桶 100 早已 < hwm-2 被淘汰
        assert!(c.check_and_insert(1300, b"now"));
        // 桶 100 已淘汰, 这里返回 true 只是证明桶确实被清 (内存有界); 真实场景 ts 校验已挡
        assert!(c.check_and_insert(1000, b"ancient"));
    }
}
