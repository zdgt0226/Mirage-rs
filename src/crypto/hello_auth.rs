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
    seen: Mutex<HashMap<u64, HashSet<Vec<u8>>>>,
}

impl TokenReplayCache {
    pub fn new() -> Self {
        Self {
            seen: Mutex::new(HashMap::new()),
        }
    }

    pub fn check_and_insert(&self, ts: u64, token: &[u8]) -> bool {
        let current_bucket = ts / REPLAY_BUCKET_SECS;
        let mut cache = self.seen.lock().unwrap();

        // 保留容忍窗口内的桶 (前后各 1 个 = 3 桶 × 10s = 30s 总窗口).
        // 配合 v0.4 协议内嵌时间同步, 内存占用比旧 5×60s=300s 大幅下降.
        cache.retain(|&k, _| (k as i64 - current_bucket as i64).abs() <= 1);

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
