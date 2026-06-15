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
        let current_bucket = ts / 60;
        let mut cache = self.seen.lock().unwrap();
        
        // Retain only buckets within 2 minutes of the inserted ts (total 5 buckets = 300s window)
        // Since ts is validated by the caller against time_sync, it accurately reflects true time.
        cache.retain(|&k, _| (k as i64 - current_bucket as i64).abs() <= 2);

        let bucket = cache.entry(current_bucket).or_default();
        if bucket.len() > 100_000 {
            // Bypass rather than fake positive replay if we are under DDoS
            tracing::warn!("ReplayCache bucket saturated at {} entries, bypassing replay protection!", bucket.len());
            return true;
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
    
    if now > ts + 60 || ts > now + 60 {
        return false;
    }
    
    let cache = REPLAY_CACHE.get_or_init(TokenReplayCache::new);
    if !cache.check_and_insert(ts, token) {
        return false; // Replay detected
    }
    
    true
}
