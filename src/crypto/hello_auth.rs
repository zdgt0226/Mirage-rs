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

/// Token v2 域分隔常量 (防跨版本差分碰撞)。
pub const TOKEN_DOMAIN: &[u8] = b"mirage-token-v2";

/// QUIC lean 每流认证绑定上下文 (与 TCP fake-TLS 的 client_random 域分隔)。
pub const QUIC_LEAN_BIND: &[u8] = b"mirage-quic-lean-v2";

fn poly1305_tag(
    password_bytes: &[u8],
    ts_bytes: &[u8; 8],
    random_prefix: &[u8; 8],
    bind: &[u8],
) -> [u8; 16] {
    let mut hasher = Sha256::new();
    hasher.update(password_bytes);
    hasher.update(ts_bytes);
    hasher.update(random_prefix);
    hasher.update(TOKEN_DOMAIN);
    let one_time_key = hasher.finalize();

    let poly = Poly1305::new(&one_time_key);
    let mut msg = Vec::with_capacity(8 + bind.len());
    msg.extend_from_slice(ts_bytes);
    msg.extend_from_slice(bind);
    let tag = poly.compute_unpadded(&msg);
    let mut out = [0u8; 16];
    out.copy_from_slice(&tag);
    out
}

pub fn make_session_token(password: &str, bind: &[u8]) -> [u8; 32] {
    let mut random_prefix = [0u8; 8];
    rand::fill(&mut random_prefix);
    
    let ts = crate::time_sync::now_sec();
    let ts_bytes = ts.to_be_bytes();
    
    let mask = ts_mask(password, &random_prefix);
    let mut hidden_ts = [0u8; 8];
    for i in 0..8 {
        hidden_ts[i] = ts_bytes[i] ^ mask[i];
    }
    
    let tag = poly1305_tag(password.as_bytes(), &ts_bytes, &random_prefix, bind);
    
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

/// (high-water-mark bucket, bucket → 该桶已见 token 集)。见 `TokenReplayCache::seen`。
type SeenBuckets = (u64, HashMap<u64, HashSet<Vec<u8>>>);

pub struct TokenReplayCache {
    /// 淘汰参考用**单调递增的 hwm** 而非当前 token 桶 —— 否则重放一个旧 token 会把参考拉回、
    /// "复活"已淘汰的桶, 使其 own 桶被当空桶重建 → 重放漏检 (F1)。hwm 只增不减, 保证淘汰单向前进。
    seen: Mutex<SeenBuckets>,
}

impl Default for TokenReplayCache {
    fn default() -> Self {
        Self::new()
    }
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

        // 检查时钟大幅回拨:
        // 若 current_bucket + retain_buckets < *hwm, 说明当前 token 的时间戳落后 hwm
        // 超过了整个保留窗口。
        //
        // 为什么清空安全:
        // 在回拨前已缓存的旧 token, 其 ts 相对新系统时间 now 落在未来, 且超出了容差范围 (> retain_buckets > tol)。
        // 任何对旧 token 的重放都会直接在 check_and_insert 前被 ts_within_tolerance 拦截,
        // 根本走不到此处, 故清空旧缓存不会引发历史 token 的重放漏洞。
        // 反之若不清空, 新时间的桶会被过时的未来 hwm 立即淘汰, 导致时钟追上 hwm 前重放全面失效。
        //
        // 为什么不破坏 F1 ("旧 token 重放不能把 hwm 拉回"):
        // 在调用本方法前, token 已通过 ts_within_tolerance(ts, now, tol) 门控, 合法 token 的 ts 必在 now ± tol 内。
        // 在时钟单调或正常容差波动下, hwm 最多比 current_bucket 领先 2*tol/bucket + 1 <= retain_buckets,
        // 因此单个旧 token (即使在容差边缘重放) 绝不会满足 current_bucket + retain_buckets < *hwm,
        // 只有服务器系统时间 now 本身发生超出保留窗口的大幅回拨时才会触发。
        if current_bucket.saturating_add(retain_buckets) < *hwm {
            tracing::warn!(
                "[REPLAY_CACHE] 检测到系统时钟大幅回拨: current_bucket={}, hwm={}, 重置缓存与 hwm",
                current_bucket,
                *hwm
            );
            cache.clear();
            *hwm = current_bucket;
        } else {
            *hwm = (*hwm).max(current_bucket);
        }
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

pub fn verify_session_token(
    password: &str,
    token: &[u8; 32],
    bind: &[u8],
    tolerance_secs: u64,
) -> bool {
    let mut random_prefix = [0u8; 8];
    random_prefix.copy_from_slice(&token[0..8]);
    
    let mut hidden_ts = [0u8; 8];
    hidden_ts.copy_from_slice(&token[8..16]);
    
    let mask = ts_mask(password, &random_prefix);
    let mut ts_bytes = [0u8; 8];
    for i in 0..8 {
        ts_bytes[i] = hidden_ts[i] ^ mask[i];
    }
    
    let expected_tag = poly1305_tag(password.as_bytes(), &ts_bytes, &random_prefix, bind);
    // 常量时间比 16B tag (握手 token 校验是真正的网络侧信道面)。用 subtle 而非手写累加器,
    // 带优化屏障, 与全仓 ct 比较统一。
    use subtle::ConstantTimeEq;
    if !bool::from(expected_tag[..].ct_eq(&token[16..32])) {
        return false;
    }
    
    let ts = u64::from_be_bytes(ts_bytes);
    // 服务端作为时间权威, 校验 token 必须用纯本地时钟 local_now_sec(),
    // 避免进程内作为客户端出站时学到的 TIME_OFFSET 污染服务端鉴权时间。
    let now = crate::time_sync::local_now_sec();

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

/// 多用户认证 (P1): 对一组 password 逐个试, 返回**首个 token tag 命中** (且 ts/replay 通过) 的索引。
///
/// 关键正确性: `verify_session_token` 内含 replay `check_and_insert`, 但**非匹配的 password 在
/// tag 常量时间比对处就返回 false, 根本走不到 replay 插入** —— 故本循环里 replay 对同一 token
/// **只在命中那次插一次**, 与单用户语义完全一致 (无双插、无跨凭据误报)。tag 由 poly1305(password_key,
/// ts, prefix, bind) 生成, 不同 password 命中同一 token 的概率 ~2^-128, 故至多一个凭据匹配。
/// O(N) HMAC/握手; 小团队 (几十用户) 可忽略。
pub fn identify_session_token(
    passwords: &[String],
    token: &[u8; 32],
    bind: &[u8],
    tolerance_secs: u64,
) -> Option<usize> {
    passwords.iter().position(|pw| verify_session_token(pw, token, bind, tolerance_secs))
}

/// 会话 bootstrap 加密帧 (客户端读 TIME_SYNC / 服务端读 first_chunk) 解密失败时的**统一排查
/// 提示**。两侧 (`pool` 客户端 + `control` 服务端) 共用同一文案, 避免诊断分散/漏项 (审计 #8)。
///
/// token 认证已过却解不开首个加密帧 = 会话密钥失配, 收敛为: 密码不一致 / 时钟超容差 (TIME_SYNC
/// 未 bootstrap) / 高级特征单边 (`pfs`/`tls_padding`/`cipher_agility` 一端开一端没开都改密钥或分帧
/// 派生)。返回 `&'static str` 便于两侧 `warn!` 复用, 且被测试锁住三项防未来漏删。
pub fn session_decrypt_failure_hint() -> &'static str {
    "bootstrap 加密帧读取失败 (解密失败或帧畸形)。最常见是**会话密钥失配**, 排查: \
     ①两端 password 是否完全一致; \
     ②系统时钟是否与对端相差超过容差 (默认 ±60s) —— 两端各跑 `date -u` 对一下, 并确认 NTP \
     正常且**不走本代理** (否则隧道挂→NTP不同步→时钟更偏 死循环); \
     ③两端高级特征是否一致: `pfs`/`tls_padding`/`cipher_agility` 一端开一端没开 (或版本过老不支持) \
     都会改会话密钥或分帧派生 → 必然失配 (见 README 安全声明 / tuning 各项注释)。若三项都排除, \
     可能是链路损坏或协议版本不匹配。"
}

#[cfg(test)]
mod multiuser_tests {
    use super::*;

    #[test]
    fn identify_matches_correct_user() {
        let pws = vec!["alice-pw".to_string(), "bob-pw".to_string(), "carol-pw".to_string()];
        let bind = [0x42u8; 32];
        // bob 的 token 必须只被 bob (index 1) 认出。
        let tok = make_session_token("bob-pw", &bind);
        assert_eq!(identify_session_token(&pws, &tok, &bind, 60), Some(1));
        // alice 的 token → index 0。
        let tok_a = make_session_token("alice-pw", &bind);
        assert_eq!(identify_session_token(&pws, &tok_a, &bind, 60), Some(0));
    }

    #[test]
    fn identify_none_when_no_credential_matches() {
        let pws = vec!["alice-pw".to_string(), "bob-pw".to_string()];
        let bind = [0x42u8; 32];
        let tok = make_session_token("stranger-pw", &bind); // 不在列表
        assert_eq!(identify_session_token(&pws, &tok, &bind, 60), None);
    }

    #[test]
    fn identify_replay_inserts_once_not_per_credential() {
        // 同一 token 连认两次: 第一次命中, 第二次因 replay 应 None (证明命中那次插了、且只插一次;
        // 非匹配凭据在 tag 比对处返回 false 不碰 replay, 故不会把别的用户的桶污染)。
        let pws = vec!["u0".to_string(), "u1".to_string(), "u2".to_string()];
        let bind = [0x55u8; 32];
        let tok = make_session_token("u2", &bind);
        assert_eq!(identify_session_token(&pws, &tok, &bind, 60), Some(2), "首次命中 u2");
        assert_eq!(identify_session_token(&pws, &tok, &bind, 60), None, "重放同 token 必拒 (replay 已插)");
    }
}

#[cfg(test)]
mod hint_tests {
    use super::session_decrypt_failure_hint;

    /// 锁住诊断三项都在, 防未来重构漏删某个排查方向 (审计 #8: 显式诊断不留静默失配)。
    #[test]
    fn hint_covers_all_three_mismatch_causes() {
        let h = session_decrypt_failure_hint();
        assert!(h.contains("password"), "诊断须提密码不一致");
        assert!(h.contains("时钟"), "诊断须提时钟容差");
        assert!(h.contains("pfs"), "诊断须提高级特征单边 (pfs 等)");
    }
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
    use super::*;

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

    #[test]
    fn clock_rollback_resets_cache_and_detects_replay() {
        let c = TokenReplayCache::new();
        // 初始在桶 200 (ts = 2000), retain = 2 桶
        assert!(c.check_and_insert(2000, b"future-tok", 2));

        // 时钟大幅回拨至桶 100 (ts = 1000): 100 + 2 < 200, 触发大幅回拨分支
        // 第一次插入新时代的 token: 应该放行 (清空旧缓存并重置 hwm 为 100)
        assert!(c.check_and_insert(1000, b"tok-after-rollback", 2));

        // 同一 token 在回拨后第二次插入: 必须检出为重放 (返回 false)!
        // (旧实现中因为 hwm 仍为 200, 桶 100 在插入后立即被 retain(<=200-2) 淘汰, 导致重放检测失效)
        assert!(
            !c.check_and_insert(1000, b"tok-after-rollback", 2),
            "回拨后同一 token 第二次插入必须被拒 (重放检测正常生效)"
        );
    }

    #[test]
    fn server_verification_unaffected_by_client_time_offset() {
        let _g = crate::time_sync::tests::TEST_LOCK.lock().unwrap();
        let _restore = crate::time_sync::tests::OffsetGuard;
        crate::time_sync::tests::reset_offset();

        let local = crate::time_sync::local_now_sec();
        // 模拟客户端出站学到了一个大的 offset (+500s)
        crate::time_sync::set_offset_from_server_time(local + 500);

        // 验证 local_now_sec() 依然是真实本地时间, 客户端 now_sec() 偏移了 500s
        // 可能跨秒边界, 容 1s; 关键是没被 +500 的 offset 带走。
        assert!(crate::time_sync::local_now_sec() - local <= 1);
        let diff = crate::time_sync::now_sec() as i64 - local as i64;
        assert!((498..=502).contains(&diff));

        // 构造一个基于服务端本地时间的合法 token (客户端时间正常的情况)
        let pw = "server-test-pw";
        let bind = [0x77u8; 32];
        let mut prefix = [0u8; 8];
        rand::fill(&mut prefix);
        let mask = ts_mask(pw, &prefix);
        let mut hidden_ts = [0u8; 8];
        let ts_bytes = local.to_be_bytes();
        for i in 0..8 {
            hidden_ts[i] = ts_bytes[i] ^ mask[i];
        }
        let tag = poly1305_tag(pw.as_bytes(), &ts_bytes, &prefix, &bind);
        let mut token = [0u8; 32];
        token[0..8].copy_from_slice(&prefix);
        token[8..16].copy_from_slice(&hidden_ts);
        token[16..32].copy_from_slice(&tag);

        // verify_session_token (服务端鉴权) 使用 local_now_sec, 容差 60s,
        // 即使 TIME_OFFSET 达到 500s, 基于服务端真实时间的 token 依然通过校验!
        assert!(verify_session_token(pw, &token, &bind, 60), "服务端校验必须不受客户端 offset 污染");
    }
}
