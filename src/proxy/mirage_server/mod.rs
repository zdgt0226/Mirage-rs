//! Mirage 服务端入站. 协议解密 + 上游 TCP/UDP 转发.
//!
//! 模块拓扑 (v0.4.2 重组):
//! - `mod.rs` 本文件: start_server + accept 循环 + UNAUTH 限流 (本模块共享状态)
//! - `handshake`: ClientHello 解析 + token 验证 + ServerHello 模拟 + fake tail (64B/80B)
//! - `camouflage`: auth 失败时伪装成正常 TLS 转发到真实站点 (反 GFW 探测)
//! - `control`: crypto channel 建立 + TIME_SYNC 帧 + first_chunk 接收 + TCP/UDP 分发
//! - `tcp_relay`: TCP 上游转发 (协议解密后)
//! - `udp_relay`: UDP 上游转发 (协议解密后)

mod handshake;
mod camouflage;
mod camouflage_rtt;
mod control;
mod tcp_relay;
pub(crate) mod udp_relay;

// 供隧道 DNS 目标头回归测试直接调服务端真解析 (dns::server 测试用)。
#[cfg(test)]
pub(crate) use control::parse_tcp_target;

// 服务端 ClientHello 计时/判定参数 (`tuning.client_hello_guard`): 由 startup 设置。
pub use handshake::{client_hello_guard_params, set_client_hello_guard};

use camouflage_rtt::CamouflageRtt;

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, LazyLock, Mutex, OnceLock};
use std::time::{Duration, Instant};
use tokio::net::TcpListener;
use tracing::{debug, error, info};

pub use std::sync::atomic::AtomicBool;

/// 凭据条目: 携带吊销令牌。改口令或删用户时, 旧条目的 `revoked` 置为 true,
/// 促使已建立的会话在下次数据块转发或状态检查时立即断开。
#[derive(Clone)]
pub struct CredEntry {
    pub name: String,
    pub password: String,
    pub revoked: Arc<AtomicBool>,
}

// 手写 Debug: 口令绝不能经 {:?} 进日志。
impl std::fmt::Debug for CredEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CredEntry")
            .field("name", &self.name)
            .field("password", &"<redacted>")
            .field("revoked", &self.revoked.load(Ordering::Relaxed))
            .finish()
    }
}

impl CredEntry {
    pub fn new(name: impl Into<String>, password: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            password: password.into(),
            revoked: Arc::new(AtomicBool::new(false)),
        }
    }
}

pub type CredsSnapshot = Arc<arc_swap::ArcSwap<Vec<CredEntry>>>;

/// 会话鉴权与吊销状态: 结合用户配额/限速句柄与凭据吊销令牌。
/// 在每次数据转发热路径上只产生极低的 Relaxed load 开销。
#[derive(Clone)]
pub struct SessionAuth {
    pub user_limit: Option<Arc<crate::proxy::user_limits::UserLimitHandle>>,
    pub cred_revoked: Arc<AtomicBool>,
}

impl std::fmt::Debug for SessionAuth {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SessionAuth")
            .field("user", &self.user_limit.as_ref().map(|u| &u.name))
            .field("cred_revoked", &self.cred_revoked.load(Ordering::Relaxed))
            .finish()
    }
}

impl SessionAuth {
    pub fn new(
        user_limit: Option<Arc<crate::proxy::user_limits::UserLimitHandle>>,
        cred_revoked: Arc<AtomicBool>,
    ) -> Self {
        Self {
            user_limit,
            cred_revoked,
        }
    }

    /// 测试/无吊销上下文时使用的快捷构造 (未设限且未吊销)
    pub fn unlimited() -> Self {
        Self {
            user_limit: None,
            cred_revoked: Arc::new(AtomicBool::new(false)),
        }
    }

    #[inline]
    pub fn should_stop(&self) -> bool {
        self.cred_revoked.load(Ordering::Relaxed)
            || self.user_limit.as_ref().is_some_and(|u| u.is_exhausted())
    }

    #[inline]
    pub async fn charge(&self, n: usize, up: bool) -> bool {
        if self.should_stop() {
            return true;
        }
        crate::proxy::user_limits::charge(self.user_limit.as_deref(), n, up).await
    }

    #[inline]
    pub fn record_bytes(&self, n: usize) -> bool {
        if self.should_stop() {
            return true;
        }
        if let Some(u) = &self.user_limit {
            u.record_bytes(n)
        } else {
            false
        }
    }
}

static CREDS_REGISTRY: LazyLock<Mutex<HashMap<String, CredsSnapshot>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

/// 构造凭据列表: [0] = ("default", 主密码), 其余 = users[].(name, password)
pub fn build_creds(password: &str, users: &[crate::config::MirageUser]) -> Vec<CredEntry> {
    let mut v = Vec::with_capacity(1 + users.len());
    v.push(CredEntry::new("default", password));
    v.extend(users.iter().map(|u| CredEntry::new(&u.name, &u.password)));
    v
}

/// 内部辅助: 比对新旧快照。同名同口令条目复用旧条目的 revoked 状态 Arc,
/// 旧快照中在新快照中不存在的条目置 revoked = true, 原地替换快照指针。
fn reconcile_and_swap_creds(target: &CredsSnapshot, mut new_creds: Vec<CredEntry>) {
    let old_snapshot = target.load_full();
    for new_entry in &mut new_creds {
        if let Some(old) = old_snapshot
            .iter()
            .find(|o| o.name == new_entry.name && o.password == new_entry.password)
        {
            new_entry.revoked = old.revoked.clone();
        }
    }
    for old in old_snapshot.iter() {
        if !new_creds
            .iter()
            .any(|n| n.name == old.name && n.password == old.password)
        {
            old.revoked.store(true, Ordering::Relaxed);
        }
    }
    target.store(Arc::new(new_creds));
}

/// 按入站 tag 注册 mirage_server 凭据快照。若已存在则原地 store 更新并返回现有 handle。
pub fn register_creds(tag: &str, initial: Vec<CredEntry>) -> CredsSnapshot {
    let mut map = CREDS_REGISTRY.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(existing) = map.get(tag) {
        reconcile_and_swap_creds(existing, initial);
        existing.clone()
    } else {
        let snapshot = Arc::new(arc_swap::ArcSwap::from_pointee(initial));
        map.insert(tag.to_string(), snapshot.clone());
        snapshot
    }
}

/// 热重载时按 tag 更新凭据快照。若 tag 尚未注册则跳过, 返回 false。
pub fn reload_creds(tag: &str, new_creds: Vec<CredEntry>) -> bool {
    let map = CREDS_REGISTRY.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(entry) = map.get(tag) {
        reconcile_and_swap_creds(entry, new_creds);
        true
    } else {
        false
    }
}

/// 获取当前已注册的所有 mirage_server 入站 tag。
pub fn registered_creds_tags() -> Vec<String> {
    let map = CREDS_REGISTRY.lock().unwrap_or_else(|e| e.into_inner());
    map.keys().cloned().collect()
}

pub(crate) const WARNED_EGRESS_CAPACITY: usize = 1024;

static WARNED_EGRESS: LazyLock<Mutex<HashMap<(String, String), Instant>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

/// 记录被阻断的出站访问 warn 日志, 10s 内同一 (user, target) 不重复刷屏。
pub fn warn_egress_blocked(proto: &str, user: &str, target: &str) {
    let now = Instant::now();
    let mut map = match WARNED_EGRESS.lock() {
        Ok(g) => g,
        Err(p) => p.into_inner(),
    };
    if let Some(last) = map.get(&(user.to_string(), target.to_string())) {
        if now.duration_since(*last) < Duration::from_secs(10) {
            return;
        }
    }
    if map.len() >= WARNED_EGRESS_CAPACITY {
        map.retain(|_, last| now.duration_since(*last) < Duration::from_secs(10));
        if map.len() >= WARNED_EGRESS_CAPACITY {
            map.clear();
        }
    }
    map.insert((user.to_string(), target.to_string()), now);
    tracing::warn!(
        "{}: 拒绝用户 `{}` 直连内网/元数据目标 `{}` (egress_allowed check failed)",
        proto,
        user,
        target
    );
}

// UNAUTH 限流 (整个 mirage_server 子模块共用). handshake.rs 在 auth 失败时
// 增 count, IpSlotGuard 在 drop 时回收.
pub(super) static UNAUTH_CONNS: OnceLock<Mutex<HashMap<IpAddr, usize>>> = OnceLock::new();
pub(super) static GLOBAL_UNAUTH: AtomicUsize = AtomicUsize::new(0);

pub(super) struct IpSlotGuard(pub(super) IpAddr);
impl Drop for IpSlotGuard {
    fn drop(&mut self) {
        GLOBAL_UNAUTH.fetch_sub(1, Ordering::SeqCst);
        // ⚠️ 决不在 Drop 里对锁 .unwrap(): 若此 drop 发生在 panic 栈展开中, 锁又
        // 恰好中毒 (持锁线程 panic 过), unwrap 二次 panic → double-panic abort
        // 当场杀进程. 用 into_inner 容忍中毒继续 —— 临界区只做 get_mut/
        // saturating_sub/remove, 数据结构不会被破坏到不可用. get() 而非
        // get_or_init: 能存在 Guard 说明插入侧已初始化过 map, 没有就没东西可减.
        if let Some(mutex) = UNAUTH_CONNS.get() {
            let mut map = match mutex.lock() {
                Ok(g) => g,
                Err(poisoned) => poisoned.into_inner(),
            };
            if let Some(c) = map.get_mut(&self.0) {
                *c = c.saturating_sub(1);
                if *c == 0 { map.remove(&self.0); }
            }
        }
    }
}

/// QUIC 未认证握手限流器: 防未认证 QUIC 握手 CPU DoS 攻击。
/// 在 accept 处按源 IP (IPv6 归一到 /64) 统计"握手中 + 未认证"并发数, 同时限制全局握手并发数。
#[derive(Debug)]
#[cfg_attr(not(feature = "quic"), allow(dead_code))]
pub(crate) struct QuicHandshakeLimiter {
    max_per_ip: usize,
    max_global: usize,
    soft_global: usize,
    global_count: AtomicUsize,
    /// 每 IP 计数按 (归一 IP, 源地址是否已验证) 分桶: 伪造源的未验证 Initial 只能占满未验证桶,
    /// 挤不掉真实客户端完成 Retry 验证后的名额 (否则冒充受害者 IP 发 32 包即可持续锁死该用户)。
    ip_counts: Mutex<HashMap<(IpAddr, bool), usize>>,
}

#[cfg_attr(not(feature = "quic"), allow(dead_code))]
impl QuicHandshakeLimiter {
    pub const DEFAULT_MAX_PER_IP: usize = 32;
    pub const DEFAULT_MAX_GLOBAL: usize = 2048;

    pub fn new(max_per_ip: usize, max_global: usize) -> Self {
        Self::new_with_soft(max_per_ip, max_global, max_global / 2)
    }

    pub fn new_with_soft(max_per_ip: usize, max_global: usize, soft_global: usize) -> Self {
        Self {
            max_per_ip,
            max_global,
            soft_global,
            global_count: AtomicUsize::new(0),
            ip_counts: Mutex::new(HashMap::new()),
        }
    }

    pub fn default_limits() -> Self {
        Self::new(Self::DEFAULT_MAX_PER_IP, Self::DEFAULT_MAX_GLOBAL)
    }

    pub fn max_per_ip(&self) -> usize {
        self.max_per_ip
    }

    pub fn max_global(&self) -> usize {
        self.max_global
    }

    #[cfg(test)]
    pub fn soft_global(&self) -> usize {
        self.soft_global
    }

    /// 查询在当前握手在途计数下, 目标 IP 或全局是否处于"有压力"状态。
    /// 当全局在途达到软阈值 (默认全局上限的一半) 或该 IP 的未验证桶已达每 IP 上限时返回 true,
    /// 触发对未经验证源地址的连接发送 QUIC Retry (地址所有权验证)。
    pub fn under_pressure(&self, ip: IpAddr) -> bool {
        if self.global_count.load(Ordering::SeqCst) >= self.soft_global {
            return true;
        }
        let norm_ip = handshake::rate_limit_key(ip);
        let map = match self.ip_counts.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };
        map.get(&(norm_ip, false)).copied().unwrap_or(0) >= self.max_per_ip
    }

    /// `validated`: 源地址是否已经 Retry 验证 (决定计入哪个每 IP 桶, 见 ip_counts)。
    pub fn try_acquire(self: &Arc<Self>, ip: IpAddr, validated: bool) -> Option<QuicHandshakeGuard> {
        let key = (handshake::rate_limit_key(ip), validated);
        let current_global = self.global_count.fetch_add(1, Ordering::SeqCst);
        if current_global >= self.max_global {
            self.global_count.fetch_sub(1, Ordering::SeqCst);
            return None;
        }

        let mut map = match self.ip_counts.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };
        let cur_ip = map.get(&key).copied().unwrap_or(0);
        if cur_ip >= self.max_per_ip {
            self.global_count.fetch_sub(1, Ordering::SeqCst);
            return None;
        }
        map.insert(key, cur_ip + 1);

        Some(QuicHandshakeGuard {
            limiter: self.clone(),
            key,
        })
    }

    #[cfg(test)]
    pub fn current_global(&self) -> usize {
        self.global_count.load(Ordering::SeqCst)
    }

    #[cfg(test)]
    pub fn current_for_ip(&self, ip: IpAddr) -> usize {
        let norm_ip = handshake::rate_limit_key(ip);
        let map = match self.ip_counts.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };
        map.get(&(norm_ip, false)).copied().unwrap_or(0) + map.get(&(norm_ip, true)).copied().unwrap_or(0)
    }

    fn release(&self, key: (IpAddr, bool)) {
        self.global_count.fetch_sub(1, Ordering::SeqCst);
        let mut map = match self.ip_counts.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };
        if let Some(c) = map.get_mut(&key) {
            *c = c.saturating_sub(1);
            if *c == 0 {
                map.remove(&key);
            }
        }
    }
}

#[cfg_attr(not(feature = "quic"), allow(dead_code))]
pub(crate) struct QuicHandshakeGuard {
    limiter: Arc<QuicHandshakeLimiter>,
    key: (IpAddr, bool),
}

impl Drop for QuicHandshakeGuard {
    fn drop(&mut self) {
        self.limiter.release(self.key);
    }
}

/// QUIC 活跃连接与双向流预算管理器: 覆盖"首流认证通过后"的整个连接与流生命周期。
/// - 连接预算: 限制每 IP (IPv6 归一到 /64) 与全局同时保持的活跃 QUIC 连接数;
/// - 流预算: 限制每 IP 与全局同时在途的双向流 task 数, 防止单连接开满 2048 流导致全局任务膨胀。
#[derive(Debug)]
#[cfg_attr(not(feature = "quic"), allow(dead_code))]
pub(crate) struct QuicRuntimeLimiter {
    max_conn_per_ip: usize,
    max_conn_global: usize,
    max_streams_per_ip: usize,
    max_streams_global: usize,
    conn_global: AtomicUsize,
    stream_global: AtomicUsize,
    conn_per_ip: Mutex<HashMap<IpAddr, usize>>,
    stream_per_ip: Mutex<HashMap<IpAddr, usize>>,
}

#[cfg_attr(not(feature = "quic"), allow(dead_code))]
impl QuicRuntimeLimiter {
    pub const DEFAULT_MAX_CONN_PER_IP: usize = 64;
    pub const DEFAULT_MAX_CONN_GLOBAL: usize = 4096;
    pub const DEFAULT_MAX_STREAMS_PER_IP: usize = 512;
    pub const DEFAULT_MAX_STREAMS_GLOBAL: usize = 16384;

    pub fn new(
        max_conn_per_ip: usize,
        max_conn_global: usize,
        max_streams_per_ip: usize,
        max_streams_global: usize,
    ) -> Self {
        Self {
            max_conn_per_ip,
            max_conn_global,
            max_streams_per_ip,
            max_streams_global,
            conn_global: AtomicUsize::new(0),
            stream_global: AtomicUsize::new(0),
            conn_per_ip: Mutex::new(HashMap::new()),
            stream_per_ip: Mutex::new(HashMap::new()),
        }
    }

    pub fn default_limits() -> Self {
        Self::new(
            Self::DEFAULT_MAX_CONN_PER_IP,
            Self::DEFAULT_MAX_CONN_GLOBAL,
            Self::DEFAULT_MAX_STREAMS_PER_IP,
            Self::DEFAULT_MAX_STREAMS_GLOBAL,
        )
    }

    pub fn try_acquire_conn(self: &Arc<Self>, ip: IpAddr) -> Option<QuicConnGuard> {
        let norm_ip = handshake::rate_limit_key(ip);
        let cur = self.conn_global.fetch_add(1, Ordering::SeqCst);
        if cur >= self.max_conn_global {
            self.conn_global.fetch_sub(1, Ordering::SeqCst);
            return None;
        }
        let mut map = match self.conn_per_ip.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };
        let cur_ip = map.get(&norm_ip).copied().unwrap_or(0);
        if cur_ip >= self.max_conn_per_ip {
            self.conn_global.fetch_sub(1, Ordering::SeqCst);
            return None;
        }
        map.insert(norm_ip, cur_ip + 1);
        Some(QuicConnGuard {
            limiter: self.clone(),
            norm_ip,
        })
    }

    pub fn try_acquire_stream(self: &Arc<Self>, ip: IpAddr) -> Option<QuicStreamGuard> {
        let norm_ip = handshake::rate_limit_key(ip);
        let cur = self.stream_global.fetch_add(1, Ordering::SeqCst);
        if cur >= self.max_streams_global {
            self.stream_global.fetch_sub(1, Ordering::SeqCst);
            return None;
        }
        let mut map = match self.stream_per_ip.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };
        let cur_ip = map.get(&norm_ip).copied().unwrap_or(0);
        if cur_ip >= self.max_streams_per_ip {
            self.stream_global.fetch_sub(1, Ordering::SeqCst);
            return None;
        }
        map.insert(norm_ip, cur_ip + 1);
        Some(QuicStreamGuard {
            limiter: self.clone(),
            norm_ip,
        })
    }

    fn release_conn(&self, norm_ip: IpAddr) {
        self.conn_global.fetch_sub(1, Ordering::SeqCst);
        let mut map = match self.conn_per_ip.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };
        if let Some(c) = map.get_mut(&norm_ip) {
            *c = c.saturating_sub(1);
            if *c == 0 {
                map.remove(&norm_ip);
            }
        }
    }

    fn release_stream(&self, norm_ip: IpAddr) {
        self.stream_global.fetch_sub(1, Ordering::SeqCst);
        let mut map = match self.stream_per_ip.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };
        if let Some(c) = map.get_mut(&norm_ip) {
            *c = c.saturating_sub(1);
            if *c == 0 {
                map.remove(&norm_ip);
            }
        }
    }

    #[cfg(test)]
    pub fn current_conn_global(&self) -> usize {
        self.conn_global.load(Ordering::SeqCst)
    }

    #[cfg(test)]
    pub fn current_conn_for_ip(&self, ip: IpAddr) -> usize {
        let norm_ip = handshake::rate_limit_key(ip);
        let map = match self.conn_per_ip.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };
        map.get(&norm_ip).copied().unwrap_or(0)
    }

    #[cfg(test)]
    pub fn current_stream_global(&self) -> usize {
        self.stream_global.load(Ordering::SeqCst)
    }

    #[cfg(test)]
    pub fn current_stream_for_ip(&self, ip: IpAddr) -> usize {
        let norm_ip = handshake::rate_limit_key(ip);
        let map = match self.stream_per_ip.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };
        map.get(&norm_ip).copied().unwrap_or(0)
    }
}

#[cfg_attr(not(feature = "quic"), allow(dead_code))]
pub(crate) struct QuicConnGuard {
    limiter: Arc<QuicRuntimeLimiter>,
    norm_ip: IpAddr,
}

impl Drop for QuicConnGuard {
    fn drop(&mut self) {
        self.limiter.release_conn(self.norm_ip);
    }
}

#[cfg_attr(not(feature = "quic"), allow(dead_code))]
pub(crate) struct QuicStreamGuard {
    limiter: Arc<QuicRuntimeLimiter>,
    norm_ip: IpAddr,
}

impl Drop for QuicStreamGuard {
    fn drop(&mut self) {
        self.limiter.release_stream(self.norm_ip);
    }
}

/// 把 `HandshakeCache` 最近一次向伪装站建连的耗时喂给 RTT 估计。
/// **零新增流量**: 预热 (启动) 与模板刷新 (每 30 分钟) 本来就会连一次伪装站。
fn seed_rtt_from_cache(cam_rtt: &Arc<CamouflageRtt>) {
    let us = crate::crypto::handshake_cache::last_connect_us();
    if us > 0 {
        cam_rtt.observe_connect(std::time::Duration::from_micros(us));
        debug!("camouflage RTT 播种/刷新: {}us (来自 HandshakeCache 建连)", us);
    }
}

pub async fn start_server(
    listen_addr: &str,
    // 凭据快照 (name, password): [0]=("default", 主密码), 其余=多用户 users。握手每次新连接 load() 最新快照。
    creds: CredsSnapshot,
    camouflage_host: &str,
    ebpf_engine: Option<Arc<tokio::sync::Mutex<crate::ebpf::EbpfEngine>>>,
    brutal_rate_bytes_per_sec: Option<u64>,
    auth_ts_tolerance_secs: u64,
    upstream: Option<std::sync::Arc<crate::proxy::upstream::UpstreamOutlet>>,
    pfs: bool,
    allow_local_targets: bool,
) {
    let listener = match TcpListener::bind(listen_addr).await {
        Ok(l) => l,
        Err(e) => {
            error!("Failed to bind Mirage Server on {}: {}", listen_addr, e);
            return;
        }
    };
    info!("Mirage Server listening on {} (auth 时钟容差 ±{}s)", listen_addr, auth_ts_tolerance_secs);

    // Brutal CC 必须在 listener 上预设算法名, 让 accept 出来的子 socket 从
    // SYN-ACK 起就是 brutal. 在已 ESTABLISHED 的 accepted socket 上中途切换
    // CC 会导致 kernel pacing 状态不一致, 实测吞吐塌方 (跟 Python POC 对比
    // 发现这个差异, 见 v0.4.4-alpha.8 CHANGELOG).
    if let Some(bps) = brutal_rate_bytes_per_sec {
        use std::os::unix::io::AsRawFd;
        crate::proxy::brutal::set_brutal_on_listener(listener.as_raw_fd());
        info!("Brutal CC enabled for downloads (server→client): {} Mbps", bps / 125_000);
    }

    // 伪装站 RTT 估计 (取代旧预热连接池, 见 camouflage_rtt.rs 与 docs/client-hello-timing-design.md)。
    // 转发路径改为"需要时才建连", 池龄恒 ≈ 0 → 真站 idle 计时起点与探测者连上的时刻只差一个
    // 服务器→伪装站 RTT, 消除旧池 8~14s 的关闭时间侧信道。
    let cam_rtt = CamouflageRtt::new();

    // E13 & R2: 伪装站 DNS 常青保活与握手模板预热并发执行 (tokio::join!).
    // R2 移除 F 播种后，"防解析耗时污染 EWMA" 的串行约束已不复存在；
    // 并发执行可将解析异常/网络抖动时的最差启动等待耗时从 2s + 5s 降至 max(2s, 5s)。
    tokio::join!(
        crate::proxy::resolver::keep_warm_dns(camouflage_host, 443),
        crate::crypto::handshake_cache::prewarm(camouflage_host),
    );

    // auth-succ 时序对齐 (`2 × cam_RTT` 注入) 的正样本来源。
    // ① 冷启动播种: prewarm 刚刚已经连过伪装站 (零新增流量), 拿它的 connect 耗时当 EWMA 初值 ——
    //    否则 "刚重启后合法用户秒回、最早几次探测却慢 2×RTT" 本身就是 T5 侧信道。
    // ② 过时防护: 同一个值在模板刷新 (30 分钟) 后重播一次, 避免少见探测的机器上初值长期不动。
    seed_rtt_from_cache(&cam_rtt);
    {
        let rtt = cam_rtt.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(std::time::Duration::from_secs(1800)).await;
                seed_rtt_from_cache(&rtt);
            }
        });
    }

    loop {
        match listener.accept().await {
            Ok((stream, peer_addr)) => {
                // 屏蔽名单 (WebUI 管理): 被屏蔽的客户端 IP 立即关连接, 省掉握手/BPF/brutal 全部开销。
                if crate::blocklist::is_blocked(&peer_addr.ip()) {
                    debug!("Mirage Server: 拒绝被屏蔽客户端 {}", peer_addr.ip());
                    drop(stream);
                    continue;
                }
                // 把客户端 IP 登记到 BPF mirage_target_ips 白名单, 让 sockops
                // RTT_CB 收集这条连接的 RTT/cwnd/重传 (没登记的连接 BPF 直接
                // return 0 不写 map). 用 try_lock 避免阻塞 accept 循环.
                if let Some(engine) = &ebpf_engine {
                    if let Ok(mut e) = engine.try_lock() {
                        let _ = e.set_target_ip(peer_addr.ip());
                    }
                }
                // accepted socket 已从 listener 继承 brutal 算法名, 只需补
                // 速率参数 (TCP_BRUTAL_PARAMS). brutal 的设计哲学就是"丢包
                // 是噪声, 死磕设定速率", 高 retrans 是 brutal 工作中的正常
                // 现象, 不是 brutal "不适合"的信号. alpha.6 加的 autofallback
                // 在 10s 内就因 retrans > 5% 把 brutal 切掉, 反而让 brutal
                // 没机会发挥, 实测速度低于 Python POC (POC 无 autofallback,
                // brutal 顶着丢包硬跑). spawn_fallback_monitor 代码保留在
                // brutal.rs, 留作未来 tuning.brutal_autofallback = true 的
                // opt-in 高级选项, 默认不调用.
                if let Some(rate) = brutal_rate_bytes_per_sec {
                    use std::os::unix::io::AsRawFd;
                    // tcp-brutal 2.0: 按 (客户端 IP, 速率) 分 group, 解决多入站串速率问题;
                    // 同速率入站仍共享一个总速率配额 (v1 模块自动回落 per-socket)。
                    let gid = crate::proxy::brutal::group_id_for(peer_addr.ip(), rate);
                    crate::proxy::brutal::set_brutal_rate(stream.as_raw_fd(), rate, gid);
                }

                // alpha.25 撤回 alpha.21 加的显式 SO_SNDBUF/SO_RCVBUF. 手动
                // 固定 8MB 反而 disable TCP auto-tune 拖垮吞吐 (7× 回归),
                // 让 kernel 自适应 BDP+丢包动态调节. 详见 tcp_relay.rs 注释.

                let creds_c = creds.clone();
                let cam = camouflage_host.to_string();
                let rtt = cam_rtt.clone();
                let up = upstream.clone();
                tokio::spawn(async move {
                    handshake::handle_connection(stream, peer_addr, creds_c, cam, rtt, auth_ts_tolerance_secs, up, pfs, allow_local_targets).await;
                });
            }
            Err(e) => {
                error!("Mirage Server accept error: {}", e);
            }
        }
    }
}

/// QUIC 服务端 (P0 实验, `--features quic`)。监听 UDP, 每条双向流当一条隧道, 复用 TCP 路径的
/// 握手/鉴权/中继逻辑 (经 handle_connection_quic → run_handshake 泛型)。brutal/eBPF sockops RTT
/// 是 TCP 内核特性, QUIC 不适用故不接。⚠️ 指纹不隐蔽, 见 docs/quic-transport-design.md。
#[cfg(feature = "quic")]
#[allow(clippy::too_many_arguments)]
pub async fn start_quic_server(
    listen_addr: &str,
    creds: CredsSnapshot,
    camouflage_host: &str,
    auth_ts_tolerance_secs: u64,
    upstream: Option<std::sync::Arc<crate::proxy::upstream::UpstreamOutlet>>,
    pfs: bool,
    quic_window_mb: u64,
    quic_cc: crate::proxy::quic::QuicCc,
    quic_obfs: Option<String>,
    quic_key_path: Option<&str>,
    allow_local_targets: bool,
) {
    let addr: std::net::SocketAddr = match listen_addr.parse() {
        Ok(a) => a,
        Err(e) => {
            error!("Mirage QUIC Server: listen 地址须为 IP:port ({}): {}", listen_addr, e);
            return;
        }
    };
    let endpoint = match crate::proxy::quic::server_endpoint(addr, quic_window_mb, quic_cc, quic_obfs.as_deref(), quic_key_path) {
        Ok(ep) => ep,
        Err(e) => {
            error!("Mirage QUIC Server: 绑定失败 {}: {:#}", listen_addr, e);
            return;
        }
    };
    info!("Mirage QUIC Server listening on {} (UDP, 实验传输 · auth 容差 ±{}s)", listen_addr, auth_ts_tolerance_secs);

    let _ = (camouflage_host, pfs); // Model X 精简: QUIC 路径不用 camouflage/fake-TLS/pfs

    let limiter = Arc::new(QuicHandshakeLimiter::default_limits());
    let runtime_limiter = Arc::new(QuicRuntimeLimiter::default_limits());

    while let Some(incoming) = endpoint.accept().await {
        let peer_addr = incoming.remote_address();
        let peer_ip = peer_addr.ip();

        // 1. 黑名单检查前置 (省下握手 CPU)
        if crate::blocklist::is_blocked(&peer_ip) {
            debug!("Mirage QUIC Server: 拒绝被屏蔽客户端 {peer_ip}");
            incoming.refuse();
            continue;
        }

        // 2. 抗 Initial 洪泛与伪造源地址:
        // 普通 HTTP/3 服务器极少恒常发 Retry (是可识别特征且增加 1 RTT)。
        // 仅在"有压力" (全局在途 ≥ 软阈值 或 该 IP 已达每 IP 上限) 时,
        // 若地址未经验证且支持 Retry, 则发 Retry 验证对端源地址所有权 (不占在途计数)。
        if !incoming.remote_address_validated()
            && limiter.under_pressure(peer_ip)
            && incoming.may_retry()
        {
            debug!("Mirage QUIC Server: 握手压力下要求地址验证 (Retry): {peer_ip}");
            if let Err(e) = incoming.retry() {
                debug!("Mirage QUIC Server: 发送 Retry 失败 ({peer_ip}): {e}");
            }
            continue;
        }

        // 3. 尝试获取未认证握手并发槽位 (硬上限检查: 覆盖至首条双向流完成 32B token 认证)
        let guard = match limiter.try_acquire(peer_ip, incoming.remote_address_validated()) {
            Some(g) => g,
            None => {
                debug!(
                    "Mirage QUIC Server: 握手/未认证并发超限 (每IP上限 {} 或全局上限 {}), 拒绝来自 {} 的连接",
                    limiter.max_per_ip(),
                    limiter.max_global(),
                    peer_ip
                );
                incoming.refuse();
                continue;
            }
        };

        let creds_c = creds.clone();
        let up = upstream.clone();
        let rt_limiter = runtime_limiter.clone();
        tokio::spawn(async move {
            let conn = match tokio::time::timeout(std::time::Duration::from_secs(10), incoming).await {
                Ok(Ok(c)) => c,
                _ => return, // QUIC 握手失败或超时 (10s), guard 在此 drop 释放槽位
            };

            let peer = conn.remote_address();
            let peer_ip = peer.ip();
            if crate::blocklist::is_blocked(&peer_ip) {
                debug!("Mirage QUIC Server: 拒绝被屏蔽客户端 {}", peer_ip);
                conn.close(quinn::VarInt::from_u32(0), b"");
                return;
            }
            if up.is_some() {
                debug!("Mirage QUIC(lean): 暂不支持上游中继, 拒绝 (改用 TCP 传输或 direct)");
                conn.close(quinn::VarInt::from_u32(0), b"");
                return;
            }

            // 状态门控 (Unauthenticated -> Authenticated):
            // 握手槽位 guard 保持到首条双向流在 5s 内完成 32B token 校验为止。
            // 首流认证前并发度=1, 任何超时、EOF 或认证失败立即关闭整条连接。
            let (mut first_send, mut first_recv) =
                match tokio::time::timeout(std::time::Duration::from_secs(5), conn.accept_bi()).await {
                    Ok(Ok(bi)) => bi,
                    _ => {
                        conn.close(quinn::VarInt::from_u32(0), b"");
                        return;
                    }
                };

            let fail_count = std::sync::Arc::new(std::sync::atomic::AtomicU32::new(0));
            let Some((first_user, first_session_auth)) = authenticate_quic_stream_token(
                &mut first_send,
                &mut first_recv,
                peer_ip,
                &creds_c,
                auth_ts_tolerance_secs,
                &conn,
                &fail_count,
                true,
            )
            .await
            else {
                conn.close(quinn::VarInt::from_u32(0), b"");
                return;
            };

            // 首流认证通过: 转移至已认证活跃连接预算与流预算, 随后释放未认证握手槽位 guard
            let Some(_conn_guard) = rt_limiter.try_acquire_conn(peer_ip) else {
                debug!("Mirage QUIC Server: 活跃连接预算超限, 关闭来自 {} 的连接", peer_ip);
                let _ = first_send.reset(quinn::VarInt::from_u32(0));
                let _ = first_recv.stop(quinn::VarInt::from_u32(0));
                conn.close(quinn::VarInt::from_u32(0), b"");
                return;
            };
            let Some(first_stream_guard) = rt_limiter.try_acquire_stream(peer_ip) else {
                debug!("Mirage QUIC Server: 活跃流预算超限, 关闭来自 {} 的首条流", peer_ip);
                let _ = first_send.reset(quinn::VarInt::from_u32(0));
                let _ = first_recv.stop(quinn::VarInt::from_u32(0));
                conn.close(quinn::VarInt::from_u32(0), b"");
                return;
            };
            drop(guard);

            tokio::spawn(async move {
                relay_authenticated_quic_stream(
                    first_send,
                    first_recv,
                    peer_ip,
                    first_user,
                    first_session_auth,
                    allow_local_targets,
                    first_stream_guard,
                )
                .await;
            });

            // 已认证连接主循环 (_conn_guard 随本循环生命周期保持):
            // 后续每条双向流仍需获取流预算守卫并逐流校验 32B token (保留热重载、吊销与多用户配额语义)。
            loop {
                match conn.accept_bi().await {
                    Ok((mut send, mut recv)) => {
                        let Some(stream_guard) = rt_limiter.try_acquire_stream(peer_ip) else {
                            debug!("Mirage QUIC Server: 活跃流预算超限, 拒绝来自 {} 的新流", peer_ip);
                            let _ = send.reset(quinn::VarInt::from_u32(0));
                            let _ = recv.stop(quinn::VarInt::from_u32(0));
                            continue;
                        };
                        let creds2 = creds_c.clone();
                        let up2 = up.clone();
                        let conn2 = conn.clone();
                        let fc = fail_count.clone();
                        tokio::spawn(async move {
                            handle_quic_stream_lean(
                                send,
                                recv,
                                peer_ip,
                                creds2,
                                auth_ts_tolerance_secs,
                                up2,
                                allow_local_targets,
                                conn2,
                                fc,
                                stream_guard,
                            )
                            .await;
                        });
                    }
                    Err(_) => break, // 连接关闭, _conn_guard 在此释放
                }
            }
        });
    }
}

/// 判定单流认证失败后是否达到关闭整条连接的阈值 (同一连接累计失败 >= 3 次)。
#[cfg(feature = "quic")]
pub(crate) fn record_stream_auth_failure(fail_count: &std::sync::atomic::AtomicU32) -> bool {
    fail_count.fetch_add(1, Ordering::SeqCst) + 1 >= 3
}

/// 读取并校验 QUIC 流首部 32B token。
/// - 超时、提前 EOF 或 HMAC 校验失败均使用通用重置码 `0` 重置流, 并计入连接 `fail_count`;
/// - 若 `is_first_stream` 为 true 或累计失败 >= 3 次, 立即关闭整条连接。
#[cfg(feature = "quic")]
#[allow(clippy::too_many_arguments)]
async fn authenticate_quic_stream_token(
    send: &mut quinn::SendStream,
    recv: &mut quinn::RecvStream,
    peer_ip: IpAddr,
    creds: &CredsSnapshot,
    tol: u64,
    conn: &quinn::Connection,
    fail_count: &std::sync::atomic::AtomicU32,
    is_first_stream: bool,
) -> Option<(String, SessionAuth)> {
    let mut token = [0u8; 32];
    match tokio::time::timeout(std::time::Duration::from_secs(5), recv.read_exact(&mut token)).await {
        Ok(Ok(_)) => {}
        _ => {
            let _ = send.reset(quinn::VarInt::from_u32(0));
            let _ = recv.stop(quinn::VarInt::from_u32(0));
            if is_first_stream || record_stream_auth_failure(fail_count) {
                conn.close(quinn::VarInt::from_u32(0), b"");
            }
            return None;
        }
    }
    let creds_snapshot = creds.load_full();
    let (user, cred_revoked) = match creds_snapshot.iter().position(|entry| {
        crate::crypto::hello_auth::verify_session_token(
            &entry.password,
            &token,
            crate::crypto::hello_auth::QUIC_LEAN_BIND,
            tol,
        )
    }) {
        Some(idx) => (
            creds_snapshot[idx].name.clone(),
            creds_snapshot[idx].revoked.clone(),
        ),
        None => {
            static HINTED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
            if !HINTED.swap(true, Ordering::Relaxed) {
                tracing::warn!(
                    "Mirage QUIC(lean): token 认证失败 from {} ({})",
                    peer_ip,
                    crate::crypto::hello_auth::session_decrypt_failure_hint()
                );
            } else {
                tracing::debug!("Mirage QUIC(lean): token 认证失败 from {}", peer_ip);
            }
            let _ = send.reset(quinn::VarInt::from_u32(0));
            let _ = recv.stop(quinn::VarInt::from_u32(0));
            if is_first_stream || record_stream_auth_failure(fail_count) {
                conn.close(quinn::VarInt::from_u32(0), b"");
            }
            return None;
        }
    };
    if cred_revoked.load(Ordering::Relaxed) {
        tracing::debug!("Mirage QUIC(lean): 凭据已吊销 from {}", peer_ip);
        let _ = send.reset(quinn::VarInt::from_u32(0));
        let _ = recv.stop(quinn::VarInt::from_u32(0));
        conn.close(quinn::VarInt::from_u32(0), b"");
        return None;
    }
    // 握手门控: 超额用户按认证失败处理 (首流立即关连接, 后续流累计达阈值关连接)
    if crate::proxy::user_limits::is_user_exhausted(&user) {
        tracing::warn!("Mirage QUIC(lean): user `{}` quota exhausted from {}", user, peer_ip);
        let _ = send.reset(quinn::VarInt::from_u32(0));
        let _ = recv.stop(quinn::VarInt::from_u32(0));
        if is_first_stream || record_stream_auth_failure(fail_count) {
            conn.close(quinn::VarInt::from_u32(0), b"");
        }
        return None;
    }
    // 分发前一次性取出用户限额句柄: 非 default 用户若取到 None (说明已被删除或不存在), 拒绝并断开整条连接。
    // 消除与后续 connect 之间的 TOCTOU 窗口。
    let user_limit = crate::proxy::user_limits::get_user_limit(&user);
    if user != "default" && user_limit.is_none() {
        tracing::debug!("Mirage QUIC(lean): 用户 `{}` 已被删除或不存在, 拒绝并断开连接", user);
        let _ = send.reset(quinn::VarInt::from_u32(0));
        let _ = recv.stop(quinn::VarInt::from_u32(0));
        conn.close(quinn::VarInt::from_u32(0), b"");
        return None;
    }
    Some((user, SessionAuth::new(user_limit, cred_revoked)))
}

/// Model X 精简 QUIC 流处理: `[token(32B)][2B target_len][target][data...]`, 无 per-stream fake-TLS、
/// 无内层 AEAD (QUIC 自己的 TLS1.3 已加密所有流)。token 为无状态每流认证 (HMAC 密码+时间, 32B 无往返)。
/// 直连出口 (upstream=SS/WG 的 lean 路径暂不支持, 有则拒)。
#[cfg(feature = "quic")]
#[allow(clippy::too_many_arguments)]
async fn handle_quic_stream_lean(
    mut send: quinn::SendStream,
    mut recv: quinn::RecvStream,
    peer_ip: IpAddr,
    creds: CredsSnapshot,
    tol: u64,
    upstream: Option<std::sync::Arc<crate::proxy::upstream::UpstreamOutlet>>,
    allow_local_targets: bool,
    conn: quinn::Connection,
    fail_count: Arc<std::sync::atomic::AtomicU32>,
    stream_guard: QuicStreamGuard,
) {
    if upstream.is_some() {
        debug!("Mirage QUIC(lean): 暂不支持上游中继, 拒绝 (改用 TCP 传输或 direct)");
        return;
    }
    let Some((user, session_auth)) = authenticate_quic_stream_token(
        &mut send,
        &mut recv,
        peer_ip,
        &creds,
        tol,
        &conn,
        &fail_count,
        false,
    )
    .await
    else {
        return;
    };
    relay_authenticated_quic_stream(
        send,
        recv,
        peer_ip,
        user,
        session_auth,
        allow_local_targets,
        stream_guard,
    )
    .await;
}

/// 已完成 32B token 校验的 QUIC 流后续处理: 读取 `[2B len][target]` 并建立双向直连转发 (`_stream_guard` 随流生命周期释放)。
#[cfg(feature = "quic")]
async fn relay_authenticated_quic_stream(
    send: quinn::SendStream,
    mut recv: quinn::RecvStream,
    peer_ip: IpAddr,
    user: String,
    session_auth: SessionAuth,
    allow_local_targets: bool,
    _stream_guard: QuicStreamGuard,
) {
    // 2. target: [2B len][host:port]
    let mut lenb = [0u8; 2];
    if tokio::time::timeout(std::time::Duration::from_secs(10), recv.read_exact(&mut lenb)).await.map(|r| r.is_err()).unwrap_or(true) {
        return;
    }
    let n = u16::from_be_bytes(lenb) as usize;
    if n == 0 || n > 512 { return; }
    let mut tb = vec![0u8; n];
    if tokio::time::timeout(std::time::Duration::from_secs(10), recv.read_exact(&mut tb)).await.map(|r| r.is_err()).unwrap_or(true) {
        return;
    }
    let target = match String::from_utf8(tb) {
        Ok(t) => t,
        Err(_) => return,
    };
    // 3. 直连出口 (带 SSRF 过滤)
    let up = match crate::proxy::resolver::connect_smart_filtered(&target, |ip| {
        crate::net_util::egress_allowed(ip, allow_local_targets)
    }).await {
        Ok(s) => s,
        Err(e) => {
            if e.kind() == std::io::ErrorKind::PermissionDenied {
                warn_egress_blocked("Mirage QUIC(lean)", &user, &target);
            } else {
                tracing::warn!("Mirage QUIC(lean): 连 {} 失败: {}", target, e);
            }
            return;
        }
    };
    let _conn = crate::monitor::register(
        target.clone(), peer_ip.to_string(), "direct".to_string(), "quic", None, Some(peer_ip.to_string()), Some(user.clone()),
    );
    // 4. 转发 (限速 + 配额计数)
    let (q_read, q_write) = tokio::io::split(crate::proxy::quic::QuicBiStream::new(send, recv));
    let (up_read, up_write) = up.into_split();

    let dev_buckets = crate::proxy::rate_limit::server_buckets_for(peer_ip);
    // 用户级限速与配额已在分发时获取 (session_auth)

    // 半关闭语义同原 copy_bidirectional: 一侧 EOF 只关对端写方向 (传 FIN), 另一方向继续传完;
    // 只有出错、用户超额或凭据吊销才发 stop 让两个方向都立刻退出。
    let (stop_tx, stop_rx) = tokio::sync::watch::channel(false);
    let t0 = tokio::time::Instant::now();
    let last_active = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));
    tokio::join!(
        quic_pump(q_read, up_write, dev_buckets.clone(), session_auth.clone(), true, stop_tx.clone(), stop_rx.clone(), t0, last_active.clone()),
        quic_pump(up_read, q_write, dev_buckets, session_auth, false, stop_tx, stop_rx, t0, last_active),
    );
}

pub(crate) const REVOKE_CHECK_INTERVAL: std::time::Duration = std::time::Duration::from_secs(10);

/// QUIC lean 单向泵: 带客户端 IP 桶 + 用户桶限速与配额计数 (`up` = 客户端→目标)。
/// - EOF: `shutdown` 对端写方向后返回, **不打断另一方向** (半关闭, 否则客户端先关写时目标的响应会被丢)。
/// - 读写出错 / 用户超额 / 凭据吊销 / 双向总空闲达 `relay_idle`: 发 stop, 另一方向随之退出。
#[cfg(feature = "quic")]
#[allow(clippy::too_many_arguments)]
async fn quic_pump<R, W>(
    mut r: R,
    mut w: W,
    ip: Option<std::sync::Arc<crate::proxy::rate_limit::DeviceBuckets>>,
    auth: SessionAuth,
    up: bool,
    stop_tx: tokio::sync::watch::Sender<bool>,
    mut stop_rx: tokio::sync::watch::Receiver<bool>,
    t0: tokio::time::Instant,
    last_active: std::sync::Arc<std::sync::atomic::AtomicU64>,
) where
    R: tokio::io::AsyncRead + Unpin,
    W: tokio::io::AsyncWrite + Unpin,
{
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut buf = vec![0u8; 32768];
    loop {
        if auth.should_stop() {
            let _ = stop_tx.send(true);
            return;
        }
        let n = tokio::select! {
            biased;
            _ = stop_rx.changed() => return,
            res = r.read(&mut buf) => match res {
                Ok(n) => n,
                Err(_) => {
                    let _ = stop_tx.send(true);
                    return;
                }
            },
            // 周期唤醒检查 auth.should_stop() 与双向总空闲超时:
            // 只要任一方向有数据流动 (如单向长下载), last_active 持续刷新不会误断;
            // 两个方向均静默达 relay_idle 时发 stop 回收孤儿流。
            _ = tokio::time::sleep(REVOKE_CHECK_INTERVAL) => {
                let now_secs = t0.elapsed().as_secs();
                let idle_secs = now_secs.saturating_sub(last_active.load(Ordering::Relaxed));
                if idle_secs >= crate::proxy::relay_idle().as_secs() {
                    let _ = stop_tx.send(true);
                    return;
                }
                continue;
            }
        };
        if n == 0 {
            let _ = w.shutdown().await; // EOF → 半关闭
            return;
        }
        last_active.store(t0.elapsed().as_secs(), Ordering::Relaxed);
        if let Some(b) = &ip {
            if up { b.up.consume(n).await } else { b.down.consume(n).await }
        }
        if auth.charge(n, up).await
            || w.write_all(&buf[..n]).await.is_err()
        {
            let _ = stop_tx.send(true); // 超额、凭据吊销或写失败 → 两个方向都断
            return;
        }
    }
}

#[cfg(test)]
mod quic_limiter_tests {
    use super::*;
    use std::net::IpAddr;

    #[test]
    fn test_quic_limiter_per_ip_limit_and_release() {
        let limiter = Arc::new(QuicHandshakeLimiter::new(2, 10));
        let ip: IpAddr = "192.0.2.1".parse().unwrap();

        let g1 = limiter.try_acquire(ip, false);
        assert!(g1.is_some());
        assert_eq!(limiter.current_for_ip(ip), 1);
        assert_eq!(limiter.current_global(), 1);

        let g2 = limiter.try_acquire(ip, false);
        assert!(g2.is_some());
        assert_eq!(limiter.current_for_ip(ip), 2);
        assert_eq!(limiter.current_global(), 2);

        // 超出每 IP 上限 (2)
        let g3 = limiter.try_acquire(ip, false);
        assert!(g3.is_none());
        assert_eq!(limiter.current_for_ip(ip), 2);
        assert_eq!(limiter.current_global(), 2);

        // drop g1 释放 1 个槽位
        drop(g1);
        assert_eq!(limiter.current_for_ip(ip), 1);
        assert_eq!(limiter.current_global(), 1);

        // 重新获取成功
        let g4 = limiter.try_acquire(ip, false);
        assert!(g4.is_some());
        assert_eq!(limiter.current_for_ip(ip), 2);
        assert_eq!(limiter.current_global(), 2);

        drop(g2);
        drop(g4);
        assert_eq!(limiter.current_for_ip(ip), 0);
        assert_eq!(limiter.current_global(), 0);
    }

    #[test]
    fn test_quic_limiter_ipv6_64_shared_limit() {
        let limiter = Arc::new(QuicHandshakeLimiter::new(2, 10));
        let ip1: IpAddr = "2001:db8::1".parse().unwrap();
        let ip2: IpAddr = "2001:db8::dead:beef".parse().unwrap();

        let g1 = limiter.try_acquire(ip1, false);
        assert!(g1.is_some());

        let g2 = limiter.try_acquire(ip2, false);
        assert!(g2.is_some());

        // 同 /64 第三个连接被拒
        let ip3: IpAddr = "2001:db8::cafe".parse().unwrap();
        let g3 = limiter.try_acquire(ip3, false);
        assert!(g3.is_none());

        drop(g1);
        let g4 = limiter.try_acquire(ip3, false);
        assert!(g4.is_some());
    }

    #[test]
    fn test_quic_limiter_global_limit() {
        let limiter = Arc::new(QuicHandshakeLimiter::new(10, 3));
        let ip1: IpAddr = "192.0.2.1".parse().unwrap();
        let ip2: IpAddr = "192.0.2.2".parse().unwrap();
        let ip3: IpAddr = "192.0.2.3".parse().unwrap();
        let ip4: IpAddr = "192.0.2.4".parse().unwrap();

        let g1 = limiter.try_acquire(ip1, false);
        let g2 = limiter.try_acquire(ip2, false);
        let g3 = limiter.try_acquire(ip3, false);
        assert!(g1.is_some() && g2.is_some() && g3.is_some());
        assert_eq!(limiter.current_global(), 3);

        // 全局达到 3, 不同 IP 也被拒
        let g4 = limiter.try_acquire(ip4, false);
        assert!(g4.is_none());
        assert_eq!(limiter.current_global(), 3);

        drop(g1);
        assert_eq!(limiter.current_global(), 2);
        let g5 = limiter.try_acquire(ip4, false);
        assert!(g5.is_some());
        assert_eq!(limiter.current_global(), 3);
    }

    /// 冒充受害者 IP 的伪造 Initial (未验证) 占满该 IP 的未验证桶后, 受害者完成 Retry 验证
    /// 的连接仍能拿到名额 —— 否则攻击者每 10s 补 32 个包即可持续把该用户锁在门外。
    #[test]
    fn test_quic_limiter_spoofed_unvalidated_cannot_lock_out_validated() {
        let limiter = Arc::new(QuicHandshakeLimiter::new(2, 10));
        let victim: IpAddr = "192.0.2.9".parse().unwrap();
        let _s1 = limiter.try_acquire(victim, false).unwrap();
        let _s2 = limiter.try_acquire(victim, false).unwrap();
        assert!(limiter.try_acquire(victim, false).is_none(), "未验证桶已满");
        assert!(limiter.under_pressure(victim), "未验证桶满 → 新的未验证 Initial 应被要求 Retry");
        assert!(limiter.try_acquire(victim, true).is_some(), "已验证连接不受伪造占满的未验证桶影响");
    }

    #[test]
    fn test_quic_limiter_under_pressure() {
        // 每 IP 上限 2, 全局上限 10, 软阈值 5
        let limiter = Arc::new(QuicHandshakeLimiter::new_with_soft(2, 10, 5));
        assert_eq!(limiter.soft_global(), 5);
        let ip1: IpAddr = "192.0.2.1".parse().unwrap();
        let ip2: IpAddr = "192.0.2.2".parse().unwrap();

        // 初始无压力
        assert!(!limiter.under_pressure(ip1));
        assert!(!limiter.under_pressure(ip2));

        // ip1 占用 1 个槽位, 未达每 IP 上限 (2), 全局为 1 (< 5)
        let _g1 = limiter.try_acquire(ip1, false).unwrap();
        assert!(!limiter.under_pressure(ip1));

        // ip1 占用第 2 个槽位, 达到每 IP 上限 (2)
        let g2 = limiter.try_acquire(ip1, false).unwrap();
        assert!(limiter.under_pressure(ip1), "IP 达到上限时应处于 under_pressure");
        // ip2 此时未达到上限, 全局在途 2 (< 5), 故无压力
        assert!(!limiter.under_pressure(ip2));

        // 释放 ip1 的 1 个槽位, 恢复无压力
        drop(g2);
        assert!(!limiter.under_pressure(ip1));

        // 测试全局软阈值: 全局到达 5 时, 任何新 IP 即使自身连接为 0 也被判定为 under_pressure
        let _g2 = limiter.try_acquire(ip1, false).unwrap(); // 全局 2
        let _g3 = limiter.try_acquire(ip2, false).unwrap(); // 全局 3
        let ip3: IpAddr = "192.0.2.3".parse().unwrap();
        let _g4 = limiter.try_acquire(ip3, false).unwrap(); // 全局 4
        let ip4: IpAddr = "192.0.2.4".parse().unwrap();
        let g5 = limiter.try_acquire(ip4, false).unwrap(); // 全局 5 (达到 soft_global)

        let ip_new: IpAddr = "192.0.2.100".parse().unwrap();
        assert!(limiter.under_pressure(ip_new), "全局达到软阈值时所有 IP 均应处于 under_pressure");

        // 释放 1 个槽位, 全局回到 4 (< 5), ip_new 恢复无压力
        drop(g5);
        assert!(!limiter.under_pressure(ip_new));

        // 测试 IPv6 /64 前缀归一化下的压力判断
        let v6_1: IpAddr = "2001:db8::1".parse().unwrap();
        let v6_2: IpAddr = "2001:db8::2".parse().unwrap();
        let v6_3: IpAddr = "2001:db8::3".parse().unwrap();
        let _gv1 = limiter.try_acquire(v6_1, false).unwrap();
        let _gv2 = limiter.try_acquire(v6_2, false).unwrap();
        assert!(limiter.under_pressure(v6_3), "同 /64 的 IPv6 达到上限应被判定为 under_pressure");
    }

    #[test]
    fn test_warned_egress_capacity_bounded() {
        for i in 0..(WARNED_EGRESS_CAPACITY + 10) {
            warn_egress_blocked("test", "alice", &format!("10.0.0.{}:80", i));
        }
        let map = WARNED_EGRESS.lock().unwrap_or_else(|e| e.into_inner());
        assert!(
            map.len() <= WARNED_EGRESS_CAPACITY,
            "warned_egress 表大小 {} 超过上限 {}",
            map.len(),
            WARNED_EGRESS_CAPACITY
        );
    }

    #[cfg(feature = "quic")]
    #[test]
    fn test_quic_stream_auth_failure_counter() {
        use std::sync::atomic::AtomicU32;
        let counter = AtomicU32::new(0);

        // 第一次失败: 不关闭连接 (返回 false)
        assert!(!record_stream_auth_failure(&counter));
        assert_eq!(counter.load(Ordering::SeqCst), 1);

        // 第二次失败: 仍不关闭连接 (返回 false)
        assert!(!record_stream_auth_failure(&counter));
        assert_eq!(counter.load(Ordering::SeqCst), 2);

        // 第三次失败: 达到阈值, 触发关闭连接 (返回 true)
        assert!(record_stream_auth_failure(&counter));
        assert_eq!(counter.load(Ordering::SeqCst), 3);

        // 后续失败: 依然超过阈值
        assert!(record_stream_auth_failure(&counter));
        assert_eq!(counter.load(Ordering::SeqCst), 4);
    }

    #[test]
    fn test_reload_creds_password_change_revokes_old_and_reuses_unchanged() {
        // 串行: config_watcher 的 apply_user_config 测试会吊销注册表中"不在其配置里"的所有 tag。
        let _creds_serial = crate::proxy::user_limits::REGISTRY_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let tag = format!("test_p2_1_ab_{}", fastrand::u64(..));
        let c1 = register_creds(&tag, vec![
            CredEntry::new("default", "pw_main"),
            CredEntry::new("alice", "pw_alice_1"),
            CredEntry::new("bob", "pw_bob"),
        ]);
        let snap1 = c1.load_full();
        let alice_old_revoked = snap1[1].revoked.clone();
        let bob_old_revoked = snap1[2].revoked.clone();
        assert!(!alice_old_revoked.load(Ordering::Relaxed));
        assert!(!bob_old_revoked.load(Ordering::Relaxed));

        // 改 alice 口令, bob 不变
        let updated = reload_creds(&tag, vec![
            CredEntry::new("default", "pw_main"),
            CredEntry::new("alice", "pw_alice_2"),
            CredEntry::new("bob", "pw_bob"),
        ]);
        assert!(updated);
        let snap2 = c1.load_full();

        // (a) 旧条目 revoked = true, 新条目 false
        assert!(alice_old_revoked.load(Ordering::Relaxed), "旧 alice 条目应被置为 revoked");
        assert!(!snap2[1].revoked.load(Ordering::Relaxed), "新 alice 条目不应被 revoked");

        // (b) 口令不变的条目复用同一 Arc 且保持 false
        assert!(!bob_old_revoked.load(Ordering::Relaxed), "bob 未修改, 不应被 revoked");
        assert!(Arc::ptr_eq(&bob_old_revoked, &snap2[2].revoked), "bob 应复用旧条目的 revoked Arc");
    }

    #[test]
    fn test_reload_creds_main_password_change_revokes_old_default() {
        // 串行: config_watcher 的 apply_user_config 测试会吊销注册表中"不在其配置里"的所有 tag。
        let _creds_serial = crate::proxy::user_limits::REGISTRY_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let tag = format!("test_p2_1_c_{}", fastrand::u64(..));
        let c = register_creds(&tag, vec![
            CredEntry::new("default", "pw_main_old"),
            CredEntry::new("alice", "pw_alice"),
        ]);
        let snap1 = c.load_full();
        let default_old_revoked = snap1[0].revoked.clone();
        assert!(!default_old_revoked.load(Ordering::Relaxed));

        // 改 default 主口令
        let updated = reload_creds(&tag, vec![
            CredEntry::new("default", "pw_main_new"),
            CredEntry::new("alice", "pw_alice"),
        ]);
        assert!(updated);
        let snap2 = c.load_full();

        assert!(default_old_revoked.load(Ordering::Relaxed), "旧 default 条目应被置为 revoked");
        assert!(!snap2[0].revoked.load(Ordering::Relaxed), "新 default 条目不应被 revoked");
    }

    #[test]
    fn test_reload_creds_remove_and_readd_same_cred_not_revoked() {
        // 串行: config_watcher 的 apply_user_config 测试会吊销注册表中"不在其配置里"的所有 tag。
        let _creds_serial = crate::proxy::user_limits::REGISTRY_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let tag = format!("test_p2_1_d_{}", fastrand::u64(..));
        let c = register_creds(&tag, vec![
            CredEntry::new("default", "pw_main"),
            CredEntry::new("alice", "pw_alice"),
        ]);
        let snap1 = c.load_full();
        let alice_old_revoked = snap1[1].revoked.clone();

        // 模拟 remove + upsert 同名同口令在同一次热重载请求中应用 (快照最终结果相同)
        let updated = reload_creds(&tag, vec![
            CredEntry::new("default", "pw_main"),
            CredEntry::new("alice", "pw_alice"),
        ]);
        assert!(updated);
        let snap2 = c.load_full();

        assert!(!alice_old_revoked.load(Ordering::Relaxed), "同名同口令未变, 不应被吊销");
        assert!(Arc::ptr_eq(&alice_old_revoked, &snap2[1].revoked), "同名同口令应复用同一 Arc");
    }

    #[test]
    fn test_reload_creds_two_inbounds_isolated() {
        // 串行: config_watcher 的 apply_user_config 测试会吊销注册表中"不在其配置里"的所有 tag。
        let _creds_serial = crate::proxy::user_limits::REGISTRY_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let tag_a = format!("test_p2_1_e_a_{}", fastrand::u64(..));
        let tag_b = format!("test_p2_1_e_b_{}", fastrand::u64(..));

        let ca = register_creds(&tag_a, vec![
            CredEntry::new("default", "pw_main_a"),
            CredEntry::new("alice", "pw_alice"),
        ]);
        let cb = register_creds(&tag_b, vec![
            CredEntry::new("default", "pw_main_b"),
            CredEntry::new("alice", "pw_alice"),
        ]);

        let snap_a1 = ca.load_full();
        let snap_b1 = cb.load_full();
        let alice_a_revoked = snap_a1[1].revoked.clone();
        let alice_b_revoked = snap_b1[1].revoked.clone();

        // 从入站 A 删掉 alice
        let updated_a = reload_creds(&tag_a, vec![
            CredEntry::new("default", "pw_main_a"),
        ]);
        assert!(updated_a);

        assert!(alice_a_revoked.load(Ordering::Relaxed), "入站 A 删掉 alice, 其条目应被吊销");
        assert!(!alice_b_revoked.load(Ordering::Relaxed), "入站 B 上的 alice 条目不应受影响");
    }

    #[tokio::test]
    #[allow(clippy::await_holding_lock)]
    async fn test_duplex_session_auth_should_stop_after_reload_creds() {
        // 串行: config_watcher 的 apply_user_config 测试会吊销注册表中"不在其配置里"的所有 tag。
        let _creds_serial = crate::proxy::user_limits::REGISTRY_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let _t = crate::time_sync::tests::TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let tag = format!("test_p2_1_f_{}", fastrand::u64(..));
        let (mut client, server) = tokio::io::duplex(8192);
        let creds_store = register_creds(&tag, vec![
            CredEntry::new("default", "main_pw"),
            CredEntry::new("alice", "alice_secret"),
        ]);

        let client_random = [0x77u8; 32];
        let token = crate::crypto::hello_auth::make_session_token("alice_secret", &client_random);

        // 构造合法 ClientHello
        let mut hs = vec![0x01, 0x00, 0x00, 0x00];
        hs.extend_from_slice(&[0x03, 0x03]);
        hs.extend_from_slice(&client_random);
        hs.push(32);
        hs.extend_from_slice(&token);
        hs.extend_from_slice(&2u16.to_be_bytes());
        hs.extend_from_slice(&[0x13, 0x01]);
        hs.extend_from_slice(&[0x01, 0x00]);
        hs.extend_from_slice(&[0x00, 0x00]);
        let body_len = (hs.len() - 4) as u32;
        hs[1..4].copy_from_slice(&body_len.to_be_bytes()[1..4]);

        let mut ch_record = vec![0x16, 0x03, 0x01];
        ch_record.extend_from_slice(&(hs.len() as u16).to_be_bytes());
        ch_record.extend_from_slice(&hs);

        let cam_rtt = CamouflageRtt::new();
        let peer_addr: std::net::SocketAddr = "127.0.0.1:12345".parse().unwrap();

        let snap = creds_store.load_full();
        let server_task = tokio::spawn(async move {
            handshake::run_handshake(server, peer_addr, &snap, "example.com", &cam_rtt, 60, false, None).await
        });

        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        client.write_all(&ch_record).await.unwrap();
        let mut resp_buf = vec![0u8; 4096];
        let n = client.read(&mut resp_buf).await.unwrap();
        assert!(n > 0);
        let tail = crate::crypto::tls_raw::build_fake_client_tail(0x1301);
        client.write_all(&tail).await.unwrap();

        let res = server_task.await.unwrap().expect("handshake success");
        let (_stream, _cr, _sr, _ecdh, idx) = res;
        assert_eq!(idx, 1, "命中 alice");

        let snap_now = creds_store.load_full();
        let alice_entry = &snap_now[idx];
        let session_auth = SessionAuth::new(None, alice_entry.revoked.clone());
        assert!(!session_auth.should_stop(), "初始未吊销");

        // 热重载修改 alice 口令
        reload_creds(&tag, vec![
            CredEntry::new("default", "main_pw"),
            CredEntry::new("alice", "alice_new_secret"),
        ]);

        assert!(session_auth.should_stop(), "改口令后在用会话的 should_stop() 必须为 true");
    }

    #[test]
    fn test_quic_runtime_limiter_conn_and_stream_budgets() {
        let rt = Arc::new(QuicRuntimeLimiter::new(2, 3, 2, 3));
        let ip1: IpAddr = "192.0.2.10".parse().unwrap();
        let ip2: IpAddr = "192.0.2.11".parse().unwrap();
        let v6_a: IpAddr = "2001:db8::1".parse().unwrap();
        let v6_b: IpAddr = "2001:db8::2".parse().unwrap();

        // 1. 每 IP 连接预算与全局连接预算
        let c1 = rt.try_acquire_conn(ip1).unwrap();
        let c2 = rt.try_acquire_conn(ip1).unwrap();
        assert!(rt.try_acquire_conn(ip1).is_none(), "单 IP 连接上限 2 已满");
        assert_eq!(rt.current_conn_for_ip(ip1), 2);
        assert_eq!(rt.current_conn_global(), 2);

        let c3 = rt.try_acquire_conn(ip2).unwrap();
        assert_eq!(rt.current_conn_global(), 3);
        assert!(rt.try_acquire_conn(v6_a).is_none(), "全局连接上限 3 已满");

        drop(c1);
        assert_eq!(rt.current_conn_for_ip(ip1), 1);
        assert_eq!(rt.current_conn_global(), 2);

        drop(c2);
        drop(c3);
        assert_eq!(rt.current_conn_global(), 0);

        // 2. IPv6 /64 共享流预算与全局流预算
        let s1 = rt.try_acquire_stream(v6_a).unwrap();
        let s2 = rt.try_acquire_stream(v6_b).unwrap();
        assert_eq!(rt.current_stream_for_ip(v6_a), 2, "同 /64 IPv6 共享流预算");
        assert!(rt.try_acquire_stream(v6_a).is_none(), "同 /64 流预算上限 2 已满");

        let s3 = rt.try_acquire_stream(ip1).unwrap();
        assert_eq!(rt.current_stream_global(), 3);
        assert!(rt.try_acquire_stream(ip2).is_none(), "全局流预算上限 3 已满");

        drop(s1);
        drop(s2);
        drop(s3);
        assert_eq!(rt.current_stream_global(), 0);
        assert_eq!(rt.current_stream_for_ip(v6_a), 0);
        assert!(rt.conn_per_ip.lock().unwrap().is_empty());
        assert!(rt.stream_per_ip.lock().unwrap().is_empty());

        // 3. max_per_ip == 0 时拒绝请求不应在 HashMap 中残留 0 值键
        let zero_rt = Arc::new(QuicRuntimeLimiter::new(0, 10, 0, 10));
        assert!(zero_rt.try_acquire_conn(ip1).is_none());
        assert!(zero_rt.try_acquire_stream(ip1).is_none());
        assert!(zero_rt.conn_per_ip.lock().unwrap().is_empty());
        assert!(zero_rt.stream_per_ip.lock().unwrap().is_empty());
    }
}
