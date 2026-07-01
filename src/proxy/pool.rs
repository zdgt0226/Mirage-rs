use crate::crypto::aead::create_crypto_pair;
use crate::proxy::tunnel::Tunnel;
use anyhow::Result;
use std::collections::VecDeque;
use std::sync::Arc;
use std::sync::atomic::AtomicU64;
use tokio::net::TcpStream;
use tokio::sync::{Mutex, Notify};
use std::sync::RwLock;
use tracing::{debug, error, info};
use tokio::time::Instant;

pub struct PoolConfig {
    pub server_host: String,
    pub server_port: u16,
    pub password: String,
    pub camouflage_host: String,
    pub pool_size: usize,
}

/**
 * [Brutal 拥塞控制状态机]
 * 维护每个节点出站连接的动态拥塞控制参数。
 * 它根据 eBPF 提取的 TCP RTT 和丢包情况动态调节传输速率（BDP 算法）。
 */
pub struct BrutalState {
    pub configured_rate: Option<u64>,
    pub current_rate: Arc<std::sync::atomic::AtomicU64>, // 当前动态调整的发送速率
    pub base_rtt: Option<u64>,                           // 连接池基准 RTT (测得的最快延迟)
    pub active_fds: Arc<std::sync::Mutex<std::collections::HashSet<i32>>>, // 正在传输数据的套接字文件描述符集合
}

/**
 * [活跃连接守卫 (RAII Guard)]
 * 用于自动管理 active_fds 集合的生命周期。
 * 创建时外部将其 FD 加入集合；当作用域结束（Guard 销毁）时，利用 Drop trait 自动将 FD 移出集合。
 * 这是防止死 FD 泄漏并干扰拥塞控制算法的核心安全机制。
 */
pub struct ActiveFdGuard {
    state: Arc<BrutalState>,
    fd: i32,
}

impl Drop for ActiveFdGuard {
    fn drop(&mut self) {
        if let Ok(mut lock) = self.state.active_fds.lock() {
            lock.remove(&self.fd);
        }
    }
}

#[derive(Debug)]
pub struct PoolStats {
    pub latency_samples: VecDeque<u64>,
    pub consecutive_failures: u32,
    pub last_sample_time: Option<Instant>,
}

impl PoolStats {
    pub fn new() -> Self {
        Self {
            latency_samples: VecDeque::with_capacity(10),
            consecutive_failures: 0,
            last_sample_time: None,
        }
    }

    pub fn record_latency(&mut self, ms: u64) {
        if self.latency_samples.len() == 10 {
            self.latency_samples.pop_front();
        }
        self.latency_samples.push_back(ms);
        self.last_sample_time = Some(Instant::now());
        self.consecutive_failures = 0;
    }

    pub fn record_failure(&mut self) {
        self.consecutive_failures += 1;
    }

    pub fn latency_ms(&self) -> Option<u64> {
        if self.latency_samples.is_empty() {
            return None;
        }
        let mut sorted: Vec<u64> = self.latency_samples.iter().copied().collect();
        sorted.sort_unstable();
        Some(sorted[sorted.len() / 2])
    }

    pub fn is_healthy(&self) -> bool {
        self.consecutive_failures < 3
    }
}

/// WarmPool 反馈式弹性算法的运行时指标 (v0.4.2+).
///
/// 替代旧的 `RPS * 3 + 2` 开环算法. 每 5 秒由 Manager task 读取并归零,
/// 根据 (wait_ratio, expired/total_gets) 做 AIAD 调节. 详见 decide_new_target.
pub struct PoolMetrics {
    /// pool.get() 等待 > 50ms 才拿到 tunnel 的次数. 反映"供给不足"压力.
    pub wait_events: AtomicU64,
    /// pool.get() 总调用数 (周期内).
    pub total_gets: AtomicU64,
    /// Sweeper 在 max_age 到期前没被 get 用过的 tunnel 数. 反映"建多了没人用".
    pub expired_unused: AtomicU64,
}

impl PoolMetrics {
    fn new() -> Self {
        Self {
            wait_events: AtomicU64::new(0),
            total_gets: AtomicU64::new(0),
            expired_unused: AtomicU64::new(0),
        }
    }
}

/// 反馈式 target 决策 — 纯函数, 便于单元测试.
///
/// AIAD (additive increase, additive decrease) 控制:
/// - 上一周期有 > 20% 的 get 经历过 50ms+ 等待 → target 加 20% (最少 +1)
/// - 上一周期 0 个 wait_event AND 过期未用 ≥ 一半使用数 → target 减 1
/// - 否则维持
///
/// 不做硬裁剪 (旧版 q.len() > target+2 那段已删), target 只控制 builder 建货
/// 节奏, queue 自然在 max_age 到期被 sweeper 收掉.
/// WarmPool 缩容底线. 突发 N 并发请求时 pool 至少要有 N 条常温 tunnel,
/// 否则 N-target 条会 wait build (770-2000ms 每条), 用户感受"卡顿".
///
/// alpha.10 之前是 2, 实测浏览器 YouTube 突发经常 6 并发, 66% wait.
/// 提到 10 = 常见浏览器并发上限, 突发时立刻各分 1 条 tunnel 无 wait.
///
/// pool_size < 10 时 floor 自动降为 max_size (下面 .min(max_size)), 避免
/// pool 永远缩不动.
const MIN_TARGET_FLOOR: usize = 10;

pub(crate) fn decide_new_target(
    cur_target: usize,
    wait_events: u64,
    total_gets: u64,
    expired_unused: u64,
    max_size: usize,
) -> usize {
    let wait_ratio = if total_gets == 0 {
        0.0
    } else {
        wait_events as f64 / total_gets as f64
    };
    let floor = MIN_TARGET_FLOOR.min(max_size);

    if wait_ratio > 0.2 && cur_target < max_size {
        let increment = (cur_target / 5).max(1);
        (cur_target + increment).min(max_size)
    } else if wait_ratio == 0.0
        && expired_unused >= total_gets / 2
        && cur_target > floor
    {
        // 缩容触发条件:
        // - 无任何等待 (wait_ratio = 0): 池子供给充足
        // - expired ≥ gets/2: 建货量远超消费 (或纯 idle 期 gets=0, expired ≥ 0 恒成立)
        // - cur_target > floor: 保留最低 idle floor (见 MIN_TARGET_FLOOR)
        //
        // 注意: 不能加 `total_gets > 0` 守护! 否则高峰期池子涨到 40 后用户睡觉
        // 流量归零 → total_gets=0 → 跳过缩容 → builder 永远维持 40 个 idle 连接
        // → max_age 到期 sweeper 杀 → builder 又建 → 一整夜烧 CPU 握手.
        // 由 cur_target > floor 兜底, 不需要额外的 traffic 守护.
        cur_target - 1
    } else {
        cur_target
    }
}

#[cfg(test)]
mod feedback_tests {
    use super::*;

    #[test]
    fn idle_at_floor_stays() {
        // 完全无流量 + cur_target 已在 floor=10: 不动 (floor 保护)
        assert_eq!(decide_new_target(10, 0, 0, 0, 50), 10);
        // floor 在 pool_size < 10 时降为 max_size, 已到 max_size 也不动
        assert_eq!(decide_new_target(5, 0, 0, 0, 5), 5);
    }

    #[test]
    fn idle_above_floor_drains() {
        // 完全无流量 + cur_target > floor: 缓慢缩容 (每周期 -1) 直到 floor.
        // 修复 #2 (前版 buggy 加了 total_gets > 0 守护, 导致高峰后池子锁死).
        assert_eq!(decide_new_target(15, 0, 0, 0, 50), 14);
        // 到 floor+1 再缩最后一次到 floor:
        assert_eq!(decide_new_target(11, 0, 0, 0, 50), 10);
        // 到 floor 后就不再缩:
        assert_eq!(decide_new_target(10, 0, 0, 0, 50), 10);
    }

    #[test]
    fn pressure_scales_up() {
        // wait_ratio > 0.2: 扩
        // 3/10 = 0.3 > 0.2, target 5 + max(1, 5/5)=1 = 6
        assert_eq!(decide_new_target(5, 3, 10, 0, 50), 6);
        // 大 target 时 +20%: 10 + 2 = 12
        assert_eq!(decide_new_target(10, 3, 10, 0, 50), 12);
    }

    #[test]
    fn pressure_clamped_by_max() {
        // 已到上限不扩
        assert_eq!(decide_new_target(50, 5, 10, 0, 50), 50);
        // 增长后超上限被夹住
        assert_eq!(decide_new_target(48, 5, 10, 0, 50), 50);
    }

    #[test]
    fn over_provision_scales_down() {
        // 0 wait, expired=6 ≥ gets/2=5 → 缩 1. cur=15 > floor=10 才能缩
        assert_eq!(decide_new_target(15, 0, 10, 6, 50), 14);
    }

    #[test]
    fn over_provision_floor_at_floor() {
        // cur=floor=10, 即便 expired 全部, 也不再缩
        assert_eq!(decide_new_target(10, 0, 10, 10, 50), 10);
    }

    #[test]
    fn waiting_blocks_shrinking() {
        // 既有 wait 又有 expired: wait 优先, 扩而不是缩
        assert_eq!(decide_new_target(10, 3, 10, 5, 50), 12);
    }

    #[test]
    fn no_traffic_with_expired_drains() {
        // 无流量 + 有 expired (高峰后池子滞留, idle 期 max_age 到期被 sweeper 收掉):
        // 应该立刻缩容 -1, 之后多周期收敛到 floor=10. 修复 #2: 资源燃烧 bug.
        assert_eq!(decide_new_target(20, 0, 0, 10, 50), 19);
    }

    #[test]
    fn moderate_use_no_change() {
        // 10% wait_ratio (< 20%) AND 不到 expired 阈值: 不动
        assert_eq!(decide_new_target(10, 1, 10, 2, 50), 10);
    }
}

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::timeout;
use std::time::Duration;

pub async fn read_server_handshake(stream: &mut tokio::net::tcp::OwnedReadHalf) -> Result<()> {
    let mut saw_sh = false;
    let mut saw_ccs = false;
    let mut saw_enc = false;

    loop {
        let t = if saw_ccs { Duration::from_millis(1500) } else { Duration::from_secs(12) };
        let mut header = [0u8; 5];
        match timeout(t, stream.read_exact(&mut header)).await {
            Ok(Ok(_)) => {
                let ct = header[0];
                let length = u16::from_be_bytes([header[3], header[4]]) as usize;
                
                let mut body = vec![0u8; length];
                match timeout(t, stream.read_exact(&mut body)).await {
                    Ok(Ok(_)) => {
                        if ct == 0x15 {
                            return Err(anyhow::anyhow!("Server sent TLS alert"));
                        } else if ct == 0x16 {
                            saw_sh = true;
                        } else if ct == 0x14 {
                            saw_ccs = true;
                        } else if ct == 0x17 {
                            saw_enc = true;
                        }
                        
                        if saw_sh && saw_ccs && saw_enc {
                            return Ok(());
                        }
                    }
                    Ok(Err(e)) => return Err(anyhow::anyhow!("Incomplete body: {}", e)),
                    Err(_) => return Err(anyhow::anyhow!("Timeout reading body")),
                }
            }
            Ok(Err(e)) => return Err(anyhow::anyhow!("Incomplete header: {}", e)),
            Err(_) => {
                if !saw_ccs {
                    return Err(anyhow::anyhow!("Timeout before CCS"));
                }
                break; // normal exit after timeout if we saw CCS
            }
        }
    }

    if !saw_sh || !saw_ccs || !saw_enc {
        return Err(anyhow::anyhow!("Incomplete flight: sh={}, ccs={}, enc={}", saw_sh, saw_ccs, saw_enc));
    }
    Ok(())
}

use std::sync::atomic::{AtomicUsize, Ordering};

/// [弹性预热连接池 (WarmPool)]
/// Mirage 的核心性能组件，用于零延迟转发。
/// 
/// 工作原理：
/// 1. 后台异步维护一个处于 TLS 握手完毕状态的空闲隧道队列。
/// 2. 客户端请求到达时，直接从池中取出一个已经建好握手的 Tunnel。
/// 3. 并发不足时弹性扩容，支持高并发无缝爆发。
pub struct WarmPool {
    queue: Arc<Mutex<VecDeque<Tunnel>>>,      // 空闲可用的隧道队列
    notify: Arc<Notify>,                      // 阻塞唤醒器（当没有连接时挂起请求）
    pub stats: Arc<RwLock<PoolStats>>,        // 连接池的延迟统计和健康检查
    pub brutal_state: Arc<BrutalState>,       // 该连接池绑定的拥塞控制状态
    metrics: Arc<PoolMetrics>,                // 反馈式弹性算法的运行时指标
}

impl WarmPool {
    pub fn new(cfg: Arc<PoolConfig>, brutal_state: Arc<BrutalState>) -> Self {
        let queue = Arc::new(Mutex::new(VecDeque::with_capacity(cfg.pool_size)));
        let notify = Arc::new(Notify::new());
        let stats = Arc::new(RwLock::new(PoolStats::new()));
        let metrics = Arc::new(PoolMetrics::new());

        let pool = Self {
            queue: queue.clone(),
            notify: notify.clone(),
            stats: stats.clone(),
            brutal_state: brutal_state.clone(),
            metrics: metrics.clone(),
        };

        // 初始 target = floor (跟 decide_new_target 的缩容底线一致), 保证客户端
        // 启动瞬间就能承接常见浏览器并发, 突发不用 wait build. floor 定义见
        // MIN_TARGET_FLOOR (=10). pool_size < floor 时降到 pool_size.
        let initial_target = MIN_TARGET_FLOOR.min(cfg.pool_size);
        let target_size = Arc::new(AtomicUsize::new(initial_target));
        let in_flight = Arc::new(AtomicUsize::new(0));

        // 弹性监控协程 (Manager Task) — 反馈式 v0.4.2+
        // 每 5s 读 metrics 决定 target 调整 + 顺手清理 max_age 过期连接.
        // 不再做硬裁剪 (旧版 q.len() > target+2 那段), 让 target 只影响 builder
        // 建货节奏, queue 自然到 max_age 被 sweeper 收掉.
        let metrics_clone = metrics.clone();
        let target_clone = target_size.clone();
        let q_clone = queue.clone();
        let max_size = cfg.pool_size;
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(5)).await;

                // 读三个计数器并归零, 进入下一周期
                let wait = metrics_clone.wait_events.swap(0, Ordering::Relaxed);
                let gets = metrics_clone.total_gets.swap(0, Ordering::Relaxed);

                // expired_unused 在 sweeper 内累加, 这里读后归零
                // (sweeper 即下方 q.drain 部分, 同一 task 内顺序执行无并发问题)
                let cur_target = target_clone.load(Ordering::Relaxed);

                // 清理 max_age 过期的 tunnel (顺手 close_notify), 同时统计 expired_unused
                let mut q = q_clone.lock().await;
                let mut to_drop = Vec::new();
                let mut alive = std::collections::VecDeque::with_capacity(q.len());
                for tunnel in q.drain(..) {
                    if tunnel.created_at.elapsed().as_secs() > tunnel.max_age_sec {
                        to_drop.push(tunnel);
                    } else {
                        alive.push_back(tunnel);
                    }
                }
                *q = alive;
                let expired_now = to_drop.len() as u64;
                metrics_clone.expired_unused.fetch_add(expired_now, Ordering::Relaxed);
                let expired_total = metrics_clone.expired_unused.swap(0, Ordering::Relaxed);
                drop(q);

                for mut tunnel in to_drop {
                    tokio::spawn(async move {
                        let _ = tunnel.writer.send_close_notify().await;
                        debug!("WarmPool Manager: Closed max_age-expired tunnel.");
                    });
                }

                // 反馈式 target 决策 (纯函数)
                let new_target = decide_new_target(cur_target, wait, gets, expired_total, max_size);
                if new_target != cur_target {
                    target_clone.store(new_target, Ordering::Relaxed);
                    let wait_ratio = if gets == 0 { 0.0 } else { wait as f64 / gets as f64 };
                    debug!(
                        "WarmPool Manager: target {} → {} (gets={}, wait={} [{:.1}%], expired={})",
                        cur_target, new_target, gets, wait, wait_ratio * 100.0, expired_total
                    );
                }
            }
        });

        // 连接补充协程 (Builder Task)
        let q_clone_builder = queue.clone();
        let n_clone_builder = notify.clone();
        let cfg_clone = cfg.clone();
        let in_flight_clone = in_flight.clone();
        let target_clone_builder = target_size.clone();
        let stats_builder = stats.clone();
        let brutal_state_builder = brutal_state.clone();
        
        tokio::spawn(async move {
            info!("WarmPool (Elastic) initialized. Max capacity: {}", cfg_clone.pool_size);
            let mut next_build_at = Instant::now();

            loop {
                let current_target = target_clone_builder.load(Ordering::Relaxed);
                let current_idle = q_clone_builder.lock().await.len();
                let current_in_flight = in_flight_clone.load(Ordering::Relaxed);

                // 判断是否需要补充连接：闲置 + 正在建连的 < 目标，且没有触碰总上限
                if current_idle + current_in_flight >= current_target || current_idle + current_in_flight >= cfg_clone.pool_size {
                    // 等待消费者拿走连接，或者Manager提升目标值
                    tokio::time::sleep(Duration::from_millis(100)).await;
                    continue;
                }

                in_flight_clone.fetch_add(1, Ordering::Relaxed);

                // 引入 0.2s 阶梯延迟 (SYN Staggering)，防止网络拥塞和暴露特征
                let now = Instant::now();
                if next_build_at > now {
                    tokio::time::sleep_until(next_build_at).await;
                }
                next_build_at = Instant::now() + Duration::from_millis(200);

                let cfg_task = cfg_clone.clone();
                let q_task = q_clone_builder.clone();
                let n_task = n_clone_builder.clone();
                let in_flight_task = in_flight_clone.clone();
                let stats_task = stats_builder.clone();
                let bs_task = brutal_state_builder.clone();

                tokio::spawn(async move {
                    let start = Instant::now();
                    match Self::connect_upstream(&cfg_task, &bs_task).await {
                        Ok(tunnel) => {
                            let elapsed = start.elapsed().as_millis() as u64;
                            stats_task.write().unwrap().record_latency(elapsed);
                            
                            q_task.lock().await.push_back(tunnel);
                            n_task.notify_one();
                            in_flight_task.fetch_sub(1, Ordering::Relaxed);
                            debug!("WarmPool: 预热连接就绪 ({}ms)", elapsed);
                        }
                        Err(e) => {
                            stats_task.write().unwrap().record_failure();
                            in_flight_task.fetch_sub(1, Ordering::Relaxed);
                            error!("WarmPool: 上游连接失败: {:?}", e);
                            tokio::time::sleep(Duration::from_secs(1)).await;
                        }
                    }
                });
            }
        });

        pool
    }

    /// 核心握手逻辑：建立 TCP 并包装 AEAD Crypto 层
    async fn connect_upstream(cfg: &PoolConfig, brutal_state: &BrutalState) -> Result<Tunnel> {
        let addr = format!("{}:{}", cfg.server_host, cfg.server_port);
        let stream = TcpStream::connect(&addr).await?;
        
        // --- 性能优化：TCP 发送缓冲区与 Brutal 拥塞控制 ---
        use std::os::unix::io::AsRawFd;
        let fd = stream.as_raw_fd();
        unsafe {
            // 2. 发送缓冲区优化: 增加 Pool 中连接的发送 buffer size
            let sndbuf: libc::c_int = 4 * 1024 * 1024; // 4MB
            libc::setsockopt(fd, libc::SOL_SOCKET, libc::SO_SNDBUF, &sndbuf as *const _ as *const libc::c_void, std::mem::size_of::<libc::c_int>() as libc::socklen_t);
            
            let mut actual: libc::c_int = 0;
            let mut sndbuf_len = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
            libc::getsockopt(fd, libc::SOL_SOCKET, libc::SO_SNDBUF, &mut actual as *mut _ as *mut libc::c_void, &mut sndbuf_len);
            
            if actual < sndbuf * 2 {
                use std::sync::atomic::{AtomicBool, Ordering};
                static SNDBUF_WARNED: AtomicBool = AtomicBool::new(false);
                if !SNDBUF_WARNED.swap(true, Ordering::Relaxed) {
                    tracing::warn!(
                        "SO_SNDBUF capped at {} bytes (requested {}). \
                         Run `sysctl -w net.core.wmem_max=8388608` for Brutal CC and large buffer performance.",
                        actual, sndbuf);
                }
            }
            
            // 3. Brutal 拥塞控制 (客户端 → 服务端方向, 控制上传速度).
            // 默认关闭: 仅当 config 显式配了 brutal_rate_mbps 才启用.
            // 动态速率调节 (基于 BPF RTT 反馈) 在另一处循环里维护, 见
            // BrutalState::current_rate 的所有 store 调用点.
            if brutal_state.configured_rate.is_some() {
                let current_rate = brutal_state.current_rate.load(std::sync::atomic::Ordering::Relaxed);
                crate::proxy::brutal::apply_brutal(fd, current_rate);
            }
        }
        // ------------------------------------------------
        
        // 关键性能优化：关闭 Nagle 算法，降低首包延迟
        stream.set_nodelay(true)?;

        let (mut read_half, mut write_half) = stream.into_split();

        // 1. 发送带 token 的 ClientHello
        let token = crate::crypto::hello_auth::make_session_token(&cfg.password);
        let (hello_bytes, client_random) = crate::crypto::tls_raw::build_client_hello(&cfg.camouflage_host, &token);
        write_half.write_all(&hello_bytes).await?;
        write_half.flush().await?;

        // 2. 读取服务端的 ServerHello 及握手 flight
        read_server_handshake(&mut read_half).await?;

        // 3. 发送假 Finished tail 完成 TLS 1.3 握手模拟
        let tail_bytes = crate::crypto::tls_raw::build_fake_client_tail();
        write_half.write_all(&tail_bytes).await?;
        write_half.flush().await?;

        // 4. 派生会话密钥 (使用 client_random 作为 salt)
        let (mut crypto_reader, crypto_writer) = create_crypto_pair(
            read_half,
            write_half,
            &cfg.password,
            &client_random,
            true, // is_initiator = true (Client -> Server)
        );

        // 5. v0.4 协议: 收 server 主动下发的 TIME_SYNC 帧, 写入全局 TIME_OFFSET.
        //    帧格式: [0x01 type][0x01 ver][8B u64 BE server unix sec] = 10 字节
        //    失败/超时降级: 用 local time 继续 (不阻塞连接), 仅 INFO 一次.
        match tokio::time::timeout(
            std::time::Duration::from_secs(3),
            crypto_reader.recv_data()
        ).await {
            Ok(Ok(data)) if data.len() == 10 && data[0] == 0x01 && data[1] == 0x01 => {
                let server_time = u64::from_be_bytes(data[2..10].try_into().unwrap());
                crate::time_sync::set_offset_from_server_time(server_time);
            }
            Ok(Ok(data)) => {
                tracing::warn!(
                    "TIME_SYNC: unexpected frame (len={}, type={:?}), proceeding without sync",
                    data.len(), data.first()
                );
            }
            Ok(Err(e)) => {
                tracing::warn!("TIME_SYNC: recv failed: {:?}, proceeding without sync", e);
            }
            Err(_) => {
                tracing::info!("TIME_SYNC: timeout waiting for server time (3s), proceeding with local time. Old server?");
            }
        }

        Ok(Tunnel::new(crypto_reader, crypto_writer))
    }

    /// O(1) 复杂度提取连接.
    ///
    /// 如果队列有现成连接, 0 延迟返回. 队列空时挂起等待 `notify` 唤醒.
    ///
    /// ★ 10s 超时硬上限 (修 bug: 雪崩) — 之前签名是 `-> Tunnel` infallible,
    /// builder 上游死后只 log + sleep 重试, 永不调 notify_one. 每个 pool.get()
    /// 死等, 浏览器请求堆积成百上千 → FD 耗尽 OOM. 现在返回 `Result<Tunnel>`,
    /// 10s 还拿不到就报错让调用方放弃这次请求, 不堆积.
    ///
    /// 反馈式弹性 (v0.4.2+) 仪表化: 入口记录开始时间, 拿到 tunnel 后若总耗时
    /// > 50ms 计一次 wait_event. Manager task 用此比率决定下周期 target 调整.
    pub async fn get(&self) -> Result<Tunnel> {
        self.metrics.total_gets.fetch_add(1, Ordering::Relaxed);
        let wait_start = Instant::now();

        let result = tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                // 先获取通知句柄（关键：避免检查队列为空和发生通知之间的竞态条件 Race Condition）
                let notified = self.notify.notified();

                if let Some(tunnel) = self.queue.lock().await.pop_front() {
                    if tunnel.created_at.elapsed().as_secs() > tunnel.max_age_sec {
                        tracing::debug!("Tunnel reached max age ({}s), gracefully closing",
                            tunnel.created_at.elapsed().as_secs());
                        tokio::spawn(async move {
                            let mut t = tunnel;
                            let _ = t.writer.send_close_notify().await;
                        });
                        continue;
                    }
                    // 拿到可用 tunnel, 看是否经历过显著等待
                    if wait_start.elapsed() > Duration::from_millis(50) {
                        self.metrics.wait_events.fetch_add(1, Ordering::Relaxed);
                    }
                    return tunnel;
                }

                // 队列真的空了，挂起当前协程等待补货
                notified.await;
            }
        }).await;

        result.map_err(|_| anyhow::anyhow!("pool.get() timed out after 10s — upstream likely unreachable"))
    }

    pub async fn update_brutal_rate(&self, new_rate: u64) {
        self.brutal_state.current_rate.store(new_rate, std::sync::atomic::Ordering::Relaxed);
        let mut fds: Vec<i32> = {
            let q = self.queue.lock().await;
            q.iter().map(|t| t.get_raw_fd()).collect()
        }; // Queue lock released here
        
        if let Ok(actives) = self.brutal_state.active_fds.lock() {
            fds.extend(actives.iter().copied());
        }
        
        let total_updated = fds.len();
        if fds.is_empty() {
            return;
        }
        
        tokio::task::spawn_blocking(move || {
            for fd in fds {
                // 常量 23301 (非 23, 23 = TCP_FASTOPEN), struct packed (12B 匹
                // 配内核 __packed). 详见 src/proxy/brutal.rs apply_brutal 的长
                // 注释 + 实测上游源码确认.
                const TCP_BRUTAL_PARAMS: libc::c_int = 23301;
                #[repr(C, packed)]
                struct BrutalParams { rate: u64, cwnd_gain: u32 }
                // 与 brutal.rs 保持一致: 15 = 1.5× BDP (跟 Python POC 实测最优).
                const CWND_GAIN_X10: u32 = 15;
                let params = BrutalParams { rate: new_rate, cwnd_gain: CWND_GAIN_X10 };
                unsafe {
                    libc::setsockopt(
                        fd,
                        libc::IPPROTO_TCP,
                        TCP_BRUTAL_PARAMS,
                        &params as *const _ as *const libc::c_void,
                        std::mem::size_of::<BrutalParams>() as libc::socklen_t
                    );
                }
            }
        }).await.ok();
        tracing::debug!("Updated Brutal rate to {} bps for {} tunnels (idle + active)", new_rate, total_updated);
    }

    pub fn active_fd_guard(&self, fd: i32) -> ActiveFdGuard {
        if let Ok(mut lock) = self.brutal_state.active_fds.lock() {
            lock.insert(fd);
        }
        ActiveFdGuard {
            state: self.brutal_state.clone(),
            fd,
        }
    }
}
