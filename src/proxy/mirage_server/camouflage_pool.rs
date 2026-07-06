//! Camouflage 目标预热 TCP 连接池.
//!
//! v0.4.5-alpha.7: 消除 auth-fail 分支 TCP 3-way RTT 侧信道. 之前 auth-fail 时
//! 服务端要 `TcpStream::connect(camouflage_host:443)` 新建 TCP, 一个 RTT (5-100ms)
//! vs auth-succ 分支的本地模板拷贝 (~0-1ms). 攻击者用大量样本对比首字节返程时间
//! 可分类. 现在 auth-fail 直接从池里 pop 一条已建 TCP, RTT 差异降到只剩
//! "camouflage_host 回 ServerHello 的 1 RTT", 显著缩窄侧信道窗口.
//!
//! 池设计:
//! - 目标容量 8 (低负载充足)
//! - 500ms 补给一次, 每次尝试补到目标容量
//! - 单连接 25s max age (camouflage_host 通常 30s idle timeout, 留 5s 余量)。
//!   之前 10s 过激: 8 条暖连接每 10s 全部过期重建 = 对 camouflage_host 持续
//!   ~0.8 conn/s 纯 TCP 不发数据、10s 关, 6.9万次/天, 像 bot 可能被对面限流/
//!   标记。25s 把 churn 降到 ~0.32 conn/s (2.5x), is_alive 兜底已死连接。
//! - 池空时 acquire() 返回 None, 上层降级到即时 connect

use std::collections::VecDeque;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::TcpStream;
use tokio::sync::Mutex;
use tracing::{debug, warn};

const POOL_TARGET_SIZE: usize = 8;
const REFILL_INTERVAL: Duration = Duration::from_millis(500);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(3);
const STREAM_MAX_AGE: Duration = Duration::from_secs(25);
/// RTT EWMA 上限, 防测量毛刺注入荒谬延迟 (远 camouflage 是坏部署, 另行建议就近选).
const RTT_MAX_US: u64 = 1_000_000;

struct Pooled {
    stream: TcpStream,
    created_at: Instant,
}

/// 探活: 一条尚未发送 ClientHello 的预热连接, 健康态应【无可读数据且无 EOF】.
/// 非阻塞 try_read 一字节:
///   Err(WouldBlock)  无数据无 EOF → 活 (正常)
///   Ok(0)            对端已发 FIN (idle 超时优雅关闭) → 死
///   Ok(n>0)          对端意外发来数据 (不该发生) → 不可用
///   其他 Err         RST / 错误 → 死
///
/// 防止把已被 camouflage_host idle-timeout 关掉的死连接交出去 —— 否则转发写入
/// 立即失败, 探针收到 RST, 与真实站点行为不一致, 暴露 camouflage.
fn is_alive(stream: &TcpStream) -> bool {
    let mut buf = [0u8; 1];
    matches!(
        stream.try_read(&mut buf),
        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock
    )
}

pub struct CamouflagePool {
    host: String,
    pool: Mutex<VecDeque<Pooled>>,
    /// 到 camouflage_host 的 RTT EWMA (微秒, 0=未知). 由 maintain 连接时测量,
    /// 供 auth-succ 时序对齐用 (注入等量延迟消除 auth-succ/fail 时序侧信道).
    rtt_us: AtomicU64,
}

impl CamouflagePool {
    /// 创建池并 spawn 后台补给 task. task 生命周期与进程一致.
    pub fn new(host: String) -> Arc<Self> {
        let arc = Arc::new(Self {
            host,
            pool: Mutex::new(VecDeque::with_capacity(POOL_TARGET_SIZE)),
            rtt_us: AtomicU64::new(0),
        });
        let bg = arc.clone();
        tokio::spawn(async move {
            bg.maintain().await;
        });
        arc
    }

    /// 当前估计的 camouflage_host RTT (微秒, 0=尚未测到). 供 auth-succ 时序对齐.
    pub fn rtt_us(&self) -> u64 {
        self.rtt_us.load(Ordering::Relaxed)
    }

    /// pop 一条 **存活的** pre-warmed 连接. 逐条探活, 跳过并丢弃已被对端关闭的
    /// 死连接. 全部死/池空则返回 None, 由调用方 fallback 到即时新建.
    pub async fn acquire(&self) -> Option<TcpStream> {
        let mut pool = self.pool.lock().await;
        while let Some(p) = pool.pop_front() {
            if is_alive(&p.stream) {
                return Some(p.stream);
            }
            // 死连接: 丢弃, 试下一条
            debug!("CamouflagePool: discarded dead stream on acquire");
        }
        None
    }

    async fn maintain(self: Arc<Self>) {
        let addr = format!("{}:443", self.host);
        loop {
            tokio::time::sleep(REFILL_INTERVAL).await;

            // 淘汰过期 + 已死 (对端 FIN/RST) 连接
            {
                let mut pool = self.pool.lock().await;
                let now = Instant::now();
                let before = pool.len();
                pool.retain(|p| {
                    now.duration_since(p.created_at) < STREAM_MAX_AGE && is_alive(&p.stream)
                });
                let purged = before - pool.len();
                if purged > 0 {
                    debug!("CamouflagePool: purged {} stale/dead streams", purged);
                }
            }

            // 补给到目标容量. 单次补给内如果 connect 失败, 停止本轮避免打爆
            // camouflage_host (对面可能临时抖动).
            loop {
                let cur = self.pool.lock().await.len();
                if cur >= POOL_TARGET_SIZE {
                    break;
                }
                let t0 = Instant::now();
                let stream = match tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect(&addr))
                    .await
                {
                    Ok(Ok(s)) => s,
                    Ok(Err(e)) => {
                        warn!("CamouflagePool: connect {} failed: {}", addr, e);
                        break;
                    }
                    Err(_) => {
                        warn!("CamouflagePool: connect {} timeout", addr);
                        break;
                    }
                };
                // TCP 3-way 耗时 ≈ 1 网络 RTT, 是 auth-fail 转发延迟 (预热连接省了
                // 3-way, 只剩 1 个 ClientHello→ServerHello app RTT) 的良好近似.
                // EWMA 平滑 (1/8 新样本), 上限防毛刺.
                let rtt = (t0.elapsed().as_micros() as u64).min(RTT_MAX_US);
                let prev = self.rtt_us.load(Ordering::Relaxed);
                let ewma = if prev == 0 { rtt } else { (prev * 7 + rtt) / 8 };
                self.rtt_us.store(ewma, Ordering::Relaxed);

                let mut pool = self.pool.lock().await;
                pool.push_back(Pooled {
                    stream,
                    created_at: Instant::now(),
                });
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::is_alive;
    use tokio::io::AsyncWriteExt;
    use tokio::net::{TcpListener, TcpStream};

    // 健康空闲连接 (对端 accept 后不发数据, 模拟等 ClientHello 的 camouflage_host)
    // 必须判为活; 对端关闭 (FIN) 后必须判为死. 防 is_alive 把好连接误杀导致池静默
    // 废掉.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn is_alive_healthy_true_closed_false() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        // 服务端 accept 后持有 socket 不发数据 (健康态)
        let accepted = tokio::spawn(async move {
            let (sock, _) = listener.accept().await.unwrap();
            sock
        });

        let client = TcpStream::connect(addr).await.unwrap();
        let server_sock = accepted.await.unwrap();

        // 健康空闲: 无数据无 EOF → 活
        assert!(is_alive(&client), "健康空闲连接应判为活");

        // 服务端关闭 → 客户端收到 FIN
        drop(server_sock);
        // 给 FIN 一点传播时间
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        assert!(!is_alive(&client), "对端 FIN 后应判为死");
    }

    // 对端发来意外数据的连接判为不可用 (预热连接不该收到 server 主动数据).
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn is_alive_unexpected_data_false() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let accepted = tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            sock.write_all(b"x").await.unwrap();
            sock.flush().await.unwrap();
            sock
        });
        let client = TcpStream::connect(addr).await.unwrap();
        let _server = accepted.await.unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        assert!(!is_alive(&client), "收到意外数据的连接应判为不可用");
    }
}
