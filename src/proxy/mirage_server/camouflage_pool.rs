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
//! - 单连接 10s max age (camouflage_host 通常 30s idle timeout, 留余量)
//! - 池空时 acquire() 返回 None, 上层降级到即时 connect

use std::collections::VecDeque;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::TcpStream;
use tokio::sync::Mutex;
use tracing::{debug, warn};

const POOL_TARGET_SIZE: usize = 8;
const REFILL_INTERVAL: Duration = Duration::from_millis(500);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(3);
const STREAM_MAX_AGE: Duration = Duration::from_secs(10);

struct Pooled {
    stream: TcpStream,
    created_at: Instant,
}

pub struct CamouflagePool {
    host: String,
    pool: Mutex<VecDeque<Pooled>>,
}

impl CamouflagePool {
    /// 创建池并 spawn 后台补给 task. task 生命周期与进程一致.
    pub fn new(host: String) -> Arc<Self> {
        let arc = Arc::new(Self {
            host,
            pool: Mutex::new(VecDeque::with_capacity(POOL_TARGET_SIZE)),
        });
        let bg = arc.clone();
        tokio::spawn(async move {
            bg.maintain().await;
        });
        arc
    }

    /// pop 一条 pre-warmed 连接. 无可用则返回 None, 由调用方 fallback 到新建.
    pub async fn acquire(&self) -> Option<TcpStream> {
        let mut pool = self.pool.lock().await;
        pool.pop_front().map(|p| p.stream)
    }

    async fn maintain(self: Arc<Self>) {
        let addr = format!("{}:443", self.host);
        loop {
            tokio::time::sleep(REFILL_INTERVAL).await;

            // 淘汰过期连接
            {
                let mut pool = self.pool.lock().await;
                let now = Instant::now();
                let before = pool.len();
                pool.retain(|p| now.duration_since(p.created_at) < STREAM_MAX_AGE);
                let purged = before - pool.len();
                if purged > 0 {
                    debug!("CamouflagePool: purged {} stale streams", purged);
                }
            }

            // 补给到目标容量. 单次补给内如果 connect 失败, 停止本轮避免打爆
            // camouflage_host (对面可能临时抖动).
            loop {
                let cur = self.pool.lock().await.len();
                if cur >= POOL_TARGET_SIZE {
                    break;
                }
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
                let mut pool = self.pool.lock().await;
                pool.push_back(Pooled {
                    stream,
                    created_at: Instant::now(),
                });
            }
        }
    }
}
