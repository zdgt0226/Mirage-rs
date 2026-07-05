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
