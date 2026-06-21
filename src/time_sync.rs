// 协议内嵌时间同步.
//
// 旧版本 (v0.3.x) 用 NTP/HTTP 主动探测服务器拿时间, 但 Mirage 服务器
// 只听代理端口, 永远拿不到 → time_sync 100% 失败 + 探测流量本身就是
// 可识别指纹. 现在改为 v0.4 协议: 每条 pool 连接的 handshake 结束后,
// 服务端通过加密 channel 主动下发一帧 [0x01][version][u64 BE time],
// 客户端解出后写 TIME_OFFSET. 完全 0 外部依赖, 0 指纹.
//
// 实现: src/proxy/mirage_server.rs (server 端发) + src/proxy/pool.rs
// (client 端收 + 调本模块 set_offset_from_server_time).

use std::sync::atomic::{AtomicI64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

// 全局时钟偏移 (秒): server_time = local_time + TIME_OFFSET
static TIME_OFFSET: AtomicI64 = AtomicI64::new(0);

/// 获取经过校正的当前 Unix 秒时间戳.
/// auth token、replay cache 等所有协议层时间运算都用这个, 不要直接
/// SystemTime::now() 否则会绕过同步.
pub fn now_sec() -> u64 {
    let local = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let offset = TIME_OFFSET.load(Ordering::Relaxed);
    (local + offset) as u64
}

/// 客户端从 server 收到 TIME_SYNC 帧后调用, 计算并存储 offset.
/// 防御异常值: offset 绝对值 > 1 天视为攻击/异常, 拒绝.
pub fn set_offset_from_server_time(server_time: u64) {
    let local = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let offset = (server_time as i64) - local;

    if offset.abs() > 86400 {
        tracing::warn!(
            "TIME_SYNC: server offset {}s > 1 day, ignoring (possible attack or system clock corrupt)",
            offset
        );
        return;
    }

    let old = TIME_OFFSET.swap(offset, Ordering::Relaxed);
    if old != offset {
        tracing::info!(
            "TIME_SYNC: offset updated {}s → {}s (Δ {}s) from server's encrypted handshake",
            old, offset, offset - old
        );
    } else {
        tracing::debug!("TIME_SYNC: offset maintained at {}s", offset);
    }
}
