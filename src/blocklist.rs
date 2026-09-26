//! 服务端「屏蔽客户端」名单 (按源 IP)。
//!
//! handshake accept 处查 (被屏蔽 IP 的连接立即关, 省掉所有握手/BPF/brutal 开销); WebUI 服务端
//! Admin/Clients 视图管理 (Block / Unblock)。全局单例, 与 monitor 同风格。
//! 持久化: 纳入 `gui.stats_persist_path` 对应文件 (blocklist 字段, 0600 权限)。
//! 屏蔽与解封操作会立即触发落盘 (`flush_current`), 避免重启后规则丢失。未配置持久化路径时安全降级为内存版。

use std::collections::HashSet;
use std::net::IpAddr;
use std::sync::{LazyLock, RwLock};

static BLOCKED: LazyLock<RwLock<HashSet<IpAddr>>> = LazyLock::new(|| RwLock::new(HashSet::new()));

pub fn block(ip: IpAddr) {
    BLOCKED.write().unwrap_or_else(|e| e.into_inner()).insert(ip);
    crate::monitor::flush_current();
}

pub fn unblock(ip: &IpAddr) {
    BLOCKED.write().unwrap_or_else(|e| e.into_inner()).remove(ip);
    crate::monitor::flush_current();
}

pub fn is_blocked(ip: &IpAddr) -> bool {
    BLOCKED.read().unwrap_or_else(|e| e.into_inner()).contains(ip)
}

/// 当前屏蔽名单 (IP 字符串, 排序稳定展示)。
pub fn list() -> Vec<String> {
    let mut v: Vec<String> = BLOCKED
        .read()
        .unwrap_or_else(|e| e.into_inner())
        .iter()
        .map(|i| i.to_string())
        .collect();
    v.sort();
    v
}

/// 获取当前所有屏蔽 IP (用于持久化序列化, 排序稳定)。
pub fn all_ips() -> Vec<IpAddr> {
    let mut v: Vec<IpAddr> = BLOCKED
        .read()
        .unwrap_or_else(|e| e.into_inner())
        .iter()
        .copied()
        .collect();
    v.sort();
    v
}

/// 批量恢复屏蔽名单 (持久化加载时调用)。
pub fn restore_all(ips: Vec<IpAddr>) {
    let mut lock = BLOCKED.write().unwrap_or_else(|e| e.into_inner());
    *lock = ips.into_iter().collect();
}

/// 清空当前屏蔽名单 (测试与重置用)。
pub fn clear() {
    BLOCKED.write().unwrap_or_else(|e| e.into_inner()).clear();
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::IpAddr;

    #[test]
    fn block_unblock_roundtrip() {
        let ip: IpAddr = "203.0.113.7".parse().unwrap();
        assert!(!is_blocked(&ip));
        block(ip);
        assert!(is_blocked(&ip));
        assert!(list().contains(&"203.0.113.7".to_string()));
        unblock(&ip);
        assert!(!is_blocked(&ip));
        assert!(!list().contains(&"203.0.113.7".to_string()));
    }
}
