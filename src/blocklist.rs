//! 服务端「屏蔽客户端」名单 (按源 IP)。内存版 —— 重启清零 (真持久化需写 config, 后续再定)。
//!
//! handshake accept 处查 (被屏蔽 IP 的连接立即关, 省掉所有握手/BPF/brutal 开销); WebUI 服务端
//! Admin/Clients 视图管理 (Block / Unblock)。全局单例, 与 monitor 同风格。

use std::collections::HashSet;
use std::net::IpAddr;
use std::sync::{LazyLock, RwLock};

static BLOCKED: LazyLock<RwLock<HashSet<IpAddr>>> = LazyLock::new(|| RwLock::new(HashSet::new()));

pub fn block(ip: IpAddr) {
    BLOCKED.write().unwrap_or_else(|e| e.into_inner()).insert(ip);
}

pub fn unblock(ip: &IpAddr) {
    BLOCKED.write().unwrap_or_else(|e| e.into_inner()).remove(ip);
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
