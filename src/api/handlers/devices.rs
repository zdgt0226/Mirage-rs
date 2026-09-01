//! GET /api/devices — 按发起方 IP 聚合的设备/来源统计。
//! 客户端: LAN 设备 (透明入站的源 IP); 服务端: 连接的客户端 IP。
//! 供 WebUI 客户端 Devices 视图 / 服务端 Clients 视图。
//!
//! 契约 §10 P2: 补 `mac` (best-effort 读 /proc/net/arp, LAN 设备可得) + `hostname` 槽
//! (暂 null —— 无免费可靠源: DHCP 租约/mDNS/反查 PTR 都需额外机制, 前端 null 时回落显示 IP)。

use axum::Json;
use serde_json::{json, Value};

/// 读 /proc/net/arp → ip→mac。best-effort: 读不到/非 Linux 返空; 跳过不完整项 (全 0 MAC)。
fn arp_macs() -> std::collections::HashMap<String, String> {
    let mut m = std::collections::HashMap::new();
    let Ok(content) = std::fs::read_to_string("/proc/net/arp") else {
        return m;
    };
    for line in content.lines().skip(1) {
        // 列: IP address / HW type / Flags / HW address / Mask / Device
        let cols: Vec<&str> = line.split_whitespace().collect();
        if cols.len() >= 4 {
            let (ip, mac) = (cols[0], cols[3]);
            if mac != "00:00:00:00:00:00" {
                m.insert(ip.to_string(), mac.to_string());
            }
        }
    }
    m
}

pub async fn get_devices() -> Json<Value> {
    let arp = arp_macs();
    let devices: Vec<Value> = crate::monitor::device_stats()
        .into_iter()
        .map(|d| {
            json!({
                "ip": d.ip,
                "conns": d.conns,
                "up": d.up,
                "down": d.down,
                "idle_ms": d.idle_ms,
                "mac": arp.get(&d.ip),   // null 若不在 ARP 表
                "hostname": Value::Null, // 需 DHCP/mDNS 源, 暂 null
            })
        })
        .collect();
    Json(json!({ "devices": devices }))
}
