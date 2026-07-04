//! 透明代理 fake-IP 本地路由的自动管理 (用户无感).
//!
//! v0.4.5-alpha.9: sk_lookup 只在【本地投递路径】的 socket 查找时触发, 而内核
//! 路由决策发生在它之前. fake-IP (如 198.18.0.0/15) 在网关/客户端上默认不是本机
//! 地址:
//!   - 网关: 内核判定为"转发" → 走 ip_forward → 绕过本地投递 → sk_lookup 不运行
//!   - 客户端: 走默认路由发出 → 不回本地投递 → sk_lookup 不运行
//! 两种情况 fake-IP 流量都到不了 sk_lookup, 透明拦截静默失效.
//!
//! 修法: 装一条 `ip route add local <fakeip> dev lo`, 告诉内核 fake-IP 段是本机
//! 可投递的, 包才会进 socket 查找路径触发 sk_lookup → bpf_sk_assign 到 mirage
//! listener. 本模块在 fake-IP 透明代理启用时自动装, 进程退出时清理, 用户无感.
//!
//! 只装 sk_lookup 严格必需的这一条 local 路由. rp_filter 校验的是【源地址】
//! (LAN 客户端合法可达), 不影响 fake-IP 目标; ip_forward + NAT 是直连流量转发的
//! 网关级配置 (与拦截无关), 由用户/install.sh 另行负责.

use std::net::Ipv4Addr;
use std::sync::{Mutex, OnceLock};
use tracing::{info, warn};

fn installed() -> &'static Mutex<Option<(Ipv4Addr, u8)>> {
    static I: OnceLock<Mutex<Option<(Ipv4Addr, u8)>>> = OnceLock::new();
    I.get_or_init(|| Mutex::new(None))
}

/// 幂等安装 fake-IP 本地路由. 用 `ip route replace` (已存在也不报错).
/// 失败仅 warn 不 panic — 装不上透明拦截会静默失效, 但不该拖垮进程.
pub async fn install(net: Ipv4Addr, prefix: u8) {
    let dst = format!("{net}/{prefix}");
    match tokio::process::Command::new("ip")
        .args(["route", "replace", "local", &dst, "dev", "lo"])
        .output()
        .await
    {
        Ok(o) if o.status.success() => {
            *installed().lock().unwrap() = Some((net, prefix));
            info!(
                "Fake-IP transparent route installed: local {} dev lo (sk_lookup interception active)",
                dst
            );
        }
        Ok(o) => warn!(
            "Fake-IP route install failed (rc={:?}): {}. sk_lookup interception WILL NOT WORK — \
             need CAP_NET_ADMIN / root.",
            o.status.code(),
            String::from_utf8_lossy(&o.stderr).trim()
        ),
        Err(e) => warn!(
            "Fake-IP route install: exec `ip` failed: {} (iproute2 installed?)",
            e
        ),
    }
}

/// 进程退出清理. 无安装记录则 no-op. 即使清理失败也无害 (fake-IP 不可路由,
/// 且 mirage 停了 DNS 也不再下发 fake-IP).
pub async fn cleanup() {
    let route = installed().lock().unwrap().take();
    if let Some((net, prefix)) = route {
        let dst = format!("{net}/{prefix}");
        let _ = tokio::process::Command::new("ip")
            .args(["route", "del", "local", &dst, "dev", "lo"])
            .output()
            .await;
        info!("Fake-IP transparent route removed: local {} dev lo", dst);
    }
}
