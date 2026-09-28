//! 网络地址小工具。

/// 拼 `host:port`, **IPv6 字面量自动加方括号** —— 裸 v6 直接 `format!("{}:{}")` 会产生
/// 歧义串 (如 `2606::1:443` / `:::443`), 解析/bind/connect 都会失败。
///
/// - v6 字面量 (`2606::1`, `::`, `::1`) → `[2606::1]:443` / `[::]:443`
/// - v4 字面量 / 域名 / 已带括号 → 原样拼 (`1.2.3.4:443`, `example.com:443`)
pub fn join_host_port(host: &str, port: u16) -> String {
    if host.parse::<std::net::Ipv6Addr>().is_ok() {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

/// 为 host 补齐默认端口 (若未显式指定):
/// 规则:
/// 1. `[v6]:port` 原样
/// 2. 能解析为 SocketAddr 的原样
/// 3. 能解析为 IpAddr (含裸 IPv6) 的用 `join_host_port(&ip.to_string(), default_port)`
/// 4. 形如 `name:port` (恰一个冒号且后半是数字) 原样
/// 5. 其余用 `join_host_port(host, default_port)`
pub fn host_with_default_port(host: &str, default_port: u16) -> String {
    if host.starts_with('[') {
        if let Some(rest) = host.strip_prefix('[') {
            if let Some((_v6, port_str)) = rest.split_once("]:") {
                if !port_str.is_empty() && port_str.chars().all(|c| c.is_ascii_digit()) {
                    return host.to_string();
                }
            }
        }
    }
    if host.parse::<std::net::SocketAddr>().is_ok() {
        return host.to_string();
    }
    if let Ok(ip) = host.parse::<std::net::IpAddr>() {
        return join_host_port(&ip.to_string(), default_port);
    }
    if let Some((name, port_str)) = host.split_once(':') {
        if !name.contains(':') && !port_str.is_empty() && port_str.chars().all(|c| c.is_ascii_digit()) {
            return host.to_string();
        }
    }
    join_host_port(host, default_port)
}

/// 从 host:port 或裸 host/IP 中提取主机名/IP 字符串 (用于 SNI 等):
/// - `[v6]:port` 或 `[v6]` → 提取方括号内的 IPv6
/// - 裸 v6 (如 `2606:4700::1`) → 原样返回
/// - `name:port` (恰一个冒号且后半是数字, 如 `example.com:8443`, `127.0.0.1:8443`) → 提取 `name`
/// - 其余 (如 `example.com`) → 原样返回
pub fn extract_hostname(host: &str) -> &str {
    if host.starts_with('[') {
        if let Some(end) = host.find(']') {
            return &host[1..end];
        }
    }
    if let Some((name, port_str)) = host.split_once(':') {
        if !name.contains(':') && !port_str.is_empty() && port_str.chars().all(|c| c.is_ascii_digit()) {
            return name;
        }
    }
    host
}

use std::collections::HashSet;
use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, LazyLock};
use arc_swap::ArcSwap;
use tracing::warn;

static LOCAL_IPS: LazyLock<ArcSwap<HashSet<IpAddr>>> = LazyLock::new(|| {
    ArcSwap::from_pointee(enumerate_local_ips().unwrap_or_else(|e| {
        warn!("枚举本机网络接口地址失败: {e}");
        HashSet::new()
    }))
});

static LOCAL_IPS_UPDATER_STARTED: AtomicBool = AtomicBool::new(false);

#[cfg(test)]
pub static LOCAL_IPS_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// 枚举本机所有网络接口上的 IPv4 与 IPv6 地址。
fn enumerate_local_ips() -> nix::Result<HashSet<IpAddr>> {
    let mut ips = HashSet::new();
    for ifa in nix::ifaddrs::getifaddrs()? {
        if let Some(storage) = ifa.address {
            if let Some(sa) = storage.as_sockaddr_in() {
                ips.insert(IpAddr::V4(sa.ip()));
            }
            if let Some(sa) = storage.as_sockaddr_in6() {
                ips.insert(IpAddr::V6(sa.ip()));
            }
        }
    }
    Ok(ips)
}

/// 刷新进程级本机地址集合。若枚举失败则 warn 并保持旧集合不变。
pub fn refresh_local_ips() {
    match enumerate_local_ips() {
        Ok(ips) => LOCAL_IPS.store(Arc::new(ips)),
        Err(e) => warn!("枚举本机网络接口地址失败: {e}"),
    }
}

/// 启动后台 60s 定期刷新本机地址集合的任务。
/// 启动时立即刷新一次, 之后每 60s 后台刷新。
pub fn start_local_ips_updater() {
    refresh_local_ips();
    if LOCAL_IPS_UPDATER_STARTED.compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst).is_ok() {
        tokio::spawn(async {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(60));
            interval.tick().await; // 跳过首触 (启动时已立即刷新一次)
            loop {
                interval.tick().await;
                refresh_local_ips();
            }
        });
    }
}

/// 检查某个 IP 是否属于本机网卡地址集合。
pub fn is_local_ip(ip: &IpAddr) -> bool {
    LOCAL_IPS.load().contains(ip)
}

#[cfg(test)]
pub fn inject_local_ip_for_test(ip: IpAddr) {
    let mut current = (**LOCAL_IPS.load()).clone();
    current.insert(ip);
    LOCAL_IPS.store(Arc::new(current));
}

#[cfg(test)]
pub fn clear_injected_local_ips_for_test() {
    refresh_local_ips();
}

/// 服务端出站目标 IP 白名单校验 (防 SSRF)。
///
/// 默认 (allow_local = false) 拒绝:
/// - 回环: 127.0.0.0/8, ::1 (防访问本机管理 API 等内部服务)
/// - 未指定: 0.0.0.0, ::
/// - 链路本地: 169.254.0.0/16 (含云元数据 169.254.169.254), fe80::/10
/// - 组播 / 广播: 224.0.0.0/4, 255.255.255.255, ff00::/8
/// - 云元数据特殊地址: fd00:ec2::254 (AWS IPv6 元数据, 属 ULA), 100.100.100.200 (阿里云元数据, 属 CGNAT), 168.63.129.16 (Azure WireServer, 属公网段)
/// - 本机自身网卡地址 (含公网 IP、docker 网桥等由 getifaddrs 枚举得到的所有接口 IP)
///
/// 放行原则:
/// - 先把 IPv4 映射的 IPv6 (::ffff:a.b.c.d) 还原成 IPv4 再判断, 防 `::ffff:127.0.0.1` 绕过。
/// - RFC1918 (10/8, 172.16/12, 192.168/16)、其余 ULA (fc00::/7)、其余 CGNAT (100.64.0.0/10) 默认放行 (支持访问局域网)。
/// - allow_local = true 时放开回环、链路本地 (含云元数据) 与本机自身网卡地址, 但组播/广播始终拒绝。
pub fn egress_allowed(ip: std::net::IpAddr, allow_local: bool) -> bool {
    // 1. 先把 IPv4-mapped IPv6 (::ffff:a.b.c.d) 还原为 IPv4
    let ip = match ip {
        std::net::IpAddr::V6(v6) => {
            if let Some(v4) = v6.to_ipv4_mapped() {
                std::net::IpAddr::V4(v4)
            } else {
                std::net::IpAddr::V6(v6)
            }
        }
        std::net::IpAddr::V4(v4) => std::net::IpAddr::V4(v4),
    };

    // 2. 组播与广播始终拒绝 (非单播目标)
    match ip {
        std::net::IpAddr::V4(v4) => {
            if v4.is_multicast() || v4.is_broadcast() {
                return false;
            }
        }
        std::net::IpAddr::V6(v6) => {
            if v6.is_multicast() {
                return false;
            }
        }
    }

    if allow_local {
        return true;
    }

    // 3. 默认安全模式: 拒绝回环、未指定、链路本地及已知云元数据
    match ip {
        std::net::IpAddr::V4(v4) => {
            if v4.is_loopback() || v4.is_unspecified() || v4.is_link_local() {
                return false;
            }
            // 阿里云元数据地址 100.100.100.200 (属于 CGNAT 100.64.0.0/10)
            if v4 == std::net::Ipv4Addr::new(100, 100, 100, 200) {
                return false;
            }
            // Azure WireServer 168.63.129.16 (属于公网段)
            if v4 == std::net::Ipv4Addr::new(168, 63, 129, 16) {
                return false;
            }
        }
        std::net::IpAddr::V6(v6) => {
            if v6.is_loopback() || v6.is_unspecified() {
                return false;
            }
            // IPv6 链路本地 fe80::/10
            let seg0 = v6.segments()[0];
            if (seg0 & 0xffc0) == 0xfe80 {
                return false;
            }
            // AWS IPv6 元数据地址 fd00:ec2::254 (属于 ULA)
            if v6 == std::net::Ipv6Addr::new(0xfd00, 0xec2, 0, 0, 0, 0, 0, 0x0254) {
                return false;
            }
        }
    }

    // 4. 本机网卡自身地址 (含公网 IP、docker 网桥等): 默认拒绝
    if is_local_ip(&ip) {
        return false;
    }

    true
}

#[cfg(test)]
mod tests {
    use super::{egress_allowed, join_host_port};

    /// 默认策略下应放行 —— 除非该地址恰好是跑测试这台机器的网卡地址 (本机地址恒拒)。
    /// 避免在网关 / 内网机器上因本机就是 192.168.1.1 之类而误挂。
    fn allowed_unless_local(s: &str) -> bool {
        let ip: std::net::IpAddr = s.parse().unwrap();
        egress_allowed(ip, false) || super::is_local_ip(&ip)
    }

    #[test]
    fn brackets_v6_literals() {
        assert_eq!(join_host_port("2606:4700:4700::1111", 443), "[2606:4700:4700::1111]:443");
        assert_eq!(join_host_port("::1", 8443), "[::1]:8443");
        assert_eq!(join_host_port("::", 443), "[::]:443", "服务端 v6 全接口 bind");
    }

    #[test]
    fn passes_v4_and_domain_through() {
        assert_eq!(join_host_port("1.2.3.4", 443), "1.2.3.4:443");
        assert_eq!(join_host_port("example.com", 443), "example.com:443");
        assert_eq!(join_host_port("0.0.0.0", 1080), "0.0.0.0:1080");
    }

    #[test]
    fn already_bracketed_stays_valid() {
        // 已带括号的输入 (parse::<Ipv6Addr> 失败) → 原样, 结果仍是合法 socket 串。
        assert_eq!(join_host_port("[::1]", 443), "[::1]:443");
    }

    #[test]
    fn results_parse_as_socketaddr() {
        // 端到端: 产物必须能 parse 成 SocketAddr (裸 format 的 v6 会在这里挂)。
        use std::net::SocketAddr;
        for (h, p) in [("2606::1", 443u16), ("::1", 80), ("::", 443), ("1.2.3.4", 8443)] {
            let s = join_host_port(h, p);
            assert!(s.parse::<SocketAddr>().is_ok(), "{s} 应能 parse 成 SocketAddr");
        }
    }

    #[test]
    fn test_egress_allowed_categories() {
        // 1. 回环拒绝 (v4 + v6)
        assert!(!egress_allowed("127.0.0.1".parse().unwrap(), false));
        assert!(!egress_allowed("127.12.34.56".parse().unwrap(), false));
        assert!(!egress_allowed("::1".parse().unwrap(), false));

        // 2. IPv4 映射的 IPv6 (::ffff:a.b.c.d) 还原判断
        assert!(!egress_allowed("::ffff:127.0.0.1".parse().unwrap(), false), "映射回环必须拒绝");
        assert!(!egress_allowed("::ffff:169.254.169.254".parse().unwrap(), false), "映射链路本地必须拒绝");
        assert!(egress_allowed("::ffff:8.8.8.8".parse().unwrap(), false), "映射公网应放行");

        // 3. 未指定地址 (0.0.0.0, ::)
        assert!(!egress_allowed("0.0.0.0".parse().unwrap(), false));
        assert!(!egress_allowed("::".parse().unwrap(), false));

        // 4. 链路本地 (169.254.0.0/16, fe80::/10) 及云元数据
        assert!(!egress_allowed("169.254.169.254".parse().unwrap(), false));
        assert!(!egress_allowed("169.254.1.1".parse().unwrap(), false));
        assert!(!egress_allowed("fe80::1".parse().unwrap(), false));
        assert!(!egress_allowed("fe80::dead:beef".parse().unwrap(), false));

        // 5. 特殊云元数据地址: AWS IPv6 (fd00:ec2::254) 与 阿里云 (100.100.100.200)
        assert!(!egress_allowed("fd00:ec2::254".parse().unwrap(), false));
        assert!(!egress_allowed("100.100.100.200".parse().unwrap(), false));

        // 6. 组播与广播始终拒绝 (无论 allow_local 是 true 还是 false)
        for al in [false, true] {
            assert!(!egress_allowed("224.0.0.1".parse().unwrap(), al));
            assert!(!egress_allowed("239.255.255.250".parse().unwrap(), al));
            assert!(!egress_allowed("255.255.255.255".parse().unwrap(), al));
            assert!(!egress_allowed("ff02::1".parse().unwrap(), al));
        }

        // 7. 默认放行: RFC1918 / ULA 其余 / CGNAT 其余 / 正常公网 IP
        assert!(allowed_unless_local("10.0.0.1"));
        assert!(allowed_unless_local("172.16.0.1"));
        assert!(allowed_unless_local("192.168.1.1"));
        assert!(allowed_unless_local("192.168.0.254"));
        assert!(egress_allowed("fd00:1::1".parse().unwrap(), false), "其他 ULA 默认放行");
        assert!(egress_allowed("100.64.0.1".parse().unwrap(), false), "其他 CGNAT 默认放行");
        assert!(allowed_unless_local("8.8.8.8"));
        assert!(allowed_unless_local("1.1.1.1"));
        assert!(allowed_unless_local("2606:4700:4700::1111"));

        // 8. allow_local = true 放行回环/链路本地/云元数据
        assert!(egress_allowed("127.0.0.1".parse().unwrap(), true));
        assert!(egress_allowed("::1".parse().unwrap(), true));
        assert!(egress_allowed("169.254.169.254".parse().unwrap(), true));
        assert!(egress_allowed("fe80::1".parse().unwrap(), true));
        assert!(egress_allowed("fd00:ec2::254".parse().unwrap(), true));
        assert!(egress_allowed("100.100.100.200".parse().unwrap(), true));

        // 9. Azure WireServer 168.63.129.16 (默认拒、allow_local 放行)
        assert!(!egress_allowed("168.63.129.16".parse().unwrap(), false), "Azure WireServer 默认应拒绝");
        assert!(egress_allowed("168.63.129.16".parse().unwrap(), true), "Azure WireServer allow_local 应放行");
        assert!(!egress_allowed("::ffff:168.63.129.16".parse().unwrap(), false), "Azure WireServer 映射版默认应拒绝");
        assert!(egress_allowed("::ffff:168.63.129.16".parse().unwrap(), true), "Azure WireServer 映射版 allow_local 应放行");
    }

    #[test]
    fn test_local_ip_injection_and_egress_filter() {
        let _serial = super::LOCAL_IPS_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let test_ip: std::net::IpAddr = "198.51.100.42".parse().unwrap();
        let mapped_test_ip: std::net::IpAddr = "::ffff:198.51.100.42".parse().unwrap();

        // 注入前: 正常外部 IP 默认放行
        assert!(egress_allowed(test_ip, false), "未注入前应放行");

        // 注入到本机地址集合
        super::inject_local_ip_for_test(test_ip);
        assert!(!egress_allowed(test_ip, false), "本机地址在 allow_local=false 时必须拒绝");
        assert!(egress_allowed(test_ip, true), "本机地址在 allow_local=true 时应放行");
        assert!(!egress_allowed(mapped_test_ip, false), "IPv4-mapped 本机地址在 allow_local=false 时必须拒绝");
        assert!(egress_allowed(mapped_test_ip, true), "IPv4-mapped 本机地址在 allow_local=true 时应放行");

        // 清理注入
        super::clear_injected_local_ips_for_test();
        assert!(egress_allowed(test_ip, false), "清理后应恢复放行");
    }

    #[test]
    fn test_host_with_default_port_and_extract_hostname() {
        use super::{extract_hostname, host_with_default_port};

        // 1. [v6]:port
        assert_eq!(host_with_default_port("[2606:4700::1]:8443", 443), "[2606:4700::1]:8443");
        assert_eq!(extract_hostname("[2606:4700::1]:8443"), "2606:4700::1");

        // 2. [v6] without port
        assert_eq!(host_with_default_port("[2606:4700::1]", 443), "[2606:4700::1]:443");
        assert_eq!(extract_hostname("[2606:4700::1]"), "2606:4700::1");

        // 3. SocketAddr (IPv4 with port)
        assert_eq!(host_with_default_port("127.0.0.1:8443", 443), "127.0.0.1:8443");
        assert_eq!(extract_hostname("127.0.0.1:8443"), "127.0.0.1");

        // 4. Bare IPv6
        assert_eq!(host_with_default_port("2606:4700::1", 443), "[2606:4700::1]:443");
        assert_eq!(extract_hostname("2606:4700::1"), "2606:4700::1");
        assert_eq!(host_with_default_port("::1", 443), "[::1]:443");
        assert_eq!(extract_hostname("::1"), "::1");

        // 5. Bare IPv4
        assert_eq!(host_with_default_port("127.0.0.1", 443), "127.0.0.1:443");
        assert_eq!(extract_hostname("127.0.0.1"), "127.0.0.1");

        // 6. name:port
        assert_eq!(host_with_default_port("example.com:8443", 443), "example.com:8443");
        assert_eq!(extract_hostname("example.com:8443"), "example.com");

        // 7. plain name
        assert_eq!(host_with_default_port("example.com", 443), "example.com:443");
        assert_eq!(extract_hostname("example.com"), "example.com");
    }
}
