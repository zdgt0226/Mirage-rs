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

/// 服务端出站目标 IP 白名单校验 (防 SSRF)。
///
/// 默认 (allow_local = false) 拒绝:
/// - 回环: 127.0.0.0/8, ::1 (防访问本机管理 API 等内部服务)
/// - 未指定: 0.0.0.0, ::
/// - 链路本地: 169.254.0.0/16 (含云元数据 169.254.169.254), fe80::/10
/// - 组播 / 广播: 224.0.0.0/4, 255.255.255.255, ff00::/8
/// - 云元数据特殊地址: fd00:ec2::254 (AWS IPv6 元数据, 属 ULA), 100.100.100.200 (阿里云元数据, 属 CGNAT)
///
/// 放行原则:
/// - 先把 IPv4 映射的 IPv6 (::ffff:a.b.c.d) 还原成 IPv4 再判断, 防 `::ffff:127.0.0.1` 绕过。
/// - RFC1918 (10/8, 172.16/12, 192.168/16)、其余 ULA (fc00::/7)、其余 CGNAT (100.64.0.0/10) 默认放行 (支持访问局域网)。
/// - allow_local = true 时放开回环与链路本地 (含云元数据), 但组播/广播始终拒绝。
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

    true
}

#[cfg(test)]
mod tests {
    use super::{egress_allowed, join_host_port};

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
        assert!(egress_allowed("10.0.0.1".parse().unwrap(), false));
        assert!(egress_allowed("172.16.0.1".parse().unwrap(), false));
        assert!(egress_allowed("192.168.1.1".parse().unwrap(), false));
        assert!(egress_allowed("192.168.0.254".parse().unwrap(), false));
        assert!(egress_allowed("fd00:1::1".parse().unwrap(), false), "其他 ULA 默认放行");
        assert!(egress_allowed("100.64.0.1".parse().unwrap(), false), "其他 CGNAT 默认放行");
        assert!(egress_allowed("8.8.8.8".parse().unwrap(), false));
        assert!(egress_allowed("1.1.1.1".parse().unwrap(), false));
        assert!(egress_allowed("2606:4700:4700::1111".parse().unwrap(), false));

        // 8. allow_local = true 放行回环/链路本地/云元数据
        assert!(egress_allowed("127.0.0.1".parse().unwrap(), true));
        assert!(egress_allowed("::1".parse().unwrap(), true));
        assert!(egress_allowed("169.254.169.254".parse().unwrap(), true));
        assert!(egress_allowed("fe80::1".parse().unwrap(), true));
        assert!(egress_allowed("fd00:ec2::254".parse().unwrap(), true));
        assert!(egress_allowed("100.100.100.200".parse().unwrap(), true));
    }
}
