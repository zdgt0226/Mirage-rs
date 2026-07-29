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

#[cfg(test)]
mod tests {
    use super::join_host_port;

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
}
