//! `mirage://` 节点 URI 的解析。
//!
//! 格式与 `install.sh` 的 `build_node_uri` / `parse_node_uri` 严格对齐:
//! ```text
//! mirage://<url编码密码>@<host>:<port>?sni=<url编码SNI>
//! ```
//! 四项 (密码 / host / port / sni) 缺一不可 —— 少任何一个都组不出可用的 mirage 出站。

use anyhow::{anyhow, Result};

#[derive(Debug, Clone, PartialEq)]
pub struct NodeUri {
    pub password: String,
    pub host: String,
    pub port: u16,
    pub sni: String,
}

/// 百分号解码。`+` **不**当空格 —— 这是 URI 的 query 部分而非
/// `application/x-www-form-urlencoded` 表单, 密码里的 `+` 是字面量, 转义会改掉密码。
fn percent_decode(s: &str) -> Result<String> {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' {
            if i + 2 >= b.len() {
                return Err(anyhow!("百分号转义不完整: ...{}", &s[i..]));
            }
            let hex = std::str::from_utf8(&b[i + 1..i + 3])?;
            let v = u8::from_str_radix(hex, 16)
                .map_err(|_| anyhow!("非法百分号转义: %{}", hex))?;
            out.push(v);
            i += 3;
        } else {
            out.push(b[i]);
            i += 1;
        }
    }
    Ok(String::from_utf8(out)?)
}

impl NodeUri {
    pub fn parse(uri: &str) -> Result<Self> {
        let uri = uri.trim();
        let rest = uri
            .strip_prefix("mirage://")
            .ok_or_else(|| anyhow!("不是 mirage:// 开头的节点 URI"))?;

        // 密码里可能含 '@' 的转义形式, 但未转义的 '@' 只应有分隔符那一个。
        // 用 rsplit_once 以最后一个 '@' 为界, 容忍密码中出现字面 '@'。
        let (pwd_enc, hostport_query) = rest
            .rsplit_once('@')
            .ok_or_else(|| anyhow!("缺少 '@' 分隔符 (格式: mirage://密码@host:port?sni=...)"))?;

        let (hostport, query) = match hostport_query.split_once('?') {
            Some((hp, q)) => (hp, q),
            None => (hostport_query, ""),
        };

        let (host, port_str) = hostport
            .rsplit_once(':')
            .ok_or_else(|| anyhow!("缺少端口 (格式: host:port)"))?;
        let port: u16 = port_str
            .parse()
            .map_err(|_| anyhow!("端口非法: `{port_str}`"))?;
        if port == 0 {
            return Err(anyhow!("端口不能为 0"));
        }

        let mut sni = String::new();
        for pair in query.split('&').filter(|p| !p.is_empty()) {
            if let Some((k, v)) = pair.split_once('=') {
                if k == "sni" {
                    sni = percent_decode(v)?;
                }
            }
        }

        let password = percent_decode(pwd_enc)?;
        if password.is_empty() {
            return Err(anyhow!("密码为空"));
        }
        if host.is_empty() {
            return Err(anyhow!("host 为空"));
        }
        if sni.is_empty() {
            return Err(anyhow!("缺少 sni 参数 (伪装域名, 必须与服务端一致)"));
        }

        Ok(NodeUri { password, host: host.to_string(), port, sni })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_basic() {
        let n = NodeUri::parse("mirage://pass123@1.2.3.4:443?sni=www.apple.com").unwrap();
        assert_eq!(n.password, "pass123");
        assert_eq!(n.host, "1.2.3.4");
        assert_eq!(n.port, 443);
        assert_eq!(n.sni, "www.apple.com");
    }

    #[test]
    fn percent_decodes_password_and_sni() {
        // "p@ss:w/rd" 的百分号编码
        let n = NodeUri::parse("mirage://p%40ss%3Aw%2Frd@h.example:8443?sni=a%2Db.com").unwrap();
        assert_eq!(n.password, "p@ss:w/rd");
        assert_eq!(n.sni, "a-b.com");
    }

    #[test]
    fn plus_is_literal_not_space() {
        // 密码里的 '+' 必须原样保留, 若当成空格会改掉密码导致认证失败
        let n = NodeUri::parse("mirage://a+b@h:1?sni=x.com").unwrap();
        assert_eq!(n.password, "a+b");
    }

    #[test]
    fn domain_host_ok() {
        let n = NodeUri::parse("mirage://p@vps.example.com:9443?sni=x.com").unwrap();
        assert_eq!(n.host, "vps.example.com");
        assert_eq!(n.port, 9443);
    }

    #[test]
    fn rejects_malformed() {
        for bad in [
            "http://p@h:1?sni=x",              // 协议不对
            "mirage://noatsign",               // 无 @
            "mirage://p@hostonly?sni=x",       // 无端口
            "mirage://p@h:notaport?sni=x",     // 端口非数字
            "mirage://p@h:0?sni=x",            // 端口 0
            "mirage://@h:1?sni=x",             // 空密码
            "mirage://p@h:1",                  // 缺 sni
            "mirage://p@h:1?sni=",             // 空 sni
        ] {
            assert!(NodeUri::parse(bad).is_err(), "应拒绝: {bad}");
        }
    }

    #[test]
    fn rejects_bad_percent_escape() {
        assert!(NodeUri::parse("mirage://p%ZZ@h:1?sni=x.com").is_err());
        assert!(NodeUri::parse("mirage://p%4@h:1?sni=x.com").is_err());
    }

    #[test]
    fn tolerates_extra_query_params() {
        // 未来新增参数不应让旧解析器炸掉
        let n = NodeUri::parse("mirage://p@h:1?sni=x.com&future=1").unwrap();
        assert_eq!(n.sni, "x.com");
    }
}
