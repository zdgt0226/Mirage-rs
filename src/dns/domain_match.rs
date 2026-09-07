//! 类型化域名匹配器 —— DNS 解析规则增强 (fakeip.exclude 等)。
//!
//! 规则字符串支持 Clash 风格前缀 (大小写不敏感):
//!   - `suffix:apple.com` —— 域名后缀 (精确 or 子域, 如 apple.com 及 *.apple.com)。**默认**: 无前缀
//!     的裸串按 suffix 处理 (向后兼容); `*.` / `.` 前缀等价 (`*.apple.com` == `.apple.com` == `apple.com`)。
//!   - `keyword:google`  —— 子串包含 (域名任意位置含该关键字)。
//!   - `regex:.*\.cn$`   —— 正则整串匹配 (RegexSet, 忽略大小写; 非法正则跳过并 WARN)。
//!   - `full:example.com` / `domain:example.com` —— 精确整域匹配。
//!
//! 匹配前域名统一小写 + 去尾点 (FQDN)。任一类型命中即算命中。

use regex::RegexSet;
use std::collections::HashSet;

#[derive(Default)]
pub struct DomainMatcher {
    full: HashSet<String>,
    suffix: Vec<String>,
    keyword: Vec<String>,
    regex: Option<RegexSet>,
}

impl DomainMatcher {
    /// 从规则串列表构建。空列表 → 空匹配器 (恒不命中)。
    pub fn from_rules(rules: Vec<String>) -> Self {
        let mut full = HashSet::new();
        let (mut suffix, mut keyword, mut regex_src) = (Vec::new(), Vec::new(), Vec::new());
        for raw in rules {
            let s = raw.trim();
            if s.is_empty() {
                continue;
            }
            // 拆前缀: 已知类型才当类型, 否则整串按 suffix (裸域名向后兼容; 域名本身不含 ':')。
            let (kind, pat) = match s.split_once(':') {
                Some((k, v)) if matches!(k.trim().to_lowercase().as_str(),
                    "suffix" | "keyword" | "regex" | "full" | "domain") =>
                {
                    (k.trim().to_lowercase(), v.trim())
                }
                _ => ("suffix".to_string(), s),
            };
            match kind.as_str() {
                "keyword" => {
                    let k = pat.to_lowercase();
                    if !k.is_empty() {
                        keyword.push(k);
                    }
                }
                "regex" => {
                    if !pat.is_empty() {
                        regex_src.push(pat.to_string());
                    }
                }
                "full" | "domain" => {
                    let f = pat.trim_end_matches('.').to_lowercase();
                    if !f.is_empty() {
                        full.insert(f);
                    }
                }
                _ => {
                    // suffix: 去 `*.` / `.` 前缀, 小写
                    let d = pat
                        .to_lowercase()
                        .trim_start_matches("*.")
                        .trim_start_matches('.')
                        .to_string();
                    if !d.is_empty() {
                        suffix.push(d);
                    }
                }
            }
        }
        // 编译正则 (忽略大小写); 逐条试编, 跳过非法项 (整体 RegexSet 要求全合法, 故先逐条过滤)。
        let mut valid_regex = Vec::new();
        for r in regex_src {
            match regex::Regex::new(&r) {
                Ok(_) => valid_regex.push(format!("(?i){r}")),
                Err(e) => tracing::warn!("[DNS] 忽略非法 regex 规则 `{}`: {}", r, e),
            }
        }
        let regex = if valid_regex.is_empty() {
            None
        } else {
            RegexSet::new(&valid_regex).ok()
        };
        Self { full, suffix, keyword, regex }
    }

    /// 是否为空 (无任何规则)。
    pub fn is_empty(&self) -> bool {
        self.full.is_empty() && self.suffix.is_empty() && self.keyword.is_empty() && self.regex.is_none()
    }

    /// 规则条数 (供日志)。
    pub fn len(&self) -> usize {
        self.full.len()
            + self.suffix.len()
            + self.keyword.len()
            + self.regex.as_ref().map_or(0, |r| r.len())
    }

    /// 域名是否命中任一规则。域名统一小写 + 去尾点。
    pub fn matches(&self, domain: &str) -> bool {
        if self.is_empty() {
            return false;
        }
        let d = domain.trim_end_matches('.').to_lowercase();
        if self.full.contains(&d) {
            return true;
        }
        if self.suffix.iter().any(|s| d == *s || d.ends_with(&format!(".{s}"))) {
            return true;
        }
        if self.keyword.iter().any(|k| d.contains(k.as_str())) {
            return true;
        }
        if let Some(rs) = &self.regex {
            if rs.is_match(&d) {
                return true;
            }
        }
        false
    }
}

#[cfg(test)]
mod tests {
    use super::DomainMatcher;

    #[test]
    fn empty_never_matches() {
        assert!(!DomainMatcher::from_rules(vec![]).matches("apple.com"));
        assert!(!DomainMatcher::from_rules(vec!["  ".into()]).matches("apple.com"));
    }

    #[test]
    fn suffix_bare_and_wildcard_and_dot() {
        let m = DomainMatcher::from_rules(vec!["Apple.com".into(), "*.lan".into(), ".example.org".into()]);
        assert!(m.matches("apple.com"));
        assert!(m.matches("APPLE.COM"));
        assert!(m.matches("gw.icloud.apple.com"));
        assert!(m.matches("nas.lan"));
        assert!(m.matches("lan"));
        assert!(m.matches("www.example.org"));
        assert!(m.matches("apple.com.")); // FQDN 尾点
        assert!(!m.matches("notapple.com"));
        assert!(!m.matches("apple.com.evil.net")); // 后缀点边界
    }

    #[test]
    fn keyword_substring() {
        let m = DomainMatcher::from_rules(vec!["keyword:google".into()]);
        assert!(m.matches("www.google.com"));
        assert!(m.matches("googlevideo.com"));
        assert!(m.matches("x.googleplex")); // 仅子串, 无点边界要求
        assert!(!m.matches("gogle.com"));
    }

    #[test]
    fn full_exact_only() {
        let m = DomainMatcher::from_rules(vec!["full:example.com".into()]);
        assert!(m.matches("example.com"));
        assert!(!m.matches("www.example.com")); // full 不含子域
    }

    #[test]
    fn regex_ci_and_invalid_skipped() {
        // 一条合法 + 一条非法 (未闭合括号) → 合法生效, 非法跳过不 panic
        let m = DomainMatcher::from_rules(vec![r"regex:.*\.cn$".into(), "regex:(unclosed".into()]);
        assert!(m.matches("baidu.cn"));
        assert!(m.matches("A.B.CN")); // 忽略大小写
        assert!(!m.matches("baidu.com"));
    }

    #[test]
    fn mixed_types() {
        let m = DomainMatcher::from_rules(vec![
            "apple.com".into(),
            "keyword:ads".into(),
            "full:router.lan".into(),
            r"regex:^t\d+\.example$".into(),
        ]);
        assert!(m.matches("cdn.apple.com"));
        assert!(m.matches("doubleclick-ads.net"));
        assert!(m.matches("router.lan"));
        assert!(!m.matches("x.router.lan"));
        assert!(m.matches("t42.example"));
        assert!(!m.matches("clean.io"));
    }
}
