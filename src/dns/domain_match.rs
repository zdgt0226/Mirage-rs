//! 类型化域名匹配器 —— DNS 解析规则增强 (fakeip.exclude 等)。
//!
//! 从结构化 [`crate::config::DomainRuleSet`] 构建 (字段命名对齐 `routing.rules`):
//!   - `domain`         —— 精确整域 (sing-box 风格)。
//!   - `domain_suffix`  —— 后缀 (精确 or 子域, 如 apple.com 及 *.apple.com); 接受 `*.` / `.` 前缀写法。
//!   - `domain_keyword` —— 子串包含 (域名任意位置含该关键字)。
//!   - `domain_regex`   —— 正则整串 (RegexSet, 忽略大小写; 非法正则跳过并 WARN)。
//!
//! 匹配前域名统一小写 + 去尾点 (FQDN)。任一类型命中即算命中。

use regex::RegexSet;
use std::collections::HashSet;

#[derive(Default, Debug)]
pub struct DomainMatcher {
    full: HashSet<String>,
    suffix: Vec<String>,
    keyword: Vec<String>,
    regex: Option<RegexSet>,
}

impl DomainMatcher {
    /// 从结构化 [`crate::config::DomainRuleSet`] 构建。全空 → 空匹配器 (恒不命中)。
    pub fn from_ruleset(rs: &crate::config::DomainRuleSet) -> Self {
        Self::from_parts(&rs.domain, &rs.domain_suffix, &rs.domain_keyword, &rs.domain_regex)
    }

    /// 从各匹配类型的原始列表构建 (归一化: 小写、去空; suffix 去 `*.`/`.` 前缀、full 去尾点)。
    pub fn from_parts(exact: &[String], suffix: &[String], keyword: &[String], regex: &[String]) -> Self {
        let full: HashSet<String> = exact
            .iter()
            .map(|s| s.trim().trim_end_matches('.').to_lowercase())
            .filter(|s| !s.is_empty())
            .collect();
        let suffix: Vec<String> = suffix
            .iter()
            .map(|s| s.trim().to_lowercase().trim_start_matches("*.").trim_start_matches('.').to_string())
            .filter(|s| !s.is_empty())
            .collect();
        let keyword: Vec<String> = keyword
            .iter()
            .map(|s| s.trim().to_lowercase())
            .filter(|s| !s.is_empty())
            .collect();
        // 编译正则 (忽略大小写); 逐条试编跳过非法 (RegexSet 要求全合法, 故先逐条过滤)。
        let mut valid_regex = Vec::new();
        for r in regex.iter().map(|s| s.trim()).filter(|s| !s.is_empty()) {
            match regex::Regex::new(r) {
                Ok(_) => valid_regex.push(format!("(?i){r}")),
                Err(e) => tracing::warn!("[DNS] 忽略非法 domain_regex 规则 `{}`: {}", r, e),
            }
        }
        let regex = if valid_regex.is_empty() { None } else { RegexSet::new(&valid_regex).ok() };
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

    // (exact, suffix, keyword, regex) 便捷构造
    fn mk(e: &[&str], s: &[&str], k: &[&str], r: &[&str]) -> DomainMatcher {
        let v = |a: &[&str]| a.iter().map(|x| x.to_string()).collect::<Vec<_>>();
        DomainMatcher::from_parts(&v(e), &v(s), &v(k), &v(r))
    }

    #[test]
    fn empty_never_matches() {
        assert!(!mk(&[], &[], &[], &[]).matches("apple.com"));
        assert!(!mk(&[], &["  "], &[], &[]).matches("apple.com"));
    }

    #[test]
    fn suffix_wildcard_and_dot_and_ci() {
        let m = mk(&[], &["Apple.com", "*.lan", ".example.org"], &[], &[]);
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
        let m = mk(&[], &[], &["google"], &[]);
        assert!(m.matches("www.google.com"));
        assert!(m.matches("googlevideo.com"));
        assert!(!m.matches("gogle.com"));
    }

    #[test]
    fn domain_exact_only() {
        let m = mk(&["example.com"], &[], &[], &[]);
        assert!(m.matches("example.com"));
        assert!(m.matches("EXAMPLE.COM."));
        assert!(!m.matches("www.example.com")); // 精确不含子域
    }

    #[test]
    fn regex_ci_and_invalid_skipped() {
        // 一条合法 + 一条非法 (未闭合括号) → 合法生效, 非法跳过不 panic
        let m = mk(&[], &[], &[], &[r".*\.cn$", "(unclosed"]);
        assert!(m.matches("baidu.cn"));
        assert!(m.matches("A.B.CN")); // 忽略大小写
        assert!(!m.matches("baidu.com"));
    }

    #[test]
    fn mixed_types_via_ruleset() {
        let rs = crate::config::DomainRuleSet {
            domain: vec!["router.lan".into()],
            domain_suffix: vec!["apple.com".into()],
            domain_keyword: vec!["ads".into()],
            domain_regex: vec![r"^t\d+\.example$".into()],
        };
        let m = DomainMatcher::from_ruleset(&rs);
        assert!(m.matches("cdn.apple.com"));
        assert!(m.matches("doubleclick-ads.net"));
        assert!(m.matches("router.lan"));
        assert!(!m.matches("x.router.lan"));
        assert!(m.matches("t42.example"));
        assert!(!m.matches("clean.io"));
    }
}
