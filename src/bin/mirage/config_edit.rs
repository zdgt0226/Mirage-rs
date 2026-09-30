//! 交互式配置修改与热重载/重启辅助模块。
//!
//! 提供两层实现:
//! 1. 纯逻辑层 (无 IO, 全部单元测试): 对 `serde_json::Value` 执行结构化增删改与改动分类 (`classify_changes`)。
//! 2. 交互层: 驱动终端菜单循环, 缓存所有修改并在用户确认保存后执行诊断校验、原子写入以及按需热重载/重启。

use std::collections::HashSet;
use std::io::{BufRead, Write};
use serde_json::Value;

// ============================================================================
// 1. 类型定义与特征 (Types & Traits)
// ============================================================================

/// 配置生效执行计划
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ApplyPlan {
    /// 配置未做任何修改
    NoChange,
    /// 仅热重载可覆盖的字段变动 (路由规则/默认出站/用户凭据与限额/Geo更新)
    HotReload,
    /// 包含不可热重载字段变动 (出站节点/入站端口与协议/Tuning核心参数等), 需重启服务
    RestartRequired { reasons: Vec<String> },
}

/// 出站节点摘要 (供列表展示)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutboundSummary {
    pub tag: String,
    pub server: String,
    pub server_port: u16,
    pub camouflage_host: String,
    pub transport: String,
    pub pfs: bool,
    pub brutal_rate_mbps: Option<u64>,
    pub pool_size: Option<u64>,
    pub is_default: bool,
    pub groups: Vec<String>,
    pub password_masked: String,
}

/// 服务端入站摘要 (供列表展示)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InboundSummary {
    pub tag: String,
    pub listen: String,
    pub port: u16,
    pub transport: String,
    pub pfs: bool,
    pub brutal_rate_mbps: Option<u64>,
    pub camouflage_host: String,
    pub user_count: usize,
    pub password_masked: String,
    pub allow_local_targets: bool,
}

/// 多用户条目摘要
#[derive(Debug, Clone, PartialEq)]
pub struct UserSummary {
    pub name: String,
    pub password_masked: String,
    pub rate_limit_kbps: Option<u64>,
    pub quota_gb: Option<f64>,
    pub quota_reset_day: Option<u8>,
}

/// 出站引用关系
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OutboundRef {
    DefaultOutbound,
    Rule { rule_index: usize },
    Group { group_tag: String },
    Underlying { outbound_tag: String },
}

impl std::fmt::Display for OutboundRef {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::DefaultOutbound => write!(f, "routing.default_outbound 默认出站"),
            Self::Rule { rule_index } => write!(f, "routing.rules[{rule_index}] 路由规则"),
            Self::Group { group_tag } => write!(f, "出站组 `{group_tag}`"),
            Self::Underlying { outbound_tag } => write!(f, "出站 `{outbound_tag}` 的 underlying 链式底座"),
        }
    }
}

/// 命令行执行器接口 (用于抽象 systemctl 执行, 便于单元与集成测试注入)
pub trait CommandExecutor {
    fn has_systemctl(&self) -> bool;
    fn execute(&self, cmd: &str, args: &[&str]) -> Result<String, String>;
}

/// 生产环境真实系统命令执行器
pub struct RealCommandExecutor;

impl CommandExecutor for RealCommandExecutor {
    fn has_systemctl(&self) -> bool {
        std::process::Command::new("which")
            .arg("systemctl")
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
            || std::path::Path::new("/bin/systemctl").exists()
            || std::path::Path::new("/usr/bin/systemctl").exists()
    }

    fn execute(&self, cmd: &str, args: &[&str]) -> Result<String, String> {
        let output = std::process::Command::new(cmd)
            .args(args)
            .output()
            .map_err(|e| format!("执行命令 `{cmd}` 失败: {e}"))?;
        let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
        if output.status.success() {
            Ok(stdout)
        } else {
            Err(if !stderr.is_empty() {
                format!("{stderr} (exit code: {:?})", output.status.code())
            } else {
                format!("{stdout} (exit code: {:?})", output.status.code())
            })
        }
    }
}

// ============================================================================
// 2. 基础辅助工具 (Formatting & URL Encoding)
// ============================================================================

/// 口令在终端展示时一律打码 (保留前2后2, 中间4个星号; 短口令全星号)
pub fn mask_password(pwd: &str) -> String {
    // 按字符切 (非字节): 多字节口令 (如中文) 按字节切片会 panic。
    let chars: Vec<char> = pwd.chars().collect();
    if chars.len() <= 4 {
        "****".to_string()
    } else {
        let prefix: String = chars[..2].iter().collect();
        let suffix: String = chars[chars.len() - 2..].iter().collect();
        format!("{}****{}", prefix, suffix)
    }
}

/// 生成 32 位小写十六进制安全随机口令
pub fn generate_random_password() -> String {
    // 口令须用 CSPRNG (rand::fill = ChaCha 线程 RNG, 与 hello_auth 一致); fastrand 非密码学安全。
    let mut bytes = [0u8; 16];
    rand::fill(&mut bytes);
    hex::encode(bytes)
}

/// RFC 3986 百分号编码 (用于构建 mirage:// 链接)
pub fn url_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char);
            }
            _ => {
                use std::fmt::Write;
                let _ = write!(out, "%{:02X}", b);
            }
        }
    }
    out
}

/// 构造 mirage:// 节点链接
pub fn build_mirage_node_uri(host: &str, port: u16, password: &str, camouflage_host: &str) -> String {
    let host_part = if host.contains(':') && !host.starts_with('[') {
        format!("[{}]", host)
    } else {
        host.to_string()
    };
    let scheme = "mirage://";
    format!(
        "{scheme}{}@{}:{}?sni={}",
        url_encode(password),
        host_part,
        port,
        url_encode(camouflage_host)
    )
}

// ============================================================================
// 3. 纯逻辑层: 配置检查与编辑操作 (Pure Logic Layer)
// ============================================================================

/// 获取所有已存在的出站 tag 集合
pub fn get_existing_outbound_tags(root: &Value) -> HashSet<String> {
    root.get("outbounds")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|o| o.get("tag").and_then(|t| t.as_str()).map(str::to_string))
                .collect()
        })
        .unwrap_or_default()
}

/// 列出所有 mirage 类型的出站节点
pub fn list_mirage_outbounds(root: &Value) -> Vec<OutboundSummary> {
    let default_outbound = root
        .get("routing")
        .and_then(|r| r.get("default_outbound"))
        .and_then(|d| d.as_str())
        .unwrap_or("");

    let arr = match root.get("outbounds").and_then(|v| v.as_array()) {
        Some(a) => a,
        None => return Vec::new(),
    };

    // 收集所有组节点成员信息 (tag -> 所属组名列表)
    let mut node_groups: std::collections::HashMap<String, Vec<String>> = std::collections::HashMap::new();
    for o in arr {
        let o_type = o.get("type").and_then(|t| t.as_str()).unwrap_or("");
        let g_tag = o.get("tag").and_then(|t| t.as_str()).unwrap_or("");
        if (o_type == "urltest" || o_type == "selector") && !g_tag.is_empty() {
            if let Some(members) = o.get("outbounds").and_then(|m| m.as_array()) {
                for m in members {
                    if let Some(m_str) = m.as_str() {
                        node_groups
                            .entry(m_str.to_string())
                            .or_default()
                            .push(g_tag.to_string());
                    }
                }
            }
        }
    }

    let mut out = Vec::new();
    for o in arr {
        if o.get("type").and_then(|t| t.as_str()) == Some("mirage") {
            let tag = o.get("tag").and_then(|t| t.as_str()).unwrap_or("").to_string();
            let server = o.get("server").and_then(|s| s.as_str()).unwrap_or("").to_string();
            let server_port = o.get("server_port").and_then(|p| p.as_u64()).unwrap_or(0) as u16;
            let pwd = o.get("password").and_then(|p| p.as_str()).unwrap_or("");
            let camouflage_host = o.get("camouflage_host").and_then(|s| s.as_str()).unwrap_or("").to_string();
            let transport = o.get("transport").and_then(|s| s.as_str()).unwrap_or("tcp").to_string();
            let pfs = o.get("pfs").and_then(|p| p.as_bool()).unwrap_or(false);
            let brutal_rate_mbps = o.get("brutal_rate_mbps").and_then(|b| b.as_u64());
            let pool_size = o.get("pool_size").and_then(|p| p.as_u64());
            let is_default = default_outbound == tag;
            let groups = node_groups.get(&tag).cloned().unwrap_or_default();

            out.push(OutboundSummary {
                tag,
                server,
                server_port,
                camouflage_host,
                transport,
                pfs,
                brutal_rate_mbps,
                pool_size,
                is_default,
                groups,
                password_masked: mask_password(pwd),
            });
        }
    }
    out
}

/// 解析 mirage:// URI 并新增为 mirage 出站
pub fn add_mirage_outbound_from_uri(
    root: &mut Value,
    uri: &str,
    tag: &str,
    group: Option<&str>,
) -> Result<(), String> {
    let tag = tag.trim();
    if tag.is_empty() {
        return Err("出站 tag 不能为空".to_string());
    }
    let existing_tags = get_existing_outbound_tags(root);
    if existing_tags.contains(tag) {
        return Err(format!("出站 tag `{tag}` 已存在于配置中"));
    }

    let node = mirage_rs::node_uri::NodeUri::parse(uri).map_err(|e| format!("URI 解析失败: {e}"))?;

    let node_json = serde_json::json!({
        "type": "mirage",
        "tag": tag,
        "server": node.host,
        "server_port": node.port,
        "password": node.password,
        "camouflage_host": node.sni
    });

    if root.get("outbounds").is_none() {
        root["outbounds"] = serde_json::json!([]);
    }
    let arr = root["outbounds"]
        .as_array_mut()
        .ok_or_else(|| "outbounds 必须为数组".to_string())?;
    arr.push(node_json);

    if let Some(grp) = group {
        add_tag_to_group(root, grp, tag)?;
    }
    Ok(())
}

/// 手动逐项输入新增 mirage 出站
#[allow(clippy::too_many_arguments)]
pub fn add_mirage_outbound_manual(
    root: &mut Value,
    tag: &str,
    server: &str,
    server_port: u16,
    password: &str,
    camouflage_host: &str,
    pfs: bool,
    transport: &str,
    quic_pin: Option<&str>,
    pool_size: Option<u64>,
    brutal_rate_mbps: Option<u64>,
    group: Option<&str>,
) -> Result<(), String> {
    let tag = tag.trim();
    if tag.is_empty() {
        return Err("出站 tag 不能为空".to_string());
    }
    let existing_tags = get_existing_outbound_tags(root);
    if existing_tags.contains(tag) {
        return Err(format!("出站 tag `{tag}` 已存在于配置中"));
    }
    let server = server.trim();
    if server.is_empty() {
        return Err("server 不能为空".to_string());
    }
    if server_port == 0 {
        return Err("server_port 必须在 1-65535 范围内".to_string());
    }
    let password = password.trim();
    if password.is_empty() {
        return Err("password 不能为空".to_string());
    }
    let camouflage_host = camouflage_host.trim();
    if camouflage_host.is_empty() {
        return Err("camouflage_host 不能为空".to_string());
    }
    let transport = transport.trim().to_lowercase();
    if transport != "tcp" && transport != "quic" {
        return Err("transport 必须为 `tcp` 或 `quic`".to_string());
    }
    if transport == "quic" {
        match quic_pin {
            Some(pin) if mirage_rs::config::is_valid_quic_pin(pin) => {}
            _ => return Err("transport=quic 必须提供合法的 43 位 base64url quic_pin 指纹".to_string()),
        }
    }
    if let Some(sz) = pool_size {
        if sz == 0 {
            return Err("pool_size 必须大于 0".to_string());
        }
    }
    if let Some(rate) = brutal_rate_mbps {
        if rate == 0 {
            return Err("brutal_rate_mbps 必须大于 0".to_string());
        }
    }

    let mut obj = serde_json::Map::new();
    obj.insert("type".to_string(), serde_json::json!("mirage"));
    obj.insert("tag".to_string(), serde_json::json!(tag));
    obj.insert("server".to_string(), serde_json::json!(server));
    obj.insert("server_port".to_string(), serde_json::json!(server_port));
    obj.insert("password".to_string(), serde_json::json!(password));
    obj.insert("camouflage_host".to_string(), serde_json::json!(camouflage_host));
    if pfs {
        obj.insert("pfs".to_string(), serde_json::json!(true));
    }
    if transport == "quic" {
        obj.insert("transport".to_string(), serde_json::json!("quic"));
        if let Some(pin) = quic_pin {
            obj.insert("quic_pin".to_string(), serde_json::json!(pin.trim()));
        }
    }
    if let Some(sz) = pool_size {
        obj.insert("pool_size".to_string(), serde_json::json!(sz));
    }
    if let Some(rate) = brutal_rate_mbps {
        obj.insert("brutal_rate_mbps".to_string(), serde_json::json!(rate));
    }

    if root.get("outbounds").is_none() {
        root["outbounds"] = serde_json::json!([]);
    }
    let arr = root["outbounds"]
        .as_array_mut()
        .ok_or_else(|| "outbounds 必须为数组".to_string())?;
    arr.push(Value::Object(obj));

    if let Some(grp) = group {
        add_tag_to_group(root, grp, tag)?;
    }
    Ok(())
}

/// 修改已有 mirage 出站
#[allow(clippy::too_many_arguments)]
pub fn modify_mirage_outbound(
    root: &mut Value,
    tag: &str,
    server: Option<String>,
    server_port: Option<u16>,
    password: Option<String>,
    camouflage_host: Option<String>,
    pfs: Option<bool>,
    transport: Option<String>,
    quic_pin: Option<String>,
    pool_size: Option<Option<u64>>,
    brutal_rate_mbps: Option<Option<u64>>,
) -> Result<(), String> {
    let arr = root
        .get_mut("outbounds")
        .and_then(|v| v.as_array_mut())
        .ok_or_else(|| "配置中缺少 outbounds 数组".to_string())?;

    let node = arr
        .iter_mut()
        .find(|o| o.get("type").and_then(|t| t.as_str()) == Some("mirage") && o.get("tag").and_then(|t| t.as_str()) == Some(tag))
        .ok_or_else(|| format!("未找到 tag 为 `{tag}` 的 mirage 出站"))?;

    let obj = node.as_object_mut().ok_or_else(|| "出站条目不是合法对象".to_string())?;

    if let Some(s) = server {
        let s = s.trim();
        if s.is_empty() { return Err("server 不能为空".to_string()); }
        obj.insert("server".to_string(), serde_json::json!(s));
    }
    if let Some(p) = server_port {
        if p == 0 { return Err("server_port 必须在 1-65535 范围内".to_string()); }
        obj.insert("server_port".to_string(), serde_json::json!(p));
    }
    if let Some(p) = password {
        let p = p.trim();
        if p.is_empty() { return Err("password 不能为空".to_string()); }
        obj.insert("password".to_string(), serde_json::json!(p));
    }
    if let Some(c) = camouflage_host {
        let c = c.trim();
        if c.is_empty() { return Err("camouflage_host 不能为空".to_string()); }
        obj.insert("camouflage_host".to_string(), serde_json::json!(c));
    }
    if let Some(pfs_val) = pfs {
        obj.insert("pfs".to_string(), serde_json::json!(pfs_val));
    }

    let mut final_transport = obj.get("transport").and_then(|t| t.as_str()).unwrap_or("tcp").to_string();
    if let Some(t) = transport {
        let t_norm = t.trim().to_lowercase();
        if t_norm != "tcp" && t_norm != "quic" {
            return Err("transport 必须为 `tcp` 或 `quic`".to_string());
        }
        obj.insert("transport".to_string(), serde_json::json!(t_norm));
        final_transport = t_norm;
    }

    if let Some(pin) = quic_pin {
        let pin = pin.trim();
        if !pin.is_empty() {
            if !mirage_rs::config::is_valid_quic_pin(pin) {
                return Err("quic_pin 格式非法 (须为 43 位 base64url SHA-256 SPKI 指纹)".to_string());
            }
            obj.insert("quic_pin".to_string(), serde_json::json!(pin));
        } else {
            obj.remove("quic_pin");
        }
    }

    if final_transport == "quic" {
        let pin = obj.get("quic_pin").and_then(|p| p.as_str()).unwrap_or("");
        if !mirage_rs::config::is_valid_quic_pin(pin) {
            return Err("transport 为 quic 时必须提供合法的 43 位 base64url quic_pin".to_string());
        }
    } else {
        obj.remove("quic_pin");
    }

    if let Some(ps_opt) = pool_size {
        match ps_opt {
            Some(sz) => {
                if sz == 0 { return Err("pool_size 必须大于 0".to_string()); }
                obj.insert("pool_size".to_string(), serde_json::json!(sz));
            }
            None => { obj.remove("pool_size"); }
        }
    }

    if let Some(rate_opt) = brutal_rate_mbps {
        match rate_opt {
            Some(r) => {
                if r == 0 { return Err("brutal_rate_mbps 必须大于 0".to_string()); }
                obj.insert("brutal_rate_mbps".to_string(), serde_json::json!(r));
            }
            None => { obj.remove("brutal_rate_mbps"); }
        }
    }

    Ok(())
}

/// 检查出站 tag 是否被其它配置项引用
pub fn check_outbound_references(root: &Value, tag: &str) -> Vec<OutboundRef> {
    let mut refs = Vec::new();

    // 1. routing.default_outbound
    if let Some(def) = root.get("routing").and_then(|r| r.get("default_outbound")).and_then(|d| d.as_str()) {
        if def == tag {
            refs.push(OutboundRef::DefaultOutbound);
        }
    }

    // 2. routing.rules[].outbound
    if let Some(rules) = root.get("routing").and_then(|r| r.get("rules")).and_then(|r| r.as_array()) {
        for (i, rule) in rules.iter().enumerate() {
            if rule.get("outbound").and_then(|o| o.as_str()) == Some(tag) {
                refs.push(OutboundRef::Rule { rule_index: i });
            }
        }
    }

    // 3. urltest / selector 组中的 outbounds
    if let Some(arr) = root.get("outbounds").and_then(|v| v.as_array()) {
        for o in arr {
            let o_tag = o.get("tag").and_then(|t| t.as_str()).unwrap_or("");
            if o_tag == tag { continue; }
            let o_type = o.get("type").and_then(|t| t.as_str()).unwrap_or("");
            if o_type == "urltest" || o_type == "selector" {
                if let Some(members) = o.get("outbounds").and_then(|m| m.as_array()) {
                    if members.iter().any(|m| m.as_str() == Some(tag)) {
                        refs.push(OutboundRef::Group { group_tag: o_tag.to_string() });
                    }
                }
            }
            // 4. underlying
            if o.get("underlying").and_then(|u| u.as_str()) == Some(tag) {
                refs.push(OutboundRef::Underlying { outbound_tag: o_tag.to_string() });
            }
        }
    }

    refs
}

/// 删除出站节点。若存在引用且非仅组引用，或 auto_remove_from_groups 为 false，则返回引用错误。
pub fn delete_outbound(
    root: &mut Value,
    tag: &str,
    auto_remove_from_groups: bool,
) -> Result<(), Vec<OutboundRef>> {
    let refs = check_outbound_references(root, tag);
    if !refs.is_empty() {
        let has_blocking = refs.iter().any(|r| !matches!(r, OutboundRef::Group { .. }));
        if has_blocking || !auto_remove_from_groups {
            return Err(refs);
        }
    }

    // 自动从组中移除
    if let Some(arr) = root.get_mut("outbounds").and_then(|v| v.as_array_mut()) {
        for o in arr.iter_mut() {
            let o_type = o.get("type").and_then(|t| t.as_str()).unwrap_or("");
            if o_type == "urltest" || o_type == "selector" {
                if let Some(members) = o.get_mut("outbounds").and_then(|m| m.as_array_mut()) {
                    members.retain(|m| m.as_str() != Some(tag));
                }
            }
        }
    }

    // 移除节点本身
    if let Some(arr) = root.get_mut("outbounds").and_then(|v| v.as_array_mut()) {
        arr.retain(|o| o.get("tag").and_then(|t| t.as_str()) != Some(tag));
    }

    Ok(())
}

/// 将 tag 追加进指定 urltest/selector 组
pub fn add_tag_to_group(root: &mut Value, group_tag: &str, target_tag: &str) -> Result<(), String> {
    let arr = root
        .get_mut("outbounds")
        .and_then(|v| v.as_array_mut())
        .ok_or_else(|| "outbounds 必须为数组".to_string())?;

    let group = arr
        .iter_mut()
        .find(|o| o.get("tag").and_then(|t| t.as_str()) == Some(group_tag))
        .ok_or_else(|| format!("未找到出站组 `{group_tag}`"))?;

    let g_type = group.get("type").and_then(|t| t.as_str()).unwrap_or("");
    if g_type != "urltest" && g_type != "selector" {
        return Err(format!("出站 `{group_tag}` 类型为 `{g_type}`, 不是出站组 (urltest/selector)"));
    }

    if group.get("outbounds").is_none() {
        group["outbounds"] = serde_json::json!([]);
    }
    let members = group["outbounds"]
        .as_array_mut()
        .ok_or_else(|| "组成员 outbounds 必须为数组".to_string())?;
    if !members.iter().any(|m| m.as_str() == Some(target_tag)) {
        members.push(serde_json::json!(target_tag));
    }
    Ok(())
}

/// 修改 routing.default_outbound
pub fn set_default_outbound(root: &mut Value, target_tag: &str) -> Result<(), String> {
    let existing = get_existing_outbound_tags(root);
    if !existing.contains(target_tag) {
        return Err(format!("目标出站 tag `{target_tag}` 在 outbounds 中不存在"));
    }
    if let Some(routing) = root.get_mut("routing").and_then(|r| r.as_object_mut()) {
        routing.insert("default_outbound".to_string(), serde_json::json!(target_tag));
    } else {
        root["routing"] = serde_json::json!({
            "default_outbound": target_tag,
            "rules": []
        });
    }
    Ok(())
}

// ----------------------------------------------------------------------------
// 服务端相关操作 (Server Inbound & Users)
// ----------------------------------------------------------------------------

/// 列出所有 mirage_server 入站
pub fn list_mirage_server_inbounds(root: &Value) -> Vec<InboundSummary> {
    let arr = match root.get("inbounds").and_then(|v| v.as_array()) {
        Some(a) => a,
        None => return Vec::new(),
    };

    let mut out = Vec::new();
    for ib in arr {
        if ib.get("type").and_then(|t| t.as_str()) == Some("mirage_server") {
            let tag = ib.get("tag").and_then(|t| t.as_str()).unwrap_or("").to_string();
            let listen = ib.get("listen").and_then(|l| l.as_str()).unwrap_or("0.0.0.0").to_string();
            let port = ib.get("port").and_then(|p| p.as_u64()).unwrap_or(0) as u16;
            let pwd = ib.get("password").and_then(|p| p.as_str()).unwrap_or("");
            let camouflage_host = ib.get("camouflage_host").and_then(|c| c.as_str()).unwrap_or("").to_string();
            let transport = ib.get("transport").and_then(|t| t.as_str()).unwrap_or("tcp").to_string();
            let pfs = ib.get("pfs").and_then(|p| p.as_bool()).unwrap_or(false);
            let brutal_rate_mbps = ib.get("brutal_rate_mbps").and_then(|b| b.as_u64());
            let allow_local_targets = ib.get("allow_local_targets").and_then(|a| a.as_bool()).unwrap_or(false);
            let user_count = ib.get("users").and_then(|u| u.as_array()).map_or(0, |a| a.len())
                + if !pwd.is_empty() { 1 } else { 0 };

            out.push(InboundSummary {
                tag,
                listen,
                port,
                transport,
                pfs,
                brutal_rate_mbps,
                camouflage_host,
                user_count,
                password_masked: mask_password(pwd),
                allow_local_targets,
            });
        }
    }
    out
}

/// 修改 mirage_server 入站参数
#[allow(clippy::too_many_arguments)]
pub fn modify_mirage_server_inbound(
    root: &mut Value,
    tag: &str,
    port: Option<u16>,
    password: Option<String>,
    camouflage_host: Option<String>,
    brutal_rate_mbps: Option<Option<u64>>,
    pfs: Option<bool>,
    allow_local_targets: Option<bool>,
) -> Result<(), String> {
    let arr = root
        .get_mut("inbounds")
        .and_then(|v| v.as_array_mut())
        .ok_or_else(|| "配置中缺少 inbounds 数组".to_string())?;

    let ib = arr
        .iter_mut()
        .find(|i| i.get("type").and_then(|t| t.as_str()) == Some("mirage_server") && i.get("tag").and_then(|t| t.as_str()) == Some(tag))
        .ok_or_else(|| format!("未找到 tag 为 `{tag}` 的 mirage_server 入站"))?;

    let obj = ib.as_object_mut().ok_or_else(|| "入站条目不是合法对象".to_string())?;

    if let Some(p) = port {
        if p == 0 { return Err("port 必须在 1-65535 范围内".to_string()); }
        obj.insert("port".to_string(), serde_json::json!(p));
    }
    if let Some(p) = password {
        let p = p.trim();
        if p.is_empty() { return Err("password 不能为空".to_string()); }
        obj.insert("password".to_string(), serde_json::json!(p));
    }
    if let Some(c) = camouflage_host {
        let c = c.trim();
        if c.is_empty() { return Err("camouflage_host 不能为空".to_string()); }
        obj.insert("camouflage_host".to_string(), serde_json::json!(c));
    }
    if let Some(rate_opt) = brutal_rate_mbps {
        match rate_opt {
            Some(r) => {
                if r == 0 { return Err("brutal_rate_mbps 必须大于 0".to_string()); }
                obj.insert("brutal_rate_mbps".to_string(), serde_json::json!(r));
            }
            None => { obj.remove("brutal_rate_mbps"); }
        }
    }
    if let Some(pfs_val) = pfs {
        obj.insert("pfs".to_string(), serde_json::json!(pfs_val));
    }
    if let Some(alt) = allow_local_targets {
        obj.insert("allow_local_targets".to_string(), serde_json::json!(alt));
    }

    Ok(())
}

/// 列出入站内的用户
pub fn list_inbound_users(root: &Value, inbound_tag: &str) -> Result<Vec<UserSummary>, String> {
    let arr = root
        .get("inbounds")
        .and_then(|v| v.as_array())
        .ok_or_else(|| "缺少 inbounds 数组".to_string())?;

    let ib = arr
        .iter()
        .find(|i| i.get("tag").and_then(|t| t.as_str()) == Some(inbound_tag))
        .ok_or_else(|| format!("未找到入站 `{inbound_tag}`"))?;

    let mut users = Vec::new();
    if let Some(u_arr) = ib.get("users").and_then(|u| u.as_array()) {
        for u in u_arr {
            let name = u.get("name").and_then(|n| n.as_str()).unwrap_or("").to_string();
            let pwd = u.get("password").and_then(|p| p.as_str()).unwrap_or("");
            let rate_limit_kbps = u.get("rate_limit_kbps").and_then(|r| r.as_u64());
            let quota_gb = u.get("quota_gb").and_then(|q| q.as_f64());
            let quota_reset_day = u.get("quota_reset_day").and_then(|d| d.as_u64()).map(|d| d as u8);

            users.push(UserSummary {
                name,
                password_masked: mask_password(pwd),
                rate_limit_kbps,
                quota_gb,
                quota_reset_day,
            });
        }
    }
    Ok(users)
}

/// 向 mirage_server 入站添加用户
pub fn add_inbound_user(
    root: &mut Value,
    inbound_tag: &str,
    name: &str,
    password: &str,
    rate_limit_kbps: Option<u64>,
    quota_gb: Option<f64>,
    quota_reset_day: Option<u8>,
) -> Result<(), String> {
    let name = name.trim();
    if name.is_empty() {
        return Err("用户名不能为空".to_string());
    }
    let password = password.trim();
    if password.is_empty() {
        return Err("用户密码不能为空".to_string());
    }
    if let Some(kbps) = rate_limit_kbps {
        if kbps == 0 {
            return Err("rate_limit_kbps 必须大于 0".to_string());
        }
    }
    if let Some(quota) = quota_gb {
        if !quota.is_finite() || quota <= 0.0 {
            return Err("quota_gb 必须为有效正数 (>0)".to_string());
        }
    }
    if let Some(day) = quota_reset_day {
        if !(1..=31).contains(&day) {
            return Err("quota_reset_day 必须在 1-31 之间".to_string());
        }
    }

    let arr = root
        .get_mut("inbounds")
        .and_then(|v| v.as_array_mut())
        .ok_or_else(|| "缺少 inbounds 数组".to_string())?;

    let ib = arr
        .iter_mut()
        .find(|i| i.get("tag").and_then(|t| t.as_str()) == Some(inbound_tag))
        .ok_or_else(|| format!("未找到入站 `{inbound_tag}`"))?;

    if ib.get("users").is_none() {
        ib["users"] = serde_json::json!([]);
    }
    let u_arr = ib["users"]
        .as_array_mut()
        .ok_or_else(|| "users 必须为数组".to_string())?;

    if u_arr.iter().any(|u| u.get("name").and_then(|n| n.as_str()) == Some(name)) {
        return Err(format!("用户名 `{name}` 已存在"));
    }

    let mut u_obj = serde_json::Map::new();
    u_obj.insert("name".to_string(), serde_json::json!(name));
    u_obj.insert("password".to_string(), serde_json::json!(password));
    if let Some(kbps) = rate_limit_kbps {
        u_obj.insert("rate_limit_kbps".to_string(), serde_json::json!(kbps));
    }
    if let Some(quota) = quota_gb {
        u_obj.insert("quota_gb".to_string(), serde_json::json!(quota));
    }
    if let Some(day) = quota_reset_day {
        u_obj.insert("quota_reset_day".to_string(), serde_json::json!(day));
    }

    u_arr.push(Value::Object(u_obj));
    Ok(())
}

/// 删除用户
pub fn delete_inbound_user(root: &mut Value, inbound_tag: &str, username: &str) -> Result<(), String> {
    let arr = root
        .get_mut("inbounds")
        .and_then(|v| v.as_array_mut())
        .ok_or_else(|| "缺少 inbounds 数组".to_string())?;

    let ib = arr
        .iter_mut()
        .find(|i| i.get("tag").and_then(|t| t.as_str()) == Some(inbound_tag))
        .ok_or_else(|| format!("未找到入站 `{inbound_tag}`"))?;

    let u_arr = ib
        .get_mut("users")
        .and_then(|u| u.as_array_mut())
        .ok_or_else(|| "该入站未配置任何额外用户".to_string())?;

    let before_len = u_arr.len();
    u_arr.retain(|u| u.get("name").and_then(|n| n.as_str()) != Some(username));
    if u_arr.len() == before_len {
        return Err(format!("未找到用户 `{username}`"));
    }
    Ok(())
}

/// 修改用户参数
pub fn modify_inbound_user(
    root: &mut Value,
    inbound_tag: &str,
    username: &str,
    new_password: Option<String>,
    rate_limit_kbps: Option<Option<u64>>,
    quota_gb: Option<Option<f64>>,
    quota_reset_day: Option<Option<u8>>,
) -> Result<(), String> {
    let arr = root
        .get_mut("inbounds")
        .and_then(|v| v.as_array_mut())
        .ok_or_else(|| "缺少 inbounds 数组".to_string())?;

    let ib = arr
        .iter_mut()
        .find(|i| i.get("tag").and_then(|t| t.as_str()) == Some(inbound_tag))
        .ok_or_else(|| format!("未找到入站 `{inbound_tag}`"))?;

    let u_arr = ib
        .get_mut("users")
        .and_then(|u| u.as_array_mut())
        .ok_or_else(|| "缺少 users 数组".to_string())?;

    let user = u_arr
        .iter_mut()
        .find(|u| u.get("name").and_then(|n| n.as_str()) == Some(username))
        .ok_or_else(|| format!("未找到用户 `{username}`"))?;

    let obj = user.as_object_mut().ok_or_else(|| "用户条目非法".to_string())?;

    if let Some(pwd) = new_password {
        let pwd = pwd.trim();
        if pwd.is_empty() { return Err("密码不能为空".to_string()); }
        obj.insert("password".to_string(), serde_json::json!(pwd));
    }
    if let Some(rl_opt) = rate_limit_kbps {
        match rl_opt {
            Some(kbps) => {
                if kbps == 0 { return Err("rate_limit_kbps 必须大于 0".to_string()); }
                obj.insert("rate_limit_kbps".to_string(), serde_json::json!(kbps));
            }
            None => { obj.remove("rate_limit_kbps"); }
        }
    }
    if let Some(q_opt) = quota_gb {
        match q_opt {
            Some(quota) => {
                if !quota.is_finite() || quota <= 0.0 { return Err("quota_gb 必须为有效正数 (>0)".to_string()); }
                obj.insert("quota_gb".to_string(), serde_json::json!(quota));
            }
            None => { obj.remove("quota_gb"); }
        }
    }
    if let Some(d_opt) = quota_reset_day {
        match d_opt {
            Some(day) => {
                if !(1..=31).contains(&day) { return Err("quota_reset_day 必须在 1-31 之间".to_string()); }
                obj.insert("quota_reset_day".to_string(), serde_json::json!(day));
            }
            None => { obj.remove("quota_reset_day"); }
        }
    }

    Ok(())
}

// ----------------------------------------------------------------------------
// Tuning 操作
// ----------------------------------------------------------------------------

pub fn modify_tuning(
    root: &mut Value,
    tls_padding: Option<bool>,
    cipher_agility: Option<bool>,
) -> Result<(), String> {
    if root.get("tuning").is_none() {
        root["tuning"] = serde_json::json!({});
    }
    let tuning = root
        .get_mut("tuning")
        .and_then(|t| t.as_object_mut())
        .ok_or_else(|| "tuning 必须为对象".to_string())?;

    if let Some(val) = tls_padding {
        tuning.insert("tls_padding".to_string(), serde_json::json!(val));
    }
    if let Some(val) = cipher_agility {
        tuning.insert("cipher_agility".to_string(), serde_json::json!(val));
    }
    Ok(())
}

// ============================================================================
// 4. 改动分类器与差异生成 (Change Classification & Diffing)
// ============================================================================

/// 两个 JSON 对象中取值不同的键 (含仅一侧存在的键), 按键名排序; 非对象按空对象处理。
fn changed_keys(old: &Value, new: &Value) -> Vec<String> {
    let empty = serde_json::Map::new();
    let o = old.as_object().unwrap_or(&empty);
    let n = new.as_object().unwrap_or(&empty);
    let mut keys: Vec<String> = o.keys().chain(n.keys()).filter(|k| o.get(*k) != n.get(*k)).cloned().collect();
    keys.sort();
    keys.dedup();
    keys
}

/// 比较新旧配置, 判定是无需变动、仅热重载生效还是必须重启服务
pub fn classify_changes(old: &Value, new: &Value) -> ApplyPlan {
    if old == new {
        return ApplyPlan::NoChange;
    }

    let mut reasons = Vec::new();

    // 1. 出站 (outbounds): 任何改动均无法热重载 (config_watcher.rs:132 明确说明保留原有 outbounds)
    if old.get("outbounds") != new.get("outbounds") {
        let old_arr = old.get("outbounds").and_then(|v| v.as_array());
        let new_arr = new.get("outbounds").and_then(|v| v.as_array());
        match (old_arr, new_arr) {
            (Some(o), Some(n)) => {
                let old_tags: HashSet<_> = o.iter().filter_map(|x| x.get("tag").and_then(|t| t.as_str())).collect();
                let new_tags: HashSet<_> = n.iter().filter_map(|x| x.get("tag").and_then(|t| t.as_str())).collect();

                for added in new_tags.difference(&old_tags) {
                    reasons.push(format!("新增出站节点/组 `{added}`"));
                }
                for removed in old_tags.difference(&new_tags) {
                    reasons.push(format!("删除出站节点/组 `{removed}`"));
                }
                for common in old_tags.intersection(&new_tags) {
                    let old_item = o.iter().find(|x| x.get("tag").and_then(|t| t.as_str()) == Some(*common));
                    let new_item = n.iter().find(|x| x.get("tag").and_then(|t| t.as_str()) == Some(*common));
                    if old_item != new_item {
                        reasons.push(format!("出站节点/组 `{common}` 参数发生变更"));
                    }
                }
                if reasons.is_empty() {
                    reasons.push("出站列表顺序或结构发生变动".to_string());
                }
            }
            _ => {
                reasons.push("出站列表结构发生变动".to_string());
            }
        }
    }

    // 2. 入站 (inbounds):
    // 能够热重载的仅限于已有 mirage_server 入站的 password 与 users (config_watcher.rs 的 apply_user_config)
    // 其它变动 (如监听端口、传输方式、PFS、伪装站、非 mirage_server 入站) 均需重启
    if old.get("inbounds") != new.get("inbounds") {
        let old_arr = old.get("inbounds").and_then(|v| v.as_array());
        let new_arr = new.get("inbounds").and_then(|v| v.as_array());
        match (old_arr, new_arr) {
            (Some(o), Some(n)) => {
                let old_tags: HashSet<_> = o.iter().filter_map(|x| x.get("tag").and_then(|t| t.as_str())).collect();
                let new_tags: HashSet<_> = n.iter().filter_map(|x| x.get("tag").and_then(|t| t.as_str())).collect();

                for added in new_tags.difference(&old_tags) {
                    reasons.push(format!("新增入站 `{added}` 需重启生效"));
                }
                for removed in old_tags.difference(&new_tags) {
                    reasons.push(format!("删除入站 `{removed}` 需重启以关闭监听端口"));
                }

                for common in old_tags.intersection(&new_tags) {
                    let old_item = o.iter().find(|x| x.get("tag").and_then(|t| t.as_str()) == Some(*common)).unwrap();
                    let new_item = n.iter().find(|x| x.get("tag").and_then(|t| t.as_str()) == Some(*common)).unwrap();

                    if old_item != new_item {
                        let old_type = old_item.get("type").and_then(|t| t.as_str()).unwrap_or("");
                        let new_type = new_item.get("type").and_then(|t| t.as_str()).unwrap_or("");
                        if old_type != new_type {
                            reasons.push(format!("入站 `{common}` 类型变更 (`{old_type}` -> `{new_type}`) 需重启"));
                        } else if old_type == "mirage_server" {
                            // 允许名单: 仅 password / users 由 apply_user_config 热重载; 其余任何字段
                            // (含将来新增字段) 一律视为需重启 —— 宁可多提示重启, 不可漏报。
                            const HOT_KEYS: [&str; 2] = ["password", "users"];
                            for key in changed_keys(old_item, new_item) {
                                if !HOT_KEYS.contains(&key.as_str()) {
                                    reasons.push(format!("mirage_server 入站 `{common}` 的 `{key}` 参数变更需重启生效"));
                                }
                            }
                        } else {
                            reasons.push(format!("入站 `{common}` ({old_type}) 参数发生变动需重启生效"));
                        }
                    }
                }
            }
            _ => {
                reasons.push("入站列表结构发生变动需重启生效".to_string());
            }
        }
    }

    // 3. tuning 调优字段:
    // 仅 geo_sources 与 geo_update_days 由 config_watcher.rs extract_updater_state 热重载
    // cipher_agility / tls_padding / ebpf_mode / dns_tcp_resolver 等均为 startup.rs 启动时应用, 需重启
    if old.get("tuning") != new.get("tuning") {
        // 允许名单: 仅 geo_sources / geo_update_days 热重载, 其余 tuning 字段一律需重启。
        const HOT_KEYS: [&str; 2] = ["geo_sources", "geo_update_days"];
        let empty = Value::Object(serde_json::Map::new());
        let old_t = old.get("tuning").unwrap_or(&empty);
        let new_t = new.get("tuning").unwrap_or(&empty);
        for key in changed_keys(old_t, new_t) {
            if !HOT_KEYS.contains(&key.as_str()) {
                reasons.push(format!("tuning.{key} 参数变更需重启服务生效"));
            }
        }
    }

    // 4. routing: rules, default_outbound, profiles, device_profiles, geo_alias 均能在 build_state 中完整热重载
    // 5. advanced_dns: 在 build_state 中完整热重载
    // 6. 其他启动期根字段: dns (传统dns/fakeip), gui, log_*
    // 允许名单: 根级仅 routing / advanced_dns 热重载 (tuning / inbounds / outbounds 已在上面分项处理);
    // 其余 (dns / fakeip / gui / log_* / 未知字段) 一律需重启。
    const HANDLED_OR_HOT: [&str; 5] = ["routing", "advanced_dns", "tuning", "inbounds", "outbounds"];
    for key in changed_keys(old, new) {
        if !HANDLED_OR_HOT.contains(&key.as_str()) {
            reasons.push(format!("{key} 配置变动需重启服务生效"));
        }
    }

    if reasons.is_empty() {
        ApplyPlan::HotReload
    } else {
        ApplyPlan::RestartRequired { reasons }
    }
}

/// 检查是否存在协议类关键参数改动 (需两端同设)
pub fn has_protocol_changes(old: &Value, new: &Value) -> bool {
    let check_fields = ["pfs", "transport", "tls_padding", "cipher_agility", "quic_obfs", "camouflage_host"];

    let has_in_obj = |obj: &serde_json::Map<String, Value>, other_obj: Option<&serde_json::Map<String, Value>>| -> bool {
        for f in &check_fields {
            let v1 = obj.get(*f);
            let v2 = other_obj.and_then(|o| o.get(*f));
            if v1 != v2 {
                return true;
            }
        }
        false
    };

    // 检查 tuning
    if let Some(t_new) = new.get("tuning").and_then(|v| v.as_object()) {
        if has_in_obj(t_new, old.get("tuning").and_then(|v| v.as_object())) {
            return true;
        }
    }

    // 检查 outbounds
    let old_out = old.get("outbounds").and_then(|v| v.as_array());
    let new_out = new.get("outbounds").and_then(|v| v.as_array());
    if let Some(arr) = new_out {
        for o in arr {
            if let Some(obj) = o.as_object() {
                let tag = obj.get("tag").and_then(|t| t.as_str()).unwrap_or("");
                let old_o = old_out.and_then(|ao| ao.iter().find(|x| x.get("tag").and_then(|t| t.as_str()) == Some(tag)).and_then(|x| x.as_object()));
                // 新增的节点不是"改了协议参数", 只比已存在的同 tag 条目
                if old_o.is_some() && has_in_obj(obj, old_o) {
                    return true;
                }
            }
        }
    }

    // 检查 inbounds
    let old_in = old.get("inbounds").and_then(|v| v.as_array());
    let new_in = new.get("inbounds").and_then(|v| v.as_array());
    if let Some(arr) = new_in {
        for i in arr {
            if let Some(obj) = i.as_object() {
                let tag = obj.get("tag").and_then(|t| t.as_str()).unwrap_or("");
                let old_i = old_in.and_then(|ai| ai.iter().find(|x| x.get("tag").and_then(|t| t.as_str()) == Some(tag)).and_then(|x| x.as_object()));
                if old_i.is_some() && has_in_obj(obj, old_i) {
                    return true;
                }
            }
        }
    }

    false
}

/// 生成人类可读的字段级差异摘要 (口令打码)
pub fn generate_diff(old: &Value, new: &Value) -> Vec<String> {
    let mut diffs = Vec::new();

    // 1. 出站节点变更
    let empty_vec = Vec::new();
    let old_out = old.get("outbounds").and_then(|v| v.as_array()).unwrap_or(&empty_vec);
    let new_out = new.get("outbounds").and_then(|v| v.as_array()).unwrap_or(&empty_vec);

    let old_tags: HashSet<_> = old_out.iter().filter_map(|x| x.get("tag").and_then(|t| t.as_str())).collect();
    let new_tags: HashSet<_> = new_out.iter().filter_map(|x| x.get("tag").and_then(|t| t.as_str())).collect();

    for added in new_tags.difference(&old_tags) {
        if let Some(o) = new_out.iter().find(|x| x.get("tag").and_then(|t| t.as_str()) == Some(*added)) {
            let o_type = o.get("type").and_then(|t| t.as_str()).unwrap_or("unknown");
            diffs.push(format!("+ 新增出站 `{added}` (类型: {o_type})"));
        }
    }
    for removed in old_tags.difference(&new_tags) {
        diffs.push(format!("- 删除出站 `{removed}`"));
    }
    for common in old_tags.intersection(&new_tags) {
        let old_item = old_out.iter().find(|x| x.get("tag").and_then(|t| t.as_str()) == Some(*common)).unwrap();
        let new_item = new_out.iter().find(|x| x.get("tag").and_then(|t| t.as_str()) == Some(*common)).unwrap();
        if old_item != new_item {
            diff_json_object(&format!("出站 `{common}`"), old_item, new_item, &mut diffs);
        }
    }

    // 2. 入站变更
    let old_in = old.get("inbounds").and_then(|v| v.as_array()).unwrap_or(&empty_vec);
    let new_in = new.get("inbounds").and_then(|v| v.as_array()).unwrap_or(&empty_vec);

    let old_in_tags: HashSet<_> = old_in.iter().filter_map(|x| x.get("tag").and_then(|t| t.as_str())).collect();
    let new_in_tags: HashSet<_> = new_in.iter().filter_map(|x| x.get("tag").and_then(|t| t.as_str())).collect();

    for added in new_in_tags.difference(&old_in_tags) {
        diffs.push(format!("+ 新增入站 `{added}`"));
    }
    for removed in old_in_tags.difference(&new_in_tags) {
        diffs.push(format!("- 删除入站 `{removed}`"));
    }
    for common in old_in_tags.intersection(&new_in_tags) {
        let old_item = old_in.iter().find(|x| x.get("tag").and_then(|t| t.as_str()) == Some(*common)).unwrap();
        let new_item = new_in.iter().find(|x| x.get("tag").and_then(|t| t.as_str()) == Some(*common)).unwrap();
        if old_item != new_item {
            diff_inbound_object(common, old_item, new_item, &mut diffs);
        }
    }

    // 3. Routing
    let old_routing = old.get("routing");
    let new_routing = new.get("routing");
    if old_routing != new_routing {
        let old_def = old_routing.and_then(|r| r.get("default_outbound")).and_then(|d| d.as_str()).unwrap_or("");
        let new_def = new_routing.and_then(|r| r.get("default_outbound")).and_then(|d| d.as_str()).unwrap_or("");
        if old_def != new_def {
            diffs.push(format!("~ routing.default_outbound: `{old_def}` -> `{new_def}`"));
        }
        if old_routing.and_then(|r| r.get("rules")) != new_routing.and_then(|r| r.get("rules")) {
            diffs.push("~ routing.rules 规则列表发生变动".to_string());
        }
    }

    // 4. Tuning
    if old.get("tuning") != new.get("tuning") {
        if let (Some(ot), Some(nt)) = (old.get("tuning"), new.get("tuning")) {
            diff_json_object("tuning", ot, nt, &mut diffs);
        } else if old.get("tuning").is_none() && new.get("tuning").is_some() {
            diffs.push("+ 添加 tuning 配置段".to_string());
        } else {
            diffs.push("- 删除 tuning 配置段".to_string());
        }
    }

    diffs
}

fn diff_json_object(prefix: &str, old_val: &Value, new_val: &Value, diffs: &mut Vec<String>) {
    let empty_map = serde_json::Map::new();
    let old_map = old_val.as_object().unwrap_or(&empty_map);
    let new_map = new_val.as_object().unwrap_or(&empty_map);

    let all_keys: HashSet<_> = old_map.keys().chain(new_map.keys()).collect();
    for k in all_keys {
        let v1 = old_map.get(k);
        let v2 = new_map.get(k);
        if v1 != v2 {
            let format_val = |key: &str, val: Option<&Value>| -> String {
                match val {
                    None => "(缺失)".to_string(),
                    Some(Value::String(s)) => {
                        if key.contains("password") {
                            mask_password(s)
                        } else {
                            s.clone()
                        }
                    }
                    Some(other) => other.to_string(),
                }
            };
            diffs.push(format!("~ {prefix}.{k}: {} -> {}", format_val(k, v1), format_val(k, v2)));
        }
    }
}

fn diff_inbound_object(tag: &str, old_val: &Value, new_val: &Value, diffs: &mut Vec<String>) {
    let empty_map = serde_json::Map::new();
    let old_map = old_val.as_object().unwrap_or(&empty_map);
    let new_map = new_val.as_object().unwrap_or(&empty_map);

    let all_keys: HashSet<_> = old_map.keys().chain(new_map.keys()).collect();
    for k in all_keys {
        if k == "users" {
            let empty_u = Vec::new();
            let old_u = old_map.get("users").and_then(|u| u.as_array()).unwrap_or(&empty_u);
            let new_u = new_map.get("users").and_then(|u| u.as_array()).unwrap_or(&empty_u);
            if old_u != new_u {
                let old_names: HashSet<_> = old_u.iter().filter_map(|u| u.get("name").and_then(|n| n.as_str())).collect();
                let new_names: HashSet<_> = new_u.iter().filter_map(|u| u.get("name").and_then(|n| n.as_str())).collect();
                for added in new_names.difference(&old_names) {
                    diffs.push(format!("+ 入站 `{tag}` 新增用户 `{added}`"));
                }
                for removed in old_names.difference(&new_names) {
                    diffs.push(format!("- 入站 `{tag}` 删除用户 `{removed}`"));
                }
                for common in old_names.intersection(&new_names) {
                    let u1 = old_u.iter().find(|u| u.get("name").and_then(|n| n.as_str()) == Some(*common)).unwrap();
                    let u2 = new_u.iter().find(|u| u.get("name").and_then(|n| n.as_str()) == Some(*common)).unwrap();
                    if u1 != u2 {
                        diff_json_object(&format!("入站 `{tag}` 用户 `{common}`"), u1, u2, diffs);
                    }
                }
            }
        } else {
            let v1 = old_map.get(k);
            let v2 = new_map.get(k);
            if v1 != v2 {
                let format_val = |key: &str, val: Option<&Value>| -> String {
                    match val {
                        None => "(缺失)".to_string(),
                        Some(Value::String(s)) => {
                            if key.contains("password") {
                                mask_password(s)
                            } else {
                                s.clone()
                            }
                        }
                        Some(other) => other.to_string(),
                    }
                };
                diffs.push(format!("~ 入站 `{tag}`.{k}: {} -> {}", format_val(k, v1), format_val(k, v2)));
            }
        }
    }
}

// ============================================================================
// 5. 交互层: 菜单循环与执行逻辑 (Interactive Layer)
// ============================================================================

/// 交互层随机生成口令并提示: 终端不显示明文, 保存后可经菜单 9 查看节点链接 (含口令)。
fn random_password_with_hint<W: Write>(writer: &mut W) -> String {
    let _ = writeln!(writer, "  已随机生成口令 (不回显); 保存后可用菜单 9 显示对应节点链接以分发给用户。");
    generate_random_password()
}

fn prompt_line<R: BufRead, W: Write>(reader: &mut R, writer: &mut W, prompt: &str) -> String {
    let _ = write!(writer, "{prompt} ");
    let _ = writer.flush();
    let mut s = String::new();
    match reader.read_line(&mut s) {
        Ok(0) | Err(_) => String::new(),
        Ok(_) => s.trim().to_string(),
    }
}

fn prompt_yes_no<R: BufRead, W: Write>(reader: &mut R, writer: &mut W, prompt: &str, default: bool) -> bool {
    let d = if default { "Y/n" } else { "y/N" };
    let ans = prompt_line(reader, writer, &format!("{prompt} [{d}]:"));
    match ans.chars().next() {
        Some('y' | 'Y') => true,
        Some('n' | 'N') => false,
        _ => default,
    }
}

/// 交互式编辑主会话 (可注入读写器与命令执行器)
pub async fn run_interactive_session<R: BufRead, W: Write, E: CommandExecutor>(
    config_path: &str,
    reader: &mut R,
    writer: &mut W,
    executor: &E,
) -> Result<ApplyPlan, String> {
    let original_content = match std::fs::read_to_string(config_path) {
        Ok(c) => c,
        Err(e) => return Err(format!("读取配置文件 {config_path} 失败: {e}")),
    };

    let original_value: Value = match serde_json::from_str(&original_content) {
        Ok(v) => v,
        Err(e) => return Err(format!("配置文件 {config_path} 不是合法的 JSON 格式: {e}")),
    };

    let mut root = original_value.clone();
    let saved_content = original_content.clone();
    let saved_value = original_value.clone();

    loop {
        let mirage_nodes = list_mirage_outbounds(&root);
        let has_mirage_nodes = !mirage_nodes.is_empty();
        let has_outbounds = root.get("outbounds").and_then(|v| v.as_array()).is_some();
        let mirage_inbounds = list_mirage_server_inbounds(&root);
        let has_server_inbounds = !mirage_inbounds.is_empty();

        writeln!(writer, "\n==================================================").map_err(|e| e.to_string())?;
        writeln!(writer, " Mirage 交互式配置管理: {config_path}").map_err(|e| e.to_string())?;
        writeln!(writer, "==================================================").map_err(|e| e.to_string())?;

        if has_mirage_nodes || has_outbounds {
            writeln!(writer, "【客户端 / 节点】").map_err(|e| e.to_string())?;
            if has_mirage_nodes {
                writeln!(writer, "  1. 列出节点").map_err(|e| e.to_string())?;
            }
            writeln!(writer, "  2. 添加节点 (支持 mirage:// 链接或手动输入)").map_err(|e| e.to_string())?;
            if has_mirage_nodes {
                writeln!(writer, "  3. 修改节点参数").map_err(|e| e.to_string())?;
                writeln!(writer, "  4. 删除节点 (引用检查)").map_err(|e| e.to_string())?;
                writeln!(writer, "  5. 设置默认出站 (routing.default_outbound)").map_err(|e| e.to_string())?;
            }
        }

        if has_server_inbounds {
            writeln!(writer, "【服务端 (mirage_server)】").map_err(|e| e.to_string())?;
            writeln!(writer, "  6. 列出入站").map_err(|e| e.to_string())?;
            writeln!(writer, "  7. 修改入站参数 (端口/口令/伪装站/PFS等)").map_err(|e| e.to_string())?;
            writeln!(writer, "  8. 用户管理 (多用户增删改/限额配置 - 支持热重载)").map_err(|e| e.to_string())?;
            writeln!(writer, "  9. 显示入站或用户的 mirage:// 节点链接").map_err(|e| e.to_string())?;
        }

        writeln!(writer, "【通用】").map_err(|e| e.to_string())?;
        writeln!(writer, " 10. tuning 配置 (tls_padding / cipher_agility 开关)").map_err(|e| e.to_string())?;
        writeln!(writer, " 11. 查看待保存改动").map_err(|e| e.to_string())?;
        writeln!(writer, " 12. 保存并应用").map_err(|e| e.to_string())?;
        writeln!(writer, "  0. 退出").map_err(|e| e.to_string())?;

        let choice = prompt_line(reader, writer, "请选择操作 [0-12]:");
        if choice.is_empty() {
            // EOF 优雅退出
            break;
        }

        match choice.as_str() {
            "1" if has_mirage_nodes => {
                writeln!(writer, "\n--- 现存 Mirage 出站节点列表 ---").map_err(|e| e.to_string())?;
                for (i, node) in mirage_nodes.iter().enumerate() {
                    let dflt_str = if node.is_default { " (★ 默认出站)" } else { "" };
                    let grp_str = if !node.groups.is_empty() {
                        format!(" [所属组: {}]", node.groups.join(", "))
                    } else {
                        String::new()
                    };
                    let brutal_str = node.brutal_rate_mbps.map_or("关".to_string(), |r| format!("{r}Mbps"));
                    let pool_str = node.pool_size.map_or("-".to_string(), |p| p.to_string());
                    writeln!(
                        writer,
                        "[{}] `{}` -> {}:{} | 伪装: {} | 传输: {} | PFS: {} | Brutal: {} | 连接池: {}{}{}\n     口令: {}",
                        i + 1,
                        node.tag,
                        node.server,
                        node.server_port,
                        node.camouflage_host,
                        node.transport,
                        if node.pfs { "开" } else { "关" },
                        brutal_str,
                        pool_str,
                        dflt_str,
                        grp_str,
                        node.password_masked
                    ).map_err(|e| e.to_string())?;
                }
            }
            "2" if has_mirage_nodes || has_outbounds => {
                writeln!(writer, "\n添加节点方式:").map_err(|e| e.to_string())?;
                writeln!(writer, "  1. 粘贴 mirage:// 链接 (推荐)").map_err(|e| e.to_string())?;
                writeln!(writer, "  2. 逐项手动输入").map_err(|e| e.to_string())?;
                let method = prompt_line(reader, writer, "选择方式 [1]:");
                let (new_tag, need_probe) = if method == "2" {
                    let tag = prompt_line(reader, writer, "出站 tag:");
                    let server = prompt_line(reader, writer, "服务器地址 (域名或 IP):");
                    let port_str = prompt_line(reader, writer, "服务器端口 [443]:");
                    let port = if port_str.is_empty() { 443 } else { port_str.parse::<u16>().unwrap_or(0) };
                    // 客户端节点口令必须与服务端一致, 随机生成无意义; 留空由 add_mirage_outbound_manual 拒绝。
                    let final_pwd = prompt_line(reader, writer, "密码 (须与服务端一致):");
                    let camouflage_host = prompt_line(reader, writer, "伪装域名 (SNI) [www.apple.com]:");
                    let final_cam = if camouflage_host.is_empty() { "www.apple.com".to_string() } else { camouflage_host };
                    let pfs = prompt_yes_no(reader, writer, "开启前向保密 (PFS)？", false);
                    let transport = prompt_line(reader, writer, "底层传输方式 (tcp/quic) [tcp]:");
                    let final_trans = if transport.is_empty() { "tcp" } else { transport.as_str() };
                    let quic_pin = if final_trans == "quic" {
                        Some(prompt_line(reader, writer, "QUIC SPKI 指纹 (quic_pin, 43位):"))
                    } else {
                        None
                    };
                    let pool_str = prompt_line(reader, writer, "连接池大小 (pool_size, 留空默认):");
                    let pool_size = pool_str.parse::<u64>().ok();
                    let brutal_str = prompt_line(reader, writer, "下载限速速率 (brutal_rate_mbps, 留空默认):");
                    let brutal_rate_mbps = brutal_str.parse::<u64>().ok();

                    let grp_prompt = prompt_line(reader, writer, "加入已有出站组 (如 auto / selector, 留空不加):");
                    let group = if grp_prompt.is_empty() { None } else { Some(grp_prompt.as_str()) };

                    match add_mirage_outbound_manual(
                        &mut root,
                        &tag,
                        &server,
                        port,
                        &final_pwd,
                        &final_cam,
                        pfs,
                        final_trans,
                        quic_pin.as_deref(),
                        pool_size,
                        brutal_rate_mbps,
                        group,
                    ) {
                        Ok(_) => {
                            writeln!(writer, "✓ 节点 `{tag}` 已添加。").map_err(|e| e.to_string())?;
                            (Some((tag, server, port, final_pwd, final_cam, final_trans.to_string())), true)
                        }
                        Err(e) => {
                            writeln!(writer, "✗ 添加失败: {e}").map_err(|e| e.to_string())?;
                            (None, false)
                        }
                    }
                } else {
                    let uri = prompt_line(reader, writer, "请输入 mirage:// 链接:");
                    let tag = prompt_line(reader, writer, "请输入该节点的出站 tag:");
                    let grp_prompt = prompt_line(reader, writer, "加入已有出站组 (如 auto / selector, 留空不加):");
                    let group = if grp_prompt.is_empty() { None } else { Some(grp_prompt.as_str()) };

                    match add_mirage_outbound_from_uri(&mut root, &uri, &tag, group) {
                        Ok(_) => {
                            writeln!(writer, "✓ 节点 `{tag}` 已添加。").map_err(|e| e.to_string())?;
                            let parsed = mirage_rs::node_uri::NodeUri::parse(&uri).ok();
                            if let Some(n) = parsed {
                                (Some((tag, n.host, n.port, n.password, n.sni, "tcp".to_string())), true)
                            } else {
                                (None, false)
                            }
                        }
                        Err(e) => {
                            writeln!(writer, "✗ 添加失败: {e}").map_err(|e| e.to_string())?;
                            (None, false)
                        }
                    }
                };

                if need_probe {
                    if let Some((tag, host, port, pwd, sni, trans)) = new_tag {
                        if trans == "tcp" && prompt_yes_no(reader, writer, &format!("是否立即测活节点 `{tag}`？"), false) {
                            write!(writer, "正在测试节点连接性 ... ").map_err(|e| e.to_string())?;
                            let _ = writer.flush();
                            match mirage_rs::proxy::probe::probe_mirage(&host, port, &pwd, &sni, 5, None).await {
                                mirage_rs::proxy::probe::ProbeOutcome::Ok { handshake_ms, .. } => {
                                    writeln!(writer, "✓ 可用 (握手+认证成功: {handshake_ms}ms)").map_err(|e| e.to_string())?;
                                }
                                mirage_rs::proxy::probe::ProbeOutcome::Unconfirmed { note, .. } => {
                                    writeln!(writer, "⚠ 可达但未完全确认: {note}").map_err(|e| e.to_string())?;
                                }
                                mirage_rs::proxy::probe::ProbeOutcome::Fail(err) => {
                                    writeln!(writer, "✗ 探测失败: {err}").map_err(|e| e.to_string())?;
                                }
                            }
                        }
                    }
                }
            }
            "3" if has_mirage_nodes => {
                let tag = prompt_line(reader, writer, "请输入要修改的节点 tag:");
                let node = mirage_nodes.iter().find(|n| n.tag == tag);
                let node = match node {
                    Some(n) => n,
                    None => {
                        writeln!(writer, "✗ 未找到 tag 为 `{tag}` 的节点").map_err(|e| e.to_string())?;
                        continue;
                    }
                };

                writeln!(writer, "提示: 直接回车保留当前原值。").map_err(|e| e.to_string())?;
                let s_str = prompt_line(reader, writer, &format!("server [{}]:", node.server));
                let server = if s_str.is_empty() { None } else { Some(s_str) };

                let p_str = prompt_line(reader, writer, &format!("server_port [{}]:", node.server_port));
                let server_port = if p_str.is_empty() { None } else { p_str.parse::<u16>().ok() };

                // 客户端节点口令须与服务端一致, 不提供随机生成。
                let pwd_str = prompt_line(reader, writer, &format!("password (须与服务端一致) [{}]:", node.password_masked));
                let password = if pwd_str.is_empty() { None } else { Some(pwd_str) };

                let c_str = prompt_line(reader, writer, &format!("camouflage_host [{}]:", node.camouflage_host));
                let camouflage_host = if c_str.is_empty() { None } else { Some(c_str) };

                let pfs_curr = if node.pfs { "开" } else { "关" };
                let pfs_str = prompt_line(reader, writer, &format!("pfs [当前: {}, y=开, n=关, 回车保持]:", pfs_curr));
                let pfs = match pfs_str.chars().next() {
                    Some('y' | 'Y') => Some(true),
                    Some('n' | 'N') => Some(false),
                    _ => None,
                };

                let t_str = prompt_line(reader, writer, &format!("transport [{}]:", node.transport));
                let transport = if t_str.is_empty() { None } else { Some(t_str) };

                let quic_pin = if transport.as_deref() == Some("quic") || (transport.is_none() && node.transport == "quic") {
                    let pin_str = prompt_line(reader, writer, "quic_pin (43位 SPKI 指纹, 留空保持):");
                    if pin_str.is_empty() { None } else { Some(pin_str) }
                } else {
                    None
                };

                let pool_curr = node.pool_size.map_or("未设置".to_string(), |v| v.to_string());
                let ps_str = prompt_line(reader, writer, &format!("pool_size [当前: {}, 输入 0 清除, 回车保持]:", pool_curr));
                let pool_size = if ps_str.is_empty() {
                    None
                } else if ps_str == "0" {
                    Some(None)
                } else {
                    ps_str.parse::<u64>().ok().map(Some)
                };

                let brutal_curr = node.brutal_rate_mbps.map_or("未设置".to_string(), |v| format!("{v}Mbps"));
                let br_str = prompt_line(reader, writer, &format!("brutal_rate_mbps [当前: {}, 输入 0 清除, 回车保持]:", brutal_curr));
                let brutal_rate_mbps = if br_str.is_empty() {
                    None
                } else if br_str == "0" {
                    Some(None)
                } else {
                    br_str.parse::<u64>().ok().map(Some)
                };

                match modify_mirage_outbound(
                    &mut root,
                    &tag,
                    server,
                    server_port,
                    password,
                    camouflage_host,
                    pfs,
                    transport,
                    quic_pin,
                    pool_size,
                    brutal_rate_mbps,
                ) {
                    Ok(_) => writeln!(writer, "✓ 节点 `{tag}` 已更新。").map_err(|e| e.to_string())?,
                    Err(e) => writeln!(writer, "✗ 修改失败: {e}").map_err(|e| e.to_string())?,
                }
            }
            "4" if has_mirage_nodes => {
                let tag = prompt_line(reader, writer, "请输入要删除的节点 tag:");
                let refs = check_outbound_references(&root, &tag);
                if !refs.is_empty() {
                    writeln!(writer, "⚠ 节点 `{tag}` 被以下配置引用:").map_err(|e| e.to_string())?;
                    for r in &refs {
                        writeln!(writer, "  · {r}").map_err(|e| e.to_string())?;
                    }

                    if refs.iter().any(|r| matches!(r, OutboundRef::DefaultOutbound)) {
                        writeln!(writer, "由于该节点是全局默认出站，必须先选定新的默认出站才能删除。").map_err(|e| e.to_string())?;
                        let other_tags: Vec<_> = mirage_nodes.iter().filter(|n| n.tag != tag).map(|n| n.tag.clone()).collect();
                        if other_tags.is_empty() {
                            writeln!(writer, "✗ 没有其它可用出站，无法删除唯一出站。").map_err(|e| e.to_string())?;
                            continue;
                        }
                        writeln!(writer, "可用候选出站: {}", other_tags.join(", ")).map_err(|e| e.to_string())?;
                        let new_def = prompt_line(reader, writer, "请输入新的默认出站 tag:");
                        if let Err(e) = set_default_outbound(&mut root, &new_def) {
                            writeln!(writer, "✗ 设置新默认出站失败: {e}，放弃删除").map_err(|e| e.to_string())?;
                            continue;
                        }
                        writeln!(writer, "✓ 默认出站已更新为 `{new_def}`。").map_err(|e| e.to_string())?;
                    }

                    // 重新检查引用
                    let remaining_refs = check_outbound_references(&root, &tag);
                    let non_group = remaining_refs.iter().any(|r| !matches!(r, OutboundRef::Group { .. }));
                    if non_group {
                        writeln!(writer, "✗ 该节点仍被规则或链式底座引用，请先修改对应规则后重试。").map_err(|e| e.to_string())?;
                        continue;
                    }

                    if prompt_yes_no(reader, writer, "是否确认从所属出站组中一并移除并删除该节点？", true) {
                        if let Err(e) = delete_outbound(&mut root, &tag, true) {
                            writeln!(writer, "✗ 删除失败: {e:?}").map_err(|e| e.to_string())?;
                        } else {
                            writeln!(writer, "✓ 节点 `{tag}` 已从配置中删除。").map_err(|e| e.to_string())?;
                        }
                    } else {
                        writeln!(writer, "操作已取消。").map_err(|e| e.to_string())?;
                    }
                } else if prompt_yes_no(reader, writer, &format!("确认删除节点 `{tag}`？"), false) {
                    if let Err(e) = delete_outbound(&mut root, &tag, false) {
                        writeln!(writer, "✗ 删除失败: {e:?}").map_err(|e| e.to_string())?;
                    } else {
                        writeln!(writer, "✓ 节点 `{tag}` 已删除。").map_err(|e| e.to_string())?;
                    }
                }
            }
            "5" if has_mirage_nodes => {
                let tags = get_existing_outbound_tags(&root);
                let cur = root.get("routing").and_then(|r| r.get("default_outbound")).and_then(|d| d.as_str()).unwrap_or("");
                writeln!(writer, "现有所有出站/组 tag: {}", tags.into_iter().collect::<Vec<_>>().join(", ")).map_err(|e| e.to_string())?;
                writeln!(writer, "当前默认出站: `{cur}`").map_err(|e| e.to_string())?;
                let new_def = prompt_line(reader, writer, "请输入要设为默认出站的 tag:");
                if !new_def.is_empty() {
                    match set_default_outbound(&mut root, &new_def) {
                        Ok(_) => writeln!(writer, "✓ 默认出站已更新为 `{new_def}`。").map_err(|e| e.to_string())?,
                        Err(e) => writeln!(writer, "✗ 设置失败: {e}").map_err(|e| e.to_string())?,
                    }
                }
            }
            "6" if has_server_inbounds => {
                writeln!(writer, "\n--- mirage_server 入站列表 ---").map_err(|e| e.to_string())?;
                for (i, ib) in mirage_inbounds.iter().enumerate() {
                    let brutal_str = ib.brutal_rate_mbps.map_or("关".to_string(), |r| format!("{r}Mbps"));
                    writeln!(
                        writer,
                        "[{}] `{}` -> {}:{} | 伪装: {} | 传输: {} | PFS: {} | Brutal: {} | 用户数: {} | 本地目标: {}\n     主口令: {}",
                        i + 1,
                        ib.tag,
                        ib.listen,
                        ib.port,
                        ib.camouflage_host,
                        ib.transport,
                        if ib.pfs { "开" } else { "关" },
                        brutal_str,
                        ib.user_count,
                        if ib.allow_local_targets { "允许" } else { "阻止" },
                        ib.password_masked
                    ).map_err(|e| e.to_string())?;
                }
            }
            "7" if has_server_inbounds => {
                let tag = prompt_line(reader, writer, "请输入要修改的入站 tag:");
                let ib = mirage_inbounds.iter().find(|i| i.tag == tag);
                let ib = match ib {
                    Some(i) => i,
                    None => {
                        writeln!(writer, "✗ 未找到 tag 为 `{tag}` 的入站").map_err(|e| e.to_string())?;
                        continue;
                    }
                };

                writeln!(writer, "提示: 直接回车保留当前原值。").map_err(|e| e.to_string())?;
                let p_str = prompt_line(reader, writer, &format!("port [{}]:", ib.port));
                let port = if p_str.is_empty() { None } else { p_str.parse::<u16>().ok() };

                let pwd_str = prompt_line(reader, writer, &format!("主口令 [{} / 输入 r 随机生成 32 字符 hex]:", ib.password_masked));
                let password = if pwd_str.is_empty() {
                    None
                } else if pwd_str == "r" || pwd_str == "random" {
                    Some(random_password_with_hint(writer))
                } else {
                    Some(pwd_str)
                };

                let c_str = prompt_line(reader, writer, &format!("camouflage_host [{}]:", ib.camouflage_host));
                let camouflage_host = if c_str.is_empty() { None } else { Some(c_str) };

                let brutal_curr = ib.brutal_rate_mbps.map_or("未设置".to_string(), |v| format!("{v}Mbps"));
                let br_str = prompt_line(reader, writer, &format!("brutal_rate_mbps [当前: {}, 输入 0 清除, 回车保持]:", brutal_curr));
                let brutal_rate_mbps = if br_str.is_empty() {
                    None
                } else if br_str == "0" {
                    Some(None)
                } else {
                    br_str.parse::<u64>().ok().map(Some)
                };

                let pfs_curr = if ib.pfs { "开" } else { "关" };
                let pfs_str = prompt_line(reader, writer, &format!("pfs [当前: {}, y=开, n=关, 回车保持]:", pfs_curr));
                let pfs = match pfs_str.chars().next() {
                    Some('y' | 'Y') => Some(true),
                    Some('n' | 'N') => Some(false),
                    _ => None,
                };

                let alt_curr = if ib.allow_local_targets { "允许" } else { "阻止" };
                let alt_str = prompt_line(reader, writer, &format!("allow_local_targets (直连回环与局域网) [当前: {}, y=允许, n=阻止, 回车保持]:", alt_curr));
                let allow_local_targets = match alt_str.chars().next() {
                    Some('y' | 'Y') => Some(true),
                    Some('n' | 'N') => Some(false),
                    _ => None,
                };

                match modify_mirage_server_inbound(&mut root, &tag, port, password, camouflage_host, brutal_rate_mbps, pfs, allow_local_targets) {
                    Ok(_) => writeln!(writer, "✓ 入站 `{tag}` 参数已更新。").map_err(|e| e.to_string())?,
                    Err(e) => writeln!(writer, "✗ 修改失败: {e}").map_err(|e| e.to_string())?,
                }
            }
            "8" if has_server_inbounds => {
                let tag = if mirage_inbounds.len() == 1 {
                    mirage_inbounds[0].tag.clone()
                } else {
                    prompt_line(reader, writer, "请输入入站 tag:")
                };

                writeln!(writer, "\n--- 用户管理 ({tag}) ---").map_err(|e| e.to_string())?;
                writeln!(writer, "  1. 列出用户").map_err(|e| e.to_string())?;
                writeln!(writer, "  2. 添加用户").map_err(|e| e.to_string())?;
                writeln!(writer, "  3. 删除用户").map_err(|e| e.to_string())?;
                writeln!(writer, "  4. 修改用户 (口令/限速/限额)").map_err(|e| e.to_string())?;
                writeln!(writer, "  0. 返回主菜单").map_err(|e| e.to_string())?;

                let sub_choice = prompt_line(reader, writer, "请选择操作 [0-4]:");
                match sub_choice.as_str() {
                    "1" => {
                        let users = list_inbound_users(&root, &tag).unwrap_or_default();
                        if users.is_empty() {
                            writeln!(writer, "(该入站除主口令外未配置额外独立用户)").map_err(|e| e.to_string())?;
                        } else {
                            for (i, u) in users.iter().enumerate() {
                                let rl = u.rate_limit_kbps.map_or("无限速".to_string(), |r| format!("{r}kbps"));
                                let quota = u.quota_gb.map_or("无限额".to_string(), |q| format!("{q}GB"));
                                let reset = u.quota_reset_day.map_or("-".to_string(), |d| format!("每月{d}日重置"));
                                writeln!(writer, "[{}] 用户名: `{}` | 口令: {} | 限速: {} | 配额: {} ({})", i + 1, u.name, u.password_masked, rl, quota, reset).map_err(|e| e.to_string())?;
                            }
                        }
                    }
                    "2" => {
                        let name = prompt_line(reader, writer, "用户名:");
                        let pwd = prompt_line(reader, writer, "用户密码 (留空随机生成):");
                        let final_pwd = if pwd.is_empty() { random_password_with_hint(writer) } else { pwd };
                        let rl_str = prompt_line(reader, writer, "限速速率 kbps (留空无限速):");
                        let rate_limit_kbps = rl_str.parse::<u64>().ok();
                        let q_str = prompt_line(reader, writer, "月度流量配额 GB (如 50.0, 留空无限额):");
                        let quota_gb = q_str.parse::<f64>().ok();
                        let d_str = prompt_line(reader, writer, "每月配额重置日 (1-31, 留空默认1日):");
                        let quota_reset_day = d_str.parse::<u8>().ok();

                        match add_inbound_user(&mut root, &tag, &name, &final_pwd, rate_limit_kbps, quota_gb, quota_reset_day) {
                            Ok(_) => writeln!(writer, "✓ 用户 `{name}` 已添加。").map_err(|e| e.to_string())?,
                            Err(e) => writeln!(writer, "✗ 添加用户失败: {e}").map_err(|e| e.to_string())?,
                        }
                    }
                    "3" => {
                        let name = prompt_line(reader, writer, "要删除的用户名:");
                        match delete_inbound_user(&mut root, &tag, &name) {
                            Ok(_) => writeln!(writer, "✓ 用户 `{name}` 已删除。").map_err(|e| e.to_string())?,
                            Err(e) => writeln!(writer, "✗ 删除失败: {e}").map_err(|e| e.to_string())?,
                        }
                    }
                    "4" => {
                        let name = prompt_line(reader, writer, "要修改的用户名:");
                        let pwd_str = prompt_line(reader, writer, "新密码 (留空保持原值, 输入 r 随机生成):");
                        let new_pwd = if pwd_str.is_empty() {
                            None
                        } else if pwd_str == "r" || pwd_str == "random" {
                            Some(random_password_with_hint(writer))
                        } else {
                            Some(pwd_str)
                        };

                        let rl_str = prompt_line(reader, writer, "限速 kbps (回车保持, 输入 0 取消限速):");
                        let rate_limit_kbps = if rl_str.is_empty() {
                            None
                        } else if rl_str == "0" {
                            Some(None)
                        } else {
                            rl_str.parse::<u64>().ok().map(Some)
                        };

                        let q_str = prompt_line(reader, writer, "配额 GB (回车保持, 输入 0 取消限额):");
                        let quota_gb = if q_str.is_empty() {
                            None
                        } else if q_str == "0" {
                            Some(None)
                        } else {
                            q_str.parse::<f64>().ok().map(Some)
                        };

                        let d_str = prompt_line(reader, writer, "重置日 (1-31, 回车保持):");
                        let quota_reset_day = if d_str.is_empty() {
                            None
                        } else {
                            d_str.parse::<u8>().ok().map(Some)
                        };

                        match modify_inbound_user(&mut root, &tag, &name, new_pwd, rate_limit_kbps, quota_gb, quota_reset_day) {
                            Ok(_) => writeln!(writer, "✓ 用户 `{name}` 已更新。").map_err(|e| e.to_string())?,
                            Err(e) => writeln!(writer, "✗ 修改失败: {e}").map_err(|e| e.to_string())?,
                        }
                    }
                    _ => {}
                }
            }
            "9" if has_server_inbounds => {
                let tag = if mirage_inbounds.len() == 1 {
                    mirage_inbounds[0].tag.clone()
                } else {
                    prompt_line(reader, writer, "请输入入站 tag:")
                };

                let arr = root.get("inbounds").and_then(|v| v.as_array());
                let ib = arr.and_then(|a| a.iter().find(|i| i.get("tag").and_then(|t| t.as_str()) == Some(&tag)));
                let ib = match ib {
                    Some(i) => i,
                    None => {
                        writeln!(writer, "✗ 未找到入站 `{tag}`").map_err(|e| e.to_string())?;
                        continue;
                    }
                };

                let port = ib.get("port").and_then(|p| p.as_u64()).unwrap_or(443) as u16;
                let sni = ib.get("camouflage_host").and_then(|s| s.as_str()).unwrap_or("www.apple.com");

                let pub_host = prompt_line(reader, writer, "请输入服务器公网地址 (域名或公网IP):");
                if pub_host.is_empty() {
                    writeln!(writer, "✗ 未输入公网地址，无法生成链接。").map_err(|e| e.to_string())?;
                    continue;
                }

                let main_pwd = ib.get("password").and_then(|p| p.as_str()).unwrap_or("");
                let users = list_inbound_users(&root, &tag).unwrap_or_default();

                // mirage:// 只含 口令/host/port/sni 四项; 两端须同设的参数无法随链接下发, 需提示客户端手动配置。
                let mut extra = Vec::new();
                if ib.get("pfs").and_then(|v| v.as_bool()).unwrap_or(false) {
                    extra.push("pfs: true".to_string());
                }
                if ib.get("transport").and_then(|v| v.as_str()) == Some("quic") {
                    extra.push("transport: \"quic\" + quic_pin (服务端运行 `mirage-rs quic-pin -c <配置>` 获取)".to_string());
                }
                for k in ["tls_padding", "cipher_agility"] {
                    if root.get("tuning").and_then(|t| t.get(k)).and_then(|v| v.as_bool()).unwrap_or(false) {
                        extra.push(format!("tuning.{k}: true"));
                    }
                }

                writeln!(writer, "\n--- 节点链接 (复制到客户端导入) ---").map_err(|e| e.to_string())?;
                if !extra.is_empty() {
                    writeln!(writer, "⚠ 链接不含以下参数, 客户端导入后须手动设置 (两端须同设, 否则连不上):").map_err(|e| e.to_string())?;
                    for e in &extra {
                        writeln!(writer, "    · {e}").map_err(|e| e.to_string())?;
                    }
                }
                if !main_pwd.is_empty() {
                    let uri = build_mirage_node_uri(&pub_host, port, main_pwd, sni);
                    writeln!(writer, "主凭据节点链接:").map_err(|e| e.to_string())?;
                    writeln!(writer, "  {uri}").map_err(|e| e.to_string())?;
                }

                for u in &users {
                    // 找出原始明文口令 (用户明确选择显示)
                    let u_obj = ib.get("users").and_then(|arr| arr.as_array()).and_then(|a| a.iter().find(|x| x.get("name").and_then(|n| n.as_str()) == Some(&u.name)));
                    if let Some(user_val) = u_obj {
                        let pwd = user_val.get("password").and_then(|p| p.as_str()).unwrap_or("");
                        let uri = build_mirage_node_uri(&pub_host, port, pwd, sni);
                        writeln!(writer, "用户 `{}` 节点链接:", u.name).map_err(|e| e.to_string())?;
                        writeln!(writer, "  {uri}").map_err(|e| e.to_string())?;
                    }
                }
            }
            "10" => {
                let tuning = root.get("tuning");
                let cur_padding = tuning.and_then(|t| t.get("tls_padding")).and_then(|v| v.as_bool()).unwrap_or(false);
                let cur_agility = tuning.and_then(|t| t.get("cipher_agility")).and_then(|v| v.as_bool()).unwrap_or(false);

                writeln!(writer, "\n--- Tuning 核心参数 ---").map_err(|e| e.to_string())?;
                writeln!(writer, "当前状态: tls_padding = {}, cipher_agility = {}", cur_padding, cur_agility).map_err(|e| e.to_string())?;
                writeln!(writer, "⚠ 警告: 协议类参数改动时，两端须同设，请同步修改对端配置。").map_err(|e| e.to_string())?;

                let new_padding = prompt_yes_no(reader, writer, "是否启用 tls_padding (TLS 原生零填充抗特征)？", cur_padding);
                let new_agility = prompt_yes_no(reader, writer, "是否启用 cipher_agility (动态密码学协商)？", cur_agility);

                if let Err(e) = modify_tuning(&mut root, Some(new_padding), Some(new_agility)) {
                    writeln!(writer, "✗ 设置失败: {e}").map_err(|e| e.to_string())?;
                } else {
                    writeln!(writer, "✓ Tuning 设置已更新。").map_err(|e| e.to_string())?;
                }
            }
            "11" => {
                writeln!(writer, "\n--- 待保存改动摘要 ---").map_err(|e| e.to_string())?;
                let diffs = generate_diff(&saved_value, &root);
                if diffs.is_empty() {
                    writeln!(writer, "(当前没有未保存的修改)").map_err(|e| e.to_string())?;
                } else {
                    for d in &diffs {
                        writeln!(writer, "  {d}").map_err(|e| e.to_string())?;
                    }
                    if has_protocol_changes(&saved_value, &root) {
                        writeln!(writer, "\n⚠ 警告: 检测到协议类参数改动 (pfs / transport / tls_padding / cipher_agility / quic_obfs / camouflage)！两端须同设，请同步修改对端配置。").map_err(|e| e.to_string())?;
                    }
                }
            }
            "12" => {
                let diffs = generate_diff(&saved_value, &root);
                if diffs.is_empty() {
                    writeln!(writer, "配置无改动，无需保存。").map_err(|e| e.to_string())?;
                    continue;
                }

                writeln!(writer, "\n--- 即将写入的改动 ---").map_err(|e| e.to_string())?;
                for d in &diffs {
                    writeln!(writer, "  {d}").map_err(|e| e.to_string())?;
                }
                if has_protocol_changes(&saved_value, &root) {
                    writeln!(writer, "\n⚠ 警告: 检测到协议类参数改动 (pfs / transport / tls_padding / cipher_agility / quic_obfs / camouflage)！两端须同设，请同步修改对端配置。").map_err(|e| e.to_string())?;
                }

                let rendered = match serde_json::to_string_pretty(&root) {
                    Ok(s) => s + "\n",
                    Err(e) => {
                        writeln!(writer, "✗ 序列化失败: {e}").map_err(|e| e.to_string())?;
                        continue;
                    }
                };

                // 执行配置语义校验
                match mirage_rs::config::Config::parse_with_diagnostics(&rendered) {
                    Err(e) => {
                        writeln!(writer, "✗ 配置语法/结构校验失败，拒绝写回 (未改动原文件): {e}").map_err(|e| e.to_string())?;
                        continue;
                    }
                    Ok((_, issues)) if !issues.is_empty() => {
                        writeln!(writer, "✗ 配置发现 {} 个问题，拒绝写回 (未改动原文件):", issues.len()).map_err(|e| e.to_string())?;
                        for iss in &issues {
                            writeln!(writer, "  · {iss}").map_err(|e| e.to_string())?;
                        }
                        continue;
                    }
                    _ => {}
                }

                if !prompt_yes_no(reader, writer, "确认保存并写回配置文件？", true) {
                    writeln!(writer, "已取消保存。").map_err(|e| e.to_string())?;
                    continue;
                }

                if let Err(e) = super::atomic_write_config(config_path, &saved_content, &rendered) {
                    writeln!(writer, "✗ 写回配置文件失败: {e}").map_err(|e| e.to_string())?;
                    continue;
                }

                let plan = classify_changes(&saved_value, &root);

                match &plan {
                    ApplyPlan::NoChange => {
                        writeln!(writer, "✓ 配置已写回 (内容无变化)。").map_err(|e| e.to_string())?;
                    }
                    ApplyPlan::HotReload => {
                        writeln!(writer, "✓ 配置已写入, 运行中的服务会自动热重载 (约 1 秒内生效)。").map_err(|e| e.to_string())?;
                    }
                    ApplyPlan::RestartRequired { reasons } => {
                        writeln!(writer, "✓ 配置已写入，但包含需重启服务才能生效的改动:").map_err(|e| e.to_string())?;
                        for r in reasons {
                            writeln!(writer, "  · {r}").map_err(|e| e.to_string())?;
                        }

                        if prompt_yes_no(reader, writer, "是否立即重启服务？", true) {
                            let is_server = !list_mirage_server_inbounds(&root).is_empty();
                            let (default_unit, lite_unit) = if is_server {
                                ("mirage-rs-server", "mirage-rs-lite-server")
                            } else {
                                ("mirage-rs-client", "mirage-rs-lite-client")
                            };

                            let mut inferred_unit = default_unit.to_string();
                            if executor.has_systemctl() {
                                if let Ok(st) = executor.execute("systemctl", &["is-active", lite_unit]) {
                                    if st == "active" {
                                        inferred_unit = lite_unit.to_string();
                                    }
                                }
                            }

                            if executor.has_systemctl() {
                                let unit_input = prompt_line(reader, writer, &format!("确认 systemd 服务单元名 [{inferred_unit}]:"));
                                let final_unit = if unit_input.is_empty() { inferred_unit } else { unit_input };

                                writeln!(writer, "正在重启服务 `{final_unit}` ...").map_err(|e| e.to_string())?;
                                match executor.execute("systemctl", &["restart", &final_unit]) {
                                    Ok(_) => {
                                        let status = executor.execute("systemctl", &["is-active", &final_unit]).unwrap_or_else(|e| e);
                                        writeln!(writer, "✓ 服务重启完成，当前状态: {status}").map_err(|e| e.to_string())?;
                                    }
                                    Err(e) => {
                                        writeln!(writer, "✗ 重启服务失败: {e}").map_err(|e| e.to_string())?;
                                    }
                                }
                            } else {
                                writeln!(writer, "未检测到 systemctl 环境。请手动重启服务: 例如 `systemctl restart {inferred_unit}` 或相应 init 脚本。").map_err(|e| e.to_string())?;
                            }
                        }
                    }
                }
                return Ok(plan);
            }
            "0" => {
                if root != saved_value {
                    if prompt_yes_no(reader, writer, "存在未保存的修改，确认放弃并退出吗？", false) {
                        writeln!(writer, "已退出配置编辑。").map_err(|e| e.to_string())?;
                        return Ok(ApplyPlan::NoChange);
                    }
                } else {
                    writeln!(writer, "已退出配置编辑。").map_err(|e| e.to_string())?;
                    return Ok(ApplyPlan::NoChange);
                }
            }
            _ => {
                writeln!(writer, "未知操作，请输入 0-12 之间的数字。").map_err(|e| e.to_string())?;
            }
        }
    }

    Ok(ApplyPlan::NoChange)
}

/// CLI `mirage config -c <config>` 入口分发
pub async fn run_config(config_path: &str) -> i32 {
    let stdin = std::io::stdin();
    let mut reader = stdin.lock();
    let mut writer = std::io::stdout();
    let executor = RealCommandExecutor;

    match run_interactive_session(config_path, &mut reader, &mut writer, &executor).await {
        Ok(_) => 0,
        Err(e) => {
            eprintln!("✗ {e}");
            1
        }
    }
}

// ============================================================================
// 6. 单元测试与集成测试 (Unit & Integration Tests)
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    // 测试用命令执行器替身 (Mock)
    pub struct MockCommandExecutor {
        pub systemctl_available: bool,
        pub recorded_calls: std::sync::Mutex<Vec<(String, Vec<String>)>>,
        pub active_units: std::sync::Mutex<HashSet<String>>,
    }

    impl MockCommandExecutor {
        pub fn new(systemctl_available: bool) -> Self {
            Self {
                systemctl_available,
                recorded_calls: std::sync::Mutex::new(Vec::new()),
                active_units: std::sync::Mutex::new(HashSet::new()),
            }
        }
    }

    impl CommandExecutor for MockCommandExecutor {
        fn has_systemctl(&self) -> bool {
            self.systemctl_available
        }

        fn execute(&self, cmd: &str, args: &[&str]) -> Result<String, String> {
            self.recorded_calls.lock().unwrap().push((cmd.to_string(), args.iter().map(|s| s.to_string()).collect()));
            if cmd == "systemctl" {
                if args.first() == Some(&"is-active") {
                    let unit = args.get(1).unwrap_or(&"");
                    if self.active_units.lock().unwrap().contains(*unit) {
                        return Ok("active".to_string());
                    } else {
                        return Ok("inactive".to_string());
                    }
                } else if args.first() == Some(&"restart") {
                    let unit = args.get(1).unwrap_or(&"");
                    self.active_units.lock().unwrap().insert(unit.to_string());
                    return Ok("".to_string());
                }
            }
            Ok("".to_string())
        }
    }

    #[test]
    fn test_mask_password_multibyte_no_panic() {
        assert_eq!(mask_password("口令很长的密码"), "口令****密码");
        assert_eq!(mask_password("中文"), "****");
    }

    #[test]
    fn test_build_mirage_node_uri_roundtrip() {
        let uri = build_mirage_node_uri("203.0.113.10", 443, "p@ss word/+", "www.example.com");
        let n = mirage_rs::node_uri::NodeUri::parse(&uri).expect("parse");
        assert_eq!(n.host, "203.0.113.10");
        assert_eq!(n.port, 443);
        assert_eq!(n.password, "p@ss word/+");
        assert_eq!(n.sni, "www.example.com");
        let v6 = build_mirage_node_uri("2001:db8::1", 8443, "pw", "www.example.com");
        let n6 = mirage_rs::node_uri::NodeUri::parse(&v6).expect("parse v6");
        assert_eq!(n6.host, "2001:db8::1");
        assert_eq!(n6.port, 8443);
    }

    #[test]
    fn test_mask_password() {
        assert_eq!(mask_password(""), "****");
        assert_eq!(mask_password("abc"), "****");
        assert_eq!(mask_password("abcd"), "****");
        assert_eq!(mask_password("abcdef"), "ab****ef");
        assert_eq!(mask_password("my_secret_pwd_123"), "my****23");
    }

    #[test]
    fn test_generate_random_password() {
        let p1 = generate_random_password();
        let p2 = generate_random_password();
        assert_eq!(p1.len(), 32);
        assert_eq!(p2.len(), 32);
        assert_ne!(p1, p2);
        assert!(p1.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_build_mirage_node_uri() {
        let uri = build_mirage_node_uri("203.0.113.10", 8443, "p@ss:123", "example.com");
        assert_eq!(uri, "mirage://p%40ss%3A123@203.0.113.10:8443?sni=example.com");

        let uri_v6 = build_mirage_node_uri("2001:db8::1", 443, "simple", "example.com");
        assert_eq!(uri_v6, "mirage://simple@[2001:db8::1]:443?sni=example.com");
    }

    #[test]
    fn test_add_and_list_mirage_outbound() {
        let mut root = json!({
            "outbounds": [],
            "routing": { "default_outbound": "direct", "rules": [] }
        });

        // 正常添加
        add_mirage_outbound_manual(
            &mut root,
            "node-1",
            "203.0.113.1",
            443,
            "secret_pass",
            "example.com",
            true,
            "tcp",
            None,
            Some(4),
            Some(100),
            None,
        ).unwrap();

        let list = list_mirage_outbounds(&root);
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].tag, "node-1");
        assert_eq!(list[0].server, "203.0.113.1");
        assert_eq!(list[0].server_port, 443);
        assert_eq!(list[0].password_masked, "se****ss");
        assert!(list[0].pfs);
        assert_eq!(list[0].pool_size, Some(4));
        assert_eq!(list[0].brutal_rate_mbps, Some(100));

        // 重复 tag 拒绝
        let err = add_mirage_outbound_manual(
            &mut root,
            "node-1",
            "203.0.113.2",
            443,
            "pw",
            "example.com",
            false,
            "tcp",
            None,
            None,
            None,
            None,
        ).unwrap_err();
        assert!(err.contains("已存在"));

        // 非法端口 0
        let err = add_mirage_outbound_manual(
            &mut root,
            "node-2",
            "203.0.113.2",
            0,
            "pw",
            "example.com",
            false,
            "tcp",
            None,
            None,
            None,
            None,
        ).unwrap_err();
        assert!(err.contains("server_port"));

        // quic 缺失 pin
        let err = add_mirage_outbound_manual(
            &mut root,
            "node-quic",
            "203.0.113.2",
            443,
            "pw",
            "example.com",
            false,
            "quic",
            None,
            None,
            None,
            None,
        ).unwrap_err();
        assert!(err.contains("quic_pin"));

        // quic pin 格式非法
        let err = add_mirage_outbound_manual(
            &mut root,
            "node-quic",
            "203.0.113.2",
            443,
            "pw",
            "example.com",
            false,
            "quic",
            Some("too_short"),
            None,
            None,
            None,
        ).unwrap_err();
        assert!(err.contains("quic_pin"));
    }

    #[test]
    fn test_modify_mirage_outbound() {
        let mut root = json!({
            "outbounds": [{
                "type": "mirage",
                "tag": "proxy",
                "server": "203.0.113.1",
                "server_port": 443,
                "password": "old_password",
                "camouflage_host": "old.example.com",
                "transport": "tcp"
            }]
        });

        // 正常修改端口与密码
        modify_mirage_outbound(
            &mut root,
            "proxy",
            Some("203.0.113.2".to_string()),
            Some(8443),
            Some("new_password".to_string()),
            None,
            Some(true),
            None,
            None,
            None,
            None,
        ).unwrap();

        let list = list_mirage_outbounds(&root);
        assert_eq!(list[0].server, "203.0.113.2");
        assert_eq!(list[0].server_port, 8443);
        assert_eq!(list[0].password_masked, "ne****rd");
        assert!(list[0].pfs);

        // 尝试改成非法的端口 0
        let err = modify_mirage_outbound(
            &mut root,
            "proxy",
            None,
            Some(0),
            None,
            None,
            None,
            None,
            None,
            None,
            None,
        ).unwrap_err();
        assert!(err.contains("server_port"));
    }

    #[test]
    fn test_delete_outbound_references_and_auto_group_removal() {
        let mut root = json!({
            "outbounds": [
                { "type": "mirage", "tag": "proxy-1", "server": "203.0.113.1", "server_port": 443, "password": "p", "camouflage_host": "example.com" },
                { "type": "mirage", "tag": "proxy-2", "server": "203.0.113.2", "server_port": 443, "password": "p", "camouflage_host": "example.com" },
                { "type": "urltest", "tag": "auto", "outbounds": ["proxy-1", "proxy-2"] }
            ],
            "routing": {
                "default_outbound": "proxy-1",
                "rules": [
                    { "outbound": "proxy-1", "domain_suffix": ["example.com"] }
                ]
            }
        });

        // 检查 proxy-1 引用: default_outbound, rules[0], urltest 组
        let refs = check_outbound_references(&root, "proxy-1");
        assert_eq!(refs.len(), 3);
        assert!(refs.contains(&OutboundRef::DefaultOutbound));
        assert!(refs.contains(&OutboundRef::Rule { rule_index: 0 }));
        assert!(refs.contains(&OutboundRef::Group { group_tag: "auto".to_string() }));

        // 直接删除应失败 (有硬引用)
        assert!(delete_outbound(&mut root, "proxy-1", true).is_err());

        // 解除 default_outbound 与规则引用
        set_default_outbound(&mut root, "proxy-2").unwrap();
        root["routing"]["rules"][0]["outbound"] = json!("proxy-2");

        // 此时仅被 urltest 组引用
        let refs2 = check_outbound_references(&root, "proxy-1");
        assert_eq!(refs2.len(), 1);
        assert_eq!(refs2[0], OutboundRef::Group { group_tag: "auto".to_string() });

        // 若 auto_remove_from_groups 为 false, 拒绝删除
        assert!(delete_outbound(&mut root, "proxy-1", false).is_err());

        // 若 auto_remove_from_groups 为 true, 成功删除并从组中移出
        assert!(delete_outbound(&mut root, "proxy-1", true).is_ok());

        let outbounds = root["outbounds"].as_array().unwrap();
        assert_eq!(outbounds.len(), 2);
        let group_members = root["outbounds"][1]["outbounds"].as_array().unwrap();
        assert_eq!(group_members.len(), 1);
        assert_eq!(group_members[0].as_str(), Some("proxy-2"));
    }

    #[test]
    fn test_server_inbound_and_user_management() {
        let mut root = json!({
            "inbounds": [{
                "type": "mirage_server",
                "tag": "mirage-in",
                "listen": "0.0.0.0",
                "port": 8443,
                "password": "main_password",
                "camouflage_host": "example.com",
                "users": []
            }]
        });

        // 1. 修改入站参数
        modify_mirage_server_inbound(
            &mut root,
            "mirage-in",
            Some(9443),
            Some("new_main_pw".to_string()),
            Some("cam.example.com".to_string()),
            Some(Some(200)),
            Some(true),
            Some(true),
        ).unwrap();

        let ib_list = list_mirage_server_inbounds(&root);
        assert_eq!(ib_list[0].port, 9443);
        assert_eq!(ib_list[0].camouflage_host, "cam.example.com");
        assert_eq!(ib_list[0].brutal_rate_mbps, Some(200));
        assert!(ib_list[0].pfs);
        assert!(ib_list[0].allow_local_targets);

        // 2. 添加用户
        add_inbound_user(&mut root, "mirage-in", "alice", "alice_pwd", Some(5000), Some(100.0), Some(15)).unwrap();

        // 查重
        assert!(add_inbound_user(&mut root, "mirage-in", "alice", "another", None, None, None).is_err());
        // 非法 quota
        assert!(add_inbound_user(&mut root, "mirage-in", "bob", "pwd", None, Some(0.0), None).is_err());
        // 非法 reset_day
        assert!(add_inbound_user(&mut root, "mirage-in", "bob", "pwd", None, None, Some(32)).is_err());

        let users = list_inbound_users(&root, "mirage-in").unwrap();
        assert_eq!(users.len(), 1);
        assert_eq!(users[0].name, "alice");
        assert_eq!(users[0].password_masked, "al****wd");
        assert_eq!(users[0].rate_limit_kbps, Some(5000));
        assert_eq!(users[0].quota_gb, Some(100.0));
        assert_eq!(users[0].quota_reset_day, Some(15));

        // 3. 修改用户
        modify_inbound_user(&mut root, "mirage-in", "alice", Some("new_alice_pwd".to_string()), Some(None), None, None).unwrap();
        let users2 = list_inbound_users(&root, "mirage-in").unwrap();
        assert_eq!(users2[0].password_masked, "ne****wd");
        assert_eq!(users2[0].rate_limit_kbps, None);

        // 4. 删除用户
        delete_inbound_user(&mut root, "mirage-in", "alice").unwrap();
        let users3 = list_inbound_users(&root, "mirage-in").unwrap();
        assert!(users3.is_empty());
    }

    #[test]
    fn test_classify_unlisted_fields_require_restart() {
        use serde_json::json;
        let base = json!({"inbounds":[{"type":"mirage_server","tag":"in","listen":"0.0.0.0","port":443,"password":"a","users":[]}],
                          "outbounds":[], "routing":{"default_outbound":"direct","rules":[]}, "tuning":{"geo_sources":[]}});
        // 入站未列举的字段 (如将来新增) → 需重启
        let mut v = base.clone(); v["inbounds"][0]["some_future_field"] = json!(1);
        assert!(matches!(classify_changes(&base, &v), ApplyPlan::RestartRequired { .. }));
        // 入站 users / password → 热重载
        let mut v = base.clone(); v["inbounds"][0]["users"] = json!([{"name":"u","password":"p"}]); v["inbounds"][0]["password"] = json!("b");
        assert!(matches!(classify_changes(&base, &v), ApplyPlan::HotReload));
        // tuning 未列举字段 → 需重启; geo_update_days → 热重载
        let mut v = base.clone(); v["tuning"]["udp_mux"] = json!(true);
        assert!(matches!(classify_changes(&base, &v), ApplyPlan::RestartRequired { .. }));
        let mut v = base.clone(); v["tuning"]["geo_update_days"] = json!(3);
        assert!(matches!(classify_changes(&base, &v), ApplyPlan::HotReload));
        // 根级未知字段 → 需重启; routing → 热重载
        let mut v = base.clone(); v["some_root"] = json!({});
        assert!(matches!(classify_changes(&base, &v), ApplyPlan::RestartRequired { .. }));
        let mut v = base.clone(); v["routing"]["default_outbound"] = json!("proxy");
        assert!(matches!(classify_changes(&base, &v), ApplyPlan::HotReload));
    }

    #[test]
    fn test_classify_changes_all_categories() {
        let base_cfg = json!({
            "inbounds": [{
                "type": "mirage_server",
                "tag": "mirage-in",
                "listen": "0.0.0.0",
                "port": 8443,
                "password": "old_pw",
                "camouflage_host": "example.com",
                "users": [{ "name": "alice", "password": "pw1" }]
            }],
            "outbounds": [{
                "type": "mirage",
                "tag": "proxy",
                "server": "203.0.113.1",
                "server_port": 443,
                "password": "pw",
                "camouflage_host": "example.com"
            }],
            "routing": {
                "default_outbound": "proxy",
                "rules": []
            },
            "tuning": {
                "tls_padding": false,
                "cipher_agility": false
            }
        });

        // 1. 无修改
        assert_eq!(classify_changes(&base_cfg, &base_cfg), ApplyPlan::NoChange);

        // 2. 纯热重载改动: 修改 mirage_server 的 users 与主 password, 以及修改 routing.default_outbound
        let mut hot_cfg = base_cfg.clone();
        hot_cfg["inbounds"][0]["password"] = json!("new_pw");
        hot_cfg["inbounds"][0]["users"][0]["password"] = json!("pw1_updated");
        hot_cfg["inbounds"][0]["users"].as_array_mut().unwrap().push(json!({ "name": "bob", "password": "pw2" }));
        hot_cfg["routing"]["default_outbound"] = json!("direct");
        assert_eq!(classify_changes(&base_cfg, &hot_cfg), ApplyPlan::HotReload);

        // 3. 需重启改动 - 出站节点变动
        let mut restart_outbound = base_cfg.clone();
        restart_outbound["outbounds"][0]["server_port"] = json!(8443);
        match classify_changes(&base_cfg, &restart_outbound) {
            ApplyPlan::RestartRequired { reasons } => {
                assert!(reasons.iter().any(|r| r.contains("出站节点/组 `proxy` 参数发生变更")));
            }
            other => panic!("预期 RestartRequired, 实际: {other:?}"),
        }

        // 4. 需重启改动 - 入站端口变动
        let mut restart_inbound = base_cfg.clone();
        restart_inbound["inbounds"][0]["port"] = json!(9443);
        match classify_changes(&base_cfg, &restart_inbound) {
            ApplyPlan::RestartRequired { reasons } => {
                assert!(reasons.iter().any(|r| r.contains("mirage_server 入站 `mirage-in` 的 `port` 参数变更需重启生效")));
            }
            other => panic!("预期 RestartRequired, 实际: {other:?}"),
        }

        // 5. 需重启改动 - Tuning tls_padding 变动
        let mut restart_tuning = base_cfg.clone();
        restart_tuning["tuning"]["tls_padding"] = json!(true);
        match classify_changes(&base_cfg, &restart_tuning) {
            ApplyPlan::RestartRequired { reasons } => {
                assert!(reasons.iter().any(|r| r.contains("tuning.tls_padding")));
            }
            other => panic!("预期 RestartRequired, 实际: {other:?}"),
        }
    }

    #[tokio::test]
    async fn test_interactive_session_add_node_save_restart_required() {
        let temp_dir = std::env::temp_dir().join(format!("mirage_test_edit_{}", fastrand::u64(..)));
        std::fs::create_dir_all(&temp_dir).unwrap();
        let cfg_path = temp_dir.join("config.json");

        let initial_cfg = json!({
            "inbounds": [{
                "type": "socks",
                "tag": "socks-in",
                "listen": "127.0.0.1",
                "port": 1080
            }],
            "outbounds": [{
                "type": "direct",
                "tag": "direct"
            }],
            "routing": {
                "default_outbound": "direct",
                "rules": []
            }
        });
        std::fs::write(&cfg_path, serde_json::to_string_pretty(&initial_cfg).unwrap()).unwrap();

        // 驱动流程:
        // 1) 选 2 添加节点 -> 手动输入(2) -> tag: node-test -> server: 203.0.113.5 -> port: 443 -> pw: pass123 -> camouflage: example.com -> pfs: n -> transport: 回车(tcp) -> pool: 回车 -> brutal: 回车 -> group: 回车
        // 2) 选 12 保存并应用 -> 确认保存: y -> 立即重启: n (测试不重启分支)
        let script = concat!(
            "2\n",          // 菜单: 添加节点
            "2\n",          // 方式: 逐项输入
            "node-test\n",  // tag
            "203.0.113.5\n",// server
            "443\n",        // server_port
            "pass123\n",    // password
            "example.com\n",// camouflage_host
            "n\n",          // pfs
            "\n",           // transport (default tcp)
            "\n",           // pool_size
            "\n",           // brutal_rate_mbps
            "\n",           // group
            "n\n",          // 是否立即测活: 否
            "12\n",         // 菜单: 保存并应用
            "y\n",          // 确认保存
            "n\n",          // 是否立即重启: 否
        );

        let mut reader = std::io::Cursor::new(script.as_bytes());
        let mut output = Vec::new();
        let executor = MockCommandExecutor::new(true);

        let plan = run_interactive_session(
            cfg_path.to_str().unwrap(),
            &mut reader,
            &mut output,
            &executor,
        ).await.unwrap();

        // 断言返回 RestartRequired
        match plan {
            ApplyPlan::RestartRequired { reasons } => {
                assert!(reasons.iter().any(|r| r.contains("新增出站节点/组 `node-test`")));
            }
            other => panic!("预期 RestartRequired, 实际: {other:?}"),
        }

        // 断言文件被更新, 包含新节点
        let saved_content = std::fs::read_to_string(&cfg_path).unwrap();
        assert!(saved_content.contains("node-test"));
        assert!(saved_content.contains("203.0.113.5"));

        // 断言 .bak 文件存在
        let bak_path = temp_dir.join("config.json.bak");
        assert!(bak_path.exists(), ".bak 备份文件必须存在");

        // 断言 0600 权限 (Unix)
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let meta = std::fs::metadata(&cfg_path).unwrap();
            assert_eq!(meta.permissions().mode() & 0o777, 0o600);
            let bak_meta = std::fs::metadata(&bak_path).unwrap();
            assert_eq!(bak_meta.permissions().mode() & 0o777, 0o600);
        }

        // 断言重启执行器未被触发 (因为选择了 n)
        assert!(executor.recorded_calls.lock().unwrap().is_empty());

        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    #[tokio::test]
    async fn test_interactive_session_add_user_hot_reload() {
        let temp_dir = std::env::temp_dir().join(format!("mirage_test_hot_{}", fastrand::u64(..)));
        std::fs::create_dir_all(&temp_dir).unwrap();
        let cfg_path = temp_dir.join("config.json");

        let initial_cfg = json!({
            "inbounds": [{
                "type": "mirage_server",
                "tag": "mirage-in",
                "listen": "0.0.0.0",
                "port": 8443,
                "password": "server_secret",
                "camouflage_host": "example.com",
                "users": []
            }],
            "outbounds": [{
                "type": "direct",
                "tag": "direct"
            }],
            "routing": {
                "default_outbound": "direct",
                "rules": []
            }
        });
        std::fs::write(&cfg_path, serde_json::to_string_pretty(&initial_cfg).unwrap()).unwrap();

        // 驱动流程:
        // 1) 选 8 用户管理 -> 2 (添加用户) -> name: charlie -> pwd: charlie_pwd -> rl: 10000 -> quota: 回车 -> reset: 回车
        // 2) 选 12 保存并应用 -> 确认保存: y
        let script = concat!(
            "8\n",           // 菜单: 用户管理
            "2\n",           // 子菜单: 添加用户
            "charlie\n",     // 用户名
            "charlie_pwd\n", // 密码
            "10000\n",       // 限速
            "\n",            // 配额
            "\n",            // 重置日
            "12\n",          // 菜单: 保存并应用
            "y\n",           // 确认保存
        );

        let mut reader = std::io::Cursor::new(script.as_bytes());
        let mut output = Vec::new();
        let executor = MockCommandExecutor::new(true);

        let plan = run_interactive_session(
            cfg_path.to_str().unwrap(),
            &mut reader,
            &mut output,
            &executor,
        ).await.unwrap();

        // 断言返回 HotReload
        assert_eq!(plan, ApplyPlan::HotReload);

        // 断言文件包含新用户
        let saved_content = std::fs::read_to_string(&cfg_path).unwrap();
        assert!(saved_content.contains("charlie"));
        assert!(saved_content.contains("charlie_pwd"));

        // 断言未调用重启执行器
        assert!(executor.recorded_calls.lock().unwrap().is_empty());

        let _ = std::fs::remove_dir_all(&temp_dir);
    }
}
