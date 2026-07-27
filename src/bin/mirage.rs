use clap::{Parser, Subcommand};

const VERSION: &str = concat!(env!("CARGO_PKG_VERSION"), " (", env!("MIRAGE_GIT"), ")");

#[derive(Parser, Debug)]
#[command(author, version = VERSION, about = "Mirage-rs Proxy Engine\nHigh-performance eBPF-accelerated proxy", long_about = None)]
struct Args {
    #[command(subcommand)]
    mode: Mode,
}

#[derive(Subcommand, Debug)]
enum Mode {
    /// Run as a proxy client
    Client {
        /// Path to configuration file
        #[arg(short, long, default_value = "config_client.json")]
        config: String,
    },
    /// Run as a proxy server
    Server {
        /// Path to configuration file
        #[arg(short, long, default_value = "config_server.json")]
        config: String,
    },
    /// 校验配置文件 (未知字段 / 引用完整性 / 明显无效值), 不启动服务
    ///
    /// 有任何问题即以非零码退出, 便于重启前做闸门:
    ///   mirage-rs check -c config.json && systemctl restart mirage-rs
    Check {
        /// Path to configuration file
        #[arg(short, long, default_value = "config.json")]
        config: String,
    },
    /// 格式化配置文件并输出到 stdout (不改动原文件)
    ///
    /// 保留原有键序与全部字段 (含未知字段), 只重排缩进:
    ///   mirage-rs format -c config.json > config.fmt.json
    Format {
        /// Path to configuration file
        #[arg(short, long, default_value = "config.json")]
        config: String,
    },
    /// 轻量客户端: 仅 SOCKS5 (TCP) 入站, 全部流量走隧道
    ///
    /// 无分流 / DNS / fake-IP / 透明代理 / 看板。协议与完整版一致, 可互通。
    /// 配置是平铺的极简格式, 见 README。
    LiteClient {
        /// Path to lite configuration file
        #[arg(short, long, default_value = "lite_client.json")]
        config: String,
    },
    /// 轻量服务端: 全部转发, 无看板 / DNS / eBPF
    ///
    /// 加密、伪装握手、认证失败转发真站均与完整版完全一致。
    LiteServer {
        /// Path to lite configuration file
        #[arg(short, long, default_value = "lite_server.json")]
        config: String,
    },
    /// 导入 mirage:// 节点 URI 为一个新的 mirage 出站 (会写回配置文件)
    ///
    /// 交互式询问出站 tag, 并保证不与现有出站 tag 冲突:
    ///   mirage-rs import -c config.json "mirage://pass@host:443?sni=www.apple.com"
    Import {
        /// Path to configuration file
        #[arg(short, long, default_value = "config.json")]
        config: String,
        /// mirage://... 节点 URI
        uri: String,
        /// 导入前测一次节点可用性 (握手+认证)。默认失败仅告警仍导入 (见 --require-live)
        #[arg(long)]
        test: bool,
        /// 只在节点测试通过时才导入 (隐含 --test); 不可用则中止不改配置
        #[arg(long)]
        require_live: bool,
        /// 建/更新一个 urltest 出站组纳入全部 mirage 节点, 并把 routing.default_outbound
        /// 指向它 = 按 RTT 自动选路。显式启用, 缺省不动路由。组名见 --group-name。
        #[arg(long)]
        group: bool,
        /// urltest 组名 (仅 --group 时生效)
        #[arg(long, default_value = "auto")]
        group_name: String,
        /// urltest 组健康检查间隔秒 (默认 300; 0=关)。仅 --group
        #[arg(long, requires = "group")]
        group_interval: Option<u64>,
        /// urltest 组 RTT 容差 ms, 现节点领先超过它才切换 (默认 50)。仅 --group
        #[arg(long, requires = "group")]
        group_tolerance: Option<u64>,
        /// urltest 组 HTTP 探测地址 (test_type≠rtt 时用; 默认 gstatic/generate_204)。仅 --group
        #[arg(long, requires = "group")]
        group_url: Option<String>,
        /// urltest 组测试方式 (默认 ping)。ping==http: 穿隧道 HTTP 探测, 端到端含 VPS 出口
        /// 质量。rtt: 内核 TCP RTT, 只量到 VPS 那一跳 (轻量/被动, 盲于出口)。仅 --group
        #[arg(long, requires = "group", value_parser = ["rtt", "ping", "http"])]
        group_test_type: Option<String>,
        /// --test/--require-live 探测的超时秒数 (握手阶段另有 15s 下限, 不受此值压低)
        #[arg(long, default_value_t = 8)]
        timeout: u64,
    },
    /// 测试配置里 mirage 出站节点的可用性 (完整握手 + 认证验证, 报 RTT)
    ///
    /// 走真 Mirage 握手并解密服务端首帧确认认证 —— 裸 TCP 连通不算数。
    ///   mirage-rs test -c config.json            # 测全部 mirage 出站
    ///   mirage-rs test -c config.json --tag proxy # 只测某个 tag
    /// 全部通过退出 0; 有任一失败退出 1 (未确认认证不算失败)。
    Test {
        /// Path to configuration file
        #[arg(short, long, default_value = "config.json")]
        config: String,
        /// 只测这个出站 tag (缺省测全部 mirage 出站)
        #[arg(short, long)]
        tag: Option<String>,
        /// 每个节点的超时秒数
        #[arg(long, default_value_t = 8)]
        timeout: u64,
        /// 关闭穿隧道 HTTP 探测 (默认开: 每节点穿隧道拉一次探测地址, 测端到端含出口质量)
        #[arg(long)]
        no_http: bool,
        /// 穿隧道 HTTP 探测地址 (仅 http://; 默认 gstatic/generate_204)
        #[arg(long, default_value = "http://www.gstatic.com/generate_204")]
        probe_url: String,
    },
    /// 从订阅 URL 批量导入 mirage 节点为出站 (会写回配置文件)
    ///
    /// 订阅格式: 每行一个 mirage:// URI (整段是 base64 则先解码, 兼容经典订阅)。
    /// 按 server:port 去重, 自动生成 tag。可选 --group 建 urltest 组按 RTT 自动选路。
    ///   mirage-rs subscribe -c config.json https://example.com/sub
    Subscribe {
        /// Path to configuration file
        #[arg(short, long, default_value = "config.json")]
        config: String,
        /// 订阅 URL (http/https, 返回 mirage:// 列表或其 base64)
        url: String,
        /// 建/更新 urltest 组纳入全部 mirage 节点 + 指向它 = 按 RTT 自动选路
        #[arg(long)]
        group: bool,
        /// urltest 组名 (仅 --group 时生效)
        #[arg(long, default_value = "auto")]
        group_name: String,
        /// urltest 组检查间隔秒 (仅 --group)
        #[arg(long, requires = "group")]
        group_interval: Option<u64>,
        /// urltest 组 RTT 容差 ms (仅 --group)
        #[arg(long, requires = "group")]
        group_tolerance: Option<u64>,
        /// urltest 组 HTTP 探测地址 (仅 --group)
        #[arg(long, requires = "group")]
        group_url: Option<String>,
        /// urltest 组测试方式 rtt/ping (仅 --group)
        #[arg(long, requires = "group", value_parser = ["rtt", "ping", "http"])]
        group_test_type: Option<String>,
        /// 拉取订阅的超时秒数
        #[arg(long, default_value_t = 15)]
        timeout: u64,
    },
}

/// 校验配置。返回进程退出码: 0 = 干净, 1 = 有问题 / 读不了 / 解析失败。
///
/// 注意与**启动时**校验的差别: 启动求"不中断"(问题只 WARN), 这里求"拦得住"(有问题即非零),
/// 因为它的用途正是在重启前当闸门。两者共用同一个 `parse_with_diagnostics`。
fn run_check(path: &str) -> i32 {
    let content = match std::fs::read_to_string(path) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("✗ 读不了 {path}: {e}");
            return 1;
        }
    };
    match mirage_rs::config::Config::parse_with_diagnostics(&content) {
        Err(e) => {
            eprintln!("✗ {path} 解析失败: {e}");
            eprintln!("  (JSON 语法错误, 或字段类型/结构与 schema 不符)");
            1
        }
        Ok((_, issues)) if issues.is_empty() => {
            println!("✓ {path} 校验通过 (无未知字段, 引用完整)");
            0
        }
        Ok((_, issues)) => {
            eprintln!("✗ {path} 发现 {} 个问题:", issues.len());
            for i in &issues {
                eprintln!("  · {i}");
            }
            1
        }
    }
}

/// 格式化输出配置到 stdout。
///
/// 走 `serde_json::Value` 而非 `Config` 结构体 —— 后者会**吞掉未知字段**并把默认值写进来,
/// 那是改写不是格式化。配合 serde_json 的 preserve_order feature, 键序也保持原样。
fn run_format(path: &str) -> i32 {
    let content = match std::fs::read_to_string(path) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("✗ 读不了 {path}: {e}");
            return 1;
        }
    };
    match serde_json::from_str::<serde_json::Value>(&content) {
        Ok(v) => match serde_json::to_string_pretty(&v) {
            Ok(s) => {
                println!("{s}");
                0
            }
            Err(e) => {
                eprintln!("✗ 序列化失败: {e}");
                1
            }
        },
        Err(e) => {
            eprintln!("✗ {path} 不是合法 JSON: {e}");
            eprintln!("  (注意: JSON 不支持注释, 带 // 注释的 .jsonc 需先去掉注释)");
            1
        }
    }
}

/// 收集配置里已有的出站 tag。
fn existing_outbound_tags(root: &serde_json::Value) -> Vec<String> {
    root.get("outbounds")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|o| o.get("tag").and_then(|t| t.as_str()).map(str::to_string))
                .collect()
        })
        .unwrap_or_default()
}

/// 交互式询问一个不与 `taken` 冲突的 tag。
///
/// stdin 非 TTY (管道/重定向) 时同样能用: 读到什么算什么, EOF 则取默认值。
/// 冲突就重问 —— 直接覆盖同名出站会静默改掉用户既有节点, 绝不能默默做。
fn prompt_unique_tag(default: &str, taken: &[String]) -> anyhow::Result<String> {
    use std::io::{BufRead, Write};
    let stdin = std::io::stdin();
    let mut lines = stdin.lock().lines();
    loop {
        // 默认值本身若已被占用, 就不提示它, 免得用户直接回车又撞车
        let dflt = if taken.iter().any(|t| t == default) { "" } else { default };
        if dflt.is_empty() {
            print!("请输入该出站的 tag: ");
        } else {
            print!("请输入该出站的 tag [{dflt}]: ");
        }
        std::io::stdout().flush()?;

        let input = match lines.next() {
            Some(l) => l?.trim().to_string(),
            None => String::new(), // EOF
        };
        let tag = if input.is_empty() { dflt.to_string() } else { input };

        if tag.is_empty() {
            println!("  tag 不能为空, 请重新输入。");
            continue;
        }
        if taken.iter().any(|t| t == &tag) {
            println!("  tag `{tag}` 已存在于配置中, 换一个 (现有: {})。", taken.join(", "));
            continue;
        }
        return Ok(tag);
    }
}

/// urltest 组的可调参数覆盖 (仅 --group 时可设)。None = 建组时省略走 serde 默认 /
/// 更新既有组时保留原值。
#[derive(Default)]
struct GroupOpts {
    interval: Option<u64>,   // 健康检查间隔秒 (默认 300; 0 = 关)
    tolerance: Option<u64>,  // RTT 容差 ms, 现节点领先超过它才切换 (默认 50)
    url: Option<String>,     // HTTP 探测地址 (test_type != rtt 时用; 默认 gstatic/generate_204)
    test_type: Option<String>, // "rtt"=内核 RTT / 否则 HTTP 探测 (默认 ping)
}

/// 建/更新一个 urltest 出站组 `group_tag`, 纳入配置里全部 mirage 出站, 并把
/// routing.default_outbound 指向它。返回 (纳入节点数, 旧 default_outbound)。
/// group_tag 已被非 urltest 出站占用则 Err。显式 --group 才调用, 是唯一会改路由的路径。
fn apply_urltest_group(root: &mut serde_json::Value, group_tag: &str, opts: &GroupOpts) -> Result<(usize, Option<String>), String> {
    let tags: Vec<String> = mirage_outbounds(root).into_iter().map(|(t, ..)| t).collect();
    if tags.is_empty() {
        return Err("配置里没有 mirage 出站可纳入组".into());
    }
    let arr = root["outbounds"].as_array_mut().ok_or("outbounds 不是数组")?;
    // 已有同名出站: 是 urltest 则更新其成员, 否则拒绝 (别踩别的出站)。
    let group = if let Some(existing) = arr.iter_mut().find(|o| o.get("tag").and_then(|t| t.as_str()) == Some(group_tag)) {
        if existing.get("type").and_then(|t| t.as_str()) != Some("urltest") {
            return Err(format!("tag `{group_tag}` 已被非 urltest 出站占用, 换个组名 (--group-name <名>)"));
        }
        existing["outbounds"] = serde_json::json!(tags);
        existing
    } else {
        arr.push(serde_json::json!({ "type": "urltest", "tag": group_tag, "outbounds": tags }));
        arr.last_mut().unwrap()
    };
    // 覆盖项: 只写用户显式传的 (未传则建组省略走默认 / 更新保留原值)。
    if let Some(v) = opts.interval { group["interval"] = serde_json::json!(v); }
    if let Some(v) = opts.tolerance { group["tolerance"] = serde_json::json!(v); }
    if let Some(v) = &opts.url { group["url"] = serde_json::json!(v); }
    if let Some(v) = &opts.test_type { group["test_type"] = serde_json::json!(v); }
    // 把默认出站指向组 = 按 RTT 自动选路 (显式 --group 请求的核心动作)。
    let old_default = root
        .get("routing")
        .and_then(|r| r.get("default_outbound"))
        .and_then(|d| d.as_str())
        .map(|s| s.to_string());
    match root.get_mut("routing").filter(|r| r.is_object()) {
        Some(routing) => routing["default_outbound"] = serde_json::json!(group_tag),
        // routing 缺失/非对象: 创建一个最小 routing 指向组, 否则会"报成功却没改路由"。
        None => root["routing"] = serde_json::json!({ "default_outbound": group_tag, "rules": [] }),
    }
    Ok((mirage_outbounds(root).len(), old_default))
}

/// 由 NodeUri 构造一个 mirage 出站 JSON。import / subscribe 共用。
fn mirage_outbound_json(tag: &str, node: &mirage_rs::node_uri::NodeUri) -> serde_json::Value {
    serde_json::json!({
        "type": "mirage",
        "tag": tag,
        "server": node.host,
        "server_port": node.port,
        "password": node.password,
        "camouflage_host": node.sni,
    })
}

/// 原子写回配置: 先备份 `<path>.bak`, 再写 `<path>.tmp` + rename (中途失败不留半截)。
fn atomic_write_config(path: &str, original: &str, rendered: &str) -> Result<(), String> {
    let bak = format!("{path}.bak");
    std::fs::write(&bak, original).map_err(|e| format!("备份到 {bak} 失败: {e} (未改动原文件)"))?;
    let tmp = format!("{path}.tmp");
    std::fs::write(&tmp, rendered).map_err(|e| format!("写临时文件 {tmp} 失败: {e} (未改动原文件)"))?;
    std::fs::rename(&tmp, path).map_err(|e| {
        let _ = std::fs::remove_file(&tmp);
        format!("替换 {path} 失败: {e}")
    })
}

/// 生成一个不与 `taken` 冲突的 tag (base 撞名则 base-2 / base-3 …)。批量非交互用。
/// 生成后即把它加进 `taken`, 供同批后续去重。
fn unique_auto_tag(base: &str, taken: &mut Vec<String>) -> String {
    let base = if base.is_empty() { "node" } else { base };
    if !taken.iter().any(|t| t == base) {
        taken.push(base.to_string());
        return base.to_string();
    }
    for n in 2.. {
        let cand = format!("{base}-{n}");
        if !taken.iter().any(|t| t == &cand) {
            taken.push(cand.clone());
            return cand;
        }
    }
    unreachable!()
}

/// 导入 mirage:// 节点为新的 mirage 出站, 写回配置文件。
async fn run_import(path: &str, uri: &str, test: bool, require_live: bool, group: Option<&str>, group_opts: &GroupOpts, timeout_secs: u64) -> i32 {
    let node = match mirage_rs::node_uri::NodeUri::parse(uri) {
        Ok(n) => n,
        Err(e) => {
            eprintln!("✗ URI 解析失败: {e}");
            eprintln!("  格式: mirage://<密码>@<host>:<port>?sni=<伪装域名>");
            return 1;
        }
    };

    let content = match std::fs::read_to_string(path) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("✗ 读不了 {path}: {e}");
            return 1;
        }
    };
    // 走 Value 而非 Config 结构体: 保留原键序与全部字段 (含未知字段), 只做增量插入。
    let mut root: serde_json::Value = match serde_json::from_str(&content) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("✗ {path} 不是合法 JSON: {e}");
            return 1;
        }
    };
    if !root.get("outbounds").map(|v| v.is_array()).unwrap_or(false) {
        eprintln!("✗ {path} 里没有 outbounds 数组, 不像是 Mirage 配置");
        return 1;
    }

    println!("节点: {}:{}  (SNI 伪装: {})", node.host, node.port, node.sni);

    // 可选: 导入前测节点可用性 (--test 告警, --require-live 硬拦)。
    if test || require_live {
        use mirage_rs::proxy::probe::{probe_mirage, ProbeOutcome};
        print!("  测试节点 … ");
        use std::io::Write;
        let _ = std::io::stdout().flush();
        // import 测活只做握手+认证 (http_probe=None), 不产生穿隧道出口流量。
        match probe_mirage(&node.host, node.port, &node.password, &node.sni, timeout_secs, None).await {
            ProbeOutcome::Ok { handshake_ms, .. } => println!("✓ 可用 (握手+认证 {handshake_ms}ms)"),
            ProbeOutcome::Unconfirmed { note, .. } => println!("⚠ 可达但未确认认证 —— {note}"),
            ProbeOutcome::Fail(reason) => {
                println!("✗ 不可用 —— {reason}");
                if require_live {
                    eprintln!("  --require-live: 节点不可用, 中止导入 (未改动配置)");
                    return 1;
                }
                eprintln!("  警告: 节点测试未通过, 仍继续导入 (要拒绝请用 --require-live)");
            }
        }
    }

    let taken = existing_outbound_tags(&root);
    if !taken.is_empty() {
        println!("现有出站 tag: {}", taken.join(", "));
    }

    let tag = match prompt_unique_tag(&node.host, &taken) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("✗ 读取输入失败: {e}");
            return 1;
        }
    };

    root["outbounds"].as_array_mut().unwrap().push(mirage_outbound_json(&tag, &node));

    // --group: 建/更新 urltest 组并指向它 (唯一改路由的路径); 否则仅在代理数>1 时给建议。
    let mut group_note: Option<String> = None;
    if let Some(gname) = group {
        match apply_urltest_group(&mut root, gname, group_opts) {
            Ok((n, old)) => {
                group_note = Some(format!(
                    "✓ 已建/更新 urltest 组 `{gname}` (纳入 {n} 个 mirage 节点), \
                     routing.default_outbound: {} → `{gname}` (按 RTT 自动选路)",
                    old.as_deref().unwrap_or("<未设>")
                ));
            }
            Err(e) => {
                eprintln!("✗ 建组失败: {e} (未改动配置)");
                return 1;
            }
        }
    }

    let rendered = match serde_json::to_string_pretty(&root) {
        Ok(s) => s + "\n",
        Err(e) => {
            eprintln!("✗ 序列化失败: {e}");
            return 1;
        }
    };

    if let Err(e) = atomic_write_config(path, &content, &rendered) {
        eprintln!("✗ {e}");
        return 1;
    }

    println!("✓ 已导入为出站 `{tag}` → {path}  (原文件备份: {path}.bak)");
    if let Some(note) = group_note {
        // --group: 路由已自动指向组, 无需再手动接线。
        println!("  {note}");
        println!("  `mirage-rs check -c {path}` 确认无误再重启。");
    } else {
        println!("  提示: 出站已添加, 但还没有任何路由规则使用它。");
        println!("        要让流量走它, 把 routing.default_outbound 或某条 rule 的 outbound 改为 `{tag}`,");
        println!("        然后 `mirage-rs check -c {path}` 确认无误再重启。");
        // 代理节点 >1: 建议 urltest 自动选路 (只建议, 不擅自改路由)。
        let proxies = mirage_outbounds(&root);
        if proxies.len() > 1 {
            let tags: Vec<&str> = proxies.iter().map(|(t, ..)| t.as_str()).collect();
            println!();
            println!("  检测到 {} 个 mirage 节点。想按 RTT 自动选路 (故障自动切换), 两个办法:", proxies.len());
            println!("    ① 重跑本命令时加 --group  (自动建 urltest 组并指向它)");
            println!("    ② 手动在 outbounds 里加一条, 再把 default_outbound 改成 \"auto\":");
            println!("         {{ \"type\": \"urltest\", \"tag\": \"auto\", \"outbounds\": {:?} }}", tags);
        }
    }
    0
}

/// 订阅解码: 整段是 base64 (经典订阅格式, 无空白) 则先解码, 否则原样当明文。
/// 再逐行取 `mirage://` (跳过空行 / `#` 注释), 解析成节点。
fn parse_subscription(body: &str) -> Vec<mirage_rs::node_uri::NodeUri> {
    use base64::Engine;
    let trimmed: String = body.split_whitespace().collect(); // 判 base64 用: 去所有空白
    let text = if !trimmed.is_empty()
        && trimmed.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/' | b'=' | b'-' | b'_'))
    {
        base64::engine::general_purpose::STANDARD
            .decode(&trimmed)
            .ok()
            .and_then(|b| String::from_utf8(b).ok())
            .unwrap_or_else(|| body.to_string())
    } else {
        body.to_string()
    };
    text.lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#') && l.starts_with("mirage://"))
        .filter_map(|l| mirage_rs::node_uri::NodeUri::parse(l).ok())
        .collect()
}

/// 从订阅 URL 拉取节点列表, 批量导入为 mirage 出站 (按 server:port 去重), 可选建 urltest 组。
async fn run_subscribe(path: &str, url: &str, group: Option<&str>, group_opts: &GroupOpts, timeout_secs: u64) -> i32 {
    let content = match std::fs::read_to_string(path) {
        Ok(c) => c,
        Err(e) => { eprintln!("✗ 读不了 {path}: {e}"); return 1; }
    };
    let mut root: serde_json::Value = match serde_json::from_str(&content) {
        Ok(v) => v,
        Err(e) => { eprintln!("✗ {path} 不是合法 JSON: {e}"); return 1; }
    };
    if !root.get("outbounds").map(|v| v.is_array()).unwrap_or(false) {
        eprintln!("✗ {path} 里没有 outbounds 数组, 不像是 Mirage 配置");
        return 1;
    }

    print!("拉取订阅 {url} … ");
    use std::io::Write;
    let _ = std::io::stdout().flush();
    let client = match reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(timeout_secs))
        .build()
    {
        Ok(c) => c,
        Err(e) => { eprintln!("✗ 构造 HTTP 客户端失败: {e}"); return 1; }
    };
    let body = match client.get(url).send().await.and_then(|r| r.error_for_status()) {
        Ok(resp) => match resp.text().await {
            Ok(t) => t,
            Err(e) => { eprintln!("✗ 读订阅响应失败: {e}"); return 1; }
        },
        Err(e) => { eprintln!("✗ 拉订阅失败: {e}"); return 1; }
    };
    let nodes = parse_subscription(&body);
    println!("解析到 {} 个 mirage 节点", nodes.len());
    if nodes.is_empty() {
        eprintln!("✗ 订阅里没有可解析的 mirage:// 节点 (格式: 每行一个 mirage:// URI, 或整段 base64)");
        return 1;
    }

    let mut taken = existing_outbound_tags(&root);
    let mut seen: std::collections::HashSet<(String, u16)> = root["outbounds"].as_array().unwrap().iter()
        .filter(|o| o.get("type").and_then(|t| t.as_str()) == Some("mirage"))
        .filter_map(|o| Some((o.get("server")?.as_str()?.to_string(), o.get("server_port")?.as_u64()? as u16)))
        .collect();
    let (mut added, mut skipped) = (0u32, 0u32);
    for node in &nodes {
        if !seen.insert((node.host.clone(), node.port)) {
            skipped += 1;
            continue;
        }
        let tag = unique_auto_tag(&node.host, &mut taken);
        root["outbounds"].as_array_mut().unwrap().push(mirage_outbound_json(&tag, node));
        added += 1;
    }
    println!("  新增 {added} 个, 跳过 {skipped} 个 (server:port 已存在)");
    // 0 新增且不建组 = 无改动早退; 带 --group 则仍对已有节点建组 (重订阅刷新组的常见用法)。
    if added == 0 && group.is_none() {
        println!("✓ 无新增节点, 配置未改动");
        return 0;
    }

    let mut group_note = None;
    if let Some(gname) = group {
        match apply_urltest_group(&mut root, gname, group_opts) {
            Ok((n, old)) => group_note = Some(format!(
                "✓ 已建/更新 urltest 组 `{gname}` (纳入 {n} 个 mirage 节点), default_outbound: {} → `{gname}`",
                old.as_deref().unwrap_or("<未设>")
            )),
            Err(e) => { eprintln!("✗ 建组失败: {e} (未改动配置)"); return 1; }
        }
    }

    let rendered = match serde_json::to_string_pretty(&root) {
        Ok(s) => s + "\n",
        Err(e) => { eprintln!("✗ 序列化失败: {e}"); return 1; }
    };
    if let Err(e) = atomic_write_config(path, &content, &rendered) {
        eprintln!("✗ {e}");
        return 1;
    }
    println!("✓ 已写回 {path} (原文件备份: {path}.bak)");
    match group_note {
        Some(note) => println!("  {note}\n  `mirage-rs check -c {path}` 确认后重启。"),
        None => println!("  提示: 出站已加但未接路由。要按 RTT 自动选路, 重跑时加 --group。"),
    }
    0
}

/// 从配置 root 里抽出全部 mirage 出站的连接参数 (tag, host, port, password, sni)。
/// 缺字段的条目跳过 (不是完整 mirage 出站)。供 test / import --test 复用。
fn mirage_outbounds(root: &serde_json::Value) -> Vec<(String, String, u16, String, String)> {
    let Some(arr) = root.get("outbounds").and_then(|v| v.as_array()) else {
        return Vec::new();
    };
    arr.iter()
        .filter(|o| o.get("type").and_then(|t| t.as_str()) == Some("mirage"))
        .filter_map(|o| {
            Some((
                o.get("tag")?.as_str()?.to_string(),
                o.get("server")?.as_str()?.to_string(),
                u16::try_from(o.get("server_port")?.as_u64()?).ok()?, // 越界端口跳过, 不截断
                o.get("password")?.as_str()?.to_string(),
                o.get("camouflage_host")?.as_str()?.to_string(),
            ))
        })
        .collect()
}

/// 测试 mirage 出站可用性。返回退出码: 0 = 全部通过 (含"未确认"), 1 = 有失败 / 读不了 / 无节点。
async fn run_test(path: &str, only_tag: Option<&str>, timeout_secs: u64, http_probe: Option<&str>) -> i32 {
    use mirage_rs::proxy::probe::{probe_mirage, ProbeOutcome};

    let content = match std::fs::read_to_string(path) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("✗ 读不了 {path}: {e}");
            return 1;
        }
    };
    let root: serde_json::Value = match serde_json::from_str(&content) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("✗ {path} 不是合法 JSON: {e}");
            return 1;
        }
    };

    let mut nodes = mirage_outbounds(&root);
    if let Some(t) = only_tag {
        nodes.retain(|(tag, ..)| tag == t);
        if nodes.is_empty() {
            eprintln!("✗ 配置里没有 tag=`{t}` 的 mirage 出站");
            return 1;
        }
    }
    if nodes.is_empty() {
        eprintln!("✗ 配置里没有 mirage 出站可测");
        return 1;
    }

    if let Some(u) = http_probe {
        if !u.starts_with("http://") {
            eprintln!("⚠ --probe-url `{u}` 不是 http:// (穿隧道探测仅支持明文 HTTP), HTTP 探测会全部失败\n");
        }
    }
    println!("测试 {} 个 mirage 节点 (并发, 每个超时 {}s)…\n", nodes.len(), timeout_secs);

    // 并发探测: 每节点一个任务, 总耗时 = 最慢节点而非累加 (串行会把各节点最坏耗时叠起来)。
    // 结果按原顺序收集后统一打印, 输出稳定。
    let http_owned = http_probe.map(|s| s.to_string());
    let mut set = tokio::task::JoinSet::new();
    for (i, (_tag, server, port, password, sni)) in nodes.iter().enumerate() {
        let (server, password, sni) = (server.clone(), password.clone(), sni.clone());
        let port = *port;
        let http = http_owned.clone();
        set.spawn(async move {
            (i, probe_mirage(&server, port, &password, &sni, timeout_secs, http.as_deref()).await)
        });
    }
    let mut results: Vec<Option<ProbeOutcome>> =
        std::iter::repeat_with(|| None).take(nodes.len()).collect();
    while let Some(joined) = set.join_next().await {
        if let Ok((i, outcome)) = joined {
            results[i] = Some(outcome);
        }
    }

    let mut failed = 0;
    for (i, (tag, server, port, ..)) in nodes.iter().enumerate() {
        print!("  {tag:<16} {server}:{port}  … ");
        let outcome = results[i].take().unwrap_or_else(|| ProbeOutcome::Fail("内部错误: 探测任务未返回".into()));
        match outcome {
            ProbeOutcome::Ok { tcp_ms, handshake_ms, http_ms } => {
                match http_ms {
                    // 协同判断: HTTP 端到端 − TCP ≈ 隧道+VPS 出口开销。差值大 = 出口是瓶颈。
                    Some(h) => {
                        let egress = h.saturating_sub(tcp_ms);
                        let hint = if egress > 300 { ", 偏高" } else { "" };
                        println!("✓ 可用  (TCP {tcp_ms}ms · 握手 {handshake_ms}ms · HTTP {h}ms; 出口 ≈ {egress}ms{hint})");
                    }
                    None if http_owned.is_some() => {
                        println!("✓ 可用  (TCP {tcp_ms}ms · 握手 {handshake_ms}ms · HTTP 探测失败/超时, 出口可能不通)");
                    }
                    None => println!("✓ 可用  (TCP {tcp_ms}ms · 握手 {handshake_ms}ms)"),
                }
            }
            ProbeOutcome::Unconfirmed { tcp_ms, note } => {
                println!("⚠ 可达但未确认认证  (TCP {tcp_ms}ms) —— {note}");
            }
            ProbeOutcome::Fail(reason) => {
                println!("✗ 不可用  —— {reason}");
                failed += 1;
            }
        }
    }
    println!();
    if failed == 0 {
        println!("✓ 全部通过 ({} 个)", nodes.len());
        0
    } else {
        eprintln!("✗ {failed}/{} 个节点不可用", nodes.len());
        1
    }
}

/// 读并解析轻量配置。错误信息带上路径, 免得用户对着裸 serde 报错猜是哪个文件。
fn load_lite<T: serde::de::DeserializeOwned>(path: &str) -> anyhow::Result<T> {
    use anyhow::Context;
    let content = std::fs::read_to_string(path)
        .with_context(|| format!("读不了轻量配置 {path}"))?;
    serde_json::from_str(&content).with_context(|| format!("解析轻量配置 {path} 失败"))
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    // check / format 是纯本地工具: 不初始化日志、不起服务、不碰网络。
    match &args.mode {
        Mode::Check { config } => std::process::exit(run_check(config)),
        Mode::Format { config } => std::process::exit(run_format(config)),
        _ => {}
    }

    // test / import: 可能需网络 (import --test / --require-live) + async, 放 tokio 运行时里。
    if let Mode::Test { config, tag, timeout, no_http, probe_url } = &args.mode {
        let http = (!no_http).then_some(probe_url.as_str());
        std::process::exit(run_test(config, tag.as_deref(), *timeout, http).await);
    }
    if let Mode::Import {
        config, uri, test, require_live, group, group_name,
        group_interval, group_tolerance, group_url, group_test_type, timeout,
    } = &args.mode
    {
        let g = group.then_some(group_name.as_str());
        let opts = GroupOpts {
            interval: *group_interval,
            tolerance: *group_tolerance,
            url: group_url.clone(),
            test_type: group_test_type.clone(),
        };
        std::process::exit(run_import(config, uri, *test, *require_live, g, &opts, *timeout).await);
    }
    if let Mode::Subscribe {
        config, url, group, group_name,
        group_interval, group_tolerance, group_url, group_test_type, timeout,
    } = &args.mode
    {
        let g = group.then_some(group_name.as_str());
        let opts = GroupOpts {
            interval: *group_interval,
            tolerance: *group_tolerance,
            url: group_url.clone(),
            test_type: group_test_type.clone(),
        };
        std::process::exit(run_subscribe(config, url, g, &opts, *timeout).await);
    }

    // 轻量模式: 平铺配置 + 精简启动路径, 不走完整版那套 (热重载/看板/geo)。
    match &args.mode {
        Mode::LiteClient { config } => {
            let cfg = load_lite(config)?;
            return mirage_rs::lite::start_client(cfg).await;
        }
        Mode::LiteServer { config } => {
            let cfg = load_lite(config)?;
            return mirage_rs::lite::start_server(cfg).await;
        }
        _ => {}
    }

    let (config_path, is_server) = match &args.mode {
        Mode::Client { config } => (config.as_str(), false),
        Mode::Server { config } => (config.as_str(), true),
        _ => unreachable!("check/format/import/test/lite-* 已在上面处理"),
    };

    mirage_rs::start_proxy(config_path, is_server).await
}

#[cfg(test)]
mod tests {
    use super::{mirage_outbounds, parse_subscription, unique_auto_tag};

    #[test]
    fn parse_subscription_plaintext_and_filters() {
        let body = "# 注释\n\nmirage://p1@a.com:443?sni=www.apple.com\nnot-a-node\nmirage://p2@b.com:8443?sni=www.bing.com\n";
        let nodes = parse_subscription(body);
        assert_eq!(nodes.len(), 2, "跳过注释/空行/非 mirage 行");
        assert_eq!(nodes[0].host, "a.com");
        assert_eq!(nodes[1].port, 8443);
    }

    #[test]
    fn parse_subscription_base64() {
        use base64::Engine;
        let plain = "mirage://p@h.com:443?sni=www.apple.com";
        let b64 = base64::engine::general_purpose::STANDARD.encode(plain);
        let nodes = parse_subscription(&b64);
        assert_eq!(nodes.len(), 1);
        assert_eq!(nodes[0].host, "h.com");
    }

    #[test]
    fn unique_auto_tag_dedups() {
        let mut taken = vec!["a".to_string()];
        assert_eq!(unique_auto_tag("a", &mut taken), "a-2");
        assert_eq!(unique_auto_tag("a", &mut taken), "a-3");
        assert_eq!(unique_auto_tag("b", &mut taken), "b");
        assert_eq!(unique_auto_tag("", &mut taken), "node");
    }

    #[test]
    fn extracts_only_complete_mirage_outbounds() {
        let root = serde_json::json!({
            "outbounds": [
                { "type": "mirage", "tag": "a", "server": "h1", "server_port": 443, "password": "p", "camouflage_host": "s1" },
                { "type": "direct", "tag": "direct" },                       // 非 mirage → 跳过
                { "type": "mirage", "tag": "incomplete", "server": "h2" },   // 缺字段 → 跳过
                { "type": "mirage", "tag": "b", "server": "h3", "server_port": 8443, "password": "q", "camouflage_host": "s2" }
            ]
        });
        let got = mirage_outbounds(&root);
        assert_eq!(got.len(), 2, "只抽完整的 mirage 出站");
        assert_eq!(got[0], ("a".into(), "h1".into(), 443, "p".into(), "s1".into()));
        assert_eq!(got[1], ("b".into(), "h3".into(), 8443, "q".into(), "s2".into()));
    }

    #[test]
    fn no_outbounds_array_yields_empty() {
        assert!(mirage_outbounds(&serde_json::json!({})).is_empty());
    }

    use super::{apply_urltest_group, GroupOpts};

    fn cfg_two_mirage() -> serde_json::Value {
        serde_json::json!({
            "outbounds": [
                { "type": "mirage", "tag": "m1", "server": "h1", "server_port": 443, "password": "p", "camouflage_host": "s" },
                { "type": "direct", "tag": "direct" },
                { "type": "mirage", "tag": "m2", "server": "h2", "server_port": 443, "password": "p", "camouflage_host": "s" }
            ],
            "routing": { "default_outbound": "m1", "rules": [] }
        })
    }

    #[test]
    fn group_creates_urltest_and_points_default() {
        let mut root = cfg_two_mirage();
        let (n, old) = apply_urltest_group(&mut root, "auto", &GroupOpts::default()).unwrap();
        assert_eq!(n, 2);
        assert_eq!(old.as_deref(), Some("m1"));
        assert_eq!(root["routing"]["default_outbound"], "auto");
        let g: Vec<_> = root["outbounds"].as_array().unwrap().iter()
            .filter(|o| o["type"] == "urltest").collect();
        assert_eq!(g.len(), 1);
        assert_eq!(g[0]["outbounds"], serde_json::json!(["m1", "m2"]));
    }

    #[test]
    fn group_is_idempotent_updates_members() {
        let mut root = cfg_two_mirage();
        apply_urltest_group(&mut root, "auto", &GroupOpts::default()).unwrap();
        // 再加一个 mirage 后重跑: 组成员更新, 不新增第二个 urltest
        root["outbounds"].as_array_mut().unwrap().push(serde_json::json!(
            { "type": "mirage", "tag": "m3", "server": "h3", "server_port": 443, "password": "p", "camouflage_host": "s" }));
        apply_urltest_group(&mut root, "auto", &GroupOpts::default()).unwrap();
        let g: Vec<_> = root["outbounds"].as_array().unwrap().iter()
            .filter(|o| o["type"] == "urltest").collect();
        assert_eq!(g.len(), 1, "不重复建组");
        assert_eq!(g[0]["outbounds"], serde_json::json!(["m1", "m2", "m3"]));
    }

    #[test]
    fn group_rejects_name_taken_by_non_urltest() {
        let mut root = cfg_two_mirage();
        // "direct" 已是非 urltest 出站 → 拒绝占用
        assert!(apply_urltest_group(&mut root, "direct", &GroupOpts::default()).is_err());
    }

    #[test]
    fn group_applies_and_preserves_params() {
        let mut root = cfg_two_mirage();
        // 建组时设 interval + tolerance
        apply_urltest_group(&mut root, "auto", &GroupOpts {
            interval: Some(120), tolerance: Some(30), ..Default::default()
        }).unwrap();
        let g = |r: &serde_json::Value| r["outbounds"].as_array().unwrap().iter()
            .find(|o| o["type"] == "urltest").unwrap().clone();
        let gv = g(&root);
        assert_eq!(gv["interval"], 120);
        assert_eq!(gv["tolerance"], 30);
        // 再跑只改 url: interval/tolerance 应保留 (未传不动)
        apply_urltest_group(&mut root, "auto", &GroupOpts {
            url: Some("http://example.com/gen204".into()), ..Default::default()
        }).unwrap();
        let gv = g(&root);
        assert_eq!(gv["interval"], 120, "未传 interval → 保留");
        assert_eq!(gv["tolerance"], 30, "未传 tolerance → 保留");
        assert_eq!(gv["url"], "http://example.com/gen204");
    }

    #[test]
    fn group_creates_routing_when_absent() {
        // routing 缺失时应创建并指向组, 不能报成功却没改路由
        let mut root = serde_json::json!({
            "outbounds": [
                { "type": "mirage", "tag": "m1", "server": "h", "server_port": 443, "password": "p", "camouflage_host": "s" }
            ]
        });
        let (n, old) = apply_urltest_group(&mut root, "auto", &GroupOpts::default()).unwrap();
        assert_eq!(n, 1);
        assert_eq!(old, None, "原本无 default");
        assert_eq!(root["routing"]["default_outbound"], "auto", "已创建 routing 并指向组");
    }
}
