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
    /// 从来源 (URL 或本地文件) 导入节点 —— mirage:// 列表, 或 export 产出的 JSON 片段
    ///
    /// 来源 payload 自动辨: 以 `{` 开头 = JSON 片段 (合并节点+组+可选路由/geo, 见 --routing);
    /// 否则每行一个 mirage:// URI (整段 base64 则先解码)。按 server:port 去重, 自动 tag。
    ///   mirage-rs subscribe -c config.json https://example.com/sub   # 远程列表
    ///   mirage-rs subscribe -c config.json share.json                # 本地片段 (export 产出)
    Subscribe {
        /// Path to configuration file
        #[arg(short, long, default_value = "config.json")]
        config: String,
        /// 来源: URL (http/https) 或本地文件路径; 内容为 mirage:// 列表或 JSON 片段
        source: String,
        /// 合并 JSON 片段时**连同路由规则一起并入** (侵入性, 默认不并; 只对片段生效)
        #[arg(long)]
        routing: bool,
        /// 建/更新 urltest 组纳入全部 mirage 节点 + 指向它 = 按 RTT 自动选路 (仅列表模式)
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
    /// 交互式导出配置片段 (选节点 + 匹配的组/路由/geo) 为可分享 JSON
    ///
    /// 询问导出哪些 mirage 节点 (全部/部分)、是否带路由规则、是否带 geo 下载地址。
    /// 组自动按所选节点过滤成员 (剔除未选的, 剔空则跳过); 引用到未导出出站的规则丢弃。
    ///   mirage-rs export -c config.json -o share.json
    ///   mirage-rs export -c config.json > share.json   # 无 -o 则写 stdout
    Export {
        /// Path to configuration file
        #[arg(short, long, default_value = "config.json")]
        config: String,
        /// 输出文件 (缺省写 stdout; 交互提示走 stderr, 不污染)
        #[arg(short, long)]
        out: Option<String>,
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
                // 混区域告警: 组内节点跨国时提示 (出口不一致)。
                if let Some(db) = load_node_geoip(&root) {
                    if let Some(w) = mixed_region_warning(&root, &db).await {
                        eprintln!("  {w}");
                    }
                }
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

/// 依次试 4 种 base64 字母表 (standard / url-safe × 有无填充) 解码成 UTF-8。都不成 → None。
/// 订阅提供方用哪种都有, 只试 STANDARD 会把 url-safe/无填充的订阅解成乱码。
fn try_base64_decode(s: &str) -> Option<String> {
    use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD};
    use base64::Engine;
    for eng in [&STANDARD, &STANDARD_NO_PAD, &URL_SAFE, &URL_SAFE_NO_PAD] {
        if let Ok(bytes) = eng.decode(s) {
            if let Ok(text) = String::from_utf8(bytes) {
                return Some(text);
            }
        }
    }
    None
}

/// 订阅解码: 整段是 base64 (经典订阅格式, 无空白) 则先解码, 否则原样当明文。
/// 再逐行取 `mirage://` (跳过空行 / `#` 注释), 解析成节点。
fn parse_subscription(body: &str) -> Vec<mirage_rs::node_uri::NodeUri> {
    let trimmed: String = body.split_whitespace().collect(); // 判 base64 用: 去所有空白
    let looks_base64 = !trimmed.is_empty()
        && trimmed.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/' | b'=' | b'-' | b'_'));
    // 像 base64 就试 4 种字母表解; 解不出 (其实是纯 base64 字符集的明文) 回落原文。
    let text = if looks_base64 {
        try_base64_decode(&trimmed).unwrap_or_else(|| body.to_string())
    } else {
        body.to_string()
    };
    text.lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#') && l.starts_with("mirage://"))
        .filter_map(|l| mirage_rs::node_uri::NodeUri::parse(l).ok())
        .collect()
}

/// 从来源 (URL 或本地文件) 导入节点。payload 以 `{` 开头 = export 的 JSON 片段 (合并
/// 节点/组/可选路由/geo), 否则按 mirage:// 列表批量导入 (按 server:port 去重, 可选建组)。
async fn run_subscribe(path: &str, source: &str, group: Option<&str>, group_opts: &GroupOpts, include_routing: bool, timeout_secs: u64) -> i32 {
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

    // 取 body: 本地文件优先, 否则当 URL 拉
    let body = if std::path::Path::new(source).is_file() {
        match std::fs::read_to_string(source) {
            Ok(b) => b,
            Err(e) => { eprintln!("✗ 读不了 {source}: {e}"); return 1; }
        }
    } else {
        print!("拉取订阅 {source} … ");
        use std::io::Write;
        let _ = std::io::stdout().flush();
        let client = match reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(timeout_secs))
            .build()
        {
            Ok(c) => c,
            Err(e) => { eprintln!("✗ 构造 HTTP 客户端失败: {e}"); return 1; }
        };
        const MAX_SUB_BYTES: u64 = 8 * 1024 * 1024; // 订阅正常 KB 级; 8MB 上限防恶意大 body OOM
        match client.get(source).send().await.and_then(|r| r.error_for_status()) {
            Ok(resp) => {
                if let Some(len) = resp.content_length() {
                    if len > MAX_SUB_BYTES {
                        eprintln!("✗ 订阅体过大 ({len} 字节 > {MAX_SUB_BYTES} 上限), 拒绝");
                        return 1;
                    }
                }
                match resp.text().await {
                    Ok(t) => t,
                    Err(e) => { eprintln!("✗ 读订阅响应失败: {e}"); return 1; }
                }
            }
            Err(e) => { eprintln!("✗ 拉订阅失败: {e}"); return 1; }
        }
    };

    // JSON 片段 (export 产出) 走合并路径; 否则按 mirage:// 列表
    if body.trim_start().starts_with('{') {
        return apply_fragment(path, &content, root, &body, include_routing);
    }

    let nodes = parse_subscription(&body);
    println!("解析到 {} 个 mirage 节点", nodes.len());
    if nodes.is_empty() {
        eprintln!("✗ 订阅里没有可解析的 mirage:// 节点 (格式: 每行一个 mirage:// URI, 或整段 base64)");
        return 1;
    }

    let mut taken = existing_outbound_tags(&root);
    let mut seen: std::collections::HashSet<(String, u16)> = root["outbounds"].as_array().unwrap().iter()
        .filter(|o| o.get("type").and_then(|t| t.as_str()) == Some("mirage"))
        .filter_map(|o| Some((o.get("server")?.as_str()?.to_string(), u16::try_from(o.get("server_port")?.as_u64()?).ok()?)))
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
    // 建组时若节点跨区域给出告警 (与 import --group 一致)
    if group.is_some() {
        if let Some(db) = load_node_geoip(&root) {
            if let Some(w) = mixed_region_warning(&root, &db).await {
                eprintln!("  {w}");
            }
        }
    }
    0
}

type GeoIpDb = Vec<(String, Vec<ipnet::IpNet>)>;

/// 从配置的 tuning 找到 geoip.dat 并解析成 (国家码, CIDRs) 全表, 供节点区域判定。
/// 找不到 geodata_dir / geoip 文件 / 解析失败 → None (区域功能静默降级)。
fn load_node_geoip(root: &serde_json::Value) -> Option<GeoIpDb> {
    let tuning = root.get("tuning")?;
    let dir = tuning.get("geodata_dir").and_then(|d| d.as_str())?;
    // geo_sources 里 kind=geoip 的 name → <dir>/<name>.dat; 否则默认 <dir>/geoip.dat
    let name = tuning.get("geo_sources").and_then(|s| s.as_array())
        .and_then(|arr| arr.iter().find(|s| s.get("kind").and_then(|k| k.as_str()) == Some("geoip")))
        .and_then(|s| s.get("name").and_then(|n| n.as_str()))
        .unwrap_or("geoip");
    let path = std::path::Path::new(dir).join(format!("{name}.dat"));
    mirage_rs::router::geo::load_all_geoip(&path).ok()
}

/// 查某 host (IP 字面量或域名) 所在国家码。域名走**带超时的异步解析** (tokio, 不阻塞
/// worker; 慢 resolver 3s 即放弃) 取首个 IP。查不到 None。
async fn region_for_host(geoip: &GeoIpDb, host: &str) -> Option<String> {
    use std::net::IpAddr;
    let ip: IpAddr = if let Ok(ip) = host.parse::<IpAddr>() {
        ip
    } else {
        tokio::time::timeout(
            std::time::Duration::from_secs(3),
            tokio::net::lookup_host((host, 0u16)),
        )
        .await
        .ok()?
        .ok()?
        .next()?
        .ip()
    };
    mirage_rs::router::geo::country_for_ip(geoip, ip)
}

/// 配置里 mirage 节点若跨多个区域, 返回告警串 (供 --group 建组时提示混区域)。
/// 无 geoip / 全同区 / <2 区域 → None。少量节点顺序解析。
async fn mixed_region_warning(root: &serde_json::Value, geoip: &GeoIpDb) -> Option<String> {
    let mut by_region: std::collections::BTreeMap<String, usize> = Default::default();
    let mut unknown = 0usize;
    for (_tag, server, ..) in mirage_outbounds(root) {
        match region_for_host(geoip, &server).await {
            Some(c) => *by_region.entry(c).or_default() += 1,
            None => unknown += 1,
        }
    }
    if by_region.len() <= 1 {
        return None;
    }
    let summary: Vec<String> = by_region.iter().map(|(c, n)| format!("{c}×{n}")).collect();
    Some(format!(
        "⚠ 组内节点跨 {} 个区域 ({}{}) —— 负载均衡/自动选路会让出口国不一致 (落地解锁/延迟受影响)。建议同区域各自分组。",
        by_region.len(),
        summary.join(" "),
        if unknown > 0 { format!(", {unknown} 个未知") } else { String::new() }
    ))
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

    // 节点区域 (GeoIP 查 server IP; 无 geoip.dat 则空)。解析带超时, 少量节点顺序即可。
    let geoip = load_node_geoip(&root);
    let mut regions: Vec<String> = Vec::with_capacity(nodes.len());
    for (_, server, ..) in &nodes {
        let r = match &geoip {
            Some(db) => region_for_host(db, server).await.map(|c| format!("[{c}]")).unwrap_or_default(),
            None => String::new(),
        };
        regions.push(r);
    }

    let mut failed = 0;
    for (i, (tag, server, port, ..)) in nodes.iter().enumerate() {
        print!("  {tag:<16} {server}:{port} {:<5} … ", regions[i]);
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

/// 合并 JSON 片段的结果统计。
#[derive(Default)]
struct MergeReport {
    added_nodes: u32,
    dup_nodes: u32,
    added_groups: u32,
    added_geo: u32,
    added_rules: u32,
    dropped_rules: u32,
    renamed: Vec<(String, String)>, // 片段原 tag → 改名后 (撞现有 tag)
    skipped_groups: Vec<String>,    // 成员合并后为空而跳过的组 (改名后的 tag)
}

/// 把 export 产出的 JSON 片段合并进配置 root (纯函数, 便于单测)。
///
/// - 节点按 `server:port` 去重: dup 不重复加, 但把片段里它的 tag **重映射到配置里已有同址节点**,
///   使引用它的组/规则不悬空。
/// - tag 撞现有出站则自动改名 (`unique_auto_tag`), 并全程重映射到组成员 / 规则 outbound。
/// - 组成员 / 规则 outbound 经重映射后仍不在最终出站集合里 → 丢弃 (组剔空则跳过整组)。
/// - `direct`/`block` 同名已存在则跳过 (不重复内建叶子)。
/// - `geo_sources` 按 `name` 去重合并; `geodata_dir` 仅在配置缺失时设。
/// - `include_routing` 为真才并入 `routing.rules` (侵入性)。`default_outbound` **一律不动**。
fn merge_fragment(root: &mut serde_json::Value, frag: &serde_json::Value, include_routing: bool) -> MergeReport {
    use serde_json::Value;
    let mut rep = MergeReport::default();
    if !root.get("outbounds").map(|v| v.is_array()).unwrap_or(false) {
        root["outbounds"] = Value::Array(Vec::new());
    }

    let mut taken = existing_outbound_tags(root);
    // 现有 mirage 节点的 (host,port) → tag, 供 dup 重映射; 现有 tag → type, 供 direct/block 同类判断
    let mut host_port: std::collections::HashMap<(String, u16), String> = std::collections::HashMap::new();
    let mut existing_type: std::collections::HashMap<String, String> = std::collections::HashMap::new();
    for o in root["outbounds"].as_array().unwrap() {
        let tag = o.get("tag").and_then(|t| t.as_str()).unwrap_or_default().to_string();
        let ty = o.get("type").and_then(|t| t.as_str()).unwrap_or_default().to_string();
        if !tag.is_empty() {
            existing_type.insert(tag.clone(), ty.clone());
        }
        if ty == "mirage" {
            if let (Some(h), Some(p)) = (o.get("server").and_then(|s| s.as_str()), o.get("server_port").and_then(|p| p.as_u64())) {
                if let Ok(p) = u16::try_from(p) {
                    host_port.insert((h.to_string(), p), tag);
                }
            }
        }
    }

    let empty = Vec::new();
    let tag_of = |o: &Value| o.get("tag").and_then(|t| t.as_str()).unwrap_or("").to_string();
    let type_of = |o: &Value| o.get("type").and_then(|t| t.as_str()).unwrap_or("").to_string();
    let mut remap: std::collections::HashMap<String, String> = std::collections::HashMap::new();

    // 1. 节点
    for n in frag.get("nodes").and_then(|n| n.as_array()).unwrap_or(&empty) {
        let orig = tag_of(n);
        let host = n.get("server").and_then(|s| s.as_str()).unwrap_or("").to_string();
        let Some(port) = n.get("server_port").and_then(|p| p.as_u64()).and_then(|p| u16::try_from(p).ok()) else {
            continue; // 无效端口, 跳过
        };
        let key = (host.clone(), port);
        if let Some(existing) = host_port.get(&key) {
            if !orig.is_empty() {
                remap.insert(orig, existing.clone()); // dup → 指向已有节点
            }
            rep.dup_nodes += 1;
            continue;
        }
        let base = if orig.is_empty() { host.as_str() } else { orig.as_str() };
        let newtag = unique_auto_tag(base, &mut taken);
        if !orig.is_empty() {
            if newtag != orig {
                rep.renamed.push((orig.clone(), newtag.clone()));
            }
            remap.insert(orig, newtag.clone());
        }
        let mut nc = n.clone();
        nc["tag"] = Value::String(newtag.clone());
        root["outbounds"].as_array_mut().unwrap().push(nc);
        host_port.insert(key, newtag);
        rep.added_nodes += 1;
    }

    // 2a. 组: 先给所有组分配最终 tag (登记 remap, 供成员前向引用)
    let group_types = ["urltest", "fallback", "selector", "load_balance"];
    let frag_out = frag.get("outbounds").and_then(|o| o.as_array()).unwrap_or(&empty);
    let mut group_newtags: Vec<(usize, String)> = Vec::new();
    for (i, g) in frag_out.iter().enumerate() {
        if !group_types.contains(&type_of(g).as_str()) {
            continue;
        }
        let orig = tag_of(g);
        if orig.is_empty() {
            continue;
        }
        let newtag = unique_auto_tag(&orig, &mut taken);
        if newtag != orig {
            rep.renamed.push((orig.clone(), newtag.clone()));
        }
        remap.insert(orig, newtag.clone());
        group_newtags.push((i, newtag));
    }
    // 2b. direct/block: **同 tag 同 type** 已存在才 dedup 跳过 (remap 恒等); 撞到异类出站则改名
    // 重映射 (否则片段的 block 会静默指到配置里同名的 direct/节点, 引用错类型)。
    for g in frag_out {
        let t = type_of(g);
        if t != "direct" && t != "block" {
            continue;
        }
        let tag = tag_of(g);
        if tag.is_empty() {
            continue;
        }
        if existing_type.get(&tag).map(|et| et == &t).unwrap_or(false) {
            remap.entry(tag.clone()).or_insert(tag); // 真·同类重复, 恒等
            continue;
        }
        if taken.contains(&tag) {
            // tag 被异类出站占用 → 改名
            let newtag = unique_auto_tag(&tag, &mut taken);
            rep.renamed.push((tag.clone(), newtag.clone()));
            remap.insert(tag, newtag.clone());
            let mut gc = g.clone();
            gc["tag"] = Value::String(newtag);
            root["outbounds"].as_array_mut().unwrap().push(gc);
        } else {
            remap.entry(tag.clone()).or_insert_with(|| tag.clone());
            root["outbounds"].as_array_mut().unwrap().push(g.clone());
            taken.push(tag);
        }
    }

    // 2c. 组落地 (present fixpoint, 学 export): present = 真实存在的出站 (节点 + direct/block +
    // 原有配置), 组只有"至少一个成员可达 present"才算 present。避免"空组 tag 仍占位 → 父组悬空"。
    let mut present: std::collections::HashSet<String> = taken.iter().cloned().collect();
    for (_, newtag) in &group_newtags {
        present.remove(newtag); // 组先移出, 下面 fixpoint 逐个加回
    }
    let member_present = |g: &Value, present: &std::collections::HashSet<String>| -> bool {
        g.get("outbounds").and_then(|m| m.as_array()).map(|ms| ms.iter().any(|m| {
            m.as_str().map(|s| present.contains(remap.get(s).map(String::as_str).unwrap_or(s))).unwrap_or(false)
        })).unwrap_or(false)
    };
    loop {
        let mut added = false;
        for (i, newtag) in &group_newtags {
            if present.contains(newtag) {
                continue;
            }
            if member_present(&frag_out[*i], &present) {
                present.insert(newtag.clone());
                added = true;
            }
        }
        if !added {
            break;
        }
    }
    // 按配置顺序落地 present 组, 成员过滤到 present (保证无悬空)
    for (i, newtag) in &group_newtags {
        if !present.contains(newtag) {
            rep.skipped_groups.push(newtag.clone());
            continue;
        }
        let g = &frag_out[*i];
        let members = g.get("outbounds").and_then(|m| m.as_array()).cloned().unwrap_or_default();
        let mapped: Vec<Value> = members.iter().filter_map(|m| {
            let s = m.as_str()?;
            let resolved = remap.get(s).cloned().unwrap_or_else(|| s.to_string());
            present.contains(&resolved).then_some(Value::String(resolved))
        }).collect();
        let mut gc = g.clone();
        gc["tag"] = Value::String(newtag.clone());
        gc["outbounds"] = Value::Array(mapped);
        root["outbounds"].as_array_mut().unwrap().push(gc);
        rep.added_groups += 1;
    }

    // 3. 路由规则 (可选): outbound 重映射, 悬空丢弃; default_outbound 不动
    if include_routing {
        if let Some(rules) = frag.get("routing").and_then(|r| r.get("rules")).and_then(|r| r.as_array()) {
            if !root.get("routing").map(|r| r.is_object()).unwrap_or(false) {
                root["routing"] = serde_json::json!({});
            }
            if !root["routing"].get("rules").map(|r| r.is_array()).unwrap_or(false) {
                root["routing"]["rules"] = Value::Array(Vec::new());
            }
            for r in rules {
                let ob = r.get("outbound").and_then(|o| o.as_str()).unwrap_or("");
                let resolved = remap.get(ob).cloned().unwrap_or_else(|| ob.to_string());
                if !present.contains(&resolved) {
                    rep.dropped_rules += 1; // 指向不存在/被跳过的出站 → 丢弃
                    continue;
                }
                let mut rc = r.clone();
                rc["outbound"] = Value::String(resolved);
                root["routing"]["rules"].as_array_mut().unwrap().push(rc);
                rep.added_rules += 1;
            }
        }
    }

    // 4. geo_sources (按 name 去重) + geodata_dir (缺则设)
    if let Some(gs) = frag.get("geo_sources").and_then(|g| g.as_array()) {
        if !root.get("tuning").map(|t| t.is_object()).unwrap_or(false) {
            root["tuning"] = serde_json::json!({});
        }
        if !root["tuning"].get("geo_sources").map(|g| g.is_array()).unwrap_or(false) {
            root["tuning"]["geo_sources"] = Value::Array(Vec::new());
        }
        let have: std::collections::HashSet<String> = root["tuning"]["geo_sources"].as_array().unwrap().iter()
            .filter_map(|s| s.get("name").and_then(|n| n.as_str()).map(str::to_string)).collect();
        for s in gs {
            let name = s.get("name").and_then(|n| n.as_str()).unwrap_or("");
            if name.is_empty() || have.contains(name) {
                continue;
            }
            root["tuning"]["geo_sources"].as_array_mut().unwrap().push(s.clone());
            rep.added_geo += 1;
        }
    }
    if let Some(dir) = frag.get("geodata_dir") {
        if root.get("tuning").and_then(|t| t.get("geodata_dir")).is_none() {
            if !root.get("tuning").map(|t| t.is_object()).unwrap_or(false) {
                root["tuning"] = serde_json::json!({});
            }
            root["tuning"]["geodata_dir"] = dir.clone();
        }
    }

    rep
}

/// 合并 JSON 片段并写回配置。校验片段含 nodes, 合并后原子写回, 打印统计。
fn apply_fragment(path: &str, content: &str, mut root: serde_json::Value, body: &str, include_routing: bool) -> i32 {
    let frag: serde_json::Value = match serde_json::from_str(body) {
        Ok(v) => v,
        Err(e) => { eprintln!("✗ 片段不是合法 JSON: {e}"); return 1; }
    };
    if !frag.get("nodes").map(|n| n.is_array()).unwrap_or(false) {
        eprintln!("✗ 片段缺 nodes 数组, 不像 export 产出的配置片段");
        return 1;
    }
    let rep = merge_fragment(&mut root, &frag, include_routing);
    if rep.added_nodes == 0 && rep.added_groups == 0 && rep.added_geo == 0 && rep.added_rules == 0 {
        println!("✓ 片段无新增 (节点/组/geo/规则都已存在), 配置未改动");
        return 0;
    }
    let rendered = match serde_json::to_string_pretty(&root) {
        Ok(s) => s + "\n",
        Err(e) => { eprintln!("✗ 序列化失败: {e}"); return 1; }
    };
    if let Err(e) = atomic_write_config(path, content, &rendered) {
        eprintln!("✗ {e}");
        return 1;
    }
    println!("✓ 已合并片段并写回 {path} (原文件备份: {path}.bak)");
    println!(
        "  节点 +{} (dup 跳过 {}), 组 +{}, geo +{}, {}",
        rep.added_nodes, rep.dup_nodes, rep.added_groups, rep.added_geo,
        if include_routing {
            format!("规则 +{} (悬空丢弃 {})", rep.added_rules, rep.dropped_rules)
        } else {
            "未并路由 (加 --routing 才并规则)".to_string()
        },
    );
    for (o, n) in &rep.renamed {
        println!("  改名: `{o}` → `{n}` (撞现有 tag; 引用它的组/规则已同步)");
    }
    for g in &rep.skipped_groups {
        println!("  跳过组 `{g}` (成员合并后为空)");
    }
    println!("  `mirage-rs check -c {path}` 确认后重启。");
    0
}

/// 从整份配置构造导出片段 (纯函数, 便于单测)。
///
/// `picked` = 要导出的 mirage 节点 tag。组自动纳入 —— 成员过滤到已导出集合 (所选节点 +
/// direct/block + 已纳入组), 剔空则跳过, 嵌套组靠 fixpoint 收敛。规则/geo 按开关带上;
/// 规则只留 `outbound` 指向已导出出站的; 被引用的 direct/block 对象一并带出。
fn build_export(
    root: &serde_json::Value,
    picked: &std::collections::HashSet<String>,
    include_rules: bool,
    include_geo: bool,
) -> serde_json::Value {
    use serde_json::{json, Value};
    let empty = Vec::new();
    let outbounds = root.get("outbounds").and_then(|v| v.as_array()).unwrap_or(&empty);
    let type_of = |o: &Value| o.get("type").and_then(|t| t.as_str()).unwrap_or("").to_string();
    let tag_of = |o: &Value| o.get("tag").and_then(|t| t.as_str()).unwrap_or("").to_string();

    // 导出的 mirage 节点对象
    let nodes: Vec<Value> = outbounds.iter()
        .filter(|o| type_of(o) == "mirage" && picked.contains(&tag_of(o)))
        .cloned().collect();

    // 已导出出站集合 (供组/规则引用解析): 所选节点 + 全部 direct/block (内建叶子)
    let mut exported: std::collections::HashSet<String> = picked.clone();
    for o in outbounds {
        let t = type_of(o);
        if t == "direct" || t == "block" {
            exported.insert(tag_of(o));
        }
    }

    // 组 fixpoint (两阶段): 先纯求可达出站集合 exported (哪些组能被纳入), 收敛后再按**最终**
    // 集合过滤每组成员。单阶段会有序 bug: 组A 引用组B 且先于 B 处理时, A 成员冻结成缺 B, 之后
    // A 已在 exported 不再重算 → 永久缺 B。分开"求集合"与"过滤成员"即可避免。
    let group_types = ["urltest", "fallback", "selector", "load_balance"];
    let all_groups: Vec<&Value> = outbounds.iter()
        .filter(|o| group_types.contains(&type_of(o).as_str()))
        .collect();
    loop {
        let mut added = false;
        for g in &all_groups {
            let tag = tag_of(g);
            if tag.is_empty() || exported.contains(&tag) {
                continue; // 无 tag 或已纳入
            }
            let Some(members) = g.get("outbounds").and_then(|m| m.as_array()) else { continue };
            let has_member = members.iter()
                .any(|m| m.as_str().map(|s| exported.contains(s)).unwrap_or(false));
            if has_member {
                exported.insert(tag); // 至少一个成员可达 → 组可纳入
                added = true;
            }
        }
        if !added {
            break;
        }
    }
    // exported 已收敛; 按最终集合过滤每个被纳入组的成员 (保持配置顺序)
    let kept_groups: Vec<Value> = all_groups.iter().filter_map(|g| {
        let tag = tag_of(g);
        if tag.is_empty() || !exported.contains(&tag) {
            return None;
        }
        let members = g.get("outbounds").and_then(|m| m.as_array())?;
        let kept: Vec<Value> = members.iter()
            .filter(|m| m.as_str().map(|s| exported.contains(s)).unwrap_or(false))
            .cloned().collect();
        let mut gc = (*g).clone();
        gc["outbounds"] = Value::Array(kept);
        Some(gc)
    }).collect();

    // 收集被引用 tag (组成员 + 后面规则的 outbound), 决定带哪些 direct/block
    let mut referenced: std::collections::HashSet<String> = std::collections::HashSet::new();
    for g in &kept_groups {
        if let Some(ms) = g.get("outbounds").and_then(|m| m.as_array()) {
            for m in ms {
                if let Some(s) = m.as_str() {
                    referenced.insert(s.to_string());
                }
            }
        }
    }

    // 路由 (可选): 只留 outbound ∈ exported 的规则; default_outbound 同理
    let routing = root.get("routing");
    let mut out_routing = serde_json::Map::new();
    if include_rules {
        if let Some(rules) = routing.and_then(|r| r.get("rules")).and_then(|r| r.as_array()) {
            let kept_rules: Vec<Value> = rules.iter()
                .filter(|r| r.get("outbound").and_then(|o| o.as_str())
                    .map(|o| exported.contains(o)).unwrap_or(false))
                .cloned().collect();
            for r in &kept_rules {
                if let Some(o) = r.get("outbound").and_then(|o| o.as_str()) {
                    referenced.insert(o.to_string());
                }
            }
            out_routing.insert("rules".into(), Value::Array(kept_rules));
        }
        if let Some(d) = routing.and_then(|r| r.get("default_outbound")).and_then(|d| d.as_str()) {
            if exported.contains(d) {
                out_routing.insert("default_outbound".into(), json!(d));
                referenced.insert(d.to_string());
            }
        }
    }

    // 被引用的 direct/block 对象带上 (和组一起放 outbounds)
    let mut out_outbounds = kept_groups;
    for o in outbounds {
        let t = type_of(o);
        if (t == "direct" || t == "block") && referenced.contains(&tag_of(o)) {
            out_outbounds.push((*o).clone());
        }
    }

    let mut export = serde_json::Map::new();
    export.insert("nodes".into(), Value::Array(nodes));
    export.insert("outbounds".into(), Value::Array(out_outbounds));
    if !out_routing.is_empty() {
        export.insert("routing".into(), Value::Object(out_routing));
    }
    if include_geo {
        if let Some(tuning) = root.get("tuning") {
            if let Some(gs) = tuning.get("geo_sources") {
                export.insert("geo_sources".into(), gs.clone());
            }
            if let Some(dir) = tuning.get("geodata_dir") {
                export.insert("geodata_dir".into(), dir.clone());
            }
        }
    }
    Value::Object(export)
}

/// 解析 "1,3,5-7" 形式的 1-based 序号选择为 0-based 去重升序索引。越界/非法 → Err。
fn parse_index_selection(sel: &str, n: usize) -> Result<Vec<usize>, String> {
    let mut set = std::collections::BTreeSet::new();
    for part in sel.split(',').map(str::trim).filter(|p| !p.is_empty()) {
        if let Some((a, b)) = part.split_once('-') {
            let a: usize = a.trim().parse().map_err(|_| format!("非法区间 `{part}`"))?;
            let b: usize = b.trim().parse().map_err(|_| format!("非法区间 `{part}`"))?;
            if a == 0 || a > b || b > n {
                return Err(format!("区间 `{part}` 越界 (有效 1..={n})"));
            }
            for i in a..=b {
                set.insert(i - 1);
            }
        } else {
            let i: usize = part.parse().map_err(|_| format!("非法序号 `{part}`"))?;
            if i == 0 || i > n {
                return Err(format!("序号 `{i}` 越界 (有效 1..={n})"));
            }
            set.insert(i - 1);
        }
    }
    if set.is_empty() {
        return Err("空选择".into());
    }
    Ok(set.into_iter().collect())
}

/// 读一行 stdin (trim)。EOF / 管道关闭 → 空串。提示走 stderr (不污染 stdout 的 JSON)。
fn prompt_line(prompt: &str) -> String {
    use std::io::{BufRead, Write};
    eprint!("{prompt} ");
    let _ = std::io::stderr().flush();
    let mut s = String::new();
    match std::io::stdin().lock().read_line(&mut s) {
        Ok(0) | Err(_) => String::new(),
        Ok(_) => s.trim().to_string(),
    }
}

/// y/n 提示。空 / EOF → default。
fn prompt_yes_no(prompt: &str, default: bool) -> bool {
    let d = if default { "Y/n" } else { "y/N" };
    let ans = prompt_line(&format!("{prompt} [{d}]:"));
    match ans.chars().next() {
        Some('y' | 'Y') => true,
        Some('n' | 'N') => false,
        _ => default,
    }
}

/// 两路径是否指向同一文件 (都存在则比 canonicalize, 否则退化为字符串相等)。
fn same_file(a: &str, b: &str) -> bool {
    match (std::fs::canonicalize(a), std::fs::canonicalize(b)) {
        (Ok(x), Ok(y)) => x == y,
        _ => a == b,
    }
}

/// 交互式导出配置片段。列 mirage 节点让用户选, 问是否带规则/geo, 构造后写 out 或 stdout。
fn run_export(path: &str, out: Option<&str>) -> i32 {
    use std::io::Write;
    // 防误覆盖源配置: 导出的是**片段**不是完整配置, 写回 config 会毁掉它
    if let Some(p) = out {
        if same_file(p, path) {
            eprintln!("✗ 拒绝: 输出 `{p}` 与源配置 `{path}` 是同一文件 (导出是片段, 会覆盖源配置)");
            return 1;
        }
    }
    let content = match std::fs::read_to_string(path) {
        Ok(c) => c,
        Err(e) => { eprintln!("✗ 读不了 {path}: {e}"); return 1; }
    };
    let root: serde_json::Value = match serde_json::from_str(&content) {
        Ok(v) => v,
        Err(e) => { eprintln!("✗ {path} 不是合法 JSON: {e}"); return 1; }
    };
    let empty = Vec::new();
    let nodes: Vec<&serde_json::Value> = root.get("outbounds").and_then(|v| v.as_array()).unwrap_or(&empty)
        .iter().filter(|o| o.get("type").and_then(|t| t.as_str()) == Some("mirage")).collect();
    if nodes.is_empty() {
        eprintln!("✗ {path} 里没有 mirage 节点可导出");
        return 1;
    }
    eprintln!("mirage 节点 ({} 个):", nodes.len());
    for (i, n) in nodes.iter().enumerate() {
        let tag = n.get("tag").and_then(|t| t.as_str()).unwrap_or("?");
        let server = n.get("server").and_then(|t| t.as_str()).unwrap_or("?");
        let port = n.get("server_port").and_then(|p| p.as_u64()).unwrap_or(0);
        eprintln!("  [{}] {tag}  {server}:{port}", i + 1);
    }
    let sel = prompt_line("选导出哪些 (回车/all=全部, 或 1,3,5-7):");
    let picked: std::collections::HashSet<String> = if sel.is_empty() || sel == "all" {
        nodes.iter().filter_map(|n| n.get("tag").and_then(|t| t.as_str()).map(str::to_string)).collect()
    } else {
        match parse_index_selection(&sel, nodes.len()) {
            Ok(idxs) => idxs.iter()
                .filter_map(|&i| nodes[i].get("tag").and_then(|t| t.as_str()).map(str::to_string)).collect(),
            Err(e) => { eprintln!("✗ 选择无效: {e}"); return 1; }
        }
    };
    if picked.is_empty() {
        eprintln!("✗ 没选中任何节点");
        return 1;
    }
    let include_rules = prompt_yes_no("导出路由规则? (只带指向已选出站的)", true);
    let include_geo = prompt_yes_no("导出 geo 下载地址 (geo_sources/geodata_dir)?", true);

    let export = build_export(&root, &picked, include_rules, include_geo);
    let ng = export.get("outbounds").and_then(|o| o.as_array()).map(|a| a.len()).unwrap_or(0);
    eprintln!(
        "导出 {} 个节点, {ng} 个出站(组/direct/block){}{}。",
        picked.len(),
        if include_rules { ", 带路由规则" } else { "" },
        if include_geo { ", 带 geo" } else { "" },
    );

    let rendered = match serde_json::to_string_pretty(&export) {
        Ok(s) => s + "\n",
        Err(e) => { eprintln!("✗ 序列化失败: {e}"); return 1; }
    };
    match out {
        Some(p) => {
            if let Err(e) = std::fs::write(p, &rendered) {
                eprintln!("✗ 写 {p} 失败: {e}");
                return 1;
            }
            eprintln!("✓ 已写 {p}");
        }
        None => {
            let _ = std::io::stdout().write_all(rendered.as_bytes());
        }
    }
    0
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    // check / format 是纯本地工具: 不初始化日志、不起服务、不碰网络。
    match &args.mode {
        Mode::Check { config } => std::process::exit(run_check(config)),
        Mode::Format { config } => std::process::exit(run_format(config)),
        Mode::Export { config, out } => std::process::exit(run_export(config, out.as_deref())),
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
        config, source, routing, group, group_name,
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
        std::process::exit(run_subscribe(config, source, g, &opts, *routing, *timeout).await);
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
    use super::{build_export, merge_fragment, mirage_outbounds, parse_index_selection, parse_subscription, unique_auto_tag};

    #[test]
    fn parse_subscription_plaintext_and_filters() {
        let body = "# 注释\n\nmirage://p1@a.com:443?sni=www.apple.com\nnot-a-node\nmirage://p2@b.com:8443?sni=www.bing.com\n";
        let nodes = parse_subscription(body);
        assert_eq!(nodes.len(), 2, "跳过注释/空行/非 mirage 行");
        assert_eq!(nodes[0].host, "a.com");
        assert_eq!(nodes[1].port, 8443);
    }

    #[test]
    fn parse_subscription_base64_all_alphabets() {
        use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD};
        use base64::Engine;
        // 两个节点, 保证编码里出现需 url-safe 的字符差异; 逐个字母表都应解出。
        let plain = "mirage://p1@a.example.com:443?sni=www.apple.com\nmirage://p2@b.example.com:8443?sni=www.bing.com";
        for b64 in [
            STANDARD.encode(plain),
            STANDARD_NO_PAD.encode(plain),
            URL_SAFE.encode(plain),
            URL_SAFE_NO_PAD.encode(plain),
        ] {
            let nodes = parse_subscription(&b64);
            assert_eq!(nodes.len(), 2, "base64 变体应都解出: {b64}");
            assert_eq!(nodes[0].host, "a.example.com");
        }
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

    #[test]
    fn index_selection_parses_ranges_and_dedups() {
        assert_eq!(parse_index_selection("1,3,5-7", 7).unwrap(), vec![0, 2, 4, 5, 6]);
        assert_eq!(parse_index_selection("2, 2 , 1", 3).unwrap(), vec![0, 1], "去重+排序");
        assert!(parse_index_selection("5", 3).is_err(), "越上界");
        assert!(parse_index_selection("0", 3).is_err(), "0 非法 (1-based)");
        assert!(parse_index_selection("3-1", 3).is_err(), "逆区间");
        assert!(parse_index_selection("x", 3).is_err(), "非数字");
        assert!(parse_index_selection("", 3).is_err(), "空选择");
    }

    fn cfg_for_export() -> serde_json::Value {
        serde_json::json!({
            "outbounds": [
                { "type": "mirage", "tag": "n1", "server": "h1", "server_port": 443, "password": "p", "camouflage_host": "s" },
                { "type": "mirage", "tag": "n2", "server": "h2", "server_port": 443, "password": "p", "camouflage_host": "s" },
                { "type": "mirage", "tag": "n3", "server": "h3", "server_port": 443, "password": "p", "camouflage_host": "s" },
                { "type": "direct", "tag": "direct" },
                { "type": "load_balance", "tag": "grpA", "outbounds": ["n1", "n2", "direct"] },
                { "type": "urltest",      "tag": "grpB", "outbounds": ["n2", "n3"] },
                { "type": "urltest",      "tag": "grpC", "outbounds": ["n3"] }
            ],
            "routing": { "default_outbound": "grpB", "rules": [
                { "outbound": "grpA", "domain_suffix": "a.com" },
                { "outbound": "n3",   "domain_suffix": "b.com" }
            ] },
            "tuning": { "geodata_dir": "/etc/mirage/geo", "geo_sources": [ { "kind": "geoip", "name": "geoip", "url": "http://x/geoip.dat" } ] }
        })
    }

    #[test]
    fn export_filters_groups_rules_and_carries_referenced_direct() {
        let root = cfg_for_export();
        let picked: std::collections::HashSet<String> = ["n1", "n2"].iter().map(|s| s.to_string()).collect();
        let e = build_export(&root, &picked, true, true);

        // 节点: 只 n1,n2
        let nodes = e["nodes"].as_array().unwrap();
        assert_eq!(nodes.len(), 2);

        // 组: grpA 全在 (n1,n2,direct) 保留; grpB 剔除 n3 → [n2]; grpC 全未选 → 跳过
        let groups: std::collections::HashMap<&str, &serde_json::Value> = e["outbounds"].as_array().unwrap()
            .iter().filter(|o| o["type"] == "load_balance" || o["type"] == "urltest")
            .map(|o| (o["tag"].as_str().unwrap(), o)).collect();
        assert!(groups.contains_key("grpA"));
        assert_eq!(groups["grpA"]["outbounds"], serde_json::json!(["n1", "n2", "direct"]));
        assert_eq!(groups["grpB"]["outbounds"], serde_json::json!(["n2"]), "剔除未选 n3");
        assert!(!groups.contains_key("grpC"), "全未选 → 跳过");

        // direct 被 grpA 引用 → 带上
        assert!(e["outbounds"].as_array().unwrap().iter().any(|o| o["tag"] == "direct"));

        // 规则: grpA 规则留, n3 规则丢; default_outbound=grpB 保留 (grpB 已导出)
        let rules = e["routing"]["rules"].as_array().unwrap();
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0]["outbound"], "grpA");
        assert_eq!(e["routing"]["default_outbound"], "grpB");

        // geo 带上
        assert_eq!(e["geodata_dir"], "/etc/mirage/geo");
        assert!(e["geo_sources"].is_array());
    }

    #[test]
    fn export_nested_group_before_dependency_keeps_member() {
        // 组A 引用组B 且在配置里排在 B 前面 —— 修复前 (单阶段 fixpoint) A 会永久缺 B
        let root = serde_json::json!({
            "outbounds": [
                { "type": "mirage", "tag": "n1", "server": "h1", "server_port": 443, "password": "p", "camouflage_host": "s" },
                { "type": "mirage", "tag": "n2", "server": "h2", "server_port": 443, "password": "p", "camouflage_host": "s" },
                { "type": "fallback", "tag": "grpA", "outbounds": ["grpB", "n1"] },
                { "type": "urltest",  "tag": "grpB", "outbounds": ["n2"] }
            ]
        });
        let picked: std::collections::HashSet<String> = ["n1", "n2"].iter().map(|s| s.to_string()).collect();
        let e = build_export(&root, &picked, false, false);
        let ga = e["outbounds"].as_array().unwrap().iter().find(|o| o["tag"] == "grpA").unwrap();
        assert_eq!(ga["outbounds"], serde_json::json!(["grpB", "n1"]), "嵌套组顺序无关, grpA 必须保留 grpB");
        let gb = e["outbounds"].as_array().unwrap().iter().find(|o| o["tag"] == "grpB").unwrap();
        assert_eq!(gb["outbounds"], serde_json::json!(["n2"]));
    }

    #[test]
    fn merge_adds_nodes_group_geo() {
        let mut root = serde_json::json!({ "outbounds": [ { "type": "direct", "tag": "direct" } ] });
        let frag = serde_json::json!({
            "nodes": [
                { "type": "mirage", "tag": "n1", "server": "h1", "server_port": 443, "password": "p", "camouflage_host": "s" },
                { "type": "mirage", "tag": "n2", "server": "h2", "server_port": 443, "password": "p", "camouflage_host": "s" }
            ],
            "outbounds": [ { "type": "load_balance", "tag": "lb", "outbounds": ["n1", "n2"] } ],
            "geo_sources": [ { "kind": "geoip", "name": "geoip", "url": "http://x/geoip.dat" } ],
            "geodata_dir": "/geo"
        });
        let rep = merge_fragment(&mut root, &frag, false);
        assert_eq!((rep.added_nodes, rep.added_groups, rep.added_geo), (2, 1, 1));
        let obs = root["outbounds"].as_array().unwrap();
        let lb = obs.iter().find(|o| o["tag"] == "lb").unwrap();
        assert_eq!(lb["outbounds"], serde_json::json!(["n1", "n2"]));
        assert_eq!(root["tuning"]["geodata_dir"], "/geo");
        assert_eq!(root["tuning"]["geo_sources"].as_array().unwrap().len(), 1);
    }

    #[test]
    fn merge_renames_colliding_tag_and_remaps_group() {
        // 配置已有 tag n1 (不同 server) → 片段 n1 改名 n1-2, 组成员同步
        let mut root = serde_json::json!({ "outbounds": [
            { "type": "mirage", "tag": "n1", "server": "OTHER", "server_port": 443, "password": "p", "camouflage_host": "s" }
        ]});
        let frag = serde_json::json!({
            "nodes": [ { "type": "mirage", "tag": "n1", "server": "h1", "server_port": 443, "password": "p", "camouflage_host": "s" } ],
            "outbounds": [ { "type": "urltest", "tag": "grp", "outbounds": ["n1"] } ]
        });
        let rep = merge_fragment(&mut root, &frag, false);
        assert_eq!(rep.added_nodes, 1);
        assert_eq!(rep.renamed, vec![("n1".to_string(), "n1-2".to_string())]);
        let grp = root["outbounds"].as_array().unwrap().iter().find(|o| o["tag"] == "grp").unwrap();
        assert_eq!(grp["outbounds"], serde_json::json!(["n1-2"]), "组成员重映射到改名后");
    }

    #[test]
    fn merge_dedups_by_hostport_remaps_to_existing() {
        // 配置已有同址节点 (tag existing) → 片段 n1 dup, 组引用指向 existing
        let mut root = serde_json::json!({ "outbounds": [
            { "type": "mirage", "tag": "existing", "server": "h1", "server_port": 443, "password": "p", "camouflage_host": "s" }
        ]});
        let frag = serde_json::json!({
            "nodes": [ { "type": "mirage", "tag": "n1", "server": "h1", "server_port": 443, "password": "p", "camouflage_host": "s" } ],
            "outbounds": [ { "type": "urltest", "tag": "grp", "outbounds": ["n1"] } ]
        });
        let rep = merge_fragment(&mut root, &frag, false);
        assert_eq!((rep.added_nodes, rep.dup_nodes), (0, 1));
        let grp = root["outbounds"].as_array().unwrap().iter().find(|o| o["tag"] == "grp").unwrap();
        assert_eq!(grp["outbounds"], serde_json::json!(["existing"]), "dup 节点的组引用指向已有 tag");
    }

    #[test]
    fn merge_routing_gated_and_drops_dangling() {
        let frag = serde_json::json!({
            "nodes": [ { "type": "mirage", "tag": "n1", "server": "h1", "server_port": 443, "password": "p", "camouflage_host": "s" } ],
            "outbounds": [],
            "routing": { "rules": [
                { "outbound": "n1", "domain_suffix": "a.com" },
                { "outbound": "ghost", "domain_suffix": "b.com" }
            ] }
        });
        // 不带 routing → 规则不并
        let mut r1 = serde_json::json!({ "outbounds": [] });
        let rep1 = merge_fragment(&mut r1, &frag, false);
        assert_eq!(rep1.added_rules, 0);
        assert!(r1.get("routing").is_none(), "未 --routing 不建 routing");
        // 带 routing → n1 规则留, ghost 悬空丢
        let mut r2 = serde_json::json!({ "outbounds": [] });
        let rep2 = merge_fragment(&mut r2, &frag, true);
        assert_eq!((rep2.added_rules, rep2.dropped_rules), (1, 1));
        let rules = r2["routing"]["rules"].as_array().unwrap();
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0]["outbound"], "n1");
    }

    #[test]
    fn merge_skipped_group_does_not_leave_dangling_parent() {
        // grpX 引用 grpY, grpY 全成员悬空 → grpY 跳过; grpX 只引 grpY → 也应跳过 (无悬空)
        let mut root = serde_json::json!({ "outbounds": [] });
        let frag = serde_json::json!({
            "nodes": [],
            "outbounds": [
                { "type": "fallback", "tag": "grpX", "outbounds": ["grpY"] },
                { "type": "urltest",  "tag": "grpY", "outbounds": ["ghost"] }
            ]
        });
        let rep = merge_fragment(&mut root, &frag, false);
        assert_eq!(rep.added_groups, 0, "两组都无可达成员 → 全跳过");
        let tags: Vec<&str> = root["outbounds"].as_array().unwrap().iter()
            .filter_map(|o| o["tag"].as_str()).collect();
        assert!(!tags.contains(&"grpX") && !tags.contains(&"grpY"), "不落地任何悬空组");
    }

    #[test]
    fn merge_directblock_type_mismatch_renames() {
        // 配置有 direct tag d1; 片段有 block tag d1 → 改名 d1-2, 组引用指向改名后的 block
        let mut root = serde_json::json!({ "outbounds": [ { "type": "direct", "tag": "d1" } ] });
        let frag = serde_json::json!({
            "nodes": [ { "type": "mirage", "tag": "n1", "server": "h1", "server_port": 443, "password": "p", "camouflage_host": "s" } ],
            "outbounds": [
                { "type": "block", "tag": "d1" },
                { "type": "urltest", "tag": "grp", "outbounds": ["d1", "n1"] }
            ]
        });
        let rep = merge_fragment(&mut root, &frag, false);
        assert!(rep.renamed.contains(&("d1".to_string(), "d1-2".to_string())), "异类同名改名");
        let obs = root["outbounds"].as_array().unwrap();
        let blk = obs.iter().find(|o| o["type"] == "block").unwrap();
        assert_eq!(blk["tag"], "d1-2");
        let grp = obs.iter().find(|o| o["tag"] == "grp").unwrap();
        assert_eq!(grp["outbounds"], serde_json::json!(["d1-2", "n1"]), "组引用指向改名后的 block");
        // 原 direct d1 未被动
        assert!(obs.iter().any(|o| o["type"] == "direct" && o["tag"] == "d1"));
    }

    #[test]
    fn export_can_drop_rules_and_geo() {
        let root = cfg_for_export();
        let picked: std::collections::HashSet<String> = ["n1", "n2", "n3"].iter().map(|s| s.to_string()).collect();
        let e = build_export(&root, &picked, false, false);
        assert!(e.get("routing").is_none(), "不带规则时无 routing");
        assert!(e.get("geo_sources").is_none(), "不带 geo");
        // 全选 → grpB 完整保留, grpC 保留
        let tags: Vec<&str> = e["outbounds"].as_array().unwrap().iter()
            .filter_map(|o| o["tag"].as_str()).collect();
        assert!(tags.contains(&"grpB") && tags.contains(&"grpC"));
    }
}
