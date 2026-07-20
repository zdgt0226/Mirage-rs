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

/// 导入 mirage:// 节点为新的 mirage 出站, 写回配置文件。
fn run_import(path: &str, uri: &str) -> i32 {
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

    let new_ob = serde_json::json!({
        "type": "mirage",
        "tag": tag,
        "server": node.host,
        "server_port": node.port,
        "password": node.password,
        "camouflage_host": node.sni,
    });
    root["outbounds"].as_array_mut().unwrap().push(new_ob);

    let rendered = match serde_json::to_string_pretty(&root) {
        Ok(s) => s + "\n",
        Err(e) => {
            eprintln!("✗ 序列化失败: {e}");
            return 1;
        }
    };

    // 写回是破坏性的: 先备份, 再写临时文件 + rename 原子替换 (中途失败不会留下半截配置)。
    let bak = format!("{path}.bak");
    if let Err(e) = std::fs::write(&bak, &content) {
        eprintln!("✗ 备份到 {bak} 失败: {e} (未改动原文件)");
        return 1;
    }
    let tmp = format!("{path}.tmp");
    if let Err(e) = std::fs::write(&tmp, &rendered) {
        eprintln!("✗ 写临时文件 {tmp} 失败: {e} (未改动原文件)");
        return 1;
    }
    if let Err(e) = std::fs::rename(&tmp, path) {
        eprintln!("✗ 替换 {path} 失败: {e}");
        let _ = std::fs::remove_file(&tmp);
        return 1;
    }

    println!("✓ 已导入为出站 `{tag}` → {path}  (原文件备份: {bak})");
    println!("  提示: 出站已添加, 但还没有任何路由规则使用它。");
    println!("        要让流量走它, 把 routing.default_outbound 或某条 rule 的 outbound 改为 `{tag}`,");
    println!("        然后 `mirage-rs check -c {path}` 确认无误再重启。");
    0
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
        Mode::Import { config, uri } => std::process::exit(run_import(config, uri)),
        _ => {}
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
        _ => unreachable!("check/format/import/lite-* 已在上面处理"),
    };

    mirage_rs::start_proxy(config_path, is_server).await
}
