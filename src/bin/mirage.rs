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

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    // check / format 是纯本地工具: 不初始化日志、不起服务、不碰网络。
    match &args.mode {
        Mode::Check { config } => std::process::exit(run_check(config)),
        Mode::Format { config } => std::process::exit(run_format(config)),
        _ => {}
    }

    let (config_path, is_server) = match &args.mode {
        Mode::Client { config } => (config.as_str(), false),
        Mode::Server { config } => (config.as_str(), true),
        _ => unreachable!("check/format 已在上面处理并退出"),
    };

    mirage_rs::start_proxy(config_path, is_server).await
}
