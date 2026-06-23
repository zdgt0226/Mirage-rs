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
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    let (config_path, is_server) = match &args.mode {
        Mode::Client { config } => (config.as_str(), false),
        Mode::Server { config } => (config.as_str(), true),
    };

    mirage_rs::start_proxy(config_path, is_server).await
}
