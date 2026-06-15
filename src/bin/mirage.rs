use clap::{Parser, Subcommand};

#[derive(Parser, Debug)]
#[command(author, version, about = "Mirage-rs Proxy Engine\nHigh-performance eBPF-accelerated proxy", long_about = None)]
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
    
    let config_path = match &args.mode {
        Mode::Client { config } => config,
        Mode::Server { config } => config,
    };

    mirage_rs::start_proxy(config_path).await
}
