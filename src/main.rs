use clap::Parser;
use siphon::SiphonServer;

#[derive(Parser)]
#[command(name = "siphon", about = "SIPhon — high-performance SIP proxy, B2BUA and IMS platform")]
struct Cli {
    /// Path to the configuration file
    #[arg(short = 'c', long = "config", default_value = "siphon.yaml")]
    config: String,
}

fn main() {
    let cli = Cli::parse();

    SiphonServer::builder()
        .config_path(&cli.config)
        .run();
}
