use clap::Parser;
use huginn_collector::NetworkCollectorBuilder;
use tokio::time::{sleep, Duration};
use tracing::info;

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    /// Network interface to monitor
    #[arg(short = 'i', long, default_value = "lo")]
    interface: String,

    /// How long to run the collector (in seconds)
    #[arg(short = 'd', long, default_value = "30")]
    duration: u64,

    /// Minimum quality threshold
    #[arg(short = 'q', long, default_value = "0.5")]
    min_quality: f64,

    /// Enable verbose logging
    #[arg(short, long)]
    verbose: bool,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    if args.verbose {
        tracing_subscriber::fmt()
            .with_max_level(tracing::Level::DEBUG)
            .init();
    } else {
        tracing_subscriber::fmt()
            .with_max_level(tracing::Level::INFO)
            .init();
    }

    info!("Starting Huginn Collector example");
    info!("Interface: {}", args.interface);
    info!("Duration: {} seconds", args.duration);
    info!("Min quality: {}", args.min_quality);

    let collector = NetworkCollectorBuilder::new(args.interface)
        .min_quality(args.min_quality)
        .buffer_size(100)
        .channel_buffer_size(1000)
        .enable_tcp(true)
        .enable_http(true)
        .enable_tls(true)
        .verbose(args.verbose)
        .build()?;

    let handle = collector.start()?;

    info!("Collector started successfully");
    info!(
        "Monitoring network traffic for {} seconds...",
        args.duration
    );

    sleep(Duration::from_secs(args.duration)).await;

    info!("Stopping collector...");

    // Stop the collector gracefully
    handle.stop().await?;

    info!("Collector stopped successfully");
    Ok(())
}
