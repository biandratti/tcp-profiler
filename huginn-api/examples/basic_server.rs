use huginn_api::server::{run_server_with_config, ApiServerConfig};
use huginn_collector::CollectorConfig;
use huginn_core::AnalyzerConfig;
use std::net::SocketAddr;
use tracing_subscriber;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize logging
    tracing_subscriber::fmt::init();

    // Create custom configuration
    let mut collector_config = CollectorConfig::default();
    collector_config.interface = "wlp0s20f3".to_string(); // Change to your interface
    collector_config.buffer_size = 500;
    collector_config.channel_buffer_size = 1000;

    // Configure analyzer
    collector_config.analyzer = AnalyzerConfig {
        enable_tcp: true,
        enable_http: true,
        enable_tls: true,
        min_quality: 0.3,
    };

    let config = ApiServerConfig {
        bind_addr: SocketAddr::from(([127, 0, 0, 1], 3000)),
        interface: "wlp0s20f3".to_string(),
        enable_collector: true,
        static_dir: Some("static".to_string()),
        enable_cors: true,
        collector_config,
    };

    println!("Starting Huginn API server...");
    println!("Server will be available at: http://127.0.0.1:3000");
    println!("WebSocket endpoint: ws://127.0.0.1:3000/ws");
    println!("API documentation: http://127.0.0.1:3000/api");

    // Run the server
    run_server_with_config(config).await?;

    Ok(())
}
