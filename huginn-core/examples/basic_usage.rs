use huginn_core::{AnalyzerConfig, HuginnAnalyzer, LoggingEventHandler};

fn main() {
    // Initialize tracing
    tracing_subscriber::fmt::init();

    // Create analyzer with default config
    let mut analyzer = HuginnAnalyzer::new();

    // Add event handler
    analyzer
        .event_dispatcher_mut()
        .add_handler(LoggingEventHandler);

    println!("Huginn Core initialized successfully!");
    println!("Version: {}", huginn_core::VERSION);

    // Example of custom configuration
    let config = AnalyzerConfig {
        enable_tcp: true,
        enable_http: true,
        enable_tls: true,
        min_quality: 0.5,
    };

    let _analyzer_with_config = HuginnAnalyzer::with_config(config);

    println!("Custom analyzer configuration created!");
}
