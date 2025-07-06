use clap::Parser;
use huginn_core::AnalyzerConfig;
use serde::{Deserialize, Serialize};

/// Configuration for the network collector
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CollectorConfig {
    /// Network interface to monitor
    pub interface: String,
    /// Buffer size for huginn-net
    pub buffer_size: usize,
    /// Channel buffer size for internal communication
    pub channel_buffer_size: usize,
    /// Analyzer configuration
    pub analyzer: AnalyzerConfig,
    /// Whether to enable detailed logging
    pub verbose: bool,
}

impl Default for CollectorConfig {
    fn default() -> Self {
        Self {
            interface: "eth0".to_string(),
            buffer_size: 100,
            channel_buffer_size: 1000,
            analyzer: AnalyzerConfig::default(),
            verbose: false,
        }
    }
}

/// Command line arguments for the collector
#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
pub struct CollectorArgs {
    /// Network interface to monitor
    #[arg(short = 'i', long)]
    pub interface: String,

    /// Buffer size for huginn-net
    #[arg(long, default_value = "100")]
    pub buffer_size: usize,

    /// Channel buffer size for internal communication
    #[arg(long, default_value = "1000")]
    pub channel_buffer_size: usize,

    /// Minimum quality threshold for analysis results
    #[arg(long, default_value = "0.0")]
    pub min_quality: f64,

    /// Enable verbose logging
    #[arg(short, long)]
    pub verbose: bool,

    /// Disable TCP analysis
    #[arg(long)]
    pub no_tcp: bool,

    /// Disable HTTP analysis
    #[arg(long)]
    pub no_http: bool,

    /// Disable TLS analysis
    #[arg(long)]
    pub no_tls: bool,
}

impl From<CollectorArgs> for CollectorConfig {
    fn from(args: CollectorArgs) -> Self {
        Self {
            interface: args.interface,
            buffer_size: args.buffer_size,
            channel_buffer_size: args.channel_buffer_size,
            analyzer: AnalyzerConfig {
                enable_tcp: !args.no_tcp,
                enable_http: !args.no_http,
                enable_tls: !args.no_tls,
                min_quality: args.min_quality,
            },
            verbose: args.verbose,
        }
    }
}

impl CollectorConfig {
    /// Create a new configuration with the specified interface
    pub fn new(interface: String) -> Self {
        Self {
            interface,
            ..Default::default()
        }
    }

    /// Set the buffer size
    pub fn with_buffer_size(mut self, size: usize) -> Self {
        self.buffer_size = size;
        self
    }

    /// Set the channel buffer size
    pub fn with_channel_buffer_size(mut self, size: usize) -> Self {
        self.channel_buffer_size = size;
        self
    }

    /// Set the analyzer configuration
    pub fn with_analyzer(mut self, analyzer: AnalyzerConfig) -> Self {
        self.analyzer = analyzer;
        self
    }

    /// Enable verbose logging
    pub fn with_verbose(mut self, verbose: bool) -> Self {
        self.verbose = verbose;
        self
    }

    /// Validate the configuration
    pub fn validate(&self) -> Result<(), String> {
        if self.interface.is_empty() {
            return Err("Interface cannot be empty".to_string());
        }

        if self.buffer_size == 0 {
            return Err("Buffer size must be greater than 0".to_string());
        }

        if self.channel_buffer_size == 0 {
            return Err("Channel buffer size must be greater than 0".to_string());
        }

        if self.analyzer.min_quality < 0.0 || self.analyzer.min_quality > 1.0 {
            return Err("Minimum quality must be between 0.0 and 1.0".to_string());
        }

        Ok(())
    }
}
