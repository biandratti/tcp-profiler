# Huginn Collector

Network traffic collector for Huginn using huginn-net and huginn-core. Captures network packets from a specified interface and converts them into structured traffic profiles.

## Features

- **Real-time Collection**: Captures network packets in real-time from any network interface
- **Async/Sync Bridge**: Seamlessly bridges between huginn-net's sync API and async processing
- **Profile Management**: Maintains an in-memory cache of traffic profiles with automatic merging
- **Configurable Analysis**: Enable/disable TCP, HTTP, and TLS analysis independently
- **Quality Filtering**: Filter results based on confidence thresholds
- **Graceful Shutdown**: Clean shutdown with proper resource cleanup

## Architecture

```
┌─────────────────┐    ┌──────────────┐    ┌─────────────────┐
│   huginn-net    │───▶│ ChannelBridge │───▶│ ProfileProcessor │
│ (blocking thread)│    │   (thread)   │    │  (async task)   │
└─────────────────┘    └──────────────┘    └─────────────────┘
                                                     │
                                                     ▼
                                            ┌─────────────────┐
                                            │  huginn-core    │
                                            │   (analyzer)    │
                                            └─────────────────┘
```

## Usage

### Basic Usage

```rust
use huginn_collector::NetworkCollectorBuilder;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Create and start collector
    let collector = NetworkCollectorBuilder::new("eth0".to_string())
        .min_quality(0.5)
        .enable_tcp(true)
        .enable_http(true)
        .enable_tls(true)
        .build()?;

    let handle = collector.start()?;
    
    // Let it run for a while
    tokio::time::sleep(tokio::time::Duration::from_secs(30)).await;
    
    // Stop gracefully
    handle.stop().await?;
    Ok(())
}
```

### Configuration Options

```rust
use huginn_collector::{CollectorConfig, NetworkCollector};
use huginn_core::AnalyzerConfig;

// Create custom configuration
let config = CollectorConfig {
    interface: "eth0".to_string(),
    buffer_size: 200,                    // huginn-net buffer size
    channel_buffer_size: 2000,           // Internal channel buffer
    analyzer: AnalyzerConfig {
        enable_tcp: true,
        enable_http: true,
        enable_tls: true,
        min_quality: 0.7,               // 70% confidence threshold
    },
    verbose: true,
};

let collector = NetworkCollector::new(config)?;
```

### Command Line Interface

```rust
use huginn_collector::config::CollectorArgs;
use clap::Parser;

let args = CollectorArgs::parse();
let config = CollectorConfig::from(args);
let collector = NetworkCollector::new(config)?;
```

## Examples

### Run Basic Collector

```bash
# Run the basic collector example
cargo run --example basic_collector -- --interface eth0 --duration 60 --min-quality 0.5 --verbose

# Available options:
# -i, --interface <INTERFACE>     Network interface to monitor
# -d, --duration <DURATION>       How long to run (seconds) [default: 30]
# -q, --min-quality <QUALITY>     Minimum quality threshold [default: 0.5]
# -v, --verbose                   Enable verbose logging
```

### Integration Example

```rust
use huginn_collector::{NetworkCollector, CollectorConfig};
use huginn_core::{TrafficProfile, TrafficEvent};
use std::collections::HashMap;

// Create collector with custom event handling
let mut collector = NetworkCollector::new(config)?;

// Start collection
let handle = collector.start()?;

// Access profiles (in a real app, you'd need to share state)
// let profiles: HashMap<String, TrafficProfile> = collector.get_profiles();

// Stop when done
handle.stop().await?;
```

## Configuration

### CollectorConfig

- `interface`: Network interface to monitor (e.g., "eth0", "wlan0", "lo")
- `buffer_size`: Buffer size for huginn-net (default: 100)
- `channel_buffer_size`: Internal channel buffer size (default: 1000)
- `analyzer`: huginn-core analyzer configuration
- `verbose`: Enable detailed logging

### AnalyzerConfig

- `enable_tcp`: Enable TCP analysis (default: true)
- `enable_http`: Enable HTTP analysis (default: true)
- `enable_tls`: Enable TLS analysis (default: true)
- `min_quality`: Minimum confidence threshold 0.0-1.0 (default: 0.0)

## Error Handling

```rust
use huginn_collector::CollectorError;

match collector.start() {
    Ok(handle) => {
        // Success
    }
    Err(CollectorError::Configuration(msg)) => {
        eprintln!("Configuration error: {}", msg);
    }
    Err(CollectorError::Collection(msg)) => {
        eprintln!("Collection error: {}", msg);
    }
    Err(e) => {
        eprintln!("Other error: {}", e);
    }
}
```

## Requirements

- **Root privileges**: Required for network packet capture
- **Network interface**: Must specify a valid network interface
- **Async runtime**: Requires tokio runtime

## Integration

Huginn Collector is designed to work with:
- **huginn-core**: Provides analysis capabilities
- **huginn-api**: Can serve collected profiles via web API
- **huginn-compose**: Docker orchestration

## Performance

- **Memory usage**: Profiles are stored in memory, size depends on traffic volume
- **CPU usage**: Depends on traffic volume and enabled analysis types
- **Network overhead**: Minimal, only captures packet headers for analysis

## Limitations

- **In-memory only**: Profiles are not persisted to disk
- **Single interface**: Can only monitor one interface per collector instance
- **Linux/Unix**: Requires platforms supported by huginn-net 