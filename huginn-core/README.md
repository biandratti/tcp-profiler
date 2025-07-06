# Huginn Core

Core library for Huginn network traffic analysis. Provides clean, modular interfaces for analyzing network traffic and converting raw huginn-net data into structured profiles.

## Features

- **Modular Analysis**: Separate TCP, HTTP, and TLS analysis with configurable options
- **Event System**: Extensible event handling for real-time traffic analysis
- **Clean Data Structures**: Well-structured data types for network profiles
- **Quality Filtering**: Configurable quality thresholds for analysis results
- **Zero Storage**: In-memory only analysis, no persistence required

## Usage

```rust
use huginn_core::{HuginnAnalyzer, AnalyzerConfig, LoggingEventHandler};

// Create analyzer with default configuration
let mut analyzer = HuginnAnalyzer::new();

// Add event handler for real-time notifications
analyzer.event_dispatcher_mut().add_handler(LoggingEventHandler);

// Custom configuration
let config = AnalyzerConfig {
    enable_tcp: true,
    enable_http: true,
    enable_tls: true,
    min_quality: 0.5, // Only accept results with 50%+ confidence
};

let analyzer = HuginnAnalyzer::with_config(config);
```

## Data Structures

### TrafficProfile
Complete traffic analysis for a network endpoint:
- **TCP Analysis**: OS detection, network distance, TCP characteristics
- **HTTP Analysis**: Browser/server detection, language, HTTP signatures
- **TLS Analysis**: JA4 fingerprints, cipher suites, TLS characteristics
- **Metadata**: Timestamps, packet counts, completeness scores

### Events
Real-time events for traffic analysis:
- `ProfileCreated`: New traffic profile detected
- `ProfileUpdated`: Existing profile updated with new data
- `TcpAnalyzed`: TCP analysis completed
- `HttpAnalyzed`: HTTP analysis completed
- `TlsAnalyzed`: TLS analysis completed
- `AnalysisError`: Analysis error occurred

## Architecture

```
huginn-core/
├── analyzer.rs    # Main analysis engine
├── profile.rs     # Data structures for traffic profiles
├── events.rs      # Event system for real-time notifications
├── error.rs       # Error handling
└── lib.rs         # Public API
```

## Examples

Run the basic usage example:
```bash
cargo run --example basic_usage
```

## Integration

Huginn Core is designed to be the foundation for:
- **huginn-collector**: Network traffic collection
- **huginn-api**: Web API and UI
- **huginn-compose**: Docker orchestration

## Dependencies

- `huginn-net`: Core network analysis library
- `serde`: Serialization/deserialization
- `chrono`: Timestamp handling
- `thiserror`: Error handling
- `tracing`: Logging and instrumentation 