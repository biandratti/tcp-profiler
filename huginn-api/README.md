# 🦉 Huginn API

Web API server for Huginn network profiler. Provides REST API and WebSocket endpoints for real-time traffic analysis.

## Features

- **REST API** - Complete HTTP API for managing traffic profiles
- **WebSocket Support** - Real-time updates for live monitoring
- **Network Collection** - Integrated with huginn-collector for live traffic analysis
- **CORS Support** - Cross-origin resource sharing for web applications
- **Static File Serving** - Serve web UI and assets
- **Configurable** - Flexible configuration via CLI or config files

## Architecture

```
huginn-api
├── REST API Endpoints
├── WebSocket Handler
├── Network Collector Integration
├── Static File Server
└── Real-time State Management
```

## Prerequisites

### System Requirements

**Ubuntu/Debian:**
```bash
sudo apt update
sudo apt install -y libssl-dev pkg-config
```

**CentOS/RHEL/Fedora:**
```bash
sudo yum install openssl-devel pkgconfig
# or on newer versions:
sudo dnf install openssl-devel pkgconfig
```

**macOS:**
```bash
brew install openssl pkg-config
```

### Network Permissions

Since huginn-api captures network traffic, it requires appropriate permissions:

```bash
# Option 1: Run with sudo (not recommended for production)
sudo cargo run --example basic_server

# Option 2: Grant capabilities to the binary (recommended)
sudo setcap cap_net_raw,cap_net_admin=eip target/debug/huginn-api

# Option 3: Add user to netdev group (Ubuntu/Debian)
sudo usermod -a -G netdev $USER
# Then logout and login again
```

## Installation

Add to your `Cargo.toml`:

```toml
[dependencies]
huginn-api = { path = "huginn-api" }
```

## Usage

### Basic Server

```rust
use huginn_api::server::run_server;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize logging
    tracing_subscriber::fmt::init();
    
    // Run server with CLI args
    run_server().await?;
    
    Ok(())
}
```

### Custom Configuration

```rust
use huginn_api::{
    server::{ApiServerConfig, run_server_with_config},
    CollectorConfig,
};
use huginn_core::AnalyzerConfig;
use std::net::SocketAddr;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut collector_config = CollectorConfig::default();
    collector_config.interface = "wlp0s20f3".to_string();
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

    run_server_with_config(config).await?;
    Ok(())
}
```

## Command Line Interface

```bash
# Start server with default settings
cargo run --bin huginn-api -- -i wlp0s20f3

# Custom bind address and interface
cargo run --bin huginn-api -- -i eth0 -b 0.0.0.0:8080

# Disable network collector (serve static profiles only)
cargo run --bin huginn-api -- --no-collector

# Configure analysis settings
cargo run --bin huginn-api -- -i wlp0s20f3 --quality-threshold 0.5 --buffer-size 2000
```

### CLI Options

- `-i, --interface <INTERFACE>` - Network interface to monitor (default: eth0)
- `-b, --bind <ADDRESS>` - Server bind address (default: 127.0.0.1:8080)
- `--no-collector` - Disable network collector
- `--static-dir <DIR>` - Static files directory (default: static)
- `--no-cors` - Disable CORS
- `--enable-tcp` - Enable TCP analysis (default: true)
- `--enable-http` - Enable HTTP analysis (default: true)
- `--enable-tls` - Enable TLS analysis (default: true)
- `--quality-threshold <THRESHOLD>` - Quality threshold (default: 0.5)
- `--buffer-size <SIZE>` - Buffer size (default: 1000)

## API Endpoints

### REST API

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/health` | Health check |
| GET | `/api` | API information |
| GET | `/api/profiles` | Get all profiles |
| GET | `/api/profiles/{key}` | Get specific profile |
| DELETE | `/api/profiles/{key}` | Delete specific profile |
| DELETE | `/api/profiles` | Clear all profiles |
| GET | `/api/stats` | Get statistics |
| GET | `/api/search` | Search profiles |

### Query Parameters

**GET /api/profiles**
- `min_completeness` - Filter by minimum completeness (0.0-1.0)
- `has_tcp` - Filter by TCP data presence (true/false)
- `has_http` - Filter by HTTP data presence (true/false)
- `has_tls` - Filter by TLS data presence (true/false)
- `limit` - Limit number of results

**GET /api/search**
- `q` - Search query string
- `limit` - Maximum number of results

### WebSocket API

Connect to `/ws` for real-time updates.

**Client Messages:**
```json
{"type": "ping"}
{"type": "get_stats"}
{"type": "get_profiles"}
{"type": "clear_profiles"}
{"type": "subscribe", "filters": {...}}
```

**Server Messages:**
```json
{"type": "initial_data", "profiles": {...}, "stats": {...}}
{"type": "profile_update", "update": {...}, "stats": {...}}
{"type": "pong"}
{"type": "stats", "stats": {...}}
{"type": "profiles", "profiles": {...}}
{"type": "profiles_cleared"}
{"type": "error", "message": "..."}
```

## Examples

### Basic Server

```bash
cargo run --example basic_server
```

### WebSocket Client

Open `examples/websocket_client.html` in your browser after starting the server.

## Configuration

### Server Configuration

```rust
pub struct ApiServerConfig {
    pub bind_addr: SocketAddr,
    pub interface: String,
    pub enable_collector: bool,
    pub static_dir: Option<String>,
    pub enable_cors: bool,
    pub collector_config: CollectorConfig,
}
```

### Collector Configuration

```rust
pub struct CollectorConfig {
    pub interface: String,
    pub buffer_size: usize,
    pub channel_buffer_size: usize,
    pub analyzer: AnalyzerConfig,
    pub verbose: bool,
}
```

## Development

### Running Tests

```bash
cargo test -p huginn-api
```

### Building

```bash
cargo build -p huginn-api
```

### Running with Debug Logging

```bash
RUST_LOG=debug cargo run --bin huginn-api
```

## Integration

### With huginn-collector

```rust
use huginn_api::server::ApiServer;
use huginn_collector::CollectorConfig;

let mut config = ApiServerConfig::default();
config.collector_config.interface = "eth0".to_string();
config.enable_collector = true;

let server = ApiServer::new(config);
server.start().await?;
```

### With Custom State Management

```rust
use huginn_api::state::AppState;
use huginn_core::TrafficProfile;

let state = AppState::new();
let profile = TrafficProfile::new(/* ... */);
state.upsert_profile("192.168.1.1:80".to_string(), profile);
```

## Performance

- **Concurrent Connections**: Supports multiple WebSocket connections
- **Real-time Updates**: Sub-second latency for profile updates
- **Memory Efficient**: Uses arc-swap for lock-free profile storage
- **Scalable**: Async/await throughout for high concurrency

## Error Handling

All API endpoints return structured error responses:

```json
{
    "error": "Profile not found: 192.168.1.1:80",
    "status": 404
}
```

## Security

- **CORS**: Configurable cross-origin resource sharing
- **Input Validation**: All inputs are validated and sanitized
- **Error Handling**: Errors don't leak sensitive information

## License

This project is licensed under the MIT License.

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests
5. Submit a pull request

## Troubleshooting

### Common Issues

**"Could not find directory of OpenSSL installation"**
- Install OpenSSL development packages:
  ```bash
  # Ubuntu/Debian
  sudo apt install libssl-dev pkg-config
  
  # CentOS/RHEL/Fedora
  sudo dnf install openssl-devel pkgconfig
  ```

**"Permission denied" when capturing network traffic**
- Run with sudo: `sudo cargo run --example basic_server`
- Or grant capabilities: `sudo setcap cap_net_raw,cap_net_admin=eip target/debug/huginn-api`
- Check if user is in netdev group: `groups $USER`

**"Permission denied" when binding to port**
- Use a port > 1024 or run with sudo
- Check if port is already in use: `netstat -tlnp | grep :8080`

**"Interface not found"**
- List available interfaces: `ip link show`
- Use the correct interface name for your system
- Check interface permissions: `ls -la /sys/class/net/`

**WebSocket connection fails**
- Check if server is running on the correct port
- Verify firewall settings
- Check browser console for errors

### Debug Mode

Enable debug logging:
```bash
RUST_LOG=huginn_api=debug cargo run --bin huginn-api
``` 