# Huginn Net Profiler

## Introduction

This project was built to provide an easy-to-use, web-based interface for testing and profiling TCP, HTTP and TLS connections using the [huginn-net](https://github.com/biandratti/huginn-net) library. The motivation behind this project is to enable researchers, network engineers, and enthusiasts to analyze  connection characteristics in real time, without the need for complex command-line tools or manual packet analysis.

By exposing the huginn-net library through a simple web application, users can:
- Instantly view detailed TCP, HTTP and TLS connection profiles for their own or specified IP addresses.
- Experiment with different network scenarios and observe how signatures and metadata change.
- Use the tool for demonstrations, or diagnostics in real-world environments.

This project aims to make advanced profiling accessible and interactive, helping users better understand network behaviors and improve their own tools or research.

### Command Line Options

```
huginn-net-profiler [OPTIONS] --interface <INTERFACE>

Options:
  -i, --interface <INTERFACE>  Network interface to monitor
      --cert <CERT>           Path to TLS certificate file (PEM format)
      --key <KEY>             Path to TLS private key file (PEM format)  
      --upgrade               Enable HTTP to HTTPS upgrade
  -h, --help                  Print help
  -V, --version               Print version
```

###  Get network Interface
```
ip link show
```

### Build and run
```
cargo build --release
```

#### HTTP-only mode
```
sudo RUST_LOG=info ./target/release/huginn-net-profiler --interface <interface>
```

#### With TLS support (HTTP + HTTPS dual protocol)
```
sudo RUST_LOG=info ./target/release/huginn-net-profiler --interface <interface> --cert cert.pem --key key.pem
```

#### With TLS and HTTP to HTTPS upgrade
```
sudo `RUST_LOG=info ./target/release/huginn-net-profiler` --interface <interface> --cert cert.pem --key key.pem --upgrade
```

#### Generate self-signed certificates for testing
```
# Generate private key
openssl genrsa -out key.pem 2048

# Generate self-signed certificate
openssl req -new -x509 -key key.pem -out cert.pem -days 365 -subj "/CN=localhost"
```

#### Debugging huginn-net
```
sudo RUST_LOG=huginn-net=debug ./target/release/huginn-net-profiler --interface <interface>
```

### TLS Dual Protocol Support

When TLS certificates are provided, the server supports both HTTP and HTTPS connections on the same port (8080):

- **HTTP requests**: Served normally or upgraded to HTTPS (if `--upgrade` is enabled)
- **HTTPS requests**: Served with TLS encryption
- **Auto-upgrade**: HTTP requests can be automatically redirected to HTTPS
- **Fallback**: If TLS certificates fail to load, the server falls back to HTTP-only mode

This approach is ideal for:
- Development environments where you want to test both protocols
- Production setups where clients might connect via HTTP by mistake
- Simplified deployment with a single port configuration

### Important Notes about Traffic Analysis

**Network Traffic Analysis Limitations:**

- **HTTP Traffic**: Only unencrypted HTTP traffic can be fully analyzed (headers, content, etc.)
- **HTTPS Traffic**: Only the initial TLS handshake can be analyzed before encryption begins
- **TLS Analysis**: Provides TLS version, cipher suites, extensions, and JA4 fingerprints from the handshake
- **TCP Analysis**: Always works as it analyzes TCP headers (not encrypted)

**What you'll see:**
- **HTTP mode**: Full HTTP request/response analysis + TCP analysis
- **HTTPS mode**: TLS handshake analysis + TCP analysis (no HTTP content analysis)
- **Both modes**: SYN/SYN-ACK, MTU, and uptime detection

This is expected behavior - encrypted traffic cannot be analyzed for content, only for connection characteristics.


### Build and run docker image
```
docker build -t huginn-net-profiler .
```
```
docker run --network host huginn-net-profiler ./huginn-net-profiler --interface <interface>
```

### UI output
![img.png](example.png)
