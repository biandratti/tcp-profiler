# TCP Profiler with Docker + Traefik

This configuration allows you to capture both **JA4** (TLS fingerprinting) and **HTTP fingerprinting** simultaneously using Docker Compose with Traefik as a reverse proxy.

## Why this architecture?

- **Problem**: Using HTTPS you lose HTTP request/response visibility, using HTTP you lose JA4
- **Solution**: Traefik terminates TLS externally, your app receives HTTP internally
- **Result**: You capture both types of fingerprints

## Architecture

```
HTTPS Client → Traefik (terminates TLS) → TCP Profiler App (HTTP)
                       ↓
        TCP Profiler captures host network traffic (wlp0s20f3)
```

## Usage

1. **Build and run**:
   ```bash
   cd docker
   docker-compose up --build
   ```

2. **Access the application**:
   - HTTPS: https://localhost
   - HTTP (redirects): http://localhost
   - Traefik Dashboard: http://localhost:8081

## Certificates

Self-signed certificates are located in `../../certs/` (parent directory):
- `cert.pem`: Public certificate
- `key.pem`: Private key

These are demonstration certificates valid for:
- `localhost`
- `127.0.0.1`
- `tcp-profiler.local`

**Note**: Certificates are in the parent directory structure:
```
repository/
├── certs/           ← Certificates here
│   ├── cert.pem
│   └── key.pem
└── personal/
    └── tcp-profiler/    ← Project here
        └── docker/
```

## Build Process

The `run.sh` script follows this process:
1. **Build Docker image**: Compiles Rust inside container for GLIBC compatibility
2. **Start services**: Launches Traefik + TCP Profiler + Sidecar
3. **Network capture**: Sidecar captures both TLS and HTTP traffic

## Logs and Debugging

```bash
# View logs from all services
docker-compose logs -f

# View logs only from tcp profiler
docker-compose logs -f tcp-profiler-app

# View traefik logs
docker-compose logs -f traefik

# Enter app container for debugging
docker exec -it tcp-profiler-app /bin/bash
```

## Network Architecture

- **Traefik**: Port 443 (HTTPS) → Internal port 8080
- **TCP Profiler**: Uses `host` network mode to access physical interfaces
- **Interface**: Monitors `wlp0s20f3` (WiFi) for local device traffic
- **Capture**: Can see all network traffic from host interface
