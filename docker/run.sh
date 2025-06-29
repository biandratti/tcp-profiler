#!/bin/bash

set -e

# Get the directory where this script is located
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "🚀 TCP Profiler Docker Setup"
echo "=============================="

# Check if certificates exist
if [ ! -f "${SCRIPT_DIR}/../../../certs/cert.pem" ] || [ ! -f "${SCRIPT_DIR}/../../../certs/key.pem" ]; then
    echo "❌ Certificates not found in ../certs/"
    echo "Please run the following commands from the parent directory:"
    echo ""
    echo "  mkdir -p certs"
    echo "  openssl genrsa -out certs/key.pem 2048"
    echo "  openssl req -new -x509 -key certs/key.pem -out certs/cert.pem -days 365 \\"
    echo "    -subj \"/C=US/ST=Test/L=Test/O=TCP-Profiler-Demo/CN=localhost\" \\"
    echo "    -addext \"subjectAltName=DNS:localhost,DNS:127.0.0.1,IP:127.0.0.1,IP:::1\""
    echo ""
    exit 1
fi

echo "✅ Certificates found"

# Check if Docker is running
if ! docker info > /dev/null 2>&1; then
    echo "❌ Docker is not running. Please start Docker and try again."
    exit 1
fi

echo "✅ Docker is running"

# Build and start Docker services (includes Rust compilation)
echo "🔨 Building and starting Docker services..."
cd "${SCRIPT_DIR}"
docker-compose up --build -d

echo ""
echo "🎉 Services are starting up!"
echo ""
echo "📡 Access points:"
echo "  • HTTPS App: https://localhost"
echo "  • HTTP (redirects): http://localhost"
echo "  • Traefik Dashboard: http://localhost:8081"
echo ""
echo "🧪 Test the fingerprinting:"
echo "  curl -k https://localhost/tcp-info"
echo ""
echo "📋 Useful commands:"
echo "  • View logs: docker-compose logs -f"
echo "  • Stop: docker-compose down"
echo "  • Debug app: docker exec -it tcp-profiler-app /bin/bash"
echo ""
echo "⚠️  Note: You'll get SSL warnings because we're using self-signed certificates"
echo "   This is normal for demonstration purposes." 
