#!/bin/bash

# Huginn Network Profiler - Testing Script
# This script runs the same tests as the CI pipeline

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Function to run a command with status reporting
run_command() {
    local cmd="$1"
    local description="$2"
    
    print_status "Running: $description"
    echo "Command: $cmd"
    
    if eval "$cmd"; then
        print_success "$description completed successfully"
        return 0
    else
        print_error "$description failed"
        return 1
    fi
}

# Check if we're in the right directory
if [ ! -f "Cargo.toml" ]; then
    print_error "This script must be run from the project root directory"
    exit 1
fi

# Check for required system dependencies
print_status "Checking system dependencies..."

if ! pkg-config --exists libpcap; then
    print_warning "libpcap not found. Please install it:"
    echo "  Ubuntu/Debian: sudo apt-get install -y libpcap-dev"
    echo "  macOS: brew install libpcap"
    echo "  Arch Linux: sudo pacman -S libpcap"
    exit 1
fi

print_success "System dependencies check passed"

# Parse command line arguments
SKIP_BUILD=false
SKIP_TESTS=false
SKIP_LINT=false
SKIP_FORMAT=false
SKIP_EXAMPLES=false
SKIP_AUDIT=false
COVERAGE=false
VERBOSE=false

while [[ $# -gt 0 ]]; do
    case $1 in
        --skip-build)
            SKIP_BUILD=true
            shift
            ;;
        --skip-tests)
            SKIP_TESTS=true
            shift
            ;;
        --skip-lint)
            SKIP_LINT=true
            shift
            ;;
        --skip-format)
            SKIP_FORMAT=true
            shift
            ;;
        --skip-examples)
            SKIP_EXAMPLES=true
            shift
            ;;
        --skip-audit)
            SKIP_AUDIT=true
            shift
            ;;
        --coverage)
            COVERAGE=true
            shift
            ;;
        --verbose)
            VERBOSE=true
            shift
            ;;
        --help)
            echo "Usage: $0 [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  --skip-build      Skip build step"
            echo "  --skip-tests      Skip test execution"
            echo "  --skip-lint       Skip linting"
            echo "  --skip-format     Skip format checking"
            echo "  --skip-examples   Skip example compilation"
            echo "  --skip-audit      Skip security audit"
            echo "  --coverage        Generate coverage report"
            echo "  --verbose         Enable verbose output"
            echo "  --help            Show this help message"
            exit 0
            ;;
        *)
            print_error "Unknown option: $1"
            echo "Use --help for usage information"
            exit 1
            ;;
    esac
done

# Set verbose flag for cargo commands
CARGO_VERBOSE=""
if [ "$VERBOSE" = true ]; then
    CARGO_VERBOSE="--verbose"
fi

print_status "Starting Huginn Network Profiler test suite..."

# Build
if [ "$SKIP_BUILD" = false ]; then
    run_command "cargo build $CARGO_VERBOSE" "Build"
fi

# Tests
if [ "$SKIP_TESTS" = false ]; then
    run_command "cargo test --workspace $CARGO_VERBOSE" "Unit tests"
    run_command "cargo test --workspace --all-features $CARGO_VERBOSE" "Tests with all features"
    run_command "cargo test --workspace --doc $CARGO_VERBOSE" "Documentation tests"
fi

# Format check
if [ "$SKIP_FORMAT" = false ]; then
    run_command "cargo fmt -- --check" "Format check"
fi

# Linting
if [ "$SKIP_LINT" = false ]; then
    run_command "cargo clippy --all-targets --all-features -- -D warnings" "Linting"
fi

# Examples
if [ "$SKIP_EXAMPLES" = false ]; then
    print_status "Checking examples..."
    
    # Build all examples
    run_command "cargo build --examples $CARGO_VERBOSE" "Build examples"
    
    # Check individual examples if they exist
    if [ -f "huginn-core/examples/basic_usage.rs" ]; then
        run_command "cargo check --example basic_usage -p huginn-core" "Check huginn-core example"
    fi
    
    if [ -f "huginn-collector/examples/basic_collector.rs" ]; then
        run_command "cargo check --example basic_collector -p huginn-collector" "Check huginn-collector example"
    fi
    
    if [ -f "huginn-api/examples/basic_server.rs" ]; then
        run_command "cargo check --example basic_server -p huginn-api" "Check huginn-api basic server example"
    fi
    
    if [ -f "huginn-api/examples/basic_server_no_collector.rs" ]; then
        run_command "cargo check --example basic_server_no_collector -p huginn-api" "Check huginn-api no collector example"
    fi
fi

# Security audit
if [ "$SKIP_AUDIT" = false ]; then
    # Check if cargo-audit is installed
    if ! command -v cargo-audit &> /dev/null; then
        print_warning "cargo-audit not found. Installing..."
        cargo install cargo-audit
    fi
    
    run_command "cargo audit" "Security audit"
fi

# Coverage
if [ "$COVERAGE" = true ]; then
    # Check if cargo-tarpaulin is installed
    if ! command -v cargo-tarpaulin &> /dev/null; then
        print_warning "cargo-tarpaulin not found. Installing..."
        cargo install cargo-tarpaulin
    fi
    
    run_command "cargo tarpaulin --verbose --all-features --workspace --timeout 120" "Coverage report"
fi

print_success "All tests completed successfully! 🎉"

# Print summary
echo ""
echo "========================================="
echo "           TEST SUMMARY"
echo "========================================="
echo "✅ Build: $([ "$SKIP_BUILD" = false ] && echo "PASSED" || echo "SKIPPED")"
echo "✅ Tests: $([ "$SKIP_TESTS" = false ] && echo "PASSED" || echo "SKIPPED")"
echo "✅ Format: $([ "$SKIP_FORMAT" = false ] && echo "PASSED" || echo "SKIPPED")"
echo "✅ Lint: $([ "$SKIP_LINT" = false ] && echo "PASSED" || echo "SKIPPED")"
echo "✅ Examples: $([ "$SKIP_EXAMPLES" = false ] && echo "PASSED" || echo "SKIPPED")"
echo "✅ Security: $([ "$SKIP_AUDIT" = false ] && echo "PASSED" || echo "SKIPPED")"
echo "✅ Coverage: $([ "$COVERAGE" = true ] && echo "GENERATED" || echo "SKIPPED")"
echo "========================================="
echo ""
echo "🚀 Ready for deployment!" 