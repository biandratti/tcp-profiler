FROM rust:1.80-slim AS builder

WORKDIR /usr/src/app

# Install build dependencies
RUN apt-get update && \
    apt-get install -y pkg-config libssl-dev && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Copy the entire context to maintain dependency paths
COPY personal/tcp-profiler/ ./personal/tcp-profiler/
COPY test/ ./test/

# Set working directory to the tcp-profiler project
WORKDIR /usr/src/app/personal/tcp-profiler

# Build the application
RUN cargo build --release

FROM debian:bookworm-slim

WORKDIR /app

RUN apt-get update && \
    apt-get install -y libssl-dev ca-certificates && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Copy the binary and static files from builder
COPY --from=builder /usr/src/app/personal/tcp-profiler/target/release/tcp-profiler /app/
COPY --from=builder /usr/src/app/personal/tcp-profiler/static /app/static

EXPOSE 8080

CMD ["./tcp-profiler"]