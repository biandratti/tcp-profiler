FROM rust:1.80-slim AS builder

WORKDIR /usr/src/app
COPY . .

RUN apt-get update && \
    apt-get install -y pkg-config libssl-dev && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN cargo build --release

FROM debian:bookworm-slim

WORKDIR /app

RUN apt-get update && \
    apt-get install -y libssl-dev ca-certificates && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

COPY --from=builder /usr/src/app/target/release/tcp-profiler /app/
COPY --from=builder /usr/src/app/static /app/static

EXPOSE 8080

CMD ["./tcp-profiler"]