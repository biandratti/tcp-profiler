# TCP Profiler

## Introduction

This project was built to provide an easy-to-use, web-based interface for testing and profiling TCP connections using the [passivetcp-rs](https://github.com/biandratti/passivetcp-rs) library. The motivation behind this project is to enable researchers, network engineers, and enthusiasts to analyze TCP fingerprinting and connection characteristics in real time, without the need for complex command-line tools or manual packet analysis.

By exposing the passive-tcp library through a simple web application, users can:
- Instantly view detailed TCP connection profiles for their own or specified IP addresses.
- Experiment with different network scenarios and observe how TCP signatures and metadata change.
- Use the tool for demonstrations, or diagnostics in real-world environments.

This project aims to make advanced TCP profiling accessible and interactive, helping users better understand network behaviors and improve their own tools or research.

###  Get network Interface
```
ip link show
```

### Build and run
```
cargo build --release
```
```
sudo RUST_LOG=info ./target/release/tcp-profiler --interface <interface>
```
or debugging passivetcp_rs
```
sudo RUST_LOG=passivetcp_rs=debug ./target/release/tcp-profiler --interface <interface>
```


### Build and run docker image
```
docker build -t tcp-profiler .
```
```
docker run --network host tcp-profiler ./tcp-profiler --interface <interface>
```

### UI output
![img.png](example.png)
