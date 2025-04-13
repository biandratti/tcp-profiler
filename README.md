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


### Build and run docker image
```
docker build -t tcp-profiler .
```
```
docker run --network host tcp-profiler ./tcp-profiler --interface <interface>
```