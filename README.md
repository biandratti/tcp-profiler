###  Get network Interface
```
ip link show
```

### Build and run
```
cargo build --release
```
```
sudo RUST_LOG=info ./target/release/tcp-fingerprint --interface <interface>
```


### Build and run docker image
```
docker run -p 8080:8080 tcp-fingerprint
```
```
docker run --network host tcp-fingerprint ./tcp-fingerprint --interface <interface>
```