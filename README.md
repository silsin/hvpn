# HVPN

A Rust-based VPN with obfuscated WebSocket transport, X25519 key exchange, ChaCha20-Poly1305 encryption, and a port-knock listener for stealth deployments.

---

## Architecture

```
hvpn-client  ←──WebSocket/TLS──→  hvpn-server
     │                                  │
 hvpn-tun (TUN device)           (routes IP traffic)
     │
 hvpn-crypto  (X25519 handshake, ChaCha20-Poly1305)
 hvpn-core    (frame codec, replay window, mux)
 hvpn-obfs    (traffic shaping / padding)
 hvpn-transport (WebSocket, HTTP/2, gRPC adapters)
 hvpn-metrics  (RTT, packet-loss tracking)
```

The client reads IP packets from a TUN device, encrypts and frames them, applies obfuscation padding, and sends them over a mutually-authenticated WebSocket connection. The server decrypts and (Phase 2) routes the packets through a NAT/IP stack.

---

## Prerequisites

| Tool | Minimum version | Notes |
|------|-----------------|-------|
| Rust + Cargo | 1.75 | Install via [rustup](https://rustup.rs/) |
| OpenSSL / system TLS | any | Needed to build `rustls` ring backend |
| Linux (server) | kernel 5.x+ | `/dev/net/tun` is required for the real TUN driver. The client falls back to `StubTun` on other platforms. |

---

## Building

```bash
# Build everything (all crates + both binaries)
cargo build --release

# Binaries are written to:
#   target/release/hvpn-server
#   target/release/hvpn-client
```

To build only one binary:

```bash
cargo build --release -p hvpn-server
cargo build --release -p hvpn-client
```

---

## Configuration

Both binaries read a single TOML config file (default path: `config.toml` in the working directory, overridden with `--config <path>`).

### Minimal `config.toml`

```toml
server_address = "vpn.example.com"   # hostname or IP of the server
server_port    = 443                  # TCP port the server listens on
tls_cert_path  = "/etc/hvpn/server.pem"  # PEM certificate for TLS verification

# Optional — traffic-shaping profile.
# Values: "browser" (default), "streaming", "voip", "idle"
obfs_profile = "browser"
```

> **server_address** is only meaningful on the client. The server always binds to `0.0.0.0:<server_port>`.

---

## Running the Server

### 1. Create a config file

```bash
cat > /etc/hvpn/server.toml << 'EOF'
server_address = "0.0.0.0"
server_port    = 443
tls_cert_path  = "/etc/hvpn/server.pem"
obfs_profile   = "browser"
EOF
```

### 2. Start the server

```bash
./target/release/hvpn-server --config /etc/hvpn/server.toml
```

The server opens two sockets:

| Socket | Purpose |
|--------|---------|
| `TCP 0.0.0.0:<server_port>` | WebSocket tunnel connections |
| `UDP 0.0.0.0:<server_port - 1>` | Port-knock listener (non-fatal if bind fails) |

**Port-knock enforcement** is disabled by default. Enable it by setting the environment variable:

```bash
HVPN_REQUIRE_KNOCK=1 ./target/release/hvpn-server --config /etc/hvpn/server.toml
```

When enabled, clients must send a valid probe token to the UDP port before the server accepts their TCP connection. The whitelist entry expires after 10 seconds.

### 3. Logging

Set the `RUST_LOG` environment variable to control verbosity:

```bash
RUST_LOG=info  ./target/release/hvpn-server   # default
RUST_LOG=debug ./target/release/hvpn-server   # verbose
RUST_LOG=warn  ./target/release/hvpn-server   # quiet
```

---

## Running the Client

### 1. Create a config file

```bash
cat > /etc/hvpn/client.toml << 'EOF'
server_address = "vpn.example.com"
server_port    = 443
tls_cert_path  = "/etc/hvpn/server.pem"
obfs_profile   = "browser"
EOF
```

### 2. Start the client

```bash
./target/release/hvpn-client --config /etc/hvpn/client.toml
```

The client:
1. Derives an ephemeral X25519 key pair.
2. Connects to the server over WebSocket.
3. Performs the crypto handshake (ephemeral public key exchanged as the first binary message).
4. Enters the tunnel loop, reading packets from the TUN device and forwarding them encrypted.
5. Shuts down cleanly on **Ctrl+C**.

> **Phase 1 note:** The client uses `StubTun` (no real TUN device). It will connect to the server and run the tunnel loop, but no actual IP packets are routed. Real TUN support is Linux-only and gated behind `#[cfg(target_os = "linux")]` in `hvpn-tun`.

If the server is unreachable, the client falls back to stub mode and logs:

```
transport not available (Phase 1 stub mode): ...
```

---

## Running the Tests

```bash
# Run all workspace tests
cargo test

# Run tests for a specific crate
cargo test -p hvpn-common
cargo test -p hvpn-crypto
cargo test -p hvpn-core
cargo test -p hvpn-server

# Show test output (useful for debugging)
cargo test -- --nocapture
```

Key test coverage:
- `hvpn-common` — config TOML round-trip, default obfs profile
- `hvpn-crypto` — handshake, cipher, replay detection
- `hvpn-server` — probe token replay rejection

---

## End-to-End Smoke Test (local machine)

Run the server and client in separate terminals on the same machine to verify the handshake and frame pipeline.

**Terminal 1 — server:**

```bash
cat > /tmp/hvpn-server.toml << 'EOF'
server_address = "127.0.0.1"
server_port    = 9443
tls_cert_path  = "/tmp/test.pem"
obfs_profile   = "browser"
EOF

RUST_LOG=info cargo run --release -p hvpn-server -- --config /tmp/hvpn-server.toml
```

**Terminal 2 — client:**

```bash
cat > /tmp/hvpn-client.toml << 'EOF'
server_address = "127.0.0.1"
server_port    = 9443
tls_cert_path  = "/tmp/test.pem"
obfs_profile   = "browser"
EOF

RUST_LOG=info cargo run --release -p hvpn-client -- --config /tmp/hvpn-client.toml
```

Expected output (server side):

```
INFO hvpn_server: HVPN server listening addr=0.0.0.0:9443
INFO hvpn_server: accepted TCP connection peer=127.0.0.1:xxxxx
INFO hvpn_server: authenticated connection established peer=127.0.0.1:xxxxx
INFO hvpn_server: crypto handshake complete peer=127.0.0.1:xxxxx
```

Expected output (client side):

```
INFO hvpn_client: starting HVPN client server=127.0.0.1 port=9443
INFO hvpn_client: handshake keys derived pubkey=<hex>
INFO hvpn_client: WebSocket transport connected
INFO hvpn_client: entering tunnel loop (Ctrl+C to exit)
```

Press **Ctrl+C** in the client terminal to shut down gracefully.

---

## Project Structure

```
HVPN/
├── Cargo.toml                  # Workspace manifest
├── bins/
│   ├── hvpn-client/            # Client binary
│   └── hvpn-server/            # Server binary
└── crates/
    ├── hvpn-common/            # Config structs, error types
    ├── hvpn-core/              # Frame codec, replay window, multiplexer
    ├── hvpn-crypto/            # X25519 handshake, ChaCha20-Poly1305, probe tokens
    ├── hvpn-metrics/           # RTT and packet-loss collector
    ├── hvpn-obfs/              # Traffic shaping and padding engine
    ├── hvpn-pq/                # Post-quantum crypto (placeholder)
    ├── hvpn-proto/             # Protobuf definitions (gRPC)
    ├── hvpn-transport/         # WebSocket, HTTP/2, gRPC transport adapters
    └── hvpn-tun/               # TUN device abstraction (Linux + stub)
```

---

## Security Notes

- Tokens include an HMAC-based timestamp (±30 s clock skew tolerated) and are checked against a replay cache for 60 seconds.
- Non-HTTP connections receive a decoy nginx page instead of a protocol error.
- Port-knock enforcement (`HVPN_REQUIRE_KNOCK=1`) limits exposure to scanners.
- Phase 1 uses zero-byte static keys for development. A production deployment must load real keys from the config file.
