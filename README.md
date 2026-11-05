# HVPN

A Rust-based, DPI-evasion VPN protocol designed to bypass deep packet inspection and network filtering using adaptive transport camouflage, onion routing, and post-quantum hybrid cryptography.

---

## Feature Overview

### Phase 1 — Core Tunnel
- **ChaCha20-Poly1305** authenticated encryption for all tunnel traffic
- **X25519** ephemeral key exchange (ECDH handshake)
- **WebSocket transport** with realistic browser HTTP headers to blend in with HTTPS traffic
- **TUN interface** abstraction (Linux `/dev/net/tun`; cross-platform `StubTun` for development)
- **Replay protection** via sliding-window sequence number cache
- **Probe-token authentication** — HMAC-based time-bounded tokens checked before WebSocket upgrade
- **Port-knocking** — UDP knock port; whitelist entry valid for 10 seconds
- **Obfuscation engine** — packet padding and inter-packet jitter
- **Frame codec** — length-prefixed binary framing with header encryption

### Phase 2 — Advanced Evasion
- **HTTP/2 and gRPC transports** — additional camouflage layers over plain TCP
- **Domain fronting** — TLS SNI differs from the HTTP Host header; routes through CDN
- **Adaptive transport switching** — probes all transports, picks the fastest; auto-switches on packet-loss or high RTT
- **Steganographic mode** — tunnels data inside carrier traffic patterns
- **Relay / onion routing** — multi-hop encrypted relay chain (configurable up to N hops)
- **Metrics collection** — RTT and packet-loss tracking via `hvpn-metrics`
- **Post-quantum hybrid KEM** — CRYSTALS-Kyber KEM combined with X25519 (harvest-now-decrypt-later protection)

### Phase 3 — Production Features
- **`hvpn-ctl`** — CLI control plane: status, connect, disconnect, switch-transport, relay management
- **NAT routing** — server-side IP masquerading for full internet access through the tunnel
- **TLS ratcheting** — periodic re-keying to limit the blast radius of any single session key
- **Protocol Buffers** — gRPC frame definitions via `hvpn-proto`

### Phase 4 — Production Hardening
- **Certificate pinning** — SHA-256 fingerprint pinning (`cert_pin_fingerprints`) to defeat MITM attacks
- **Full config validation** — `Config::load_and_validate` collects all errors before startup
- **Structured audit trail** — JSON-lines audit log (`HVPN_AUDIT_LOG` env var) with event types: `client_connected`, `client_disconnected`, `handshake_failed`, `probe_rejected`, `knock_accepted`, `transport_switched`, `ratchet_rotated`, `nat_assigned`
- **Systemd service units** — `deploy/hvpn-server.service`, `deploy/hvpn-client.service`
- **Debian packaging** — `deploy/build-deb.sh` produces a `.deb` installable package

---

## Architecture

```
Client TUN → ObfsEngine → FrameCodec → Crypto (ChaCha20/X25519/PQ) → Transport (WS/H2/gRPC)
  → [Optional: Relay chain (onion)] → Server Transport → Crypto decrypt → NAT → Internet
```

### Crate Dependencies

```
bins/hvpn-client ─────────────────────────────────────────────────────┐
bins/hvpn-server ─────────────────────────────────────────────────────┤
bins/hvpn-ctl ────────────────────────────────────────────────────────┤
                                                                        │
crates/hvpn-transport ──► hvpn-common, hvpn-crypto, hvpn-metrics      │
crates/hvpn-core ────────► hvpn-common                                 │
crates/hvpn-crypto ──────► hvpn-common                                 │
crates/hvpn-obfs ────────► hvpn-common                                 │
crates/hvpn-tun ─────────► hvpn-common                                 │
crates/hvpn-relay ───────► hvpn-common, hvpn-crypto                   │
crates/hvpn-stego ───────► hvpn-common                                 │
crates/hvpn-pq ──────────► hvpn-common, hvpn-crypto                   │
crates/hvpn-proto ───────► (protobuf generated)                        │
crates/hvpn-metrics ─────► (standalone)                                │
crates/hvpn-common ──────► (base: config, error, audit)                │
```

---

## Quick Start

### 1. Prerequisites

| Tool | Minimum version | Notes |
|------|-----------------|-------|
| Rust + Cargo | 1.75 | Install via [rustup](https://rustup.rs/) |
| Linux (server) | kernel 5.x+ | `/dev/net/tun` required for real TUN; `StubTun` used elsewhere |

### 2. Build

```bash
git clone https://github.com/example/hvpn
cd hvpn
cargo build --workspace --release
# Binaries: target/release/hvpn-server, hvpn-client, hvpn-ctl
```

### 3. Generate Keys

```bash
# Generate a 32-byte server static key (hex-encoded):
openssl rand -hex 32
```

### 4. Configure the Server

```bash
cp deploy/example-server.toml /etc/hvpn/server.toml
# Edit /etc/hvpn/server.toml
```

### 5. Run the Server

```bash
RUST_LOG=info ./target/release/hvpn-server --config /etc/hvpn/server.toml
```

### 6. Configure and Run the Client

```bash
cp deploy/example-client.toml /etc/hvpn/client.toml
# Edit /etc/hvpn/client.toml — set server_address
RUST_LOG=info ./target/release/hvpn-client --config /etc/hvpn/client.toml
```

---

## Configuration Reference

Both `hvpn-server` and `hvpn-client` read a single TOML config file (default: `config.toml`; override with `--config <path>`).

| Field | Type | Default | Description |
|---|---|---|---|
| `server_address` | string | — | Server hostname or IP. Clients connect here; server binds `0.0.0.0`. |
| `server_port` | integer | — | TCP port for tunnel connections (1–65535). |
| `tls_cert_path` | string | — | Path to server TLS certificate (PEM). |
| `obfs_profile` | enum | `"browser"` | Traffic-shaping profile: `browser`, `streaming`, `voip`, `idle`. |
| `relay_chain` | array | `null` | List of relay hops (`address`, `pubkey_hex`). `null` = direct connection. |
| `stego_mode` | bool | `false` | Enable steganographic transport mode. |
| `post_quantum` | bool | `false` | Enable post-quantum hybrid KEM (CRYSTALS-Kyber + X25519). |
| `nat_enabled` | bool | `false` | Enable server-side NAT routing (Linux only). |
| `tun_ip` | string | `"10.8.0.2"` | IP address for the TUN interface. |
| `tun_netmask` | string | `"255.255.255.0"` | Netmask for the TUN interface. |
| `dns_servers` | array | `[]` | DNS servers to use over the tunnel. |
| `cert_pin_fingerprints` | array | `[]` | SHA-256 cert fingerprints (hex, 64 chars each). Non-empty enables pinning. |

---

## Security Model

| Layer | Protection |
|---|---|
| **Transport obfuscation** | Browser-like WebSocket headers defeat passive DPI signature matching. Adaptive switching evades active probing. |
| **Certificate pinning** | SHA-256 fingerprint pinning defeats MITM attacks by intermediate certificate authorities. |
| **Post-quantum KEM** | Kyber-1024 + X25519 hybrid protects against harvest-now-decrypt-later attacks by well-resourced adversaries. |
| **Replay protection** | Sliding-window sequence number cache prevents replaying captured packets. |
| **Probe-token auth** | HMAC-based, time-bounded token must be presented in the WebSocket upgrade request; tokens expire after 30 seconds. |
| **Port-knocking** | Optional (`HVPN_REQUIRE_KNOCK=1`): server ignores TCP connections until a valid UDP knock is received. Whitelist entry expires after 10 seconds. |
| **Decoy response** | Non-authenticated TCP connections receive a realistic nginx HTML page instead of a protocol error, reducing server fingerprinting. |
| **Audit trail** | Structured JSON-lines audit log records all security-relevant events for post-incident analysis. |

---

## Relay Chain Usage

Enable multi-hop onion routing by adding a `relay_chain` section to your config:

```toml
server_address = "exit-node.example.com"
server_port = 443
tls_cert_path = "/etc/hvpn/cert.pem"

[[relay_chain]]
address = "relay1.example.com:7001"
pubkey_hex = "aabbcc...64hexchars..."

[[relay_chain]]
address = "relay2.example.com:7002"
pubkey_hex = "ddeeff...64hexchars..."
```

Each hop's `pubkey_hex` is the 64-character hex-encoded X25519 public key of that relay node. Traffic is encrypted in layers; each relay unwraps only its own layer.

---

## Steganographic Mode

Enable steganographic transport by setting `stego_mode = true` in your config. In this mode the `hvpn-stego` crate encodes tunnel frames inside carrier traffic that resembles legitimate application data, making the VPN traffic invisible to statistical analysis.

```toml
stego_mode = true
```

No other changes are required; the transport layer automatically selects the steganographic carrier.

---

## Post-Quantum Mode

Enable post-quantum protection by setting `post_quantum = true`:

```toml
post_quantum = true
```

The handshake runs a CRYSTALS-Kyber-1024 KEM encapsulation alongside the standard X25519 ECDH. The final session key is derived from both shared secrets using HKDF, so security requires breaking both schemes simultaneously.

Note: post-quantum mode increases handshake size and CPU cost. Using more than 3 relay hops with `post_quantum = true` may produce noticeably higher latency.

---

## Certificate Pinning

Add one or more SHA-256 fingerprints of your server's TLS certificate DER bytes:

```toml
cert_pin_fingerprints = [
  "a3b4c5d6e7f8...64hexchars...",
]
```

Obtain the fingerprint of a running server:

```bash
openssl s_client -connect vpn.example.com:443 </dev/null 2>/dev/null \
  | openssl x509 -fingerprint -sha256 -noout \
  | sed 's/://g' | awk -F= '{print tolower($2)}'
```

When `cert_pin_fingerprints` is empty (the default), standard WebPKI verification is used.

---

## hvpn-ctl Command Reference

`hvpn-ctl` communicates with a running `hvpn-client` daemon via a Unix socket at `/tmp/hvpn.sock`.

| Command | Description |
|---|---|
| `hvpn-ctl status` | Show connection status, transport kind, RTT, bytes in/out, active streams. |
| `hvpn-ctl connect --config <path>` | Instruct the daemon to connect using the specified config file. |
| `hvpn-ctl disconnect` | Gracefully disconnect the active tunnel. |
| `hvpn-ctl switch-transport <websocket\|http2\|grpc>` | Switch to a different transport while the tunnel is active. |
| `hvpn-ctl relay-add --address <host:port> --pubkey-hex <hex>` | Append a hop to the active relay chain. |
| `hvpn-ctl relay-clear` | Remove all relay hops (revert to direct connection). |

---

## Audit Trail

Set the `HVPN_AUDIT_LOG` environment variable to a file path to enable file-based JSON-lines audit logging:

```bash
HVPN_AUDIT_LOG=/var/log/hvpn/audit.jsonl ./target/release/hvpn-server --config /etc/hvpn/server.toml
```

Without `HVPN_AUDIT_LOG`, audit events are written to stderr.

Each line is a valid JSON object. Example events:

```json
{"event":"client_connected","peer_ip":"1.2.3.4","timestamp":1700000000}
{"event":"knock_accepted","peer_ip":"1.2.3.4","timestamp":1700000001}
{"event":"handshake_failed","peer_ip":"1.2.3.4","reason":"...","timestamp":1700000002}
{"event":"client_disconnected","peer_ip":"1.2.3.4","reason":"clean close","timestamp":1700000100}
```

---

## Deployment Guide

### Systemd (recommended)

```bash
# Build release binaries
cargo build --release

# Install
sudo bash deploy/install.sh

# Configure
sudo cp deploy/example-server.toml /etc/hvpn/server.toml
sudo nano /etc/hvpn/server.toml  # set server_port, tls_cert_path, etc.

# Enable and start
sudo systemctl enable --now hvpn-server
sudo journalctl -fu hvpn-server
```

The service unit applies security hardening: `NoNewPrivileges`, `ProtectSystem=strict`, `ProtectHome`, `CAP_NET_ADMIN` and `CAP_NET_RAW` capabilities only.

### Debian Package

```bash
# Requires dpkg-deb
bash deploy/build-deb.sh 0.1.0
sudo dpkg -i hvpn_0.1.0_amd64.deb
```

---

## Running the Tests

```bash
# Run all workspace tests
cargo test --workspace

# Run tests for a specific crate
cargo test -p hvpn-common
cargo test -p hvpn-transport
cargo test -p hvpn-crypto
cargo test -p hvpn-core

# Show test output
cargo test --workspace -- --nocapture
```

---

## Project Structure

```
HVPN/
├── Cargo.toml                  # Workspace manifest
├── README.md                   # This file
├── deploy/
│   ├── hvpn-server.service     # Systemd unit for the server
│   ├── hvpn-client.service     # Systemd unit for the client
│   ├── install.sh              # Install script
│   ├── build-deb.sh            # Debian package builder
│   ├── build-windows.ps1       # Windows release build / staging script
│   ├── example-server.toml     # Example server config
│   └── example-client.toml     # Example client config
├── bins/
│   ├── hvpn-client/            # Client binary (interactive + Windows service)
│   ├── hvpn-server/            # Server binary
│   ├── hvpn-ctl/               # Control CLI
│   └── hvpn-tray/              # Windows GUI tray app
└── crates/
    ├── hvpn-common/            # Config, error types, audit logger
    ├── hvpn-core/              # Frame codec, replay window, multiplexer
    ├── hvpn-crypto/            # X25519, ChaCha20-Poly1305, probe tokens, TLS ratchet
    ├── hvpn-metrics/           # RTT and packet-loss collector
    ├── hvpn-obfs/              # Traffic shaping and padding engine
    ├── hvpn-pq/                # Post-quantum KEM (CRYSTALS-Kyber + X25519 hybrid)
    ├── hvpn-proto/             # Protobuf/gRPC definitions
    ├── hvpn-relay/             # Onion relay routing
    ├── hvpn-stego/             # Steganographic transport
    ├── hvpn-transport/         # WebSocket, HTTP/2, gRPC adapters; cert pinning
    └── hvpn-tun/               # TUN device abstraction (Linux /dev/net/tun, Windows WinTun, stub)
```

---

## Environment Variables

| Variable | Default | Description |
|---|---|---|
| `RUST_LOG` | `info` | Log verbosity: `error`, `warn`, `info`, `debug`, `trace`. |
| `HVPN_REQUIRE_KNOCK` | unset | Set to any value to require a valid port-knock before accepting TCP connections. |
| `HVPN_AUDIT_LOG` | unset | Path for JSON-lines audit log file. Falls back to stderr if unset or if the file cannot be opened. |

---

## Security Notes

- Static server keys are zeroed in development. A production deployment must load real keys from the config file.
- Tokens are HMAC-based with a ±30 second clock-skew window and are checked against a 60-second replay cache.
- Non-HTTP connections receive a decoy nginx page to avoid protocol fingerprinting.
- Certificate pinning defeats MITM by any CA (including rogue CAs), at the cost of requiring manual fingerprint updates on certificate rotation.
- The `ProtectSystem=strict` systemd directive makes the filesystem read-only except for `ReadWritePaths`; review and expand `ReadWritePaths` if you write logs to a custom directory.

---

## Windows Support

Phase 5 adds first-class Windows support. All Windows-specific code lives behind `#[cfg(target_os = "windows")]` gates; the existing Linux code is unchanged and still compiles on both platforms.

### WinTun driver

Windows uses the [WinTun](https://wintun.net/) layer-3 kernel driver from WireGuard instead of `/dev/net/tun`. The `hvpn-tun` crate wraps it via the `wintun` Rust crate, but the driver itself is a **signed DLL you must download yourself**:

1. Download `wintun.dll` from <https://wintun.net/>.
2. Place `wintun.dll` next to `hvpn-client.exe` (and `hvpn-server.exe`) in the same directory.

The binaries compile without the DLL present; it is only required at runtime.

### Building on Windows

```powershell
# Build all Windows binaries in release mode
cargo build --workspace --release
# Binaries land in target\release\: hvpn-client.exe, hvpn-server.exe, hvpn-ctl.exe, hvpn-tray.exe
```

Or use the helper script, which builds and stages everything into `dist\hvpn-windows\`:

```powershell
powershell -File deploy\build-windows.ps1
```

The script copies `hvpn-client.exe`, `hvpn-server.exe`, `hvpn-ctl.exe`, `hvpn-tray.exe`, and `example-client.toml` into `dist\hvpn-windows\` and reminds you to drop `wintun.dll` alongside them.

### Service installation

`hvpn-client` can run as a Windows service that auto-starts on boot. Install and remove it with flags (run from an elevated prompt):

```powershell
.\hvpn-client.exe --install     # register the service (AutoStart, restarts on failure)
.\hvpn-client.exe --uninstall   # stop and remove the service
```

The service launches with `--service --config "C:\Program Files\HVPN\client.toml"`. It reports StartPending → Running → Stopped status to the Service Control Manager and shuts down cleanly on a Stop control via a cancellation token. Failure-recovery actions are configured to restart the service after 5 seconds.

Run interactively (no service) the same way as on Linux: `.\hvpn-client.exe --config client.toml`.

### GUI tray app

`hvpn-tray.exe` is a system-tray application (green = connected, yellow = connecting, red = disconnected) with a context menu: Connect, Disconnect, Status, a Transport selector (WebSocket / HTTP/2 / gRPC), and Exit. It communicates with the running daemon over the named-pipe control socket and refreshes status every 5 seconds. Tray icons are generated in code (no image files needed).

### Named-pipe control socket

On Windows the control socket is a named pipe at `\\.\pipe\hvpn` (on Linux it is the Unix socket `/tmp/hvpn.sock`). `hvpn-ctl` auto-detects the platform and connects to the right endpoint, so the same commands work everywhere:

```powershell
.\hvpn-ctl.exe status
.\hvpn-ctl.exe connect --config client.toml
.\hvpn-ctl.exe disconnect
.\hvpn-ctl.exe switch-transport websocket
```

### Route management

On Windows, interface configuration is driven by `netsh`:

- IP address: `netsh interface ip set address name="<iface>" static <tun_ip> <netmask>`
- MTU: `netsh interface ip set subinterface "<iface>" mtu=<mtu>`
- Default route: `netsh interface ip add route 0.0.0.0/0 "<iface>" <gateway>`
- Server exclusion (prevents tunnel recursion): `route add <server_ip> <gateway> metric 0`
- DNS: `netsh interface ip set dns name="<iface>" static <dns> primary` (plus `add dns ... index=N` for additional servers)

The default physical gateway is discovered by parsing `route print`. All of this requires Administrator privileges, since creating network adapters and changing routes is a privileged operation.
