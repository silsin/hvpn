use anyhow::{Context, Result};
use clap::Parser;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use tokio::signal;
use tracing::info;

use hvpn_common::{Config, RelayHopConfig};
use hvpn_core::{Frame, FrameCodec, FrameType};
use hvpn_crypto::{encrypt_packet, perform_handshake_client};
use hvpn_obfs::ObfsEngine;
use hvpn_transport::{Transport, TransportConfig, WebSocketTransport};
use hvpn_tun::{StubTun, TunDevice};

/// HVPN client — connects to an HVPN server and tunnels IP traffic.
#[derive(Parser, Debug)]
#[command(name = "hvpn-client", version, about)]
struct Cli {
    /// Path to the TOML configuration file.
    #[arg(long, default_value = "config.toml")]
    config: PathBuf,
}

// ── Shared daemon state ────────────────────────────────────────────────────────

/// Transport kind as reported to `hvpn-ctl status`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransportKind {
    WebSocket,
    Http2,
    Grpc,
}

impl std::fmt::Display for TransportKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TransportKind::WebSocket => write!(f, "websocket"),
            TransportKind::Http2 => write!(f, "http2"),
            TransportKind::Grpc => write!(f, "grpc"),
        }
    }
}

/// In-memory state shared between the tunnel loop and the control socket.
pub struct AppState {
    pub connected: bool,
    pub transport_kind: TransportKind,
    /// Round-trip time in milliseconds (placeholder).
    pub rtt_ms: u64,
    /// Bytes received from server.
    pub bytes_in: u64,
    /// Bytes sent to server.
    pub bytes_out: u64,
    /// Number of active streams (placeholder).
    pub active_streams: u32,
    /// Relay chain.
    pub relay_chain: Vec<RelayHopConfig>,
    /// Config path used to connect.
    pub config_path: String,
}

impl AppState {
    fn new() -> Self {
        AppState {
            connected: false,
            transport_kind: TransportKind::WebSocket,
            rtt_ms: 0,
            bytes_in: 0,
            bytes_out: 0,
            active_streams: 0,
            relay_chain: Vec::new(),
            config_path: String::new(),
        }
    }
}

// ── Control socket (Unix only) ─────────────────────────────────────────────────

#[cfg(unix)]
mod control {
    use super::AppState;
    use serde_json::{json, Value};
    use std::sync::{Arc, Mutex};
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    use tokio::net::UnixListener;
    use tracing::{error, info, warn};

    const SOCK_PATH: &str = "/tmp/hvpn.sock";

    pub async fn listen_control_socket(state: Arc<Mutex<AppState>>) {
        // Remove stale socket file if present.
        let _ = std::fs::remove_file(SOCK_PATH);

        let listener = match UnixListener::bind(SOCK_PATH) {
            Ok(l) => {
                info!("control socket listening on {}", SOCK_PATH);
                l
            }
            Err(e) => {
                error!("failed to bind control socket {}: {}", SOCK_PATH, e);
                return;
            }
        };

        loop {
            match listener.accept().await {
                Ok((stream, _addr)) => {
                    let state = Arc::clone(&state);
                    tokio::spawn(async move {
                        if let Err(e) = handle_connection(stream, state).await {
                            warn!("control connection error: {}", e);
                        }
                    });
                }
                Err(e) => {
                    error!("control socket accept error: {}", e);
                }
            }
        }
    }

    async fn handle_connection(
        stream: tokio::net::UnixStream,
        state: Arc<Mutex<AppState>>,
    ) -> anyhow::Result<()> {
        let (reader, mut writer) = tokio::io::split(stream);
        let mut buf_reader = BufReader::new(reader);
        let mut line = String::new();

        buf_reader.read_line(&mut line).await?;
        let cmd: Value = serde_json::from_str(line.trim())?;

        let response = dispatch(&cmd, &state);

        let mut resp_line = serde_json::to_string(&response)?;
        resp_line.push('\n');
        writer.write_all(resp_line.as_bytes()).await?;
        Ok(())
    }

    fn dispatch(cmd: &Value, state: &Arc<Mutex<AppState>>) -> Value {
        let cmd_str = match cmd.get("cmd").and_then(Value::as_str) {
            Some(s) => s,
            None => return json!({"ok": false, "error": "missing 'cmd' field"}),
        };

        match cmd_str {
            "status" => {
                let s = state.lock().unwrap();
                json!({
                    "ok": true,
                    "status": {
                        "connected": s.connected,
                        "transport": s.transport_kind.to_string(),
                        "rtt_ms": s.rtt_ms,
                        "bytes_in": s.bytes_in,
                        "bytes_out": s.bytes_out,
                        "active_streams": s.active_streams,
                    }
                })
            }
            "connect" => {
                let path = cmd
                    .get("config")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_string();
                let mut s = state.lock().unwrap();
                s.connected = true;
                s.config_path = path;
                json!({"ok": true})
            }
            "disconnect" => {
                let mut s = state.lock().unwrap();
                s.connected = false;
                json!({"ok": true})
            }
            "switch-transport" => {
                let kind_str = match cmd.get("kind").and_then(Value::as_str) {
                    Some(k) => k,
                    None => return json!({"ok": false, "error": "missing 'kind' field"}),
                };
                let kind = match kind_str {
                    "websocket" => super::TransportKind::WebSocket,
                    "http2" => super::TransportKind::Http2,
                    "grpc" => super::TransportKind::Grpc,
                    other => {
                        return json!({"ok": false, "error": format!("unknown transport kind '{other}'")})
                    }
                };
                let mut s = state.lock().unwrap();
                s.transport_kind = kind;
                json!({"ok": true})
            }
            "relay-add" => {
                let address = match cmd.get("address").and_then(Value::as_str) {
                    Some(a) => a.to_string(),
                    None => return json!({"ok": false, "error": "missing 'address' field"}),
                };
                let pubkey_hex = match cmd.get("pubkey_hex").and_then(Value::as_str) {
                    Some(k) => k.to_string(),
                    None => return json!({"ok": false, "error": "missing 'pubkey_hex' field"}),
                };
                let mut s = state.lock().unwrap();
                s.relay_chain.push(super::RelayHopConfig { address, pubkey_hex });
                json!({"ok": true})
            }
            "relay-clear" => {
                let mut s = state.lock().unwrap();
                s.relay_chain.clear();
                json!({"ok": true})
            }
            other => json!({"ok": false, "error": format!("unknown command '{other}'")}),
        }
    }
}

#[cfg(not(unix))]
mod control {
    use super::AppState;
    use std::sync::{Arc, Mutex};

    /// No-op stub on non-Unix platforms.
    pub async fn listen_control_socket(_state: Arc<Mutex<AppState>>) {
        // Control socket not supported on this platform.
    }
}

// ── Entry point ────────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() -> Result<()> {
    // Initialise structured logging.
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive("hvpn_client=info".parse()?),
        )
        .init();

    let cli = Cli::parse();

    // Load configuration.
    let cfg = Config::load_and_validate(cli.config.to_str().unwrap_or("config.toml"))
        .unwrap_or_else(|e| {
            eprintln!("[hvpn-client] configuration error:\n{}", e);
            std::process::exit(1);
        });

    info!(
        server = %cfg.server_address,
        port   = cfg.server_port,
        "starting HVPN client"
    );

    // Initialise shared state.
    let state = Arc::new(Mutex::new(AppState::new()));

    // Spawn control socket listener.
    {
        let state = Arc::clone(&state);
        tokio::spawn(async move {
            control::listen_control_socket(state).await;
        });
    }

    // NOTE: In Phase 1 we use StubTun so the binary compiles and runs on any
    // platform, including the development machine.  The Linux /dev/net/tun
    // path is gated behind #[cfg(target_os = "linux")] inside hvpn-tun.
    let mut tun: Box<dyn TunDevice> = Box::new(StubTun::new());

    // Connect transport.
    let transport_cfg = TransportConfig::new(cfg.server_address.clone(), cfg.server_port, "/hvpn");

    // For now we use a well-known dummy server public key (32 zero bytes).
    // A real deployment would load this from the config file.
    let server_pubkey = [0u8; 32];
    let (ephemeral_pub, session_keys) = perform_handshake_client(&server_pubkey)
        .context("client handshake failed")?;

    info!(pubkey = %hex_encode(&ephemeral_pub), "handshake keys derived");

    let codec = FrameCodec::new(session_keys.header_key);
    let mut obfs = ObfsEngine::new();
    let mut seq: u64 = 0;

    // Attempt to connect; log and exit gracefully on failure (server may not
    // be running in Phase 1 testing).
    let transport_result = WebSocketTransport::connect(&transport_cfg).await;
    let transport: Option<WebSocketTransport> = match transport_result {
        Ok(t) => {
            info!("WebSocket transport connected");
            {
                let mut s = state.lock().unwrap();
                s.connected = true;
            }
            Some(t)
        }
        Err(e) => {
            info!("transport not available (Phase 1 stub mode): {}", e);
            None
        }
    };

    info!("entering tunnel loop (Ctrl+C to exit)");

    // Main tunnel loop — graceful shutdown on Ctrl+C.
    let result = tokio::select! {
        _ = signal::ctrl_c() => {
            info!("received Ctrl+C, shutting down");
            Ok(())
        }
        res = tunnel_loop(
            &mut tun,
            transport.as_ref(),
            &codec,
            &mut obfs,
            &mut seq,
            &session_keys,
            Arc::clone(&state),
        ) => res,
    };

    if let Some(t) = transport.as_ref() {
        let _ = t.close().await;
    }

    {
        let mut s = state.lock().unwrap();
        s.connected = false;
    }

    result
}

async fn tunnel_loop(
    tun: &mut Box<dyn TunDevice>,
    transport: Option<&WebSocketTransport>,
    codec: &FrameCodec,
    obfs: &mut ObfsEngine,
    seq: &mut u64,
    keys: &hvpn_crypto::SessionKeys,
    state: Arc<Mutex<AppState>>,
) -> Result<()> {
    loop {
        // Read a packet from TUN.
        match tun.read_packet().await {
            Ok(pkt) => {
                // Encrypt.
                let ciphertext =
                    encrypt_packet(keys, &pkt, *seq, None).context("encrypt failed")?;

                // Wrap in a frame.
                let frame = Frame {
                    seq: *seq,
                    stream_id: 0,
                    frame_type: FrameType::Data,
                    flags: 0,
                    payload: ciphertext,
                    padding: vec![],
                };
                let encoded = codec.encode(&frame);

                // Obfuscate.
                let padded = obfs.pad_packet(encoded);

                // Send.
                if let Some(t) = transport {
                    let len = padded.len() as u64;
                    t.send(padded).await.context("send failed")?;
                    let mut s = state.lock().unwrap();
                    s.bytes_out = s.bytes_out.wrapping_add(len);
                }

                obfs.apply_jitter().await;
                *seq = seq.wrapping_add(1);
            }
            Err(_) => {
                // StubTun is empty — yield to avoid busy-loop.
                tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;
            }
        }
    }
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}
