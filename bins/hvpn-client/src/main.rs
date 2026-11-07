use anyhow::{Context, Result};
use clap::Parser;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use tokio::signal;
use tokio_util::sync::CancellationToken;
use tracing::info;

// Install the ring crypto provider for rustls at process startup.
fn install_crypto_provider() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}

#[cfg(target_os = "windows")]
mod service;
#[cfg(target_os = "windows")]
mod install;

use hvpn_common::{Config, RelayHopConfig};
use hvpn_core::{Frame, FrameCodec};
use hvpn_crypto::{encrypt_packet, perform_handshake_client, RatchetState};
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

// ── Control command dispatch (platform-independent) ───────────────────────────

/// Dispatch a single JSON control command against the shared state.
///
/// Shared by the Unix-socket and Windows named-pipe control listeners so that
/// the command set stays identical across platforms.
fn dispatch(cmd: &serde_json::Value, state: &Arc<Mutex<AppState>>) -> serde_json::Value {
    use serde_json::{json, Value};

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
                "websocket" => TransportKind::WebSocket,
                "http2" => TransportKind::Http2,
                "grpc" => TransportKind::Grpc,
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
            s.relay_chain.push(RelayHopConfig { address, pubkey_hex });
            json!({"ok": true})
        }
        "relay-clear" => {
            let mut s = state.lock().unwrap();
            s.relay_chain.clear();
            json!({"ok": true})
        }
        "add_profile" => {
            let profile_val = match cmd.get("profile") {
                Some(v) => v.clone(),
                None => return json!({"ok": false, "error": "missing 'profile' field"}),
            };
            match serde_json::from_value::<hvpn_common::ConnectionProfile>(profile_val) {
                Ok(profile) => {
                    let mut profiles = hvpn_common::load_profiles();
                    profiles.push(profile);
                    match hvpn_common::save_profiles(&profiles) {
                        Ok(_) => json!({"ok": true}),
                        Err(e) => json!({"ok": false, "error": e.to_string()}),
                    }
                }
                Err(e) => json!({"ok": false, "error": e.to_string()}),
            }
        }
        "list_profiles" => {
            let profiles = hvpn_common::load_profiles();
            json!({"ok": true, "profiles": profiles})
        }
        "activate_profile" => {
            let name = match cmd.get("name").and_then(Value::as_str) {
                Some(n) => n.to_string(),
                None => return json!({"ok": false, "error": "missing 'name' field"}),
            };
            let profiles = hvpn_common::load_profiles();
            match profiles.iter().find(|p| p.name.as_deref() == Some(&name) || p.server == name) {
                Some(p) => {
                    let mut s = state.lock().unwrap();
                    s.connected = false; // trigger reconnect
                    s.config_path = p.server.clone();
                    json!({"ok": true, "server": p.server})
                }
                None => json!({"ok": false, "error": "profile not found"}),
            }
        }
        "get_settings" => {
            let s = state.lock().unwrap();
            json!({
                "ok": true,
                "transport": s.transport_kind.to_string(),
                "connected": s.connected,
            })
        }
        "set_setting" => {
            let key = match cmd.get("key").and_then(Value::as_str) {
                Some(k) => k.to_string(),
                None => return json!({"ok": false, "error": "missing 'key' field"}),
            };
            let value = match cmd.get("value").and_then(Value::as_str) {
                Some(v) => v.to_string(),
                None => return json!({"ok": false, "error": "missing 'value' field"}),
            };
            match key.as_str() {
                "transport" => {
                    let kind = match value.as_str() {
                        "websocket" => TransportKind::WebSocket,
                        "http2" => TransportKind::Http2,
                        "grpc" => TransportKind::Grpc,
                        _ => return json!({"ok": false, "error": "unknown transport kind"}),
                    };
                    state.lock().unwrap().transport_kind = kind;
                    json!({"ok": true})
                }
                _ => json!({"ok": true, "note": "setting acknowledged"}),
            }
        }
        other => json!({"ok": false, "error": format!("unknown command '{other}'")}),
    }
}

// ── Control socket ─────────────────────────────────────────────────────────────

#[cfg(unix)]
mod control {
    use super::AppState;
    use serde_json::Value;
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

        let response = super::dispatch(&cmd, &state);

        let mut resp_line = serde_json::to_string(&response)?;
        resp_line.push('\n');
        writer.write_all(resp_line.as_bytes()).await?;
        Ok(())
    }
}

#[cfg(windows)]
mod control {
    use super::AppState;
    use serde_json::Value;
    use std::sync::{Arc, Mutex};
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    use tokio::net::windows::named_pipe::ServerOptions;
    use tracing::{error, info, warn};

    /// Named pipe the daemon listens on: `\\.\pipe\hvpn`.
    const PIPE_NAME: &str = r"\\.\pipe\hvpn";

    pub async fn listen_control_socket(state: Arc<Mutex<AppState>>) {
        info!("control socket listening on named pipe {}", PIPE_NAME);

        loop {
            // Create a fresh named-pipe server instance each iteration so we can
            // service one client per instance concurrently.
            let server = match ServerOptions::new().create(PIPE_NAME) {
                Ok(s) => s,
                Err(e) => {
                    error!("failed to create named pipe {}: {}", PIPE_NAME, e);
                    tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                    continue;
                }
            };

            // Block until a client connects.
            if let Err(e) = server.connect().await {
                warn!("named pipe connect error: {}", e);
                continue;
            }

            let state = Arc::clone(&state);
            tokio::spawn(async move {
                if let Err(e) = handle_connection(server, state).await {
                    warn!("control connection error: {}", e);
                }
            });
        }
    }

    async fn handle_connection(
        stream: tokio::net::windows::named_pipe::NamedPipeServer,
        state: Arc<Mutex<AppState>>,
    ) -> anyhow::Result<()> {
        let (reader, mut writer) = tokio::io::split(stream);
        let mut buf_reader = BufReader::new(reader);
        let mut line = String::new();

        buf_reader.read_line(&mut line).await?;
        let cmd: Value = serde_json::from_str(line.trim())?;

        let response = super::dispatch(&cmd, &state);

        let mut resp_line = serde_json::to_string(&response)?;
        resp_line.push('\n');
        writer.write_all(resp_line.as_bytes()).await?;
        Ok(())
    }
}

#[cfg(not(any(unix, windows)))]
mod control {
    use super::AppState;
    use std::sync::{Arc, Mutex};

    /// No-op stub on unsupported platforms.
    pub async fn listen_control_socket(_state: Arc<Mutex<AppState>>) {
        // Control socket not supported on this platform.
    }
}

// ── Entry point ────────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() -> Result<()> {
    install_crypto_provider();
    // Initialise structured logging.
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive("hvpn_client=info".parse()?),
        )
        .init();

    // Windows: handle service / install / uninstall flags before normal CLI
    // parsing, since the Windows service manager launches us with these flags.
    #[cfg(target_os = "windows")]
    {
        let args: Vec<String> = std::env::args().collect();
        if args.iter().any(|a| a == "--service") {
            // Run the service control dispatcher on this (main) thread.
            return service::run().map_err(|e| anyhow::anyhow!("service error: {:?}", e));
        }
        if args.iter().any(|a| a == "--install") {
            install::install_service()
                .map_err(|e| anyhow::anyhow!("install error: {:?}", e))?;
            println!("HVPN Client service installed.");
            return Ok(());
        }
        if args.iter().any(|a| a == "--uninstall") {
            install::uninstall_service()
                .map_err(|e| anyhow::anyhow!("uninstall error: {:?}", e))?;
            println!("HVPN Client service uninstalled.");
            return Ok(());
        }
        if let Err(e) = install::ensure_wintun() {
            eprintln!("[hvpn-client] warn: could not ensure wintun.dll: {}", e);
        }
    }

    let cli = Cli::parse();

    // Graceful shutdown token; cancelled by Ctrl+C in interactive mode.
    let shutdown = CancellationToken::new();
    {
        let token = shutdown.clone();
        tokio::spawn(async move {
            if signal::ctrl_c().await.is_ok() {
                info!("received Ctrl+C, shutting down");
                token.cancel();
            }
        });
    }

    run_client(&cli.config.to_string_lossy(), shutdown).await
}

/// Core client loop shared by the interactive and Windows-service entry points.
///
/// Runs the control socket listener, performs the handshake, connects the
/// transport, and pumps packets through the TUN device until `shutdown` is
/// cancelled.
pub async fn run_client(config_path: &str, shutdown: CancellationToken) -> Result<()> {
    // Resolve config path: if the given path doesn't exist, try the platform default.
    let resolved_config = if std::path::Path::new(config_path).exists() {
        config_path.to_string()
    } else {
        #[cfg(target_os = "windows")]
        let default = std::env::var("APPDATA")
            .map(|a| format!(r"{}\HVPN\client.toml", a))
            .unwrap_or_else(|_| config_path.to_string());
        #[cfg(not(target_os = "windows"))]
        let default = std::env::var("HOME")
            .map(|h| format!("{}/.config/hvpn/client.toml", h))
            .unwrap_or_else(|_| config_path.to_string());
        default
    };

    // Load configuration, falling back to saved profiles.
    let cfg = match Config::load_and_validate(&resolved_config) {
        Ok(c) => c,
        Err(_) => {
            let profiles = hvpn_common::load_profiles();
            if let Some(first) = profiles.first() {
                eprintln!("[hvpn-client] No config file found. Using saved profile: {}", first.server);
                Config {
                    server_address: first.server.clone(),
                    server_port: first.port,
                    tls_cert_path: String::new(),
                    obfs_profile: hvpn_common::ObfsProfile::Browser,
                    relay_chain: None,
                    stego_mode: false,
                    post_quantum: false,
                    nat_enabled: false,
                    tun_ip: "10.8.0.2".to_string(),
                    tun_netmask: "255.255.255.0".to_string(),
                    dns_servers: vec!["1.1.1.1".to_string()],
                    cert_pin_fingerprints: vec![],
                    use_tls: false,
                    accept_invalid_certs: true,
                }
            } else {
                eprintln!("[hvpn-client] No config found. On Windows, use the HVPN tray app to set up. On Linux, run: hvpn-client --config <path>");
                return Err(anyhow::anyhow!("no configuration available"));
            }
        }
    };

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

    // Open TUN device — WinTun on Windows, LinuxTun on Linux, StubTun as fallback.
    #[cfg(target_os = "windows")]
    let mut tun: Box<dyn TunDevice> = {
        use hvpn_tun::WinTunDevice;
        match WinTunDevice::open("hvpn0", &format!("{}/24", cfg.tun_ip), &cfg.server_address).await {
            Ok(dev) => {
                info!("WinTun device opened successfully");
                // Wait for the WinTun adapter to fully initialise before touching the routing table.
                tokio::time::sleep(std::time::Duration::from_millis(500)).await;

                // Get real gateway BEFORE setting VPN default route (otherwise VPN wins and gateway lookup returns VPN).
                let real_gateway = hvpn_tun::get_default_gateway().ok();
                info!("real gateway detected: {:?}", real_gateway);

                // FIRST: add server exclusion route via real gateway.
                if let Some(ref gateway) = real_gateway {
                    // Delete stale route first.
                    let _ = std::process::Command::new("route")
                        .args(["delete", &cfg.server_address])
                        .output();
                    match std::process::Command::new("route")
                        .args(["add", &cfg.server_address, "mask", "255.255.255.255", gateway, "metric", "1"])
                        .output() {
                        Ok(o) if o.status.success() => info!("server exclusion route set via {}", gateway),
                        Ok(o) => tracing::warn!("route add server exclusion failed: {}", String::from_utf8_lossy(&o.stdout)),
                        Err(e) => tracing::warn!("route add server exclusion error: {}", e),
                    }
                }

                // SECOND: set VPN default route.
                match hvpn_tun::set_default_route("hvpn0", "10.8.0.1") {
                    Ok(_) => info!("default route set through VPN tunnel OK"),
                    Err(e) => tracing::warn!("set_default_route failed: {}", e),
                }
                // Set DNS servers.
                if !cfg.dns_servers.is_empty() {
                    let _ = hvpn_tun::set_dns("hvpn0", &cfg.dns_servers);
                }
                // Log the default routes so we can confirm the VPN route was installed.
                match std::process::Command::new("route").arg("print").output() {
                    Ok(out) => {
                        let text = String::from_utf8_lossy(&out.stdout);
                        for line in text.lines().filter(|l| l.contains("0.0.0.0")) {
                            info!("route: {}", line.trim());
                        }
                    }
                    Err(e) => tracing::warn!("could not run `route print`: {}", e),
                }
                Box::new(dev)
            }
            Err(e) => {
                tracing::warn!("WinTun not available ({}), using stub — traffic will NOT be routed", e);
                Box::new(StubTun::new())
            }
        }
    };
    #[cfg(target_os = "linux")]
    let mut tun: Box<dyn TunDevice> = {
        use hvpn_tun::LinuxTun;
        match LinuxTun::open("hvpn0", &format!("{}/24", cfg.tun_ip), &cfg.server_address).await {
            Ok(dev) => {
                info!("Linux TUN device opened successfully");
                Box::new(dev)
            }
            Err(e) => {
                tracing::warn!("TUN not available ({}), using stub", e);
                Box::new(StubTun::new())
            }
        }
    };
    #[cfg(not(any(target_os = "windows", target_os = "linux")))]
    let mut tun: Box<dyn TunDevice> = Box::new(StubTun::new());

    // Connect transport.
    let transport_cfg = TransportConfig::new(cfg.server_address.clone(), cfg.server_port, "/hvpn");
    let transport_cfg = {
        let mut tc = transport_cfg;
        tc.danger_accept_invalid_certs = cfg.accept_invalid_certs;

        // Load auth_secret from saved profile matching this server.
        let profiles = hvpn_common::load_profiles();
        if let Some(profile) = profiles.iter().find(|p| p.server == cfg.server_address) {
            if profile.auth_secret.len() == 64 {
                let secret_bytes: Vec<u8> = (0..profile.auth_secret.len())
                    .step_by(2)
                    .filter_map(|i| {
                        u8::from_str_radix(profile.auth_secret.get(i..i+2)?, 16).ok()
                    })
                    .collect();
                if secret_bytes.len() == 32 {
                    let mut arr = [0u8; 32];
                    arr.copy_from_slice(&secret_bytes);
                    tc.auth_secret = Some(arr);
                    info!("auth secret loaded from saved profile");
                }
            }
        }

        tc
    };

    // Load server pubkey from saved profiles if available, else use zeroed key.
    let server_pubkey: [u8; 32] = {
        let profiles = hvpn_common::load_profiles();
        let matching = profiles.iter().find(|p| p.server == cfg.server_address);
        if let Some(profile) = matching {
            let bytes = (0..profile.pubkey.len())
                .step_by(2)
                .filter_map(|i| u8::from_str_radix(profile.pubkey.get(i..i+2)?, 16).ok())
                .collect::<Vec<u8>>();
            if bytes.len() == 32 {
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&bytes);
                info!("using server pubkey from saved profile");
                arr
            } else {
                tracing::warn!("saved profile pubkey invalid length, using zeroed key");
                [0u8; 32]
            }
        } else {
            tracing::warn!("no saved profile found for {}, using zeroed server pubkey — crypto handshake will fail", cfg.server_address);
            [0u8; 32]
        }
    };
    let (ephemeral_pub, session_keys) = perform_handshake_client(&server_pubkey)
        .context("client handshake failed")?;

    info!(pubkey = %hex_encode(&ephemeral_pub), "handshake keys derived");

    let codec = FrameCodec::new(session_keys.header_key);
    let mut obfs = ObfsEngine::new();
    let mut seq: u64 = 0;

    // Attempt to connect; log and exit gracefully on failure (server may not
    // be running in Phase 1 testing).
    let transport_result = if cfg.use_tls {
        WebSocketTransport::connect(&transport_cfg).await
    } else {
        WebSocketTransport::connect_plain(&transport_cfg).await
    };
    let transport: Option<WebSocketTransport> = match transport_result {
        Ok(t) => {
            info!("WebSocket transport connected");
            // Send our ephemeral pubkey to the server as the first message
            // so the server can complete the X25519 handshake.
            if let Err(e) = t.send(ephemeral_pub.to_vec()).await {
                tracing::warn!("failed to send ephemeral pubkey to server: {}", e);
            } else {
                info!("crypto handshake pubkey sent to server");
            }
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

    info!("entering tunnel loop (stop signal to exit)");

    // Main tunnel loop — graceful shutdown on the cancellation token.
    let result = tokio::select! {
        _ = shutdown.cancelled() => {
            info!("shutdown requested, stopping");
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
    use hvpn_core::{FrameType, ReplayWindow};
    use hvpn_crypto::decrypt_packet;
    use rand::{Rng, SeedableRng};

    let transport = match transport {
        Some(t) => t.clone(),
        None => {
            tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;
            return Ok(());
        }
    };

    // Split into two concurrent tasks for full-duplex operation.
    // This is critical for throughput — select! blocks one direction
    // while the other is processing, halving effective speed.

    let header_key = keys.header_key;
    let keys_clone = keys.clone();

    // Channel for inbound packets to be written to TUN.
    let (inbound_tx, mut inbound_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(1024);

    // Clone transport for the download task (uses Arc internally, cheap clone).
    let transport_rx = transport.clone();

    // Spawn the server→TUN (download) task — runs independently for full duplex.
    let inbound_state = Arc::clone(&state);
    let inbound_task = tokio::spawn(async move {
        let codec_in = FrameCodec::new(header_key);
        let mut replay = ReplayWindow::new();
        let mut total_in: u64 = 0;

        loop {
            match transport_rx.recv().await {
                Ok(data) => {
                    // Unpad — read the 2-byte prefix, strip padding.
                    let unpadded = if data.len() >= 2 {
                        let pad_len = u16::from_le_bytes([data[0], data[1]]) as usize;
                        let end = data.len().saturating_sub(pad_len);
                        if end > 2 { data[2..end].to_vec() } else { continue; }
                    } else { continue; };

                    match codec_in.decode(&unpadded) {
                        Ok(frame) => {
                            if frame.frame_type != FrameType::Data { continue; }
                            if replay.check_and_advance(frame.seq).is_err() { continue; }
                            match decrypt_packet(&keys_clone, &frame.payload, frame.seq, None) {
                                Ok(ip_pkt) => {
                                    total_in = total_in.wrapping_add(ip_pkt.len() as u64);
                                    if inbound_tx.send(ip_pkt).await.is_err() { break; }
                                    // Update state every 100 packets to avoid lock contention.
                                    if total_in % (100 * 1400) == 0 {
                                        let mut s = inbound_state.lock().unwrap();
                                        s.bytes_in = s.bytes_in.wrapping_add(total_in);
                                        total_in = 0;
                                    }
                                }
                                Err(_) => continue,
                            }
                        }
                        Err(_) => continue,
                    }
                }
                Err(e) => {
                    tracing::warn!("transport recv error: {}", e);
                    break;
                }
            }
        }
    });

    // Main TUN→server (upload) loop, interleaved with writing inbound packets.
    let mut total_out: u64 = 0;
    let mut rng = rand::rngs::StdRng::from_entropy();

    loop {
        tokio::select! {
            // Write inbound packets to TUN when available.
            Some(ip_pkt) = inbound_rx.recv() => {
                if let Err(e) = tun.write_packet(&ip_pkt).await {
                    tracing::warn!("tun write error: {}", e);
                    break;
                }
            }
            // Read outbound packets from TUN and send to server.
            tun_result = tun.read_packet() => {
                match tun_result {
                    Ok(pkt) if !pkt.is_empty() => {
                        let ciphertext = encrypt_packet(&keys, &pkt, *seq, None)
                            .context("encrypt failed")?;

                        // Minimal padding: 2-byte header + 0-16 bytes random.
                        // Full 512-byte padding kills throughput.
                        let pad_len: u16 = rng.gen_range(0u16..16);
                        let mut padded = Vec::with_capacity(2 + ciphertext.len() + 4 + pad_len as usize);
                        let frame = Frame {
                            seq: *seq,
                            stream_id: 0,
                            frame_type: FrameType::Data,
                            flags: 0,
                            payload: ciphertext,
                            padding: vec![],
                        };
                        let encoded = codec.encode(&frame);
                        padded.extend_from_slice(&pad_len.to_le_bytes());
                        padded.extend_from_slice(&encoded);
                        let pad: Vec<u8> = (0..pad_len).map(|_| rng.gen::<u8>()).collect();
                        padded.extend_from_slice(&pad);

                        let len = padded.len() as u64;
                        if transport.send(padded).await.is_err() { break; }
                        total_out = total_out.wrapping_add(len);
                        *seq = seq.wrapping_add(1);

                        // Update state periodically, not every packet.
                        if *seq % 100 == 0 {
                            let mut s = state.lock().unwrap();
                            s.bytes_out = s.bytes_out.wrapping_add(total_out);
                            total_out = 0;
                        }
                    }
                    Ok(_) => {
                        // Empty packet — small yield to avoid busy loop.
                        tokio::task::yield_now().await;
                    }
                    Err(e) => {
                        tracing::warn!("tun read error: {}", e);
                        tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;
                    }
                }
            }
        }
    }

    inbound_task.abort();
    Ok(())
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

