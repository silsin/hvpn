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

mod supervisor;
pub use supervisor::run_client;

use hvpn_common::RelayHopConfig;
use hvpn_core::{Frame, FrameCodec};
use hvpn_crypto::encrypt_packet;
use hvpn_obfs::ObfsEngine;
use hvpn_transport::{Transport, WebSocketTransport};
use hvpn_tun::TunDevice;

/// HVPN client — connects to an HVPN server and tunnels IP traffic.
#[derive(Parser, Debug)]
#[command(name = "hvpn-client", version, about)]
struct Cli {
    /// Path to the TOML configuration file.
    #[arg(long, default_value = "config.toml")]
    config: PathBuf,

    /// Import a link from your server (akbar://v1/...) and connect with it.
    #[arg(long)]
    link: Option<String>,
}

/// Writes log lines to stdout and to `client.log` next to the saved profiles,
/// so users can attach the file when reporting a problem.
struct LogTee(Option<Arc<std::fs::File>>);

impl std::io::Write for LogTee {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let _ = std::io::stdout().write_all(buf);
        if let Some(f) = &self.0 {
            let _ = (&**f).write_all(buf);
        }
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        let _ = std::io::stdout().flush();
        Ok(())
    }
}

/// Path of the client log file.
fn log_file_path() -> PathBuf {
    hvpn_common::profiles_path().with_file_name("client.log")
}

fn open_log_file() -> Option<Arc<std::fs::File>> {
    let path = log_file_path();
    if let Some(dir) = path.parent() {
        let _ = std::fs::create_dir_all(dir);
    }
    // Keep the log from growing forever: start fresh past 2 MiB.
    if std::fs::metadata(&path).map(|m| m.len() > 2 * 1024 * 1024).unwrap_or(false) {
        let _ = std::fs::remove_file(&path);
    }
    std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .ok()
        .map(Arc::new)
}

/// Import a link from `--link`: save it as a profile and make it the active one.
fn import_link(link: &str) -> Result<String> {
    let profile = hvpn_common::ConnectionProfile::from_link(link)
        .map_err(|e| anyhow::anyhow!("that link isn't valid: {e}"))?;
    let mut profiles = hvpn_common::load_profiles();
    let name = hvpn_common::upsert_profile(&mut profiles, profile);
    hvpn_common::save_profiles(&profiles)
        .map_err(|e| anyhow::anyhow!("couldn't save the profile: {e}"))?;
    hvpn_common::save_active_profile(&name);
    Ok(name)
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

/// Where the connection currently is, as shown to the user.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Phase {
    /// Not connected, and not trying to be.
    Idle,
    /// First attempt in progress.
    Connecting,
    /// Tunnel is up.
    Connected,
    /// Lost or failed; trying again automatically.
    Reconnecting,
    /// Gave up; `last_error` says why. Needs the user.
    Failed,
}

impl Phase {
    pub fn as_str(self) -> &'static str {
        match self {
            Phase::Idle => "idle",
            Phase::Connecting => "connecting",
            Phase::Connected => "connected",
            Phase::Reconnecting => "reconnecting",
            Phase::Failed => "failed",
        }
    }
}

/// Lock-free packet byte counters, updated from the tunnel hot path.
#[derive(Default)]
pub struct Counters {
    pub bytes_in: std::sync::atomic::AtomicU64,
    pub bytes_out: std::sync::atomic::AtomicU64,
}

/// In-memory state shared between the tunnel loop and the control socket.
pub struct AppState {
    pub connected: bool,
    pub transport_kind: TransportKind,
    /// Round-trip time through the tunnel in milliseconds (0 = unknown).
    pub rtt_ms: u64,
    /// Bytes received from server this session.
    pub bytes_in: u64,
    /// Bytes sent to server this session.
    pub bytes_out: u64,
    /// Number of active streams (placeholder).
    pub active_streams: u32,
    /// Relay chain.
    pub relay_chain: Vec<RelayHopConfig>,
    /// Config path used to connect.
    pub config_path: String,

    // ── Connection lifecycle (see supervisor.rs) ──
    pub phase: Phase,
    /// The user wants the tunnel up (false after Disconnect or a fatal error).
    pub want_connected: bool,
    /// Name of the profile selected by the user, if any.
    pub active_profile: Option<String>,
    /// Display name of the server being used.
    pub server: String,
    /// Latest problem, in plain language.
    pub last_error: Option<String>,
    /// Current connection attempt (1-based) while connecting/reconnecting.
    pub attempt: u32,
    /// When the next automatic retry happens.
    pub retry_at: Option<std::time::Instant>,
    pub connected_at: Option<std::time::Instant>,
    /// Smoothed throughput in bytes per second.
    pub speed_in: u64,
    pub speed_out: u64,
    pub counters: Arc<Counters>,
    /// Wakes the supervisor (connect / disconnect / retry now).
    pub wake: Arc<tokio::sync::Notify>,
    /// Cancels the running session.
    pub session_cancel: Option<CancellationToken>,
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
            phase: Phase::Idle,
            want_connected: false,
            active_profile: None,
            server: String::new(),
            last_error: None,
            attempt: 0,
            retry_at: None,
            connected_at: None,
            speed_in: 0,
            speed_out: 0,
            counters: Arc::new(Counters::default()),
            wake: Arc::new(tokio::sync::Notify::new()),
            session_cancel: None,
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
                    "phase": s.phase.as_str(),
                    "server": s.server,
                    "profile": s.active_profile,
                    "last_error": s.last_error,
                    "attempt": s.attempt,
                    "retry_in_secs": s.retry_at.map(|t| {
                        t.saturating_duration_since(std::time::Instant::now()).as_secs()
                    }),
                    "uptime_secs": s.connected_at.map(|t| t.elapsed().as_secs()),
                    "speed_in": s.speed_in,
                    "speed_out": s.speed_out,
                }
            })
        }
        "connect" => {
            // Optional "profile": name or server of a saved profile to use.
            let profile = cmd.get("profile").and_then(Value::as_str).map(String::from);
            let mut s = state.lock().unwrap_or_else(|p| p.into_inner());
            let switching = match &profile {
                Some(name) if s.active_profile.as_deref() != Some(name.as_str()) => {
                    hvpn_common::save_active_profile(name);
                    s.active_profile = Some(name.clone());
                    true
                }
                _ => false,
            };
            s.want_connected = true;
            s.last_error = None;
            if matches!(s.phase, Phase::Failed | Phase::Idle) {
                s.phase = Phase::Connecting;
            }
            if switching {
                // Drop the current session; the supervisor reconnects to the new server.
                if let Some(c) = &s.session_cancel {
                    c.cancel();
                }
            }
            s.wake.notify_one();
            json!({"ok": true})
        }
        "disconnect" => {
            let mut s = state.lock().unwrap_or_else(|p| p.into_inner());
            s.want_connected = false;
            s.last_error = None;
            if let Some(c) = &s.session_cancel {
                c.cancel();
            }
            s.wake.notify_one();
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
            let names: Vec<String> = profiles.iter().map(|p| p.display_name()).collect();
            let active = state
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .active_profile
                .clone();
            json!({"ok": true, "profiles": profiles, "names": names, "active": active})
        }
        "activate_profile" => {
            let name = match cmd.get("name").and_then(Value::as_str) {
                Some(n) => n.to_string(),
                None => return json!({"ok": false, "error": "missing 'name' field"}),
            };
            let profiles = hvpn_common::load_profiles();
            match hvpn_common::find_profile(&profiles, &name) {
                Some(p) => {
                    let display = p.display_name();
                    hvpn_common::save_active_profile(&display);
                    let mut s = state.lock().unwrap_or_else(|p| p.into_inner());
                    s.active_profile = Some(display);
                    s.want_connected = true;
                    s.last_error = None;
                    if let Some(c) = &s.session_cancel {
                        c.cancel();
                    }
                    s.wake.notify_one();
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
    let log_file = open_log_file();
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive("hvpn_client=info".parse()?),
        )
        .with_ansi(false)
        .with_writer(move || LogTee(log_file.clone()))
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

    if let Some(link) = cli.link.as_deref() {
        let name = import_link(link)?;
        info!("imported server '{}' and selected it", name);
    }

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

    // Lock-free byte counters (folded into totals/speeds by the supervisor).
    use std::sync::atomic::Ordering::Relaxed;
    let counters_out = state.lock().unwrap_or_else(|p| p.into_inner()).counters.clone();
    let counters_in = Arc::clone(&counters_out);

    /// Aborts the wrapped task when dropped, so cancelling the tunnel (or an
    /// early return) never leaves the download task running.
    struct AbortOnDrop(tokio::task::JoinHandle<()>);
    impl Drop for AbortOnDrop {
        fn drop(&mut self) {
            self.0.abort();
        }
    }

    // Channel for inbound packets to be written to TUN.
    let (inbound_tx, mut inbound_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(1024);

    // Clone transport for the download task (uses Arc internally, cheap clone).
    let transport_rx = transport.clone();

    // Spawn the server→TUN (download) task — runs independently for full duplex.
    let _inbound_task = AbortOnDrop(tokio::spawn(async move {
        let codec_in = FrameCodec::new(header_key);
        let mut replay = ReplayWindow::new();

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
                                    counters_in.bytes_in.fetch_add(ip_pkt.len() as u64, Relaxed);
                                    if inbound_tx.send(ip_pkt).await.is_err() { break; }
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
        // Dropping `inbound_tx` here tells the main loop the server is gone.
    }));

    // Main TUN→server (upload) loop, interleaved with writing inbound packets.
    let mut rng = rand::rngs::StdRng::from_entropy();
    let mut tun_read_errors: u32 = 0;

    loop {
        tokio::select! {
            // Write inbound packets to TUN when available.
            inbound = inbound_rx.recv() => {
                let Some(ip_pkt) = inbound else {
                    tracing::warn!("connection to server lost");
                    break;
                };
                if let Err(e) = tun.write_packet(&ip_pkt).await {
                    tracing::warn!("tun write error: {}", e);
                    break;
                }
            }
            // Read outbound packets from TUN and send to server.
            tun_result = tun.read_packet() => {
                match tun_result {
                    Ok(pkt) if !pkt.is_empty() => {
                        tun_read_errors = 0;
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
                        counters_out.bytes_out.fetch_add(len, Relaxed);
                        *seq = seq.wrapping_add(1);
                    }
                    Ok(_) => {
                        // Empty packet — small yield to avoid busy loop.
                        tokio::task::yield_now().await;
                    }
                    Err(e) => {
                        tun_read_errors += 1;
                        tracing::warn!("tun read error: {}", e);
                        if tun_read_errors >= 20 {
                            // The adapter is gone; end the session so we can recover.
                            return Err(anyhow::anyhow!("network adapter stopped responding"));
                        }
                        tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;
                    }
                }
            }
        }
    }

    Ok(())
}


