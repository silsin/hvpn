//! Connection supervisor: owns the connect → run → reconnect lifecycle.
//!
//! The daemon used to make a single connection attempt at start-up and exit
//! when it dropped. The supervisor instead:
//!
//! * connects (and reconnects with exponential backoff) while the user wants
//!   to be connected,
//! * only touches the system routing table *after* the server connection is
//!   established, so a failed attempt never blackholes the user's internet,
//! * reports a human-readable phase and error through [`AppState`] so the tray
//!   can show "Reconnecting (attempt 3)…" instead of a mystery colour,
//! * publishes live traffic statistics (bytes, speed, uptime, latency).

use anyhow::Result;
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};

use hvpn_common::{find_profile, load_active_profile, load_profiles, Config, ConnectionProfile};
use hvpn_core::FrameCodec;
use hvpn_crypto::perform_handshake_client;
use hvpn_obfs::ObfsEngine;
use hvpn_transport::{CertPin, Transport, TransportConfig, WebSocketTransport};
#[cfg(not(any(target_os = "windows", target_os = "linux")))]
use hvpn_tun::StubTun;
use hvpn_tun::TunDevice;

use crate::{tunnel_loop, AppState, Phase};

/// Address of the server end of the tunnel (answers ICMP echo for latency).
const TUNNEL_GATEWAY: &str = "10.8.0.1";
/// How long to wait for the transport (TCP + TLS + WebSocket upgrade).
const CONNECT_TIMEOUT: Duration = Duration::from_secs(15);
/// A session that lasted this long counts as "was working": backoff resets.
const STABLE_AFTER: Duration = Duration::from_secs(10);
const BACKOFF_SECS: [u64; 6] = [1, 2, 4, 8, 15, 30];

// ── Errors ────────────────────────────────────────────────────────────────────

/// Why a connection attempt failed, in words a user can act on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionError {
    pub message: String,
    /// `false` when retrying automatically cannot help (bad link, no admin
    /// rights, certificate mismatch…).
    pub retry: bool,
}

impl SessionError {
    fn fatal(message: impl Into<String>) -> Self {
        Self { message: message.into(), retry: false }
    }
    fn transient(message: impl Into<String>) -> Self {
        Self { message: message.into(), retry: true }
    }
}

/// Translate a low-level connect error into a [`SessionError`].
pub fn friendly_connect_error(raw: &str) -> SessionError {
    let l = raw.to_ascii_lowercase();
    let has = |needles: &[&str]| needles.iter().any(|n| l.contains(n));

    if has(&["certificate", "unknownissuer", "invalid peer", "bad_certificate"]) {
        return SessionError::fatal(
            "The server's security certificate didn't match. Your link may be out of date, \
             or someone may be intercepting the connection.",
        );
    }
    if has(&["403", "401", "forbidden", "unauthorized"]) {
        return SessionError::fatal(
            "The server rejected this connection. Check that your link is current.",
        );
    }
    if has(&["timed out", "timeout", "os error 10060", "os error 110"]) {
        return SessionError::transient("The server didn't respond in time.");
    }
    if has(&["refused", "os error 10061", "os error 111"]) {
        return SessionError::transient("The server refused the connection. It may be offline.");
    }
    if has(&[
        "dns", "resolve", "no such host", "failed to lookup", "name or service",
        "os error 11001", "nodename nor servname",
    ]) {
        return SessionError::transient(
            "Couldn't find the server. Check your internet connection and the server address.",
        );
    }
    if has(&["unreachable", "os error 10051", "os error 10065", "os error 101", "os error 113"]) {
        return SessionError::transient("No internet connection.");
    }
    let detail: String = raw.chars().take(140).collect();
    SessionError::transient(format!("Couldn't connect: {detail}"))
}

/// Delay before reconnect attempt number `attempt` (1-based).
pub fn backoff_delay(attempt: u32) -> Duration {
    let idx = (attempt.saturating_sub(1) as usize).min(BACKOFF_SECS.len() - 1);
    Duration::from_secs(BACKOFF_SECS[idx])
}

/// Extract the round-trip time (ms) from `ping` output in any language.
///
/// Looks for the first number written as `=12ms`, `<1ms`, `=12.3 ms`, which is
/// how both Windows and Linux ping print the per-reply time.
pub fn parse_ping_ms(text: &str) -> Option<u64> {
    let bytes = text.as_bytes();
    let mut i = 0;
    while i + 1 < bytes.len() {
        if (bytes[i] == b'=' || bytes[i] == b'<') && i + 1 < bytes.len() {
            let mut j = i + 1;
            while j < bytes.len() && bytes[j] == b' ' {
                j += 1;
            }
            let start = j;
            while j < bytes.len() && (bytes[j].is_ascii_digit() || bytes[j] == b'.') {
                j += 1;
            }
            if j > start {
                let num = &text[start..j];
                let mut k = j;
                while k < bytes.len() && bytes[k] == b' ' {
                    k += 1;
                }
                if text[k..].to_ascii_lowercase().starts_with("ms") {
                    if let Ok(v) = num.parse::<f64>() {
                        return Some(v.round().max(1.0) as u64);
                    }
                }
            }
        }
        i += 1;
    }
    None
}

fn decode_hex32(s: &str) -> Option<[u8; 32]> {
    if s.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, chunk) in out.iter_mut().enumerate() {
        *chunk = u8::from_str_radix(s.get(i * 2..i * 2 + 2)?, 16).ok()?;
    }
    Some(out)
}

// ── Configuration ─────────────────────────────────────────────────────────────

fn default_config_path(fallback: &str) -> String {
    #[cfg(target_os = "windows")]
    {
        std::env::var("APPDATA")
            .map(|a| format!(r"{}\HVPN\client.toml", a))
            .unwrap_or_else(|_| fallback.to_string())
    }
    #[cfg(not(target_os = "windows"))]
    {
        std::env::var("HOME")
            .map(|h| format!("{}/.config/hvpn/client.toml", h))
            .unwrap_or_else(|_| fallback.to_string())
    }
}

/// A minimal client config for a saved profile (used when no config file exists).
pub fn config_from_profile(p: &ConnectionProfile) -> Config {
    Config {
        server_address: p.server.clone(),
        server_port: p.port,
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
        // A pinned profile always means TLS.
        use_tls: !p.cert_sha256.is_empty(),
        accept_invalid_certs: true,
    }
}

/// Pick the configuration + profile to connect with.
///
/// * a profile the user selected (tray / `--link`) wins for server + port;
/// * otherwise the config file is used as before;
/// * with no config file, the first saved profile is used.
fn resolve_config(
    config_path: &str,
    active: Option<&str>,
) -> Result<(Config, Option<ConnectionProfile>), String> {
    let resolved = if std::path::Path::new(config_path).exists() {
        config_path.to_string()
    } else {
        default_config_path(config_path)
    };
    let profiles = load_profiles();
    let selected = active.and_then(|n| find_profile(&profiles, n)).cloned();
    let file_cfg = Config::load_and_validate(&resolved).ok();

    match (file_cfg, selected) {
        (Some(mut cfg), Some(p)) => {
            cfg.server_address = p.server.clone();
            cfg.server_port = p.port;
            if !p.cert_sha256.is_empty() {
                cfg.use_tls = true;
            }
            Ok((cfg, Some(p)))
        }
        (Some(cfg), None) => {
            let p = profiles.iter().find(|p| p.server == cfg.server_address).cloned();
            Ok((cfg, p))
        }
        (None, Some(p)) => Ok((config_from_profile(&p), Some(p))),
        (None, None) => match profiles.first() {
            Some(p) => Ok((config_from_profile(p), Some(p.clone()))),
            None => Err("No server set up yet. Add one with a link from your server.".to_string()),
        },
    }
}

// ── State helpers ─────────────────────────────────────────────────────────────

fn with_state<R>(state: &Arc<Mutex<AppState>>, f: impl FnOnce(&mut AppState) -> R) -> R {
    let mut guard = state.lock().unwrap_or_else(|p| p.into_inner());
    f(&mut guard)
}

fn set_idle(state: &Arc<Mutex<AppState>>) {
    with_state(state, |s| {
        s.phase = Phase::Idle;
        s.connected = false;
        s.connected_at = None;
        s.retry_at = None;
        s.attempt = 0;
        s.speed_in = 0;
        s.speed_out = 0;
        s.rtt_ms = 0;
    });
}

fn set_connecting(state: &Arc<Mutex<AppState>>, label: &str, attempt: u32) {
    with_state(state, |s| {
        s.phase = if s.last_error.is_some() { Phase::Reconnecting } else { Phase::Connecting };
        s.connected = false;
        s.connected_at = None;
        s.retry_at = None;
        s.attempt = attempt;
        s.server = label.to_string();
    });
}

fn mark_connected(state: &Arc<Mutex<AppState>>) {
    with_state(state, |s| {
        s.phase = Phase::Connected;
        s.connected = true;
        s.connected_at = Some(Instant::now());
        s.last_error = None;
        s.retry_at = None;
        s.attempt = 0;
        s.counters.bytes_in.store(0, Ordering::Relaxed);
        s.counters.bytes_out.store(0, Ordering::Relaxed);
        s.bytes_in = 0;
        s.bytes_out = 0;
    });
}

fn mark_disconnected(state: &Arc<Mutex<AppState>>) {
    with_state(state, |s| {
        s.connected = false;
        s.connected_at = None;
        s.speed_in = 0;
        s.speed_out = 0;
        s.rtt_ms = 0;
    });
}

/// Give up (no more automatic retries) and tell the user why.
fn fail(state: &Arc<Mutex<AppState>>, message: String) {
    warn!("connection failed: {}", message);
    with_state(state, |s| {
        s.phase = Phase::Failed;
        s.connected = false;
        s.want_connected = false;
        s.connected_at = None;
        s.retry_at = None;
        s.attempt = 0;
        s.last_error = Some(message);
    });
}

// ── Entry point ───────────────────────────────────────────────────────────────

/// Core client loop shared by the interactive and Windows-service entry points.
///
/// Runs the control socket, then keeps the tunnel up (reconnecting as needed)
/// until `shutdown` is cancelled.
pub async fn run_client(config_path: &str, shutdown: CancellationToken) -> Result<()> {
    let state = Arc::new(Mutex::new(AppState::new()));
    with_state(&state, |s| {
        s.active_profile = load_active_profile();
        s.want_connected = true;
    });

    // Control socket for the tray / hvpn-ctl.
    {
        let state = Arc::clone(&state);
        tokio::spawn(async move {
            crate::control::listen_control_socket(state).await;
        });
    }
    tokio::spawn(stats_task(Arc::clone(&state), shutdown.clone()));

    // Nothing to connect to yet?
    let active = with_state(&state, |s| s.active_profile.clone());
    if let Err(msg) = resolve_config(config_path, active.as_deref()) {
        if cfg!(target_os = "windows") {
            // The tray app will add a profile and ask us to connect.
            info!("{msg} Waiting for the tray app.");
            fail(&state, msg);
        } else {
            eprintln!(
                "[hvpn-client] {msg} Run: hvpn-client --config <path> or hvpn-client --link <link>"
            );
            return Err(anyhow::anyhow!("no configuration available"));
        }
    }

    supervise(config_path, &state, &shutdown).await;
    Ok(())
}

async fn supervise(config_path: &str, state: &Arc<Mutex<AppState>>, shutdown: &CancellationToken) {
    let wake = with_state(state, |s| s.wake.clone());
    let mut attempt: u32 = 0;

    loop {
        if shutdown.is_cancelled() {
            break;
        }

        // Wait here while the user wants to be disconnected.
        if !with_state(state, |s| s.want_connected) {
            if !matches!(with_state(state, |s| s.phase), Phase::Failed) {
                set_idle(state);
            }
            tokio::select! {
                _ = wake.notified() => {}
                _ = shutdown.cancelled() => break,
            }
            attempt = 0;
            continue;
        }

        let active = with_state(state, |s| s.active_profile.clone());
        let (cfg, profile) = match resolve_config(config_path, active.as_deref()) {
            Ok(x) => x,
            Err(msg) => {
                fail(state, msg);
                continue;
            }
        };
        let label = profile
            .as_ref()
            .map(|p| p.display_name())
            .unwrap_or_else(|| cfg.server_address.clone());

        attempt += 1;
        set_connecting(state, &label, attempt);
        info!(server = %cfg.server_address, port = cfg.server_port, attempt, "connecting");

        let cancel = shutdown.child_token();
        with_state(state, |s| s.session_cancel = Some(cancel.clone()));
        // A disconnect may have arrived between the check above and now.
        if !with_state(state, |s| s.want_connected) {
            cancel.cancel();
        }

        let started = Instant::now();
        let outcome = run_session(&cfg, profile.as_ref(), state, &cancel).await;
        with_state(state, |s| s.session_cancel = None);

        if shutdown.is_cancelled() {
            break;
        }

        match outcome {
            // User pressed Disconnect, or switched server: no error, no backoff.
            Ok(SessionEnd::Cancelled) => {
                attempt = 0;
                continue;
            }
            Ok(SessionEnd::Lost(reason)) => {
                if started.elapsed() >= STABLE_AFTER {
                    attempt = 0;
                }
                with_state(state, |s| s.last_error = Some(reason));
            }
            Err(e) if !e.retry => {
                fail(state, e.message);
                attempt = 0;
                continue;
            }
            Err(e) => {
                warn!("attempt {} failed: {}", attempt, e.message);
                with_state(state, |s| s.last_error = Some(e.message));
            }
        }

        // Back off, but let "Connect" (retry now) or shutdown interrupt.
        let delay = backoff_delay(attempt.max(1));
        with_state(state, |s| {
            s.phase = Phase::Reconnecting;
            s.retry_at = Some(Instant::now() + delay);
        });
        tokio::select! {
            _ = tokio::time::sleep(delay) => {}
            _ = wake.notified() => { attempt = 0; }
            _ = shutdown.cancelled() => break,
        }
    }
    set_idle(state);
}

// ── One connection ────────────────────────────────────────────────────────────

enum SessionEnd {
    /// Stopped on purpose (disconnect, server switch, shutdown).
    Cancelled,
    /// Dropped after being established.
    Lost(String),
}

async fn run_session(
    cfg: &Config,
    profile: Option<&ConnectionProfile>,
    state: &Arc<Mutex<AppState>>,
    cancel: &CancellationToken,
) -> Result<SessionEnd, SessionError> {
    // 1. Keys and credentials from the saved profile.
    let profile = profile
        .cloned()
        .or_else(|| load_profiles().into_iter().find(|p| p.server == cfg.server_address))
        .ok_or_else(|| {
            SessionError::fatal("No saved key for this server. Import your link again.")
        })?;
    let server_pubkey = decode_hex32(&profile.pubkey).ok_or_else(|| {
        SessionError::fatal("The saved server key is invalid. Import your link again.")
    })?;
    let (ephemeral_pub, session_keys) = perform_handshake_client(&server_pubkey)
        .map_err(|e| SessionError::fatal(format!("Security handshake failed: {e}")))?;

    // 2. Transport configuration.
    let mut tc = TransportConfig::new(cfg.server_address.clone(), cfg.server_port, "/hvpn");
    tc.danger_accept_invalid_certs = cfg.accept_invalid_certs;
    tc.auth_secret = decode_hex32(&profile.auth_secret);
    let mut use_tls = cfg.use_tls;
    if let Some(fp) = decode_hex32(&profile.cert_sha256) {
        // Pinned: only this exact server certificate is accepted.
        tc.cert_pin = Some(CertPin { sha256_fingerprints: vec![fp] });
        tc.danger_accept_invalid_certs = false;
        use_tls = true;
    } else if use_tls && tc.danger_accept_invalid_certs {
        warn!("server certificate is NOT pinned; ask the server owner for a newer link");
    }

    // 3. Connect the transport (before touching routes or DNS).
    let connect = async {
        if use_tls {
            WebSocketTransport::connect(&tc).await
        } else {
            WebSocketTransport::connect_plain(&tc).await
        }
    };
    let transport = tokio::select! {
        _ = cancel.cancelled() => return Ok(SessionEnd::Cancelled),
        r = tokio::time::timeout(CONNECT_TIMEOUT, connect) => match r {
            Ok(Ok(t)) => t,
            Ok(Err(e)) => return Err(friendly_connect_error(&e.to_string())),
            Err(_) => return Err(SessionError::transient("The server didn't respond in time.")),
        }
    };
    info!("transport connected");
    if let Err(e) = transport.send(ephemeral_pub.to_vec()).await {
        return Err(SessionError::transient(format!("Lost connection while connecting: {e}")));
    }

    // 4. Network adapter + routes (only now that the server is reachable).
    let mut tun = match open_tun(cfg).await {
        Ok(t) => t,
        Err(msg) => {
            let _ = transport.close().await;
            return Err(SessionError::fatal(msg));
        }
    };

    // 5. Up.
    mark_connected(state);
    info!(server = %cfg.server_address, "tunnel up");
    let monitor = cancel.child_token();
    tokio::spawn(rtt_monitor(Arc::clone(state), monitor.clone()));

    let codec = FrameCodec::new(session_keys.header_key);
    let mut obfs = ObfsEngine::new();
    let mut seq: u64 = 0;
    let result = tokio::select! {
        _ = cancel.cancelled() => None,
        r = tunnel_loop(
            &mut tun,
            Some(&transport),
            &codec,
            &mut obfs,
            &mut seq,
            &session_keys,
            Arc::clone(state),
        ) => Some(r),
    };

    // 6. Tear down so routes/adapter don't linger while disconnected.
    monitor.cancel();
    let _ = transport.close().await;
    drop(tun);
    cleanup_routes(cfg);
    mark_disconnected(state);

    Ok(match result {
        None => SessionEnd::Cancelled,
        Some(Ok(())) => SessionEnd::Lost("The connection to the server was lost.".to_string()),
        Some(Err(e)) => SessionEnd::Lost(format!("Connection error: {e}")),
    })
}

// ── Network adapter ───────────────────────────────────────────────────────────

#[cfg(target_os = "windows")]
async fn open_tun(cfg: &Config) -> Result<Box<dyn TunDevice>, String> {
    use hvpn_tun::WinTunDevice;

    let dev = WinTunDevice::open("hvpn0", &format!("{}/24", cfg.tun_ip), &cfg.server_address)
        .await
        .map_err(|e| {
            warn!("WinTun open failed: {}", e);
            "Couldn't create the network adapter. Run HVPN as administrator.".to_string()
        })?;
    info!("WinTun device opened successfully");
    if let Err(e) = dev.set_mtu(1380) {
        warn!("failed to set TUN MTU: {}", e);
    }
    // Wait for the adapter to fully initialise before touching the routing table.
    tokio::time::sleep(Duration::from_millis(500)).await;

    // Real gateway BEFORE installing the VPN default route.
    let real_gateway = hvpn_tun::get_default_gateway().ok();
    info!("real gateway detected: {:?}", real_gateway);

    // FIRST: keep the server itself reachable outside the tunnel.
    if let Some(ref gateway) = real_gateway {
        let _ = std::process::Command::new("route")
            .args(["delete", &cfg.server_address])
            .output();
        match std::process::Command::new("route")
            .args(["add", &cfg.server_address, "mask", "255.255.255.255", gateway, "metric", "1"])
            .output()
        {
            Ok(o) if o.status.success() => info!("server exclusion route set via {}", gateway),
            Ok(o) => warn!("route add server exclusion failed: {}", String::from_utf8_lossy(&o.stdout)),
            Err(e) => warn!("route add server exclusion error: {}", e),
        }
    }

    // SECOND: send everything else through the tunnel.
    match hvpn_tun::set_default_route("hvpn0", TUNNEL_GATEWAY) {
        Ok(_) => info!("default route set through VPN tunnel OK"),
        Err(e) => warn!("set_default_route failed: {}", e),
    }
    if !cfg.dns_servers.is_empty() {
        let _ = hvpn_tun::set_dns("hvpn0", &cfg.dns_servers);
    }
    Ok(Box::new(dev))
}

#[cfg(target_os = "linux")]
async fn open_tun(cfg: &Config) -> Result<Box<dyn TunDevice>, String> {
    use hvpn_tun::LinuxTun;
    let dev = LinuxTun::open("hvpn0", &format!("{}/24", cfg.tun_ip), &cfg.server_address)
        .await
        .map_err(|e| {
            warn!("TUN open failed: {}", e);
            "Couldn't create the network interface. Run as root (or grant CAP_NET_ADMIN).".to_string()
        })?;
    info!("Linux TUN device opened successfully");
    Ok(Box::new(dev))
}

#[cfg(not(any(target_os = "windows", target_os = "linux")))]
async fn open_tun(_cfg: &Config) -> Result<Box<dyn TunDevice>, String> {
    Ok(Box::new(StubTun::new()))
}

#[cfg(target_os = "windows")]
fn cleanup_routes(cfg: &Config) {
    let _ = std::process::Command::new("route")
        .args(["delete", &cfg.server_address])
        .output();
}

#[cfg(not(target_os = "windows"))]
fn cleanup_routes(_cfg: &Config) {}

// ── Background monitors ───────────────────────────────────────────────────────

/// Once a second: fold the packet counters into totals and smoothed speeds.
async fn stats_task(state: Arc<Mutex<AppState>>, shutdown: CancellationToken) {
    let mut ticker = tokio::time::interval(Duration::from_secs(1));
    let (mut last_in, mut last_out) = (0u64, 0u64);
    loop {
        tokio::select! {
            _ = ticker.tick() => {}
            _ = shutdown.cancelled() => return,
        }
        with_state(&state, |s| {
            let total_in = s.counters.bytes_in.load(Ordering::Relaxed);
            let total_out = s.counters.bytes_out.load(Ordering::Relaxed);
            // Counters reset to 0 on each new session.
            let d_in = total_in.saturating_sub(if total_in < last_in { 0 } else { last_in });
            let d_out = total_out.saturating_sub(if total_out < last_out { 0 } else { last_out });
            last_in = total_in;
            last_out = total_out;
            s.bytes_in = total_in;
            s.bytes_out = total_out;
            if s.connected {
                // Light smoothing so the number doesn't flicker.
                s.speed_in = (s.speed_in * 6 + d_in * 4) / 10;
                s.speed_out = (s.speed_out * 6 + d_out * 4) / 10;
            } else {
                s.speed_in = 0;
                s.speed_out = 0;
            }
        });
    }
}

/// Measure latency *through the tunnel* by pinging the server's tunnel address.
/// This looks like ordinary tunnelled traffic and reflects what the user feels.
async fn rtt_monitor(state: Arc<Mutex<AppState>>, cancel: CancellationToken) {
    // Give the routes a moment to settle.
    tokio::select! {
        _ = tokio::time::sleep(Duration::from_secs(2)) => {}
        _ = cancel.cancelled() => return,
    }
    loop {
        let ms = tokio::task::spawn_blocking(ping_gateway).await.ok().flatten();
        if let Some(ms) = ms {
            with_state(&state, |s| {
                if s.connected {
                    s.rtt_ms = ms;
                }
            });
        }
        tokio::select! {
            _ = tokio::time::sleep(Duration::from_secs(5)) => {}
            _ = cancel.cancelled() => return,
        }
    }
}

fn ping_gateway() -> Option<u64> {
    let mut cmd = std::process::Command::new("ping");
    #[cfg(target_os = "windows")]
    {
        use std::os::windows::process::CommandExt;
        cmd.args(["-n", "1", "-w", "2000", TUNNEL_GATEWAY]);
        cmd.creation_flags(0x0800_0000); // CREATE_NO_WINDOW
    }
    #[cfg(not(target_os = "windows"))]
    {
        cmd.args(["-c", "1", "-W", "2", TUNNEL_GATEWAY]);
    }
    let out = cmd.output().ok()?;
    parse_ping_ms(&String::from_utf8_lossy(&out.stdout))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ping_parsing_handles_windows_linux_and_other_languages() {
        assert_eq!(parse_ping_ms("Reply from 10.8.0.1: bytes=32 time=12ms TTL=64"), Some(12));
        assert_eq!(parse_ping_ms("Reply from 10.8.0.1: bytes=32 time<1ms TTL=64"), Some(1));
        assert_eq!(parse_ping_ms("64 bytes from 10.8.0.1: icmp_seq=1 ttl=64 time=12.6 ms"), Some(13));
        assert_eq!(parse_ping_ms("Antwort von 10.8.0.1: Bytes=32 Zeit=48ms TTL=64"), Some(48));
        assert_eq!(parse_ping_ms("Request timed out."), None);
        assert_eq!(parse_ping_ms("Destination host unreachable."), None);
        assert_eq!(parse_ping_ms(""), None);
    }

    #[test]
    fn backoff_grows_then_caps() {
        let secs: Vec<u64> = (1..=9).map(|n| backoff_delay(n).as_secs()).collect();
        assert_eq!(secs, vec![1, 2, 4, 8, 15, 30, 30, 30, 30]);
        assert_eq!(backoff_delay(0).as_secs(), 1);
    }

    #[test]
    fn errors_are_translated_and_classified() {
        let e = friendly_connect_error("HTTP error: 403 Forbidden");
        assert!(!e.retry && e.message.contains("rejected"));
        let e = friendly_connect_error("invalid peer certificate: UnknownIssuer");
        assert!(!e.retry && e.message.contains("certificate"));
        let e = friendly_connect_error("IO error: Connection refused (os error 111)");
        assert!(e.retry && e.message.contains("offline"));
        let e = friendly_connect_error("failed to lookup address information");
        assert!(e.retry && e.message.contains("find the server"));
        let e = friendly_connect_error("Network is unreachable (os error 101)");
        assert!(e.retry && e.message.contains("internet"));
        let e = friendly_connect_error("something odd");
        assert!(e.retry && e.message.contains("something odd"));
    }

    /// Wait until `cond` holds for the shared state (or fail after `secs`).
    async fn wait_for(state: &Arc<Mutex<AppState>>, secs: u64, what: &str, cond: impl Fn(&AppState) -> bool) {
        let deadline = Instant::now() + Duration::from_secs(secs);
        loop {
            if with_state(state, |s| cond(s)) {
                return;
            }
            assert!(Instant::now() < deadline, "timed out waiting for: {what}");
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }

    /// End-to-end behaviour of the supervisor against a closed port, using a
    /// throw-away profile folder (never touches the real one). No adapter is
    /// created because the transport fails first, so no admin rights needed.
    #[tokio::test]
    async fn supervisor_reports_errors_retries_and_obeys_disconnect() {
        let dir = std::env::temp_dir().join(format!("hvpn_supervisor_test_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::env::set_var("APPDATA", &dir);
        std::env::set_var("HOME", &dir);

        // A free local port that nothing listens on.
        let port = {
            let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            l.local_addr().unwrap().port()
        };
        let good = ConnectionProfile {
            server: "127.0.0.1".to_string(),
            port,
            pubkey: "ab".repeat(32),
            version: 1,
            auth_secret: "cd".repeat(32),
            name: Some("Test".to_string()),
            cert_sha256: String::new(),
        };
        hvpn_common::save_profiles(&[good.clone()]).unwrap();

        let state = Arc::new(Mutex::new(AppState::new()));
        with_state(&state, |s| s.want_connected = true);
        let shutdown = CancellationToken::new();
        let task = {
            let (state, shutdown) = (Arc::clone(&state), shutdown.clone());
            tokio::spawn(async move { supervise("does-not-exist.toml", &state, &shutdown).await })
        };

        // 1. Server unreachable: friendly message, automatic retry scheduled.
        wait_for(&state, 8, "reconnecting with an error", |s| {
            s.phase == Phase::Reconnecting && s.last_error.is_some() && s.retry_at.is_some()
        })
        .await;
        let msg = with_state(&state, |s| s.last_error.clone().unwrap());
        assert!(msg.contains("refused") || msg.contains("respond") || msg.contains("Couldn't"), "got: {msg}");
        assert!(!with_state(&state, |s| s.connected));

        // 2. A second attempt actually happens (backoff elapsed).
        wait_for(&state, 8, "attempt 2", |s| s.attempt >= 2).await;

        // 3. Disconnect stops retrying and goes idle.
        let resp = crate::dispatch(&serde_json::json!({"cmd": "disconnect"}), &state);
        assert_eq!(resp["ok"], true);
        wait_for(&state, 5, "idle after disconnect", |s| s.phase == Phase::Idle && !s.want_connected).await;
        let status = crate::dispatch(&serde_json::json!({"cmd": "status"}), &state);
        assert_eq!(status["status"]["phase"], "idle");
        assert_eq!(status["status"]["connected"], false);

        // 4. Connect again retries immediately.
        crate::dispatch(&serde_json::json!({"cmd": "connect", "profile": "Test"}), &state);
        wait_for(&state, 8, "reconnecting again", |s| s.want_connected && s.phase != Phase::Idle).await;

        // 5. A profile with a corrupt key is a fatal error: no endless retries.
        let mut bad = good.clone();
        bad.pubkey = "zz".repeat(32);
        bad.name = Some("Broken".to_string());
        bad.server = "127.0.0.2".to_string();
        hvpn_common::save_profiles(&[good, bad]).unwrap();
        crate::dispatch(&serde_json::json!({"cmd": "connect", "profile": "Broken"}), &state);
        wait_for(&state, 8, "fatal failure", |s| s.phase == Phase::Failed).await;
        with_state(&state, |s| {
            assert!(!s.want_connected, "should stop retrying after a fatal error");
            assert!(s.last_error.as_deref().unwrap().contains("key"));
        });

        shutdown.cancel();
        tokio::time::timeout(Duration::from_secs(5), task).await.expect("supervisor should stop").unwrap();
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn hex32_decoding() {
        assert_eq!(decode_hex32(&"ab".repeat(32)), Some([0xab; 32]));
        assert_eq!(decode_hex32("abc"), None);
        assert_eq!(decode_hex32(&"zz".repeat(32)), None);
    }
}
