use anyhow::{Context, Result};
use clap::Parser;
use dashmap::DashMap;
use futures_util::{SinkExt, StreamExt};
use std::path::PathBuf;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::io::{AsyncRead, AsyncWrite};
use tracing::{info, warn};

use hvpn_common::{AuditEvent, AuditLogger, Config};
use hvpn_core::FrameCodec;
use hvpn_crypto::{generate_probe_token, perform_handshake_server, decrypt_packet, RatchetState};
use hvpn_obfs::ObfsEngine;

mod nat;

/// HVPN server — accepts tunnelled connections from HVPN clients.
#[derive(Parser, Debug)]
#[command(name = "hvpn-server", version, about)]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,
    /// Path to the TOML configuration file.
    #[arg(long, default_value = "config.toml", global = true)]
    config: PathBuf,
}

#[derive(clap::Subcommand, Debug)]
enum Command {
    /// Generate server config, print QR code connection string, and exit.
    Setup,
}

/// Realistic nginx decoy page served to unauthenticated probes.
#[allow(dead_code)]
const DECOY_PAGE: &[u8] = b"HTTP/1.1 200 OK\r\n\
Content-Type: text/html\r\n\
Connection: close\r\n\
\r\n\
<!DOCTYPE html>\n\
<html lang=\"en\">\n\
<head><meta charset=\"UTF-8\"><title>Welcome to Nginx</title></head>\n\
<body>\n\
<h1>Welcome to nginx!</h1>\n\
<p>If you see this page, the nginx web server is successfully installed and working. Further configuration is required.</p>\n\
<p>For online documentation and support please refer to <a href=\"http://nginx.org/\">nginx.org</a>.</p>\n\
<p><em>Thank you for using nginx.</em></p>\n\
</body>\n\
</html>\r\n";

/// Shared server state passed to every connection task.
struct ServerState {
    server_secret: [u8; 32],
    mac_key: [u8; 32],
    /// Optional auth secret loaded from `/etc/hvpn/server.auth`.
    /// When `None`, the server logs a warning and rejects all tokens.
    auth_secret: Option<[u8; 32]>,
    /// Replay cache: maps 40-byte token → UNIX timestamp of first use.
    nonce_cache: Arc<DashMap<[u8; 40], u64>>,
    /// Present only on Linux when `config.nat_enabled = true`.
    #[cfg(target_os = "linux")]
    nat_router: Option<Arc<nat::NatRouter>>,
    /// Shared TUN device for NAT forwarding (Linux only).
    #[cfg(target_os = "linux")]
    shared_tun: Option<Arc<tokio::sync::Mutex<hvpn_tun::LinuxTun>>>,
}

// ── TLS cert helpers ──────────────────────────────────────────────────────────

/// Ensure `/etc/hvpn/server.pem` and `/etc/hvpn/server.key` exist.
/// If they are missing, generate a self-signed ECDSA cert using rcgen and save them.
/// Returns `(cert_pem, key_pem)` on success.
fn ensure_tls_cert(cert_path: &str, key_path: &str) -> Result<(Vec<u8>, Vec<u8>)> {
    let cert_exists = std::path::Path::new(cert_path).exists();
    let key_exists = std::path::Path::new(key_path).exists();

    if cert_exists && key_exists {
        let cert_pem = std::fs::read(cert_path)
            .with_context(|| format!("reading {}", cert_path))?;
        let key_pem = std::fs::read(key_path)
            .with_context(|| format!("reading {}", key_path))?;
        info!("TLS cert loaded from {} / {}", cert_path, key_path);
        return Ok((cert_pem, key_pem));
    }

    // Generate self-signed cert with ECDSA P-256 (equivalent security to RSA 2048+).
    info!("Generating self-signed TLS certificate (ECDSA P-256)");
    let key_pair = rcgen::KeyPair::generate()
        .context("rcgen: failed to generate key pair")?;
    let mut params = rcgen::CertificateParams::new(
        vec!["localhost".to_string(), "hvpn-server".to_string()]
    ).context("rcgen: failed to create cert params")?;
    let cert = params.self_signed(&key_pair)
        .context("rcgen: failed to self-sign certificate")?;

    let cert_pem = cert.pem().into_bytes();
    let key_pem = key_pair.serialize_pem().into_bytes();

    // Create parent directory if needed.
    if let Some(parent) = std::path::Path::new(cert_path).parent() {
        if !parent.exists() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("creating {}", parent.display()))?;
        }
    }

    std::fs::write(cert_path, &cert_pem)
        .with_context(|| format!("writing {}", cert_path))?;
    std::fs::write(key_path, &key_pem)
        .with_context(|| format!("writing {}", key_path))?;

    info!("Self-signed TLS cert saved to {} / {}", cert_path, key_path);
    Ok((cert_pem, key_pem))
}

/// Build a `rustls::ServerConfig` from PEM cert and key bytes.
fn build_rustls_server_config(cert_pem: &[u8], key_pem: &[u8]) -> Result<Arc<rustls::ServerConfig>> {
    use rustls::pki_types::PrivateKeyDer;

    let certs: Vec<rustls::pki_types::CertificateDer<'static>> = {
        let mut cursor = std::io::Cursor::new(cert_pem);
        rustls_pemfile::certs(&mut cursor)
            .collect::<std::result::Result<_, _>>()
            .context("parsing TLS cert PEM")?
    };

    let key = {
        let mut cursor = std::io::Cursor::new(key_pem);
        rustls_pemfile::private_key(&mut cursor)
            .context("parsing TLS key PEM")?
            .context("no private key found in PEM")?
    };

    // Convert to the owned variant required by ServerConfig.
    let key_owned: PrivateKeyDer<'static> = match key {
        PrivateKeyDer::Pkcs1(k) => PrivateKeyDer::Pkcs1(k.clone_key()),
        PrivateKeyDer::Pkcs8(k) => PrivateKeyDer::Pkcs8(k.clone_key()),
        PrivateKeyDer::Sec1(k) => PrivateKeyDer::Sec1(k.clone_key()),
        other => other,
    };

    let server_cfg = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key_owned)
        .context("building rustls ServerConfig")?;

    Ok(Arc::new(server_cfg))
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive("hvpn_server=info".parse()?),
        )
        .init();

    let cli = Cli::parse();

    if let Some(Command::Setup) = cli.command {
        return run_setup();
    }

    let cfg = Config::load_and_validate(cli.config.to_str().unwrap_or("config.toml"))
        .unwrap_or_else(|e| {
            eprintln!("[hvpn-server] configuration error:\n{}", e);
            std::process::exit(1);
        });

    let bind_addr = format!("0.0.0.0:{}", cfg.server_port);
    info!(addr = %bind_addr, "HVPN server listening");

    let listener = TcpListener::bind(&bind_addr)
        .await
        .with_context(|| format!("binding to {}", bind_addr))?;

    // Server static X25519 key — load from /etc/hvpn/server_x25519.key if present.
    let server_secret_bytes: [u8; 32] = std::fs::read_to_string("/etc/hvpn/server_x25519.key")
        .ok()
        .and_then(|s| {
            let hex = s.trim();
            if hex.len() == 64 {
                let bytes: Vec<u8> = (0..hex.len())
                    .step_by(2)
                    .filter_map(|i| u8::from_str_radix(&hex[i..i+2], 16).ok())
                    .collect();
                if bytes.len() == 32 {
                    let mut arr = [0u8; 32];
                    arr.copy_from_slice(&bytes);
                    Some(arr)
                } else { None }
            } else { None }
        })
        .unwrap_or_else(|| {
            tracing::warn!("X25519 private key not found at /etc/hvpn/server_x25519.key — using zeroed key (run 'hvpn-server setup' to generate)");
            [0u8; 32]
        });

    // Derive a stable mac_key from the server secret for probe-token verification.
    let mac_key: [u8; 32] = {
        let dummy_ephemeral = [0xFFu8; 32];
        match perform_handshake_server(&dummy_ephemeral, &server_secret_bytes) {
            Ok(k) => k.mac_key,
            Err(_) => [0xABu8; 32],
        }
    };

    // Load auth secret from /etc/hvpn/server.auth (generated in --setup, Step 4).
    // If the file doesn't exist, warn and operate without auth (reject all tokens).
    #[cfg(target_os = "windows")]
    let auth_secret_path = r"C:\ProgramData\hvpn\server.auth";
    #[cfg(not(target_os = "windows"))]
    let auth_secret_path = "/etc/hvpn/server.auth";

    let auth_secret: Option<[u8; 32]> = std::fs::read_to_string(auth_secret_path)
        .ok()
        .and_then(|s| {
            let hex = s.trim();
            if hex.len() == 64 {
                let bytes: Vec<u8> = (0..hex.len())
                    .step_by(2)
                    .filter_map(|i| u8::from_str_radix(&hex[i..i+2], 16).ok())
                    .collect();
                if bytes.len() == 32 {
                    let mut arr = [0u8; 32];
                    arr.copy_from_slice(&bytes);
                    Some(arr)
                } else { None }
            } else { None }
        });

    if auth_secret.is_none() {
        warn!("auth secret not found at {} — auth token validation disabled (run '--setup' to generate)", auth_secret_path);
    } else {
        info!("auth secret loaded from {}", auth_secret_path);
    }

    // ── TLS setup ─────────────────────────────────────────────────────────
    #[cfg(target_os = "windows")]
    let (tls_cert_path, tls_key_path) = (r"C:\ProgramData\hvpn\server.pem", r"C:\ProgramData\hvpn\server.key");
    #[cfg(not(target_os = "windows"))]
    let (tls_cert_path, tls_key_path) = ("/etc/hvpn/server.pem", "/etc/hvpn/server.key");

    let tls_acceptor: Option<tokio_rustls::TlsAcceptor> =
        match ensure_tls_cert(tls_cert_path, tls_key_path) {
            Ok((cert_pem, key_pem)) => {
                match build_rustls_server_config(&cert_pem, &key_pem) {
                    Ok(server_cfg) => {
                        info!("TLS enabled — connections will use wss://");
                        Some(tokio_rustls::TlsAcceptor::from(server_cfg))
                    }
                    Err(e) => {
                        warn!("TLS config build failed: {} — falling back to plain WebSocket", e);
                        None
                    }
                }
            }
            Err(e) => {
                warn!("TLS cert unavailable: {} — falling back to plain WebSocket", e);
                None
            }
        };

    // ── NAT routing setup + shared TUN (Linux only) ──────────────────────
    #[cfg(target_os = "linux")]
    let (nat_router, shared_tun) = if cfg.nat_enabled {
        match nat::setup_nat("10.8.0.1") {
            Ok(tun_fd) => {
                info!("NAT routing enabled");
                let tun = hvpn_tun::LinuxTun::from_raw_fd(tun_fd, "hvpn0")
                    .expect("failed to wrap TUN fd");
                info!("shared TUN device ready for NAT forwarding");
                (
                    Some(Arc::new(nat::NatRouter::new())),
                    Some(Arc::new(tokio::sync::Mutex::new(tun))),
                )
            }
            Err(e) => {
                warn!("NAT setup failed: {} — NAT disabled", e);
                (None, None)
            }
        }
    } else {
        (None, None)
    };

    // Nonce / replay cache: maps 40-byte token → UNIX timestamp of first use.
    let nonce_cache: Arc<DashMap<[u8; 40], u64>> = Arc::new(DashMap::new());

    let state = Arc::new(ServerState {
        server_secret: server_secret_bytes,
        mac_key,
        auth_secret,
        nonce_cache,
        #[cfg(target_os = "linux")]
        nat_router,
        #[cfg(target_os = "linux")]
        shared_tun,
    });

    // ── Audit logger ──────────────────────────────────────────────────────
    let audit_log_path = std::env::var("HVPN_AUDIT_LOG").ok();
    let audit = Arc::new(AuditLogger::new(audit_log_path.as_deref()));

    // ── Port-knock listener ────────────────────────────────────────────────
    let knock_whitelist: Arc<DashMap<std::net::IpAddr, std::time::Instant>> =
        Arc::new(DashMap::new());

    {
        let knock_port = cfg.server_port.saturating_sub(1);
        let knock_addr = format!("0.0.0.0:{}", knock_port);
        match tokio::net::UdpSocket::bind(&knock_addr).await {
            Ok(sock) => {
                let knock_socket = Arc::new(sock);
                let whitelist = knock_whitelist.clone();
                let mac_key_for_knock = mac_key;
                let audit_knock = audit.clone();
                tokio::spawn(async move {
                    let mut buf = [0u8; 256];
                    loop {
                        if let Ok((len, src)) = knock_socket.recv_from(&mut buf).await {
                            let data = &buf[..len];
                            let hex = std::str::from_utf8(data).unwrap_or("");
                            let bytes = hex_decode(hex);
                            if bytes.len() == 32 {
                                let ts = current_timestamp_secs();
                                let nonce = [0u8; 16];
                                let valid = (0u64..3).any(|delta| {
                                    let expected = generate_probe_token(
                                        &mac_key_for_knock,
                                        ts.saturating_sub(delta * 10),
                                        &nonce,
                                    );
                                    bytes.as_slice() == expected.as_slice()
                                });
                                if valid {
                                    whitelist.insert(src.ip(), std::time::Instant::now());
                                    info!(ip = %src.ip(), "port-knock accepted");
                                    audit_knock.log(AuditEvent::KnockAccepted {
                                        peer_ip: src.ip().to_string(),
                                        timestamp: AuditLogger::current_timestamp(),
                                    });
                                }
                            }
                        }
                    }
                });
                info!(port = knock_port, "port-knock listener started");
            }
            Err(e) => {
                warn!("could not bind knock port (non-fatal): {}", e);
            }
        }
    }

    let require_knock = std::env::var("HVPN_REQUIRE_KNOCK").is_ok();
    let tls_acceptor = Arc::new(tls_acceptor);

    loop {
        let (stream, peer_addr) = listener.accept().await?;
        info!(%peer_addr, "accepted TCP connection");

        // ── Port-knock enforcement ─────────────────────────────────────────
        if require_knock {
            knock_whitelist.retain(|_, ts| ts.elapsed().as_secs() < 10);
            if !knock_whitelist.contains_key(&peer_addr.ip()) {
                warn!(%peer_addr, "port-knock required — closing connection");
                drop(stream);
                continue;
            }
        }

        let state_clone = state.clone();
        let audit_clone = audit.clone();
        let tls_clone = tls_acceptor.clone();

        audit_clone.log(AuditEvent::ClientConnected {
            peer_ip: peer_addr.ip().to_string(),
            timestamp: AuditLogger::current_timestamp(),
        });

        tokio::spawn(async move {
            let result = if let Some(ref acceptor) = *tls_clone {
                handle_connection_tls(stream, peer_addr, state_clone, audit_clone, acceptor.clone()).await
            } else {
                handle_connection_plain(stream, peer_addr, state_clone, audit_clone).await
            };
            if let Err(e) = result {
                warn!(%peer_addr, error = %e, "connection error");
            }
        });
    }
}

// ── Auth token validation ─────────────────────────────────────────────────────

/// Validate the `X-Auth-Token` header from a WebSocket upgrade request.
///
/// Token format: 40 bytes hex-encoded (80 chars).
///   - bytes[0..8]  = LE timestamp (unix seconds)
///   - bytes[8..40] = HMAC-SHA256(auth_secret, timestamp_le || [0u8;16])
///
/// Returns `Ok([u8; 40])` with the raw token bytes on success (for replay cache).
/// Returns `Err(reason)` if auth is disabled, token is missing, malformed, or invalid.
fn validate_auth_token(
    req: &tokio_tungstenite::tungstenite::handshake::server::Request,
    auth_secret: Option<[u8; 32]>,
) -> Result<[u8; 40], String> {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;

    let secret = match auth_secret {
        Some(s) => s,
        None => return Err("no auth secret configured — rejecting all tokens".to_string()),
    };

    // Extract header.
    let token_hex = match req.headers().get("x-auth-token") {
        Some(v) => v.to_str().unwrap_or(""),
        None => return Err("missing X-Auth-Token header".to_string()),
    };

    if token_hex.len() != 80 {
        return Err(format!("X-Auth-Token wrong length: {} (expected 80 hex chars)", token_hex.len()));
    }

    // Hex-decode.
    let token_bytes: Vec<u8> = (0..token_hex.len())
        .step_by(2)
        .filter_map(|i| u8::from_str_radix(token_hex.get(i..i+2)?, 16).ok())
        .collect();
    if token_bytes.len() != 40 {
        return Err("X-Auth-Token hex decode failed".to_string());
    }

    let mut token_arr = [0u8; 40];
    token_arr.copy_from_slice(&token_bytes);

    // Extract timestamp.
    let mut ts_bytes = [0u8; 8];
    ts_bytes.copy_from_slice(&token_arr[0..8]);
    let token_ts = u64::from_le_bytes(ts_bytes);
    let server_ts = current_timestamp_secs();

    // Allow ±30 seconds of clock skew.
    let diff = if server_ts >= token_ts {
        server_ts - token_ts
    } else {
        token_ts - server_ts
    };
    if diff > 30 {
        return Err(format!("X-Auth-Token timestamp out of range (diff={}s)", diff));
    }

    // Recompute expected HMAC and verify in constant time via hmac::Mac::verify_slice,
    // which uses subtle internally — avoids timing oracle on partial prefix matches.
    let mut mac_input = [0u8; 24];
    mac_input[..8].copy_from_slice(&ts_bytes);
    // bytes [8..24] stay zero (fixed nonce).

    let mut mac = Hmac::<Sha256>::new_from_slice(&secret)
        .expect("HMAC accepts any key length");
    mac.update(&mac_input);
    let received = &token_arr[8..40];
    if mac.verify_slice(received).is_err() {
        return Err("X-Auth-Token HMAC mismatch".to_string());
    }

    Ok(token_arr)
}

// ── TLS connection path ───────────────────────────────────────────────────────

async fn handle_connection_tls(
    stream: tokio::net::TcpStream,
    peer_addr: std::net::SocketAddr,
    state: Arc<ServerState>,
    audit: Arc<AuditLogger>,
    acceptor: tokio_rustls::TlsAcceptor,
) -> Result<()> {
    let peer = peer_addr.to_string();

    // Perform TLS handshake.
    let tls_stream = match acceptor.accept(stream).await {
        Ok(s) => s,
        Err(e) => {
            warn!(%peer, "TLS handshake failed: {}", e);
            audit.log(AuditEvent::HandshakeFailed {
                peer_ip: peer_addr.ip().to_string(),
                reason: format!("TLS: {}", e),
                timestamp: AuditLogger::current_timestamp(),
            });
            return Ok(());
        }
    };

    // WebSocket upgrade with HMAC token auth.
    let auth_secret_opt = state.auth_secret;
    let validated_token: Arc<std::sync::Mutex<Option<[u8; 40]>>> =
        Arc::new(std::sync::Mutex::new(None));
    let vt_clone = validated_token.clone();

    #[allow(clippy::result_large_err)]
    let ws_result = tokio_tungstenite::accept_hdr_async(
        tls_stream,
        move |req: &tokio_tungstenite::tungstenite::handshake::server::Request,
              mut resp: tokio_tungstenite::tungstenite::handshake::server::Response| {
            match validate_auth_token(req, auth_secret_opt) {
                Ok(token_arr) => {
                    let mut guard = vt_clone.lock().unwrap();
                    *guard = Some(token_arr);
                    Ok(resp)
                }
                Err(reason) => {
                    warn!("auth token rejected: {}", reason);
                    let mut err_resp = http::Response::new(Some(reason));
                    *err_resp.status_mut() = http::StatusCode::FORBIDDEN;
                    Err(err_resp)
                }
            }
        },
    )
    .await;

    match ws_result {
        Ok(ws_stream) => {
            // Check if auth succeeded (validated_token must be Some).
            let token_arr = {
                let guard = validated_token.lock().unwrap();
                *guard
            };
            let token_arr = match token_arr {
                Some(t) => t,
                None => {
                    warn!(%peer, "connection closed: auth token missing or invalid");
                    let (mut sink, _) = ws_stream.split();
                    let _ = sink.close().await;
                    return Ok(());
                }
            };
            // Replay check.
            let now = current_timestamp_secs();
            state.nonce_cache.retain(|_, &mut stored_ts| now.saturating_sub(stored_ts) <= 60);
            if state.nonce_cache.contains_key(&token_arr) {
                warn!(%peer, "replay token detected — closing connection");
                let (mut sink, _) = ws_stream.split();
                let _ = sink.close().await;
                return Ok(());
            }
            state.nonce_cache.insert(token_arr, now);

            handle_authenticated(ws_stream, peer, peer_addr, state, audit).await
        }
        Err(e) => {
            warn!(%peer, "WS upgrade failed: {}", e);
            audit.log(AuditEvent::HandshakeFailed {
                peer_ip: peer_addr.ip().to_string(),
                reason: e.to_string(),
                timestamp: AuditLogger::current_timestamp(),
            });
            Ok(())
        }
    }
}

// ── Plain WebSocket connection path (fallback when TLS unavailable) ───────────

async fn handle_connection_plain(
    stream: tokio::net::TcpStream,
    peer_addr: std::net::SocketAddr,
    state: Arc<ServerState>,
    audit: Arc<AuditLogger>,
) -> Result<()> {
    use tokio::io::AsyncWriteExt;

    let peer = peer_addr.to_string();

    // Peek at the first 4 bytes: if not "GET " serve the nginx decoy and close.
    let mut peek_buf = [0u8; 4];
    let n = stream.peek(&mut peek_buf).await?;
    if n < 4 || &peek_buf[..4] != b"GET " {
        let mut owned = stream;
        let _ = owned.write_all(DECOY_PAGE).await;
        warn!(%peer, "non-HTTP probe — served decoy page");
        audit.log(AuditEvent::ProbeRejected {
            peer_ip: peer_addr.ip().to_string(),
            timestamp: AuditLogger::current_timestamp(),
        });
        return Ok(());
    }

    // ── WebSocket handshake with HMAC token auth ──────────────────────────
    let auth_secret_opt = state.auth_secret;
    let validated_token: Arc<std::sync::Mutex<Option<[u8; 40]>>> =
        Arc::new(std::sync::Mutex::new(None));
    let vt_clone = validated_token.clone();

    #[allow(clippy::result_large_err)]
    let ws_stream_result = tokio_tungstenite::accept_hdr_async(
        stream,
        move |req: &tokio_tungstenite::tungstenite::handshake::server::Request,
              mut resp: tokio_tungstenite::tungstenite::handshake::server::Response| {
            match validate_auth_token(req, auth_secret_opt) {
                Ok(token_arr) => {
                    let mut guard = vt_clone.lock().unwrap();
                    *guard = Some(token_arr);
                    Ok(resp)
                }
                Err(reason) => {
                    warn!("auth token rejected: {}", reason);
                    let mut err_resp = http::Response::new(Some(reason));
                    *err_resp.status_mut() = http::StatusCode::FORBIDDEN;
                    Err(err_resp)
                }
            }
        },
    )
    .await;

    match ws_stream_result {
        Ok(ws_stream) => {
            // Check if auth succeeded (validated_token must be Some).
            let token_arr = {
                let guard = validated_token.lock().unwrap();
                *guard
            };
            let token_arr = match token_arr {
                Some(t) => t,
                None => {
                    warn!(%peer, "connection closed: auth token missing or invalid");
                    let (mut sink, _) = ws_stream.split();
                    let _ = sink.close().await;
                    return Ok(());
                }
            };
            // Replay check.
            let now = current_timestamp_secs();
            state.nonce_cache.retain(|_, &mut stored_ts| now.saturating_sub(stored_ts) <= 60);
            if state.nonce_cache.contains_key(&token_arr) {
                warn!(%peer, "replay token detected — closing connection");
                let (mut sink, _) = ws_stream.split();
                let _ = sink.close().await;
                return Ok(());
            }
            state.nonce_cache.insert(token_arr, now);

            handle_authenticated(ws_stream, peer, peer_addr, state, audit).await
        }
        Err(e) => {
            warn!(%peer, "rejected connection: {}", e);
            audit.log(AuditEvent::HandshakeFailed {
                peer_ip: peer_addr.ip().to_string(),
                reason: e.to_string(),
                timestamp: AuditLogger::current_timestamp(),
            });
            Ok(())
        }
    }
}

// ── Shared authenticated session handler ─────────────────────────────────────

#[allow(unused_variables)]
async fn handle_authenticated<S>(
    ws_stream: tokio_tungstenite::WebSocketStream<S>,
    peer: String,
    peer_addr: std::net::SocketAddr,
    state: Arc<ServerState>,
    audit: Arc<AuditLogger>,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    use tokio_tungstenite::tungstenite::protocol::Message;

    info!(%peer, "authenticated connection established");

    let (mut sink, mut source) = ws_stream.split();

    // First message: client's ephemeral X25519 public key (32 bytes).
    let session_keys = match source.next().await {
        Some(Ok(Message::Binary(data))) if data.len() >= 32 => {
            let mut ephemeral = [0u8; 32];
            ephemeral.copy_from_slice(&data[..32]);
            perform_handshake_server(&ephemeral, &state.server_secret)
                .map_err(|e| anyhow::anyhow!("handshake error: {}", e))?
        }
        other => {
            warn!(%peer, "unexpected first message: {:?}", other);
            return Ok(());
        }
    };

    info!(%peer, "crypto handshake complete");

    // Initialise the double ratchet for this session (server role).
    // Split into independent send/recv halves guarded by separate Mutexes so
    // both directions can advance concurrently without blocking.
    let ratchet = RatchetState::init_server(&session_keys);
    let ratchet_send = std::sync::Arc::new(std::sync::Mutex::new(ratchet.send));
    let ratchet_recv = std::sync::Arc::new(std::sync::Mutex::new(ratchet.recv));

    // Save the header key so we can build fresh FrameCodec instances per task.
    let header_key = session_keys.header_key;

    // ── NAT routing path (Linux only) ─────────────────────────────────────
    #[cfg(target_os = "linux")]
    if let Some(router) = state.nat_router.as_ref().map(Arc::clone) {
        use hvpn_core::Frame;
        use hvpn_core::FrameType;
        use hvpn_tun::LinuxTun;
        use hvpn_tun::TunDevice;

        // Assign this client a VPN IP.
        let _client_ip = router.assign_client_ip(peer_addr);

        // Use the shared TUN device for reading (server→client direction).
        let shared_tun = match state.shared_tun.as_ref() {
            Some(t) => Arc::clone(t),
            None => {
                warn!(%peer, "shared TUN not available — falling back to log loop");
                drop(router);
                return Ok(());
            }
        };

        // Duplicate the TUN fd for writing (client→internet direction).
        let tun_write = {
            let tun = shared_tun.lock().await;
            match tun.try_clone() {
                Ok(t) => t,
                Err(e) => {
                    warn!(%peer, "could not open write TUN fd: {} — falling back to log loop", e);
                    drop(router);
                    return Ok(());
                }
            }
        };

        let keys_a = session_keys.clone();
        let keys_b = session_keys.clone();
        let peer_a = peer.clone();
        let peer_b = peer.clone();
        let router_b = router.clone();
        let client_addr = peer_addr;
        let tun_a = Arc::clone(&shared_tun);  // read TUN (server→client)
        let tun_b = tun_write;                 // write TUN (client→internet)

        // Clone ratchet halves for each task.
        let ratchet_send_a = std::sync::Arc::clone(&ratchet_send);
        let ratchet_recv_b = std::sync::Arc::clone(&ratchet_recv);

        // Task A: server TUN → client WS (server send direction)
        let tun_to_client = tokio::spawn(async move {
            let codec_a = FrameCodec::new(keys_a.header_key);
            let mut obfs_a = ObfsEngine::new();
            let mut out_seq: u64 = 0;
            loop {
                let ip_pkt = {
                    let mut tun = tun_a.lock().await;
                    match tun.read_packet().await {
                        Ok(p) => p,
                        Err(e) => { warn!(peer = %peer_a, "TUN read: {}", e); break; }
                    }
                };
                // Derive the per-packet encryption key from the send ratchet.
                let msg_key = ratchet_send_a.lock().unwrap().next_key();
                let ratchet_session = hvpn_crypto::SessionKeys {
                    send_key: msg_key,
                    recv_key: [0u8; 32],
                    header_key: keys_a.header_key,
                    mac_key: keys_a.mac_key,
                };
                match hvpn_crypto::encrypt_packet(&ratchet_session, &ip_pkt, out_seq, None) {
                    Ok(ciphertext) => {
                        let frame = Frame {
                            seq: out_seq,
                            stream_id: 0,
                            frame_type: FrameType::Data,
                            flags: 0,
                            payload: ciphertext,
                            padding: vec![],
                        };
                        let encoded = codec_a.encode(&frame);
                        let padded = obfs_a.pad_packet(encoded);
                        if sink.send(Message::Binary(padded)).await.is_err() { break; }
                        out_seq = out_seq.wrapping_add(1);
                    }
                    Err(e) => warn!(peer = %peer_a, "encrypt: {}", e),
                }
            }
        });

        // Task B: client WS → server TUN (internet) (server recv direction)
        let client_to_tun = tokio::spawn(async move {
            let codec_b = FrameCodec::new(keys_b.header_key);
            let obfs_b = ObfsEngine::new();
            let mut replay = hvpn_core::ReplayWindow::new();
            let mut tun_b = tun_b;
            while let Some(msg) = source.next().await {
                match msg {
                    Ok(Message::Binary(data)) => {
                        let unpadded = obfs_b.unpad_packet(data);
                        match codec_b.decode(&unpadded) {
                            Ok(frame) => {
                                if replay.check_and_advance(frame.seq).is_err() { continue; }
                                // Derive the per-packet decryption key from the recv ratchet.
                                let msg_key = ratchet_recv_b.lock().unwrap().next_key();
                                let ratchet_session = hvpn_crypto::SessionKeys {
                                    send_key: [0u8; 32],
                                    recv_key: msg_key,
                                    header_key: keys_b.header_key,
                                    mac_key: keys_b.mac_key,
                                };
                                match hvpn_crypto::decrypt_packet(&ratchet_session, &frame.payload, frame.seq, None) {
                                    Ok(ip_pkt) => {
                                        if let Err(e) = tun_b.write_packet(&ip_pkt).await {
                                            warn!(peer = %peer_b, "TUN write: {}", e);
                                            break;
                                        }
                                    }
                                    Err(e) => warn!(peer = %peer_b, "decrypt: {}", e),
                                }
                            }
                            Err(e) => warn!(peer = %peer_b, "frame decode: {}", e),
                        }
                    }
                    Ok(Message::Close(_)) => { info!(peer = %peer_b, "client closed"); break; }
                    Ok(_) => {}
                    Err(e) => { warn!(peer = %peer_b, "ws error: {}", e); break; }
                }
            }
            router_b.release_client_ip(&client_addr);
        });

        tokio::select! {
            _ = tun_to_client => {}
            _ = client_to_tun => {}
        }
        info!(%peer, "NAT connection closed");
        audit.log(AuditEvent::ClientDisconnected {
            peer_ip: peer_addr.ip().to_string(),
            reason: "clean close".to_string(),
            timestamp: AuditLogger::current_timestamp(),
        });
        return Ok(());
    }

    // ── Phase-1 log-only loop (NAT disabled or TUN unavailable) ───────────
    let codec = FrameCodec::new(header_key);
    let obfs = ObfsEngine::new();
    let mut replay = hvpn_core::ReplayWindow::new();

    while let Some(msg) = source.next().await {
        match msg {
            Ok(Message::Binary(data)) => {
                let unpadded = obfs.unpad_packet(data);
                match codec.decode(&unpadded) {
                    Ok(frame) => {
                        if let Err(e) = replay.check_and_advance(frame.seq) {
                            warn!(%peer, "replay: {}", e);
                            continue;
                        }
                        // Derive the per-packet decryption key from the recv ratchet.
                        let msg_key = ratchet_recv.lock().unwrap().next_key();
                        let ratchet_session = hvpn_crypto::SessionKeys {
                            send_key: [0u8; 32],
                            recv_key: msg_key,
                            header_key: session_keys.header_key,
                            mac_key: session_keys.mac_key,
                        };
                        match decrypt_packet(&ratchet_session, &frame.payload, frame.seq, None) {
                            Ok(plaintext) => {
                                info!(
                                    %peer,
                                    seq  = frame.seq,
                                    sid  = frame.stream_id,
                                    len  = plaintext.len(),
                                    "received IP packet (NAT disabled: logging only)"
                                );
                            }
                            Err(e) => warn!(%peer, "decrypt failed: {}", e),
                        }
                    }
                    Err(e) => warn!(%peer, "frame decode error: {}", e),
                }
            }
            Ok(Message::Close(_)) => {
                info!(%peer, "client closed connection");
                break;
            }
            Ok(_) => {}
            Err(e) => {
                warn!(%peer, "ws error: {}", e);
                break;
            }
        }
    }

    let _ = sink.close().await;
    info!(%peer, "connection closed");
    audit.log(AuditEvent::ClientDisconnected {
        peer_ip: peer_addr.ip().to_string(),
        reason: "clean close".to_string(),
        timestamp: AuditLogger::current_timestamp(),
    });
    Ok(())
}

fn run_setup() -> anyhow::Result<()> {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
    use hvpn_crypto::KeyPair;
    use qrcode::QrCode;
    use qrcode::render::unicode;
    use rand::RngCore;
    use x25519_dalek::{StaticSecret, PublicKey};
    use rand::rngs::OsRng;

    // Generate fresh Ed25519 server keypair (for identity).
    let kp = KeyPair::generate();
    let ed_pubkey_bytes = kp.public_key_bytes();
    let ed_pubkey_hex: String = ed_pubkey_bytes.iter().map(|b| format!("{:02x}", b)).collect();

    // Generate fresh X25519 keypair (for tunnel handshake).
    let x25519_secret = StaticSecret::random_from_rng(OsRng);
    let x25519_public = PublicKey::from(&x25519_secret);
    let x25519_secret_hex: String = x25519_secret.as_bytes().iter().map(|b| format!("{:02x}", b)).collect();
    let x25519_pubkey_hex: String = x25519_public.as_bytes().iter().map(|b| format!("{:02x}", b)).collect();

    // Generate random 32-byte auth secret.
    let mut auth_secret_bytes = [0u8; 32];
    OsRng.fill_bytes(&mut auth_secret_bytes);
    let auth_secret_hex: String = auth_secret_bytes.iter().map(|b| format!("{:02x}", b)).collect();

    // Detect public IP.
    let ip = reqwest::blocking::get("https://api.ipify.org")?.text()?;
    let ip = ip.trim().to_string();

    let port: u16 = 443;

    #[cfg(target_os = "windows")]
    let config_dir = std::path::PathBuf::from(r"C:\ProgramData\hvpn");
    #[cfg(not(target_os = "windows"))]
    let config_dir = std::path::PathBuf::from("/etc/hvpn");

    std::fs::create_dir_all(&config_dir)?;

    // Write server config.
    #[cfg(target_os = "windows")]
    let tls_cert_path = r"C:\ProgramData\hvpn\server.pem";
    #[cfg(not(target_os = "windows"))]
    let tls_cert_path = "/etc/hvpn/server.pem";

    let config_content = format!(
        r#"server_address = "{ip}"
server_port = {port}
tls_cert_path = "{tls_cert}"
nat_enabled = true
dns_servers = ["1.1.1.1", "8.8.8.8"]
tun_ip = "10.8.0.1"
tun_netmask = "255.255.255.0"
"#,
        ip = ip, port = port, tls_cert = tls_cert_path,
    );
    std::fs::write(config_dir.join("server.toml"), &config_content)?;

    // Write Ed25519 public key.
    std::fs::write(config_dir.join("server.pub"), &ed_pubkey_hex)?;

    // Write X25519 private key (keep secret!).
    std::fs::write(config_dir.join("server_x25519.key"), &x25519_secret_hex)?;
    // Write X25519 public key.
    std::fs::write(config_dir.join("server_x25519.pub"), &x25519_pubkey_hex)?;

    // Write auth secret (keep secret — shared with clients via connection string).
    std::fs::write(config_dir.join("server.auth"), &auth_secret_hex)?;

    println!("Server config written to {:?}", config_dir.join("server.toml"));
    println!("X25519 private key written to {:?} (keep secret!)", config_dir.join("server_x25519.key"));
    println!("Auth secret written to {:?} (keep secret!)", config_dir.join("server.auth"));

    // Build connection string using X25519 pubkey + auth_secret.
    let conn_json = serde_json::json!({
        "server": ip,
        "port": port,
        "pubkey": x25519_pubkey_hex,
        "version": 1,
        "auth_secret": auth_secret_hex,
    });
    let conn_str = URL_SAFE_NO_PAD.encode(conn_json.to_string().as_bytes());

    // Generate and print QR code.
    let code = QrCode::new(conn_str.as_bytes())?;
    let image = code.render::<unicode::Dense1x2>().build();
    println!("{}", image);

    println!("\nConnection string:\n{}", conn_str);
    println!("\nScan this QR code in the HVPN tray app, or paste the connection string manually.");
    println!("\nIMPORTANT: The connection string contains the X25519 public key and auth secret.");

    Ok(())
}

fn hex_decode(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .filter_map(|i| u8::from_str_radix(s.get(i..i + 2)?, 16).ok())
        .collect()
}

fn current_timestamp_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use dashmap::DashMap;

    #[test]
    fn probe_token_replay_rejection() {
        let cache: DashMap<[u8; 40], u64> = DashMap::new();
        let token: [u8; 40] = [0xAB; 40];
        let ts: u64 = 1_700_000_000;

        // First insertion should succeed (key was absent).
        let first_insert = cache.insert(token, ts).is_none();
        assert!(first_insert, "first insertion should succeed (key was absent)");

        // Second attempt: key already exists → replay detected.
        let is_replay = cache.contains_key(&token);
        assert!(is_replay, "second token should be detected as replay");
    }

    // ── helpers ──────────────────────────────────────────────────────────────

    /// Mint a valid 40-byte auth token given a secret and a timestamp (unix secs).
    /// Matches exactly the logic in `validate_auth_token`.
    fn mint_token(auth_secret: &[u8; 32], ts: u64) -> [u8; 40] {
        use hmac::{Hmac, Mac};
        use sha2::Sha256;

        let ts_le = ts.to_le_bytes();
        let mut mac_input = [0u8; 24];
        mac_input[..8].copy_from_slice(&ts_le);
        // bytes [8..24] are zero (fixed nonce).

        let mut mac = Hmac::<Sha256>::new_from_slice(auth_secret)
            .expect("HMAC accepts any key length");
        mac.update(&mac_input);
        let hmac_bytes: [u8; 32] = mac.finalize().into_bytes().into();

        let mut token = [0u8; 40];
        token[..8].copy_from_slice(&ts_le);
        token[8..].copy_from_slice(&hmac_bytes);
        token
    }

    /// Build an `http::Request<()>` with the given `X-Auth-Token` header value.
    fn make_ws_request_with_token(token_hex: &str) -> tokio_tungstenite::tungstenite::handshake::server::Request {
        http::Request::builder()
            .uri("ws://localhost/ws")
            .header("X-Auth-Token", token_hex)
            .body(())
            .expect("build request")
    }

    /// Build an `http::Request<()>` with no `X-Auth-Token` header.
    fn make_ws_request_no_token() -> tokio_tungstenite::tungstenite::handshake::server::Request {
        http::Request::builder()
            .uri("ws://localhost/ws")
            .body(())
            .expect("build request")
    }

    // ── test_auth_token_validation ────────────────────────────────────────────

    /// A freshly minted token validates, a tampered token is rejected, an
    /// expired token is rejected, and a replayed token is detected by the
    /// `DashMap`-based nonce cache.
    #[test]
    fn test_auth_token_validation() {
        use dashmap::DashMap;
        use super::{validate_auth_token, current_timestamp_secs};

        let auth_secret: [u8; 32] = [0x42u8; 32];

        // 1. Fresh token (current timestamp) — must validate.
        let ts_now = current_timestamp_secs();
        let token = mint_token(&auth_secret, ts_now);
        let token_hex: String = token.iter().map(|b| format!("{:02x}", b)).collect();
        let req = make_ws_request_with_token(&token_hex);
        let result = validate_auth_token(&req, Some(auth_secret));
        assert!(result.is_ok(), "fresh token should be accepted: {:?}", result);

        // 2. Token with timestamp 31 seconds in the past — must be rejected.
        let ts_old = ts_now.saturating_sub(31);
        let old_token = mint_token(&auth_secret, ts_old);
        let old_hex: String = old_token.iter().map(|b| format!("{:02x}", b)).collect();
        let req_old = make_ws_request_with_token(&old_hex);
        let result_old = validate_auth_token(&req_old, Some(auth_secret));
        assert!(result_old.is_err(), "expired token (31s old) should be rejected");
        assert!(result_old.unwrap_err().contains("timestamp out of range"),
            "error should mention timestamp");

        // 3. Token with a tampered HMAC — must be rejected.
        let mut tampered = token;
        tampered[8] ^= 0xFF; // flip bits in the HMAC portion
        let tampered_hex: String = tampered.iter().map(|b| format!("{:02x}", b)).collect();
        let req_tampered = make_ws_request_with_token(&tampered_hex);
        let result_tampered = validate_auth_token(&req_tampered, Some(auth_secret));
        assert!(result_tampered.is_err(), "tampered HMAC should be rejected");
        assert!(result_tampered.unwrap_err().contains("HMAC mismatch"),
            "error should mention HMAC mismatch");

        // 4. Missing header — must be rejected.
        let req_no_hdr = make_ws_request_no_token();
        let result_no_hdr = validate_auth_token(&req_no_hdr, Some(auth_secret));
        assert!(result_no_hdr.is_err(), "missing header should be rejected");

        // 5. No auth secret configured — all tokens rejected.
        let req_any = make_ws_request_with_token(&token_hex);
        let result_no_secret = validate_auth_token(&req_any, None);
        assert!(result_no_secret.is_err(), "missing secret should reject any token");

        // 6. Replay detection via nonce cache.
        let nonce_cache: DashMap<[u8; 40], u64> = DashMap::new();
        let token_arr = result.unwrap(); // the good token from step 1
        // First use — insert succeeds.
        assert!(!nonce_cache.contains_key(&token_arr), "should not yet be in cache");
        nonce_cache.insert(token_arr, ts_now);
        // Second use — detected as replay.
        assert!(nonce_cache.contains_key(&token_arr), "replay token must be detected");
    }

    // ── test_tls_self_signed ──────────────────────────────────────────────────

    /// `ensure_tls_cert` generates a self-signed cert when none exists, and
    /// `DangerVerifier` accepts it unconditionally.
    #[test]
    fn test_tls_self_signed() {
        use super::ensure_tls_cert;
        use hvpn_transport::DangerVerifier;
        use rustls::client::danger::ServerCertVerifier;
        use rustls::pki_types::{CertificateDer, ServerName, UnixTime};

        // Install ring crypto provider so rustls is operational.
        let _ = rustls::crypto::ring::default_provider().install_default();

        // Use a temp directory so the test is self-contained.
        let tmp = std::env::temp_dir().join("hvpn_tls_test");
        std::fs::create_dir_all(&tmp).unwrap();
        let cert_path = tmp.join("server.pem");
        let key_path = tmp.join("server.key");

        // Remove any leftovers from a prior run.
        let _ = std::fs::remove_file(&cert_path);
        let _ = std::fs::remove_file(&key_path);

        let cert_path_str = cert_path.to_str().unwrap();
        let key_path_str = key_path.to_str().unwrap();

        // 1. ensure_tls_cert generates fresh files when they don't exist.
        let (cert_pem, key_pem) = ensure_tls_cert(cert_path_str, key_path_str)
            .expect("should generate self-signed cert");
        assert!(!cert_pem.is_empty(), "cert_pem must not be empty");
        assert!(!key_pem.is_empty(), "key_pem must not be empty");
        assert!(cert_path.exists(), "cert file must be written to disk");
        assert!(key_path.exists(), "key file must be written to disk");

        // 2. ensure_tls_cert loads existing files on subsequent calls.
        let (cert_pem2, _key_pem2) = ensure_tls_cert(cert_path_str, key_path_str)
            .expect("should load existing cert");
        assert_eq!(cert_pem, cert_pem2, "loaded cert must equal generated cert");

        // 3. DangerVerifier accepts the self-signed cert without complaint.
        //    Parse the DER cert out of the PEM.
        let der_certs: Vec<CertificateDer<'static>> = {
            let mut cursor = std::io::Cursor::new(&cert_pem);
            rustls_pemfile::certs(&mut cursor)
                .filter_map(|r| r.ok())
                .collect()
        };
        assert!(!der_certs.is_empty(), "PEM must contain at least one DER cert");

        let verifier = DangerVerifier;
        let server_name = ServerName::try_from("hvpn-server").unwrap();
        let now = UnixTime::since_unix_epoch(std::time::Duration::from_secs(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
        ));

        let verify_result = verifier.verify_server_cert(
            &der_certs[0],
            &[],
            &server_name,
            &[],
            now,
        );
        assert!(
            verify_result.is_ok(),
            "DangerVerifier must accept self-signed cert: {:?}",
            verify_result
        );

        // Cleanup.
        let _ = std::fs::remove_file(&cert_path);
        let _ = std::fs::remove_file(&key_path);
    }
}




