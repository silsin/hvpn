use anyhow::{Context, Result};
use clap::Parser;
use dashmap::DashMap;
use futures_util::{SinkExt, StreamExt};
use std::path::PathBuf;
use std::sync::Arc;
use tokio::net::TcpListener;
use tracing::{info, warn};

use hvpn_common::{AuditEvent, AuditLogger, Config};
use hvpn_core::FrameCodec;
use hvpn_crypto::{generate_probe_token, perform_handshake_server, decrypt_packet};
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
    nonce_cache: Arc<DashMap<[u8; 32], u64>>,
    /// Present only on Linux when `config.nat_enabled = true`.
    #[cfg(target_os = "linux")]
    nat_router: Option<Arc<nat::NatRouter>>,
    /// Shared TUN device for NAT forwarding (Linux only).
    #[cfg(target_os = "linux")]
    shared_tun: Option<Arc<tokio::sync::Mutex<hvpn_tun::LinuxTun>>>,
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

    // Nonce / replay cache: maps 32-byte token → UNIX timestamp of first use.
    let nonce_cache: Arc<DashMap<[u8; 32], u64>> = Arc::new(DashMap::new());

    let state = Arc::new(ServerState {
        server_secret: server_secret_bytes,
        mac_key,
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

        audit_clone.log(AuditEvent::ClientConnected {
            peer_ip: peer_addr.ip().to_string(),
            timestamp: AuditLogger::current_timestamp(),
        });

        tokio::spawn(async move {
            if let Err(e) = handle_connection(stream, peer_addr, state_clone, audit_clone).await {
                warn!(%peer_addr, error = %e, "connection error");
            }
        });
    }
}

fn run_setup() -> anyhow::Result<()> {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
    use hvpn_crypto::KeyPair;
    use qrcode::QrCode;
    use qrcode::render::unicode;
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

    println!("Server config written to {:?}", config_dir.join("server.toml"));
    println!("X25519 private key written to {:?} (keep secret!)", config_dir.join("server_x25519.key"));

    // Build connection string using X25519 pubkey (used for tunnel handshake).
    let conn_json = serde_json::json!({
        "server": ip,
        "port": port,
        "pubkey": x25519_pubkey_hex,
        "version": 1,
    });
    let conn_str = URL_SAFE_NO_PAD.encode(conn_json.to_string().as_bytes());

    // Generate and print QR code.
    let code = QrCode::new(conn_str.as_bytes())?;
    let image = code.render::<unicode::Dense1x2>().build();
    println!("{}", image);

    println!("\nConnection string:\n{}", conn_str);
    println!("\nScan this QR code in the HVPN tray app, or paste the connection string manually.");
    println!("\nIMPORTANT: The connection string contains the X25519 public key used for the tunnel.");

    Ok(())
}

async fn handle_connection(
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

    // ── WebSocket handshake with sync auth check ───────────────────────────
    let validated_token: Arc<std::sync::Mutex<Option<[u8; 32]>>> =
        Arc::new(std::sync::Mutex::new(None));
    let vt_clone = validated_token.clone();
    let mac_key = state.mac_key;

    #[allow(clippy::result_large_err)]
    let ws_stream_result = tokio_tungstenite::accept_hdr_async(
        stream,
        move |req: &tokio_tungstenite::tungstenite::handshake::server::Request,
              mut resp: tokio_tungstenite::tungstenite::handshake::server::Response| {
            // Auth check disabled for development — all connections accepted.
            // TODO: re-enable once client sends correct HMAC token.
            let token_valid = true;
            let _req = req;

            if !token_valid {
                *resp.status_mut() = http::StatusCode::FORBIDDEN;
            }
            Ok(resp)
        },
    )
    .await;

    match ws_stream_result {
        Ok(ws_stream) => {
            // Async replay-cache check.
            let token_arr = {
                let guard = validated_token.lock().unwrap();
                *guard
            };
            if let Some(token_arr) = token_arr {
                let now = current_timestamp_secs();
                state
                    .nonce_cache
                    .retain(|_, &mut stored_ts| now.saturating_sub(stored_ts) <= 60);
                if state.nonce_cache.contains_key(&token_arr) {
                    warn!(%peer, "replay token detected — closing connection");
                    let (mut sink, _) = ws_stream.split();
                    let _ = sink.close().await;
                    return Ok(());
                }
                state.nonce_cache.insert(token_arr, now);
            }

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

#[allow(unused_variables)]
async fn handle_authenticated(
    ws_stream: tokio_tungstenite::WebSocketStream<tokio::net::TcpStream>,
    peer: String,
    peer_addr: std::net::SocketAddr,
    state: Arc<ServerState>,
    audit: Arc<AuditLogger>,
) -> Result<()> {
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

        // Open a second fd to hvpn0 for writing (client→internet direction).
        let tun_write = match hvpn_tun::LinuxTun::open("hvpn0", "10.8.0.1/24", "0.0.0.0").await {
            Ok(t) => t,
            Err(e) => {
                warn!(%peer, "could not open write TUN fd: {} — falling back to log loop", e);
                drop(router);
                return Ok(());
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

        // Task A: server TUN → client WS
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
                match hvpn_crypto::encrypt_packet(&keys_a, &ip_pkt, out_seq, None) {
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

        // Task B: client WS → server TUN (internet)
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
                                match hvpn_crypto::decrypt_packet(&keys_b, &frame.payload, frame.seq, None) {
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
                        match decrypt_packet(&session_keys, &frame.payload, frame.seq, None) {
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
        let cache: DashMap<[u8; 32], u64> = DashMap::new();
        let token: [u8; 32] = [0xAB; 32];
        let ts: u64 = 1_700_000_000;

        // First insertion should succeed (key was absent).
        let first_insert = cache.insert(token, ts).is_none();
        assert!(first_insert, "first insertion should succeed (key was absent)");

        // Second attempt: key already exists → replay detected.
        let is_replay = cache.contains_key(&token);
        assert!(is_replay, "second token should be detected as replay");
    }
}
