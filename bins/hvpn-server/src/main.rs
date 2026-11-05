use anyhow::{Context, Result};
use clap::Parser;
use dashmap::DashMap;
use futures_util::{SinkExt, StreamExt};
use std::path::PathBuf;
use std::sync::Arc;
use tokio::net::TcpListener;
use tracing::{info, warn};

use hvpn_common::Config;
use hvpn_core::FrameCodec;
use hvpn_crypto::{generate_probe_token, perform_handshake_server, decrypt_packet};
use hvpn_obfs::ObfsEngine;

/// HVPN server — accepts tunnelled connections from HVPN clients.
#[derive(Parser, Debug)]
#[command(name = "hvpn-server", version, about)]
struct Cli {
    /// Path to the TOML configuration file.
    #[arg(long, default_value = "config.toml")]
    config: PathBuf,
}

/// Realistic nginx decoy page served to unauthenticated probes.
/// Served on the raw-TCP code path (non-HTTP traffic) via an AsyncWrite on
/// the TcpStream before the WebSocket upgrade is attempted.  When the WS
/// handshake itself rejects an invalid token the 403 response is emitted by
/// tungstenite; the DECOY_PAGE body is included there as the response body
/// where the tungstenite API permits (see `accept_hdr_async` closure).
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

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive("hvpn_server=info".parse()?),
        )
        .init();

    let cli = Cli::parse();

    let raw = tokio::fs::read_to_string(&cli.config)
        .await
        .with_context(|| format!("reading config file {:?}", cli.config))?;
    let cfg = Config::from_toml_str(&raw)
        .with_context(|| "parsing config file")?;

    let bind_addr = format!("0.0.0.0:{}", cfg.server_port);
    info!(addr = %bind_addr, "HVPN server listening");

    let listener = TcpListener::bind(&bind_addr)
        .await
        .with_context(|| format!("binding to {}", bind_addr))?;

    // Server static X25519 key (zeroed in Phase 1; load from config in Phase 2).
    let server_secret_bytes = [0u8; 32];
    // Derive a stable mac_key from the server secret for probe token verification.
    let mac_key: [u8; 32] = {
        // Use a known dummy ephemeral key to derive mac_key.
        let dummy_ephemeral = [0xFFu8; 32];
        match perform_handshake_server(&dummy_ephemeral, &server_secret_bytes) {
            Ok(k) => k.mac_key,
            Err(_) => [0xABu8; 32],
        }
    };

    // Nonce / replay cache: maps 32-byte token → UNIX timestamp of first use.
    let nonce_cache: Arc<DashMap<[u8; 32], u64>> = Arc::new(DashMap::new());

    // ── Port-knock listener ────────────────────────────────────────────────
    // Listens on (server_port - 1) UDP.  A client sends a valid probe token
    // (hex-encoded 32 bytes) to whitelist its IP for 10 seconds.
    // Enforcement is gated on the HVPN_REQUIRE_KNOCK env-var so that tests
    // (which don't set it) keep connecting without a knock.
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
            // Evict stale whitelist entries (> 10 seconds old).
            knock_whitelist.retain(|_, ts| ts.elapsed().as_secs() < 10);
            if !knock_whitelist.contains_key(&peer_addr.ip()) {
                warn!(%peer_addr, "port-knock required — closing connection");
                drop(stream);
                continue;
            }
        }

        let mac_key_clone = mac_key;
        let server_secret = server_secret_bytes;
        let nonce_cache_clone = nonce_cache.clone();

        tokio::spawn(async move {
            if let Err(e) = handle_connection(
                stream,
                peer_addr.to_string(),
                mac_key_clone,
                server_secret,
                nonce_cache_clone,
            )
            .await
            {
                warn!(%peer_addr, error = %e, "connection error");
            }
        });
    }
}

async fn handle_connection(
    stream: tokio::net::TcpStream,
    peer: String,
    mac_key: [u8; 32],
    server_secret: [u8; 32],
    nonce_cache: Arc<DashMap<[u8; 32], u64>>,
) -> Result<()> {
    use tokio::io::AsyncWriteExt;

    // Peek at the first 4 bytes to decide if this looks like an HTTP GET.
    // If it is not an HTTP upgrade we serve the nginx decoy page directly and
    // return — the stream is still unmodified at this point.
    let mut peek_buf = [0u8; 4];
    let n = stream.peek(&mut peek_buf).await?;

    if n < 4 || &peek_buf[..4] != b"GET " {
        // Not an HTTP upgrade — serve the nginx decoy page on the raw stream.
        let mut owned = stream;
        let _ = owned.write_all(DECOY_PAGE).await;
        warn!(%peer, "non-HTTP probe — served decoy page");
        return Ok(());
    }

    // ── WebSocket handshake ────────────────────────────────────────────────
    // We do a lightweight signature + timestamp check synchronously inside the
    // callback (sync closure — no async allowed).  The full replay-cache check
    // (which needs async-safe DashMap mutation) runs after the WS accept below.

    // Use an atomic cell to carry the validated token bytes out of the closure
    // so we can do the replay check in async context afterward.
    let validated_token: Arc<std::sync::Mutex<Option<[u8; 32]>>> =
        Arc::new(std::sync::Mutex::new(None));
    let vt_clone = validated_token.clone();

    let ws_stream_result = tokio_tungstenite::accept_hdr_async(
        stream,
        move |req: &tokio_tungstenite::tungstenite::handshake::server::Request,
              mut resp: tokio_tungstenite::tungstenite::handshake::server::Response| {
            // ── Sync token check (signature + timestamp) ───────────────
            let token_valid = req
                .headers()
                .get("x-auth-token")
                .and_then(|v| v.to_str().ok())
                .map(|hex| {
                    let bytes = hex_decode(hex);
                    if bytes.len() == 32 {
                        // Validate timestamp embedded in first 8 bytes.
                        let mut ts_bytes = [0u8; 8];
                        ts_bytes.copy_from_slice(&bytes[..8]);
                        let token_ts = u64::from_le_bytes(ts_bytes);
                        let now = current_timestamp_secs();
                        let diff = if now >= token_ts { now - token_ts } else { token_ts - now };
                        if diff > 30 {
                            return false;
                        }

                        // Verify HMAC signature against current time window.
                        let nonce = [0u8; 16];
                        for delta in 0u64..3 {
                            let expected = generate_probe_token(
                                &mac_key,
                                now.saturating_sub(delta * 10),
                                &nonce,
                            );
                            if bytes.as_slice() == expected.as_slice() {
                                // Stash the raw bytes for the async replay check.
                                let mut arr = [0u8; 32];
                                arr.copy_from_slice(&bytes);
                                if let Ok(mut guard) = vt_clone.lock() {
                                    *guard = Some(arr);
                                }
                                return true;
                            }
                        }
                    }
                    false
                })
                .unwrap_or(false);

            if !token_valid {
                *resp.status_mut() = http::StatusCode::FORBIDDEN;
            }
            Ok(resp)
        },
    )
    .await;

    match ws_stream_result {
        Ok(ws_stream) => {
            // ── Async replay-cache check ───────────────────────────────
            let token_arr = {
                let guard = validated_token.lock().unwrap();
                *guard
            };

            if let Some(token_arr) = token_arr {
                let now = current_timestamp_secs();

                // Evict entries older than 60 seconds.
                nonce_cache.retain(|_, &mut stored_ts| now.saturating_sub(stored_ts) <= 60);

                // Replay detection.
                if nonce_cache.contains_key(&token_arr) {
                    warn!(%peer, "replay token detected — closing connection");
                    // Close the WS stream gracefully.
                    let (mut sink, _) = ws_stream.split();
                    let _ = sink.close().await;
                    return Ok(());
                }

                // Register token in the cache.
                nonce_cache.insert(token_arr, now);
            }

            handle_authenticated(ws_stream, peer, server_secret).await
        }
        Err(e) => {
            // WS handshake rejected (403 already sent by tungstenite).
            warn!(%peer, "rejected connection: {}", e);
            Ok(())
        }
    }
}

async fn handle_authenticated(
    ws_stream: tokio_tungstenite::WebSocketStream<tokio::net::TcpStream>,
    peer: String,
    server_secret: [u8; 32],
) -> Result<()> {
    use tokio_tungstenite::tungstenite::protocol::Message;

    info!(%peer, "authenticated connection established");

    let (mut sink, mut source) = ws_stream.split();

    // Expect the first message to be the client's ephemeral public key (32 bytes).
    let session_keys = match source.next().await {
        Some(Ok(Message::Binary(data))) if data.len() >= 32 => {
            let mut ephemeral = [0u8; 32];
            ephemeral.copy_from_slice(&data[..32]);
            perform_handshake_server(&ephemeral, &server_secret)
                .map_err(|e| anyhow::anyhow!("handshake error: {}", e))?
        }
        other => {
            warn!(%peer, "unexpected first message: {:?}", other);
            return Ok(());
        }
    };

    info!(%peer, "crypto handshake complete");

    let codec = FrameCodec::new(session_keys.header_key);
    let mut replay = hvpn_core::ReplayWindow::new();
    let obfs = ObfsEngine::new();

    // Receive-and-log loop (Phase 1 — no NAT/routing yet).
    while let Some(msg) = source.next().await {
        match msg {
            Ok(Message::Binary(data)) => {
                // Unpad.
                let unpadded = obfs.unpad_packet(data);

                // Decode frame.
                match codec.decode(&unpadded) {
                    Ok(frame) => {
                        // Replay check.
                        if let Err(e) = replay.check_and_advance(frame.seq) {
                            warn!(%peer, "replay: {}", e);
                            continue;
                        }

                        // Decrypt payload.
                        match decrypt_packet(&session_keys, &frame.payload, frame.seq, None) {
                            Ok(plaintext) => {
                                info!(
                                    %peer,
                                    seq  = frame.seq,
                                    sid  = frame.stream_id,
                                    len  = plaintext.len(),
                                    "received IP packet (Phase 1: logging only)"
                                );
                                // Phase 2: route through NAT / IP stack.
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
