use anyhow::{Context, Result};
use clap::Parser;
use futures_util::{SinkExt, StreamExt};
use std::path::PathBuf;
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

/// Static HTML served to unauthenticated probes (200 OK decoy page).
/// Phase 2 will wire this up to the raw TCP fallback path.
#[allow(dead_code)]
const DECOY_PAGE: &[u8] = b"HTTP/1.1 200 OK\r\n\
Content-Type: text/html\r\n\
Connection: close\r\n\
\r\n\
<!DOCTYPE html><html><head><title>Welcome</title></head>\
<body><h1>Welcome</h1><p>Nothing to see here.</p></body></html>\r\n";

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
        use hvpn_crypto::perform_handshake_server;
        // Use a known dummy ephemeral key to get a mac_key.
        let dummy_ephemeral = [0xFFu8; 32];
        match perform_handshake_server(&dummy_ephemeral, &server_secret_bytes) {
            Ok(k) => k.mac_key,
            Err(_) => [0xABu8; 32],
        }
    };

    loop {
        let (stream, peer_addr) = listener.accept().await?;
        info!(%peer_addr, "accepted TCP connection");

        let mac_key_clone = mac_key;
        let server_secret = server_secret_bytes;

        tokio::spawn(async move {
            if let Err(e) =
                handle_connection(stream, peer_addr.to_string(), mac_key_clone, server_secret)
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
) -> Result<()> {
    // Peek at the first bytes to decide if this is an HTTP upgrade or a raw probe.
    // In Phase 1 we accept the WebSocket upgrade without TLS (plain TCP).
    // Full TLS termination arrives in Phase 2 when cert paths are wired up.

    // Perform WebSocket server handshake.
    let ws_stream_result =
        tokio_tungstenite::accept_hdr_async(stream, |req: &tokio_tungstenite::tungstenite::handshake::server::Request, mut resp: tokio_tungstenite::tungstenite::handshake::server::Response| {
            // Probe defense: check X-Auth-Token header.
            let token_valid = req
                .headers()
                .get("x-auth-token")
                .and_then(|v| v.to_str().ok())
                .map(|hex| {
                    // Parse the hex token and verify against current time window.
                    let bytes = hex_decode(hex);
                    if bytes.len() == 32 {
                        let ts = current_timestamp_secs();
                        let nonce = [0u8; 16]; // Phase 1: fixed nonce
                        // Accept tokens within a 30-second window.
                        for delta in 0u64..3 {
                            let expected = generate_probe_token(&mac_key, ts.saturating_sub(delta * 10), &nonce);
                            if bytes.as_slice() == expected.as_slice() {
                                return true;
                            }
                        }
                    }
                    false
                })
                .unwrap_or(false);

            if !token_valid {
                // Return 403 to signal rejection; the raw-TCP decoy page is
                // served below when the stream is still a plain TCP stream.
                *resp.status_mut() = http::StatusCode::FORBIDDEN;
            }

            Ok(resp)
        })
        .await;

    match ws_stream_result {
        Ok(ws_stream) => {
            handle_authenticated(ws_stream, peer, server_secret).await
        }
        Err(e) => {
            // WS handshake rejected — this is expected for probes.
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
