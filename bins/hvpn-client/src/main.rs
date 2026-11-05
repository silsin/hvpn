use anyhow::{Context, Result};
use clap::Parser;
use std::path::PathBuf;
use tokio::signal;
use tracing::info;

use hvpn_common::Config;
use hvpn_core::{FrameCodec, FrameType, Frame};
use hvpn_crypto::{perform_handshake_client, encrypt_packet};
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
    let raw = tokio::fs::read_to_string(&cli.config)
        .await
        .with_context(|| format!("reading config file {:?}", cli.config))?;
    let cfg = Config::from_toml_str(&raw)
        .with_context(|| "parsing config file")?;

    info!(
        server = %cfg.server_address,
        port   = cfg.server_port,
        "starting HVPN client"
    );

    // NOTE: In Phase 1 we use StubTun so the binary compiles and runs on any
    // platform, including the development machine.  The Linux /dev/net/tun
    // path is gated behind #[cfg(target_os = "linux")] inside hvpn-tun.
    let mut tun: Box<dyn TunDevice> = Box::new(StubTun::new());

    // Connect transport.
    let transport_cfg = TransportConfig::new(
        cfg.server_address.clone(),
        cfg.server_port,
        "/hvpn",
    );

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
        ) => res,
    };

    if let Some(t) = transport.as_ref() {
        let _ = t.close().await;
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
) -> Result<()> {
    loop {
        // Read a packet from TUN.
        match tun.read_packet().await {
            Ok(pkt) => {
                // Encrypt.
                let ciphertext = encrypt_packet(keys, &pkt, *seq, None)
                    .context("encrypt failed")?;

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
                    t.send(padded).await.context("send failed")?;
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
