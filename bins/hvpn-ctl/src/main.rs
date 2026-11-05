use clap::{Parser, Subcommand};

#[cfg(unix)]
const SOCK_PATH: &str = "/tmp/hvpn.sock";

/// HVPN management CLI — communicates with the running hvpn-client daemon.
#[derive(Parser, Debug)]
#[command(name = "hvpn-ctl", version, about)]
struct Cli {
    #[command(subcommand)]
    command: Cmd,
}

#[derive(Subcommand, Debug)]
enum Cmd {
    /// Print connection status (connected/disconnected, transport, RTT, bytes, streams).
    Status,

    /// Send a connect command to the daemon.
    Connect {
        /// Path to the TOML configuration file.
        #[arg(long)]
        config: String,
    },

    /// Send a disconnect command to the daemon.
    Disconnect,

    /// Force a transport switch.
    SwitchTransport {
        /// Transport kind: websocket, http2, or grpc.
        kind: String,
    },

    /// Relay chain management.
    Relay {
        #[command(subcommand)]
        action: RelayCmd,
    },
}

#[derive(Subcommand, Debug)]
enum RelayCmd {
    /// Add a relay hop to the chain.
    Add {
        /// Address of the relay node (host:port).
        address: String,
        /// Hex-encoded 32-byte public key of the relay node.
        pubkey_hex: String,
    },
    /// Clear the relay chain (go direct).
    Clear,
}

// ── Platform gate ──────────────────────────────────────────────────────────────

#[cfg(not(unix))]
fn main() {
    eprintln!("hvpn-ctl: Unix socket control is not supported on this platform.");
    std::process::exit(1);
}

#[cfg(unix)]
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    use serde_json::json;

    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let cli = Cli::parse();

    let cmd_json = match &cli.command {
        Cmd::Status => json!({"cmd": "status"}),
        Cmd::Connect { config } => json!({"cmd": "connect", "config": config}),
        Cmd::Disconnect => json!({"cmd": "disconnect"}),
        Cmd::SwitchTransport { kind } => json!({"cmd": "switch-transport", "kind": kind}),
        Cmd::Relay { action } => match action {
            RelayCmd::Add { address, pubkey_hex } => {
                json!({"cmd": "relay-add", "address": address, "pubkey_hex": pubkey_hex})
            }
            RelayCmd::Clear => json!({"cmd": "relay-clear"}),
        },
    };

    let response = send_command(cmd_json).await?;
    println!("{}", serde_json::to_string_pretty(&response)?);
    Ok(())
}

/// Connect to the daemon's Unix socket, send one JSON command line, and read
/// one JSON response line back.
#[cfg(unix)]
async fn send_command(cmd: serde_json::Value) -> anyhow::Result<serde_json::Value> {
    use anyhow::{bail, Context};
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    use tokio::net::UnixStream;

    let stream = UnixStream::connect(SOCK_PATH)
        .await
        .with_context(|| format!("connecting to daemon socket {SOCK_PATH} (is hvpn-client running?)"))?;

    let (reader, mut writer) = tokio::io::split(stream);

    // Send command followed by newline.
    let mut line = serde_json::to_string(&cmd)?;
    line.push('\n');
    writer.write_all(line.as_bytes()).await.context("writing command")?;

    // Read one response line.
    let mut buf_reader = BufReader::new(reader);
    let mut resp_line = String::new();
    buf_reader
        .read_line(&mut resp_line)
        .await
        .context("reading response")?;

    if resp_line.is_empty() {
        bail!("daemon closed connection without a response");
    }

    let resp: serde_json::Value =
        serde_json::from_str(resp_line.trim()).context("parsing response JSON")?;

    // Surface daemon-reported errors.
    if let Some(false) = resp.get("ok").and_then(serde_json::Value::as_bool) {
        let msg = resp
            .get("error")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("unknown error");
        bail!("daemon error: {msg}");
    }

    Ok(resp)
}
