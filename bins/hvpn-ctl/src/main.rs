use anyhow::{bail, Context};
use clap::{Parser, Subcommand};
use serde_json::{json, Value};

/// Windows named pipe the daemon listens on (`\\.\pipe\hvpn`).
#[cfg(windows)]
const PIPE_NAME: &str = r"\\.\pipe\hvpn";

/// Unix domain socket path the daemon listens on (`/tmp/hvpn.sock`).
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

// ── Shared command building ────────────────────────────────────────────────────

/// Build the JSON command object for a given CLI subcommand.  Identical across
/// platforms — only the transport used to send it differs.
fn build_command(command: &Cmd) -> Value {
    match command {
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
    }
}

/// Pretty-print a JSON response, surfacing any daemon-reported error.
fn print_response(response: &Value) -> anyhow::Result<()> {
    println!("{}", serde_json::to_string_pretty(response)?);
    Ok(())
}

// ── Unix (Unix domain socket) ──────────────────────────────────────────────────

#[cfg(unix)]
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let cli = Cli::parse();
    let cmd = build_command(&cli.command);
    let response = send_command(cmd).await?;
    print_response(&response)
}

/// Connect to the daemon's Unix socket, send one JSON command line, and read
/// one JSON response line back.
#[cfg(unix)]
async fn send_command(cmd: Value) -> anyhow::Result<Value> {
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    use tokio::net::UnixStream;

    let stream = UnixStream::connect(SOCK_PATH).await.with_context(|| {
        format!("connecting to daemon socket {SOCK_PATH} (is hvpn-client running?)")
    })?;

    let (reader, mut writer) = tokio::io::split(stream);

    let mut line = serde_json::to_string(&cmd)?;
    line.push('\n');
    writer.write_all(line.as_bytes()).await.context("writing command")?;

    let mut buf_reader = BufReader::new(reader);
    let mut resp_line = String::new();
    buf_reader
        .read_line(&mut resp_line)
        .await
        .context("reading response")?;

    finish_response(resp_line)
}

// ── Windows (named pipe) ───────────────────────────────────────────────────────

#[cfg(windows)]
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let cli = Cli::parse();
    let cmd = build_command(&cli.command);
    let response = send_command(cmd).await?;
    print_response(&response)
}

/// Connect to the daemon's named pipe (`\\.\pipe\hvpn`), send one JSON command
/// line, and read one JSON response line back.  Retries briefly if all pipe
/// instances are momentarily busy.
#[cfg(windows)]
async fn send_command(cmd: Value) -> anyhow::Result<Value> {
    use std::time::Duration;
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    use tokio::net::windows::named_pipe::ClientOptions;

    // ERROR_PIPE_BUSY: the pipe exists but all instances are in use. Retry a
    // few times before giving up so a brief busy state doesn't fail the CLI.
    const ERROR_PIPE_BUSY: i32 = 231;

    let mut client = loop {
        match ClientOptions::new().open(PIPE_NAME) {
            Ok(c) => break c,
            Err(e) if e.raw_os_error() == Some(ERROR_PIPE_BUSY) => {
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
            Err(e) => {
                bail!(
                    "connecting to daemon pipe {} (is hvpn-client running?): {}",
                    PIPE_NAME,
                    e
                );
            }
        }
    };

    let mut line = serde_json::to_string(&cmd)?;
    line.push('\n');
    client.write_all(line.as_bytes()).await.context("writing command")?;

    let mut buf_reader = BufReader::new(client);
    let mut resp_line = String::new();
    buf_reader
        .read_line(&mut resp_line)
        .await
        .context("reading response")?;

    finish_response(resp_line)
}

// ── Shared response parsing ────────────────────────────────────────────────────

/// Parse the single response line and surface daemon-reported errors.
fn finish_response(resp_line: String) -> anyhow::Result<Value> {
    if resp_line.is_empty() {
        bail!("daemon closed connection without a response");
    }

    let resp: Value = serde_json::from_str(resp_line.trim()).context("parsing response JSON")?;

    if let Some(false) = resp.get("ok").and_then(Value::as_bool) {
        let msg = resp
            .get("error")
            .and_then(Value::as_str)
            .unwrap_or("unknown error");
        bail!("daemon error: {msg}");
    }

    Ok(resp)
}

// ── Unsupported platforms ───────────────────────────────────────────────────────

#[cfg(not(any(unix, windows)))]
fn main() {
    eprintln!("hvpn-ctl: control socket is not supported on this platform.");
    std::process::exit(1);
}
