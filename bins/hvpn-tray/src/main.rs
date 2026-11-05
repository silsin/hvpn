//! HVPN GUI tray application (Windows-only).
//!
//! Shows a system-tray icon reflecting the daemon connection state
//! (green = connected, yellow = connecting, red = disconnected) and offers a
//! context menu to connect / disconnect / check status / switch transport /
//! exit.  It talks to the running `hvpn-client` daemon over the `\\.\pipe\hvpn`
//! named pipe using the same JSON newline-delimited protocol as `hvpn-ctl`.
//!
//! A background worker thread owns a Tokio runtime for the (blocking) named
//! pipe I/O; the foreground thread runs the `tao` Win32 event loop and owns
//! the tray icon (which must live on the event-loop thread).  Status updates
//! flow from the worker to the loop via the `tao` `EventLoopProxy`; commands
//! flow the other way through a `tokio::sync::mpsc` channel.

#[cfg(target_os = "windows")]
use std::sync::{Arc, Mutex};
#[cfg(target_os = "windows")]
use std::time::Duration;

#[cfg(target_os = "windows")]
use serde_json::{json, Value};
#[cfg(target_os = "windows")]
use tao::event::{Event, StartCause};
#[cfg(target_os = "windows")]
use tao::event_loop::{ControlFlow, EventLoop, EventLoopProxy};
#[cfg(target_os = "windows")]
use tokio::sync::mpsc;
#[cfg(target_os = "windows")]
use tray_icon::menu::{Menu, MenuEvent, MenuItem, PredefinedMenuItem, Submenu};
#[cfg(target_os = "windows")]
use tray_icon::{Icon, TrayIcon, TrayIconBuilder};
#[cfg(target_os = "windows")]
use tracing::{error, info, warn};

#[cfg(target_os = "windows")]
use anyhow::Context as _;

/// Named pipe the daemon listens on.
#[cfg(target_os = "windows")]
const PIPE_NAME: &str = r"\\.\pipe\hvpn";

/// Config path the "Connect" menu item sends to the daemon.
#[cfg(target_os = "windows")]
const DEFAULT_CONFIG: &str = r"C:\Program Files\HVPN\client.toml";

/// Tray icon RGBA colors (32x32 solid squares).
#[cfg(target_os = "windows")]
const COLOR_CONNECTED: [u8; 4] = [0, 200, 0, 255];
#[cfg(target_os = "windows")]
const COLOR_DISCONNECTED: [u8; 4] = [200, 0, 0, 255];
#[cfg(target_os = "windows")]
const COLOR_CONNECTING: [u8; 4] = [200, 200, 0, 255];

// ── Windows entry point ────────────────────────────────────────────────────────

#[cfg(target_os = "windows")]
fn main() {
    if let Err(e) = try_main() {
        eprintln!("hvpn-tray: {e:?}");
    }
}

#[cfg(target_os = "windows")]
fn try_main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive("hvpn_tray=info".parse()?),
        )
        .init();

    info!("starting HVPN tray app");

    // tao event loop (carries no payload; we wake it with `()` events).
    let event_loop = EventLoop::new();
    let proxy = event_loop.create_proxy();

    // Command channel: event loop (menu clicks) -> worker thread.
    let (cmd_tx, cmd_rx) = mpsc::channel::<TrayCmd>(32);
    // Shared latest connection state: worker -> event loop.
    let latest_connected = Arc::new(Mutex::new(false));

    // Spawn the background control worker (owns the Tokio runtime).
    let worker_proxy = proxy.clone();
    let worker_latest = Arc::clone(&latest_connected);
    std::thread::Builder::new()
        .name("hvpn-tray-ctl".to_string())
        .spawn(move || control_worker(worker_proxy, cmd_rx, worker_latest))
        .context("failed to spawn control worker")?;

    let menu_receiver = MenuEvent::receiver();

    // Mutable tray state, owned by the event-loop thread.
    let mut state = TrayState {
        tray: None,
        items: None,
        conn: ConnState::Disconnected,
    };

    event_loop.run(move |event, _target, control_flow| {
        *control_flow = ControlFlow::Wait;

        match event {
            Event::NewEvents(cause) => {
                // Build the tray icon once the loop is actually running.
                if matches!(cause, StartCause::Init) {
                    let items = build_items();
                    let menu = build_menu(&items);
                    match TrayIconBuilder::new()
                        .with_menu(Box::new(menu))
                        .with_tooltip("HVPN Client")
                        .with_icon(icon_for(state.conn))
                        .build()
                    {
                        Ok(tray) => {
                            state.tray = Some(tray);
                            state.items = Some(items);
                        }
                        Err(e) => {
                            error!("failed to build tray icon: {e:?}");
                        }
                    }
                }

                // Poll any queued menu events.
                while let Ok(ev) = menu_receiver.try_recv() {
                    handle_menu_event(&ev, &mut state, &cmd_tx, control_flow);
                }
            }
            Event::UserEvent(()) => {
                let connected = latest_connected.lock().map(|g| *g).unwrap_or(false);
                state.conn = if connected {
                    ConnState::Connected
                } else {
                    ConnState::Disconnected
                };
                if let Some(tray) = &state.tray {
                    let _ = tray.set_icon(Some(icon_for(state.conn)));
                    let _ = tray.set_tooltip(Some(tooltip_for(state.conn)));
                }
            }
            _ => {}
        }
    });
}

// ── Menu ──────────────────────────────────────────────────────────────────────

#[cfg(target_os = "windows")]
struct TrayItems {
    connect: MenuItem,
    disconnect: MenuItem,
    status: MenuItem,
    ws: MenuItem,
    h2: MenuItem,
    grpc: MenuItem,
    exit: MenuItem,
}

#[cfg(target_os = "windows")]
fn build_items() -> TrayItems {
    TrayItems {
        connect: MenuItem::new("Connect", true, None),
        disconnect: MenuItem::new("Disconnect", true, None),
        status: MenuItem::new("Status", true, None),
        ws: MenuItem::new("WebSocket", true, None),
        h2: MenuItem::new("HTTP/2", true, None),
        grpc: MenuItem::new("gRPC", true, None),
        exit: MenuItem::new("Exit", true, None),
    }
}

#[cfg(target_os = "windows")]
fn build_menu(items: &TrayItems) -> Menu {
    let menu = Menu::new();
    let _ = menu.append(&items.connect);
    let _ = menu.append(&items.disconnect);
    let _ = menu.append(&items.status);
    let _ = menu.append(&PredefinedMenuItem::separator());
    if let Ok(transport) =
        Submenu::with_items("Transport", true, &[&items.ws, &items.h2, &items.grpc])
    {
        let _ = menu.append(&transport);
    }
    let _ = menu.append(&PredefinedMenuItem::separator());
    let _ = menu.append(&items.exit);
    menu
}

/// Decide which (if any) action a menu event corresponds to.  Done in a
/// separate borrowed scope so the `items` borrow ends before we mutate state.
#[derive(Debug)]
#[cfg(target_os = "windows")]
enum TrayAction {
    Connect,
    Disconnect,
    Status,
    Switch(String),
    Exit,
}

#[cfg(target_os = "windows")]
fn handle_menu_event(
    ev: &MenuEvent,
    state: &mut TrayState,
    cmd_tx: &mpsc::Sender<TrayCmd>,
    control_flow: &mut ControlFlow,
) {
    let action = match &state.items {
        Some(items) => {
            let id = &ev.id;
            if id == items.connect.id() {
                Some(TrayAction::Connect)
            } else if id == items.disconnect.id() {
                Some(TrayAction::Disconnect)
            } else if id == items.status.id() {
                Some(TrayAction::Status)
            } else if id == items.ws.id() {
                Some(TrayAction::Switch("websocket".to_string()))
            } else if id == items.h2.id() {
                Some(TrayAction::Switch("http2".to_string()))
            } else if id == items.grpc.id() {
                Some(TrayAction::Switch("grpc".to_string()))
            } else if id == items.exit.id() {
                Some(TrayAction::Exit)
            } else {
                None
            }
        }
        None => None,
    };

    match action {
        Some(TrayAction::Connect) => {
            let _ = cmd_tx.blocking_send(TrayCmd::Connect(DEFAULT_CONFIG.to_string()));
            // Optimistically show the connecting state until the next poll.
            state.conn = ConnState::Connecting;
            if let Some(tray) = &state.tray {
                let _ = tray.set_icon(Some(icon_for(state.conn)));
                let _ = tray.set_tooltip(Some(tooltip_for(state.conn)));
            }
        }
        Some(TrayAction::Disconnect) => {
            let _ = cmd_tx.blocking_send(TrayCmd::Disconnect);
        }
        Some(TrayAction::Status) => {
            let _ = cmd_tx.blocking_send(TrayCmd::Status);
        }
        Some(TrayAction::Switch(kind)) => {
            let _ = cmd_tx.blocking_send(TrayCmd::SwitchTransport(kind));
        }
        Some(TrayAction::Exit) => {
            info!("exit requested");
            *control_flow = ControlFlow::Exit;
        }
        None => {}
    }
}

// ── State / icons ──────────────────────────────────────────────────────────────

#[cfg(target_os = "windows")]
#[derive(Default, Clone, Copy)]
enum ConnState {
    #[default]
    Disconnected,
    Connected,
    Connecting,
}

#[cfg(target_os = "windows")]
struct TrayState {
    tray: Option<TrayIcon>,
    items: Option<TrayItems>,
    conn: ConnState,
}

#[cfg(target_os = "windows")]
fn solid_icon(color: [u8; 4]) -> Icon {
    let mut rgba = Vec::with_capacity(32 * 32 * 4);
    for _ in 0..(32 * 32) {
        rgba.extend_from_slice(&color);
    }
    Icon::from_rgba(rgba, 32, 32).expect("invalid icon rgba buffer")
}

#[cfg(target_os = "windows")]
fn icon_for(conn: ConnState) -> Icon {
    match conn {
        ConnState::Connected => solid_icon(COLOR_CONNECTED),
        ConnState::Disconnected => solid_icon(COLOR_DISCONNECTED),
        ConnState::Connecting => solid_icon(COLOR_CONNECTING),
    }
}

#[cfg(target_os = "windows")]
fn tooltip_for(conn: ConnState) -> String {
    match conn {
        ConnState::Connected => "HVPN Client — connected".to_string(),
        ConnState::Disconnected => "HVPN Client — disconnected".to_string(),
        ConnState::Connecting => "HVPN Client — connecting".to_string(),
    }
}

// ── Worker thread (named-pipe control I/O) ─────────────────────────────────────

#[derive(Debug)]
#[cfg(target_os = "windows")]
enum TrayCmd {
    Status,
    Connect(String),
    Disconnect,
    SwitchTransport(String),
}

#[cfg(target_os = "windows")]
fn control_worker(proxy: EventLoopProxy<()>, mut cmd_rx: mpsc::Receiver<TrayCmd>, latest: Arc<Mutex<bool>>) {
    let rt = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            error!("failed to create tokio runtime for control worker: {e}");
            return;
        }
    };

    rt.block_on(async move {
        let mut ticker = tokio::time::interval(Duration::from_secs(5));
        loop {
            tokio::select! {
                _ = ticker.tick() => {
                    if let Some(resp) = send_command(json!({"cmd": "status"})).await {
                        publish_status(&resp, &proxy, &latest);
                    }
                }
                Some(cmd) = cmd_rx.recv() => {
                    let req = match &cmd {
                        TrayCmd::Status => json!({"cmd": "status"}),
                        TrayCmd::Connect(path) => json!({"cmd": "connect", "config": path}),
                        TrayCmd::Disconnect => json!({"cmd": "disconnect"}),
                        TrayCmd::SwitchTransport(k) => json!({"cmd": "switch-transport", "kind": k}),
                    };
                    let resp = send_command(req).await;
                    if matches!(cmd, TrayCmd::Status) {
                        if let Some(r) = resp {
                            publish_status(&r, &proxy, &latest);
                        }
                    }
                }
            }
        }
    });
}

/// Extract the `connected` flag from a status response, stash it in the shared
/// state, and wake the event loop so the icon updates.
#[cfg(target_os = "windows")]
fn publish_status(resp: &Value, proxy: &EventLoopProxy<()>, latest: &Arc<Mutex<bool>>) {
    let connected = resp
        .get("status")
        .and_then(|s| s.get("connected"))
        .and_then(Value::as_bool)
        .unwrap_or(false);
    if let Ok(mut guard) = latest.lock() {
        *guard = connected;
    }
    let _ = proxy.send_event(());
}

/// Send one JSON command to the daemon over the named pipe and return the
/// parsed JSON response, or `None` on any error.
#[cfg(target_os = "windows")]
async fn send_command(cmd: Value) -> Option<Value> {
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    use tokio::net::windows::named_pipe::ClientOptions;

    // ERROR_PIPE_BUSY: the pipe exists but all instances are in use.
    const ERROR_PIPE_BUSY: i32 = 231;

    let mut client = loop {
        match ClientOptions::new().open(PIPE_NAME) {
            Ok(c) => break c,
            Err(e) if e.raw_os_error() == Some(ERROR_PIPE_BUSY) => {
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
            Err(_) => return None,
        }
    };

    let mut line = serde_json::to_string(&cmd).ok()?;
    line.push('\n');
    if client.write_all(line.as_bytes()).await.is_err() {
        return None;
    }

    let mut reader = BufReader::new(client);
    let mut resp = String::new();
    if reader.read_line(&mut resp).await.is_err() {
        return None;
    }

    match serde_json::from_str(resp.trim()) {
        Ok(v) => Some(v),
        Err(e) => {
            warn!("invalid daemon response: {e}");
            None
        }
    }
}

// ── Non-Windows stub ──────────────────────────────────────────────────────────

#[cfg(not(target_os = "windows"))]
fn main() {
    println!("Tray app is Windows-only");
}
