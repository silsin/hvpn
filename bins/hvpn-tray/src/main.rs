//! HVPN GUI tray application (Windows-only).
//!
//! Shows a system-tray icon reflecting the daemon connection state and offers
//! a context menu to connect / disconnect / open settings / exit.
//! On first run (no saved profiles), opens the First-Run Wizard WebView window.
//! Talks to `hvpn-client` over `\\.\pipe\hvpn`.

#[cfg(target_os = "windows")]
use std::sync::{Arc, Mutex};
#[cfg(target_os = "windows")]
use std::time::Duration;

#[cfg(target_os = "windows")]
use serde_json::{json, Value};
#[cfg(target_os = "windows")]
use tao::event::{Event, StartCause};
#[cfg(target_os = "windows")]
use tao::event_loop::{ControlFlow, EventLoopBuilder, EventLoopProxy};
#[cfg(target_os = "windows")]
use tokio::sync::mpsc;
#[cfg(target_os = "windows")]
use tray_icon::menu::{Menu, MenuEvent, MenuItem, PredefinedMenuItem};
#[cfg(target_os = "windows")]
use tray_icon::{Icon, TrayIcon, TrayIconBuilder};
#[cfg(target_os = "windows")]
use tracing::{error, info, warn};
#[cfg(target_os = "windows")]
use anyhow::Context as _;

/// Named pipe the daemon listens on.
#[cfg(target_os = "windows")]
const PIPE_NAME: &str = r"\\.\pipe\hvpn";

/// Tray icon RGBA colors (32x32 solid squares).
#[cfg(target_os = "windows")]
const COLOR_CONNECTED: [u8; 4] = [0, 200, 0, 255];
#[cfg(target_os = "windows")]
const COLOR_DISCONNECTED: [u8; 4] = [200, 0, 0, 255];
#[cfg(target_os = "windows")]
const COLOR_CONNECTING: [u8; 4] = [200, 200, 0, 255];

// ── Embedded HTML ─────────────────────────────────────────────────────────────

#[cfg(target_os = "windows")]
const WIZARD_HTML: &str = r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>HVPN Setup</title>
<style>
  * { box-sizing: border-box; margin: 0; padding: 0; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; }
  body { background: #0f0f1a; color: #e0e0ff; height: 100vh; display: flex; align-items: center; justify-content: center; }
  .page { display: none; flex-direction: column; align-items: center; justify-content: center; width: 100%; padding: 40px; text-align: center; }
  .page.active { display: flex; }
  .logo { font-size: 64px; margin-bottom: 16px; }
  h1 { font-size: 28px; font-weight: 700; margin-bottom: 8px; }
  .tagline { color: #8888bb; margin-bottom: 40px; font-size: 16px; }
  .btn { background: #6c63ff; color: white; border: none; border-radius: 8px; padding: 14px 32px; font-size: 16px; cursor: pointer; transition: background 0.2s; }
  .btn:hover { background: #574fd6; }
  .tabs { display: flex; gap: 0; margin-bottom: 20px; border-radius: 8px; overflow: hidden; border: 1px solid #333; }
  .tab { flex: 1; padding: 10px; background: #1a1a2e; border: none; color: #8888bb; cursor: pointer; font-size: 14px; }
  .tab.active { background: #6c63ff; color: white; }
  .tab-content { display: none; width: 100%; }
  .tab-content.active { display: block; }
  video, canvas { width: 100%; max-height: 220px; border-radius: 8px; background: #000; }
  canvas { display: none; }
  textarea { width: 100%; height: 80px; background: #1a1a2e; border: 1px solid #333; border-radius: 8px; color: #e0e0ff; padding: 10px; font-family: monospace; font-size: 12px; resize: none; margin-bottom: 12px; }
  .success-icon { font-size: 64px; margin-bottom: 16px; }
  .server-addr { color: #8888bb; margin-bottom: 20px; font-size: 14px; }
  a { color: #6c63ff; cursor: pointer; text-decoration: underline; }
</style>
</head>
<body>
<div id="page1" class="page active">
  <div class="logo">🔒 HVPN</div>
  <h1>Welcome</h1>
  <div class="tagline">Secure. Private. Simple.</div>
  <button class="btn" onclick="showPage(2)">Get Started →</button>
</div>
<div id="page2" class="page">
  <h1 style="margin-bottom:20px">Connect to Server</h1>
  <div class="tabs">
    <button class="tab active" onclick="switchTab('qr')">Scan QR Code</button>
    <button class="tab" onclick="switchTab('paste')">Paste Code</button>
  </div>
  <div id="tab-qr" class="tab-content active">
    <video id="vid" autoplay playsinline></video>
    <canvas id="cvs"></canvas>
    <p style="margin-top:10px; color:#8888bb; font-size:12px">Point your camera at the QR code shown on the server</p>
  </div>
  <div id="tab-paste" class="tab-content">
    <textarea id="connstr" placeholder="Paste your connection string here..."></textarea>
    <button class="btn" onclick="submitPaste()">Connect</button>
  </div>
</div>
<div id="page3" class="page">
  <div class="success-icon">&#x2705;</div>
  <h1>You're protected</h1>
  <div class="server-addr" id="connectedServer"></div>
  <a onclick="openSettings()">Open Settings</a>
  <br><br>
  <button class="btn" onclick="window.ipc.postMessage(JSON.stringify({type:'close_wizard'}))">Done</button>
</div>
<script src="https://cdn.jsdelivr.net/npm/jsqr@1.4.0/dist/jsQR.js"></script>
<script>
let scanning = false;
function showPage(n) {
  document.querySelectorAll('.page').forEach(p => p.classList.remove('active'));
  document.getElementById('page'+n).classList.add('active');
  if (n === 2) startQR();
}
function switchTab(t) {
  document.querySelectorAll('.tab').forEach((b,i) => b.classList.toggle('active', ['qr','paste'][i]===t));
  document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
  document.getElementById('tab-'+t).classList.add('active');
  if (t === 'qr') startQR(); else stopQR();
}
function startQR() {
  if (scanning) return;
  navigator.mediaDevices.getUserMedia({video:true}).then(stream => {
    const vid = document.getElementById('vid');
    vid.srcObject = stream;
    scanning = true;
    requestAnimationFrame(tick);
  }).catch(() => {});
}
function stopQR() {
  scanning = false;
  const vid = document.getElementById('vid');
  if (vid.srcObject) { vid.srcObject.getTracks().forEach(t => t.stop()); vid.srcObject = null; }
}
function tick() {
  if (!scanning) return;
  const vid = document.getElementById('vid');
  const cvs = document.getElementById('cvs');
  if (vid.readyState === vid.HAVE_ENOUGH_DATA) {
    cvs.width = vid.videoWidth; cvs.height = vid.videoHeight;
    const ctx = cvs.getContext('2d');
    ctx.drawImage(vid, 0, 0);
    const d = ctx.getImageData(0,0,cvs.width,cvs.height);
    const code = jsQR(d.data, d.width, d.height);
    if (code) { scanning = false; window.ipc.postMessage(JSON.stringify({type:'qr_scanned', data: code.data})); return; }
  }
  requestAnimationFrame(tick);
}
function submitPaste() {
  const v = document.getElementById('connstr').value.trim();
  if (v) window.ipc.postMessage(JSON.stringify({type:'connect_string', data: v}));
}
function openSettings() {
  window.ipc.postMessage(JSON.stringify({type:'open_settings'}));
}
function onConnected(server) {
  document.getElementById('connectedServer').textContent = 'Connected to ' + server;
  showPage(3);
}
</script>
</body>
</html>"#;

#[cfg(target_os = "windows")]
const SETTINGS_HTML: &str = r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>HVPN Settings</title>
<style>
  * { box-sizing: border-box; margin: 0; padding: 0; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; }
  body { background: #0f0f1a; color: #e0e0ff; padding: 24px; overflow-y: auto; }
  h2 { font-size: 20px; margin-bottom: 16px; border-bottom: 1px solid #333; padding-bottom: 8px; }
  h3 { font-size: 14px; color: #8888bb; text-transform: uppercase; letter-spacing: 1px; margin: 20px 0 10px; }
  .row { display: flex; align-items: center; justify-content: space-between; margin-bottom: 12px; }
  label { font-size: 14px; }
  select, input[type=text] { background: #1a1a2e; border: 1px solid #333; color: #e0e0ff; border-radius: 6px; padding: 6px 10px; font-size: 14px; }
  .toggle { position: relative; width: 44px; height: 24px; }
  .toggle input { opacity: 0; width: 0; height: 0; }
  .slider { position: absolute; inset: 0; background: #333; border-radius: 24px; cursor: pointer; transition: 0.2s; }
  .slider:before { content: ''; position: absolute; height: 18px; width: 18px; left: 3px; bottom: 3px; background: white; border-radius: 50%; transition: 0.2s; }
  input:checked + .slider { background: #6c63ff; }
  input:checked + .slider:before { transform: translateX(20px); }
  .profile-item { display: flex; align-items: center; justify-content: space-between; background: #1a1a2e; border-radius: 8px; padding: 10px 14px; margin-bottom: 8px; }
  .profile-name { font-size: 14px; }
  .profile-server { font-size: 12px; color: #8888bb; }
  .del-btn { background: none; border: none; color: #ff4466; cursor: pointer; font-size: 16px; }
  .add-btn { background: #6c63ff; color: white; border: none; border-radius: 6px; padding: 8px 16px; font-size: 14px; cursor: pointer; margin-top: 8px; }
  .about-row { color: #8888bb; font-size: 13px; margin-bottom: 6px; }
</style>
</head>
<body>
<h2>&#x2699;&#xFE0F; HVPN Settings</h2>

<h3>Connection</h3>
<div id="profiles"></div>
<button class="add-btn" onclick="addNew()">+ Add New</button>

<h3>Transport</h3>
<div class="row">
  <label>Protocol</label>
  <select onchange="setting('transport', this.value)">
    <option value="auto">Auto</option>
    <option value="websocket">WebSocket</option>
    <option value="http2">HTTP/2</option>
    <option value="grpc">gRPC</option>
  </select>
</div>

<h3>Obfuscation</h3>
<div class="row">
  <label>Steganographic Mode</label>
  <label class="toggle"><input type="checkbox" onchange="setting('stego_mode', this.checked)"><span class="slider"></span></label>
</div>
<div class="row">
  <label>Traffic Profile</label>
  <select onchange="setting('obfs_profile', this.value)">
    <option value="browser">Browser</option>
    <option value="streaming">Streaming</option>
    <option value="voip">VoIP</option>
    <option value="idle">Idle</option>
  </select>
</div>

<h3>Advanced</h3>
<div class="row">
  <label>Post-Quantum Crypto</label>
  <label class="toggle"><input type="checkbox" onchange="setting('post_quantum', this.checked)"><span class="slider"></span></label>
</div>
<div class="row">
  <label>DNS Servers</label>
  <input type="text" placeholder="1.1.1.1, 8.8.8.8" onchange="setting('dns_servers', this.value)">
</div>

<h3>About</h3>
<div class="about-row">HVPN v0.1.0</div>
<div class="about-row" id="buildDate"></div>
<div class="about-row">15 crates</div>

<script>
document.getElementById('buildDate').textContent = 'Built ' + new Date().toLocaleDateString();
function setting(key, value) {
  window.ipc.postMessage(JSON.stringify({type:'setting', key, value: String(value)}));
}
function addNew() {
  window.ipc.postMessage(JSON.stringify({type:'open_wizard'}));
}
function deleteProfile(name) {
  window.ipc.postMessage(JSON.stringify({type:'delete_profile', name}));
}
function renderProfiles(profiles) {
  const el = document.getElementById('profiles');
  el.innerHTML = profiles.map(p => `
    <div class="profile-item">
      <div><div class="profile-name">${p.name||p.server}</div><div class="profile-server">${p.server}:${p.port}</div></div>
      <button class="del-btn" onclick="deleteProfile('${p.name||p.server}')">&#x2715;</button>
    </div>
  `).join('');
}
// Request profiles on load
window.ipc.postMessage(JSON.stringify({type:'get_profiles'}));
</script>
</body>
</html>"#;

// ── Windows entry point ────────────────────────────────────────────────────────

#[cfg(target_os = "windows")]
fn main() {
    if let Err(e) = try_main() {
        eprintln!("hvpn-tray: {e:?}");
    }
}

#[cfg(target_os = "windows")]
#[derive(Debug)]
enum TrayEvent {
    StatusUpdate,
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

    // Load saved profiles — if none, open the wizard on startup.
    let profiles = hvpn_common::load_profiles();
    let has_profiles = !profiles.is_empty();

    // Create the event loop with our custom user-event type.
    let event_loop = EventLoopBuilder::<TrayEvent>::with_user_event().build();
    let proxy = event_loop.create_proxy();

    // Channel: event loop (menu clicks) -> worker thread.
    let (cmd_tx, cmd_rx) = mpsc::channel::<TrayCmd>(32);
    // Shared latest connection state: worker -> event loop.
    let latest_connected = Arc::new(Mutex::new(false));
    // Shared connected-server name.
    let latest_server: Arc<Mutex<String>> = Arc::new(Mutex::new(String::new()));

    // Shared IPC message queue: webview ipc -> event loop.
    let ipc_queue: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));

    // Spawn the background control worker.
    let worker_proxy = proxy.clone();
    let worker_latest = Arc::clone(&latest_connected);
    std::thread::Builder::new()
        .name("hvpn-tray-ctl".to_string())
        .spawn(move || control_worker(worker_proxy, cmd_rx, worker_latest))
        .context("failed to spawn control worker")?;

    let menu_receiver = MenuEvent::receiver();

    // Mutable tray/webview state, owned by the event-loop thread.
    let mut state = TrayState {
        tray: None,
        items: None,
        conn: ConnState::Disconnected,
        server_name: String::new(),
    };

    let mut wizard_window: Option<tao::window::Window> = None;
    let mut wizard_webview: Option<wry::WebView> = None;
    let mut settings_window: Option<tao::window::Window> = None;
    let mut settings_webview: Option<wry::WebView> = None;

    let ipc_queue_ev = Arc::clone(&ipc_queue);

    event_loop.run(move |event, target, control_flow| {
        *control_flow = ControlFlow::Wait;

        match &event {
            Event::NewEvents(cause) => {
                if matches!(cause, StartCause::Init) {
                    // Build tray icon.
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
                        Err(e) => error!("failed to build tray icon: {e:?}"),
                    }

                    // Open wizard if no profiles exist.
                    if !has_profiles {
                        match open_wizard_window(target, Arc::clone(&ipc_queue_ev)) {
                            Ok((win, wv)) => {
                                wizard_window = Some(win);
                                wizard_webview = Some(wv);
                            }
                            Err(e) => error!("failed to open wizard: {e:?}"),
                        }
                    }
                }

                // Poll menu events.
                while let Ok(ev) = menu_receiver.try_recv() {
                    handle_menu_event(
                        &ev, &mut state, &cmd_tx, control_flow, target,
                        &ipc_queue_ev,
                        &mut wizard_window, &mut wizard_webview,
                        &mut settings_window, &mut settings_webview,
                    );
                }

                // Drain IPC queue.
                let msgs: Vec<String> = {
                    let mut q = ipc_queue_ev.lock().unwrap();
                    std::mem::take(&mut *q)
                };
                for msg in msgs {
                    handle_ipc_message(
                        &msg, &mut state, &cmd_tx, &latest_server,
                        &mut wizard_webview, &mut wizard_window,
                        &mut settings_webview, &mut settings_window,
                        target, &ipc_queue_ev,
                    );
                }
            }
            Event::UserEvent(TrayEvent::StatusUpdate) => {
                let connected = latest_connected.lock().map(|g| *g).unwrap_or(false);
                let server = latest_server.lock().map(|g| g.clone()).unwrap_or_default();
                state.conn = if connected { ConnState::Connected } else { ConnState::Disconnected };
                state.server_name = server;
                if let Some(tray) = &state.tray {
                    let _ = tray.set_icon(Some(icon_for(state.conn)));
                    let _ = tray.set_tooltip(Some(tooltip_for(&state)));
                }
            }
            Event::WindowEvent {
                event: tao::event::WindowEvent::CloseRequested,
                window_id,
                ..
            } => {
                if wizard_window.as_ref().map(|w| w.id()) == Some(*window_id) {
                    wizard_webview = None;
                    wizard_window = None;
                }
                if settings_window.as_ref().map(|w| w.id()) == Some(*window_id) {
                    settings_webview = None;
                    settings_window = None;
                }
            }
            _ => {}
        }
    });
}

// ── WebView window helpers ────────────────────────────────────────────────────

#[cfg(target_os = "windows")]
fn open_wizard_window(
    target: &tao::event_loop::EventLoopWindowTarget<TrayEvent>,
    ipc_queue: Arc<Mutex<Vec<String>>>,
) -> anyhow::Result<(tao::window::Window, wry::WebView)> {
    use tao::dpi::LogicalSize;
    use tao::window::WindowBuilder;
    use wry::WebViewBuilder;

    let window = WindowBuilder::new()
        .with_title("HVPN Setup")
        .with_inner_size(LogicalSize::new(480u32, 520u32))
        .with_resizable(false)
        .build(target)?;

    let webview = WebViewBuilder::new(&window)
        .with_html(WIZARD_HTML)
        .with_ipc_handler(move |msg: wry::http::Request<String>| {
            ipc_queue.lock().unwrap().push(msg.body().clone());
        })
        .build()?;

    Ok((window, webview))
}

#[cfg(target_os = "windows")]
fn open_settings_window(
    target: &tao::event_loop::EventLoopWindowTarget<TrayEvent>,
    ipc_queue: Arc<Mutex<Vec<String>>>,
) -> anyhow::Result<(tao::window::Window, wry::WebView)> {
    use tao::dpi::LogicalSize;
    use tao::window::WindowBuilder;
    use wry::WebViewBuilder;

    let window = WindowBuilder::new()
        .with_title("HVPN Settings")
        .with_inner_size(LogicalSize::new(520u32, 600u32))
        .build(target)?;

    let webview = WebViewBuilder::new(&window)
        .with_html(SETTINGS_HTML)
        .with_ipc_handler(move |msg: wry::http::Request<String>| {
            ipc_queue.lock().unwrap().push(msg.body().clone());
        })
        .build()?;

    Ok((window, webview))
}

// ── IPC message handler ───────────────────────────────────────────────────────

#[cfg(target_os = "windows")]
#[allow(clippy::too_many_arguments)]
fn handle_ipc_message(
    msg: &str,
    state: &mut TrayState,
    cmd_tx: &mpsc::Sender<TrayCmd>,
    latest_server: &Arc<Mutex<String>>,
    wizard_webview: &mut Option<wry::WebView>,
    wizard_window: &mut Option<tao::window::Window>,
    settings_webview: &mut Option<wry::WebView>,
    settings_window: &mut Option<tao::window::Window>,
    target: &tao::event_loop::EventLoopWindowTarget<TrayEvent>,
    ipc_queue: &Arc<Mutex<Vec<String>>>,
) {
    let parsed: Value = match serde_json::from_str(msg) {
        Ok(v) => v,
        Err(e) => { warn!("invalid IPC message: {e}"); return; }
    };

    let msg_type = match parsed.get("type").and_then(Value::as_str) {
        Some(t) => t,
        None => return,
    };

    match msg_type {
        "qr_scanned" | "connect_string" => {
            let data = match parsed.get("data").and_then(Value::as_str) {
                Some(d) => d,
                None => return,
            };
            match hvpn_common::ConnectionProfile::from_connection_string(data) {
                Ok(profile) => {
                    let server = profile.server.clone();
                    let mut profiles = hvpn_common::load_profiles();
                    profiles.push(profile);
                    if let Err(e) = hvpn_common::save_profiles(&profiles) {
                        warn!("failed to save profiles: {e}");
                    }
                    let config_path = std::env::var("APPDATA")
                        .map(|a| format!(r"{}\HVPN\client.toml", a))
                        .unwrap_or_else(|_| r"C:\Program Files\HVPN\client.toml".to_string());
                    let _ = cmd_tx.blocking_send(TrayCmd::Connect(config_path));
                    state.conn = ConnState::Connecting;
                    if let Ok(mut s) = latest_server.lock() { *s = server.clone(); }
                    if let Some(wv) = wizard_webview.as_ref() {
                        let js = format!("onConnected('{}')", server.replace('\'', "\\'"));
                        let _ = wv.evaluate_script(&js);
                    }
                }
                Err(e) => warn!("invalid connection string: {e}"),
            }
        }
        "close_wizard" => {
            *wizard_webview = None;
            *wizard_window = None;
        }
        "open_settings" => {
            if settings_webview.is_none() {
                match open_settings_window(target, Arc::clone(ipc_queue)) {
                    Ok((win, wv)) => { *settings_window = Some(win); *settings_webview = Some(wv); }
                    Err(e) => error!("failed to open settings: {e:?}"),
                }
            } else if let Some(sw) = settings_window.as_ref() {
                sw.set_focus();
            }
        }
        "open_wizard" => {
            if wizard_webview.is_none() {
                match open_wizard_window(target, Arc::clone(ipc_queue)) {
                    Ok((win, wv)) => { *wizard_window = Some(win); *wizard_webview = Some(wv); }
                    Err(e) => error!("failed to open wizard: {e:?}"),
                }
            } else if let Some(ww) = wizard_window.as_ref() {
                ww.set_focus();
            }
        }
        "get_profiles" => {
            let profiles = hvpn_common::load_profiles();
            if let Ok(json) = serde_json::to_string(&profiles) {
                if let Some(wv) = settings_webview.as_ref() {
                    let _ = wv.evaluate_script(&format!("renderProfiles({})", json));
                }
            }
        }
        "delete_profile" => {
            let name = match parsed.get("name").and_then(Value::as_str) {
                Some(n) => n,
                None => return,
            };
            let mut profiles = hvpn_common::load_profiles();
            profiles.retain(|p| p.name.as_deref() != Some(name) && p.server != name);
            if let Err(e) = hvpn_common::save_profiles(&profiles) {
                warn!("failed to save profiles: {e}");
            }
            if let Ok(json) = serde_json::to_string(&profiles) {
                if let Some(wv) = settings_webview.as_ref() {
                    let _ = wv.evaluate_script(&format!("renderProfiles({})", json));
                }
            }
        }
        "setting" => {
            let key = match parsed.get("key").and_then(Value::as_str) {
                Some(k) => k,
                None => return,
            };
            let value = match parsed.get("value").and_then(Value::as_str) {
                Some(v) => v,
                None => return,
            };
            let cmd = json!({"cmd": "set_setting", "key": key, "value": value});
            let _ = cmd_tx.blocking_send(TrayCmd::Raw(cmd));
        }
        _ => info!("unhandled IPC message type: {}", msg_type),
    }
}

// ── Menu ──────────────────────────────────────────────────────────────────────

#[cfg(target_os = "windows")]
struct TrayItems {
    status_label: MenuItem,
    connect: MenuItem,
    disconnect: MenuItem,
    settings: MenuItem,
    exit: MenuItem,
}

#[cfg(target_os = "windows")]
fn build_items() -> TrayItems {
    TrayItems {
        status_label: MenuItem::new("🔴 Disconnected", false, None),
        connect: MenuItem::new("Connect", true, None),
        disconnect: MenuItem::new("Disconnect", false, None),
        settings: MenuItem::new("Settings...", true, None),
        exit: MenuItem::new("Exit", true, None),
    }
}

#[cfg(target_os = "windows")]
fn build_menu(items: &TrayItems) -> Menu {
    let menu = Menu::new();
    let _ = menu.append(&items.status_label);
    let _ = menu.append(&PredefinedMenuItem::separator());
    let _ = menu.append(&items.connect);
    let _ = menu.append(&items.disconnect);
    let _ = menu.append(&items.settings);
    let _ = menu.append(&PredefinedMenuItem::separator());
    let _ = menu.append(&items.exit);
    menu
}

#[cfg(target_os = "windows")]
#[derive(Debug)]
enum TrayAction {
    Connect,
    Disconnect,
    Settings,
    Exit,
}

#[cfg(target_os = "windows")]
#[allow(clippy::too_many_arguments)]
fn handle_menu_event(
    ev: &MenuEvent,
    state: &mut TrayState,
    cmd_tx: &mpsc::Sender<TrayCmd>,
    control_flow: &mut ControlFlow,
    target: &tao::event_loop::EventLoopWindowTarget<TrayEvent>,
    ipc_queue: &Arc<Mutex<Vec<String>>>,
    _wizard_window: &mut Option<tao::window::Window>,
    _wizard_webview: &mut Option<wry::WebView>,
    settings_window: &mut Option<tao::window::Window>,
    settings_webview: &mut Option<wry::WebView>,
) {
    let action = state.items.as_ref().and_then(|items| {
        let id = &ev.id;
        if id == items.connect.id() { Some(TrayAction::Connect) }
        else if id == items.disconnect.id() { Some(TrayAction::Disconnect) }
        else if id == items.settings.id() { Some(TrayAction::Settings) }
        else if id == items.exit.id() { Some(TrayAction::Exit) }
        else { None }
    });

    match action {
        Some(TrayAction::Connect) => {
            let config_path = std::env::var("APPDATA")
                .map(|a| format!(r"{}\HVPN\client.toml", a))
                .unwrap_or_else(|_| r"C:\Program Files\HVPN\client.toml".to_string());
            let _ = cmd_tx.blocking_send(TrayCmd::Connect(config_path));
            state.conn = ConnState::Connecting;
            if let Some(tray) = &state.tray {
                let _ = tray.set_icon(Some(icon_for(state.conn)));
                let _ = tray.set_tooltip(Some(tooltip_for(state)));
            }
        }
        Some(TrayAction::Disconnect) => {
            let _ = cmd_tx.blocking_send(TrayCmd::Disconnect);
        }
        Some(TrayAction::Settings) => {
            if settings_webview.is_none() {
                match open_settings_window(target, Arc::clone(ipc_queue)) {
                    Ok((win, wv)) => { *settings_window = Some(win); *settings_webview = Some(wv); }
                    Err(e) => error!("failed to open settings: {e:?}"),
                }
            } else if let Some(sw) = settings_window.as_ref() {
                sw.set_focus();
            }
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
    server_name: String,
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
fn tooltip_for(state: &TrayState) -> String {
    match state.conn {
        ConnState::Connected if !state.server_name.is_empty() => {
            format!("🟢 Connected to {}", state.server_name)
        }
        ConnState::Connected => "🟢 Connected".to_string(),
        ConnState::Disconnected => "🔴 Disconnected".to_string(),
        ConnState::Connecting => "🟡 Connecting...".to_string(),
    }
}

// ── Worker thread (named-pipe control I/O) ─────────────────────────────────────

#[cfg(target_os = "windows")]
#[derive(Debug)]
#[allow(dead_code)]
enum TrayCmd {
    Status,
    Connect(String),
    Disconnect,
    SwitchTransport(String),
    Raw(Value),
}

#[cfg(target_os = "windows")]
fn control_worker(
    proxy: EventLoopProxy<TrayEvent>,
    mut cmd_rx: mpsc::Receiver<TrayCmd>,
    latest: Arc<Mutex<bool>>,
) {
    let rt = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => { error!("failed to create tokio runtime for control worker: {e}"); return; }
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
                        TrayCmd::Raw(v) => v.clone(),
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

#[cfg(target_os = "windows")]
fn publish_status(resp: &Value, proxy: &EventLoopProxy<TrayEvent>, latest: &Arc<Mutex<bool>>) {
    let connected = resp
        .get("status")
        .and_then(|s| s.get("connected"))
        .and_then(Value::as_bool)
        .unwrap_or(false);
    if let Ok(mut guard) = latest.lock() { *guard = connected; }
    let _ = proxy.send_event(TrayEvent::StatusUpdate);
}

#[cfg(target_os = "windows")]
async fn send_command(cmd: Value) -> Option<Value> {
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    use tokio::net::windows::named_pipe::ClientOptions;

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
    if client.write_all(line.as_bytes()).await.is_err() { return None; }

    let mut reader = BufReader::new(client);
    let mut resp = String::new();
    if reader.read_line(&mut resp).await.is_err() { return None; }

    match serde_json::from_str(resp.trim()) {
        Ok(v) => Some(v),
        Err(e) => { warn!("invalid daemon response: {e}"); None }
    }
}

// ── Non-Windows stub ──────────────────────────────────────────────────────────

#[cfg(not(target_os = "windows"))]
fn main() {
    println!("Tray app is Windows-only");
}
