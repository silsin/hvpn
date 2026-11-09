#![cfg_attr(not(target_os = "windows"), allow(dead_code, unused_imports))]
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
use tray_icon::menu::{CheckMenuItem, Menu, MenuEvent, MenuItem, PredefinedMenuItem, Submenu};
#[cfg(target_os = "windows")]
use tray_icon::{Icon, TrayIcon, TrayIconBuilder};
#[cfg(target_os = "windows")]
use tracing::{error, info, warn};
#[cfg(target_os = "windows")]
use anyhow::Context as _;

/// Named pipe the daemon listens on.
#[cfg(target_os = "windows")]
const PIPE_NAME: &str = r"\\.\pipe\hvpn";


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
    <textarea id="connstr" placeholder="Paste your link here (akbar://...)"></textarea>
    <div id="pasteError" style="color:#ff6b81; font-size:13px; min-height:18px; margin-bottom:8px"></div>
    <button class="btn" onclick="submitPaste()">Connect</button>
  </div>
</div>
<div id="page3" class="page">
  <div class="success-icon" id="statusIcon">&#x23F3;</div>
  <h1 id="statusTitle">Connecting&hellip;</h1>
  <div class="server-addr" id="connectedServer"></div>
  <div class="server-addr" id="statusDetail"></div>
  <a onclick="openSettings()">Open Settings</a>
  <br><br>
  <button class="btn" id="doneBtn" onclick="window.ipc.postMessage(JSON.stringify({type:'close_wizard'}))">Done</button>
  <button class="btn" id="retryBtn" style="display:none" onclick="showPage(2)">Try another link</button>
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
  document.getElementById('pasteError').textContent = '';
  if (v) window.ipc.postMessage(JSON.stringify({type:'connect_string', data: v}));
}
function showError(msg) {
  document.getElementById('pasteError').textContent = msg;
  showPage(2);
  switchTab('paste');
}
function openSettings() {
  window.ipc.postMessage(JSON.stringify({type:'open_settings'}));
}
function onConnected(server) {
  document.getElementById('connectedServer').textContent = server;
  showPage(3);
  onStatus('connecting', '');
}
// Called by the tray whenever the connection state changes.
function onStatus(phase, detail) {
  const icon = document.getElementById('statusIcon');
  const title = document.getElementById('statusTitle');
  const det = document.getElementById('statusDetail');
  const retry = document.getElementById('retryBtn');
  if (!icon) return;
  det.textContent = '';
  retry.style.display = 'none';
  if (phase === 'connected') {
    icon.textContent = '\u2705'; title.textContent = "You're protected";
  } else if (phase === 'failed') {
    icon.textContent = '\u26A0\uFE0F'; title.textContent = "Couldn't connect";
    det.textContent = detail || 'Something went wrong.';
    retry.style.display = 'inline-block';
  } else if (phase === 'connecting' || phase === 'reconnecting') {
    icon.textContent = '\u23F3'; title.textContent = 'Connecting\u2026';
    det.textContent = detail || '';
  }
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
  .link-btn { background: none; border: 1px solid #444; color: #b8b8ff; border-radius: 6px; padding: 4px 10px; font-size: 12px; cursor: pointer; margin-right: 8px; }
  .link-btn:hover { border-color: #6c63ff; }
  #linkBox { display: none; background: #1a1a2e; border-radius: 8px; padding: 12px; margin: 8px 0 12px; }
  #linkText { width: 100%; height: 70px; background: #0f0f1a; border: 1px solid #333; border-radius: 6px; color: #e0e0ff; padding: 8px; font-family: monospace; font-size: 11px; resize: none; }
  .warn { color: #f59e0b; }
</style>
</head>
<body>
<h2>&#x2699;&#xFE0F; HVPN Settings</h2>

<h3>Connection</h3>
<div id="profiles"></div>
<div id="linkBox">
  <div class="about-row" id="linkTitle"></div>
  <textarea id="linkText" readonly onclick="this.select()"></textarea>
  <div class="about-row" id="linkNote"></div>
  <div class="about-row warn">Anyone with this link can use your server. Share it only with people you trust.</div>
</div>
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
function renderProfiles(profiles, active) {
  // Built with DOM APIs and textContent so a server name can never inject markup.
  const el = document.getElementById('profiles');
  el.textContent = '';
  profiles.forEach(p => {
    const row = document.createElement('div'); row.className = 'profile-item';
    const info = document.createElement('div');
    const n = document.createElement('div'); n.className = 'profile-name';
    n.textContent = p.name + (p.name === active ? '  \u2713' : '');
    const sv = document.createElement('div'); sv.className = 'profile-server';
    sv.textContent = p.server + ':' + p.port + (p.pinned ? '  \u00B7 certificate pinned' : '');
    info.append(n, sv);
    const btns = document.createElement('div');
    const copy = document.createElement('button'); copy.className = 'link-btn'; copy.textContent = 'Share link';
    copy.addEventListener('click', () => window.ipc.postMessage(JSON.stringify({type:'get_link', name: p.name})));
    const del = document.createElement('button'); del.className = 'del-btn'; del.textContent = '\u2715'; del.title = 'Remove';
    del.addEventListener('click', () => deleteProfile(p.name));
    btns.append(copy, del);
    row.append(info, btns);
    el.appendChild(row);
  });
  if (!profiles.length) el.textContent = 'No servers yet. Add one with a link from your server.';
}
function showLink(name, link) {
  document.getElementById('linkBox').style.display = 'block';
  document.getElementById('linkTitle').textContent = 'Link for ' + name;
  const t = document.getElementById('linkText');
  t.value = link; t.focus(); t.select();
  const note = document.getElementById('linkNote');
  note.textContent = 'Select the text and press Ctrl+C to copy.';
  if (navigator.clipboard && navigator.clipboard.writeText) {
    navigator.clipboard.writeText(link).then(() => { note.textContent = 'Copied to clipboard.'; }).catch(() => {});
  }
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

// ── Status snapshot (daemon → tray) ───────────────────────────────────────────

/// Everything the tray shows, copied from the daemon's `status` reply.
#[cfg(target_os = "windows")]
#[derive(Clone, Debug, Default, PartialEq)]
struct Snapshot {
    /// Could we talk to the daemon at all?
    reachable: bool,
    phase: String,
    server: String,
    profile: Option<String>,
    last_error: Option<String>,
    attempt: u32,
    retry_in: Option<u64>,
    uptime: Option<u64>,
    rtt_ms: u64,
    speed_in: u64,
    speed_out: u64,
    bytes_in: u64,
    bytes_out: u64,
}

/// Which icon / colour to show.
#[cfg(target_os = "windows")]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Look {
    Connected,
    Working,
    Idle,
    Failed,
}

#[cfg(target_os = "windows")]
impl Snapshot {
    fn from_response(resp: &Value) -> Snapshot {
        let st = match resp.get("status") {
            Some(s) => s,
            None => return Snapshot::default(),
        };
        let text = |k: &str| st.get(k).and_then(Value::as_str).map(String::from);
        let num = |k: &str| st.get(k).and_then(Value::as_u64).unwrap_or(0);
        let phase = text("phase").unwrap_or_else(|| {
            // Older daemons only report a boolean.
            if st.get("connected").and_then(Value::as_bool).unwrap_or(false) {
                "connected".to_string()
            } else {
                "idle".to_string()
            }
        });
        Snapshot {
            reachable: true,
            phase,
            server: text("server").unwrap_or_default(),
            profile: text("profile"),
            last_error: text("last_error"),
            attempt: num("attempt") as u32,
            retry_in: st.get("retry_in_secs").and_then(Value::as_u64),
            uptime: st.get("uptime_secs").and_then(Value::as_u64),
            rtt_ms: num("rtt_ms"),
            speed_in: num("speed_in"),
            speed_out: num("speed_out"),
            bytes_in: num("bytes_in"),
            bytes_out: num("bytes_out"),
        }
    }

    fn look(&self) -> Look {
        if !self.reachable {
            return Look::Idle;
        }
        match self.phase.as_str() {
            "connected" => Look::Connected,
            "connecting" | "reconnecting" => Look::Working,
            "failed" => Look::Failed,
            _ => Look::Idle,
        }
    }

    fn is_active(&self) -> bool {
        self.reachable && matches!(self.phase.as_str(), "connected" | "connecting" | "reconnecting")
    }
}

// ── Formatting helpers ────────────────────────────────────────────────────────

fn fmt_bytes(b: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KB", "MB", "GB", "TB"];
    let mut v = b as f64;
    let mut i = 0;
    while v >= 1024.0 && i < UNITS.len() - 1 {
        v /= 1024.0;
        i += 1;
    }
    if i == 0 {
        format!("{} B", b)
    } else if v >= 100.0 {
        format!("{:.0} {}", v, UNITS[i])
    } else {
        format!("{:.1} {}", v, UNITS[i])
    }
}

fn fmt_speed(bytes_per_sec: u64) -> String {
    format!("{}/s", fmt_bytes(bytes_per_sec))
}

fn fmt_duration(secs: u64) -> String {
    let (h, m, s) = (secs / 3600, (secs % 3600) / 60, secs % 60);
    if h > 0 {
        format!("{}:{:02}:{:02}", h, m, s)
    } else {
        format!("{:02}:{:02}", m, s)
    }
}

/// Shorten `text` to at most `max` characters for menu rows.
fn shorten(text: &str, max: usize) -> String {
    let t = text.trim();
    if t.chars().count() <= max {
        t.to_string()
    } else {
        let cut: String = t.chars().take(max.saturating_sub(1)).collect();
        format!("{}…", cut.trim_end())
    }
}

/// (title, detail, stats) rows for the menu.
#[cfg(target_os = "windows")]
fn status_lines(s: &Snapshot) -> (String, String, String) {
    if !s.reachable {
        return (
            "⚪ HVPN service isn't running".into(),
            "Start the “HVPN Client” service".into(),
            "".into(),
        );
    }
    let err = s.last_error.as_deref().map(|e| shorten(e, 58)).unwrap_or_default();
    match s.phase.as_str() {
        "connected" => (
            format!("🟢 Connected · {}", shorten(&s.server, 28)),
            format!("↓ {}    ↑ {}", fmt_speed(s.speed_in), fmt_speed(s.speed_out)),
            format!(
                "{} · ping {} · {} used",
                fmt_duration(s.uptime.unwrap_or(0)),
                if s.rtt_ms > 0 { format!("{} ms", s.rtt_ms) } else { "—".to_string() },
                fmt_bytes(s.bytes_in.saturating_add(s.bytes_out)),
            ),
        ),
        "connecting" => (
            format!("🟡 Connecting to {}…", shorten(&s.server, 24)),
            "Please wait".into(),
            "".into(),
        ),
        "reconnecting" => (
            format!("🟡 Reconnecting… (attempt {})", s.attempt.max(1)),
            if err.is_empty() { "Connection lost".into() } else { err },
            match s.retry_in {
                Some(n) if n > 0 => format!("Next try in {} s — or choose “Retry now”", n),
                _ => "Trying now…".into(),
            },
        ),
        "failed" => (
            "🔴 Couldn't connect".into(),
            if err.is_empty() { "Something went wrong".into() } else { err },
            "Choose Connect to try again".into(),
        ),
        _ => (
            "⚪ Disconnected".into(),
            "You are not protected".into(),
            "Choose Connect to start".into(),
        ),
    }
}

#[cfg(target_os = "windows")]
fn tooltip_for(s: &Snapshot) -> String {
    let (title, detail, _) = status_lines(s);
    // Windows limits tray tooltips to 127 characters.
    shorten(&format!("HVPN — {}\n{}", title, detail), 120)
}

// ── Icon (shield + state glyph) ───────────────────────────────────────────────

#[cfg(target_os = "windows")]
fn dist_to_segment(px: f32, py: f32, a: (f32, f32), b: (f32, f32)) -> f32 {
    let (dx, dy) = (b.0 - a.0, b.1 - a.1);
    let len2 = dx * dx + dy * dy;
    let t = if len2 == 0.0 { 0.0 } else { (((px - a.0) * dx + (py - a.1) * dy) / len2).clamp(0.0, 1.0) };
    let (cx, cy) = (a.0 + t * dx, a.1 + t * dy);
    ((px - cx).powi(2) + (py - cy).powi(2)).sqrt()
}

#[cfg(target_os = "windows")]
fn in_shield(x: f32, y: f32) -> bool {
    if !(3.0..=30.0).contains(&y) {
        return false;
    }
    let half = if y <= 17.0 {
        12.5
    } else {
        let t = (y - 17.0) / 13.0;
        12.5 * (1.0 - t.powf(1.6))
    };
    (x - 16.0).abs() <= half
}

/// Whether (x, y) is on the white glyph that tells the state apart without
/// relying on colour (✓ connected, … working, – idle, × failed).
#[cfg(target_os = "windows")]
fn on_glyph(look: Look, x: f32, y: f32) -> bool {
    const W: f32 = 1.35; // half stroke width
    let seg = |a: (f32, f32), b: (f32, f32)| dist_to_segment(x, y, a, b) <= W;
    match look {
        Look::Connected => seg((9.5, 15.5), (14.0, 20.0)) || seg((14.0, 20.0), (22.5, 10.5)),
        Look::Failed => seg((11.0, 10.5), (21.0, 20.5)) || seg((21.0, 10.5), (11.0, 20.5)),
        Look::Idle => seg((10.0, 15.5), (22.0, 15.5)),
        Look::Working => [10.0f32, 16.0, 22.0]
            .iter()
            .any(|cx| (x - cx).powi(2) + (y - 15.5).powi(2) <= 2.2 * 2.2),
    }
}

#[cfg(target_os = "windows")]
fn shield_icon(look: Look) -> Icon {
    let fill: [f32; 3] = match look {
        Look::Connected => [34.0, 197.0, 94.0],
        Look::Working => [245.0, 158.0, 11.0],
        Look::Idle => [107.0, 114.0, 128.0],
        Look::Failed => [239.0, 68.0, 68.0],
    };
    const N: usize = 32;
    const SS: usize = 4; // 4x4 supersampling for smooth edges
    let mut rgba = Vec::with_capacity(N * N * 4);
    for py in 0..N {
        for px in 0..N {
            let (mut r, mut g, mut b, mut inside) = (0.0f32, 0.0f32, 0.0f32, 0.0f32);
            for sy in 0..SS {
                for sx in 0..SS {
                    let x = px as f32 + (sx as f32 + 0.5) / SS as f32;
                    let y = py as f32 + (sy as f32 + 0.5) / SS as f32;
                    if in_shield(x, y) {
                        inside += 1.0;
                        let c = if on_glyph(look, x, y) { [255.0; 3] } else { fill };
                        r += c[0];
                        g += c[1];
                        b += c[2];
                    }
                }
            }
            if inside > 0.0 {
                let alpha = (inside / (SS * SS) as f32 * 255.0).round() as u8;
                rgba.extend_from_slice(&[
                    (r / inside).round() as u8,
                    (g / inside).round() as u8,
                    (b / inside).round() as u8,
                    alpha,
                ]);
            } else {
                rgba.extend_from_slice(&[0, 0, 0, 0]);
            }
        }
    }
    Icon::from_rgba(rgba, N as u32, N as u32).expect("invalid icon rgba buffer")
}

// ── Small Windows helpers ─────────────────────────────────────────────────────

#[cfg(target_os = "windows")]
const RUN_KEY: &str = r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run";
#[cfg(target_os = "windows")]
const RUN_VALUE: &str = "HVPN Tray";

/// Run a console tool without flashing a window.
#[cfg(target_os = "windows")]
fn quiet(program: &str, args: &[&str]) -> Option<std::process::Output> {
    use std::os::windows::process::CommandExt;
    std::process::Command::new(program)
        .args(args)
        .creation_flags(0x0800_0000) // CREATE_NO_WINDOW
        .output()
        .ok()
}

#[cfg(target_os = "windows")]
fn autostart_enabled() -> bool {
    quiet("reg", &["query", RUN_KEY, "/v", RUN_VALUE])
        .map(|o| o.status.success())
        .unwrap_or(false)
}

#[cfg(target_os = "windows")]
fn set_autostart(on: bool) {
    if on {
        if let Ok(exe) = std::env::current_exe() {
            let value = format!("\"{}\"", exe.display());
            let _ = quiet("reg", &["add", RUN_KEY, "/v", RUN_VALUE, "/t", "REG_SZ", "/d", &value, "/f"]);
        }
    } else {
        let _ = quiet("reg", &["delete", RUN_KEY, "/v", RUN_VALUE, "/f"]);
    }
}

/// Show a native warning box without blocking the tray's event loop.
#[cfg(target_os = "windows")]
fn show_problem(message: String) {
    std::thread::spawn(move || {
        use windows::core::PCWSTR;
        use windows::Win32::UI::WindowsAndMessaging::{
            MessageBoxW, MB_ICONWARNING, MB_OK, MB_SETFOREGROUND,
        };
        let title: Vec<u16> = "HVPN".encode_utf16().chain(Some(0)).collect();
        let text: Vec<u16> = message.encode_utf16().chain(Some(0)).collect();
        unsafe {
            MessageBoxW(
                None,
                PCWSTR(text.as_ptr()),
                PCWSTR(title.as_ptr()),
                MB_OK | MB_ICONWARNING | MB_SETFOREGROUND,
            );
        }
    });
}

#[cfg(target_os = "windows")]
fn open_log_file() {
    let path = hvpn_common::profiles_path().with_file_name("client.log");
    if path.exists() {
        let _ = std::process::Command::new("notepad").arg(path).spawn();
    } else {
        show_problem("No log file yet. It is created when the HVPN Client service runs.".to_string());
    }
}

/// JS string literal for `s` (safe to splice into `evaluate_script`).
#[cfg(target_os = "windows")]
fn js_str(s: &str) -> String {
    serde_json::to_string(s).unwrap_or_else(|_| "\"\"".to_string())
}

// ── Main ──────────────────────────────────────────────────────────────────────

/// Windows owned by the tray.
#[cfg(target_os = "windows")]
#[derive(Default)]
struct Ui {
    wizard_window: Option<tao::window::Window>,
    wizard_webview: Option<wry::WebView>,
    settings_window: Option<tao::window::Window>,
    settings_webview: Option<wry::WebView>,
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
    let has_profiles = !hvpn_common::load_profiles().is_empty();

    // Create the event loop with our custom user-event type.
    let event_loop = EventLoopBuilder::<TrayEvent>::with_user_event().build();
    let proxy = event_loop.create_proxy();

    // Channel: event loop (menu clicks) -> worker thread.
    let (cmd_tx, cmd_rx) = mpsc::channel::<TrayCmd>(32);
    // Latest daemon status: worker -> event loop.
    let latest: Arc<Mutex<Snapshot>> = Arc::new(Mutex::new(Snapshot::default()));

    // Shared IPC message queue: webview ipc -> event loop.
    let ipc_queue: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));

    // Spawn the background control worker.
    let worker_proxy = proxy.clone();
    let worker_latest = Arc::clone(&latest);
    std::thread::Builder::new()
        .name("hvpn-tray-ctl".to_string())
        .spawn(move || control_worker(worker_proxy, cmd_rx, worker_latest))
        .context("failed to spawn control worker")?;

    let menu_receiver = MenuEvent::receiver();

    // Mutable tray/webview state, owned by the event-loop thread.
    let mut state = TrayState {
        tray: None,
        items: None,
        snap: Snapshot::default(),
        shown_error: None,
        menu_profiles: Vec::new(),
        menu_active: None,
        autostart: autostart_enabled(),
    };
    let mut ui = Ui::default();
    let ipc_queue_ev = Arc::clone(&ipc_queue);

    event_loop.run(move |event, target, control_flow| {
        *control_flow = ControlFlow::Wait;

        match &event {
            Event::NewEvents(cause) => {
                if matches!(cause, StartCause::Init) {
                    rebuild_menu(&mut state);
                    refresh_ui(&mut state, &ui);

                    // Open wizard if no profiles exist.
                    if !has_profiles {
                        match open_wizard_window(target, Arc::clone(&ipc_queue_ev)) {
                            Ok((win, wv)) => {
                                ui.wizard_window = Some(win);
                                ui.wizard_webview = Some(wv);
                            }
                            Err(e) => error!("failed to open wizard: {e:?}"),
                        }
                    }
                }

                // Poll menu events.
                while let Ok(ev) = menu_receiver.try_recv() {
                    handle_menu_event(&ev, &mut state, &cmd_tx, control_flow, target, &ipc_queue_ev, &mut ui);
                }

                // Drain IPC queue.
                let msgs: Vec<String> = {
                    let mut q = ipc_queue_ev.lock().unwrap();
                    std::mem::take(&mut *q)
                };
                for msg in msgs {
                    handle_ipc_message(&msg, &mut state, &cmd_tx, target, &ipc_queue_ev, &mut ui);
                }
            }
            Event::UserEvent(TrayEvent::StatusUpdate) => {
                state.snap = latest.lock().map(|g| g.clone()).unwrap_or_default();
                // Pick up profile changes made elsewhere (wizard, settings, another tool).
                if menu_is_stale(&state) {
                    rebuild_menu(&mut state);
                }
                refresh_ui(&mut state, &ui);
            }
            Event::WindowEvent {
                event: tao::event::WindowEvent::CloseRequested,
                window_id,
                ..
            } => {
                if ui.wizard_window.as_ref().map(|w| w.id()) == Some(*window_id) {
                    ui.wizard_webview = None;
                    ui.wizard_window = None;
                }
                if ui.settings_window.as_ref().map(|w| w.id()) == Some(*window_id) {
                    ui.settings_webview = None;
                    ui.settings_window = None;
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
        .with_inner_size(LogicalSize::new(480u32, 560u32))
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
        .with_inner_size(LogicalSize::new(520u32, 640u32))
        .build(target)?;

    let webview = WebViewBuilder::new(&window)
        .with_html(SETTINGS_HTML)
        .with_ipc_handler(move |msg: wry::http::Request<String>| {
            ipc_queue.lock().unwrap().push(msg.body().clone());
        })
        .build()?;

    Ok((window, webview))
}

#[cfg(target_os = "windows")]
fn open_or_focus_settings(
    target: &tao::event_loop::EventLoopWindowTarget<TrayEvent>,
    ipc_queue: &Arc<Mutex<Vec<String>>>,
    ui: &mut Ui,
) {
    if ui.settings_webview.is_none() {
        match open_settings_window(target, Arc::clone(ipc_queue)) {
            Ok((win, wv)) => {
                ui.settings_window = Some(win);
                ui.settings_webview = Some(wv);
            }
            Err(e) => error!("failed to open settings: {e:?}"),
        }
    } else if let Some(sw) = ui.settings_window.as_ref() {
        sw.set_focus();
    }
}

/// Send the saved profiles (and the active one) to the settings page.
#[cfg(target_os = "windows")]
fn push_profiles(ui: &Ui, active: Option<&str>) {
    let profiles = hvpn_common::load_profiles();
    // Never send secrets to the page: only what it displays.
    let safe: Vec<Value> = profiles
        .iter()
        .map(|p| {
            json!({
                "name": p.display_name(),
                "server": p.server,
                "port": p.port,
                "pinned": !p.cert_sha256.is_empty(),
            })
        })
        .collect();
    if let (Ok(list), Some(wv)) = (serde_json::to_string(&safe), ui.settings_webview.as_ref()) {
        let _ = wv.evaluate_script(&format!(
            "renderProfiles({}, {})",
            list,
            active.map(js_str).unwrap_or_else(|| "null".to_string())
        ));
    }
}

// ── IPC message handler ───────────────────────────────────────────────────────

#[cfg(target_os = "windows")]
fn handle_ipc_message(
    msg: &str,
    state: &mut TrayState,
    cmd_tx: &mpsc::Sender<TrayCmd>,
    target: &tao::event_loop::EventLoopWindowTarget<TrayEvent>,
    ipc_queue: &Arc<Mutex<Vec<String>>>,
    ui: &mut Ui,
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
            // Accepts akbar:// links, hvpn:// links and bare connection strings.
            match hvpn_common::ConnectionProfile::from_link(data) {
                Ok(profile) => {
                    let mut profiles = hvpn_common::load_profiles();
                    let name = hvpn_common::upsert_profile(&mut profiles, profile);
                    if let Err(e) = hvpn_common::save_profiles(&profiles) {
                        warn!("failed to save profiles: {e}");
                        if let Some(wv) = ui.wizard_webview.as_ref() {
                            let _ = wv.evaluate_script(&format!(
                                "showError({})",
                                js_str("Couldn't save this server. Check that you can write to your user folder.")
                            ));
                        }
                        return;
                    }
                    hvpn_common::save_active_profile(&name);
                    let _ = cmd_tx.blocking_send(TrayCmd::Connect(Some(name.clone())));
                    // Optimistic status until the daemon answers.
                    state.snap.reachable = true;
                    state.snap.phase = "connecting".to_string();
                    state.snap.server = name.clone();
                    state.snap.profile = Some(name.clone());
                    state.snap.last_error = None;
                    rebuild_menu(state);
                    refresh_ui(state, ui);
                    if let Some(wv) = ui.wizard_webview.as_ref() {
                        let _ = wv.evaluate_script(&format!("onConnected({})", js_str(&name)));
                    }
                }
                Err(e) => {
                    warn!("invalid link: {e}");
                    if let Some(wv) = ui.wizard_webview.as_ref() {
                        let _ = wv.evaluate_script(&format!(
                            "showError({})",
                            js_str("That doesn't look like a valid link. Copy the whole link from your server and try again.")
                        ));
                    }
                }
            }
        }
        "close_wizard" => {
            ui.wizard_webview = None;
            ui.wizard_window = None;
        }
        "open_settings" => open_or_focus_settings(target, ipc_queue, ui),
        "open_wizard" => {
            if ui.wizard_webview.is_none() {
                match open_wizard_window(target, Arc::clone(ipc_queue)) {
                    Ok((win, wv)) => { ui.wizard_window = Some(win); ui.wizard_webview = Some(wv); }
                    Err(e) => error!("failed to open wizard: {e:?}"),
                }
            } else if let Some(ww) = ui.wizard_window.as_ref() {
                ww.set_focus();
            }
        }
        "get_profiles" => push_profiles(ui, state.snap.profile.as_deref()),
        "get_link" => {
            let name = match parsed.get("name").and_then(Value::as_str) {
                Some(n) => n,
                None => return,
            };
            let profiles = hvpn_common::load_profiles();
            if let (Some(p), Some(wv)) = (hvpn_common::find_profile(&profiles, name), ui.settings_webview.as_ref()) {
                let _ = wv.evaluate_script(&format!("showLink({}, {})", js_str(&p.display_name()), js_str(&p.to_link())));
            }
        }
        "delete_profile" => {
            let name = match parsed.get("name").and_then(Value::as_str) {
                Some(n) => n,
                None => return,
            };
            let mut profiles = hvpn_common::load_profiles();
            profiles.retain(|p| p.name.as_deref() != Some(name) && p.server != name && p.display_name() != name);
            if let Err(e) = hvpn_common::save_profiles(&profiles) {
                warn!("failed to save profiles: {e}");
            }
            rebuild_menu(state);
            push_profiles(ui, state.snap.profile.as_deref());
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
    status: MenuItem,
    detail: MenuItem,
    stats: MenuItem,
    connect: MenuItem,
    disconnect: MenuItem,
    /// One check item per saved server; the string is the profile name.
    servers: Vec<(CheckMenuItem, String)>,
    settings: MenuItem,
    autostart: CheckMenuItem,
    logs: MenuItem,
    exit: MenuItem,
}

#[cfg(target_os = "windows")]
fn saved_profile_names() -> Vec<String> {
    hvpn_common::load_profiles().iter().map(|p| p.display_name()).collect()
}

/// The profile to tick in the menu: what the daemon uses, else the first one.
#[cfg(target_os = "windows")]
fn effective_active(state: &TrayState, names: &[String]) -> Option<String> {
    state
        .snap
        .profile
        .clone()
        .filter(|p| names.contains(p))
        .or_else(|| names.first().cloned())
}

#[cfg(target_os = "windows")]
fn menu_is_stale(state: &TrayState) -> bool {
    let names = saved_profile_names();
    names != state.menu_profiles || effective_active(state, &names) != state.menu_active
}

/// (Re)build the whole tray menu from the saved profiles.
#[cfg(target_os = "windows")]
fn rebuild_menu(state: &mut TrayState) {
    let names = saved_profile_names();
    let active = effective_active(state, &names);

    let items = TrayItems {
        status: MenuItem::new("⚪ HVPN", false, None),
        detail: MenuItem::new("", false, None),
        stats: MenuItem::new("", false, None),
        connect: MenuItem::new("Connect", true, None),
        disconnect: MenuItem::new("Disconnect", false, None),
        servers: names
            .iter()
            .map(|n| (CheckMenuItem::new(n, true, active.as_deref() == Some(n.as_str()), None), n.clone()))
            .collect(),
        settings: MenuItem::new("Settings…", true, None),
        autostart: CheckMenuItem::new("Start with Windows", true, state.autostart, None),
        logs: MenuItem::new("Open log file", true, None),
        exit: MenuItem::new("Exit", true, None),
    };

    let menu = Menu::new();
    let _ = menu.append(&items.status);
    let _ = menu.append(&items.detail);
    let _ = menu.append(&items.stats);
    let _ = menu.append(&PredefinedMenuItem::separator());
    let _ = menu.append(&items.connect);
    let _ = menu.append(&items.disconnect);
    if !items.servers.is_empty() {
        let sub = Submenu::new("Server", true);
        for (item, _) in &items.servers {
            let _ = sub.append(item);
        }
        let _ = menu.append(&sub);
    }
    let _ = menu.append(&PredefinedMenuItem::separator());
    let _ = menu.append(&items.settings);
    let _ = menu.append(&items.autostart);
    let _ = menu.append(&items.logs);
    let _ = menu.append(&PredefinedMenuItem::separator());
    let _ = menu.append(&items.exit);

    match &state.tray {
        Some(tray) => tray.set_menu(Some(Box::new(menu))),
        None => {
            match TrayIconBuilder::new()
                .with_menu(Box::new(menu))
                .with_tooltip("HVPN")
                .with_icon(shield_icon(state.snap.look()))
                .build()
            {
                Ok(tray) => state.tray = Some(tray),
                Err(e) => error!("failed to build tray icon: {e:?}"),
            }
        }
    }
    state.items = Some(items);
    state.menu_profiles = names;
    state.menu_active = active;
}

/// Push the current snapshot into the menu text, icon, tooltip and wizard.
#[cfg(target_os = "windows")]
fn refresh_ui(state: &mut TrayState, ui: &Ui) {
    let snap = state.snap.clone();
    let look = snap.look();
    let (title, detail, stats) = status_lines(&snap);

    if let Some(items) = &state.items {
        items.status.set_text(&title);
        items.detail.set_text(if detail.is_empty() { " " } else { &detail });
        items.stats.set_text(if stats.is_empty() { " " } else { &stats });

        let reconnecting = snap.reachable && snap.phase == "reconnecting";
        items.connect.set_text(if reconnecting { "Retry now" } else { "Connect" });
        items.connect.set_enabled(snap.reachable && (!snap.is_active() || reconnecting));
        items.disconnect.set_enabled(snap.is_active());
        items.autostart.set_checked(state.autostart);
        for (item, name) in &items.servers {
            item.set_checked(state.menu_active.as_deref() == Some(name.as_str()));
        }
    }
    if let Some(tray) = &state.tray {
        let _ = tray.set_icon(Some(shield_icon(look)));
        let _ = tray.set_tooltip(Some(tooltip_for(&snap)));
    }

    // Keep the setup wizard honest about what is happening.
    if let Some(wv) = ui.wizard_webview.as_ref() {
        let detail = snap.last_error.clone().unwrap_or_default();
        let _ = wv.evaluate_script(&format!("onStatus({}, {})", js_str(&snap.phase), js_str(&detail)));
    }

    // A problem the user has to act on: tell them once, in plain words.
    if look == Look::Failed {
        if let Some(err) = snap.last_error.clone() {
            if state.shown_error.as_deref() != Some(err.as_str()) {
                state.shown_error = Some(err.clone());
                if ui.wizard_webview.is_none() {
                    show_problem(err);
                }
            }
        }
    } else if look == Look::Connected {
        state.shown_error = None;
    }
}

#[cfg(target_os = "windows")]
fn handle_menu_event(
    ev: &MenuEvent,
    state: &mut TrayState,
    cmd_tx: &mpsc::Sender<TrayCmd>,
    control_flow: &mut ControlFlow,
    target: &tao::event_loop::EventLoopWindowTarget<TrayEvent>,
    ipc_queue: &Arc<Mutex<Vec<String>>>,
    ui: &mut Ui,
) {
    enum Action {
        Connect,
        Disconnect,
        PickServer(String),
        Settings,
        Autostart,
        Logs,
        Exit,
    }

    let action = state.items.as_ref().and_then(|items| {
        let id = &ev.id;
        if id == items.connect.id() { Some(Action::Connect) }
        else if id == items.disconnect.id() { Some(Action::Disconnect) }
        else if id == items.settings.id() { Some(Action::Settings) }
        else if id == items.autostart.id() { Some(Action::Autostart) }
        else if id == items.logs.id() { Some(Action::Logs) }
        else if id == items.exit.id() { Some(Action::Exit) }
        else {
            items
                .servers
                .iter()
                .find(|(item, _)| id == item.id())
                .map(|(_, name)| Action::PickServer(name.clone()))
        }
    });

    match action {
        Some(Action::Connect) => {
            let _ = cmd_tx.blocking_send(TrayCmd::Connect(state.menu_active.clone()));
            state.snap.reachable = true;
            state.snap.phase = "connecting".to_string();
            state.snap.last_error = None;
            refresh_ui(state, ui);
        }
        Some(Action::Disconnect) => {
            let _ = cmd_tx.blocking_send(TrayCmd::Disconnect);
            state.snap.phase = "idle".to_string();
            refresh_ui(state, ui);
        }
        Some(Action::PickServer(name)) => {
            hvpn_common::save_active_profile(&name);
            let _ = cmd_tx.blocking_send(TrayCmd::Connect(Some(name.clone())));
            state.snap.reachable = true;
            state.snap.phase = "connecting".to_string();
            state.snap.server = name.clone();
            state.snap.profile = Some(name.clone());
            state.snap.last_error = None;
            state.menu_active = Some(name);
            refresh_ui(state, ui);
        }
        Some(Action::Settings) => open_or_focus_settings(target, ipc_queue, ui),
        Some(Action::Autostart) => {
            state.autostart = !state.autostart;
            set_autostart(state.autostart);
            // Re-read the truth in case `reg` was blocked.
            state.autostart = autostart_enabled();
            refresh_ui(state, ui);
        }
        Some(Action::Logs) => open_log_file(),
        Some(Action::Exit) => {
            info!("exit requested");
            *control_flow = ControlFlow::Exit;
        }
        None => {}
    }
}

// ── State ──────────────────────────────────────────────────────────────────────

#[cfg(target_os = "windows")]
struct TrayState {
    tray: Option<TrayIcon>,
    items: Option<TrayItems>,
    snap: Snapshot,
    /// Last problem we already told the user about.
    shown_error: Option<String>,
    /// Profile names the menu was built from.
    menu_profiles: Vec<String>,
    menu_active: Option<String>,
    autostart: bool,
}

// ── Worker thread (named-pipe control I/O) ─────────────────────────────────────

#[cfg(target_os = "windows")]
#[derive(Debug)]
enum TrayCmd {
    /// Connect, optionally to a specific saved profile.
    Connect(Option<String>),
    Disconnect,
    Raw(Value),
}

#[cfg(target_os = "windows")]
fn control_worker(
    proxy: EventLoopProxy<TrayEvent>,
    mut cmd_rx: mpsc::Receiver<TrayCmd>,
    latest: Arc<Mutex<Snapshot>>,
) {
    let rt = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => { error!("failed to create tokio runtime for control worker: {e}"); return; }
    };

    rt.block_on(async move {
        // Local pipe: cheap enough to poll every 2 s so speeds feel live.
        let mut ticker = tokio::time::interval(Duration::from_secs(2));
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            tokio::select! {
                _ = ticker.tick() => {
                    let resp = send_command(json!({"cmd": "status"})).await;
                    publish_status(resp.as_ref(), &proxy, &latest);
                }
                Some(cmd) = cmd_rx.recv() => {
                    let req = match &cmd {
                        TrayCmd::Connect(Some(name)) => json!({"cmd": "connect", "profile": name}),
                        TrayCmd::Connect(None) => json!({"cmd": "connect"}),
                        TrayCmd::Disconnect => json!({"cmd": "disconnect"}),
                        TrayCmd::Raw(v) => v.clone(),
                    };
                    let _ = send_command(req).await;
                    // Show the result straight away instead of waiting for the next tick.
                    let resp = send_command(json!({"cmd": "status"})).await;
                    publish_status(resp.as_ref(), &proxy, &latest);
                }
            }
        }
    });
}

#[cfg(target_os = "windows")]
fn publish_status(resp: Option<&Value>, proxy: &EventLoopProxy<TrayEvent>, latest: &Arc<Mutex<Snapshot>>) {
    let snap = match resp {
        Some(r) => Snapshot::from_response(r),
        None => Snapshot::default(), // daemon unreachable
    };
    if let Ok(mut guard) = latest.lock() { *guard = snap; }
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

#[cfg(all(test, target_os = "windows"))]
mod tests {
    use super::*;

    #[test]
    fn formats_sizes_speeds_and_durations() {
        assert_eq!(fmt_bytes(0), "0 B");
        assert_eq!(fmt_bytes(1023), "1023 B");
        assert_eq!(fmt_bytes(1536), "1.5 KB");
        assert_eq!(fmt_bytes(5 * 1024 * 1024), "5.0 MB");
        assert_eq!(fmt_bytes(250 * 1024 * 1024), "250 MB");
        assert_eq!(fmt_speed(2_097_152), "2.0 MB/s");
        assert_eq!(fmt_duration(65), "01:05");
        assert_eq!(fmt_duration(3725), "1:02:05");
    }

    #[test]
    fn shorten_respects_char_boundaries() {
        assert_eq!(shorten("short", 10), "short");
        let s = shorten("ééééééééééééé", 5);
        assert_eq!(s.chars().count(), 5);
        assert!(s.ends_with('…'));
    }

    #[test]
    fn snapshot_parsing_and_lines() {
        let resp = json!({"ok": true, "status": {
            "connected": true, "phase": "connected", "server": "Home",
            "speed_in": 1048576, "speed_out": 2048, "bytes_in": 3000, "bytes_out": 1000,
            "rtt_ms": 23, "uptime_secs": 75, "attempt": 0
        }});
        let s = Snapshot::from_response(&resp);
        assert_eq!(s.look(), Look::Connected);
        let (title, detail, stats) = status_lines(&s);
        assert!(title.contains("Connected") && title.contains("Home"));
        assert!(detail.contains("1.0 MB/s") && detail.contains("2.0 KB/s"));
        assert!(stats.contains("01:15") && stats.contains("23 ms"));

        let failed = Snapshot::from_response(&json!({"status": {
            "phase": "failed", "last_error": "The server rejected this connection."}}));
        assert_eq!(failed.look(), Look::Failed);
        assert!(!failed.is_active());

        let reconnecting = Snapshot::from_response(&json!({"status": {
            "phase": "reconnecting", "attempt": 3, "retry_in_secs": 8,
            "last_error": "No internet connection."}}));
        assert!(reconnecting.is_active());
        let (t, _, s3) = status_lines(&reconnecting);
        assert!(t.contains("attempt 3") && s3.contains("8 s"));

        // Daemon not running.
        let gone = Snapshot::default();
        assert!(!gone.reachable && !gone.is_active());
        assert!(status_lines(&gone).0.contains("service"));

        // Older daemon without "phase".
        let old = Snapshot::from_response(&json!({"status": {"connected": true}}));
        assert_eq!(old.phase, "connected");
    }

    #[test]
    fn icons_render_for_every_state() {
        for look in [Look::Connected, Look::Working, Look::Idle, Look::Failed] {
            let _ = shield_icon(look); // panics if the RGBA buffer is malformed
        }
        assert!(in_shield(16.0, 10.0));
        assert!(!in_shield(1.0, 10.0));
        assert!(!in_shield(16.0, 31.0));
    }

    #[test]
    fn js_strings_are_escaped() {
        let s = js_str("a'b\"c\\d\n</script>");
        assert!(s.starts_with('"') && s.ends_with('"'));
        assert!(!s.contains('\n'));
        let back: String = serde_json::from_str(&s).unwrap();
        assert_eq!(back, "a'b\"c\\d\n</script>");
    }
}
