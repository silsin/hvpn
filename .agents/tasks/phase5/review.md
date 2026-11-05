# Phase 5 — Windows Support: Review

## Evidence

### Build / test (recorded output, not re-run)

- `final_build_stdout.txt` / `final_build_stderr.txt`: `Finished 'dev' profile … in 2.15s` — zero errors.
- `final_test_stdout.txt` / `final_test_stderr.txt`: 69 tests pass, 0 fail across all 14 crates/binaries (64 baseline + 5 new `hvpn-tun windows::tests`). All unit test runners listed, including `hvpn_tray` (0 tests, expected for a GUI binary).

### Required files — all present

| File | Status |
|------|--------|
| `crates/hvpn-tun/src/windows.rs` | ✓ exists |
| `bins/hvpn-tray/src/main.rs` | ✓ exists |
| `bins/hvpn-tray/Cargo.toml` | ✓ exists |
| `deploy/build-windows.ps1` | ✓ exists |

### Workspace member

`bins/hvpn-tray` is listed as a workspace member in the root `Cargo.toml`.

### Dependency versions (resolved in `Cargo.lock`)

| Dep | Required | Resolved |
|-----|----------|----------|
| `wintun` | 0.5.0 | 0.5.1 (patch bump, semver-compatible) |
| `windows-service` | 0.7.0 | 0.7.0 ✓ |
| `tray-icon` | 0.14.0 | 0.14.3 (patch bump, semver-compatible) |
| `tao` | 0.29.0 | 0.29.1 (patch bump, semver-compatible) |

All dependencies are Windows-gated where required:
- `crates/hvpn-tun/Cargo.toml`: `[target.'cfg(target_os = "windows")'.dependencies] wintun = "0.5.0"` ✓
- `bins/hvpn-client/Cargo.toml`: `[target.'cfg(target_os = "windows")'.dependencies] windows-service = "0.7.0"` ✓
- `bins/hvpn-tray/Cargo.toml`: `tray-icon` / `tao` are unconditional deps, but the binary itself compiles to a stub `fn main()` on non-Windows via `#[cfg(not(target_os = "windows"))]` — acceptable because tray-icon/tao are cross-platform crates that compile on all platforms. ✓

### cfg gates

Every new Windows-only module and entry point is correctly gated:

- `crates/hvpn-tun/src/lib.rs`: `#[cfg(target_os = "windows")] mod windows` + `pub use` + `PlatformTun` alias ✓
- `crates/hvpn-tun/src/windows.rs`: entire file — functions inside are only reachable under the module gate ✓
- `bins/hvpn-client/src/main.rs`: `#[cfg(target_os = "windows")] mod service`, `mod install`, and the `--service/--install/--uninstall` block inside `main` ✓
- `bins/hvpn-client/src/main.rs`: Unix control socket `#[cfg(unix)]`, Windows named-pipe `#[cfg(windows)]`, stub `#[cfg(not(any(unix, windows)))]` — covers all targets ✓
- `bins/hvpn-ctl/src/main.rs`: three separate `#[tokio::main] async fn main()` — `#[cfg(unix)]`, `#[cfg(windows)]`, `#[cfg(not(any(unix, windows)))]` ✓
- `bins/hvpn-tray/src/main.rs`: all Windows code behind `#[cfg(target_os = "windows")]`; non-Windows stub `fn main()` ✓

### Existing Linux-targeted code

The diff confirms the Linux `#[cfg(unix)]` `mod control` block (UnixListener, `/tmp/hvpn.sock`) is preserved intact; no Linux path was removed or altered. The `#[cfg(target_os = "linux")] mod linux` and `LinuxTun` export in `hvpn-tun/src/lib.rs` are unchanged. The old `#[cfg(not(unix))]` no-op stub was narrowed to `#[cfg(not(any(unix, windows)))]` — that is correct behaviour, not a regression.

### Step-by-step task requirements

| Step | Requirement | Met |
|------|-------------|-----|
| 1 | `WinTunDevice` implementing `TunDevice` trait; channel-based reader; `open`/`read_packet`/`write_packet`/`close`/`set_mtu`; wintun 0.5.0 | ✓ |
| 2 | `set_default_route`, `exclude_server_route`, `set_dns`, `get_default_gateway` in `windows.rs` | ✓ |
| 3 | `service.rs` (HVPNClient, AutoStart, STOP via CancellationToken); `install.rs` (install/uninstall + recovery actions); `main.rs` --service/--install/--uninstall; windows-service 0.7.0 | ✓ |
| 4 | `bins/hvpn-tray` binary; tray-icon 0.14.0 + tao 0.29.0; green/red/yellow icons; context menu; `\\.\pipe\hvpn`; 32×32 RGBA icons; cfg-gated; workspace member | ✓ |
| 5 | `hvpn-client` Unix vs Windows control socket; `hvpn-ctl` cfg-gated connect; same JSON newline-delimited protocol | ✓ |
| 6 | `deploy/build-windows.ps1` builds release, copies exes + config to `dist\hvpn-windows`, notes wintun.dll | ✓ |
| 7 | README Windows Support section (wintun.dll, build, service install, tray, named pipe, routes) | ✓ |

### API correctness spot-check

`wintun::Adapter::open` and `::create` both return `Result<Arc<Adapter>, Error>` (confirmed from wintun 0.5.1 source). `start_session` takes `self: &Arc<Self>`. The code stores `_adapter: Arc<wintun::Adapter>` and calls `adapter.start_session(...)` — type-correct. The `Arc::new(session)` wrapping and the `Arc::clone(&session)` for the reader thread are consistent with `session::Session` not implementing `Clone` directly.

## Verdict

No blockers found.
