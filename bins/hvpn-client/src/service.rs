//! Windows service wrapper for `hvpn-client`.
//!
//! When the binary is launched with `--service` (as done by the Windows Service
//! Control Manager after installation), [`run`] starts the service dispatcher,
//! which hands control to [`my_service_main`] on a background thread.  That
//! thread reports status transitions (StartPending → Running → Stopped) to the
//! SCM and runs the VPN tunnel inside its own Tokio runtime, stopping cleanly
//! when the SCM sends a `Stop` control.
//!
//! Only compiled on Windows.

use std::ffi::OsString;
use std::sync::mpsc;
use std::time::Duration;

use tokio_util::sync::CancellationToken;
use windows_service::define_windows_service;
use windows_service::service::{
    ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus, ServiceType,
};
use windows_service::service_control_handler::{self, ServiceControlHandlerResult};
use windows_service::service_dispatcher;

/// Service identifier registered with the SCM.
pub const SERVICE_NAME: &str = "HVPNClient";

/// Default configuration path used when no `--config` is supplied to the service.
const DEFAULT_CONFIG: &str = r"C:\Program Files\HVPN\client.toml";

const SERVICE_TYPE: ServiceType = ServiceType::OWN_PROCESS;

// ── Dispatcher entry ───────────────────────────────────────────────────────────

/// Start the Windows service control dispatcher.  Blocks the calling thread
/// until the service stops.  Must be called from the process's main thread.
pub fn run() -> windows_service::Result<()> {
    service_dispatcher::start(SERVICE_NAME, ffi_service_main)
}

// Generate the low-level service entry boilerplate.  It parses incoming
// service arguments into `Vec<OsString>` and forwards them to `my_service_main`.
define_windows_service!(ffi_service_main, my_service_main);

/// Service entry point invoked on a background thread by the SCM.
fn my_service_main(arguments: Vec<OsString>) {
    if let Err(e) = run_service(arguments) {
        eprintln!("[hvpn-client] service failed: {:?}", e);
    }
}

// ── Service logic ──────────────────────────────────────────────────────────────

fn run_service(arguments: Vec<OsString>) -> Result<(), Box<dyn std::error::Error>> {
    // Resolve the config path from the service launch arguments (falling back
    // to the default install location).
    let config_path = parse_config_arg(&arguments).unwrap_or_else(|| DEFAULT_CONFIG.to_string());

    // Channel used by the SCM control handler to signal a stop request.
    let (shutdown_tx, shutdown_rx) = mpsc::channel::<()>();

    let event_handler = move |control_event| -> ServiceControlHandlerResult {
        match control_event {
            ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
            ServiceControl::Stop => {
                let _ = shutdown_tx.send(());
                ServiceControlHandlerResult::NoError
            }
            _ => ServiceControlHandlerResult::NotImplemented,
        }
    };

    let status_handle = service_control_handler::register(SERVICE_NAME, event_handler)?;

    // ── StartPending ────────────────────────────────────────────────────
    status_handle.set_service_status(ServiceStatus {
        service_type: SERVICE_TYPE,
        current_state: ServiceState::StartPending,
        controls_accepted: ServiceControlAccept::empty(),
        exit_code: ServiceExitCode::NO_ERROR,
        checkpoint: 0,
        wait_hint: Duration::from_secs(10),
        process_id: None,
    })?;

    // Cancellation token shared with the tunnel; cancelled when the SCM sends
    // a Stop control (received through `shutdown_rx` below).
    let token = CancellationToken::new();
    let cancel_token = token.clone();
    std::thread::Builder::new()
        .name("hvpn-service-stop".to_string())
        .spawn(move || {
            // Block until Stop is requested or the channel is disconnected.
            let _ = shutdown_rx.recv();
            cancel_token.cancel();
        })?;

    // ── Running ──────────────────────────────────────────────────────────
    status_handle.set_service_status(ServiceStatus {
        service_type: SERVICE_TYPE,
        current_state: ServiceState::Running,
        controls_accepted: ServiceControlAccept::STOP,
        exit_code: ServiceExitCode::NO_ERROR,
        checkpoint: 0,
        wait_hint: Duration::default(),
        process_id: None,
    })?;

    // Run the VPN tunnel in its own Tokio runtime.
    let runtime = tokio::runtime::Runtime::new()?;
    let result = runtime.block_on(crate::run_client(&config_path, token));
    drop(runtime);

    // ── Stopped ──────────────────────────────────────────────────────────
    let exit_code = match &result {
        Ok(()) => ServiceExitCode::NO_ERROR,
        Err(e) => {
            eprintln!("[hvpn-client] tunnel error: {:?}", e);
            ServiceExitCode::ServiceSpecific(1)
        }
    };
    status_handle.set_service_status(ServiceStatus {
        service_type: SERVICE_TYPE,
        current_state: ServiceState::Stopped,
        controls_accepted: ServiceControlAccept::empty(),
        exit_code,
        checkpoint: 0,
        wait_hint: Duration::default(),
        process_id: None,
    })?;

    Ok(())
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Search the service launch arguments for `--config <path>`, skipping the
/// leading service-name argument.
fn parse_config_arg(arguments: &[OsString]) -> Option<String> {
    let mut iter = arguments.iter().skip(1);
    while let Some(arg) = iter.next() {
        if arg.to_string_lossy() == "--config" {
            if let Some(path) = iter.next() {
                return Some(path.to_string_lossy().into_owned());
            }
        }
    }
    None
}
