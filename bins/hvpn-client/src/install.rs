//! Windows service installation / uninstallation helpers for `hvpn-client`.
//!
//! `hvpn-client --install` registers the service with the SCM (auto-start on
//! boot) and configures failure recovery actions so the service restarts after
//! a crash.  `hvpn-client --uninstall` stops and removes it.
//!
//! Only compiled on Windows.

use std::ffi::OsString;
use std::time::Duration;

use windows_service::service::{
    ServiceAccess, ServiceAction, ServiceActionType, ServiceErrorControl, ServiceFailureActions,
    ServiceFailureResetPeriod, ServiceInfo, ServiceStartType, ServiceState, ServiceType,
};
use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};

use super::service::SERVICE_NAME;

const SERVICE_DISPLAY_NAME: &str = "HVPN Client";
const SERVICE_DESCRIPTION: &str = "HVPN client tunnel service.";
/// Path to the config file the service launches with.
const DEFAULT_CONFIG: &str = r"C:\Program Files\HVPN\client.toml";

// ── Install ────────────────────────────────────────────────────────────────────

/// Register the HVPN client service with the SCM and configure it to
/// auto-start on boot and restart on failure.
pub fn install_service() -> windows_service::Result<()> {
    let manager_access = ServiceManagerAccess::CONNECT | ServiceManagerAccess::CREATE_SERVICE;
    let service_manager = ServiceManager::local_computer(None::<&str>, manager_access)?;

    // Resolve the path to this executable so the SCM can launch it.
    let exe_path = std::env::current_exe()
        .map_err(windows_service::Error::Winapi)?
        .with_file_name("hvpn-client.exe");

    let service_info = ServiceInfo {
        name: OsString::from(SERVICE_NAME),
        display_name: OsString::from(SERVICE_DISPLAY_NAME),
        service_type: ServiceType::OWN_PROCESS,
        start_type: ServiceStartType::AutoStart,
        error_control: ServiceErrorControl::Normal,
        executable_path: exe_path,
        // The service manager launches us with these flags; `--service` makes
        // main() enter the dispatcher path.
        launch_arguments: vec![
            OsString::from("--service"),
            OsString::from("--config"),
            OsString::from(DEFAULT_CONFIG),
        ],
        dependencies: vec![],
        account_name: None, // run as LocalSystem
        account_password: None,
    };

    let service_access = ServiceAccess::CHANGE_CONFIG | ServiceAccess::START;
    let service = service_manager.create_service(&service_info, service_access)?;
    service.set_description(SERVICE_DESCRIPTION)?;

    // Failure recovery: restart after 5 seconds, reset the failure counter
    // after one day.
    let actions = vec![ServiceAction {
        action_type: ServiceActionType::Restart,
        delay: Duration::from_secs(5),
    }];
    let failure_actions = ServiceFailureActions {
        reset_period: ServiceFailureResetPeriod::After(Duration::from_secs(86400)),
        reboot_msg: None,
        command: None,
        actions: Some(actions),
    };
    service.update_failure_actions(failure_actions)?;
    // Treat non-crash (non-zero exit) failures as recoverable too.
    service.set_failure_actions_on_non_crash_failures(true)?;

    Ok(())
}

// ── Uninstall ──────────────────────────────────────────────────────────────────

/// Stop (if running) and remove the HVPN client service from the SCM.
pub fn uninstall_service() -> windows_service::Result<()> {
    let manager_access = ServiceManagerAccess::CONNECT;
    let service_manager = ServiceManager::local_computer(None::<&str>, manager_access)?;

    let service_access =
        ServiceAccess::QUERY_STATUS | ServiceAccess::STOP | ServiceAccess::DELETE;
    let service = service_manager.open_service(SERVICE_NAME, service_access)?;

    // Stop the service first if it is running.
    if service.query_status()?.current_state != ServiceState::Stopped {
        service.stop()?;
    }

    // Mark for deletion (finalised once all handles are closed).
    service.delete()?;
    drop(service);

    Ok(())
}

// ── WinTun auto-download ───────────────────────────────────────────────────────

/// Download wintun.dll next to the executable if it is not already present.
/// Called at startup before the TUN device is opened.
#[cfg(target_os = "windows")]
pub fn ensure_wintun() -> anyhow::Result<()> {
    let exe_dir = std::env::current_exe()?
        .parent()
        .ok_or_else(|| anyhow::anyhow!("cannot determine exe directory"))?
        .to_path_buf();
    let dll_path = exe_dir.join("wintun.dll");
    if dll_path.exists() {
        return Ok(());
    }
    println!("[hvpn-client] wintun.dll not found — downloading...");
    let url = "https://www.wintun.net/builds/wintun-0.14.1.zip";
    let bytes = reqwest::blocking::get(url)?.bytes()?;
    let cursor = std::io::Cursor::new(bytes);
    let mut archive = zip::ZipArchive::new(cursor)?;
    for i in 0..archive.len() {
        let mut file = archive.by_index(i)?;
        let name = file.name().to_string();
        if name.ends_with("amd64/wintun.dll") {
            let mut out = std::fs::File::create(&dll_path)?;
            std::io::copy(&mut file, &mut out)?;
            println!("[hvpn-client] wintun.dll installed to {:?}", dll_path);
            return Ok(());
        }
    }
    anyhow::bail!("wintun.dll not found in downloaded zip")
}
