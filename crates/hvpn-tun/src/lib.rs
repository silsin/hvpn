mod stub;
mod tun_trait;

#[cfg(target_os = "linux")]
mod linux;

#[cfg(target_os = "windows")]
mod windows;

pub use stub::StubTun;
pub use tun_trait::TunDevice;

#[cfg(target_os = "linux")]
pub use linux::LinuxTun;

#[cfg(target_os = "windows")]
pub use windows::WinTunDevice;

#[cfg(target_os = "windows")]
pub use windows::{exclude_server_route, get_default_gateway, set_default_route, set_dns};

/// Platform-native TUN device type alias.
///
/// - Linux  → [`LinuxTun`]
/// - Windows → [`WinTunDevice`]
/// - other  → [`StubTun`]
#[cfg(target_os = "linux")]
pub type PlatformTun = LinuxTun;

#[cfg(target_os = "windows")]
pub type PlatformTun = WinTunDevice;

#[cfg(not(any(target_os = "linux", target_os = "windows")))]
pub type PlatformTun = StubTun;
