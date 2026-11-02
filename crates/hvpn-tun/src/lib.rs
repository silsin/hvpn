mod stub;
mod tun_trait;

#[cfg(target_os = "linux")]
mod linux;

pub use stub::StubTun;
pub use tun_trait::TunDevice;

#[cfg(target_os = "linux")]
pub use linux::LinuxTun;
