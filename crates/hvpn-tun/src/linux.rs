//! Linux `/dev/net/tun` TUN device implementation.
//! Only compiled on Linux.

use async_trait::async_trait;
use hvpn_common::HvpnError;
use std::fs::OpenOptions;
use std::os::unix::io::{AsRawFd, RawFd};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::fs::File;

use crate::tun_trait::TunDevice;

// Linux ioctl constants for TUN/TAP
const TUNSETIFF: u64 = 0x400454CA;
const IFF_TUN:  i16 = 0x0001;
const IFF_NO_PI: i16 = 0x1000;

/// Represents the ifreq structure used by TUNSETIFF ioctl.
#[repr(C)]
struct Ifreq {
    ifr_name: [u8; 16],
    ifr_flags: i16,
    _pad: [u8; 22],
}

/// Linux TUN device backed by `/dev/net/tun`.
pub struct LinuxTun {
    file: File,
    #[allow(dead_code)]
    iface_name: String,
}

impl LinuxTun {
    /// Open and configure a new TUN device.
    ///
    /// `iface_name` is the desired interface name (e.g. `"hvpn0"`). If the
    /// name is an empty string the kernel assigns one automatically.
    pub async fn open(iface_name: &str) -> Result<Self, HvpnError> {
        // Open /dev/net/tun.
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/net/tun")
            .map_err(|e| HvpnError::Tun(format!("open /dev/net/tun: {}", e)))?;

        let raw_fd: RawFd = file.as_raw_fd();

        // Build the ifreq struct.
        let mut ifr = Ifreq {
            ifr_name: [0u8; 16],
            ifr_flags: IFF_TUN | IFF_NO_PI,
            _pad: [0u8; 22],
        };
        let name_bytes = iface_name.as_bytes();
        let copy_len = name_bytes.len().min(15);
        ifr.ifr_name[..copy_len].copy_from_slice(&name_bytes[..copy_len]);

        // Issue TUNSETIFF ioctl.
        let ret = unsafe { libc_ioctl(raw_fd, TUNSETIFF, &ifr as *const Ifreq as u64) };
        if ret < 0 {
            return Err(HvpnError::Tun(format!(
                "TUNSETIFF ioctl failed: errno {}",
                ret
            )));
        }

        // Determine actual interface name.
        let actual_name = std::str::from_utf8(
            ifr.ifr_name.split(|&b| b == 0).next().unwrap_or(&[]),
        )
        .unwrap_or("unknown")
        .to_string();

        // Convert to async Tokio file.
        let async_file = File::from_std(file);

        Ok(Self {
            file: async_file,
            iface_name: actual_name,
        })
    }
}

/// Thin wrapper around the raw `ioctl` syscall.
#[cfg(target_os = "linux")]
unsafe fn libc_ioctl(fd: RawFd, request: u64, arg: u64) -> i64 {
    libc::ioctl(fd, request, arg) as i64
}

#[async_trait]
impl TunDevice for LinuxTun {
    async fn read_packet(&mut self) -> Result<Vec<u8>, HvpnError> {
        let mut buf = vec![0u8; 65535];
        let n = self
            .file
            .read(&mut buf)
            .await
            .map_err(|e| HvpnError::Tun(e.to_string()))?;
        buf.truncate(n);
        Ok(buf)
    }

    async fn write_packet(&mut self, pkt: &[u8]) -> Result<(), HvpnError> {
        self.file
            .write_all(pkt)
            .await
            .map_err(|e| HvpnError::Tun(e.to_string()))
    }
}
