//! Linux `/dev/net/tun` TUN device implementation.
//! Only compiled on Linux.

use async_trait::async_trait;
use hvpn_common::HvpnError;
use std::fs::OpenOptions;
use std::os::unix::io::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use tokio::io::unix::AsyncFd;

use crate::tun_trait::TunDevice;

// Linux ioctl constants for TUN/TAP
const TUNSETIFF: u64 = 0x400454CA;
const IFF_TUN: i16 = 0x0001;
const IFF_NO_PI: i16 = 0x1000;

/// Represents the ifreq structure used by TUNSETIFF ioctl.
#[repr(C)]
struct Ifreq {
    ifr_name: [u8; 16],
    ifr_flags: i16,
    _pad: [u8; 22],
}

/// Linux TUN device backed by `/dev/net/tun`.
///
/// The fd is non-blocking and driven by the reactor (`AsyncFd`), so reads and
/// writes take `&self` and can run concurrently on a shared `Arc<LinuxTun>`
/// without any lock (a read never blocks a write).
pub struct LinuxTun {
    fd: AsyncFd<OwnedFd>,
    /// Actual kernel interface name, e.g. `"hvpn0"`.
    ifname: String,
}

impl LinuxTun {
    /// Create a `LinuxTun` from an already-open raw file descriptor.
    /// The fd must already be configured with TUNSETIFF.
    /// Used by the server to reuse the fd opened by `setup_nat`.
    pub fn from_raw_fd(fd: RawFd, ifname: &str) -> Result<Self, HvpnError> {
        let owned = unsafe { OwnedFd::from_raw_fd(fd) };
        Ok(Self {
            fd: make_async_fd(owned)?,
            ifname: ifname.to_string(),
        })
    }

    /// Open and configure a new TUN device.
    ///
    /// - `iface_name` — desired interface name (e.g. `"hvpn0"`); empty means kernel-assigned.
    /// - `tun_ip`     — CIDR address to assign to the interface, e.g. `"10.8.0.2/24"`.
    /// - `server_ip`  — VPN server's real IP; will be routed outside the TUN so the tunnel
    ///                  itself does not recurse.
    pub async fn open(
        iface_name: &str,
        tun_ip: &str,
        server_ip: &str,
    ) -> Result<Self, HvpnError> {
        // ── 1. Open /dev/net/tun ─────────────────────────────────────────────
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/net/tun")
            .map_err(|e| HvpnError::Tun(format!("open /dev/net/tun: {}", e)))?;

        let raw_fd: RawFd = file.as_raw_fd();

        // ── 2. TUNSETIFF ─────────────────────────────────────────────────────
        let mut ifr = Ifreq {
            ifr_name: [0u8; 16],
            ifr_flags: IFF_TUN | IFF_NO_PI,
            _pad: [0u8; 22],
        };
        let name_bytes = iface_name.as_bytes();
        let copy_len = name_bytes.len().min(15);
        ifr.ifr_name[..copy_len].copy_from_slice(&name_bytes[..copy_len]);

        let ret = unsafe { libc_ioctl(raw_fd, TUNSETIFF, &ifr as *const Ifreq as u64) };
        if ret < 0 {
            let errno = unsafe { *libc::__errno_location() };
            return Err(HvpnError::Tun(format!(
                "TUNSETIFF ioctl failed: errno {}",
                errno
            )));
        }

        // Determine actual interface name assigned by the kernel.
        let ifname = std::str::from_utf8(
            ifr.ifr_name.split(|&b| b == 0).next().unwrap_or(&[]),
        )
        .unwrap_or("unknown")
        .to_string();

        // Convert to a non-blocking, reactor-driven fd.
        let tun = Self {
            fd: make_async_fd(OwnedFd::from(file))?,
            ifname,
        };

        // ── 3. IP / routing setup ────────────────────────────────────────────
        tun.configure_interface(tun_ip, server_ip)?;

        Ok(tun)
    }

    /// Assign address, bring the interface up, and install routes.
    fn configure_interface(&self, tun_ip: &str, server_ip: &str) -> Result<(), HvpnError> {
        // 3a. Assign IP address  (tun_ip must be in CIDR form, e.g. "10.8.0.2/24")
        run_cmd("ip", &["addr", "add", tun_ip, "dev", &self.ifname])?;

        // 3b. Bring the interface up
        run_cmd("ip", &["link", "set", &self.ifname, "up"])?;

        // 3c. Default route through TUN
        run_cmd(
            "ip",
            &["route", "add", "0.0.0.0/0", "dev", &self.ifname],
        )?;

        // 3d. Exclude the real server IP so traffic to it still goes via the
        //     physical default gateway (prevents tunnel recursion).
        let gateway = read_default_gateway()?;
        run_cmd(
            "ip",
            &[
                "route",
                "add",
                &format!("{}/32", server_ip),
                "via",
                &gateway,
            ],
        )?;

        Ok(())
    }

    /// Read one IP packet. Takes `&self`; safe to call concurrently with
    /// `write_shared` on the same device.
    pub async fn read_shared(&self) -> Result<Vec<u8>, HvpnError> {
        // TUN MTU is <= 1500 in practice; 4 KiB leaves ample headroom and
        // avoids zeroing/allocating 64 KiB per packet.
        let mut buf = [0u8; 4096];
        loop {
            let mut guard = self
                .fd
                .readable()
                .await
                .map_err(|e| HvpnError::Tun(e.to_string()))?;
            match guard.try_io(|inner| {
                let n = unsafe {
                    libc::read(inner.as_raw_fd(), buf.as_mut_ptr() as *mut libc::c_void, buf.len())
                };
                if n < 0 {
                    Err(std::io::Error::last_os_error())
                } else {
                    Ok(n as usize)
                }
            }) {
                Ok(Ok(n)) => return Ok(buf[..n].to_vec()),
                Ok(Err(e)) => return Err(HvpnError::Tun(e.to_string())),
                Err(_would_block) => continue,
            }
        }
    }

    /// Write one IP packet. Takes `&self`; safe to call concurrently with
    /// `read_shared` on the same device.
    pub async fn write_shared(&self, pkt: &[u8]) -> Result<(), HvpnError> {
        loop {
            let mut guard = self
                .fd
                .writable()
                .await
                .map_err(|e| HvpnError::Tun(e.to_string()))?;
            match guard.try_io(|inner| {
                let n = unsafe {
                    libc::write(inner.as_raw_fd(), pkt.as_ptr() as *const libc::c_void, pkt.len())
                };
                if n < 0 {
                    Err(std::io::Error::last_os_error())
                } else {
                    Ok(n as usize)
                }
            }) {
                Ok(Ok(_)) => return Ok(()),
                Ok(Err(e)) => return Err(HvpnError::Tun(e.to_string())),
                Err(_would_block) => continue,
            }
        }
    }

    /// Set the MTU of the TUN interface.
    pub fn set_mtu(&self, mtu: u32) -> Result<(), HvpnError> {
        run_cmd(
            "ip",
            &["link", "set", &self.ifname, "mtu", &mtu.to_string()],
        )
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Put `fd` in non-blocking mode and register it with the tokio reactor.
/// Must be called from within a tokio runtime.
fn make_async_fd(fd: OwnedFd) -> Result<AsyncFd<OwnedFd>, HvpnError> {
    let raw = fd.as_raw_fd();
    unsafe {
        let flags = libc::fcntl(raw, libc::F_GETFL);
        if flags < 0 || libc::fcntl(raw, libc::F_SETFL, flags | libc::O_NONBLOCK) < 0 {
            return Err(HvpnError::Tun(format!(
                "set O_NONBLOCK: {}",
                std::io::Error::last_os_error()
            )));
        }
    }
    AsyncFd::new(fd).map_err(|e| HvpnError::Tun(format!("register tun fd: {}", e)))
}

/// Run an external command and return an error if it exits non-zero.
fn run_cmd(prog: &str, args: &[&str]) -> Result<(), HvpnError> {
    let status = std::process::Command::new(prog)
        .args(args)
        .status()
        .map_err(|e| HvpnError::Tun(format!("spawn `{} {}`: {}", prog, args.join(" "), e)))?;

    if status.success() {
        Ok(())
    } else {
        Err(HvpnError::Tun(format!(
            "`{} {}` exited with {}",
            prog,
            args.join(" "),
            status
        )))
    }
}

/// Parse `/proc/net/route` and return the IPv4 gateway of the default route
/// as a dotted-decimal string (e.g. `"192.168.1.1"`).
///
/// The file has space-separated fields; the default route is the line whose
/// Destination field is `00000000`. The Gateway field is the third column,
/// stored as a little-endian 32-bit hex value.
fn read_default_gateway() -> Result<String, HvpnError> {
    let content = std::fs::read_to_string("/proc/net/route")
        .map_err(|e| HvpnError::Tun(format!("read /proc/net/route: {}", e)))?;

    for line in content.lines().skip(1) {
        // Columns: Iface Destination Gateway Flags RefCnt Use Metric Mask MTU Window IRTT
        let cols: Vec<&str> = line.split_whitespace().collect();
        if cols.len() < 3 {
            continue;
        }
        if cols[1] == "00000000" {
            // Gateway is little-endian hex; parse as u32 and convert.
            let gw_hex = cols[2];
            let gw_u32 = u32::from_str_radix(gw_hex, 16)
                .map_err(|e| HvpnError::Tun(format!("parse gateway hex '{}': {}", gw_hex, e)))?;
            // Little-endian: byte 0 = bits 0-7 of u32, etc.
            let b0 = (gw_u32 & 0xFF) as u8;
            let b1 = ((gw_u32 >> 8) & 0xFF) as u8;
            let b2 = ((gw_u32 >> 16) & 0xFF) as u8;
            let b3 = (gw_u32 >> 24) as u8;
            return Ok(format!("{}.{}.{}.{}", b0, b1, b2, b3));
        }
    }

    Err(HvpnError::Tun(
        "no default route found in /proc/net/route".to_string(),
    ))
}

/// Thin wrapper around the raw `ioctl` syscall.
unsafe fn libc_ioctl(fd: RawFd, request: u64, arg: u64) -> i64 {
    libc::ioctl(fd, request, arg) as i64
}

// ── TunDevice impl ────────────────────────────────────────────────────────────

#[async_trait]
impl TunDevice for LinuxTun {
    async fn read_packet(&mut self) -> Result<Vec<u8>, HvpnError> {
        self.read_shared().await
    }

    async fn write_packet(&mut self, pkt: &[u8]) -> Result<(), HvpnError> {
        self.write_shared(pkt).await
    }
}
