/// NAT routing support for hvpn-server.
///
/// Compiled only on Linux.  The types and functions below are re-exported at
/// the module root so that `main.rs` can reference them inside
/// `#[cfg(target_os = "linux")]` blocks without any platform-specific syntax
/// at the call sites.

#[cfg(target_os = "linux")]
pub use linux_nat::{NatRouter, setup_nat};

#[cfg(target_os = "linux")]
mod linux_nat {
    use std::collections::HashMap;
    use std::net::{Ipv4Addr, SocketAddr};
    use std::sync::{Arc, Mutex};

    use hvpn_common::HvpnError;
    use tracing::{info, warn};

    // ── IP pool ───────────────────────────────────────────────────────────────
    // Client IPs are allocated from 10.8.0.2 upward; the server itself uses
    // 10.8.0.1.  POOL_END is exclusive (10.8.0.255 is the broadcast address).

    /// First IP to assign: 10.8.0.2
    const POOL_START: u32 = (10 << 24) | (8 << 16) | 2;
    /// Exclusive upper bound: 10.8.0.255
    const POOL_END: u32 = (10 << 24) | (8 << 16) | 255;

    // ── NatRouter ─────────────────────────────────────────────────────────────

    /// Tracks per-client IP assignments and the next free IP in the pool.
    pub struct NatRouter {
        /// Map from client socket address to assigned VPN IP.
        pub client_ips: Arc<Mutex<HashMap<SocketAddr, Ipv4Addr>>>,
        /// Next IP to hand out (stored as u32 for easy increment).
        next_ip: Mutex<u32>,
    }

    impl NatRouter {
        /// Create a new router with an empty client table.
        pub fn new() -> Self {
            Self {
                client_ips: Arc::new(Mutex::new(HashMap::new())),
                next_ip: Mutex::new(POOL_START),
            }
        }

        /// Assign (or re-use) a VPN IP for `addr`.  Returns `None` if the pool
        /// is exhausted.
        pub fn assign_client_ip(&self, addr: SocketAddr) -> Option<Ipv4Addr> {
            let mut map = self.client_ips.lock().unwrap();
            if let Some(existing) = map.get(&addr) {
                return Some(*existing);
            }
            let mut next = self.next_ip.lock().unwrap();
            if *next >= POOL_END {
                warn!("IP pool exhausted — cannot assign IP to {}", addr);
                return None;
            }
            let ip = Ipv4Addr::from(*next);
            *next += 1;
            map.insert(addr, ip);
            info!(client = %addr, assigned_ip = %ip, "assigned client IP");
            Some(ip)
        }

        /// Release the IP held by `addr` when the client disconnects.
        pub fn release_client_ip(&self, addr: &SocketAddr) {
            let mut map = self.client_ips.lock().unwrap();
            if let Some(ip) = map.remove(addr) {
                info!(client = %addr, released_ip = %ip, "released client IP");
            }
        }
    }

    // ── setup_nat ─────────────────────────────────────────────────────────────

    /// Prepare the server for NAT routing and return the raw TUN fd for reuse.
    pub fn setup_nat(tun_ip: &str) -> Result<std::os::unix::io::RawFd, HvpnError> {
        // 1. Create hvpn0 TUN interface and get its fd.
        let fd = open_tun_interface("hvpn0", tun_ip)
            .map_err(|e| HvpnError::Tun(e.to_string()))?;

        // 2. Enable IP forwarding.
        std::fs::write("/proc/sys/net/ipv4/ip_forward", "1\n")
            .map_err(|e| HvpnError::Tun(format!("enable ip_forward: {}", e)))?;
        info!("IP forwarding enabled");

        // 3. NAT masquerade for the VPN subnet.
        run_cmd(
            "iptables",
            &["-t", "nat", "-A", "POSTROUTING", "-s", "10.8.0.0/24", "-j", "MASQUERADE"],
        )?;
        info!("iptables NAT masquerade rule installed (10.8.0.0/24)");

        Ok(fd)
    }

    // ── helpers ───────────────────────────────────────────────────────────────

    /// Open `/dev/net/tun`, configure it as `iface_name`, assign `tun_ip/24`,
    /// bring the interface up, and return the raw file descriptor for reuse.
    fn open_tun_interface(iface_name: &str, tun_ip: &str) -> Result<std::os::unix::io::RawFd, String> {
        use std::fs::OpenOptions;
        use std::os::unix::io::{AsRawFd, IntoRawFd};

        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/net/tun")
            .map_err(|e| format!("open /dev/net/tun: {}", e))?;

        let raw_fd = file.as_raw_fd();

        const TUNSETIFF: u64 = 0x400454CA;
        const IFF_TUN: i16 = 0x0001;
        const IFF_NO_PI: i16 = 0x1000;

        #[repr(C)]
        struct Ifreq {
            ifr_name: [u8; 16],
            ifr_flags: i16,
            _pad: [u8; 22],
        }

        let mut ifr = Ifreq {
            ifr_name: [0u8; 16],
            ifr_flags: IFF_TUN | IFF_NO_PI,
            _pad: [0u8; 22],
        };
        let name_bytes = iface_name.as_bytes();
        let copy_len = name_bytes.len().min(15);
        ifr.ifr_name[..copy_len].copy_from_slice(&name_bytes[..copy_len]);

        let ret = unsafe { libc::ioctl(raw_fd, TUNSETIFF, &ifr as *const Ifreq as u64) };
        if ret < 0 {
            let errno = unsafe { *libc::__errno_location() };
            return Err(format!("TUNSETIFF ioctl failed (errno {})", errno));
        }

        let cidr = if tun_ip.contains('/') {
            tun_ip.to_string()
        } else {
            format!("{}/24", tun_ip)
        };
        run_cmd("ip", &["addr", "add", &cidr, "dev", iface_name])
            .map_err(|e| e.to_string())?;
        run_cmd("ip", &["link", "set", iface_name, "up"])
            .map_err(|e| e.to_string())?;

        info!(iface = iface_name, ip = tun_ip, "TUN interface configured");

        // Return the fd — caller owns it now.
        Ok(file.into_raw_fd())
    }

    /// Run an external command; return an error if it exits non-zero.
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
}
