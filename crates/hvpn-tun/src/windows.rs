//! Windows WinTun TUN device implementation.
//!
//! Backed by the official WinTun kernel driver from WireGuard, accessed through
//! the safe `wintun` crate.  Requires `wintun.dll` to be present at runtime
//! (download from <https://wintun.net>); the code still compiles without it.
//!
//! Only compiled on Windows.

use async_trait::async_trait;
use hvpn_common::HvpnError;
use std::sync::Arc;
use tokio::sync::mpsc;

use crate::tun_trait::TunDevice;

/// Windows TUN device backed by the WinTun driver.
///
/// Reads are served from a background OS thread that loops on
/// [`wintun::Session::receive_blocking`] and forwards packets through a
/// `tokio::sync::mpsc` channel.  Writes allocate a send packet directly on the
/// session.  Both the adapter and session close themselves on drop.
pub struct WinTunDevice {
    /// Owns the kernel adapter; dropping it closes the adapter.
    _adapter: Arc<wintun::Adapter>,
    /// Shared session used by the writer and the background reader thread.
    session: Arc<wintun::Session>,
    /// Friendly interface name, used for `netsh` commands.
    iface_name: String,
    /// Receive channel fed by the background blocking-reader thread.
    rx: mpsc::Receiver<Vec<u8>>,
}

impl WinTunDevice {
    /// Open and configure a new WinTun device.
    ///
    /// - `iface_name` — friendly name for the adapter (e.g. `"hvpn0"`).
    /// - `tun_ip`     — IP address to assign.  May be bare (`"10.8.0.2"`) or in
    ///                  CIDR form (`"10.8.0.2/24"`); a bare IP defaults to `/24`.
    /// - `server_ip`  — VPN server's real IP; a host route is installed so traffic
    ///                  to it bypasses the tunnel (prevents recursion).
    pub async fn open(
        iface_name: &str,
        tun_ip: &str,
        server_ip: &str,
    ) -> Result<Self, HvpnError> {
        // ── 1. Load the wintun.dll driver ───────────────────────────────────
        let wintun = unsafe { wintun::load() }
            .map_err(|e| HvpnError::Tun(format!("load wintun.dll: {:?}", e)))?;

        // ── 2. Create or open the adapter ───────────────────────────────────
        let adapter = match wintun::Adapter::open(&wintun, iface_name) {
            Ok(a) => a,
            Err(_) => {
                wintun::Adapter::create(&wintun, iface_name, "HVPN", None)
                    .map_err(|e| HvpnError::Tun(format!("create wintun adapter: {:?}", e)))?
            }
        };

        // ── 3. Start a session ─────────────────────────────────────────────
        let session = adapter
            .start_session(wintun::MAX_RING_CAPACITY)
            .map_err(|e| HvpnError::Tun(format!("start wintun session: {:?}", e)))?;
        let session = Arc::new(session);

        // ── 4. Assign the IP address via netsh ─────────────────────────────
        let (ip, mask) = split_cidr_or_default(tun_ip);
        set_interface_ip(iface_name, &ip, &mask)?;

        // ── 5. Exclude the real server IP from the tunnel (best effort) ────
        if let Ok(gateway) = get_default_gateway() {
            let _ = exclude_server_route(server_ip, &gateway);
        }

        // ── 6. Spawn the background blocking reader thread ─────────────────
        let (tx, rx) = mpsc::channel::<Vec<u8>>(1024);
        let session_clone = Arc::clone(&session);
        std::thread::Builder::new()
            .name("wintun-reader".to_string())
            .spawn(move || reader_loop(session_clone, tx))
            .map_err(|e| HvpnError::Tun(format!("spawn wintun reader thread: {}", e)))?;

        Ok(Self {
            _adapter: adapter,
            session,
            iface_name: iface_name.to_string(),
            rx,
        })
    }

    /// Set the MTU of the WinTun interface.
    pub fn set_mtu(&self, mtu: u32) -> Result<(), HvpnError> {
        run_cmd(
            "netsh",
            &[
                "interface",
                "ip",
                "set",
                "subinterface",
                &self.iface_name,
                &format!("mtu={}", mtu),
            ],
        )
    }

    /// Gracefully stop the reader thread and release all resources.
    ///
    /// Cancels any active `receive_blocking` call so the background thread can
    /// exit; the session and adapter are then closed when this struct is dropped.
    pub fn close(&mut self) {
        let _ = self.session.shutdown();
    }
}

impl Drop for WinTunDevice {
    fn drop(&mut self) {
        // Ensure the blocking reader wakes up and exits even if `close` was not
        // called explicitly.
        let _ = self.session.shutdown();
    }
}

// ── TunDevice impl ────────────────────────────────────────────────────────────

#[async_trait]
impl TunDevice for WinTunDevice {
    async fn read_packet(&mut self) -> Result<Vec<u8>, HvpnError> {
        self.rx
            .recv()
            .await
            .ok_or_else(|| HvpnError::Tun("wintun reader channel closed".to_string()))
    }

    async fn write_packet(&mut self, pkt: &[u8]) -> Result<(), HvpnError> {
        let len =
            u16::try_from(pkt.len()).map_err(|_| HvpnError::Tun("packet too large for wintun".into()))?;

        let mut send = self
            .session
            .allocate_send_packet(len)
            .map_err(|e| HvpnError::Tun(format!("allocate send packet: {:?}", e)))?;
        send.bytes_mut()[..pkt.len()].copy_from_slice(pkt);
        self.session.send_packet(send);
        Ok(())
    }
}

// ── Background reader ─────────────────────────────────────────────────────────

/// Loop on the blocking WinTun receiver, copying each packet into a `Vec` and
/// forwarding it through the channel.  Exits when the session is shut down or the
/// receiver is dropped.
fn reader_loop(session: Arc<wintun::Session>, tx: mpsc::Sender<Vec<u8>>) {
    loop {
        match session.receive_blocking() {
            Ok(packet) => {
                let data = packet.bytes().to_vec();
                if tx.blocking_send(data).is_err() {
                    // Receiver dropped — device is gone, stop the thread.
                    break;
                }
            }
            Err(_) => {
                // Session shut down or a driver error — stop the thread.
                break;
            }
        }
    }
}

// ── Route / DNS helpers (Step 2) ───────────────────────────────────────────────

/// Look up the Windows interface index for an adapter by its friendly name.
pub fn get_interface_index(iface_name: &str) -> Result<u32, HvpnError> {
    use windows::Win32::NetworkManagement::IpHelper::{
        GetAdaptersAddresses, IP_ADAPTER_ADDRESSES_LH, GAA_FLAG_INCLUDE_ALL_INTERFACES,
        GET_ADAPTERS_ADDRESSES_FLAGS,
    };
    use windows::Win32::Networking::WinSock::AF_UNSPEC;
    use windows::Win32::Foundation::ERROR_BUFFER_OVERFLOW;

    let mut buf_len: u32 = 15000;
    let mut buf: Vec<u8> = vec![0u8; buf_len as usize];
    let flags = GET_ADAPTERS_ADDRESSES_FLAGS(GAA_FLAG_INCLUDE_ALL_INTERFACES.0);

    // First call may return ERROR_BUFFER_OVERFLOW with the required size.
    let mut result = unsafe {
        GetAdaptersAddresses(
            AF_UNSPEC.0 as u32,
            flags,
            None,
            Some(buf.as_mut_ptr() as *mut IP_ADAPTER_ADDRESSES_LH),
            &mut buf_len,
        )
    };
    if result == ERROR_BUFFER_OVERFLOW.0 {
        buf.resize(buf_len as usize, 0);
        result = unsafe {
            GetAdaptersAddresses(
                AF_UNSPEC.0 as u32,
                flags,
                None,
                Some(buf.as_mut_ptr() as *mut IP_ADAPTER_ADDRESSES_LH),
                &mut buf_len,
            )
        };
    }
    if result != 0 {
        return Err(HvpnError::Tun(format!("GetAdaptersAddresses failed: {}", result)));
    }

    // Walk the linked list.
    let mut ptr = buf.as_ptr() as *const IP_ADAPTER_ADDRESSES_LH;
    while !ptr.is_null() {
        let adapter = unsafe { &*ptr };
        let friendly = unsafe { adapter.FriendlyName.to_string() }
            .unwrap_or_default();
        if friendly.eq_ignore_ascii_case(iface_name) {
            return Ok(unsafe { adapter.Anonymous1.Anonymous.IfIndex });
        }
        ptr = adapter.Next;
    }
    Err(HvpnError::Tun(format!("interface '{}' not found", iface_name)))
}

/// Set a fixed metric on a network interface, disabling automatic metric selection.
pub fn set_interface_metric(iface_index: u32, metric: u32) -> Result<(), HvpnError> {
    use windows::Win32::NetworkManagement::IpHelper::{
        GetIpInterfaceEntry, SetIpInterfaceEntry, MIB_IPINTERFACE_ROW,
    };
    use windows::Win32::Networking::WinSock::AF_INET;
    use windows::Win32::Foundation::NO_ERROR;

    let mut row: MIB_IPINTERFACE_ROW = unsafe { std::mem::zeroed() };
    row.Family = AF_INET;
    row.InterfaceIndex = iface_index;

    let result = unsafe { GetIpInterfaceEntry(&mut row) };
    if result != NO_ERROR {
        return Err(HvpnError::Tun(format!("GetIpInterfaceEntry failed: {:?}", result)));
    }

    row.Metric = metric;
    row.UseAutomaticMetric = false.into();

    let result = unsafe { SetIpInterfaceEntry(&mut row) };
    if result != NO_ERROR {
        return Err(HvpnError::Tun(format!("SetIpInterfaceEntry failed: {:?}", result)));
    }
    Ok(())
}

/// Install a default route (`0.0.0.0/0`) through the WinTun interface using the
/// Windows IP Helper API. This avoids the metric problems caused by `route add`.
pub fn set_default_route(iface_name: &str, gateway_ip: &str) -> Result<(), HvpnError> {
    use windows::Win32::NetworkManagement::IpHelper::{
        CreateIpForwardEntry, DeleteIpForwardEntry, GetIpForwardTable,
        MIB_IPFORWARDROW, MIB_IPFORWARDTABLE,
    };
    use std::net::Ipv4Addr;

    let iface_index = get_interface_index(iface_name)?;

    let gw_addr: Ipv4Addr = gateway_ip.parse()
        .map_err(|_| HvpnError::Tun(format!("invalid gateway IP: {}", gateway_ip)))?;
    // Windows DWORD fields store IPv4 addresses in network byte order (big-endian).
    let gw_dword = u32::from_be_bytes(gw_addr.octets());

    // Delete any existing 0.0.0.0/0 routes through this interface.
    let mut table_size: u32 = 0;
    let _ = unsafe { GetIpForwardTable(None, &mut table_size, false) };
    let mut table_buf: Vec<u8> = vec![0u8; table_size as usize];
    let ret = unsafe {
        GetIpForwardTable(
            Some(table_buf.as_mut_ptr() as *mut MIB_IPFORWARDTABLE),
            &mut table_size,
            false,
        )
    };
    if ret == 0 {
        let table = table_buf.as_ptr() as *const MIB_IPFORWARDTABLE;
        let n_rows = unsafe { (*table).dwNumEntries } as usize;
        let rows_ptr = unsafe { (*table).table.as_ptr() };
        for i in 0..n_rows {
            let row = unsafe { &*rows_ptr.add(i) };
            if row.dwForwardDest == 0 && row.dwForwardMask == 0 && row.dwForwardIfIndex == iface_index {
                let _ = unsafe { DeleteIpForwardEntry(row as *const MIB_IPFORWARDROW) };
            }
        }
    }

    // Build the new default route entry.
    let mut row: MIB_IPFORWARDROW = unsafe { std::mem::zeroed() };
    row.dwForwardDest     = 0;   // 0.0.0.0
    row.dwForwardMask     = 0;   // 0.0.0.0
    row.dwForwardNextHop  = gw_dword;
    row.dwForwardIfIndex  = iface_index;
    row.dwForwardMetric1  = 1;
    row.Anonymous1.dwForwardType     = 4;   // MIB_IPROUTE_TYPE_INDIRECT
    row.Anonymous2.dwForwardProto    = 3;   // MIB_IPPROTO_NETMGMT

    let ret = unsafe { CreateIpForwardEntry(&row) };
    if ret != 0 {
        return Err(HvpnError::Tun(format!("CreateIpForwardEntry failed: {}", ret)));
    }
    Ok(())
}

/// Add a host route for `server_ip` via the physical gateway so traffic to the
/// VPN server bypasses the tunnel (prevents routing recursion).
pub fn exclude_server_route(server_ip: &str, gateway: &str) -> Result<(), HvpnError> {
    use windows::Win32::NetworkManagement::IpHelper::{
        CreateIpForwardEntry, DeleteIpForwardEntry, GetIpForwardTable,
        MIB_IPFORWARDROW, MIB_IPFORWARDTABLE,
    };
    use std::net::Ipv4Addr;

    let srv_addr: Ipv4Addr = server_ip.parse()
        .map_err(|_| HvpnError::Tun(format!("invalid server IP: {}", server_ip)))?;
    let gw_addr: Ipv4Addr = gateway.parse()
        .map_err(|_| HvpnError::Tun(format!("invalid gateway: {}", gateway)))?;
    let srv_dword = u32::from_be_bytes(srv_addr.octets());
    let gw_dword  = u32::from_be_bytes(gw_addr.octets());
    // 255.255.255.255 — all octets 0xFF so byte order is irrelevant.
    let host_mask_dword = u32::from_be_bytes([255, 255, 255, 255]);

    // Find the physical interface index and remove any stale server host route.
    let mut phys_iface_index: u32 = 0;
    let mut table_size: u32 = 0;
    let _ = unsafe { GetIpForwardTable(None, &mut table_size, false) };
    let mut table_buf: Vec<u8> = vec![0u8; table_size as usize];
    let ret = unsafe {
        GetIpForwardTable(
            Some(table_buf.as_mut_ptr() as *mut MIB_IPFORWARDTABLE),
            &mut table_size,
            false,
        )
    };
    if ret == 0 {
        let table = table_buf.as_ptr() as *const MIB_IPFORWARDTABLE;
        let n_rows = unsafe { (*table).dwNumEntries } as usize;
        let rows_ptr = unsafe { (*table).table.as_ptr() };
        // Find the physical default route (0.0.0.0/0) that goes via the given gateway.
        for i in 0..n_rows {
            let row = unsafe { &*rows_ptr.add(i) };
            if row.dwForwardDest == 0 && row.dwForwardMask == 0 && row.dwForwardNextHop == gw_dword {
                phys_iface_index = row.dwForwardIfIndex;
                break;
            }
        }
        // Delete any existing host route for server_ip.
        for i in 0..n_rows {
            let row = unsafe { &*rows_ptr.add(i) };
            if row.dwForwardDest == srv_dword && row.dwForwardMask == host_mask_dword {
                let _ = unsafe { DeleteIpForwardEntry(row as *const MIB_IPFORWARDROW) };
            }
        }
    }

    // Add a host route for server_ip via the physical gateway.
    let mut row: MIB_IPFORWARDROW = unsafe { std::mem::zeroed() };
    row.dwForwardDest     = srv_dword;
    row.dwForwardMask     = host_mask_dword;
    row.dwForwardNextHop  = gw_dword;
    row.dwForwardIfIndex  = phys_iface_index; // 0 is acceptable; Windows will pick the right one
    row.dwForwardMetric1  = 1;
    row.Anonymous1.dwForwardType     = 4; // MIB_IPROUTE_TYPE_INDIRECT
    row.Anonymous2.dwForwardProto    = 3; // MIB_IPPROTO_NETMGMT

    let ret = unsafe { CreateIpForwardEntry(&row) };
    if ret != 0 {
        return Err(HvpnError::Tun(format!("CreateIpForwardEntry for server route failed: {}", ret)));
    }
    Ok(())
}

/// Configure DNS servers for the WinTun interface.
///
/// The first server is set as the primary; additional servers are appended with
/// increasing indices.
pub fn set_dns(iface_name: &str, dns_servers: &[String]) -> Result<(), HvpnError> {
    if dns_servers.is_empty() {
        return Ok(());
    }

    // First server: set as primary.
    run_cmd(
        "netsh",
        &[
            "interface",
            "ip",
            "set",
            "dns",
            &format!("name=\"{}\"", iface_name),
            "static",
            &dns_servers[0],
            "primary",
        ],
    )?;

    // Additional servers: append with index starting at 2.
    for (i, dns) in dns_servers.iter().enumerate().skip(1) {
        run_cmd(
            "netsh",
            &[
                "interface",
                "ip",
                "add",
                "dns",
                &format!("name=\"{}\"", iface_name),
                dns,
                &format!("index={}", i + 1),
            ],
        )?;
    }

    Ok(())
}

/// Parse `route print` output and return the IPv4 gateway of the default route
/// (the `0.0.0.0/0` entry with the lowest metric) as a dotted-decimal string.
pub fn get_default_gateway() -> Result<String, HvpnError> {
    let output = std::process::Command::new("route")
        .arg("print")
        .output()
        .map_err(|e| HvpnError::Tun(format!("run `route print`: {}", e)))?;

    let text = String::from_utf8_lossy(&output.stdout);
    parse_default_gateway(&text)
        .ok_or_else(|| HvpnError::Tun("no default route found in `route print`".to_string()))
}

/// Pure parser used by [`get_default_gateway`]; separated so it can be unit tested
/// without spawning a process.
fn parse_default_gateway(route_print_output: &str) -> Option<String> {
    let mut best: Option<(u32, String)> = None;

    for line in route_print_output.lines() {
        let cols: Vec<&str> = line.split_whitespace().collect();
        // IPv4 route rows: Network Destination, Netmask, Gateway, Interface, Metric
        if cols.len() < 5 {
            continue;
        }
        if cols[0] == "0.0.0.0" && cols[1] == "0.0.0.0" {
            let gateway = cols[2].to_string();
            let metric: u32 = cols[4].parse().unwrap_or(u32::MAX);
            match &best {
                None => best = Some((metric, gateway)),
                Some((m, _)) if metric < *m => best = Some((metric, gateway)),
                _ => {}
            }
        }
    }

    best.map(|(_, g)| g)
}

// ── Command helpers ───────────────────────────────────────────────────────────

/// Assign a static IPv4 address and netmask to `iface_name` via `netsh`.
fn set_interface_ip(iface_name: &str, ip: &str, netmask: &str) -> Result<(), HvpnError> {
    // Set static IP address.
    run_cmd(
        "netsh",
        &[
            "interface", "ip", "set", "address",
            &format!("name=\"{}\"", iface_name),
            "static", ip, netmask,
        ],
    )?;

    // Set the interface metric via the IP Helper API so Windows cannot
    // override it with automatic metric selection.
    if let Ok(idx) = get_interface_index(iface_name) {
        let _ = set_interface_metric(idx, 1);
    }

    Ok(())
}

/// Split an address that may be in CIDR form (`"10.8.0.2/24"`) into an IP and a
/// dotted-decimal netmask.  A bare IP defaults to a `/24` mask.
fn split_cidr_or_default(tun_ip: &str) -> (String, String) {
    if let Some((ip, prefix)) = tun_ip.split_once('/') {
        let mask = prefix
            .parse::<u8>()
            .ok()
            .and_then(prefix_to_netmask)
            .unwrap_or_else(|| "255.255.255.0".to_string());
        (ip.to_string(), mask)
    } else {
        (tun_ip.to_string(), "255.255.255.0".to_string())
    }
}

/// Convert an IPv4 prefix length (0–32) into a dotted-decimal netmask.
fn prefix_to_netmask(prefix: u8) -> Option<String> {
    if prefix > 32 {
        return None;
    }
    let bits: u32 = if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix as u32)
    };
    Some(format!(
        "{}.{}.{}.{}",
        (bits >> 24) & 0xFF,
        (bits >> 16) & 0xFF,
        (bits >> 8) & 0xFF,
        bits & 0xFF
    ))
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

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prefix_to_netmask_known_values() {
        assert_eq!(prefix_to_netmask(0), Some("0.0.0.0".to_string()));
        assert_eq!(prefix_to_netmask(8), Some("255.0.0.0".to_string()));
        assert_eq!(prefix_to_netmask(16), Some("255.255.0.0".to_string()));
        assert_eq!(prefix_to_netmask(24), Some("255.255.255.0".to_string()));
        assert_eq!(prefix_to_netmask(32), Some("255.255.255.255".to_string()));
        assert_eq!(prefix_to_netmask(33), None);
    }

    #[test]
    fn split_cidr_bare_ip_defaults_to_24() {
        let (ip, mask) = split_cidr_or_default("10.8.0.2");
        assert_eq!(ip, "10.8.0.2");
        assert_eq!(mask, "255.255.255.0");
    }

    #[test]
    fn split_cidr_with_prefix_uses_prefix_mask() {
        let (ip, mask) = split_cidr_or_default("10.8.0.2/16");
        assert_eq!(ip, "10.8.0.2");
        assert_eq!(mask, "255.255.0.0");
    }

    #[test]
    fn parse_default_gateway_picks_lowest_metric() {
        let output = "\
IPv4 Route Table
===========================================================================
Active Routes:
Network Destination        Netmask          Gateway       Interface  Metric
          0.0.0.0          0.0.0.0      192.168.1.1      192.168.1.5     25
          0.0.0.0          0.0.0.0      10.0.0.1        10.0.0.5        10
        127.0.0.0        255.0.0.0         On-link         127.0.0.1    331
===========================================================================
";
        assert_eq!(parse_default_gateway(output), Some("10.0.0.1".to_string()));
    }

    #[test]
    fn parse_default_gateway_none_when_no_default_route() {
        let output = "Network Destination        Netmask          Gateway       Interface  Metric\n  127.0.0.0  255.0.0.0  On-link  127.0.0.1  331\n";
        assert_eq!(parse_default_gateway(output), None);
    }
}
