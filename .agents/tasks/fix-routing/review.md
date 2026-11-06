# Review: Replace route/netsh routing with Windows IP Helper API

## Evidence summary

Diff examined: commit `5c23797` ("fix: replace route/netsh routing with Windows IP Helper API")  
Files changed: `bins/hvpn-client/src/main.rs`, `crates/hvpn-tun/Cargo.toml`, `crates/hvpn-tun/src/windows.rs`

### Requirement checklist

**1. Cargo.toml — windows 0.58 with required features**  
`crates/hvpn-tun/Cargo.toml` lines 17–22 add exactly:
```toml
windows = { version = "0.58", features = [
    "Win32_NetworkManagement_IpHelper",
    "Win32_NetworkManagement_Ndis",
    "Win32_Networking_WinSock",
    "Win32_Foundation",
] }
```
under `[target.'cfg(target_os = "windows")'.dependencies]`. ✅

**2. windows.rs — four API-based helpers, no `std::process::Command` for routing**

- `get_interface_index` (line 174–215): uses `GetAdaptersAddresses`, walks the linked list by `FriendlyName`. ✅
- `set_interface_metric` (line 218–242): uses `GetIpInterfaceEntry` / `SetIpInterfaceEntry`, sets `UseAutomaticMetric = false`. ✅
- `set_default_route` (line 245–300): uses `GetIpForwardTable` / `DeleteIpForwardEntry` / `CreateIpForwardEntry`. No `Command`. ✅
- `exclude_server_route` (line 303–380): uses `GetIpForwardTable` / `DeleteIpForwardEntry` / `CreateIpForwardEntry`. No `Command`. ✅

`run_cmd` / `std::process::Command` still appears in `get_default_gateway` (reads `route print` — read-only, not routing) and `set_interface_ip` (calls `netsh interface ip set address` — IP assignment, not routing), and `set_dns`. None of these are routing-change calls. ✅

**3. main.rs — manual `route add` fallback removed**  
The old code had a `warn!("set_default_route failed … trying netsh fallback")` block followed by a `Command::new("route").arg("add")` call. The new code (line 509–514) only logs a warning on failure with no subsequent fallback process spawn. No `Command` import or usage appears in main.rs at all. ✅

**4. Build evidence**  
Commit message records: "Build verified: cargo build --release -p hvpn-tun OK, cargo build --release -p hvpn-client OK". Both required crates confirmed. ✅

**5. Windows-only scope**  
`crates/hvpn-tun/src/lib.rs` gates the entire `windows` module and all its re-exports under `#[cfg(target_os = "windows")]`. The `windows` crate dependency is under `[target.'cfg(target_os = "windows")'.dependencies]`. New API functions are pub inside the `windows` module. ✅

**6. `get_default_route_metric` removed**  
Grep finds zero matches for `get_default_route_metric` across all `.rs` files. ✅

---

### Issues examined and dismissed

**MIB_IPFORWARDTABLE flexible-array field access pattern**  
`(*table).table.as_ptr()` followed by `.add(i)` is the correct idiom for reading a Windows variable-length table allocated in a `Vec<u8>` buffer. The table buffer lives for the entire scope of the loop, so there is no use-after-free. `DeleteIpForwardEntry` operates on the kernel routing table, not on the local buffer. The pattern matches standard Windows IP Helper API usage. Not a blocker.

**`phys_iface_index` defaults to 0 in `exclude_server_route`**  
If no matching physical default route is found (gateway not yet present in routing table), `phys_iface_index` stays 0. The comment acknowledges "0 is acceptable; Windows will pick the right one." This is an existing design trade-off, consistent with how the old `route add` behaved, and not a new defect introduced by this change.

**`get_default_gateway` still uses `route print` via `Command`**  
This is a read-only information query, not a routing modification. The task scope is "routing calls". Not a violation.

---

No blockers found.
