//! Per-client VPN addressing and return-path routing.
//!
//! Every connection gets its own address from `10.8.0.0/24`. Packets coming
//! back from the shared TUN device are routed to the right client by their
//! destination address, and packets from a client are only accepted if their
//! source address is the one assigned to it (anti-spoofing).
//!
//! Platform independent so it can be unit-tested anywhere.

use dashmap::DashMap;
use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Mutex;
use tokio::sync::mpsc;

/// First assignable address: 10.8.0.2 (10.8.0.1 is the server).
const POOL_START: u32 = (10 << 24) | (8 << 16) | 2;
/// Exclusive end: 10.8.0.255 is broadcast.
const POOL_END: u32 = (10 << 24) | (8 << 16) | 255;

pub struct ClientRouter {
    assigned: Mutex<HashMap<SocketAddr, Ipv4Addr>>,
    routes: DashMap<Ipv4Addr, mpsc::Sender<Vec<u8>>>,
}

impl ClientRouter {
    pub fn new() -> Self {
        Self { assigned: Mutex::new(HashMap::new()), routes: DashMap::new() }
    }

    /// Assign (or return the existing) address for a connection. Freed
    /// addresses are reused, so the pool never runs dry over time.
    pub fn assign(&self, addr: SocketAddr) -> Option<Ipv4Addr> {
        let mut map = self.assigned.lock().unwrap();
        if let Some(ip) = map.get(&addr) {
            return Some(*ip);
        }
        let used: std::collections::HashSet<Ipv4Addr> = map.values().copied().collect();
        let ip = (POOL_START..POOL_END).map(Ipv4Addr::from).find(|ip| !used.contains(ip))?;
        map.insert(addr, ip);
        Some(ip)
    }

    /// Send return traffic for `ip` into `tx`.
    pub fn register(&self, ip: Ipv4Addr, tx: mpsc::Sender<Vec<u8>>) {
        self.routes.insert(ip, tx);
    }

    /// Forget a connection: frees its address and return route.
    pub fn release(&self, addr: &SocketAddr) {
        if let Some(ip) = self.assigned.lock().unwrap().remove(addr) {
            self.routes.remove(&ip);
        }
    }

    /// Deliver a packet read from the TUN device to the client that owns its
    /// destination address. Returns `false` if it was dropped (unknown
    /// destination, non-IPv4, or that client's queue is full).
    pub fn dispatch(&self, pkt: Vec<u8>) -> bool {
        match ipv4_dst(&pkt).and_then(|ip| self.routes.get(&ip)) {
            Some(tx) => tx.try_send(pkt).is_ok(),
            None => false,
        }
    }

    pub fn client_count(&self) -> usize {
        self.assigned.lock().unwrap().len()
    }
}

/// Destination address of an IPv4 packet.
pub fn ipv4_dst(pkt: &[u8]) -> Option<Ipv4Addr> {
    (pkt.len() >= 20 && pkt[0] >> 4 == 4).then(|| Ipv4Addr::new(pkt[16], pkt[17], pkt[18], pkt[19]))
}

/// Source address of an IPv4 packet.
pub fn ipv4_src(pkt: &[u8]) -> Option<Ipv4Addr> {
    (pkt.len() >= 20 && pkt[0] >> 4 == 4).then(|| Ipv4Addr::new(pkt[12], pkt[13], pkt[14], pkt[15]))
}

/// Magic prefix of the in-band address assignment message sent over
/// WebSocket (QUIC carries the address in its auth acknowledgement instead).
pub const ASSIGN_MAGIC: &[u8; 4] = b"HVIP";

#[cfg(test)]
mod tests {
    use super::*;

    fn pkt(src: [u8; 4], dst: [u8; 4]) -> Vec<u8> {
        let mut p = vec![0u8; 40];
        p[0] = 0x45;
        p[12..16].copy_from_slice(&src);
        p[16..20].copy_from_slice(&dst);
        p
    }

    #[test]
    fn clients_get_distinct_addresses_and_are_reused_after_release() {
        let r = ClientRouter::new();
        let a: SocketAddr = "1.1.1.1:1000".parse().unwrap();
        let b: SocketAddr = "2.2.2.2:2000".parse().unwrap();
        let ia = r.assign(a).unwrap();
        let ib = r.assign(b).unwrap();
        assert_eq!(ia, Ipv4Addr::new(10, 8, 0, 2));
        assert_eq!(ib, Ipv4Addr::new(10, 8, 0, 3));
        assert_eq!(r.assign(a), Some(ia)); // idempotent
        r.release(&a);
        let c: SocketAddr = "3.3.3.3:3000".parse().unwrap();
        assert_eq!(r.assign(c), Some(ia)); // freed address reused
    }

    #[test]
    fn pool_survives_many_reconnects() {
        let r = ClientRouter::new();
        for i in 0..2000u16 {
            let a: SocketAddr = format!("9.9.9.9:{}", 1000 + i).parse().unwrap();
            assert!(r.assign(a).is_some(), "exhausted at {i}");
            r.release(&a);
        }
    }

    #[test]
    fn pool_exhaustion_returns_none() {
        let r = ClientRouter::new();
        for i in 0..253u16 {
            assert!(r.assign(format!("9.9.9.9:{}", 1000 + i).parse().unwrap()).is_some());
        }
        assert!(r.assign("8.8.8.8:1".parse().unwrap()).is_none());
    }

    #[tokio::test]
    async fn return_traffic_goes_to_the_right_client() {
        let r = ClientRouter::new();
        let a: SocketAddr = "1.1.1.1:1".parse().unwrap();
        let b: SocketAddr = "2.2.2.2:2".parse().unwrap();
        let (ia, ib) = (r.assign(a).unwrap(), r.assign(b).unwrap());
        let (ta, mut ra) = mpsc::channel(8);
        let (tb, mut rb) = mpsc::channel(8);
        r.register(ia, ta);
        r.register(ib, tb);

        assert!(r.dispatch(pkt([8, 8, 8, 8], ib.octets())));
        assert!(r.dispatch(pkt([8, 8, 8, 8], ia.octets())));
        assert_eq!(ipv4_dst(&rb.recv().await.unwrap()), Some(ib));
        assert_eq!(ipv4_dst(&ra.recv().await.unwrap()), Some(ia));

        assert!(!r.dispatch(pkt([8, 8, 8, 8], [10, 8, 0, 200]))); // unknown client
        assert!(!r.dispatch(vec![0x60; 40])); // IPv6 is dropped
        r.release(&b);
        assert!(!r.dispatch(pkt([8, 8, 8, 8], ib.octets()))); // route gone
    }

    #[test]
    fn src_dst_parsing() {
        let p = pkt([10, 8, 0, 2], [1, 1, 1, 1]);
        assert_eq!(ipv4_src(&p), Some(Ipv4Addr::new(10, 8, 0, 2)));
        assert_eq!(ipv4_dst(&p), Some(Ipv4Addr::new(1, 1, 1, 1)));
        assert_eq!(ipv4_src(&[0u8; 10]), None);
    }
}
