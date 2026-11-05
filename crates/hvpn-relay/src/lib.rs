//! Multi-hop onion relay chain for HVPN.
//!
//! Implements layered onion encryption over ChaCha20-Poly1305, where each
//! relay peels exactly one layer before forwarding the packet to the next hop.

use hvpn_common::HvpnError;
use hvpn_crypto::{decrypt_packet, encrypt_packet, SessionKeys};
use hvpn_transport::{TransportConfig, WebSocketTransport};
use hvpn_transport::Transport;
use serde::{Deserialize, Serialize};

/// A single relay node in the hop chain.
#[derive(Debug, Clone)]
pub struct RelayHop {
    /// Hostname or IP address of this relay node.
    pub address: String,
    /// Node's X25519 public key (used for key agreement, stored for reference).
    pub pubkey: [u8; 32],
}

/// Sequence number used for all onion-layer encryption (fixed, since onion
/// layers are single-use and authenticated by the AEAD tag).
const ONION_SEQ: u64 = 0;

/// An onion-encrypted packet containing one layer per hop.
///
/// `layers[0]` is the outermost layer (for the entry relay);
/// `layers[last]` is the innermost layer (for the exit node).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OnionPacket {
    /// Encrypted layers, outermost first.
    pub layers: Vec<Vec<u8>>,
}

impl OnionPacket {
    /// Wrap `payload` in `hops.len()` onion layers using the provided session keys.
    ///
    /// Encryption proceeds from innermost (exit) to outermost (entry):
    /// - Exit layer: encrypt `payload`, prepend 32 zero bytes (no next hop).
    /// - Each outer layer i: encrypt the previous layer, prepend `hops[i+1].address`
    ///   padded/truncated to 32 bytes so the relay knows its successor.
    ///
    /// `layers` is stored outermost-first so `layers[0]` is what the entry node sees.
    pub fn wrap(payload: Vec<u8>, hops: &[RelayHop], session_keys: &[SessionKeys]) -> OnionPacket {
        assert_eq!(
            hops.len(),
            session_keys.len(),
            "hops and session_keys must be the same length"
        );
        assert!(!hops.is_empty(), "at least one hop is required");

        let n = hops.len();

        // Step 1: build the innermost (exit) layer.
        // Prepend 32 zero bytes to signal "no next hop" to the exit relay.
        let exit_addr = [0u8; 32];
        let mut inner: Vec<u8> = exit_addr.to_vec();
        inner.extend_from_slice(&payload);

        // encrypt_packet uses send_key; we reuse send_key for wrapping.
        let mut current_layer = encrypt_packet(&session_keys[n - 1], &inner, ONION_SEQ, None)
            .expect("exit layer encryption failed");

        // We'll collect layers from innermost to outermost, then reverse.
        let mut layers: Vec<Vec<u8>> = Vec::with_capacity(n);
        layers.push(current_layer.clone());

        // Step 2: wrap each outer layer from exit-1 down to entry (index 0).
        for i in (0..n - 1).rev() {
            // The next-hop address for layer i is hops[i+1].address.
            let next_addr = addr_to_32_bytes(&hops[i + 1].address);
            let mut plaintext: Vec<u8> = next_addr.to_vec();
            plaintext.extend_from_slice(&current_layer);

            current_layer = encrypt_packet(&session_keys[i], &plaintext, ONION_SEQ, None)
                .expect("outer layer encryption failed");

            layers.push(current_layer.clone());
        }

        // layers is currently [exit_layer, ..., entry_layer]; reverse to outermost-first.
        layers.reverse();

        OnionPacket { layers }
    }

    /// Peel the outermost layer using `key`.
    ///
    /// Returns `(inner_payload, next_hop)` where:
    /// - `inner_payload` is the data after the 32-byte address prefix.
    /// - `next_hop` is `None` at the exit node (all-zero prefix) or `Some(address)`.
    pub fn unwrap_layer(
        mut self,
        key: &SessionKeys,
    ) -> Result<(Vec<u8>, Option<String>), HvpnError> {
        if self.layers.is_empty() {
            return Err(HvpnError::Protocol("OnionPacket has no layers".to_string()));
        }

        // Take the outermost layer; decrypt uses recv_key.
        let outer = self.layers.remove(0);
        let plaintext = decrypt_packet(key, &outer, ONION_SEQ, None)?;

        if plaintext.len() < 32 {
            return Err(HvpnError::Protocol(
                "decrypted layer too short to contain address prefix".to_string(),
            ));
        }

        let addr_bytes = &plaintext[..32];
        let payload = plaintext[32..].to_vec();

        // All-zero address means this is the exit node.
        let next_hop = if addr_bytes.iter().all(|&b| b == 0) {
            None
        } else {
            // Trim trailing null bytes and interpret as UTF-8 address string.
            let trimmed = addr_bytes
                .iter()
                .rposition(|&b| b != 0)
                .map(|pos| &addr_bytes[..=pos])
                .unwrap_or(&[]);
            Some(
                String::from_utf8_lossy(trimmed).into_owned(),
            )
        };

        Ok((payload, next_hop))
    }
}

/// Action returned by the relay after peeling one onion layer.
#[derive(Debug)]
pub enum RelayAction {
    /// Forward the peeled packet bytes to the named next-hop address.
    Forward(Vec<u8>, String),
    /// This node is the exit; deliver the inner payload.
    Exit(Vec<u8>),
}

/// Routes onion packets between relay nodes.
pub struct RelayRouter;

impl RelayRouter {
    /// Serialize `packet` and forward it over a WebSocket to `next_hop`.
    ///
    /// `next_hop` should be a `host:port` string; the WebSocket path `/relay`
    /// is appended automatically.
    pub async fn forward(packet: OnionPacket, next_hop: &str) -> Result<(), HvpnError> {
        // Serialize the packet with bincode for a compact wire format.
        let bytes = bincode::serialize(&packet)
            .map_err(|e| HvpnError::Protocol(format!("serialization error: {e}")))?;

        // Parse host:port from next_hop.
        let (host, port) = parse_host_port(next_hop)?;

        let cfg = TransportConfig::new(host, port, "/relay");
        let transport = WebSocketTransport::connect(&cfg).await?;
        transport.send(bytes).await?;
        transport.close().await?;
        Ok(())
    }

    /// Deserialize raw bytes into an `OnionPacket`, peel one layer, and return
    /// the appropriate `RelayAction`.
    pub async fn handle_relay_packet(
        raw: Vec<u8>,
        our_key: &SessionKeys,
    ) -> RelayAction {
        let packet: OnionPacket = match bincode::deserialize(&raw) {
            Ok(p) => p,
            Err(e) => {
                return RelayAction::Exit(
                    format!("deserialization error: {e}").into_bytes(),
                );
            }
        };

        match packet.unwrap_layer(our_key) {
            Ok((payload, Some(next_hop))) => {
                // Re-wrap remaining layers into a new OnionPacket for forwarding.
                // After unwrap_layer, `payload` contains the serialized inner packet bytes.
                RelayAction::Forward(payload, next_hop)
            }
            Ok((payload, None)) => RelayAction::Exit(payload),
            Err(e) => RelayAction::Exit(format!("unwrap error: {e}").into_bytes()),
        }
    }
}

// ── helpers ──────────────────────────────────────────────────────────────────

/// Encode an address string into a fixed 32-byte array (padded with zeros,
/// truncated if longer than 32 bytes).
fn addr_to_32_bytes(addr: &str) -> [u8; 32] {
    let mut buf = [0u8; 32];
    let bytes = addr.as_bytes();
    let len = bytes.len().min(32);
    buf[..len].copy_from_slice(&bytes[..len]);
    buf
}

/// Split a `"host:port"` string into `(host, port)`.
fn parse_host_port(addr: &str) -> Result<(String, u16), HvpnError> {
    // Handle IPv6 bracket notation: [::1]:8080
    if addr.starts_with('[') {
        let bracket_end = addr
            .find(']')
            .ok_or_else(|| HvpnError::Protocol(format!("invalid address: {addr}")))?;
        let host = addr[1..bracket_end].to_string();
        let rest = &addr[bracket_end + 1..];
        let port_str = rest.strip_prefix(':').ok_or_else(|| {
            HvpnError::Protocol(format!("missing port in address: {addr}"))
        })?;
        let port = port_str
            .parse::<u16>()
            .map_err(|_| HvpnError::Protocol(format!("invalid port in address: {addr}")))?;
        return Ok((host, port));
    }

    // Plain host:port
    let colon = addr
        .rfind(':')
        .ok_or_else(|| HvpnError::Protocol(format!("missing port in address: {addr}")))?;
    let host = addr[..colon].to_string();
    let port = addr[colon + 1..]
        .parse::<u16>()
        .map_err(|_| HvpnError::Protocol(format!("invalid port in address: {addr}")))?;
    Ok((host, port))
}

// ── tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a `SessionKeys` where send_key == recv_key so round-trip works.
    fn make_keys(byte: u8) -> SessionKeys {
        SessionKeys {
            send_key: [byte; 32],
            recv_key: [byte; 32],
            header_key: [0u8; 32],
            mac_key: [0u8; 32],
        }
    }

    fn make_hop(address: &str, pubkey_byte: u8) -> RelayHop {
        RelayHop {
            address: address.to_string(),
            pubkey: [pubkey_byte; 32],
        }
    }

    #[test]
    fn test_onion_wrap_unwrap() {
        let payload = b"hello from the exit node".to_vec();

        // Three hops: entry -> middle -> exit
        let hops = vec![
            make_hop("relay1.example.com:8080", 0xAA),
            make_hop("relay2.example.com:8080", 0xBB),
            make_hop("relay3.example.com:8080", 0xCC),
        ];

        // Matching session keys; send_key == recv_key for test round-trips.
        let keys = vec![
            make_keys(0x11),
            make_keys(0x22),
            make_keys(0x33),
        ];

        let packet = OnionPacket::wrap(payload.clone(), &hops, &keys);
        assert_eq!(packet.layers.len(), 3, "should have one layer per hop");

        // --- Entry relay (hop 0) peels layer 0 ---
        // Its recv_key == keys[0].recv_key, but wrap used keys[0].send_key.
        // Because make_keys sets send_key == recv_key this round-trips correctly.
        let (inner0, next0) = packet.unwrap_layer(&keys[0]).expect("entry unwrap failed");
        assert_eq!(
            next0.as_deref(),
            Some("relay2.example.com:8080"),
            "entry hop should forward to relay2"
        );

        // `inner0` is the serialized remaining bytes (the two inner layers encoded
        // by wrap). Re-construct an OnionPacket from the remaining layers by
        // deserializing — in the real relay this arrives as the next raw packet.
        // For the test we replay by rebuilding: after unwrap_layer the payload
        // is the ciphertext of layers[1..], so wrap the two inner ciphertexts back.
        // Actually the simplest is to re-wrap with the known layers directly.
        // Let's reconstruct: inner0 is the plaintext of layers[0] after stripping
        // the 32-byte address, which IS layers[1] (the middle layer ciphertext).
        // We wrap it in a fresh OnionPacket with one layer to simulate forwarding.
        let packet2 = OnionPacket { layers: vec![inner0] };

        // --- Middle relay (hop 1) peels its layer ---
        let (inner1, next1) = packet2.unwrap_layer(&keys[1]).expect("middle unwrap failed");
        assert_eq!(
            next1.as_deref(),
            Some("relay3.example.com:8080"),
            "middle hop should forward to relay3"
        );

        let packet3 = OnionPacket { layers: vec![inner1] };

        // --- Exit relay (hop 2) peels its layer ---
        let (final_payload, next2) = packet3.unwrap_layer(&keys[2]).expect("exit unwrap failed");
        assert!(next2.is_none(), "exit node should have no next hop");
        assert_eq!(final_payload, payload, "recovered payload must match original");
    }

    #[test]
    fn test_addr_to_32_bytes_roundtrip() {
        let addr = "relay.example.com:9000";
        let encoded = addr_to_32_bytes(addr);
        let trimmed = encoded
            .iter()
            .rposition(|&b| b != 0)
            .map(|pos| &encoded[..=pos])
            .unwrap_or(&[]);
        assert_eq!(String::from_utf8_lossy(trimmed), addr);
    }

    #[test]
    fn test_addr_to_32_bytes_truncation() {
        // Addresses longer than 32 bytes should be truncated without panic.
        let long_addr = "this-is-a-very-long-hostname-that-exceeds-32-bytes.example.com:443";
        let encoded = addr_to_32_bytes(long_addr);
        assert_eq!(encoded.len(), 32);
    }

    #[test]
    fn test_parse_host_port() {
        let (host, port) = parse_host_port("relay.example.com:8080").unwrap();
        assert_eq!(host, "relay.example.com");
        assert_eq!(port, 8080);
    }

    #[test]
    fn test_parse_host_port_ipv6() {
        let (host, port) = parse_host_port("[::1]:9000").unwrap();
        assert_eq!(host, "::1");
        assert_eq!(port, 9000);
    }

    #[test]
    fn test_unwrap_layer_too_short() {
        let keys = make_keys(0x01);
        // Encrypt something shorter than 32 bytes as plaintext.
        // Actually we need to encrypt first so decryption succeeds, then check
        // that the length check fires. Encrypt a 10-byte plaintext.
        let short = vec![0u8; 10];
        let ct = encrypt_packet(&keys, &short, ONION_SEQ, None).unwrap();
        let packet = OnionPacket { layers: vec![ct] };
        let result = packet.unwrap_layer(&keys);
        assert!(result.is_err(), "should fail when decrypted layer < 32 bytes");
    }

    #[test]
    fn test_empty_packet_error() {
        let keys = make_keys(0x01);
        let packet = OnionPacket { layers: vec![] };
        assert!(packet.unwrap_layer(&keys).is_err());
    }
}
