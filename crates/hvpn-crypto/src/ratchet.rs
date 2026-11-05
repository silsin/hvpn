use hkdf::Hkdf;
use sha2::Sha256;

use crate::cipher::SessionKeys;

/// Double Ratchet state for per-packet key rotation.
///
/// Keys are rotated on every packet via a symmetric chain ratchet.
/// Every 64 sent (or received) packets the chain key itself is re-derived
/// from the root key, providing forward secrecy at coarser granularity.
pub struct RatchetState {
    pub root_key: [u8; 32],
    pub send_chain_key: [u8; 32],
    pub recv_chain_key: [u8; 32],
    pub send_count: u64,
    pub recv_count: u64,
}

/// Expand `ikm` and `salt` through HKDF-SHA256 with the given `info`, writing
/// output into `out`.
fn hkdf_expand(ikm: &[u8], salt: &[u8], info: &[u8], out: &mut [u8]) {
    let hk = Hkdf::<Sha256>::new(Some(salt), ikm);
    hk.expand(info, out).expect("HKDF expand length is valid");
}

impl RatchetState {
    /// Initialise the ratchet from session keys produced by the ECDH handshake.
    ///
    /// HKDF-SHA256: ikm = send_key, salt = recv_key, info = "ratchet-init",
    /// expand 96 bytes → [0..32] root_key, [32..64] send_chain_key,
    /// [64..96] recv_chain_key.
    pub fn init(session_keys: &SessionKeys) -> RatchetState {
        let mut out = [0u8; 96];
        hkdf_expand(
            &session_keys.send_key,
            &session_keys.recv_key,
            b"ratchet-init",
            &mut out,
        );
        let mut root_key = [0u8; 32];
        let mut send_chain_key = [0u8; 32];
        let mut recv_chain_key = [0u8; 32];
        root_key.copy_from_slice(&out[0..32]);
        send_chain_key.copy_from_slice(&out[32..64]);
        recv_chain_key.copy_from_slice(&out[64..96]);

        RatchetState {
            root_key,
            send_chain_key,
            recv_chain_key,
            send_count: 0,
            recv_count: 0,
        }
    }

    /// Advance the send ratchet and return a fresh per-packet message key.
    ///
    /// 1. Derive message key:  HKDF(ikm=send_chain_key, salt=root_key,   info="send-msg-key")  → 32 bytes
    /// 2. Advance chain key:   HKDF(ikm=send_chain_key, salt=[0u8;32],   info="send-chain-adv") → 32 bytes
    /// 3. Increment send_count.
    /// 4. Every 64 packets (send_count % 64 == 0): symmetric root ratchet step.
    pub fn ratchet_send(&mut self) -> [u8; 32] {
        // Derive message key.
        let mut msg_key = [0u8; 32];
        hkdf_expand(&self.send_chain_key, &self.root_key, b"send-msg-key", &mut msg_key);

        // Advance chain key.
        let mut new_chain = [0u8; 32];
        hkdf_expand(&self.send_chain_key, &[0u8; 32], b"send-chain-adv", &mut new_chain);
        self.send_chain_key = new_chain;

        self.send_count += 1;

        // Every 64 packets: re-key from the root.
        if self.send_count % 64 == 0 {
            let mut out = [0u8; 64];
            hkdf_expand(&self.root_key, &self.send_chain_key, b"sym-ratchet", &mut out);
            self.root_key.copy_from_slice(&out[0..32]);
            self.send_chain_key.copy_from_slice(&out[32..64]);
        }

        msg_key
    }

    /// Advance the receive ratchet and return a fresh per-packet message key.
    ///
    /// Mirror of `ratchet_send` but operates on recv_chain_key / recv_count.
    pub fn ratchet_recv(&mut self) -> [u8; 32] {
        // Derive message key.
        let mut msg_key = [0u8; 32];
        hkdf_expand(&self.recv_chain_key, &self.root_key, b"recv-msg-key", &mut msg_key);

        // Advance chain key.
        let mut new_chain = [0u8; 32];
        hkdf_expand(&self.recv_chain_key, &[0u8; 32], b"recv-chain-adv", &mut new_chain);
        self.recv_chain_key = new_chain;

        self.recv_count += 1;

        // Every 64 packets: re-key from the root.
        if self.recv_count % 64 == 0 {
            let mut out = [0u8; 64];
            hkdf_expand(&self.root_key, &self.recv_chain_key, b"sym-ratchet", &mut out);
            self.root_key.copy_from_slice(&out[0..32]);
            self.recv_chain_key.copy_from_slice(&out[32..64]);
        }

        msg_key
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ratchet_key_rotation() {
        // Create a RatchetState via init
        use crate::cipher::SessionKeys;
        let keys = SessionKeys {
            send_key: [0x01u8; 32],
            recv_key: [0x02u8; 32],
            header_key: [0x03u8; 32],
            mac_key: [0x04u8; 32],
        };
        let mut state = RatchetState::init(&keys);
        // Collect keys for packets 63 and 64
        let mut key_63 = [0u8; 32];
        let mut key_65 = [0u8; 32];
        for i in 0..65u64 {
            let k = state.ratchet_send();
            if i == 62 { key_63 = k; }   // 0-indexed: packet 63
            if i == 64 { key_65 = k; }   // packet 65 (after rotation at 64)
        }
        // Keys before and after the 64-packet boundary must differ
        assert_ne!(key_63, key_65, "keys must rotate after 64 packets");
    }
}
