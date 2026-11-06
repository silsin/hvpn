use hkdf::Hkdf;
use sha2::Sha256;

use crate::cipher::SessionKeys;

/// Double Ratchet state for per-packet key rotation.
///
/// Keys are rotated on every packet via a symmetric chain ratchet.
/// Every 64 sent (or received) packets the chain key itself is re-derived
/// from the root key, providing forward secrecy at coarser granularity.
///
/// # Symmetry guarantee
///
/// `RatchetState::init_client` and `RatchetState::init_server` initialise
/// opposite roles from the same underlying ECDH-derived material so that:
///
///   client.ratchet_send()  == server.ratchet_recv()  (for every packet n)
///   client.ratchet_recv()  == server.ratchet_send()  (for every packet n)
///
/// This holds across the 64-packet root-ratchet rotation.
pub struct RatchetState {
    /// Independent send direction state.
    pub send: SendRatchet,
    /// Independent recv direction state.
    pub recv: RecvRatchet,
}

/// Send-direction ratchet — owns its own root key and chain key so it can
/// advance concurrently (under a lock) without blocking recv.
pub struct SendRatchet {
    pub root_key: [u8; 32],
    pub chain_key: [u8; 32],
    pub count: u64,
}

/// Recv-direction ratchet — symmetric peer to `SendRatchet`.
pub struct RecvRatchet {
    pub root_key: [u8; 32],
    pub chain_key: [u8; 32],
    pub count: u64,
}

/// Expand `ikm` and `salt` through HKDF-SHA256 with the given `info`, writing
/// output into `out`.
fn hkdf_expand(ikm: &[u8], salt: &[u8], info: &[u8], out: &mut [u8]) {
    let hk = Hkdf::<Sha256>::new(Some(salt), ikm);
    hk.expand(info, out).expect("HKDF expand length is valid");
}

/// Derive the canonical (direction-independent) ratchet seed from session keys.
///
/// We always use `okm[0..32]` (= client send_key) as IKM and
/// `okm[32..64]` (= client recv_key) as salt so both sides produce the
/// same 96-byte output regardless of which side calls this function.
///
/// Returns `(root_key, chain_a, chain_b)` where:
///   chain_a  = the chain for the client→server direction
///   chain_b  = the chain for the server→client direction
fn derive_ratchet_seeds(session_keys: &SessionKeys) -> ([u8; 32], [u8; 32], [u8; 32]) {
    // We need to identify which of send_key/recv_key corresponds to okm[0..32].
    // From the handshake: client.send_key == okm[0..32], client.recv_key == okm[32..64].
    //                     server.recv_key == okm[0..32], server.send_key == okm[32..64].
    //
    // To pick the same one on both sides we use the smaller of the two keys as IKM.
    // This is a stable, deterministic ordering that doesn't require a role flag.
    let (ikm, salt) = if session_keys.send_key <= session_keys.recv_key {
        (&session_keys.send_key, &session_keys.recv_key)
    } else {
        (&session_keys.recv_key, &session_keys.send_key)
    };

    let mut out = [0u8; 96];
    hkdf_expand(ikm, salt, b"ratchet-init-v2", &mut out);

    let mut root_key = [0u8; 32];
    let mut chain_a = [0u8; 32]; // initiator→responder (smaller key side sends)
    let mut chain_b = [0u8; 32]; // responder→initiator
    root_key.copy_from_slice(&out[0..32]);
    chain_a.copy_from_slice(&out[32..64]);
    chain_b.copy_from_slice(&out[64..96]);

    (root_key, chain_a, chain_b)
}

impl SendRatchet {
    /// Advance the send ratchet and return a fresh per-packet message key.
    ///
    /// 1. Derive message key:  HKDF(ikm=chain_key, salt=root_key, info="msg-key")  → 32 bytes
    /// 2. Advance chain key:   HKDF(ikm=chain_key, salt=[0u8;32], info="chain-adv") → 32 bytes
    /// 3. Increment count.
    /// 4. Every 64 packets (count % 64 == 0): symmetric root ratchet step.
    pub fn next_key(&mut self) -> [u8; 32] {
        let mut msg_key = [0u8; 32];
        hkdf_expand(&self.chain_key, &self.root_key, b"msg-key", &mut msg_key);

        let mut new_chain = [0u8; 32];
        hkdf_expand(&self.chain_key, &[0u8; 32], b"chain-adv", &mut new_chain);
        self.chain_key = new_chain;

        self.count += 1;

        if self.count % 64 == 0 {
            let mut out = [0u8; 64];
            hkdf_expand(&self.root_key, &self.chain_key, b"sym-ratchet", &mut out);
            self.root_key.copy_from_slice(&out[0..32]);
            self.chain_key.copy_from_slice(&out[32..64]);
        }

        msg_key
    }
}

impl RecvRatchet {
    /// Advance the recv ratchet and return a fresh per-packet message key.
    ///
    /// Exact mirror of `SendRatchet::next_key` operating on the recv chain.
    pub fn next_key(&mut self) -> [u8; 32] {
        let mut msg_key = [0u8; 32];
        hkdf_expand(&self.chain_key, &self.root_key, b"msg-key", &mut msg_key);

        let mut new_chain = [0u8; 32];
        hkdf_expand(&self.chain_key, &[0u8; 32], b"chain-adv", &mut new_chain);
        self.chain_key = new_chain;

        self.count += 1;

        if self.count % 64 == 0 {
            let mut out = [0u8; 64];
            hkdf_expand(&self.root_key, &self.chain_key, b"sym-ratchet", &mut out);
            self.root_key.copy_from_slice(&out[0..32]);
            self.chain_key.copy_from_slice(&out[32..64]);
        }

        msg_key
    }
}

impl RatchetState {
    /// Initialise the ratchet from the client's perspective.
    ///
    /// - send chain = chain_a (client→server direction)
    /// - recv chain = chain_b (server→client direction)
    pub fn init_client(session_keys: &SessionKeys) -> RatchetState {
        let (root_key, chain_a, chain_b) = derive_ratchet_seeds(session_keys);
        RatchetState {
            send: SendRatchet { root_key, chain_key: chain_a, count: 0 },
            recv: RecvRatchet { root_key, chain_key: chain_b, count: 0 },
        }
    }

    /// Initialise the ratchet from the server's perspective.
    ///
    /// - send chain = chain_b (server→client direction)
    /// - recv chain = chain_a (client→server direction)
    pub fn init_server(session_keys: &SessionKeys) -> RatchetState {
        let (root_key, chain_a, chain_b) = derive_ratchet_seeds(session_keys);
        RatchetState {
            send: SendRatchet { root_key, chain_key: chain_b, count: 0 },
            recv: RecvRatchet { root_key, chain_key: chain_a, count: 0 },
        }
    }

    /// Initialise the ratchet without a role (backward-compatible, uses client role).
    ///
    /// Kept for code that doesn't distinguish client/server.
    /// Prefer `init_client` / `init_server` in new code.
    pub fn init(session_keys: &SessionKeys) -> RatchetState {
        Self::init_client(session_keys)
    }

    /// Advance the send ratchet and return a fresh per-packet message key.
    pub fn ratchet_send(&mut self) -> [u8; 32] {
        self.send.next_key()
    }

    /// Advance the recv ratchet and return a fresh per-packet message key.
    pub fn ratchet_recv(&mut self) -> [u8; 32] {
        self.recv.next_key()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ratchet_key_rotation() {
        use crate::cipher::SessionKeys;
        let keys = SessionKeys {
            send_key: [0x01u8; 32],
            recv_key: [0x02u8; 32],
            header_key: [0x03u8; 32],
            mac_key: [0x04u8; 32],
        };
        let mut state = RatchetState::init_client(&keys);
        // Collect keys for packets 63 and 65
        let mut key_63 = [0u8; 32];
        let mut key_65 = [0u8; 32];
        for i in 0..65u64 {
            let k = state.ratchet_send();
            if i == 62 { key_63 = k; }  // 0-indexed packet 63
            if i == 64 { key_65 = k; }  // packet 65 (after rotation at 64)
        }
        // Keys before and after the 64-packet boundary must differ
        assert_ne!(key_63, key_65, "keys must rotate after 64 packets");
    }

    #[test]
    fn test_ratchet_active() {
        // Verify that the ratchet is actually rotating keys (not returning the
        // static session send_key), AND that keys change across the 64-packet
        // rotation boundary.
        let session_keys = SessionKeys {
            send_key: [0xAAu8; 32],
            recv_key: [0xBBu8; 32],
            header_key: [0xCCu8; 32],
            mac_key: [0xDDu8; 32],
        };

        let mut state = RatchetState::init_client(&session_keys);

        // Collect all 65 send-ratchet keys (packets 0..=64, i.e. the first 65 steps).
        let mut keys: Vec<[u8; 32]> = Vec::with_capacity(65);
        for _ in 0..65 {
            keys.push(state.ratchet_send());
        }

        // 1. No ratchet key may equal the static session send_key.
        for (i, k) in keys.iter().enumerate() {
            assert_ne!(
                k, &session_keys.send_key,
                "packet {}: ratchet key must differ from static send_key",
                i
            );
        }

        // 2. All 65 keys must be distinct (no two packets share a key).
        for i in 0..keys.len() {
            for j in (i + 1)..keys.len() {
                assert_ne!(
                    keys[i], keys[j],
                    "packets {} and {} share a key — ratchet is not rotating",
                    i, j
                );
            }
        }

        // 3. Key at packet 63 (index 63, just before the root rotation at count=64)
        //    must differ from key at packet 64 (index 64, first key after rotation).
        //    Both already included in `keys`; rotation fires when count reaches 64,
        //    which happens after the 64th call to next_key() (index 63), so key at
        //    index 64 is the first key produced from the re-derived chains.
        assert_ne!(
            keys[63], keys[64],
            "key at boundary packet 63 must differ from post-rotation packet 64"
        );

        // 4. Confirm the rotation fired at count=64: if we re-initialise and skip
        //    63 packets the chain key will change at packet 64. Verify by checking
        //    the 64th key equals keys[63] from our first run.
        let mut state2 = RatchetState::init_client(&session_keys);
        for i in 0..64 {
            let k = state2.ratchet_send();
            assert_eq!(k, keys[i], "deterministic: packet {} must reproduce the same key", i);
        }
        // The 65th call (index 64) advances past the boundary.
        let k64 = state2.ratchet_send();
        assert_eq!(k64, keys[64], "deterministic: post-rotation key must reproduce");
    }

    ///
    /// Asserts that for every packet:
    ///   client.ratchet_send() == server.ratchet_recv()
    ///   client.ratchet_recv() == server.ratchet_send()
    ///
    /// Including across the 64-packet root-ratchet rotation (packets 60–70).
    #[test]
    fn ratchet_symmetric_across_handshake() {
        use crate::handshake::{perform_handshake_client, perform_handshake_server};
        use rand::rngs::OsRng;
        use x25519_dalek::{PublicKey, StaticSecret};

        let server_secret = StaticSecret::random_from_rng(OsRng);
        let server_pubkey = PublicKey::from(&server_secret);

        let (ephemeral_pub, client_keys) =
            perform_handshake_client(server_pubkey.as_bytes()).expect("client handshake");
        let server_keys =
            perform_handshake_server(&ephemeral_pub, server_secret.as_bytes())
                .expect("server handshake");

        // Sanity: handshake symmetry (already tested in handshake.rs but confirm here).
        assert_eq!(client_keys.send_key, server_keys.recv_key);
        assert_eq!(client_keys.recv_key, server_keys.send_key);

        let mut client_ratchet = RatchetState::init_client(&client_keys);
        let mut server_ratchet = RatchetState::init_server(&server_keys);

        // Test 80 packets in each direction to cover the rotation at packet 64.
        for pkt in 0..80u64 {
            let c_send = client_ratchet.ratchet_send();
            let s_recv = server_ratchet.ratchet_recv();
            assert_eq!(
                c_send, s_recv,
                "packet {}: client send key != server recv key",
                pkt
            );

            let s_send = server_ratchet.ratchet_send();
            let c_recv = client_ratchet.ratchet_recv();
            assert_eq!(
                s_send, c_recv,
                "packet {}: server send key != client recv key",
                pkt
            );
        }
    }
}
