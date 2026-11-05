use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Key, Nonce,
};
use hvpn_common::HvpnError;

use crate::ratchet::RatchetState;

/// Per-session symmetric keys derived from the ECDH handshake.
#[derive(Clone)]
pub struct SessionKeys {
    /// ChaCha20-Poly1305 key for outbound (send) traffic.
    pub send_key: [u8; 32],
    /// ChaCha20-Poly1305 key for inbound (recv) traffic.
    pub recv_key: [u8; 32],
    /// Key used to encrypt/decrypt frame headers.
    pub header_key: [u8; 32],
    /// HMAC-SHA256 key used for probe-token generation/verification.
    pub mac_key: [u8; 32],
}

/// Build a 12-byte nonce by placing `seq_num` as little-endian u64 in the
/// first 8 bytes and leaving the remaining 4 bytes zero.
fn nonce_from_seq(seq_num: u64) -> Nonce {
    let mut nonce = [0u8; 12];
    nonce[..8].copy_from_slice(&seq_num.to_le_bytes());
    *Nonce::from_slice(&nonce)
}

/// Encrypt `plaintext` using the session send key (or a ratchet-derived key).
///
/// When `ratchet` is `Some`, a fresh per-packet key is derived via
/// `ratchet.ratchet_send()` and used instead of `keys.send_key`.
/// When `ratchet` is `None`, `keys.send_key` is used unchanged (backward compat).
///
/// Returns `ciphertext || tag` (ChaCha20-Poly1305 appends a 16-byte tag).
pub fn encrypt_packet(
    keys: &SessionKeys,
    plaintext: &[u8],
    seq_num: u64,
    ratchet: Option<&mut RatchetState>,
) -> Result<Vec<u8>, HvpnError> {
    let raw_key: [u8; 32] = match ratchet {
        Some(r) => r.ratchet_send(),
        None => keys.send_key,
    };
    let key = Key::from_slice(&raw_key);
    let cipher = ChaCha20Poly1305::new(key);
    let nonce = nonce_from_seq(seq_num);
    cipher
        .encrypt(&nonce, plaintext)
        .map_err(|e| HvpnError::Crypto(e.to_string()))
}

/// Decrypt `ciphertext` (which must include the 16-byte AEAD tag).
///
/// When `ratchet` is `Some`, a fresh per-packet key is derived via
/// `ratchet.ratchet_recv()` and used instead of `keys.recv_key`.
/// When `ratchet` is `None`, `keys.recv_key` is used unchanged (backward compat).
pub fn decrypt_packet(
    keys: &SessionKeys,
    ciphertext: &[u8],
    seq_num: u64,
    ratchet: Option<&mut RatchetState>,
) -> Result<Vec<u8>, HvpnError> {
    let raw_key: [u8; 32] = match ratchet {
        Some(r) => r.ratchet_recv(),
        None => keys.recv_key,
    };
    let key = Key::from_slice(&raw_key);
    let cipher = ChaCha20Poly1305::new(key);
    let nonce = nonce_from_seq(seq_num);
    cipher
        .decrypt(&nonce, ciphertext)
        .map_err(|e| HvpnError::Crypto(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_keys() -> SessionKeys {
        SessionKeys {
            send_key: [0x01u8; 32],
            recv_key: [0x01u8; 32], // same key so we can round-trip
            header_key: [0x02u8; 32],
            mac_key: [0x03u8; 32],
        }
    }

    #[test]
    fn encrypt_decrypt_round_trip() {
        let keys = test_keys();
        let plaintext = b"Hello, HVPN tunnel!";
        let seq = 42u64;

        let ciphertext = encrypt_packet(&keys, plaintext, seq, None).expect("encrypt failed");
        let decrypted = decrypt_packet(&keys, &ciphertext, seq, None).expect("decrypt failed");

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn wrong_seq_fails_decryption() {
        let keys = test_keys();
        let plaintext = b"sensitive data";
        let ciphertext = encrypt_packet(&keys, plaintext, 1, None).expect("encrypt");
        // Using a different sequence number produces a different nonce → AEAD tag mismatch
        assert!(decrypt_packet(&keys, &ciphertext, 2, None).is_err());
    }
}
