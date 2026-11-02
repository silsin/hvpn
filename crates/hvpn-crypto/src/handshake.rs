use hkdf::Hkdf;
use hvpn_common::HvpnError;
use rand::rngs::OsRng;
use sha2::Sha512;
use x25519_dalek::{EphemeralSecret, PublicKey, StaticSecret};

use crate::cipher::SessionKeys;

/// HKDF-SHA512 context label
const HKDF_INFO: &[u8] = b"HVPN-v1-session-keys";

/// Derive four 32-byte sub-keys from a shared secret via HKDF-SHA512.
fn derive_session_keys(shared_secret: &[u8]) -> Result<SessionKeys, HvpnError> {
    let hk = Hkdf::<Sha512>::new(None, shared_secret);
    let mut okm = [0u8; 128]; // 4 × 32 bytes
    hk.expand(HKDF_INFO, &mut okm)
        .map_err(|e| HvpnError::Crypto(e.to_string()))?;

    let mut send_key = [0u8; 32];
    let mut recv_key = [0u8; 32];
    let mut header_key = [0u8; 32];
    let mut mac_key = [0u8; 32];

    send_key.copy_from_slice(&okm[0..32]);
    recv_key.copy_from_slice(&okm[32..64]);
    header_key.copy_from_slice(&okm[64..96]);
    mac_key.copy_from_slice(&okm[96..128]);

    Ok(SessionKeys {
        send_key,
        recv_key,
        header_key,
        mac_key,
    })
}

/// **Client side** of the X25519 handshake.
///
/// Returns `(ephemeral_pubkey_bytes, session_keys)`.
/// The caller must send `ephemeral_pubkey_bytes` to the server, then the
/// server's response gives the server static public key (already known here).
pub fn perform_handshake_client(
    server_pubkey_bytes: &[u8; 32],
) -> Result<([u8; 32], SessionKeys), HvpnError> {
    let ephemeral_secret = EphemeralSecret::random_from_rng(OsRng);
    let ephemeral_public = PublicKey::from(&ephemeral_secret);

    let server_pubkey = PublicKey::from(*server_pubkey_bytes);
    let shared = ephemeral_secret.diffie_hellman(&server_pubkey);

    let keys = derive_session_keys(shared.as_bytes())?;
    Ok((*ephemeral_public.as_bytes(), keys))
}

/// **Server side** of the X25519 handshake.
///
/// `client_ephemeral_pubkey_bytes` is the 32-byte ephemeral public key sent
/// by the client. `server_static_secret_bytes` is the server's long-term
/// X25519 private key (stored as 32 bytes).
pub fn perform_handshake_server(
    client_ephemeral_pubkey_bytes: &[u8; 32],
    server_static_secret_bytes: &[u8; 32],
) -> Result<SessionKeys, HvpnError> {
    let server_static = StaticSecret::from(*server_static_secret_bytes);
    let client_ephemeral = PublicKey::from(*client_ephemeral_pubkey_bytes);
    let shared = server_static.diffie_hellman(&client_ephemeral);

    // Mirror the client's HKDF so both sides produce the same key material.
    // The server's HKDF input is the same shared secret; send/recv are
    // intentionally swapped from the client's perspective.
    let hk = Hkdf::<Sha512>::new(None, shared.as_bytes());
    let mut okm = [0u8; 128];
    hk.expand(HKDF_INFO, &mut okm)
        .map_err(|e| HvpnError::Crypto(e.to_string()))?;

    // From the client's view: okm[0..32] = send, okm[32..64] = recv.
    // From the server's view those are swapped.
    let mut recv_key = [0u8; 32]; // what client sends → server recvs
    let mut send_key = [0u8; 32]; // what server sends → client recvs
    let mut header_key = [0u8; 32];
    let mut mac_key = [0u8; 32];

    recv_key.copy_from_slice(&okm[0..32]);
    send_key.copy_from_slice(&okm[32..64]);
    header_key.copy_from_slice(&okm[64..96]);
    mac_key.copy_from_slice(&okm[96..128]);

    Ok(SessionKeys {
        send_key,
        recv_key,
        header_key,
        mac_key,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use x25519_dalek::StaticSecret;

    #[test]
    fn handshake_produces_matching_send_recv_keys() {
        // Generate a server static key pair.
        let server_secret = StaticSecret::random_from_rng(OsRng);
        let server_pubkey = PublicKey::from(&server_secret);

        // Client side.
        let (ephemeral_pub, client_keys) =
            perform_handshake_client(server_pubkey.as_bytes()).expect("client handshake");

        // Server side.
        let server_keys =
            perform_handshake_server(&ephemeral_pub, server_secret.as_bytes())
                .expect("server handshake");

        // Client send == Server recv, and vice-versa.
        assert_eq!(client_keys.send_key, server_keys.recv_key);
        assert_eq!(client_keys.recv_key, server_keys.send_key);
        assert_eq!(client_keys.header_key, server_keys.header_key);
        assert_eq!(client_keys.mac_key, server_keys.mac_key);
    }
}
