use hmac::{Hmac, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

/// Generate a 32-byte probe authentication token.
///
/// The token is `HMAC-SHA256(mac_key, timestamp_le || nonce)` truncated to
/// 32 bytes.
pub fn generate_probe_token(mac_key: &[u8; 32], timestamp: u64, nonce: &[u8; 16]) -> [u8; 32] {
    let mut mac =
        HmacSha256::new_from_slice(mac_key).expect("HMAC accepts any key length");

    mac.update(&timestamp.to_le_bytes());
    mac.update(nonce);

    let result = mac.finalize().into_bytes();
    let mut token = [0u8; 32];
    token.copy_from_slice(&result[..32]);
    token
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn probe_token_is_deterministic() {
        let mac_key = [0xABu8; 32];
        let ts = 1_700_000_000u64;
        let nonce = [0x01u8; 16];

        let t1 = generate_probe_token(&mac_key, ts, &nonce);
        let t2 = generate_probe_token(&mac_key, ts, &nonce);
        assert_eq!(t1, t2);
    }

    #[test]
    fn probe_token_changes_with_timestamp() {
        let mac_key = [0xABu8; 32];
        let nonce = [0x01u8; 16];

        let t1 = generate_probe_token(&mac_key, 1000, &nonce);
        let t2 = generate_probe_token(&mac_key, 1001, &nonce);
        assert_ne!(t1, t2);
    }
}
