#![allow(deprecated)] // ExpandedKeyEncoding is deprecated in ml-kem 0.3.x but still functional.

use hkdf::Hkdf;
use hvpn_common::error::HvpnError;
use ml_kem::{
    array::Array, Decapsulate, Encapsulate, ExpandedKeyEncoding, Kem, KeyExport, MlKem768,
    TryKeyInit,
};
use rand::{CryptoRng, RngCore};
use sha2::Sha512;
use x25519_dalek::{EphemeralSecret, PublicKey, StaticSecret};

// ML-KEM-768 sizes (FIPS 203):
//   encapsulation (public) key : 1184 bytes
//   decapsulation (secret) key : 2400 bytes (expanded form)
//   ciphertext                 : 1088 bytes
//   shared secret              : 32 bytes
const PQ_PUBLIC_LEN: usize = 1184;
const PQ_SECRET_LEN: usize = 2400;
const PQ_CT_LEN: usize = 1088;
const X25519_PUB_LEN: usize = 32;

/// A hybrid X25519 + ML-KEM-768 keypair.
pub struct HybridKeypair {
    /// X25519 static secret for the classical ECDH leg.
    pub classical: StaticSecret,
    /// ML-KEM-768 encapsulation (public) key bytes (1184 bytes, FIPS 203).
    pub pq_public: [u8; PQ_PUBLIC_LEN],
    /// ML-KEM-768 decapsulation (secret) key bytes in expanded form (2400 bytes, FIPS 203).
    pub pq_secret: [u8; PQ_SECRET_LEN],
}

/// Hybrid key-exchange combining X25519 ECDH and ML-KEM-768,
/// with HKDF-SHA-512 key derivation.
pub struct HybridHandshake;

impl HybridHandshake {
    /// Generate a fresh hybrid keypair using the provided CSPRNG.
    ///
    /// The X25519 key is generated from `rng`; the ML-KEM-768 key is generated
    /// using the system's `getrandom` entropy source.
    pub fn generate_keypair(rng: &mut (impl CryptoRng + RngCore)) -> HybridKeypair {
        // Classical leg: X25519 static secret
        let classical = StaticSecret::random_from_rng(&mut *rng);

        // PQ leg: ML-KEM-768 keypair (uses getrandom internally)
        let (dk, ek) = MlKem768::generate_keypair();

        // Serialize encapsulation (public) key — 1184 bytes
        let ek_bytes = ek.to_bytes();
        let mut pq_public = [0u8; PQ_PUBLIC_LEN];
        pq_public.copy_from_slice(ek_bytes.as_slice());

        // Serialize decapsulation (secret) key in legacy expanded form — 2400 bytes
        let dk_bytes = dk.to_expanded_bytes();
        let mut pq_secret = [0u8; PQ_SECRET_LEN];
        pq_secret.copy_from_slice(dk_bytes.as_slice());

        HybridKeypair {
            classical,
            pq_public,
            pq_secret,
        }
    }

    /// Encapsulate a shared secret toward a peer.
    ///
    /// Arguments:
    /// - `peer_classical_pub`: the peer's X25519 public key (32 bytes)
    /// - `peer_pq_pub`: the peer's ML-KEM-768 encapsulation key (1184 bytes)
    ///
    /// Returns `(ciphertext_bundle, combined_key)` where:
    /// - `ciphertext_bundle` = `classical_ephemeral_pub(32) || pq_ciphertext(1088)`
    /// - `combined_key` is a 64-byte key derived via `HKDF-SHA-512(classical_ss || pq_ss, "hvpn-hybrid-v1")`
    pub fn encapsulate(
        rng: &mut (impl CryptoRng + RngCore),
        peer_classical_pub: &[u8; X25519_PUB_LEN],
        peer_pq_pub: &[u8; PQ_PUBLIC_LEN],
    ) -> (Vec<u8>, [u8; 64]) {
        // --- Classical leg: ephemeral X25519 ECDH ---
        let ephemeral_secret = EphemeralSecret::random_from_rng(&mut *rng);
        let ephemeral_pub = PublicKey::from(&ephemeral_secret);
        let peer_pub = PublicKey::from(*peer_classical_pub);
        let classical_shared: [u8; 32] = ephemeral_secret.diffie_hellman(&peer_pub).to_bytes();

        // --- PQ leg: ML-KEM-768 encapsulate (uses getrandom internally) ---
        let ek = ml_kem::EncapsulationKey::<MlKem768>::new_from_slice(peer_pq_pub)
            .expect("peer_pq_pub must be 1184 valid bytes");
        let (pq_ct_arr, pq_ss_arr) = ek.encapsulate();
        let pq_shared: [u8; 32] = pq_ss_arr.into();
        let pq_ct: [u8; PQ_CT_LEN] = pq_ct_arr.into();

        // --- HKDF-SHA-512 combine ---
        let combined_key = hkdf_combine(&classical_shared, &pq_shared);

        // --- Build ciphertext bundle: ephemeral_pub(32) || pq_ciphertext(1088) ---
        let mut bundle = Vec::with_capacity(X25519_PUB_LEN + PQ_CT_LEN);
        bundle.extend_from_slice(ephemeral_pub.as_bytes());
        bundle.extend_from_slice(&pq_ct);

        (bundle, combined_key)
    }

    /// Decapsulate a ciphertext bundle using the local hybrid keypair.
    ///
    /// The bundle format is `classical_ephemeral_pub(32) || pq_ciphertext(1088)`.
    ///
    /// Returns the same 64-byte combined key that was produced during `encapsulate`.
    pub fn decapsulate(
        keypair: &HybridKeypair,
        ciphertext_bundle: &[u8],
    ) -> Result<[u8; 64], HvpnError> {
        let expected_len = X25519_PUB_LEN + PQ_CT_LEN;
        if ciphertext_bundle.len() != expected_len {
            return Err(HvpnError::Crypto(format!(
                "ciphertext bundle length {} != {}",
                ciphertext_bundle.len(),
                expected_len
            )));
        }

        // Split bundle
        let (classical_pub_bytes, pq_ct_bytes) = ciphertext_bundle.split_at(X25519_PUB_LEN);

        // --- Classical leg: X25519 ECDH ---
        let peer_ephemeral_pub = PublicKey::from(
            <[u8; 32]>::try_from(classical_pub_bytes)
                .map_err(|_| HvpnError::Crypto("invalid classical pub bytes length".into()))?,
        );
        let classical_shared: [u8; 32] =
            keypair.classical.diffie_hellman(&peer_ephemeral_pub).to_bytes();

        // --- PQ leg: ML-KEM-768 decapsulate ---
        // Reconstruct the decapsulation key from its 2400-byte expanded representation.
        let dk_expanded: Array<u8, _> = Array::try_from(keypair.pq_secret.as_slice())
            .map_err(|_| HvpnError::Crypto("pq_secret is wrong length".into()))?;
        let dk = ml_kem::DecapsulationKey::<MlKem768>::from_expanded_bytes(&dk_expanded)
            .map_err(|_| HvpnError::Crypto("invalid ML-KEM-768 expanded decapsulation key".into()))?;

        let pq_ss_arr = dk
            .decapsulate_slice(pq_ct_bytes)
            .map_err(|e| HvpnError::Crypto(format!("ml-kem decapsulate: {e}")))?;
        let pq_shared: [u8; 32] = pq_ss_arr.into();

        // --- HKDF-SHA-512 combine ---
        Ok(hkdf_combine(&classical_shared, &pq_shared))
    }
}

/// HKDF-SHA-512 key combiner.
///
/// IKM = `classical_secret(32) || pq_secret(32)` (64 bytes total).
/// Info = `b"hvpn-hybrid-v1"`. Output = 64 bytes.
fn hkdf_combine(classical: &[u8; 32], pq: &[u8; 32]) -> [u8; 64] {
    let mut ikm = [0u8; 64];
    ikm[..32].copy_from_slice(classical);
    ikm[32..].copy_from_slice(pq);

    let hk = Hkdf::<Sha512>::new(None, &ikm);
    let mut okm = [0u8; 64];
    hk.expand(b"hvpn-hybrid-v1", &mut okm)
        .expect("HKDF-SHA-512 expand with 64-byte output is always valid");
    okm
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    #[test]
    fn test_hybrid_handshake() {
        let mut rng = ChaCha20Rng::from_entropy();

        // Receiver generates a keypair
        let keypair = HybridHandshake::generate_keypair(&mut rng);

        // Derive the receiver's X25519 public key
        let classical_pub: [u8; 32] = *PublicKey::from(&keypair.classical).as_bytes();

        // Sender encapsulates toward the receiver
        let (ciphertext_bundle, key1) =
            HybridHandshake::encapsulate(&mut rng, &classical_pub, &keypair.pq_public);

        // Receiver decapsulates
        let key2 = HybridHandshake::decapsulate(&keypair, &ciphertext_bundle)
            .expect("decapsulate must succeed");

        assert_eq!(key1, key2, "encapsulated and decapsulated keys must match");
    }
}
