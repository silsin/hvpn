use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use hvpn_common::HvpnError;
use rand::rngs::OsRng;

/// Ed25519 identity key pair used for node authentication.
pub struct KeyPair {
    signing_key: SigningKey,
}

impl KeyPair {
    /// Generate a fresh key pair using the OS CSPRNG.
    pub fn generate() -> Self {
        let signing_key = SigningKey::generate(&mut OsRng);
        Self { signing_key }
    }

    /// Restore a key pair from a 32-byte seed.
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        let signing_key = SigningKey::from_bytes(seed);
        Self { signing_key }
    }

    /// Return the 32-byte compressed public key.
    pub fn public_key_bytes(&self) -> [u8; 32] {
        self.signing_key.verifying_key().to_bytes()
    }

    /// Sign `message` and return the 64-byte signature.
    pub fn sign(&self, message: &[u8]) -> [u8; 64] {
        self.signing_key.sign(message).to_bytes()
    }

    /// Verify a signature produced by `public_key_bytes`.
    pub fn verify(
        public_key_bytes: &[u8; 32],
        message: &[u8],
        signature_bytes: &[u8; 64],
    ) -> Result<(), HvpnError> {
        let vk = VerifyingKey::from_bytes(public_key_bytes)
            .map_err(|e| HvpnError::Crypto(e.to_string()))?;
        let sig = Signature::from_bytes(signature_bytes);
        vk.verify(message, &sig)
            .map_err(|e| HvpnError::Crypto(e.to_string()))
    }
}
