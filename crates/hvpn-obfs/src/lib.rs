//! Obfuscation engine: traffic padding and timing jitter.

use rand::{Rng, SeedableRng};
use tokio::time::{sleep, Duration};

/// Maximum random padding added per packet (bytes).
const MAX_PADDING: usize = 512;

/// Jitter parameters (milliseconds).
const JITTER_MEAN_MS: f64 = 2.0;
const JITTER_STDDEV_MS: f64 = 4.0;
const JITTER_MAX_MS: u64 = 20;

/// Traffic obfuscation engine.
///
/// Handles per-packet padding and inter-packet timing jitter to resist
/// traffic-analysis-based deep-packet inspection.
pub struct ObfsEngine {
    rng: rand::rngs::StdRng,
}

impl ObfsEngine {
    /// Create a new engine seeded from the OS CSPRNG.
    pub fn new() -> Self {
        Self {
            rng: rand::rngs::StdRng::from_entropy(),
        }
    }

    /// Prepend a 2-byte little-endian padding-length field and append
    /// `pad_len` random bytes to `data`.
    ///
    /// Layout: `[ pad_len : u16 LE | original data | random padding ]`
    pub fn pad_packet(&mut self, data: Vec<u8>) -> Vec<u8> {
        let pad_len: usize = self.rng.gen_range(0..=MAX_PADDING);
        let mut out = Vec::with_capacity(2 + data.len() + pad_len);

        // 2-byte length prefix.
        out.extend_from_slice(&(pad_len as u16).to_le_bytes());
        out.extend_from_slice(&data);

        // Random padding.
        let pad: Vec<u8> = (0..pad_len).map(|_| self.rng.gen::<u8>()).collect();
        out.extend_from_slice(&pad);

        out
    }

    /// Strip padding added by `pad_packet`.
    ///
    /// Reads the 2-byte length prefix and removes that many trailing bytes.
    pub fn unpad_packet(&self, data: Vec<u8>) -> Vec<u8> {
        if data.len() < 2 {
            return data;
        }
        let pad_len = u16::from_le_bytes([data[0], data[1]]) as usize;
        let payload_end = data.len().saturating_sub(pad_len);
        // Skip the 2-byte header; take bytes [2..payload_end].
        if payload_end < 2 {
            return vec![];
        }
        data[2..payload_end].to_vec()
    }

    /// Sleep for a Gaussian-distributed delay clamped to `[0, JITTER_MAX_MS]` ms.
    ///
    /// Uses the Box-Muller transform to approximate a normal distribution from
    /// two uniform random variates.
    pub async fn apply_jitter(&mut self) {
        let delay_ms = self.gaussian_ms();
        if delay_ms > 0 {
            sleep(Duration::from_millis(delay_ms)).await;
        }
    }

    /// Sample from N(JITTER_MEAN_MS, JITTER_STDDEV_MS²) and clamp to [0, JITTER_MAX_MS].
    fn gaussian_ms(&mut self) -> u64 {
        // Box-Muller transform: two uniform samples → one standard-normal sample.
        let u1: f64 = self.rng.gen::<f64>().max(1e-10); // avoid log(0)
        let u2: f64 = self.rng.gen::<f64>();

        let z0 = (-2.0_f64 * u1.ln()).sqrt() * (2.0 * std::f64::consts::PI * u2).cos();
        let sample = JITTER_MEAN_MS + JITTER_STDDEV_MS * z0;

        let clamped = sample.max(0.0).min(JITTER_MAX_MS as f64);
        clamped.round() as u64
    }
}

impl Default for ObfsEngine {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pad_then_unpad_round_trip() {
        let mut engine = ObfsEngine::new();
        let original = b"Hello, obfuscated world!".to_vec();

        let padded = engine.pad_packet(original.clone());
        let recovered = engine.unpad_packet(padded);

        assert_eq!(recovered, original);
    }

    #[test]
    fn padded_packet_is_longer_or_equal() {
        let mut engine = ObfsEngine::new();
        let data = b"short".to_vec();
        let padded = engine.pad_packet(data.clone());
        // At minimum: 2 (header) + data.len() bytes
        assert!(padded.len() >= 2 + data.len());
    }

    #[test]
    fn empty_payload_round_trips() {
        let mut engine = ObfsEngine::new();
        let original: Vec<u8> = vec![];
        let padded = engine.pad_packet(original.clone());
        let recovered = engine.unpad_packet(padded);
        assert_eq!(recovered, original);
    }

    #[tokio::test]
    async fn apply_jitter_completes() {
        let mut engine = ObfsEngine::new();
        // Just verify it doesn't panic or hang.
        tokio::time::timeout(
            Duration::from_millis(100),
            engine.apply_jitter(),
        )
        .await
        .expect("jitter timed out");
    }
}
