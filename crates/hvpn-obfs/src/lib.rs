//! Obfuscation engine: traffic padding and timing jitter.

use flate2::{read::DeflateDecoder, write::DeflateEncoder, Compression};
use rand::{Rng, SeedableRng};
use tokio::time::{sleep, Duration};

/// Maximum random padding added per packet (bytes).
const MAX_PADDING: usize = 512;

/// Padding cap for the tunnel data path. Large padding adds ~18% overhead on
/// full-size packets and was a measurable throughput cost.
const DATA_PATH_MAX_PADDING: usize = 16;

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
    pub shaping: ShapingState,
}

impl ObfsEngine {
    /// Create a new engine seeded from the OS CSPRNG.
    pub fn new() -> Self {
        Self {
            rng: rand::rngs::StdRng::from_entropy(),
            shaping: ShapingState::new(),
        }
    }

    /// Prepend a 2-byte little-endian padding-length field and append
    /// `pad_len` random bytes to `data`.
    ///
    /// Layout: `[ pad_len : u16 LE | original data | random padding ]`
    pub fn pad_packet(&mut self, data: Vec<u8>) -> Vec<u8> {
        self.pad_packet_max(data, MAX_PADDING)
    }

    /// Like `pad_packet` but with a small padding cap suited to high-volume
    /// tunnel data (see `DATA_PATH_MAX_PADDING`).
    pub fn pad_data_packet(&mut self, data: Vec<u8>) -> Vec<u8> {
        self.pad_packet_max(data, DATA_PATH_MAX_PADDING)
    }

    fn pad_packet_max(&mut self, data: Vec<u8>, max_pad: usize) -> Vec<u8> {
        let pad_len: usize = self.rng.gen_range(0..=max_pad);
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

    /// Compute the delay to apply before sending a packet of `packet_size` bytes
    /// according to the traffic profile.
    pub fn shape_delay(&mut self, profile: TrafficProfile, packet_size: usize) -> Duration {
        match profile {
            TrafficProfile::Browser => {
                if self.shaping.burst_count < 8 {
                    self.shaping.burst_count += 1;
                    Duration::from_millis(0)
                } else {
                    self.shaping.burst_count = 0;
                    let ms = self.rng.gen_range(50u64..=200u64);
                    Duration::from_millis(ms)
                }
            }
            TrafficProfile::Streaming => {
                // 2 Mbps = 2_000_000 bits/sec
                let bits = (packet_size as f64) * 8.0;
                let secs = bits / 2_000_000.0;
                Duration::from_secs_f64(secs)
            }
            TrafficProfile::Voip => Duration::from_millis(20),
            TrafficProfile::Idle => Duration::from_millis(5_000),
        }
    }

    /// Compress data with flate2 deflate. Prepend 0x01 if compressed,
    /// 0x00 if not (compression did not help).
    pub fn normalize_entropy(&self, data: Vec<u8>) -> Vec<u8> {
        use std::io::Write;

        let mut encoder = DeflateEncoder::new(Vec::new(), Compression::new(1));
        encoder.write_all(&data).ok();
        let compressed = encoder.finish().unwrap_or_default();

        if compressed.len() < data.len() {
            let mut out = Vec::with_capacity(1 + compressed.len());
            out.push(0x01u8);
            out.extend_from_slice(&compressed);
            out
        } else {
            let mut out = Vec::with_capacity(1 + data.len());
            out.push(0x00u8);
            out.extend_from_slice(&data);
            out
        }
    }

    /// Decompress or pass through based on the flag byte.
    pub fn denormalize_entropy(&self, data: Vec<u8>) -> Result<Vec<u8>, hvpn_common::HvpnError> {
        use std::io::Read;

        if data.is_empty() {
            return Err(hvpn_common::HvpnError::Protocol("empty input to denormalize".into()));
        }
        let flag = data[0];
        let payload = &data[1..];
        match flag {
            0x01 => {
                let mut decoder = DeflateDecoder::new(payload);
                let mut out = Vec::new();
                decoder.read_to_end(&mut out)
                    .map_err(|e| hvpn_common::HvpnError::Protocol(e.to_string()))?;
                Ok(out)
            }
            0x00 => Ok(payload.to_vec()),
            _ => Err(hvpn_common::HvpnError::Protocol("unknown entropy flag".into())),
        }
    }
}

impl Default for ObfsEngine {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Traffic shaping profile
// ---------------------------------------------------------------------------

use hvpn_common::ObfsProfile;

/// Traffic profile used to shape inter-packet delays.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TrafficProfile {
    Browser,
    Streaming,
    Voip,
    Idle,
}

impl From<ObfsProfile> for TrafficProfile {
    fn from(p: ObfsProfile) -> Self {
        match p {
            ObfsProfile::Browser   => TrafficProfile::Browser,
            ObfsProfile::Streaming => TrafficProfile::Streaming,
            ObfsProfile::Voip      => TrafficProfile::Voip,
            ObfsProfile::Idle      => TrafficProfile::Idle,
        }
    }
}

// ---------------------------------------------------------------------------
// Shaping state
// ---------------------------------------------------------------------------

use std::time::Instant;

/// Per-connection state for traffic shaping.
pub struct ShapingState {
    pub last_send: Option<Instant>,
    pub bytes_this_window: u64,
    pub window_start: Instant,
    pub burst_count: u32,
}

impl ShapingState {
    pub fn new() -> Self {
        ShapingState {
            last_send: None,
            bytes_this_window: 0,
            window_start: Instant::now(),
            burst_count: 0,
        }
    }
}

impl Default for ShapingState {
    fn default() -> Self { Self::new() }
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

    #[test]
    fn test_entropy_normalize_roundtrip() {
        let engine = ObfsEngine::new();
        // 1000 bytes of repetitive data — deflate should compress well.
        let original: Vec<u8> = (0u8..=99).cycle().take(1000).collect();
        let normalized = engine.normalize_entropy(original.clone());
        let recovered = engine.denormalize_entropy(normalized).expect("denormalize failed");
        assert_eq!(recovered, original);
    }

    #[test]
    fn test_traffic_shaping_voip() {
        let mut engine = ObfsEngine::new();
        let delay = engine.shape_delay(TrafficProfile::Voip, 160);
        assert_eq!(delay, Duration::from_millis(20));
    }

    #[test]
    fn test_browser_burst() {
        let mut engine = ObfsEngine::new();
        // First 8 calls must all return zero delay.
        for i in 0..8 {
            let d = engine.shape_delay(TrafficProfile::Browser, 100);
            assert_eq!(d, Duration::ZERO, "call {} should be 0ms", i + 1);
        }
        // 9th call triggers the pause (50–200 ms).
        let d = engine.shape_delay(TrafficProfile::Browser, 100);
        assert!(d >= Duration::from_millis(50), "9th call should be >= 50ms, got {:?}", d);
    }
}
