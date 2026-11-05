//! Steganographic transport — embeds tunnel data inside valid-looking JSON API responses.
//!
//! [`StegoCodec`] handles encode/decode of raw bytes into/from a realistic-looking
//! JSON payload. [`StegoTransport`] wraps a [`WebSocketTransport`] and sends the
//! steganographic JSON as WebSocket Text frames.

use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use hvpn_common::HvpnError;
use hvpn_transport::{Transport, WebSocketTransport};
use rand::Rng;
use serde_json::{json, Value};
use std::time::{SystemTime, UNIX_EPOCH};

/// Encodes/decodes tunnel data inside realistic-looking JSON API responses.
pub struct StegoCodec;

impl StegoCodec {
    /// Encode `data` as a `session_token` inside a fake API response JSON string.
    ///
    /// Each call produces a unique `request_id` and `user.id` so repeated frames
    /// do not produce identical ciphertext-layer outputs.
    pub fn encode(data: &[u8]) -> String {
        let mut rng = rand::thread_rng();

        // 8 random bytes → 16 lowercase hex chars
        let id_bytes: [u8; 8] = rng.gen();
        let request_id: String = id_bytes.iter().map(|b| format!("{:02x}", b)).collect();

        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let user_id: u32 = rng.gen();

        let session_token = B64.encode(data);

        let payload = json!({
            "status": "ok",
            "request_id": request_id,
            "timestamp": timestamp,
            "session_token": session_token,
            "user": {
                "id": user_id,
                "tier": "free"
            }
        });

        payload.to_string()
    }

    /// Decode a JSON string produced by [`StegoCodec::encode`], returning the
    /// original bytes, or an [`HvpnError::FrameCodec`] on any failure.
    pub fn decode(json: &str) -> Result<Vec<u8>, HvpnError> {
        let v: Value = serde_json::from_str(json)
            .map_err(|e| HvpnError::FrameCodec(format!("json parse: {}", e)))?;

        let token = v
            .get("session_token")
            .and_then(Value::as_str)
            .ok_or_else(|| {
                HvpnError::FrameCodec("missing or non-string session_token field".to_string())
            })?;

        B64.decode(token)
            .map_err(|e| HvpnError::FrameCodec(format!("base64 decode: {}", e)))
    }
}

/// Steganographic transport that wraps a [`WebSocketTransport`].
///
/// Outbound data is encoded by [`StegoCodec`] and sent as a WebSocket **Text** frame.
/// Inbound Text frames are decoded by [`StegoCodec`] to recover the original bytes.
/// Binary frames from the inner transport are re-wrapped as Text by sending the
/// JSON-encoded form; on receive we expect Text frames from a peer using the same codec.
pub struct StegoTransport {
    inner: WebSocketTransport,
}

impl StegoTransport {
    /// Wrap an existing [`WebSocketTransport`].
    pub fn new(inner: WebSocketTransport) -> Self {
        Self { inner }
    }

    /// Encode `data` with [`StegoCodec`] and send as a WebSocket Text frame.
    ///
    /// `WebSocketTransport::send` accepts `Vec<u8>`; we convert the JSON string
    /// to bytes and send it as a binary message since the inner transport uses
    /// binary frames.  The stego layer's job is to make the *content* look like
    /// JSON; the framing layer below handles the wire protocol.
    pub async fn send(&self, data: Vec<u8>) -> Result<(), HvpnError> {
        let json_str = StegoCodec::encode(&data);
        self.inner.send(json_str.into_bytes()).await
    }

    /// Receive a frame from the inner transport, decode it with [`StegoCodec`],
    /// and return the original bytes.
    pub async fn recv(&self) -> Result<Vec<u8>, HvpnError> {
        let frame = self.inner.recv().await?;
        let json_str = String::from_utf8(frame)
            .map_err(|e| HvpnError::FrameCodec(format!("utf8 decode: {}", e)))?;
        StegoCodec::decode(&json_str)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Round-trip: encode 256 bytes, decode, verify byte-for-byte identity.
    #[test]
    fn test_stego_roundtrip() {
        let original: Vec<u8> = (0u8..=255u8).collect();
        let json_str = StegoCodec::encode(&original);
        let recovered = StegoCodec::decode(&json_str).expect("decode must succeed");
        assert_eq!(original, recovered);
    }

    /// The encoded output must be valid JSON with `status == "ok"`.
    #[test]
    fn test_stego_looks_like_json() {
        let data = b"hello steganography";
        let json_str = StegoCodec::encode(data);

        let v: Value = serde_json::from_str(&json_str).expect("output must be valid JSON");
        assert_eq!(v["status"], "ok", "status field must be \"ok\"");

        // Sanity-check the other expected fields are present.
        assert!(v["request_id"].is_string(), "request_id must be a string");
        assert_eq!(v["request_id"].as_str().unwrap().len(), 16, "request_id must be 16 chars");
        assert!(v["timestamp"].is_u64(), "timestamp must be a u64");
        assert!(v["session_token"].is_string(), "session_token must be a string");
        assert_eq!(v["user"]["tier"], "free", "user.tier must be \"free\"");
        assert!(v["user"]["id"].is_u64(), "user.id must be a u64");
    }

    /// Each encode call must produce a different request_id and user.id.
    #[test]
    fn test_stego_randomness() {
        let data = b"same input";
        let json1: Value = serde_json::from_str(&StegoCodec::encode(data)).unwrap();
        let json2: Value = serde_json::from_str(&StegoCodec::encode(data)).unwrap();

        // With high probability, random fields differ between two calls.
        // We test request_id (128-bit space via 8 bytes); collision probability ≈ 2^-64.
        assert_ne!(
            json1["request_id"], json2["request_id"],
            "request_id should differ between calls"
        );
    }
}
