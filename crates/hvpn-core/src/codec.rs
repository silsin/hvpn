//! Wire-format framing for HVPN packets.
//!
//! Frame layout (all integers little-endian):
//! ```text
//! [ seq:u64 | stream_id:u32 | frame_type:u8 | flags:u8 | pad_len:u16
//!   | payload_len:u32 | payload | padding ]
//! ```
//! Total fixed header = 8 + 4 + 1 + 1 + 2 + 4 = 20 bytes.

use hvpn_common::HvpnError;

/// Frame type discriminant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum FrameType {
    Data    = 0x01,
    Control = 0x02,
    Ping    = 0x03,
    Pong    = 0x04,
    Close   = 0x05,
}

impl TryFrom<u8> for FrameType {
    type Error = HvpnError;

    fn try_from(v: u8) -> Result<Self, Self::Error> {
        match v {
            0x01 => Ok(Self::Data),
            0x02 => Ok(Self::Control),
            0x03 => Ok(Self::Ping),
            0x04 => Ok(Self::Pong),
            0x05 => Ok(Self::Close),
            other => Err(HvpnError::FrameCodec(format!(
                "unknown frame type: {:#04x}",
                other
            ))),
        }
    }
}

/// A single HVPN protocol frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Frame {
    pub seq: u64,
    pub stream_id: u32,
    pub frame_type: FrameType,
    pub flags: u8,
    pub payload: Vec<u8>,
    pub padding: Vec<u8>,
}

/// Fixed header size in bytes.
const HEADER_SIZE: usize = 8 + 4 + 1 + 1 + 2 + 4; // 20

/// Encodes and decodes `Frame` values to/from raw bytes.
///
/// In a real deployment the 20-byte header would be encrypted with
/// `header_key`; here we XOR each header byte with the first byte of
/// `header_key` as a lightweight placeholder that keeps the API consistent.
pub struct FrameCodec {
    header_key: [u8; 32],
}

impl FrameCodec {
    pub fn new(header_key: [u8; 32]) -> Self {
        Self { header_key }
    }

    /// Encode a `Frame` into a `Vec<u8>`.
    pub fn encode(&self, frame: &Frame) -> Vec<u8> {
        let pad_len = frame.padding.len() as u16;
        let payload_len = frame.payload.len() as u32;

        let total = HEADER_SIZE + frame.payload.len() + frame.padding.len();
        let mut buf = Vec::with_capacity(total);

        buf.extend_from_slice(&frame.seq.to_le_bytes());
        buf.extend_from_slice(&frame.stream_id.to_le_bytes());
        buf.push(frame.frame_type as u8);
        buf.push(frame.flags);
        buf.extend_from_slice(&pad_len.to_le_bytes());
        buf.extend_from_slice(&payload_len.to_le_bytes());
        buf.extend_from_slice(&frame.payload);
        buf.extend_from_slice(&frame.padding);

        // XOR the header bytes with the header_key mask byte.
        let mask = self.header_key[0];
        for byte in buf[..HEADER_SIZE].iter_mut() {
            *byte ^= mask;
        }

        buf
    }

    /// Decode a `Frame` from raw bytes.
    pub fn decode(&self, data: &[u8]) -> Result<Frame, HvpnError> {
        if data.len() < HEADER_SIZE {
            return Err(HvpnError::FrameCodec(format!(
                "buffer too short: {} < {}",
                data.len(),
                HEADER_SIZE
            )));
        }

        // Un-mask the header.
        let mut header = [0u8; HEADER_SIZE];
        header.copy_from_slice(&data[..HEADER_SIZE]);
        let mask = self.header_key[0];
        for byte in header.iter_mut() {
            *byte ^= mask;
        }

        let seq = u64::from_le_bytes(header[0..8].try_into().unwrap());
        let stream_id = u32::from_le_bytes(header[8..12].try_into().unwrap());
        let frame_type = FrameType::try_from(header[12])?;
        let flags = header[13];
        let pad_len = u16::from_le_bytes(header[14..16].try_into().unwrap()) as usize;
        let payload_len = u32::from_le_bytes(header[16..20].try_into().unwrap()) as usize;

        let expected = HEADER_SIZE + payload_len + pad_len;
        if data.len() < expected {
            return Err(HvpnError::FrameCodec(format!(
                "buffer too short for payload+padding: {} < {}",
                data.len(),
                expected
            )));
        }

        let payload = data[HEADER_SIZE..HEADER_SIZE + payload_len].to_vec();
        let padding =
            data[HEADER_SIZE + payload_len..HEADER_SIZE + payload_len + pad_len].to_vec();

        Ok(Frame {
            seq,
            stream_id,
            frame_type,
            flags,
            payload,
            padding,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frame_encode_decode_round_trip() {
        let header_key = [0x7Fu8; 32];
        let codec = FrameCodec::new(header_key);

        let original = Frame {
            seq: 12345,
            stream_id: 7,
            frame_type: FrameType::Data,
            flags: 0b0000_0001,
            payload: b"test payload data".to_vec(),
            padding: vec![0u8; 16],
        };

        let encoded = codec.encode(&original);
        let decoded = codec.decode(&encoded).expect("decode failed");

        assert_eq!(original, decoded);
    }

    #[test]
    fn frame_types_round_trip() {
        for &ft in &[
            FrameType::Data,
            FrameType::Control,
            FrameType::Ping,
            FrameType::Pong,
            FrameType::Close,
        ] {
            assert_eq!(ft, FrameType::try_from(ft as u8).unwrap());
        }
    }

    #[test]
    fn decode_truncated_buffer_returns_error() {
        let codec = FrameCodec::new([0u8; 32]);
        assert!(codec.decode(&[0u8; 5]).is_err());
    }
}
