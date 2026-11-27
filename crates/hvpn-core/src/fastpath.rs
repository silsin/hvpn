//! Allocation-light data path.
//!
//! Builds / parses exactly the same wire format as the generic
//! `encrypt_packet` + `FrameCodec::encode` + obfs-padding pipeline
//! (`[pad_len:u16 | frame header(20) | ciphertext+tag | padding]`), but with a
//! single buffer and in-place AEAD instead of four allocations and copies per
//! packet in each direction.

use hvpn_common::HvpnError;
use hvpn_crypto::{open_in_place, seal_in_place, SessionKeys};
use rand::{Rng, RngCore};

use crate::codec::{FrameCodec, FrameType, HEADER_SIZE};
use crate::replay::ReplayWindow;

const TAG_LEN: usize = 16;

/// Encrypt `plaintext` (one IP packet) into a ready-to-send wire packet with up
/// to `max_pad` random padding bytes.
pub fn seal_data_packet<R: RngCore>(
    keys: &SessionKeys,
    codec: &FrameCodec,
    rng: &mut R,
    seq: u64,
    plaintext: &[u8],
    max_pad: usize,
) -> Result<Vec<u8>, HvpnError> {
    let pad = rng.gen_range(0..=max_pad);
    let mut out = Vec::with_capacity(2 + HEADER_SIZE + plaintext.len() + TAG_LEN + pad);
    out.extend_from_slice(&(pad as u16).to_le_bytes());
    codec.write_header(
        &mut out,
        seq,
        0,
        FrameType::Data,
        0,
        0,
        (plaintext.len() + TAG_LEN) as u32,
    );
    let start = out.len();
    out.extend_from_slice(plaintext);
    let tag = seal_in_place(keys, &mut out[start..], seq)?;
    out.extend_from_slice(&tag);
    let pad_start = out.len();
    out.resize(pad_start + pad, 0);
    rng.fill_bytes(&mut out[pad_start..]);
    Ok(out)
}

/// Parse and decrypt a wire packet, returning the inner IP packet.
///
/// Fails (and the caller should just drop the packet) on malformed input, a
/// non-data frame, authentication failure or replay. The replay window is only
/// advanced after the packet authenticated, so forged packets cannot move it.
pub fn open_data_packet(
    keys: &SessionKeys,
    codec: &FrameCodec,
    data: &[u8],
    replay: &mut ReplayWindow,
) -> Result<Vec<u8>, HvpnError> {
    if data.len() < 2 {
        return Err(HvpnError::FrameCodec("packet too short".into()));
    }
    let pad = u16::from_le_bytes([data[0], data[1]]) as usize;
    let end = data
        .len()
        .checked_sub(pad)
        .filter(|e| *e >= 2)
        .ok_or_else(|| HvpnError::FrameCodec("bad padding length".into()))?;
    let body = &data[2..end];

    let (seq, frame_type, frame_pad, payload_len) = codec.read_header(body)?;
    if frame_type != FrameType::Data {
        return Err(HvpnError::FrameCodec("not a data frame".into()));
    }
    let _ = frame_pad;
    if payload_len < TAG_LEN {
        return Err(HvpnError::FrameCodec("payload shorter than tag".into()));
    }
    let payload = &body[HEADER_SIZE..HEADER_SIZE + payload_len];
    let (ct, tag) = payload.split_at(payload_len - TAG_LEN);
    let mut tag_arr = [0u8; TAG_LEN];
    tag_arr.copy_from_slice(tag);

    let mut plain = ct.to_vec();
    open_in_place(keys, &mut plain, &tag_arr, seq)?;
    replay.check_and_advance(seq)?;
    Ok(plain)
}

#[cfg(test)]
mod tests {
    use super::*;
    use hvpn_crypto::{decrypt_packet, encrypt_packet};
    use rand::SeedableRng;

    fn keys_pair() -> (SessionKeys, SessionKeys) {
        let a = SessionKeys {
            send_key: [1; 32],
            recv_key: [2; 32],
            header_key: [3; 32],
            mac_key: [4; 32],
        };
        let b = SessionKeys {
            send_key: [2; 32],
            recv_key: [1; 32],
            header_key: [3; 32],
            mac_key: [4; 32],
        };
        (a, b)
    }

    #[test]
    fn fast_seal_open_round_trip() {
        let (a, b) = keys_pair();
        let codec = FrameCodec::new(a.header_key);
        let mut rng = rand::rngs::StdRng::seed_from_u64(1);
        let mut replay = ReplayWindow::new();
        let pkt = vec![0x45u8; 1200];
        let wire = seal_data_packet(&a, &codec, &mut rng, 5, &pkt, 16).unwrap();
        assert_eq!(open_data_packet(&b, &codec, &wire, &mut replay).unwrap(), pkt);
        // Replay is rejected.
        assert!(open_data_packet(&b, &codec, &wire, &mut replay).is_err());
    }

    #[test]
    fn fast_path_matches_legacy_wire_format() {
        use crate::codec::Frame;
        let (a, b) = keys_pair();
        let codec = FrameCodec::new(a.header_key);
        let mut rng = rand::rngs::StdRng::seed_from_u64(2);
        let pkt = vec![7u8; 300];

        // Legacy sender -> fast receiver.
        let ct = encrypt_packet(&a, &pkt, 9, None).unwrap();
        let frame = Frame {
            seq: 9,
            stream_id: 0,
            frame_type: FrameType::Data,
            flags: 0,
            payload: ct,
            padding: vec![],
        };
        let enc = codec.encode(&frame);
        let mut legacy = Vec::new();
        legacy.extend_from_slice(&3u16.to_le_bytes());
        legacy.extend_from_slice(&enc);
        legacy.extend_from_slice(&[0xEE; 3]);
        let mut replay = ReplayWindow::new();
        assert_eq!(open_data_packet(&b, &codec, &legacy, &mut replay).unwrap(), pkt);

        // Fast sender -> legacy receiver.
        let wire = seal_data_packet(&a, &codec, &mut rng, 10, &pkt, 16).unwrap();
        let pad = u16::from_le_bytes([wire[0], wire[1]]) as usize;
        let inner = &wire[2..wire.len() - pad];
        let f = codec.decode(inner).unwrap();
        assert_eq!(decrypt_packet(&b, &f.payload, f.seq, None).unwrap(), pkt);
    }

    #[test]
    fn tampered_packet_does_not_advance_replay() {
        let (a, b) = keys_pair();
        let codec = FrameCodec::new(a.header_key);
        let mut rng = rand::rngs::StdRng::seed_from_u64(3);
        let mut replay = ReplayWindow::new();
        let mut wire = seal_data_packet(&a, &codec, &mut rng, 1, &[9u8; 100], 0).unwrap();
        let n = wire.len();
        wire[n - 1] ^= 1;
        assert!(open_data_packet(&b, &codec, &wire, &mut replay).is_err());
        wire[n - 1] ^= 1;
        assert!(open_data_packet(&b, &codec, &wire, &mut replay).is_ok());
    }
}
