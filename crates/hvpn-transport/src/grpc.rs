//! gRPC-framed transport built on top of `Http2Transport`.

use async_trait::async_trait;
use hvpn_common::HvpnError;

use crate::http2::Http2Transport;
use crate::transport_trait::Transport;
use crate::websocket::TransportConfig;

pub struct GrpcTransport {
    inner: Http2Transport,
}

impl GrpcTransport {
    pub async fn connect(cfg: &TransportConfig) -> Result<Self, HvpnError> {
        Ok(Self {
            inner: Http2Transport::connect(cfg).await?,
        })
    }

    /// Wrap `payload` in a 5-byte gRPC length-prefixed frame (uncompressed).
    fn grpc_frame(payload: &[u8]) -> Vec<u8> {
        let mut frame = Vec::with_capacity(5 + payload.len());
        frame.push(0x00); // compression flag: uncompressed
        let len = payload.len() as u32;
        frame.extend_from_slice(&len.to_be_bytes());
        frame.extend_from_slice(payload);
        frame
    }

    /// Strip the 5-byte gRPC length-prefixed frame and return the inner payload.
    fn strip_grpc_frame(data: Vec<u8>) -> Result<Vec<u8>, HvpnError> {
        if data.len() < 5 {
            return Err(HvpnError::Protocol("gRPC frame too short".into()));
        }
        let len = u32::from_be_bytes([data[1], data[2], data[3], data[4]]) as usize;
        if data.len() < 5 + len {
            return Err(HvpnError::Protocol("gRPC frame truncated".into()));
        }
        Ok(data[5..5 + len].to_vec())
    }
}

#[async_trait]
impl Transport for GrpcTransport {
    async fn send(&self, data: Vec<u8>) -> Result<(), HvpnError> {
        let framed = Self::grpc_frame(&data);
        self.inner.send(framed).await
    }

    async fn recv(&self) -> Result<Vec<u8>, HvpnError> {
        let raw = self.inner.recv().await?;
        Self::strip_grpc_frame(raw)
    }

    async fn close(&self) -> Result<(), HvpnError> {
        self.inner.close().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn grpc_frame_round_trip() {
        let payload = b"hello grpc";
        let framed = GrpcTransport::grpc_frame(payload);
        assert_eq!(framed.len(), 5 + payload.len());
        assert_eq!(framed[0], 0x00); // uncompressed
        let stripped = GrpcTransport::strip_grpc_frame(framed).unwrap();
        assert_eq!(stripped, payload);
    }

    #[test]
    fn strip_grpc_frame_too_short() {
        let result = GrpcTransport::strip_grpc_frame(vec![0x00, 0x00]);
        assert!(result.is_err());
    }

    #[test]
    fn strip_grpc_frame_truncated() {
        // Claims 100 bytes but provides only 10 total (5 header + 5 data)
        let mut frame = vec![0x00, 0x00, 0x00, 0x00, 0x64]; // len = 100
        frame.extend_from_slice(&[0u8; 5]);
        let result = GrpcTransport::strip_grpc_frame(frame);
        assert!(result.is_err());
    }
}
