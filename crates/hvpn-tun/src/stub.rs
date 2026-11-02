//! In-memory TUN stub for testing — no kernel interaction required.

use async_trait::async_trait;
use hvpn_common::HvpnError;
use std::collections::VecDeque;

use crate::tun_trait::TunDevice;

/// A pure in-memory TUN device for unit tests.
pub struct StubTun {
    queue: VecDeque<Vec<u8>>,
}

impl StubTun {
    pub fn new() -> Self {
        Self {
            queue: VecDeque::new(),
        }
    }
}

impl Default for StubTun {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl TunDevice for StubTun {
    async fn read_packet(&mut self) -> Result<Vec<u8>, HvpnError> {
        self.queue
            .pop_front()
            .ok_or_else(|| HvpnError::Tun("stub queue is empty".to_string()))
    }

    async fn write_packet(&mut self, pkt: &[u8]) -> Result<(), HvpnError> {
        self.queue.push_back(pkt.to_vec());
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn stub_write_then_read_round_trip() {
        let mut tun = StubTun::new();
        let packet = b"\x45\x00\x00\x28test IP packet".to_vec();

        tun.write_packet(&packet).await.expect("write failed");
        let received = tun.read_packet().await.expect("read failed");

        assert_eq!(received, packet);
    }

    #[tokio::test]
    async fn stub_read_empty_returns_error() {
        let mut tun = StubTun::new();
        assert!(tun.read_packet().await.is_err());
    }
}
