use async_trait::async_trait;
use hvpn_common::HvpnError;

/// Async abstraction over a TUN network device.
#[async_trait]
pub trait TunDevice: Send + Sync {
    /// Read one IP packet from the TUN device.
    async fn read_packet(&mut self) -> Result<Vec<u8>, HvpnError>;

    /// Write one IP packet to the TUN device.
    async fn write_packet(&mut self, pkt: &[u8]) -> Result<(), HvpnError>;
}
