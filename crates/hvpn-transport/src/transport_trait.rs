use async_trait::async_trait;
use hvpn_common::HvpnError;

/// Async byte-stream transport abstraction.
#[async_trait]
pub trait Transport: Send + Sync {
    /// Send a binary message.
    async fn send(&self, data: Vec<u8>) -> Result<(), HvpnError>;

    /// Receive the next binary message.
    async fn recv(&self) -> Result<Vec<u8>, HvpnError>;

    /// Gracefully close the transport.
    async fn close(&self) -> Result<(), HvpnError>;
}
