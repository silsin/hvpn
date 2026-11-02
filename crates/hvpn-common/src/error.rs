use thiserror::Error;

/// Unified error type used across all HVPN crates.
#[derive(Debug, Error)]
pub enum HvpnError {
    /// Cryptographic operation failed.
    #[error("crypto error: {0}")]
    Crypto(String),

    /// Transport-layer error (WebSocket / TLS).
    #[error("transport error: {0}")]
    Transport(String),

    /// TUN device error.
    #[error("tun error: {0}")]
    Tun(String),

    /// Underlying I/O error.
    #[error("io error: {source}")]
    Io {
        #[from]
        source: std::io::Error,
    },

    /// Packet replay detected.
    #[error("replay detected: sequence number {seq} already seen")]
    ReplayDetected { seq: u64 },

    /// Frame decoding / encoding error.
    #[error("frame codec error: {0}")]
    FrameCodec(String),

    /// Authentication / probe-token failure.
    #[error("auth error: {0}")]
    Auth(String),

    /// Configuration parse error.
    #[error("config error: {0}")]
    Config(String),
}
