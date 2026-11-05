mod transport_trait;
mod websocket;
mod http2;
mod grpc;

pub use transport_trait::Transport;
pub use websocket::{TransportConfig, WebSocketTransport};
pub use http2::Http2Transport;
pub use grpc::GrpcTransport;
pub use hvpn_crypto::{build_tls_config_raw, TlsProfile, TlsProfileConfig};

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

/// Domain fronting configuration: TLS SNI differs from the HTTP Host header.
#[derive(Debug, Clone)]
pub struct DomainFrontConfig {
    /// TLS SNI hostname (CDN or fronting domain).
    pub front_domain: String,
    /// HTTP Host header (the real backend service).
    pub real_host: String,
}

/// Which transport protocol to use.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransportKind {
    WebSocket,
    Http2,
    Grpc,
}

/// Probes all transports and selects the best one.
pub struct TransportProber;

impl TransportProber {
    /// Try each transport with a 2-second timeout; return successful ones with latency.
    pub async fn probe_all(config: &TransportConfig) -> Vec<(TransportKind, std::time::Duration)> {
        let mut results = Vec::new();

        // WebSocket probe
        let start = std::time::Instant::now();
        if tokio::time::timeout(
            std::time::Duration::from_secs(2),
            WebSocketTransport::connect(config),
        )
        .await
        .is_ok()
        {
            results.push((TransportKind::WebSocket, start.elapsed()));
        }

        // HTTP/2 probe
        let start = std::time::Instant::now();
        if tokio::time::timeout(
            std::time::Duration::from_secs(2),
            Http2Transport::connect(config),
        )
        .await
        .is_ok()
        {
            results.push((TransportKind::Http2, start.elapsed()));
        }

        // gRPC probe
        let start = std::time::Instant::now();
        if tokio::time::timeout(
            std::time::Duration::from_secs(2),
            GrpcTransport::connect(config),
        )
        .await
        .is_ok()
        {
            results.push((TransportKind::Grpc, start.elapsed()));
        }

        results
    }

    /// Return the transport kind with the lowest latency.
    pub fn pick_best(
        results: Vec<(TransportKind, std::time::Duration)>,
    ) -> Option<TransportKind> {
        results.into_iter().min_by_key(|(_, d)| *d).map(|(k, _)| k)
    }
}

/// Adaptive transport that can switch between transport kinds based on metrics.
pub struct AdaptiveTransport {
    pub active: TransportKind,
    pub outbound: Arc<Mutex<VecDeque<Vec<u8>>>>,
}

impl AdaptiveTransport {
    pub fn new(initial: TransportKind) -> Self {
        Self {
            active: initial,
            outbound: Arc::new(Mutex::new(VecDeque::new())),
        }
    }

    /// Switch transport if metrics indicate poor performance (>5% loss or >500 ms RTT).
    pub async fn switch_if_needed(
        &mut self,
        metrics: &hvpn_metrics::MetricsCollector,
        config: &TransportConfig,
    ) {
        let snap = metrics.snapshot();
        if snap.packet_loss_rate > 0.05 || snap.rtt_ms > 500.0 {
            let results = TransportProber::probe_all(config).await;
            if let Some(best) = TransportProber::pick_best(results) {
                self.active = best;
            }
        }
    }

    /// Enqueue data for sending via the active transport.
    pub fn send(&self, data: Vec<u8>) {
        if let Ok(mut q) = self.outbound.lock() {
            q.push_back(data);
        }
    }

    /// Dequeue the next received payload.
    pub fn recv(&self) -> Vec<u8> {
        if let Ok(mut q) = self.outbound.lock() {
            q.pop_front().unwrap_or_default()
        } else {
            vec![]
        }
    }
}
