use std::sync::Arc;

/// Point-in-time snapshot of connection metrics.
#[derive(Clone, Debug, Default)]
pub struct Metrics {
    pub packet_loss_rate: f64,
    pub rtt_ms: f64,
    pub bytes_sent: u64,
    pub bytes_recv: u64,
    pub active_streams: u32,
}

/// Thread-safe metrics collector backed by a shared `Mutex<Metrics>`.
#[derive(Clone)]
pub struct MetricsCollector {
    inner: Arc<parking_lot::Mutex<Metrics>>,
}

impl MetricsCollector {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(parking_lot::Mutex::new(Metrics::default())),
        }
    }

    /// Set the latest round-trip time in milliseconds.
    pub fn record_rtt(&self, ms: f64) {
        self.inner.lock().rtt_ms = ms;
    }

    /// Increment packet-loss rate by 0.01, clamped to 1.0.
    pub fn record_loss(&self) {
        let mut m = self.inner.lock();
        m.packet_loss_rate = (m.packet_loss_rate + 0.01).min(1.0);
    }

    /// Add `sent` and `recv` byte counts to the running totals.
    pub fn record_bytes(&self, sent: u64, recv: u64) {
        let mut m = self.inner.lock();
        m.bytes_sent += sent;
        m.bytes_recv += recv;
    }

    /// Return a clone of the current metrics.
    pub fn snapshot(&self) -> Metrics {
        self.inner.lock().clone()
    }
}

impl Default for MetricsCollector {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_record_rtt() {
        let col = MetricsCollector::new();
        col.record_rtt(50.0);
        let snap = col.snapshot();
        assert_eq!(snap.rtt_ms, 50.0);
    }

    #[test]
    fn test_record_bytes() {
        let col = MetricsCollector::new();
        col.record_bytes(100, 200);
        let snap = col.snapshot();
        assert_eq!(snap.bytes_sent, 100);
        assert_eq!(snap.bytes_recv, 200);
    }

    #[test]
    fn test_clone_shares_state() {
        let col1 = MetricsCollector::new();
        let col2 = col1.clone();
        col1.record_rtt(75.0);
        col1.record_bytes(512, 1024);
        let snap = col2.snapshot();
        assert_eq!(snap.rtt_ms, 75.0);
        assert_eq!(snap.bytes_sent, 512);
        assert_eq!(snap.bytes_recv, 1024);
    }
}
