use serde::Serialize;
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::time::{SystemTime, UNIX_EPOCH};

/// Audit events emitted by the HVPN server.
#[derive(Debug, Serialize)]
#[serde(tag = "event", rename_all = "snake_case")]
pub enum AuditEvent {
    ClientConnected {
        peer_ip: String,
        timestamp: u64,
    },
    ClientDisconnected {
        peer_ip: String,
        reason: String,
        timestamp: u64,
    },
    HandshakeFailed {
        peer_ip: String,
        reason: String,
        timestamp: u64,
    },
    ProbeRejected {
        peer_ip: String,
        timestamp: u64,
    },
    KnockAccepted {
        peer_ip: String,
        timestamp: u64,
    },
    TransportSwitched {
        from: String,
        to: String,
        timestamp: u64,
    },
    RatchetRotated {
        session_id: u64,
        packet_count: u64,
        timestamp: u64,
    },
    NatAssigned {
        peer_ip: String,
        tun_ip: String,
        timestamp: u64,
    },
}

enum LogSink {
    File(std::sync::Mutex<File>),
    Stderr,
}

pub struct AuditLogger {
    sink: LogSink,
}

impl AuditLogger {
    /// Create a new `AuditLogger`. If `log_path` is `Some`, open the file in
    /// append mode; otherwise log to stderr.
    pub fn new(log_path: Option<&str>) -> AuditLogger {
        let sink = match log_path {
            Some(path) => {
                match OpenOptions::new().create(true).append(true).open(path) {
                    Ok(f) => LogSink::File(std::sync::Mutex::new(f)),
                    Err(e) => {
                        eprintln!(
                            "[audit] cannot open log file {path}: {e}; falling back to stderr"
                        );
                        LogSink::Stderr
                    }
                }
            }
            None => LogSink::Stderr,
        };
        AuditLogger { sink }
    }

    /// Log an audit event as a JSON line.
    pub fn log(&self, event: AuditEvent) {
        let line = match serde_json::to_string(&event) {
            Ok(s) => s,
            Err(e) => format!("{{\"error\": \"{}\"}}", e),
        };
        match &self.sink {
            LogSink::File(m) => {
                if let Ok(mut f) = m.lock() {
                    let _ = writeln!(f, "{}", line);
                }
            }
            LogSink::Stderr => {
                eprintln!("{}", line);
            }
        }
    }

    /// Current UNIX timestamp in seconds.
    pub fn current_timestamp() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn audit_event_serializes_to_json() {
        let event = AuditEvent::ClientConnected {
            peer_ip: "1.2.3.4".to_string(),
            timestamp: 1_700_000_000,
        };
        let json = serde_json::to_string(&event).unwrap();
        assert!(json.contains("client_connected"));
        assert!(json.contains("1.2.3.4"));
    }

    #[test]
    fn audit_logger_stderr_does_not_panic() {
        let logger = AuditLogger::new(None);
        logger.log(AuditEvent::ProbeRejected {
            peer_ip: "10.0.0.1".to_string(),
            timestamp: AuditLogger::current_timestamp(),
        });
    }

    #[test]
    fn current_timestamp_is_reasonable() {
        let ts = AuditLogger::current_timestamp();
        // After 2020-01-01 (1577836800) and before 2100-01-01 (4102444800).
        assert!(ts > 1_577_836_800, "timestamp looks too old");
        assert!(ts < 4_102_444_800, "timestamp looks too far in the future");
    }
}
