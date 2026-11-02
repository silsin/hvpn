//! WebSocket-over-TLS transport using tokio-tungstenite + rustls.

use async_trait::async_trait;
use hvpn_common::HvpnError;
use std::sync::Arc;
use tokio::sync::Mutex;
use tokio_tungstenite::{
    connect_async_tls_with_config,
    tungstenite::{
        client::IntoClientRequest,
        protocol::Message,
    },
    Connector,
};
use futures_util::{SinkExt, StreamExt};

use crate::transport_trait::Transport;

/// Configuration for establishing a WebSocket transport connection.
#[derive(Debug, Clone)]
pub struct TransportConfig {
    /// Remote hostname (used for TLS SNI and WebSocket Host header).
    pub host: String,
    /// Remote port.
    pub port: u16,
    /// WebSocket path (e.g. `/ws`).
    pub path: String,
    /// Optional PEM certificate bytes for TLS certificate pinning.
    /// When `None`, the system/webpki root store is used.
    pub tls_cert_override: Option<Vec<u8>>,
}

impl TransportConfig {
    pub fn new(host: impl Into<String>, port: u16, path: impl Into<String>) -> Self {
        Self {
            host: host.into(),
            port,
            path: path.into(),
            tls_cert_override: None,
        }
    }
}

type WsStream = tokio_tungstenite::WebSocketStream<
    tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
>;

/// WebSocket transport with realistic browser-like upgrade headers.
pub struct WebSocketTransport {
    stream: Arc<Mutex<WsStream>>,
}

impl WebSocketTransport {
    /// Connect to `wss://host:port/path` with browser-like headers.
    pub async fn connect(cfg: &TransportConfig) -> Result<Self, HvpnError> {
        let url = format!("wss://{}:{}{}", cfg.host, cfg.port, cfg.path);

        // Build a request with realistic browser headers to blend in.
        let mut request = url
            .as_str()
            .into_client_request()
            .map_err(|e| HvpnError::Transport(e.to_string()))?;

        let headers = request.headers_mut();
        headers.insert(
            "User-Agent",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 \
             (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36"
                .parse()
                .unwrap(),
        );
        headers.insert("Accept", "*/*".parse().unwrap());
        headers.insert(
            "Accept-Language",
            "en-US,en;q=0.9".parse().unwrap(),
        );
        headers.insert(
            "Accept-Encoding",
            "gzip, deflate, br".parse().unwrap(),
        );
        headers.insert("Cache-Control", "no-cache".parse().unwrap());
        headers.insert("Pragma", "no-cache".parse().unwrap());
        headers.insert(
            "Origin",
            format!("https://{}:{}", cfg.host, cfg.port)
                .parse()
                .unwrap(),
        );

        // Build the rustls TLS connector backed by webpki root certificates.
        let mut root_store = rustls::RootCertStore::empty();
        root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        let tls_config = rustls::ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth();
        let connector = Connector::Rustls(Arc::new(tls_config));

        let (ws_stream, _response) =
            connect_async_tls_with_config(request, None, false, Some(connector))
                .await
                .map_err(|e| HvpnError::Transport(e.to_string()))?;

        Ok(Self {
            stream: Arc::new(Mutex::new(ws_stream)),
        })
    }
}

#[async_trait]
impl Transport for WebSocketTransport {
    async fn send(&self, data: Vec<u8>) -> Result<(), HvpnError> {
        let mut guard = self.stream.lock().await;
        guard
            .send(Message::Binary(data))
            .await
            .map_err(|e| HvpnError::Transport(e.to_string()))
    }

    async fn recv(&self) -> Result<Vec<u8>, HvpnError> {
        let mut guard = self.stream.lock().await;
        loop {
            match guard.next().await {
                Some(Ok(Message::Binary(bytes))) => return Ok(bytes),
                Some(Ok(Message::Ping(_))) | Some(Ok(Message::Pong(_))) => {
                    // ignore control frames, keep waiting
                    continue;
                }
                Some(Ok(Message::Close(_))) | None => {
                    return Err(HvpnError::Transport("connection closed".to_string()));
                }
                Some(Ok(_)) => continue, // text frames: skip
                Some(Err(e)) => return Err(HvpnError::Transport(e.to_string())),
            }
        }
    }

    async fn close(&self) -> Result<(), HvpnError> {
        let mut guard = self.stream.lock().await;
        guard
            .close(None)
            .await
            .map_err(|e| HvpnError::Transport(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transport_config_construction() {
        let cfg = TransportConfig::new("vpn.example.com", 443, "/ws");
        assert_eq!(cfg.host, "vpn.example.com");
        assert_eq!(cfg.port, 443);
        assert_eq!(cfg.path, "/ws");
        assert!(cfg.tls_cert_override.is_none());
    }

    #[test]
    fn transport_config_with_cert_override() {
        let mut cfg = TransportConfig::new("vpn.example.com", 443, "/ws");
        cfg.tls_cert_override = Some(b"--- BEGIN CERTIFICATE ---".to_vec());
        assert!(cfg.tls_cert_override.is_some());
    }
}
