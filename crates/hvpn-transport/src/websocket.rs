//! WebSocket-over-TLS transport using tokio-tungstenite + rustls.

use async_trait::async_trait;
use hvpn_common::HvpnError;
use sha2::{Digest, Sha256};
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
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, Error as TlsError, SignatureScheme};

use crate::transport_trait::Transport;
use crate::DomainFrontConfig;
use crate::CertPin;

// ── Certificate pinning verifier ──────────────────────────────────────────────

/// A custom `ServerCertVerifier` that enforces SHA-256 certificate fingerprint
/// pinning when fingerprints are provided, and falls back to standard WebPKI
/// verification when the pin list is empty.
#[derive(Debug)]
pub struct CertVerifier {
    cert_pin: CertPin,
    /// Delegate verifier used for standard WebPKI and signature verification.
    webpki: Arc<rustls::client::WebPkiServerVerifier>,
}

impl CertVerifier {
    pub fn new(cert_pin: CertPin, root_store: rustls::RootCertStore) -> Self {
        let webpki = rustls::client::WebPkiServerVerifier::builder(Arc::new(root_store))
            .build()
            .expect("failed to build WebPkiServerVerifier");
        Self { cert_pin, webpki }
    }
}

impl ServerCertVerifier for CertVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, TlsError> {
        // Compute SHA-256 of the DER-encoded end-entity certificate.
        let mut hasher = Sha256::new();
        hasher.update(end_entity.as_ref());
        let fingerprint: [u8; 32] = hasher.finalize().into();

        if self.cert_pin.sha256_fingerprints.is_empty() {
            // No pins configured: fall back to full WebPKI verification.
            self.webpki.verify_server_cert(
                end_entity,
                intermediates,
                server_name,
                ocsp_response,
                now,
            )
        } else {
            // Pin mode: check fingerprint against the allow-list.
            let matched = self
                .cert_pin
                .sha256_fingerprints
                .iter()
                .any(|pin| pin == &fingerprint);
            if matched {
                Ok(ServerCertVerified::assertion())
            } else {
                Err(TlsError::InvalidCertificate(
                    rustls::CertificateError::UnknownIssuer,
                ))
            }
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        self.webpki.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        self.webpki.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.webpki.supported_verify_schemes()
    }
}

// ── TransportConfig ───────────────────────────────────────────────────────────

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
    /// Optional certificate fingerprint pin. When `Some`, the `CertVerifier`
    /// is installed as a custom verifier.
    pub cert_pin: Option<CertPin>,
}

impl TransportConfig {
    pub fn new(host: impl Into<String>, port: u16, path: impl Into<String>) -> Self {
        Self {
            host: host.into(),
            port,
            path: path.into(),
            tls_cert_override: None,
            cert_pin: None,
        }
    }
}

// ── WebSocketTransport ────────────────────────────────────────────────────────

type WsStream = tokio_tungstenite::WebSocketStream<
    tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
>;

/// WebSocket transport with realistic browser-like upgrade headers.
#[derive(Clone)]
pub struct WebSocketTransport {
    stream: Arc<Mutex<WsStream>>,
    pub domain_front: Option<DomainFrontConfig>,
}

impl WebSocketTransport {
    /// Connect to `ws://host:port/path` without TLS (plain WebSocket).
    pub async fn connect_plain(cfg: &TransportConfig) -> Result<Self, HvpnError> {
        use tokio_tungstenite::connect_async;
        let url = format!("ws://{}:{}{}", cfg.host, cfg.port, cfg.path);

        let mut request = url
            .as_str()
            .into_client_request()
            .map_err(|e| HvpnError::Transport(e.to_string()))?;

        // Phase 1: use a fixed shared mac_key that matches the server's fallback.
        // The server derives mac_key via HKDF from a zeroed ECDH shared secret.
        // Both sides use the same zeroed input → same HKDF output.
        let mac_key: [u8; 32] = {
            use hkdf::Hkdf;
            use sha2::Sha512;
            let shared_secret = [0u8; 32]; // zeroed server secret + zeroed ephemeral = zero shared
            let hk = Hkdf::<Sha512>::new(None, &shared_secret);
            let mut okm = [0u8; 128];
            let _ = hk.expand(b"HVPN-v1-session-keys", &mut okm);
            let mut mac_key = [0u8; 32];
            mac_key.copy_from_slice(&okm[96..128]);
            mac_key
        };
        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let nonce = [0u8; 16];
        let token = hvpn_crypto::generate_probe_token(&mac_key, ts, &nonce);
        let token_hex: String = token.iter().map(|b| format!("{:02x}", b)).collect();

        let headers = request.headers_mut();
        headers.insert("X-Auth-Token", token_hex.parse().unwrap());
        headers.insert(
            "User-Agent",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 \
             (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36"
                .parse()
                .unwrap(),
        );
        headers.insert("Accept", "*/*".parse().unwrap());
        headers.insert("Accept-Language", "en-US,en;q=0.9".parse().unwrap());
        headers.insert("Cache-Control", "no-cache".parse().unwrap());

        let (ws_stream, _response) = connect_async(request)
            .await
            .map_err(|e| HvpnError::Transport(e.to_string()))?;

        Ok(Self {
            stream: Arc::new(Mutex::new(ws_stream)),
            domain_front: None,
        })
    }

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

        // Build the rustls TLS connector.
        let mut root_store = rustls::RootCertStore::empty();
        root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

        let tls_config = if let Some(ref pin) = cfg.cert_pin {
            // Install a custom cert verifier that enforces fingerprint pinning.
            rustls::ClientConfig::builder()
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(CertVerifier::new(
                    pin.clone(),
                    root_store,
                )))
                .with_no_client_auth()
        } else {
            rustls::ClientConfig::builder()
                .with_root_certificates(root_store)
                .with_no_client_auth()
        };

        let connector = Connector::Rustls(Arc::new(tls_config));

        let (ws_stream, _response) =
            connect_async_tls_with_config(request, None, false, Some(connector))
                .await
                .map_err(|e| HvpnError::Transport(e.to_string()))?;

        Ok(Self {
            stream: Arc::new(Mutex::new(ws_stream)),
            domain_front: None,
        })
    }

    /// Connect with domain fronting: TLS SNI uses `front_domain`, HTTP Host uses `real_host`.
    pub async fn connect_with_domain_front(
        cfg: &TransportConfig,
        domain_front: DomainFrontConfig,
    ) -> Result<Self, HvpnError> {
        // Build URL using the fronting CDN domain for the TCP+TLS connection.
        let url = format!(
            "wss://{}:{}{}",
            domain_front.front_domain, cfg.port, cfg.path
        );

        let mut request = url
            .as_str()
            .into_client_request()
            .map_err(|e| HvpnError::Transport(e.to_string()))?;

        let headers = request.headers_mut();
        // Override Host to direct traffic to the real backend through the CDN.
        headers.insert(
            "host",
            domain_front.real_host.parse().unwrap(),
        );
        headers.insert(
            "User-Agent",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 \
             (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36"
                .parse()
                .unwrap(),
        );
        headers.insert("Accept", "*/*".parse().unwrap());
        headers.insert("Accept-Language", "en-US,en;q=0.9".parse().unwrap());
        headers.insert("Accept-Encoding", "gzip, deflate, br".parse().unwrap());
        headers.insert("Cache-Control", "no-cache".parse().unwrap());
        headers.insert("Pragma", "no-cache".parse().unwrap());
        headers.insert(
            "Origin",
            format!("https://{}:{}", domain_front.front_domain, cfg.port)
                .parse()
                .unwrap(),
        );

        // TLS connector uses webpki roots; SNI is taken from the URL hostname (front_domain).
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
            domain_front: Some(domain_front),
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

// ── Tests ─────────────────────────────────────────────────────────────────────

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
        assert!(cfg.cert_pin.is_none());
    }

    #[test]
    fn transport_config_with_cert_override() {
        let mut cfg = TransportConfig::new("vpn.example.com", 443, "/ws");
        cfg.tls_cert_override = Some(b"--- BEGIN CERTIFICATE ---".to_vec());
        assert!(cfg.tls_cert_override.is_some());
    }

    /// Install the ring crypto provider (needed by WebPkiServerVerifier in rustls 0.23).
    /// Safe to call multiple times — subsequent calls are no-ops.
    fn install_ring() {
        let _ = rustls::crypto::ring::default_provider().install_default();
    }

    #[test]
    fn test_cert_pin_rejects_wrong_cert() {
        install_ring();

        // Build a CertPin with a dummy fingerprint (all 0xAA bytes).
        let pin = CertPin {
            sha256_fingerprints: vec![[0xAAu8; 32]],
        };
        let mut root_store = rustls::RootCertStore::empty();
        root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        let verifier = CertVerifier::new(pin, root_store);

        // Construct a fake DER cert (random bytes — not a real cert).
        // The SHA-256 of these bytes will not be [0xAA; 32].
        let fake_cert = CertificateDer::from(vec![0x01u8; 64]);
        let server_name = ServerName::try_from("example.com").unwrap();
        let now = UnixTime::since_unix_epoch(std::time::Duration::from_secs(0));

        let result = verifier.verify_server_cert(&fake_cert, &[], &server_name, &[], now);
        assert!(result.is_err(), "wrong fingerprint should be rejected");
    }

    #[test]
    fn test_cert_pin_empty_falls_back_to_webpki() {
        install_ring();

        // Empty fingerprint list — verifier should not do pin checking.
        // A fake cert will fail WebPKI (which is expected), but must NOT
        // fail with an UnknownIssuer fingerprint mismatch error.
        let pin = CertPin {
            sha256_fingerprints: vec![],
        };
        let mut root_store = rustls::RootCertStore::empty();
        root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        let verifier = CertVerifier::new(pin, root_store);

        let fake_cert = CertificateDer::from(vec![0x01u8; 64]);
        let server_name = ServerName::try_from("example.com").unwrap();
        let now = UnixTime::since_unix_epoch(std::time::Duration::from_secs(0));

        let result = verifier.verify_server_cert(&fake_cert, &[], &server_name, &[], now);
        // Expected: error from WebPKI (not a valid cert), but it reached WebPKI
        // rather than being rejected by pin matching.
        assert!(result.is_err());
        // Must NOT be UnknownIssuer (which would indicate pin rejection, not WebPKI fallback).
        if let Err(TlsError::InvalidCertificate(rustls::CertificateError::UnknownIssuer)) = result
        {
            panic!("empty pin list should fall back to WebPKI, not reject by pin");
        }
    }
}
