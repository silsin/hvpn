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

// ── Accept-any-cert verifier ──────────────────────────────────────────────────

/// A `ServerCertVerifier` that accepts any certificate without validation.
/// Used when `danger_accept_invalid_certs = true` (e.g. self-signed server cert).
#[derive(Debug)]
pub struct DangerVerifier;

impl ServerCertVerifier for DangerVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, TlsError> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::RSA_PKCS1_SHA384,
            SignatureScheme::RSA_PKCS1_SHA512,
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::ED25519,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PSS_SHA384,
            SignatureScheme::RSA_PSS_SHA512,
        ]
    }
}

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
    /// When `true`, skip all TLS certificate verification — useful for
    /// self-signed server certificates.
    pub danger_accept_invalid_certs: bool,
    /// Shared auth secret (32 bytes) used to mint HMAC-based `X-Auth-Token` headers.
    /// When `None`, no auth header is sent (backwards-compatible fallback).
    pub auth_secret: Option<[u8; 32]>,
}

impl TransportConfig {
    pub fn new(host: impl Into<String>, port: u16, path: impl Into<String>) -> Self {
        Self {
            host: host.into(),
            port,
            path: path.into(),
            tls_cert_override: None,
            cert_pin: None,
            danger_accept_invalid_certs: false,
            auth_secret: None,
        }
    }
}

// ── Auth token helper ─────────────────────────────────────────────────────────

/// Generate a 40-byte auth token: `timestamp_le(8) || HMAC-SHA256(secret, ts || [0u8;16])(32)`.
/// Returns the token hex-encoded (80 hex chars).
fn generate_auth_token(auth_secret: &[u8; 32]) -> String {
    use hmac::{Hmac, Mac};

    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let ts_le = ts.to_le_bytes(); // 8 bytes, little-endian

    // HMAC input: timestamp_le (8 bytes) || zero nonce (16 bytes)
    let mut mac_input = [0u8; 24];
    mac_input[..8].copy_from_slice(&ts_le);
    // bytes [8..24] remain zero (zero nonce)

    let mut mac = Hmac::<sha2::Sha256>::new_from_slice(auth_secret)
        .expect("HMAC accepts any key length");
    mac.update(&mac_input);
    let hmac_bytes: [u8; 32] = mac.finalize().into_bytes().into();

    // Token = ts_le(8) || hmac(32) = 40 bytes total → 80 hex chars
    let mut token = [0u8; 40];
    token[..8].copy_from_slice(&ts_le);
    token[8..].copy_from_slice(&hmac_bytes);

    token.iter().map(|b| format!("{:02x}", b)).collect()
}

// ── WebSocketTransport ────────────────────────────────────────────────────────

type WsStream = tokio_tungstenite::WebSocketStream<
    tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
>;

type WsSink = futures_util::stream::SplitSink<WsStream, Message>;
type WsSource = futures_util::stream::SplitStream<WsStream>;

/// WebSocket transport with realistic browser-like upgrade headers.
/// Uses split send/recv halves to allow concurrent full-duplex operation
/// without mutex deadlock.
#[derive(Clone)]
pub struct WebSocketTransport {
    sink: Arc<Mutex<WsSink>>,
    source: Arc<Mutex<WsSource>>,
    pub domain_front: Option<DomainFrontConfig>,
}

impl WebSocketTransport {
    fn from_stream(stream: WsStream, domain_front: Option<DomainFrontConfig>) -> Self {
        use futures_util::StreamExt;
        let (sink, source) = stream.split();
        Self {
            sink: Arc::new(Mutex::new(sink)),
            source: Arc::new(Mutex::new(source)),
            domain_front,
        }
    }
    /// Connect to `ws://host:port/path` without TLS (plain WebSocket).
    pub async fn connect_plain(cfg: &TransportConfig) -> Result<Self, HvpnError> {
        use tokio_tungstenite::connect_async;
        let url = format!("ws://{}:{}{}", cfg.host, cfg.port, cfg.path);

        let mut request = url
            .as_str()
            .into_client_request()
            .map_err(|e| HvpnError::Transport(e.to_string()))?;

        let headers = request.headers_mut();

        // Send X-Auth-Token when an auth secret is configured.
        if let Some(ref secret) = cfg.auth_secret {
            let token_hex = generate_auth_token(secret);
            headers.insert("X-Auth-Token", token_hex.parse().unwrap());
        }

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

        Ok(Self::from_stream(ws_stream, None))
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

        // Send X-Auth-Token when an auth secret is configured.
        if let Some(ref secret) = cfg.auth_secret {
            let token_hex = generate_auth_token(secret);
            headers.insert("X-Auth-Token", token_hex.parse().unwrap());
        }

        // Build the rustls TLS connector.
        let mut root_store = rustls::RootCertStore::empty();
        root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

        let tls_config = if cfg.danger_accept_invalid_certs {
            // Skip all cert verification — needed for self-signed server certificates.
            rustls::ClientConfig::builder()
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(DangerVerifier))
                .with_no_client_auth()
        } else if let Some(ref pin) = cfg.cert_pin {
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

        Ok(Self::from_stream(ws_stream, None))
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

        Ok(Self::from_stream(ws_stream, Some(domain_front)))
    }
}

#[async_trait]
impl Transport for WebSocketTransport {
    async fn send(&self, data: Vec<u8>) -> Result<(), HvpnError> {
        use futures_util::SinkExt;
        let mut guard = self.sink.lock().await;
        guard
            .send(Message::Binary(data))
            .await
            .map_err(|e| HvpnError::Transport(e.to_string()))
    }

    async fn recv(&self) -> Result<Vec<u8>, HvpnError> {
        use futures_util::StreamExt;
        let mut guard = self.source.lock().await;
        loop {
            match guard.next().await {
                Some(Ok(Message::Binary(bytes))) => return Ok(bytes),
                Some(Ok(Message::Ping(_))) | Some(Ok(Message::Pong(_))) => continue,
                Some(Ok(Message::Close(_))) | None => {
                    return Err(HvpnError::Transport("connection closed".to_string()));
                }
                Some(Ok(_)) => continue,
                Some(Err(e)) => return Err(HvpnError::Transport(e.to_string())),
            }
        }
    }

    async fn close(&self) -> Result<(), HvpnError> {
        use futures_util::SinkExt;
        let mut guard = self.sink.lock().await;
        guard
            .close()
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

