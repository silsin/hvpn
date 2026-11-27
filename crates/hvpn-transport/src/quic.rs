//! QUIC datagram transport.
//!
//! The tunnel carries IP packets as unreliable QUIC DATAGRAMs, so there is no
//! TCP-over-TCP: a lost packet is simply lost and the inner TCP connection
//! recovers it, instead of two stacked retransmission layers fighting.
//! Congestion control (BBR) still applies at the QUIC layer.
//!
//! Wire flow:
//!   1. client opens a QUIC connection (ALPN `h3`, so it looks like HTTP/3)
//!   2. client opens one bidirectional stream and sends
//!      `auth_token(40) || hello` (hello = 32-byte ephemeral X25519 key)
//!   3. server validates the token and answers one byte (`1` = ok)
//!   4. both sides exchange packets as DATAGRAMs.

use async_trait::async_trait;
use hvpn_common::HvpnError;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use crate::transport_trait::Transport;
use crate::websocket::{build_tls_client_config, generate_auth_token_bytes, TransportConfig};

/// ALPN advertised on the wire.
pub const QUIC_ALPN: &[u8] = b"h3";
/// Length of the hello message the client sends after the auth token.
pub const QUIC_HELLO_LEN: usize = 32;
/// Total size of the client's first stream message.
pub const QUIC_AUTH_MSG_LEN: usize = 40 + QUIC_HELLO_LEN;
/// MTU the TUN device should use so tunnelled packets fit one datagram.
pub const QUIC_TUNNEL_MTU: u32 = 1200;

/// Shared QUIC tuning for both client and server.
pub fn quic_transport_config() -> quinn::TransportConfig {
    let mut t = quinn::TransportConfig::default();
    // Datagram queues sized for bursts at a few hundred Mbit/s.
    t.datagram_receive_buffer_size(Some(8 * 1024 * 1024));
    t.datagram_send_buffer_size(8 * 1024 * 1024);
    // Allow datagrams big enough for a 1200-byte inner packet plus framing.
    t.initial_mtu(1350);
    t.mtu_discovery_config(Some(quinn::MtuDiscoveryConfig::default()));
    t.keep_alive_interval(Some(Duration::from_secs(10)));
    if let Ok(idle) = quinn::IdleTimeout::try_from(Duration::from_secs(30)) {
        t.max_idle_timeout(Some(idle));
    }
    // BBR keeps throughput up on lossy / long links where Cubic collapses.
    // Override with HVPN_QUIC_CC=cubic if BBR underperforms on your path.
    if std::env::var("HVPN_QUIC_CC").map(|v| v.eq_ignore_ascii_case("cubic")).unwrap_or(false) {
        t.congestion_controller_factory(Arc::new(quinn::congestion::CubicConfig::default()));
    } else {
        t.congestion_controller_factory(Arc::new(quinn::congestion::BbrConfig::default()));
    }
    // Only the single auth stream is ever used.
    t.max_concurrent_uni_streams(0u32.into());
    t.max_concurrent_bidi_streams(2u32.into());
    t
}

/// Build a server endpoint from a rustls server config.
pub fn quic_server_endpoint(
    addr: SocketAddr,
    tls: &rustls::ServerConfig,
) -> Result<quinn::Endpoint, HvpnError> {
    let mut tls = tls.clone();
    tls.alpn_protocols = vec![QUIC_ALPN.to_vec()];
    let crypto = quinn::crypto::rustls::QuicServerConfig::try_from(Arc::new(tls))
        .map_err(|e| HvpnError::Transport(format!("quic tls: {e}")))?;
    let mut server_cfg = quinn::ServerConfig::with_crypto(Arc::new(crypto));
    server_cfg.transport_config(Arc::new(quic_transport_config()));
    quinn::Endpoint::server(server_cfg, addr)
        .map_err(|e| HvpnError::Transport(format!("quic bind {addr}: {e}")))
}

/// A QUIC connection carrying tunnel packets as datagrams.
#[derive(Clone)]
pub struct QuicTransport {
    conn: quinn::Connection,
    /// VPN address the server assigned to this client, if any.
    assigned_ip: Option<std::net::Ipv4Addr>,
    /// Kept alive so the client's UDP socket stays open.
    _endpoint: Option<quinn::Endpoint>,
}

impl QuicTransport {
    /// Wrap an already-authenticated server-side connection.
    pub fn from_connection(conn: quinn::Connection) -> Self {
        Self { conn, assigned_ip: None, _endpoint: None }
    }

    /// Connect, authenticate and send `hello`. Returns once the server accepted.
    pub async fn connect(cfg: &TransportConfig, hello: &[u8]) -> Result<Self, HvpnError> {
        let secret = cfg
            .auth_secret
            .ok_or_else(|| HvpnError::Transport("quic requires an auth secret".into()))?;
        if hello.len() != QUIC_HELLO_LEN {
            return Err(HvpnError::Transport("bad hello length".into()));
        }

        let remote = tokio::net::lookup_host((cfg.host.as_str(), cfg.port))
            .await
            .map_err(|e| HvpnError::Transport(format!("resolve {}: {e}", cfg.host)))?
            .next()
            .ok_or_else(|| HvpnError::Transport("no address for host".into()))?;
        let local: SocketAddr = if remote.is_ipv6() {
            "[::]:0".parse().unwrap()
        } else {
            "0.0.0.0:0".parse().unwrap()
        };

        let mut tls = build_tls_client_config(cfg);
        tls.alpn_protocols = vec![QUIC_ALPN.to_vec()];
        let crypto = quinn::crypto::rustls::QuicClientConfig::try_from(Arc::new(tls))
            .map_err(|e| HvpnError::Transport(format!("quic tls: {e}")))?;
        let mut client_cfg = quinn::ClientConfig::new(Arc::new(crypto));
        client_cfg.transport_config(Arc::new(quic_transport_config()));

        let mut endpoint = quinn::Endpoint::client(local)
            .map_err(|e| HvpnError::Transport(format!("quic endpoint: {e}")))?;
        endpoint.set_default_client_config(client_cfg);

        let conn = endpoint
            .connect(remote, &cfg.host)
            .map_err(|e| HvpnError::Transport(format!("quic connect: {e}")))?
            .await
            .map_err(|e| HvpnError::Transport(format!("quic handshake: {e}")))?;

        let (mut send, mut recv) = conn
            .open_bi()
            .await
            .map_err(|e| HvpnError::Transport(format!("quic stream: {e}")))?;
        let mut msg = Vec::with_capacity(QUIC_AUTH_MSG_LEN);
        msg.extend_from_slice(&generate_auth_token_bytes(&secret));
        msg.extend_from_slice(hello);
        send.write_all(&msg)
            .await
            .map_err(|e| HvpnError::Transport(format!("quic auth send: {e}")))?;

        // Reply: ok byte + 4-byte assigned VPN address (0.0.0.0 = none).
        let mut ack = [0u8; 5];
        recv.read_exact(&mut ack)
            .await
            .map_err(|e| HvpnError::Transport(format!("server rejected connection: {e}")))?;
        if ack[0] != 1 {
            return Err(HvpnError::Transport("server rejected connection".into()));
        }
        let ip = std::net::Ipv4Addr::new(ack[1], ack[2], ack[3], ack[4]);
        let assigned_ip = (!ip.is_unspecified()).then_some(ip);
        Ok(Self { conn, assigned_ip, _endpoint: Some(endpoint) })
    }

    /// VPN address assigned by the server (None if the server assigns none).
    pub fn assigned_ip(&self) -> Option<std::net::Ipv4Addr> {
        self.assigned_ip
    }

    /// Largest datagram the path currently allows.
    pub fn max_datagram_size(&self) -> Option<usize> {
        self.conn.max_datagram_size()
    }

    pub fn rtt(&self) -> Duration {
        self.conn.rtt()
    }
}

#[async_trait]
impl Transport for QuicTransport {
    async fn send(&self, data: Vec<u8>) -> Result<(), HvpnError> {
        match self.conn.send_datagram(data.into()) {
            Ok(()) => Ok(()),
            // Too big for the current path MTU: drop it; inner TCP adapts.
            Err(quinn::SendDatagramError::TooLarge) => Ok(()),
            Err(e) => Err(HvpnError::Transport(format!("quic send: {e}"))),
        }
    }

    async fn recv(&self) -> Result<Vec<u8>, HvpnError> {
        self.conn
            .read_datagram()
            .await
            .map(|b| b.to_vec())
            .map_err(|e| HvpnError::Transport(format!("quic recv: {e}")))
    }

    async fn close(&self) -> Result<(), HvpnError> {
        self.conn.close(0u32.into(), b"bye");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Instant;

    fn server_tls() -> rustls::ServerConfig {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
        let der = cert.cert.der().clone();
        let key = rustls::pki_types::PrivateKeyDer::Pkcs8(
            rustls::pki_types::PrivatePkcs8KeyDer::from(cert.key_pair.serialize_der()),
        );
        rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![der], key)
            .unwrap()
    }

    /// Minimal server: checks the 40-byte token is non-zero, acks, then counts datagrams.
    async fn run_server(ep: quinn::Endpoint, expect: usize) -> usize {
        let conn = ep.accept().await.unwrap().await.unwrap();
        let (mut send, mut recv) = conn.accept_bi().await.unwrap();
        let mut msg = [0u8; QUIC_AUTH_MSG_LEN];
        recv.read_exact(&mut msg).await.unwrap();
        send.write_all(&[1, 10, 8, 0, 9]).await.unwrap();
        let mut got = 0;
        let deadline = Instant::now() + Duration::from_secs(20);
        while got < expect && Instant::now() < deadline {
            match tokio::time::timeout(Duration::from_millis(1500), conn.read_datagram()).await {
                Ok(Ok(_)) => got += 1,
                Ok(Err(_)) => break,
                Err(_) => break,
            }
        }
        got
    }

    #[tokio::test]
    async fn quic_datagram_loopback_throughput() {
        let ep = quic_server_endpoint("127.0.0.1:0".parse().unwrap(), &server_tls()).unwrap();
        let port = ep.local_addr().unwrap().port();
        const N: usize = 20_000;
        let server = tokio::spawn(run_server(ep, N));

        let mut cfg = TransportConfig::new("127.0.0.1", port, "/");
        cfg.danger_accept_invalid_certs = true;
        cfg.auth_secret = Some([7u8; 32]);
        let t = QuicTransport::connect(&cfg, &[1u8; 32]).await.expect("connect");
        assert_eq!(t.assigned_ip(), Some(std::net::Ipv4Addr::new(10, 8, 0, 9)));

        let payload = vec![0xABu8; 1250];
        let start = Instant::now();
        for _ in 0..N {
            let _ = t.send(payload.clone()).await;
            tokio::task::yield_now().await;
        }
        let got = server.await.unwrap();
        let secs = start.elapsed().as_secs_f64();
        let mbps = (got * payload.len() * 8) as f64 / secs / 1e6;
        println!("quic loopback: {got}/{N} datagrams, {mbps:.0} Mbit/s");
        assert!(got > N / 2, "too many datagrams lost on loopback: {got}/{N}");
    }
}
