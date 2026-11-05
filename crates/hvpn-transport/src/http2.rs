//! HTTP/2 transport using the `h2` crate over a plain TCP connection.

use async_trait::async_trait;
use bytes::Bytes;
use http::{Method, Request};
use hvpn_common::HvpnError;
use std::sync::Arc;
use tokio::net::TcpStream;
use tokio::sync::Mutex;

use crate::transport_trait::Transport;
use crate::websocket::TransportConfig;

pub struct Http2Transport {
    pub config: TransportConfig,
    send_request: Arc<Mutex<h2::client::SendRequest<Bytes>>>,
}

impl Http2Transport {
    pub async fn connect(cfg: &TransportConfig) -> Result<Self, HvpnError> {
        let addr = format!("{}:{}", cfg.host, cfg.port);
        let tcp = TcpStream::connect(&addr)
            .await
            .map_err(|e| HvpnError::Transport(e.to_string()))?;
        let (send_request, connection) = h2::client::handshake(tcp)
            .await
            .map_err(|e| HvpnError::Transport(e.to_string()))?;
        tokio::spawn(async move {
            let _ = connection.await;
        });
        Ok(Self {
            config: cfg.clone(),
            send_request: Arc::new(Mutex::new(send_request)),
        })
    }
}

#[async_trait]
impl Transport for Http2Transport {
    async fn send(&self, data: Vec<u8>) -> Result<(), HvpnError> {
        // Clone out of the mutex — SendRequest is Arc-backed and cheap to clone.
        let sr_clone = {
            let guard = self.send_request.lock().await;
            guard.clone()
        };
        // `.ready()` returns a Future; awaiting it polls until the connection
        // can accept a new request, then gives back a ready `SendRequest`.
        let mut ready_sr = sr_clone
            .ready()
            .await
            .map_err(|e| HvpnError::Transport(e.to_string()))?;
        let req = Request::builder()
            .method(Method::POST)
            .uri("/api/v1/data")
            .header("content-type", "application/grpc")
            .header("user-agent", "grpc-rust/0.6.2")
            .body(())
            .map_err(|e| HvpnError::Transport(e.to_string()))?;
        let (_resp, mut send_stream) = ready_sr
            .send_request(req, false)
            .map_err(|e| HvpnError::Transport(e.to_string()))?;
        send_stream
            .send_data(Bytes::from(data), true)
            .map_err(|e| HvpnError::Transport(e.to_string()))?;
        Ok(())
    }

    async fn recv(&self) -> Result<Vec<u8>, HvpnError> {
        // Full bidirectional streaming requires holding onto a ResponseFuture/RecvStream
        // per request; a shared recv channel is outside the scope of this transport stub.
        Err(HvpnError::Transport(
            "Http2Transport::recv requires an active response stream".into(),
        ))
    }

    async fn close(&self) -> Result<(), HvpnError> {
        Ok(())
    }
}
