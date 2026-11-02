//! Stream multiplexer: routes incoming `Frame`s to per-stream tokio channels.

use std::collections::HashMap;

use tokio::sync::mpsc;

use crate::codec::Frame;

const CHANNEL_CAPACITY: usize = 256;

/// A handle for one logical stream: the receiver end of the per-stream channel.
pub type StreamReceiver = mpsc::Receiver<Frame>;

/// Manages multiple logical streams over a single HVPN session.
pub struct StreamMultiplexer {
    /// `stream_id` → sender half of that stream's channel.
    streams: HashMap<u32, mpsc::Sender<Frame>>,
}

impl StreamMultiplexer {
    pub fn new() -> Self {
        Self {
            streams: HashMap::new(),
        }
    }

    /// Open a new stream and return the receiver half.
    ///
    /// Returns `None` if `stream_id` is already in use.
    pub fn open_stream(&mut self, stream_id: u32) -> Option<StreamReceiver> {
        if self.streams.contains_key(&stream_id) {
            return None;
        }
        let (tx, rx) = mpsc::channel(CHANNEL_CAPACITY);
        self.streams.insert(stream_id, tx);
        Some(rx)
    }

    /// Close and remove the stream identified by `stream_id`.
    pub fn close_stream(&mut self, stream_id: u32) {
        self.streams.remove(&stream_id);
    }

    /// Route an incoming `Frame` to the appropriate stream channel.
    ///
    /// Returns `true` if the frame was delivered, `false` if no such stream
    /// exists or the channel is full/closed.
    pub async fn route_frame(&self, frame: Frame) -> bool {
        match self.streams.get(&frame.stream_id) {
            Some(tx) => tx.send(frame).await.is_ok(),
            None => false,
        }
    }

    /// Returns the number of currently open streams.
    pub fn stream_count(&self) -> usize {
        self.streams.len()
    }
}

impl Default for StreamMultiplexer {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codec::FrameType;

    fn make_frame(stream_id: u32) -> Frame {
        Frame {
            seq: 1,
            stream_id,
            frame_type: FrameType::Data,
            flags: 0,
            payload: b"hello".to_vec(),
            padding: vec![],
        }
    }

    #[tokio::test]
    async fn open_route_receive() {
        let mut mux = StreamMultiplexer::new();
        let mut rx = mux.open_stream(1).expect("should open");

        let delivered = mux.route_frame(make_frame(1)).await;
        assert!(delivered);

        let received = rx.recv().await.expect("should receive");
        assert_eq!(received.stream_id, 1);
    }

    #[tokio::test]
    async fn unknown_stream_not_delivered() {
        let mux = StreamMultiplexer::new();
        let delivered = mux.route_frame(make_frame(99)).await;
        assert!(!delivered);
    }

    #[tokio::test]
    async fn duplicate_open_returns_none() {
        let mut mux = StreamMultiplexer::new();
        assert!(mux.open_stream(5).is_some());
        assert!(mux.open_stream(5).is_none());
    }
}
