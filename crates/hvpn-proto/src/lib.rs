//! Hand-written prost message stubs for Phase 1.
//! A prost-build code-generation pass (requiring `protoc`) will replace these
//! in Phase 2.  The struct layout mirrors `proto/hvpn.proto` exactly.

pub mod hvpn {
    use prost::Message;

    /// Sent by the client to initiate a session.
    #[derive(Clone, PartialEq, Message)]
    pub struct HandshakeInit {
        /// Client's ephemeral X25519 public key (32 bytes).
        #[prost(bytes = "vec", tag = "1")]
        pub ephemeral_pubkey: Vec<u8>,

        /// HMAC probe-defense token (32 bytes).
        #[prost(bytes = "vec", tag = "2")]
        pub probe_token: Vec<u8>,
    }

    /// Sent by the server in response to a `HandshakeInit`.
    #[derive(Clone, PartialEq, Message)]
    pub struct HandshakeResponse {
        /// Server's static X25519 public key (32 bytes).
        #[prost(bytes = "vec", tag = "1")]
        pub server_pubkey: Vec<u8>,

        /// Whether the session was accepted.
        #[prost(bool, tag = "2")]
        pub accepted: bool,
    }
}

#[cfg(test)]
mod tests {
    use super::hvpn::*;
    use prost::Message;

    #[test]
    fn handshake_init_encode_decode() {
        let msg = HandshakeInit {
            ephemeral_pubkey: vec![0x01u8; 32],
            probe_token: vec![0x02u8; 32],
        };
        let encoded = msg.encode_to_vec();
        let decoded = HandshakeInit::decode(encoded.as_slice()).expect("decode failed");
        assert_eq!(decoded.ephemeral_pubkey, msg.ephemeral_pubkey);
        assert_eq!(decoded.probe_token, msg.probe_token);
    }
}
