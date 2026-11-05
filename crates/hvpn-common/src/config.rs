use serde::{Deserialize, Serialize};

/// Obfuscation traffic-shaping profile.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ObfsProfile {
    /// Mimic browser HTTPS traffic patterns.
    #[default]
    Browser,
    /// Mimic video/audio streaming traffic patterns.
    Streaming,
    /// Mimic VoIP call traffic patterns.
    Voip,
    /// Mimic an idle keep-alive connection.
    Idle,
}

/// A single hop in an onion relay chain.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RelayHopConfig {
    /// Address of the relay node (hostname or IP with optional port).
    pub address: String,

    /// Hex-encoded 32-byte public key of the relay node.
    pub pubkey_hex: String,
}

/// Top-level HVPN configuration loaded from `config.toml`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    /// Remote server hostname or IP address.
    pub server_address: String,

    /// Remote server port.
    pub server_port: u16,

    /// Path to the TLS certificate (PEM) used for server verification or pinning.
    pub tls_cert_path: String,

    /// Obfuscation profile to apply to the tunnel traffic.
    #[serde(default)]
    pub obfs_profile: ObfsProfile,

    /// Optional onion relay chain. `None` means direct connection; `Some` enables multi-hop routing.
    #[serde(default)]
    pub relay_chain: Option<Vec<RelayHopConfig>>,

    /// Enable steganographic transport layer.
    #[serde(default)]
    pub stego_mode: bool,

    /// Enable post-quantum hybrid KEM handshake.
    #[serde(default)]
    pub post_quantum: bool,

    /// Enable server-side NAT routing.
    #[serde(default)]
    pub nat_enabled: bool,

    /// IP address assigned to the TUN interface (e.g. "10.8.0.2").
    #[serde(default = "default_tun_ip")]
    pub tun_ip: String,

    /// Netmask for the TUN interface (e.g. "255.255.255.0").
    #[serde(default = "default_tun_netmask")]
    pub tun_netmask: String,

    /// DNS servers to use over the tunnel (e.g. ["1.1.1.1", "8.8.8.8"]).
    #[serde(default)]
    pub dns_servers: Vec<String>,
}

fn default_tun_ip() -> String {
    "10.8.0.2".to_string()
}

fn default_tun_netmask() -> String {
    "255.255.255.0".to_string()
}

impl Config {
    /// Parse a `Config` from a TOML string.
    pub fn from_toml_str(s: &str) -> Result<Self, toml::de::Error> {
        toml::from_str(s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_round_trip_from_toml() {
        let toml_str = r#"
            server_address = "vpn.example.com"
            server_port    = 443
            tls_cert_path  = "/etc/hvpn/server.pem"
            obfs_profile   = "streaming"
        "#;

        let cfg = Config::from_toml_str(toml_str).expect("parse failed");
        assert_eq!(cfg.server_address, "vpn.example.com");
        assert_eq!(cfg.server_port, 443);
        assert_eq!(cfg.tls_cert_path, "/etc/hvpn/server.pem");
        assert_eq!(cfg.obfs_profile, ObfsProfile::Streaming);
    }

    #[test]
    fn config_default_obfs_profile() {
        let toml_str = r#"
            server_address = "10.0.0.1"
            server_port    = 8443
            tls_cert_path  = "/tmp/cert.pem"
        "#;

        let cfg = Config::from_toml_str(toml_str).expect("parse failed");
        assert_eq!(cfg.obfs_profile, ObfsProfile::Browser);
    }
}
