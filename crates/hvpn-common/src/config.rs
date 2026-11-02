use serde::{Deserialize, Serialize};

/// Obfuscation traffic-shaping profile.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ObfsProfile {
    /// Mimic browser HTTPS traffic patterns.
    Browser,
    /// Mimic video/audio streaming traffic patterns.
    Streaming,
    /// Mimic VoIP call traffic patterns.
    Voip,
    /// Mimic an idle keep-alive connection.
    Idle,
}

impl Default for ObfsProfile {
    fn default() -> Self {
        Self::Browser
    }
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
