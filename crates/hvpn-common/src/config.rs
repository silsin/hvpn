use serde::{Deserialize, Serialize};
use std::str::FromStr;

use crate::HvpnError;

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
    #[serde(default)]
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

    /// SHA-256 certificate fingerprints for cert pinning (64 hex chars each).
    /// When non-empty, the TLS connection is rejected unless the server cert
    /// matches one of these fingerprints.
    #[serde(default)]
    pub cert_pin_fingerprints: Vec<String>,

    /// Use TLS for the transport connection. Set to false when the server
    /// does not have a TLS certificate (plain WebSocket).
    #[serde(default = "default_use_tls")]
    pub use_tls: bool,
}

fn default_tun_ip() -> String {
    "10.8.0.2".to_string()
}

fn default_tun_netmask() -> String {
    "255.255.255.0".to_string()
}

fn default_use_tls() -> bool {
    true
}

/// Returns `true` if `s` consists entirely of lowercase hex characters and has the given length.
fn is_hex_str(s: &str, expected_len: usize) -> bool {
    s.len() == expected_len && s.chars().all(|c| c.is_ascii_hexdigit())
}

impl Config {
    /// Parse a `Config` from a TOML string.
    pub fn from_toml_str(s: &str) -> Result<Self, toml::de::Error> {
        toml::from_str(s)
    }

    /// Validate the configuration, collecting all errors into a `Vec<String>`.
    ///
    /// Returns `Ok(())` when validation passes, or `Err(errors)` with every
    /// problem found so the caller can report them all at once.
    pub fn validate(&self) -> Result<(), Vec<String>> {
        let mut errors: Vec<String> = Vec::new();

        // 1. server_address must not be empty.
        if self.server_address.is_empty() {
            errors.push("server_address must not be empty".to_string());
        }

        // 2. server_port must be in range 1–65535 (u16, so only 0 is invalid).
        if self.server_port == 0 {
            errors.push("server_port must be between 1 and 65535".to_string());
        }

        // 3. tun_ip must be a valid IPv4 address.
        if !self.tun_ip.is_empty()
            && std::net::Ipv4Addr::from_str(&self.tun_ip).is_err()
        {
            errors.push("tun_ip is not a valid IPv4 address".to_string());
        }

        // 4. tun_netmask must be a valid IPv4 address.
        if !self.tun_netmask.is_empty()
            && std::net::Ipv4Addr::from_str(&self.tun_netmask).is_err()
        {
            errors.push("tun_netmask is not a valid IPv4 address".to_string());
        }

        // 5. dns_servers: each entry must be a valid IP address.
        for (i, addr) in self.dns_servers.iter().enumerate() {
            if std::net::IpAddr::from_str(addr).is_err() {
                errors.push(format!(
                    "dns_servers[{}] is not a valid IP address: {}",
                    i, addr
                ));
            }
        }

        // 6. relay_chain: if Some, must have ≥1 hop; each hop's pubkey_hex must be 64 hex chars.
        if let Some(ref hops) = self.relay_chain {
            if hops.is_empty() {
                errors.push("relay_chain must have at least 1 hop".to_string());
            } else {
                for (i, hop) in hops.iter().enumerate() {
                    if !is_hex_str(&hop.pubkey_hex, 64) {
                        errors.push(format!(
                            "relay_chain[{}].pubkey_hex must be exactly 64 hex characters",
                            i
                        ));
                    }
                }
            }
        }

        // 7. cert_pin_fingerprints: each must be exactly 64 hex chars.
        for (i, fp) in self.cert_pin_fingerprints.iter().enumerate() {
            if !is_hex_str(fp, 64) {
                errors.push(format!(
                    "cert_pin_fingerprints[{}] must be exactly 64 hex characters",
                    i
                ));
            }
        }

        // 8. WARN: post_quantum with >3 relay hops may have high latency.
        if self.post_quantum {
            if let Some(ref hops) = self.relay_chain {
                if hops.len() > 3 {
                    errors.push(
                        "WARN: post_quantum with >3 relay hops may have high latency".to_string(),
                    );
                }
            }
        }

        // 9. nat_enabled requires tun_ip.
        if self.nat_enabled && self.tun_ip.is_empty() {
            errors.push("nat_enabled requires tun_ip".to_string());
        }

        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }

    /// Load a config file from `path`, parse it, and validate it.
    ///
    /// Returns the parsed `Config` on success, or an `HvpnError::Config` with
    /// all validation errors joined by newlines on failure.
    pub fn load_and_validate(path: &str) -> Result<Self, HvpnError> {
        let raw = std::fs::read_to_string(path).map_err(|e| HvpnError::Io { source: e })?;
        let cfg: Config =
            toml::from_str(&raw).map_err(|e| HvpnError::Config(e.to_string()))?;
        cfg.validate()
            .map_err(|errors| HvpnError::Config(errors.join("\n")))?;
        Ok(cfg)
    }
}

/// A parsed connection profile decoded from a server connection string.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectionProfile {
    pub server: String,
    pub port: u16,
    /// Hex-encoded Ed25519 server public key (64 hex chars).
    pub pubkey: String,
    pub version: u8,
    /// User-assigned display name (not part of the wire format).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
}

impl ConnectionProfile {
    /// Decode a ConnectionProfile from a base64url connection string.
    pub fn from_connection_string(s: &str) -> Result<Self, HvpnError> {
        use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
        let bytes = URL_SAFE_NO_PAD
            .decode(s.trim())
            .map_err(|e| HvpnError::Config(format!("base64 decode error: {}", e)))?;
        let json_str = std::str::from_utf8(&bytes)
            .map_err(|e| HvpnError::Config(format!("utf8 error: {}", e)))?;
        let profile: ConnectionProfile = serde_json::from_str(json_str)
            .map_err(|e| HvpnError::Config(format!("json parse error: {}", e)))?;
        profile.validate()?;
        Ok(profile)
    }

    /// Encode this ConnectionProfile to a base64url connection string.
    /// The `name` field is excluded from the wire format.
    pub fn to_connection_string(&self) -> String {
        use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
        // Build wire-format object without name.
        let wire = serde_json::json!({
            "server": self.server,
            "port": self.port,
            "pubkey": self.pubkey,
            "version": self.version,
        });
        URL_SAFE_NO_PAD.encode(wire.to_string().as_bytes())
    }

    /// Validate that all fields are well-formed.
    pub fn validate(&self) -> Result<(), HvpnError> {
        if self.server.is_empty() {
            return Err(HvpnError::Config("server must not be empty".to_string()));
        }
        if self.port == 0 {
            return Err(HvpnError::Config("port must not be 0".to_string()));
        }
        if self.pubkey.len() != 64 || !self.pubkey.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(HvpnError::Config(
                "pubkey must be exactly 64 hex characters".to_string(),
            ));
        }
        Ok(())
    }
}

/// Returns the platform-appropriate path for the saved profiles JSON file.
/// Windows: %APPDATA%\HVPN\profiles.json
/// Linux/macOS: ~/.config/hvpn/profiles.json
pub fn profiles_path() -> std::path::PathBuf {
    #[cfg(target_os = "windows")]
    {
        let base = std::env::var("APPDATA")
            .map(std::path::PathBuf::from)
            .unwrap_or_else(|_| std::path::PathBuf::from("."));
        base.join("HVPN").join("profiles.json")
    }
    #[cfg(not(target_os = "windows"))]
    {
        let base = std::env::var("HOME")
            .map(std::path::PathBuf::from)
            .unwrap_or_else(|_| std::path::PathBuf::from("."));
        base.join(".config").join("hvpn").join("profiles.json")
    }
}

/// Load saved profiles from the platform profile path.
/// Returns an empty Vec on any error (file not found, parse error, etc.).
pub fn load_profiles() -> Vec<ConnectionProfile> {
    let path = profiles_path();
    match std::fs::read_to_string(&path) {
        Ok(s) => serde_json::from_str(&s).unwrap_or_default(),
        Err(_) => Vec::new(),
    }
}

/// Save profiles to the platform profile path, creating parent directories.
pub fn save_profiles(profiles: &[ConnectionProfile]) -> Result<(), HvpnError> {
    let path = profiles_path();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| HvpnError::Io { source: e })?;
    }
    let json = serde_json::to_string_pretty(profiles)
        .map_err(|e| HvpnError::Config(format!("json serialize error: {}", e)))?;
    std::fs::write(&path, json).map_err(|e| HvpnError::Io { source: e })?;
    Ok(())
}

// ── Tests ─────────────────────────────────────────────────────────────────────
#[cfg(test)]
mod tests {
    use super::*;

    /// Construct a minimal valid Config for use as a base in tests.
    fn valid_config() -> Config {
        Config {
            server_address: "vpn.example.com".to_string(),
            server_port: 443,
            tls_cert_path: "/etc/hvpn/cert.pem".to_string(),
            obfs_profile: ObfsProfile::Browser,
            relay_chain: None,
            stego_mode: false,
            post_quantum: false,
            nat_enabled: false,
            tun_ip: "10.8.0.1".to_string(),
            tun_netmask: "255.255.255.0".to_string(),
            dns_servers: vec!["1.1.1.1".to_string()],
            cert_pin_fingerprints: vec![],
            use_tls: true,
        }
    }

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

    #[test]
    fn test_config_validate_ok() {
        let cfg = valid_config();
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn test_config_validate_missing_address() {
        let mut cfg = valid_config();
        cfg.server_address = "".to_string();
        let errs = cfg.validate().unwrap_err();
        assert!(errs.iter().any(|e| e.contains("server_address")));
    }

    #[test]
    fn test_config_validate_bad_port() {
        let mut cfg = valid_config();
        cfg.server_port = 0;
        let errs = cfg.validate().unwrap_err();
        assert!(errs.iter().any(|e| e.contains("server_port")));
    }

    #[test]
    fn test_config_validate_bad_relay_pubkey() {
        let mut cfg = valid_config();
        cfg.relay_chain = Some(vec![RelayHopConfig {
            address: "relay1.example.com:1234".to_string(),
            pubkey_hex: "abc".to_string(), // only 3 chars, not 64
        }]);
        let errs = cfg.validate().unwrap_err();
        assert!(errs.iter().any(|e| e.contains("pubkey_hex")));
    }

    #[test]
    fn test_config_validate_collects_all_errors() {
        let cfg = Config {
            server_address: "".to_string(), // error 1
            server_port: 0,                 // error 2
            tls_cert_path: "".to_string(),
            obfs_profile: ObfsProfile::Browser,
            relay_chain: Some(vec![RelayHopConfig {
                address: "relay.example.com:9".to_string(),
                pubkey_hex: "zz".to_string(), // error 3 (invalid hex + wrong length)
            }]),
            stego_mode: false,
            post_quantum: false,
            nat_enabled: false,
            tun_ip: "10.8.0.1".to_string(),
            tun_netmask: "255.255.255.0".to_string(),
            dns_servers: vec![],
            cert_pin_fingerprints: vec![],
            use_tls: true,
        };
        let errs = cfg.validate().unwrap_err();
        assert!(
            errs.len() >= 3,
            "expected at least 3 errors, got: {:?}",
            errs
        );
    }

    #[test]
    fn test_config_validate_bad_tun_ip() {
        let mut cfg = valid_config();
        cfg.tun_ip = "not-an-ip".to_string();
        let errs = cfg.validate().unwrap_err();
        assert!(errs.iter().any(|e| e.contains("tun_ip")));
    }

    #[test]
    fn test_config_validate_bad_dns_server() {
        let mut cfg = valid_config();
        cfg.dns_servers = vec!["not-an-ip".to_string()];
        let errs = cfg.validate().unwrap_err();
        assert!(errs.iter().any(|e| e.contains("dns_servers[0]")));
    }

    #[test]
    fn test_config_validate_bad_cert_pin_fingerprint() {
        let mut cfg = valid_config();
        cfg.cert_pin_fingerprints = vec!["tooshort".to_string()];
        let errs = cfg.validate().unwrap_err();
        assert!(errs.iter().any(|e| e.contains("cert_pin_fingerprints[0]")));
    }

    #[test]
    fn test_config_validate_valid_cert_pin_fingerprint() {
        let mut cfg = valid_config();
        // 64 hex chars = valid SHA-256 fingerprint
        cfg.cert_pin_fingerprints = vec!["a".repeat(64)];
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn test_connection_profile_roundtrip() {
        let profile = ConnectionProfile {
            server: "1.2.3.4".to_string(),
            port: 443,
            pubkey: "a".repeat(64),
            version: 1,
            name: Some("my server".to_string()),
        };
        let s = profile.to_connection_string();
        let decoded = ConnectionProfile::from_connection_string(&s).expect("decode failed");
        assert_eq!(decoded.server, profile.server);
        assert_eq!(decoded.port, profile.port);
        assert_eq!(decoded.pubkey, profile.pubkey);
        assert_eq!(decoded.version, profile.version);
        // name is not part of the wire format
        assert!(decoded.name.is_none());
    }

    #[test]
    fn test_connection_profile_validate_bad_pubkey() {
        let profile = ConnectionProfile {
            server: "1.2.3.4".to_string(),
            port: 443,
            pubkey: "a".repeat(63), // 63 chars, not 64
            version: 1,
            name: None,
        };
        let err = profile.validate().unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("pubkey"), "expected pubkey error, got: {}", msg);
    }

    #[test]
    fn test_profiles_save_load() {
        // Use a temp dir so this test is self-contained.
        let dir = std::env::temp_dir().join("hvpn_test_profiles");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("profiles.json");
        let profiles = vec![
            ConnectionProfile {
                server: "10.0.0.1".to_string(),
                port: 443,
                pubkey: "a".repeat(64),
                version: 1,
                name: Some("server-a".to_string()),
            },
            ConnectionProfile {
                server: "10.0.0.2".to_string(),
                port: 1194,
                pubkey: "b".repeat(64),
                version: 1,
                name: Some("server-b".to_string()),
            },
        ];
        // Write directly to temp path for isolation.
        let json = serde_json::to_string_pretty(&profiles).unwrap();
        std::fs::write(&path, json).unwrap();
        let loaded: Vec<ConnectionProfile> = serde_json::from_str(
            &std::fs::read_to_string(&path).unwrap()
        ).unwrap();
        assert_eq!(loaded.len(), 2);
        assert_eq!(loaded[0].server, "10.0.0.1");
        assert_eq!(loaded[1].server, "10.0.0.2");
        // Cleanup
        let _ = std::fs::remove_file(&path);
    }
}
