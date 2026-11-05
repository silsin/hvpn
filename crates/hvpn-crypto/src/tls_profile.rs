// JA3 TLS fingerprint profiles for browser impersonation.
// Uses rustls 0.22.x API.

use rand::Rng;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TlsProfile {
    Chrome123,
    Firefox124,
    Safari17,
    Random,
}

/// Plain data struct describing a TLS fingerprint profile configuration.
#[derive(Debug, Clone)]
pub struct TlsProfileConfig {
    /// Cipher suite preference order (names as strings for downstream use)
    pub cipher_suites: Vec<String>,
    /// ALPN protocols
    pub alpn_protocols: Vec<Vec<u8>>,
    /// Whether to enable session tickets
    pub session_tickets: bool,
}

/// Build a [`TlsProfileConfig`] for the given [`TlsProfile`].
pub fn build_tls_config_raw(profile: TlsProfile) -> TlsProfileConfig {
    const CHROME_ORDER: [&str; 3] = [
        "TLS13_AES_128_GCM_SHA256",
        "TLS13_AES_256_GCM_SHA384",
        "TLS13_CHACHA20_POLY1305_SHA256",
    ];
    const FIREFOX_ORDER: [&str; 3] = [
        "TLS13_AES_128_GCM_SHA256",
        "TLS13_CHACHA20_POLY1305_SHA256",
        "TLS13_AES_256_GCM_SHA384",
    ];
    const SAFARI_ORDER: [&str; 3] = [
        "TLS13_AES_256_GCM_SHA384",
        "TLS13_AES_128_GCM_SHA256",
        "TLS13_CHACHA20_POLY1305_SHA256",
    ];

    let alpn = vec![b"h2".to_vec(), b"http/1.1".to_vec()];

    match profile {
        TlsProfile::Chrome123 => TlsProfileConfig {
            cipher_suites: CHROME_ORDER.iter().map(|s| s.to_string()).collect(),
            alpn_protocols: alpn,
            session_tickets: true,
        },
        TlsProfile::Firefox124 => TlsProfileConfig {
            cipher_suites: FIREFOX_ORDER.iter().map(|s| s.to_string()).collect(),
            alpn_protocols: alpn,
            session_tickets: true,
        },
        TlsProfile::Safari17 => TlsProfileConfig {
            cipher_suites: SAFARI_ORDER.iter().map(|s| s.to_string()).collect(),
            alpn_protocols: alpn,
            session_tickets: false,
        },
        TlsProfile::Random => {
            let mut rng = rand::thread_rng();
            let mut suites: Vec<String> = CHROME_ORDER.iter().map(|s| s.to_string()).collect();
            // Fisher-Yates shuffle
            for i in (1..suites.len()).rev() {
                let j = rng.gen_range(0..=i);
                suites.swap(i, j);
            }
            TlsProfileConfig {
                cipher_suites: suites,
                alpn_protocols: alpn,
                session_tickets: rng.gen(),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_chrome123_cipher_order() {
        let cfg = build_tls_config_raw(TlsProfile::Chrome123);
        assert_eq!(cfg.cipher_suites[0], "TLS13_AES_128_GCM_SHA256");
    }

    #[test]
    fn test_random_has_all_suites() {
        let expected: std::collections::HashSet<&str> = [
            "TLS13_AES_128_GCM_SHA256",
            "TLS13_AES_256_GCM_SHA384",
            "TLS13_CHACHA20_POLY1305_SHA256",
        ]
        .iter()
        .copied()
        .collect();

        for _ in 0..10 {
            let cfg = build_tls_config_raw(TlsProfile::Random);
            assert_eq!(cfg.cipher_suites.len(), 3, "random profile must have 3 cipher suites");
            let got: std::collections::HashSet<&str> =
                cfg.cipher_suites.iter().map(|s| s.as_str()).collect();
            assert_eq!(got, expected, "random profile must contain all 3 expected suites");
        }
    }
}
