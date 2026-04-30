//! Cryptographic primitive detection engine.
//!
//! Inspects protocol payloads and TLS/DTLS handshake records to identify
//! which cryptographic algorithms are in use. Detected primitives are
//! classified for post-quantum vulnerability assessment.

use crate::protocols::{ParsedPacket, TlsRecord};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::fmt;

/// A cryptographic primitive detected in traffic.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct DetectedPrimitive {
    /// Algorithm name (e.g., "RSA-2048", "ECDHE-P256", "AES-128-GCM").
    pub algorithm: String,
    /// Category of the primitive.
    pub category: PrimitiveCategory,
    /// How the primitive was detected.
    pub source: DetectionSource,
    /// Post-quantum safety classification.
    pub pqc_status: PqcStatus,
}

/// Broad category of a cryptographic primitive.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum PrimitiveCategory {
    /// Key exchange (DH, ECDH, etc.)
    KeyExchange,
    /// Digital signature (RSA, ECDSA, EdDSA, etc.)
    Signature,
    /// Symmetric cipher (AES, ChaCha20, etc.)
    SymmetricCipher,
    /// Hash function (SHA-256, SHA-3, etc.)
    Hash,
    /// Key encapsulation mechanism
    Kem,
    /// Authenticated encryption (AES-GCM, AES-CCM, etc.)
    Aead,
}

impl fmt::Display for PrimitiveCategory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::KeyExchange => write!(f, "Key Exchange"),
            Self::Signature => write!(f, "Digital Signature"),
            Self::SymmetricCipher => write!(f, "Symmetric Cipher"),
            Self::Hash => write!(f, "Hash Function"),
            Self::Kem => write!(f, "Key Encapsulation"),
            Self::Aead => write!(f, "AEAD"),
        }
    }
}

/// Post-quantum safety classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum PqcStatus {
    /// Safe against known quantum attacks (e.g., AES-256, SHA-3, ML-KEM).
    QuantumSafe,
    /// Broken by Shor's or Grover's algorithm with practical advantage.
    QuantumVulnerable,
    /// Insufficient information to classify, or algorithm is not well-studied.
    Unknown,
}

impl fmt::Display for PqcStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::QuantumSafe => write!(f, "Quantum-Safe"),
            Self::QuantumVulnerable => write!(f, "QUANTUM-VULNERABLE"),
            Self::Unknown => write!(f, "Unknown"),
        }
    }
}

/// How a primitive was discovered.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum DetectionSource {
    /// From a TLS/DTLS cipher suite identifier.
    CipherSuite(u16),
    /// From an RPL Security section algorithm field.
    RplSecurityOption,
    /// From payload byte-pattern heuristic.
    PayloadHeuristic,
    /// From protocol metadata (e.g., MQTT CONNECT properties).
    ProtocolMetadata,
}

impl fmt::Display for DetectionSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CipherSuite(cs) => write!(f, "TLS CipherSuite 0x{:04X}", cs),
            Self::RplSecurityOption => write!(f, "RPL Security Option"),
            Self::PayloadHeuristic => write!(f, "Payload Heuristic"),
            Self::ProtocolMetadata => write!(f, "Protocol Metadata"),
        }
    }
}

/// Run cryptographic detection on a parsed packet.
/// Returns a set of all detected primitives.
pub fn detect(packet: &ParsedPacket) -> HashSet<DetectedPrimitive> {
    let mut primitives = HashSet::new();

    // 1. Analyze TLS/DTLS cipher suite
    if let Some(ref tls) = packet.tls_record {
        detect_from_cipher_suite(tls, &mut primitives);
    }

    // 2. Check RPL security section metadata
    detect_from_rpl_security(&packet.metadata, &mut primitives);

    // 3. Payload heuristic scan
    detect_from_payload(&packet.payload, &mut primitives);

    // 4. Protocol metadata scan
    detect_from_metadata(&packet.metadata, &mut primitives);

    primitives
}

/// Map a TLS/DTLS cipher suite to its constituent primitives.
fn detect_from_cipher_suite(tls: &TlsRecord, out: &mut HashSet<DetectedPrimitive>) {
    if let Some(cs) = tls.cipher_suite {
        let source = DetectionSource::CipherSuite(cs);
        let components = cipher_suite_components(cs);
        for (algo, cat, status) in components {
            out.insert(DetectedPrimitive {
                algorithm: algo,
                category: cat,
                source: source.clone(),
                pqc_status: status,
            });
        }
    }
}

/// Return (algorithm_name, category, pqc_status) for known cipher suites.
fn cipher_suite_components(cs: u16) -> Vec<(String, PrimitiveCategory, PqcStatus)> {
    match cs {
        // TLS_RSA_WITH_AES_128_CBC_SHA
        0x002F => vec![
            ("RSA".into(), PrimitiveCategory::KeyExchange, PqcStatus::QuantumVulnerable),
            ("RSA".into(), PrimitiveCategory::Signature, PqcStatus::QuantumVulnerable),
            ("AES-128-CBC".into(), PrimitiveCategory::SymmetricCipher, PqcStatus::QuantumSafe),
            ("SHA-1".into(), PrimitiveCategory::Hash, PqcStatus::QuantumSafe),
        ],
        // TLS_RSA_WITH_AES_256_CBC_SHA
        0x0035 => vec![
            ("RSA".into(), PrimitiveCategory::KeyExchange, PqcStatus::QuantumVulnerable),
            ("RSA".into(), PrimitiveCategory::Signature, PqcStatus::QuantumVulnerable),
            ("AES-256-CBC".into(), PrimitiveCategory::SymmetricCipher, PqcStatus::QuantumSafe),
            ("SHA-1".into(), PrimitiveCategory::Hash, PqcStatus::QuantumSafe),
        ],
        // TLS_RSA_WITH_AES_128_GCM_SHA256
        0x009C => vec![
            ("RSA".into(), PrimitiveCategory::KeyExchange, PqcStatus::QuantumVulnerable),
            ("RSA".into(), PrimitiveCategory::Signature, PqcStatus::QuantumVulnerable),
            ("AES-128-GCM".into(), PrimitiveCategory::Aead, PqcStatus::QuantumSafe),
            ("SHA-256".into(), PrimitiveCategory::Hash, PqcStatus::QuantumSafe),
        ],
        // TLS_RSA_WITH_AES_256_GCM_SHA384
        0x009D => vec![
            ("RSA".into(), PrimitiveCategory::KeyExchange, PqcStatus::QuantumVulnerable),
            ("RSA".into(), PrimitiveCategory::Signature, PqcStatus::QuantumVulnerable),
            ("AES-256-GCM".into(), PrimitiveCategory::Aead, PqcStatus::QuantumSafe),
            ("SHA-384".into(), PrimitiveCategory::Hash, PqcStatus::QuantumSafe),
        ],
        // TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
        0xC02F => vec![
            ("ECDHE".into(), PrimitiveCategory::KeyExchange, PqcStatus::QuantumVulnerable),
            ("RSA".into(), PrimitiveCategory::Signature, PqcStatus::QuantumVulnerable),
            ("AES-128-GCM".into(), PrimitiveCategory::Aead, PqcStatus::QuantumSafe),
            ("SHA-256".into(), PrimitiveCategory::Hash, PqcStatus::QuantumSafe),
        ],
        // TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
        0xC030 => vec![
            ("ECDHE".into(), PrimitiveCategory::KeyExchange, PqcStatus::QuantumVulnerable),
            ("RSA".into(), PrimitiveCategory::Signature, PqcStatus::QuantumVulnerable),
            ("AES-256-GCM".into(), PrimitiveCategory::Aead, PqcStatus::QuantumSafe),
            ("SHA-384".into(), PrimitiveCategory::Hash, PqcStatus::QuantumSafe),
        ],
        // TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
        0xC02B => vec![
            ("ECDHE".into(), PrimitiveCategory::KeyExchange, PqcStatus::QuantumVulnerable),
            ("ECDSA".into(), PrimitiveCategory::Signature, PqcStatus::QuantumVulnerable),
            ("AES-128-GCM".into(), PrimitiveCategory::Aead, PqcStatus::QuantumSafe),
            ("SHA-256".into(), PrimitiveCategory::Hash, PqcStatus::QuantumSafe),
        ],
        // TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
        0xC02C => vec![
            ("ECDHE".into(), PrimitiveCategory::KeyExchange, PqcStatus::QuantumVulnerable),
            ("ECDSA".into(), PrimitiveCategory::Signature, PqcStatus::QuantumVulnerable),
            ("AES-256-GCM".into(), PrimitiveCategory::Aead, PqcStatus::QuantumSafe),
            ("SHA-384".into(), PrimitiveCategory::Hash, PqcStatus::QuantumSafe),
        ],
        // TLS_AES_128_GCM_SHA256 (TLS 1.3)
        0x1301 => vec![
            ("AES-128-GCM".into(), PrimitiveCategory::Aead, PqcStatus::QuantumSafe),
            ("SHA-256".into(), PrimitiveCategory::Hash, PqcStatus::QuantumSafe),
        ],
        // TLS_AES_256_GCM_SHA384 (TLS 1.3)
        0x1302 => vec![
            ("AES-256-GCM".into(), PrimitiveCategory::Aead, PqcStatus::QuantumSafe),
            ("SHA-384".into(), PrimitiveCategory::Hash, PqcStatus::QuantumSafe),
        ],
        // TLS_CHACHA20_POLY1305_SHA256 (TLS 1.3)
        0x1303 => vec![
            ("ChaCha20-Poly1305".into(), PrimitiveCategory::Aead, PqcStatus::QuantumSafe),
            ("SHA-256".into(), PrimitiveCategory::Hash, PqcStatus::QuantumSafe),
        ],
        // TLS_PSK_WITH_AES_128_CCM (IoT-common)
        0xC0A4 => vec![
            ("PSK".into(), PrimitiveCategory::KeyExchange, PqcStatus::QuantumSafe),
            ("AES-128-CCM".into(), PrimitiveCategory::Aead, PqcStatus::QuantumSafe),
        ],
        // TLS_PSK_WITH_AES_256_CCM
        0xC0A5 => vec![
            ("PSK".into(), PrimitiveCategory::KeyExchange, PqcStatus::QuantumSafe),
            ("AES-256-CCM".into(), PrimitiveCategory::Aead, PqcStatus::QuantumSafe),
        ],
        // Unknown suite
        _ => vec![("Unknown-CipherSuite".into(), PrimitiveCategory::SymmetricCipher, PqcStatus::Unknown)],
    }
}

/// Detect crypto from RPL security metadata.
fn detect_from_rpl_security(metadata: &[(String, String)], out: &mut HashSet<DetectedPrimitive>) {
    for (key, value) in metadata {
        if key == "security_algorithm" {
            let (algo, cat, status) = match value.as_str() {
                "CCM-AES-128" => (
                    "AES-128-CCM".to_string(),
                    PrimitiveCategory::Aead,
                    PqcStatus::QuantumSafe,
                ),
                "RSA-SHA256" => (
                    "RSA-SHA256".to_string(),
                    PrimitiveCategory::Signature,
                    PqcStatus::QuantumVulnerable,
                ),
                "ECDSA-P256" => (
                    "ECDSA-P256".to_string(),
                    PrimitiveCategory::Signature,
                    PqcStatus::QuantumVulnerable,
                ),
                other => (other.to_string(), PrimitiveCategory::SymmetricCipher, PqcStatus::Unknown),
            };
            out.insert(DetectedPrimitive {
                algorithm: algo,
                category: cat,
                source: DetectionSource::RplSecurityOption,
                pqc_status: status,
            });
        }
    }
}

/// Heuristic scan of payload bytes for known cryptographic markers.
fn detect_from_payload(payload: &[u8], out: &mut HashSet<DetectedPrimitive>) {
    let payload_hex = hex::encode(payload);
    let payload_str = String::from_utf8_lossy(payload);

    // OID-based detection (DER-encoded OIDs found in certificates / handshakes)
    let oid_patterns: &[(&str, &str, PrimitiveCategory, PqcStatus)] = &[
        // RSA encryption OID: 1.2.840.113549.1.1.1
        ("2a864886f70d010101", "RSA", PrimitiveCategory::Signature, PqcStatus::QuantumVulnerable),
        // RSA-SHA256 OID: 1.2.840.113549.1.1.11
        ("2a864886f70d01010b", "RSA-SHA256", PrimitiveCategory::Signature, PqcStatus::QuantumVulnerable),
        // ECDSA-SHA256 OID: 1.2.840.10045.4.3.2
        ("2a8648ce3d040302", "ECDSA-SHA256", PrimitiveCategory::Signature, PqcStatus::QuantumVulnerable),
        // EC public key OID: 1.2.840.10045.2.1
        ("2a8648ce3d0201", "ECDH", PrimitiveCategory::KeyExchange, PqcStatus::QuantumVulnerable),
        // P-256 curve OID: 1.2.840.10045.3.1.7
        ("2a8648ce3d030107", "ECDH-P256", PrimitiveCategory::KeyExchange, PqcStatus::QuantumVulnerable),
        // AES-128-CBC OID: 2.16.840.1.101.3.4.1.2
        ("608648016503040102", "AES-128-CBC", PrimitiveCategory::SymmetricCipher, PqcStatus::QuantumSafe),
        // AES-256-CBC OID: 2.16.840.1.101.3.4.1.42
        ("6086480165030401", "AES-256-CBC", PrimitiveCategory::SymmetricCipher, PqcStatus::QuantumSafe),
        // SHA-256 OID: 2.16.840.1.101.3.4.2.1
        ("608648016503040201", "SHA-256", PrimitiveCategory::Hash, PqcStatus::QuantumSafe),
        // SHA-384 OID: 2.16.840.1.101.3.4.2.2
        ("608648016503040202", "SHA-384", PrimitiveCategory::Hash, PqcStatus::QuantumSafe),
        // SHA-512 OID: 2.16.840.1.101.3.4.2.3
        ("608648016503040203", "SHA-512", PrimitiveCategory::Hash, PqcStatus::QuantumSafe),
        // Ed25519 OID: 1.3.101.112
        ("2b6570", "Ed25519", PrimitiveCategory::Signature, PqcStatus::QuantumVulnerable),
        // X25519 OID: 1.3.101.110
        ("2b656e", "X25519", PrimitiveCategory::KeyExchange, PqcStatus::QuantumVulnerable),
    ];

    for (hex_oid, algo, cat, status) in oid_patterns {
        if payload_hex.contains(hex_oid) {
            out.insert(DetectedPrimitive {
                algorithm: algo.to_string(),
                category: *cat,
                source: DetectionSource::PayloadHeuristic,
                pqc_status: *status,
            });
        }
    }

    // Text-based detection (algorithm names in protocol payloads)
    let text_patterns: &[(&str, &str, PrimitiveCategory, PqcStatus)] = &[
        ("rsa", "RSA", PrimitiveCategory::Signature, PqcStatus::QuantumVulnerable),
        ("ecdsa", "ECDSA", PrimitiveCategory::Signature, PqcStatus::QuantumVulnerable),
        ("ecdh", "ECDH", PrimitiveCategory::KeyExchange, PqcStatus::QuantumVulnerable),
        ("aes-128", "AES-128", PrimitiveCategory::SymmetricCipher, PqcStatus::QuantumSafe),
        ("aes-256", "AES-256", PrimitiveCategory::SymmetricCipher, PqcStatus::QuantumSafe),
        ("sha-256", "SHA-256", PrimitiveCategory::Hash, PqcStatus::QuantumSafe),
        ("sha-384", "SHA-384", PrimitiveCategory::Hash, PqcStatus::QuantumSafe),
        ("chacha20", "ChaCha20", PrimitiveCategory::SymmetricCipher, PqcStatus::QuantumSafe),
        ("ml-kem", "ML-KEM", PrimitiveCategory::Kem, PqcStatus::QuantumSafe),
        ("ml-dsa", "ML-DSA", PrimitiveCategory::Signature, PqcStatus::QuantumSafe),
        ("kyber", "ML-KEM/Kyber", PrimitiveCategory::Kem, PqcStatus::QuantumSafe),
        ("dilithium", "ML-DSA/Dilithium", PrimitiveCategory::Signature, PqcStatus::QuantumSafe),
    ];

    let lower = payload_str.to_lowercase();
    for (pattern, algo, cat, status) in text_patterns {
        if lower.contains(pattern) {
            out.insert(DetectedPrimitive {
                algorithm: algo.to_string(),
                category: *cat,
                source: DetectionSource::PayloadHeuristic,
                pqc_status: *status,
            });
        }
    }
}

/// Detect from protocol-level metadata fields.
fn detect_from_metadata(metadata: &[(String, String)], out: &mut HashSet<DetectedPrimitive>) {
    for (key, value) in metadata {
        if key == "content_format" {
            // CoAP content format 61 = application/cbor-cose (COSE signed/encrypted)
            if value == "61" || value == "96" || value == "98" {
                out.insert(DetectedPrimitive {
                    algorithm: "COSE-Crypto".into(),
                    category: PrimitiveCategory::Signature,
                    source: DetectionSource::ProtocolMetadata,
                    pqc_status: PqcStatus::Unknown,
                });
            }
        }
    }
}

/// Suggest a post-quantum replacement for a given classical algorithm.
pub fn suggest_pqc_replacement(algorithm: &str) -> Option<PqcReplacement> {
    let algo_lower = algorithm.to_lowercase();
    if algo_lower.contains("rsa") && !algo_lower.contains("ml-") {
        if algo_lower.contains("sha") || algo_lower.contains("sign") || algo_lower.contains("pss") {
            return Some(PqcReplacement {
                classical: algorithm.to_string(),
                quantum_safe: "ML-DSA-65 (FIPS 204)".into(),
                nist_standard: "FIPS 204".into(),
                category: PrimitiveCategory::Signature,
                notes: "ML-DSA (Dilithium) provides comparable security to RSA-3072+ signatures with smaller signature sizes for security level 3.".into(),
            });
        }
        return Some(PqcReplacement {
            classical: algorithm.to_string(),
            quantum_safe: "ML-KEM-768 (FIPS 203)".into(),
            nist_standard: "FIPS 203".into(),
            category: PrimitiveCategory::Kem,
            notes: "ML-KEM (Kyber) replaces RSA key transport with IND-CCA2 secure key encapsulation.".into(),
        });
    }

    if algo_lower.contains("ecdsa") || algo_lower == "ed25519" {
        return Some(PqcReplacement {
            classical: algorithm.to_string(),
            quantum_safe: "ML-DSA-44 (FIPS 204)".into(),
            nist_standard: "FIPS 204".into(),
            category: PrimitiveCategory::Signature,
            notes: "ML-DSA replaces ECDSA/EdDSA; ML-DSA-44 targets NIST Level 2, comparable to P-256.".into(),
        });
    }

    if algo_lower.contains("ecdh") || algo_lower.contains("x25519") || algo_lower.contains("ecdhe") {
        return Some(PqcReplacement {
            classical: algorithm.to_string(),
            quantum_safe: "ML-KEM-768 (FIPS 203)".into(),
            nist_standard: "FIPS 203".into(),
            category: PrimitiveCategory::Kem,
            notes: "ML-KEM replaces ECDH key agreement. Hybrid X25519+ML-KEM-768 recommended during transition (RFC 9370).".into(),
        });
    }

    if algo_lower.contains("dh") && !algo_lower.contains("ecdh") {
        return Some(PqcReplacement {
            classical: algorithm.to_string(),
            quantum_safe: "ML-KEM-1024 (FIPS 203)".into(),
            nist_standard: "FIPS 203".into(),
            category: PrimitiveCategory::Kem,
            notes: "ML-KEM-1024 provides NIST Level 5 security, replacing classical DH groups.".into(),
        });
    }

    // Symmetric / hash algorithms are already quantum-safe at sufficient key sizes
    None
}

/// Describes a recommended PQC migration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PqcReplacement {
    pub classical: String,
    pub quantum_safe: String,
    pub nist_standard: String,
    pub category: PrimitiveCategory,
    pub notes: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocols::ProtocolType;

    #[test]
    fn detect_from_tls_cipher_suite() {
        let packet = ParsedPacket {
            protocol: ProtocolType::CoAP,
            header_summary: String::new(),
            payload: Vec::new(),
            tls_record: Some(TlsRecord {
                content_type: 22,
                version_major: 0xFE,
                version_minor: 0xFD,
                cipher_suite: Some(0xC02F), // ECDHE_RSA_WITH_AES_128_GCM_SHA256
                fragment: Vec::new(),
            }),
            metadata: Vec::new(),
        };
        let detected = detect(&packet);
        let algos: Vec<&str> = detected.iter().map(|p| p.algorithm.as_str()).collect();
        assert!(algos.contains(&"ECDHE"));
        assert!(algos.contains(&"RSA"));
        assert!(algos.contains(&"AES-128-GCM"));
        // Verify ECDHE is quantum-vulnerable
        let ecdhe = detected.iter().find(|p| p.algorithm == "ECDHE").unwrap();
        assert_eq!(ecdhe.pqc_status, PqcStatus::QuantumVulnerable);
    }

    #[test]
    fn detect_from_rpl_security() {
        let packet = ParsedPacket {
            protocol: ProtocolType::RPL,
            header_summary: String::new(),
            payload: Vec::new(),
            tls_record: None,
            metadata: vec![("security_algorithm".into(), "ECDSA-P256".into())],
        };
        let detected = detect(&packet);
        let has_ecdsa = detected.iter().any(|p| p.algorithm == "ECDSA-P256");
        assert!(has_ecdsa);
    }

    #[test]
    fn detect_from_payload_oid() {
        // Embed RSA OID in payload
        let rsa_oid = hex::decode("2a864886f70d010101").unwrap();
        let packet = ParsedPacket {
            protocol: ProtocolType::MQTT,
            header_summary: String::new(),
            payload: rsa_oid,
            tls_record: None,
            metadata: Vec::new(),
        };
        let detected = detect(&packet);
        let has_rsa = detected.iter().any(|p| p.algorithm == "RSA");
        assert!(has_rsa);
    }

    #[test]
    fn pqc_replacement_rsa() {
        let r = suggest_pqc_replacement("RSA-2048").unwrap();
        assert!(r.quantum_safe.contains("ML-KEM"));
    }

    #[test]
    fn pqc_replacement_ecdsa() {
        let r = suggest_pqc_replacement("ECDSA-P256").unwrap();
        assert!(r.quantum_safe.contains("ML-DSA"));
    }

    #[test]
    fn no_replacement_for_aes() {
        assert!(suggest_pqc_replacement("AES-256-GCM").is_none());
    }
}
