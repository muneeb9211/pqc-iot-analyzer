//! # PQC-Ready IoT Protocol Analyzer
//!
//! A library for analyzing IoT network protocol traffic and assessing
//! post-quantum cryptographic (PQC) readiness. Supports CoAP, MQTT, and RPL
//! protocol parsing with automatic detection of cryptographic primitives and
//! NIST PQC migration recommendations.
//!
//! ## Architecture
//!
//! - **`protocols`** -- Packet parsers for CoAP (RFC 7252), MQTT (v3.1.1/5.0),
//!   and RPL (RFC 6550) that extract headers, payloads, and TLS/DTLS records.
//! - **`crypto`** -- Cryptographic primitive detection engine using TLS cipher
//!   suites, ASN.1 OIDs, RPL security options, and payload heuristics.
//! - **`analyzer`** -- PQC readiness scoring engine with weighted category
//!   scoring and migration recommendation generation.
//! - **`report`** -- JSON and human-readable report formatters.
//!
//! ## Example
//!
//! ```rust
//! use pqc_iot_analyzer::protocols;
//! use pqc_iot_analyzer::analyzer;
//! use pqc_iot_analyzer::report::{self, ReportFormat};
//!
//! // Parse a CoAP packet (version 1, CON, GET, MsgID=1)
//! let raw = vec![0x40, 0x01, 0x00, 0x01];
//! let packet = protocols::auto_parse(&raw).unwrap();
//! let result = analyzer::analyze(&[packet]);
//! let text = report::generate(&result, ReportFormat::Text);
//! println!("{}", text);
//! ```

pub mod analyzer;
pub mod crypto;
pub mod protocols;
pub mod report;

use thiserror::Error;

/// Top-level error type for the PQC IoT Analyzer.
#[derive(Debug, Error)]
pub enum PqcError {
    #[error("protocol parse error: {0}")]
    Parse(String),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("invalid sample data: {0}")]
    SampleData(String),
}

/// Load sample packet data from a file.
///
/// The file format is line-oriented hex:
/// - Lines starting with `#` are comments.
/// - Blank lines are ignored.
/// - Each non-comment line is hex-decoded into a packet.
pub fn load_sample_file(path: &std::path::Path) -> Result<Vec<Vec<u8>>, PqcError> {
    let content = std::fs::read_to_string(path)?;
    load_sample_data(&content)
}

/// Parse sample data from a string (hex-encoded packets, one per line).
pub fn load_sample_data(content: &str) -> Result<Vec<Vec<u8>>, PqcError> {
    let mut packets = Vec::new();
    for (line_num, line) in content.lines().enumerate() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        // Strip all whitespace within the hex string (allows "AABB CCDD" formatting)
        let clean: String = trimmed.chars().filter(|c| !c.is_whitespace()).collect();
        let bytes = hex::decode(&clean).map_err(|e| {
            PqcError::SampleData(format!("line {}: invalid hex: {}", line_num + 1, e))
        })?;
        packets.push(bytes);
    }
    Ok(packets)
}
