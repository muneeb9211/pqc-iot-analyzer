//! Integration tests for the full PQC IoT analysis pipeline.

use pqc_iot_analyzer::analyzer;
use pqc_iot_analyzer::crypto::{self, PqcStatus};
use pqc_iot_analyzer::protocols::{self, ParsedPacket, ProtocolType, TlsRecord};
use pqc_iot_analyzer::report::{self, ReportFormat};

/// Helper: parse hex lines (ignoring comments/blanks) and run through full pipeline.
fn analyze_hex_data(hex_lines: &str) -> analyzer::AnalysisResult {
    let raw_packets = pqc_iot_analyzer::load_sample_data(hex_lines).unwrap();
    let mut parsed = Vec::new();
    for raw in &raw_packets {
        if let Ok(pkt) = protocols::auto_parse(raw) {
            parsed.push(pkt);
        }
    }
    analyzer::analyze(&parsed)
}

/// Helper: create a fake parsed packet with a known cipher suite for testing crypto detection.
fn make_dtls_packet(cipher_suite: u16) -> ParsedPacket {
    ParsedPacket {
        protocol: ProtocolType::CoAP,
        header_summary: "CoAP with DTLS".into(),
        payload: Vec::new(),
        tls_record: Some(TlsRecord {
            content_type: 22,
            version_major: 0xFE,
            version_minor: 0xFD,
            cipher_suite: Some(cipher_suite),
            fragment: Vec::new(),
        }),
        metadata: Vec::new(),
    }
}

/// Helper: create a fake RPL packet with a security algorithm metadata entry.
fn make_rpl_security_packet(algo: &str) -> ParsedPacket {
    ParsedPacket {
        protocol: ProtocolType::RPL,
        header_summary: "RPL Secure DIO".into(),
        payload: Vec::new(),
        tls_record: None,
        metadata: vec![("security_algorithm".into(), algo.into())],
    }
}

#[test]
fn full_pipeline_coap_plaintext() {
    let result = analyze_hex_data("# CoAP GET plaintext\n4201000100AABB\n");
    assert_eq!(result.score, 100);
    assert_eq!(result.detected_primitives.len(), 0);
}

#[test]
fn full_pipeline_coap_dtls_ecdhe() {
    // Test via constructed packet (DTLS extraction from raw hex is fragile)
    let pkt = make_dtls_packet(0xC02B); // TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
    let result = analyzer::analyze(&[pkt]);
    assert!(result.detected_primitives.len() >= 3, "Expected >= 3 primitives, got {}", result.detected_primitives.len());
    let vuln: Vec<_> = result
        .detected_primitives
        .iter()
        .filter(|p| p.pqc_status == PqcStatus::QuantumVulnerable)
        .collect();
    assert!(vuln.len() >= 2, "Expected >= 2 vulnerable, got {}", vuln.len());
    assert!(!result.recommendations.is_empty());
    assert!(result.score < 80, "Score {} should be < 80", result.score);
}

#[test]
fn full_pipeline_mqtt_connect() {
    let hex = "# MQTT CONNECT\n101600044D5154540402003800087365 6E736F72 3031\n";
    let result = analyze_hex_data(hex);
    assert_eq!(result.packets_analyzed, 1);
}

#[test]
fn full_pipeline_rpl_secure_ecdsa() {
    let pkt = make_rpl_security_packet("ECDSA-P256");
    let result = analyzer::analyze(&[pkt]);
    let has_ecdsa = result.detected_primitives.iter().any(|p| p.algorithm.contains("ECDSA"));
    assert!(has_ecdsa, "Should detect ECDSA-P256");
    assert!(result.score < 100);
}

#[test]
fn full_pipeline_rpl_secure_aes_ccm() {
    let pkt = make_rpl_security_packet("CCM-AES-128");
    let result = analyzer::analyze(&[pkt]);
    let has_aes = result.detected_primitives.iter().any(|p| p.algorithm.contains("AES"));
    assert!(has_aes, "Should detect AES-128-CCM");
    assert!(result.score >= 80);
}

#[test]
fn json_report_roundtrip() {
    let pkt = make_dtls_packet(0xC02B);
    let result = analyzer::analyze(&[pkt]);
    let json_str = report::generate(&result, ReportFormat::Json);
    let parsed: serde_json::Value = serde_json::from_str(&json_str).unwrap();
    assert_eq!(parsed["packets_analyzed"], 1);
    assert!(parsed["score"].as_u64().unwrap() < 80);
    assert!(parsed["detected_primitives"].as_array().unwrap().len() >= 3);
}

#[test]
fn text_report_formatting() {
    let pkt = make_dtls_packet(0xC02B);
    let result = analyzer::analyze(&[pkt]);
    let text = report::generate(&result, ReportFormat::Text);
    assert!(text.contains("PQC Readiness Score"), "Missing score header");
    assert!(text.contains("QUANTUM-VULNERABLE") || text.contains("[VULN]") || text.contains("Vulnerable"), "Missing vulnerability marker in:\n{}", text);
    assert!(text.contains("ML-KEM") || text.contains("ML-DSA"), "Missing PQC recommendation");
}

#[test]
fn auto_detect_protocol_type() {
    // CoAP: first byte 0x40-0x7F (version 1, high nibble 0x4)
    let coap = protocols::auto_parse(&[0x40, 0x01, 0x00, 0x01]).unwrap();
    assert_eq!(coap.protocol, ProtocolType::CoAP);

    // RPL: first byte 0x9B (ICMPv6 type 155)
    let rpl = protocols::auto_parse(&[0x9B, 0x00, 0x12, 0x34]).unwrap();
    assert_eq!(rpl.protocol, ProtocolType::RPL);
}

#[test]
fn pqc_replacement_suggestions() {
    let rsa_rep = crypto::suggest_pqc_replacement("RSA-2048").unwrap();
    assert!(rsa_rep.quantum_safe.contains("ML-KEM"));

    let ecdsa_rep = crypto::suggest_pqc_replacement("ECDSA-P256").unwrap();
    assert!(ecdsa_rep.quantum_safe.contains("ML-DSA"));

    let ecdh_rep = crypto::suggest_pqc_replacement("ECDH-P256").unwrap();
    assert!(ecdh_rep.quantum_safe.contains("ML-KEM"));

    assert!(crypto::suggest_pqc_replacement("AES-256-GCM").is_none());
}

#[test]
fn mixed_traffic_analysis() {
    // Mix of plaintext CoAP + RPL with ECDSA + CoAP with DTLS ECDHE
    // Minimal CoAP GET, CON, TKL=0, no options, no payload
    let coap_pkt = protocols::auto_parse(&[0x40, 0x01, 0x00, 0x01]).unwrap();
    let rpl_pkt = make_rpl_security_packet("ECDSA-P256");
    let dtls_pkt = make_dtls_packet(0xC02B);

    let result = analyzer::analyze(&[coap_pkt, rpl_pkt, dtls_pkt]);
    assert_eq!(result.packets_analyzed, 3);

    let safe = result.detected_primitives.iter().filter(|p| p.pqc_status == PqcStatus::QuantumSafe).count();
    let vuln = result.detected_primitives.iter().filter(|p| p.pqc_status == PqcStatus::QuantumVulnerable).count();
    assert!(safe > 0, "Expected some safe primitives");
    assert!(vuln > 0, "Expected some vulnerable primitives");
}

#[test]
fn load_sample_data_handles_comments_and_blanks() {
    let input = "# This is a comment\n\n  # Another comment\n  4201000100AABB  \n\n";
    let packets = pqc_iot_analyzer::load_sample_data(input).unwrap();
    assert_eq!(packets.len(), 1);
}

#[test]
fn load_sample_data_rejects_invalid_hex() {
    let input = "ZZZZ";
    let result = pqc_iot_analyzer::load_sample_data(input);
    assert!(result.is_err());
}
