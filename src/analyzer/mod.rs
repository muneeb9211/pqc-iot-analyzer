//! PQC readiness scoring engine.
//!
//! Analyzes collections of detected cryptographic primitives and produces
//! a quantitative PQC readiness score (0-100) along with actionable
//! migration recommendations.

use crate::crypto::{self, DetectedPrimitive, PqcReplacement, PqcStatus, PrimitiveCategory};
use crate::protocols::ParsedPacket;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

/// Complete analysis result for a set of packets (a "flow" or capture).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisResult {
    /// Overall PQC readiness score (0 = fully vulnerable, 100 = fully quantum-safe).
    pub score: u32,
    /// Human-readable risk level.
    pub risk_level: RiskLevel,
    /// Total packets analyzed.
    pub packets_analyzed: usize,
    /// All unique detected primitives across the capture.
    pub detected_primitives: Vec<DetectedPrimitive>,
    /// Recommended PQC migrations for each vulnerable primitive.
    pub recommendations: Vec<PqcReplacement>,
    /// Per-category breakdown.
    pub category_scores: Vec<CategoryScore>,
    /// Summary text.
    pub summary: String,
}

/// Risk level derived from the overall score.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RiskLevel {
    /// Score 80-100: deployment is largely quantum-ready.
    Low,
    /// Score 50-79: some quantum-vulnerable components remain.
    Medium,
    /// Score 20-49: significant quantum exposure.
    High,
    /// Score 0-19: almost entirely quantum-vulnerable.
    Critical,
}

impl RiskLevel {
    fn from_score(score: u32) -> Self {
        match score {
            80..=100 => Self::Low,
            50..=79 => Self::Medium,
            20..=49 => Self::High,
            _ => Self::Critical,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Low => "LOW",
            Self::Medium => "MEDIUM",
            Self::High => "HIGH",
            Self::Critical => "CRITICAL",
        }
    }
}

impl std::fmt::Display for RiskLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Score breakdown for one category of cryptographic primitive.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CategoryScore {
    pub category: PrimitiveCategory,
    /// Score for this category alone (0-100).
    pub score: u32,
    /// Number of safe primitives found.
    pub safe_count: usize,
    /// Number of vulnerable primitives found.
    pub vulnerable_count: usize,
    /// Number of unknown-status primitives found.
    pub unknown_count: usize,
}

/// Weights for each category when computing the overall score.
/// Key exchange and signatures are weighted more heavily because
/// they are the components broken by Shor's algorithm.
const WEIGHT_KEY_EXCHANGE: f64 = 30.0;
const WEIGHT_SIGNATURE: f64 = 30.0;
const WEIGHT_SYMMETRIC: f64 = 15.0;
const WEIGHT_HASH: f64 = 10.0;
const WEIGHT_KEM: f64 = 10.0;
const WEIGHT_AEAD: f64 = 5.0;

fn category_weight(cat: PrimitiveCategory) -> f64 {
    match cat {
        PrimitiveCategory::KeyExchange => WEIGHT_KEY_EXCHANGE,
        PrimitiveCategory::Signature => WEIGHT_SIGNATURE,
        PrimitiveCategory::SymmetricCipher => WEIGHT_SYMMETRIC,
        PrimitiveCategory::Hash => WEIGHT_HASH,
        PrimitiveCategory::Kem => WEIGHT_KEM,
        PrimitiveCategory::Aead => WEIGHT_AEAD,
    }
}

/// Analyze a set of parsed packets for PQC readiness.
pub fn analyze(packets: &[ParsedPacket]) -> AnalysisResult {
    // Collect all detected primitives
    let mut all_primitives: HashSet<DetectedPrimitive> = HashSet::new();
    for pkt in packets {
        let detected = crypto::detect(pkt);
        all_primitives.extend(detected);
    }

    if all_primitives.is_empty() {
        return AnalysisResult {
            score: 100,
            risk_level: RiskLevel::Low,
            packets_analyzed: packets.len(),
            detected_primitives: Vec::new(),
            recommendations: Vec::new(),
            category_scores: Vec::new(),
            summary: "No cryptographic primitives detected. If traffic is unencrypted, \
                      PQC readiness is not applicable but the lack of encryption is itself \
                      a critical security concern."
                .into(),
        };
    }

    // Group by category
    let categories = [
        PrimitiveCategory::KeyExchange,
        PrimitiveCategory::Signature,
        PrimitiveCategory::SymmetricCipher,
        PrimitiveCategory::Hash,
        PrimitiveCategory::Kem,
        PrimitiveCategory::Aead,
    ];

    let mut category_scores = Vec::new();
    let mut weighted_score_sum = 0.0;
    let mut weight_sum = 0.0;

    for &cat in &categories {
        let prims: Vec<&DetectedPrimitive> = all_primitives.iter().filter(|p| p.category == cat).collect();
        if prims.is_empty() {
            continue;
        }

        let safe_count = prims.iter().filter(|p| p.pqc_status == PqcStatus::QuantumSafe).count();
        let vuln_count = prims
            .iter()
            .filter(|p| p.pqc_status == PqcStatus::QuantumVulnerable)
            .count();
        let unknown_count = prims.iter().filter(|p| p.pqc_status == PqcStatus::Unknown).count();
        let total = prims.len();

        // Category score: percentage of safe primitives,
        // with unknown counting as half-safe.
        let cat_score = if total > 0 {
            let effective_safe = safe_count as f64 + unknown_count as f64 * 0.5;
            ((effective_safe / total as f64) * 100.0) as u32
        } else {
            100
        };

        let w = category_weight(cat);
        weighted_score_sum += cat_score as f64 * w;
        weight_sum += w;

        category_scores.push(CategoryScore {
            category: cat,
            score: cat_score,
            safe_count,
            vulnerable_count: vuln_count,
            unknown_count,
        });
    }

    let overall_score = if weight_sum > 0.0 {
        (weighted_score_sum / weight_sum).round() as u32
    } else {
        100
    };
    let overall_score = overall_score.min(100);
    let risk_level = RiskLevel::from_score(overall_score);

    // Generate recommendations
    let mut recommendations: Vec<PqcReplacement> = Vec::new();
    let mut seen_algos: HashSet<String> = HashSet::new();
    for prim in &all_primitives {
        if prim.pqc_status == PqcStatus::QuantumVulnerable && !seen_algos.contains(&prim.algorithm) {
            seen_algos.insert(prim.algorithm.clone());
            if let Some(replacement) = crypto::suggest_pqc_replacement(&prim.algorithm) {
                recommendations.push(replacement);
            }
        }
    }

    let vuln_count = all_primitives
        .iter()
        .filter(|p| p.pqc_status == PqcStatus::QuantumVulnerable)
        .count();
    let safe_count = all_primitives
        .iter()
        .filter(|p| p.pqc_status == PqcStatus::QuantumSafe)
        .count();

    let summary = format!(
        "Analyzed {} packet(s). Detected {} unique cryptographic primitive(s): {} quantum-safe, \
         {} quantum-vulnerable, {} unknown. Overall PQC readiness score: {}/100 ({}). \
         {} migration recommendation(s) generated.",
        packets.len(),
        all_primitives.len(),
        safe_count,
        vuln_count,
        all_primitives.len() - safe_count - vuln_count,
        overall_score,
        risk_level,
        recommendations.len()
    );

    let mut primitives_vec: Vec<DetectedPrimitive> = all_primitives.into_iter().collect();
    primitives_vec.sort_by(|a, b| a.algorithm.cmp(&b.algorithm));

    AnalysisResult {
        score: overall_score,
        risk_level,
        packets_analyzed: packets.len(),
        detected_primitives: primitives_vec,
        recommendations,
        category_scores,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocols::{ProtocolType, TlsRecord};

    fn make_packet_with_cipher_suite(cs: u16) -> ParsedPacket {
        ParsedPacket {
            protocol: ProtocolType::CoAP,
            header_summary: "test".into(),
            payload: Vec::new(),
            tls_record: Some(TlsRecord {
                content_type: 22,
                version_major: 0xFE,
                version_minor: 0xFD,
                cipher_suite: Some(cs),
                fragment: Vec::new(),
            }),
            metadata: Vec::new(),
        }
    }

    #[test]
    fn fully_vulnerable_scores_low() {
        // RSA-only cipher suite
        let packets = vec![make_packet_with_cipher_suite(0x002F)];
        let result = analyze(&packets);
        assert!(result.score < 80, "Score {} should be < 80 for RSA-only", result.score);
        assert!(result.recommendations.len() > 0);
    }

    #[test]
    fn tls13_scores_higher() {
        // TLS 1.3 AES-256-GCM (no key exchange info in cipher suite = symmetric only)
        let packets = vec![make_packet_with_cipher_suite(0x1302)];
        let result = analyze(&packets);
        assert!(result.score >= 80, "Score {} should be >= 80 for TLS 1.3 AEAD", result.score);
    }

    #[test]
    fn no_crypto_detected() {
        let packets = vec![ParsedPacket {
            protocol: ProtocolType::MQTT,
            header_summary: "test".into(),
            payload: vec![0x00, 0x01, 0x02],
            tls_record: None,
            metadata: Vec::new(),
        }];
        let result = analyze(&packets);
        assert_eq!(result.score, 100);
        assert!(result.summary.contains("No cryptographic primitives detected"));
    }

    #[test]
    fn mixed_traffic() {
        let packets = vec![
            make_packet_with_cipher_suite(0xC02B), // ECDHE_ECDSA_AES128_GCM (vulnerable KE + sig)
            make_packet_with_cipher_suite(0x1301), // TLS 1.3 AES-128-GCM (safe)
        ];
        let result = analyze(&packets);
        // Should be somewhere in the middle
        assert!(result.score > 0 && result.score < 100);
        assert!(result.recommendations.len() > 0);
    }

    #[test]
    fn category_scores_present() {
        let packets = vec![make_packet_with_cipher_suite(0xC02F)];
        let result = analyze(&packets);
        assert!(result.category_scores.len() > 0);
        let ke = result
            .category_scores
            .iter()
            .find(|c| matches!(c.category, PrimitiveCategory::KeyExchange));
        assert!(ke.is_some());
    }
}
