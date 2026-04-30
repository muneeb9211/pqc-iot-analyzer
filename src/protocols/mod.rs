pub mod coap;
pub mod mqtt;
pub mod rpl;

use serde::{Deserialize, Serialize};
use std::fmt;

/// IoT protocol discriminant.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ProtocolType {
    CoAP,
    MQTT,
    RPL,
}

impl fmt::Display for ProtocolType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ProtocolType::CoAP => write!(f, "CoAP"),
            ProtocolType::MQTT => write!(f, "MQTT"),
            ProtocolType::RPL => write!(f, "RPL"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParsedPacket {
    pub protocol: ProtocolType,
    pub header_summary: String,
    #[serde(with = "hex::serde")]
    pub payload: Vec<u8>,
    pub tls_record: Option<TlsRecord>,
    pub metadata: Vec<(String, String)>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsRecord {
    pub content_type: u8,
    pub version_major: u8,
    pub version_minor: u8,
    pub cipher_suite: Option<u16>,
    #[serde(with = "hex::serde")]
    pub fragment: Vec<u8>,
}

/// Auto-detect protocol and parse. Discriminates on first byte, falls back to
/// trying each parser in sequence.
pub fn auto_parse(data: &[u8]) -> Result<ParsedPacket, crate::PqcError> {
    if data.is_empty() {
        return Err(crate::PqcError::Parse("empty packet data".into()));
    }
    let first = data[0];
    if (first & 0xC0) == 0x40 {
        return coap::parse(data);
    }
    if first == 0x9B || first == 0x9C || first == 0x9D {
        return rpl::parse(data);
    }
    if (first >> 4) >= 1 && (first >> 4) <= 14 && mqtt::looks_like_mqtt(data) {
        return mqtt::parse(data);
    }
    coap::parse(data)
        .or_else(|_| mqtt::parse(data))
        .or_else(|_| rpl::parse(data))
        .map_err(|_| crate::PqcError::Parse("unrecognised protocol".into()))
}
