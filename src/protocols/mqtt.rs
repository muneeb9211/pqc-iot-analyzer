//! MQTT v3.1.1/5.0 packet parser with TLS record extraction.

use super::{ParsedPacket, ProtocolType, TlsRecord};
use crate::PqcError;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PacketType {
    Connect,
    ConnAck,
    Publish,
    PubAck,
    Subscribe,
    SubAck,
    Unsubscribe,
    UnsubAck,
    PingReq,
    PingResp,
    Disconnect,
    Auth,
    Unknown(u8),
}

impl PacketType {
    fn from_nibble(n: u8) -> Self {
        match n {
            1 => Self::Connect,
            2 => Self::ConnAck,
            3 => Self::Publish,
            4 => Self::PubAck,
            8 => Self::Subscribe,
            9 => Self::SubAck,
            10 => Self::Unsubscribe,
            11 => Self::UnsubAck,
            12 => Self::PingReq,
            13 => Self::PingResp,
            14 => Self::Disconnect,
            15 => Self::Auth,
            x => Self::Unknown(x),
        }
    }

    fn as_str(&self) -> String {
        match self {
            Self::Connect => "CONNECT".into(),
            Self::ConnAck => "CONNACK".into(),
            Self::Publish => "PUBLISH".into(),
            Self::PubAck => "PUBACK".into(),
            Self::Subscribe => "SUBSCRIBE".into(),
            Self::SubAck => "SUBACK".into(),
            Self::Unsubscribe => "UNSUBSCRIBE".into(),
            Self::UnsubAck => "UNSUBACK".into(),
            Self::PingReq => "PINGREQ".into(),
            Self::PingResp => "PINGRESP".into(),
            Self::Disconnect => "DISCONNECT".into(),
            Self::Auth => "AUTH".into(),
            Self::Unknown(x) => format!("UNKNOWN({})", x),
        }
    }
}

pub fn looks_like_mqtt(data: &[u8]) -> bool {
    if data.len() < 2 {
        return false;
    }
    let ptype = data[0] >> 4;
    // Valid MQTT packet types are 1..=15
    if ptype == 0 {
        return false;
    }
    // For CONNECT, verify protocol name
    if ptype == 1 && data.len() >= 8 {
        // After remaining-length decode, we should see 0x00 0x04 "MQTT"
        let (_, hdr_len) = decode_remaining_length(&data[1..]).unwrap_or((0, 0));
        let var_start = 1 + hdr_len;
        if data.len() > var_start + 6 {
            let name = &data[var_start + 2..var_start + 6];
            return name == b"MQTT" || name == b"MQIs";
        }
    }
    // Generic: remaining length should be decodable
    decode_remaining_length(&data[1..]).is_some()
}

fn decode_remaining_length(data: &[u8]) -> Option<(u32, usize)> {
    let mut multiplier: u32 = 1;
    let mut value: u32 = 0;
    for (i, &byte) in data.iter().enumerate().take(4) {
        value += (byte as u32 & 0x7F) * multiplier;
        if byte & 0x80 == 0 {
            return Some((value, i + 1));
        }
        multiplier *= 128;
    }
    None
}

pub fn parse(data: &[u8]) -> Result<ParsedPacket, PqcError> {
    if data.len() < 2 {
        return Err(PqcError::Parse("MQTT packet too short".into()));
    }

    let ptype = PacketType::from_nibble(data[0] >> 4);
    let flags = data[0] & 0x0F;
    let (remaining_len, rl_bytes) =
        decode_remaining_length(&data[1..]).ok_or_else(|| PqcError::Parse("invalid MQTT remaining length".into()))?;

    let var_start = 1 + rl_bytes;
    let packet_end = std::cmp::min(var_start + remaining_len as usize, data.len());
    let variable_and_payload = &data[var_start..packet_end];

    let mut metadata: Vec<(String, String)> = vec![
        ("packet_type".into(), ptype.as_str()),
        ("flags".into(), format!("{:04b}", flags)),
        ("remaining_length".into(), remaining_len.to_string()),
    ];

    // Parse variable header for CONNECT
    let mut protocol_version = String::new();
    if let PacketType::Connect = ptype {
        if variable_and_payload.len() >= 7 {
            let proto_name_len = u16::from_be_bytes([variable_and_payload[0], variable_and_payload[1]]) as usize;
            if variable_and_payload.len() >= 2 + proto_name_len + 1 {
                if let Ok(name) = std::str::from_utf8(&variable_and_payload[2..2 + proto_name_len]) {
                    metadata.push(("protocol_name".into(), name.to_string()));
                }
                let version = variable_and_payload[2 + proto_name_len];
                protocol_version = match version {
                    4 => "3.1.1".into(),
                    5 => "5.0".into(),
                    v => format!("unknown({})", v),
                };
                metadata.push(("protocol_version".into(), protocol_version.clone()));

                let connect_flags = variable_and_payload[2 + proto_name_len + 1];
                metadata.push(("clean_session".into(), ((connect_flags >> 1) & 1 == 1).to_string()));
                metadata.push(("has_will".into(), ((connect_flags >> 2) & 1 == 1).to_string()));
                metadata.push(("has_username".into(), ((connect_flags >> 7) & 1 == 1).to_string()));
                metadata.push(("has_password".into(), ((connect_flags >> 6) & 1 == 1).to_string()));
            }
        }
    }

    // For PUBLISH, extract topic
    if let PacketType::Publish = ptype {
        if variable_and_payload.len() >= 2 {
            let topic_len = u16::from_be_bytes([variable_and_payload[0], variable_and_payload[1]]) as usize;
            if variable_and_payload.len() >= 2 + topic_len {
                if let Ok(topic) = std::str::from_utf8(&variable_and_payload[2..2 + topic_len]) {
                    metadata.push(("topic".into(), topic.to_string()));
                }
            }
        }
    }

    let payload = variable_and_payload.to_vec();

    // Detect TLS record in payload (for MQTTS interleaved capture)
    let tls_record = extract_tls_record(&payload);

    let ver_str = if protocol_version.is_empty() {
        String::new()
    } else {
        format!(" v{}", protocol_version)
    };
    let header_summary = format!(
        "MQTT{} {} Flags={:04b} Len={}",
        ver_str,
        ptype.as_str(),
        flags,
        remaining_len
    );

    Ok(ParsedPacket {
        protocol: ProtocolType::MQTT,
        header_summary,
        payload,
        tls_record,
        metadata,
    })
}

/// Extract TLS record from a buffer (for MQTTS).
fn extract_tls_record(payload: &[u8]) -> Option<TlsRecord> {
    if payload.len() < 5 {
        return None;
    }
    let content_type = payload[0];
    if !(20..=25).contains(&content_type) {
        return None;
    }
    let ver_major = payload[1];
    let ver_minor = payload[2];
    // TLS versions: 1.0=0x0301, 1.2=0x0303, 1.3=0x0304
    if ver_major != 0x03 {
        return None;
    }
    if ver_minor > 0x04 {
        return None;
    }
    let frag_len = u16::from_be_bytes([payload[3], payload[4]]) as usize;
    let end = std::cmp::min(5 + frag_len, payload.len());
    let fragment = payload[5..end].to_vec();

    // Extract cipher suite from ServerHello if handshake
    let cipher_suite = if content_type == 22 && fragment.len() > 38 {
        if fragment[0] == 2 {
            // ServerHello: type(1) len(3) version(2) random(32) sid_len(1) ...
            let sid_len = fragment[38] as usize;
            let cs_off = 39 + sid_len;
            if cs_off + 2 <= fragment.len() {
                Some(u16::from_be_bytes([fragment[cs_off], fragment[cs_off + 1]]))
            } else {
                None
            }
        } else {
            None
        }
    } else {
        None
    };

    Some(TlsRecord {
        content_type,
        version_major: ver_major,
        version_minor: ver_minor,
        cipher_suite,
        fragment,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build_connect_packet() -> Vec<u8> {
        // CONNECT, flags=0, remaining_length=12
        // Variable: proto_name_len=4 "MQTT" version=4 connect_flags=0x02 keepalive=60
        let mut pkt = vec![
            0x10, // CONNECT type=1, flags=0
            12,   // remaining length
            0x00, 0x04, b'M', b'Q', b'T', b'T', // protocol name
            4,    // version 3.1.1
            0x02, // connect flags (clean session)
            0x00, 0x3C, // keep alive 60s
        ];
        // Client ID length + id
        pkt.push(0x00);
        pkt.push(0x00); // empty client id (allowed in 3.1.1 w/ clean session)
        // Adjust remaining length
        pkt[1] = (pkt.len() - 2) as u8;
        pkt
    }

    #[test]
    fn parse_connect() {
        let pkt = build_connect_packet();
        let parsed = parse(&pkt).unwrap();
        assert_eq!(parsed.protocol, ProtocolType::MQTT);
        assert!(parsed.header_summary.contains("CONNECT"));
        let ver = parsed.metadata.iter().find(|(k, _)| k == "protocol_version").unwrap();
        assert_eq!(ver.1, "3.1.1");
    }

    #[test]
    fn parse_publish() {
        // PUBLISH, QoS 0, topic "temp"
        let topic = b"temp";
        let payload_data = b"22.5";
        let remaining = 2 + topic.len() + payload_data.len();
        let mut pkt = vec![0x30, remaining as u8]; // PUBLISH type=3, flags=0
        pkt.extend_from_slice(&(topic.len() as u16).to_be_bytes());
        pkt.extend_from_slice(topic);
        pkt.extend_from_slice(payload_data);

        let parsed = parse(&pkt).unwrap();
        assert!(parsed.header_summary.contains("PUBLISH"));
        let topic_meta = parsed.metadata.iter().find(|(k, _)| k == "topic").unwrap();
        assert_eq!(topic_meta.1, "temp");
    }

    #[test]
    fn looks_like_mqtt_heuristic() {
        let pkt = build_connect_packet();
        assert!(looks_like_mqtt(&pkt));
        assert!(!looks_like_mqtt(&[0x00]));
    }
}
