//! CoAP packet parser (RFC 7252) with DTLS record extraction (RFC 6347).

use super::{ParsedPacket, ProtocolType, TlsRecord};
use crate::PqcError;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MessageType {
    Confirmable,
    NonConfirmable,
    Acknowledgement,
    Reset,
}

impl MessageType {
    fn from_bits(bits: u8) -> Self {
        match bits & 0x03 {
            0 => Self::Confirmable,
            1 => Self::NonConfirmable,
            2 => Self::Acknowledgement,
            _ => Self::Reset,
        }
    }

    fn as_str(&self) -> &'static str {
        match self {
            Self::Confirmable => "CON",
            Self::NonConfirmable => "NON",
            Self::Acknowledgement => "ACK",
            Self::Reset => "RST",
        }
    }
}

fn code_to_string(class: u8, detail: u8) -> String {
    match (class, detail) {
        (0, 1) => "GET".into(),
        (0, 2) => "POST".into(),
        (0, 3) => "PUT".into(),
        (0, 4) => "DELETE".into(),
        (2, 1) => "2.01 Created".into(),
        (2, 4) => "2.04 Changed".into(),
        (2, 5) => "2.05 Content".into(),
        (4, 4) => "4.04 Not Found".into(),
        (5, 0) => "5.00 Internal Server Error".into(),
        _ => format!("{}.{:02}", class, detail),
    }
}

/// RFC 7252 message format:
/// ```text
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |Ver| T |  TKL  |     Code      |         Message ID            |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |   Token (if any, TKL bytes) ...
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |   Options (if any) ...
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |1 1 1 1 1 1 1 1| Payload (if any) ...
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
pub fn parse(data: &[u8]) -> Result<ParsedPacket, PqcError> {
    if data.len() < 4 {
        return Err(PqcError::Parse("CoAP packet too short (need >= 4 bytes)".into()));
    }

    let ver = (data[0] >> 6) & 0x03;
    if ver != 1 {
        return Err(PqcError::Parse(format!("CoAP version {} unsupported (expected 1)", ver)));
    }

    let msg_type = MessageType::from_bits((data[0] >> 4) & 0x03);
    let tkl = (data[0] & 0x0F) as usize;
    let code_class = (data[1] >> 5) & 0x07;
    let code_detail = data[1] & 0x1F;
    let message_id = u16::from_be_bytes([data[2], data[3]]);

    if data.len() < 4 + tkl {
        return Err(PqcError::Parse("CoAP packet truncated in token field".into()));
    }

    let token = &data[4..4 + tkl];

    let mut cursor = 4 + tkl;
    let mut options: Vec<(u16, Vec<u8>)> = Vec::new();
    let mut option_number: u16 = 0;

    while cursor < data.len() {
        if data[cursor] == 0xFF {
            // Payload marker
            cursor += 1;
            break;
        }
        let delta_nibble = (data[cursor] >> 4) & 0x0F;
        let len_nibble = data[cursor] & 0x0F;
        cursor += 1;

        let delta = decode_option_field(delta_nibble, data, &mut cursor)?;
        let length = decode_option_field(len_nibble, data, &mut cursor)?;

        option_number += delta;
        if cursor + length as usize > data.len() {
            return Err(PqcError::Parse("CoAP option overflows packet".into()));
        }
        options.push((option_number, data[cursor..cursor + length as usize].to_vec()));
        cursor += length as usize;
    }

    let payload = if cursor < data.len() {
        data[cursor..].to_vec()
    } else {
        Vec::new()
    };

    let tls_record = extract_dtls_record(&payload);

    let code_str = code_to_string(code_class, code_detail);
    let header_summary = format!(
        "CoAP v1 {} {} MsgID={} Token={} Options={}",
        msg_type.as_str(),
        code_str,
        message_id,
        hex::encode(token),
        options.len()
    );

    let mut metadata = vec![
        ("version".into(), "1".into()),
        ("type".into(), msg_type.as_str().into()),
        ("code".into(), code_str),
        ("message_id".into(), message_id.to_string()),
        ("token".into(), hex::encode(token)),
        ("token_length".into(), tkl.to_string()),
        ("option_count".into(), options.len().to_string()),
    ];

    for (num, val) in &options {
        match num {
            11 => {
                if let Ok(s) = std::str::from_utf8(val) {
                    metadata.push(("uri_path".into(), s.to_string()));
                }
            }
            12 => {
                if val.len() <= 2 {
                    let cf = option_bytes_to_u16(val);
                    metadata.push(("content_format".into(), cf.to_string()));
                }
            }
            _ => {}
        }
    }

    Ok(ParsedPacket {
        protocol: ProtocolType::CoAP,
        header_summary,
        payload,
        tls_record,
        metadata,
    })
}

fn decode_option_field(nibble: u8, data: &[u8], cursor: &mut usize) -> Result<u16, PqcError> {
    match nibble {
        0..=12 => Ok(nibble as u16),
        13 => {
            if *cursor >= data.len() {
                return Err(PqcError::Parse("CoAP option field truncated".into()));
            }
            let val = data[*cursor] as u16 + 13;
            *cursor += 1;
            Ok(val)
        }
        14 => {
            if *cursor + 1 >= data.len() {
                return Err(PqcError::Parse("CoAP option field truncated".into()));
            }
            let val = u16::from_be_bytes([data[*cursor], data[*cursor + 1]]) + 269;
            *cursor += 2;
            Ok(val)
        }
        _ => Err(PqcError::Parse("CoAP option field reserved value 15".into())),
    }
}

fn option_bytes_to_u16(bytes: &[u8]) -> u16 {
    match bytes.len() {
        0 => 0,
        1 => bytes[0] as u16,
        _ => u16::from_be_bytes([bytes[0], bytes[1]]),
    }
}

/// Extract DTLS record from payload. Layout: ContentType(1) Version(2) Epoch(2) SeqNum(6) Length(2) Fragment(...)
fn extract_dtls_record(payload: &[u8]) -> Option<TlsRecord> {
    if payload.len() < 13 {
        return None;
    }
    let content_type = payload[0];
    if !(20..=25).contains(&content_type) {
        return None;
    }
    let ver_major = payload[1];
    let ver_minor = payload[2];
    if ver_major != 0xFE {
        return None;
    }
    if ver_minor != 0xFF && ver_minor != 0xFD {
        return None;
    }
    let frag_len = u16::from_be_bytes([payload[11], payload[12]]) as usize;
    let fragment_end = std::cmp::min(13 + frag_len, payload.len());
    let fragment = payload[13..fragment_end].to_vec();

    // Extract cipher suite from ServerHello (handshake type 2)
    let cipher_suite = if content_type == 22 && fragment.len() >= 40 {
        if fragment[0] == 2 && fragment.len() > 12 + 2 + 32 + 1 {
            let sid_offset = 12 + 2 + 32;
            let sid_len = fragment[sid_offset] as usize;
            let cs_offset = sid_offset + 1 + sid_len;
            if cs_offset + 2 <= fragment.len() {
                Some(u16::from_be_bytes([fragment[cs_offset], fragment[cs_offset + 1]]))
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

    #[test]
    fn parse_minimal_coap_get() {
        // CoAP GET, CON, MsgID=0x0001, no token, no options, no payload
        let data = [0x40, 0x01, 0x00, 0x01];
        let pkt = parse(&data).unwrap();
        assert_eq!(pkt.protocol, ProtocolType::CoAP);
        assert!(pkt.header_summary.contains("CON"));
        assert!(pkt.header_summary.contains("GET"));
    }

    #[test]
    fn parse_coap_with_token_and_payload() {
        // Ver=1, T=NON(1), TKL=2, Code=2.05 Content, MsgID=0x1234
        // Token: 0xAB 0xCD
        // Payload marker 0xFF, then "hello"
        let mut data = vec![0x52, 0x45, 0x12, 0x34, 0xAB, 0xCD, 0xFF];
        data.extend_from_slice(b"hello");
        let pkt = parse(&data).unwrap();
        assert_eq!(pkt.protocol, ProtocolType::CoAP);
        assert!(pkt.header_summary.contains("NON"));
        assert_eq!(pkt.payload, b"hello");
        let token_meta = pkt.metadata.iter().find(|(k, _)| k == "token").unwrap();
        assert_eq!(token_meta.1, "abcd");
    }

    #[test]
    fn reject_wrong_version() {
        let data = [0x00, 0x01, 0x00, 0x01]; // ver=0
        assert!(parse(&data).is_err());
    }
}
