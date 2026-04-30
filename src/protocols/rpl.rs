//! RPL (Routing Protocol for Low-Power and Lossy Networks) packet parser.
//!
//! Implements parsing of RPL control messages carried in ICMPv6 (type 155).
//! Covers DIS, DIO, and DAO message formats per RFC 6550.
//! Detects RPL security options that indicate cryptographic primitive usage.

use super::{ParsedPacket, ProtocolType};
use crate::PqcError;

/// RPL ICMPv6 control message codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RplCode {
    /// DODAG Information Solicitation
    Dis,
    /// DODAG Information Object
    Dio,
    /// Destination Advertisement Object
    Dao,
    /// DAO Acknowledgement
    DaoAck,
    /// Secure variant (bit 7 set in code)
    SecureDis,
    SecureDio,
    SecureDao,
    SecureDaoAck,
    /// Consistency Check
    Cc,
    Unknown(u8),
}

impl RplCode {
    fn from_byte(b: u8) -> Self {
        match b {
            0x00 => Self::Dis,
            0x01 => Self::Dio,
            0x02 => Self::Dao,
            0x03 => Self::DaoAck,
            0x80 => Self::SecureDis,
            0x81 => Self::SecureDio,
            0x82 => Self::SecureDao,
            0x83 => Self::SecureDaoAck,
            0x0A => Self::Cc,
            x => Self::Unknown(x),
        }
    }

    fn as_str(&self) -> String {
        match self {
            Self::Dis => "DIS".into(),
            Self::Dio => "DIO".into(),
            Self::Dao => "DAO".into(),
            Self::DaoAck => "DAO-ACK".into(),
            Self::SecureDis => "SEC-DIS".into(),
            Self::SecureDio => "SEC-DIO".into(),
            Self::SecureDao => "SEC-DAO".into(),
            Self::SecureDaoAck => "SEC-DAO-ACK".into(),
            Self::Cc => "CC".into(),
            Self::Unknown(x) => format!("UNKNOWN(0x{:02X})", x),
        }
    }

    fn is_secure(&self) -> bool {
        matches!(
            self,
            Self::SecureDis | Self::SecureDio | Self::SecureDao | Self::SecureDaoAck
        )
    }
}

/// RPL security algorithm identifiers (from the Security section option).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RplSecurityAlgorithm {
    /// CCM with AES-128
    CcmAes128,
    /// RSA with SHA-256
    RsaSha256,
    /// ECDSA with P-256
    EcdsaP256,
    /// Unknown / vendor-specific
    Unknown(u8),
}

impl RplSecurityAlgorithm {
    fn from_byte(b: u8) -> Self {
        match b {
            0 => Self::CcmAes128,
            1 => Self::RsaSha256,
            2 => Self::EcdsaP256,
            x => Self::Unknown(x),
        }
    }

    fn as_str(&self) -> &'static str {
        match self {
            Self::CcmAes128 => "CCM-AES-128",
            Self::RsaSha256 => "RSA-SHA256",
            Self::EcdsaP256 => "ECDSA-P256",
            Self::Unknown(_) => "Unknown",
        }
    }
}

/// Parse an RPL control message.
///
/// # Expected format
/// ```text
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |  Type (155)   |     Code      |          Checksum             |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                       Message Body ...                        |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
///
/// We use 0x9B as the type byte (155 in decimal). The parser also accepts
/// 0x9C and 0x9D as extended RPL types for future compatibility.
pub fn parse(data: &[u8]) -> Result<ParsedPacket, PqcError> {
    if data.len() < 4 {
        return Err(PqcError::Parse("RPL packet too short (need >= 4 bytes)".into()));
    }

    let icmp_type = data[0];
    if icmp_type != 0x9B && icmp_type != 0x9C && icmp_type != 0x9D {
        return Err(PqcError::Parse(format!(
            "not an RPL ICMPv6 packet (type=0x{:02X}, expected 0x9B)",
            icmp_type
        )));
    }

    let code = RplCode::from_byte(data[1]);
    let checksum = u16::from_be_bytes([data[2], data[3]]);

    let body = &data[4..];
    let mut metadata: Vec<(String, String)> = vec![
        ("icmpv6_type".into(), format!("0x{:02X}", icmp_type)),
        ("rpl_code".into(), code.as_str()),
        ("checksum".into(), format!("0x{:04X}", checksum)),
        ("secured".into(), code.is_secure().to_string()),
    ];

    let mut payload = body.to_vec();

    // Parse DIO base object if applicable (code 0x01 or 0x81)
    match code {
        RplCode::Dio | RplCode::SecureDio => {
            let offset = if code.is_secure() {
                // Secure variant has a security section (6 bytes minimum) before the DIO base
                parse_security_section(body, &mut metadata);
                6
            } else {
                0
            };
            if body.len() >= offset + 24 {
                let dio_base = &body[offset..];
                let rpl_instance_id = dio_base[0];
                let version_number = dio_base[1];
                let rank = u16::from_be_bytes([dio_base[2], dio_base[3]]);
                let grounded = (dio_base[4] >> 7) & 1 == 1;
                let mop = (dio_base[4] >> 3) & 0x07;
                // DODAGID is bytes 8..24 (16 bytes, IPv6 address)
                let dodagid = &dio_base[8..24];

                metadata.push(("rpl_instance_id".into(), rpl_instance_id.to_string()));
                metadata.push(("version".into(), version_number.to_string()));
                metadata.push(("rank".into(), rank.to_string()));
                metadata.push(("grounded".into(), grounded.to_string()));
                metadata.push(("mode_of_operation".into(), mop.to_string()));
                metadata.push(("dodagid".into(), hex::encode(dodagid)));

                payload = dio_base[24..].to_vec();
            }
        }
        RplCode::Dao | RplCode::SecureDao => {
            let offset = if code.is_secure() {
                parse_security_section(body, &mut metadata);
                6
            } else {
                0
            };
            if body.len() >= offset + 4 {
                let dao_base = &body[offset..];
                let rpl_instance_id = dao_base[0];
                let k_flag = (dao_base[1] >> 7) & 1 == 1;
                let dao_sequence = dao_base[2];
                metadata.push(("rpl_instance_id".into(), rpl_instance_id.to_string()));
                metadata.push(("k_flag".into(), k_flag.to_string()));
                metadata.push(("dao_sequence".into(), dao_sequence.to_string()));

                payload = dao_base[4..].to_vec();
            }
        }
        _ => {
            if code.is_secure() && body.len() >= 6 {
                parse_security_section(body, &mut metadata);
            }
        }
    }

    // Walk RPL options in remaining payload
    parse_rpl_options(&payload, &mut metadata);

    let header_summary = format!(
        "RPL {} Checksum=0x{:04X} Secure={} BodyLen={}",
        code.as_str(),
        checksum,
        code.is_secure(),
        body.len()
    );

    Ok(ParsedPacket {
        protocol: ProtocolType::RPL,
        header_summary,
        payload,
        tls_record: None, // RPL doesn't use TLS; security is in-band
        metadata,
    })
}

/// Parse the RPL Security section (6 bytes) and record algorithm info.
fn parse_security_section(body: &[u8], metadata: &mut Vec<(String, String)>) {
    if body.len() < 6 {
        return;
    }
    let _security_level = body[0] & 0x07;
    let algorithm = RplSecurityAlgorithm::from_byte(body[1]);
    let _key_id_mode = (body[0] >> 3) & 0x03;

    metadata.push(("security_algorithm".into(), algorithm.as_str().into()));
    metadata.push(("security_level".into(), (_security_level).to_string()));
}

/// Walk type-length-value RPL options.
fn parse_rpl_options(data: &[u8], metadata: &mut Vec<(String, String)>) {
    let mut cursor = 0;
    let mut opt_count = 0;
    while cursor < data.len() {
        let opt_type = data[cursor];
        if opt_type == 0 {
            // Pad1
            cursor += 1;
            continue;
        }
        if cursor + 1 >= data.len() {
            break;
        }
        let opt_len = data[cursor + 1] as usize;
        if cursor + 2 + opt_len > data.len() {
            break;
        }
        opt_count += 1;
        match opt_type {
            0x04 => metadata.push(("option".into(), "Route-Information".into())),
            0x08 => metadata.push(("option".into(), "DODAG-Configuration".into())),
            0x06 => metadata.push(("option".into(), "RPL-Target".into())),
            0x09 => metadata.push(("option".into(), "Transit-Information".into())),
            _ => metadata.push(("option".into(), format!("Type-0x{:02X}", opt_type))),
        }
        cursor += 2 + opt_len;
    }
    if opt_count > 0 {
        metadata.push(("rpl_option_count".into(), opt_count.to_string()));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_dis() {
        // Minimal DIS: type=0x9B, code=0x00, checksum=0x0000
        let data = [0x9B, 0x00, 0x00, 0x00];
        let pkt = parse(&data).unwrap();
        assert_eq!(pkt.protocol, ProtocolType::RPL);
        assert!(pkt.header_summary.contains("DIS"));
    }

    #[test]
    fn parse_dio_with_base() {
        let mut data = vec![
            0x9B, 0x01, 0x12, 0x34, // ICMPv6 RPL DIO
        ];
        // DIO base: instance_id=1, version=2, rank=256
        // G=1, MOP=2, Prf=0, DTSN=0, flags=0, reserved=0
        // DODAGID = 16 bytes of 0xFD...
        data.extend_from_slice(&[
            0x01, 0x02, 0x01, 0x00, // instance, version, rank
            0x88, 0x00, 0x00, 0x00, // grounded=1, MOP=1
            0xFD, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // DODAGID (first 8)
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, // DODAGID (last 8)
        ]);
        let pkt = parse(&data).unwrap();
        assert!(pkt.header_summary.contains("DIO"));
        let rank = pkt.metadata.iter().find(|(k, _)| k == "rank").unwrap();
        assert_eq!(rank.1, "256");
    }

    #[test]
    fn parse_secure_dio() {
        let mut data = vec![
            0x9B, 0x81, 0x00, 0x00, // Secure DIO
        ];
        // Security section: level=3, algorithm=2 (ECDSA-P256), + 4 pad bytes
        data.extend_from_slice(&[0x03, 0x02, 0x00, 0x00, 0x00, 0x00]);
        // DIO base (24 bytes)
        data.extend_from_slice(&[
            0x01, 0x01, 0x00, 0x80, 0x80, 0x00, 0x00, 0x00, 0xFD, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
        ]);

        let pkt = parse(&data).unwrap();
        assert!(pkt.header_summary.contains("SEC-DIO"));
        let algo = pkt.metadata.iter().find(|(k, _)| k == "security_algorithm").unwrap();
        assert_eq!(algo.1, "ECDSA-P256");
    }

    #[test]
    fn reject_non_rpl() {
        let data = [0x80, 0x00, 0x00, 0x00]; // ICMPv6 type 128 = Echo Request
        assert!(parse(&data).is_err());
    }
}
