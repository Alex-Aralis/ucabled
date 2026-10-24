// SPDX-License-Identifier: GPL-3.0-or-later

use std::time::{SystemTime, UNIX_EPOCH};

use crate::cbor;

pub const QR_SECRET_SIZE: usize = 16;
pub const COMPRESSED_PUBLIC_KEY_SIZE: usize = 33;

/// QR CBOR map keys (PXP §5.3.1).
const QR_KEY_PUBLIC_KEY: u8 = 0;
const QR_KEY_SECRET: u8 = 1;
const QR_KEY_NUM_KNOWN_DOMAINS: u8 = 2;
const QR_KEY_EPOCH_SECONDS: u8 = 3;
const QR_KEY_SUPPORTS_LINKING: u8 = 4;
const QR_KEY_REQUEST_TYPE: u8 = 5;
/// PXP §5.3.1 (key 6): list of data transfer channels the client supports.
const QR_KEY_TRANSPORTS: u8 = 6;

/// Data transfer channel identifiers for QR `Key 6`.
pub const TRANSPORT_WEBSOCKET: u64 = 0;
pub const TRANSPORT_BLE: u64 = 1;

/// Seven-byte chunks are encoded as 17-digit decimal numbers.
const DIGIT_CHUNK_BYTES: usize = 7;
const DIGIT_CHUNK_DIGITS: usize = 17;
/// Bits in a chunk hold over from the previous chunk (all but the last byte).
const DIGIT_CHUNK_OVERFLOW_BITS: u32 = 56;

#[derive(Clone, Copy, Debug)]
pub enum RequestType {
    MakeCredential,
    GetAssertion,
}

impl RequestType {
    /// The wire name used inside the QR contents (PXP §5.3.1, key 5)
    /// and handed to helpers so they can tell the two commands apart.
    pub fn as_str(self) -> &'static str {
        match self {
            RequestType::MakeCredential => "mc",
            RequestType::GetAssertion => "ga",
        }
    }
}

const WIDTHS: [usize; 8] = [0, 3, 5, 8, 10, 13, 15, 17];

pub fn bytes_to_digits(input: &[u8]) -> String {
    use std::fmt::Write;
    let mut ret =
        String::with_capacity(input.len().div_ceil(DIGIT_CHUNK_BYTES) * DIGIT_CHUNK_DIGITS);
    for chunk in input.chunks(DIGIT_CHUNK_BYTES) {
        let mut buf = [0u8; 8];
        buf[..chunk.len()].copy_from_slice(chunk);
        let v = u64::from_le_bytes(buf);
        let width = WIDTHS[chunk.len()];
        write!(ret, "{:0width$}", v, width = width).unwrap();
    }
    ret
}

pub fn digits_to_bytes(digits: &str) -> Option<Vec<u8>> {
    if !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let mut ret = Vec::new();
    let mut rest = digits;
    while rest.len() >= DIGIT_CHUNK_DIGITS {
        let v: u64 = rest[..DIGIT_CHUNK_DIGITS].parse().ok()?;
        if v >> DIGIT_CHUNK_OVERFLOW_BITS != 0 {
            return None;
        }
        ret.extend_from_slice(&v.to_le_bytes()[..DIGIT_CHUNK_BYTES]);
        rest = &rest[DIGIT_CHUNK_DIGITS..];
    }
    if !rest.is_empty() {
        let n = (1..DIGIT_CHUNK_BYTES).find(|&n| WIDTHS[n] == rest.len())?;
        let v: u64 = rest.parse().ok()?;
        if v >> (n * 8) != 0 {
            return None;
        }
        ret.extend_from_slice(&v.to_le_bytes()[..n]);
    }
    Some(ret)
}

pub fn encode_qr_contents(
    compressed_public_key: &[u8; COMPRESSED_PUBLIC_KEY_SIZE],
    secret: &[u8; QR_SECRET_SIZE],
    num_known_domains: u8,
    supports_linking: bool,
    request_type: RequestType,
    channels: &[u64],
) -> Vec<u8> {
    // Key 6 is only written when the client offers more than the WebSocket
    // tunnel: its absence means exactly that (PXP §5.3.1).  Chrome's QR codes
    // carry keys 0-5 only, and phones built against them, Android's linking
    // among them, are only known to work with that shape.
    let websocket_only = channels == [TRANSPORT_WEBSOCKET];
    let mut out = Vec::new();
    cbor::map(&mut out, if websocket_only { 6 } else { 7 });

    cbor::uint(&mut out, QR_KEY_PUBLIC_KEY as u64);
    cbor::bytes(&mut out, compressed_public_key);

    cbor::uint(&mut out, QR_KEY_SECRET as u64);
    cbor::bytes(&mut out, secret);

    cbor::uint(&mut out, QR_KEY_NUM_KNOWN_DOMAINS as u64);
    cbor::uint(&mut out, num_known_domains as u64);

    cbor::uint(&mut out, QR_KEY_EPOCH_SECONDS as u64);
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    cbor::uint(&mut out, now);

    cbor::uint(&mut out, QR_KEY_SUPPORTS_LINKING as u64);
    out.push(if supports_linking {
        cbor::TRUE
    } else {
        cbor::FALSE
    });

    cbor::uint(&mut out, QR_KEY_REQUEST_TYPE as u64);
    cbor::text(&mut out, request_type.as_str());

    if !websocket_only {
        cbor::uint(&mut out, QR_KEY_TRANSPORTS as u64);
        cbor::array(&mut out, channels.len() as u64);
        for &channel in channels {
            cbor::uint(&mut out, channel);
        }
    }

    out
}

pub fn encode_qr_url(
    compressed_public_key: &[u8; COMPRESSED_PUBLIC_KEY_SIZE],
    secret: &[u8; QR_SECRET_SIZE],
    num_known_domains: u8,
    supports_linking: bool,
    request_type: RequestType,
    channels: &[u64],
) -> String {
    let contents = encode_qr_contents(
        compressed_public_key,
        secret,
        num_known_domains,
        supports_linking,
        request_type,
        channels,
    );
    format!("FIDO:/{}", bytes_to_digits(&contents))
}

pub struct ParsedQr {
    pub compressed_public_key: [u8; COMPRESSED_PUBLIC_KEY_SIZE],
    pub secret: [u8; QR_SECRET_SIZE],
}

/// Parse a "FIDO:/..." QR URL. Only extracts keys 0 and 1, which are all the
/// phone side needs; unknown keys are ignored as the spec requires.
pub fn parse_qr_url(url: &str) -> Option<ParsedQr> {
    let digits = url.get(6..)?;
    if !url[..6].eq_ignore_ascii_case("FIDO:/") {
        return None;
    }
    let cbor = digits_to_bytes(digits)?;
    parse_qr_cbor(&cbor)
}

fn parse_qr_cbor(data: &[u8]) -> Option<ParsedQr> {
    let mut d = cbor::Decoder::new(data);
    let pairs = d.map_header()?;

    let mut public_key: Option<[u8; COMPRESSED_PUBLIC_KEY_SIZE]> = None;
    let mut secret: Option<[u8; QR_SECRET_SIZE]> = None;

    for _ in 0..pairs {
        let key = d.uint()?;
        match key {
            k if k == QR_KEY_PUBLIC_KEY as u64 => {
                public_key = Some(d.bytes()?.try_into().ok()?);
            }
            k if k == QR_KEY_SECRET as u64 => {
                secret = Some(d.bytes()?.try_into().ok()?);
            }
            // Unknown keys are skipped generically (the spec requires ignoring
            // them); the shared decoder bounds any nesting they contain.
            _ => d.skip_value()?,
        }
    }

    Some(ParsedQr {
        compressed_public_key: public_key?,
        secret: secret?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn digits_roundtrip() {
        for len in [1usize, 2, 3, 5, 6, 7, 8, 13, 14, 49, 50, 60] {
            let data: Vec<u8> = (0..len).map(|i| (i * 37 + 11) as u8).collect();
            let digits = bytes_to_digits(&data);
            let back = digits_to_bytes(&digits).unwrap();
            assert_eq!(data, back, "len {len}");
        }
    }

    #[test]
    fn digits_leading_zero_chunk() {
        let data = vec![0u8; 7];
        let digits = bytes_to_digits(&data);
        assert_eq!(digits, "00000000000000000");
        assert_eq!(digits_to_bytes(&digits).unwrap(), data);
    }

    #[test]
    fn digits_reject_malformed_input() {
        assert!(digits_to_bytes("abc").is_none());
        assert!(digits_to_bytes("12a45").is_none());
        // Invalid tail length (1 digit is not a legal 1..6 byte chunk).
        assert!(digits_to_bytes("1").is_none());
        // Too large for the chunk's byte width.
        assert!(digits_to_bytes("18446744073709551616").is_none());
    }

    #[test]
    fn digits_empty_is_empty() {
        assert_eq!(digits_to_bytes("").unwrap(), Vec::<u8>::new());
    }

    #[test]
    fn parse_ignores_transport_channels() {
        let public_key = [0x11u8; COMPRESSED_PUBLIC_KEY_SIZE];
        let secret = [0x22u8; QR_SECRET_SIZE];
        let url = encode_qr_url(
            &public_key,
            &secret,
            2,
            false,
            RequestType::GetAssertion,
            &[TRANSPORT_WEBSOCKET, TRANSPORT_BLE],
        );
        let parsed = parse_qr_url(&url).unwrap();
        assert_eq!(parsed.compressed_public_key, public_key);
        assert_eq!(parsed.secret, secret);
    }

    #[test]
    fn websocket_only_qr_has_chromes_keys_0_to_5() {
        let public_key = [0x11u8; COMPRESSED_PUBLIC_KEY_SIZE];
        let secret = [0x22u8; QR_SECRET_SIZE];
        let contents = encode_qr_contents(
            &public_key,
            &secret,
            2,
            true,
            RequestType::GetAssertion,
            &[TRANSPORT_WEBSOCKET],
        );
        let mut c = cbor::Decoder::new(&contents);
        assert_eq!(c.map_header(), Some(6));
        let mut keys = Vec::new();
        for _ in 0..6 {
            keys.push(c.uint().unwrap());
            c.skip_value().unwrap();
        }
        assert_eq!(keys, [0, 1, 2, 3, 4, 5]);
        // Key 4 (supports linking) is true.
        assert!(contents.windows(2).any(|w| w == [0x04, cbor::TRUE]));

        let with_ble = encode_qr_contents(
            &public_key,
            &secret,
            2,
            true,
            RequestType::GetAssertion,
            &[TRANSPORT_WEBSOCKET, TRANSPORT_BLE],
        );
        assert_eq!(cbor::Decoder::new(&with_ble).map_header(), Some(7));
    }
}
