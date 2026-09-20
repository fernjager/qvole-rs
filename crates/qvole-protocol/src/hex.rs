//! Lowercase hex encoding/decoding with Go `encoding/hex` semantics.
//!
//! Go's `hex.EncodeToString` produces lowercase; `hex.DecodeString` errors on
//! odd length and on invalid bytes. The relay and engine layers both need
//! these, so they live here instead of being duplicated per crate.

/// Lowercase hex encoding (Go `hex.EncodeToString`).
pub fn to_hex_lower(b: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(b.len() * 2);
    for &byte in b {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

/// Decodes lowercase or uppercase hex.
///
/// Returns `None` for odd-length input or invalid characters, mirroring the
/// error cases of Go's `hex.DecodeString` (callers map `None` to their Go
/// error paths).
pub fn hex_decode(s: &str) -> Option<Vec<u8>> {
    let b = s.as_bytes();
    if !b.len().is_multiple_of(2) {
        return None;
    }
    fn val(c: u8) -> Option<u8> {
        match c {
            b'0'..=b'9' => Some(c - b'0'),
            b'a'..=b'f' => Some(c - b'a' + 10),
            b'A'..=b'F' => Some(c - b'A' + 10),
            _ => None,
        }
    }
    let mut out = Vec::with_capacity(b.len() / 2);
    let mut i = 0;
    while i < b.len() {
        let hi = val(b[i])?;
        let lo = val(b[i + 1])?;
        out.push(hi << 4 | lo);
        i += 2;
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_roundtrip() {
        let data = [0x00, 0xAB, 0xCD, 0xEF, 0x01, 0xFF];
        let hex = to_hex_lower(&data);
        assert_eq!(hex, "00abcdef01ff");
        assert_eq!(hex_decode(&hex).as_deref(), Some(data.as_slice()));
    }

    #[test]
    fn hex_decode_uppercase() {
        assert_eq!(hex_decode("ABCD").as_deref(), Some([0xAB, 0xCD].as_slice()));
    }

    #[test]
    fn hex_decode_odd_length() {
        assert_eq!(hex_decode("abc"), None);
    }

    #[test]
    fn hex_decode_invalid_char() {
        assert_eq!(hex_decode("not-hex!!!"), None);
    }

    #[test]
    fn hex_decode_empty() {
        assert_eq!(hex_decode("").unwrap(), Vec::<u8>::new());
    }
}
