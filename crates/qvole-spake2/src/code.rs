//! Shared-connection-code generation and nameplates.
//!
//! Port of `internal/util/code.go`.

use rand_core::RngCore;
use sha2::{Digest, Sha256};

use crate::{Error, words};

/// Matches auto-generated codes of the form `"1234-word-word-word"`
/// (Go: `GeneratedCodeRe = ^\d{4}-`; Go `\d` is `[0-9]`).
pub fn is_generated_code(code: &str) -> bool {
    let b = code.as_bytes();
    b.len() >= 5 && b[..4].iter().all(|c| c.is_ascii_digit()) && b[4] == b'-'
}

/// Creates a new random connection code in the format
/// `"0000-word-word-word"`.
///
/// Port of `GenerateCode`.
pub fn generate_code() -> Result<String, Error> {
    let words = words::code_words();
    let maxes = [10_000, words.len(), words.len(), words.len()];
    let mut vals = [0usize; 4];
    for (i, &m) in maxes.iter().enumerate() {
        vals[i] = rand_int(m).map_err(|e| Error::GenerateCode(e.to_string()))?;
    }
    Ok(format!(
        "{:04}-{}-{}-{}",
        vals[0], words[vals[1]], words[vals[2]], words[vals[3]]
    ))
}

/// Returns a uniform random int in `[0, max)` using rejection sampling to
/// eliminate modulo bias. `max` must be in `(0, 65536]`.
///
/// Port of `randInt`.
pub(crate) fn rand_int(max: usize) -> Result<usize, Error> {
    if max == 0 || max > 65536 {
        return Err(Error::RandIntRange(max));
    }
    // Largest multiple of max that fits in uint16
    let limit = (65536 / max) * max;
    let mut rng = rand_core::OsRng;
    let mut b = [0u8; 2];
    loop {
        rng.fill_bytes(&mut b);
        let v = u16::from_be_bytes(b) as usize;
        if v < limit {
            return Ok(v % max);
        }
    }
}

/// Derives a 4-byte room identifier from a code. For auto-generated codes it
/// uses the numeric prefix; otherwise it returns a truncated SHA-256 hash.
///
/// Port of `Nameplate`.
pub fn nameplate(code: &str) -> String {
    if is_generated_code(code) {
        return code[..4].to_owned();
    }
    let h = Sha256::digest(format!("qvole-nameplate:{code}").as_bytes());
    hex_encode(&h[..4])
}

/// Minimal lowercase hex encoder (avoids a dependency for four bytes).
fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}
