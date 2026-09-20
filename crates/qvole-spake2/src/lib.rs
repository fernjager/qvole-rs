//! SPAKE2 key agreement, shared-code generation, and word-list handling.
//!
//! Port of `spake2/spake2.go`, `spake2/words.go`, and `internal/util/code.go`
//! from the Go reference at commit `8f8ee569bbfc8ab4575ebd7094cf02fe492412e0`.

#![forbid(unsafe_code)]

#[cfg(test)]
mod tests;

pub mod code;
pub mod spake2;
pub mod words;

pub use spake2::{
    State, compute_confirm, compute_weierstrass_y, decrypt_metadata, derive_session_key,
    encrypt_metadata, hash_to_curve, new_state, password_to_scalar, session_aad, verify_confirm,
    zero_bytes,
};

/// Errors from the SPAKE2 and code-generation layers.
///
/// Display text mirrors the Go error strings where they are observable.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Randomness generation failed (Go: `spake2 randM: ...` / `spake2 randN: ...`).
    #[error("spake2 rand: {0}")]
    Rand(String),
    /// Peer point encoding is malformed (Go: `invalid peer spake2 point`).
    #[error("invalid peer spake2 point")]
    InvalidPeerPoint,
    /// Peer point is not on P-256 (Go: `peer spake2 point not on curve`).
    #[error("peer spake2 point not on curve")]
    PeerPointOffCurve,
    /// Go: `spake2: unblinded point is identity`.
    #[error("spake2: unblinded point is identity")]
    UnblindedIdentity,
    /// Go: `spake2: shared x-coordinate is zero`.
    #[error("spake2: shared x-coordinate is zero")]
    SharedXZero,
    /// Go: `spake2: confirm nonce must be non-empty`.
    #[error("spake2: confirm nonce must be non-empty")]
    EmptyNonce,
    /// Go: `ciphertext too short`.
    #[error("ciphertext too short")]
    CiphertextTooShort,
    /// AES-GCM operation failed.
    #[error("{0}")]
    Gcm(String),
    /// GCM authentication tag mismatch (Go: `cipher: message authentication failed`).
    #[error("cipher: message authentication failed")]
    GcmAuth,
    /// HKDF expansion failed (Go: `hkdf read: ...`).
    #[error("hkdf read: {0}")]
    Hkdf(String),
    /// HMAC setup failed.
    #[error("hmac: {0}")]
    Hmac(String),
    /// Go: `randInt: max out of range: %d`.
    #[error("randInt: max out of range: {0}")]
    RandIntRange(usize),
    /// Go: `generate code: %w`.
    #[error("generate code: {0}")]
    GenerateCode(String),
}
