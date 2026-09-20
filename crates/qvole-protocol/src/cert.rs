//! Self-signed certificate generation (Go `internal/util/cert.go`).
//!
//! Every peer generates a fresh ECDSA P-256 self-signed certificate per
//! connection. Peers authenticate each other by pinning the SHA-256
//! fingerprint of the certificate exchanged during the SPAKE2 phase, not by
//! any trust anchor (Go uses `InsecureSkipVerify` plus
//! `VerifyPeerCertificate`).

use rand::RngCore;
use rcgen::{
    CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa, KeyPair,
    KeyUsagePurpose, SerialNumber,
};
use sha2::{Digest, Sha256};
use thiserror::Error;
use time::{Duration, OffsetDateTime};

/// Certificate common name (Go `certCommonName`).
pub const CERT_COMMON_NAME: &str = "qvole";

/// Certificate validity (Go: 365 days).
const VALIDITY: Duration = Duration::days(365);

/// A generated self-signed certificate with its private key and fingerprint.
#[derive(Debug, Clone)]
pub struct SelfSignedCert {
    /// DER-encoded certificate (the only certificate in the chain).
    pub der: Vec<u8>,
    /// PKCS#8 DER-encoded ECDSA P-256 private key.
    pub key: Vec<u8>,
    /// SHA-256 fingerprint of [`SelfSignedCert::der`].
    pub fingerprint: [u8; 32],
}

/// Errors from certificate generation. Display text mirrors the Go error
/// wrapping.
#[derive(Debug, Error)]
pub enum CertError {
    /// `generate key: {0}`
    #[error("generate key: {0}")]
    GenerateKey(String),
    /// `create cert: {0}`
    #[error("create cert: {0}")]
    CreateCert(String),
}

/// Port of `util.GenerateSelfSignedCert`.
///
/// Creates a self-signed ECDSA P-256 certificate valid for 1 year with
/// `digitalSignature` key usage and `serverAuth` + `clientAuth` extended key
/// usages, subject `O=qvole, CN=commonName`.
pub fn generate_self_signed_cert(common_name: &str) -> Result<SelfSignedCert, CertError> {
    let key = KeyPair::generate().map_err(|e| CertError::GenerateKey(e.to_string()))?;

    // Go picks a random 128-bit serial number; keep it positive by clearing
    // the top bit (x509 requires positive serials).
    let mut serial = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut serial);
    serial[0] &= 0x7f;

    let now = OffsetDateTime::now_utc();
    let mut dn = DistinguishedName::new();
    dn.push(DnType::OrganizationName, "qvole");
    dn.push(DnType::CommonName, common_name);

    let mut params = CertificateParams::default();
    params.not_before = now;
    params.not_after = now + VALIDITY;
    params.serial_number = Some(SerialNumber::from_slice(&serial));
    params.distinguished_name = dn;
    params.is_ca = IsCa::ExplicitNoCa;
    params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    params.extended_key_usages = vec![
        ExtendedKeyUsagePurpose::ServerAuth,
        ExtendedKeyUsagePurpose::ClientAuth,
    ];

    let cert = params
        .self_signed(&key)
        .map_err(|e| CertError::CreateCert(e.to_string()))?;
    let der = cert.der().to_vec();
    let fingerprint =
        cert_fingerprint(std::slice::from_ref(&der)).expect("freshly created cert is non-empty");
    Ok(SelfSignedCert {
        der,
        key: key.serialize_der(),
        fingerprint,
    })
}

/// Port of `util.CertFingerprint`.
///
/// SHA-256 of the first DER certificate, or `None` when the slice is empty
/// (Go returns `nil`).
#[must_use]
pub fn cert_fingerprint(der_certs: &[Vec<u8>]) -> Option<[u8; 32]> {
    let first = der_certs.first()?;
    let h = Sha256::digest(first);
    Some(h.into())
}

/// Constant-time byte comparison (Go `crypto/subtle.ConstantTimeCompare`).
#[must_use]
pub(crate) fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b) {
        diff |= x ^ y;
    }
    diff == 0
}

#[cfg(test)]
#[path = "cert_tests.rs"]
mod tests;
