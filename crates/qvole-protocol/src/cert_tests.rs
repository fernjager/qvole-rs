//! Tests ported from `qvole-go/internal/util/cert_test.go`.

use super::*;
use sha2::Digest;
use x509_parser::extensions::{ExtendedKeyUsage, KeyUsage, ParsedExtension};
use x509_parser::prelude::X509Certificate;

fn parse(der: &[u8]) -> X509Certificate<'_> {
    x509_parser::parse_x509_certificate(der).unwrap().1
}

fn sha256(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

/// Collect the parsed `KeyUsage` / `ExtendedKeyUsage` extensions.
fn key_usages<'a>(
    parsed: &'a X509Certificate<'_>,
) -> (Option<&'a KeyUsage>, Option<&'a ExtendedKeyUsage<'a>>) {
    let mut ku = None;
    let mut eku = None;
    for e in parsed.tbs_certificate.extensions() {
        match e.parsed_extension() {
            ParsedExtension::KeyUsage(k) => ku = Some(k),
            ParsedExtension::ExtendedKeyUsage(k) => eku = Some(k),
            _ => {}
        }
    }
    (ku, eku)
}

#[test]
fn generate_self_signed_cert_success() {
    let cert = generate_self_signed_cert("test-qvole").unwrap();
    assert!(!cert.der.is_empty(), "no certificate bytes");
    assert!(!cert.key.is_empty(), "no private key bytes");
}

#[test]
fn generate_self_signed_cert_key_type() {
    let cert = generate_self_signed_cert("test").unwrap();
    // The private key must be a valid ECDSA P-256 PKCS#8 key. ring's
    // `EcdsaKeyPair::from_pkcs8` only accepts P-256 keys for this
    // algorithm, so a successful parse proves both the algorithm and the
    // curve.
    let key = ring::signature::EcdsaKeyPair::from_pkcs8(
        &ring::signature::ECDSA_P256_SHA256_ASN1_SIGNING,
        &cert.key,
        &ring::rand::SystemRandom::new(),
    )
    .expect("expected an ECDSA P-256 PKCS#8 private key");
    // And the certificate public key must use the id-ecPublicKey OID.
    let parsed = parse(&cert.der);
    assert_eq!(
        parsed
            .tbs_certificate
            .public_key()
            .algorithm
            .oid()
            .to_string(),
        "1.2.840.10045.2.1",
        "expected id-ecPublicKey in the certificate"
    );
    let _ = key;
}

#[test]
fn generate_self_signed_cert_parse_certificate() {
    let cert = generate_self_signed_cert("qvole-test").unwrap();
    let parsed = parse(&cert.der);
    let cn = parsed
        .tbs_certificate
        .subject()
        .iter_common_name()
        .next()
        .and_then(|c| c.as_str().ok());
    assert_eq!(cn, Some("qvole-test"), "expected CommonName 'qvole-test'");
}

#[test]
fn generate_self_signed_cert_organization() {
    let cert = generate_self_signed_cert("qvole").unwrap();
    let parsed = parse(&cert.der);
    let org = parsed
        .tbs_certificate
        .subject()
        .iter_attributes()
        .find(|a| a.attr_type().to_string() == "2.5.4.10")
        .and_then(|a| a.as_str().ok());
    assert_eq!(org, Some("qvole"), "expected Organization 'qvole'");
}

#[test]
fn generate_self_signed_cert_key_usage() {
    let cert = generate_self_signed_cert("test").unwrap();
    let parsed = parse(&cert.der);
    let (ku, _) = key_usages(&parsed);
    let ku = ku.expect("KeyUsage extension missing");
    assert!(ku.digital_signature(), "expected KeyUsageDigitalSignature");
    assert!(
        !ku.key_encipherment(),
        "unexpected KeyUsageKeyEncipherment for ECDSA cert"
    );
}

#[test]
fn generate_self_signed_cert_ext_key_usage() {
    let cert = generate_self_signed_cert("test").unwrap();
    let parsed = parse(&cert.der);
    let (_, eku) = key_usages(&parsed);
    let eku = eku.expect("ExtendedKeyUsage extension missing");
    assert!(eku.server_auth, "expected ExtKeyUsageServerAuth");
    assert!(eku.client_auth, "expected ExtKeyUsageClientAuth");
}

#[test]
fn cert_fingerprint_length() {
    let cert = generate_self_signed_cert("test").unwrap();
    assert_eq!(
        cert_fingerprint(std::slice::from_ref(&cert.der))
            .unwrap()
            .len(),
        32
    );
}

#[test]
fn cert_fingerprint_matches_sha256() {
    let cert = generate_self_signed_cert("test").unwrap();
    let fp = cert_fingerprint(std::slice::from_ref(&cert.der)).unwrap();
    let expected = sha256(&cert.der);
    assert_eq!(
        fp, expected,
        "fingerprint does not match SHA-256 of DER bytes"
    );
}

#[test]
fn cert_fingerprint_empty() {
    assert_eq!(cert_fingerprint(&[]), None, "expected None for empty chain");
}

#[test]
fn generate_self_signed_cert_not_identical() {
    let c1 = generate_self_signed_cert("test").unwrap();
    let c2 = generate_self_signed_cert("test").unwrap();
    assert_ne!(
        c1.fingerprint, c2.fingerprint,
        "certificates should not be identical (random keys)"
    );
}

#[test]
fn generate_self_signed_cert_not_before_not_after() {
    let cert = generate_self_signed_cert("test").unwrap();
    let parsed = parse(&cert.der);
    let validity = parsed.tbs_certificate.validity();
    assert!(
        validity.not_before < validity.not_after,
        "NotBefore must be before NotAfter"
    );
}

#[test]
fn generate_self_signed_cert_self_signed() {
    let cert = generate_self_signed_cert("test").unwrap();
    let parsed = parse(&cert.der);
    parsed
        .verify_signature(None)
        .expect("self-signature verification failed");
}

#[test]
fn cert_fingerprint_stable_across_parsing() {
    let cert = generate_self_signed_cert("test").unwrap();
    let fp1 = cert_fingerprint(std::slice::from_ref(&cert.der)).unwrap();
    let parsed = parse(&cert.der);
    let fp2 = cert_fingerprint(&[parsed.as_raw().to_vec()]).unwrap();
    assert_eq!(
        fp1, fp2,
        "fingerprint should be stable across parse/re-encode"
    );
}

#[test]
fn cert_fingerprint_multi_der() {
    let cert1 = generate_self_signed_cert("first").unwrap();
    let cert2 = generate_self_signed_cert("second").unwrap();
    let der1 = cert1.der.clone();
    let der2 = cert2.der.clone();
    let fp = cert_fingerprint(&[der1, der2]).unwrap();
    let expected = sha256(&cert1.der);
    assert_eq!(
        fp, expected,
        "fingerprint should match first DER, ignoring subsequent certs"
    );
}
