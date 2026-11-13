# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
Versions follow the upstream Go release line.

## [0.2.7] - 2026-11-13

### Security

- Cap SPAKE2 candidates at 8 per exchange with no eviction, aborting on the
  next new point; each answered point was an online guess at the code.
- Update `rustls-webpki` to 0.103.17, `rustls-pki-types` to 1.16.0, and
  `crypto-bigint` to 0.7.11. `cargo audit` reports no advisories.

### Fixed

- Keep resending the matching SPAKE2 confirm via the relay after the
  exchange, so a lost final confirm no longer fails the session after 90 s.
- Ignore the relay's own address during hole punching, so a relay sharing the
  peer's IP is no longer mistaken for the peer.

### Changed

- Update `const-oid`, `errno`, `syn`, and `webpki-root-certs` patch releases,
  and track qvole-go v0.2.7.

## [0.2.6] - 2026-11-08

### Security

- Update `p256` to 0.14.0, `elliptic-curve` to 0.14.3, and `crypto-bigint` to
  0.7.10, clearing RUSTSEC-2026-0387 (secret-dependent branches in operations
  intended to be constant-time: subtraction, zero counting, division,
  Montgomery multiplication, and equality). SPAKE2 applies these operations to
  the password scalar and ephemeral keys.
- Update `aws-lc-rs` to 1.19.0 (and `aws-lc-sys` to 0.47.0) and
  `webpki-root-certs` to 1.0.11. OSV reports no advisories for the lockfile.

### Changed

- Move the rest of the RustCrypto stack to the matching generation:
  `primeorder` 0.14, `sha2` 0.11, `hmac` 0.13, `hkdf` 0.13, `pbkdf2` 0.13, and
  `aes-gcm` 0.11. The P-256 base field element is named through
  `elliptic_curve::hazmat::FieldArithmetic`, and SEC1 conversions use the
  renamed `FromSec1Point`/`ToSec1Point` traits.
- Add a generator regression test that pins the M/N points to the Go
  reference, so a future curve-library change cannot silently break wire
  compatibility.
- Bump the workspace and binary version to 0.2.6, matching qvole-go v0.2.6.

## [0.2.5] - 2026-10-26

### Security

- Fix the critical relay impersonation: the confirm HMAC and HKDF now bind both
  peers' certificate fingerprints in sender/receiver order; reflected
  fingerprints are rejected. Protocol 0.2 is wire-breaking (ALPN
  `qvole-v0.2`); 0.1 peers are rejected.
- Disable TLS session resumption on clients and session tickets on servers so a
  resumed session cannot skip the pinned certificate check.
- Validate relay-supplied addresses as literal `IP:port`, reject
  unspecified/multicast/broadcast peer targets, and bound the listener wait.
- Deduplicate SPAKE2 candidates by full payload with bounded eviction and
  rate-limit inbound `MSGD`.
- Harden the relay with per-room pending caps, per-prefix client caps, IPv6
  /64 grouping for per-IP limits, bounded/rate-limited drop logs, and TTL
  checks at cookie completion.

## [0.2.4] - 2026-10-21

### Security

- Update `rustls` to 0.23.46, `quinn-proto` to 0.11.19 (via `quinn` 0.11.12),
  `rustls-webpki` to 0.103.16, and `webpki-root-certs` to 1.0.10, clearing all
  11 RustSec advisories in the previous lockfile.

### Changed

- Bump the workspace and binary version to `0.2.4`, matching qvole-go v0.2.4.
  The binary's default version now comes from `CARGO_PKG_VERSION`.
- Update `tokio` to 1.54.1, `tokio-util` to 0.7.20, `sha2` to 0.11.1,
  `zeroize` to 1.9.1, and other transitive dependencies.
- Bump CI actions and build/test with `--locked`.

### Docs

- Update the pinned baseline to qvole-go v0.2.4.

## [0.2.3] - 2026-09-20

### Added

- Initial Rust port of qvole-go v0.2.3: SPAKE2 authentication, UDP hole
  punching, QUIC transport, pipe/exec/tunnel features, and the UDP relay.
- Wire-compatible relay protocol and ALPN (`qvole-v0.1`) for interop with Go
  peers.
