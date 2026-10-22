# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
Versions follow the upstream Go release line.

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
