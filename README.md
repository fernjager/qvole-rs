<p align="center"><img src="assets/logo.svg" width="96" alt="qvole-rs"></p>

<h1 align="center">qvole-rs</h1>
<p align="center">
  <a href="https://github.com/fernjager/qvole-rs/actions/workflows/ci.yml"><img src="https://github.com/fernjager/qvole-rs/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-green" alt="License"></a>
  <img src="https://img.shields.io/badge/rust-edition%202024-orange" alt="Rust Edition">
</p>
<p align="center"><em>Fast, encrypted peer-to-peer tunnels over QUIC, burrowed through NATs.</em></p>

A Rust implementation of [qvole](https://github.com/fernjager/qvole).

qvole connects two machines (usually both behind NAT) from a short shared
code. It gives you stdin/stdout pipes, TCP port forwarding, and remote command
execution over a single direct QUIC connection: one binary, no accounts, no
config files, and a minimal public relay that handles rendezvous only.

Two peers exchange the code over a public UDP relay, perform a SPAKE2 key
agreement, hole-punch a direct QUIC connection with mutually pinned self-signed
certificates, and then run `pipe`, `exec`, or `tunnel` over it.

A qvole connection has exactly two peers. Despite the "VPN" framing sometimes
used for tools in this space, qvole is not a mesh VPN and creates no virtual
network interface: it is a point-to-point tunnel plus stdio pipes and TCP
forwarding, designed to compose with the tools you already use.

This port is wire-compatible with the Go implementation and mirrors its layout
module for module. It targets Linux and macOS; Windows is not supported.

Initial baseline: qvole-go commit
[`8f8ee569bbfc8ab4575ebd7094cf02fe492412e0`](https://github.com/fernjager/qvole/commit/8f8ee569bbfc8ab4575ebd7094cf02fe492412e0) (v0.2.3).

## Quick Start

The command line and wire protocol match upstream apart from the `--version`
self-identifier, so the [qvole README](https://github.com/fernjager/qvole#readme)
is the reference for flags, tuning variables, and more examples. All upstream
`QVOLE_*` environment variables are honored; the relay adds one of its own,
`QVOLE_RELAY_TRACE`.

```bash
# Send a file
alice$ qvole pipe < in                         # prints connection code, waits for bob
bob$   QVOLE_CODE=CODE qvole pipe > out        # bob connects, receiving file from alice

# Send a directory
alice$ tar czf - dir/ | qvole pipe
bob$   QVOLE_CODE=CODE qvole pipe | tar xzf -

# Port forwarding: each side authorizes the target the other may reach (-aF);
# the accessing side picks its own convenient local port (-L)
alice$ qvole tunnel -L 8080:localhost:80 -aF localhost:22
bob$   QVOLE_CODE=CODE qvole tunnel -aF localhost:80 -L 2222:localhost:22
alice$ curl localhost:8080                     # reaches bob's :80
bob$   ssh -p 2222 localhost                   # reaches alice's sshd

# Remote command (alice hosts the command, bob connects)
alice$ qvole exec --cmd "uptime"               # runs on alice, bob sees output
bob$   QVOLE_CODE=CODE qvole exec

# Run a private relay server (UDP)
relay$ qvole relay --listen :9009
```

## Install

Prebuilt binaries, releases, and the upstream `get.qvole.dev` installer are
published by the Go project. The wire protocol is shared, so Go and Rust peers
interoperate:

<https://github.com/fernjager/qvole>

This port also publishes its own builds and follows the Go release line
exactly: pushing a `vX.Y.Z` tag builds Linux/amd64, Linux/arm64, and macOS
(Apple Silicon and Intel) binaries, attaches them to a GitHub Release, and
writes a `SHA256SUMS` file. The tag and the binary's `--version` output are the
same `X.Y.Z` as the Go release.

Build this port from source (Linux or macOS):

```sh
cargo build --release          # binary at target/release/qvole
```

## How it works

qvole composes three well-understood primitives:

- **SPAKE2 (password-authenticated key exchange).** Each peer sends a blinded
  P-256 point and the pair derives a shared secret that nobody else can
  compute, not even the relay. The code *is* the credential, and after the
  handshake its role is done.
- **QUIC over UDP.** One socket carries multiple independent streams with
  TLS 1.3 built in, so every connection is always encrypted and authenticated.
- **UDP hole punching.** Both peers send to each other's external address at
  once; each outbound packet opens a pinhole that lets the other side's packet
  through. This is the same NAT traversal technique used by video calls.

A TLS certificate fingerprint is exchanged alongside the SPAKE2 blinded point
and bound to the shared secret, handing a low-entropy code off to a strong,
pinned TLS 1.3 session with forward secrecy. After the handshake the relay sees
only opaque handshake material: it cannot derive keys, decrypt traffic, or
impersonate a peer.

Full specifications live upstream:

- [Protocol specification](https://github.com/fernjager/qvole/blob/main/docs/PROTOCOL.md)
- [Security documentation](https://github.com/fernjager/qvole/blob/main/SECURITY.md)

## Security posture

Neither implementation is fully constant-time. Both build on constant-time
elliptic-curve backends (Go's `nistec` and the `p256` crate's formulas), but
each still routes some secret-derived values through vartime helpers: Go uses
`math/big` for scalar reductions and comparisons, while this port uses
`from_repr_vartime`, `is_zero_vartime`, and a value-dependent branch in
`reduce_mod_n`. The `p256` crate also warns that its constant-time behavior has
not been verified at the assembly level on common CPUs. The port does not claim
a timing advantage over Go.

## Limitations

These are properties of the shared design, not of this port; the upstream
README and security documentation cover them in more detail.

- **NAT traversal is best-effort.** Whether a connection forms depends on the
  two networks. There is no higher-level fallback, so some network pairs will
  not connect.
- **UDP only, and no TURN/data-relay fallback.** The relay never touches user
  data, which keeps it simple but means restrictive symmetric NATs that block
  hole punching, and networks that block outbound UDP, cannot connect.
- **The relay is a single point of failure for rendezvous.** Peers cannot
  discover each other without it, though it cannot decrypt established traffic.
- **Two peers per connection.** Multi-party connections are not supported.
- **The relay is stateless and rate limited.** Handshake messages can be lost
  if a client is briefly unreachable, and signaling is capped per client.

## Layout

| Crate | Mirrors |
| --- | --- |
| `crates/qvole-spake2` | `spake2/`, `internal/util/code.go` |
| `crates/qvole-protocol` | `internal/engine/`, `internal/util/` (non-code) |
| `crates/qvole-relay` | `relay/` |
| `crates/qvole-app` | `internal/app/`, `qvole.go`, `options.go`, `stream.go` |
| `crates/qvole-bin` | `cmd/qvole/` |

## Build and test

```sh
cargo build --release          # binary at target/release/qvole
cargo test --workspace         # in-crate unit tests
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
```

CI runs these checks, plus a release build, on Linux/amd64, Linux/arm64, and
macOS (Apple Silicon).

## Notable differences from qvole-go

### Language and runtime

- Goroutines, channels, and `context.Context` become tokio tasks,
  `tokio::sync::mpsc` channels (`flume` for the relay's multi-consumer queue),
  and `CancellationToken`.
- quic-go becomes [quinn](https://github.com/quinn-rs/quinn); `crypto/tls`
  becomes rustls; certificates are generated with `rcgen` and `x509-cert`
  instead of `crypto/x509`.
- SPAKE2 uses the `p256` crate's typed `Scalar`/`ProjectivePoint` API; Go
  drives `crypto/elliptic` with `math/big` scalars (its P-256 curve arithmetic
  is itself constant-time via `nistec`).
- CLI flag parsing is a small hand-rolled parser that reproduces Go's `flag`
  package semantics (usage text, error strings, exit codes) instead of using a
  Rust CLI framework.
- `#![forbid(unsafe_code)]` in every first-party crate.
- The `--version` line appends `, rust port` so a release identifies itself;
  the usage text, flag errors, and exit codes stay byte-identical to Go.

### Wire compatibility

The relay protocol, ALPN (`qvole-v0.1`), TLS 1.3 settings, SPAKE2/P-256
exchange, and SHA-256 certificate-fingerprint pinning all match the Go
implementation. Certificate serial numbers differ from Go's random 128-bit
serial, which is not observable under fingerprint pinning.

### Behavioral differences from the pinned Go reference

As of the v0.2.3 baseline, the relay hardening, `exec` stdin half-close,
`PasswordToScalar`, `pipe` stats teardown, and atomic `Debug` fixes are present
in both implementations, so they are no longer differences.

- **Stream announcement.** quinn, like quic-go, does not tell the peer about a
  locally opened stream until data, FIN, or a reset is sent. This port writes a
  0-byte STREAM frame right after `open_bi`; quinn puts that frame on the wire,
  so a quinn peer (and a quic-go peer) can accept the stream early. quic-go's
  own 0-byte write is a no-op, so a Go-opened stream that has not written or
  finished stays invisible to quinn. That remains a known interop gap for
  Go-to-Rust silent/interactive `exec` and would need a coordinated wire
  change.
- **Process exit.** Stdin is read on a dedicated thread rather than through
  `tokio::io::stdin()`, and the runtime is shut down in the background, so a
  process whose main future has finished does not wait on an uncancellable
  blocking stdin read.
- **Connection close.** A short explicit delay after `Connection::close` gives
  quinn's connection driver a chance to put `CONNECTION_CLOSE` on the wire
  before the process exits.
- **Relay trace logging.** `QVOLE_RELAY_TRACE` enables verbose relay tracing;
  the Go relay has no equivalent knob.

## Advantages and tradeoffs vs the Go implementation

The two implementations are wire-compatible and can be mixed freely; the
choice is mostly about platform, ecosystem, and which safety properties you
value. The points below are relative to the **pinned reference commit** above.

**Advantages of this port**

- **Memory and data-race safety by construction.** Every first-party crate is
  `#![forbid(unsafe_code)]`; Rust's type system rejects shared mutable state
  without synchronization, so a data race or a silent slice alias cannot be
  written in safe code. Go reaches the same guarantees here with atomics and
  explicit copies (v0.2.3), but that relies on the programmer doing so.
- **Explicit hardening where the runtimes differ.** A dedicated stdin thread
  plus `shutdown_background()` means a finished main future never hangs on an
  uncancellable blocking read, and `flush_close()` guarantees
  `CONNECTION_CLOSE` reaches the wire before the process exits. Go's runtime
  gives this for free; the port had to make it explicit.

**Tradeoffs and disadvantages**

- **Linux and macOS.** Go builds for Linux, macOS, FreeBSD, and Windows. This
  port is developed and tested on Linux and also builds and passes its test
  suite on macOS (Apple Silicon); Windows is not supported, and FreeBSD is
  untested.
- **Build from source.** Prebuilt binaries, the `get.qvole.dev` installer, and
  release artifacts are the Go project's.
- **No published, documented library surface.** Go is an importable library
  with `docs/LIBRARY.md`; the Rust crates are a workspace, not a published or
  documented API of the same standing.
- **Smaller docs and community surface.** Protocol, security, library, and
  privacy docs plus translated READMEs live upstream; this tree carries the
  code and this README.
- **One interop sharp edge.** A Go-opened stream that has not yet written or
  finished is invisible to a quinn peer, so silent/interactive `exec` from a Go
  host can deadlock. This is a protocol-wide limit, not a Rust-only one:
  Go-to-Go has the same hang (upstream `docs/PROTOCOL.md` §7.2). This port's
  0-byte announce fixes Rust-opened streams; a complete fix needs a coordinated
  wire change.
- **Lockstep maintenance.** The port tracks a pinned Go commit, so protocol or
  behavior changes must be carried across both codebases by hand. At the
  v0.2.3 baseline the two are behaviorally aligned except for the
  stream-announcement asymmetry above.

In short: prefer the Go implementation for cross-platform use, prebuilt
artifacts, and embedding; prefer this port when you want a Rust codebase and the
stronger static-safety guarantees, on Linux or macOS.

## Testing scope

This tree contains the in-crate unit tests. The port's binary-level
integration suite, cargo-fuzz targets, interop harnesses, and porting journal
are not included.

## License

MIT. See [LICENSE](LICENSE).
