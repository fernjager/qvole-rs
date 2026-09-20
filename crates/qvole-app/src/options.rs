//! Library connection options (Go `options.go`).
//!
//! Go's functional-options API is mirrored 1:1: each `with_*` function
//! returns an [`Option`] - a boxed closure that sets one field of
//! [`Options`]. Like Go's zero value, a zero duration/counter field means
//! "unset": the engine's env → built-in-default chain applies (see
//! `qvole_protocol::exchange::PeerConfig`).

use std::time::Duration;

/// Go `Option`: a closure that sets one field of [`Options`].
///
/// `Send` so options slices can move across task boundaries (Go options are
/// plain values used from goroutines).
pub type Option<'a> = Box<dyn Fn(&mut Options) + Send + Sync + 'a>;

/// Go `options`: resolved library options.
#[derive(Default)]
pub struct Options {
    /// Shared secret code for peer authentication.
    pub(crate) code: String,
    /// Relay server address (host:port).
    pub(crate) relay: String,
    /// Maximum duration for UDP hole punching. 0 = env/default chain.
    pub(crate) punch_timeout: Duration,
    /// Maximum duration for the SPAKE2 exchange. 0 = env/default chain.
    pub(crate) exchange_deadline: Duration,
    /// QUIC keepalive interval. 0 = env/default chain.
    pub(crate) keep_alive_period: Duration,
    /// QUIC idle timeout. 0 = env/default chain.
    pub(crate) idle_timeout: Duration,
    /// QUIC handshake timeout. 0 = env/default chain.
    pub(crate) handshake_timeout: Duration,
    /// Maximum incoming bidirectional streams. 0 = env/default chain.
    pub(crate) max_streams: i64,
    /// Maximum incoming bidirectional streams tunnel forwards may open.
    /// 0 = env/default chain.
    pub(crate) forward_max_streams: i64,
    /// Inactivity window before silent forward tunnel streams are reaped.
    /// 0 = disabled (Go default).
    pub(crate) stream_idle_timeout: Duration,
    /// Command to run in exec mode.
    pub(crate) command: String,
    /// Whether this side runs the command (`true`) or bridges stdin/stdout.
    pub(crate) cmd_mode: bool,
    /// Local tunnel specs (`[laddr:]lport:raddr:rport`).
    pub(crate) local_tunnels: Vec<String>,
    /// Remote tunnel specs (`[raddr:]rport:laddr:lport`).
    pub(crate) remote_tunnels: Vec<String>,
    /// Accept all peer tunnel requests (unsafe).
    pub(crate) allow_all: bool,
    /// `addr:port` allowlist for peer `-R` (listen) requests.
    pub(crate) allow_listen: Vec<String>,
    /// `addr:port` allowlist for peer `-L` (forward) requests.
    pub(crate) allow_forward: Vec<String>,
}

/// Go `WithCode`: sets the shared secret code for peer authentication.
pub fn with_code(code: &str) -> Option<'_> {
    Box::new(move |o: &mut Options| o.code = code.to_string())
}

/// Go `WithRelay`: sets the relay server address.
pub fn with_relay(addr: &str) -> Option<'_> {
    Box::new(move |o: &mut Options| o.relay = addr.to_string())
}

/// Go `WithPunchTimeout`: overrides the UDP hole-punch timeout.
pub fn with_punch_timeout(d: Duration) -> Option<'static> {
    Box::new(move |o: &mut Options| o.punch_timeout = d)
}

/// Go `WithExchangeDeadline`: overrides the SPAKE2 exchange deadline.
pub fn with_exchange_deadline(d: Duration) -> Option<'static> {
    Box::new(move |o: &mut Options| o.exchange_deadline = d)
}

/// Go `WithKeepAlive`: overrides the QUIC keepalive interval.
pub fn with_keep_alive(d: Duration) -> Option<'static> {
    Box::new(move |o: &mut Options| o.keep_alive_period = d)
}

/// Go `WithIdleTimeout`: overrides the QUIC idle timeout.
pub fn with_idle_timeout(d: Duration) -> Option<'static> {
    Box::new(move |o: &mut Options| o.idle_timeout = d)
}

/// Go `WithHandshakeTimeout`: overrides the QUIC handshake timeout.
pub fn with_handshake_timeout(d: Duration) -> Option<'static> {
    Box::new(move |o: &mut Options| o.handshake_timeout = d)
}

/// Go `WithMaxStreams`: overrides the max incoming bidirectional streams.
pub fn with_max_streams(n: i64) -> Option<'static> {
    Box::new(move |o: &mut Options| o.max_streams = n)
}

/// Go `WithForwardMaxStreams`: overrides the max incoming bidirectional
/// streams tunnel forwards may open.
pub fn with_forward_max_streams(n: i64) -> Option<'static> {
    Box::new(move |o: &mut Options| o.forward_max_streams = n)
}

/// Go `WithStreamIdleTimeout`: sets the inactivity window before silent
/// forward tunnel streams are reaped (0 = disabled).
pub fn with_stream_idle_timeout(d: Duration) -> Option<'static> {
    Box::new(move |o: &mut Options| o.stream_idle_timeout = d)
}

/// Go `WithCommand`: sets the command to run in exec mode.
pub fn with_command(cmd: &str) -> Option<'_> {
    Box::new(move |o: &mut Options| o.command = cmd.to_string())
}

/// Go `WithCmdMode`: sets whether this side runs the command (`true`) or
/// bridges stdin/stdout (`false`).
pub fn with_cmd_mode(b: bool) -> Option<'static> {
    Box::new(move |o: &mut Options| o.cmd_mode = b)
}

/// Go `WithLocalTunnel`: adds a local tunnel spec.
pub fn with_local_tunnel(spec: &str) -> Option<'_> {
    Box::new(move |o: &mut Options| o.local_tunnels.push(spec.to_string()))
}

/// Go `WithRemoteTunnel`: adds a remote tunnel spec.
pub fn with_remote_tunnel(spec: &str) -> Option<'_> {
    Box::new(move |o: &mut Options| o.remote_tunnels.push(spec.to_string()))
}

/// Go `WithAllowAll`: accepts all peer tunnel requests (unsafe).
pub fn with_allow_all(b: bool) -> Option<'static> {
    Box::new(move |o: &mut Options| o.allow_all = b)
}

/// Go `WithAllowListen`: adds an `addr:port` to the `-R` listen allowlist.
pub fn with_allow_listen(addr: &str) -> Option<'_> {
    Box::new(move |o: &mut Options| o.allow_listen.push(addr.to_string()))
}

/// Go `WithAllowForward`: adds an `addr:port` to the `-L` forward allowlist.
pub fn with_allow_forward(addr: &str) -> Option<'_> {
    Box::new(move |o: &mut Options| o.allow_forward.push(addr.to_string()))
}
