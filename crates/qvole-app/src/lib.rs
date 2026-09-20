//! Application features: `pipe`, `exec`, `tunnel` (port of `qvole internal/app` and top-level API).
//!
//! Port of `internal/app/*` and the top-level Go `qvole` package API
//! (`qvole.go`, `options.go`, `stream.go`) from the Go reference at commit
//! `8f8ee569bbfc8ab4575ebd7094cf02fe492412e0`.

#![forbid(unsafe_code)]

pub mod copy;
pub mod exec;
pub mod options;
pub mod pipe;
pub mod stdin_reader;
pub mod stream_conn;
pub mod tunnel;
pub mod tunnel_allow;
pub mod tunnel_request;

#[cfg(test)]
pub(crate) mod testutil;

// ---------------------------------------------------------------------------
// Library surface (Go `qvole.go`, `options.go`, `stream.go`)
// ---------------------------------------------------------------------------

use std::time::Duration;

use quinn::VarInt;
use tokio_util::sync::CancellationToken;

/// Go `qvole.ProtocolVersion`: protocol version for relay messages.
pub const PROTOCOL_VERSION: &str = qvole_protocol::transport::PROTOCOL_VERSION;
/// Go `qvole.MinCodeLen`: minimum code length.
pub const MIN_CODE_LEN: usize = 8;
/// Go `qvole.MaxCodeLen`: maximum code length.
pub const MAX_CODE_LEN: usize = 256;

/// Go `qvole.Option` and the `with_*` builders (Go `options.go`).
pub use options::{
    Option, Options, with_allow_all, with_allow_forward, with_allow_listen, with_cmd_mode,
    with_code, with_command, with_exchange_deadline, with_forward_max_streams,
    with_handshake_timeout, with_idle_timeout, with_keep_alive, with_local_tunnel,
    with_max_streams, with_punch_timeout, with_relay, with_remote_tunnel, with_stream_idle_timeout,
};

/// Go `qvole.Connect` result: the established peer connection.
pub use qvole_protocol::connect::Connected;
/// Go `qvole.GetBuffer`/`PutBuffer` (the shared `sync.Pool` port).
pub use qvole_protocol::pool::{get_buffer, put_buffer};
/// Go `qvole.GenerateCode`/`Nameplate` (Go `internal/util` ports).
pub use qvole_spake2::code::{generate_code, nameplate};
/// Go `qvole.Dial`/`Accept` stream type (Go `stream.go`).
pub use stdin_reader::StdinReader;
pub use stream_conn::QuicStreamConn;
/// Go `qvole.ParseTunnelRequest` / `TunnelRequest` (Go `qvole.go` +
/// `internal/app/tunnel.go`).
pub use tunnel_request::{TunnelRequest, parse_tunnel_request};

/// Errors returned by the library surface (Go `qvole.go` returns bare
/// errors; each variant maps to the Go error path of one entry point).
#[derive(Debug, thiserror::Error)]
pub enum LibError {
    /// Code/relay validation (Go `validate`).
    #[error("{0}")]
    Validation(String),
    /// Connection establishment (Go: `ConnectPeerWithConfig` error).
    #[error(transparent)]
    Connect(#[from] qvole_protocol::connect::ConnectError),
    /// QUIC stream open/accept failure (Go: returned as-is).
    #[error("{0}")]
    Stream(String),
    /// Exec failure (Go `Exec` → `RunExecWithConfig` error).
    #[error(transparent)]
    Exec(#[from] exec::ExecError),
    /// Tunnel failure (Go `Tunnel` → `RunTunnelWithConfig` error).
    #[error(transparent)]
    Tunnel(#[from] tunnel::TunnelError),
}

/// Go `resolveOptions`.
fn resolve_options<'a>(opts: &[Option<'a>]) -> Options {
    let mut o = Options::default();
    for opt in opts {
        opt(&mut o);
    }
    o
}

/// Go `validate`.
fn validate(o: &Options) -> Result<(), LibError> {
    if o.code.is_empty() {
        return Err(LibError::Validation("code is required".into()));
    }
    if o.code.len() < MIN_CODE_LEN {
        return Err(LibError::Validation(format!(
            "code must be at least {MIN_CODE_LEN} characters"
        )));
    }
    if o.code.len() > MAX_CODE_LEN {
        return Err(LibError::Validation(format!(
            "code must be at most {MAX_CODE_LEN} characters"
        )));
    }
    if o.relay.is_empty() {
        return Err(LibError::Validation("relay is required".into()));
    }
    Ok(())
}

/// Go `toPeerConfig`. Zero option fields stay unset so the engine's
/// env → default chain applies (Go: zero-value `PeerConfig` fields).
fn to_peer_config(o: &Options) -> qvole_protocol::exchange::PeerConfig {
    let dur = |v: Duration| (v != Duration::ZERO).then_some(v);
    let num = |v: i64| (v > 0).then_some(v as u32);
    qvole_protocol::exchange::PeerConfig {
        punch_timeout: dur(o.punch_timeout),
        exchange_deadline: dur(o.exchange_deadline),
        spake2_resend: None,
        confirm_resend: None,
        read_deadline: None,
        reg_interval: None,
        max_streams: num(o.max_streams),
        forward_max_streams: num(o.forward_max_streams),
        keep_alive_period: dur(o.keep_alive_period),
        idle_timeout: dur(o.idle_timeout),
        handshake_timeout: dur(o.handshake_timeout),
    }
}

/// Go `Dial`: connects to a peer via relay and opens a bidirectional
/// stream.
///
/// The stream is announced with a 0-byte write right after opening. Note
/// that this is a quinn workaround, **not** Go `OpenStreamSync` parity:
/// quic-go also opens lazily; see [`stream_conn::announce_stream`].
pub async fn dial<'a>(
    cancel: &CancellationToken,
    opts: &[Option<'a>],
) -> Result<QuicStreamConn, LibError> {
    let o = resolve_options(opts);
    validate(&o)?;
    let connected =
        qvole_protocol::connect::connect_peer(cancel, &o.relay, &o.code, &to_peer_config(&o))
            .await?;
    let (mut send, recv) = connected
        .conn
        .open_bi()
        .await
        .map_err(|e| LibError::Stream(e.to_string()))?;
    let send = match stream_conn::announce_stream(&mut send).await {
        Ok(()) => send,
        Err(e) => {
            connected.conn.close(VarInt::from_u32(0), b"");
            return Err(LibError::Stream(e.to_string()));
        }
    };
    Ok(QuicStreamConn::with_endpoint(
        connected.conn,
        send,
        recv,
        connected.endpoint,
    ))
}

/// Go `Accept`: waits for a peer to connect and returns the stream.
pub async fn accept<'a>(
    cancel: &CancellationToken,
    opts: &[Option<'a>],
) -> Result<QuicStreamConn, LibError> {
    let o = resolve_options(opts);
    validate(&o)?;
    let connected =
        qvole_protocol::connect::connect_peer(cancel, &o.relay, &o.code, &to_peer_config(&o))
            .await?;
    match connected.conn.accept_bi().await {
        Ok((send, recv)) => Ok(QuicStreamConn::with_endpoint(
            connected.conn,
            send,
            recv,
            connected.endpoint,
        )),
        Err(e) => {
            connected.conn.close(VarInt::from_u32(0), b"");
            Err(LibError::Stream(e.to_string()))
        }
    }
}

/// Go `Connect`: connects to a peer via relay and returns the underlying
/// QUIC connection and whether this side is the server.
///
/// Returns the full [`Connected`] value so the caller can keep the
/// endpoint alive (Go returns only the connection handle; the endpoint
/// keeps the connection rooted in quinn).
pub async fn connect<'a>(
    cancel: &CancellationToken,
    opts: &[Option<'a>],
) -> Result<Connected, LibError> {
    let o = resolve_options(opts);
    validate(&o)?;
    Ok(
        qvole_protocol::connect::connect_peer(cancel, &o.relay, &o.code, &to_peer_config(&o))
            .await?,
    )
}

/// Go `Exec`: runs an exec command or bridges stdin/stdout.
///
/// In command mode (`with_cmd_mode(true)`), the command runs locally and
/// its stdin/stdout are bridged over the QUIC stream; in pipe mode
/// (`with_cmd_mode(false)`), the local stdin/stdout are bridged to the
/// peer (Go `RunPipeMode`).
pub async fn exec<'a>(cancel: &CancellationToken, opts: &[Option<'a>]) -> Result<(), LibError> {
    let o = resolve_options(opts);
    validate(&o)?;
    exec::run_exec(
        cancel,
        &o.relay,
        &o.code,
        &to_peer_config(&o),
        &o.command,
        o.cmd_mode,
        StdinReader::new(),
        tokio::io::stdout(),
        || {},
    )
    .await
    .map_err(LibError::Exec)
}

/// Go `Tunnel`: starts tunneling.
pub async fn tunnel<'a>(cancel: &CancellationToken, opts: &[Option<'a>]) -> Result<(), LibError> {
    let o = resolve_options(opts);
    validate(&o)?;
    tunnel::run_tunnel_with_config(
        cancel,
        &o.relay,
        &o.code,
        &o.local_tunnels,
        &o.remote_tunnels,
        o.allow_all,
        &o.allow_listen,
        &o.allow_forward,
        o.forward_max_streams,
        o.stream_idle_timeout,
        &to_peer_config(&o),
    )
    .await
    .map_err(LibError::Tunnel)
}

/// Go `CloseWrite`: closes the send half of a QUIC stream (FIN) without
/// closing the receive side.
pub async fn close_write(conn: &mut QuicStreamConn) -> Result<(), quinn::ClosedStream> {
    conn.close_write().await
}
