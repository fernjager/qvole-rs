//! Port-forwarding tunnel (Go `internal/app/tunnel.go`): config exchange,
//! stream acceptor, TCP listeners, idle reaping, outbound guard.
//!
//! ## Design notes
//!
//! * Go passes one `net.Conn` / one `*quic.Stream` to both copy directions.
//!   Rust's borrow checker forbids two `&mut` of the same value, so
//!   [`tunnel_copy`] splits the `TcpStream` into read/write halves with
//!   `tokio::io::split` (tokio 1.53 `TcpStream` is not cloneable) and uses
//!   the separate quinn send/recv halves for the other end.
//! * Go's `stream.SetReadDeadline` on the QUIC side has no direct quinn
//!   equivalent; [`IdleReader`] emulates it with a shared sliding
//!   deadline (`Arc<Mutex<Option<Sleep>>>`) that fires `TimedOut` and is
//!   re-armed on data - by the reader itself or by the refresh callback
//!   (Go refreshes both deadlines on any data; the same shared-callback
//!   structure is used here).
//! * Go's global `chan struct{}` outbound guard becomes a
//!   `static Mutex<Option<(usize, Arc<Semaphore>)>>`; `OwnedSemaphorePermit`
//!   plays the role of the channel token.
//! * Go's per-session `sync.Map` + `sync.Once` announcement state becomes
//!   `Mutex<HashMap<usize, bool>>` (first call for an index announces).
//! * Go's `defer`-based cleanup (stream FIN, TCP close, guard release) is
//!   mirrored by dropping the respective handle at function exit: dropping
//!   a quinn `SendStream` sends FIN, dropping a `TcpStream` closes it.
//! * `readAcceptLine` reads byte-by-byte (one line, capped at
//!   [`SCANNER_MAX_TOKEN_SIZE`]) instead of a `bufio.Scanner`.

use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;

use quinn::{Connection, RecvStream, SendStream, VarInt};
use tokio::io::{AsyncRead, AsyncReadExt, ReadBuf};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Semaphore, mpsc};
use tokio::time::timeout;
use tokio_util::sync::CancellationToken;

use qvole_protocol::connect::{ConnectError, Connected, connect_peer};
use qvole_protocol::disconnect::log_disconnect;
use qvole_protocol::env::env_duration_ms;
use qvole_protocol::exchange::PeerConfig;
use qvole_protocol::logger::{LOG_TUNNEL, bold};
use qvole_protocol::role::role_string;
use qvole_protocol::transport::get_forward_max_streams;

use crate::copy::bidirectional_copy;
use crate::tunnel_allow::TunnelAllow;
use crate::tunnel_request::{
    DIAL_TIMEOUT, MAX_TUNNEL_REQUESTS, SCANNER_MAX_TOKEN_SIZE, STREAM_CONFIG_TIMEOUT,
    STREAM_HEADER_TIMEOUT, TunnelRequest, parse_tunnel_request, read_requests_from_stream,
    strip_eol,
};

/// Go `dialTimeout` env var name.
pub const DIAL_TIMEOUT_ENV: &str = "QVOLE_DIAL_TIMEOUT_MS";
/// Go `streamIdleTimeout` env var name.
pub const STREAM_IDLE_TIMEOUT_ENV: &str = "QVOLE_STREAM_IDLE_TIMEOUT_MS";

/// A pinned, storable `Sleep`: `tokio::time::Sleep` is `!Unpin`, so the
/// shared deadline handle stores `Pin<Box<Sleep>>`.
type PinnedSleep = Pin<Box<tokio::time::Sleep>>;

/// Errors from the tunnel feature. Display text mirrors Go's error
/// wrapping.
#[derive(Debug, thiserror::Error)]
pub enum TunnelError {
    /// Connection failure (Go: wrapped `ConnectError`).
    #[error(transparent)]
    Connect(#[from] ConnectError),
    /// The session context was canceled (Go `context.Canceled`).
    #[error("canceled")]
    Canceled,
    /// Any other error (Go `fmt.Errorf` with the various messages below).
    #[error("{0}")]
    Other(String),
}

impl TunnelError {
    fn is_canceled(&self) -> bool {
        matches!(self, Self::Canceled)
    }
}

/// Go `streamIdleTimeout`: the per-tunneled-connection inactivity window.
/// Defaults to 0 (disabled): with 0, forwarded connections rely purely on
/// the connection-level QUIC keepalive/idle timeouts and are never
/// force-closed. A non-zero override takes precedence over the env var.
pub fn stream_idle_timeout(override_val: Duration) -> Duration {
    stream_idle_timeout_from(
        override_val,
        std::env::var(STREAM_IDLE_TIMEOUT_ENV).ok().as_deref(),
    )
}

/// Pure form of [`stream_idle_timeout`] (Go `util.EnvDuration` rules:
/// absent / non-numeric / non-positive values fall back to the default).
pub(crate) fn stream_idle_timeout_from(override_val: Duration, env_val: Option<&str>) -> Duration {
    if override_val > Duration::ZERO {
        return override_val;
    }
    match env_val.and_then(|v| v.parse::<i64>().ok()) {
        Some(ms) if ms > 0 => Duration::from_millis((ms as u64).min(i64::MAX as u64 / 1000)),
        _ => Duration::ZERO,
    }
}

/// Go `initOutboundGuard`: (re)creates the process-wide outbound stream
/// guard when the requested size differs from the current one, so each
/// tunnel session's limit takes effect under repeated in-process library
/// use. In-flight handlers keep releasing into the semaphore they acquired
/// from, so swapping is safe.
pub fn init_outbound_guard(n: i64) {
    let n = n.max(0) as usize;
    let mut guard = OUTBOUND_GUARD.lock().unwrap();
    if guard.is_none() || guard.as_ref().unwrap().0 != n {
        *guard = Some((n, Arc::new(Semaphore::new(n))));
    }
}

/// Go `getOutboundGuard`: returns the outbound semaphore, initializing it
/// lazily from `get_forward_max_streams(None)` when
/// [`init_outbound_guard`] was not called.
pub fn get_outbound_guard() -> Arc<Semaphore> {
    let mut guard = OUTBOUND_GUARD.lock().unwrap();
    let entry = guard.get_or_insert_with(|| {
        let n = get_forward_max_streams(None).max(0) as usize;
        (n, Arc::new(Semaphore::new(n)))
    });
    Arc::clone(&entry.1)
}

static OUTBOUND_GUARD: Mutex<Option<(usize, Arc<Semaphore>)>> = Mutex::new(None);

/// Go `announceTunnelOnce`: logs a one-time success message the first time
/// a connection is established through tunnel spec `idx` within a tunnel
/// session. The map is per-`run_tunnel` (not global) so repeated or
/// concurrent sessions announce independently. Returns `true` for the call
/// that performed the announcement.
fn announce_tunnel_once(announced: &Mutex<HashMap<usize, bool>>, idx: usize, target: &str) -> bool {
    let mut map = announced.lock().unwrap();
    let first = !*map.entry(idx).or_insert(false);
    if first {
        map.insert(idx, true);
        LOG_TUNNEL.printf_success(&format!("Tunnel established: ↔ {}", bold(target)));
    }
    first
}

/// A reader with a sliding idle deadline: each successful data read resets
/// the deadline; if no data arrives within the window, the next read fails
/// with `TimedOut`.
///
/// Go parity: `SetReadDeadline(now + idle)` plus refresh-on-data. Go
/// refreshes *both* sides' deadlines whenever either side produces data;
/// here both the TCP and QUIC read sides share one deadline handle, so a
/// read on either side re-arms both (no separate refresh callback is
/// needed).
pub(crate) struct IdleReader<R: AsyncRead + Unpin> {
    inner: R,
    idle: Duration,
    deadline: Arc<Mutex<Option<PinnedSleep>>>,
}

impl<R: AsyncRead + Unpin> IdleReader<R> {
    fn new(inner: R, idle: Duration, deadline: Arc<Mutex<Option<PinnedSleep>>>) -> Self {
        Self {
            inner,
            idle,
            deadline,
        }
    }
}

impl<R: AsyncRead + Unpin> AsyncRead for IdleReader<R> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        {
            let mut deadline = self.deadline.lock().unwrap();
            if let Some(sleep) = deadline.as_mut()
                && std::future::Future::poll(sleep.as_mut(), cx).is_ready()
            {
                return Poll::Ready(Err(io::Error::new(io::ErrorKind::TimedOut, "idle timeout")));
            }
        }
        let before = buf.filled().len();
        let res = Pin::new(&mut self.inner).poll_read(cx, buf);
        // Reset the deadline only when bytes were actually read (tokio
        // reports both data and EOF as `Ok(())`).
        if matches!(&res, Poll::Ready(Ok(()))) && buf.filled().len() > before {
            *self.deadline.lock().unwrap() = Some(Box::pin(tokio::time::sleep(self.idle)));
        }
        res
    }
}

/// Go `tunnelCopy`: bridges a tunneled TCP connection and its QUIC stream
/// bidirectionally. When `idle > 0` it arms initial read deadlines on both
/// sides and refreshes them whenever either side produces data, turning an
/// absolute lifetime cap into an activity-based reaper. When `idle` is 0
/// (default, disabled) no per-stream deadline is applied and the copy runs
/// indefinitely, relying on connection-level QUIC keepalive/idle timeouts
/// for liveness.
pub(crate) async fn tunnel_copy(
    tcp: TcpStream,
    mut quic_send: SendStream,
    mut quic_recv: RecvStream,
    idle: Duration,
) {
    let stop = CancellationToken::new();
    // Go passes one `net.Conn` to both copy directions; `tokio::io::split`
    // yields independent read/write handles over the same socket.
    let (mut tcp_read, mut tcp_write) = tokio::io::split(tcp);
    if idle <= Duration::ZERO {
        bidirectional_copy(
            Pin::new(&mut tcp_read),
            Pin::new(&mut tcp_write),
            Pin::new(&mut quic_recv),
            Pin::new(&mut quic_send),
            &stop,
            None,
            || {},
        )
        .await;
        return;
    }
    // Go arms both deadlines before the copy starts; the shared handle is
    // re-armed by either read side on data.
    let deadline: Arc<Mutex<Option<PinnedSleep>>> =
        Arc::new(Mutex::new(Some(Box::pin(tokio::time::sleep(idle)))));
    let mut tcp_read = IdleReader::new(tcp_read, idle, Arc::clone(&deadline));
    let mut quic_read = IdleReader::new(quic_recv, idle, deadline);
    bidirectional_copy(
        Pin::new(&mut tcp_read),
        Pin::new(&mut tcp_write),
        Pin::new(&mut quic_read),
        Pin::new(&mut quic_send),
        &stop,
        None,
        || {},
    )
    .await;
}

/// Go `readAcceptLine`: reads the ACCEPT line and parses the boolean.
async fn read_accept_line<R: AsyncRead + Unpin>(reader: &mut R) -> Result<bool, String> {
    let mut line: Vec<u8> = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        match reader.read(&mut byte).await {
            Ok(0) => return Err("read accept: unexpected EOF".to_string()),
            Ok(_) => {
                if byte[0] == b'\n' {
                    break;
                }
                if line.len() >= SCANNER_MAX_TOKEN_SIZE {
                    return Err("read accept: token too long".to_string());
                }
                line.push(byte[0]);
            }
            Err(e) => return Err(format!("read accept: {e}")),
        }
    }
    let text = strip_eol(&line);
    match text.as_str() {
        "ACCEPT true" => Ok(true),
        "ACCEPT false" => Ok(false),
        _ => Err(format!("unexpected line: {text:?}")),
    }
}

/// Go `ExchangeTunnelConfig`: exchanges tunnel config over a QUIC control
/// stream.
///
/// Returns `(peer_accept, reqs, my_req_start)`: whether the peer is willing
/// to accept the request set, the combined request list (the client's
/// requests come first, then the server's), and the index of this side's
/// first request within the combined list (0 for the client,
/// `len(peer_reqs)` for the server).
///
/// The client opens the control stream and the server accepts it, which is
/// deterministic on both sides. Both sides write their config on the stream
/// and read the peer's config from the same stream; reads and writes are
/// bounded by [`STREAM_CONFIG_TIMEOUT`] so a stalled peer cannot hold the
/// exchange open indefinitely.
pub async fn exchange_tunnel_config(
    cancel: &CancellationToken,
    conn: &Connection,
    my_reqs: &[TunnelRequest],
    allow: &TunnelAllow,
    is_server: bool,
) -> Result<(bool, Vec<TunnelRequest>, usize), String> {
    if my_reqs.len() > MAX_TUNNEL_REQUESTS {
        return Err(format!(
            "too many tunnel requests: {} (max {})",
            my_reqs.len(),
            MAX_TUNNEL_REQUESTS
        ));
    }

    let (mut send, mut recv) = if is_server {
        // Server: accept the client's stream, bounded so a peer that never
        // opens one cannot stall the exchange.
        let r = tokio::select! {
            r = conn.accept_bi() => r,
            () = tokio::time::sleep(STREAM_CONFIG_TIMEOUT) => {
                return Err("accept control stream: timeout".to_string())
            }
            () = cancel.cancelled() => return Err("canceled".to_string()),
        };
        r.map_err(|e| format!("accept control stream: {e}"))?
    } else {
        // Client: open the control stream.
        let r = tokio::select! {
            r = conn.open_bi() => r,
            () = cancel.cancelled() => return Err("canceled".to_string()),
        };
        r.map_err(|e| format!("open control stream: {e}"))?
    };
    // `send` is FINned when dropped (Go `defer stream.Close()`).

    // Each side writes its config, bounded by one write deadline for the
    // whole phase (Go `stream.SetWriteDeadline(now + streamConfigTimeout)`).
    let write_phase: Result<Result<(), String>, _> = timeout(STREAM_CONFIG_TIMEOUT, async {
        let accept_line = format!("ACCEPT {}\n", allow.accepts());
        send.write_all(accept_line.as_bytes())
            .await
            .map_err(|e| format!("write accept: {e}"))?;
        for (i, r) in my_reqs.iter().enumerate() {
            let line = format!("{} {} {}\n", r.typ, r.listen_addr, r.target_addr);
            send.write_all(line.as_bytes())
                .await
                .map_err(|e| format!("write request {i}: {e}"))?;
        }
        send.write_all(b"END\n")
            .await
            .map_err(|e| format!("write end: {e}"))?;
        Ok(())
    })
    .await;
    match write_phase {
        Err(_) => return Err("write config: deadline exceeded".to_string()),
        Ok(Err(e)) => return Err(e),
        Ok(Ok(())) => {}
    }

    // Go `logSentConfig`.
    if my_reqs.is_empty() {
        LOG_TUNNEL.printf_info("Awaiting tunnel request(s) from peer");
    } else {
        LOG_TUNNEL.printf_success(&format!("Sent {} tunnel request(s)", my_reqs.len()));
    }

    // Then read the peer's config, bounded by one read deadline for the
    // whole phase (Go `stream.SetReadDeadline(now + streamConfigTimeout)`).
    let read_phase: Result<Result<(bool, Vec<TunnelRequest>), String>, _> =
        timeout(STREAM_CONFIG_TIMEOUT, async {
            let peer_accept = read_accept_line(&mut recv).await?;
            let peer_reqs = read_requests_from_stream(&mut recv)
                .await
                .map_err(|e| e.to_string())?;
            Ok((peer_accept, peer_reqs))
        })
        .await;
    let (peer_accept, peer_reqs) = match read_phase {
        Err(_) => return Err("read config: deadline exceeded".to_string()),
        Ok(Err(e)) => return Err(e),
        Ok(Ok(v)) => v,
    };

    // Canonical ordering: the client's requests first, then the server's.
    let (reqs, my_req_start) = if is_server {
        let start = peer_reqs.len();
        let mut all = peer_reqs.clone();
        all.extend_from_slice(my_reqs);
        (all, start)
    } else {
        let mut all = my_reqs.to_vec();
        all.extend(peer_reqs.iter().cloned());
        (all, 0)
    };
    LOG_TUNNEL.printf_info(&format!(
        "Received {} tunnel request(s) from peer",
        peer_reqs.len()
    ));
    Ok((peer_accept, reqs, my_req_start))
}

/// Go `RunTunnelWithConfig`: runs the tunnel feature for one session.
#[allow(clippy::too_many_arguments)]
pub async fn run_tunnel_with_config(
    cancel: &CancellationToken,
    relay_addr: &str,
    code: &str,
    local_tunnels: &[String],
    remote_tunnels: &[String],
    allow_all: bool,
    allow_listen: &[String],
    allow_forward: &[String],
    forward_max_streams: i64,
    stream_idle_timeout_override: Duration,
    cfg: &PeerConfig,
) -> Result<(), TunnelError> {
    let mut allow = TunnelAllow::default();
    allow.all = allow_all;
    allow.listen = allow_listen.to_vec();
    allow.forward = allow_forward.to_vec();
    allow.validate().map_err(TunnelError::Other)?;
    allow.resolve().await;

    let idle = stream_idle_timeout(stream_idle_timeout_override);

    let connected: Connected = connect_peer(cancel, relay_addr, code, cfg).await?;
    let Connected {
        conn, is_server, ..
    } = connected;
    // Go `defer conn.CloseWithError(0, "done")`: on every return path.
    let _closer = ConnCloser { conn: conn.clone() };
    LOG_TUNNEL.printf_success(&format!("Connected as {}", role_string(is_server)));

    let mut my_reqs: Vec<TunnelRequest> = Vec::new();
    for f in local_tunnels {
        my_reqs.push(
            parse_tunnel_request(f, "L")
                .map_err(|e| TunnelError::Other(format!("invalid -L spec {f:?}: {e}")))?,
        );
    }
    for f in remote_tunnels {
        my_reqs.push(
            parse_tunnel_request(f, "R")
                .map_err(|e| TunnelError::Other(format!("invalid -R spec {f:?}: {e}")))?,
        );
    }

    let (peer_accept, reqs, my_req_start) =
        exchange_tunnel_config(cancel, &conn, &my_reqs, &allow, is_server)
            .await
            .map_err(|e| TunnelError::Other(format!("config exchange: {e}")))?;
    let my_req_count = my_reqs.len();
    let mine = |i: usize| i >= my_req_start && i < my_req_start + my_req_count;

    if reqs.is_empty() {
        return Err(TunnelError::Other(
            "no tunnel requests exchanged".to_string(),
        ));
    }

    for (i, req) in reqs.iter().enumerate() {
        let my = mine(i);
        match (my, peer_accept) {
            (true, false) if req.typ == "L" => {
                // Peer has no allowlist (-a/-aL/-aF); tell the operator what
                // the peer needs to run to accept each of our requests.
                LOG_TUNNEL.printf_warn(&format!(
                    "Peer rejected -L {} -> {} (peer must run with -aF {} to allow)",
                    req.listen_addr, req.target_addr, req.target_addr
                ));
            }
            (true, false) if req.typ == "R" => {
                LOG_TUNNEL.printf_warn(&format!(
                    "Peer rejected -R {} -> {} (peer must run with -aL {} to allow)",
                    req.listen_addr, req.target_addr, req.listen_addr
                ));
            }
            (false, _) if !allow.accepts() => {
                LOG_TUNNEL.printf_warn(&format!(
                    "Ignoring peer request -{} {} -> {} (run with -aL/-aF to accept, or -a to allow all)",
                    req.typ, req.listen_addr, req.target_addr
                ));
            }
            (true, true) if req.typ == "R" => {
                // The peer listens on our -R address; we dial the target
                // for each inbound connection.
                LOG_TUNNEL
                    .printf_success(&format!("Tunnel forwarding to {}", bold(&req.target_addr)));
            }
            (false, _) if req.typ == "L" && allow.allows_forward(&req.target_addr) => {
                // The peer's -L: they listen; we dial their target for each
                // inbound connection.
                LOG_TUNNEL
                    .printf_success(&format!("Tunnel forwarding to {}", bold(&req.target_addr)));
            }
            _ => {}
        }
    }

    // Go `ctx, cancel := context.WithCancel(ctx); defer cancel()`.
    let session = cancel.child_token();

    // Resolve the forward max streams limit (zero means use env/default).
    let fms = if forward_max_streams > 0 {
        forward_max_streams
    } else {
        get_forward_max_streams(None)
    };
    init_outbound_guard(fms);

    // Per-session announcement state: each session announces "Tunnel N
    // established" once per spec, independent of other sessions.
    let announced: Arc<Mutex<HashMap<usize, bool>>> = Arc::new(Mutex::new(HashMap::new()));

    let conn_a = conn.clone();
    let reqs_a = reqs.clone();
    let allow_a = allow.clone();
    let session_a = session.clone();
    let announced_a = Arc::clone(&announced);
    let acceptor = tokio::spawn(async move {
        // Go: `defer func() { cancel(); wg.Done() }()` - a failure (or a
        // clean disconnect) on one side cancels the session.
        let r = run_stream_acceptor(
            &session_a,
            &conn_a,
            &reqs_a,
            my_req_start,
            my_req_count,
            &allow_a,
            fms,
            &announced_a,
            idle,
        )
        .await;
        session_a.cancel();
        r
    });

    let conn_l = conn.clone();
    let reqs_l = reqs.clone();
    let allow_l = allow.clone();
    let session_l = session.clone();
    let listener = tokio::spawn(async move {
        let r = run_tcp_listeners(
            &session_l,
            &conn_l,
            &reqs_l,
            my_req_start,
            my_req_count,
            peer_accept,
            &allow_l,
            idle,
        )
        .await;
        session_l.cancel();
        r
    });

    let (acceptor_res, listener_res) = tokio::join!(acceptor, listener);
    let acceptor_res = acceptor_res.expect("acceptor task panicked");
    let listener_res = listener_res.expect("listener task panicked");

    // A failure on one side cancels the session, which makes the other side
    // report Canceled; prefer the real error so it is not shadowed and
    // silently swallowed by the caller.
    match (acceptor_res, listener_res) {
        (Err(e), _) if !e.is_canceled() => return Err(e),
        (_, Err(e)) if !e.is_canceled() => return Err(e),
        (Err(e), _) => return Err(e),
        (Ok(()), Err(e)) => return Err(e),
        (Ok(()), Ok(())) => {}
    }
    Ok(())
}

/// Go `RunTunnel`: [`run_tunnel_with_config`] with the default
/// [`PeerConfig`].
#[allow(clippy::too_many_arguments)]
pub async fn run_tunnel(
    cancel: &CancellationToken,
    relay_addr: &str,
    code: &str,
    local_tunnels: &[String],
    remote_tunnels: &[String],
    allow_all: bool,
    allow_listen: &[String],
    allow_forward: &[String],
    forward_max_streams: i64,
    stream_idle_timeout_override: Duration,
) -> Result<(), TunnelError> {
    run_tunnel_with_config(
        cancel,
        relay_addr,
        code,
        local_tunnels,
        remote_tunnels,
        allow_all,
        allow_listen,
        allow_forward,
        forward_max_streams,
        stream_idle_timeout_override,
        &PeerConfig::default(),
    )
    .await
}

/// Go `RunStreamAcceptor`: accepts inbound QUIC streams and dispatches them
/// to [`handle_tunnel_stream`], bounded by `forward_max_streams`.
/// `my_req_start`/`my_req_count` describe the index range of this side's
/// requests within `reqs` (see [`exchange_tunnel_config`]); `announced` is
/// the per-session announcement map (see [`announce_tunnel_once`]).
#[allow(clippy::too_many_arguments)]
pub async fn run_stream_acceptor(
    cancel: &CancellationToken,
    conn: &Connection,
    reqs: &[TunnelRequest],
    my_req_start: usize,
    my_req_count: usize,
    allow: &TunnelAllow,
    forward_max_streams: i64,
    announced: &Arc<Mutex<HashMap<usize, bool>>>,
    idle: Duration,
) -> Result<(), TunnelError> {
    let guard = Arc::new(Semaphore::new(forward_max_streams.max(0) as usize));
    loop {
        let (send, recv) = tokio::select! {
            r = conn.accept_bi() => match r {
                Ok(s) => s,
                Err(e) => {
                    // Any remote close (graceful, application error 0, or
                    // abrupt) ends the session: report it as a disconnect
                    // rather than failing silently or dumping a raw quinn
                    // error.
                    if log_disconnect(&LOG_TUNNEL, &e) {
                        return Ok(());
                    }
                    return Err(TunnelError::Other(e.to_string()));
                }
            },
            () = cancel.cancelled() => return Err(TunnelError::Canceled),
        };

        let permit = tokio::select! {
            r = Arc::clone(&guard).acquire_owned() => match r {
                Ok(p) => p,
                Err(_) => return Err(TunnelError::Canceled),
            },
            () = cancel.cancelled() => {
                // A sibling failure (e.g. `run_tcp_listeners`) cancels the
                // session; bail out instead of parking forever on a full
                // guard. `send` is FINned by its drop (Go `stream.Close()`).
                return Err(TunnelError::Canceled);
            }
        };

        let cancel_h = cancel.clone();
        let reqs_h = reqs.to_vec();
        let allow_h = allow.clone();
        let announced_h = Arc::clone(announced);
        tokio::spawn(async move {
            let _permit = permit; // released when the handler finishes
            handle_tunnel_stream(
                &cancel_h,
                send,
                recv,
                &reqs_h,
                my_req_start,
                my_req_count,
                &allow_h,
                &announced_h,
                idle,
            )
            .await;
        });
    }
}

/// Go `RunTCPListeners`: starts TCP listeners for local (-L) tunnels this
/// side owns and remote (-R) tunnels the peer owns, forwarding accepted
/// connections over QUIC streams. Peer -R requests are honored only when
/// their listen address matches an `-aL` allowlist entry (or `-a` is set).
#[allow(clippy::too_many_arguments)]
pub async fn run_tcp_listeners(
    cancel: &CancellationToken,
    conn: &Connection,
    reqs: &[TunnelRequest],
    my_req_start: usize,
    my_req_count: usize,
    peer_accept: bool,
    allow: &TunnelAllow,
    idle: Duration,
) -> Result<(), TunnelError> {
    // Go `ctx, cancel := context.WithCancel(ctx); defer cancel()`.
    let session = cancel.child_token();
    let (err_tx, mut err_rx) = mpsc::unbounded_channel::<String>();

    for (i, req) in reqs.iter().enumerate() {
        let my_req = i >= my_req_start && i < my_req_start + my_req_count;
        if my_req {
            if req.typ == "R" {
                continue; // -R means peer should listen, not me
            }
            if !peer_accept {
                continue; // peer must accept my tunnels
            }
        } else {
            if req.typ == "L" {
                continue; // -L means peer should listen, not me
            }
            if !allow.allows_listen(&req.listen_addr) {
                LOG_TUNNEL.printf_warn(&format!(
                    "Ignoring peer request -R {} -> {} (add -aL {} to allow)",
                    req.listen_addr, req.target_addr, req.listen_addr
                ));
                continue;
            }
        }

        let listener = TcpListener::bind(&req.listen_addr)
            .await
            .map_err(|e| TunnelError::Other(format!("listen on {}: {e}", req.listen_addr)))?;
        // Listeners are closed when the session ends (Go
        // `go func() { <-ctx.Done(); listener.Close() }()`).

        let conn_a = conn.clone();
        let req_a = req.clone();
        let err_tx_a = err_tx.clone();
        let session_c = session.clone();
        tokio::spawn(async move {
            LOG_TUNNEL.printf_success(&format!(
                "Tunnel listening on {} ({} -> {})",
                bold(&req_a.listen_addr),
                req_a.typ,
                bold(&req_a.target_addr)
            ));
            loop {
                // Go closes the listener in a sibling goroutine when the
                // session ends, making `Accept` return an error; here the
                // accept loop itself is interrupted by the session token
                // (same observable behavior: no more connections served).
                let accept = listener.accept();
                tokio::pin!(accept);
                let r = tokio::select! {
                    r = &mut accept => r,
                    () = session_c.cancelled() => return,
                };
                let (tcp_conn, _) = match r {
                    Ok(c) => c,
                    Err(e) => {
                        if session_c.is_cancelled() {
                            return;
                        }
                        session_c.cancel();
                        let _ = err_tx_a.send(format!("accept on {}: {e}", req_a.listen_addr));
                        return;
                    }
                };
                LOG_TUNNEL.printf(&format!("New connection on {}", req_a.listen_addr));
                let conn_h = conn_a.clone();
                let session_h = session_c.clone();
                tokio::spawn(async move {
                    handle_tunnel_tcp(&session_h, &conn_h, tcp_conn, i, idle).await;
                });
            }
        });
    }

    tokio::select! {
        Some(e) = err_rx.recv() => Err(TunnelError::Other(e)),
        () = session.cancelled() => Err(TunnelError::Canceled),
    }
}

/// Go `HandleTunnelTCP`: opens a QUIC stream for a local TCP connection,
/// writing a 2-byte header with the tunnel spec index before bridging data.
async fn handle_tunnel_tcp(
    cancel: &CancellationToken,
    conn: &Connection,
    tcp: TcpStream,
    spec_idx: usize,
    idle: Duration,
) {
    // `tcp` is closed by its drop on every exit (Go `defer tcpConn.Close()`).
    if spec_idx > u16::MAX as usize {
        LOG_TUNNEL.printf_warn(&format!("Spec index {spec_idx} exceeds uint16 max"));
        return;
    }

    // Capture the semaphore once so acquire and release use the same
    // instance even if a later session re-creates it via
    // `init_outbound_guard`.
    let guard = get_outbound_guard();
    let _permit = match guard.try_acquire_owned() {
        Ok(p) => p,
        Err(_) => {
            LOG_TUNNEL.printf_warn(&format!(
                "Outbound stream limit reached, rejecting tunnel {spec_idx}"
            ));
            return;
        }
    };

    let stream = tokio::select! {
        r = conn.open_bi() => r,
        () = cancel.cancelled() => return,
    };
    let (mut send, recv) = match stream {
        Ok(s) => s,
        Err(e) => {
            LOG_TUNNEL.printf_error(&format!("Opening stream for tunnel {spec_idx} failed: {e}"));
            return;
        }
    };

    let header = (spec_idx as u16).to_be_bytes();
    if let Err(e) = send.write_all(&header).await {
        // `send` is FINned by its drop (Go `stream.Close()`).
        LOG_TUNNEL.printf_error(&format!("Writing header for tunnel {spec_idx} failed: {e}"));
        return;
    }

    tunnel_copy(tcp, send, recv, idle).await;
    // `send` is FINned by its drop (Go `stream.Close()`); `_permit` is
    // released here (Go `defer func() { <-guard }()`).
}

/// Go `HandleTunnelStream`: reads the stream header and dials the
/// corresponding tunnel target, bridging the TCP connection and QUIC stream
/// bidirectionally.
#[allow(clippy::too_many_arguments)]
pub async fn handle_tunnel_stream(
    cancel: &CancellationToken,
    send: SendStream,
    recv: RecvStream,
    reqs: &[TunnelRequest],
    my_req_start: usize,
    my_req_count: usize,
    allow: &TunnelAllow,
    announced: &Arc<Mutex<HashMap<usize, bool>>>,
    idle: Duration,
) {
    let dial_timeout = Duration::from_millis(env_duration_ms(
        DIAL_TIMEOUT_ENV,
        DIAL_TIMEOUT.as_millis() as u64,
    ));
    handle_tunnel_stream_with_timeout(
        cancel,
        send,
        recv,
        reqs,
        my_req_start,
        my_req_count,
        allow,
        announced,
        idle,
        dial_timeout,
    )
    .await;
}

/// [`handle_tunnel_stream`] with an explicit dial timeout.
///
/// The public entry point derives the timeout from
/// `QVOLE_DIAL_TIMEOUT_MS`; tests call this directly because the crate
/// forbids `unsafe` (so `std::env::set_var` is unavailable) and a
/// deterministic short timeout keeps the dial tests fast.
#[allow(clippy::too_many_arguments)]
async fn handle_tunnel_stream_with_timeout(
    cancel: &CancellationToken,
    send: SendStream,
    mut recv: RecvStream,
    reqs: &[TunnelRequest],
    my_req_start: usize,
    my_req_count: usize,
    allow: &TunnelAllow,
    announced: &Arc<Mutex<HashMap<usize, bool>>>,
    idle: Duration,
    dial_timeout_val: Duration,
) {
    // `send` is FINned by its drop on every exit (Go `defer stream.Close()`).
    let mut header = [0u8; 2];
    let read_res = timeout(STREAM_HEADER_TIMEOUT, recv.read_exact(&mut header)).await;
    if read_res.is_err() || read_res.as_ref().is_err() {
        return;
    }
    let idx = u16::from_be_bytes(header) as usize;
    if idx >= reqs.len() {
        LOG_TUNNEL.printf_warn(&format!(
            "Invalid tunnel index {idx} (max {})",
            reqs.len().saturating_sub(1)
        ));
        return;
    }

    let req = &reqs[idx];

    // Dial for peer's -L (they listened) or my -R (they listened on my
    // behalf).
    let my_req = idx >= my_req_start && idx < my_req_start + my_req_count;
    if req.typ == "L" && my_req {
        return; // I listened for my -L; peer shouldn't open streams for it
    }
    if req.typ == "R" && !my_req {
        return; // I listened for peer's -R; peer shouldn't open streams for it
    }

    // Allowlist check: peer-initiated tunnels are honored only when the
    // target matches an -aF entry (or -a is set). Peer -R requests returned
    // earlier, so only peer -L requests reach this point. The target is
    // resolved once and we dial only the allowed IP literal(s), so the
    // allowlist check and the connect use the same address and a
    // DNS-rebinding / host-alias spoof cannot reach an unintended target.
    let mut tcp = None;
    let mut dial_err: Option<String> = None;
    if my_req {
        // My own -R request: the peer connects to the address I declared
        // and I dial the target on my side. No allowlist applies to my own
        // target.
        match dial_tcp(cancel, dial_timeout_val, &req.target_addr).await {
            Ok(c) => tcp = Some(c),
            Err(e) => dial_err = Some(e),
        }
    } else {
        let (ips, port_str, ok) = allow.forward_ips(&req.target_addr).await;
        if !ok {
            LOG_TUNNEL.printf_warn(&format!(
                "Tunnel rejected: {} -> {} (add -aF {} to allow)",
                req.listen_addr, req.target_addr, req.target_addr
            ));
            return;
        }
        match port_str.parse::<u16>() {
            Ok(port) => {
                for ip in &ips {
                    let addr = SocketAddr::new(*ip, port);
                    match dial_tcp(cancel, dial_timeout_val, &addr.to_string()).await {
                        Ok(c) => {
                            tcp = Some(c);
                            break;
                        }
                        Err(e) => dial_err = Some(e),
                    }
                }
            }
            Err(_) => dial_err = Some(format!("invalid port {port_str:?}")),
        }
    }
    let tcp = match tcp {
        Some(c) => c,
        None => {
            LOG_TUNNEL.printf_error(&format!(
                "Connecting to {} for tunnel {} failed: {}",
                bold(&req.target_addr),
                idx,
                dial_err.unwrap_or_else(|| "<nil>".to_string())
            ));
            return;
        }
    };

    // Announce the first successful connection through this tunnel spec
    // once; later connections only log at debug level so busy tunnels don't
    // spam.
    announce_tunnel_once(announced, idx, &req.target_addr);
    LOG_TUNNEL.printf(&format!(
        "Tunnel {idx} connection: ↔ {}",
        bold(&req.target_addr)
    ));

    // Bridge the TCP connection and QUIC stream. When `idle > 0` it is
    // refreshed on activity so only silent streams are reaped; when 0
    // (default) the forwarded connection relies on the connection-level
    // QUIC keepalive/idle timeouts and is never force-closed.
    tunnel_copy(tcp, send, recv, idle).await;
}

/// Dial a TCP target with a timeout, cancellable by `cancel`.
async fn dial_tcp(
    cancel: &CancellationToken,
    dial_timeout: Duration,
    target: &str,
) -> Result<TcpStream, String> {
    let dial = TcpStream::connect(target);
    tokio::select! {
        r = timeout(dial_timeout, dial) => match r {
            Ok(Ok(c)) => Ok(c),
            Ok(Err(e)) => Err(e.to_string()),
            Err(_) => Err(format!("dial {target}: deadline exceeded")),
        },
        () = cancel.cancelled() => Err("canceled".to_string()),
    }
}

/// Closes the QUIC connection with `(0, "done")` when dropped (Go
/// `defer conn.CloseWithError(0, "done")`).
struct ConnCloser {
    conn: Connection,
}

impl Drop for ConnCloser {
    fn drop(&mut self) {
        self.conn.close(VarInt::from_u32(0), b"done");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::quic_pair;
    use tokio::io::AsyncWriteExt;

    /// Write a big-endian spec index header, FIN, and hand the accepted
    /// stream to [`handle_tunnel_stream`] with the given parameters.
    /// Returns once the handler finishes (bounded by `handler_timeout`).
    #[allow(clippy::too_many_arguments)]
    async fn spawn_stream_handler(
        client: &Connection,
        server: &Connection,
        idx: u16,
        reqs: &[TunnelRequest],
        my_req_start: usize,
        my_req_count: usize,
        allow: &TunnelAllow,
        announced: &Arc<Mutex<HashMap<usize, bool>>>,
        idle: Duration,
        dial_timeout: Duration,
        handler_timeout: Duration,
    ) {
        let (mut send, _recv) = client.open_bi().await.expect("open_bi should succeed");
        let mut header = [0u8; 2];
        header.copy_from_slice(&idx.to_be_bytes());
        send.write_all(&header).await.expect("write header");
        let _ = send.finish();

        let (h_send, h_recv) = server.accept_bi().await.expect("accept_bi should succeed");
        let cancel = CancellationToken::new();
        let allow_c = allow.clone();
        let reqs_c = reqs.to_vec();
        let announced_c = Arc::clone(announced);
        let handler = tokio::spawn(async move {
            handle_tunnel_stream_with_timeout(
                &cancel,
                h_send,
                h_recv,
                &reqs_c,
                my_req_start,
                my_req_count,
                &allow_c,
                &announced_c,
                idle,
                dial_timeout,
            )
            .await;
        });
        tokio::time::timeout(handler_timeout, handler)
            .await
            .expect("handler should return for this case")
            .expect("handler task should not panic");
    }

    /// TestHandleTunnelStream_InvalidIndex
    #[tokio::test]
    async fn test_handle_tunnel_stream_invalid_index() {
        let (client_conn, client_ep, server_conn, server_ep) = quic_pair().await;
        let _keep = (
            client_ep,
            server_ep,
            client_conn.clone(),
            server_conn.clone(),
        );

        let reqs = vec![TunnelRequest {
            typ: "L".into(),
            listen_addr: "127.0.0.1:8080".into(),
            target_addr: "127.0.0.1:80".into(),
        }];
        let announced = Arc::new(Mutex::new(HashMap::new()));
        spawn_stream_handler(
            &client_conn,
            &server_conn,
            (reqs.len() + 5) as u16,
            &reqs,
            0,
            0,
            &TunnelAllow::default(),
            &announced,
            Duration::ZERO,
            DIAL_TIMEOUT,
            Duration::from_secs(2),
        )
        .await;
    }

    /// TestHandleTunnelStream_WrongDirection
    #[tokio::test]
    async fn test_handle_tunnel_stream_wrong_direction() {
        let (client_conn, client_ep, server_conn, server_ep) = quic_pair().await;
        let _keep = (
            client_ep,
            server_ep,
            client_conn.clone(),
            server_conn.clone(),
        );

        let reqs = vec![TunnelRequest {
            typ: "L".into(),
            listen_addr: "127.0.0.1:8080".into(),
            target_addr: "8.8.8.8:53".into(),
        }];
        let announced = Arc::new(Mutex::new(HashMap::new()));
        // Initiator has type L, so shouldDial = (spec.Type == "R") = false.
        spawn_stream_handler(
            &client_conn,
            &server_conn,
            0,
            &reqs,
            0,
            1,
            &TunnelAllow::default(),
            &announced,
            Duration::ZERO,
            DIAL_TIMEOUT,
            Duration::from_secs(2),
        )
        .await;
    }

    /// TestHandleTunnelStream_AllowlistRejection
    #[tokio::test]
    async fn test_handle_tunnel_stream_allowlist_rejection() {
        let (client_conn, client_ep, server_conn, server_ep) = quic_pair().await;
        let _keep = (
            client_ep,
            server_ep,
            client_conn.clone(),
            server_conn.clone(),
        );

        let reqs = vec![TunnelRequest {
            typ: "L".into(),
            listen_addr: "127.0.0.1:8080".into(),
            target_addr: "192.0.2.1:9999".into(),
        }];
        let announced = Arc::new(Mutex::new(HashMap::new()));

        // Peer -L spec (my_req_count = 0) targeting an address with an
        // empty --allow-forward allowlist: rejected without dialing.
        spawn_stream_handler(
            &client_conn,
            &server_conn,
            0,
            &reqs,
            0,
            0,
            &TunnelAllow::default(),
            &announced,
            Duration::ZERO,
            DIAL_TIMEOUT,
            Duration::from_secs(2),
        )
        .await;

        // With the target allowlisted, the stream is dialed (to an
        // unroutable address, so the handler returns after the 10s dial
        // timeout, not rejection).
        let mut allow = TunnelAllow::default();
        allow.forward = vec!["192.0.2.1:9999".to_string()];
        allow.resolve().await;
        spawn_stream_handler(
            &client_conn,
            &server_conn,
            0,
            &reqs,
            0,
            0,
            &allow,
            &announced,
            Duration::ZERO,
            // Short, explicit dial timeout: the target is unroutable, so a
            // real dial attempt times out here rather than after 10s.
            Duration::from_millis(250),
            Duration::from_secs(15),
        )
        .await;
    }

    /// TestAnnounceTunnelOnce
    #[test]
    fn test_announce_tunnel_once() {
        let announced = Arc::new(Mutex::new(HashMap::new()));

        use std::sync::atomic::{AtomicBool, Ordering as AOrdering};
        const IDX: usize = 7;
        const N: usize = 32;
        let results: Vec<AtomicBool> = (0..N).map(|_| AtomicBool::new(false)).collect();
        let results_ref = &results;
        let announced_ref = &announced;
        std::thread::scope(|s| {
            for slot in results_ref.iter() {
                s.spawn(move || {
                    slot.store(
                        announce_tunnel_once(announced_ref, IDX, "localhost:8080"),
                        AOrdering::SeqCst,
                    );
                });
            }
        });

        let firsts = results.iter().filter(|c| c.load(AOrdering::SeqCst)).count();
        assert_eq!(firsts, 1, "exactly one thread should announce");

        // A different spec announces independently; repeats stay silent.
        assert!(
            announce_tunnel_once(&announced, IDX + 1, "localhost:80"),
            "new spec should announce on first connection"
        );
        assert!(
            !announce_tunnel_once(&announced, IDX + 1, "localhost:80"),
            "spec should not announce again"
        );

        // A separate session map announces independently of the first
        // session, including for the same spec index (per-session state,
        // not global).
        let other = Mutex::new(HashMap::new());
        assert!(
            announce_tunnel_once(&other, IDX, "localhost:9090"),
            "a fresh session should announce again for the same spec index"
        );
        assert!(
            !announce_tunnel_once(&other, IDX, "localhost:9090"),
            "spec should not announce twice within one session"
        );
    }

    /// TestHandleTunnelTCP_SpecIndexUint16Truncation
    #[test]
    fn test_handle_tunnel_tcp_spec_index_uint16_truncation() {
        // `as u16` truncates large indices to uint16, mirroring
        // `binary.BigEndian.PutUint16(header, uint16(specIdx))`.
        assert_eq!(65536u32 as u16, 0, "uint16(65536) wraps around to 0");
        assert_eq!(65535u32 as u16, 65535, "uint16 max is preserved");
    }

    /// TestHandleTunnelTCP_Success
    #[tokio::test]
    async fn test_handle_tunnel_tcp_success() {
        let (client_conn, client_ep, server_conn, server_ep) = quic_pair().await;
        let _keep = (
            client_ep,
            server_ep,
            client_conn.clone(),
            server_conn.clone(),
        );

        // Loopback TCP pair (the Go test uses `net.Pipe`).
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("local_addr");
        let mut local = TcpStream::connect(addr).await.expect("connect");
        let remote = listener.accept().await.expect("accept").0;

        // Start HandleTunnelTCP on the server side; it opens a QUIC stream
        // pointing at the client conn and copies data to/from the TCP side.
        let cancel = CancellationToken::new();
        let cancel_h = cancel.clone();
        let conn_h = server_conn.clone();
        tokio::spawn(async move {
            handle_tunnel_tcp(&cancel_h, &conn_h, remote, 42, Duration::ZERO).await;
        });

        // Client side: accept the stream, verify header, exchange data.
        let (mut send, mut recv) = client_conn.accept_bi().await.expect("accept_bi");

        let mut header = [0u8; 2];
        tokio::time::timeout(Duration::from_secs(2), recv.read_exact(&mut header))
            .await
            .expect("header read timed out")
            .expect("read header");
        let idx = u16::from_be_bytes(header) as usize;
        assert_eq!(idx, 42, "expected spec index 42");

        // Write through the stream: should reach the TCP side.
        send.write_all(b"hello-tunnel-tcp")
            .await
            .expect("write stream");
        let mut buf = [0u8; 64];
        let mut total = 0;
        while total < b"hello-tunnel-tcp".len() {
            let n = tokio::time::timeout(
                Duration::from_secs(2),
                tokio::io::AsyncReadExt::read(&mut local, &mut buf[total..]),
            )
            .await
            .expect("tcp read timed out")
            .expect("read tcp");
            total += n;
        }
        assert_eq!(&buf[..total], b"hello-tunnel-tcp");

        // Write back through the TCP side: should reach the stream.
        local
            .write_all(b"goodbye-tunnel-tcp")
            .await
            .expect("write tcp");
        let mut total = 0;
        while total < b"goodbye-tunnel-tcp".len() {
            let n = tokio::time::timeout(
                Duration::from_secs(2),
                tokio::io::AsyncReadExt::read(&mut recv, &mut buf[total..]),
            )
            .await
            .expect("stream read timed out")
            .expect("read stream");
            total += n;
        }
        assert_eq!(&buf[..total], b"goodbye-tunnel-tcp");
    }

    /// TestHandleTunnelTCP_OpenStreamError
    #[tokio::test]
    async fn test_handle_tunnel_tcp_open_stream_error() {
        let (_client_conn, _client_ep, server_conn, server_ep) = quic_pair().await;
        let _keep = (_client_ep, server_ep, server_conn.clone());
        // Close the server conn so open_bi fails.
        server_conn.close(VarInt::from_u32(0), b"test");

        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("local_addr");
        let _local = TcpStream::connect(addr).await.expect("connect");
        let remote = listener.accept().await.expect("accept").0;

        let cancel = CancellationToken::new();
        cancel.cancel(); // A canceled ctx triggers an immediate return.

        // Should not panic, just return.
        handle_tunnel_tcp(&cancel, &server_conn, remote, 0, Duration::ZERO).await;
    }

    /// TestHandleTunnelTCP_WriteHeaderError
    #[tokio::test]
    async fn test_handle_tunnel_tcp_write_header_error() {
        let (client_conn, client_ep, server_conn, server_ep) = quic_pair().await;
        let _keep = (client_ep, server_ep, client_conn, server_conn.clone());
        // Close the server conn so the write fails.
        server_conn.close(VarInt::from_u32(0), b"test");

        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("local_addr");
        let _local = TcpStream::connect(addr).await.expect("connect");
        let remote = listener.accept().await.expect("accept").0;

        let cancel = CancellationToken::new();
        // Should not panic; open_bi fails or the write fails.
        handle_tunnel_tcp(&cancel, &server_conn, remote, 0, Duration::ZERO).await;
    }

    /// TestHandleTunnelStream_DialTimeout. The Go test was originally
    /// degenerate: with `myReqCount = 0` an "R" request is a peer -R spec,
    /// which returns before the dial. It now passes `myReqCount = 1` (my -R
    /// path) with a short dial timeout, so the dial actually runs.
    #[tokio::test]
    async fn test_handle_tunnel_stream_dial_timeout() {
        let (client_conn, client_ep, server_conn, server_ep) = quic_pair().await;
        let _keep = (
            client_ep,
            server_ep,
            client_conn.clone(),
            server_conn.clone(),
        );

        // TEST-NET-1 (192.0.2.0/24) is unroutable; the dial blackholes and
        // hits the deadline.
        let reqs = vec![TunnelRequest {
            typ: "R".into(),
            listen_addr: "127.0.0.1:8080".into(),
            target_addr: "192.0.2.1:9999".into(),
        }];
        let announced = Arc::new(Mutex::new(HashMap::new()));
        let started = std::time::Instant::now();
        spawn_stream_handler(
            &client_conn,
            &server_conn,
            0,
            &reqs,
            0,
            1, // my -R: the handler dials the declared target
            &TunnelAllow::default(),
            &announced,
            Duration::ZERO,
            Duration::from_millis(250),
            Duration::from_secs(5),
        )
        .await;
        let elapsed = started.elapsed();
        // A degenerate (no-dial) run would return almost instantly; the real
        // dial holds for the timeout. Keep a loose upper bound for slow hosts.
        assert!(
            elapsed >= Duration::from_millis(200),
            "handler returned in {elapsed:?}; the dial path was not exercised"
        );
        assert!(
            elapsed < Duration::from_secs(5),
            "HandleTunnelStream did not return promptly: {elapsed:?}"
        );
    }

    /// TestHandleTunnelStream_DialsTarget: deterministic proof that the dial
    /// path is reached and connects - the handler dials a real local
    /// listener, which accepts the connection.
    #[tokio::test]
    async fn test_handle_tunnel_stream_dials_target() {
        let (client_conn, client_ep, server_conn, server_ep) = quic_pair().await;
        let _keep = (
            client_ep,
            server_ep,
            client_conn.clone(),
            server_conn.clone(),
        );

        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let target = listener.local_addr().expect("local_addr");

        // my -R: dial the target I declared; no allowlist applies.
        let reqs = vec![TunnelRequest {
            typ: "R".into(),
            listen_addr: "127.0.0.1:8080".into(),
            target_addr: target.to_string(),
        }];
        let announced = Arc::new(Mutex::new(HashMap::new()));

        let client_c = client_conn.clone();
        let server_c = server_conn.clone();
        let reqs_c = reqs.clone();
        let announced_c = Arc::clone(&announced);
        let handle = tokio::spawn(async move {
            spawn_stream_handler(
                &client_c,
                &server_c,
                0,
                &reqs_c,
                0,
                1,
                &TunnelAllow::default(),
                &announced_c,
                Duration::ZERO,
                Duration::from_secs(2),
                Duration::from_secs(5),
            )
            .await;
        });

        // The dial must actually land: accept completes.
        let (tcp, _peer) = timeout(Duration::from_secs(5), listener.accept())
            .await
            .expect("handler never dialed the target")
            .expect("accept failed");
        // Close the TCP side so the handler's bridge completes; the client
        // stream send half was already FINed by the helper.
        drop(tcp);
        handle.await.expect("handler task panicked");
    }

    /// TestHandleTunnelStream_ShortHeader
    #[tokio::test]
    async fn test_handle_tunnel_stream_short_header() {
        let (client_conn, client_ep, server_conn, server_ep) = quic_pair().await;
        let _keep = (
            client_ep,
            server_ep,
            client_conn.clone(),
            server_conn.clone(),
        );

        let reqs = vec![TunnelRequest {
            typ: "L".into(),
            listen_addr: "127.0.0.1:8080".into(),
            target_addr: "8.8.8.8:53".into(),
        }];
        let announced = Arc::new(Mutex::new(HashMap::new()));

        // Only one header byte, then FIN: ReadFull fails with EOF.
        let (mut send, _recv) = client_conn.open_bi().await.expect("open_bi");
        send.write_all(&[0x00]).await.expect("write");
        let _ = send.finish();
        let (h_send, h_recv) = server_conn.accept_bi().await.expect("accept_bi");
        let cancel = CancellationToken::new();
        let handler = tokio::spawn(async move {
            handle_tunnel_stream(
                &cancel,
                h_send,
                h_recv,
                &reqs,
                0,
                1,
                &TunnelAllow::default(),
                &announced,
                Duration::ZERO,
            )
            .await;
        });
        tokio::time::timeout(Duration::from_secs(2), handler)
            .await
            .expect("handler should return for short header")
            .expect("handler task should not panic");
    }

    /// TestHandleTunnelStream_PeerRType
    #[tokio::test]
    async fn test_handle_tunnel_stream_peer_r_type() {
        let (client_conn, client_ep, server_conn, server_ep) = quic_pair().await;
        let _keep = (
            client_ep,
            server_ep,
            client_conn.clone(),
            server_conn.clone(),
        );

        let reqs = vec![TunnelRequest {
            typ: "R".into(),
            listen_addr: "127.0.0.1:8080".into(),
            target_addr: "8.8.8.8:53".into(),
        }];
        let announced = Arc::new(Mutex::new(HashMap::new()));
        // my_req_count = 0: this is a peer spec; req.Type == "R" && !my_req
        // -> return without dialing.
        spawn_stream_handler(
            &client_conn,
            &server_conn,
            0,
            &reqs,
            0,
            0,
            &TunnelAllow::default(),
            &announced,
            Duration::ZERO,
            DIAL_TIMEOUT,
            Duration::from_secs(2),
        )
        .await;
    }

    /// TestTunnelRunStreamAcceptor_ConnectionClosed
    #[tokio::test]
    async fn test_run_stream_acceptor_connection_closed() {
        let (client_conn, client_ep, server_conn, server_ep) = quic_pair().await;
        let _keep = (
            client_ep,
            server_ep,
            client_conn.clone(),
            server_conn.clone(),
        );

        let reqs = vec![TunnelRequest {
            typ: "L".into(),
            listen_addr: "127.0.0.1:8080".into(),
            target_addr: "8.8.8.8:53".into(),
        }];

        // Close the connection with a peer application error: this is a
        // remote disconnect, not a fatal error, so run_stream_acceptor
        // should end cleanly.
        client_conn.close(VarInt::from_u32(1), b"test");

        let cancel = CancellationToken::new();
        let announced = Arc::new(Mutex::new(HashMap::new()));
        let err = run_stream_acceptor(
            &cancel,
            &server_conn,
            &reqs,
            0,
            1,
            &TunnelAllow::default(),
            200,
            &announced,
            Duration::ZERO,
        )
        .await;
        assert!(
            err.is_ok(),
            "expected nil error on peer disconnect, got {err:?}"
        );
    }

    /// TestRunStreamAcceptor_GuardFullContextCancel
    #[tokio::test]
    async fn test_run_stream_acceptor_guard_full_context_cancel() {
        let (client_conn, client_ep, server_conn, server_ep) = quic_pair().await;
        let _keep = (
            client_ep,
            server_ep,
            client_conn.clone(),
            server_conn.clone(),
        );

        let reqs = vec![TunnelRequest {
            typ: "L".into(),
            listen_addr: "127.0.0.1:8080".into(),
            target_addr: "8.8.8.8:53".into(),
        }];

        // Fill the single guard slot with a stream whose handler blocks
        // waiting for a header, then open a second stream so the acceptor
        // parks on the full guard.
        let s1 = client_conn.open_bi().await.expect("open stream 1");
        let s2 = client_conn.open_bi().await.expect("open stream 2");
        let (s1, _) = s1;
        let (s2, _) = s2;

        let cancel = CancellationToken::new();
        let announced = Arc::new(Mutex::new(HashMap::new()));
        let cancel_h = cancel.clone();
        let conn_h = server_conn.clone();
        let reqs_h = reqs.clone();
        let announced_h = Arc::clone(&announced);
        let acceptor = tokio::spawn(async move {
            run_stream_acceptor(
                &cancel_h,
                &conn_h,
                &reqs_h,
                0,
                1,
                &TunnelAllow::default(),
                1,
                &announced_h,
                Duration::ZERO,
            )
            .await
        });

        // Let the acceptor accept s1 (occupying the guard) and park on s2.
        tokio::time::sleep(Duration::from_millis(200)).await;
        cancel.cancel();

        match tokio::time::timeout(Duration::from_secs(3), acceptor).await {
            Ok(Ok(Err(TunnelError::Canceled))) => {}
            other => panic!("expected Canceled, got {other:?}"),
        }
        let _ = (s1, s2);
    }

    /// TestTunnelRunTCPListeners_BindFailure
    #[tokio::test]
    async fn test_run_tcp_listeners_bind_failure() {
        // First, bind a port to create a conflict.
        let used = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let used_port = used.local_addr().expect("local_addr").port();

        let (_client_conn, _client_ep, server_conn, server_ep) = quic_pair().await;
        let _keep = (server_ep, server_conn.clone());

        let reqs = vec![TunnelRequest {
            typ: "L".into(),
            listen_addr: format!("127.0.0.1:{used_port}"),
            target_addr: "8.8.8.8:53".into(),
        }];

        let cancel = CancellationToken::new();
        let err = run_tcp_listeners(
            &cancel,
            &server_conn,
            &reqs,
            0,
            1,
            true,
            &TunnelAllow::default(),
            Duration::ZERO,
        )
        .await;
        assert!(err.is_err(), "expected error for port already in use");
    }

    /// TestStreamIdleTimeout_Configurable
    #[test]
    fn test_stream_idle_timeout_configurable() {
        // Disabled by default (override 0, env absent).
        assert_eq!(
            stream_idle_timeout_from(Duration::ZERO, None),
            Duration::ZERO,
            "default disabled"
        );

        // Enabled in milliseconds.
        assert_eq!(
            stream_idle_timeout_from(Duration::ZERO, Some("300000")),
            Duration::from_secs(300),
            "300000ms = 5m"
        );

        // Invalid (negative) and non-numeric values fall back to disabled.
        assert_eq!(
            stream_idle_timeout_from(Duration::ZERO, Some("-100")),
            Duration::ZERO,
            "negative falls back"
        );
        assert_eq!(
            stream_idle_timeout_from(Duration::ZERO, Some("abc")),
            Duration::ZERO,
            "non-numeric falls back"
        );

        // A non-zero override takes precedence over the env var.
        assert_eq!(
            stream_idle_timeout_from(Duration::from_secs(7), Some("300000")),
            Duration::from_secs(7),
            "override wins"
        );
    }

    /// TestHandleTunnelTCP_ActiveTransferNotCapped: with the stream idle
    /// timeout enabled, an actively transferring pipe is not torn down -
    /// the deadline is refreshed on traffic, so it survives well past the
    /// configured window.
    #[tokio::test]
    async fn test_handle_tunnel_tcp_active_transfer_not_capped() {
        let (client_conn, client_ep, server_conn, server_ep) = quic_pair().await;
        let _keep = (
            client_ep,
            server_ep,
            client_conn.clone(),
            server_conn.clone(),
        );

        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("local_addr");
        let mut local = TcpStream::connect(addr).await.expect("connect");
        let remote = listener.accept().await.expect("accept").0;

        let cancel = CancellationToken::new();
        let cancel_h = cancel.clone();
        let conn_h = server_conn.clone();
        tokio::spawn(async move {
            handle_tunnel_tcp(&cancel_h, &conn_h, remote, 42, Duration::from_secs(1)).await;
        });

        let (mut send, mut recv) = client_conn.accept_bi().await.expect("accept_bi");
        let mut header = [0u8; 2];
        recv.read_exact(&mut header).await.expect("header");

        // Pump data continuously for well past the window; with a refreshed
        // deadline the pipe must survive, whereas an absolute-cap regression
        // would tear it down.
        let end = std::time::Instant::now() + Duration::from_millis(2500);
        let mut one = [0u8; 1];
        while std::time::Instant::now() < end {
            send.write_all(b"x").await.expect("write stream");
            let n = tokio::time::timeout(Duration::from_secs(2), local.read(&mut one))
                .await
                .expect("tcp read timed out (pipe torn down?)")
                .expect("read tcp (pipe torn down?)");
            assert!(n >= 1);
        }
    }

    /// TestHandleTunnelTCP_SilentStreamReaped: with the stream idle timeout
    /// enabled, a stream that goes completely silent is reaped after the
    /// window.
    ///
    /// Note: the Go test asserts `err != nil` from `stream.Read`, which
    /// holds because Go's read returns `io.EOF` (a non-nil error) once the
    /// server FINs the stream after reaping. In Rust/tokio the same event
    /// is `Ok(0)`, so we assert EOF here (semantically identical).
    #[tokio::test]
    async fn test_handle_tunnel_tcp_silent_stream_reaped() {
        let (client_conn, client_ep, server_conn, server_ep) = quic_pair().await;
        let _keep = (
            client_ep,
            server_ep,
            client_conn.clone(),
            server_conn.clone(),
        );

        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("local_addr");
        let _local = TcpStream::connect(addr).await.expect("connect");
        let remote = listener.accept().await.expect("accept").0;

        let cancel = CancellationToken::new();
        let cancel_h = cancel.clone();
        let conn_h = server_conn.clone();
        tokio::spawn(async move {
            handle_tunnel_tcp(&cancel_h, &conn_h, remote, 42, Duration::from_millis(300)).await;
        });

        let (_send, mut recv) = client_conn.accept_bi().await.expect("accept_bi");
        let mut header = [0u8; 2];
        recv.read_exact(&mut header).await.expect("header");

        // No data after the header: the tunnel side must reap the silent
        // stream after the idle window, then FIN it.
        tokio::time::sleep(Duration::from_millis(1200)).await;
        let mut b = [0u8; 1];
        let n = tokio::time::timeout(
            Duration::from_secs(2),
            tokio::io::AsyncReadExt::read(&mut recv, &mut b),
        )
        .await
        .expect("stream read timed out")
        .expect("read stream");
        assert_eq!(
            n, 0,
            "expected silent stream to be reaped (FIN) after the idle window"
        );
    }

    /// TestInitOutboundGuard_ResizesPerSession
    #[test]
    fn test_init_outbound_guard_resizes_per_session() {
        // Restore the default-sized guard so other tests are unaffected.
        let restore = get_forward_max_streams(None);

        init_outbound_guard(5);
        assert_eq!(
            get_outbound_guard().available_permits(),
            5,
            "guard capacity 5"
        );

        // A later session with a different limit must re-create the guard
        // rather than keeping the first session's size.
        init_outbound_guard(9);
        assert_eq!(
            get_outbound_guard().available_permits(),
            9,
            "guard capacity 9"
        );

        // Same size keeps the existing semaphore (capacity unchanged).
        init_outbound_guard(9);
        assert_eq!(
            get_outbound_guard().available_permits(),
            9,
            "same-size guard kept"
        );

        init_outbound_guard(restore);
    }

    /// ExchangeTunnelConfig_TooManySpecs
    #[tokio::test]
    async fn test_exchange_tunnel_config_too_many_specs() {
        let reqs: Vec<TunnelRequest> = (0..MAX_TUNNEL_REQUESTS + 1)
            .map(|_| TunnelRequest {
                typ: "L".into(),
                listen_addr: "127.0.0.1:8080".into(),
                target_addr: "8.8.8.8:53".into(),
            })
            .collect();

        let (conn, _ce, _sc, _se) = quic_pair().await;
        let _keep = (conn.clone(), _ce, _sc, _se);

        let cancel = CancellationToken::new();
        let err = exchange_tunnel_config(&cancel, &conn, &reqs, &TunnelAllow::default(), false)
            .await
            .expect_err("should reject too many requests");
        assert!(
            err.contains("too many tunnel requests"),
            "unexpected error: {err}"
        );
    }

    /// ExchangeTunnelConfig_InitiatorAndResponder: both sides exchange real
    /// config through [`exchange_tunnel_config`] (the Go test hand-rolls the
    /// wire protocol on one side; both sides here use the real function).
    #[tokio::test]
    async fn test_exchange_tunnel_config_initiator_and_responder() {
        let (client_conn, client_ep, server_conn, server_ep) = quic_pair().await;
        let _keep = (
            client_ep,
            server_ep,
            client_conn.clone(),
            server_conn.clone(),
        );

        let client_reqs = vec![TunnelRequest {
            typ: "L".into(),
            listen_addr: "127.0.0.1:8080".into(),
            target_addr: "8.8.8.8:53".into(),
        }];
        let server_reqs = vec![TunnelRequest {
            typ: "R".into(),
            listen_addr: "127.0.0.1:9022".into(),
            target_addr: "93.184.216.34:22".into(),
        }];

        let cancel = CancellationToken::new();

        let cancel_c = cancel.clone();
        let conn_c = client_conn.clone();
        let client_task = tokio::spawn(async move {
            let mut allow = TunnelAllow::default();
            allow.all = true;
            exchange_tunnel_config(&cancel_c, &conn_c, &client_reqs, &allow, false).await
        });
        let cancel_s = cancel.clone();
        let conn_s = server_conn.clone();
        let server_task = tokio::spawn(async move {
            let mut allow = TunnelAllow::default();
            allow.all = true;
            exchange_tunnel_config(&cancel_s, &conn_s, &server_reqs, &allow, true).await
        });

        let (cr, sr) = tokio::join!(client_task, server_task);
        let (client_accept, client_reqs, client_start) =
            cr.expect("client task").expect("client error");
        let (server_accept, server_reqs, server_start) =
            sr.expect("server task").expect("server error");

        // Both sides are willing to accept requests, so both see
        // peerAccept=true.
        assert!(client_accept, "expected client peerAccept=true");
        assert!(server_accept, "expected server peerAccept=true");

        assert_eq!(
            client_reqs.len(),
            2,
            "client got {} requests, want 2",
            client_reqs.len()
        );
        assert_eq!(
            server_reqs.len(),
            2,
            "server got {} requests, want 2",
            server_reqs.len()
        );
        assert_eq!(client_reqs[0].typ, "L");
        assert_eq!(client_reqs[1].typ, "R");
        assert_eq!(server_reqs[0].typ, "L");
        assert_eq!(server_reqs[1].typ, "R");
        assert_eq!(client_start, 0);
        assert_eq!(server_start, 1);
    }

    /// ExchangeTunnelConfig_BothSidesRequests (canonical ordering + myStart).
    #[tokio::test]
    async fn test_exchange_tunnel_config_both_sides_requests() {
        let (client_conn, client_ep, server_conn, server_ep) = quic_pair().await;
        let _keep = (
            client_ep,
            server_ep,
            client_conn.clone(),
            server_conn.clone(),
        );

        let client_reqs = vec![TunnelRequest {
            typ: "L".into(),
            listen_addr: "127.0.0.1:8080".into(),
            target_addr: "8.8.8.8:53".into(),
        }];
        let server_reqs = vec![TunnelRequest {
            typ: "R".into(),
            listen_addr: "127.0.0.1:9022".into(),
            target_addr: "93.184.216.34:22".into(),
        }];

        let cancel = CancellationToken::new();
        let cancel_c = cancel.clone();
        let conn_c = client_conn.clone();
        let client_task = tokio::spawn(async move {
            let mut allow = TunnelAllow::default();
            allow.listen = vec!["127.0.0.1:8080".to_string()];
            exchange_tunnel_config(&cancel_c, &conn_c, &client_reqs, &allow, false).await
        });
        let cancel_s = cancel.clone();
        let conn_s = server_conn.clone();
        let server_task = tokio::spawn(async move {
            let mut allow = TunnelAllow::default();
            allow.listen = vec!["127.0.0.1:9022".to_string()];
            exchange_tunnel_config(&cancel_s, &conn_s, &server_reqs, &allow, true).await
        });

        let (cr, sr) = tokio::join!(client_task, server_task);
        let (client_accept, client_reqs, client_start) =
            cr.expect("client task").expect("client error");
        let (server_accept, server_reqs, server_start) =
            sr.expect("server task").expect("server error");

        // Both sides have requests, so neither can assume it is the sole
        // initiator; both sides accept (non-empty -aL allowlist).
        assert!(client_accept, "expected client peerAccept=true");
        assert!(server_accept, "expected server peerAccept=true");

        assert_eq!(client_reqs.len(), 2);
        assert_eq!(server_reqs.len(), 2);
        assert_eq!(client_reqs[0].typ, "L");
        assert_eq!(client_reqs[1].typ, "R");
        assert_eq!(server_reqs[0].typ, "L");
        assert_eq!(server_reqs[1].typ, "R");

        // my_req_start locates each side's requests in the shared layout:
        // the client's at 0, the server's after the client's.
        assert_eq!(client_start, 0);
        assert_eq!(server_start, 1);
    }

    /// ExchangeTunnelConfig_ResponderOnly
    #[tokio::test]
    async fn test_exchange_tunnel_config_responder_only() {
        let (client_conn, client_ep, server_conn, server_ep) = quic_pair().await;
        let _keep = (
            client_ep,
            server_ep,
            client_conn.clone(),
            server_conn.clone(),
        );

        let client_reqs = vec![TunnelRequest {
            typ: "L".into(),
            listen_addr: "127.0.0.1:8080".into(),
            target_addr: "8.8.8.8:53".into(),
        }];

        let cancel = CancellationToken::new();
        let cancel_c = cancel.clone();
        let conn_c = client_conn.clone();
        let client_task = tokio::spawn(async move {
            let mut allow = TunnelAllow::default();
            allow.listen = vec!["127.0.0.1:8080".to_string()];
            exchange_tunnel_config(&cancel_c, &conn_c, &client_reqs, &allow, false).await
        });
        let cancel_s = cancel.clone();
        let conn_s = server_conn.clone();
        let server_task = tokio::spawn(async move {
            let mut allow = TunnelAllow::default();
            allow.listen = vec!["127.0.0.1:9022".to_string()];
            exchange_tunnel_config(&cancel_s, &conn_s, &[], &allow, true).await
        });

        let (cr, sr) = tokio::join!(client_task, server_task);
        let (client_accept, client_reqs, _) = cr.expect("client task").expect("client error");
        let (server_accept, server_reqs, server_start) =
            sr.expect("server task").expect("server error");

        assert!(client_accept, "expected client peerAccept=true");
        assert!(server_accept, "expected server peerAccept=true");

        // The client's request is the only one exchanged.
        assert_eq!(client_reqs.len(), 1);
        assert_eq!(server_reqs.len(), 1);
        assert_eq!(client_reqs[0].typ, "L");
        // The server owns no requests: its (empty) range starts after the
        // client's.
        assert_eq!(server_start, 1, "server has no own requests");
    }

    /// ExchangeTunnelConfig_DirectCall
    #[tokio::test]
    async fn test_exchange_tunnel_config_direct_call() {
        let (client_conn, client_ep, server_conn, server_ep) = quic_pair().await;
        let _keep = (
            client_ep,
            server_ep,
            client_conn.clone(),
            server_conn.clone(),
        );

        let client_reqs = vec![TunnelRequest {
            typ: "L".into(),
            listen_addr: "127.0.0.1:8080".into(),
            target_addr: "8.8.8.8:53".into(),
        }];

        let cancel = CancellationToken::new();
        let cancel_c = cancel.clone();
        let conn_c = client_conn.clone();
        let client_task = tokio::spawn(async move {
            let mut allow = TunnelAllow::default();
            allow.listen = vec!["127.0.0.1:8080".to_string()];
            exchange_tunnel_config(&cancel_c, &conn_c, &client_reqs, &allow, false).await
        });
        let cancel_s = cancel.clone();
        let conn_s = server_conn.clone();
        let server_task = tokio::spawn(async move {
            exchange_tunnel_config(&cancel_s, &conn_s, &[], &TunnelAllow::default(), true).await
        });

        let (cr, sr) = tokio::join!(client_task, server_task);
        let (client_accept, client_reqs, _) = cr.expect("client task").expect("client error");
        let (server_accept, server_reqs, _) = sr.expect("server task").expect("server error");

        // The server (responder) has an empty allowlist, so it sends
        // ACCEPT false; the client (with a -aL entry) sends ACCEPT true.
        assert!(
            server_accept,
            "expected server peerAccept=true (client sent ACCEPT true)"
        );
        assert!(
            !client_accept,
            "expected client peerAccept=false (server sent ACCEPT false)"
        );
        assert_eq!(client_reqs.len(), 1);
        assert_eq!(server_reqs.len(), 1);
        assert_eq!(client_reqs[0].typ, "L");
    }

    /// ExchangeTunnelConfig_ExactlyMaxTunnelRequests: the cap is inclusive.
    /// (The Go test hand-rolls the wire protocol on the writing side and
    /// counts the lines; the same shape is kept here - the reading side
    /// uses the real reader.)
    #[tokio::test]
    async fn test_exchange_tunnel_config_exactly_max_tunnel_requests() {
        let (client_conn, client_ep, server_conn, server_ep) = quic_pair().await;
        let _keep = (
            client_ep,
            server_ep,
            client_conn.clone(),
            server_conn.clone(),
        );

        let (mut send, _recv) = client_conn.open_bi().await.expect("open_bi");
        send.write_all(b"ACCEPT true\n")
            .await
            .expect("write accept");
        for _ in 0..MAX_TUNNEL_REQUESTS {
            send.write_all(b"L 127.0.0.1:8080 8.8.8.8:53\n")
                .await
                .expect("write spec");
        }
        send.write_all(b"END\n").await.expect("write end");

        let (_s_send, mut s_recv) = server_conn.accept_bi().await.expect("accept_bi");
        let accept = read_accept_line(&mut s_recv).await.expect("read accept");
        assert!(accept);
        let reqs = read_requests_from_stream(&mut s_recv)
            .await
            .expect("exactly max requests is allowed (cap is inclusive)");
        assert_eq!(reqs.len(), MAX_TUNNEL_REQUESTS);
    }

    /// ExchangeTunnelConfig_ExceedsScannerBuffer: an overlong line is an
    /// error, not a truncation (via the reader used by the exchange).
    #[tokio::test]
    async fn test_exchange_tunnel_config_exceeds_scanner_buffer() {
        let mut line = vec![b'x'; SCANNER_MAX_TOKEN_SIZE + 1];
        line[0] = b'L';
        line[1] = b' ';
        let mut data = String::new();
        data.push_str("ACCEPT true\n");
        data.push_str(std::str::from_utf8(&line).unwrap());
        data.push('\n');
        data.push_str("END\n");

        let mut cursor = std::io::Cursor::new(data.into_bytes());
        let accept = read_accept_line(&mut cursor).await.expect("read accept");
        assert!(accept);
        let err = read_requests_from_stream(&mut cursor)
            .await
            .expect_err("overlong line must be an error");
        assert!(
            err.to_string().contains("too long"),
            "expected buffer overflow error, got {err}"
        );
    }

    /// ExchangeTunnelConfig_MalformedLine: a line without three fields is an
    /// error.
    #[tokio::test]
    async fn test_exchange_tunnel_config_malformed_line() {
        let data = b"ACCEPT true\nL 127.0.0.1:8080\nEND\n";
        let mut cursor = std::io::Cursor::new(data.to_vec());
        let accept = read_accept_line(&mut cursor).await.expect("read accept");
        assert!(accept);
        let err = read_requests_from_stream(&mut cursor)
            .await
            .expect_err("malformed line must be an error");
        assert!(
            err.to_string().contains("invalid request line"),
            "unexpected error: {err}"
        );
    }

    /// ExchangeTunnelConfig_PeerSendsTooManySpecs: more than max peer
    /// requests is an error.
    #[tokio::test]
    async fn test_exchange_tunnel_config_peer_sends_too_many_specs() {
        let mut data = String::from("ACCEPT true\n");
        for _ in 0..MAX_TUNNEL_REQUESTS * 2 + 1 {
            data.push_str("L 127.0.0.1:8080 8.8.8.8:53\n");
        }
        data.push_str("END\n");

        let mut cursor = std::io::Cursor::new(data.into_bytes());
        let _accept = read_accept_line(&mut cursor).await.expect("read accept");
        let err = read_requests_from_stream(&mut cursor)
            .await
            .expect_err("too many peer specs must be an error");
        assert!(
            err.to_string().contains("too many tunnel requests"),
            "unexpected error: {err}"
        );
    }
}
