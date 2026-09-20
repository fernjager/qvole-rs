//! Peer connection orchestration (Go `internal/engine/connect.go`).
//!
//! `connect_peer` mirrors `ConnectPeerWithConfig` end to end: code
//! generation -> certificate generation -> relay exchange -> socket rebind
//! with SO_REUSEADDR -> hole punching (with QUIC fallback) -> post-punch
//! keep-alive helper -> QUIC handshake (accept for the server role, dial for
//! the client role).

use std::net::SocketAddr;
use std::sync::Arc;

use quinn::{Connection, Endpoint};
use socket2::{Domain, Protocol, Socket, Type};
use tokio::net::UdpSocket;
use tokio_util::sync::CancellationToken;

use crate::cert::{self, SelfSignedCert};
use crate::exchange::{self, ExchangeError, PeerConfig};
use crate::logger::{LOG_HOLE, bold};
use crate::punch::{PunchOutcome, await_punch, start_hole_punching};
use crate::role::role_string;
use crate::transport::{
    self, HELPER_TICKER_INTERVAL, HELPER_TIMEOUT, KEEPALIVE_PAYLOAD, quic_client_config,
    quic_server_config,
};

/// Errors from `connect_peer`. Display text mirrors Go's error wrapping.
#[derive(Debug, thiserror::Error)]
pub enum ConnectError {
    /// `generate code: {0}`
    #[error("generate code: {0}")]
    GenerateCode(#[from] qvole_spake2::Error),
    /// `generate cert: {0}`
    #[error("generate cert: {0}")]
    GenerateCert(#[from] cert::CertError),
    /// `resolve relay: {0}`
    #[error("resolve relay: {0}")]
    ResolveRelay(String),
    /// `dial relay: {0}`
    #[error("dial relay: {0}")]
    DialRelay(String),
    /// `exchange: {0}`
    #[error("exchange: {0}")]
    Exchange(#[from] ExchangeError),
    /// `re-bind for QUIC: {0}`
    #[error("re-bind for QUIC: {0}")]
    Rebind(String),
    /// `resolve peer: {0}`
    #[error("resolve peer: {0}")]
    ResolvePeer(String),
    /// `invalid peer address: {0}`
    #[error("invalid peer address: {0}")]
    InvalidPeerAddr(String),
    /// `listen: {0}`
    #[error("listen: {0}")]
    Listen(String),
    /// `accept: {0}`
    #[error("accept: {0}")]
    Accept(String),
    /// `dial: {0}`
    #[error("dial: {0}")]
    Dial(String),
}

/// Result of the full peer connection (Go `ConnectPeer`'s `(*quic.Conn, bool)`
/// plus the addresses the app layer needs for stream bookkeeping).
#[derive(Clone)]
pub struct Connected {
    /// Established QUIC connection (Go `*quic.Conn`).
    pub conn: Connection,
    /// The QUIC endpoint (socket) hosting the connection.
    ///
    /// Unlike Go, where the accepted connection outlives the closed
    /// listener, quinn's endpoint driver terminates when the last endpoint
    /// handle is dropped - so this must be kept alive for the lifetime of
    /// [`Connected::conn`].
    pub endpoint: Endpoint,
    /// `true` when this peer accepted (server role), `false` when it dialed
    /// (client role). Go `isServer`.
    pub is_server: bool,
    /// The peer's UDP address after hole-punch port correction.
    pub peer_addr: SocketAddr,
    /// The local UDP address the QUIC endpoint is bound to
    /// (`0.0.0.0:<port>` for IPv4, like Go's exchange socket).
    pub local_addr: SocketAddr,
    /// The self-signed certificate used for this connection.
    pub cert: SelfSignedCert,
}

/// Port of `ConnectPeerWithConfig`.
///
/// `relay_addr` is the relay endpoint address (`host:port`). `code` may be
/// empty, in which case a new code is generated and printed to stderr as
/// `QVOLE_CODE=<code>`.
pub async fn connect_peer(
    cancel: &CancellationToken,
    relay_addr: &str,
    code: &str,
    cfg: &PeerConfig,
) -> Result<Connected, ConnectError> {
    // Go `defer helperCancel()`: the post-punch keep-alive helper lives at
    // most until `connect_peer` returns.
    let helper_cancel = cancel.child_token();
    let result = connect_inner(cancel, relay_addr, code, cfg, &helper_cancel).await;
    helper_cancel.cancel();
    result
}

async fn connect_inner(
    cancel: &CancellationToken,
    relay_addr: &str,
    code: &str,
    cfg: &PeerConfig,
    helper_cancel: &CancellationToken,
) -> Result<Connected, ConnectError> {
    let mut code = code.to_owned();
    if code.is_empty() {
        code = qvole_spake2::code::generate_code()?;
        eprintln!("QVOLE_CODE={code}");
    }
    let room = qvole_spake2::code::nameplate(&code);

    let my_cert = cert::generate_self_signed_cert(cert::CERT_COMMON_NAME)?;
    let my_fingerprint = my_cert.fingerprint;

    // Go `net.ResolveUDPAddr("udp", relayAddr)`: split host:port, resolve
    // the port (numeric or /etc/services), then the host (literal IP or
    // DNS). Error strings are byte-identical to Go's.
    let relay_udp_addr: SocketAddr = crate::resolver::resolve_udp_addr(relay_addr)
        .await
        .map_err(ConnectError::ResolveRelay)?;

    // A connected UDP socket for the exchange phase so the kernel filters
    // spoofed packets from non-relay sources on shared networks.
    let bind_addr = match relay_udp_addr {
        SocketAddr::V4(_) => "0.0.0.0:0",
        SocketAddr::V6(_) => "[::]:0",
    };
    let exchange_sock = UdpSocket::bind(bind_addr)
        .await
        .map_err(|e| ConnectError::DialRelay(e.to_string()))?;
    exchange_sock
        .connect(relay_udp_addr)
        .await
        .map_err(|e| ConnectError::DialRelay(e.to_string()))?;

    // Go captures the local address before closing the exchange socket.
    let local_addr = exchange_sock
        .local_addr()
        .map_err(|e| ConnectError::DialRelay(e.to_string()))?;

    let (peer_addr_str, peer_fingerprint, is_server) =
        exchange::register_and_exchange(cancel, &exchange_sock, &room, &code, &my_fingerprint, cfg)
            .await?;
    drop(exchange_sock);

    // Re-bind on the same concrete local address for hole punching and QUIC.
    // SO_REUSEADDR avoids EADDRINUSE from the just-closed socket.
    let (quic_std_sock, quic_sock) =
        rebind_udp(local_addr).map_err(|e| ConnectError::Rebind(e.to_string()))?;
    let quic_sock = Arc::new(quic_sock);

    let mut peer_udp_addr: SocketAddr = peer_addr_str
        .parse()
        .map_err(|e: std::net::AddrParseError| ConnectError::ResolvePeer(e.to_string()))?;
    if peer_udp_addr.ip().is_unspecified() || peer_udp_addr.port() == 0 {
        return Err(ConnectError::InvalidPeerAddr(peer_addr_str));
    }

    let role = role_string(is_server);
    LOG_HOLE.printf_info(&format!(
        "Hole punching to {} as {}",
        bold(&peer_udp_addr.to_string()),
        role
    ));

    let punch_cancel = cancel.child_token();
    let (rx, punch_handle) =
        start_hole_punching(&punch_cancel, Arc::clone(&quic_sock), peer_udp_addr);
    let outcome = await_punch(rx, cfg.punch_timeout()).await;

    match outcome {
        PunchOutcome::Observed(observed_addr) => {
            LOG_HOLE.printf_success("Hole punch succeeded");
            if observed_addr.ip() == peer_udp_addr.ip()
                && observed_addr.port() != peer_udp_addr.port()
            {
                LOG_HOLE.printf_info(&format!(
                    "Peer port corrected: {} -> {}",
                    peer_udp_addr.port(),
                    observed_addr.port()
                ));
                peer_udp_addr = observed_addr;
            }
        }
        PunchOutcome::Aborted => {
            LOG_HOLE.printf_warn("Hole punch aborted, falling back to QUIC");
        }
        PunchOutcome::TimedOut => {
            LOG_HOLE.printf_warn("Hole punch timed out, falling back to QUIC");
        }
    }
    punch_cancel.cancel();
    // Go `<-successCh`: wait for the hole punch goroutines to observe
    // cancellation before handing the socket to QUIC.
    let _ = punch_handle.await;

    // Go `go helper(...)`: keep the NAT mapping warm while the QUIC
    // handshake flies through.
    start_helper(helper_cancel, Arc::clone(&quic_sock), peer_udp_addr);

    let endpoint = make_endpoint(&quic_std_sock, &my_cert, &peer_fingerprint, is_server, cfg)?;

    let conn = if is_server {
        accept_quic(&endpoint, cancel, cfg).await?
    } else {
        dial_quic(
            &endpoint,
            &my_cert,
            &peer_fingerprint,
            peer_udp_addr,
            cancel,
            cfg,
        )
        .await?
    };

    transport::close_on_cancel(cancel, &conn);

    Ok(Connected {
        conn,
        endpoint,
        is_server,
        peer_addr: peer_udp_addr,
        local_addr,
        cert: my_cert,
    })
}

/// Rebinds a UDP socket to `local_addr` with SO_REUSEADDR (Go
/// `rebindControl` + `ListenConfig.ListenPacket`).
///
/// Returns both a blocking std handle (handed to the QUIC endpoint) and a
/// tokio handle (used for punching and the helper) referring to the same
/// underlying socket, so both share the kernel's NAT 4-tuple exactly like
/// Go's single `*net.UDPConn`.
fn rebind_udp(local_addr: SocketAddr) -> Result<(std::net::UdpSocket, UdpSocket), std::io::Error> {
    let domain = match local_addr {
        SocketAddr::V4(_) => Domain::IPV4,
        SocketAddr::V6(_) => Domain::IPV6,
    };
    let sock = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))?;
    sock.set_reuse_address(true)?;
    sock.bind(&local_addr.into())?;
    let tokio_handle = sock.try_clone()?;
    tokio_handle.set_nonblocking(true)?;
    let std_handle: std::net::UdpSocket = sock.into();
    let tokio_handle: std::net::UdpSocket = tokio_handle.into();
    let tokio_sock = UdpSocket::from_std(tokio_handle)?;
    Ok((std_handle, tokio_sock))
}

/// Creates the QUIC endpoint on the re-bound socket, installing the server
/// config when this peer plays the server role (Go `quic.Listen`).
fn make_endpoint(
    sock: &std::net::UdpSocket,
    my_cert: &SelfSignedCert,
    peer_fingerprint: &[u8],
    is_server: bool,
    cfg: &PeerConfig,
) -> Result<Endpoint, ConnectError> {
    // Quinn takes the transport profile from the client/server configs, not
    // from the endpoint config (unlike quic-go, which takes it per-call).
    let endpoint_config = quinn::EndpointConfig::default();
    let server_config = if is_server {
        Some(
            quic_server_config(my_cert, peer_fingerprint, cfg).map_err(|e| {
                LOG_HOLE.printf_error(&format!("QUIC listen failed: {e}"));
                ConnectError::Listen(e.to_string())
            })?,
        )
    } else {
        None
    };
    let runtime =
        quinn::default_runtime().ok_or_else(|| ConnectError::Listen("no tokio runtime".into()))?;
    Endpoint::new(
        endpoint_config,
        server_config,
        sock.try_clone()
            .map_err(|e| ConnectError::Listen(e.to_string()))?,
        runtime,
    )
    .map_err(|e| {
        LOG_HOLE.printf_error(&format!("QUIC listen failed: {e}"));
        ConnectError::Listen(e.to_string())
    })
}

/// Go `ln.Accept(ctx)`: waits for the first incoming connection, then
/// completes its handshake within `cfg.handshake_timeout()`.
///
/// The Go timeout is `quic.Config.HandshakeIdleTimeout`, which has no quinn
/// equivalent; it is applied here explicitly.
async fn accept_quic(
    endpoint: &Endpoint,
    cancel: &CancellationToken,
    cfg: &PeerConfig,
) -> Result<Connection, ConnectError> {
    let incoming = loop {
        tokio::select! {
            accepted = endpoint.accept() => match accepted {
                Some(incoming) => break incoming,
                None => continue, // endpoint closed
            },
            _ = cancel.cancelled() => return Err(ConnectError::Accept("context canceled".into())),
        }
    };
    let conn = tokio::select! {
        result = tokio::time::timeout(cfg.handshake_timeout(), incoming) => match result {
            Ok(result) => result,
            Err(_) => return Err(ConnectError::Accept("handshake timeout".into())),
        },
        _ = cancel.cancelled() => return Err(ConnectError::Accept("context canceled".into())),
    };
    let conn = conn.map_err(|e| {
        LOG_HOLE.printf_error(&format!("QUIC accept failed: {e}"));
        ConnectError::Accept(e.to_string())
    })?;
    Ok(conn)
}

/// Go `quic.Dial(ctx, ...)`: dials the peer and completes the handshake
/// within `cfg.handshake_timeout()`.
///
/// As in Go's quic-go, the SNI / server name is the peer's IP literal
/// (certificate host verification is skipped by the pinned verifier).
async fn dial_quic(
    endpoint: &Endpoint,
    my_cert: &SelfSignedCert,
    peer_fingerprint: &[u8],
    peer: SocketAddr,
    cancel: &CancellationToken,
    cfg: &PeerConfig,
) -> Result<Connection, ConnectError> {
    let client_config = quic_client_config(my_cert, peer_fingerprint, cfg)
        .map_err(|e| ConnectError::Dial(e.to_string()))?;
    let connecting = endpoint
        .connect_with(client_config, peer, &peer.ip().to_string())
        .map_err(|e| ConnectError::Dial(e.to_string()))?;
    let conn = tokio::select! {
        result = tokio::time::timeout(cfg.handshake_timeout(), connecting) => match result {
            Ok(result) => result,
            Err(_) => return Err(ConnectError::Dial("handshake timeout".into())),
        },
        _ = cancel.cancelled() => return Err(ConnectError::Dial("context canceled".into())),
    };
    let conn = conn.map_err(|e| {
        LOG_HOLE.printf_error(&format!("QUIC dial to {peer} failed: {e}"));
        ConnectError::Dial(e.to_string())
    })?;
    Ok(conn)
}

/// Go `helper`: for `HELPER_TIMEOUT` after the punch, sends a 1-byte probe
/// every `HELPER_TICKER_INTERVAL` to the peer on the same socket, keeping
/// the NAT mapping alive while the QUIC handshake flies through.
fn start_helper(
    cancel: &CancellationToken,
    sock: Arc<UdpSocket>,
    peer: SocketAddr,
) -> tokio::task::JoinHandle<()> {
    let cancel = cancel.clone();
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval_at(
            tokio::time::Instant::now() + HELPER_TICKER_INTERVAL,
            HELPER_TICKER_INTERVAL,
        );
        let stop = tokio::time::sleep(HELPER_TIMEOUT);
        tokio::pin!(stop);
        loop {
            tokio::select! {
                _ = cancel.cancelled() => return,
                _ = &mut stop => return,
                _ = ticker.tick() => {
                    // Go ignores write errors (UDP is best-effort).
                    let _ = sock.send_to(KEEPALIVE_PAYLOAD, peer).await;
                }
            }
        }
    })
}
