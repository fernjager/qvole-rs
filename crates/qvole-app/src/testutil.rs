//! Shared test utilities: a plain QUIC pair (pinned self-signed certs,
//! localhost UDP), mirroring Go's `helper_test.setupQUICPair`.
//!
//! The returned endpoints MUST be kept alive by the caller for the lifetime
//! of the connections (quinn's driver terminates when the last `Endpoint`
//! handle is dropped).

use std::net::SocketAddr;
use std::time::Duration;

use quinn::Connection;
use tokio::time::timeout;

use qvole_protocol::cert::generate_self_signed_cert;
use qvole_protocol::exchange::PeerConfig;
use qvole_protocol::transport::{quic_client_config, quic_server_config};

pub const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(15);

/// Binds a localhost UDP socket and builds a quinn endpoint over it.
pub fn bind_endpoint(server_config: Option<quinn::ServerConfig>) -> (quinn::Endpoint, SocketAddr) {
    let sock = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let addr = sock.local_addr().unwrap();
    let runtime = quinn::default_runtime().expect("tokio runtime");
    let ep = quinn::Endpoint::new(
        quinn::EndpointConfig::default(),
        server_config,
        sock,
        runtime,
    )
    .expect("endpoint");
    (ep, addr)
}

/// Establishes a QUIC pair like Go's `helper_test.setupQUICPair`.
/// Returns (client_conn, client_endpoint, server_conn, server_endpoint).
pub async fn quic_pair() -> (Connection, quinn::Endpoint, Connection, quinn::Endpoint) {
    let cert = generate_self_signed_cert("test").unwrap();
    let fp = cert.fingerprint;
    let cfg = PeerConfig::default();

    let server_cfg = quic_server_config(&cert, &fp, &cfg).unwrap();
    let (server_ep, server_addr) = bind_endpoint(Some(server_cfg));

    let server_ep_task = server_ep.clone();
    let server_task = tokio::spawn(async move {
        let incoming = timeout(HANDSHAKE_TIMEOUT, server_ep_task.accept())
            .await
            .expect("server accept timed out")
            .expect("no incoming connection");
        timeout(HANDSHAKE_TIMEOUT, incoming)
            .await
            .expect("handshake timed out")
            .expect("handshake failed")
    });

    let client_cfg = quic_client_config(&cert, &fp, &cfg).unwrap();
    let (client_ep, _client_addr) = bind_endpoint(None);
    let connecting = client_ep
        .connect_with(client_cfg, server_addr, &server_addr.ip().to_string())
        .expect("connect_with");
    let client_conn = timeout(HANDSHAKE_TIMEOUT, connecting)
        .await
        .expect("client handshake timed out")
        .expect("client handshake failed");

    let server_conn = server_task.await.unwrap();
    (client_conn, client_ep, server_conn, server_ep)
}
