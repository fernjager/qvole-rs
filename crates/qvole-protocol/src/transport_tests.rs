//! Tests ported from `qvole-go/internal/engine/transport_test.go`.
//!
//! Go's env-based tests (`TestEnvDuration*`, `TestEnvInt*`) are already
//! covered by the `env` module tests; because `std::env::set_var` is unsafe
//! in edition 2024 (and this crate forbids unsafe), the equivalent
//! behavior here is exercised through explicit `PeerConfig` fields and the
//! pure `get_forward_max_streams` override forms.
//!
//! The Go fingerprint/signature unit tests are exercised through the same
//! verification code paths used by the TLS verifiers, plus the end-to-end
//! handshake tests below (which verify both sides' TLS 1.3 certificate
//! signatures through `verify_tls13_signature`).

use super::*;
use crate::cert::generate_self_signed_cert;
use quinn::{ConnectionError, Endpoint, EndpointConfig};
use std::net::SocketAddr;

const HANDSHAKE_TEST_TIMEOUT: Duration = Duration::from_secs(15);

// --- Fingerprint verification (Go `TestBaseTLSConfig_*`) ---

#[test]
fn check_fingerprint_mismatch() {
    let cert = generate_self_signed_cert("other").unwrap();
    let mut wrong_fp = [0u8; 32];
    wrong_fp[0] = 0x01;
    let err = check_fingerprint(wrong_fp, &cert.der).unwrap_err();
    assert!(
        err.to_string()
            .contains("peer certificate fingerprint mismatch"),
        "unexpected error text: {err}"
    );
}

#[test]
fn check_fingerprint_match() {
    let cert = generate_self_signed_cert("test").unwrap();
    let fp: [u8; 32] = cert.fingerprint;
    assert!(check_fingerprint(fp, &cert.der).is_ok());
}

#[test]
fn check_fingerprint_end_entity_only() {
    // Go hashes only `rawCerts[0]`: the verifier sees exactly the
    // end-entity DER, so a different end entity must not pass even when
    // it appears later in a chain.
    let cert1 = generate_self_signed_cert("first").unwrap();
    let cert2 = generate_self_signed_cert("second").unwrap();
    let fp1: [u8; 32] = cert1.fingerprint;
    assert!(check_fingerprint(fp1, &cert1.der).is_ok());
    assert!(
        check_fingerprint(fp1, &cert2.der).is_err(),
        "different end entity must fail the pin"
    );
}

// --- TLS config construction (Go `TestBaseTLSConfig_MinVersion`,
// `TestServerClientTLSConfig`) ---

#[test]
fn tls_configs_alpn() {
    let cert = generate_self_signed_cert("test").unwrap();
    let fp: [u8; 32] = cert.fingerprint;

    let client = client_tls_config(&cert, &fp).expect("client tls config");
    assert_eq!(
        client.alpn_protocols,
        vec![ALPN.to_vec()],
        "expected NextProtos [\"qvole-v0.1\"]"
    );

    let server = server_tls_config(&cert, &fp).expect("server tls config");
    assert_eq!(server.alpn_protocols, vec![ALPN.to_vec()]);
}

#[test]
fn tls_config_bad_fingerprint_length() {
    let cert = generate_self_signed_cert("test").unwrap();
    let err = client_tls_config(&cert, &[0u8; 31]).unwrap_err();
    assert!(
        err.to_string().contains("bad peer fingerprint length"),
        "unexpected error text: {err}"
    );
    let err = server_tls_config(&cert, &[0u8; 33]).unwrap_err();
    assert!(
        err.to_string().contains("bad peer fingerprint length"),
        "unexpected error text: {err}"
    );
}

#[test]
fn server_tls_config_requires_client_cert() {
    // Go `RequireAnyClientCert`: the client-auth offer is mandatory.
    let verifier = PinnedClientVerifier::new([0u8; 32]);
    assert!(verifier.offer_client_auth());
    assert!(verifier.client_auth_mandatory());
}

// --- Transport profile (Go `TestQUICConfig_*`) ---

#[test]
fn quic_config_defaults() {
    let cfg = PeerConfig::default();
    assert_eq!(cfg.max_streams(), DEFAULT_MAX_INCOMING_STREAMS);
    assert_eq!(cfg.keep_alive_period(), DEFAULT_KEEP_ALIVE_PERIOD);
    assert_eq!(cfg.idle_timeout(), DEFAULT_MAX_IDLE_TIMEOUT);
    assert_eq!(cfg.handshake_timeout(), DEFAULT_HANDSHAKE_TIMEOUT);
    assert_eq!(
        initial_stream_window(),
        DEFAULT_INITIAL_STREAM_WINDOW as u64
    );
    assert_eq!(
        initial_connection_window(),
        DEFAULT_INITIAL_CONNECTION_WINDOW as u64
    );
    // `quic_transport_config` must build without error for the defaults.
    let _tc = quic_transport_config(&cfg);
}

#[test]
fn varint_mappings() {
    // Durations are encoded in milliseconds (the QUIC unit for idle timeouts).
    assert_eq!(
        millis_varint(DEFAULT_MAX_IDLE_TIMEOUT),
        VarInt::from_u32(120_000)
    );
    // Windows are capped at the varint maximum like quic-go's uint64 cast.
    assert_eq!(
        byte_varint(DEFAULT_INITIAL_STREAM_WINDOW as u64),
        VarInt::from_u32(1024 * 1024)
    );
    assert_eq!(byte_varint(u64::MAX), VarInt::from_u32(u32::MAX));
    assert_eq!(
        millis_varint(Duration::from_millis(u64::from(u32::MAX) + 1)),
        VarInt::from_u32(u32::MAX)
    );
}

#[test]
fn quic_config_overrides() {
    let cfg = PeerConfig {
        max_streams: Some(500),
        keep_alive_period: Some(Duration::from_millis(7000)),
        idle_timeout: Some(Duration::from_secs(60)),
        handshake_timeout: Some(Duration::from_secs(15)),
        ..Default::default()
    };
    assert_eq!(cfg.max_streams(), 500);
    assert_eq!(cfg.keep_alive_period(), Duration::from_millis(7000));
    assert_eq!(cfg.idle_timeout(), Duration::from_secs(60));
    assert_eq!(cfg.handshake_timeout(), Duration::from_secs(15));

    // The transport profile must build with the overrides in effect.
    let _tc = quic_transport_config(&cfg);
}

#[test]
fn quic_config_zero_falls_back() {
    // Go zero-value semantics: zero durations fall back to defaults.
    let cfg = PeerConfig {
        keep_alive_period: Some(Duration::ZERO),
        idle_timeout: Some(Duration::ZERO),
        ..Default::default()
    };
    assert_eq!(cfg.keep_alive_period(), DEFAULT_KEEP_ALIVE_PERIOD);
    assert_eq!(cfg.idle_timeout(), DEFAULT_MAX_IDLE_TIMEOUT);
}

#[test]
fn get_forward_max_streams_default_and_override() {
    // CI never sets QVOLE_FORWARD_MAX_STREAMS, so the default applies.
    assert_eq!(get_forward_max_streams(None), DEFAULT_FORWARD_MAX_STREAMS);
    assert_eq!(
        get_forward_max_streams(Some(0)),
        DEFAULT_FORWARD_MAX_STREAMS
    );
    assert_eq!(get_forward_max_streams(Some(50)), 50);
}

// --- End-to-end handshake (Go `TestCloseOnCancel`) ---

fn bind_endpoint(server_config: Option<quinn::ServerConfig>) -> (Endpoint, SocketAddr) {
    let sock = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let addr = sock.local_addr().unwrap();
    let runtime = quinn::default_runtime().expect("tokio runtime");
    let ep =
        Endpoint::new(EndpointConfig::default(), server_config, sock, runtime).expect("endpoint");
    (ep, addr)
}

/// Full QUIC handshake on localhost with pinned certificates, then cancel
/// the context and verify the connection is torn down with the cancel
/// error code on both sides.
#[tokio::test]
async fn close_on_cancel_e2e() {
    // Both endpoints use the same freshly generated certificate (the Go
    // test does the same; in production each side pins the other's).
    let cert = generate_self_signed_cert("test").unwrap();
    let fp: [u8; 32] = cert.fingerprint;
    let cfg = PeerConfig::default();

    // Server endpoint.
    let server_cfg = quic_server_config(&cert, &fp, &cfg).unwrap();
    let (server_ep, server_addr) = bind_endpoint(Some(server_cfg));

    let server_task = tokio::spawn(async move {
        let incoming = tokio::time::timeout(HANDSHAKE_TEST_TIMEOUT, server_ep.accept())
            .await
            .expect("server accept timed out")
            .expect("no incoming connection");
        let conn = tokio::time::timeout(HANDSHAKE_TEST_TIMEOUT, incoming)
            .await
            .expect("handshake timed out")
            .expect("handshake failed");
        // Wait for the connection to close; report how it closed.
        conn.closed().await
    });

    // Client endpoint.
    let client_cfg = quic_client_config(&cert, &fp, &cfg).unwrap();
    let (client_ep, _client_addr) = bind_endpoint(None);
    let connecting = client_ep
        .connect_with(client_cfg, server_addr, &server_addr.ip().to_string())
        .expect("connect_with");
    let client_conn = tokio::time::timeout(HANDSHAKE_TEST_TIMEOUT, connecting)
        .await
        .expect("client handshake timed out")
        .expect("client handshake failed");

    // Canceling must tear the connection down (Go `closeOnCancel`).
    let cancel = CancellationToken::new();
    close_on_cancel(&cancel, &client_conn);
    cancel.cancel();

    // Local view: locally closed; peer view: application close carrying
    // the cancel error code.
    let local = tokio::time::timeout(HANDSHAKE_TEST_TIMEOUT, client_conn.closed())
        .await
        .expect("local close timed out");
    assert!(
        matches!(local, ConnectionError::LocallyClosed),
        "expected LocallyClosed, got {local:?}"
    );

    let remote = tokio::time::timeout(HANDSHAKE_TEST_TIMEOUT, server_task)
        .await
        .expect("server close timed out")
        .expect("server task panicked");
    match remote {
        ConnectionError::ApplicationClosed(close) => {
            assert_eq!(
                u64::from(close.error_code),
                CANCEL_ERROR_CODE as u64,
                "expected cancel error code"
            );
            assert_eq!(close.reason.as_ref(), b"canceled");
        }
        other => panic!("expected ApplicationClosed, got {other:?}"),
    }
}

/// The handshake must fail when the client pins a fingerprint that does
/// not match the server certificate (Go `TestBaseTLSConfig_WrongFingerprint`
/// end-to-end form).
#[tokio::test]
async fn handshake_rejects_wrong_fingerprint() {
    let server_cert = generate_self_signed_cert("server").unwrap();
    let client_cert = generate_self_signed_cert("client").unwrap();
    let wrong_cert = generate_self_signed_cert("wrong").unwrap();
    let cfg = PeerConfig::default();

    // Server expects the real client cert.
    let server_cfg = quic_server_config(&server_cert, &client_cert.fingerprint, &cfg).unwrap();
    let (server_ep, server_addr) = bind_endpoint(Some(server_cfg));

    // Quinn (unlike quic-go) does not begin an incoming connection's
    // handshake until it is accepted, so a task must accept it.
    let server_task = tokio::spawn(async move {
        let Ok(incoming) = tokio::time::timeout(HANDSHAKE_TEST_TIMEOUT, server_ep.accept()).await
        else {
            return;
        };
        let Some(incoming) = incoming else { return };
        let Ok(connecting) = incoming.accept() else {
            return;
        };
        let _ = tokio::time::timeout(HANDSHAKE_TEST_TIMEOUT, connecting).await;
    });

    // Client presents its real cert but pins a fingerprint that matches
    // neither endpoint, so its verification of the server must fail.
    let client_cfg = quic_client_config(&client_cert, &wrong_cert.fingerprint, &cfg).unwrap();
    let (client_ep, _client_addr) = bind_endpoint(None);
    let connecting = client_ep
        .connect_with(client_cfg, server_addr, &server_addr.ip().to_string())
        .expect("connect_with");

    let res = tokio::time::timeout(HANDSHAKE_TEST_TIMEOUT, connecting).await;
    assert!(
        matches!(res, Ok(Err(ConnectionError::TransportError(_)))),
        "expected a crypto/transport handshake failure, got {res:?}",
    );
    let _ = server_task.await;
}

/// In-process quinn<->quinn bidirectional stream exchange: verifies that a
/// stream opened by one endpoint is promptly accepted by the other and data
/// flows both ways. This isolates stream interop from any quic-go behavior.
#[tokio::test]
async fn quinn_stream_exchange_in_process() {
    let cert = generate_self_signed_cert("t").unwrap();
    let fp = cert.fingerprint;
    let cfg = PeerConfig::default();

    let server_cfg = quic_server_config(&cert, &fp, &cfg).unwrap();
    let (server_ep, server_addr) = bind_endpoint(Some(server_cfg));

    let server_task = tokio::spawn(async move {
        let Ok(incoming) = tokio::time::timeout(HANDSHAKE_TEST_TIMEOUT, server_ep.accept()).await
        else {
            return None;
        };
        let incoming = incoming?;
        let Ok(connecting) = incoming.accept() else {
            return None;
        };
        let Ok(inner) = tokio::time::timeout(HANDSHAKE_TEST_TIMEOUT, connecting).await else {
            return None;
        };
        let Ok(conn) = inner else { return None };
        let Ok(inner2) = tokio::time::timeout(HANDSHAKE_TEST_TIMEOUT, conn.accept_bi()).await
        else {
            return None;
        };
        let Ok((mut send, mut recv)) = inner2 else {
            return None;
        };
        // read one line from client
        let mut line = Vec::new();
        let mut byte = [0u8; 1];
        let mut ok = true;
        loop {
            match tokio::time::timeout(HANDSHAKE_TEST_TIMEOUT, recv.read_exact(&mut byte)).await {
                Ok(Ok(())) => {
                    line.push(byte[0]);
                    if byte[0] == b'\n' {
                        break;
                    }
                }
                _ => {
                    ok = false;
                    break;
                }
            }
        }
        let _ = send.write_all(b"SERVER-REPLY\n").await;
        // Wait for the client's FIN so the connection (owned by this task)
        // stays alive until the client has read the reply.
        let _ = recv.read_to_end(1024).await;
        let _ = send.finish();
        Some((line, ok))
    });

    let client_cfg = quic_client_config(&cert, &fp, &cfg).unwrap();
    let (client_ep, _addr) = bind_endpoint(None);
    let conn = client_ep
        .connect_with(client_cfg, server_addr, &server_addr.ip().to_string())
        .expect("connect_with");
    let conn = tokio::time::timeout(HANDSHAKE_TEST_TIMEOUT, conn)
        .await
        .expect("handshake")
        .expect("conn");

    let (mut send, mut recv) = conn.open_bi().await.expect("open_bi");
    send.write_all(b"CLIENT-HELLO\n").await.expect("write");

    // read server reply
    let mut reply = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        match tokio::time::timeout(HANDSHAKE_TEST_TIMEOUT, recv.read_exact(&mut byte)).await {
            Ok(Ok(())) => {
                reply.push(byte[0]);
                if byte[0] == b'\n' {
                    break;
                }
            }
            Ok(Err(e)) => panic!("read error: {e}"),
            Err(_) => panic!("no server reply (timeout)"),
        }
    }

    // Half-close our send side so the server's read_to_end completes.
    let _ = send.finish();
    let (line, ok) = server_task
        .await
        .expect("server task")
        .expect("server result");
    assert!(ok, "server read failed");
    assert_eq!(line, b"CLIENT-HELLO\n");
    assert_eq!(reply, b"SERVER-REPLY\n");
}
