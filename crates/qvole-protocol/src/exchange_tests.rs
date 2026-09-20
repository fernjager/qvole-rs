//! Tests for the SPAKE2 exchange (port of `internal/engine/connect_test.go`).

use super::*;
use std::time::Duration;

const TEST_FINGERPRINT: [u8; 32] = [
    0xAB, 0xCD, 0xEF, 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0x01, 0x23, 0x45, 0x67, 0x89,
    0xAB, 0xCD, 0xEF, 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0x01, 0x23, 0x45, 0x67, 0x89,
];

/// Port of `setupSPAKE2Session`.
fn setup_spake2_session(password: &str) -> ([u8; 32], [u8; 32], Vec<u8>, Vec<u8>) {
    let mut my_state = spake2::new_state(password).unwrap();
    let peer_state = spake2::new_state(password).unwrap();

    let my_m = my_state.blinded_bytes_m();
    let peer_m = peer_state.blinded_bytes_m();
    let my_n = my_state.blinded_bytes_n();
    let peer_n = peer_state.blinded_bytes_n();

    let my_is_server = my_m > peer_m;
    let (my_point, peer_point) = if my_is_server {
        (my_n, peer_m)
    } else {
        (my_m, peer_n)
    };

    let peer_used_m = my_is_server;
    let mut shared = my_state.compute_shared(&peer_point, peer_used_m).unwrap();
    my_state.destroy();

    let (ck, ek) = spake2::derive_session_key(&shared, &my_point, &peer_point).unwrap();
    spake2::zero_bytes(&mut shared);
    (ck, ek, my_point, peer_point)
}

// ---- detectOutboundAddr tests ----

#[test]
fn detect_outbound_addr_specific_ip() {
    let addr = detect_outbound_addr("127.0.0.1:12345".parse().unwrap());
    let (host, port) = addr.rsplit_once(':').unwrap();
    assert_eq!(host, "127.0.0.1");
    assert!(!port.is_empty());
}

#[test]
fn detect_outbound_addr_unspecified_fallback() {
    let addr = detect_outbound_addr("0.0.0.0:54321".parse().unwrap());
    let (host, port) = addr.rsplit_once(':').unwrap();
    assert!(!host.is_empty() && host != "0.0.0.0");
    assert!(!port.is_empty());
}

#[test]
fn detect_outbound_addr_ipv6() {
    let addr = detect_outbound_addr("[::1]:54321".parse().unwrap());
    assert!(addr.contains("54321"));
}

#[test]
fn detect_outbound_addr_ipv6_unspecified() {
    let addr = detect_outbound_addr("[::]:54321".parse().unwrap());
    let (host, port) = addr.rsplit_once(':').unwrap();
    assert!(host != "::");
    assert!(!port.is_empty());
}

// ---- processSpakeMsg tests ----

#[test]
fn process_spake_msg_too_short() {
    let state = spake2::new_state("test-too-short").unwrap();
    let my_m = state.blinded_bytes_m();
    let my_n = state.blinded_bytes_n();

    let short_hex = hex::to_hex_lower(&[0u8; 30]);
    let err = process_spake_msg(&short_hex, &state, &my_m, &my_n).unwrap_err();
    assert!(err.to_string().contains("too short"));
}

#[test]
fn process_spake_msg_invalid_hex() {
    let state = spake2::new_state("test-invalid-hex").unwrap();
    let my_m = state.blinded_bytes_m();
    let my_n = state.blinded_bytes_n();

    let err = process_spake_msg("not-a-valid-hex-string!", &state, &my_m, &my_n).unwrap_err();
    assert!(err.to_string().contains("hex"));
}

#[test]
fn process_spake_msg_success() {
    let password = "test-process-spake-success";
    let my_state = spake2::new_state(password).unwrap();
    let peer_state = spake2::new_state(password).unwrap();
    let my_m = my_state.blinded_bytes_m();
    let my_n = my_state.blinded_bytes_n();
    let peer_m = peer_state.blinded_bytes_m();
    let peer_n = peer_state.blinded_bytes_n();
    let mut peer_fingerprint = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut peer_fingerprint);

    let mut payload = Vec::with_capacity(SPAKE2_PAYLOAD_LEN);
    payload.extend_from_slice(&peer_m);
    payload.extend_from_slice(&peer_n);
    payload.extend_from_slice(&peer_fingerprint);
    let hex_body = hex::to_hex_lower(&payload);

    let proc = process_spake_msg(&hex_body, &my_state, &my_m, &my_n).unwrap();
    assert_eq!(proc.effective_my_point.len(), 65);
    assert_eq!(proc.effective_peer_point.len(), 65);
    assert_eq!(proc.peer_fingerprint.len(), 32);
    assert_eq!(proc.confirm_key.len(), 32);
    assert_eq!(proc.enc_key.len(), 32);
    assert_eq!(
        proc.peer_fingerprint.as_slice(),
        peer_fingerprint.as_slice()
    );
}

#[test]
fn process_spake_msg_reflected_point() {
    let state = spake2::new_state("test-reflected-point").unwrap();
    let my_m = state.blinded_bytes_m();
    let my_n = state.blinded_bytes_n();
    let mut peer_fingerprint = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut peer_fingerprint);

    let mut payload = Vec::with_capacity(SPAKE2_PAYLOAD_LEN);
    payload.extend_from_slice(&my_m); // reflected M point
    payload.extend_from_slice(&my_n); // reflected N point
    payload.extend_from_slice(&peer_fingerprint);
    let hex_body = hex::to_hex_lower(&payload);

    let err = process_spake_msg(&hex_body, &state, &my_m, &my_n).unwrap_err();
    assert!(err.to_string().contains("reflected"));
}

// ---- buildConfirmPayload tests ----

#[test]
fn build_confirm_payload_size() {
    let (ck, ek, my_point, peer_point) = setup_spake2_session("test-confirm-size");
    let cp = build_confirm_payload(
        &ck,
        &ek,
        &my_point,
        &peer_point,
        &TEST_FINGERPRINT,
        "10.0.0.1:8080",
    )
    .unwrap();
    assert_eq!(cp.len(), CONFIRM_PAYLOAD_SIZE);
}

#[test]
fn build_confirm_payload_nonce_random() {
    let (ck, ek, my_point, peer_point) = setup_spake2_session("test-nonce-random");
    let p1 = build_confirm_payload(
        &ck,
        &ek,
        &my_point,
        &peer_point,
        &TEST_FINGERPRINT,
        "10.0.0.1:8080",
    )
    .unwrap();
    let p2 = build_confirm_payload(
        &ck,
        &ek,
        &my_point,
        &peer_point,
        &TEST_FINGERPRINT,
        "10.0.0.1:8080",
    )
    .unwrap();
    assert_ne!(&p1[..16], &p2[..16], "nonce should be random");
}

#[test]
fn build_confirm_payload_address_too_long() {
    let (ck, ek, my_point, peer_point) = setup_spake2_session("test-addr-too-long");
    let long_addr = "x".repeat(MAX_METADATA_SIZE + 1);
    let err = build_confirm_payload(
        &ck,
        &ek,
        &my_point,
        &peer_point,
        &TEST_FINGERPRINT,
        &long_addr,
    )
    .unwrap_err();
    assert!(err.to_string().contains("address too long"));
}

// ---- processConfirmMsg tests ----

#[test]
fn process_confirm_msg_too_short() {
    let short_hex = hex::to_hex_lower(&[0u8; 64]);
    let err = process_confirm_msg(&short_hex, &[], &[], &[], &[], &[]).unwrap_err();
    assert!(matches!(err, ExchangeError::ConfirmPayloadTooShort));
}

#[test]
fn process_confirm_msg_invalid_hex() {
    let err = process_confirm_msg("not-hex!!!", &[], &[], &[], &[], &[]).unwrap_err();
    assert!(matches!(err, ExchangeError::Hex(_)));
}

#[test]
fn process_confirm_msg_wrong_key() {
    let (ck, _ek, my_point, peer_point) = setup_spake2_session("test-wrong-confirm");
    let ek = [0u8; 32];
    let payload = build_confirm_payload(
        &ck,
        &ek,
        &my_point,
        &peer_point,
        &TEST_FINGERPRINT,
        "10.0.0.1:8080",
    )
    .unwrap();
    let hex_payload = hex::to_hex_lower(&payload);

    let mut wrong_key = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut wrong_key);

    let err = process_confirm_msg(
        &hex_payload,
        &wrong_key,
        &ek,
        &my_point,
        &peer_point,
        &TEST_FINGERPRINT,
    )
    .unwrap_err();
    assert!(err.to_string().contains("confirmation mismatch"));
}

#[test]
fn process_confirm_msg_round_trip() {
    let (ck, ek, my_point, peer_point) = setup_spake2_session("test-confirm-roundtrip");
    let payload = build_confirm_payload(
        &ck,
        &ek,
        &my_point,
        &peer_point,
        &TEST_FINGERPRINT,
        "10.0.0.1:8080",
    )
    .unwrap();
    let hex_payload = hex::to_hex_lower(&payload);

    let peer_addr = process_confirm_msg(
        &hex_payload,
        &ck,
        &ek,
        &my_point,
        &peer_point,
        &TEST_FINGERPRINT,
    )
    .unwrap();
    assert_eq!(peer_addr, "10.0.0.1:8080");
}

// ---- constants ----

#[test]
fn confirm_payload_size_const() {
    assert_eq!(
        CONFIRM_PAYLOAD_SIZE,
        16 + 32 + 12 + MAX_METADATA_SIZE + 16 + 32
    );
    assert_eq!(CONFIRM_PAYLOAD_SIZE, 160);
}

#[test]
fn metadata_padding_with_embedded_nulls() {
    let key = [0u8; 32];
    let aad = b"test-aad";
    let mut addr_bytes = b"10.0.0.1:8080".to_vec();
    if addr_bytes.len() < MAX_METADATA_SIZE {
        addr_bytes.resize(MAX_METADATA_SIZE, 0);
    }

    let enc = spake2::encrypt_metadata(&key, aad, &addr_bytes).unwrap();
    let dec = spake2::decrypt_metadata(&key, aad, &enc).unwrap();

    let mut trimmed = dec;
    while trimmed.last() == Some(&0) {
        trimmed.pop();
    }
    assert_eq!(trimmed, b"10.0.0.1:8080");
}

// ---- registerAndExchange integration tests ----

async fn bind_udp() -> UdpSocket {
    UdpSocket::bind("127.0.0.1:0".parse::<std::net::SocketAddr>().unwrap())
        .await
        .unwrap()
}

#[tokio::test]
async fn register_and_exchange_context_cancellation() {
    let peer = bind_udp().await;
    let relay = bind_udp().await;
    peer.connect(relay.local_addr().unwrap()).await.unwrap();

    let cancel = CancellationToken::new();
    cancel.cancel();

    let err = register_and_exchange(
        &cancel,
        &peer,
        "testroom4",
        "test-code-for-spake2",
        b"fp",
        &PeerConfig::default(),
    )
    .await
    .unwrap_err();
    assert!(matches!(err, ExchangeError::Cancelled));
}

/// Relay-side helper: respond to every REG with `REGD <room> <src>` (the Go
/// test form, which is neither an OK nor a cookie payload), and to the first
/// MSG with the given response.
async fn relay_sim(
    relay: UdpSocket,
    room: &'static str,
    iterations: usize,
    read_timeout: Duration,
    on_msg: Option<Box<dyn Fn() -> Option<Vec<u8>> + Send>>,
) {
    let mut buf = vec![0u8; READ_BUFFER_SIZE];
    let mut msg_responded = false;
    for _ in 0..iterations {
        let (n, src) = match tokio::time::timeout(read_timeout, relay.recv_from(&mut buf)).await {
            Ok(Ok(v)) => v,
            _ => continue,
        };
        let line = std::str::from_utf8(&buf[..n]).unwrap_or("");
        if line.starts_with("REG ") {
            let resp = format!("REGD {room} {src}\n");
            let _ = relay.send_to(resp.as_bytes(), src).await;
        }
        if let Some(on_msg) = on_msg.as_ref()
            && line.starts_with("MSG ")
            && !msg_responded
        {
            if let Some(resp) = on_msg() {
                let _ = relay.send_to(&resp, src).await;
            }
            msg_responded = true;
        }
    }
}

#[tokio::test]
async fn register_and_exchange_spake2_payload_too_short() {
    let relay = bind_udp().await;
    let peer = bind_udp().await;
    peer.connect(relay.local_addr().unwrap()).await.unwrap();

    let cancel = CancellationToken::new();
    let cfg = PeerConfig {
        exchange_deadline: Some(Duration::from_millis(400)),
        read_deadline: Some(Duration::from_millis(100)),
        ..Default::default()
    };
    let relay_task = tokio::spawn(async move {
        let on_msg =
            move || Some(format!("MSGD spake2 {}\n", hex::to_hex_lower(&[0u8; 30])).into_bytes());
        relay_sim(
            relay,
            "testroom1",
            30,
            Duration::from_millis(200),
            Some(Box::new(on_msg)),
        )
        .await
    });
    let result = tokio::time::timeout(
        Duration::from_secs(30),
        register_and_exchange(
            &cancel,
            &peer,
            "testroom1",
            "test-code-for-spake2",
            b"fingerprint",
            &cfg,
        ),
    )
    .await;
    relay_task.abort();
    // Should time out or error; both are acceptable (Go test).
    if let Ok(Ok(_)) = result {
        panic!("unexpected success");
    }
}

#[tokio::test]
async fn register_and_exchange_confirm_before_spake2() {
    let relay = bind_udp().await;
    let peer = bind_udp().await;
    peer.connect(relay.local_addr().unwrap()).await.unwrap();

    let cancel = CancellationToken::new();
    let cfg = PeerConfig {
        exchange_deadline: Some(Duration::from_millis(400)),
        read_deadline: Some(Duration::from_millis(100)),
        ..Default::default()
    };
    let relay_task = tokio::spawn(async move {
        let on_msg = move || {
            Some(
                format!(
                    "MSGD confirm {}\n",
                    hex::to_hex_lower(&[0u8; CONFIRM_PAYLOAD_SIZE])
                )
                .into_bytes(),
            )
        };
        relay_sim(
            relay,
            "testroom2",
            30,
            Duration::from_millis(200),
            Some(Box::new(on_msg)),
        )
        .await
    });
    let result = tokio::time::timeout(
        Duration::from_secs(30),
        register_and_exchange(
            &cancel,
            &peer,
            "testroom2",
            "test-code-for-spake2",
            b"fingerprint",
            &cfg,
        ),
    )
    .await;
    relay_task.abort();
    if let Ok(Ok(_)) = result {
        panic!("unexpected success");
    }
}

#[tokio::test]
async fn register_and_exchange_confirm_payload_too_short() {
    let relay = bind_udp().await;
    let peer = bind_udp().await;
    peer.connect(relay.local_addr().unwrap()).await.unwrap();

    let cancel = CancellationToken::new();
    let cfg = PeerConfig {
        exchange_deadline: Some(Duration::from_millis(400)),
        read_deadline: Some(Duration::from_millis(100)),
        ..Default::default()
    };

    // Build a valid peer SPAKE2 payload, like the Go test.
    let peer_state = spake2::new_state("test-code-for-spake2").unwrap();
    let peer_m = peer_state.blinded_bytes_m();
    let peer_n = peer_state.blinded_bytes_n();
    let mut payload = Vec::with_capacity(SPAKE2_PAYLOAD_LEN);
    payload.extend_from_slice(&peer_m);
    payload.extend_from_slice(&peer_n);
    payload.extend_from_slice(&[0u8; 32]);
    let hex_spake2 = hex::to_hex_lower(&payload);

    let relay_task = tokio::spawn({
        let hs = hex_spake2;
        async move {
            let on_msg = move || {
                let mut resp = format!("MSGD spake2 {hs}\n").into_bytes();
                resp.extend(
                    format!("MSGD confirm {}\n", hex::to_hex_lower(&[0u8; 64])).into_bytes(),
                );
                Some(resp)
            };
            relay_sim(
                relay,
                "testroom3",
                30,
                Duration::from_millis(200),
                Some(Box::new(on_msg)),
            )
            .await
        }
    });
    let result = tokio::time::timeout(
        Duration::from_secs(30),
        register_and_exchange(
            &cancel,
            &peer,
            "testroom3",
            "test-code-for-spake2",
            b"fingerprint",
            &cfg,
        ),
    )
    .await;
    relay_task.abort();
    if let Ok(Ok(_)) = result {
        panic!("unexpected success");
    }
}

#[tokio::test]
async fn register_and_exchange_exchange_timeout() {
    let _relay = bind_udp().await; // never reads: unresponsive relay
    let peer = bind_udp().await;
    peer.connect(_relay.local_addr().unwrap()).await.unwrap();

    let cancel = CancellationToken::new();
    let cfg = PeerConfig {
        exchange_deadline: Some(Duration::from_millis(300)),
        read_deadline: Some(Duration::from_millis(100)),
        ..Default::default()
    };
    let err = tokio::time::timeout(
        Duration::from_secs(30),
        register_and_exchange(
            &cancel,
            &peer,
            "timeout-test",
            "timeout-test-code",
            b"fp",
            &cfg,
        ),
    )
    .await
    .unwrap()
    .unwrap_err();
    assert!(matches!(err, ExchangeError::Timeout));
}

#[tokio::test]
async fn register_and_exchange_non_timeout_net_error() {
    // The Go test closes the peer conn mid-operation. tokio's UdpSocket
    // cannot be closed from outside, so the Rust analog closes the remote
    // side instead: the peer's REG packet triggers an ICMP
    // port-unreachable, making the next read a non-timeout error.
    let relay = bind_udp().await;
    let relay_addr = relay.local_addr().unwrap();
    drop(relay);

    let peer = bind_udp().await;
    peer.connect(relay_addr).await.unwrap();

    let cancel = CancellationToken::new();
    let cfg = PeerConfig {
        exchange_deadline: Some(Duration::from_secs(2)),
        read_deadline: Some(Duration::from_millis(100)),
        ..Default::default()
    };

    let result = tokio::time::timeout(
        Duration::from_secs(30),
        register_and_exchange(
            &cancel,
            &peer,
            "testroom-neterr",
            "test-code-neterr-test",
            b"fingerprint",
            &cfg,
        ),
    )
    .await;
    // Should return some error (Go: non-nil after close).
    if let Ok(Ok(_)) = result {
        panic!("unexpected success");
    }
}
