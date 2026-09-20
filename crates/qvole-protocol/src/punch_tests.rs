//! Tests for hole punching (port of `internal/engine/punch_test.go`).

use super::*;
use std::sync::Arc;

async fn new_udp() -> UdpSocket {
    UdpSocket::bind("127.0.0.1:0".parse::<std::net::SocketAddr>().unwrap())
        .await
        .unwrap()
}

#[tokio::test]
async fn listen_for_punch_receives_from_correct_peer() {
    let listener = Arc::new(new_udp().await);
    let sender = new_udp().await;
    let peer_ip = Some(sender.local_addr().unwrap().ip());

    let (tx, mut rx) = mpsc::channel::<std::net::SocketAddr>(1);
    let cancel = CancellationToken::new();
    let cancel2 = cancel.clone();
    let l2 = std::sync::Arc::clone(&listener);
    let task = tokio::spawn(async move { listen_for_punch(&cancel2, &l2, peer_ip, tx).await });

    tokio::time::sleep(Duration::from_millis(50)).await;
    sender
        .send_to(b"punch", listener.local_addr().unwrap())
        .await
        .unwrap();

    match tokio::time::timeout(Duration::from_secs(2), rx.recv()).await {
        Ok(Some(_)) => {}
        _ => panic!("did not receive punch from correct peer"),
    }
    cancel.cancel();
    let _ = task.await;
}

#[tokio::test]
async fn listen_for_punch_accepts_same_ip_different_port() {
    let listener = Arc::new(new_udp().await);
    let _correct_sender = new_udp().await;
    let wrong_sender = new_udp().await; // same IP (127.0.0.1), different port

    let peer_ip = _correct_sender.local_addr().unwrap().ip();
    let (tx, mut rx) = mpsc::channel::<std::net::SocketAddr>(1);
    let cancel = CancellationToken::new();
    let cancel2 = cancel.clone();
    let l2 = std::sync::Arc::clone(&listener);
    let task =
        tokio::spawn(async move { listen_for_punch(&cancel2, &l2, Some(peer_ip), tx).await });

    tokio::time::sleep(Duration::from_millis(50)).await;
    wrong_sender
        .send_to(b"wrong", listener.local_addr().unwrap())
        .await
        .unwrap();

    let addr = match tokio::time::timeout(Duration::from_secs(2), rx.recv()).await {
        Ok(Some(a)) => a,
        _ => panic!("punch from same IP, different port was rejected"),
    };
    assert_eq!(addr.ip(), peer_ip);
    cancel.cancel();
    let _ = task.await;
}

#[tokio::test]
async fn listen_for_punch_nil_peer_addr() {
    let listener = Arc::new(new_udp().await);
    let sender = new_udp().await;

    let (tx, mut rx) = mpsc::channel::<std::net::SocketAddr>(1);
    let cancel = CancellationToken::new();
    let cancel2 = cancel.clone();
    let l2 = std::sync::Arc::clone(&listener);
    let task = tokio::spawn(async move { listen_for_punch(&cancel2, &l2, None, tx).await });

    tokio::time::sleep(Duration::from_millis(50)).await;
    sender
        .send_to(b"punch", listener.local_addr().unwrap())
        .await
        .unwrap();

    match tokio::time::timeout(Duration::from_secs(2), rx.recv()).await {
        Ok(Some(_)) => {}
        _ => panic!("did not receive punch with nil peer addr"),
    }
    cancel.cancel();
    let _ = task.await;
}

#[tokio::test]
async fn listen_for_punch_context_cancel() {
    let listener = Arc::new(new_udp().await);
    let (_tx, _rx) = mpsc::channel::<std::net::SocketAddr>(1);
    let cancel = CancellationToken::new();
    let cancel2 = cancel.clone();
    let l2 = std::sync::Arc::clone(&listener);
    let task = tokio::spawn(async move { listen_for_punch(&cancel2, &l2, None, _tx).await });

    tokio::time::sleep(Duration::from_millis(50)).await;
    cancel.cancel();

    match tokio::time::timeout(Duration::from_secs(2), task).await {
        Ok(Ok(Ok(_))) => {}
        other => panic!("listen_for_punch did not exit on cancel: {other:?}"),
    }
}

#[tokio::test]
async fn listen_for_punch_zero_length_packet() {
    let listener = Arc::new(new_udp().await);
    let sender = new_udp().await;

    let (tx, mut rx) = mpsc::channel::<std::net::SocketAddr>(1);
    let cancel = CancellationToken::new();
    let cancel2 = cancel.clone();
    let l2 = std::sync::Arc::clone(&listener);
    let task = tokio::spawn(async move { listen_for_punch(&cancel2, &l2, None, tx).await });

    tokio::time::sleep(Duration::from_millis(50)).await;
    // Zero-length packet must be ignored (Go: n <= 0 continue).
    sender
        .send_to(b"", listener.local_addr().unwrap())
        .await
        .unwrap();

    // The listener must not have accepted it.
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(
        rx.try_recv().is_err(),
        "zero-length packet must not be accepted"
    );
    cancel.cancel();
    let _ = task.await;
}

#[tokio::test]
async fn listen_for_punch_non_timeout_read_error() {
    // The Go test closes the conn mid-loop. tokio's UdpSocket cannot be
    // closed from outside, so the Rust analog pre-arms an ICMP
    // port-unreachable: the first recv_from fails with a non-timeout error,
    // and the listener must survive it and still exit on cancel.
    let dead = new_udp().await;
    let dead_addr = dead.local_addr().unwrap();
    drop(dead);

    let listener = new_udp().await;
    listener.connect(dead_addr).await.unwrap();
    let _ = listener.send(b"x").await; // queue the ICMP port-unreachable

    let (_tx, _rx) = mpsc::channel::<std::net::SocketAddr>(1);
    let cancel = CancellationToken::new();
    let cancel2 = cancel.clone();
    let task = tokio::spawn(async move { listen_for_punch(&cancel2, &listener, None, _tx).await });

    tokio::time::sleep(Duration::from_millis(150)).await;
    cancel.cancel();

    match tokio::time::timeout(Duration::from_secs(2), task).await {
        Ok(Ok(Ok(_))) => {}
        other => panic!("listen_for_punch did not exit after read error: {other:?}"),
    }
}

#[tokio::test]
async fn start_hole_punching_sends_packets() {
    let receiver = new_udp().await;
    let puncher = Arc::new(new_udp().await);
    let peer_addr = receiver.local_addr().unwrap();

    let cancel = CancellationToken::new();
    let (rx, _handle) = start_hole_punching(&cancel, puncher, peer_addr);

    let mut buf = vec![0u8; PUNCH_BUFFER_SIZE];
    let n = tokio::time::timeout(Duration::from_secs(2), receiver.recv_from(&mut buf))
        .await
        .unwrap()
        .unwrap()
        .0;
    assert!(n > 0, "did not receive punch packet");
    cancel.cancel();
    drop(rx);
}

#[tokio::test]
async fn start_hole_punching_context_cancel() {
    let _receiver = new_udp().await;
    let puncher = Arc::new(new_udp().await);
    let peer_addr = _receiver.local_addr().unwrap();

    let cancel = CancellationToken::new();
    let (rx, handle) = start_hole_punching(&cancel, puncher, peer_addr);

    tokio::time::sleep(Duration::from_millis(100)).await;
    cancel.cancel();

    match tokio::time::timeout(Duration::from_secs(3), rx).await {
        Ok(Ok(None)) => {}
        other => panic!("start_hole_punching did not exit after cancel: {other:?}"),
    }
    // The task must also terminate once cancellation is observed.
    let _ = handle.await;
}

#[tokio::test]
async fn start_hole_punching_detects_peer() {
    let puncher = Arc::new(new_udp().await);
    let peer = new_udp().await;
    let puncher_addr = puncher.local_addr().unwrap();
    let peer_addr = peer.local_addr().unwrap();

    let cancel = CancellationToken::new();

    // Peer receives the first punch and replies.
    let reply_task = tokio::spawn(async move {
        let mut buf = vec![0u8; PUNCH_BUFFER_SIZE];
        let n = match tokio::time::timeout(Duration::from_secs(3), peer.recv_from(&mut buf)).await {
            Ok(Ok(v)) => v.0,
            _ => return,
        };
        if n > 0 {
            let _ = peer.send_to(b"reply", puncher_addr).await;
        }
    });

    let (rx, _handle) = start_hole_punching(&cancel, puncher, peer_addr);
    match tokio::time::timeout(Duration::from_secs(5), rx).await {
        Ok(Ok(Some(addr))) => {
            assert_eq!(addr.ip(), peer_addr.ip());
        }
        other => panic!("start_hole_punching did not detect peer: {other:?}"),
    }
    cancel.cancel();
    let _ = reply_task.await;
}
