//! Regression test for the lost final confirm (Go
//! `TestConnect_SurvivesLostFinalConfirm`): a peer stops answering the
//! moment the other side's confirm arrives, so if every confirm it sent
//! before then is lost, the other side never completes the exchange. The
//! relay here drops all confirms from the first peer to send one for a 3 s
//! burst, then forwards normally. Before the fix this failed every time.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use qvole_protocol::connect::connect_peer;
use qvole_protocol::exchange::PeerConfig;
use qvole_relay::Relay;
use tokio::net::UdpSocket;
use tokio_util::sync::CancellationToken;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn connect_survives_lost_final_confirm() {
    let sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let relay_addr = sock.local_addr().unwrap().to_string();

    let relay_sock = Arc::clone(&sock);
    let relay_task = tokio::spawn(async move {
        let relay = Relay::new();
        let mut victim: Option<(SocketAddr, Instant)> = None;
        let mut buf = vec![0u8; 1500];
        loop {
            let Ok((n, src)) = relay_sock.recv_from(&mut buf).await else {
                return;
            };
            let data = &buf[..n];
            let is_confirm =
                data.starts_with(b"MSG ") && data.windows(9).any(|w| w == b" confirm ");
            if is_confirm {
                let (v, start) = *victim.get_or_insert((src, Instant::now()));
                if v == src && start.elapsed() < Duration::from_secs(3) {
                    continue;
                }
            }
            relay.handle_packet(&relay_sock, data, src).await;
        }
    });

    let code = format!(
        "lost-confirm-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    );
    let cfg = PeerConfig {
        exchange_deadline: Some(Duration::from_secs(15)),
        punch_timeout: Some(Duration::from_secs(3)),
        handshake_timeout: Some(Duration::from_secs(10)),
        ..Default::default()
    };
    let cancel = CancellationToken::new();

    let mut peers = Vec::new();
    for _ in 0..2 {
        let (cancel, relay_addr, code) = (cancel.clone(), relay_addr.clone(), code.clone());
        peers.push(tokio::spawn(async move {
            connect_peer(&cancel, &relay_addr, &code, &cfg).await
        }));
        tokio::time::sleep(Duration::from_millis(300)).await;
    }

    let mut failures = Vec::new();
    let mut conns = Vec::new();
    for (i, p) in peers.into_iter().enumerate() {
        match tokio::time::timeout(Duration::from_secs(30), p).await {
            Ok(Ok(Ok(c))) => conns.push(c),
            Ok(Ok(Err(e))) => failures.push(format!("peer {i}: {e}")),
            Ok(Err(e)) => failures.push(format!("peer {i}: task: {e}")),
            Err(_) => failures.push(format!("peer {i}: timed out")),
        }
    }
    for c in &conns {
        c.conn.close(0u32.into(), b"done");
    }
    relay_task.abort();
    assert!(failures.is_empty(), "{failures:?}");
}
