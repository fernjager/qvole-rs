//! Hole punching (Go `internal/engine/punch.go`).
//!
//! After the SPAKE2 exchange, the two peers send small UDP payloads directly
//! at the addresses learned from the confirm messages until the NAT
//! mappings open. The receiving side matches packets by IP only (the port is
//! relaxed for symmetric NATs).

use std::time::Duration;

use rand::RngCore;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use crate::logger::LOG_HOLE;

pub const PUNCH_BUFFER_SIZE: usize = 1600;
pub const PUNCH_READ_DEADLINE: Duration = Duration::from_millis(100);
const PUNCH_LOG_INTERVAL: u32 = 50;
const PUNCH_INTERVAL_CHANGE: u32 = 5;
pub const PUNCH_INTERVALS: [Duration; 3] = [
    Duration::from_millis(50),
    Duration::from_millis(100),
    Duration::from_millis(200),
];
pub const PUNCH_PAYLOAD_SIZES: [usize; 4] = [5, 50, 100, 200];

/// Listens for the first packet from the peer's IP (Go `listenForPunch`).
///
/// `peer_ip = None` accepts from anyone. The IP filter is relaxed on the
/// port for symmetric NATs (documented in Go). Every non-matching packet is
/// consumed, like Go's `ReadFromUDP`.
///
/// Note: like Go, this leaves a 100 ms read deadline set on `sock` when it
/// returns; the caller clears it before handing the socket to QUIC
/// (Go `udpConn.SetReadDeadline(time.Time{})` in `ConnectPeerWithConfig`).
pub async fn listen_for_punch(
    cancel: &CancellationToken,
    sock: &UdpSocket,
    peer_ip: Option<std::net::IpAddr>,
    tx: mpsc::Sender<std::net::SocketAddr>,
) -> std::io::Result<()> {
    let mut buf = vec![0u8; PUNCH_BUFFER_SIZE];
    loop {
        if cancel.is_cancelled() {
            return Ok(());
        }
        // Go: SetReadDeadline(now + punchReadDeadline) before every read.
        // tokio UDP has no deadline API; a timeout-wrapped recv_from is
        // equivalent (and leaves no stale deadline on the socket).
        let (n, from) =
            match tokio::time::timeout(PUNCH_READ_DEADLINE, sock.recv_from(&mut buf)).await {
                Ok(Ok(v)) => v,
                // Go continues on every net error (timeout or not).
                Ok(Err(_)) | Err(_) => continue,
            };
        if n == 0 {
            continue;
        }
        if let Some(expected) = peer_ip
            && from.ip() != expected
        {
            continue;
        }
        LOG_HOLE.printf(&format!("Punch packet received from {from}"));
        let _ = tx.try_send(from);
        return Ok(());
    }
}

/// Starts the punch loop and first-packet listener in the background (Go
/// `startHolePunching`).
///
/// Returns the receiver (resolving with the observed source address when the
/// first direct packet from the peer's IP arrives, or `None` if `cancel`
/// fires first - Go's channel closed after the timeout) and the task handle,
/// so the caller can wait for the goroutines to observe cancellation (Go's
/// `<-successCh` after `cancel()`).
pub fn start_hole_punching(
    cancel: &CancellationToken,
    sock: std::sync::Arc<UdpSocket>,
    peer_addr: std::net::SocketAddr,
) -> (
    tokio::sync::oneshot::Receiver<Option<std::net::SocketAddr>>,
    tokio::task::JoinHandle<()>,
) {
    let (tx, rx) = tokio::sync::oneshot::channel::<Option<std::net::SocketAddr>>();
    let main_cancel = cancel.clone();
    let listener_cancel = cancel.clone();
    let peer_ip = Some(peer_addr.ip());

    let handle = tokio::spawn(async move {
        let mut payloads: Vec<Vec<u8>> = Vec::with_capacity(PUNCH_PAYLOAD_SIZES.len());
        for &sz in &PUNCH_PAYLOAD_SIZES {
            let mut p = vec![0u8; sz];
            rand::rngs::OsRng.fill_bytes(&mut p);
            payloads.push(p);
        }

        LOG_HOLE.printf(&format!("Hole punching to {peer_addr}"));

        let (punch_tx, mut punch_rx) = mpsc::channel::<std::net::SocketAddr>(1);
        let listener_sock = std::sync::Arc::clone(&sock);
        let listener = tokio::spawn(async move {
            listen_for_punch(&listener_cancel, &listener_sock, peer_ip, punch_tx).await
        });

        let mut interval_idx = 0usize;
        let mut attempt = 0u32;
        let mut ticker = tokio::time::interval_at(
            tokio::time::Instant::now() + PUNCH_INTERVALS[0],
            PUNCH_INTERVALS[0],
        );
        let result = loop {
            tokio::select! {
                _ = main_cancel.cancelled() => break None,
                maybe = punch_rx.recv() => match maybe {
                    Some(first) => break Some(first),
                    None => break None,
                },
                _ = ticker.tick() => {
                    // Go: conn.WriteTo(payload, peerAddr), best-effort.
                    let _ = sock.send_to(&payloads[attempt as usize % PUNCH_PAYLOAD_SIZES.len()], peer_addr).await;
                    attempt += 1;
                    if attempt.is_multiple_of(PUNCH_LOG_INTERVAL) {
                        LOG_HOLE.printf(&format!(
                            "Hole punch attempt {attempt}, interval {:?}",
                            PUNCH_INTERVALS[interval_idx]
                        ));
                    }
                    if attempt.is_multiple_of(PUNCH_INTERVAL_CHANGE) && interval_idx < PUNCH_INTERVALS.len() - 1
                    {
                        interval_idx += 1;
                        ticker.reset_after(PUNCH_INTERVALS[interval_idx]);
                    }
                }
            }
        };
        // Go: <-punchDone - wait for the listener to observe cancellation or
        // complete before returning.
        let _ = listener.await;
        let _ = tx.send(result);
    });
    (rx, handle)
}

/// Outcome of waiting for the punch (Go's `select` over `successCh` and
/// `punchCtx.Done()` in `ConnectPeerWithConfig`).
#[derive(Debug)]
pub enum PunchOutcome {
    /// Go: `observedAddr != nil` - first packet observed from the peer.
    Observed(std::net::SocketAddr),
    /// Go: `observedAddr == nil` - the punch task was canceled before any
    /// packet arrived ("Hole punch aborted, falling back to QUIC").
    Aborted,
    /// Go: `<-punchCtx.Done()` - the punch timeout expired ("Hole punch
    /// timed out, falling back to QUIC").
    TimedOut,
}

/// Resolves the punch outcome within `punch_timeout`.
pub async fn await_punch(
    rx: tokio::sync::oneshot::Receiver<Option<std::net::SocketAddr>>,
    punch_timeout: Duration,
) -> PunchOutcome {
    tokio::select! {
        r = rx => match r {
            Ok(Some(addr)) => PunchOutcome::Observed(addr),
            _ => PunchOutcome::Aborted,
        },
        _ = tokio::time::sleep(punch_timeout) => PunchOutcome::TimedOut,
    }
}

#[cfg(test)]
#[path = "punch_tests.rs"]
mod tests;
