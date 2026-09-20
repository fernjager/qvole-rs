//! Pipe feature: stdin/stdout bridging over QUIC.
//!
//! Port of `internal/app/pipe.go` (`StartStdinPipe`) and the `RunPipe` flow
//! in `internal/engine/client.go`.
//!
//! ## Design notes
//!
//! * Go's `StartStdinPipe(ctx, rwc)` takes one `io.ReadWriteCloser` and
//!   reads/writes the process `os.Stdin`/`os.Stdout` directly. The Rust port
//!   injects the stream halves and the stdio halves instead (quinn streams
//!   have single-owner send/recv halves, and real stdio must stay
//!   replaceable for tests).
//! * Go's `sync.Once` closer (`rwc.Close()` + `os.Stdin.Close()`) becomes
//!   the `close_stdin` closure, invoked at most once when either bridge
//!   direction completes. The stream's send half is FINned when the
//!   stdin→stream direction ends (Go's `rwc.Close()`), not only on drop, so
//!   a local stdin EOF half-closes the stream while the peer→stdout
//!   direction keeps reading.
//! * Go's `RunPipe` watcher goroutine (conn done or ctx done →
//!   `closeStdin`) becomes a task that cancels a child stop token; the
//!   stdin→stream copy stops on that token, and the stream FIN is implicit
//!   in the `SendStream` drop.
//! * Go's `RunPipe` does not close the QUIC connection on ctx cancel; the
//!   inbound copy relies on the peer's graceful close (or the 120 s idle
//!   timeout) to end. Rust's [`connect_peer`] installs `close_on_cancel`,
//!   so the inbound read unblocks immediately on cancel (an improvement).
//! * The accept-phase `tokio::select!` is biased toward cancel so a local
//!   cancellation deterministically takes the "canceled" branch (a Go
//!   `select` picks randomly among ready branches).
//! * Go's `RunPipe` originally skipped `StopAndLog` and the finish-delay
//!   sleep on the accept-canceled and accept-error paths, leaving the tracker
//!   goroutine running until process exit. This port tears the tracker down
//!   unconditionally: [`run_pipe_connected`] always stops the reporter and
//!   applies the finish delay before closing the connection, on every return
//!   path.

use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use quinn::{Connection, VarInt};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio_util::sync::CancellationToken;

use qvole_protocol::connect::{self, ConnectError};
use qvole_protocol::disconnect::log_disconnect;
use qvole_protocol::exchange::PeerConfig;
use qvole_protocol::logger::{LOG_EXEC, LOG_PIPE};
use qvole_protocol::role::role_string;
use qvole_protocol::stats::StatsTracker;

use crate::copy::{CopyErrorKind, conn_close_kind, copy_stream, flush_close};

use crate::stream_conn::announce_stream;

/// Go `pipeFinishDelay`: grace sleep between the last copy finishing and the
/// connection close (CONNECTION_CLOSE does not guarantee delivery of
/// unacknowledged stream data).
pub const PIPE_FINISH_DELAY: Duration = Duration::from_millis(500);

/// Go `pipeCloseGrace`: after the inbound copy completes, wait up to this
/// long for the local stdin→stream copy to finish before closing the
/// outbound stream.
pub const PIPE_CLOSE_GRACE: Duration = Duration::from_secs(5);

/// Go `statsReportInterval`.
pub const STATS_REPORT_INTERVAL: Duration = Duration::from_secs(2);

/// Errors from the pipe feature.
#[derive(Debug, thiserror::Error)]
pub enum PipeError {
    /// Connection establishment failed (Go: the `ConnectPeer` error).
    #[error(transparent)]
    Connect(#[from] ConnectError),
    /// Local cancellation (Go: `context.Canceled`).
    #[error("canceled")]
    Canceled,
    /// Other QUIC-level failure (Go: the wrapped error returned as-is).
    #[error("quic: {0}")]
    Quic(String),
}

/// Port of `StartStdinPipe`: bridges a QUIC stream to stdin/stdout,
/// bidirectionally.
///
/// `rwc_read`/`rwc_write` are the two halves of the peer stream (Go: one
/// `io.ReadWriteCloser`); `stdin`/`stdout` are the local stdio. Data flows
/// both ways until both directions complete (EOF or error) or `cancel`
/// fires (Go: `ctx.Done` → the `stdinCloser` goroutine).
///
/// **Half-close semantics:** when local stdin reaches EOF,
/// only the stream's send half is FINned; the peer→stdout direction keeps
/// running until the peer FINs. This mirrors Go, where `stdinCloser` does
/// `rwc.Close()` (a send-side FIN) + `os.Stdin.Close()` while the
/// peer→stdout `io.Copy` keeps reading. Rust cannot rely on closing stdin to
/// unblock a parked read on all platforms, so the stdin direction is
/// additionally stopped when the peer→stdout direction finishes first.
///
/// `close_stdin` is invoked at most once, when the first direction completes
/// (Go's `sync.Once` closer: `rwc.Close()` + `os.Stdin.Close()`); the stream
/// send-half FIN happens when the stdin direction ends.
pub async fn start_stdin_pipe<R, W, IN, OUT>(
    cancel: &CancellationToken,
    rwc_read: Pin<&mut R>,
    rwc_write: Pin<&mut W>,
    stdin: Pin<&mut IN>,
    stdout: Pin<&mut OUT>,
    close_stdin: impl FnOnce(),
) where
    R: AsyncRead,
    W: AsyncWrite,
    IN: AsyncRead,
    OUT: AsyncWrite,
{
    let mut close_stdin = Some(close_stdin);
    // ctx cancel stops both directions; the stdin direction also stops when
    // the peer→stdout direction finishes first (Go's `os.Stdin.Close()`).
    let stop = cancel.child_token();
    let stdin_stop = stop.child_token();
    let stdin_copy_stop = stdin_stop.clone();

    // stdin → stream: FIN the send half when stdin ends (Go `rwc.Close()`).
    let mut stdin_write = rwc_write;
    let mut stdin_src = stdin;
    let mut stdin_dir = Box::pin(async move {
        let _ = copy_stream(
            stdin_write.as_mut(),
            stdin_src.as_mut(),
            None,
            &stdin_copy_stop,
        )
        .await;
        let _ = AsyncWriteExt::shutdown(&mut stdin_write).await;
    });

    // stream → stdout: keeps running after local stdin EOF (Go semantics).
    let mut rwc_src = rwc_read;
    let mut out = stdout;
    let mut inbound_dir = Box::pin(async move {
        let _ = copy_stream(out.as_mut(), rwc_src.as_mut(), None, &stop).await;
    });

    let mut fired = false;
    let mut stdin_done = false;
    let mut inbound_done = false;
    std::future::poll_fn(move |cx| {
        if !stdin_done {
            stdin_done = stdin_dir.as_mut().poll(cx).is_ready();
        }
        if !inbound_done {
            inbound_done = inbound_dir.as_mut().poll(cx).is_ready();
        }
        if (stdin_done || inbound_done) && !fired {
            fired = true;
            // Go stdinCloser: `rwc.Close()` (the stdin direction FINs the
            // send half) + `os.Stdin.Close()`.
            if let Some(f) = close_stdin.take() {
                f();
            }
        }
        if inbound_done && !stdin_done {
            // The peer is done and a parked stdin read cannot be unblocked by
            // closing stdin on all platforms; stop the stdin direction.
            stdin_stop.cancel();
        }
        if stdin_done && inbound_done {
            std::task::Poll::Ready(())
        } else {
            std::task::Poll::Pending
        }
    })
    .await;
}

/// Port of `RunPipeMode`: accepts the peer's bidirectional stream and
/// bridges it to stdin/stdout.
///
/// `cancel` (Go's `ctx`) unblocks the accept and the stdin bridge. On
/// cancel this returns [`PipeError::Canceled`] (Go: `ctx.Err()`); the
/// stream close is implicit (the stream halves are dropped).
pub async fn run_pipe_mode<IN, OUT>(
    cancel: &CancellationToken,
    conn: &Connection,
    role: &str,
    stdin: Pin<&mut IN>,
    stdout: Pin<&mut OUT>,
    close_stdin: impl FnOnce(),
) -> Result<(), PipeError>
where
    IN: AsyncRead,
    OUT: AsyncWrite,
{
    LOG_EXEC.printf_success(&format!("Connected as {role}"));
    let bi = tokio::select! {
        biased;
        () = cancel.cancelled() => return Err(PipeError::Canceled),
        r = conn.accept_bi() => r,
    };
    let (mut rwc_write, mut rwc_read) = match bi {
        Ok(bi) => bi,
        Err(e) => match conn_close_kind(&e) {
            // Go: `*quic.ApplicationError` with ErrorCode 0 → nil.
            CopyErrorKind::Benign => return Ok(()),
            // Go: `LogDisconnect` → nil.
            CopyErrorKind::Disconnect => {
                let _ = log_disconnect(&LOG_EXEC, &e);
                return Ok(());
            }
            // Go: `return err` (including `context.Canceled`, which the
            // biased select above takes first).
            _ => return Err(PipeError::Quic(e.to_string())),
        },
    };

    start_stdin_pipe(
        cancel,
        Pin::new(&mut rwc_read),
        Pin::new(&mut rwc_write),
        stdin,
        stdout,
        close_stdin,
    )
    .await;

    // Go: select on done (→ nil) vs ctx.Done (→ stream.Close + ctx.Err).
    // When `cancel` fired, `start_stdin_pipe` returned via its stop token,
    // so report cancellation; otherwise the bridge completed normally.
    if cancel.is_cancelled() {
        Err(PipeError::Canceled)
    } else {
        Ok(())
    }
}

/// Port of `engine.RunPipe`: establishes a peer-to-peer connection and
/// bridges stdin/stdout over QUIC streams.
///
/// `cancel` (Go's `ctx`) tears the connection down: [`connect_peer`]
/// installs `close_on_cancel`, so every blocking call below unblocks on
/// cancel. `stats` enables periodic throughput logging;
/// `stdin_is_terminal` mirrors Go's `isTerminal(os.Stdin)` (a terminal
/// stdin opens no outbound stream).
///
/// `stdin`/`stdout` are moved into the copy tasks (production:
/// `tokio::io::stdin()` / `tokio::io::stdout()`).
#[allow(clippy::too_many_arguments)] // Go RunPipe parity (8 params)
pub async fn run_pipe<IN, OUT>(
    cancel: &CancellationToken,
    relay_addr: &str,
    code: &str,
    cfg: &PeerConfig,
    stats: bool,
    stdin_is_terminal: bool,
    stdin: IN,
    stdout: OUT,
) -> Result<(), PipeError>
where
    IN: AsyncRead + Unpin + Send + 'static,
    OUT: AsyncWrite + Unpin + Send + 'static,
{
    let connected = connect::connect_peer(cancel, relay_addr, code, cfg).await?;
    // `connected` (endpoint + connection) stays alive for the whole pipe.
    run_pipe_connected(
        cancel,
        &connected.conn,
        connected.is_server,
        stats,
        stdin_is_terminal,
        stdin,
        stdout,
    )
    .await
}

/// Port of the post-connect phase of `engine.RunPipe`.
///
/// `conn` is an established QUIC connection (in production from
/// [`connect_peer`]; in tests a plain QUIC handshake). See [`run_pipe`] for
/// the parameter semantics.
pub async fn run_pipe_connected<IN, OUT>(
    cancel: &CancellationToken,
    conn: &Connection,
    is_server: bool,
    stats: bool,
    stdin_is_terminal: bool,
    stdin: IN,
    stdout: OUT,
) -> Result<(), PipeError>
where
    IN: AsyncRead + Unpin + Send + 'static,
    OUT: AsyncWrite + Unpin + Send + 'static,
{
    let role = role_string(is_server);
    LOG_PIPE.printf_success(&format!("Connected as {role}"));

    let tracker = Arc::new(StatsTracker::new());
    if stats {
        // Go: `tracker.Start(statsReportInterval)`; the reporter lives
        // until `stop_and_log()`. Detached: dropping the handle does not
        // abort the spawned task.
        let reporter = Arc::clone(&tracker).start(STATS_REPORT_INTERVAL);
        drop(reporter);
    }

    let result = run_pipe_body(
        cancel,
        conn,
        Arc::clone(&tracker),
        stdin_is_terminal,
        stdin,
        stdout,
    )
    .await;

    // Teardown is unconditional after the tracker
    // starts. The finish delay precedes the connection close so
    // CONNECTION_CLOSE cannot race in-flight stream data. `stop_and_log` is
    // idempotent, so this is safe even if a path already stopped it.
    tracker.stop_and_log();
    tokio::time::sleep(PIPE_FINISH_DELAY).await;

    // Go: `defer conn.CloseWithError(0, "done")`.
    conn.close(VarInt::from_u32(0), b"done");
    flush_close().await;
    result
}

/// Body of [`run_pipe_connected`]: performs the stream setup and the
/// bidirectional copy, without stopping the stats tracker or closing the
/// connection (the caller owns the unconditional teardown). Early returns
/// therefore carry the outcome only.
async fn run_pipe_body<IN, OUT>(
    cancel: &CancellationToken,
    conn: &Connection,
    tracker: Arc<StatsTracker>,
    stdin_is_terminal: bool,
    stdin: IN,
    stdout: OUT,
) -> Result<(), PipeError>
where
    IN: AsyncRead + Unpin + Send + 'static,
    OUT: AsyncWrite + Unpin + Send + 'static,
{
    // Go watcher goroutine: conn done OR ctx done → closeStdin.
    let pair_stop = cancel.child_token();
    {
        let cancel = cancel.clone();
        let conn = conn.clone();
        let pair_stop = pair_stop.clone();
        tokio::spawn(async move {
            tokio::select! {
                _ = cancel.cancelled() => {}
                _ = conn.closed() => {}
            }
            pair_stop.cancel();
        });
    }

    let mut stdin_task: Option<tokio::task::JoinHandle<()>> = None;

    if !stdin_is_terminal {
        let mut send = match conn.open_bi().await {
            // The recv half of our outbound stream is unused (the peer only
            // writes on its own outbound stream).
            Ok((send, _recv)) => send,
            Err(e) => {
                LOG_PIPE.printf_error(&format!("Open outbound stream failed: {e}"));
                // Go: return err; the deferred `conn.CloseWithError(0, "done")`.
                return Err(PipeError::Quic(e.to_string()));
            }
        };
        // Go quic-go does *not* announce a locally-opened stream until data
        // or FIN, and quinn defers the stream header to the first write.
        // Force the header now so a quinn peer can accept the stream and send
        // to us even when our stdin is empty (this is a
        // quinn↔quinn workaround and does not fix Go→Rust silent exec).
        if let Err(e) = announce_stream(&mut send).await {
            LOG_PIPE.printf_error(&format!("Open outbound stream failed: {e}"));
            return Err(PipeError::Quic(e.to_string()));
        }
        // Go: a detached goroutine - RunPipe must not wait for it (a stdin
        // read blocked on a pipe cannot always be interrupted).
        let tracker = Arc::clone(&tracker);
        let pair_stop = pair_stop.clone();
        stdin_task = Some(tokio::spawn(async move {
            let mut dst = tracker.tx_async_writer(send);
            let mut src = stdin;
            let _ = copy_stream(Pin::new(&mut dst), Pin::new(&mut src), None, &pair_stop).await;
            // Go: closeStdin() after the copy → out.Close() (FIN) +
            // os.Stdin.Close(). `shutdown` maps to `SendStream::finish`
            // (FIN); the stdin handle is dropped with the task.
            let _ = dst.shutdown().await;
            pair_stop.cancel();
        }));
    }

    // Go: `s, acceptErr := conn.AcceptStream(ctx)`.
    let inbound = tokio::select! {
        biased;
        () = cancel.cancelled() => {
            pair_stop.cancel(); // Go: closeStdin()
            LOG_PIPE.printf("Accept inbound stream canceled");
            return Ok(());
        }
        r = conn.accept_bi() => r,
    };

    let mut recv = match inbound {
        // The send half of the peer's stream is unused (the peer never
        // writes to it).
        Ok((_send, recv)) => recv,
        Err(e) => {
            pair_stop.cancel(); // Go: closeStdin()
            match conn_close_kind(&e) {
                CopyErrorKind::Benign => return Ok(()),
                CopyErrorKind::Disconnect => {
                    let _ = log_disconnect(&LOG_PIPE, &e);
                    return Ok(());
                }
                _ => {
                    LOG_PIPE.printf_error(&format!("Accept inbound stream failed: {e}"));
                    return Err(PipeError::Quic(e.to_string()));
                }
            }
        }
    };

    // Inbound copy: stream → stdout (counting RX). No stop token
    // (Go-faithful: a raw `io.CopyBuffer` with no ctx); the read unblocks
    // when the peer FINs the stream or the connection closes (on cancel,
    // via `close_on_cancel`).
    {
        let mut dst = tracker.rx_async_writer(stdout);
        let never = CancellationToken::new();
        let _ = copy_stream(Pin::new(&mut dst), Pin::new(&mut recv), None, &never).await;
    }

    // Go: `<-inboundDone`, then wait for the stdin copy or the grace window,
    // then closeStdin.
    if let Some(mut task) = stdin_task {
        tokio::select! {
            _ = &mut task => {}
            () = tokio::time::sleep(PIPE_CLOSE_GRACE) => {}
        }
        pair_stop.cancel(); // Go: closeStdin() (idempotent)
        // The task is deliberately not awaited (Go's detached goroutine).
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::{HANDSHAKE_TIMEOUT, quic_pair};
    use std::io::Cursor;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::task::Context;
    use std::time::Instant;
    use tokio::io::ReadBuf;

    use tokio::time::timeout;

    /// A reader that never becomes ready (models a blocked stdin/pipe read).
    struct BlockingReader;
    impl AsyncRead for BlockingReader {
        fn poll_read(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            _buf: &mut ReadBuf<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::task::Poll::Pending
        }
    }

    /// Port of `TestStartStdinPipe_ContextCancel`: a context cancel
    /// unblocks the bridge and `close_stdin` fires exactly once.
    #[tokio::test]
    async fn start_stdin_pipe_context_cancel() {
        let cancel = CancellationToken::new();
        let cancel2 = cancel.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(100)).await;
            cancel2.cancel();
        });

        let mut rwc_read = BlockingReader; // models the blocked pipe read
        let mut rwc_write: Vec<u8> = Vec::new(); // models io.Discard
        let mut stdin = BlockingReader;
        let mut stdout: Vec<u8> = Vec::new();
        let closed = Arc::new(AtomicUsize::new(0));
        let closed2 = closed.clone();

        let start = Instant::now();
        start_stdin_pipe(
            &cancel,
            Pin::new(&mut rwc_read),
            Pin::new(&mut rwc_write),
            Pin::new(&mut stdin),
            Pin::new(&mut stdout),
            move || {
                closed2.fetch_add(1, Ordering::SeqCst);
            },
        )
        .await;

        assert!(
            start.elapsed() < Duration::from_secs(2),
            "did not exit after context cancel"
        );
        assert_eq!(
            closed.load(Ordering::SeqCst),
            1,
            "close_stdin must fire exactly once"
        );
    }

    /// Port of `TestStartStdinPipe_PeerCloseUnblocksStdin`: the peer closing
    /// the stream ends the bridge even while the stdin read is blocked.
    #[tokio::test]
    async fn start_stdin_pipe_peer_eof_unblocks_stdin() {
        let cancel = CancellationToken::new(); // never canceled
        let mut rwc_read: Cursor<Vec<u8>> = Cursor::new(Vec::new()); // immediate EOF (peer closed)
        let mut rwc_write: Vec<u8> = Vec::new();
        let mut stdin = BlockingReader;
        let mut stdout: Vec<u8> = Vec::new();
        let closed = Arc::new(AtomicUsize::new(0));
        let closed2 = closed.clone();

        let start = Instant::now();
        start_stdin_pipe(
            &cancel,
            Pin::new(&mut rwc_read),
            Pin::new(&mut rwc_write),
            Pin::new(&mut stdin),
            Pin::new(&mut stdout),
            move || {
                closed2.fetch_add(1, Ordering::SeqCst);
            },
        )
        .await;

        assert!(
            start.elapsed() < Duration::from_secs(2),
            "did not return after peer closed"
        );
        assert_eq!(
            closed.load(Ordering::SeqCst),
            1,
            "close_stdin must fire exactly once"
        );
    }

    /// Port of `TestRunPipeMode_ContextCancel`.
    #[tokio::test]
    async fn run_pipe_mode_context_cancel() {
        let (_client, _client_ep, server, _server_ep) = quic_pair().await;
        let cancel = CancellationToken::new();
        let cancel2 = cancel.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(100)).await;
            cancel2.cancel();
        });

        let mut stdin: Cursor<Vec<u8>> = Cursor::new(Vec::new());
        let mut stdout: Vec<u8> = Vec::new();
        let closed = Arc::new(AtomicUsize::new(0));
        let closed2 = closed.clone();

        let err = run_pipe_mode(
            &cancel,
            &server,
            "server",
            Pin::new(&mut stdin),
            Pin::new(&mut stdout),
            move || {
                closed2.fetch_add(1, Ordering::SeqCst);
            },
        )
        .await
        .unwrap_err();
        assert!(matches!(err, PipeError::Canceled), "got {err:?}");
    }

    /// Port of `TestRunPipeMode_ClosedStream`: the peer opens and
    /// immediately closes (FINs) its stream; the bridge completes normally.
    #[tokio::test]
    async fn run_pipe_mode_closed_stream() {
        let (client, _client_ep, server, _server_ep) = quic_pair().await;

        // Peer opens a bidirectional stream and FINs it without data.
        let (mut send, _recv) = timeout(HANDSHAKE_TIMEOUT, client.open_bi())
            .await
            .expect("open_bi timed out")
            .expect("open_bi failed");
        send.finish().expect("finish failed");

        let cancel = CancellationToken::new();
        let mut stdin: Cursor<Vec<u8>> = Cursor::new(Vec::new());
        let mut stdout: Vec<u8> = Vec::new();
        let closed = Arc::new(AtomicUsize::new(0));
        let closed2 = closed.clone();

        let res = run_pipe_mode(
            &cancel,
            &server,
            "server",
            Pin::new(&mut stdin),
            Pin::new(&mut stdout),
            move || {
                closed2.fetch_add(1, Ordering::SeqCst);
            },
        )
        .await;
        assert!(res.is_ok(), "expected Ok, got {res:?}");
        assert_eq!(
            closed.load(Ordering::SeqCst),
            1,
            "close_stdin must fire exactly once"
        );
        assert!(stdout.is_empty());
    }

    /// A stdout sink that writes into a shared buffer (the sink is moved
    /// into the pipe, so the test observes the data through the Arc).
    #[derive(Clone, Default)]
    struct SharedOut(std::sync::Arc<std::sync::Mutex<Vec<u8>>>);

    impl AsyncWrite for SharedOut {
        fn poll_write(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &[u8],
        ) -> std::task::Poll<std::io::Result<usize>> {
            self.0.lock().unwrap().extend_from_slice(buf);
            std::task::Poll::Ready(Ok(buf.len()))
        }
        fn poll_flush(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::task::Poll::Ready(Ok(()))
        }
        fn poll_shutdown(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::task::Poll::Ready(Ok(()))
        }
    }

    /// Full bidirectional pipe over a plain QUIC pair (mirrors the
    /// interop-level verification of `engine.RunPipe`): each side's stdin
    /// reaches the peer's stdout, and both sides exit cleanly.
    #[tokio::test]
    async fn run_pipe_connected_bidirectional() {
        let (client, _client_ep, server, _server_ep) = quic_pair().await;
        let cancel = CancellationToken::new();

        let client_out = SharedOut::default();
        let client_out2 = client_out.clone();
        let client_cancel = cancel.clone();
        let client_task = tokio::spawn(async move {
            run_pipe_connected(
                &client_cancel,
                &client,
                false,
                false,
                false,
                Cursor::new(b"hello\n"),
                client_out2,
            )
            .await
            .expect("client run_pipe_connected failed")
        });

        let server_out = SharedOut::default();
        let server_out2 = server_out.clone();
        let server_cancel = cancel.clone();
        let server_task = tokio::spawn(async move {
            run_pipe_connected(
                &server_cancel,
                &server,
                true,
                false,
                false,
                Cursor::new(b"world\n"),
                server_out2,
            )
            .await
            .expect("server run_pipe_connected failed")
        });

        timeout(HANDSHAKE_TIMEOUT, client_task)
            .await
            .expect("client timed out")
            .unwrap();
        timeout(HANDSHAKE_TIMEOUT, server_task)
            .await
            .expect("server timed out")
            .unwrap();

        assert_eq!(&client_out.0.lock().unwrap()[..], b"world\n");
        assert_eq!(&server_out.0.lock().unwrap()[..], b"hello\n");
    }

    /// Regression test (quinn lazy stream header): an outbound pipe whose
    /// stdin reaches EOF before any write used to deadlock - the outbound
    /// stream was never announced, so the peer's accept never completed
    /// and the outbound side could not receive the peer's data.
    /// `announce_stream` forces the 0-byte STREAM header right after
    /// `open_bi`; this announces the stream to a **quinn** peer (quic-go
    /// ignores a 0-byte write).
    #[tokio::test]
    async fn run_pipe_connected_outbound_empty_stdin() {
        let (client, _client_ep, server, _server_ep) = quic_pair().await;
        let cancel = CancellationToken::new();

        // Client = outbound side with an immediately-EOF stdin.
        let client_out = SharedOut::default();
        let client_out2 = client_out.clone();
        let client_cancel = cancel.clone();
        let client_task = tokio::spawn(async move {
            run_pipe_connected(
                &client_cancel,
                &client,
                false,
                false,
                false,
                Cursor::new(Vec::<u8>::new()),
                client_out2,
            )
            .await
            .expect("client run_pipe_connected failed")
        });

        // Server = outbound side with data; its accept of the client's
        // empty-stdin stream is the step that deadlocked before the fix.
        let server_out = SharedOut::default();
        let server_out2 = server_out.clone();
        let server_cancel = cancel.clone();
        let server_task = tokio::spawn(async move {
            run_pipe_connected(
                &server_cancel,
                &server,
                true,
                false,
                false,
                Cursor::new(b"hello-accept\n"),
                server_out2,
            )
            .await
            .expect("server run_pipe_connected failed")
        });

        timeout(HANDSHAKE_TIMEOUT, client_task)
            .await
            .expect("client timed out")
            .unwrap();
        timeout(HANDSHAKE_TIMEOUT, server_task)
            .await
            .expect("server timed out")
            .unwrap();

        // The empty-stdin side must still receive the peer's data.
        assert_eq!(&client_out.0.lock().unwrap()[..], b"hello-accept\n");
    }
}
