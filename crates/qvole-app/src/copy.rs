//! Bidirectional copy helpers (Go `internal/app/pipe.go` copy machinery).
//!
//! Port of `isClosedError`, `copyErrorKind`, `refreshReader`, `copyDirection`,
//! and `bidirectionalCopy` from `internal/app/pipe.go`, plus the raw
//! `io.CopyBuffer` one-direction copies used by `RunPipe`
//! (`internal/engine/client.go`).
//!
//! Design (deviation from Go): Go runs one goroutine per direction
//! and a `sync.Once` closer; quinn streams are single-owner, so the Rust port
//! runs both directions as futures inside one task, polled alternately to
//! completion. `interrupt` fires once when the *first* direction completes
//! (Go `closeBoth`), a private stop token is canceled so the second direction
//! unblocks, and the copy returns when *both* are done (Go `wg.Wait`).

use std::io;
use std::pin::Pin;
use std::task::Poll;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio_util::sync::CancellationToken;

use qvole_protocol::logger::LOG_COPY;
use qvole_protocol::pool;

/// Grace period after scheduling [`quinn::Connection::close`]: quinn only
/// *schedules* the CONNECTION_CLOSE frame; the per-connection driver task
/// (woken by `close`) sends it on its next poll. Go's quic-go instead
/// flushes close synchronously inside `CloseWithError`. The binary runs
/// with `shutdown_background`, so the process may exit immediately after
/// the main future returns - yielding briefly here guarantees the frame
/// reaches the socket (see `run_exec`/`run_pipe_connected`/tunnel).
pub const CLOSE_FLUSH_DELAY: std::time::Duration = std::time::Duration::from_millis(50);

/// Yield [`CLOSE_FLUSH_DELAY`] after `Connection::close` so the woken
/// driver task can send the CONNECTION_CLOSE frame before the process
/// exits.
pub async fn flush_close() {
    tokio::time::sleep(CLOSE_FLUSH_DELAY).await;
}

/// Classification of a copy failure for logging purposes.
///
/// Port of Go's `copyErrorKind` return strings: `""` (benign, not logged),
/// `"timeout"`, `"disconnect"`, `"error"`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CopyErrorKind {
    /// Benign: graceful close, locally closed stream, or similar expected
    /// teardown. Go logs nothing (`""`).
    Benign,
    /// Peer disconnected (transport abort, idle timeout, stateless reset, or
    /// a non-zero application close). Go logs at debug level.
    Disconnect,
    /// A read/write deadline expired. Go logs at debug level.
    Timeout,
    /// Any other failure. Go logs at error level.
    Error,
}

/// Classify a `quinn::ConnectionError` (port of the relevant parts of
/// `copyErrorKind`/`IsPeerDisconnect`).
///
/// A zero-code [`quinn::ApplicationClose`] is a graceful remote close
/// (Go: `errors.As(err, &appErr) && appErr.ErrorCode == 0` → benign, not
/// logged); every other connection error the peer caused is a disconnect.
pub fn conn_close_kind(err: &quinn::ConnectionError) -> CopyErrorKind {
    match err {
        quinn::ConnectionError::ApplicationClosed(close) => {
            if close.error_code.into_inner() == 0 {
                CopyErrorKind::Benign
            } else {
                CopyErrorKind::Disconnect
            }
        }
        // Peer transport abort, idle timeout, stateless reset
        // (Go `IsPeerDisconnect`: ApplicationClosed | ConnectionClosed |
        // TransportError | Reset | TimedOut).
        quinn::ConnectionError::ConnectionClosed(_)
        | quinn::ConnectionError::TransportError(_)
        | quinn::ConnectionError::Reset
        | quinn::ConnectionError::TimedOut => CopyErrorKind::Disconnect,
        // Local close (Go: not a peer disconnect).
        quinn::ConnectionError::LocallyClosed => CopyErrorKind::Benign,
        quinn::ConnectionError::VersionMismatch | quinn::ConnectionError::CidsExhausted => {
            CopyErrorKind::Error
        }
    }
}

/// Classify an I/O error for copy logging (port of `copyErrorKind`).
///
/// Quinn surfaces its typed errors as the `io::Error` source
/// (`From<ReadError>/From<WriteError> for io::Error`), so the typed variant
/// is recovered with the consuming [`io::Error::downcast`] (this rustc has
/// no `io::Error::downcast_ref` or usable `io::Error::source`).
pub fn copy_error_kind(err: io::Error) -> CopyErrorKind {
    let err = match err.downcast::<quinn::ReadError>() {
        Ok(re) => {
            return match re {
                // Peer RESET_STREAM (Go: *quic.StreamError - not in
                // IsPeerDisconnect, so it lands in the "error" bucket).
                quinn::ReadError::Reset(_) => CopyErrorKind::Error,
                quinn::ReadError::ConnectionLost(ce) => conn_close_kind(&ce),
                // Locally stopped/finished stream: expected teardown.
                quinn::ReadError::ClosedStream => CopyErrorKind::Benign,
                quinn::ReadError::IllegalOrderedRead | quinn::ReadError::ZeroRttRejected => {
                    CopyErrorKind::Error
                }
            };
        }
        Err(e) => e,
    };
    let err = match err.downcast::<quinn::WriteError>() {
        Ok(we) => {
            return match we {
                // Peer sent STOP_SENDING (Go: quic.StreamError → "error").
                quinn::WriteError::Stopped(_) => CopyErrorKind::Error,
                quinn::WriteError::ConnectionLost(ce) => conn_close_kind(&ce),
                // Locally finished stream: expected teardown.
                quinn::WriteError::ClosedStream => CopyErrorKind::Benign,
                quinn::WriteError::ZeroRttRejected => CopyErrorKind::Error,
            };
        }
        Err(e) => e,
    };
    let err = match err.downcast::<quinn::ConnectionError>() {
        Ok(ce) => return conn_close_kind(&ce),
        Err(e) => e,
    };
    // Plain I/O (Go: net.ErrClosed/os.ErrClosed/io.ErrClosedPipe → "";
    // net.Error.Timeout() → "timeout"; everything else → "error").
    match err.kind() {
        io::ErrorKind::TimedOut => CopyErrorKind::Timeout,
        // Local close races: tokio reports a closed local stream as
        // ConnectionAborted (read) / BrokenPipe (write) - Go net.ErrClosed.
        io::ErrorKind::ConnectionAborted | io::ErrorKind::BrokenPipe => CopyErrorKind::Benign,
        _ => CopyErrorKind::Error,
    }
}

/// Port of the logging in `copyDirection` (`timeout`/`disconnect` at debug
/// level, `error` at error level; benign is not logged).
fn log_copy_error(dir: &str, err: io::Error) {
    let msg = err.to_string();
    match copy_error_kind(err) {
        CopyErrorKind::Timeout => LOG_COPY.printf(&format!("Copy timeout ({dir}): {msg}")),
        CopyErrorKind::Disconnect => LOG_COPY.printf(&format!("Copy disconnect ({dir}): {msg}")),
        CopyErrorKind::Error => LOG_COPY.printf_error(&format!("Copy error ({dir}): {msg}")),
        CopyErrorKind::Benign => {}
    }
}

/// One-directional async copy with stop-token and refresh (no error
/// classification or logging - the raw `io.CopyBuffer` used by `RunPipe`).
///
/// `stop` unblocks the copy without logging (Go: the copied-over source is
/// closed by the surrounding flow, which unblocks `io.CopyBuffer`); `refresh`
/// is invoked after every read that returns data (Go `refreshReader`).
///
/// Returns `Ok(())` on source EOF, or the first read/write error.
pub async fn copy_stream<R, W>(
    dst: Pin<&mut W>,
    src: Pin<&mut R>,
    refresh: Option<&(dyn Fn() + Send + Sync)>,
    stop: &CancellationToken,
) -> io::Result<()>
where
    R: AsyncRead,
    W: AsyncWrite,
{
    let mut dst = dst;
    let mut src = src;
    let mut buf = pool::get_buffer();
    // Go: defer engine.PutBuffer(buf).
    let result = copy_inner(&mut dst, &mut src, &mut buf, refresh, stop, false).await;
    pool::put_buffer(&mut buf);
    result
}

async fn copy_inner<R, W>(
    dst: &mut Pin<&mut W>,
    src: &mut Pin<&mut R>,
    buf: &mut [u8],
    refresh: Option<&(dyn Fn() + Send + Sync)>,
    stop: &CancellationToken,
    interleave: bool,
) -> io::Result<()>
where
    R: AsyncRead,
    W: AsyncWrite,
{
    loop {
        let read = tokio::select! {
            biased;
            () = stop.cancelled() => return Ok(()),
            r = src.read(buf) => r,
        };
        match read {
            Ok(0) => return Ok(()), // EOF
            Ok(n) => {
                if let Some(f) = refresh {
                    f();
                }
                dst.write_all(&buf[..n]).await?;
            }
            Err(e) => return Err(e),
        }
        if interleave {
            // Yield so a `tokio::select!` over two such copies interleaves
            // them fairly: without this, a direction whose I/O is always
            // ready would run to completion in the first poll and the other
            // direction would be dropped before doing any work (Go's
            // goroutine scheduler interleaves both directions instead).
            tokio::task::yield_now().await;
        }
    }
}

/// One-directional copy with error classification and logging
/// (port of `copyDirection`, `dir` is the "a←b" style direction label).
///
/// Errors are classified via [`copy_error_kind`] and logged; the error itself
/// is swallowed (the copy simply stops), mirroring Go.
pub async fn copy_direction<R, W>(
    dst: Pin<&mut W>,
    src: Pin<&mut R>,
    dir: &'static str,
    refresh: Option<&(dyn Fn() + Send + Sync)>,
    stop: &CancellationToken,
) where
    R: AsyncRead,
    W: AsyncWrite,
{
    let mut dst = dst;
    let mut src = src;
    let mut buf = pool::get_buffer();
    // Go: defer engine.PutBuffer(buf).
    let result = copy_inner(&mut dst, &mut src, &mut buf, refresh, stop, false).await;
    pool::put_buffer(&mut buf);
    if let Err(e) = result {
        log_copy_error(dir, e);
    }
}

/// Like [`copy_direction`] but yields after each read+write step so that two
/// such copies inside a `tokio::select!` make progress alternately even when
/// all I/O is immediately ready (see `copy_inner`).
async fn copy_direction_fair<R, W>(
    dst: Pin<&mut W>,
    src: Pin<&mut R>,
    dir: &'static str,
    refresh: Option<&(dyn Fn() + Send + Sync)>,
    stop: &CancellationToken,
) where
    R: AsyncRead,
    W: AsyncWrite,
{
    let mut dst = dst;
    let mut src = src;
    let mut buf = pool::get_buffer();
    let result = copy_inner(&mut dst, &mut src, &mut buf, refresh, stop, true).await;
    pool::put_buffer(&mut buf);
    if let Err(e) = result {
        log_copy_error(dir, e);
    }
}

/// Port of `bidirectionalCopy` over two endpoints.
///
/// `a` and `b` are given as separate read/write halves (Go's
/// `io.ReadWriter`s). Data flows both ways until *both* directions complete
/// (Go `wg.Wait`); `interrupt` is invoked once, when the first direction
/// completes (Go `closeBoth`), and a private stop token is canceled so the
/// still-running direction unblocks promptly.
pub async fn bidirectional_copy<AR, AW, BR, BW>(
    a_read: Pin<&mut AR>,
    a_write: Pin<&mut AW>,
    b_read: Pin<&mut BR>,
    b_write: Pin<&mut BW>,
    stop: &CancellationToken,
    refresh: Option<&(dyn Fn() + Send + Sync)>,
    interrupt: impl FnMut(),
) where
    AR: AsyncRead,
    AW: AsyncWrite,
    BR: AsyncRead,
    BW: AsyncWrite,
{
    // Both directions run to completion (Go: `wg.Wait` on both copy
    // goroutines). `interrupt` fires once when the *first* direction
    // finishes (Go: `closeBoth`), and the stop token handed to the copies is
    // canceled so the still-running direction unblocks promptly (Go's
    // closeBoth closes the endpoints, which unblocks the other copy; the
    // caller's interrupt closure performs the equivalent resource close).
    let pair_stop = stop.child_token();
    // Direction "a←b": read b, write a. Direction "b←a": read a, write b.
    // Both directions use the yielding variant so they interleave fairly.
    let mut dir_ab = Box::pin(copy_direction_fair(
        a_write, b_read, "a←b", refresh, &pair_stop,
    ));
    let mut dir_ba = Box::pin(copy_direction_fair(
        b_write, a_read, "b←a", refresh, &pair_stop,
    ));
    let mut fired = false;
    let mut interrupt = interrupt;
    let mut a_done = false;
    let mut b_done = false;
    let done_stop = pair_stop.clone();
    std::future::poll_fn(move |cx| {
        if !a_done {
            a_done = dir_ab.as_mut().poll(cx).is_ready();
        }
        if !b_done {
            b_done = dir_ba.as_mut().poll(cx).is_ready();
        }
        if (a_done || b_done) && !fired {
            fired = true;
            interrupt();
            done_stop.cancel();
        }
        if a_done && b_done {
            Poll::Ready(())
        } else {
            Poll::Pending
        }
    })
    .await;
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Cursor, ErrorKind};
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};

    /// Port of `TestCopyErrorKind` (table).
    #[test]
    fn copy_error_kind_table() {
        use ConnectionError::*;
        use bytes::Bytes;
        use quinn::{
            ApplicationClose, ConnectionClose, ConnectionError, TransportErrorCode, VarInt,
        };

        let graceful = || {
            io::Error::new(
                ErrorKind::NotConnected,
                quinn::ReadError::ConnectionLost(ApplicationClosed(ApplicationClose {
                    error_code: VarInt::from_u32(0),
                    reason: Bytes::new(),
                })),
            )
        };
        let graceful_write = || {
            io::Error::new(
                ErrorKind::NotConnected,
                quinn::WriteError::ConnectionLost(ApplicationClosed(ApplicationClose {
                    error_code: VarInt::from_u32(0),
                    reason: Bytes::new(),
                })),
            )
        };
        let app_error = |code: u32| {
            io::Error::new(
                ErrorKind::NotConnected,
                quinn::ReadError::ConnectionLost(ApplicationClosed(ApplicationClose {
                    error_code: VarInt::from_u32(code),
                    reason: Bytes::new(),
                })),
            )
        };
        let idle_timeout = io::Error::new(
            ErrorKind::NotConnected,
            quinn::ReadError::ConnectionLost(TimedOut),
        );
        let reset = io::Error::new(
            ErrorKind::NotConnected,
            quinn::ReadError::ConnectionLost(Reset),
        );
        let transport = io::Error::new(
            ErrorKind::NotConnected,
            quinn::ReadError::ConnectionLost(ConnectionClosed(ConnectionClose {
                error_code: TransportErrorCode::FRAME_ENCODING_ERROR,
                frame_type: None,
                reason: Bytes::new(),
            })),
        );
        let locally_closed = io::Error::new(
            ErrorKind::NotConnected,
            quinn::ReadError::ConnectionLost(LocallyClosed),
        );

        let cases = [
            ("graceful read", graceful(), CopyErrorKind::Benign),
            ("graceful write", graceful_write(), CopyErrorKind::Benign),
            ("app error code 1", app_error(1), CopyErrorKind::Disconnect),
            ("idle timeout", idle_timeout, CopyErrorKind::Disconnect),
            ("stateless reset", reset, CopyErrorKind::Disconnect),
            ("transport error", transport, CopyErrorKind::Disconnect),
            ("locally closed", locally_closed, CopyErrorKind::Benign),
            (
                "closed stream (read)",
                io::Error::new(ErrorKind::NotConnected, quinn::ReadError::ClosedStream),
                CopyErrorKind::Benign,
            ),
            // Go: *quic.StreamError is not a peer disconnect → "error".
            (
                "stream reset by peer",
                io::Error::new(
                    ErrorKind::ConnectionReset,
                    quinn::ReadError::Reset(VarInt::from_u32(1)),
                ),
                CopyErrorKind::Error,
            ),
            (
                "stopped by peer (write)",
                io::Error::new(
                    ErrorKind::ConnectionReset,
                    quinn::WriteError::Stopped(1u32.into()),
                ),
                CopyErrorKind::Error,
            ),
            (
                "deadline exceeded",
                io::Error::new(ErrorKind::TimedOut, "read: i/o timeout"),
                CopyErrorKind::Timeout,
            ),
            (
                "local read closed",
                io::Error::new(ErrorKind::ConnectionAborted, "read: connection aborted"),
                CopyErrorKind::Benign,
            ),
            (
                "local write closed",
                io::Error::new(ErrorKind::BrokenPipe, "write: broken pipe"),
                CopyErrorKind::Benign,
            ),
            (
                "unexpected eof",
                io::Error::new(ErrorKind::UnexpectedEof, "unexpected eof"),
                CopyErrorKind::Error,
            ),
            (
                "plain error",
                io::Error::other("boom"),
                CopyErrorKind::Error,
            ),
        ];
        for (name, err, want) in cases {
            let got = copy_error_kind(err);
            assert_eq!(got, want, "case {name}: got {got:?}, want {want:?}");
        }
    }

    /// Port of `TestIsTimeoutError` (via the public classification).
    #[test]
    fn timeout_errors_classify_as_timeout() {
        let e = io::Error::new(ErrorKind::TimedOut, "read tcp: i/o timeout");
        assert_eq!(copy_error_kind(e), CopyErrorKind::Timeout);
        let e = io::Error::new(ErrorKind::TimedOut, "write: deadline exceeded");
        assert_eq!(copy_error_kind(e), CopyErrorKind::Timeout);
    }

    /// Port of `TestRefreshReader_InvokesOnReadOnDataOnly`: refresh fires
    /// after every read that returns data, and not on the EOF read.
    #[tokio::test]
    async fn refresh_reader_invoked_on_data_only() {
        let mut data = Cursor::new(b"hello world");
        let mut sink: Vec<u8> = Vec::new();
        let calls = Arc::new(AtomicUsize::new(0));
        let calls2 = calls.clone();
        let stop = CancellationToken::new();
        copy_stream(
            Pin::new(&mut sink),
            Pin::new(&mut data),
            Some(&move || {
                calls2.fetch_add(1, Ordering::SeqCst);
            }),
            &stop,
        )
        .await
        .unwrap();
        assert_eq!(sink, b"hello world");
        assert_eq!(calls.load(Ordering::SeqCst), 1); // one data read, then EOF
    }

    /// Port of `TestRefreshReader_NilOnRead`: no refresh is fine.
    #[tokio::test]
    async fn refresh_reader_none_ok() {
        let mut data = Cursor::new(b"abc");
        let mut sink: Vec<u8> = Vec::new();
        let stop = CancellationToken::new();
        copy_stream(Pin::new(&mut sink), Pin::new(&mut data), None, &stop)
            .await
            .unwrap();
        assert_eq!(sink, b"abc");
    }

    /// Port of `TestBidirectionalCopy_TransfersBothDirections`.
    #[tokio::test]
    async fn bidirectional_copy_transfers_both_directions() {
        // a = (reader, writer), b = (reader, writer); both sides deliver one
        // chunk and then EOF.
        let mut a_in = Cursor::new(b"from a");
        let mut a_out: Vec<u8> = Vec::new();
        let mut b_in = Cursor::new(b"from b");
        let mut b_out: Vec<u8> = Vec::new();
        let stop = CancellationToken::new();
        let interrupted = Arc::new(AtomicBool::new(false));
        let interrupted2 = interrupted.clone();
        bidirectional_copy(
            Pin::new(&mut a_in),
            Pin::new(&mut a_out),
            Pin::new(&mut b_in),
            Pin::new(&mut b_out),
            &stop,
            None,
            move || {
                interrupted2.store(true, Ordering::SeqCst);
            },
        )
        .await;
        assert_eq!(a_out, b"from b");
        assert_eq!(b_out, b"from a");
        assert!(interrupted.load(Ordering::SeqCst));
    }

    /// Port of `TestBidirectionalCopy_ClosesBoth`: interrupt fires exactly
    /// once when both sides reach EOF (and also when one side errors).
    #[tokio::test]
    async fn bidirectional_copy_closes_both() {
        let mut a_in: Cursor<Vec<u8>> = Cursor::new(Vec::new()); // EOF
        let mut a_out: Vec<u8> = Vec::new();
        let mut b_in: Cursor<Vec<u8>> = Cursor::new(Vec::new()); // EOF
        let mut b_out: Vec<u8> = Vec::new();
        let stop = CancellationToken::new();
        let calls = Arc::new(AtomicUsize::new(0));
        let calls2 = calls.clone();
        bidirectional_copy(
            Pin::new(&mut a_in),
            Pin::new(&mut a_out),
            Pin::new(&mut b_in),
            Pin::new(&mut b_out),
            &stop,
            None,
            move || {
                calls2.fetch_add(1, Ordering::SeqCst);
            },
        )
        .await;
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    /// Port of `TestBidirectionalCopy_EmptyStreams`.
    #[tokio::test]
    async fn bidirectional_copy_empty_streams() {
        let mut a_in: Cursor<Vec<u8>> = Cursor::new(Vec::new());
        let mut a_out: Vec<u8> = Vec::new();
        let mut b_in: Cursor<Vec<u8>> = Cursor::new(Vec::new());
        let mut b_out: Vec<u8> = Vec::new();
        let stop = CancellationToken::new();
        bidirectional_copy(
            Pin::new(&mut a_in),
            Pin::new(&mut a_out),
            Pin::new(&mut b_in),
            Pin::new(&mut b_out),
            &stop,
            None,
            || {},
        )
        .await;
        assert!(a_out.is_empty());
        assert!(b_out.is_empty());
    }

    /// Port of `TestBidirectionalCopy_LargeData` with equal-size payloads.
    ///
    /// Go's test uses 128K/64K and asserts full transfer of both, which
    /// works there only because the test endpoints are not `io.Closer`s, so
    /// `closeBoth` is a no-op and both copies run to EOF. With real QUIC
    /// streams (Go's Closer endpoints), the second direction *is* cut off
    /// when the first completes - the semantics Rust mirrors via
    /// interrupt+stop. Equal sizes avoid that truncation: both directions
    /// reach EOF after the same number of steps.
    #[tokio::test]
    async fn bidirectional_copy_large_data() {
        let big_a = vec![0xa5u8; 128 * 1024];
        let big_b = vec![0x5au8; 128 * 1024];
        let mut a_in = Cursor::new(big_a);
        let mut a_out: Vec<u8> = Vec::new();
        let mut b_in = Cursor::new(big_b);
        let mut b_out: Vec<u8> = Vec::new();
        let stop = CancellationToken::new();
        bidirectional_copy(
            Pin::new(&mut a_in),
            Pin::new(&mut a_out),
            Pin::new(&mut b_in),
            Pin::new(&mut b_out),
            &stop,
            None,
            || {},
        )
        .await;
        assert_eq!(a_out.len(), 128 * 1024);
        assert_eq!(b_out.len(), 128 * 1024);
        assert!(a_out.iter().all(|&b| b == 0x5a));
        assert!(b_out.iter().all(|&b| b == 0xa5));
    }

    /// Port of `TestBidirectionalCopy_NoCloserInterface`: plain readers and
    /// writers (no Close) work.
    #[tokio::test]
    async fn bidirectional_copy_no_closer_interface() {
        // Vec<u8> writer and Cursor reader have no Close method.
        let mut a_in = Cursor::new(b"x");
        let mut a_out: Vec<u8> = Vec::new();
        let mut b_in = Cursor::new(b"y");
        let mut b_out: Vec<u8> = Vec::new();
        let stop = CancellationToken::new();
        bidirectional_copy(
            Pin::new(&mut a_in),
            Pin::new(&mut a_out),
            Pin::new(&mut b_in),
            Pin::new(&mut b_out),
            &stop,
            None,
            || {},
        )
        .await;
        assert_eq!(a_out, b"y");
        assert_eq!(b_out, b"x");
    }

    /// Port of `TestBidirectionalCopy_ReadError`: a read error on one side
    /// still ends the copy and fires interrupt.
    #[tokio::test]
    async fn bidirectional_copy_read_error() {
        struct FailReader;
        impl AsyncRead for FailReader {
            fn poll_read(
                self: Pin<&mut Self>,
                _cx: &mut std::task::Context<'_>,
                _buf: &mut tokio::io::ReadBuf<'_>,
            ) -> std::task::Poll<std::io::Result<()>> {
                std::task::Poll::Ready(Err(io::Error::new(ErrorKind::UnexpectedEof, "boom")))
            }
        }
        let mut a_in: Cursor<Vec<u8>> = Cursor::new(Vec::new());
        let mut a_out: Vec<u8> = Vec::new();
        let mut b_in = FailReader;
        let mut b_out: Vec<u8> = Vec::new();
        let stop = CancellationToken::new();
        let calls = Arc::new(AtomicUsize::new(0));
        let calls2 = calls.clone();
        bidirectional_copy(
            Pin::new(&mut a_in),
            Pin::new(&mut a_out),
            Pin::new(&mut b_in),
            Pin::new(&mut b_out),
            &stop,
            None,
            move || {
                calls2.fetch_add(1, Ordering::SeqCst);
            },
        )
        .await;
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    /// Port of `TestBidirectionalCopy_WriteError`: a write error on one side
    /// still ends the copy.
    #[tokio::test]
    async fn bidirectional_copy_write_error() {
        struct FailWriter;
        impl AsyncWrite for FailWriter {
            fn poll_write(
                self: Pin<&mut Self>,
                _cx: &mut std::task::Context<'_>,
                _buf: &[u8],
            ) -> std::task::Poll<std::io::Result<usize>> {
                std::task::Poll::Ready(Err(io::Error::other("nope")))
            }
            fn poll_flush(
                self: Pin<&mut Self>,
                _cx: &mut std::task::Context<'_>,
            ) -> std::task::Poll<std::io::Result<()>> {
                std::task::Poll::Ready(Ok(()))
            }
            fn poll_shutdown(
                self: Pin<&mut Self>,
                _cx: &mut std::task::Context<'_>,
            ) -> std::task::Poll<std::io::Result<()>> {
                std::task::Poll::Ready(Ok(()))
            }
        }
        let mut a_in = Cursor::new(b"data to write");
        let mut a_out = FailWriter;
        let mut b_in: Cursor<Vec<u8>> = Cursor::new(Vec::new());
        let mut b_out: Vec<u8> = Vec::new();
        let stop = CancellationToken::new();
        let calls = Arc::new(AtomicUsize::new(0));
        let calls2 = calls.clone();
        bidirectional_copy(
            Pin::new(&mut a_in),
            Pin::new(&mut a_out),
            Pin::new(&mut b_in),
            Pin::new(&mut b_out),
            &stop,
            None,
            move || {
                calls2.fetch_add(1, Ordering::SeqCst);
            },
        )
        .await;
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    /// Port of `TestBidirectionalCopy_StopToken`: canceling the stop token
    /// ends the copy promptly (Go: the ctx.Done closer unblocks the copies).
    #[tokio::test]
    async fn bidirectional_copy_stop_token() {
        struct BlockingReader;
        impl AsyncRead for BlockingReader {
            fn poll_read(
                self: Pin<&mut Self>,
                _cx: &mut std::task::Context<'_>,
                _buf: &mut tokio::io::ReadBuf<'_>,
            ) -> std::task::Poll<std::io::Result<()>> {
                std::task::Poll::Pending
            }
        }
        let mut a_in = BlockingReader;
        let mut a_out: Vec<u8> = Vec::new();
        let mut b_in = BlockingReader;
        let mut b_out: Vec<u8> = Vec::new();
        let stop = CancellationToken::new();
        let stop2 = stop.clone();
        tokio::spawn(async move {
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            stop2.cancel();
        });
        let start = std::time::Instant::now();
        bidirectional_copy(
            Pin::new(&mut a_in),
            Pin::new(&mut a_out),
            Pin::new(&mut b_in),
            Pin::new(&mut b_out),
            &stop,
            None,
            || {},
        )
        .await;
        assert!(start.elapsed() < std::time::Duration::from_secs(2));
    }

    /// Port of `TestCopyDirection_ReadErrorLogs` behavior: a read error ends
    /// the copy (classification already covered above); here: silent benign
    /// end on EOF.
    #[tokio::test]
    async fn copy_direction_eof_is_silent() {
        let mut data: Cursor<Vec<u8>> = Cursor::new(Vec::new());
        let mut sink: Vec<u8> = Vec::new();
        let stop = CancellationToken::new();
        // Must not panic or block; returns immediately on EOF.
        copy_direction(
            Pin::new(&mut sink),
            Pin::new(&mut data),
            "test",
            None,
            &stop,
        )
        .await;
        assert!(sink.is_empty());
    }

    /// Buffer pool: concurrent copies do not deadlock and buffers are
    /// returned (pool is thread-local; just exercise it under concurrency).
    #[tokio::test]
    async fn concurrent_copies_use_pool() {
        let mut handles = Vec::new();
        for i in 0..8 {
            let payload = vec![i as u8; 64 * 1024];
            let rx = tokio::spawn(async move {
                let mut src = Cursor::new(payload);
                let mut dst: Vec<u8> = Vec::new();
                let stop = CancellationToken::new();
                copy_stream(Pin::new(&mut dst), Pin::new(&mut src), None, &stop)
                    .await
                    .unwrap();
                dst
            });
            handles.push(rx);
        }
        for h in handles {
            let out = h.await.unwrap();
            assert_eq!(out.len(), 64 * 1024);
        }
    }

    /// `Mutex`-guarded shared flag to prove interrupt is called exactly once
    /// even when both directions finish "simultaneously".
    #[tokio::test]
    async fn bidirectional_copy_interrupt_once() {
        let mut a_in = Cursor::new(b"1");
        let mut a_out: Vec<u8> = Vec::new();
        let mut b_in = Cursor::new(b"2");
        let mut b_out: Vec<u8> = Vec::new();
        let stop = CancellationToken::new();
        let count = Arc::new(Mutex::new(0usize));
        let count2 = count.clone();
        bidirectional_copy(
            Pin::new(&mut a_in),
            Pin::new(&mut a_out),
            Pin::new(&mut b_in),
            Pin::new(&mut b_out),
            &stop,
            None,
            move || {
                *count2.lock().unwrap() += 1;
            },
        )
        .await;
        assert_eq!(*count.lock().unwrap(), 1);
        assert_eq!(a_out, b"2");
        assert_eq!(b_out, b"1");
    }
}
