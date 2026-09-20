//! Cancellable stdin reader (port of Go's `os.Stdin` read goroutine).
//!
//! Go reads stdin on a dedicated goroutine; `os.Exit` simply abandons it.
//! `tokio::io::stdin()` instead dispatches each read via `spawn_blocking`,
//! and that read is *impossible to cancel* (tokio docs): a parked blocking
//! read keeps the runtime's blocking shutdown (the drain in
//! `Runtime::drop` after `block_on`) alive until stdin reaches EOF, so a
//! process whose main future already finished cannot exit while stdin is
//! held open.
//!
//! This reader runs the blocking reads on a raw `std::thread` and forwards
//! bytes through a channel. The runtime never tracks the thread, so
//! dropping the receiver, cancelling the copy, or exiting the process all
//! abandon the reader immediately - exactly Go's semantics.

use std::io;
use std::io::Read as _;
use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, ReadBuf};
use tokio::sync::mpsc;

/// Chunk size for one blocking read (matches `copy_inner`'s 8 KiB buffer).
const CHUNK: usize = 8192;

/// An [`AsyncRead`] over process stdin backed by a dedicated reader thread.
///
/// Cancellable: no read ever parks inside the tokio runtime, so selecting
/// the copy away (stop token) or exiting the process abandons the reader
/// thread at once.
#[derive(Debug)]
pub struct StdinReader {
    rx: mpsc::Receiver<io::Result<Vec<u8>>>,
    /// Bytes read but not yet delivered (caller buffer smaller than a chunk).
    pending: Option<Vec<u8>>,
    /// EOF seen; no further data will arrive.
    eof: bool,
}

impl Default for StdinReader {
    fn default() -> Self {
        Self::new()
    }
}

impl StdinReader {
    /// Start the reader thread over the process's standard input.
    pub fn new() -> Self {
        let (tx, rx) = mpsc::channel::<io::Result<Vec<u8>>>(8);
        std::thread::spawn(move || {
            let mut stdin = std::io::stdin();
            let mut buf = vec![0u8; CHUNK];
            loop {
                match stdin.read(&mut buf) {
                    // EOF: signal and stop.
                    Ok(0) => {
                        let _ = tx.blocking_send(Ok(Vec::new()));
                        break;
                    }
                    Ok(n) => {
                        if tx.blocking_send(Ok(buf[..n].to_vec())).is_err() {
                            // Receiver dropped: give up.
                            break;
                        }
                    }
                    Err(e) => {
                        let _ = tx.blocking_send(Err(e));
                        break;
                    }
                }
            }
        });
        Self {
            rx,
            pending: None,
            eof: false,
        }
    }
}

impl AsyncRead for StdinReader {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();

        // Deliver leftover bytes first.
        if let Some(p) = this.pending.as_mut() {
            if !p.is_empty() {
                let n = p.len().min(buf.remaining());
                buf.put_slice(&p[..n]);
                if n < p.len() {
                    this.pending = Some(p.split_off(n));
                } else {
                    this.pending = None;
                }
                return Poll::Ready(Ok(()));
            }
            this.pending = None;
        }

        if this.eof {
            return Poll::Ready(Ok(()));
        }

        match this.rx.poll_recv(cx) {
            Poll::Ready(Some(Ok(chunk))) => {
                if chunk.is_empty() {
                    this.eof = true;
                    return Poll::Ready(Ok(()));
                }
                let n = chunk.len().min(buf.remaining());
                buf.put_slice(&chunk[..n]);
                if n < chunk.len() {
                    this.pending = Some(chunk[n..].to_vec());
                }
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Some(Err(e))) => Poll::Ready(Err(e)),
            // Reader thread gone without an error: treat as EOF.
            Poll::Ready(None) => {
                this.eof = true;
                Poll::Ready(Ok(()))
            }
            Poll::Pending => Poll::Pending,
        }
    }
}
