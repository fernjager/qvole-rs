//! TX/RX byte counting and throughput reporting (Go `internal/engine/stats.go`).

use std::io::{self, Write};
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicI64, Ordering};
use std::task::{Context, Poll};
use std::time::Duration;

use tokio::io::AsyncWrite;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

/// Wraps a writer to count the bytes written (Go `directionWriter`).
pub struct DirectionWriter<'a, W: Write> {
    w: W,
    counter: &'a AtomicI64,
}

impl<W: Write> Write for DirectionWriter<'_, W> {
    fn write(&mut self, p: &[u8]) -> std::io::Result<usize> {
        let n = self.w.write(p)?;
        // Count even on error, like Go (n is 0 on hard errors anyway).
        self.counter.fetch_add(n as i64, Ordering::SeqCst);
        Ok(n)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.w.flush()
    }
}

/// Wraps an [`AsyncWrite`] to count the bytes written (the async analogue of
/// [`DirectionWriter`]; used for QUIC streams, which are `AsyncWrite` rather
/// than `Write`). `W` must be `Unpin` (quinn's `SendStream` is).
pub struct AsyncDirectionWriter<'a, W: AsyncWrite + Unpin> {
    w: W,
    counter: &'a AtomicI64,
}

impl<W: AsyncWrite + Unpin> AsyncWrite for AsyncDirectionWriter<'_, W> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        let n = match Pin::new(&mut this.w).poll_write(cx, buf) {
            Poll::Ready(Ok(n)) => n,
            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
            Poll::Pending => return Poll::Pending,
        };
        // Count even on error, like Go (n is 0 on hard errors anyway).
        this.counter.fetch_add(n as i64, Ordering::SeqCst);
        Poll::Ready(Ok(n))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        Pin::new(&mut this.w).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        Pin::new(&mut this.w).poll_shutdown(cx)
    }
}

/// Tracks TX/RX byte counts for throughput reporting (Go `StatsTracker`).
pub struct StatsTracker {
    tx: AtomicI64,
    rx: AtomicI64,
    done: CancellationToken,
    /// Go's `StopAndLog` is `sync.Once`-guarded; mirror that so an
    /// unconditional teardown can run on every return path without printing
    /// the final line more than once.
    stopped: AtomicBool,
}

impl Default for StatsTracker {
    fn default() -> Self {
        Self::new()
    }
}

impl StatsTracker {
    /// Creates a new StatsTracker ready for use (Go `NewStatsTracker`).
    #[must_use]
    pub fn new() -> Self {
        Self {
            tx: AtomicI64::new(0),
            rx: AtomicI64::new(0),
            done: CancellationToken::new(),
            stopped: AtomicBool::new(false),
        }
    }

    /// Wraps `w` to count transmitted bytes (Go `TXWriter`).
    pub fn tx_writer<'a, W: Write>(&'a self, w: W) -> DirectionWriter<'a, W> {
        DirectionWriter {
            w,
            counter: &self.tx,
        }
    }

    /// Wraps `w` to count received bytes (Go `RXWriter`).
    pub fn rx_writer<'a, W: Write>(&'a self, w: W) -> DirectionWriter<'a, W> {
        DirectionWriter {
            w,
            counter: &self.rx,
        }
    }

    /// Wraps an `AsyncWrite` `w` to count transmitted bytes (the async
    /// analogue of `TXWriter`; Go's `TXWriter(out)` over a QUIC stream).
    pub fn tx_async_writer<'a, W: AsyncWrite + Unpin>(
        &'a self,
        w: W,
    ) -> AsyncDirectionWriter<'a, W> {
        AsyncDirectionWriter {
            w,
            counter: &self.tx,
        }
    }

    /// Wraps an `AsyncWrite` `w` to count received bytes (the async analogue
    /// of `RXWriter`; Go's `RXWriter(os.Stdout)`).
    pub fn rx_async_writer<'a, W: AsyncWrite + Unpin>(
        &'a self,
        w: W,
    ) -> AsyncDirectionWriter<'a, W> {
        AsyncDirectionWriter {
            w,
            counter: &self.rx,
        }
    }

    /// Begins periodic throughput logging at the given interval
    /// (Go `Start`; the goroutine becomes a spawned task).
    pub fn start(self: std::sync::Arc<Self>, interval: Duration) -> JoinHandle<()> {
        let done = self.done.clone();
        tokio::spawn(async move {
            let tx = &self.tx;
            let rx = &self.rx;
            let mut ticker =
                tokio::time::interval_at(tokio::time::Instant::now() + interval, interval);
            let mut last_tx: i64 = 0;
            let mut last_rx: i64 = 0;
            let mut last_time = tokio::time::Instant::now();
            let mut first = true;
            loop {
                tokio::select! {
                    _ = done.cancelled() => return,
                    t = ticker.tick() => {
                        let tx_now = tx.load(Ordering::SeqCst);
                        let rx_now = rx.load(Ordering::SeqCst);
                        let elapsed = t.duration_since(last_time).as_secs_f64();

                        if first {
                            first = false;
                            last_tx = tx_now;
                            last_rx = rx_now;
                            last_time = t;
                            continue;
                        }

                        let tx_delta = tx_now - last_tx;
                        let rx_delta = rx_now - last_rx;

                        if tx_delta > 0 || rx_delta > 0 {
                            crate::logger::LOG_PIPE.printf_info(&format!(
                                "↑ {} ({})  ↓ {} ({})",
                                format_bytes(tx_now),
                                crate::logger::bold(&format_bytes_rate(
                                    tx_delta as f64 / elapsed
                                )),
                                format_bytes(rx_now),
                                crate::logger::bold(&format_bytes_rate(
                                    rx_delta as f64 / elapsed
                                )),
                            ));
                        }
                        last_tx = tx_now;
                        last_rx = rx_now;
                        last_time = t;
                    }
                }
            }
        })
    }

    /// Stops the periodic logger and prints the final totals
    /// (Go `StopAndLog`).
    ///
    /// Idempotent: only the first call stops the reporter and prints (Go's
    /// `sync.Once`), so unconditional teardown on every return path is safe.
    pub fn stop_and_log(&self) {
        if self.stopped.swap(true, Ordering::SeqCst) {
            return;
        }
        self.done.cancel();
        let tx = self.tx.load(Ordering::SeqCst);
        let rx = self.rx.load(Ordering::SeqCst);
        if tx > 0 || rx > 0 {
            crate::logger::LOG_PIPE.printf_info(&format!(
                "Total: ↑ {}  ↓ {}",
                crate::logger::bold(&format_bytes(tx)),
                crate::logger::bold(&format_bytes(rx))
            ));
        } else {
            crate::logger::LOG_PIPE.printf_success("Done!");
        }
    }

    /// Total transmitted bytes so far.
    #[must_use]
    pub fn tx(&self) -> i64 {
        self.tx.load(Ordering::SeqCst)
    }

    /// Total received bytes so far.
    #[must_use]
    pub fn rx(&self) -> i64 {
        self.rx.load(Ordering::SeqCst)
    }
}

/// Go `formatBytesValue`.
fn format_bytes_value(val: f64, suffix: &str, exact_int: bool) -> String {
    if val >= 1073741824.0 {
        format!("{:.2} G{suffix}", val / 1073741824.0)
    } else if val >= 1048576.0 {
        format!("{:.2} M{suffix}", val / 1048576.0)
    } else if val >= 1024.0 {
        format!("{:.2} K{suffix}", val / 1024.0)
    } else if exact_int {
        format!("{} {suffix}", val as i64)
    } else {
        format!("{val:.0} {suffix}")
    }
}

/// Human-readable byte count (Go `formatBytes`).
#[must_use]
pub fn format_bytes(n: i64) -> String {
    format_bytes_value(n as f64, "B", true)
}

/// Human-readable byte rate (Go `formatBytesRate`).
#[must_use]
pub fn format_bytes_rate(r: f64) -> String {
    format_bytes_value(r, "B/s", false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    struct CountingWriter {
        n: AtomicI64,
    }

    impl Write for CountingWriter {
        fn write(&mut self, p: &[u8]) -> std::io::Result<usize> {
            self.n.fetch_add(p.len() as i64, Ordering::SeqCst);
            Ok(p.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn format_bytes_values() {
        let cases = [(0, "0 B"), (1, "1 B"), (512, "512 B"), (1023, "1023 B")];
        for (n, want) in cases {
            assert_eq!(format_bytes(n), want, "formatBytes({n})");
        }
        // Prefix/unit checks, mirroring the Go test.
        let big = [
            (1024, "1.00", "KB"),
            (1536, "1.50", "KB"),
            (1048576, "1.00", "MB"),
            (1572864, "1.50", "MB"),
            (1073741824, "1.00", "GB"),
            (1610612736, "1.50", "GB"),
        ];
        for (n, num, unit) in big {
            let got = format_bytes(n);
            assert!(got.starts_with(num), "formatBytes({n}) = {got}");
            assert!(got.contains(unit), "formatBytes({n}) = {got}");
        }
    }

    #[test]
    fn format_bytes_rate_units() {
        let cases = [
            (0.0, "B/s"),
            (500.0, "B/s"),
            (1024.0, "KB/s"),
            (1048576.0, "MB/s"),
            (1073741824.0, "GB/s"),
        ];
        for (r, unit) in cases {
            let got = format_bytes_rate(r);
            assert!(
                got.contains(unit),
                "formatBytesRate({r}) = {got}, want unit {unit}"
            );
        }
    }

    #[test]
    fn direction_writer_counts() {
        let counter = AtomicI64::new(0);
        let mut dw = DirectionWriter {
            w: CountingWriter {
                n: AtomicI64::new(0),
            },
            counter: &counter,
        };
        let n = dw.write(b"hello").unwrap();
        assert_eq!(n, 5);
        assert_eq!(counter.load(Ordering::SeqCst), 5);
    }

    #[test]
    fn direction_writer_multiple_writes() {
        let counter = AtomicI64::new(0);
        let mut dw = DirectionWriter {
            w: CountingWriter {
                n: AtomicI64::new(0),
            },
            counter: &counter,
        };
        dw.write_all(b"abc").unwrap();
        dw.write_all(b"def").unwrap();
        dw.write_all(b"ghi").unwrap();
        assert_eq!(counter.load(Ordering::SeqCst), 9);
    }

    #[test]
    fn tracker_txrx() {
        let st = StatsTracker::new();
        let mut tx = st.tx_writer(CountingWriter {
            n: AtomicI64::new(0),
        });
        let mut rx = st.rx_writer(CountingWriter {
            n: AtomicI64::new(0),
        });
        tx.write_all(b"tx-data").unwrap();
        rx.write_all(b"rx-data").unwrap();
        assert_eq!(st.tx(), 7);
        assert_eq!(st.rx(), 7);
    }

    #[test]
    fn tracker_stop_and_log() {
        let st = StatsTracker::new();
        st.stop_and_log(); // must not panic
    }

    #[tokio::test]
    async fn async_direction_writer_counts() {
        use tokio::io::AsyncWriteExt;

        let counter = AtomicI64::new(0);
        let mut sink: Vec<u8> = Vec::new();
        let mut dw = AsyncDirectionWriter {
            w: &mut sink,
            counter: &counter,
        };
        dw.write_all(b"hello").await.unwrap();
        dw.write_all(b"world").await.unwrap();
        assert_eq!(counter.load(Ordering::SeqCst), 10);
        assert_eq!(&sink[..], b"helloworld");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn direction_writer_concurrent() {
        let counter = Arc::new(AtomicI64::new(0));
        let handles: Vec<_> = (0..100)
            .map(|_| {
                let counter = Arc::clone(&counter);
                tokio::spawn(async move {
                    let mut dw = DirectionWriter {
                        w: CountingWriter {
                            n: AtomicI64::new(0),
                        },
                        counter: &counter,
                    };
                    dw.write_all(b"x").unwrap();
                })
            })
            .collect();
        for h in handles {
            h.await.unwrap();
        }
        assert_eq!(counter.load(Ordering::SeqCst), 100);
    }
}
