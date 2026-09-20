//! A QUIC bidirectional stream exposed as a single async read/write
//! endpoint (Go `stream.go` `quicStreamConn`).
//!
//! Go parity:
//! * `Read`/`Write` delegate to the stream halves.
//! * `CloseWrite` sends FIN on the send half (`SendStream::finish`).
//! * `Close` sends FIN, waits [`STREAM_CLOSE_DELAY`] so unacknowledged
//!   stream data can still be delivered (quic-go makes no delivery
//!   guarantee once `CONNECTION_CLOSE` is on the wire), then closes the
//!   connection with `(0, "normal close")`.

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

use quinn::{ClosedStream, Connection, Endpoint, RecvStream, SendStream, VarInt};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// Go `streamCloseDelay` (500 ms).
pub const STREAM_CLOSE_DELAY: Duration = Duration::from_millis(500);

/// Force quinn to announce a freshly opened bidirectional stream to the
/// peer.
///
/// **Corrected claim.** This is *not* "Go `OpenStreamSync`
/// parity": quic-go (v0.61.0) also does **not** announce a locally-opened
/// stream until data, FIN, or a reset is sent. quic-go documents it -
/// *"There is no signaling to the peer about new streams: the peer can only
/// accept the stream after data has been sent on the stream, or the stream
/// has been reset or closed."* Empirically, against quic-go a plain
/// `OpenStreamSync` and even a 0-byte write leave the peer's `AcceptStream`
/// blocked; only real data or FIN announces it.
///
/// quinn is lazy too, but a 0-byte `write` **does** queue one 0-byte STREAM
/// frame, which announces the stream. So this workaround makes a
/// quinn↔quinn pair behave as both sides expect, but it does **not** help
/// against a quic-go peer: a Rust-opened stream with a 0-byte announce is
/// accepted by quic-go (quinn puts a frame on the wire), while a Go-opened
/// stream stays invisible to quinn until Go writes or FINs.
///
/// Consequently this cannot fix interactive exec against a Go host (Go opens
/// the exec stream and writes nothing until the command produces output).
/// That needs a coordinated wire change; do not change the wire
/// unilaterally.
///
/// Call this on the send half immediately after `open_bi()` when the peer
/// may send before we do.
pub async fn announce_stream(send: &mut SendStream) -> io::Result<()> {
    send.write(b"").await.map(|_| ()).map_err(io::Error::from)
}

/// A QUIC bidirectional stream usable as one async endpoint
/// (Go `quicStreamConn`).
pub struct QuicStreamConn {
    send: SendStream,
    recv: RecvStream,
    conn: Connection,
    /// Owned endpoint handle keeping the QUIC connection alive after the
    /// `Connected` value that produced the stream is dropped (Go parity:
    /// the `quicStreamConn.conn` field keeps the connection rooted while the
    /// stream is live; quinn instead roots the driver on the `Endpoint`).
    endpoint: Option<Endpoint>,
}

impl QuicStreamConn {
    /// Wrap an already-opened bidirectional stream. The endpoint is not
    /// owned; the caller must keep it alive (in-crate tests do this by
    /// holding the `Connected` value).
    pub fn new(conn: Connection, send: SendStream, recv: RecvStream) -> Self {
        Self {
            send,
            recv,
            conn,
            endpoint: None,
        }
    }

    /// Wrap an already-opened bidirectional stream and own the endpoint, so
    /// the connection outlives the `Connected` value that opened the stream
    /// (used by the library `dial`/`accept` API).
    pub fn with_endpoint(
        conn: Connection,
        send: SendStream,
        recv: RecvStream,
        endpoint: Endpoint,
    ) -> Self {
        Self {
            send,
            recv,
            conn,
            endpoint: Some(endpoint),
        }
    }

    /// The underlying QUIC connection handle.
    pub fn conn(&self) -> &Connection {
        &self.conn
    }

    /// The owned endpoint handle (if any) keeping the connection alive.
    pub fn endpoint(&self) -> Option<&Endpoint> {
        self.endpoint.as_ref()
    }

    /// Go `CloseWrite`: close the send half (FIN) without closing the
    /// connection.
    pub async fn close_write(&mut self) -> Result<(), ClosedStream> {
        self.send.finish()
    }

    /// Go `Close`: close the stream, wait [`STREAM_CLOSE_DELAY`], then
    /// close the QUIC connection with `(0, "normal close")`.
    pub async fn close(&mut self) -> Result<(), ClosedStream> {
        let err = self.send.finish();
        tokio::time::sleep(STREAM_CLOSE_DELAY).await;
        self.conn.close(VarInt::from_u32(0), b"normal close");
        err
    }
}

// quinn's stream halves have inherent `poll_*` methods with quinn error
// types; call the tokio trait impls explicitly.
impl std::fmt::Debug for QuicStreamConn {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("QuicStreamConn")
            .field("conn", &self.conn)
            .finish_non_exhaustive()
    }
}

impl AsyncRead for QuicStreamConn {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        tokio::io::AsyncRead::poll_read(Pin::new(&mut self.recv), cx, buf)
    }
}

impl AsyncWrite for QuicStreamConn {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        tokio::io::AsyncWrite::poll_write(Pin::new(&mut self.send), cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        tokio::io::AsyncWrite::poll_flush(Pin::new(&mut self.send), cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        tokio::io::AsyncWrite::poll_shutdown(Pin::new(&mut self.send), cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::{HANDSHAKE_TIMEOUT, quic_pair};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// Round-trip data through a [`QuicStreamConn`], then verify `close()`
    /// delivers an EOF before tearing the connection down.
    #[tokio::test]
    async fn test_quic_stream_conn_roundtrip_and_close() {
        let (client_conn, client_ep, server_conn, server_ep) = quic_pair().await;
        // Keep both endpoints (and one handle per side) alive for the whole
        // test so no implicit CONNECTION_CLOSE is emitted early.
        let _keep = (
            client_ep,
            server_ep,
            client_conn.clone(),
            server_conn.clone(),
        );

        let (send, recv) = tokio::time::timeout(HANDSHAKE_TIMEOUT, client_conn.open_bi())
            .await
            .expect("open_bi timed out")
            .expect("open_bi failed");
        let mut client = QuicStreamConn::new(client_conn, send, recv);

        // Write first: quinn only notifies the peer about the new stream
        // once it is actually used (the same lazy-open behavior quic-go
        // documents; see `announce_stream`).
        client.write_all(b"ping").await.expect("write");

        let (server_send, server_recv) =
            tokio::time::timeout(HANDSHAKE_TIMEOUT, server_conn.accept_bi())
                .await
                .expect("accept_bi timed out")
                .expect("accept_bi failed");
        let mut server = QuicStreamConn::new(server_conn, server_send, server_recv);

        let mut buf = [0u8; 4];
        server.read_exact(&mut buf).await.expect("read");
        assert_eq!(&buf, b"ping");

        // echo back
        server.write_all(b"pong").await.expect("write");
        client.read_exact(&mut buf).await.expect("read");
        assert_eq!(&buf, b"pong");

        // Close(): FIN first, then connection close after the grace delay.
        client.close().await.expect("close");
        // The server must observe EOF (FIN) - not a connection error - on
        // the stream.
        let n = server.read(&mut buf).await.expect("eof read");
        assert_eq!(n, 0, "expected EOF after Close(), got {n} bytes");
    }

    /// Pin quinn's stream-announcement behavior
    /// so the quinn/quic-go asymmetry is visible in-tree.
    ///
    /// quinn, like quic-go, does not announce an opened stream that has sent
    /// no data and is not finished; `announce_stream`'s 0-byte write **does**
    /// announce it to a quinn peer. quic-go additionally treats a 0-byte
    /// write as a no-op, which is why Go→Rust silent/interactive exec still
    /// needs a coordinated protocol change.
    #[tokio::test]
    async fn test_stream_announcement_requires_data_or_fin_on_quinn() {
        let (client_conn, client_ep, server_conn, server_ep) = quic_pair().await;
        let _keep = (
            client_ep,
            server_ep,
            client_conn.clone(),
            server_conn.clone(),
        );

        // Open with no write: the peer must not observe the stream yet.
        let (_send1, _recv1) = client_conn.open_bi().await.expect("open_bi");
        assert!(
            tokio::time::timeout(Duration::from_millis(500), server_conn.accept_bi())
                .await
                .is_err(),
            "quinn announced a stream before any data/FIN"
        );

        // announce_stream (0-byte write) *does* announce it on a quinn peer.
        let (mut send2, _recv2) = client_conn.open_bi().await.expect("open_bi");
        announce_stream(&mut send2).await.expect("announce_stream");
        let _accepted = tokio::time::timeout(HANDSHAKE_TIMEOUT, server_conn.accept_bi())
            .await
            .expect("accept timed out: 0-byte announce did not announce")
            .expect("accept_bi failed");
    }

    /// `close_write` FINs the send half while the connection stays usable
    /// for the recv half.
    #[tokio::test]
    async fn test_close_write_fins_only_send_side() {
        let (client_conn, client_ep, server_conn, server_ep) = quic_pair().await;
        let _keep = (
            client_ep,
            server_ep,
            client_conn.clone(),
            server_conn.clone(),
        );

        let (send, recv) = tokio::time::timeout(HANDSHAKE_TIMEOUT, client_conn.open_bi())
            .await
            .expect("open_bi timed out")
            .expect("open_bi failed");
        let mut client = QuicStreamConn::new(client_conn, send, recv);

        // Write + FIN first: quinn only notifies the peer about the new
        // stream once it is actually used.
        client.write_all(b"half").await.expect("write");
        client.close_write().await.expect("close_write");

        let (server_send, mut server_recv) =
            tokio::time::timeout(HANDSHAKE_TIMEOUT, server_conn.accept_bi())
                .await
                .expect("accept_bi timed out")
                .expect("accept_bi failed");
        let _server_send = server_send;

        let mut buf = [0u8; 4];
        server_recv.read_exact(&mut buf).await.expect("read");
        assert_eq!(&buf, b"half");
        let n = tokio::io::AsyncReadExt::read(&mut server_recv, &mut buf)
            .await
            .expect("eof");
        assert_eq!(n, 0);
    }
}
