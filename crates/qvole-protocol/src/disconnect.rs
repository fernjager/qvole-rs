//! Disconnect classification (Go `internal/engine/disconnect.go`).

use quinn::ConnectionError;

use crate::logger::{Logger, debug_enabled};

/// Port of `IsPeerDisconnect`.
///
/// Reports whether `err` means the remote peer closed or lost the connection
/// (application error, peer transport abort, idle timeout, or stateless
/// reset), as opposed to a local cancellation or an unexpected local
/// failure.
#[must_use]
pub fn is_peer_disconnect(err: &ConnectionError) -> bool {
    matches!(
        err,
        ConnectionError::ApplicationClosed(_)
            | ConnectionError::ConnectionClosed(_)
            | ConnectionError::TransportError(_)
            | ConnectionError::Reset
            | ConnectionError::TimedOut
    )
}

/// Port of `LogDisconnect`.
///
/// Logs a friendly "Remote host disconnected" message, keeping the
/// underlying error detail for `--debug`. Returns `true` when `err` was a
/// peer disconnect (and a message was logged).
#[must_use]
pub fn log_disconnect(l: &Logger, err: &ConnectionError) -> bool {
    if !is_peer_disconnect(err) {
        return false;
    }
    if debug_enabled() {
        l.printf_warn(&format!("Remote host disconnected: {err}"));
    } else {
        l.printf_warn("Remote host disconnected");
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use quinn::{ApplicationClose, ConnectionClose};

    #[test]
    fn peer_disconnect_variants() {
        let app = ConnectionError::ApplicationClosed(ApplicationClose {
            error_code: quinn::VarInt::from_u32(1),
            reason: Default::default(),
        });
        assert!(is_peer_disconnect(&app), "application close");
        let reset = ConnectionError::Reset;
        assert!(is_peer_disconnect(&reset), "stateless reset");
        let timeout = ConnectionError::TimedOut;
        assert!(is_peer_disconnect(&timeout), "idle timeout");
    }

    #[test]
    fn local_and_other_errors_are_not_peer_disconnects() {
        let local = ConnectionError::LocallyClosed;
        assert!(!is_peer_disconnect(&local), "local close");
        let version = ConnectionError::VersionMismatch;
        assert!(!is_peer_disconnect(&version), "version mismatch");
        let cids = ConnectionError::CidsExhausted;
        assert!(!is_peer_disconnect(&cids), "cids exhausted");
        let closed = ConnectionError::ConnectionClosed(ConnectionClose {
            error_code: quinn::TransportErrorCode::NO_ERROR,
            frame_type: None,
            reason: Default::default(),
        });
        assert!(is_peer_disconnect(&closed), "peer connection close");
    }
}
