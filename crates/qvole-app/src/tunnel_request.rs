//! Tunnel request parsing (Go `internal/app/tunnel_request.go`).
//!
//! One port-forwarding tunnel spec, plus the peer-supplied request-list
//! reader and the `[laddr:]lport:raddr:rport` spec parser. All address
//! handling is textual: Go `net.JoinHostPort` semantics are replicated in
//! [`join_host_port`] (bracket hosts containing a colon; the error cases of
//! the Go function are unreachable here because bracketed inputs are
//! already stripped before joining).

use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt};

/// Go `dialTimeout`: dial timeout for peer-initiated forward targets.
/// (Env-overridable via `QVOLE_DIAL_TIMEOUT_MS` at the call site, Go
/// `tunnel.go:547`.)
pub const DIAL_TIMEOUT: Duration = Duration::from_secs(10);

/// Go `scannerMaxTokenSize`: max line length in the peer request stream.
pub const SCANNER_MAX_TOKEN_SIZE: usize = 4096;

/// Go `maxTunnelRequests`: per-side cap on peer tunnel requests.
pub const MAX_TUNNEL_REQUESTS: usize = 100;

/// Go `streamHeaderTimeout`: read deadline for the first bytes of a tunnel
/// data stream.
pub const STREAM_HEADER_TIMEOUT: Duration = Duration::from_secs(15);

/// Go `streamConfigTimeout`: deadline for the whole tunnel config exchange.
pub const STREAM_CONFIG_TIMEOUT: Duration = Duration::from_secs(30);

/// Go `TunnelRequest`: one port-forwarding tunnel specification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TunnelRequest {
    /// "L" or "R".
    pub typ: String,
    pub listen_addr: String,
    pub target_addr: String,
}

/// Errors from [`read_requests_from_stream`].
#[derive(Debug, thiserror::Error)]
pub enum TunnelRequestError {
    /// Go: `too many tunnel requests from peer`.
    #[error("too many tunnel requests from peer")]
    TooMany,
    /// Go: `invalid request line: %q`.
    #[error("invalid request line: {0:?}")]
    InvalidLine(String),
    /// Go: `invalid tunnel type %q in line: %q`.
    #[error("invalid tunnel type {0:?} in line: {1:?}")]
    InvalidType(String, String),
    /// Go: `read requests: %w` (I/O or `bufio.Scanner: token too long`).
    #[error("read requests: {0}")]
    Read(String),
}

/// Port of `readRequestsFromStream`: reads `TYPE listen target` lines from
/// `reader` until an `END` line or EOF, capping at [`MAX_TUNNEL_REQUESTS`]
/// and each line (token) at [`SCANNER_MAX_TOKEN_SIZE`] bytes (Go's
/// `bufio.Scanner` max token size; a longer line is an error, not a
/// truncation).
///
/// `reader` is any async byte source (in production the peer's tunnel
/// stream; in tests a `Cursor`).
pub async fn read_requests_from_stream<R>(
    reader: &mut R,
) -> Result<Vec<TunnelRequest>, TunnelRequestError>
where
    R: AsyncRead + Unpin,
{
    let mut reqs: Vec<TunnelRequest> = Vec::new();
    let mut line: Vec<u8> = Vec::new();
    let mut chunk: Vec<u8> = Vec::with_capacity(4096); // bytes from the last read
    let mut pos = 0usize;

    loop {
        // Read one "token" (line) at a time, Go `scanner.Scan()`.
        line.clear();
        loop {
            if pos >= chunk.len() {
                chunk.resize(4096, 0);
                let n = reader
                    .read(&mut chunk)
                    .await
                    .map_err(|e| TunnelRequestError::Read(e.to_string()))?;
                if n == 0 {
                    // EOF: clear the (fully consumed) chunk so the next
                    // line-accumulation pass sees an empty buffer, not
                    // stale/zeroed bytes.
                    chunk.clear();
                    pos = 0;
                    break; // possibly with a final unterminated line
                }
                chunk.truncate(n);
                pos = 0;
            }
            let b = chunk[pos];
            pos += 1;
            if b == b'\n' {
                line.push(b);
                break; // token complete
            }
            if line.len() >= SCANNER_MAX_TOKEN_SIZE {
                // Go: bufio.ErrTooLong → scanner.Err() → wrapped below.
                return Err(TunnelRequestError::Read(
                    "bufio.Scanner: token too long".to_string(),
                ));
            }
            line.push(b);
        }
        if line.is_empty() {
            break; // EOF before any data
        }

        // Go `scanner.Text()`: strip trailing \r\n / \n.
        let text = strip_eol(&line);
        if text == "END" {
            break;
        }
        if reqs.len() >= MAX_TUNNEL_REQUESTS {
            return Err(TunnelRequestError::TooMany);
        }
        let mut parts = text.splitn(3, ' ');
        let (Some(typ), Some(listen), Some(target)) = (parts.next(), parts.next(), parts.next())
        else {
            return Err(TunnelRequestError::InvalidLine(text));
        };
        if typ != "L" && typ != "R" {
            return Err(TunnelRequestError::InvalidType(typ.to_string(), text));
        }
        reqs.push(TunnelRequest {
            typ: typ.to_string(),
            listen_addr: parse_addr(listen),
            target_addr: parse_addr(target),
        });
    }
    Ok(reqs)
}

pub(crate) fn strip_eol(line: &[u8]) -> String {
    let mut end = line.len();
    if end > 0 && line[end - 1] == b'\n' {
        end -= 1;
    }
    if end > 0 && line[end - 1] == b'\r' {
        end -= 1;
    }
    String::from_utf8_lossy(&line[..end]).into_owned()
}

/// Port of `SplitTunnelRequest`: splits a tunnel spec by colons, respecting
/// bracketed IPv6 addresses. Returns `None` for malformed input.
///
/// Byte-exact: the delimiter characters (`:`, `[`, `]`) are all ASCII, so a
/// byte scan reproduces Go's rune scan (including its `i+1` boundaries).
pub fn split_tunnel_request(spec: &str) -> Option<Vec<String>> {
    let mut parts: Vec<String> = Vec::new();
    let mut depth = 0i32;
    let mut start = 0usize;
    for (i, &c) in spec.as_bytes().iter().enumerate() {
        match c {
            b'[' => depth += 1,
            b']' => {
                depth -= 1;
                if depth < 0 {
                    return None;
                }
            }
            b':' if depth == 0 => {
                parts.push(spec[start..i].to_string());
                start = i + 1;
            }
            _ => {}
        }
    }
    if depth != 0 {
        return None;
    }
    parts.push(spec[start..].to_string());
    Some(parts)
}

/// Port of `stripBrackets`.
pub fn strip_brackets(s: &str) -> String {
    if s.len() >= 2 && s.starts_with('[') && s.ends_with(']') {
        s[1..s.len() - 1].to_string()
    } else {
        s.to_string()
    }
}

/// Port of `parseAddr`: strips control characters, keeping only printable
/// ASCII (32..=126) from a peer-supplied address string. Peer-supplied
/// addresses are logged and used as dial/listen targets; control characters
/// could enable log-injection attacks on terminals.
pub fn parse_addr(s: &str) -> String {
    s.bytes()
        .filter(|&c| (32..127).contains(&c))
        .map(|c| c as char)
        .collect()
}

/// Go `net.JoinHostPort`: brackets a host containing a colon (literal
/// IPv6) and joins with `:`.
pub fn join_host_port(host: &str, port: &str) -> String {
    if host.contains(':') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

/// Port of `ParseTunnelRequest`: parses a local (`L`) or remote (`R`)
/// tunnel spec of the form `[laddr:]lport:raddr:rport`.
///
/// 3-part (`lport:raddr:rport`): listen on `127.0.0.1:lport`.
/// 4-part (`laddr:lport:raddr:rport`): empty listen host defaults to
/// `127.0.0.1`.
pub fn parse_tunnel_request(spec: &str, typ: &str) -> Result<TunnelRequest, String> {
    let parts = split_tunnel_request(spec).unwrap_or_default();

    let (listen_addr, target_addr) = match parts.len() {
        3 => (
            join_host_port("127.0.0.1", &parts[0]),
            join_host_port(&strip_brackets(&parts[1]), &parts[2]),
        ),
        4 => {
            let listen_host = strip_brackets(&parts[0]);
            let listen_host = if listen_host.is_empty() {
                "127.0.0.1".to_string()
            } else {
                listen_host
            };
            (
                join_host_port(&listen_host, &parts[1]),
                join_host_port(&strip_brackets(&parts[2]), &parts[3]),
            )
        }
        _ => {
            return Err(
                "expected [laddr:]lport:raddr:rport or [raddr:]rport:laddr:lport format"
                    .to_string(),
            );
        }
    };

    Ok(TunnelRequest {
        typ: typ.to_string(),
        listen_addr,
        target_addr,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn req(spec: &str, typ: &str) -> TunnelRequest {
        parse_tunnel_request(spec, typ).unwrap_or_else(|e| panic!("parse {spec:?}: {e}"))
    }

    #[test]
    fn parse_tunnel_request_local_3part() {
        let s = req("8080:localhost:80", "L");
        assert_eq!(s.typ, "L");
        assert_eq!(s.listen_addr, "127.0.0.1:8080");
        assert_eq!(s.target_addr, "localhost:80");
    }

    #[test]
    fn parse_tunnel_request_local_4part() {
        let s = req("0.0.0.0:8080:localhost:80", "L");
        assert_eq!(s.listen_addr, "0.0.0.0:8080");
        assert_eq!(s.target_addr, "localhost:80");
    }

    #[test]
    fn parse_tunnel_request_remote_3part() {
        let s = req("9000:localhost:22", "R");
        assert_eq!(s.typ, "R");
        assert_eq!(s.listen_addr, "127.0.0.1:9000");
        assert_eq!(s.target_addr, "localhost:22");
    }

    #[test]
    fn parse_tunnel_request_remote_4part() {
        let s = req("127.0.0.1:9000:localhost:22", "R");
        assert_eq!(s.listen_addr, "127.0.0.1:9000");
        assert_eq!(s.target_addr, "localhost:22");
    }

    #[test]
    fn parse_tunnel_request_ipv6_listen() {
        let s = req("[::1]:8080:localhost:80", "L");
        assert_eq!(s.listen_addr, "[::1]:8080");
        assert_eq!(s.target_addr, "localhost:80");
    }

    #[test]
    fn parse_tunnel_request_ipv6_target() {
        let s = req("8080:[::1]:80", "L");
        assert_eq!(s.listen_addr, "127.0.0.1:8080");
        assert_eq!(s.target_addr, "[::1]:80");
    }

    #[test]
    fn parse_tunnel_request_ipv6_both() {
        let s = req("[::1]:8080:[::1]:80", "L");
        assert_eq!(s.listen_addr, "[::1]:8080");
        assert_eq!(s.target_addr, "[::1]:80");
    }

    #[test]
    fn split_tunnel_request_edge_cases() {
        let cases: &[(&str, Option<usize>)] = &[
            ("8080:localhost:80", Some(3)),
            ("127.0.0.1:8080:localhost:80", Some(4)),
            ("[::1]:8080:localhost:80", Some(4)),
            ("[::1]:8080:[::1]:80", Some(4)),
            ("", Some(1)),
            ("a:b", Some(2)),
            ("a:b:c", Some(3)),
            ("a:b:c:d", Some(4)),
            (":::", Some(4)),
            ("[::1", None),
            ("]abc[", None),
            ("[", None),
            ("[[::]]:80:80", Some(3)),
        ];
        for (spec, want) in cases {
            let parts = split_tunnel_request(spec);
            match want {
                None => {
                    assert!(
                        parts.is_none(),
                        "SplitTunnelRequest({spec:?}) = {parts:?}, want None"
                    )
                }
                Some(n) => {
                    let parts = parts.unwrap_or_else(|| {
                        panic!("SplitTunnelRequest({spec:?}) = None, want {n} parts")
                    });
                    assert_eq!(
                        parts.len(),
                        *n,
                        "SplitTunnelRequest({spec:?}) = {parts:?} ({} parts), want {n} parts",
                        parts.len()
                    );
                }
            }
        }
    }

    #[test]
    fn parse_tunnel_request_invalid() {
        let cases = [
            ("invalid", "L"),
            ("a:b:c:d:e", "L"),
            ("", "L"),
            ("a:b", "L"),
            ("8080", "L"),
            ("[::1:8080:localhost:80", "L"),
        ];
        for (spec, typ) in cases {
            assert!(
                parse_tunnel_request(spec, typ).is_err(),
                "expected error for spec {spec:?} type {typ:?}"
            );
        }
    }

    #[test]
    fn tunnel_constants() {
        assert_eq!(
            qvole_protocol::transport::get_forward_max_streams(None),
            200
        );
        assert_eq!(MAX_TUNNEL_REQUESTS, 100);
        assert_eq!(SCANNER_MAX_TOKEN_SIZE, 4096);
    }

    #[test]
    fn parse_tunnel_request_4part_empty_listen_host() {
        // Empty listen host in ":8080:host:80" defaults to 127.0.0.1.
        let s = req(":8080:localhost:80", "L");
        assert_eq!(s.listen_addr, "127.0.0.1:8080");
        assert_eq!(s.target_addr, "localhost:80");
    }

    #[test]
    fn parse_tunnel_request_4part_explicit_all_interfaces() {
        // Explicit 0.0.0.0 should be preserved.
        let s = req("0.0.0.0:8080:localhost:80", "L");
        assert_eq!(s.listen_addr, "0.0.0.0:8080");
    }

    #[test]
    fn tunnel_request_struct() {
        let s = TunnelRequest {
            typ: "L".into(),
            listen_addr: "127.0.0.1:8080".into(),
            target_addr: "8.8.8.8:53".into(),
        };
        assert_eq!(s.typ, "L");
        assert_eq!(s.listen_addr, "127.0.0.1:8080");
        assert_eq!(s.target_addr, "8.8.8.8:53");
    }

    #[test]
    fn parse_tunnel_request_port_only() {
        assert!(
            parse_tunnel_request("8080", "L").is_err(),
            "expected error for single-part spec"
        );
    }

    fn build_requests(n: usize) -> Vec<u8> {
        let mut out = Vec::new();
        for _ in 0..n {
            out.extend_from_slice(b"L 127.0.0.1:8080 localhost:80\n");
        }
        out.extend_from_slice(b"END\n");
        out
    }

    #[tokio::test]
    async fn read_requests_from_stream_peer_cap() {
        // maxTunnelRequests is the per-side cap: exactly that many are accepted.
        let mut reader = Cursor::new(build_requests(MAX_TUNNEL_REQUESTS));
        let reqs = read_requests_from_stream(&mut reader)
            .await
            .expect("exactly at cap is allowed");
        assert_eq!(reqs.len(), MAX_TUNNEL_REQUESTS);

        // One more exceeds the per-side cap.
        let mut reader = Cursor::new(build_requests(MAX_TUNNEL_REQUESTS + 1));
        assert!(
            read_requests_from_stream(&mut reader).await.is_err(),
            "expected error when peer exceeds maxTunnelRequests"
        );
    }

    #[tokio::test]
    async fn read_requests_from_stream_rejects_invalid_type() {
        let valid_cases = [
            "L 127.0.0.1:8080 localhost:80\nEND\n",
            "R 127.0.0.1:8080 localhost:80\nEND\n",
            "L 127.0.0.1:8080 localhost:80\nR 127.0.0.1:9090 localhost:22\nEND\n",
        ];
        for input in valid_cases {
            let mut reader = Cursor::new(input.as_bytes().to_vec());
            let reqs = read_requests_from_stream(&mut reader)
                .await
                .unwrap_or_else(|e| panic!("valid case {input:?}: {e}"));
            assert!(
                !reqs.is_empty(),
                "valid case {input:?}: expected non-empty requests"
            );
        }

        let invalid_cases = [
            "X 127.0.0.1:8080 localhost:80\nEND\n",
            "LR 127.0.0.1:8080 localhost:80\nEND\n",
            "l 127.0.0.1:8080 localhost:80\nEND\n",
            " 127.0.0.1:8080 localhost:80\nEND\n",
        ];
        for input in invalid_cases {
            let mut reader = Cursor::new(input.as_bytes().to_vec());
            assert!(
                read_requests_from_stream(&mut reader).await.is_err(),
                "invalid case {input:?}: expected error"
            );
        }
    }

    #[tokio::test]
    async fn read_requests_from_stream_token_too_long() {
        // A line longer than SCANNER_MAX_TOKEN_SIZE fails, like Go's
        // bufio.Scanner.ErrTooLong.
        let mut input: Vec<u8> = Vec::new();
        input.extend_from_slice(b"L ");
        input.extend_from_slice(&[b'a'; SCANNER_MAX_TOKEN_SIZE + 1]);
        input.extend_from_slice(b"\nEND\n");
        let mut reader = Cursor::new(input);
        let err = read_requests_from_stream(&mut reader).await.unwrap_err();
        assert!(matches!(err, TunnelRequestError::Read(_)));
        let msg = err.to_string();
        assert!(msg.contains("token too long"), "got: {msg}");
    }

    #[tokio::test]
    async fn read_requests_from_stream_final_line_without_newline() {
        // Go's scanner also yields a final unterminated token.
        let input = b"L 127.0.0.1:8080 localhost:80"; // no trailing END/newline
        let mut reader = Cursor::new(input.to_vec());
        let reqs = read_requests_from_stream(&mut reader).await.unwrap();
        assert_eq!(reqs.len(), 1);
        assert_eq!(reqs[0].target_addr, "localhost:80");
    }

    #[tokio::test]
    async fn read_requests_from_stream_strips_control_chars_in_addrs() {
        // parse_addr drops control characters from peer-supplied addrs.
        let input: Vec<u8> = b"L 127.0.0.1:808\x010 localhost:80\nEND\n".to_vec();
        let mut reader = Cursor::new(input);
        let reqs = read_requests_from_stream(&mut reader).await.unwrap();
        assert_eq!(reqs.len(), 1);
        assert_eq!(
            reqs[0].listen_addr, "127.0.0.1:8080",
            "control char stripped"
        );
        assert_eq!(reqs[0].target_addr, "localhost:80");
    }

    #[tokio::test]
    async fn read_requests_from_stream_tab_is_not_a_delimiter() {
        // Only ' ' splits (Go strings.SplitN on " "); a tab lands inside
        // the type field and fails the L/R check.
        let input = b"L\t127.0.0.1:8080 localhost:80\nEND\n";
        let mut reader = Cursor::new(input.to_vec());
        let err = read_requests_from_stream(&mut reader).await.unwrap_err();
        assert!(
            matches!(err, TunnelRequestError::InvalidLine(_)),
            "got: {err:?}"
        );
    }
}
