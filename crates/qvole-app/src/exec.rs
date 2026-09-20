//! Exec feature: local command hosting with stream bridging (Go
//! `internal/app/exec.go` + `exec_unix.go` - `childSysProcAttr()` is nil on
//! Linux, so no `SysProcAttr` handling here).
//!
//! ## Design notes
//!
//! * Go's `exec.CommandContext(execCtx, ...)` kills the child (SIGKILL) when
//!   `execCtx` is canceled. The port does the same in the wait/select loop:
//!   on `exec_stop` it calls `child.kill()` (SIGKILL on Unix), then reaps.
//!   `exec_stop` is canceled by the parent cancel (Go: `execCtx` derived from
//!   `ctx`) or by connection loss (Go: `conn.Context().Done()`), **not** by
//!   the stream→stdin copy finishing: a stdin half-close only closes the
//!   child's stdin, so the child keeps running and its real exit code is
//!   preserved.
//! * Go's `cmd.Stdout = stream` makes os/exec use an internal pipe + copy
//!   goroutine, and `cmd.Wait()` waits for that copy to complete. The port
//!   spawns an equivalent stdout copy task and awaits it before returning
//!   (same ordering, and the same grandchild-holds-the-pipe hazard - Go sets
//!   no `WaitDelay` either).
//! * Go's `stream.CancelRead(0)` → quinn `RecvStream::stop(0)` (STOP_SENDING;
//!   subsequent reads return `ReadError::ClosedStream`, classified Benign).
//! * The stream's send half is FINned explicitly after the stdout copy
//!   completes (Go's `defer stream.Close()`); on early-return paths the FIN
//!   is implicit in the `SendStream` drop.

use std::pin::Pin;
use std::time::Duration;

use quinn::{Connection, VarInt};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::process::Command;
use tokio_util::sync::CancellationToken;

use qvole_protocol::connect::{self, ConnectError};
use qvole_protocol::env::env_duration_ms;
use qvole_protocol::exchange::PeerConfig;
use qvole_protocol::logger::{LOG_EXEC, bold};
use qvole_protocol::role::role_string;

use crate::copy::{copy_stream, flush_close};
use crate::pipe::{PipeError, run_pipe_mode};
use crate::stream_conn::announce_stream;

/// Go `execDrainTimeout`.
pub const EXEC_DRAIN_TIMEOUT: Duration = Duration::from_secs(5);

/// Go `execFinishDelay`: grace between the command's stream ending and the
/// connection close (CONNECTION_CLOSE does not guarantee delivery of
/// unacknowledged stream data).
pub const EXEC_FINISH_DELAY: Duration = Duration::from_millis(500);

/// Errors from the exec feature.
#[derive(Debug, thiserror::Error)]
pub enum ExecError {
    /// Connection establishment failed (Go: the `ConnectPeer` error).
    #[error(transparent)]
    Connect(#[from] ConnectError),
    /// Local cancellation (Go: `context.Canceled`).
    #[error("canceled")]
    Canceled,
    /// QUIC-level failure (Go: the wrapped error returned as-is).
    #[error("quic: {0}")]
    Quic(String),
    /// Other local failure (Go: `empty command`, `cmd.StdinPipe`/`Start`
    /// errors, returned as-is).
    #[error("{0}")]
    Other(String),
    /// Child exited non-zero (Go: `*exec.ExitError` with `ExitCode >= 0`).
    #[error("exit status {0}")]
    Exit(i32),
    /// Child killed by a signal (Go: `*exec.ExitError` with `ExitCode -1`;
    /// message matches os/exec's "signal: killed").
    #[error("signal: killed")]
    Killed,
}

impl From<PipeError> for ExecError {
    fn from(e: PipeError) -> Self {
        match e {
            PipeError::Connect(c) => ExecError::Connect(c),
            PipeError::Canceled => ExecError::Canceled,
            PipeError::Quic(s) => ExecError::Quic(s),
        }
    }
}

/// Port of `SplitCommand`: minimal shell-like splitting on spaces/tabs with
/// single and double quotes. Quoted empty arguments are preserved; escape
/// sequences, backticks, globs, redirections, and pipelines are not handled.
/// Returns `None` for unmatched quotes (Go: `nil`).
pub fn split_command(s: &str) -> Option<Vec<String>> {
    let mut args: Vec<String> = Vec::new();
    let mut current: Vec<u8> = Vec::new();
    let mut started = false; // any characters or quotes consumed for the arg
    let mut in_single = false;
    let mut in_double = false;

    for &c in s.as_bytes() {
        if in_single {
            if c == b'\'' {
                in_single = false;
            } else {
                current.push(c);
            }
            continue;
        }
        if in_double {
            if c == b'"' {
                in_double = false;
            } else {
                current.push(c);
            }
            continue;
        }
        match c {
            b'\'' => {
                in_single = true;
                started = true;
            }
            b'"' => {
                in_double = true;
                started = true;
            }
            b' ' | b'\t' => {
                if started {
                    args.push(owned_string(&current));
                    current.clear();
                    started = false;
                }
            }
            _ => {
                current.push(c);
                started = true;
            }
        }
    }
    if in_single || in_double {
        None
    } else {
        if started {
            args.push(owned_string(&current));
        }
        Some(args)
    }
}

/// Byte-exact like Go's `string(current)`: raw bytes become a String
/// (commands arrive as UTF-8; invalid bytes are replaced rather than
/// rejected, which Go would pass through to exec unchanged).
fn owned_string(bytes: &[u8]) -> String {
    match std::str::from_utf8(bytes) {
        Ok(s) => s.to_owned(),
        Err(_) => String::from_utf8_lossy(bytes).into_owned(),
    }
}

/// Port of `RunExecCommand`: opens a QUIC stream, runs the given command
/// with stdin/stdout bridged to the stream, and returns the command's exit
/// error. Stderr goes to the local stderr, never the stream. When the peer
/// closes the stream (read EOF) the child is killed via `exec_stop`.
pub async fn run_exec_command(
    cancel: &CancellationToken,
    conn: &Connection,
    command: &str,
) -> Result<(), ExecError> {
    // Go: `stream, err := conn.OpenStreamSync(ctx)`; `defer stream.Close()`.
    let (mut send, mut recv) = match conn.open_bi().await {
        Ok(bi) => bi,
        Err(e) => {
            if cancel.is_cancelled() {
                // Go: OpenStreamSync returns context.Canceled → main exits 0.
                return Err(ExecError::Canceled);
            }
            return Err(ExecError::Quic(e.to_string()));
        }
    };
    // Force the stream header now (0-byte STREAM frame) so a quinn peer can
    // accept the stream and send its stdin before the command emits output.
    // This is a quinn-side workaround, not Go parity: quic-go is lazy too
    // and ignores a 0-byte write, so a Go-opened stream still cannot reach a
    // quinn peer.
    if let Err(e) = announce_stream(&mut send).await {
        if cancel.is_cancelled() {
            return Err(ExecError::Canceled);
        }
        return Err(ExecError::Quic(e.to_string()));
    }

    // Go: `args := SplitCommand(command); if len(args) == 0 → "empty command"`.
    let args = match split_command(command) {
        Some(args) if !args.is_empty() => args,
        _ => return Err(ExecError::Other("empty command".into())),
    };

    // Go: `execCtx, execCancel := context.WithCancel(ctx)`; the child is
    // killed only on parent-ctx cancel or connection loss.
    let exec_stop = cancel.child_token();

    // Go: `connDone := conn.Context().Done()` watcher - a lost QUIC
    // connection cancels the exec context and kills the child.
    {
        let exec_stop = exec_stop.clone();
        let conn = conn.clone();
        tokio::spawn(async move {
            tokio::select! {
                _ = conn.closed() => exec_stop.cancel(),
                _ = exec_stop.cancelled() => {}
            }
        });
    }

    // Go: `cmd := exec.CommandContext(execCtx, args[0], args[1:]...)`;
    // `cmd.SysProcAttr = childSysProcAttr()` (nil on Linux);
    // `cmd.Stdout = stream`; `cmd.Stderr = os.Stderr`.
    let mut cmd = Command::new(&args[0]);
    cmd.args(&args[1..]);
    cmd.stdin(std::process::Stdio::piped());
    cmd.stdout(std::process::Stdio::piped());
    cmd.stderr(std::process::Stdio::inherit());

    let mut child = cmd.spawn().map_err(|e| ExecError::Other(e.to_string()))?;
    let mut child_stdin = child
        .stdin
        .take()
        .ok_or_else(|| ExecError::Other("take child stdin".to_string()))?;
    let child_stdout = child
        .stdout
        .take()
        .ok_or_else(|| ExecError::Other("take child stdout".to_string()))?;

    // Go copy goroutine: `io.Copy(stdin, stream)` → `stdin.Close()` +
    // `execCancel()` + `close(copyDone)`.
    //
    // `recv` is owned by this task, so the Go drain phase's
    // `stream.CancelRead(0)` is issued *here*: whenever the copy was
    // interrupted by `copy_stop` (peer-side exec_stop or the drain timeout)
    // rather than by a normal read EOF, the task stops the receive side.
    let copy_done = CancellationToken::new();
    let copy_stop = CancellationToken::new();
    {
        // exec_stop (child reaped / ctx canceled) also interrupts the copy.
        let exec_stop = exec_stop.clone();
        let copy_stop = copy_stop.clone();
        tokio::spawn(async move {
            exec_stop.cancelled().await;
            copy_stop.cancel();
        });
    }
    {
        let copy_done = copy_done.clone();
        let copy_stop = copy_stop.clone();
        tokio::spawn(async move {
            let res = copy_stream(
                Pin::new(&mut child_stdin),
                Pin::new(&mut recv),
                None,
                &copy_stop,
            )
            .await;
            // Go drain: `stream.CancelRead(0)` (STOP_SENDING) on interrupt.
            if copy_stop.is_cancelled() {
                let _ = recv.stop(VarInt::from_u32(0));
            }
            let _ = res;
            // Go: stdin.Close() - close the write end (child sees EOF). A
            // stdin half-close no longer cancels the exec context, so the
            // child keeps running and its real exit code survives.
            let _ = child_stdin.shutdown().await;
            copy_done.cancel();
        });
    }

    // Go: `cmd.Stdout = stream` (os/exec pipe copy). Child stdout → stream;
    // FIN the send half once exhausted.
    let stdout_task = tokio::spawn(async move {
        let mut src = child_stdout;
        let mut dst = send;
        let never = CancellationToken::new();
        let _ = copy_stream(Pin::new(&mut dst), Pin::new(&mut src), None, &never).await;
        // Go: `defer stream.Close()` - FIN after all child output is written.
        let _ = dst.finish();
    });

    // Go: `cmdErr := cmd.Wait()`; CommandContext kills the child on
    // execCtx.Done (port: `child.kill()` = SIGKILL, Go's default KillSignal).
    let status = loop {
        tokio::select! {
            s = child.wait() => break s,
            () = exec_stop.cancelled() => {
                // Already-exited children make kill() return Ok(false);
                // the next loop iteration reaps them.
                let _ = child.kill().await;
            }
        }
    };

    let cmd_err: Option<ExecError> = match &status {
        Ok(st) if st.success() => None,
        Ok(st) => match st.code() {
            Some(c) => Some(ExecError::Exit(c)),
            // Exited via signal (e.g. our kill): Go ExitError code -1.
            None => Some(ExecError::Killed),
        },
        Err(e) => Some(ExecError::Other(format!("wait: {e}"))),
    };
    if let Some(e) = &cmd_err {
        // Go: `util.LogExec.PrintfInfo("Command exited: %v", cmdErr)`.
        LOG_EXEC.printf_info(&format!("Command exited: {e}"));
    }

    // Go drain select: copyDone | execCtx.Done (→ CancelRead + wait) |
    // time.After(execDrainTimeout) (→ CancelRead + wait).
    let drain_ms = env_duration_ms(
        "QVOLE_EXEC_DRAIN_TIMEOUT_MS",
        EXEC_DRAIN_TIMEOUT.as_millis() as u64,
    );
    let drain = Duration::from_millis(drain_ms);
    tokio::select! {
        () = copy_done.cancelled() => {}
        () = exec_stop.cancelled() => {
            copy_stop.cancel(); // → copy task issues recv.stop(0)
            copy_done.cancelled().await;
        }
        () = tokio::time::sleep(drain) => {
            copy_stop.cancel(); // Go: time.After(execDrainTimeout) → CancelRead
            copy_done.cancelled().await;
        }
    }

    // Go: cmd.Wait() has already waited for the os/exec stdout copy to
    // complete; mirror that before returning (and before the stream FIN,
    // which the task performs at its end).
    let stdout_res = stdout_task.await;
    // Go: `defer execCancel()` - stop the connection watcher and any copy
    // still parked on the exec context once the command is done.
    exec_stop.cancel();

    if let Err(e) = stdout_res {
        return Err(ExecError::Other(format!("stdout copy: {e}")));
    }

    match cmd_err {
        Some(e) => Err(e),
        None => Ok(()),
    }
}

/// Port of `RunExec`: connects to a peer and either runs a command locally
/// (cmdMode) or bridges stdin/stdout (pipe mode fallback).
///
/// On the cmdMode path this logs the role + command, runs it, sleeps
/// [`EXEC_FINISH_DELAY`], and closes the connection with
/// `CloseWithError(0, "")` (Go parity - note the empty close reason, unlike
/// the pipe paths' `"done"`).
#[allow(clippy::too_many_arguments)] // Go RunExec parity (9 params)
pub async fn run_exec<IN, OUT>(
    cancel: &CancellationToken,
    relay_addr: &str,
    code: &str,
    cfg: &PeerConfig,
    command: &str,
    cmd_mode: bool,
    mut stdin: IN,
    mut stdout: OUT,
    close_stdin: impl FnOnce(),
) -> Result<(), ExecError>
where
    IN: AsyncRead + Unpin + Send + 'static,
    OUT: AsyncWrite + Unpin + Send + 'static,
{
    let connected = connect::connect_peer(cancel, relay_addr, code, cfg).await?;
    let role = role_string(connected.is_server);

    if cmd_mode {
        LOG_EXEC.printf_success(&format!("Connected as {role}"));
        LOG_EXEC.printf_info(&format!("Running command: {}", bold(command)));
        let err = run_exec_command(cancel, &connected.conn, command).await;
        // Go: `time.Sleep(execFinishDelay); conn.CloseWithError(0, "")`.
        tokio::time::sleep(EXEC_FINISH_DELAY).await;
        connected.conn.close(VarInt::from_u32(0), b"");
        // Let the woken driver send the CONNECTION_CLOSE before the
        // process exits (quinn schedules, Go quic-go flushes inline).
        flush_close().await;
        return err;
    }

    // Go: `defer conn.CloseWithError(0, "done"); return RunPipeMode(...)`.
    let res = run_pipe_mode(
        cancel,
        &connected.conn,
        role,
        Pin::new(&mut stdin),
        Pin::new(&mut stdout),
        close_stdin,
    )
    .await;
    connected.conn.close(VarInt::from_u32(0), b"done");
    // Let the woken driver send the CONNECTION_CLOSE before the process
    // exits (quinn schedules, Go quic-go flushes inline).
    flush_close().await;
    res.map_err(ExecError::from)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::quic_pair;
    use tokio::time::timeout;

    // ---- SplitCommand (port of TestSplitCommand_*) ----

    #[test]
    fn split_command_empty() {
        assert_eq!(split_command("").unwrap(), Vec::<String>::new());
    }

    #[test]
    fn split_command_simple() {
        assert_eq!(
            split_command("echo hello world").unwrap(),
            vec!["echo", "hello", "world"]
        );
    }

    #[test]
    fn split_command_single_quotes() {
        assert_eq!(
            split_command("echo 'hello world' foo").unwrap(),
            vec!["echo", "hello world", "foo"]
        );
    }

    #[test]
    fn split_command_double_quotes() {
        assert_eq!(
            split_command(r#"echo "hello world" foo"#).unwrap(),
            vec!["echo", "hello world", "foo"]
        );
    }

    #[test]
    fn split_command_unmatched_single_quote() {
        assert!(split_command("echo 'unclosed").is_none());
    }

    #[test]
    fn split_command_unmatched_double_quote() {
        assert!(split_command(r#"echo "unclosed"#).is_none());
    }

    #[test]
    fn split_command_multiple_spaces() {
        assert_eq!(
            split_command("echo   hello    world  ").unwrap(),
            vec!["echo", "hello", "world"]
        );
    }

    #[test]
    fn split_command_tabs() {
        assert_eq!(
            split_command("echo\thello\tworld").unwrap(),
            vec!["echo", "hello", "world"]
        );
    }

    #[test]
    fn split_command_nested_quotes() {
        assert_eq!(
            split_command(r#"echo "it's a test""#).unwrap(),
            vec!["echo", "it's a test"]
        );
    }

    #[test]
    fn split_command_just_whitespace() {
        assert_eq!(split_command("   \t  \t  ").unwrap(), Vec::<String>::new());
    }

    #[test]
    fn split_command_single_word() {
        assert_eq!(split_command("single").unwrap(), vec!["single"]);
    }

    #[test]
    fn split_command_empty_quoted_arg() {
        let cases = [
            ("run '' x", vec!["run", "", "x"]),
            (r##"run "" x"##, vec!["run", "", "x"]),
            ("run ''", vec!["run", ""]),
            ("'' run", vec!["", "run"]),
            ("''", vec![""]),
            ("a ''b c", vec!["a", "b", "c"]),
        ];
        for (input, want) in cases {
            assert_eq!(split_command(input).unwrap(), want, "input: {input:?}");
        }
    }

    // ---- RunExecCommand (ports of TestRunExecCommand_*) ----
    //
    // These use the plain QUIC pair from helper_test.go: the spawned side
    // runs the command (opening the stream), the other side accepts it.
    // NOTE: like the Go tests, echo/large-output take ~5s (Go's drain
    // timeout) because the accepting side never FINs its send half.

    async fn accept_and_read(conn: &Connection) -> Vec<u8> {
        let (_send, mut recv) = conn.accept_bi().await.expect("accept_bi failed");
        recv.read_to_end(u32::MAX as usize)
            .await
            .expect("read_to_end failed")
    }

    #[tokio::test]
    async fn run_exec_command_echo() {
        let (client, _client_ep, server, _server_ep) = quic_pair().await;

        let exec_task = tokio::spawn(async move {
            run_exec_command(&CancellationToken::new(), &server, "echo hello-exec").await
        });

        let out = accept_and_read(&client).await;
        let err = exec_task.await.unwrap();
        assert!(err.is_ok(), "RunExecCommand: {err:?}");
        assert!(
            String::from_utf8_lossy(&out).contains("hello-exec"),
            "expected 'hello-exec', got {out:?}"
        );
    }

    #[tokio::test]
    async fn run_exec_command_exit_code() {
        let (client, _client_ep, server, _server_ep) = quic_pair().await;

        let exec_task = tokio::spawn(async move {
            run_exec_command(&CancellationToken::new(), &server, "sh -c 'exit 42'").await
        });

        let _out = accept_and_read(&client).await;
        let err = exec_task.await.unwrap();
        match err {
            Err(ExecError::Exit(42)) => {}
            other => panic!("expected Exit(42), got {other:?}"),
        }
    }

    #[tokio::test]
    async fn run_exec_command_large_output() {
        let (client, _client_ep, server, _server_ep) = quic_pair().await;

        let exec_task = tokio::spawn(async move {
            run_exec_command(
                &CancellationToken::new(),
                &server,
                "sh -c 'dd if=/dev/zero bs=1048576 count=1 2>/dev/null'",
            )
            .await
        });

        let out = accept_and_read(&client).await;
        let err = exec_task.await.unwrap();
        assert!(err.is_ok(), "RunExecCommand: {err:?}");
        assert_eq!(out.len(), 1048576);
    }

    #[tokio::test]
    async fn run_exec_command_open_stream_smoke() {
        let (_client, _client_ep, server, _server_ep) = quic_pair().await;
        // Go TestRunExecCommand_OpenStreamSyncError: verify OpenStreamSync
        // (open_bi) succeeds on a valid connection.
        let (mut send, _recv) = server.open_bi().await.expect("open_bi failed");
        let _ = send.finish();
    }

    #[tokio::test]
    async fn run_exec_command_nonexistent_command() {
        let (_client, _client_ep, server, _server_ep) = quic_pair().await;

        let res = timeout(
            std::time::Duration::from_secs(5),
            run_exec_command(
                &CancellationToken::new(),
                &server,
                "nonexistent-binary-xyz-12345",
            ),
        )
        .await
        .expect("timed out");
        assert!(res.is_err(), "expected error for nonexistent command");
    }

    #[tokio::test]
    async fn run_exec_command_context_cancellation() {
        let (_client, _client_ep, server, _server_ep) = quic_pair().await;

        let cancel = CancellationToken::new();
        let cancel2 = cancel.clone();
        tokio::spawn(async move {
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            cancel2.cancel();
        });

        let res = timeout(
            std::time::Duration::from_secs(5),
            run_exec_command(&cancel, &server, "sleep 60"),
        )
        .await
        .expect("timed out");
        assert!(res.is_err(), "expected error after context cancellation");
        assert!(matches!(res.unwrap_err(), ExecError::Killed));
    }

    #[tokio::test]
    async fn run_exec_command_stderr_not_on_stream() {
        let (client, _client_ep, server, _server_ep) = quic_pair().await;

        let exec_task = tokio::spawn(async move {
            run_exec_command(
                &CancellationToken::new(),
                &server,
                "sh -c 'echo stdout-msg; echo stderr-msg >&2'",
            )
            .await
        });

        let out = accept_and_read(&client).await;
        let _ = exec_task.await.unwrap();
        let s = String::from_utf8_lossy(&out);
        assert!(
            s.contains("stdout-msg"),
            "expected stdout output, got {s:?}"
        );
        assert!(
            !s.contains("stderr-msg"),
            "stderr should not appear on stream"
        );
    }

    /// Regression test (quinn lazy stream header): a command that reads
    /// stdin before writing stdout (`cat`) used to deadlock - quinn does
    /// not send the stream header until the first write, so the client's
    /// `accept_bi` never completed while the host waited for the command's
    /// first output. `announce_stream` forces the header (a 0-byte STREAM
    /// frame) right after `open_bi`, so a quinn peer accepts the stream.
    ///
    /// Note: the previous claim that this "matches Go
    /// quic-go, which announces streams on open" was wrong - quic-go does
    /// **not** announce a locally-opened stream until data or FIN is sent,
    /// and a 0-byte write is a no-op against it. This test therefore covers
    /// only the quinn↔quinn path; Rust→Go silent exec still needs the joint
    /// protocol decision.
    #[tokio::test]
    async fn run_exec_command_read_first_command() {
        let (client, _client_ep, server, _server_ep) = quic_pair().await;
        // Keep a second handle alive past `run_exec_command`'s return: the
        // last quinn handle drop sends an implicit CONNECTION_CLOSE that
        // would otherwise discard the echo still in the send buffer.
        let server_keepalive = server.clone();

        let exec_task = tokio::spawn(async move {
            run_exec_command(&CancellationToken::new(), &server, "cat").await
        });

        // Accepting the stream must complete even though the host has not
        // written anything yet (`cat` only writes after it reads).
        let (mut send, mut recv) = timeout(std::time::Duration::from_secs(5), client.accept_bi())
            .await
            .expect("accept_bi timed out: stream not announced before first write")
            .expect("accept_bi failed");

        send.write_all(b"ping-cat").await.expect("write failed");
        send.finish().expect("finish failed");

        let out = recv
            .read_to_end(u32::MAX as usize)
            .await
            .expect("read_to_end failed");
        assert_eq!(out, b"ping-cat");

        drop(server_keepalive);
        let res = exec_task.await.unwrap();
        // The stdin half-close no longer cancels the exec
        // context, so `cat` sees EOF on stdin and exits cleanly (exit 0).
        assert!(res.is_ok(), "expected clean exit, got {res:?}");
    }

    /// Regression test: a client that half-closes stdin
    /// immediately (`qvole exec < /dev/null`) must not SIGKILL a still-running
    /// child; the child's real exit code must survive.
    #[tokio::test]
    async fn run_exec_command_stdin_eof_preserves_exit_code() {
        let (client, _client_ep, server, _server_ep) = quic_pair().await;
        let server_keepalive = server.clone();

        let exec_task = tokio::spawn(async move {
            run_exec_command(
                &CancellationToken::new(),
                &server,
                "sh -c 'echo ready; sleep 1; exit 3'",
            )
            .await
        });

        let (mut send, mut recv) = timeout(std::time::Duration::from_secs(5), client.accept_bi())
            .await
            .expect("accept_bi timed out")
            .expect("accept_bi failed");
        // Empty stdin: FIN immediately, as `</dev/null` does.
        send.finish().expect("finish failed");

        let out = recv
            .read_to_end(u32::MAX as usize)
            .await
            .expect("read_to_end failed");
        assert!(
            String::from_utf8_lossy(&out).contains("ready"),
            "expected the child's early output, got {out:?}"
        );

        drop(server_keepalive);
        let res = exec_task.await.unwrap();
        match res {
            Err(ExecError::Exit(3)) => {}
            other => panic!("expected Exit(3) (not 0/Killed), got {other:?}"),
        }
    }

    #[tokio::test]
    async fn run_exec_command_empty_command() {
        let (client, _client_ep, server, _server_ep) = quic_pair().await;

        // The main task must keep the client connection alive for the whole
        // test: dropping the last quinn `Connection` handle sends an implicit
        // CONNECTION_CLOSE(0, "") that would break the server's accept.
        let client_clone = client.clone();
        let cancel = CancellationToken::new();
        let exec_task =
            tokio::spawn(async move { run_exec_command(&cancel, &client_clone, "").await });

        // Accept (and close) the stream on the server side, like Go.
        let (mut send, _recv) = server.accept_bi().await.expect("accept failed");
        let _ = send.finish();

        let res = timeout(std::time::Duration::from_secs(3), exec_task)
            .await
            .expect("timed out")
            .unwrap();
        match res {
            Err(ExecError::Other(msg)) => {
                assert!(msg.contains("empty command"), "unexpected error: {msg}")
            }
            other => panic!("expected 'empty command' error, got {other:?}"),
        }
    }
}
