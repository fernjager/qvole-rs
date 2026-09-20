//! `qvole` command-line binary.
//!
//! Port of `cmd/qvole/main.go` + `cmd/qvole/signal_unix.go` (Go reference
//! commit `8f8ee569bbfc8ab4575ebd7094cf02fe492412e0`).
//!
//! ## Fidelity notes
//!
//! * Flag parsing reproduces Go's `flag` package semantics - including its
//!   exact error strings, the `-h`/`-help` special case, and the `--`
//!   terminator - with a small hand-rolled parser instead of `clap`, so help
//!   output, flag errors, and exit codes are byte-identical to the Go binary
//!   (verified against the Go binary).
//! * The usage text is a verbatim port of `printUsage`.
//! * Go's `main` sets `QUIC_GO_DISABLE_RECEIVE_BUFFER_WARNING=1`; quinn has
//!   no receive-buffer warning, so nothing equivalent is set.

#![forbid(unsafe_code)]

use std::time::Duration;

use qvole_app::StdinReader;
use qvole_app::exec::{ExecError, run_exec as run_exec_app};
use qvole_app::pipe::{PipeError, run_pipe as run_pipe_app};
use qvole_app::tunnel::{TunnelError, run_tunnel as run_tunnel_app};
use qvole_app::tunnel_allow::TunnelAllow;
use qvole_app::tunnel_request::parse_tunnel_request;
use qvole_protocol::logger::{LOG_EXEC, LOG_PIPE, LOG_RELAY, LOG_TUNNEL, set_debug};
use qvole_protocol::resolver::split_host_port as split_host_port_go;
use qvole_protocol::transport::PROTOCOL_VERSION;
use tokio_util::sync::CancellationToken;

/// Go `version` variable (the release this port mirrors for CLI parity).
///
/// Release builds override it with `QVOLE_VERSION` (the pushed tag, with its
/// leading `v` stripped), so a released binary always reports the tag it was
/// built from. Ordinary builds and tests use the committed fallback.
const VERSION: &str = match option_env!("QVOLE_VERSION") {
    Some(v) => v,
    None => "0.2.3",
};
/// Go `defaultRelayAddr`.
const DEFAULT_RELAY_ADDR: &str = "relay.qvole.dev:9009";
/// Go `defaultListenAddr`.
const DEFAULT_LISTEN_ADDR: &str = ":9009";
/// Go `qvole.MinCodeLen`.
const MIN_CODE_LEN: usize = 8;
/// Go `qvole.MaxCodeLen`.
const MAX_CODE_LEN: usize = 256;
/// Go `maxTunnelSpecs` (mirrors `maxTunnelRequests`).
const MAX_TUNNEL_SPECS: usize = 100;
/// Go `exitCodeInterrupt` (128+SIGINT).
const EXIT_CODE_INTERRUPT: i32 = 130;

/// Verbatim port of `printUsage` (version interpolated).
fn usage_text() -> String {
    format!(
        r##"qvole {version}: Fast tunnels over QUIC, burrowed through NATs.

Commands:

  pipe [--stats]                  Bidirectional stream between two peers over QUIC

  tunnel                          TCP port tunneling over P2P QUIC
    -L [laddr:]lport:raddr:rport    ...listen on local port, forward to remote addr:port (peer allows with -aF)
    -R [raddr:]rport:laddr:lport    ...listen on remote port, forward to local addr:port (peer allows with -aL)
    -aL addr:port                   ...allow peer to open a listening port on this addr (allow peer's -R)
    -aF addr:port                   ...allow peer to connect to the addr:port thru you (allow peer's -L)
    -a                              ...allow ALL peer tunnel requests (not safe)

  exec                            Execute a command or connect to an exec peer
    --cmd                           ...run command, pipe stdin/stdout to peer

  relay                           Relay server (UDP)
    --listen <addr>                ...listen address (default :9009)

Common Flags (pipe / exec / tunnel):
  --code CODE                     connection code (or $QVOLE_CODE environment var)
  [--relay addr]                  relay server address (host:port)
  [--debug]                       verbose debug logging to stderr
  [--stats]                       log TX/RX throughput to stderr every 2 s (pipe-only)

Examples:

  # Send a file
  alice$ qvole pipe < in                                          # prints connection code, waits for bob
  bob$   QVOLE_CODE=CODE qvole pipe > out                         # bob connects, receiving file from alice

  # Send a directory
  alice$ tar czf - dir/ | qvole pipe                              # alice streams tar of dir/ to bob
  bob$   QVOLE_CODE=CODE qvole pipe | tar xzf -                   # bob receives and extracts

  # Port Forwarding
  alice$ qvole tunnel -L 8080:localhost:80 -R 2222:localhost:22   # alice configures port forwarding requests
  bob$   QVOLE_CODE=CODE qvole tunnel \
           -aL 127.0.0.1:2222 -aF localhost:80                    # bob allowlists what alice may reach
  alice$ curl localhost:8080                                      # alice can now reach bob's :80
  bob$   ssh -p 2222 localhost                                    # bob can now reach alice's sshd

  # Remote command (alice hosts the command, bob connects)
  alice$ qvole exec --cmd "uptime"                                # command runs on alice, bob sees output
  alice$ qvole exec --cmd "script -q bash /dev/null"              # alice gives bob remote shell
  bob$   QVOLE_CODE=CODE qvole exec

"##,
        version = VERSION
    )
}

fn print_usage() {
    eprint!("{}", usage_text());
}

// ---------------------------------------------------------------------------
// Flag parsing (Go `flag` package semantics)
// ---------------------------------------------------------------------------

/// The kinds of flag values qvole uses (Go `flag` String/Bool/Var-stringSlice).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum FlagType {
    Bool,
    String,
    /// Repeatable string (Go `stringSlice`); `flag.Value.Type()` is unknown,
    /// so Go's usage prints `value` as the type name.
    Slice,
}

/// One flag definition (Go `fs.String/Bool/Var` registration).
#[derive(Debug)]
struct FlagSpec {
    name: &'static str,
    ty: FlagType,
    /// Non-empty default for string flags (shown as `(default "...")`).
    default: Option<&'static str>,
    usage: &'static str,
}

const SPECS_RELAY_FLAG: &FlagSpec = &FlagSpec {
    name: "relay",
    ty: FlagType::String,
    default: None,
    usage: "Relay address (host:port)",
};
const SPECS_DEBUG_FLAG: &FlagSpec = &FlagSpec {
    name: "debug",
    ty: FlagType::Bool,
    default: None,
    usage: "Verbose debug logging to stderr",
};
const SPECS_CODE_FLAG: &FlagSpec = &FlagSpec {
    name: "code",
    ty: FlagType::String,
    default: None,
    usage: "Connection code (or $QVOLE_CODE)",
};
const SPECS_LISTEN_FLAG: &FlagSpec = &FlagSpec {
    name: "listen",
    ty: FlagType::String,
    default: Some(DEFAULT_LISTEN_ADDR),
    usage: "UDP listen address (host:port)",
};
const SPECS_STATS_FLAG: &FlagSpec = &FlagSpec {
    name: "stats",
    ty: FlagType::Bool,
    default: None,
    usage: "Log transfer statistics to stderr",
};
const SPECS_CMD_FLAG: &FlagSpec = &FlagSpec {
    name: "cmd",
    ty: FlagType::String,
    default: None,
    usage: "Run command",
};
const SPECS_A_FLAG: &FlagSpec = &FlagSpec {
    name: "a",
    ty: FlagType::Bool,
    default: None,
    usage: "Allow ALL peer tunnel requests (not safe)",
};
const SPECS_L_FLAG: &FlagSpec = &FlagSpec {
    name: "L",
    ty: FlagType::Slice,
    default: None,
    usage: "Local tunnel request ([laddr:]lport:raddr:rport)",
};
const SPECS_R_FLAG: &FlagSpec = &FlagSpec {
    name: "R",
    ty: FlagType::Slice,
    default: None,
    usage: "Remote tunnel request ([raddr:]rport:laddr:lport)",
};
const SPECS_AL_FLAG: &FlagSpec = &FlagSpec {
    name: "aL",
    ty: FlagType::Slice,
    default: None,
    usage: "Allow peer to open a listening port on this addr (allow peer's -R; repeatable)",
};
const SPECS_AF_FLAG: &FlagSpec = &FlagSpec {
    name: "aF",
    ty: FlagType::Slice,
    default: None,
    usage: "Allow peer to connect to the addr:port thru you (allow peer's -L; repeatable)",
};

/// Parsed flag values.
#[derive(Debug, Default)]
struct FlagValues {
    bools: std::collections::HashMap<String, bool>,
    strings: std::collections::HashMap<String, String>,
    slices: std::collections::HashMap<String, Vec<String>>,
}

impl FlagValues {
    fn bool(&self, name: &str) -> bool {
        self.bools.get(name).copied().unwrap_or(false)
    }

    fn string(&self, name: &str) -> String {
        self.strings.get(name).cloned().unwrap_or_default()
    }

    fn slice(&self, name: &str) -> Vec<String> {
        self.slices.get(name).cloned().unwrap_or_default()
    }
}

/// Errors from [`parse_flags`].
#[derive(Debug, PartialEq)]
enum FlagsError {
    /// Go: undefined `-h`/`-help` → `f.usage()` + `ErrHelp`
    /// (`"flag: help requested"`).
    Help,
    /// Any `failf` message (already formatted Go-style).
    Message(String),
}

/// Go `strconv.ParseBool` accepted values and error text.
fn parse_bool_value(s: &str) -> Result<bool, String> {
    match s {
        "1" | "t" | "T" | "true" | "TRUE" | "True" => Ok(true),
        "0" | "f" | "F" | "false" | "FALSE" | "False" => Ok(false),
        _ => Err(format!("strconv.ParseBool: parsing {s:?}: invalid syntax")),
    }
}

/// Parses `args` against `specs` with Go `flag.FlagSet.Parse` semantics:
/// `-flag`/`--flag`, `-flag=value`, repeatable slice flags, `--` terminator,
/// and stop-at-first-positional. Error strings match Go exactly.
fn parse_flags(args: &[String], specs: &[&FlagSpec]) -> Result<FlagValues, FlagsError> {
    let mut values = FlagValues::default();
    let mut rest = args;
    while let Some(s) = rest.first() {
        if s.len() < 2 || !s.starts_with('-') {
            break; // not a flag
        }
        let mut num_minuses = 1;
        if s.as_bytes()[1] == b'-' {
            num_minuses = 2;
            if s.len() == 2 {
                break; // "--" terminates the flags
            }
        }
        let name = &s[num_minuses..];
        if name.is_empty() || name.starts_with('-') || name.starts_with('=') {
            return Err(FlagsError::Message(format!("bad flag syntax: {s}")));
        }

        // Split off an inline value at the first '='.
        let (flag_name, inline_value, has_value) = match name.find('=') {
            Some(i) => (&name[..i], name[i + 1..].to_string(), true),
            None => (name, String::new(), false),
        };

        match specs.iter().find(|f| f.name == flag_name) {
            None => {
                // Go special case: undefined -h/-help prints usage + ErrHelp.
                if flag_name == "help" || flag_name == "h" {
                    return Err(FlagsError::Help);
                }
                return Err(FlagsError::Message(format!(
                    "flag provided but not defined: -{flag_name}"
                )));
            }
            Some(spec) => {
                if spec.ty == FlagType::Bool {
                    let v = if has_value {
                        parse_bool_value(&inline_value).map_err(|e| {
                            // Go: `invalid boolean value %q for -%s: %v`
                            FlagsError::Message(format!(
                                "invalid boolean value {inline_value:?} for -{}: {e}",
                                spec.name
                            ))
                        })?
                    } else {
                        true
                    };
                    values.bools.insert(spec.name.to_string(), v);
                } else {
                    let v = if has_value {
                        inline_value
                    } else {
                        match rest.get(1) {
                            Some(v) => {
                                rest = &rest[1..];
                                v.clone()
                            }
                            None => {
                                return Err(FlagsError::Message(format!(
                                    "flag needs an argument: -{}",
                                    spec.name
                                )));
                            }
                        }
                    };
                    match spec.ty {
                        FlagType::String => {
                            values.strings.insert(spec.name.to_string(), v);
                        }
                        FlagType::Slice => {
                            values
                                .slices
                                .entry(spec.name.to_string())
                                .or_default()
                                .push(v);
                        }
                        FlagType::Bool => unreachable!(),
                    }
                }
            }
        }
        rest = &rest[1..];
    }
    Ok(values)
}

/// Go `FlagSet.Usage` for a named set: `Usage of <name>:` + sorted
/// `PrintDefaults` (byte-identical to Go's output, tabs included).
fn flagset_usage(set_name: &str, specs: &[&FlagSpec]) -> String {
    let mut out = format!("Usage of {set_name}:\n");
    let mut sorted: Vec<&FlagSpec> = specs.to_vec();
    sorted.sort_by(|a, b| a.name.cmp(b.name));
    for f in sorted {
        let type_name = match f.ty {
            FlagType::Bool => "",
            FlagType::String => "string",
            FlagType::Slice => "value",
        };
        let mut line = format!("  -{}", f.name);
        if !type_name.is_empty() {
            line.push(' ');
            line.push_str(type_name);
        }
        if line.len() <= 4 {
            line.push('\t'); // one-letter bool: same line
        } else {
            line.push_str("\n    \t");
        }
        line.push_str(f.usage);
        if let Some(d) = f.default
            && !d.is_empty()
        {
            line.push_str(&format!(" (default \"{d}\")"));
        }
        line.push('\n');
        out.push_str(&line);
    }
    out
}

/// Prints the flag error exactly as Go `fatalf(logger, "flag: %v", err)`
/// does (including the extra `FlagSet.Usage` line for the -h/-help case).
fn report_flag_error(logger: &qvole_protocol::logger::Logger, set_name: &str, err: FlagsError) {
    match err {
        FlagsError::Help => {
            // The caller also prints this through the fatalf-style logger;
            // Go's usage() goes to stderr before ErrHelp is returned.
            eprint!("{}", flagset_usage(set_name, &flag_specs_for(set_name)));
            logger.printf_error("flag: flag: help requested");
        }
        FlagsError::Message(m) => {
            logger.printf_error(&format!("flag: {m}"));
        }
    }
}

/// The spec table per subcommand (must match the run_* flag tables).
fn flag_specs_for(set_name: &str) -> Vec<&'static FlagSpec> {
    match set_name {
        "relay" => vec![SPECS_LISTEN_FLAG, SPECS_DEBUG_FLAG],
        "qvole" => vec![
            SPECS_CODE_FLAG,
            SPECS_RELAY_FLAG,
            SPECS_DEBUG_FLAG,
            SPECS_STATS_FLAG,
        ],
        "exec" => vec![
            SPECS_CODE_FLAG,
            SPECS_RELAY_FLAG,
            SPECS_DEBUG_FLAG,
            SPECS_CMD_FLAG,
        ],
        "tunnel" => vec![
            SPECS_CODE_FLAG,
            SPECS_RELAY_FLAG,
            SPECS_DEBUG_FLAG,
            SPECS_A_FLAG,
            SPECS_L_FLAG,
            SPECS_R_FLAG,
            SPECS_AL_FLAG,
            SPECS_AF_FLAG,
        ],
        _ => Vec::new(),
    }
}

// ---------------------------------------------------------------------------
// Code resolution and tunnel pre-validation (Go main.go helpers)
// ---------------------------------------------------------------------------

/// Go `resolveCode`: flag, then `$QVOLE_CODE`, then length checks.
fn resolve_code_from(flag_val: &str, env_val: Option<&str>) -> Result<String, String> {
    let val = if flag_val.is_empty() {
        env_val.unwrap_or_default().to_string()
    } else {
        flag_val.to_string()
    };
    if val.is_empty() {
        return Ok(String::new());
    }
    if val.len() < MIN_CODE_LEN {
        return Err(format!(
            "code is too short ({} chars); minimum is {MIN_CODE_LEN}",
            val.len()
        ));
    }
    if val.len() > MAX_CODE_LEN {
        return Err(format!(
            "code exceeds maximum length of {MAX_CODE_LEN} characters"
        ));
    }
    Ok(val)
}

/// Go `resolveOrGenerateCode`: resolve or generate a fresh code.
fn resolve_or_generate_code_from(
    flag_val: &str,
    env_val: Option<&str>,
) -> Result<(String, bool), String> {
    match resolve_code_from(flag_val, env_val) {
        Err(e) => Err(e),
        Ok(code) if !code.is_empty() => Ok((code, false)),
        Ok(_) => {
            let code =
                qvole_spake2::code::generate_code().map_err(|e| format!("generate code: {e}"))?;
            Ok((code, true))
        }
    }
}

fn resolve_or_generate_code(flag_val: &str) -> Result<(String, bool), String> {
    resolve_or_generate_code_from(flag_val, std::env::var("QVOLE_CODE").ok().as_deref())
}

/// Go `validateTunnelSpec`: parse + port checks for one -L/-R spec.
fn validate_tunnel_spec(spec: &str, typ: &str) -> Result<(), String> {
    let req = parse_tunnel_request(spec, typ)
        .map_err(|e| format!("invalid -{typ} spec {spec:?}: {e}"))?;
    for addr in [&req.listen_addr, &req.target_addr] {
        let (_host, port) =
            split_host_port_go(addr).map_err(|e| format!("invalid -{typ} spec {spec:?}: {e}"))?;
        match port.parse::<i32>() {
            Ok(p) if (1..=65535).contains(&p) => {}
            _ => {
                return Err(format!(
                    "invalid -{typ} spec {spec:?}: invalid port {port:?}"
                ));
            }
        }
    }
    Ok(())
}

/// Go `validateTunnelConfig`: up-front validation of all specs + allowlists.
fn validate_tunnel_config(
    local_tunnels: &[String],
    remote_tunnels: &[String],
    allow_listen: &[String],
    allow_forward: &[String],
    allow_all: bool,
) -> Result<(), String> {
    let n = local_tunnels.len() + remote_tunnels.len();
    if n > MAX_TUNNEL_SPECS {
        return Err(format!(
            "too many tunnel requests: {n} (max {MAX_TUNNEL_SPECS})"
        ));
    }
    for f in local_tunnels {
        validate_tunnel_spec(f, "L")?;
    }
    for f in remote_tunnels {
        validate_tunnel_spec(f, "R")?;
    }
    let mut allow = TunnelAllow::default();
    allow.all = allow_all;
    allow.listen = allow_listen.to_vec();
    allow.forward = allow_forward.to_vec();
    allow.validate()
}

/// Go `tunnelPeerCommand`: builds the peer's ready-to-paste tunnel command.
fn tunnel_peer_command(
    code: &str,
    local_tunnels: &[String],
    remote_tunnels: &[String],
) -> Result<String, String> {
    let mut seen_listen: std::collections::HashSet<String> = std::collections::HashSet::new();
    let mut seen_forward: std::collections::HashSet<String> = std::collections::HashSet::new();
    let mut a_l: Vec<String> = Vec::new();
    let mut a_f: Vec<String> = Vec::new();
    for spec in remote_tunnels {
        let req = parse_tunnel_request(spec, "R")?;
        if seen_listen.insert(req.listen_addr.clone()) {
            a_l.push(req.listen_addr);
        }
    }
    for spec in local_tunnels {
        let req = parse_tunnel_request(spec, "L")?;
        if seen_forward.insert(req.target_addr.clone()) {
            a_f.push(req.target_addr);
        }
    }
    if a_l.is_empty() && a_f.is_empty() {
        return Ok(String::new());
    }
    let mut cmd = format!("QVOLE_CODE={code} qvole tunnel");
    for v in &a_l {
        cmd.push_str(&format!(" -aL {v}"));
    }
    for v in &a_f {
        cmd.push_str(&format!(" -aF {v}"));
    }
    Ok(cmd)
}

/// Go `peerHintBlock`.
fn peer_hint_block(peer_cmd: &str) -> String {
    format!("# peer command\n{peer_cmd}\n")
}

/// Go `isTerminal(os.Stdin)`: stat fd 0, true for character devices
/// (includes /dev/null, not just TTYs - matches Go's `ModeCharDevice`).
#[cfg(unix)]
fn stdin_char_device() -> bool {
    use std::os::unix::fs::FileTypeExt;
    std::fs::metadata("/dev/stdin")
        .ok()
        .map(|m| m.file_type().is_char_device())
        .unwrap_or(false)
}

#[cfg(not(unix))]
fn stdin_char_device() -> bool {
    false
}

// ---------------------------------------------------------------------------
// Subcommands
// ---------------------------------------------------------------------------

fn resolve_relay(relay_addr: &str) -> String {
    if relay_addr.is_empty() {
        DEFAULT_RELAY_ADDR.to_string()
    } else {
        relay_addr.to_string()
    }
}

/// Go `signalContext`: SIGINT/SIGTERM cancel the token (first signal wins;
/// later signals are swallowed like Go's `signal.NotifyContext`).
fn spawn_signal_cancel(cancel: CancellationToken) {
    tokio::spawn(async move {
        use tokio::signal::unix::{SignalKind, signal};
        let mut sigint = signal(SignalKind::interrupt()).expect("SIGINT handler");
        let mut sigterm = signal(SignalKind::terminate()).expect("SIGTERM handler");
        tokio::select! {
            _ = sigint.recv() => {}
            _ = sigterm.recv() => {}
        }
        cancel.cancel();
    });
}

fn run_relay(args: &[String]) -> i32 {
    let specs = flag_specs_for("relay");
    let values = match parse_flags(args, &specs) {
        Err(e) => {
            report_flag_error(&LOG_RELAY, "relay", e);
            return 1;
        }
        Ok(v) => v,
    };
    set_debug(values.bool("debug"));
    let listen = values.string("listen");
    let listen = if listen.is_empty() {
        DEFAULT_LISTEN_ADDR.to_string()
    } else {
        listen
    };

    let cancel = CancellationToken::new();
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("tokio runtime");
    let result = runtime.block_on(async move {
        spawn_signal_cancel(cancel.clone());
        let relay = std::sync::Arc::new(qvole_relay::Relay::with_config(
            qvole_relay::Config::from_env(),
        ));
        relay.run(&listen, cancel).await
    });
    // Go's os.Exit abandons parked goroutines (e.g. a blocking stdin or
    // stdout read dispatched via spawn_blocking, which the runtime drain
    // would wait on forever while stdin is held open). A background
    // shutdown has the same effect: the drain proceeds on a daemon
    // thread and the process exits as soon as main returns.
    runtime.shutdown_background();
    match result {
        Ok(()) => 0,
        Err(e) => {
            LOG_RELAY.printf_error(&e.to_string());
            1
        }
    }
}

fn run_pipe(args: &[String]) -> i32 {
    let specs = flag_specs_for("qvole");
    let values = match parse_flags(args, &specs) {
        Err(e) => {
            report_flag_error(&LOG_PIPE, "qvole", e);
            return 1;
        }
        Ok(v) => v,
    };
    set_debug(values.bool("debug"));
    let relay_addr = resolve_relay(&values.string("relay"));
    let stats = values.bool("stats");

    let (final_code, generated) = match resolve_or_generate_code(&values.string("code")) {
        Err(e) => {
            LOG_PIPE.printf_error(&e);
            return 1;
        }
        Ok(v) => v,
    };
    if generated {
        eprint!(
            "{}",
            peer_hint_block(&format!("QVOLE_CODE={final_code} qvole pipe"))
        );
    }

    let cancel = CancellationToken::new();
    let stdin_term = stdin_char_device();
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("tokio runtime");
    let result = runtime.block_on(async move {
        spawn_signal_cancel(cancel.clone());
        run_pipe_app(
            &cancel,
            &relay_addr,
            &final_code,
            &qvole_protocol::exchange::PeerConfig::default(),
            stats,
            stdin_term,
            StdinReader::new(),
            tokio::io::stdout(),
        )
        .await
    });
    // Go's os.Exit abandons parked goroutines (e.g. a blocking stdin or
    // stdout read dispatched via spawn_blocking, which the runtime drain
    // would wait on forever while stdin is held open). A background
    // shutdown has the same effect: the drain proceeds on a daemon
    // thread and the process exits as soon as main returns.
    runtime.shutdown_background();
    match result {
        Ok(()) => 0,
        Err(PipeError::Canceled) => 0,
        Err(e) => {
            LOG_PIPE.printf_error(&e.to_string());
            1
        }
    }
}

fn run_exec(args: &[String]) -> i32 {
    let specs = flag_specs_for("exec");
    let values = match parse_flags(args, &specs) {
        Err(e) => {
            report_flag_error(&LOG_EXEC, "exec", e);
            return 1;
        }
        Ok(v) => v,
    };
    set_debug(values.bool("debug"));
    let relay_addr = resolve_relay(&values.string("relay"));
    let cmd = values.string("cmd");

    let (final_code, generated) = match resolve_or_generate_code(&values.string("code")) {
        Err(e) => {
            LOG_EXEC.printf_error(&e);
            return 1;
        }
        Ok(v) => v,
    };
    if generated {
        eprint!(
            "{}",
            peer_hint_block(&format!("QVOLE_CODE={final_code} qvole exec"))
        );
    }

    let cancel = CancellationToken::new();
    let cancel_check = cancel.clone();
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("tokio runtime");
    let result = runtime.block_on(async move {
        spawn_signal_cancel(cancel.clone());
        // Command mode pipes the PEER's stdin to the child, not the local
        // terminal's; local stdin/stdout are used only in pipe mode
        // (Go: RunPipeMode/StartStdinPipe). `close_stdin` is a no-op:
        // Go's os.Stdin.Close() unblocks the reader goroutine, while our
        // stop-token unblocks the copy and the process exit abandons the
        // reader thread (see `StdinReader`).
        run_exec_app(
            &cancel,
            &relay_addr,
            &final_code,
            &qvole_protocol::exchange::PeerConfig::default(),
            &cmd,
            !cmd.is_empty(),
            StdinReader::new(),
            tokio::io::stdout(),
            || {},
        )
        .await
    });
    // Go's os.Exit abandons parked goroutines (e.g. a blocking stdin or
    // stdout read dispatched via spawn_blocking, which the runtime drain
    // would wait on forever while stdin is held open). A background
    // shutdown has the same effect: the drain proceeds on a daemon
    // thread and the process exits as soon as main returns.
    runtime.shutdown_background();
    match result {
        Ok(()) => 0,
        Err(ExecError::Canceled) => 0,
        // Go `childExitStatus`: a child exit code >= 0 propagates verbatim
        // (0 exits 0).
        Err(ExecError::Exit(code)) if code >= 0 => code,
        // Go `childExitStatus`: signal-killed child → 130 when locally
        // interrupted (SIGINT), 0 when the peer ended the run.
        Err(ExecError::Killed) => {
            if cancel_check.is_cancelled() {
                EXIT_CODE_INTERRUPT
            } else {
                0
            }
        }
        Err(e) => {
            LOG_EXEC.printf_error(&e.to_string());
            1
        }
    }
}

fn run_tunnel(args: &[String]) -> i32 {
    let specs = flag_specs_for("tunnel");
    let values = match parse_flags(args, &specs) {
        Err(e) => {
            report_flag_error(&LOG_TUNNEL, "tunnel", e);
            return 1;
        }
        Ok(v) => v,
    };
    set_debug(values.bool("debug"));
    let relay_addr = resolve_relay(&values.string("relay"));
    let allow_all = values.bool("a");
    let local_tunnels = values.slice("L");
    let remote_tunnels = values.slice("R");
    let allow_listen = values.slice("aL");
    let allow_forward = values.slice("aF");

    // Fail fast on bad specs before printing a connection code (Go).
    if let Err(e) = validate_tunnel_config(
        &local_tunnels,
        &remote_tunnels,
        &allow_listen,
        &allow_forward,
        allow_all,
    ) {
        LOG_TUNNEL.printf_error(&e);
        return 1;
    }

    let (final_code, generated) = match resolve_or_generate_code(&values.string("code")) {
        Err(e) => {
            LOG_TUNNEL.printf_error(&e);
            return 1;
        }
        Ok(v) => v,
    };
    if generated {
        match tunnel_peer_command(&final_code, &local_tunnels, &remote_tunnels) {
            Err(herr) => {
                // Specs were validated above, so this should not happen; keep
                // the hint failure visible rather than silently dropping it.
                eprintln!("peer hint unavailable: {herr}");
            }
            Ok(hint) => {
                let hint = if hint.is_empty() {
                    format!("QVOLE_CODE={final_code} qvole tunnel")
                } else {
                    hint
                };
                eprint!("{}", peer_hint_block(&hint));
            }
        }
    }

    let cancel = CancellationToken::new();
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("tokio runtime");
    let result = runtime.block_on(async move {
        spawn_signal_cancel(cancel.clone());
        let res = run_tunnel_app(
            &cancel,
            &relay_addr,
            &final_code,
            &local_tunnels,
            &remote_tunnels,
            allow_all,
            &allow_listen,
            &allow_forward,
            0,
            Duration::ZERO,
        )
        .await;
        // `run_tunnel_app` drops its `ConnCloser` on return, which
        // schedules CONNECTION_CLOSE (Go: deferred
        // `conn.CloseWithError(0, "done")`). Yield so the woken
        // driver can send the frame before the process exits.
        qvole_app::copy::flush_close().await;
        res
    });
    // Go's os.Exit abandons parked goroutines (e.g. a blocking stdin or
    // stdout read dispatched via spawn_blocking, which the runtime drain
    // would wait on forever while stdin is held open). A background
    // shutdown has the same effect: the drain proceeds on a daemon
    // thread and the process exits as soon as main returns.
    runtime.shutdown_background();
    match result {
        Ok(()) => 0,
        Err(TunnelError::Canceled) => 0,
        Err(e) => {
            LOG_TUNNEL.printf_error(&e.to_string());
            1
        }
    }
}

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let code = match args.as_slice() {
        [] => {
            print_usage();
            0
        }
        // -v/--version is only honored in the subcommand position; later
        // occurrences may be flag values (e.g. exec --cmd -v).
        [first, ..] if first == "-v" || first == "--version" => {
            eprintln!("qvole {VERSION} (protocol v{PROTOCOL_VERSION}, rust port)");
            0
        }
        _ => match args[0].as_str() {
            "relay" => run_relay(&args[1..]),
            "exec" => run_exec(&args[1..]),
            "tunnel" => run_tunnel(&args[1..]),
            "pipe" => run_pipe(&args[1..]),
            "-h" | "--help" | "help" => {
                print_usage();
                0
            }
            _ => {
                print_usage();
                0
            }
        },
    };
    std::process::exit(code);
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn specs() -> Vec<&'static FlagSpec> {
        vec![
            SPECS_CODE_FLAG,
            SPECS_RELAY_FLAG,
            SPECS_DEBUG_FLAG,
            SPECS_STATS_FLAG,
        ]
    }

    fn args(s: &str) -> Vec<String> {
        s.split_whitespace().map(String::from).collect()
    }

    #[test]
    fn test_parse_basic_flags() {
        let v = parse_flags(&args("--code abc --debug -stats"), &specs()).unwrap();
        assert_eq!(v.string("code"), "abc");
        assert!(v.bool("debug"));
        assert!(v.bool("stats"));
    }

    #[test]
    fn test_parse_equals_forms() {
        let v = parse_flags(&args("-code=abc --debug=true -stats=false"), &specs()).unwrap();
        assert_eq!(v.string("code"), "abc");
        assert!(v.bool("debug"));
        assert!(!v.bool("stats"));
    }

    #[test]
    fn test_parse_double_dash_terminates() {
        let v = parse_flags(&args("--debug -- --code"), &specs()).unwrap();
        assert!(v.bool("debug"));
        assert_eq!(v.string("code"), ""); // "--code" after -- is positional, ignored
    }

    #[test]
    fn test_parse_stops_at_positional() {
        let v = parse_flags(&args("--debug extra --code"), &specs()).unwrap();
        assert!(v.bool("debug"));
        assert_eq!(v.string("code"), "");
    }

    #[test]
    fn test_parse_slice_flag() {
        let specs: Vec<&FlagSpec> = vec![SPECS_L_FLAG];
        let v = parse_flags(&args("-L a -L b --L=c"), &specs).unwrap();
        assert_eq!(v.slice("L"), vec!["a", "b", "c"]);
    }

    #[test]
    fn test_parse_unknown_flag() {
        let err = parse_flags(&args("--bogus"), &specs()).unwrap_err();
        assert_eq!(
            err,
            FlagsError::Message("flag provided but not defined: -bogus".into())
        );
    }

    #[test]
    fn test_parse_help_special_case() {
        assert_eq!(
            parse_flags(&args("-h"), &specs()).unwrap_err(),
            FlagsError::Help
        );
        assert_eq!(
            parse_flags(&args("--help"), &specs()).unwrap_err(),
            FlagsError::Help
        );
    }

    #[test]
    fn test_parse_bad_syntax() {
        // "-" alone is positional (parsing stops), not a syntax error.
        for s in ["---", "-=x"] {
            let err = parse_flags(&args(s), &specs()).unwrap_err();
            match err {
                FlagsError::Message(m) if m.contains("bad flag syntax") => {}
                other => panic!("expected bad flag syntax for {s:?}, got {other:?}"),
            }
        }
    }

    #[test]
    fn test_parse_missing_argument() {
        let err = parse_flags(&args("--code"), &specs()).unwrap_err();
        assert_eq!(
            err,
            FlagsError::Message("flag needs an argument: -code".into())
        );
    }

    #[test]
    fn test_parse_bad_bool_value() {
        let err = parse_flags(&args("--debug=maybe"), &specs()).unwrap_err();
        match err {
            FlagsError::Message(m) => {
                assert!(
                    m.contains("invalid boolean value \"maybe\" for -debug"),
                    "{m}"
                );
                assert!(m.contains("strconv.ParseBool"), "{m}");
            }
            other => panic!("expected message, got {other:?}"),
        }
    }

    #[test]
    fn test_flagset_usage_matches_go_relay() {
        let specs = flag_specs_for("relay");
        let got = flagset_usage("relay", &specs);
        let want = "Usage of relay:\n\
                    \x20\x20-debug\n\
                    \x20\x20\x20\x20\tVerbose debug logging to stderr\n\
                    \x20\x20-listen string\n\
                    \x20\x20\x20\x20\tUDP listen address (host:port) (default \":9009\")\n";
        assert_eq!(got, want);
    }

    #[test]
    fn test_flagset_usage_matches_go_tunnel() {
        let specs = flag_specs_for("tunnel");
        let got = flagset_usage("tunnel", &specs);
        let want = "Usage of tunnel:\n\
                    \x20\x20-L value\n\
                    \x20\x20\x20\x20\tLocal tunnel request ([laddr:]lport:raddr:rport)\n\
                    \x20\x20-R value\n\
                    \x20\x20\x20\x20\tRemote tunnel request ([raddr:]rport:laddr:lport)\n\
                    \x20\x20-a\tAllow ALL peer tunnel requests (not safe)\n\
                    \x20\x20-aF value\n\
                    \x20\x20\x20\x20\tAllow peer to connect to the addr:port thru you (allow peer's -L; repeatable)\n\
                    \x20\x20-aL value\n\
                    \x20\x20\x20\x20\tAllow peer to open a listening port on this addr (allow peer's -R; repeatable)\n\
                    \x20\x20-code string\n\
                    \x20\x20\x20\x20\tConnection code (or $QVOLE_CODE)\n\
                    \x20\x20-debug\n\
                    \x20\x20\x20\x20\tVerbose debug logging to stderr\n\
                    \x20\x20-relay string\n\
                    \x20\x20\x20\x20\tRelay address (host:port)\n";
        assert_eq!(got, want);
    }

    #[test]
    fn test_every_flag_appears_in_help() {
        // Assert each flag appears in the help output.
        let usage = usage_text();
        for flag in [
            "pipe", "tunnel", "exec", "relay", "-L ", "-R ", "-aL ", "-aF ", "-a ", "--cmd",
            "--listen", "--code", "--relay", "--debug", "--stats",
        ] {
            assert!(usage.contains(flag), "missing {flag:?} in help:\n{usage}");
        }
    }

    #[test]
    fn test_usage_matches_go_verbatim() {
        // Byte-compare against the Go `printUsage` output (qvole 0.2.3).
        let go_usage = include_str!("usage_go.txt");
        assert_eq!(usage_text(), go_usage);
    }

    #[test]
    fn test_resolve_code_env_fallback() {
        assert_eq!(resolve_code_from("", Some("abcdefgh")).unwrap(), "abcdefgh");
        assert_eq!(
            resolve_code_from("abcdefgh", Some("zz")).unwrap(),
            "abcdefgh"
        );
        assert_eq!(resolve_code_from("", None).unwrap(), "");
    }

    #[test]
    fn test_resolve_code_length_errors() {
        let err = resolve_code_from("abc", None).unwrap_err();
        assert_eq!(err, "code is too short (3 chars); minimum is 8");
        let long = "x".repeat(MAX_CODE_LEN + 1);
        let err = resolve_code_from(&long, None).unwrap_err();
        assert_eq!(
            err,
            format!("code exceeds maximum length of {MAX_CODE_LEN} characters")
        );
    }

    // Go TestResolveCode_BoundaryMin/BoundaryMax.
    #[test]
    fn test_resolve_code_boundaries() {
        let min = "x".repeat(MIN_CODE_LEN);
        assert_eq!(resolve_code_from(&min, None).unwrap(), min);
        let max = "x".repeat(MAX_CODE_LEN);
        assert_eq!(resolve_code_from(&max, None).unwrap(), max);
    }

    // Go TestStringSlice_Empty / TestStringSlice_Set / TestStringSlice_FlagValue.
    #[test]
    fn test_slice_flag_empty_default() {
        let v = parse_flags(&args(""), &specs()).unwrap();
        assert!(v.slice("L").is_empty());
    }

    // Go TestResolveRelay_Custom / TestResolveRelay_Default.
    #[test]
    fn test_resolve_relay() {
        assert_eq!(resolve_relay("1.2.3.4:9009"), "1.2.3.4:9009");
        assert_eq!(resolve_relay(""), DEFAULT_RELAY_ADDR);
    }

    // Go TestValidateTunnelConfig_Valid.
    #[test]
    fn test_validate_tunnel_config_valid() {
        let l = vec![
            "8080:localhost:80".to_string(),
            ":9090:127.0.0.1:9090".to_string(),
            "[::1]:8081:localhost:81".to_string(),
        ];
        let r = vec!["2222:localhost:22".to_string()];
        let al = vec!["127.0.0.1:2222".to_string()];
        let af = vec!["localhost:80".to_string()];
        assert!(validate_tunnel_config(&l, &r, &al, &af, false).is_ok());
    }

    // Go TestValidateTunnelConfig_InvalidPort.
    #[test]
    fn test_validate_tunnel_config_invalid_ports() {
        for spec in [
            "abc:host:80",
            "8080:host:xyz",
            "8080:host:99999",
            "0:host:80",
            "8080:host:0",
        ] {
            let l = vec![spec.to_string()];
            let r = vec![spec.to_string()];
            assert!(
                validate_tunnel_config(&l, &[], &[], &[], false).is_err(),
                "-L {spec}"
            );
            assert!(
                validate_tunnel_config(&[], &r, &[], &[], false).is_err(),
                "-R {spec}"
            );
        }
    }

    #[test]
    fn test_resolve_or_generate_code_format() {
        let (code, generated) = resolve_or_generate_code_from("", None).unwrap();
        assert!(generated);
        assert!(
            qvole_spake2::code::is_generated_code(&code),
            "generated code {code:?} should match ^\\d{{4}}-"
        );
        let (code, generated) = resolve_or_generate_code_from("abcdefgh", None).unwrap();
        assert!(!generated);
        assert_eq!(code, "abcdefgh");
    }

    #[test]
    fn test_validate_tunnel_spec_ok() {
        assert!(validate_tunnel_spec("8080:localhost:80", "L").is_ok());
        assert!(validate_tunnel_spec("127.0.0.1:2222:localhost:22", "R").is_ok());
    }

    #[test]
    fn test_validate_tunnel_spec_errors() {
        let err = validate_tunnel_spec("8080:localhost:80:1.2.3.4", "L").unwrap_err();
        assert!(err.contains("invalid -L spec"), "{err}");
        let err = validate_tunnel_spec("99999:localhost:80", "L").unwrap_err();
        assert!(err.contains("invalid port"), "{err}");
        let err = validate_tunnel_spec("localhost", "L").unwrap_err();
        assert!(err.contains("expected [laddr:]lport:raddr:rport"), "{err}");
    }

    #[test]
    fn test_validate_tunnel_config_too_many() {
        let mut l: Vec<String> = Vec::new();
        for i in 0..MAX_TUNNEL_SPECS + 1 {
            let port = i + 1000;
            l.push(format!("{port}:localhost:1"));
        }
        let err = validate_tunnel_config(&l, &[], &[], &[], false).unwrap_err();
        assert!(
            err == format!(
                "too many tunnel requests: {} (max {MAX_TUNNEL_SPECS})",
                l.len()
            ),
            "{err}"
        );
    }

    #[test]
    fn test_split_host_port_err_messages() {
        assert_eq!(
            // Go 1.27 AddrError format: `address <addr>: <why>`.
            split_host_port_go("localhost").unwrap_err(),
            "address localhost: missing port in address"
        );
        assert_eq!(
            split_host_port_go("a:b:c").unwrap_err(),
            "address a:b:c: too many colons in address"
        );
        assert_eq!(
            split_host_port_go("[::1").unwrap_err(),
            "address [::1: missing ']' in address"
        );
        let (h, p) = split_host_port_go("[::1]:80").unwrap();
        assert_eq!((h.as_str(), p.as_str()), ("::1", "80"));
        let (h, p) = split_host_port_go("127.0.0.1:8080").unwrap();
        assert_eq!((h.as_str(), p.as_str()), ("127.0.0.1", "8080"));
    }

    #[test]
    fn test_tunnel_peer_command() {
        let l = vec!["8080:localhost:80".to_string()];
        let r = vec!["127.0.0.1:2222:localhost:22".to_string()];
        let cmd = tunnel_peer_command("code1234", &l, &r).unwrap();
        assert_eq!(
            cmd,
            "QVOLE_CODE=code1234 qvole tunnel -aL 127.0.0.1:2222 -aF localhost:80"
        );
        assert_eq!(tunnel_peer_command("code1234", &[], &[]).unwrap(), "");
    }

    #[test]
    fn test_peer_hint_block() {
        assert_eq!(
            peer_hint_block("QVOLE_CODE=x qvole pipe"),
            "# peer command\nQVOLE_CODE=x qvole pipe\n"
        );
    }

    #[test]
    fn test_version_output() {
        // Go: `qvole %s (protocol v%s)`, plus a `, rust port` self-identifier.
        assert_eq!(
            format!("qvole {VERSION} (protocol v{PROTOCOL_VERSION}, rust port)"),
            "qvole 0.2.3 (protocol v0.1, rust port)"
        );
    }
}
