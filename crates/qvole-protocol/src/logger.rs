//! Port of `internal/util/logger.go`.
//!
//! Tagged, color-coded logger writing to stderr. Line format (colors on):
//! `DIM(ts) RESET "  " COLOR(tag) RESET "  " [COLOR(msg) RESET]` where the
//! tag is left-justified to [`PREFIX_WIDTH`] characters. Colors off
//! (NO_COLOR set): `ts "  " tag "  " msg`.
//!
//! The Go reference calls `log.SetFlags(0)` in `main`, so no extra
//! timestamp is prepended; this port writes the line directly.

use std::io::Write;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicBool, Ordering};

const PREFIX_WIDTH: usize = 10;

const ANSI_DIM: &str = "\u{1b}[2m";
const ANSI_BOLD: &str = "\u{1b}[1m";
const ANSI_RED: &str = "\u{1b}[31m";
const ANSI_GREEN: &str = "\u{1b}[32m";
const ANSI_YELLOW: &str = "\u{1b}[33m";
const ANSI_RESET: &str = "\u{1b}[0m";

static DISABLE_COLORS: OnceLock<bool> = OnceLock::new();
static DEBUG: AtomicBool = AtomicBool::new(false);

/// Port of the Go package-level `Debug` flag: controls whether `printf`-level
/// (plain) messages are shown. Error, warning, success, and info messages are
/// always shown. Set from the CLI flag in the binary (see `qvole-bin`).
pub fn set_debug(on: bool) {
    DEBUG.store(on, Ordering::SeqCst);
}

/// Whether `printf`-level messages are enabled.
pub fn debug_enabled() -> bool {
    DEBUG.load(Ordering::SeqCst)
}

fn colors_disabled() -> bool {
    *DISABLE_COLORS.get_or_init(|| matches!(std::env::var("NO_COLOR"), Ok(v) if !v.is_empty()))
}

/// Port of `util.Bold`: wraps `s` in ANSI bold unless NO_COLOR is set.
pub fn bold(s: &str) -> String {
    format_bold(s, colors_disabled())
}

fn format_bold(s: &str, no_color: bool) -> String {
    if no_color {
        s.to_string()
    } else {
        format!("{ANSI_BOLD}{s}{ANSI_RESET}")
    }
}

/// Local wall-clock timestamp formatted like Go's
/// `time.Now().Format("2006-01-02 15:04:05")`.
fn local_timestamp() -> String {
    const FMT: &str = "[year]-[month]-[day] [hour]:[minute]:[second]";
    let fmt = time::format_description::parse_borrowed::<3>(FMT).expect("static format parses");
    match time::OffsetDateTime::now_local() {
        Ok(dt) => dt.format(&fmt).unwrap_or_default(),
        Err(_) => String::new(),
    }
}

/// A tagged, color-coded logger (port of `util.Logger`).
#[derive(Debug)]
pub struct Logger {
    prefix: &'static str,
    color: &'static str,
}

impl Logger {
    const fn new(prefix: &'static str, color: &'static str) -> Self {
        Self { prefix, color }
    }

    /// Port of `Logger.logf`.
    fn logf(&self, msg_color: &str, msg: &str) -> String {
        format_line(
            self.prefix,
            self.color,
            msg_color,
            msg,
            &local_timestamp(),
            colors_disabled(),
        )
    }

    fn emit(&self, line: String) {
        let mut err = std::io::stderr();
        let _ = writeln!(err, "{line}");
        let _ = err.flush();
    }

    /// Port of `Logger.Printf`: plain message, shown only when debug is on.
    pub fn printf(&self, msg: &str) {
        if debug_enabled() {
            self.emit(self.logf("", msg));
        }
    }

    /// Port of `Logger.PrintfInfo`.
    pub fn printf_info(&self, msg: &str) {
        self.emit(self.logf("", msg));
    }

    /// Port of `Logger.PrintfError`.
    pub fn printf_error(&self, msg: &str) {
        self.emit(self.logf(ANSI_RED, msg));
    }

    /// Port of `Logger.PrintfWarn`.
    pub fn printf_warn(&self, msg: &str) {
        self.emit(self.logf(ANSI_YELLOW, msg));
    }

    /// Port of `Logger.PrintfSuccess`.
    pub fn printf_success(&self, msg: &str) {
        self.emit(self.logf(ANSI_GREEN, msg));
    }
}

/// Port of the Go `logf` formatting, factored out for testing without
/// depending on the process-global NO_COLOR state.
fn format_line(
    prefix: &str,
    color: &str,
    msg_color: &str,
    msg: &str,
    ts: &str,
    no_color: bool,
) -> String {
    let tag = format!("{:<width$}", prefix, width = PREFIX_WIDTH);
    if no_color {
        return format!("{ts}  {tag}  {msg}");
    }
    let colored_msg = if msg_color.is_empty() {
        msg.to_string()
    } else {
        format!("{msg_color}{msg}{ANSI_RESET}")
    };
    format!("{ANSI_DIM}{ts}{ANSI_RESET}  {color}{tag}{ANSI_RESET}  {colored_msg}")
}

/// Tagged loggers mirroring the Go `util.Log*` globals.
pub static LOG_PIPE: Logger = Logger::new("Pipe", "\u{1b}[36m"); // cyan
pub static LOG_TUNNEL: Logger = Logger::new("Tunnel", "\u{1b}[32m"); // green
pub static LOG_RELAY: Logger = Logger::new("Relay", "\u{1b}[33m"); // yellow
pub static LOG_HOLE: Logger = Logger::new("HolePunch", "\u{1b}[34m"); // blue
pub static LOG_SPAKE2: Logger = Logger::new("SPAKE2", "\u{1b}[35m"); // magenta
pub static LOG_COPY: Logger = Logger::new("Copy", "\u{1b}[90m"); // gray
pub static LOG_EXEC: Logger = Logger::new("Exec", "\u{1b}[96m"); // bright cyan

#[cfg(test)]
mod tests {
    use super::*;

    const TS: &str = "2026-09-10 06:33:00";

    #[test]
    fn test_tag_left_justified_to_prefix_width() {
        // "Relay" (5 chars) padded to 10, plus the two separator spaces,
        // as in the Go reference: tag is "Relay     " (5 spaces).
        let l = format_line("Relay", "\u{1b}[33m", "", "hello", TS, true);
        assert_eq!(l, format!("{TS}  Relay       hello"));
    }

    #[test]
    fn test_no_color_format_shape() {
        // "SPAKE2" (6 chars) padded to 10, plus the two separator spaces.
        let l = format_line("SPAKE2", "\u{1b}[35m", "", "msg", TS, true);
        assert!(!l.contains('\u{1b}'), "expected no ANSI, got {l:?}");
        assert_eq!(l, format!("{TS}  SPAKE2      msg"));
    }

    #[test]
    fn test_colored_format_shape() {
        let l = format_line("Relay", "\u{1b}[33m", "", "hello", TS, false);
        assert!(
            l == format!("{ANSI_DIM}{TS}{ANSI_RESET}  \u{1b}[33mRelay     {ANSI_RESET}  hello"),
            "got {l:?}"
        );
    }

    #[test]
    fn test_message_coloring() {
        let l = format_line("Relay", "\u{1b}[33m", ANSI_RED, "bad", TS, false);
        assert!(
            l.ends_with(&format!("  {ANSI_RED}bad{ANSI_RESET}")),
            "got {l:?}"
        );
    }

    #[test]
    fn test_bold() {
        assert_eq!(format_bold("x", true), "x");
        assert_eq!(format_bold("x", false), format!("{ANSI_BOLD}x{ANSI_RESET}"));
    }
}
