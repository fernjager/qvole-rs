//! Port of `internal/util/env.go`.

/// Port of `util.EnvInt`.
///
/// Reads an integer from the environment variable `name`. Returns `def` if
/// the variable is absent, unparseable, or <= 0.
pub fn env_int(name: &str, def: i64) -> i64 {
    env_int_from(std::env::var(name).ok().as_deref(), def)
}

/// Pure form of [`env_int`]: applies the Go parse rules to a raw value.
fn env_int_from(v: Option<&str>, def: i64) -> i64 {
    match v {
        Some(s) if !s.is_empty() => match s.parse::<i64>() {
            Ok(n) if n > 0 => n,
            _ => def,
        },
        _ => def,
    }
}

/// Port of `util.EnvDuration`, in milliseconds.
///
/// Reads a duration in milliseconds from the environment variable `name`.
/// Returns `def_ms` if the variable is absent, unparseable, or <= 0. Caps at
/// a sane maximum to prevent integer wraparound to negative durations.
pub fn env_duration_ms(name: &str, def_ms: u64) -> u64 {
    env_duration_ms_from(std::env::var(name).ok().as_deref(), def_ms)
}

/// Pure form of [`env_duration_ms`]: applies the Go parse rules to a raw
/// value.
fn env_duration_ms_from(v: Option<&str>, def_ms: u64) -> u64 {
    const MAX_MS: u64 = i64::MAX as u64 / 1000;
    match v {
        Some(s) if !s.is_empty() => match s.parse::<i64>() {
            Ok(ms) if ms > 0 => (ms as u64).min(MAX_MS),
            _ => def_ms,
        },
        _ => def_ms,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Ports of the Go env-helper semantics (absent / unparseable / <= 0 all
    /// fall back to the default).
    #[test]
    fn test_env_int_semantics() {
        assert_eq!(env_int_from(None, 7), 7, "absent");
        assert_eq!(env_int_from(Some(""), 7), 7, "empty");
        assert_eq!(env_int_from(Some("0"), 7), 7, "zero");
        assert_eq!(env_int_from(Some("-5"), 7), 7, "negative");
        assert_eq!(env_int_from(Some("abc"), 7), 7, "unparseable");
        assert_eq!(env_int_from(Some("42"), 7), 42, "valid");
        assert_eq!(
            env_int_from(Some("9223372036854775808"), 7),
            7,
            "i64 overflow"
        );
    }

    #[test]
    fn test_env_duration_semantics() {
        assert_eq!(env_duration_ms_from(None, 1000), 1000, "absent");
        assert_eq!(env_duration_ms_from(Some(""), 1000), 1000, "empty");
        assert_eq!(env_duration_ms_from(Some("0"), 1000), 1000, "zero");
        assert_eq!(env_duration_ms_from(Some("-1"), 1000), 1000, "negative");
        assert_eq!(env_duration_ms_from(Some("x"), 1000), 1000, "unparseable");
        assert_eq!(env_duration_ms_from(Some("250"), 1000), 250, "valid");
        // Capped like Go: parseable values above i64::MAX/1000 clamp, never
        // wrap. (Values above i64::MAX fail to parse and fall back to def,
        // exactly as strconv.Atoi does in Go.)
        let huge = env_duration_ms_from(Some("9223372036854775807"), 1000);
        assert_eq!(huge, i64::MAX as u64 / 1000, "cap");
        let overflow = env_duration_ms_from(Some("99999999999999999999"), 1000);
        assert_eq!(overflow, 1000, "parse failure falls back to default");
    }
}
