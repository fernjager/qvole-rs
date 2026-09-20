//! Peer role naming (Go `internal/util/role.go`).

/// Returns the role string for a connection side.
///
/// Port of `util.RoleString`.
#[must_use]
pub fn role_string(is_server: bool) -> &'static str {
    if is_server { "server" } else { "client" }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn role_names() {
        assert_eq!(role_string(true), "server");
        assert_eq!(role_string(false), "client");
    }
}
