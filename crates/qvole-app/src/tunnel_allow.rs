//! Tunnel allowlist (Go `internal/app/tunnel_allow.go`).
//!
//! Controls which peer tunnel requests this side will honor. An empty
//! allowlist accepts nothing: peer `-L` and `-R` requests are ignored
//! unless they match an entry (or `all` is set).
//!
//! `forward_ips` is the authoritative, address-aware check used for
//! dialing peer-initiated forward targets: it resolves both the peer's
//! address and the allowlist entries to IP literals and pins the dial to
//! an allowed IP, closing the DNS-rebinding / host-alias window.
//! `allows_listen`/`allows_forward` are textual pre-filters only.

use std::net::IpAddr;
use std::time::Duration;

/// Go `resolveTimeout`: bounds hostname resolution so a stalled/hostile DNS
/// cannot block a tunnel.
pub const RESOLVE_TIMEOUT: Duration = Duration::from_secs(3);

/// Go `ipRule`: one resolution-aware `-aF` entry. `None` ip (with a
/// non-empty port) matches any host on that port.
#[derive(Debug, Clone)]
pub struct IpRule {
    pub port: String,
    pub ip: Option<IpAddr>,
}

/// Go `TunnelAllow`.
#[derive(Debug, Clone, Default)]
pub struct TunnelAllow {
    /// Accepts every peer tunnel request without matching (`-a`, not
    /// safe): a peer may open arbitrary listening ports and reach
    /// arbitrary addresses through this machine. Prefer explicit
    /// `listen`/`forward` entries.
    pub all: bool,
    /// `-aL addr:port` entries: the peer may ask this side to open a
    /// listening port on a matching address.
    pub listen: Vec<String>,
    /// `-aF addr:port` entries: the peer may reach a matching addr:port
    /// through this side.
    pub forward: Vec<String>,
    /// Address-aware form of `forward`, built once by [`TunnelAllow::resolve`]
    /// so the dial path can pin to allowed IPs without re-resolving the
    /// allowlist on every connection.
    forward_rules: Vec<IpRule>,
}

impl TunnelAllow {
    /// Go `Accepts`: whether this side is willing to accept any peer
    /// tunnel requests.
    pub fn accepts(&self) -> bool {
        self.all || !self.listen.is_empty() || !self.forward.is_empty()
    }

    /// Go `Validate`: parses every allowlist entry as addr:port, returning
    /// an error that lists malformed entries so typos fail fast instead of
    /// silently changing what is allowed.
    pub fn validate(&self) -> Result<(), String> {
        let mut bad: Vec<String> = Vec::new();
        for e in &self.listen {
            match split_host_port(e) {
                Some((_, port)) if !port.is_empty() => {}
                _ => bad.push(format!("-aL {e:?}")),
            }
        }
        for e in &self.forward {
            match split_host_port(e) {
                Some((_, port)) if !port.is_empty() => {}
                _ => bad.push(format!("-aF {e:?}")),
            }
        }
        if bad.is_empty() {
            Ok(())
        } else {
            Err(format!(
                "invalid tunnel allowlist entries (expected addr:port): {}",
                bad.join(", ")
            ))
        }
    }

    /// Go `Resolve`: builds the address-aware forward rules by resolving
    /// each `-aF` hostname once, at startup. Hostnames that fail to resolve
    /// are dropped (they simply will not match, so the dial path fails
    /// closed rather than over-permitting). IP literals and `:port`
    /// wildcards are kept as-is. Call after `validate`.
    pub async fn resolve(&mut self) {
        self.forward_rules = build_forward_rules(&self.forward).await;
    }

    /// Go `AllowsListen`: whether the peer may ask this side to listen on
    /// `addr`.
    pub fn allows_listen(&self, addr: &str) -> bool {
        self.all || allow_match(&self.listen, addr)
    }

    /// Go `AllowsForward`: whether the peer may reach `addr` through this
    /// side.
    ///
    /// This is a string/address pre-filter on the exact host the peer sent;
    /// it does NOT resolve the peer's address. The authoritative,
    /// address-aware check used for actually dialing a peer-initiated
    /// forward target is [`Self::forward_ips`].
    pub fn allows_forward(&self, addr: &str) -> bool {
        self.all || allow_match(&self.forward, addr)
    }

    /// Go `ForwardIPs`: resolves the peer-supplied forward target to its
    /// addresses and returns the subset allowed by the `-aF` allowlist
    /// (plus the port to dial).
    ///
    /// Dialing one of these IP literals keeps the allowlist check and the
    /// connect on the same address, closing the DNS-rebinding / host-alias
    /// window and treating aliases such as localhost vs 127.0.0.1
    /// consistently. `ok` is false when the target resolves to no allowed
    /// address, in which case the caller must reject.
    pub async fn forward_ips(&self, addr: &str) -> (Vec<IpAddr>, String, bool) {
        let Some((host, port)) = split_host_port(addr) else {
            return (Vec::new(), String::new(), false);
        };
        let all = resolve_all_ips(&host).await;
        if all.is_empty() {
            return (Vec::new(), String::new(), false);
        }
        if self.all {
            return (all, port, true);
        }
        // Go's lazy fallback (in `matchForwardIPs`): build the rules when
        // the caller constructed a TunnelAllow without Resolve() (e.g.
        // tests). Same behavior: rebuilt on every call until Resolve runs.
        let rules = if self.forward_rules.is_empty() && !self.forward.is_empty() {
            build_forward_rules(&self.forward).await
        } else {
            self.forward_rules.clone()
        };
        let allowed: Vec<IpAddr> = all
            .into_iter()
            .filter(|ip| match_forward_ips(&rules, *ip, &port))
            .collect();
        if allowed.is_empty() {
            return (Vec::new(), String::new(), false);
        }
        (allowed, port, true)
    }
}

/// Go `matchForwardIPs`: whether `ip:port` is permitted by the rules.
fn match_forward_ips(rules: &[IpRule], ip: IpAddr, port: &str) -> bool {
    for r in rules {
        if r.port != port {
            continue;
        }
        if r.ip.is_none() || r.ip == Some(ip) {
            return true;
        }
    }
    false
}

/// Go `buildForwardRules`: converts `-aF` entries into address-aware rules.
/// Empty-host entries (`:port`) become wildcards (`None` IP). Hostnames are
/// resolved to all their addresses; entries that fail to resolve are
/// dropped.
pub async fn build_forward_rules(entries: &[String]) -> Vec<IpRule> {
    let mut out: Vec<IpRule> = Vec::new();
    for e in entries {
        let Some((host, port)) = split_host_port(e) else {
            continue; // malformed entries rejected by Validate
        };
        if host.is_empty() {
            out.push(IpRule { port, ip: None });
            continue;
        }
        for ip in resolve_all_ips(&host).await {
            out.push(IpRule {
                port: port.clone(),
                ip: Some(ip),
            });
        }
    }
    out
}

/// Go `resolveAllIPs`: returns the addresses for `host`: an IP literal
/// resolves to itself, a hostname is resolved (bounded by
/// [`RESOLVE_TIMEOUT`]). Returns empty on failure or for an empty host.
pub async fn resolve_all_ips(host: &str) -> Vec<IpAddr> {
    if let Some(ip) = parse_ip_go(host) {
        return vec![ip];
    }
    if host.is_empty() {
        return Vec::new();
    }
    let result = tokio::time::timeout(RESOLVE_TIMEOUT, tokio::net::lookup_host((host, 0))).await;
    let addrs = match result {
        Ok(Ok(addrs)) => addrs,
        _ => return Vec::new(),
    };
    addrs.into_iter().map(|sa| sa.ip()).collect()
}

/// Go `net.ParseIP` (stricter than Rust's `IpAddr::from_str`, which accepts
/// IPv4 shorthand like "127.1"): requires the full dotted form for IPv4.
fn parse_ip_go(s: &str) -> Option<IpAddr> {
    let ip: IpAddr = s.parse().ok()?;
    if ip.is_ipv4() {
        let groups: Vec<&str> = s.split('.').collect();
        if groups.len() != 4 {
            return None;
        }
        for g in &groups {
            if g.is_empty() || g.len() > 3 || (g.len() > 1 && g.starts_with('0')) {
                return None;
            }
        }
    }
    Some(ip)
}

/// Go `allowMatch`: whether `addr` matches any allowlist entry. Ports must
/// match exactly; an entry host of `""` (e.g. `:8081`) matches any host.
/// Hosts are compared case-insensitively. This remains a textual
/// comparison: it is a pre-filter, not a resolution-aware authority (see
/// [`TunnelAllow::forward_ips`]).
fn allow_match(entries: &[String], addr: &str) -> bool {
    let Some((addr_host, addr_port)) = split_host_port(addr) else {
        return false;
    };
    let addr_host = addr_host.to_lowercase();
    for e in entries {
        let Some((e_host, e_port)) = split_host_port(e) else {
            continue; // malformed entries are rejected by Validate
        };
        if e_port != addr_port {
            continue;
        }
        if e_host.is_empty() || e_host.to_lowercase() == addr_host {
            return true;
        }
    }
    false
}

/// Go `net.SplitHostPort` (ipsock.go): splits "host:port",
/// "[host]:port" (bracketed IPv6) into host/port.
///
/// Returns `None` for the Go error cases: missing port, too many colons,
/// missing/unexpected brackets. Note the Go function does NOT reject an
/// empty port - callers (like `Validate`) check for that.
pub fn split_host_port(hostport: &str) -> Option<(String, String)> {
    let bytes = hostport.as_bytes();
    let i = bytes.iter().rposition(|&b| b == b':')?; // missing port in address

    let (host, j, k) = if hostport.starts_with('[') {
        let end = bytes.iter().position(|&b| b == b']')?; // missing ']' in address
        if end + 1 == hostport.len() {
            return None; // missing port in address
        }
        if end + 1 != i {
            return None; // too many colons / missing port
        }
        (hostport[1..end].to_string(), 1, end + 1)
    } else {
        let host = &hostport[..i];
        if host.contains(':') {
            return None; // too many colons in address
        }
        (host.to_string(), 0, 0)
    };

    if hostport[j..].contains('[') {
        return None; // unexpected '[' in address
    }
    if hostport[k..].contains(']') {
        return None; // unexpected ']' in address
    }

    Some((host, hostport[i + 1..].to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tunnel_allow_accepts() {
        let empty = TunnelAllow::default();
        assert!(
            !empty.accepts(),
            "empty allowlist should not accept anything"
        );

        let listen_only = TunnelAllow {
            all: false,
            listen: vec!["127.0.0.1:2222".into()],
            forward: vec![],
            forward_rules: vec![],
        };
        assert!(
            listen_only.accepts(),
            "listen entry should make allowlist accept"
        );

        let forward_only = TunnelAllow {
            all: false,
            listen: vec![],
            forward: vec!["localhost:80".into()],
            forward_rules: vec![],
        };
        assert!(
            forward_only.accepts(),
            "forward entry should make allowlist accept"
        );

        let all = TunnelAllow {
            all: true,
            ..Default::default()
        };
        assert!(all.accepts(), "All should make allowlist accept");
    }

    #[test]
    fn tunnel_allow_validate() {
        let valid = [
            TunnelAllow::default(),
            TunnelAllow {
                all: false,
                listen: vec!["127.0.0.1:2222".into()],
                forward: vec![],
                forward_rules: vec![],
            },
            TunnelAllow {
                all: false,
                listen: vec![":8081".into()],
                forward: vec![],
                forward_rules: vec![],
            },
            TunnelAllow {
                all: false,
                listen: vec![],
                forward: vec!["localhost:80".into()],
                forward_rules: vec![],
            },
            TunnelAllow {
                all: false,
                listen: vec![],
                forward: vec!["[::1]:80".into()],
                forward_rules: vec![],
            },
        ];
        for a in &valid {
            assert!(a.validate().is_ok(), "Validate({a:?}) should pass");
        }

        let invalid = [
            TunnelAllow {
                all: false,
                listen: vec!["8081".into()],
                forward: vec![],
                forward_rules: vec![],
            },
            TunnelAllow {
                all: false,
                listen: vec!["localhost".into()],
                forward: vec![],
                forward_rules: vec![],
            },
            TunnelAllow {
                all: false,
                listen: vec!["localhost:".into()],
                forward: vec![],
                forward_rules: vec![],
            },
            TunnelAllow {
                all: false,
                listen: vec![],
                forward: vec!["host:port:extra".into()],
                forward_rules: vec![],
            },
            TunnelAllow {
                all: false,
                listen: vec![],
                forward: vec!["127.0.0.1:80".into(), "nonsense".into()],
                forward_rules: vec![],
            },
        ];
        for a in &invalid {
            assert!(a.validate().is_err(), "Validate({a:?}) should fail");
        }

        let err = TunnelAllow {
            all: false,
            listen: vec!["8081".into()],
            forward: vec!["bad".into()],
            forward_rules: vec![],
        }
        .validate()
        .unwrap_err();
        assert!(err.contains("-aL"), "error should name -aL: {err}");
        assert!(err.contains("-aF"), "error should name -aF: {err}");
    }

    #[test]
    fn tunnel_allow_allows_listen() {
        let a = TunnelAllow {
            all: false,
            listen: vec!["127.0.0.1:2222".into(), ":8081".into()],
            forward: vec![],
            forward_rules: vec![],
        };

        let cases = [
            ("127.0.0.1:2222", true),
            ("127.0.0.1:8081", true), // wildcard host entry
            ("0.0.0.0:8081", true),   // wildcard host entry
            ("127.0.0.2:2222", false),
            ("0.0.0.0:2222", false),
            ("127.0.0.1:2223", false),
            ("127.0.0.1", false), // no port
            ("", false),
        ];
        for (addr, want) in cases {
            assert_eq!(
                a.allows_listen(addr),
                want,
                "AllowsListen({addr:?}) != {want}"
            );
        }

        assert!(
            !TunnelAllow::default().allows_listen("127.0.0.1:2222"),
            "empty allowlist must not allow any listen address"
        );
        assert!(
            TunnelAllow {
                all: true,
                ..Default::default()
            }
            .allows_listen("0.0.0.0:1"),
            "All must allow any listen address"
        );
    }

    #[test]
    fn tunnel_allow_allows_forward() {
        let a = TunnelAllow {
            all: false,
            listen: vec![],
            forward: vec!["localhost:80".into(), "[::1]:443".into()],
            forward_rules: vec![],
        };

        let cases = [
            ("localhost:80", true),
            ("LOCALHOST:80", true), // case-insensitive host
            ("127.0.0.1:80", false),
            ("localhost:8080", false),
            ("[::1]:443", true),
            ("::1:443", false), // unbracketed IPv6 is not a valid host:port
            ("[::1]:444", false),
        ];
        for (addr, want) in cases {
            assert_eq!(
                a.allows_forward(addr),
                want,
                "AllowsForward({addr:?}) != {want}"
            );
        }

        assert!(
            !TunnelAllow::default().allows_forward("localhost:80"),
            "empty allowlist must not allow any forward target"
        );
        assert!(
            TunnelAllow {
                all: true,
                ..Default::default()
            }
            .allows_forward("10.0.0.5:22"),
            "All must allow any forward target"
        );
    }

    #[tokio::test]
    async fn tunnel_allow_forward_ips() {
        // IP-literal allowlist: exact match allowed; wrong host or port rejected.
        let a = TunnelAllow {
            all: false,
            listen: vec![],
            forward: vec!["192.0.2.5:8080".into()],
            forward_rules: vec![],
        };
        let (ips, port, ok) = a.forward_ips("192.0.2.5:8080").await;
        assert!(ok, "exact match must be allowed");
        assert_eq!(port, "8080");
        assert_eq!(ips, vec![IpAddr::V4(std::net::Ipv4Addr::new(192, 0, 2, 5))]);

        let (_, _, ok) = a.forward_ips("192.0.2.6:8080").await;
        assert!(!ok, "must reject a target host not in the allowlist");

        let (_, _, ok) = a.forward_ips("192.0.2.5:8081").await;
        assert!(!ok, "must reject a target port not in the allowlist");

        // Empty allowlist accepts nothing.
        let (_, _, ok) = TunnelAllow::default().forward_ips("192.0.2.5:8080").await;
        assert!(!ok, "empty allowlist must not allow any forward target");
    }

    #[tokio::test]
    async fn tunnel_allow_forward_ips_wildcard_and_all() {
        let wc = TunnelAllow {
            all: false,
            listen: vec![],
            forward: vec![":8080".into()],
            forward_rules: vec![],
        };
        let (_, _, ok) = wc.forward_ips("192.0.2.9:8080").await;
        assert!(ok, "wildcard :port should allow any host on that port");

        let (_, _, ok) = wc.forward_ips("192.0.2.9:8081").await;
        assert!(!ok, "wildcard :port must reject other ports");

        let all = TunnelAllow {
            all: true,
            ..Default::default()
        };
        let (ips, port, ok) = all.forward_ips("8.8.8.8:53").await;
        assert!(ok, "All must allow any forward target");
        assert_eq!(port, "53");
        assert_eq!(ips, vec![IpAddr::V4(std::net::Ipv4Addr::new(8, 8, 8, 8))]);
    }

    #[tokio::test]
    async fn tunnel_allow_resolve_alias() {
        // After resolve(), a 127.0.0.1 rule matches a target spelled as
        // localhost, because forward_ips resolves both sides to an IP
        // before matching.
        let mut a = TunnelAllow {
            all: false,
            listen: vec![],
            forward: vec!["127.0.0.1:8080".into()],
            forward_rules: vec![],
        };
        a.resolve().await;
        let (ips, port, ok) = a.forward_ips("localhost:8080").await;
        if !ok {
            eprintln!(
                "skipping: localhost did not resolve to a loopback address in this environment"
            );
            return;
        }
        assert_eq!(port, "8080");
        assert!(
            ips.contains(&IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1))),
            "alias allowed IPs = {ips:?}, want to include 127.0.0.1"
        );
    }

    #[test]
    fn split_host_port_cases() {
        // Go net.SplitHostPort semantics (port may be empty).
        assert_eq!(
            split_host_port("localhost:80"),
            Some(("localhost".into(), "80".into()))
        );
        assert_eq!(split_host_port(":8081"), Some(("".into(), "8081".into())));
        assert_eq!(
            split_host_port("localhost:"),
            Some(("localhost".into(), "".into()))
        );
        assert_eq!(
            split_host_port("[::1]:80"),
            Some(("::1".into(), "80".into()))
        );
        assert_eq!(split_host_port("8081"), None, "missing port");
        assert_eq!(split_host_port(""), None, "empty address");
        assert_eq!(split_host_port("host:port:extra"), None, "too many colons");
        assert_eq!(split_host_port("[::1"), None, "missing ']'");
        assert_eq!(split_host_port("[::1]"), None, "missing port after ']'");
    }
}
