//! Go `net.ResolveUDPAddr`-compatible address resolution.
//!
//! Byte-faithful port of the error paths Go uses when resolving relay and
//! listen addresses (`net.ResolveUDPAddr("udp", addr)`), so CLI error
//! messages match the Go binary exactly. Verified against Go 1.27's
//! `net.SplitHostPort`, `net.LookupPort`, and the resolver's DNS error
//! wrapping.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};

/// Go `net.SplitHostPort` - exact error strings as wrapped by Go 1.27's
/// `AddrError.Error()` (`address <addr>: <why>`, no quoting).
pub fn split_host_port(hostport: &str) -> Result<(String, String), String> {
    const MISSING_PORT: &str = "missing port in address";
    const TOO_MANY_COLONS: &str = "too many colons in address";

    let Some(i) = hostport.rfind(':') else {
        return Err(addr_err(hostport, MISSING_PORT));
    };
    let (host, j, k) = if hostport.starts_with('[') {
        let end = hostport
            .find(']')
            .ok_or_else(|| addr_err(hostport, "missing ']' in address"))?;
        let after = end + 1;
        if after == hostport.len() {
            return Err(addr_err(hostport, MISSING_PORT));
        }
        if after != i {
            if hostport.as_bytes()[after] == b':' {
                return Err(addr_err(hostport, TOO_MANY_COLONS));
            }
            return Err(addr_err(hostport, MISSING_PORT));
        }
        (hostport[1..end].to_string(), 1, after)
    } else {
        let host = &hostport[..i];
        if host.contains(':') {
            return Err(addr_err(hostport, TOO_MANY_COLONS));
        }
        (host.to_string(), 0, 0)
    };
    if hostport[j..].contains('[') {
        return Err(addr_err(hostport, "unexpected '[' in address"));
    }
    if hostport[k..].contains(']') {
        return Err(addr_err(hostport, "unexpected ']' in address"));
    }
    Ok((host, hostport[i + 1..].to_string()))
}

fn addr_err(addr: &str, why: &str) -> String {
    // Go 1.27 `net.AddrError.Error()`: `address <addr>: <why>`.
    format!("address {addr}: {why}")
}

/// Go `net.parsePort` + `LookupPort` range check for the udp network.
///
/// Numeric ports (including `+80`, `-1`, `0`) are parsed in full; anything
/// with a non-digit is a service name looked up in `/etc/services`.
fn lookup_port(service: &str) -> Result<u16, String> {
    if let Some(port) = parse_port(service) {
        if (0..=65535i64).contains(&port) {
            return Ok(port as u16);
        }
        return Err(format!("address {service}: invalid port"));
    }
    if let Some(port) = services_lookup(service) {
        return Ok(port);
    }
    // Go DNSError text (same for cgo and pure-Go resolvers).
    Err(format!("lookup udp/{service}: unknown port"))
}

/// Go `net.parsePort`: decimal with an optional leading sign, clamped to
/// `2^30` so out-of-range values fail the caller's range check rather than
/// overflow. Returns `None` when `service` is empty or contains a
/// non-digit (those become service names).
fn parse_port(service: &str) -> Option<i64> {
    if service.is_empty() {
        return Some(0);
    }
    let mut s = service;
    let neg = if let Some(rest) = s.strip_prefix('+') {
        s = rest;
        false
    } else if let Some(rest) = s.strip_prefix('-') {
        s = rest;
        true
    } else {
        false
    };
    const MAX: i64 = u32::MAX as i64;
    const CUTOFF: i64 = 1 << 30;
    let mut n: i64 = 0;
    for c in s.chars() {
        let d = c.to_digit(10)?;
        if n >= CUTOFF {
            n = MAX;
            break;
        }
        n *= 10;
        let nn = n.saturating_add(d as i64);
        if nn < n || nn > MAX {
            n = MAX;
            break;
        }
        n = nn;
    }
    let v = if !neg && n >= CUTOFF {
        CUTOFF - 1
    } else if neg && n > CUTOFF {
        CUTOFF
    } else {
        n
    };
    Some(if neg { -v } else { v })
}

/// Go `readServices`/`lookupPortMap`: scan `/etc/services` for
/// `<name> <port>/udp` lines (aliases in later fields included).
fn services_lookup(service: &str) -> Option<u16> {
    let content = std::fs::read_to_string("/etc/services").ok()?;
    for line in content.lines() {
        let line = line.split('#').next().unwrap_or("");
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 2 {
            continue;
        }
        let portnet = fields[1];
        let Some(j) = portnet.find('/') else {
            continue;
        };
        let Some(port) = parse_port(&portnet[..j]) else {
            continue;
        };
        if !(0..=65535).contains(&port) {
            continue;
        }
        if &portnet[j + 1..] != "udp" {
            continue;
        }
        for (i, f) in fields.iter().enumerate() {
            if i != 1 && *f == service {
                return Some(port as u16);
            }
        }
    }
    None
}

/// Go `net.ResolveUDPAddr("udp", addr)`.
///
/// Deviations from Go:
/// * Empty host maps to `0.0.0.0:<port>` (Go yields a nil-IP `*UDPAddr`;
///   the socket dial then picks the family).
/// * DNS failure text omits Go's ` on <server>` suffix and approximates
///   exotic `getaddrinfo` reasons with the raw system message.
pub async fn resolve_udp_addr(addr: &str) -> Result<SocketAddr, String> {
    let (host, port_str) = split_host_port(addr)?;
    let port = lookup_port(&port_str)?;
    let ip = if host.is_empty() {
        IpAddr::V4(Ipv4Addr::UNSPECIFIED)
    } else if let Ok(ip) = host.parse::<IpAddr>() {
        ip
    } else {
        resolve_host(&host, port).await?
    };
    Ok(SocketAddr::new(ip, port))
}

async fn resolve_host(host: &str, port: u16) -> Result<IpAddr, String> {
    use std::net::ToSocketAddrs;
    let host = host.to_string();
    let host_lookup = host.clone();
    let addrs = tokio::task::spawn_blocking(move || -> std::io::Result<Vec<SocketAddr>> {
        (host_lookup.as_str(), port)
            .to_socket_addrs()
            .and_then(|it| {
                it.map(Ok::<SocketAddr, std::io::Error>)
                    .collect::<std::io::Result<Vec<_>>>()
            })
    })
    .await
    .map_err(|e| format!("lookup {host}: {e}"))?
    .map_err(|e| dns_error(&host, &e))?;
    match addrs.into_iter().next() {
        Some(a) => Ok(a.ip()),
        None => Err(format!("lookup {host}: no such host")),
    }
}

/// Map a `getaddrinfo` failure to Go's DNSError text (`lookup <host>: <reason>`).
fn dns_error(host: &str, err: &std::io::Error) -> String {
    let msg = err.to_string();
    let reason = if msg.contains("Name or service not known") {
        "no such host"
    } else if msg.contains("Temporary failure in name resolution") {
        "server misbehaving"
    } else {
        msg.rsplit(": ").next().unwrap_or(&msg)
    };
    format!("lookup {host}: {reason}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_split_host_port() {
        assert_eq!(
            split_host_port("127.0.0.1:8080").unwrap(),
            ("127.0.0.1".to_string(), "8080".to_string())
        );
        assert_eq!(
            split_host_port("[::1]:80").unwrap(),
            ("::1".to_string(), "80".to_string())
        );
        assert_eq!(
            split_host_port(":80").unwrap(),
            ("".to_string(), "80".to_string())
        );
        let cases = [
            ("x", "address x: missing port in address"),
            ("1.2.3.4", "address 1.2.3.4: missing port in address"),
            ("[::1]", "address [::1]: missing port in address"),
            ("a:b:c", "address a:b:c: too many colons in address"),
            ("[::1", "address [::1: missing ']' in address"),
            (
                "[foo]bar:baz",
                "address [foo]bar:baz: missing port in address",
            ),
            ("[foo:bar]", "address [foo:bar]: missing port in address"),
            (
                "[foo:bar]baz",
                "address [foo:bar]baz: missing port in address",
            ),
            (
                "foo[bar:baz",
                "address foo[bar:baz: unexpected '[' in address",
            ),
            (
                "foo]bar:baz",
                "address foo]bar:baz: unexpected ']' in address",
            ),
            ("a[b]:80", "address a[b]:80: unexpected '[' in address"),
        ];
        for (input, want) in cases {
            assert_eq!(split_host_port(input).unwrap_err(), want, "input {input:?}");
        }
    }

    #[test]
    fn test_parse_port() {
        assert_eq!(parse_port("80"), Some(80));
        assert_eq!(parse_port("+80"), Some(80));
        assert_eq!(parse_port("0"), Some(0));
        assert_eq!(parse_port("65535"), Some(65535));
        assert_eq!(parse_port("99999"), Some(99999));
        assert_eq!(parse_port("-1"), Some(-1));
        assert!(parse_port("http").is_none());
        assert!(parse_port("8a").is_none());
        assert_eq!(parse_port(""), Some(0));
    }

    #[tokio::test]
    async fn test_resolve_udp_addr_literal() {
        assert_eq!(
            resolve_udp_addr("127.0.0.1:9009").await.unwrap(),
            "127.0.0.1:9009".parse().unwrap()
        );
        assert_eq!(
            resolve_udp_addr("[::1]:80").await.unwrap(),
            "[::1]:80".parse().unwrap()
        );
        assert_eq!(
            resolve_udp_addr(":9009").await.unwrap(),
            "0.0.0.0:9009".parse().unwrap()
        );
        assert_eq!(
            resolve_udp_addr("1.2.3.4:0").await.unwrap(),
            "1.2.3.4:0".parse().unwrap()
        );
    }

    #[tokio::test]
    async fn test_resolve_udp_addr_errors() {
        assert_eq!(
            resolve_udp_addr("x").await.unwrap_err(),
            "address x: missing port in address"
        );
        assert_eq!(
            resolve_udp_addr("host:99999").await.unwrap_err(),
            "address 99999: invalid port"
        );
        assert_eq!(
            resolve_udp_addr("host:[bad").await.unwrap_err(),
            "address host:[bad: unexpected '[' in address"
        );
        assert_eq!(
            resolve_udp_addr("host:-1").await.unwrap_err(),
            "address -1: invalid port"
        );
        // /etc/services in this image has no udp entry for "http"
        // (only 80/tcp), mirroring Go's `lookup udp/http: unknown port`.
        let err = resolve_udp_addr("host:nosuchsvc99").await.unwrap_err();
        assert_eq!(err, "lookup udp/nosuchsvc99: unknown port");
    }

    #[test]
    fn test_services_lookup() {
        // /etc/services has `https 443/udp` (HTTP/3).
        assert_eq!(services_lookup("https"), Some(443));
        assert_eq!(services_lookup("nosuchsvc99"), None);
    }
}
