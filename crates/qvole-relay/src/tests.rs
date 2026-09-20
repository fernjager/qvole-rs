//! Ported tests for the relay crate.
//!
//! Mirrors `relay/relay_test.go` and `relay/relay_packet_test.go` from the Go
//! reference. Go tests live in-package, call `HandlePacket` directly with a
//! source address (no real inbound datagrams), and mutate package globals;
//! here this module sits inside the `relay` module (same visibility), and
//! each test gets a fresh `Relay`, the Rust equivalent of the Go
//! `resetRooms/resetIPCounts/resetRegRateLimits` setup.
//!
//! Deliberately not ported (no Rust equivalent or already covered elsewhere):
//! - `TestIsRateLimited_Concurrent`: Rust's type system prevents the shared
//!   mutable state the Go test guards with a mutex.
//! - `TestIsRateLimited_ZeroWindow`: `Instant` has no zero value.
//! - `TestClientInfo_LastSeen`: trivial struct field check.
//! - `TestIPKey_PassesHostname` / `TestIPKey_FallbackOnParseError`:
//!   `SocketAddr` cannot hold hostnames; the Go `ipKey` string fallback has no
//!   Rust input domain.
//! - The engine/spake2/bufferpool halves of `TestRelayConstants` etc.:
//!   covered by the qvole-spake2 crate and the future engine port.

use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use tokio::net::UdpSocket;
use tokio_util::sync::CancellationToken;

use super::*;
use crate::room::{MAX_ROOM_NAME_LEN, PENDING_REG_TTL_MS, RateLimiter};

// ---------------------------------------------------------------------------
// helpers

/// One pass of the production room-cleanup tick (Go `cleanupRegs`
/// roomTicker branch).
fn run_cleanup_pass(relay: &Relay) {
    let now = Instant::now();
    let ttl = relay.reg_ttl();
    let mut evicted = 0;
    for shard in &relay.shards {
        let mut g = shard.lock().expect("room shard poisoned");
        let (n, unlinked) = evict_stale_rooms(&mut g, now, ttl);
        evicted += n;
        for (ip, r) in unlinked {
            relay.remove_ip_room(ip, &r);
        }
    }
    if evicted > 0 {
        relay.total_room_count.fetch_sub(evicted, Ordering::Relaxed);
    }
    relay.remove_stale_pending_regs(Instant::now());
}

fn insert_room_with_client(
    relay: &Relay,
    room: &str,
    client: &str,
    client_ts: Instant,
    room_ts: Instant,
) {
    let entry = relay.insert_room_for_test(room);
    let mut e = entry.lock().expect("room entry poisoned");
    let addr: SocketAddr = client.parse().expect("valid client addr");
    e.udp_clients.insert(
        client.to_string(),
        crate::room::UdpClient {
            last_seen: client_ts,
            rate_limiter: RateLimiter {
                msg_count: 0,
                window_start: client_ts,
            },
            resolved_addr: Some(addr),
        },
    );
    e.t = room_ts;
}

async fn setup() -> (Arc<Relay>, UdpSocket) {
    let relay = Arc::new(Relay::new());
    let sock = UdpSocket::bind("127.0.0.1:0").await.expect("bind relay");
    (relay, sock)
}

async fn client() -> (UdpSocket, SocketAddr) {
    let c = UdpSocket::bind("127.0.0.1:0").await.expect("bind client");
    let addr = c.local_addr().expect("client local addr");
    (c, addr)
}

fn unique_room(prefix: &str) -> String {
    let n = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .as_nanos();
    format!("{prefix}-{n}")
}

async fn read_line(sock: &UdpSocket, timeout: Duration) -> Option<String> {
    let mut buf = [0u8; READ_BUF_SIZE];
    match tokio::time::timeout(timeout, sock.recv_from(&mut buf)).await {
        Ok(Ok((n, _src))) => Some(String::from_utf8_lossy(&buf[..n]).trim().to_string()),
        _ => None,
    }
}

async fn expect_no_line(sock: &UdpSocket, timeout: Duration) {
    assert!(
        read_line(sock, timeout).await.is_none(),
        "expected no response, but one arrived"
    );
}

/// Injects a datagram exactly as the Go tests do: `HandlePacket` directly
/// with the source address (no real inbound UDP traffic).
async fn inject(relay: &Arc<Relay>, relay_sock: &UdpSocket, data: &str, src: SocketAddr) {
    relay.handle_packet(relay_sock, data.as_bytes(), src).await;
}

/// Full two-step REG cookie handshake (Go `registerClient`).
async fn register_client(
    relay: &Arc<Relay>,
    relay_sock: &UdpSocket,
    client_sock: &UdpSocket,
    client_addr: SocketAddr,
    room: &str,
) {
    inject(relay, relay_sock, &format!("REG {room}\n"), client_addr).await;
    let line = read_line(client_sock, Duration::from_millis(500))
        .await
        .expect("REGD challenge");
    let expect = format!("REGD {room} ");
    assert!(
        line.starts_with(&expect),
        "expected REGD cookie challenge, got {line:?}"
    );
    let cookie = &line[expect.len()..];
    inject(
        relay,
        relay_sock,
        &format!("REG {room} {cookie}\n"),
        client_addr,
    )
    .await;
    let line2 = read_line(client_sock, Duration::from_millis(500))
        .await
        .expect("REGD OK");
    assert!(
        line2.starts_with(&format!("REGD {room} OK ")),
        "expected REGD OK confirmation, got {line2:?}"
    );
}

// ---------------------------------------------------------------------------
// room.rs unit tests (Go: relay_test.go)

#[test]
fn valid_room_name_valid() {
    let exact64 = "a".repeat(MAX_ROOM_NAME_LEN);
    for r in [
        "1234", "abcd", "room-42", "AZ", "\u{21}", // 33 '!'
        "\u{7e}", // 126 '~'
        &exact64,
    ] {
        assert!(valid_room_name(r.as_bytes()), "expected valid for {r:?}");
    }
}

#[test]
fn valid_room_name_too_long() {
    let room = "a".repeat(MAX_ROOM_NAME_LEN + 1);
    assert!(!valid_room_name(room.as_bytes()));
}

#[test]
fn valid_room_name_empty() {
    assert!(!valid_room_name(b""));
}

#[test]
fn valid_room_name_non_printable() {
    for r in [
        b"room\x00".as_slice(),
        b"test\x7f",
        b"abc\n",
        b"\troom",
        b"a\x1b",
        b"room with space",
    ] {
        assert!(!valid_room_name(r), "expected invalid for {r:?}");
    }
}

#[test]
fn valid_room_name_out_of_range() {
    assert!(!valid_room_name(&[31]));
    assert!(!valid_room_name(&[32])); // space excluded
    assert!(valid_room_name(&[33]));
    assert!(valid_room_name(&[126]));
    assert!(!valid_room_name(&[127]));
}

#[test]
fn is_valid_hex_valid() {
    for c in [
        "ff",
        "FF",
        "aAbB",
        "00",
        "deadbeef",
        "0123456789abcdefABCDEF",
    ] {
        assert!(is_valid_hex(c.as_bytes()), "expected valid hex: {c:?}");
    }
}

#[test]
fn is_valid_hex_invalid() {
    for c in ["", "f", "gg", "0x12", "hello", "abcg", "ff ", " ff"] {
        assert!(!is_valid_hex(c.as_bytes()), "expected invalid hex: {c:?}");
    }
}

#[test]
fn shard_for_deterministic() {
    for room in ["0000", "1234", "abcd", "room-42", ""] {
        let s1 = shard_idx(room, NUM_SHARDS);
        let s2 = shard_idx(room, NUM_SHARDS);
        assert_eq!(s1, s2, "shard_idx({room:?}) not deterministic");
    }
}

#[test]
fn total_rooms_zero() {
    let relay = Relay::new();
    assert_eq!(relay.total_rooms(), 0);
}

#[test]
fn ip_key_canonicalizes_ipv6() {
    let a: SocketAddr = "[2001:db8::1]:1234".parse().unwrap();
    let b: SocketAddr = "[2001:db8:0:0:0:0:0:1]:1234".parse().unwrap();
    let c: SocketAddr = "[2001:0db8:0000:0000:0000:0000:0000:0001]:1234"
        .parse()
        .unwrap();
    assert_eq!(ip_key(a), ip_key(b), "ipv6 variant mismatch");
    assert_eq!(ip_key(b), ip_key(c), "ipv6 variant mismatch");
}

#[test]
fn ip_key_canonicalizes_ipv4_mapped_ipv6() {
    let v6: SocketAddr = "[::ffff:1.2.3.4]:5678".parse().unwrap();
    let v4: SocketAddr = "1.2.3.4:5678".parse().unwrap();
    assert_eq!(ip_key(v6), ip_key(v4), "ipv4-mapped ipv6 not collapsed");
}

#[test]
fn ip_key_basic() {
    let a: SocketAddr = "1.2.3.4:5678".parse().unwrap();
    assert_eq!(ip_key(a), IpAddr::from([1, 2, 3, 4]));
    let b: SocketAddr = "[::1]:9009".parse().unwrap();
    assert_eq!(ip_key(b), IpAddr::V6(Ipv6Addr::LOCALHOST));
}

#[test]
fn relay_constants() {
    let d = Config::defaults();
    assert_eq!(d.max_rooms, 10_000);
    assert_eq!(d.max_msg_rate, 10);
    assert_eq!(d.max_reg_rate, 10);
    assert_eq!(d.max_pending_global, 65_536);
    assert_eq!(MAX_DATAGRAM_LEN, 1400);
    assert_eq!(d.reg_ttl, Duration::from_secs(60));
    assert_eq!(d.reg_cleanup_interval, Duration::from_secs(60));
    assert_eq!(d.max_rooms_per_ip, 10);
    assert_eq!(NUM_REG_SHARDS, 16);
    assert_eq!(d.max_clients_hard, 20);
}

// --- MSG rate limiter (Go TestIsRateLimited_*) ---

#[test]
fn msg_rate_limiter_under_limit() {
    let mut rl = RateLimiter::new();
    let w = Duration::from_secs(1);
    for i in 0..10 {
        assert!(
            !rl.is_limited(w, 10),
            "rate limited at {i}, window max is 10"
        );
    }
}

#[test]
fn msg_rate_limiter_over_limit() {
    let mut rl = RateLimiter::new();
    let w = Duration::from_secs(1);
    for _ in 0..10 {
        rl.is_limited(w, 10);
    }
    assert!(
        rl.is_limited(w, 10),
        "expected limited after exhausting window"
    );
}

#[test]
fn msg_rate_limiter_window_reset() {
    let mut rl = RateLimiter::new();
    let w = Duration::from_secs(1);
    for _ in 0..10 {
        rl.is_limited(w, 10);
    }
    rl.window_start = Instant::now() - Duration::from_secs(2);
    assert!(
        !rl.is_limited(w, 10),
        "expected not limited after window reset"
    );
}

#[test]
fn msg_rate_limiter_after_window_elapsed() {
    let mut rl = RateLimiter {
        msg_count: 0,
        window_start: Instant::now() - Duration::from_secs(2),
    };
    let w = Duration::from_secs(1);
    assert!(
        !rl.is_limited(w, 10),
        "should not be limited after window elapsed"
    );
    for _ in 0..10 {
        rl.is_limited(w, 10);
    }
    assert!(
        rl.is_limited(w, 10),
        "should be limited after exhausting fresh window"
    );
}

#[test]
fn total_clients() {
    let relay = Relay::new();
    assert_eq!(relay.total_clients(), 0);
}

// --- REG rate limiter (Go TestIsRegRateLimited_*) ---

#[test]
fn reg_rate_limited_under_limit() {
    let relay = Relay::new();
    for i in 0..10 {
        assert!(
            !relay.is_reg_rate_limited("test-src"),
            "limited at call {i}, max is 10"
        );
    }
}

#[test]
fn reg_rate_limited_over_limit() {
    let relay = Relay::new();
    for _ in 0..10 {
        relay.is_reg_rate_limited("test-src");
    }
    assert!(
        relay.is_reg_rate_limited("test-src"),
        "expected reg rate limited"
    );
}

#[test]
fn reg_rate_limited_separate_sources() {
    let relay = Relay::new();
    for _ in 0..10 {
        relay.is_reg_rate_limited("src-1");
        assert!(
            !relay.is_reg_rate_limited("src-2"),
            "src2 limited after src1 activity"
        );
    }
}

#[test]
fn reg_rate_limited_window_reset() {
    let relay = Relay::new();
    for _ in 0..10 {
        relay.is_reg_rate_limited("test-src");
    }
    assert!(
        relay.is_reg_rate_limited("test-src"),
        "expected rate limited"
    );
    relay.set_reg_rate_time("test-src", Instant::now() - Duration::from_secs(2));
    assert!(
        !relay.is_reg_rate_limited("test-src"),
        "expected not limited after window reset"
    );
}

#[test]
fn reg_rate_limited_first_call() {
    let relay = Relay::new();
    assert!(
        !relay.is_reg_rate_limited("new-src"),
        "first call should not be limited"
    );
}

#[test]
fn reg_rate_limited_cleanup() {
    let relay = Relay::new();
    for _ in 0..10 {
        relay.is_reg_rate_limited("cleanup-test-src");
    }
    assert!(
        relay.is_reg_rate_limited("cleanup-test-src"),
        "expected rate limited"
    );
    relay.set_reg_rate_time("cleanup-test-src", Instant::now() - Duration::from_secs(3));
    // Go applies the cleanup condition manually; here use the production
    // RegShard::cleanup_stale with the same max age (2 * rateWindow).
    {
        let mut g = relay.reg_shards[shard_idx("cleanup-test-src", NUM_REG_SHARDS)]
            .lock()
            .unwrap();
        g.cleanup_stale(Duration::from_secs(2));
    }
    assert!(
        !relay.is_reg_rate_limited("cleanup-test-src"),
        "expected not limited after cleanup"
    );
}

/// REG admission uses the dedicated `maxRegRate`, decoupled
/// from `QVOLE_RELAY_MSG_RATE`.
#[test]
fn reg_rate_limited_separate_from_msg_rate() {
    // Lowering the MSG rate to 1 must not lower the default REG allowance (10).
    let relay = Relay::new();
    relay.set_max_msg_rate(1);
    for i in 0..10 {
        assert!(
            !relay.is_reg_rate_limited("decoupled-src"),
            "REG limited at call {i} by the MSG rate"
        );
    }
    assert!(
        relay.is_reg_rate_limited("decoupled-src"),
        "expected REG limit at the dedicated rate"
    );

    // A dedicated REG rate of 2 limits after two calls.
    let relay2 = Relay::new();
    relay2.set_max_reg_rate(2);
    assert!(!relay2.is_reg_rate_limited("k"));
    assert!(!relay2.is_reg_rate_limited("k"));
    assert!(relay2.is_reg_rate_limited("k"));
}

// --- IP room links (Go TestAddRemoveIPRoom / TestRemoveIPRoom_Nonexistent) ---

#[test]
fn add_remove_ip_room() {
    let relay = Relay::new();
    let ip = IpAddr::from([10, 0, 0, 1]);
    relay.add_ip_room(ip, "room-a");
    assert_eq!(relay.count_ip_rooms(ip), 1);
    relay.add_ip_room(ip, "room-b");
    assert_eq!(relay.count_ip_rooms(ip), 2);
    relay.add_ip_room(ip, "room-a");
    assert_eq!(
        relay.count_ip_rooms(ip),
        2,
        "duplicate add must not double-count"
    );
    relay.remove_ip_room(ip, "room-a");
    assert_eq!(relay.count_ip_rooms(ip), 1);
    relay.remove_ip_room(ip, "room-b");
    assert_eq!(relay.count_ip_rooms(ip), 0);
}

#[test]
fn remove_ip_room_nonexistent() {
    let relay = Relay::new();
    let ip = IpAddr::from([99, 99, 99, 99]);
    relay.remove_ip_room(ip, "no-such-room");
    assert_eq!(relay.count_ip_rooms(ip), 0);
}

// ---------------------------------------------------------------------------
// HandlePacket dispatch (Go: relay_packet_test.go)

#[tokio::test]
async fn handle_packet_empty_data() {
    let (relay, relay_sock) = setup().await;
    let (c, addr) = client().await;
    inject(&relay, &relay_sock, "", addr).await;
    expect_no_line(&c, Duration::from_millis(50)).await;
}

#[tokio::test]
async fn handle_packet_too_large() {
    let (relay, relay_sock) = setup().await;
    let (c, addr) = client().await;
    let big = vec![0u8; MAX_DATAGRAM_LEN + 1];
    relay.handle_packet(&relay_sock, &big, addr).await;
    expect_no_line(&c, Duration::from_millis(50)).await;
}

#[tokio::test]
async fn handle_packet_too_short() {
    let (relay, relay_sock) = setup().await;
    let (c, addr) = client().await;
    inject(&relay, &relay_sock, "ab", addr).await;
    expect_no_line(&c, Duration::from_millis(50)).await;
}

#[tokio::test]
async fn handle_packet_unknown_command() {
    let (relay, relay_sock) = setup().await;
    let (c, addr) = client().await;
    inject(&relay, &relay_sock, "UNKNOWN foo\n", addr).await;
    expect_no_line(&c, Duration::from_millis(50)).await;
}

#[tokio::test]
async fn handle_packet_non_prefix_command() {
    let (relay, relay_sock) = setup().await;
    let (c, addr) = client().await;
    inject(&relay, &relay_sock, "PING room\n", addr).await;
    expect_no_line(&c, Duration::from_millis(50)).await;
    inject(&relay, &relay_sock, "GET / HTTP/1.1\n", addr).await;
    expect_no_line(&c, Duration::from_millis(50)).await;
}

// ---------------------------------------------------------------------------
// REG flow

#[tokio::test]
async fn handle_reg_new_room() {
    let (relay, relay_sock) = setup().await;
    let (c, addr) = client().await;
    let room = unique_room("reg-new");
    register_client(&relay, &relay_sock, &c, addr, &room).await;
    let arc = relay.get_room_for_test(&room).expect("room created");
    assert!(
        arc.lock()
            .unwrap()
            .udp_clients
            .contains_key(&addr.to_string()),
        "client not registered"
    );
}

#[tokio::test]
async fn handle_reg_empty_room() {
    let (relay, relay_sock) = setup().await;
    let (c, addr) = client().await;
    inject(&relay, &relay_sock, "REG  \n", addr).await;
    expect_no_line(&c, Duration::from_millis(50)).await;
}

#[tokio::test]
async fn handle_reg_invalid_room_name() {
    let (relay, relay_sock) = setup().await;
    let (c, addr) = client().await;
    relay
        .handle_packet(&relay_sock, b"REG room\x00bad\n", addr)
        .await;
    expect_no_line(&c, Duration::from_millis(50)).await;
}

#[tokio::test]
async fn handle_reg_re_registration() {
    let (relay, relay_sock) = setup().await;
    let (c, addr) = client().await;
    let room = unique_room("reg-rereg");
    register_client(&relay, &relay_sock, &c, addr, &room).await;
    // Re-reg (no cookie): room exists, client already admitted -> REGD again.
    inject(&relay, &relay_sock, &format!("REG {room}\n"), addr).await;
    let resp = read_line(&c, Duration::from_millis(500))
        .await
        .expect("REGD on re-reg");
    assert!(
        resp.starts_with(&format!("REGD {room} ")),
        "expected REGD on re-reg, got {resp:?}"
    );
}

#[tokio::test]
async fn handle_reg_hard_cap() {
    let (relay, relay_sock) = setup().await;
    let room = unique_room("reg-hard-cap");
    relay.set_max_clients_hard(3);
    for _ in 0..3 {
        let (c, addr) = client().await;
        register_client(&relay, &relay_sock, &c, addr, &room).await;
    }
    let (extra, extra_addr) = client().await;
    inject(&relay, &relay_sock, &format!("REG {room}\n"), extra_addr).await;
    expect_no_line(&extra, Duration::from_millis(100)).await;
}

#[tokio::test]
async fn handle_reg_room_capacity_limit() {
    let (relay, relay_sock) = setup().await;
    let (c, addr) = client().await;
    relay.set_total_rooms(relay.max_rooms_for_test());
    let room = unique_room("reg-cap-limit");

    // Initial REG still gets a cookie challenge (cap is checked at cookie
    // completion).
    inject(&relay, &relay_sock, &format!("REG {room}\n"), addr).await;
    let line = read_line(&c, Duration::from_millis(500))
        .await
        .expect("challenge");
    let expect = format!("REGD {room} ");
    assert!(
        line.starts_with(&expect),
        "expected challenge, got {line:?}"
    );
    let cookie = &line[expect.len()..];

    // Cookie completion must be rejected: room capacity is full and there is
    // nothing stale to evict.
    inject(&relay, &relay_sock, &format!("REG {room} {cookie}\n"), addr).await;
    expect_no_line(&c, Duration::from_millis(100)).await;
}

#[tokio::test]
async fn handle_reg_pending_cap_existing_room() {
    let (relay, relay_sock) = setup().await;
    let (c, addr) = client().await;
    let room = unique_room("pending-cap");
    register_client(&relay, &relay_sock, &c, addr, &room).await;

    relay.set_max_pending_per_ip(3);
    // Flood the existing room with REGs from one IP, randomizing the source
    // port so each lands as a fresh pending registration.
    for i in 0..5 {
        let src: SocketAddr = format!("127.0.0.1:{}", 30000 + i).parse().unwrap();
        inject(&relay, &relay_sock, &format!("REG {room}\n"), src).await;
    }
    assert_eq!(
        relay.pending_count_in_room(&room),
        3,
        "per-IP pending cap not enforced"
    );
}

#[tokio::test]
async fn handle_reg_concurrent_eviction() {
    // Registrations racing the stale-room sweeper: the shard lock must be
    // held until the entry lock is acquired, or eviction can orphan the room.
    let (relay, relay_sock) = setup().await;
    let (c, addr) = client().await;
    let room = unique_room("evict-race");
    register_client(&relay, &relay_sock, &c, addr, &room).await;

    let cancel = CancellationToken::new();
    {
        let r = Arc::clone(&relay);
        let cancel2 = cancel.clone();
        tokio::spawn(async move {
            while !cancel2.is_cancelled() {
                run_cleanup_pass(&r);
                // Yield so the current-thread runtime can make progress
                // (the sync cleanup pass alone would starve the test task).
                tokio::task::yield_now().await;
            }
        });
    }
    for i in 0..20 {
        let src: SocketAddr = format!("127.0.0.1:{}", 31000 + i).parse().unwrap();
        inject(&relay, &relay_sock, &format!("REG {room}\n"), src).await;
        tokio::task::yield_now().await; // let the sweeper run between REGs
    }
    cancel.cancel();
    // The test passes if no deadlock or panic occurs (Go test likewise).
}

#[tokio::test]
async fn handle_reg_per_ip_room_limit() {
    let (relay, relay_sock) = setup().await;
    relay.set_max_reg_rate(1000); // avoid the REG rate limiter tripping

    for i in 0..10 {
        let (c, addr) = client().await;
        let room = unique_room(&format!("ip-limit-{i}"));
        register_client(&relay, &relay_sock, &c, addr, &room).await;
    }

    let (extra, extra_addr) = client().await;
    let extra_room = unique_room("ip-limit-extra");
    inject(
        &relay,
        &relay_sock,
        &format!("REG {extra_room}\n"),
        extra_addr,
    )
    .await;
    expect_no_line(&extra, Duration::from_millis(100)).await;
}

// ---------------------------------------------------------------------------
// Pending registration store

#[tokio::test]
async fn pending_reg_does_not_create_room() {
    let (relay, relay_sock) = setup().await;
    let (c, addr) = client().await;
    let room = unique_room("pending-noroom");

    inject(&relay, &relay_sock, &format!("REG {room}\n"), addr).await;
    let line = read_line(&c, Duration::from_millis(500))
        .await
        .expect("challenge");
    let expect = format!("REGD {room} ");
    assert!(
        line.starts_with(&expect),
        "expected challenge, got {line:?}"
    );

    assert!(
        relay.get_room_for_test(&room).is_none(),
        "room must not exist yet"
    );
    assert_eq!(relay.total_rooms(), 0, "totalRooms must not increase");
    assert!(
        relay.get_pending_reg(&room, &addr.to_string()).is_some(),
        "pending registration not found in store"
    );
}

#[tokio::test]
async fn pending_reg_cookie_completion_creates_room() {
    let (relay, relay_sock) = setup().await;
    let (c, addr) = client().await;
    let room = unique_room("pending-create");

    register_client(&relay, &relay_sock, &c, addr, &room).await;

    let arc = relay
        .get_room_for_test(&room)
        .expect("room exists after cookie completion");
    assert!(
        arc.lock()
            .unwrap()
            .udp_clients
            .contains_key(&addr.to_string()),
        "client should be admitted"
    );
    assert_eq!(relay.total_rooms(), 1);
    assert!(
        relay.get_pending_reg(&room, &addr.to_string()).is_none(),
        "pending registration should have been removed"
    );
}

#[tokio::test]
async fn pending_reg_room_exhaustion() {
    let (relay, relay_sock) = setup().await;
    relay.set_max_rooms(10);
    relay.set_max_reg_rate(1000); // avoid the REG rate limiter tripping

    // Flood initial REGs from distinct local ports (all 127.0.0.1). None may
    // create rooms.
    for i in 0..30 {
        let (c, addr) = client().await;
        let room = unique_room(&format!("exhaust-{i}"));
        inject(&relay, &relay_sock, &format!("REG {room}\n"), addr).await;
        let _ = read_line(&c, Duration::from_millis(100)).await;
    }

    assert_eq!(
        relay.total_rooms(),
        0,
        "rooms should not be created on initial REG"
    );
}

#[tokio::test]
async fn cookie_completion_rechecks_hard_cap() {
    let (relay, relay_sock) = setup().await;
    let room = unique_room("cookie-hardcap");
    relay.set_max_clients_hard(3);

    let (c1, addr1) = client().await;
    register_client(&relay, &relay_sock, &c1, addr1, &room).await;

    // Collect cookies for 3 more clients while the room is under the cap.
    let mut extras: Vec<(UdpSocket, SocketAddr, String)> = Vec::new();
    for _ in 0..3 {
        let (c, addr) = client().await;
        inject(&relay, &relay_sock, &format!("REG {room}\n"), addr).await;
        let line = read_line(&c, Duration::from_millis(500))
            .await
            .expect("cookie");
        let expect = format!("REGD {room} ");
        assert!(line.starts_with(&expect), "expected cookie, got {line:?}");
        extras.push((c, addr, line[expect.len()..].to_string()));
    }

    // First two complete successfully (filling the cap to 3); the third is
    // rejected by the re-check.
    let mut admitted = 0;
    for (c, addr, cookie) in extras {
        inject(&relay, &relay_sock, &format!("REG {room} {cookie}\n"), addr).await;
        match read_line(&c, Duration::from_millis(500)).await {
            Some(line) if line.starts_with(&format!("REGD {room} OK ")) => admitted += 1,
            _ => {}
        }
    }
    assert!(
        admitted <= 2,
        "admitted {admitted} extras, want at most 2 (hard cap re-check failed)"
    );
    assert_eq!(relay.client_count(&room).unwrap(), 3);
}

#[tokio::test]
async fn cookie_completion_rechecks_per_ip_cap() {
    let (relay, relay_sock) = setup().await;
    let (c, addr) = client().await;
    relay.set_max_rooms_per_ip(2);

    // Collect cookies for 3 rooms via the pending store (rooms don't exist
    // yet, so the initial REG is not blocked by the per-IP cap).
    let mut cookies: Vec<(String, String)> = Vec::new();
    for i in 0..3 {
        let room = unique_room(&format!("ipcap-{i}"));
        inject(&relay, &relay_sock, &format!("REG {room}\n"), addr).await;
        let line = read_line(&c, Duration::from_millis(500))
            .await
            .expect("cookie");
        let expect = format!("REGD {room} ");
        assert!(line.starts_with(&expect), "expected cookie, got {line:?}");
        cookies.push((room, line[expect.len()..].to_string()));
    }

    // Complete the first two; both succeed (IP count goes 0 -> 1 -> 2).
    for (room, cookie) in &cookies[..2] {
        inject(&relay, &relay_sock, &format!("REG {room} {cookie}\n"), addr).await;
        let line = read_line(&c, Duration::from_millis(500))
            .await
            .expect("REGD OK");
        assert!(
            line.starts_with(&format!("REGD {room} OK ")),
            "expected REGD OK, got {line:?}"
        );
    }

    // Complete the third; rejected because the IP is at its cap (2).
    let (room3, cookie3) = &cookies[2];
    inject(
        &relay,
        &relay_sock,
        &format!("REG {room3} {cookie3}\n"),
        addr,
    )
    .await;
    expect_no_line(&c, Duration::from_millis(100)).await;
}

#[tokio::test]
async fn cookie_completion_rechecks_per_ip_cap_existing_room() {
    let (relay, relay_sock) = setup().await;
    let (ca, ca_addr) = client().await;
    relay.set_max_rooms_per_ip(2);

    // B is a distinct (unroutable) source IP; responses to it are not
    // observed, so its cookies are read from the pending store instead.
    let b_addr: SocketAddr = "10.99.99.99:4242".parse().unwrap();
    let b_src = b_addr.to_string();
    let fake_ip: IpAddr = "10.99.99.99".parse().unwrap();

    let room_x = unique_room("ipcapx");
    let room_y = unique_room("ipcapy");
    let room_z = unique_room("ipcapz");

    // B pre-registers X, Y, Z via the pending store (none exist yet).
    let mut cookies = Vec::new();
    for room in [&room_x, &room_y, &room_z] {
        inject(&relay, &relay_sock, &format!("REG {room}\n"), b_addr).await;
        let p = relay
            .get_pending_reg(room, &b_src)
            .unwrap_or_else(|| panic!("room {room}: expected pending registration"));
        cookies.push(
            p.cookie
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>(),
        );
    }

    // Client A (127.0.0.1) creates room X via the pending store.
    register_client(&relay, &relay_sock, &ca, ca_addr, &room_x).await;

    // B completes Y and Z; both create rooms, putting B's IP at cap (2).
    for (i, room) in [room_y.clone(), room_z.clone()].into_iter().enumerate() {
        let cookie = cookies[i + 1].clone();
        inject(
            &relay,
            &relay_sock,
            &format!("REG {room} {cookie}\n"),
            b_addr,
        )
        .await;
        assert_eq!(
            relay.count_ip_rooms(fake_ip),
            i + 1,
            "after completing {room}: countIPRooms mismatch"
        );
    }

    // B completes X; room exists (created by A), B's IP is at cap and not in
    // the room, so the exists-branch per-IP re-check must reject it.
    let cookie_x = cookies[0].clone();
    inject(
        &relay,
        &relay_sock,
        &format!("REG {room_x} {cookie_x}\n"),
        b_addr,
    )
    .await;
    assert_eq!(
        relay.count_ip_rooms(fake_ip),
        2,
        "per-IP cap bypassed on rejected completion"
    );
    let arc = relay
        .get_room_for_test(&room_x)
        .expect("room X disappeared");
    let n_clients = {
        let e = arc.lock().unwrap();
        assert!(
            !e.udp_clients.contains_key(&b_src),
            "B admitted despite per-IP cap"
        );
        e.udp_clients.len()
    };

    // Room X must remain usable: client C (same IP as A, already in room X)
    // completes its cookie and is admitted.
    let (cc, cc_addr) = client().await;
    inject(&relay, &relay_sock, &format!("REG {room_x}\n"), cc_addr).await;
    let line_c = read_line(&cc, Duration::from_millis(500))
        .await
        .expect("C cookie");
    let expect = format!("REGD {room_x} ");
    assert!(
        line_c.starts_with(&expect),
        "expected C cookie, got {line_c:?}"
    );
    let cookie_c = &line_c[expect.len()..];
    inject(
        &relay,
        &relay_sock,
        &format!("REG {room_x} {cookie_c}\n"),
        cc_addr,
    )
    .await;
    let line_c2 = read_line(&cc, Duration::from_millis(500))
        .await
        .expect("C REGD OK");
    assert!(
        line_c2.starts_with(&format!("REGD {room_x} OK ")),
        "expected C REGD OK, got {line_c2:?}"
    );
    assert_eq!(
        relay.client_count(&room_x).unwrap(),
        n_clients + 1,
        "room X client count mismatch after C joined"
    );
}

#[tokio::test]
async fn cookie_reg_unknown_room_rechallenged() {
    let (relay, relay_sock) = setup().await;
    let (c, addr) = client().await;

    let room = unique_room("rechal");
    // Initial REG -> pending store + challenge.
    inject(&relay, &relay_sock, &format!("REG {room}\n"), addr).await;
    let line1 = read_line(&c, Duration::from_millis(500))
        .await
        .expect("cookie1");
    let expect = format!("REGD {room} ");
    assert!(line1.starts_with(&expect), "expected cookie, got {line1:?}");
    let cookie1 = &line1[expect.len()..];

    // Evict the pending entry, simulating pendingRegTTL expiry.
    relay.remove_stale_pending_regs(Instant::now() + Duration::from_secs(3600));

    // Cookie REG for the now-unknown room must be re-challenged, not dropped.
    inject(
        &relay,
        &relay_sock,
        &format!("REG {room} {cookie1}\n"),
        addr,
    )
    .await;
    let line2 = read_line(&c, Duration::from_millis(500))
        .await
        .expect("re-challenge");
    assert!(
        line2.starts_with(&expect),
        "expected re-challenge, got {line2:?}"
    );
    assert!(
        !line2.starts_with(&format!("REGD {room} OK ")),
        "expected a fresh cookie challenge, not admission"
    );
    let cookie2 = &line2[expect.len()..];
    assert_ne!(cookie1, cookie2, "re-challenge must issue a fresh cookie");

    // Completing with the fresh cookie creates the room and admits the client.
    inject(
        &relay,
        &relay_sock,
        &format!("REG {room} {cookie2}\n"),
        addr,
    )
    .await;
    let line3 = read_line(&c, Duration::from_millis(500))
        .await
        .expect("REGD OK");
    assert!(
        line3.starts_with(&format!("REGD {room} OK ")),
        "expected REGD OK after re-challenge, got {line3:?}"
    );
}

#[test]
fn pending_reg_cleanup() {
    let relay = Relay::new();
    let room = unique_room("pending-cleanup");

    let mut cookie = [0x00u8; PENDING_COOKIE_BYTES];
    cookie[..4].copy_from_slice(&[0xde, 0xad, 0xbe, 0xef]);
    relay.store_pending_reg(
        &room,
        "1.2.3.4:5678",
        crate::room::PendingReg {
            cookie,
            created_at: Instant::now() - Duration::from_millis(PENDING_REG_TTL_MS * 2),
            resolved_addr: "1.2.3.4:5678".parse().unwrap(),
        },
    );
    assert!(
        relay.get_pending_reg(&room, "1.2.3.4:5678").is_some(),
        "pending registration should exist before cleanup"
    );

    relay.remove_stale_pending_regs(Instant::now());

    assert!(
        relay.get_pending_reg(&room, "1.2.3.4:5678").is_none(),
        "stale pending registration should have been evicted"
    );
}

#[tokio::test]
async fn pending_reg_per_ip_limit() {
    let (relay, relay_sock) = setup().await;
    relay.set_max_pending_per_ip(2);

    for i in 0..2 {
        let (c, addr) = client().await;
        let room = unique_room(&format!("pend-limit-{i}"));
        inject(&relay, &relay_sock, &format!("REG {room}\n"), addr).await;
        let _ = read_line(&c, Duration::from_millis(100)).await;
    }

    let (extra, extra_addr) = client().await;
    let extra_room = unique_room("pend-limit-extra");
    inject(
        &relay,
        &relay_sock,
        &format!("REG {extra_room}\n"),
        extra_addr,
    )
    .await;
    expect_no_line(&extra, Duration::from_millis(100)).await;
}

/// The global pending store is bounded by maxPendingGlobal.
#[tokio::test]
async fn pending_store_global_cap() {
    let (relay, relay_sock) = setup().await;
    relay.set_max_pending_global(3);
    let (c, addr) = client().await;

    // Three new rooms fit; each gets a challenge.
    for i in 0..3 {
        let room = unique_room(&format!("gcap-{i}"));
        inject(&relay, &relay_sock, &format!("REG {room}\n"), addr).await;
        let line = read_line(&c, Duration::from_millis(500))
            .await
            .expect("challenge");
        assert!(
            line.starts_with(&format!("REGD {room} ")),
            "expected challenge, got {line:?}"
        );
    }
    assert_eq!(relay.pending_total(), 3, "global pending count mismatch");

    // The fourth new room is dropped (no challenge) while the store is full.
    let room4 = unique_room("gcap-full");
    inject(&relay, &relay_sock, &format!("REG {room4}\n"), addr).await;
    expect_no_line(&c, Duration::from_millis(100)).await;
    assert_eq!(relay.pending_total(), 3, "global cap exceeded");
}

/// Pending counters stay accurate across store, replace,
/// delete and stale eviction (global and per-room).
#[test]
fn pending_counts_stay_accurate() {
    let relay = Relay::new();
    let a: SocketAddr = "10.0.0.1:1000".parse().unwrap();
    let b: SocketAddr = "10.0.0.2:2000".parse().unwrap();
    let mk = |ts: Instant, resolved: SocketAddr| PendingReg {
        cookie: [7u8; PENDING_COOKIE_BYTES],
        created_at: ts,
        resolved_addr: resolved,
    };
    let now = Instant::now();

    assert!(relay.store_pending_reg("r1", &a.to_string(), mk(now, a)));
    assert!(relay.store_pending_reg("r2", &a.to_string(), mk(now, a)));
    assert!(relay.store_pending_reg("r3", &b.to_string(), mk(now, b)));
    assert_eq!(relay.pending_total(), 3);
    assert_eq!(relay.pending_count_for_ip(ip_key(a)), 2);
    assert_eq!(relay.pending_count_for_ip(ip_key(b)), 1);

    // Replacing an existing key must not bump the counters.
    assert!(relay.store_pending_reg("r1", &a.to_string(), mk(now, a)));
    assert_eq!(relay.pending_total(), 3);
    assert_eq!(relay.pending_count_for_ip(ip_key(a)), 2);

    // Delete one; deleting again must not underflow.
    relay.delete_pending_reg("r1", &a.to_string());
    relay.delete_pending_reg("r1", &a.to_string());
    assert_eq!(relay.pending_total(), 2);
    assert_eq!(relay.pending_count_for_ip(ip_key(a)), 1);

    // Stale eviction keeps both counters in sync.
    let old = now - Duration::from_millis(PENDING_REG_TTL_MS * 2);
    assert!(relay.store_pending_reg("r4", &b.to_string(), mk(old, b)));
    relay.remove_stale_pending_regs(Instant::now());
    assert_eq!(
        relay.pending_total(),
        2,
        "stale global entry not counted out"
    );
    assert_eq!(relay.pending_count_for_ip(ip_key(b)), 1, "b count mismatch");
    assert_eq!(relay.pending_count_for_ip(ip_key(a)), 1, "a count mismatch");

    // In-room pending counters.
    let mut entry = RoomEntry::new();
    entry.add_pending(&a.to_string(), mk(now, a));
    entry.add_pending(&a.to_string(), mk(now, a)); // replace, no double count
    assert_eq!(entry.pending_count_for_ip(ip_key(a)), 1);
    assert!(entry.remove_pending(&a.to_string()).is_some());
    assert_eq!(entry.pending_count_for_ip(ip_key(a)), 0);
    assert!(entry.remove_pending(&a.to_string()).is_none());
}

/// Cookie completion sweeps stale rooms in *all* shards
/// before re-checking maxRooms (the stale room here lives in another shard).
#[tokio::test]
async fn cookie_completion_evicts_stale_rooms_across_shards() {
    let (relay, relay_sock) = setup().await;
    let (c, addr) = client().await;
    let target = unique_room("xshard-target");

    // Find a room name that hashes to a different shard than `target`.
    let target_shard = shard_idx(&target, NUM_SHARDS);
    let mut stale_room = unique_room("xshard-stale-0");
    let mut i = 0;
    while shard_idx(&stale_room, NUM_SHARDS) == target_shard {
        i += 1;
        stale_room = unique_room(&format!("xshard-stale-{i}"));
    }

    let stale_ts = Instant::now() - Duration::from_secs(120); // 2x reg TTL
    insert_room_with_client(&relay, &stale_room, "10.1.1.1:5000", stale_ts, stale_ts);
    relay.set_total_rooms(1); // the stale room is counted
    relay.set_max_rooms(1);

    // Initial REG for the target is still challenged (cap checked at completion).
    inject(&relay, &relay_sock, &format!("REG {target}\n"), addr).await;
    let line = read_line(&c, Duration::from_millis(500))
        .await
        .expect("challenge");
    let expect = format!("REGD {target} ");
    assert!(
        line.starts_with(&expect),
        "expected challenge, got {line:?}"
    );
    let cookie = &line[expect.len()..];

    // Completion must evict the stale room in the other shard and create the
    // target rather than rejecting with "max rooms reached".
    inject(
        &relay,
        &relay_sock,
        &format!("REG {target} {cookie}\n"),
        addr,
    )
    .await;
    let line2 = read_line(&c, Duration::from_millis(500))
        .await
        .expect("REGD OK");
    assert!(
        line2.starts_with(&format!("REGD {target} OK ")),
        "expected REGD OK, got {line2:?}"
    );
    assert!(
        relay.get_room_for_test(&stale_room).is_none(),
        "stale room in another shard was not evicted"
    );
    assert!(
        relay.get_room_for_test(&target).is_some(),
        "target room not created"
    );
    assert_eq!(relay.total_rooms(), 1, "room count mismatch after sweep");
}

/// Global pending store branch: a cookie completion into an
/// existing room evicts stale clients before enforcing maxClientsHard.
#[tokio::test]
async fn cookie_completion_existing_room_evicts_stale_clients() {
    let (relay, relay_sock) = setup().await;
    relay.set_max_clients_hard(1);

    // B (unroutable source) pre-registers room X in the global pending store.
    let b_addr: SocketAddr = "10.88.88.88:4242".parse().unwrap();
    let b_src = b_addr.to_string();
    let room_x = unique_room("xroom");
    inject(&relay, &relay_sock, &format!("REG {room_x}\n"), b_addr).await;
    let p = relay
        .get_pending_reg(&room_x, &b_src)
        .expect("B pending registration");
    let cookie = to_hex_lower(&p.cookie);

    // A creates room X (1 client == the hard cap).
    let (ca, ca_addr) = client().await;
    register_client(&relay, &relay_sock, &ca, ca_addr, &room_x).await;

    // Age A out; B's completion must evict A and admit B.
    relay.touch_client_last_seen(
        &room_x,
        &ca_addr.to_string(),
        Instant::now() - Duration::from_secs(120),
    );
    inject(
        &relay,
        &relay_sock,
        &format!("REG {room_x} {cookie}\n"),
        b_addr,
    )
    .await;

    let arc = relay.get_room_for_test(&room_x).expect("room X");
    let e = arc.lock().unwrap();
    assert!(
        e.udp_clients.contains_key(&b_src),
        "B not admitted after stale-client eviction"
    );
    assert!(
        !e.udp_clients.contains_key(&ca_addr.to_string()),
        "stale client A not evicted"
    );
}

/// In-room pending branch: the same stale-client eviction
/// happens for a cookie carried by `entry.pending`.
#[tokio::test]
async fn cookie_completion_in_room_evicts_stale_clients() {
    let (relay, relay_sock) = setup().await;
    relay.set_max_clients_hard(2);

    let room = unique_room("inroom-stale");

    // A creates the room.
    let (ca, aa) = client().await;
    register_client(&relay, &relay_sock, &ca, aa, &room).await;

    // B gets an in-room challenge while the room is under the cap.
    let (cb, ab) = client().await;
    inject(&relay, &relay_sock, &format!("REG {room}\n"), ab).await;
    let line = read_line(&cb, Duration::from_millis(500))
        .await
        .expect("B challenge");
    let expect = format!("REGD {room} ");
    assert!(line.starts_with(&expect), "expected B cookie, got {line:?}");
    let cookie_b = line[expect.len()..].to_string();

    // C fills the room to the hard cap.
    let (cc, ac) = client().await;
    register_client(&relay, &relay_sock, &cc, ac, &room).await;
    assert_eq!(relay.client_count(&room).unwrap(), 2);

    // Age both admitted clients out.
    let stale = Instant::now() - Duration::from_secs(120);
    relay.touch_client_last_seen(&room, &aa.to_string(), stale);
    relay.touch_client_last_seen(&room, &ac.to_string(), stale);

    // B completes: stale clients must be evicted before the hard-cap check.
    inject(&relay, &relay_sock, &format!("REG {room} {cookie_b}\n"), ab).await;
    let line2 = read_line(&cb, Duration::from_millis(500))
        .await
        .expect("B REGD OK");
    assert!(
        line2.starts_with(&format!("REGD {room} OK ")),
        "expected B admission, got {line2:?}"
    );
    assert_eq!(relay.client_count(&room).unwrap(), 1);
}

// ---------------------------------------------------------------------------
// MSG flow

#[tokio::test]
async fn handle_msg_forward_to_other_client() {
    let (relay, relay_sock) = setup().await;
    let (c1, a1) = client().await;
    let (c2, a2) = client().await;
    let room = unique_room("msg-fwd");
    register_client(&relay, &relay_sock, &c1, a1, &room).await;
    register_client(&relay, &relay_sock, &c2, a2, &room).await;

    inject(
        &relay,
        &relay_sock,
        &format!("MSG {room} spake2 deadbeef\n"),
        a1,
    )
    .await;
    let resp = read_line(&c2, Duration::from_millis(500))
        .await
        .expect("MSGD");
    assert_eq!(resp, "MSGD spake2 deadbeef");
}

#[tokio::test]
async fn handle_msg_sender_does_not_receive_own_message() {
    let (relay, relay_sock) = setup().await;
    let (c1, a1) = client().await;
    let (c2, a2) = client().await;
    let room = unique_room("msg-noecho");
    register_client(&relay, &relay_sock, &c1, a1, &room).await;
    register_client(&relay, &relay_sock, &c2, a2, &room).await;

    inject(
        &relay,
        &relay_sock,
        &format!("MSG {room} confirm aabb\n"),
        a1,
    )
    .await;
    expect_no_line(&c1, Duration::from_millis(100)).await;
}

#[tokio::test]
async fn handle_msg_broadcast_to_multiple_clients() {
    let (relay, relay_sock) = setup().await;
    let (s, sa) = client().await;
    let (r1, ra1) = client().await;
    let (r2, ra2) = client().await;
    let room = unique_room("msg-bcast3");
    register_client(&relay, &relay_sock, &s, sa, &room).await;
    register_client(&relay, &relay_sock, &r1, ra1, &room).await;
    register_client(&relay, &relay_sock, &r2, ra2, &room).await;

    inject(
        &relay,
        &relay_sock,
        &format!("MSG {room} spake2 beef3c01\n"),
        sa,
    )
    .await;
    assert_eq!(
        read_line(&r1, Duration::from_millis(500)).await.unwrap(),
        "MSGD spake2 beef3c01"
    );
    assert_eq!(
        read_line(&r2, Duration::from_millis(500)).await.unwrap(),
        "MSGD spake2 beef3c01"
    );
    expect_no_line(&s, Duration::from_millis(100)).await;
}

#[tokio::test]
async fn remove_stale_clients_on_reg() {
    let (relay, relay_sock) = setup().await;
    let (ca, aa) = client().await;
    let (cb, ab) = client().await;
    let (cc, ac) = client().await;
    let room = unique_room("stale-reg");
    register_client(&relay, &relay_sock, &ca, aa, &room).await;
    register_client(&relay, &relay_sock, &cb, ab, &room).await;

    // Age out client A (2x reg TTL).
    relay.touch_client_last_seen(
        &room,
        &aa.to_string(),
        Instant::now() - Duration::from_secs(120),
    );

    // C's REG triggers removeStaleClients, evicting A.
    register_client(&relay, &relay_sock, &cc, ac, &room).await;

    inject(
        &relay,
        &relay_sock,
        &format!("MSG {room} spake2 deadbeef\n"),
        ab,
    )
    .await;
    let resp = read_line(&cc, Duration::from_millis(500))
        .await
        .expect("C MSGD");
    assert_eq!(resp, "MSGD spake2 deadbeef");
    expect_no_line(&ca, Duration::from_millis(100)).await;
}

#[tokio::test]
async fn re_reg_does_not_bump_room_ttl() {
    let (relay, relay_sock) = setup().await;
    let (c, addr) = client().await;
    let room = unique_room("rereg-ttl");
    register_client(&relay, &relay_sock, &c, addr, &room).await;

    let orig_t = relay.room_t(&room).expect("room t");
    tokio::time::sleep(Duration::from_millis(10)).await;
    inject(&relay, &relay_sock, &format!("REG {room}\n"), addr).await;
    let _ = read_line(&c, Duration::from_millis(500)).await;

    let new_t = relay.room_t(&room).expect("room t");
    assert!(
        new_t <= orig_t + Duration::from_millis(5),
        "entry.t was bumped: orig={orig_t:?} new={new_t:?}"
    );
}

#[tokio::test]
async fn handle_msg_invalid_format() {
    let (relay, relay_sock) = setup().await;
    let (c, addr) = client().await;
    let room = unique_room("msg-invalid");
    register_client(&relay, &relay_sock, &c, addr, &room).await;

    inject(&relay, &relay_sock, &format!("MSG {room}\n"), addr).await;
    expect_no_line(&c, Duration::from_millis(50)).await;
}

#[tokio::test]
async fn handle_msg_invalid_hex() {
    let (relay, relay_sock) = setup().await;
    let (c, addr) = client().await;
    let room = unique_room("msg-hex");
    register_client(&relay, &relay_sock, &c, addr, &room).await;

    inject(
        &relay,
        &relay_sock,
        &format!("MSG {room} spake2 zzzz\n"),
        addr,
    )
    .await;
    expect_no_line(&c, Duration::from_millis(50)).await;
}

#[tokio::test]
async fn handle_msg_rate_limiting() {
    let (relay, relay_sock) = setup().await;
    let (c1, a1) = client().await;
    let (c2, a2) = client().await;
    let room = unique_room("msg-rate");
    register_client(&relay, &relay_sock, &c1, a1, &room).await;
    register_client(&relay, &relay_sock, &c2, a2, &room).await;

    for i in 0..10 {
        inject(
            &relay,
            &relay_sock,
            &format!("MSG {room} spake2 {i:02x}\n"),
            a1,
        )
        .await;
        read_line(&c2, Duration::from_millis(500)).await;
    }

    inject(&relay, &relay_sock, &format!("MSG {room} spake2 ff\n"), a1).await;
    expect_no_line(&c2, Duration::from_millis(100)).await;
}

#[tokio::test]
async fn handle_msg_unknown_room() {
    let (relay, relay_sock) = setup().await;
    let (c, addr) = client().await;
    inject(&relay, &relay_sock, "MSG unknown-room spake2 aabb\n", addr).await;
    expect_no_line(&c, Duration::from_millis(50)).await;
}

#[tokio::test]
async fn handle_msg_unknown_sender() {
    let (relay, relay_sock) = setup().await;
    let (c1, a1) = client().await;
    let (c2, a2) = client().await;
    let room = unique_room("msg-unknown-sender");

    // c1 is admitted; c2 (a2) never registers.
    register_client(&relay, &relay_sock, &c1, a1, &room).await;

    inject(
        &relay,
        &relay_sock,
        &format!("MSG {room} spake2 aabb\n"),
        a2,
    )
    .await;
    expect_no_line(&c2, Duration::from_millis(50)).await;
}

#[tokio::test]
async fn handle_msg_unknown_phase() {
    let (relay, relay_sock) = setup().await;
    let (c1, a1) = client().await;
    let (c2, a2) = client().await;
    let room = unique_room("msg-unknown-phase");
    register_client(&relay, &relay_sock, &c1, a1, &room).await;
    register_client(&relay, &relay_sock, &c2, a2, &room).await;

    inject(
        &relay,
        &relay_sock,
        &format!("MSG {room} badphase aabb\n"),
        a1,
    )
    .await;
    expect_no_line(&c2, Duration::from_millis(50)).await;
}

#[tokio::test]
async fn handle_msg_known_phases_forwarded() {
    let (relay, relay_sock) = setup().await;
    let (c1, a1) = client().await;
    let (c2, a2) = client().await;
    let room = unique_room("msg-known-phase");
    register_client(&relay, &relay_sock, &c1, a1, &room).await;
    register_client(&relay, &relay_sock, &c2, a2, &room).await;

    inject(
        &relay,
        &relay_sock,
        &format!("MSG {room} spake2 aabb\n"),
        a1,
    )
    .await;
    let msg = read_line(&c2, Duration::from_millis(500))
        .await
        .expect("MSGD spake2");
    assert!(msg.starts_with("MSGD spake2 "), "got {msg:?}");

    inject(
        &relay,
        &relay_sock,
        &format!("MSG {room} confirm aabb\n"),
        a1,
    )
    .await;
    let msg = read_line(&c2, Duration::from_millis(500))
        .await
        .expect("MSGD confirm");
    assert!(msg.starts_with("MSGD confirm "), "got {msg:?}");
}

#[tokio::test]
async fn handle_msg_nil_resolved_addr() {
    let (relay, relay_sock) = setup().await;
    let (c1, a1) = client().await;
    let (c2, a2) = client().await;
    let room = unique_room("msg-nil-addr");
    register_client(&relay, &relay_sock, &c1, a1, &room).await;
    register_client(&relay, &relay_sock, &c2, a2, &room).await;

    relay.set_client_resolved_addr(&room, &a1.to_string(), None);

    inject(
        &relay,
        &relay_sock,
        &format!("MSG {room} spake2 deadbeef\n"),
        a2,
    )
    .await;
    expect_no_line(&c1, Duration::from_millis(100)).await;
}

/// statMsgs counts only messages that were actually relayed.
#[tokio::test]
async fn stat_msgs_only_when_relayed() {
    let (relay, relay_sock) = setup().await;
    let (c1, a1) = client().await;
    let (c2, a2) = client().await;
    let room = unique_room("stat-msgs");
    register_client(&relay, &relay_sock, &c1, a1, &room).await;

    // Zero targets (sender is the only client): not counted as relayed.
    inject(
        &relay,
        &relay_sock,
        &format!("MSG {room} spake2 aabb\n"),
        a1,
    )
    .await;
    assert_eq!(relay.stats().msgs, 0, "zero-target MSG counted");

    // A second client joins: the next MSG has one target and is counted.
    register_client(&relay, &relay_sock, &c2, a2, &room).await;
    inject(
        &relay,
        &relay_sock,
        &format!("MSG {room} spake2 aabb\n"),
        a1,
    )
    .await;
    assert_eq!(relay.stats().msgs, 1, "relayed MSG not counted");
    let _ = read_line(&c2, Duration::from_millis(500)).await;
}

#[tokio::test]
async fn handle_reg_no_queued_messages_on_join() {
    let (relay, relay_sock) = setup().await;
    let (c1, a1) = client().await;
    let (c2, a2) = client().await;
    let room = unique_room("reg-noqueue");

    // c1 challenges (room not created), then sends a MSG that is dropped
    // (room unknown, c1 unadmitted).
    inject(&relay, &relay_sock, &format!("REG {room}\n"), a1).await;
    let _ = read_line(&c1, Duration::from_millis(500)).await;

    inject(
        &relay,
        &relay_sock,
        &format!("MSG {room} spake2 aabb\n"),
        a1,
    )
    .await;

    inject(&relay, &relay_sock, &format!("REG {room}\n"), a2).await;
    let reg_resp = read_line(&c2, Duration::from_millis(500))
        .await
        .expect("REGD");
    assert!(
        reg_resp.starts_with("REGD "),
        "expected REGD, got {reg_resp:?}"
    );

    expect_no_line(&c2, Duration::from_millis(100)).await;
}

#[tokio::test]
async fn handle_packet_concurrent_reg_and_msg() {
    let (relay, relay_sock) = setup().await;
    let (c1, a1) = client().await;
    let (c2, a2) = client().await;
    let room = unique_room("concurrent-reg-msg");
    register_client(&relay, &relay_sock, &c1, a1, &room).await;
    register_client(&relay, &relay_sock, &c2, a2, &room).await;

    // tokio 1.53 removed `UdpSocket::try_clone`, so both sides share the
    // relay socket by reference, interleaved via `tokio::join!` (same
    // concurrency semantics as the Go test, minus real goroutines).
    tokio::join!(
        async {
            for i in 0..5u8 {
                relay
                    .handle_packet(
                        &relay_sock,
                        format!("MSG {room} spake2 {i:02x}\n").as_bytes(),
                        a1,
                    )
                    .await;
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        },
        async {
            for i in 0..5u8 {
                relay
                    .handle_packet(
                        &relay_sock,
                        format!("MSG {room} confirm {i:02x}\n").as_bytes(),
                        a2,
                    )
                    .await;
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        },
    );

    let mut received = 0;
    while read_line(&c1, Duration::from_millis(100)).await.is_some() {
        received += 1;
    }
    while read_line(&c2, Duration::from_millis(100)).await.is_some() {
        received += 1;
    }
    assert!(received > 0, "expected at least some messages");
}

// ---------------------------------------------------------------------------
// Cleanup / eviction

#[test]
fn evict_stale_rooms_direct_call() {
    let relay = Relay::new();
    let room = unique_room("evict-direct");
    let stale = Instant::now() - Duration::from_secs(120); // 2x reg TTL
    insert_room_with_client(&relay, &room, "1.2.3.4:5678", stale, stale);
    relay.set_total_rooms(1);

    run_cleanup_pass(&relay);

    assert!(
        relay.get_room_for_test(&room).is_none(),
        "stale room not evicted"
    );
    assert_eq!(relay.total_rooms(), 0, "totalRooms not decremented");
}

#[test]
fn cleanup_evicts_stale_rooms() {
    let relay = Relay::new();
    let room = unique_room("cleanup-test");
    let stale = Instant::now() - Duration::from_secs(120); // 2x reg TTL
    insert_room_with_client(&relay, &room, "127.0.0.1:12345", stale, stale);

    run_cleanup_pass(&relay);

    assert!(
        relay.get_room_for_test(&room).is_none(),
        "stale room should be evicted"
    );
}

#[test]
fn cleanup_keeps_active_rooms() {
    let relay = Relay::new();
    let room = unique_room("cleanup-active");
    let now = Instant::now();
    insert_room_with_client(&relay, &room, "127.0.0.1:12345", now, now);

    run_cleanup_pass(&relay);

    assert!(
        relay.get_room_for_test(&room).is_some(),
        "active room should not be evicted"
    );
}

#[test]
fn cleanup_live() {
    let relay = Relay::new();
    relay.set_reg_ttl(Duration::from_millis(50));
    let room = unique_room("cleanup-live");
    let stale = Instant::now() - Duration::from_millis(100);
    insert_room_with_client(&relay, &room, "1.2.3.4:5678", stale, stale);
    relay.set_total_rooms(1);

    run_cleanup_pass(&relay);

    assert!(
        relay.get_room_for_test(&room).is_none(),
        "stale room should be evicted by cleanup"
    );
}

// ---------------------------------------------------------------------------
// writeRelay

#[tokio::test]
async fn write_relay_direct() {
    let relay = Arc::new(Relay::new());
    let relay_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let (client_sock, client_addr) = client().await;

    let msg = b"test message\n";
    relay
        .write_relay(&relay_sock, msg, client_addr)
        .await
        .expect("write_relay");

    let mut buf = [0u8; READ_BUF_SIZE];
    let (n, _src) =
        tokio::time::timeout(Duration::from_millis(500), client_sock.recv_from(&mut buf))
            .await
            .expect("recv")
            .expect("recv ok");
    assert_eq!(&buf[..n], msg);
}
