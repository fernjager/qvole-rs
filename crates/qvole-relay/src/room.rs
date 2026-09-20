//! Port of `relay/room.go`: room state, sharding, rate limiting, pending
//! (pre-cookie) registrations, per-IP accounting, and validation helpers.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// Number of room shards (Go `numShards`).
pub const NUM_SHARDS: usize = 16;
/// Number of REG rate-limit shards (Go `numRegShards`).
pub const NUM_REG_SHARDS: usize = 16;
/// Maximum room name length in bytes (Go `maxRoomNameLen`).
pub const MAX_ROOM_NAME_LEN: usize = 64;
/// Maximum accepted inbound datagram size (Go `maxDatagramLen`).
pub const MAX_DATAGRAM_LEN: usize = 1400;
/// TTL for pending (pre-cookie) registrations (Go `pendingRegTTL`).
pub const PENDING_REG_TTL_MS: u64 = 5_000;
/// Cookie size in bytes (Go `pendingCookieBytes`).
pub const PENDING_COOKIE_BYTES: usize = 16;
/// Hard cap on REG rate-limit map entries per shard (Go `maxRegShardEntries`).
pub const MAX_REG_SHARD_ENTRIES: usize = 100_000;

/// Port of `shardIdx`: FNV-1a 32-bit, matching Go's `hash/fnv` New32a.
pub fn fnv1a32(key: &str) -> u32 {
    let mut h: u32 = 0x811c_9dc5;
    for b in key.as_bytes() {
        h ^= u32::from(*b);
        h = h.wrapping_mul(0x0100_0193);
    }
    h
}

pub fn shard_idx(key: &str, n: usize) -> usize {
    (fnv1a32(key) % n as u32) as usize
}

/// Port of `ipKey`: the IP part of `src`, canonicalized so textual variants
/// of the same IP collapse to a single key.
pub fn ip_key(src: SocketAddr) -> IpAddr {
    // SocketAddr already carries the parsed IP; the only divergence from
    // Go's net.ParseIP(...).String() is IPv4-mapped IPv6, which Go renders
    // in dotted-quad form.
    match src {
        SocketAddr::V4(v) => IpAddr::V4(*v.ip()),
        SocketAddr::V6(v) => match v.ip().to_ipv4_mapped() {
            Some(v4) => IpAddr::V4(v4),
            None => IpAddr::V6(*v.ip()),
        },
    }
}

/// Port of `validRoomName`: non-empty, at most [`MAX_ROOM_NAME_LEN`] bytes,
/// every character in the printable ASCII range 33..=126.
///
/// Byte-oriented like the Go `[]byte` handling: any multi-byte UTF-8 or
/// invalid sequence contains a byte >= 0x80 and is rejected, exactly as the
/// Go rune loop rejects runes > 126 (including U+FFFD for invalid UTF-8).
pub fn valid_room_name(room: &[u8]) -> bool {
    if room.is_empty() || room.len() > MAX_ROOM_NAME_LEN {
        return false;
    }
    room.iter().all(|c| (33..=126).contains(c))
}

/// Port of `isValidHex`: non-empty, even length, hex characters only.
pub fn is_valid_hex(s: &[u8]) -> bool {
    if s.is_empty() || !s.len().is_multiple_of(2) {
        return false;
    }
    s.iter().all(|b| b.is_ascii_hexdigit())
}

/// Port of Go's `bytes.TrimSpace`: trims ASCII whitespace
/// (tab, LF, VT, FF, CR, space) from both ends.
pub fn trim_ascii_space(b: &[u8]) -> &[u8] {
    const WS: &[u8] = b"\t\n\x0b\x0c\r ";
    let start = b.iter().position(|c| !WS.contains(c)).unwrap_or(b.len());
    let end = b
        .iter()
        .rposition(|c| !WS.contains(c))
        .map(|i| i + 1)
        .unwrap_or(start);
    &b[start..end]
}

/// Port of `rateLimiter` + `isLimited`.
///
/// Callers must hold the owning room entry's lock (Go holds entry.mu).
#[derive(Debug)]
pub struct RateLimiter {
    pub msg_count: u32,
    pub window_start: Instant,
}

impl Default for RateLimiter {
    fn default() -> Self {
        Self {
            msg_count: 0,
            window_start: Instant::now(),
        }
    }
}

impl RateLimiter {
    pub fn new() -> Self {
        Self::default()
    }

    /// Port of `(*rateLimiter).isLimited`.
    pub fn is_limited(&mut self, rate_window: Duration, max_msg_rate: u32) -> bool {
        let now = Instant::now();
        if now.duration_since(self.window_start) > rate_window {
            self.msg_count = 0;
            self.window_start = now;
        }
        if self.msg_count >= max_msg_rate {
            return true;
        }
        self.msg_count += 1;
        false
    }
}

/// Port of `udpClient`.
#[derive(Debug)]
pub struct UdpClient {
    pub last_seen: Instant,
    pub rate_limiter: RateLimiter,
    pub resolved_addr: Option<SocketAddr>,
}

impl UdpClient {
    pub fn new(resolved_addr: Option<SocketAddr>) -> Self {
        let now = Instant::now();
        Self {
            last_seen: now,
            rate_limiter: RateLimiter::new(),
            resolved_addr,
        }
    }
}

/// Port of `pendingReg`: a return-routability cookie for a client that sent
/// REG but has not completed the cookie handshake.
#[derive(Debug, Clone)]
pub struct PendingReg {
    pub cookie: [u8; PENDING_COOKIE_BYTES],
    pub created_at: Instant,
    pub resolved_addr: SocketAddr,
}

/// Port of `roomEntry`.
#[derive(Debug)]
pub struct RoomEntry {
    pub udp_clients: HashMap<String, UdpClient>,
    pub pending: HashMap<String, PendingReg>,
    /// Per-IP in-room pending counts, maintained alongside `pending` so
    /// `pending_count_for_ip` is O(1) (Go `pendingByIP`).
    pub pending_by_ip: HashMap<IpAddr, usize>,
    pub t: Instant,
}

impl Default for RoomEntry {
    fn default() -> Self {
        Self::new()
    }
}

impl RoomEntry {
    pub fn new() -> Self {
        Self {
            udp_clients: HashMap::new(),
            pending: HashMap::new(),
            pending_by_ip: HashMap::new(),
            t: Instant::now(),
        }
    }

    /// Insert an in-room pending registration, keeping the per-IP count in
    /// sync (Go `(*roomEntry).addPending`).
    pub fn add_pending(&mut self, src: &str, p: PendingReg) {
        let ip = ip_key(src.parse().expect("pending source addr is valid"));
        if self.pending.insert(src.to_string(), p).is_none() {
            *self.pending_by_ip.entry(ip).or_insert(0) += 1;
        }
    }

    /// Remove an in-room pending registration, keeping the per-IP count in
    /// sync (Go `(*roomEntry).removePending`).
    pub fn remove_pending(&mut self, src: &str) -> Option<PendingReg> {
        let removed = self.pending.remove(src);
        if removed.is_some() {
            let ip = ip_key(src.parse().expect("pending source addr is valid"));
            if let Some(c) = self.pending_by_ip.get_mut(&ip) {
                *c = c.saturating_sub(1);
                if *c == 0 {
                    self.pending_by_ip.remove(&ip);
                }
            }
        }
        removed
    }

    /// Port of `(*roomEntry).pendingCountForIP`. Caller must hold the entry lock.
    ///
    /// O(1) via the maintained per-IP map.
    pub fn pending_count_for_ip(&self, ip: IpAddr) -> usize {
        self.pending_by_ip.get(&ip).copied().unwrap_or(0)
    }

    /// Port of `(*roomEntry).removeStaleClients`.
    ///
    /// Caller must hold the entry lock. Returns the `(ip, room)` pairs whose
    /// per-IP room link was dropped; the caller updates the IP count shards.
    pub fn remove_stale_clients(
        &mut self,
        room: &str,
        now: Instant,
        reg_ttl: Duration,
    ) -> Vec<(IpAddr, String)> {
        let mut unlinked = Vec::new();
        let stale: Vec<String> = self
            .udp_clients
            .iter()
            .filter(|(_, info)| now.duration_since(info.last_seen) > reg_ttl)
            .map(|(addr, _)| addr.clone())
            .collect();
        for addr in &stale {
            let ip = ip_key(addr.parse().expect("stored addr is valid"));
            let still_in_room = self.udp_clients.keys().any(|other| {
                other != addr && ip_key(other.parse().expect("stored addr is valid")) == ip
            });
            if !still_in_room {
                unlinked.push((ip, room.to_string()));
            }
        }
        for addr in stale {
            self.udp_clients.remove(&addr);
        }
        // Evict expired pending registrations (keeping per-IP counts in sync).
        let expired: Vec<String> = self
            .pending
            .iter()
            .filter(|(_, p)| {
                now.duration_since(p.created_at) > Duration::from_millis(PENDING_REG_TTL_MS)
            })
            .map(|(addr, _)| addr.clone())
            .collect();
        for addr in expired {
            self.remove_pending(&addr);
        }
        unlinked
    }
}

/// Port of `regLimitShard`: per-source REG rate limiting state.
#[derive(Debug, Default)]
pub struct RegShard {
    pub sent: HashMap<String, u32>,
    pub times: HashMap<String, Instant>,
}

impl RegShard {
    /// Port of `isRegRateLimited` (Go `room.go:292`).
    ///
    /// Go reuses the MSG rate settings (`maxMsgRate`, `rateWindow`) for REG
    /// admission. Key is the canonical IP string.
    pub fn is_limited(&mut self, src: &str, rate_window: Duration, max_rate: u32) -> bool {
        let now = Instant::now();
        match self.times.get(src) {
            None => {
                if self.times.len() >= MAX_REG_SHARD_ENTRIES {
                    // Map is at the hard cap (flood). Rate-limit new entries.
                    return true;
                }
                self.sent.insert(src.to_string(), 1);
                self.times.insert(src.to_string(), now);
                false
            }
            Some(reset) => {
                if now.duration_since(*reset) > rate_window {
                    self.sent.insert(src.to_string(), 1);
                    self.times.insert(src.to_string(), now);
                    false
                } else {
                    let count = self.sent.entry(src.to_string()).or_insert(0);
                    if *count >= max_rate {
                        return true;
                    }
                    *count += 1;
                    false
                }
            }
        }
    }

    /// Port of `(*regLimitShard).cleanupStale`.
    pub fn cleanup_stale(&mut self, max_age: Duration) {
        let now = Instant::now();
        self.times.retain(|src, t| {
            if now.duration_since(*t) > max_age {
                self.sent.remove(src);
                false
            } else {
                true
            }
        });
        if self.sent.len() > MAX_REG_SHARD_ENTRIES {
            self.sent.clear();
        }
        if self.times.len() > MAX_REG_SHARD_ENTRIES {
            self.times.clear();
        }
    }
}

/// Port of `ipRateLimiter`: per-IP rate limiting for drop log lines.
#[derive(Debug, Default)]
pub struct DropLogLimiter {
    last: HashMap<String, Instant>,
}

impl DropLogLimiter {
    pub fn new() -> Self {
        Self {
            last: HashMap::new(),
        }
    }

    /// Port of `(*ipRateLimiter).allow`.
    pub fn allow(&mut self, ip: &str, interval: Duration) -> bool {
        let now = Instant::now();
        if let Some(last) = self.last.get(ip)
            && now.duration_since(*last) < interval
        {
            return false;
        }
        self.last.insert(ip.to_string(), now);
        true
    }

    /// Port of `(*ipRateLimiter).cleanupStale`.
    pub fn cleanup_stale(&mut self, max_age: Duration) {
        let now = Instant::now();
        self.last
            .retain(|_, last| now.duration_since(*last) <= max_age);
    }
}

/// Actions a REG handler may require after releasing all locks.
/// Mirrors the Go handler's terminal `sendREGD` / `sendRegChallenge` calls.
#[derive(Debug, PartialEq, Clone)]
pub enum RegAction {
    /// Send `REGD <room> OK <src>\n` to the client.
    Regd,
    /// Send a `REGD <room> <cookie-hex>\n` challenge.
    Challenge([u8; PENDING_COOKIE_BYTES]),
    /// No reply (packet dropped or rate limited).
    None,
}

/// Port of `evictStaleRooms`.
///
/// `rooms` must be the shard's room map **already locked by the caller**
/// (Go's `evictStaleRooms` does not take the shard lock itself).
/// Returns `(evicted_count, unlinked_ip_room_pairs)`; the caller applies the
/// unlinks to the IP count shards.
pub fn evict_stale_rooms(
    rooms: &mut HashMap<String, Arc<Mutex<RoomEntry>>>,
    now: Instant,
    reg_ttl: Duration,
) -> (usize, Vec<(IpAddr, String)>) {
    let mut unlinked_all = Vec::new();
    let to_remove: Vec<String> = rooms
        .iter()
        .filter_map(|(room, arc)| {
            let mut entry = arc.lock().expect("room entry poisoned");
            unlinked_all.extend(entry.remove_stale_clients(room, now, reg_ttl));
            let empty = entry.udp_clients.is_empty();
            let stale = now.duration_since(entry.t) > reg_ttl;
            if empty && stale {
                Some(room.clone())
            } else {
                None
            }
        })
        .collect();
    for room in &to_remove {
        rooms.remove(room);
    }
    (to_remove.len(), unlinked_all)
}
