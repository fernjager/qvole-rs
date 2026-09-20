//! Port of `relay/relay.go`: the UDP relay server.
//!
//! Wire protocol:
//! - `REG {room}\n` -> `REGD {room} {cookie-hex}\n` -> `REG {room} {cookie}\n`
//!   -> `REGD {room} OK {src}\n`
//! - `MSG {room} {phase} {hex-body}\n` -> `MSGD {phase} {hex-body}\n` to each
//!   other registered client.

use std::collections::{HashMap, HashSet};
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use flume::bounded;
use qvole_protocol::env::{env_duration_ms, env_int};
use qvole_protocol::logger::{LOG_RELAY, bold};
use rand::RngCore;
use tokio::net::UdpSocket;
use tokio_util::sync::CancellationToken;

use crate::room::{
    DropLogLimiter, MAX_DATAGRAM_LEN, NUM_REG_SHARDS, NUM_SHARDS, PENDING_COOKIE_BYTES, PendingReg,
    RegAction, RegShard, RoomEntry, UdpClient, evict_stale_rooms, ip_key, is_valid_hex, shard_idx,
    trim_ascii_space, valid_room_name,
};

/// Inbound read buffer size (Go `readBufSize`).
pub const READ_BUF_SIZE: usize = 1500;
/// Command prefix length (Go `cmdPrefixLen`).
const CMD_PREFIX_LEN: usize = 4;
/// Max datagram bytes quoted in unknown-type logs (Go `unknownTypeMaxLogLen`).
const UNKNOWN_TYPE_MAX_LOG_LEN: usize = 40;
/// Max MSG body length in hex chars, 512 bytes (Go `maxMSGBodyLen`).
const MAX_MSG_BODY_LEN: usize = 1024;
/// Per-IP log throttle for drop lines (Go `dropLogInterval`).
const DROP_LOG_INTERVAL: Duration = Duration::from_secs(1);
/// REG rate-limit map cleanup interval (Go `rateMapCleanupInterval`).
const RATE_MAP_CLEANUP_INTERVAL: Duration = Duration::from_secs(5);

const DEFAULT_PKT_CHAN_BUF: i64 = 256;
const DEFAULT_WRITE_POOL_SIZE: i64 = 256;
const DEFAULT_RELAY_STATS_INTERVAL_MS: u64 = 5 * 60 * 1000;
const DEFAULT_WRITE_DEADLINE_MS: u64 = 500;
const DEFAULT_MAX_ROOMS: i64 = 10_000;
const DEFAULT_MAX_ROOMS_PER_IP: i64 = 10;
const DEFAULT_MAX_MSG_RATE: i64 = 10;
const DEFAULT_RATE_WINDOW_MS: u64 = 1000;
const DEFAULT_REG_CLEANUP_INTERVAL_MS: u64 = 60_000;
const DEFAULT_REG_TTL_MS: u64 = 60_000;
const DEFAULT_RELAY_WORKERS: i64 = 4;
const DEFAULT_MAX_CLIENTS_HARD: i64 = 20;
const DEFAULT_MAX_PENDING_PER_IP: i64 = 50;
/// Dedicated REG admission rate per IP per window.
const DEFAULT_REG_RATE: i64 = 10;
/// Global cap on pre-cookie pending registrations.
const DEFAULT_MAX_PENDING_GLOBAL: i64 = 65_536;

/// Relay configuration (Go: package globals initialized in `init()`).
#[derive(Debug, Clone)]
pub struct Config {
    pub pkt_chan_buf: usize,
    pub write_pool_size: usize,
    pub relay_stats_interval: Duration,
    pub write_deadline: Duration,
    pub max_rooms: i64,
    pub max_rooms_per_ip: i64,
    pub max_msg_rate: i64,
    /// Dedicated REG admission rate (Go `maxRegRate` + `QVOLE_RELAY_REG_RATE`).
    pub max_reg_rate: i64,
    pub rate_window: Duration,
    pub reg_cleanup_interval: Duration,
    pub reg_ttl: Duration,
    pub relay_workers: usize,
    pub max_clients_hard: i64,
    pub max_pending_per_ip: i64,
    /// Global pre-cookie pending store bound (Go `maxPendingGlobal` +
    /// `QVOLE_RELAY_MAX_PENDING`).
    pub max_pending_global: i64,
}

impl Default for Config {
    fn default() -> Self {
        Self::from_env()
    }
}

impl Config {
    /// Pure defaults (Go: the `default*` constants), no environment lookup.
    pub fn defaults() -> Self {
        Self {
            pkt_chan_buf: DEFAULT_PKT_CHAN_BUF as usize,
            write_pool_size: DEFAULT_WRITE_POOL_SIZE as usize,
            relay_stats_interval: Duration::from_millis(DEFAULT_RELAY_STATS_INTERVAL_MS),
            write_deadline: Duration::from_millis(DEFAULT_WRITE_DEADLINE_MS),
            max_rooms: DEFAULT_MAX_ROOMS,
            max_rooms_per_ip: DEFAULT_MAX_ROOMS_PER_IP,
            max_msg_rate: DEFAULT_MAX_MSG_RATE,
            max_reg_rate: DEFAULT_REG_RATE,
            rate_window: Duration::from_millis(DEFAULT_RATE_WINDOW_MS),
            reg_cleanup_interval: Duration::from_millis(DEFAULT_REG_CLEANUP_INTERVAL_MS),
            reg_ttl: Duration::from_millis(DEFAULT_REG_TTL_MS),
            relay_workers: DEFAULT_RELAY_WORKERS as usize,
            max_clients_hard: DEFAULT_MAX_CLIENTS_HARD,
            max_pending_per_ip: DEFAULT_MAX_PENDING_PER_IP,
            max_pending_global: DEFAULT_MAX_PENDING_GLOBAL,
        }
    }

    /// Port of the Go `init()` env handling: defaults unless overridden by
    /// `QVOLE_RELAY_*` environment variables.
    pub fn from_env() -> Self {
        let d = Self::defaults();
        Self {
            pkt_chan_buf: env_int("QVOLE_RELAY_PKT_CHAN_BUF", d.pkt_chan_buf as i64) as usize,
            write_pool_size: env_int("QVOLE_RELAY_WRITE_POOL", d.write_pool_size as i64) as usize,
            relay_stats_interval: Duration::from_millis(env_duration_ms(
                "QVOLE_RELAY_STATS_INTERVAL_MS",
                d.relay_stats_interval.as_millis() as u64,
            )),
            write_deadline: Duration::from_millis(env_duration_ms(
                "QVOLE_RELAY_WRITE_DEADLINE_MS",
                d.write_deadline.as_millis() as u64,
            )),
            max_rooms: env_int("QVOLE_RELAY_MAX_ROOMS", d.max_rooms),
            max_rooms_per_ip: env_int("QVOLE_RELAY_MAX_ROOMS_PER_IP", d.max_rooms_per_ip),
            max_msg_rate: env_int("QVOLE_RELAY_MSG_RATE", d.max_msg_rate),
            max_reg_rate: env_int("QVOLE_RELAY_REG_RATE", d.max_reg_rate),
            rate_window: Duration::from_millis(env_duration_ms(
                "QVOLE_RELAY_RATE_WINDOW_MS",
                d.rate_window.as_millis() as u64,
            )),
            reg_cleanup_interval: Duration::from_millis(env_duration_ms(
                "QVOLE_RELAY_CLEANUP_INTERVAL_MS",
                d.reg_cleanup_interval.as_millis() as u64,
            )),
            reg_ttl: Duration::from_millis(env_duration_ms(
                "QVOLE_RELAY_TTL_MS",
                d.reg_ttl.as_millis() as u64,
            )),
            relay_workers: env_int("QVOLE_RELAY_WORKERS", d.relay_workers as i64) as usize,
            max_clients_hard: env_int("QVOLE_RELAY_MAX_CLIENTS_HARD", d.max_clients_hard),
            max_pending_per_ip: env_int("QVOLE_RELAY_MAX_PENDING_PER_IP", d.max_pending_per_ip),
            max_pending_global: env_int("QVOLE_RELAY_MAX_PENDING", d.max_pending_global),
        }
    }
}

/// Counters reported by the periodic stats log (Go `statRegs/statMsgs/statDrops`).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct StatsSnapshot {
    pub regs: usize,
    pub msgs: usize,
    pub drops: usize,
}

/// The UDP relay server state (Go: package-level globals in `relay`).
pub struct Relay {
    cfg: Config,
    /// Room table sharded 16 ways (Go `shards`).
    shards: Vec<Mutex<HashMap<String, Arc<Mutex<RoomEntry>>>>>,
    /// REG rate-limit shards (Go `regShards`).
    reg_shards: Vec<Mutex<RegShard>>,
    /// Per-IP room link counts, sharded 16 ways (Go `ipCounts`).
    ip_counts: Vec<Mutex<HashMap<IpAddr, HashSet<String>>>>,
    /// Pre-cookie pending registrations for not-yet-existing rooms
    /// (Go `pendingRegs`), sharded 16 ways by room.
    pending_shards: Vec<Mutex<HashMap<String, HashMap<String, PendingReg>>>>,
    /// Per-IP pending counts across all rooms (Go `pendingIPShards`),
    /// maintained alongside the pending store so `pending_count_for_ip` is
    /// O(1) instead of O(total pending).
    pending_ip_shards: Vec<Mutex<HashMap<IpAddr, usize>>>,
    /// Global pending-store total (Go `pendingTotal`), bounding the store.
    pending_total: AtomicUsize,
    /// Per-IP throttle for drop log lines (Go `dropLogLimiter`).
    drop_log_limiter: Mutex<DropLogLimiter>,
    /// Total live rooms (Go `totalRoomCount`).
    total_room_count: AtomicUsize,
    stat_regs: AtomicUsize,
    stat_msgs: AtomicUsize,
    stat_drops: AtomicUsize,
    /// Config values that tests mutate directly (Go tests set the package
    /// globals); held atomically so a running relay sees the new values.
    max_rooms: AtomicUsize,
    max_rooms_per_ip: AtomicUsize,
    max_clients_hard: AtomicUsize,
    max_msg_rate: AtomicUsize,
    max_reg_rate: AtomicUsize,
    rate_window_ms: AtomicU64,
    reg_ttl_ms: AtomicU64,
    max_pending_per_ip: AtomicUsize,
    max_pending_global: AtomicUsize,
    /// Bounded outbound-write semaphore; `None` in tests (direct writes,
    /// mirroring Go's nil `writePool`), set by [`Relay::run`] in production.
    write_pool: OnceLock<Arc<tokio::sync::Semaphore>>,
}

type AtomicU64 = std::sync::atomic::AtomicU64;

impl Relay {
    /// Creates a relay with configuration from `QVOLE_RELAY_*` env vars
    /// (Go: `init()`).
    pub fn new() -> Self {
        Self::with_config(Config::default())
    }

    /// Creates a relay with an explicit configuration.
    pub fn with_config(cfg: Config) -> Self {
        let max_rooms = cfg.max_rooms as usize;
        let max_rooms_per_ip = cfg.max_rooms_per_ip as usize;
        let max_clients_hard = cfg.max_clients_hard as usize;
        let max_msg_rate = cfg.max_msg_rate as usize;
        let rate_window_ms = cfg.rate_window.as_millis() as u64;
        let reg_ttl_ms = cfg.reg_ttl.as_millis() as u64;
        let max_pending_per_ip = cfg.max_pending_per_ip as usize;
        let max_reg_rate = cfg.max_reg_rate as usize;
        let max_pending_global = cfg.max_pending_global as usize;
        Self {
            cfg,
            shards: (0..NUM_SHARDS)
                .map(|_| Mutex::new(HashMap::new()))
                .collect(),
            reg_shards: (0..NUM_REG_SHARDS)
                .map(|_| Mutex::new(RegShard::default()))
                .collect(),
            ip_counts: (0..NUM_SHARDS)
                .map(|_| Mutex::new(HashMap::new()))
                .collect(),
            pending_shards: (0..NUM_SHARDS)
                .map(|_| Mutex::new(HashMap::new()))
                .collect(),
            pending_ip_shards: (0..NUM_SHARDS)
                .map(|_| Mutex::new(HashMap::new()))
                .collect(),
            pending_total: AtomicUsize::new(0),
            drop_log_limiter: Mutex::new(DropLogLimiter::new()),
            total_room_count: AtomicUsize::new(0),
            stat_regs: AtomicUsize::new(0),
            stat_msgs: AtomicUsize::new(0),
            stat_drops: AtomicUsize::new(0),
            max_rooms: AtomicUsize::new(max_rooms),
            max_rooms_per_ip: AtomicUsize::new(max_rooms_per_ip),
            max_clients_hard: AtomicUsize::new(max_clients_hard),
            max_msg_rate: AtomicUsize::new(max_msg_rate),
            max_reg_rate: AtomicUsize::new(max_reg_rate),
            rate_window_ms: AtomicU64::new(rate_window_ms),
            reg_ttl_ms: AtomicU64::new(reg_ttl_ms),
            max_pending_per_ip: AtomicUsize::new(max_pending_per_ip),
            max_pending_global: AtomicUsize::new(max_pending_global),
            write_pool: OnceLock::new(),
        }
    }

    // --- config accessors (live values; tests mutate the atomics) ---

    fn max_rooms(&self) -> usize {
        self.max_rooms.load(Ordering::Relaxed)
    }
    fn max_rooms_per_ip(&self) -> usize {
        self.max_rooms_per_ip.load(Ordering::Relaxed)
    }
    fn max_clients_hard(&self) -> usize {
        self.max_clients_hard.load(Ordering::Relaxed)
    }
    fn max_msg_rate(&self) -> u32 {
        self.max_msg_rate.load(Ordering::Relaxed) as u32
    }
    fn max_reg_rate(&self) -> u32 {
        self.max_reg_rate.load(Ordering::Relaxed) as u32
    }
    fn rate_window(&self) -> Duration {
        Duration::from_millis(self.rate_window_ms.load(Ordering::Relaxed))
    }
    fn reg_ttl(&self) -> Duration {
        Duration::from_millis(self.reg_ttl_ms.load(Ordering::Relaxed))
    }
    fn max_pending_per_ip(&self) -> usize {
        self.max_pending_per_ip.load(Ordering::Relaxed)
    }
    fn max_pending_global(&self) -> usize {
        self.max_pending_global.load(Ordering::Relaxed)
    }

    /// Total live rooms (Go `totalRooms()`).
    pub fn total_rooms(&self) -> usize {
        self.total_room_count.load(Ordering::Relaxed)
    }

    /// Total admitted clients across all rooms (Go `totalClients()`).
    pub fn total_clients(&self) -> usize {
        let mut n = 0;
        for shard in &self.shards {
            let g = shard.lock().expect("room shard poisoned");
            for arc in g.values() {
                let e = arc.lock().expect("room entry poisoned");
                n += e.udp_clients.len();
            }
        }
        n
    }

    /// Snapshot of the REG/MSG/drop counters (Go `statRegs/statMsgs/statDrops`).
    pub fn stats(&self) -> StatsSnapshot {
        StatsSnapshot {
            regs: self.stat_regs.load(Ordering::Relaxed),
            msgs: self.stat_msgs.load(Ordering::Relaxed),
            drops: self.stat_drops.load(Ordering::Relaxed),
        }
    }

    // --- IP count shards (Go `addIPRoom`/`removeIPRoom`/`countIPRooms`) ---

    fn add_ip_room(&self, ip: IpAddr, room: &str) {
        let mut g = self.ip_counts[shard_idx(&ip.to_string(), NUM_SHARDS)]
            .lock()
            .expect("ip count shard poisoned");
        g.entry(ip).or_default().insert(room.to_string());
    }

    fn remove_ip_room(&self, ip: IpAddr, room: &str) {
        let mut g = self.ip_counts[shard_idx(&ip.to_string(), NUM_SHARDS)]
            .lock()
            .expect("ip count shard poisoned");
        if let Some(set) = g.get_mut(&ip) {
            set.remove(room);
            if set.is_empty() {
                g.remove(&ip);
            }
        }
    }

    /// Number of distinct rooms the IP is linked to (Go `countIPRooms`).
    pub fn count_ip_rooms(&self, ip: IpAddr) -> usize {
        let g = self.ip_counts[shard_idx(&ip.to_string(), NUM_SHARDS)]
            .lock()
            .expect("ip count shard poisoned");
        g.get(&ip).map(|s| s.len()).unwrap_or(0)
    }

    // --- Global pending store (Go `storePendingReg` & co.) ---

    fn get_pending_reg(&self, room: &str, src: &str) -> Option<PendingReg> {
        let g = self.pending_shards[shard_idx(room, NUM_SHARDS)]
            .lock()
            .expect("pending shard poisoned");
        g.get(room).and_then(|rm| rm.get(src)).cloned()
    }

    /// Store a pre-cookie pending registration.
    ///
    /// Returns `false` when the global pending store is full and the entry is
    /// new (Go `storePendingReg`). Replacing an existing key
    /// never fails and never changes the counters.
    ///
    /// The per-IP counter is incremented only when a new key is inserted, so
    /// `pending_count_for_ip` stays O(1) and accurate.
    fn store_pending_reg(&self, room: &str, src: &str, p: PendingReg) -> bool {
        let mut g = self.pending_shards[shard_idx(room, NUM_SHARDS)]
            .lock()
            .expect("pending shard poisoned");
        // Replacing an existing key never fails and never changes counters.
        if let Some(rm) = g.get_mut(room)
            && rm.contains_key(src)
        {
            rm.insert(src.to_string(), p);
            return true;
        }
        if self.pending_total.load(Ordering::Relaxed) >= self.max_pending_global() {
            return false;
        }
        g.entry(room.to_string())
            .or_default()
            .insert(src.to_string(), p);
        self.pending_total.fetch_add(1, Ordering::Relaxed);
        self.add_pending_ip(ip_key(src.parse().expect("pending source addr is valid")));
        true
    }

    fn delete_pending_reg(&self, room: &str, src: &str) {
        let mut g = self.pending_shards[shard_idx(room, NUM_SHARDS)]
            .lock()
            .expect("pending shard poisoned");
        if let Some(rm) = g.get_mut(room) {
            if rm.remove(src).is_some() {
                self.pending_total.fetch_sub(1, Ordering::Relaxed);
                self.remove_pending_ip(ip_key(src.parse().expect("pending source addr is valid")));
            }
            if rm.is_empty() {
                g.remove(room);
            }
        }
    }

    /// Increment the per-IP pending counter (Go `pendingIPShards` update).
    fn add_pending_ip(&self, ip: IpAddr) {
        let mut g = self.pending_ip_shards[shard_idx(&ip.to_string(), NUM_SHARDS)]
            .lock()
            .expect("pending ip shard poisoned");
        *g.entry(ip).or_insert(0) += 1;
    }

    /// Decrement the per-IP pending counter, dropping the key at zero.
    fn remove_pending_ip(&self, ip: IpAddr) {
        let mut g = self.pending_ip_shards[shard_idx(&ip.to_string(), NUM_SHARDS)]
            .lock()
            .expect("pending ip shard poisoned");
        if let Some(c) = g.get_mut(&ip) {
            *c = c.saturating_sub(1);
            if *c == 0 {
                g.remove(&ip);
            }
        }
    }

    /// Pending registrations across all rooms for the IP (Go `countPendingForIP`).
    ///
    /// O(1): reads the maintained per-IP counter.
    pub fn pending_count_for_ip(&self, ip: IpAddr) -> usize {
        let g = self.pending_ip_shards[shard_idx(&ip.to_string(), NUM_SHARDS)]
            .lock()
            .expect("pending ip shard poisoned");
        g.get(&ip).copied().unwrap_or(0)
    }

    /// Total pre-cookie pending registrations (Go `pendingTotal`); test/diagnostic.
    pub fn pending_total(&self) -> usize {
        self.pending_total.load(Ordering::Relaxed)
    }

    /// Evict pending registrations older than the TTL (Go `removeStalePendingRegs`).
    ///
    /// Keeps the global total and the per-IP counters in sync with the
    /// removals.
    fn remove_stale_pending_regs(&self, now: Instant) {
        let ttl = Duration::from_millis(crate::room::PENDING_REG_TTL_MS);
        let mut evicted_ips: Vec<IpAddr> = Vec::new();
        for sh in &self.pending_shards {
            let mut g = sh.lock().expect("pending shard poisoned");
            for rm in g.values_mut() {
                rm.retain(|src, p| {
                    let keep = now.duration_since(p.created_at) <= ttl;
                    if !keep {
                        evicted_ips
                            .push(ip_key(src.parse().expect("pending source addr is valid")));
                    }
                    keep
                });
            }
            g.retain(|_, rm| !rm.is_empty());
        }
        if !evicted_ips.is_empty() {
            self.pending_total
                .fetch_sub(evicted_ips.len(), Ordering::Relaxed);
            for ip in evicted_ips {
                self.remove_pending_ip(ip);
            }
        }
    }

    /// Evict stale rooms across **all** shards, locking one shard at a time.
    ///
    /// Never holds two shard locks at once: callers must not hold a shard
    /// lock when they call this, or two concurrent sweeps in different
    /// shards could deadlock. Returns the number of rooms evicted.
    fn evict_stale_rooms_all(&self, now: Instant) -> usize {
        let ttl = self.reg_ttl();
        let mut total = 0;
        for shard in &self.shards {
            let mut g = shard.lock().expect("room shard poisoned");
            let (n, unlinked) = evict_stale_rooms(&mut g, now, ttl);
            total += n;
            for (ip, r) in unlinked {
                self.remove_ip_room(ip, &r);
            }
        }
        if total > 0 {
            self.total_room_count.fetch_sub(total, Ordering::Relaxed);
        }
        total
    }

    // --- REG rate limiting (Go `isRegRateLimited`) ---

    fn is_reg_rate_limited(&self, key: &str) -> bool {
        let mut g = self.reg_shards[shard_idx(key, NUM_REG_SHARDS)]
            .lock()
            .expect("reg shard poisoned");
        // Dedicated REG knob, decoupled from QVOLE_RELAY_MSG_RATE.
        g.is_limited(key, self.rate_window(), self.max_reg_rate())
    }

    // --- drop / write paths (Go `dropPacket`/`writeRelay`/`sendREGD`) ---

    /// Port of `dropPacket`: always counts the drop; log line is throttled
    /// per source IP to one per second.
    fn drop_packet(&self, src: SocketAddr, msg: &str) {
        self.stat_drops.fetch_add(1, Ordering::Relaxed);
        let ip = ip_key(src).to_string();
        let mut lim = self.drop_log_limiter.lock().expect("drop limiter poisoned");
        if !lim.allow(&ip, DROP_LOG_INTERVAL) {
            return;
        }
        LOG_RELAY.printf_warn(msg);
    }

    /// Env-gated trace logging: enabled when `QVOLE_RELAY_TRACE` is set.
    fn rtrace(msg: &str) {
        static ON: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
        if *ON.get_or_init(|| std::env::var_os("QVOLE_RELAY_TRACE").is_some()) {
            eprintln!("[rt] {msg}");
        }
    }

    /// Port of `writeRelay`. When the write pool is configured, a permit is
    /// acquired first; if the pool is full the write is dropped and counted
    /// (Go `WritePool` semantics: tryAcquire, drop on full). Note: tokio 1.53
    /// removed `UdpSocket::try_clone`, so the pool bounds in-flight writes in
    /// place instead of dispatching to a separate task pool (the relay
    /// workers themselves bound concurrency).
    async fn write_relay(&self, sock: &UdpSocket, msg: &[u8], addr: SocketAddr) -> io::Result<()> {
        let _permit = match self.write_pool.get() {
            Some(pool) => match pool.try_acquire() {
                Ok(p) => Some(p),
                Err(_) => {
                    self.stat_drops.fetch_add(1, Ordering::Relaxed);
                    return Ok(());
                }
            },
            None => None,
        };
        match tokio::time::timeout(self.cfg.write_deadline, sock.send_to(msg, addr)).await {
            Ok(Ok(_)) => Ok(()),
            Ok(Err(e)) => Err(e),
            Err(_) => Err(io::Error::new(
                io::ErrorKind::TimedOut,
                format!("write deadline {:?} exceeded", self.cfg.write_deadline),
            )),
        }
    }

    /// Port of `sendREGD`: `REGD {room} OK {src}\n`.
    async fn send_regd(&self, sock: &UdpSocket, room: &str, src: SocketAddr) {
        let msg = format!("REGD {room} OK {src}\n");
        Self::rtrace(&format!("REGD OK -> {src} room={room}"));
        if let Err(e) = self.write_relay(sock, msg.as_bytes(), src).await {
            LOG_RELAY.printf_warn(&format!("REGD write to {src} failed: {e}"));
        }
    }

    /// Port of `sendRegChallenge`: `REGD {room} {cookie-hex}\n`.
    async fn send_reg_challenge(
        &self,
        sock: &UdpSocket,
        room: &str,
        cookie: &[u8; PENDING_COOKIE_BYTES],
        src: SocketAddr,
    ) {
        let msg = format!("REGD {room} {}\n", to_hex_lower(cookie));
        Self::rtrace(&format!("REGD challenge -> {src} room={room}"));
        if let Err(e) = self.write_relay(sock, msg.as_bytes(), src).await {
            LOG_RELAY.printf_warn(&format!("REGD challenge write to {src} failed: {e}"));
        }
    }

    // --- packet dispatch (Go `HandlePacket`) ---

    /// Port of `HandlePacket`: dispatch one inbound datagram.
    pub async fn handle_packet(&self, sock: &UdpSocket, data: &[u8], src: SocketAddr) {
        if data.is_empty() || data.len() > MAX_DATAGRAM_LEN {
            self.drop_packet(
                src,
                &format!(
                    "Dropped oversized datagram ({} bytes) from {src}",
                    data.len()
                ),
            );
            return;
        }
        let trimmed = trim_ascii_space(data);
        if trimmed.len() >= CMD_PREFIX_LEN && trimmed.starts_with(b"REG ") {
            let rest = trim_ascii_space(&trimmed[CMD_PREFIX_LEN..]);
            // bytes.SplitN(rest, " ", 2)
            let mut split = rest.splitn(2, |&b| b == b' ');
            let (room, cookie) = match (split.next(), split.next()) {
                (Some(r), Some(c)) => (r, trim_ascii_space(c)),
                (Some(r), None) => (r, &b""[..]),
                _ => unreachable!(),
            };
            if room.is_empty() {
                self.drop_packet(src, &format!("Dropped REG with empty room from {src}"));
                return;
            }
            if !valid_room_name(room) {
                self.drop_packet(
                    src,
                    &format!(
                        "Dropped REG with invalid room {:?} from {src}",
                        String::from_utf8_lossy(room)
                    ),
                );
                return;
            }
            // Room name was validated as printable ASCII above, so this
            // cannot fail.
            let room_str = std::str::from_utf8(room).expect("valid room is ASCII");
            self.handle_reg(sock, room_str, cookie, src).await;
        } else if trimmed.len() >= CMD_PREFIX_LEN && trimmed.starts_with(b"MSG ") {
            self.handle_msg(sock, &trimmed[CMD_PREFIX_LEN..], src).await;
        } else {
            let end = trimmed.len().min(UNKNOWN_TYPE_MAX_LOG_LEN);
            self.drop_packet(
                src,
                &format!(
                    "Dropped unknown packet type from {src}: {:?}",
                    String::from_utf8_lossy(&trimmed[..end])
                ),
            );
        }
    }

    // --- REG handler (Go `handleReg`) ---

    async fn handle_reg(&self, sock: &UdpSocket, room: &str, cookie: &[u8], src: SocketAddr) {
        let src_str = src.to_string();
        Self::rtrace(&format!(
            "REG from {src_str} room={room} cookie={}",
            cookie.len() / 2
        ));
        let src_ip = ip_key(src);

        if !cookie.is_empty() {
            // Follow-up REG carrying a cookie.
            if !is_valid_hex(cookie) || cookie.len() != PENDING_COOKIE_BYTES * 2 {
                self.drop_packet(
                    src,
                    &format!("Dropped REG with invalid cookie from {src_str}"),
                );
                return;
            }
            let cookie_bytes = match hex_decode(cookie) {
                Some(c) => c,
                None => {
                    self.drop_packet(
                        src,
                        &format!("Dropped REG with invalid cookie hex from {src_str}"),
                    );
                    return;
                }
            };

            // Check the global pending store first; these are pre-cookie
            // registrations for rooms that don't exist yet.
            if let Some(pend) = self.get_pending_reg(room, &src_str) {
                if pend.cookie != cookie_bytes.as_slice() {
                    self.drop_packet(
                        src,
                        &format!(
                            "Dropped REG with mismatched cookie from {src_str} in room {room} (pending store)"
                        ),
                    );
                    return;
                }
                // Cookie matches. Remove from pending store and admit the
                // client, creating the room if necessary.
                self.delete_pending_reg(room, &src_str);
                if matches!(
                    self.reg_cookie_create_or_admit(
                        room,
                        &src_str,
                        src_ip,
                        pend.resolved_addr,
                        src
                    ),
                    RegAction::Regd
                ) {
                    self.send_regd(sock, room, src).await;
                }
                return;
            }

            // Not in the pending store; check existing rooms. Hold the shard
            // lock until the entry lock is acquired (shard -> entry order) so
            // evictStaleRooms cannot delete the entry in between.
            let shard = &self.shards[shard_idx(room, NUM_SHARDS)];
            let entry_arc = {
                let g = shard.lock().expect("room shard poisoned");
                g.get(room).cloned()
            };
            match entry_arc {
                None => {
                    // The pending registration expired or was evicted.
                    // Re-issue a fresh challenge instead of dropping.
                    if self.is_reg_rate_limited(&src.to_string()) {
                        self.drop_packet(src, &format!("Rate-limited REG from {src_str}"));
                        return;
                    }
                    if self.count_ip_rooms(src_ip) >= self.max_rooms_per_ip() {
                        self.drop_packet(src, &format!("Room limit per IP reached for {src_str}"));
                        return;
                    }
                    if self.pending_count_for_ip(src_ip) >= self.max_pending_per_ip() {
                        self.drop_packet(
                            src,
                            &format!("Pending limit per IP reached for {src_str}"),
                        );
                        return;
                    }
                    let cb = random_cookie();
                    if !self.store_pending_reg(
                        room,
                        &src_str,
                        PendingReg {
                            cookie: cb,
                            created_at: Instant::now(),
                            resolved_addr: src,
                        },
                    ) {
                        self.drop_packet(src, &format!("Pending store full for {src_str}"));
                        return;
                    }
                    self.send_reg_challenge(sock, room, &cb, src).await;
                    return;
                }
                Some(arc) => {
                    let action = {
                        let _g = shard.lock().expect("room shard poisoned");
                        let mut entry = arc.lock().expect("room entry poisoned");
                        // Clone the pending match so the entry can be mutated
                        // (stale-client eviction) while the lookup is live.
                        let matched = entry.pending.get(&src_str).cloned();
                        match matched {
                            None => {
                                self.drop_packet(
                                    src,
                                    &format!(
                                        "Dropped REG with mismatched cookie from {src_str} in room {room}"
                                    ),
                                );
                                RegAction::None
                            }
                            Some(pend) if pend.cookie != cookie_bytes.as_slice() => {
                                self.drop_packet(
                                    src,
                                    &format!(
                                        "Dropped REG with mismatched cookie from {src_str} in room {room}"
                                    ),
                                );
                                RegAction::None
                            }
                            Some(pend) => {
                                // Capture the resolved address before eviction
                                // can invalidate the matched pending entry.
                                let resolved = pend.resolved_addr;
                                // Evict stale clients before the cap checks so a
                                // valid cookie completion is not rejected because
                                // of long-idle clients.
                                for (ip, r) in
                                    entry.remove_stale_clients(room, Instant::now(), self.reg_ttl())
                                {
                                    self.remove_ip_room(ip, &r);
                                }
                                // Cookie matches; admit the client, re-checking caps.
                                let is_new = !entry.udp_clients.contains_key(&src_str);
                                let hard_cap =
                                    entry.udp_clients.len() >= self.max_clients_hard() && is_new;
                                let ip_capped = if is_new {
                                    let ip_already = entry.udp_clients.keys().any(|a| {
                                        ip_key(a.parse().expect("stored addr is valid")) == src_ip
                                    });
                                    !ip_already
                                        && self.count_ip_rooms(src_ip) >= self.max_rooms_per_ip()
                                } else {
                                    false
                                };
                                if hard_cap {
                                    self.drop_packet(
                                        src,
                                        &format!(
                                            "Room {room} at hard cap ({}), rejecting {src_str} (cookie admission)",
                                            self.max_clients_hard()
                                        ),
                                    );
                                    RegAction::None
                                } else if ip_capped {
                                    self.drop_packet(
                                        src,
                                        &format!(
                                            "Room limit per IP reached for {src_str} (cookie admission)"
                                        ),
                                    );
                                    RegAction::None
                                } else {
                                    // Admit (Go: unconditional after the cap
                                    // checks; re-admits already-admitted
                                    // clients, refreshing last_seen).
                                    entry.remove_pending(&src_str);
                                    entry
                                        .udp_clients
                                        .insert(src_str.clone(), UdpClient::new(Some(resolved)));
                                    entry.t = Instant::now();
                                    let ip_already = entry.udp_clients.keys().any(|a| {
                                        a != &src_str
                                            && ip_key(a.parse().expect("stored addr is valid"))
                                                == src_ip
                                    });
                                    if !ip_already {
                                        self.add_ip_room(src_ip, room);
                                    }
                                    self.stat_regs.fetch_add(1, Ordering::Relaxed);
                                    RegAction::Regd
                                }
                            }
                        }
                    };
                    if action == RegAction::Regd {
                        self.send_regd(sock, room, src).await;
                    }
                }
            }
            return;
        }

        // No cookie: initial REG. (Go keys the REG rate limit by the full
        // source string, not just the IP.)
        if self.is_reg_rate_limited(&src.to_string()) {
            self.drop_packet(src, &format!("Rate-limited REG from {src_str}"));
            return;
        }
        if self.count_ip_rooms(src_ip) >= self.max_rooms_per_ip() {
            self.drop_packet(src, &format!("Room limit per IP reached for {src_str}"));
            return;
        }

        let shard = &self.shards[shard_idx(room, NUM_SHARDS)];
        let entry_arc = {
            let g = shard.lock().expect("room shard poisoned");
            g.get(room).cloned()
        };
        match entry_arc {
            None => {
                // Room does not exist. Store a pending registration instead of
                // creating the room immediately (prevents room-table
                // exhaustion from spoofed source IPs).
                if self.pending_count_for_ip(src_ip) >= self.max_pending_per_ip() {
                    self.drop_packet(src, &format!("Pending limit per IP reached for {src_str}"));
                    return;
                }
                let cb = random_cookie();
                if !self.store_pending_reg(
                    room,
                    &src_str,
                    PendingReg {
                        cookie: cb,
                        created_at: Instant::now(),
                        resolved_addr: src,
                    },
                ) {
                    self.drop_packet(src, &format!("Pending store full for {src_str}"));
                    return;
                }
                self.send_reg_challenge(sock, room, &cb, src).await;
            }
            Some(arc) => {
                let action = {
                    let _g = shard.lock().expect("room shard poisoned");
                    let mut entry = arc.lock().expect("room entry poisoned");
                    for (ip, r) in entry.remove_stale_clients(room, Instant::now(), self.reg_ttl())
                    {
                        self.remove_ip_room(ip, &r);
                    }
                    // Check the hard cap. It counts admitted `udpClients`
                    // only; in-room pending is bounded separately by the
                    // per-IP pending cap below.
                    if entry.udp_clients.len() >= self.max_clients_hard()
                        && !entry.udp_clients.contains_key(&src_str)
                    {
                        self.drop_packet(
                            src,
                            &format!(
                                "Room {room} at hard cap ({}), rejecting {src_str}",
                                self.max_clients_hard()
                            ),
                        );
                        RegAction::None
                    } else if let Some(info) = entry.udp_clients.get_mut(&src_str) {
                        // Re-registration of an already-admitted client.
                        info.last_seen = Instant::now();
                        info.resolved_addr = Some(src);
                        self.stat_regs.fetch_add(1, Ordering::Relaxed);
                        RegAction::Regd
                    } else if let Some(pend) = entry.pending.get_mut(&src_str) {
                        // Existing pending registration; re-issue the same cookie.
                        pend.created_at = Instant::now();
                        pend.resolved_addr = src;
                        let cb = pend.cookie;
                        RegAction::Challenge(cb)
                    } else {
                        // Fresh pending registration. Enforce the per-IP
                        // pending cap counting this room's pending map too.
                        if self.pending_count_for_ip(src_ip) + entry.pending_count_for_ip(src_ip)
                            >= self.max_pending_per_ip()
                        {
                            self.drop_packet(
                                src,
                                &format!("Pending limit per IP reached for {src_str}"),
                            );
                            RegAction::None
                        } else {
                            let cb = random_cookie();
                            entry.add_pending(
                                &src_str,
                                PendingReg {
                                    cookie: cb,
                                    created_at: Instant::now(),
                                    resolved_addr: src,
                                },
                            );
                            RegAction::Challenge(cb)
                        }
                    }
                };
                match action {
                    RegAction::Regd => self.send_regd(sock, room, src).await,
                    RegAction::Challenge(c) => self.send_reg_challenge(sock, room, &c, src).await,
                    RegAction::None => {}
                }
            }
        }
    }

    /// Cookie-completion admission when the global pending store matched:
    /// create the room if missing (re-checking all caps) or admit into the
    /// existing room. Port of `relay.go:268-350`.
    fn reg_cookie_create_or_admit(
        &self,
        room: &str,
        src_str: &str,
        src_ip: IpAddr,
        resolved: SocketAddr,
        src: SocketAddr,
    ) -> RegAction {
        let shard = &self.shards[shard_idx(room, NUM_SHARDS)];
        // Sweep stale rooms in *all* shards before re-checking the cap,
        // without holding any shard lock: two completions in different shards
        // sweeping in opposite orders would otherwise deadlock. The target-shard
        // re-sweep under the lock below remains a
        // best-effort recheck.
        if self.total_rooms() >= self.max_rooms() {
            let n = self.evict_stale_rooms_all(Instant::now());
            if n > 0 {
                LOG_RELAY.printf_warn(&format!("Evicted {n} stale room(s)"));
            }
        }
        let mut g = shard.lock().expect("room shard poisoned");
        match g.get(room).cloned() {
            None => {
                // Room doesn't exist yet; create it, re-checking all caps.
                if self.total_rooms() >= self.max_rooms() {
                    let (n, unlinked) = evict_stale_rooms(&mut g, Instant::now(), self.reg_ttl());
                    if n > 0 {
                        // Go decrements totalRoomCount inside evictStaleRooms;
                        // the Rust helper reports the count, the caller applies it.
                        self.total_room_count.fetch_sub(n, Ordering::Relaxed);
                        LOG_RELAY.printf_warn(&format!("Evicted {n} stale room(s)"));
                    }
                    for (ip, r) in unlinked {
                        self.remove_ip_room(ip, &r);
                    }
                }
                if self.total_rooms() >= self.max_rooms() {
                    self.drop_packet(
                        src,
                        &format!("Room {room} rejected: max rooms reached (cookie completion)"),
                    );
                    return RegAction::None;
                }
                if self.count_ip_rooms(src_ip) >= self.max_rooms_per_ip() {
                    self.drop_packet(
                        src,
                        &format!("Room limit per IP reached for {src_str} (cookie completion)"),
                    );
                    return RegAction::None;
                }
                let mut entry = RoomEntry::new();
                entry
                    .udp_clients
                    .insert(src_str.to_string(), UdpClient::new(Some(resolved)));
                entry.t = Instant::now();
                g.insert(room.to_string(), Arc::new(Mutex::new(entry)));
                self.total_room_count.fetch_add(1, Ordering::Relaxed);
                self.add_ip_room(src_ip, room);
                self.stat_regs.fetch_add(1, Ordering::Relaxed);
                RegAction::Regd
            }
            Some(arc) => {
                let mut entry = arc.lock().expect("room entry poisoned");
                // The shard guard is intentionally held across the entry lock
                // (shard -> entry order, same as the Go original).
                //
                // Evict stale clients before the cap checks so a valid cookie
                // completion is not rejected because of long-idle clients.
                for (ip, r) in entry.remove_stale_clients(room, Instant::now(), self.reg_ttl()) {
                    self.remove_ip_room(ip, &r);
                }
                let ip_already = entry
                    .udp_clients
                    .keys()
                    .any(|a| ip_key(a.parse().expect("stored addr is valid")) == src_ip);
                if entry.udp_clients.len() >= self.max_clients_hard()
                    && !entry.udp_clients.contains_key(src_str)
                {
                    self.drop_packet(
                        src,
                        &format!(
                            "Room {room} at hard cap ({}), rejecting {src_str} (cookie completion)",
                            self.max_clients_hard()
                        ),
                    );
                    return RegAction::None;
                }
                if !ip_already && self.count_ip_rooms(src_ip) >= self.max_rooms_per_ip() {
                    self.drop_packet(
                        src,
                        &format!("Room limit per IP reached for {src_str} (cookie completion)"),
                    );
                    return RegAction::None;
                }
                entry
                    .udp_clients
                    .insert(src_str.to_string(), UdpClient::new(Some(resolved)));
                entry.t = Instant::now();
                if !ip_already {
                    self.add_ip_room(src_ip, room);
                }
                self.stat_regs.fetch_add(1, Ordering::Relaxed);
                RegAction::Regd
            }
        }
    }

    // --- MSG handler (Go `handleMsg`) ---

    async fn handle_msg(&self, sock: &UdpSocket, payload: &[u8], src: SocketAddr) {
        // bytes.SplitN(payload, " ", 3) must yield exactly three parts.
        let mut parts = payload.splitn(3, |&b| b == b' ');
        let (Some(room), Some(phase), Some(body)) = (parts.next(), parts.next(), parts.next())
        else {
            self.drop_packet(src, &format!("Dropped malformed MSG from {src}"));
            return;
        };
        if phase != b"spake2" && phase != b"confirm" {
            self.drop_packet(
                src,
                &format!(
                    "Dropped MSG with unknown phase {:?} from {src} in room {:?}",
                    String::from_utf8_lossy(phase),
                    String::from_utf8_lossy(room)
                ),
            );
            return;
        }
        if !valid_room_name(room) {
            self.drop_packet(
                src,
                &format!(
                    "Dropped MSG with invalid room {:?} from {src}",
                    String::from_utf8_lossy(room)
                ),
            );
            return;
        }
        if !is_valid_hex(body) || body.len() > MAX_MSG_BODY_LEN {
            self.drop_packet(
                src,
                &format!(
                    "Dropped MSG with invalid body from {src} in room {:?}",
                    String::from_utf8_lossy(room)
                ),
            );
            return;
        }
        let room = std::str::from_utf8(room).expect("room validated as ASCII");
        let phase = std::str::from_utf8(phase).expect("phase matched a literal");
        let body = std::str::from_utf8(body).expect("body validated as hex");
        let src_str = src.to_string();

        let shard = &self.shards[shard_idx(room, NUM_SHARDS)];
        let entry_arc = {
            let g = shard.lock().expect("room shard poisoned");
            g.get(room).cloned()
        };
        let Some(arc) = entry_arc else {
            self.drop_packet(
                src,
                &format!("Dropped MSG for unknown room {room} from {src}"),
            );
            return;
        };

        let targets: Vec<SocketAddr> = {
            let mut entry = arc.lock().expect("room entry poisoned");
            let Some(info) = entry.udp_clients.get_mut(&src_str) else {
                self.drop_packet(
                    src,
                    &format!("Dropped message from unregistered client {src_str} in room {room}"),
                );
                return;
            };
            if info
                .rate_limiter
                .is_limited(self.rate_window(), self.max_msg_rate())
            {
                self.drop_packet(
                    src,
                    &format!("Rate-limited MSG from {src_str} in room {room}"),
                );
                return;
            }
            entry
                .udp_clients
                .iter()
                .filter(|(addr, ci)| addr.as_str() != src_str && ci.resolved_addr.is_some())
                .map(|(_, ci)| ci.resolved_addr.unwrap())
                .collect()
        };

        Self::rtrace(&format!(
            "MSG {phase} from {src_str}: {} target(s): {}",
            targets.len(),
            targets
                .iter()
                .map(|a| a.to_string())
                .collect::<Vec<_>>()
                .join(",")
        ));
        let msg_wire = format!("MSGD {phase} {body}\n");
        let had_targets = !targets.is_empty();
        for t in targets {
            match self.write_relay(sock, msg_wire.as_bytes(), t).await {
                Ok(()) => Self::rtrace(&format!("  wrote MSGD {phase} to {t} ok")),
                Err(e) => Self::rtrace(&format!("  wrote MSGD {phase} to {t} FAILED: {e}")),
            }
        }
        // Count a message as relayed only when there was at least one
        // target: a lone client's MSG, or one whose peers all lack a
        // resolved address, relays nothing.
        if had_targets {
            self.stat_msgs.fetch_add(1, Ordering::Relaxed);
        }
    }

    // --- server loop (Go `RunRelay`) ---

    /// Port of `RunRelay`: bind `addr`, serve REG/MSG traffic until `cancel`
    /// fires, then shut down.
    ///
    /// Sockets are cloned via `std::net::UdpSocket::try_clone` before
    /// wrapping, because tokio 1.53 removed `UdpSocket::try_clone`.
    pub async fn run(self: &Arc<Self>, addr: &str, cancel: CancellationToken) -> io::Result<()> {
        // Go `RunRelay`: `net.ResolveUDPAddr("udp", addr)` wrapped as
        // `resolve UDP: {err}`; error text is byte-identical to Go's.
        let sock_addr = qvole_protocol::resolver::resolve_udp_addr(addr)
            .await
            .map_err(|e| {
                io::Error::new(io::ErrorKind::InvalidInput, format!("resolve UDP: {e}"))
            })?;
        let std_sock = std::net::UdpSocket::bind(sock_addr)
            .map_err(|e| io::Error::new(e.kind(), format!("listen UDP: {e}")))?;
        // tokio 1.53 refuses blocking std sockets in `from_std`.
        std_sock
            .set_nonblocking(true)
            .map_err(|e| io::Error::new(e.kind(), format!("set nonblocking: {e}")))?;
        let mut std_clones = Vec::with_capacity(self.cfg.relay_workers + 1);
        for _ in 0..=self.cfg.relay_workers {
            std_clones.push(
                std_sock
                    .try_clone()
                    .map_err(|e| io::Error::new(e.kind(), format!("clone UDP socket: {e}")))?,
            );
        }
        let sock = UdpSocket::from_std(std_clones.remove(0))
            .map_err(|e| io::Error::new(e.kind(), format!("wrap UDP socket: {e}")))?;

        // Go: writePool is only installed when > 0 (nil pool = direct writes).
        if self.cfg.write_pool_size > 0 {
            let pool = Arc::new(tokio::sync::Semaphore::new(self.cfg.write_pool_size));
            let _ = self.write_pool.set(pool);
        }

        // One bounded channel with N worker consumers, like Go's single pktCh
        // ranged by relayWorkers goroutines. flume's Receiver is cloneable and
        // all clones consume the same queue.
        let (tx, rx) = bounded::<(Vec<u8>, SocketAddr)>(self.cfg.pkt_chan_buf);

        for std_clone in std_clones {
            let relay = Arc::clone(self);
            let rx = rx.clone();
            let sock = UdpSocket::from_std(std_clone)
                .map_err(|e| io::Error::new(e.kind(), format!("wrap UDP socket: {e}")))?;
            tokio::spawn(async move {
                while let Ok((data, src)) = rx.recv_async().await {
                    relay.handle_packet(&sock, &data, src).await;
                }
            });
        }

        LOG_RELAY.printf_success(&format!(
            "Listening on UDP {} ({} workers, {} writePool)",
            bold(addr),
            self.cfg.relay_workers,
            self.cfg.write_pool_size
        ));

        // Periodic stats log (Go stats ticker).
        {
            let relay = Arc::clone(self);
            let cancel = cancel.clone();
            let interval = self.cfg.relay_stats_interval;
            tokio::spawn(async move {
                let mut ticker =
                    tokio::time::interval_at(tokio::time::Instant::now() + interval, interval);
                loop {
                    tokio::select! {
                        _ = cancel.cancelled() => break,
                        _ = ticker.tick() => {
                            LOG_RELAY.printf(&format!(
                                "Stats: {} rooms, {} clients | {} REGs, {} MSGs relayed, {} drops",
                                relay.total_rooms(),
                                relay.total_clients(),
                                relay.stat_regs.load(Ordering::Relaxed),
                                relay.stat_msgs.load(Ordering::Relaxed),
                                relay.stat_drops.load(Ordering::Relaxed),
                            ));
                        }
                    }
                }
            });
        }

        // Periodic cleanup (Go `cleanupRegs`).
        {
            let relay = Arc::clone(self);
            let cancel = cancel.clone();
            let room_interval = self.cfg.reg_cleanup_interval;
            tokio::spawn(async move {
                let mut rate_tick = tokio::time::interval_at(
                    tokio::time::Instant::now() + RATE_MAP_CLEANUP_INTERVAL,
                    RATE_MAP_CLEANUP_INTERVAL,
                );
                let mut room_tick = tokio::time::interval_at(
                    tokio::time::Instant::now() + room_interval,
                    room_interval,
                );
                loop {
                    tokio::select! {
                        _ = cancel.cancelled() => break,
                        _ = rate_tick.tick() => {
                            let max_age = relay.rate_window() * 2;
                            for sh in &relay.reg_shards {
                                sh.lock().expect("reg shard poisoned").cleanup_stale(max_age);
                            }
                            relay
                                .drop_log_limiter
                                .lock()
                                .expect("drop limiter poisoned")
                                .cleanup_stale(DROP_LOG_INTERVAL * 2);
                        }
                        _ = room_tick.tick() => {
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
                    }
                }
            });
        }

        // Read loop (Go: conn.ReadFromUDP in a for-loop).
        let mut buf = vec![0u8; READ_BUF_SIZE];
        loop {
            tokio::select! {
                _ = cancel.cancelled() => {
                    drop(tx);
                    return Ok(());
                }
                res = sock.recv_from(&mut buf) => {
                    match res {
                        Ok((n, src)) => {
                            let data = buf[..n].to_vec();
                            if tx.try_send((data, src)).is_err() {
                                self.stat_drops.fetch_add(1, Ordering::Relaxed);
                                LOG_RELAY.printf_warn(&format!(
                                    "Packet dropped from {src}: worker channel full"
                                ));
                            }
                        }
                        Err(e) => {
                            LOG_RELAY.printf_error(&format!("UDP read error: {e}"));
                            drop(tx);
                            return Err(e);
                        }
                    }
                }
            }
        }
    }
}

impl Default for Relay {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
#[path = "tests.rs"]
mod tests;

/// Port of `rand.Read` cookie generation (16 random bytes).
fn random_cookie() -> [u8; PENDING_COOKIE_BYTES] {
    let mut cb = [0u8; PENDING_COOKIE_BYTES];
    rand::rngs::OsRng.fill_bytes(&mut cb);
    cb
}

/// Decode a lowercase/uppercase hex byte string (Go `hex.DecodeString` on
/// pre-validated input).
/// Lowercase hex encoding (Go `fmt.Sprintf("%x", b)`).
fn to_hex_lower(b: &[u8]) -> String {
    let mut s = String::with_capacity(b.len() * 2);
    for byte in b {
        s.push_str(&format!("{byte:02x}"));
    }
    s
}

fn hex_decode(b: &[u8]) -> Option<Vec<u8>> {
    fn hv(c: u8) -> Option<u8> {
        match c {
            b'0'..=b'9' => Some(c - b'0'),
            b'a'..=b'f' => Some(c - b'a' + 10),
            b'A'..=b'F' => Some(c - b'A' + 10),
            _ => None,
        }
    }
    let (pairs, tail) = b.as_chunks::<2>();
    if !tail.is_empty() {
        return None;
    }
    let mut out = Vec::with_capacity(pairs.len());
    for chunk in pairs {
        out.push(hv(chunk[0])? * 16 + hv(chunk[1])?);
    }
    Some(out)
}

// --- Test-only accessors (Go tests mutate package globals and maps directly;
// these mirror that without exposing interior mutability to production code).

#[cfg(any(test, feature = "test-util"))]
impl Relay {
    /// Go tests read the current global config values; these expose the
    /// live atomic values without env or cfg coupling.
    pub fn max_rooms_for_test(&self) -> usize {
        self.max_rooms()
    }
    pub fn max_clients_hard_for_test(&self) -> usize {
        self.max_clients_hard()
    }

    /// Go tests mutate the package-global config values directly; these
    /// mirror that via the atomics a running relay observes live.
    pub fn set_max_rooms(&self, v: usize) {
        self.max_rooms.store(v, Ordering::Relaxed);
    }
    pub fn set_max_rooms_per_ip(&self, v: usize) {
        self.max_rooms_per_ip.store(v, Ordering::Relaxed);
    }
    pub fn set_max_clients_hard(&self, v: usize) {
        self.max_clients_hard.store(v, Ordering::Relaxed);
    }
    pub fn set_max_msg_rate(&self, v: u32) {
        self.max_msg_rate.store(v as usize, Ordering::Relaxed);
    }
    pub fn set_max_reg_rate(&self, v: u32) {
        self.max_reg_rate.store(v as usize, Ordering::Relaxed);
    }
    pub fn set_reg_ttl(&self, d: Duration) {
        self.reg_ttl_ms
            .store(d.as_millis() as u64, Ordering::Relaxed);
    }
    pub fn set_max_pending_per_ip(&self, v: usize) {
        self.max_pending_per_ip.store(v, Ordering::Relaxed);
    }
    pub fn set_max_pending_global(&self, v: usize) {
        self.max_pending_global.store(v, Ordering::Relaxed);
    }
    /// Go tests set `totalRoomCount` directly to force the room cap.
    pub fn set_total_rooms(&self, v: usize) {
        self.total_room_count.store(v, Ordering::Relaxed);
    }

    /// Insert a room entry without touching the room counter
    /// (Go tests do `rooms[shardIdx(room, numShards)][room] = entry`).
    pub fn insert_room_for_test(&self, room: &str) -> Arc<Mutex<RoomEntry>> {
        let entry = Arc::new(Mutex::new(RoomEntry::new()));
        self.shards[shard_idx(room, NUM_SHARDS)]
            .lock()
            .expect("room shard poisoned")
            .insert(room.to_string(), Arc::clone(&entry));
        entry
    }

    pub fn get_room_for_test(&self, room: &str) -> Option<Arc<Mutex<RoomEntry>>> {
        self.shards[shard_idx(room, NUM_SHARDS)]
            .lock()
            .expect("room shard poisoned")
            .get(room)
            .cloned()
    }

    pub fn client_count(&self, room: &str) -> Option<usize> {
        let arc = self.get_room_for_test(room)?;
        Some(arc.lock().expect("room entry poisoned").udp_clients.len())
    }

    pub fn set_client_resolved_addr(&self, room: &str, client: &str, addr: Option<SocketAddr>) {
        let Some(arc) = self.get_room_for_test(room) else {
            return;
        };
        let mut e = arc.lock().expect("room entry poisoned");
        if let Some(c) = e.udp_clients.get_mut(client) {
            c.resolved_addr = addr;
        }
    }

    pub fn touch_client_last_seen(&self, room: &str, client: &str, ts: Instant) {
        let Some(arc) = self.get_room_for_test(room) else {
            return;
        };
        let mut e = arc.lock().expect("room entry poisoned");
        if let Some(c) = e.udp_clients.get_mut(client) {
            c.last_seen = ts;
        }
    }

    pub fn room_t(&self, room: &str) -> Option<Instant> {
        let arc = self.get_room_for_test(room)?;
        Some(arc.lock().expect("room entry poisoned").t)
    }

    pub fn set_room_t(&self, room: &str, ts: Instant) {
        let Some(arc) = self.get_room_for_test(room) else {
            return;
        };
        arc.lock().expect("room entry poisoned").t = ts;
    }

    pub fn pending_count_in_room(&self, room: &str) -> usize {
        let Some(arc) = self.get_room_for_test(room) else {
            return 0;
        };
        arc.lock().expect("room entry poisoned").pending.len()
    }

    /// Go tests set `regShard[src].times[src]` to age a REG rate-limit entry.
    pub fn set_reg_rate_time(&self, key: &str, ts: Instant) {
        let mut g = self.reg_shards[shard_idx(key, NUM_REG_SHARDS)]
            .lock()
            .expect("reg shard poisoned");
        g.times.insert(key.to_string(), ts);
    }
}
