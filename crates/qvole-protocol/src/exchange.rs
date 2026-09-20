//! SPAKE2 exchange over the relay (Go `internal/engine/spake2_exchange.go`
//! and the exchange-facing parts of `connect.go`).
//!
//! Wire protocol: the SPAKE2 datagram is a hex-encoded
//! `myPointM (65) || myPointN (65) || fingerprint (32)` payload sent as
//! `MSG <room> spake2 <hex>\n`; confirmation is
//! `nonce (16) || confirm HMAC (32) || encAddr (80) || rand pad (32)` sent as
//! `MSG <room> confirm <hex>\n`. The role is chosen by comparing M-points as
//! byte strings: the larger side is the server, and equal M-points are
//! rejected (reflection check).

use std::collections::HashMap;
use std::time::{Duration, Instant};

use rand::RngCore;
use tokio::net::UdpSocket;
use tokio_util::sync::CancellationToken;

use qvole_spake2 as spake2;

use crate::hex;
use crate::logger::{LOG_RELAY, LOG_SPAKE2, bold};

pub const POINT_LEN: usize = 65;
pub const FINGERPRINT_SIZE: usize = 32;
pub const SPAKE2_PAYLOAD_LEN: usize = POINT_LEN * 2 + FINGERPRINT_SIZE; // 162
pub const MAX_CANDIDATES: usize = 50;
pub const MAX_BUFFERED_CONFIRMS: usize = 200;
pub const READ_BUFFER_SIZE: usize = 1500;
pub const SPAKE2_RESEND_INTERVAL: Duration = Duration::from_secs(2);
pub const CONFIRM_RESEND_INTERVAL: Duration = Duration::from_secs(2);
pub const EXCHANGE_READ_DEADLINE: Duration = Duration::from_secs(1);

// Go `connect.go` shared constants.
pub const EXCHANGE_DEADLINE: Duration = Duration::from_secs(90);
pub const REG_INTERVAL: Duration = Duration::from_secs(30);
pub const MAX_METADATA_SIZE: usize = 52;
const CONFIRM_NONCE_SIZE: usize = 16;
const CONFIRM_HMAC_SIZE: usize = 32;
pub const ENCRYPTED_ADDR_SIZE: usize = 12 + MAX_METADATA_SIZE + 16; // 80
pub const CONFIRM_MIN_SIZE: usize = CONFIRM_NONCE_SIZE + CONFIRM_HMAC_SIZE + ENCRYPTED_ADDR_SIZE;
pub const CONFIRM_RAND_PAD: usize = 32;
pub const CONFIRM_PAYLOAD_SIZE: usize = CONFIRM_MIN_SIZE + CONFIRM_RAND_PAD; // 160
pub const DEFAULT_PUNCH_TIMEOUT: Duration = Duration::from_secs(10);

/// Optional overrides for connection parameters (Go `PeerConfig`).
///
/// `None` fields fall back to `QVOLE_*` environment variables or built-in
/// defaults (Go zero-value semantics).
#[derive(Debug, Clone, Copy, Default)]
pub struct PeerConfig {
    pub punch_timeout: Option<Duration>,
    pub exchange_deadline: Option<Duration>,
    pub spake2_resend: Option<Duration>,
    pub confirm_resend: Option<Duration>,
    pub read_deadline: Option<Duration>,
    pub reg_interval: Option<Duration>,
    // QUIC transport fields.
    pub max_streams: Option<u32>,
    pub forward_max_streams: Option<u32>,
    pub keep_alive_period: Option<Duration>,
    pub idle_timeout: Option<Duration>,
    pub handshake_timeout: Option<Duration>,
}

impl PeerConfig {
    fn resolve_dur(val: Option<Duration>, env_name: &str, def: Duration) -> Duration {
        match val {
            Some(d) if d > Duration::ZERO => d,
            _ => Duration::from_millis(crate::env::env_duration_ms(
                env_name,
                def.as_millis() as u64,
            )),
        }
    }

    /// Go `punchTimeout()`: `QVOLE_PUNCH_TIMEOUT_MS`, default 10s.
    #[must_use]
    pub fn punch_timeout(&self) -> Duration {
        Self::resolve_dur(
            self.punch_timeout,
            "QVOLE_PUNCH_TIMEOUT_MS",
            DEFAULT_PUNCH_TIMEOUT,
        )
    }

    /// Go `exchangeDeadline()`: `QVOLE_EXCHANGE_DEADLINE_MS`, default 90s.
    #[must_use]
    pub fn exchange_deadline(&self) -> Duration {
        Self::resolve_dur(
            self.exchange_deadline,
            "QVOLE_EXCHANGE_DEADLINE_MS",
            EXCHANGE_DEADLINE,
        )
    }

    /// Go `spake2Resend()`: `QVOLE_SPAKE2_RESEND_MS`, default 2s.
    #[must_use]
    pub fn spake2_resend(&self) -> Duration {
        Self::resolve_dur(
            self.spake2_resend,
            "QVOLE_SPAKE2_RESEND_MS",
            SPAKE2_RESEND_INTERVAL,
        )
    }

    /// Go `confirmResend()`: `QVOLE_CONFIRM_RESEND_MS`, default 2s.
    #[must_use]
    pub fn confirm_resend(&self) -> Duration {
        Self::resolve_dur(
            self.confirm_resend,
            "QVOLE_CONFIRM_RESEND_MS",
            CONFIRM_RESEND_INTERVAL,
        )
    }

    /// Go `readDeadline()`: `QVOLE_EXCHANGE_READ_DEADLINE_MS`, default 1s.
    #[must_use]
    pub fn read_deadline(&self) -> Duration {
        Self::resolve_dur(
            self.read_deadline,
            "QVOLE_EXCHANGE_READ_DEADLINE_MS",
            EXCHANGE_READ_DEADLINE,
        )
    }

    /// Go `regInterval()`: `QVOLE_REG_INTERVAL_MS`, default 30s.
    #[must_use]
    pub fn reg_interval(&self) -> Duration {
        Self::resolve_dur(self.reg_interval, "QVOLE_REG_INTERVAL_MS", REG_INTERVAL)
    }

    /// Go `resolveInt(cfg.MaxStreams, "QVOLE_MAX_STREAMS", 100)`.
    #[must_use]
    pub fn max_streams(&self) -> u32 {
        match self.max_streams {
            Some(v) if v > 0 => v,
            _ => crate::env::env_int(
                "QVOLE_MAX_STREAMS",
                crate::transport::DEFAULT_MAX_INCOMING_STREAMS as i64,
            ) as u32,
        }
    }

    /// Go `resolveDur(cfg.KeepAlivePeriod, "QVOLE_KEEPALIVE_MS", 5s)`.
    #[must_use]
    pub fn keep_alive_period(&self) -> Duration {
        Self::resolve_dur(
            self.keep_alive_period,
            "QVOLE_KEEPALIVE_MS",
            crate::transport::DEFAULT_KEEP_ALIVE_PERIOD,
        )
    }

    /// Go `resolveDur(cfg.IdleTimeout, "QVOLE_IDLE_TIMEOUT_MS", 2min)`.
    #[must_use]
    pub fn idle_timeout(&self) -> Duration {
        Self::resolve_dur(
            self.idle_timeout,
            "QVOLE_IDLE_TIMEOUT_MS",
            crate::transport::DEFAULT_MAX_IDLE_TIMEOUT,
        )
    }

    /// Go `resolveDur(cfg.HandshakeTimeout, "QVOLE_HANDSHAKE_TIMEOUT_MS", 30s)`.
    #[must_use]
    pub fn handshake_timeout(&self) -> Duration {
        Self::resolve_dur(
            self.handshake_timeout,
            "QVOLE_HANDSHAKE_TIMEOUT_MS",
            crate::transport::DEFAULT_HANDSHAKE_TIMEOUT,
        )
    }
}

/// Errors from the exchange phase. Display text mirrors the Go error strings
/// where they are observable (tests assert on the substrings).
#[derive(Debug, thiserror::Error)]
pub enum ExchangeError {
    /// `spake2 state: {0}`
    #[error("spake2 state: {0}")]
    Spake2State(#[from] spake2::Error),
    /// Go `encoding/hex` decode failure.
    #[error("encoding/hex: {0}")]
    Hex(String),
    /// Fixed wire-format errors.
    #[error("{0}")]
    Wire(String),
    /// `spake2 derive key: {0}`
    #[error("spake2 derive key: {0}")]
    DeriveKey(String),
    /// `compute confirm: {0}`
    #[error("compute confirm: {0}")]
    ComputeConfirm(String),
    /// `encrypt addr: {0}`
    #[error("encrypt addr: {0}")]
    EncryptAddr(String),
    /// `address too long: {0} bytes (max {1})`
    #[error("address too long: {0} bytes (max {1})")]
    AddressTooLong(usize, usize),
    /// `confirm payload too short`
    #[error("confirm payload too short")]
    ConfirmPayloadTooShort,
    /// `spake2 confirmation mismatch`
    #[error("spake2 confirmation mismatch")]
    ConfirmMismatch,
    /// `decrypt peer addr: {0}`
    #[error("decrypt peer addr: {0}")]
    DecryptAddr(String),
    /// `timeout exchanging with peer`
    #[error("timeout exchanging with peer")]
    Timeout,
    /// `relay read: {0}`
    #[error("relay read: {0}")]
    RelayRead(std::io::Error),
    /// Go `context.Canceled`.
    #[error("context canceled")]
    Cancelled,
}

/// Trims ASCII whitespace (Go `bytes.TrimSpace`).
#[must_use]
pub fn trim_ascii(b: &[u8]) -> &[u8] {
    const WS: &[u8] = b" \t\n\x0b\x0c\r";
    let start = b.iter().take_while(|c| WS.contains(c)).count();
    let end = b.iter().rev().take_while(|c| WS.contains(c)).count();
    &b[start..b.len() - end]
}

/// Result of processing a peer SPAKE2 payload (Go `processSpakeMsg` outputs).
#[derive(Debug)]
pub struct ProcessedSpake {
    pub effective_my_point: Vec<u8>,
    pub effective_peer_point: Vec<u8>,
    pub peer_fingerprint: Vec<u8>,
    pub is_server: bool,
    pub confirm_key: [u8; 32],
    pub enc_key: [u8; 32],
}

/// Parses the peer's SPAKE2 payload (`myPointM || myPointN || fingerprint`),
/// determines the role by comparing M-points, and derives the session keys.
///
/// Server (larger M-point) uses N; client uses M.
///
/// Port of `processSpakeMsg`.
pub fn process_spake_msg(
    body: &str,
    state: &spake2::State,
    my_point_m: &[u8],
    my_point_n: &[u8],
) -> Result<ProcessedSpake, ExchangeError> {
    let peer_payload = hex::hex_decode(body)
        .ok_or_else(|| ExchangeError::Hex("invalid hex string".to_string()))?;
    if peer_payload.len() < SPAKE2_PAYLOAD_LEN {
        return Err(ExchangeError::Wire("spake2 payload too short".into()));
    }
    let peer_point_m = &peer_payload[..POINT_LEN];
    let peer_point_n = &peer_payload[POINT_LEN..POINT_LEN * 2];
    let peer_fingerprint = peer_payload[POINT_LEN * 2..SPAKE2_PAYLOAD_LEN].to_vec();

    if my_point_m == peer_point_m {
        return Err(ExchangeError::Wire(
            "spake2: peer sent reflected point".into(),
        ));
    }
    let is_server = my_point_m > peer_point_m;

    let (effective_my_point, effective_peer_point) = if is_server {
        (my_point_n.to_vec(), peer_point_m.to_vec())
    } else {
        (my_point_m.to_vec(), peer_point_n.to_vec())
    };

    let peer_used_m = is_server;
    let mut shared = state.compute_shared(&effective_peer_point, peer_used_m)?;
    let (ck, ek) = spake2::derive_session_key(&shared, &effective_my_point, &effective_peer_point)
        .map_err(|e| ExchangeError::DeriveKey(e.to_string()))?;
    spake2::zero_bytes(&mut shared);

    Ok(ProcessedSpake {
        effective_my_point,
        effective_peer_point,
        peer_fingerprint,
        is_server,
        confirm_key: ck,
        enc_key: ek,
    })
}

/// Builds the confirm payload
/// `nonce (16) || confirm HMAC (32) || encAddr (80) || rand pad (32)`.
///
/// Port of `buildConfirmPayload`.
pub fn build_confirm_payload(
    confirm_key: &[u8],
    enc_key: &[u8],
    my_point: &[u8],
    peer_point: &[u8],
    peer_fingerprint: &[u8],
    my_addr: &str,
) -> Result<Vec<u8>, ExchangeError> {
    let aad = spake2::session_aad(my_point, peer_point);
    let mut confirm_nonce = [0u8; CONFIRM_NONCE_SIZE];
    rand::rngs::OsRng.fill_bytes(&mut confirm_nonce);
    let confirm = spake2::compute_confirm(
        confirm_key,
        my_point,
        peer_point,
        &confirm_nonce,
        peer_fingerprint,
    )
    .map_err(|e| ExchangeError::ComputeConfirm(e.to_string()))?;

    let mut addr_bytes = my_addr.as_bytes().to_vec();
    if addr_bytes.len() > MAX_METADATA_SIZE {
        return Err(ExchangeError::AddressTooLong(
            addr_bytes.len(),
            MAX_METADATA_SIZE,
        ));
    }
    addr_bytes.resize(MAX_METADATA_SIZE, 0);

    let enc_addr = spake2::encrypt_metadata(enc_key, &aad, &addr_bytes)
        .map_err(|e| ExchangeError::EncryptAddr(e.to_string()))?;
    spake2::zero_bytes(&mut addr_bytes);

    let mut cp = Vec::with_capacity(CONFIRM_PAYLOAD_SIZE);
    cp.extend_from_slice(&confirm_nonce);
    cp.extend_from_slice(&confirm);
    cp.extend_from_slice(&enc_addr);
    if cp.len() < CONFIRM_PAYLOAD_SIZE {
        let mut pad = vec![0u8; CONFIRM_PAYLOAD_SIZE - cp.len()];
        rand::rngs::OsRng.fill_bytes(&mut pad);
        cp.extend_from_slice(&pad);
    }
    Ok(cp)
}

/// Verifies a peer confirm payload and decrypts the peer's UDP address.
///
/// Port of `processConfirmMsg`.
pub fn process_confirm_msg(
    hex_body: &str,
    confirm_key: &[u8],
    enc_key: &[u8],
    my_point: &[u8],
    peer_point: &[u8],
    my_fingerprint: &[u8],
) -> Result<String, ExchangeError> {
    let peer_confirm_payload =
        hex::hex_decode(hex_body).ok_or_else(|| ExchangeError::Hex("invalid hex string".into()))?;
    if peer_confirm_payload.len() < CONFIRM_PAYLOAD_SIZE {
        return Err(ExchangeError::ConfirmPayloadTooShort);
    }
    let peer_nonce = &peer_confirm_payload[..CONFIRM_NONCE_SIZE];
    let peer_confirm =
        &peer_confirm_payload[CONFIRM_NONCE_SIZE..CONFIRM_NONCE_SIZE + CONFIRM_HMAC_SIZE];
    let peer_enc_addr = &peer_confirm_payload
        [CONFIRM_NONCE_SIZE + CONFIRM_HMAC_SIZE..CONFIRM_PAYLOAD_SIZE - CONFIRM_RAND_PAD];

    if !spake2::verify_confirm(
        confirm_key,
        my_point,
        peer_point,
        peer_nonce,
        my_fingerprint,
        peer_confirm,
    ) {
        return Err(ExchangeError::ConfirmMismatch);
    }
    let aad = spake2::session_aad(my_point, peer_point);
    let peer_addr_bytes = spake2::decrypt_metadata(enc_key, &aad, peer_enc_addr)
        .map_err(|e| ExchangeError::DecryptAddr(e.to_string()))?;
    Ok(peer_addr_bytes
        .iter()
        .copied()
        .take_while(|&b| b != 0)
        .map(char::from)
        .collect())
}

/// Resolves the address to advertise in the confirm metadata.
///
/// Port of `detectOutboundAddr`: an unspecified local IP becomes
/// `localhost:<port>`.
#[must_use]
pub fn detect_outbound_addr(local: std::net::SocketAddr) -> String {
    let (is_unspecified, port) = match local {
        std::net::SocketAddr::V4(v) => (v.ip().is_unspecified(), v.port()),
        std::net::SocketAddr::V6(v) => (v.ip().is_unspecified(), v.port()),
    };
    if is_unspecified {
        return format!("localhost:{port}");
    }
    local.to_string()
}

struct PeerCandidate {
    point: Vec<u8>,
    fingerprint: Vec<u8>,
    confirm_key: [u8; 32],
    enc_key: [u8; 32],
    confirm_payload: Vec<u8>,
    is_server: bool,
    effective_my_point: Vec<u8>,
}

struct StateGuard(spake2::State);

impl Drop for StateGuard {
    fn drop(&mut self) {
        self.0.destroy();
    }
}

/// Wraps the candidate map so session keys are zeroed on scope exit
/// (Go `defer`: `state.Destroy()` + `spake2.ZeroBytes` over all keys).
struct CandidatesGuard(HashMap<String, PeerCandidate>);

impl Drop for CandidatesGuard {
    fn drop(&mut self) {
        for cand in self.0.values_mut() {
            spake2::zero_bytes(&mut cand.confirm_key);
            spake2::zero_bytes(&mut cand.enc_key);
        }
    }
}

impl CandidatesGuard {
    fn len(&self) -> usize {
        self.0.len()
    }

    fn contains(&self, k: &str) -> bool {
        self.0.contains_key(k)
    }

    fn insert(&mut self, k: String, v: PeerCandidate) {
        self.0.insert(k, v);
    }

    fn iter(&self) -> impl Iterator<Item = (&String, &PeerCandidate)> {
        self.0.iter()
    }
}

/// Registers the peer in the room and completes the SPAKE2 exchange,
/// returning `(peerAddr, peerFingerprint, isServer)`.
///
/// Port of `registerAndExchange`.
pub async fn register_and_exchange(
    cancel: &CancellationToken,
    sock: &UdpSocket,
    room: &str,
    code: &str,
    my_fingerprint: &[u8],
    cfg: &PeerConfig,
) -> Result<(String, Vec<u8>, bool), ExchangeError> {
    let state = spake2::new_state(code)?;
    let state = StateGuard(state);
    let my_point_m = state.0.blinded_bytes_m();
    let my_point_n = state.0.blinded_bytes_n();

    let mut my_addr = detect_outbound_addr(sock.local_addr().map_err(ExchangeError::RelayRead)?);
    LOG_RELAY.printf(&format!("Local address {}", bold(&my_addr)));

    let mut spake2_payload = Vec::with_capacity(SPAKE2_PAYLOAD_LEN);
    spake2_payload.extend_from_slice(&my_point_m);
    spake2_payload.extend_from_slice(&my_point_n);
    spake2_payload.extend_from_slice(my_fingerprint);

    let mut candidates = CandidatesGuard(HashMap::new());
    let mut confirm_last_sent: HashMap<String, Instant> = HashMap::new();
    let mut buffered_confirms: Vec<String> = Vec::with_capacity(MAX_BUFFERED_CONFIRMS);

    let exchange_deadline = cfg.exchange_deadline();
    let spake2_resend = cfg.spake2_resend();
    let confirm_resend = cfg.confirm_resend();
    let read_deadline = cfg.read_deadline();
    let reg_interval = cfg.reg_interval();
    let mut read_buf = vec![0u8; READ_BUFFER_SIZE];
    let deadline = Instant::now() + exchange_deadline;
    let mut last_spake2_sent: Option<Instant> = None;
    let mut last_reg_sent: Option<Instant> = None;
    let mut received_regd = false;
    let mut pending_cookie = String::new();

    loop {
        if cancel.is_cancelled() {
            return Err(ExchangeError::Cancelled);
        }
        if Instant::now() > deadline {
            return Err(ExchangeError::Timeout);
        }

        // REG (re)registration.
        if last_reg_sent.is_none_or(|t| Instant::now().duration_since(t) > reg_interval) {
            let msg = if pending_cookie.is_empty() {
                format!("REG {room}\n")
            } else {
                format!("REG {room} {pending_cookie}\n")
            };
            let _ = sock.send(msg.as_bytes()).await; // Go ignores write errors

            last_reg_sent = Some(Instant::now());
        }

        // SPAKE2 (re)send once registered.
        if received_regd
            && last_spake2_sent.is_none_or(|t| Instant::now().duration_since(t) > spake2_resend)
        {
            let msg = format!("MSG {room} spake2 {}\n", hex::to_hex_lower(&spake2_payload));
            let _ = sock.send(msg.as_bytes()).await;
            last_spake2_sent = Some(Instant::now());
        }

        // Confirm resends.
        let mut resends: Vec<(String, Vec<u8>)> = Vec::new();
        for (point_hex, cand) in candidates.iter() {
            let due = confirm_last_sent
                .get(point_hex)
                .is_none_or(|t| Instant::now().duration_since(*t) > confirm_resend);
            if due {
                resends.push((point_hex.clone(), cand.confirm_payload.clone()));
            }
        }
        for (point_hex, payload) in resends {
            let msg = format!("MSG {room} confirm {}\n", hex::to_hex_lower(&payload));
            let _ = sock.send(msg.as_bytes()).await;
            confirm_last_sent.insert(point_hex, Instant::now());
        }

        let n = match tokio::time::timeout(read_deadline, sock.recv(&mut read_buf)).await {
            Ok(Ok(n)) => n,
            Ok(Err(e)) => return Err(ExchangeError::RelayRead(e)),
            Err(_) => continue, // read deadline (Go: net timeout)
        };
        let line = trim_ascii(&read_buf[..n]);

        if let Some(rest) = line.strip_prefix(b"REGD ") {
            let (relay_room, relay_payload) = match rest.iter().position(|&c| c == b' ') {
                Some(i) => (&rest[..i], &rest[i + 1..]),
                None => continue,
            };
            let room_match = std::str::from_utf8(relay_room)
                .map(|s| s == room)
                .unwrap_or(false);
            if !room_match {
                continue;
            }
            let payload = trim_ascii(relay_payload);
            // "REGD <room> OK <addr>"; confirmed registration.
            if let Some(ok_rest) = payload.strip_prefix(b"OK ") {
                received_regd = true;
                let ext_addr = trim_ascii(ok_rest);
                if !ext_addr.is_empty() {
                    let ext = String::from_utf8_lossy(ext_addr).into_owned();
                    my_addr = ext;
                    LOG_RELAY
                        .printf_success(&format!("Connected! Ext. address: {}", bold(&my_addr)));
                }
                continue;
            }
            // "REGD <room> <cookie>"; cookie challenge (32 hex chars).
            if payload.len() == 32
                && let Ok(s) = std::str::from_utf8(payload)
                && hex::hex_decode(s).is_some()
            {
                pending_cookie = s.to_string();
                last_reg_sent = None; // send cookie-bearing REG immediately
            }
        }

        if let Some(hex_body) = line
            .strip_prefix(b"MSGD spake2 ")
            .and_then(|b| std::str::from_utf8(b).ok())
        {
            let peer_payload = match hex::hex_decode(hex_body) {
                Some(p) if p.len() >= SPAKE2_PAYLOAD_LEN => p,
                _ => {
                    LOG_SPAKE2.printf_warn("Invalid SPAKE2 message: short payload");
                    continue;
                }
            };
            let point_hex = hex::to_hex_lower(&peer_payload[..POINT_LEN]);
            if candidates.contains(&point_hex) {
                continue;
            }
            if candidates.len() >= MAX_CANDIDATES {
                LOG_SPAKE2.printf_warn(&format!(
                    "Too many SPAKE2 candidates ({}), dropping",
                    candidates.len()
                ));
                continue;
            }

            let mut proc = match process_spake_msg(hex_body, &state.0, &my_point_m, &my_point_n) {
                Ok(p) => p,
                Err(e) => {
                    LOG_SPAKE2.printf_warn(&format!("Invalid SPAKE2 message: {e}"));
                    continue;
                }
            };
            let cp = match build_confirm_payload(
                &proc.confirm_key,
                &proc.enc_key,
                &proc.effective_my_point,
                &proc.effective_peer_point,
                &proc.peer_fingerprint,
                &my_addr,
            ) {
                Ok(cp) => cp,
                Err(e) => {
                    LOG_SPAKE2.printf_error(&format!("Failed to build confirm payload: {e}"));
                    spake2::zero_bytes(&mut proc.confirm_key);
                    spake2::zero_bytes(&mut proc.enc_key);
                    continue;
                }
            };
            candidates.insert(
                point_hex.clone(),
                PeerCandidate {
                    point: proc.effective_peer_point.clone(),
                    fingerprint: proc.peer_fingerprint.clone(),
                    confirm_key: proc.confirm_key,
                    enc_key: proc.enc_key,
                    confirm_payload: cp.clone(),
                    is_server: proc.is_server,
                    effective_my_point: proc.effective_my_point.clone(),
                },
            );

            let msg = format!("MSG {room} confirm {}\n", hex::to_hex_lower(&cp));
            let _ = sock.send(msg.as_bytes()).await;
            confirm_last_sent.insert(point_hex.clone(), Instant::now());

            LOG_SPAKE2.printf_success("Points exchanged with peer");

            for buffered in buffered_confirms.clone() {
                if let Ok(pa) = process_confirm_msg(
                    &buffered,
                    &proc.confirm_key,
                    &proc.enc_key,
                    &proc.effective_my_point,
                    &proc.effective_peer_point,
                    my_fingerprint,
                ) {
                    LOG_SPAKE2.printf_success("Peer authenticated (buffered)");
                    return Ok((pa, proc.peer_fingerprint, proc.is_server));
                }
            }
        }

        if let Some(hex_body) = line
            .strip_prefix(b"MSGD confirm ")
            .and_then(|b| std::str::from_utf8(b).ok())
        {
            'candidates: for (_hex, cand) in candidates.iter() {
                let pa = match process_confirm_msg(
                    hex_body,
                    &cand.confirm_key,
                    &cand.enc_key,
                    &cand.effective_my_point,
                    &cand.point,
                    my_fingerprint,
                ) {
                    Ok(pa) => pa,
                    Err(_) => continue 'candidates,
                };
                LOG_SPAKE2.printf_success("Peer authenticated");
                return Ok((pa, cand.fingerprint.clone(), cand.is_server));
            }

            if buffered_confirms.len() < MAX_BUFFERED_CONFIRMS {
                buffered_confirms.push(hex_body.to_string());
            }
        }
    }
}

#[cfg(test)]
#[path = "exchange_tests.rs"]
mod tests;
