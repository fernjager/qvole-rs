//! Relay exchange, hole punching, QUIC transport, and shared utilities.
//!
//! Port of `internal/engine/*` and `internal/util/{cert,env,logger,role}.go`
//! from the Go reference at commit `8f8ee569bbfc8ab4575ebd7094cf02fe492412e0`.

#![forbid(unsafe_code)]

pub mod cert;
pub mod connect;
pub mod disconnect;
pub mod env;
pub mod exchange;
pub mod hex;
pub mod logger;
pub mod pool;
pub mod punch;
pub mod resolver;
pub mod role;
pub mod stats;
pub mod transport;
