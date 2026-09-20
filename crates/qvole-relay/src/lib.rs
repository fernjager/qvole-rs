//! Port of the qvole UDP relay (Go `relay` package).
//!
//! This crate contains:
//! - [`room`]: room state, sharding, rate limiting, pending registrations
//! - [`relay`]: the relay server and packet handlers

#![forbid(unsafe_code)]

pub mod relay;
pub mod room;

pub use relay::{Config, Relay, StatsSnapshot};
