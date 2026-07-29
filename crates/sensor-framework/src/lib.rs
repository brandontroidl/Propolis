//! The shared harness every sensor uses: listener lifecycle, WAN attribution, capture
//! sanitization, event emission, and the quarantine spool. See
//! `internal/design/02-sensor-framework.md` for the design this crate implements. Capture
//! sanitization, WAN attribution, event emission, the quarantine spool, and listener lifecycle
//! plus resource bounds exist so far; the remaining piece (off-response-path capture hand-off)
//! lands in a later task of the same sub-project.

pub mod bounds;
pub mod config;
pub mod emit;
pub mod listener;
pub mod sanitize;
pub mod spool;
pub mod wan;

pub use bounds::ConnectionBounds;
pub use config::SensorConfig;
pub use emit::EventEmitter;
pub use listener::{run_tcp_listener, run_udp_listener, shutdown_signal};
pub use sanitize::{sanitize_value, to_hex_bounded};
pub use spool::{QuarantineSpool, SpoolError};
pub use wan::WanResolver;
