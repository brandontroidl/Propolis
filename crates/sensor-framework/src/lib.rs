//! The shared harness every sensor uses: listener lifecycle, WAN attribution, capture
//! sanitization, event emission, and the quarantine spool. See
//! `internal/design/02-sensor-framework.md` for the design this crate implements. Capture
//! sanitization, WAN attribution, and event emission exist so far; the remaining pieces (spool,
//! listener lifecycle, resource bounds, capture hand-off) land in later tasks of the same
//! sub-project.

pub mod emit;
pub mod sanitize;
pub mod wan;

pub use emit::EventEmitter;
pub use sanitize::{sanitize_value, to_hex_bounded};
pub use wan::WanResolver;
