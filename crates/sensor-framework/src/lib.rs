//! The shared harness every sensor uses: listener lifecycle, WAN attribution, capture
//! sanitization, event emission, and the quarantine spool. See
//! `internal/design/02-sensor-framework.md` for the design this crate implements. Capture
//! sanitization, WAN attribution, event emission, and the quarantine spool exist so far; the
//! remaining pieces (listener lifecycle, resource bounds, capture hand-off) land in later tasks
//! of the same sub-project.

pub mod emit;
pub mod sanitize;
pub mod spool;
pub mod wan;

pub use emit::EventEmitter;
pub use sanitize::{sanitize_value, to_hex_bounded};
pub use spool::{QuarantineSpool, SpoolError};
pub use wan::WanResolver;
