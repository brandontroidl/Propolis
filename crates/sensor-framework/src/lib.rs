//! The shared harness every sensor uses: listener lifecycle, WAN attribution, capture
//! sanitization, event emission, and the quarantine spool. See
//! `internal/design/02-sensor-framework.md` for the design this crate implements. Only capture
//! sanitization exists so far; the remaining pieces land in later tasks of the same sub-project.

pub mod sanitize;
pub use sanitize::{sanitize_value, to_hex_bounded};
