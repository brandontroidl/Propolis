//! File tailing with a durable, rotation-aware cursor. Extracted from `intake` so the
//! collector-side shipper can tail sensor NDJSON logs without depending on the control-plane
//! DB stack. The low-trust-boundary hardening (MAX_LINE_BYTES over-length discard) lives here
//! and therefore applies to BOTH the shipper->gateway path and the gateway-spool->intake path.
mod cursor;
mod tailer;

pub use cursor::{CursorState, DurableCursor, RotationEvent, compute_fingerprint, get_inode};
pub use tailer::LogTailer;
