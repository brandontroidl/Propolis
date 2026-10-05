//! The shared harness every sensor uses: listener lifecycle, WAN attribution, capture
//! sanitization, event emission, the quarantine spool, and off-response-path capture hand-off.
//! See `internal/design/02-sensor-framework.md` for the design this crate implements. Every
//! framework piece the design lists now exists; `sensor-catchall` and `sensor-ssh` (later tasks
//! of the same sub-project) are thin compositions over it.

pub mod admission;
pub mod binaries;
pub mod bounds;
pub mod budget;
pub mod command_codec;
pub mod config;
pub mod coverage;
pub mod emit;
pub mod env;
pub mod fakefs;
pub mod handoff;
pub mod listener;
pub mod outbox;
pub mod persona;
pub mod replay;
pub mod sanitize;
pub mod shell;
pub mod spool;
pub mod wan;

pub use admission::{PerSourceLimiter, SourceGuard, default_per_source_cap};
pub use bounds::ConnectionBounds;
pub use budget::{BudgetLimits, ConnectionBudget, EgressState, limits_from};
pub use command_codec::CommandCodec;
pub use config::SensorConfig;
pub use emit::EventEmitter;
pub use env::env_with_legacy;
pub use handoff::{CaptureDropped, CaptureEnd, CaptureHandoff, CaptureJob, upload_metadata};
pub use listener::{run_tcp_listener, run_udp_listener, shutdown_signal};
pub use outbox::{CustodyDisposition, CustodyState, ManifestRow, OutboxManifest};
pub use sanitize::{sanitize_value, to_hex_bounded};
pub use spool::{QuarantineSpool, SpoolError};
pub use uuid::Uuid;
pub use wan::WanResolver;
