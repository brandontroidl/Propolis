//! Public API surface for `feed`: the blocklist feed builder, exclusion engine, exporters, and
//! publisher for sub-project 5. See `internal/design/05-blocklist-feed.md` for the full spec.
//!
//! This crate covers the whole pipeline: the read path from `ip_score` to an in-memory
//! `FeedSnapshot` (`builder`/`exclusion`), the format conversion from a `FeedSnapshot`'s entries to
//! plain text/JSON/CSV/CIDR (`export`), and the atomic publish of those formats plus a checksummed
//! `manifest.json` to a configurable output directory (`publisher`). `src/main.rs` (the `feed`
//! binary) wires all three together into a periodic build loop; it consumes only this public API,
//! never crate-internal items.

pub mod builder;
pub mod exclusion;
pub mod export;
pub mod publisher;

pub use builder::{FeedBuilder, FeedConfig, FeedEntry, FeedError, FeedSnapshot, coarsen_to_hour};
pub use exclusion::ExclusionEngine;
pub use export::{export_cidr, export_csv, export_json, export_plaintext};
pub use publisher::{PublishError, Publisher};
