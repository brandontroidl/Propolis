//! Public API surface for `feed`: the blocklist feed builder, exclusion engine, and exporters for
//! sub-project 5. See `internal/design/05-blocklist-feed.md` for the full spec.
//!
//! This crate now covers the read path from `ip_score` to an in-memory `FeedSnapshot`
//! (`builder`/`exclusion`) and the format conversion from a `FeedSnapshot`'s entries to plain
//! text/JSON/CSV/CIDR (`export`). The publisher + binary are a later task in the same
//! sub-project; it will consume `FeedSnapshot`, `ExclusionEngine`, and the `export_*` functions
//! from this crate rather than redefining them.

pub mod builder;
pub mod exclusion;
pub mod export;

pub use builder::{FeedBuilder, FeedConfig, FeedEntry, FeedError, FeedSnapshot, coarsen_to_hour};
pub use exclusion::ExclusionEngine;
pub use export::{export_cidr, export_csv, export_json, export_plaintext};
