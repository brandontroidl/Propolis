//! Public API surface for `feed`: the blocklist feed builder and exclusion engine for
//! sub-project 5. See `internal/design/05-blocklist-feed.md` for the full spec.
//!
//! This task (crate scaffold + exclusion engine + feed builder) covers the read path from
//! `ip_score` to an in-memory `FeedSnapshot`. The exporters (plain text/JSON/CSV/CIDR) and the
//! publisher + binary are later tasks in the same sub-project; they consume `FeedSnapshot`,
//! `FeedEntry`, and `coarsen_to_hour` from this crate rather than redefining them.

pub mod builder;
pub mod exclusion;

pub use builder::{FeedBuilder, FeedConfig, FeedEntry, FeedError, FeedSnapshot, coarsen_to_hour};
pub use exclusion::ExclusionEngine;
