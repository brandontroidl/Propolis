//! Public API surface for `core-scoring`.
//!
//! Consumers should use the crate-root re-exports below
//! (`core_scoring::append_event`, `core_scoring::EventInput`, ...) rather than
//! reaching into submodules. `domain` and `repository` stay `pub mod` because
//! existing integration tests (`tests/repository.rs`, `tests/replay.rs`)
//! address items through their full submodule paths
//! (`core_scoring::domain::enums::Protocol`,
//! `core_scoring::repository::{append_event, ...}`); narrowing those to
//! private would break the existing, already-passing test suite. `hashing`
//! and `scoring` stay crate-private - internal engine/chain-hashing details -
//! except for one cherry-picked re-export: `effective_score`. The console's IP
//! detail page (`internal/design/06-console-observability.md`'s "Score
//! summary: raw score, effective score, ...") needs the breadth-adjusted score
//! the blocklist recommendation gate actually uses, not just the boolean
//! `IpScore::recommended_for_blocklist` flag. Re-exporting the one pure
//! function (rather than widening `scoring` to `pub mod`) keeps every other
//! scoring internal - constants, the engine, tier/eligibility logic - exactly
//! as private as before, and keeps this the single source of truth for the
//! breadth-bonus formula (a consumer computing its own copy from
//! `IpScore::raw_score`/`distinct_wan_count` would silently drift from this
//! crate's constants on the next tuning change).

pub mod domain;
mod hashing;
pub mod net;
pub mod repository;
mod scoring;

pub use domain::enums::{Category, FeedTier, Protocol, ReviewState, SignalType};
pub use domain::types::{EventInput, IpScore, ValidationError};
pub use domain::weights::{SignalWeight, signal_weight};
pub use net::is_reserved_ip;
pub use repository::{
    ChainStatus, RepoError, append_event, read_score, rebuild_projection, verify_chain,
};
pub use scoring::breadth::effective_score;
