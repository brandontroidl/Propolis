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
//! and `scoring` are internal engine/chain-hashing details with no external
//! consumer and are crate-private.

pub mod domain;
mod hashing;
pub mod repository;
mod scoring;

pub use domain::enums::{Category, FeedTier, Protocol, ReviewState, SignalType};
pub use domain::types::{EventInput, IpScore, ValidationError};
pub use domain::weights::{signal_weight, SignalWeight};
pub use repository::{append_event, read_score, rebuild_projection, verify_chain, ChainStatus, RepoError};
