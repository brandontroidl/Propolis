//! Fleet health: the listener inventory the control plane believes exists, the durable result of
//! probing it, and the pure rules that turn both into an operator-facing verdict.
//!
//! A separate crate rather than a module inside `review` or `core-scoring` because it belongs to
//! neither: `review` owns the queue, vendor submissions and fetcher state, `core-scoring` owns the
//! ledger and scoring, and three binaries need this one (`console` renders it, `propolis` migrates
//! and later probes, `intake` later confirms). It keeps its own migrator under its own bookkeeping
//! table for exactly the reason `review::migrator` documents at length: sqlx's migration table is
//! flat and keyed only by version number, so two crates numbering from `0001` against one physical
//! database need one bookkeeping table each.
//!
//! The invariant the whole crate exists to hold: **absence of evidence is not health.** A
//! configured listener with no probe row is `Unknown`, a probe older than two sweep intervals is
//! `Alarm` no matter how good its last result was, and an empty inventory yields `Unknown` rather
//! than a vacuous `Ok`. See [`health`].

pub mod health;
pub mod inventory;
pub mod store;

pub use health::Level;
pub use inventory::{InventoryError, Listener, Proto, parse_listeners, parse_listeners_env};
pub use store::{ProbeOutcome, ProbeRecord, ProbeRow};

/// This crate's own migrator, tracked under a table name distinct from core-scoring's default
/// `_sqlx_migrations` and from `review`'s. See `review::migrator`'s doc comment for the full
/// reasoning; the mechanism here is identical.
pub fn migrator() -> sqlx::migrate::Migrator {
    let mut m = sqlx::migrate!();
    m.dangerous_set_table_name("_sqlx_migrations_fleet");
    m
}
