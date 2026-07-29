//! Public API surface for `review`: the review queue, gatekeeper, vendor
//! adapters, and submission daemon for sub-project 4. Task 1 wires the crate
//! scaffold, migrations, and the review queue state machine only; the
//! gatekeeper, vendor adapters, submission daemon, and CLI land in later
//! tasks.

pub mod queue;

pub use queue::{QueueEntry, ReviewError, ReviewQueue};

/// This crate's own migrator, tracked under a table name distinct from
/// core-scoring's default `_sqlx_migrations`.
///
/// This crate's migrations (`review_queue`, `vendor_submission`) apply to the
/// same physical Postgres database as core-scoring's (`event`, `ip_score`) -
/// one database, two independent migration histories. sqlx's migration
/// bookkeeping table is a single flat table keyed only by version number,
/// with no per-crate namespacing: `Migrator::run_direct` rejects any row
/// already in that table whose version its OWN migration list does not
/// contain (`MigrateError::VersionMissing`), and since both crates' SQL files
/// start numbering at `0001`, a shared table would also hit a checksum
/// mismatch the moment the content at a shared version number differs
/// (`MigrateError::VersionMismatch`). Confirmed empirically: running this
/// crate's migrator against the default table name after core-scoring's had
/// already applied its own three migrations failed with `VersionMissing(3)`.
/// `dangerous_set_table_name` gives this crate its own independent
/// bookkeeping table so it never observes core-scoring's rows and vice versa.
/// The "dangerous" warning in sqlx's own docs is about renaming a table with
/// EXISTING tracked history mid-flight, which does not apply here since
/// `_sqlx_migrations_review` starts with no history but this crate's own.
pub fn migrator() -> sqlx::migrate::Migrator {
    let mut m = sqlx::migrate!();
    m.dangerous_set_table_name("_sqlx_migrations_review");
    m
}
