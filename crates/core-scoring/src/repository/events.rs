//! Transactional append path and read projection over real Postgres.
//!
//! INET columns are read with a `::text` cast and `parse()`d to `IpAddr` in
//! Rust, and written with a `$n::inet` cast on the bound string parameter, so
//! we never depend on an INET/ipnetwork type mapping. All queries use the
//! RUNTIME `sqlx::query*` API (not the compile-time macros) so the build does
//! not require a live database or an offline cache.
//!
//! # Single-writer model
//!
//! `append_event` serializes ALL appends against a single, transaction-scoped
//! Postgres advisory lock (`pg_advisory_xact_lock`, keyed on
//! [`APPEND_LOCK_KEY`]). The transaction first pins `READ COMMITTED` isolation
//! (required for the lock to serialize correctly), then acquires the lock before
//! the chain-head read, so the chain-head read + event INSERT + projection read +
//! vantage/sensor set upserts + `ip_score` UPSERT all execute as one serialized
//! critical section. Under READ COMMITTED each statement takes a fresh snapshot,
//! so once the lock is granted the chain-head read sees the prior appender's
//! committed row (under REPEATABLE READ / SERIALIZABLE the snapshot would freeze
//! before the lock and the chain could fork - hence the explicit pin). This
//! guarantees, under any number of concurrent callers:
//!
//! - the tamper-evident hash chain cannot fork (no two appends can read the
//!   same `prev_hash` and both insert against it);
//! - the `ip_score` projection UPSERT cannot lose an update to a
//!   last-write-wins race;
//! - the `ip_vantage` / `ip_sensor` sets an append counts from hold every
//!   scored event committed before it;
//! - the dedup window read (`MAX(observed_at)` for the same `source_ip` +
//!   `signal_type`) cannot be bypassed by an interleaved concurrent insert.
//!
//! `pg_advisory_xact_lock` auto-releases at transaction end (commit or
//! rollback), so a failed/rolled-back append never leaves the lock held.
//!
//! [`append_events`](super::batch::append_events) takes the same lock once for a whole batch and
//! leaves the state these per-event functions would; it is the reference these functions are
//! proven against, so a change to one path's rules must reach the other
//! (`tests/batch_equivalence.rs` fails if they diverge).
//!
//! This implements the design's "projection advancement is single-writer per
//! deployment" assumption at the database level. It serializes appends within
//! ONE Postgres instance; it does not decide WHICH process/node is the writer
//! of record in a multi-node deployment - that is cluster-level leader
//! election, the responsibility of sub-project 7, layered on top of this
//! DB-level guard.

use std::collections::BTreeMap;
use std::net::IpAddr;

use chrono::{DateTime, NaiveDate, SubsecRound, Utc};
use sqlx::{PgPool, Postgres, Row};

use crate::domain::enums::{Category, Protocol, SignalType};
use crate::domain::types::{EventInput, IpScore, ValidationError};
use crate::hashing::chain_hash;
use crate::scoring::breadth::{WanVantage, distinct_wan_count};
use crate::scoring::constants::{DEDUP_WINDOW_SECONDS, HALF_LIFE_SECONDS};
use crate::scoring::engine::{CategoryStat, apply_event, project_to_now};

/// Errors from the repository layer. Every variant is a fail-closed outcome:
/// the caller gets an error and (for the append path) the transaction rolls
/// back, so no projection is committed.
#[derive(Debug, thiserror::Error)]
pub enum RepoError {
    /// A database/driver error. Rolls back the append transaction.
    #[error("database error: {0}")]
    Db(#[from] sqlx::Error),
    /// The event failed domain validation; nothing was written.
    #[error("invalid event: {0:?}")]
    Invalid(ValidationError),
    /// Stored state could not be parsed into the expected shape (e.g. a
    /// `category_breakdown` JSON that is not a valid `CategoryStat` map, or an
    /// unparseable stored IP). We return this instead of letting the engine
    /// `.expect()` panic on the corrupt value - the read path fails closed.
    #[error("corrupt stored state: {0}")]
    Corrupt(String),
    /// A telemetry signal was handed to the scoring append path. Telemetry describes an
    /// interaction and must never move a score, so the two paths are separate and this one fails
    /// closed rather than quietly folding the row - see [`append_telemetry_event`].
    #[error("{0:?} is telemetry; append it with append_telemetry_event")]
    NotScorable(SignalType),
}

/// Excludes telemetry rows from a read of a source's ledger rows for scoring: `rebuild_projection`
/// loads its events through it. A macro rather than a `const` so the queries stay `&'static str`
/// literals that sqlx accepts without a dynamic-SQL escape hatch.
/// `the_exclusion_predicate_names_every_telemetry_signal` fails if a telemetry signal is added
/// without extending it. Migration 0014's backfill spells the same predicate out, since a
/// migration file cannot use the macro.
macro_rules! exclude_telemetry {
    () => {
        "signal_type <> 'honeypot_session_end'"
    };
}
pub(crate) use exclude_telemetry;

/// The `ip_score` columns [`score_from_row`] decodes, shared by the single and batched reads so
/// the two cannot select different things. A macro for the same reason as `exclude_telemetry!`.
macro_rules! stored_score_columns {
    () => {
        "host(source_ip) AS source_ip, raw_score, decay_anchor, max_confidence, \
         event_count, established_event_count, distinct_categories, category_breakdown, \
         has_confirmed_real, distinct_wan_count, distinct_sensor_count, first_seen, last_seen, \
         eligible, recommended_for_vendor, recommended_for_blocklist, tier, delisted, \
         active_days, last_active_day"
    };
}
pub(crate) use stored_score_columns;

// Manual `From` (not thiserror `#[from]`) so we do not require `ValidationError`
// to implement `std::error::Error`; it stays a plain domain value type.
impl From<ValidationError> for RepoError {
    fn from(e: ValidationError) -> Self {
        RepoError::Invalid(e)
    }
}

/// The single global advisory-lock key used to serialize every call to
/// `append_event` against every other call, within one Postgres instance.
/// Fixed and arbitrary (any stable `i64` works); documented here so its
/// value is never accidentally reused for an unrelated lock. Held for the
/// lifetime of the append transaction via `pg_advisory_xact_lock`, which
/// auto-releases on commit or rollback.
pub(super) const APPEND_LOCK_KEY: i64 = 7_265_646_772_697_400_001;

/// The dedup read: the newest prior observation of this source and signal. Runs inside the append
/// lock on every scored event, so its plan decides intake throughput. Migration 0013's
/// `event_dedup_idx` answers it in one backward step. The alternative the planner also weighs is
/// walking `event_observed_at_idx` down from the ledger head until the source turns up, which
/// costs one row per event newer than the source's last sighting, so it grows with intake lag.
///
/// The address is wrapped in a scalar subquery so the planner cannot see it. Given the literal
/// value, it looks the address up in the column statistics, and a bot loop holding a large share
/// of the ledger is estimated to turn up within a few rows of the head: the walk then costs about
/// the same as the index on paper, and it was still chosen with `event_dedup_idx` present on a
/// ledger shaped like the incident. Hidden, the address is costed as an average source, for which
/// the walk is never competitive. `dedup_read_plan_*` in this module's tests holds the plan to the
/// index.
const DEDUP_PRIOR_SQL: &str = "SELECT MAX(observed_at) FROM event \
     WHERE source_ip = (SELECT $1::inet) AND signal_type = $2 AND id < $3";

/// Normalize the storage-lossy fields to their STORED precision BEFORE both hashing and
/// inserting, so the bytes we hash are byte-identical to the bytes storage returns on read.
/// `verify_chain` reconstructs each event FROM storage and re-hashes; if we hashed a value more
/// precise than the column can hold, the re-hash would never match and an UNTAMPERED chain would
/// falsely verify as `Broken`. The principle is "hash what you store":
///   - `observed_at` is `TIMESTAMPTZ` (microsecond precision) -> truncate the sub-µs nanoseconds
///     so the inserted value already carries no precision the column would drop (e.g. a raw
///     `Utc::now()` carries nanoseconds).
///   - `confidence` is `NUMERIC(4,3)` (scale 3) -> rescale to exactly 3 decimal places.
///     `round_dp(3)` only trims excess scale, it never pads (dec!(0.9).round_dp(3) stays "0.9"),
///     so a value-equal low-scale confidence would hash as "0.9" here but read back as "0.900"
///     from storage and false-break verify_chain. `rescale(3)` pads (and rounds if >3dp,
///     unreachable after validate()).
///   - `metadata` is `JSONB` and is intentionally NOT rewritten here: the documented canonical
///     metadata form (JSON integers, strings, and nested objects/arrays thereof) round-trips
///     unchanged, because sqlx re-parses stored `JSONB` into a `BTreeMap`-backed
///     `serde_json::Value` whose lexicographic key order already matches the in-memory value's
///     (this crate does not enable serde_json's `preserve_order`). Floating-point JSON numbers
///     are NOT guaranteed stable across the `JSONB` round-trip and are outside that canonical
///     form. Verified by `verify_chain_intact_with_rich_metadata`.
///
/// `canonical_bytes`/`chain_hash` stay unchanged (deterministic already); normalization belongs
/// at the append boundary, and every append path (single, telemetry, batch) goes through here.
pub(super) fn normalize_event(event: EventInput) -> EventInput {
    let mut confidence = event.confidence;
    confidence.rescale(3);
    EventInput {
        observed_at: event.observed_at.trunc_subsecs(6),
        confidence,
        ..event
    }
}

/// Append one event to the ledger and update the `ip_score` projection in a
/// single transaction, returning the new projection.
///
/// Fails closed: `event.validate()` runs BEFORE any transaction opens, so a
/// malformed event returns `RepoError::Invalid` and writes nothing. Every
/// error inside the transaction propagates, dropping the transaction and
/// rolling it back with no projection committed.
pub async fn append_event(pool: &PgPool, event: EventInput) -> Result<IpScore, RepoError> {
    // 1. Validate first: a malformed event writes NOTHING (no tx opened).
    event.validate()?;

    // 1a. Telemetry never enters the scoring path. Refusing it here, rather than folding a
    // zero-weight row, is what makes "telemetry cannot move a score" a property of the code
    // instead of a property of a tunable number.
    if event.signal_type.is_telemetry() {
        return Err(RepoError::NotScorable(event.signal_type));
    }

    let event = normalize_event(event);

    let mut tx = pool.begin().await?;

    // Pin READ COMMITTED for this transaction regardless of the server's default
    // isolation. The advisory-lock serialization below is only correct under READ
    // COMMITTED, where each statement takes a fresh snapshot so the post-lock
    // chain-head read sees the prior appender's just-committed row. Under REPEATABLE
    // READ / SERIALIZABLE the tx snapshot freezes at the first statement (before the
    // lock is granted), so the head read would miss a concurrent commit and the chain
    // could fork. Must be the first statement in the transaction.
    sqlx::query("SET TRANSACTION ISOLATION LEVEL READ COMMITTED")
        .execute(&mut *tx)
        .await?;

    // 0. Serialize this append against every other concurrent append BEFORE
    // reading the chain head: this is what turns "read head, insert, read
    // projection, upsert" into one atomic critical section. See the
    // module-level "Single-writer model" doc comment for why this is safe
    // and what it does/does not guarantee across a multi-node deployment.
    sqlx::query("SELECT pg_advisory_xact_lock($1)")
        .bind(APPEND_LOCK_KEY)
        .execute(&mut *tx)
        .await?;

    // 2a-2c. Append the row to the hash chain (see `insert_chained`); the returned id anchors
    // the dedup lookup below.
    let new_id = insert_chained(&mut tx, &event).await?;

    // 2d. Read the UN-projected stored projection (double-decay guard: the write
    // path reads the stored raw score AS STORED, never a read-projected value).
    // A corrupt stored `category_breakdown` fails closed here rather than
    // panicking inside the engine's `.expect()`.
    let stored = read_stored_ip_score(&mut *tx, event.source_ip).await?;

    // 2e. Dedup on (source_ip, signal_type): the most recent prior observation,
    // excluding the row we just inserted (id < new_id).
    let prior_observed: Option<DateTime<Utc>> = sqlx::query_scalar(DEDUP_PRIOR_SQL)
        .bind(event.source_ip.to_string())
        .bind(event.signal_type)
        .bind(new_id)
        .fetch_one(&mut *tx)
        .await?;
    // Symmetric window: dedup only a same-signal observation within DEDUP_WINDOW_SECONDS in
    // EITHER time direction. A one-sided `elapsed <= WINDOW` treats any negative elapsed
    // (an out-of-order/earlier-timestamped event from a buffered or clock-skewed sensor) as a
    // duplicate and silently drops its weight, suppressing a genuine attacker's score.
    let deduped = match prior_observed {
        Some(prior) => (event.observed_at - prior).num_seconds().abs() <= DEDUP_WINDOW_SECONDS,
        None => false,
    };

    // 2f. Breadth inputs for this source, INCLUDING the row just inserted.
    let (dwc, dsc) = fold_breadth_sets(&mut tx, &event).await?;

    // 2g. Pure projection step (no DB, no clock).
    let new_score = apply_event(stored, &event, HALF_LIFE_SECONDS, deduped, dwc, dsc);

    // 2h. Upsert the projection.
    sqlx::query(
        "INSERT INTO ip_score \
         (source_ip, raw_score, decay_anchor, max_confidence, event_count, distinct_categories, \
          category_breakdown, has_confirmed_real, distinct_wan_count, distinct_sensor_count, \
          first_seen, last_seen, eligible, recommended_for_vendor, recommended_for_blocklist, tier, delisted, \
          active_days, last_active_day, established_event_count) \
         VALUES ($1::inet, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20) \
         ON CONFLICT (source_ip) DO UPDATE SET \
           raw_score = EXCLUDED.raw_score, \
           decay_anchor = EXCLUDED.decay_anchor, \
           max_confidence = EXCLUDED.max_confidence, \
           event_count = EXCLUDED.event_count, \
           distinct_categories = EXCLUDED.distinct_categories, \
           category_breakdown = EXCLUDED.category_breakdown, \
           has_confirmed_real = EXCLUDED.has_confirmed_real, \
           distinct_wan_count = EXCLUDED.distinct_wan_count, \
           distinct_sensor_count = EXCLUDED.distinct_sensor_count, \
           first_seen = EXCLUDED.first_seen, \
           last_seen = EXCLUDED.last_seen, \
           eligible = EXCLUDED.eligible, \
           recommended_for_vendor = EXCLUDED.recommended_for_vendor, \
           recommended_for_blocklist = EXCLUDED.recommended_for_blocklist, \
           tier = EXCLUDED.tier, \
           active_days = EXCLUDED.active_days, \
           last_active_day = EXCLUDED.last_active_day, \
           established_event_count = EXCLUDED.established_event_count",
    )
    .bind(new_score.source_ip.to_string())
    .bind(new_score.raw_score)
    .bind(new_score.decay_anchor)
    .bind(new_score.max_confidence)
    .bind(new_score.event_count)
    .bind(new_score.distinct_categories)
    .bind(&new_score.category_breakdown)
    .bind(new_score.has_confirmed_real)
    .bind(new_score.distinct_wan_count)
    .bind(new_score.distinct_sensor_count)
    .bind(new_score.first_seen)
    .bind(new_score.last_seen)
    .bind(new_score.eligible)
    .bind(new_score.recommended_for_vendor)
    .bind(new_score.recommended_for_blocklist)
    .bind(new_score.tier)
    .bind(new_score.delisted)
    .bind(new_score.active_days)
    .bind(new_score.last_active_day)
    .bind(new_score.established_event_count)
    .execute(&mut *tx)
    .await?;

    // 2i. Commit; only now is the projection durable.
    tx.commit().await?;
    Ok(new_score)
}

/// Read the chain head, bind this event's hash to it, and insert the row. Shared by the scoring
/// append and [`append_telemetry_event`] so the two can never compute the chain differently; both
/// call it while holding the append advisory lock, which is what makes the head read and the
/// insert one critical section.
pub(super) async fn insert_chained(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    event: &EventInput,
) -> Result<i64, RepoError> {
    let prev_head: Option<Vec<u8>> =
        sqlx::query_scalar("SELECT hash FROM event ORDER BY id DESC LIMIT 1")
            .fetch_optional(&mut **tx)
            .await?;
    let hash = chain_hash(prev_head.as_deref(), event);
    let wan_ip_txt: Option<String> = event.wan_ip.map(|ip| ip.to_string());
    let new_id: i64 = sqlx::query_scalar(
        "INSERT INTO event \
         (source_ip, wan_ip, sensor, signal_type, protocol, authenticated, category, \
          weight, confidence, observed_at, metadata, prev_hash, hash, session_id) \
         VALUES ($1::inet, $2::inet, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14) \
         RETURNING id",
    )
    .bind(event.source_ip.to_string())
    .bind(wan_ip_txt)
    .bind(&event.sensor)
    .bind(event.signal_type)
    .bind(event.protocol)
    .bind(event.authenticated)
    .bind(event.category)
    .bind(event.weight as i32)
    .bind(event.confidence)
    .bind(event.observed_at)
    .bind(&event.metadata)
    .bind(prev_head.as_deref())
    .bind(hash.as_slice())
    .bind(event.session_id)
    .fetch_one(&mut **tx)
    .await?;
    Ok(new_id)
}

/// Fold one scored event into its source's vantage and sensor sets (migration 0014) and return the
/// breadth inputs `apply_event` takes: the distinct authenticated WAN vantage count and the
/// distinct sensor count, both including this event.
///
/// The sets hold exactly what the whole-history aggregates this replaced derived from the ledger
/// (a `GROUP BY wan_ip` with `bool_or(protocol = 'tcp' AND authenticated)`, and a
/// `COUNT(DISTINCT sensor)`, each over the source's scored rows), so each append reads one row per
/// WAN and one per sensor however long the source's history is. Called only by [`append_event`],
/// under the append lock, after the event row is inserted; [`append_telemetry_event`] never calls
/// it, which is what keeps telemetry out of breadth. `rebuild_projection` still derives both
/// inputs from the ledger rows themselves, so replay stays an independent check on these sets.
///
/// The vantage upsert writes only when the flag turns from false to true. Ever-seen is an OR over
/// the source's history, so a conflicting row that is already true, or an event that is not
/// authenticated TCP, changes nothing, and skipping the write spares a dead row version per event
/// for a bot loop that hits the same WAN all day.
async fn fold_breadth_sets(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    event: &EventInput,
) -> Result<(i32, i32), RepoError> {
    let source_ip = event.source_ip.to_string();
    if let Some(wan_ip) = event.wan_ip {
        sqlx::query(
            "INSERT INTO ip_vantage (source_ip, wan_ip, saw_authenticated_tcp) \
             VALUES ($1::inet, $2::inet, $3) \
             ON CONFLICT (source_ip, wan_ip) DO UPDATE \
             SET saw_authenticated_tcp = ip_vantage.saw_authenticated_tcp OR EXCLUDED.saw_authenticated_tcp \
             WHERE EXCLUDED.saw_authenticated_tcp AND NOT ip_vantage.saw_authenticated_tcp",
        )
        .bind(&source_ip)
        .bind(wan_ip.to_string())
        .bind(event.protocol == Protocol::Tcp && event.authenticated)
        .execute(&mut **tx)
        .await?;
    }
    sqlx::query(
        "INSERT INTO ip_sensor (source_ip, sensor) VALUES ($1::inet, $2) \
         ON CONFLICT (source_ip, sensor) DO NOTHING",
    )
    .bind(&source_ip)
    .bind(&event.sensor)
    .execute(&mut **tx)
    .await?;

    let vantage_rows = sqlx::query(
        "SELECT host(wan_ip) AS wan, saw_authenticated_tcp FROM ip_vantage WHERE source_ip = $1::inet",
    )
    .bind(&source_ip)
    .fetch_all(&mut **tx)
    .await?;
    let mut vantages: Vec<WanVantage> = Vec::with_capacity(vantage_rows.len());
    for row in vantage_rows {
        let wan: String = row.try_get("wan")?;
        let wan_ip: IpAddr = wan
            .parse()
            .map_err(|e| RepoError::Corrupt(format!("stored wan_ip {wan}: {e}")))?;
        vantages.push(WanVantage {
            wan_ip,
            saw_authenticated_tcp: row.try_get("saw_authenticated_tcp")?,
        });
    }
    let sensors: i64 =
        sqlx::query_scalar("SELECT count(*) FROM ip_sensor WHERE source_ip = $1::inet")
            .bind(&source_ip)
            .fetch_one(&mut **tx)
            .await?;
    Ok((distinct_wan_count(&vantages) as i32, sensors as i32))
}

/// Append a TELEMETRY event: it joins the hash chain like any other record, and touches no
/// scoring state at all - no projection is read or written, so an address seen only through
/// telemetry has no `ip_score` row, and an address that already has one keeps it byte for byte.
///
/// This is the only way a telemetry signal reaches the ledger; [`append_event`] refuses one. The
/// separation is deliberate: it makes "telemetry cannot move a score" a structural property
/// rather than an arithmetic accident of a zero weight, which someone could later tune.
pub async fn append_telemetry_event(pool: &PgPool, event: EventInput) -> Result<(), RepoError> {
    event.validate()?;
    if !event.signal_type.is_telemetry() {
        return Err(RepoError::NotScorable(event.signal_type));
    }
    let event = normalize_event(event);

    let mut tx = pool.begin().await?;
    sqlx::query("SET TRANSACTION ISOLATION LEVEL READ COMMITTED")
        .execute(&mut *tx)
        .await?;
    // The same append lock the scoring path takes: the chain is one sequence, so a telemetry
    // append and a scored append must not interleave between head-read and insert.
    sqlx::query("SELECT pg_advisory_xact_lock($1)")
        .bind(APPEND_LOCK_KEY)
        .execute(&mut *tx)
        .await?;
    insert_chained(&mut tx, &event).await?;
    tx.commit().await?;
    Ok(())
}

/// Read the stored projection for `ip`, projected to now: `raw_score` and each category weight are
/// decayed to now and the gate flags (eligible/tier/recommendations/`max_confidence`) are
/// RE-DERIVED, so the returned facts are current rather than frozen at the last write (a category
/// that has decayed below the 0.5 floor drops eligibility/tier).
///
/// PURE read: the projected value is NEVER written back - the stored row stays un-projected so a
/// later append reads its raw score un-decayed (double-decay guard).
pub async fn read_score<'e, E>(exec: E, ip: IpAddr) -> Result<Option<IpScore>, RepoError>
where
    E: sqlx::Executor<'e, Database = Postgres>,
{
    let Some(stored) = read_stored_ip_score(exec, ip).await? else {
        return Ok(None);
    };
    Ok(Some(project_to_now(stored, Utc::now(), HALF_LIFE_SECONDS)))
}

/// Read the stored `ip_score` row AS STORED - no decay-to-now projection.
///
/// Unlike [`read_score`], this returns the raw persisted projection exactly as
/// the incremental append path last wrote it (its `raw_score` still anchored at
/// the last event's `observed_at`). This is the correct comparison target for
/// replay verification: `rebuild_projection` reproduces this stored value, not a
/// value re-decayed to the current wall clock.
pub async fn read_stored_score(pool: &PgPool, ip: IpAddr) -> Result<Option<IpScore>, RepoError> {
    read_stored_ip_score(pool, ip).await
}

/// Read the stored `ip_score` row AS STORED (no projection), mapping it into an
/// `IpScore`. Returns `Ok(None)` when absent. Fails closed with
/// `RepoError::Corrupt` if the stored IP or `category_breakdown` cannot be
/// parsed into the shape the engine requires.
async fn read_stored_ip_score<'e, E>(exec: E, ip: IpAddr) -> Result<Option<IpScore>, RepoError>
where
    E: sqlx::Executor<'e, Database = Postgres>,
{
    let row = sqlx::query(concat!(
        "SELECT ",
        stored_score_columns!(),
        " FROM ip_score WHERE source_ip = $1::inet"
    ))
    .bind(ip.to_string())
    .fetch_optional(exec)
    .await?;

    row.as_ref().map(score_from_row).transpose()
}

/// Decode one `ip_score` row selected with [`stored_score_columns!`].
pub(super) fn score_from_row(row: &sqlx::postgres::PgRow) -> Result<IpScore, RepoError> {
    let source_ip_txt: String = row.try_get("source_ip")?;
    let source_ip: IpAddr = source_ip_txt
        .parse()
        .map_err(|e| RepoError::Corrupt(format!("stored source_ip {source_ip_txt}: {e}")))?;

    let category_breakdown: serde_json::Value = row.try_get("category_breakdown")?;
    // Guard the value the engine will `.expect()` on: if it is not a valid
    // CategoryStat map, fail closed here instead of panicking downstream.
    serde_json::from_value::<BTreeMap<Category, CategoryStat>>(category_breakdown.clone())
        .map_err(|e| RepoError::Corrupt(format!("category_breakdown for {source_ip}: {e}")))?;

    Ok(IpScore {
        source_ip,
        raw_score: row.try_get("raw_score")?,
        decay_anchor: row.try_get("decay_anchor")?,
        max_confidence: row.try_get("max_confidence")?,
        event_count: row.try_get("event_count")?,
        established_event_count: row.try_get("established_event_count")?,
        distinct_categories: row.try_get("distinct_categories")?,
        category_breakdown,
        has_confirmed_real: row.try_get("has_confirmed_real")?,
        distinct_wan_count: row.try_get("distinct_wan_count")?,
        distinct_sensor_count: row.try_get("distinct_sensor_count")?,
        active_days: row.try_get("active_days")?,
        // Backfilled to last_seen's date by migration 0010; fall back to it defensively so a NULL
        // can never panic the read path.
        last_active_day: row
            .try_get::<Option<NaiveDate>, _>("last_active_day")?
            .unwrap_or_else(|| {
                row.try_get::<DateTime<Utc>, _>("last_seen")
                    .map(|ls| ls.date_naive())
                    .unwrap_or_default()
            }),
        first_seen: row.try_get("first_seen")?,
        last_seen: row.try_get("last_seen")?,
        eligible: row.try_get("eligible")?,
        recommended_for_vendor: row.try_get("recommended_for_vendor")?,
        recommended_for_blocklist: row.try_get("recommended_for_blocklist")?,
        tier: row.try_get("tier")?,
        delisted: row.try_get("delisted")?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A bot loop whose history is all older than the rest of the ledger.
    const HOT: &str = "198.51.100.3";
    const LEDGER_ROWS: i64 = 100_000;
    const HOT_ROWS: i64 = 30_000;

    /// Loads a ledger shaped like the October 2026 incident: one source holds 30% of the rows, all
    /// of them older than every other sensor's 70,000 newer rows, so its latest sighting sits far
    /// below the head of `event_observed_at_idx`. Statistics are gathered from every row (the
    /// targets exceed the table), so the planner's inputs are the same on every run. Returns the id
    /// the next append would get, which is the `id < $3` bound the append path passes.
    async fn load_incident_ledger(pool: &PgPool) -> sqlx::Result<i64> {
        sqlx::query("ALTER TABLE event DISABLE TRIGGER trg_enforce_chain_linkage")
            .execute(pool)
            .await?;
        sqlx::query(
            "INSERT INTO event (source_ip, wan_ip, sensor, signal_type, protocol, authenticated, \
                                category, weight, confidence, observed_at, metadata, prev_hash, hash) \
             SELECT CASE WHEN g <= $2 THEN $3::inet ELSE '10.0.0.0'::inet + (g % 5000) END, \
                    '203.0.113.10'::inet, \
                    CASE WHEN g <= $2 THEN 'telnet' ELSE 'vnc' END, \
                    'honeypot_command_exec', 'tcp', true, 'honeypot', 60, 0.950, \
                    timestamptz '2026-08-01 00:00:00+00' + g * interval '10 seconds', \
                    '{}'::jsonb, \
                    CASE WHEN g = 1 THEN NULL ELSE sha256(int8send(g - 1)) END, \
                    sha256(int8send(g)) \
             FROM generate_series(1, $1) AS g",
        )
        .bind(LEDGER_ROWS)
        .bind(HOT_ROWS)
        .bind(HOT)
        .execute(pool)
        .await?;
        sqlx::query("ALTER TABLE event ENABLE TRIGGER trg_enforce_chain_linkage")
            .execute(pool)
            .await?;
        for column in ["id", "source_ip", "signal_type", "observed_at"] {
            sqlx::query(sqlx::AssertSqlSafe(format!(
                "ALTER TABLE event ALTER COLUMN {column} SET STATISTICS 10000"
            )))
            .execute(pool)
            .await?;
        }
        sqlx::query("ANALYZE event").execute(pool).await?;
        sqlx::query_scalar("SELECT max(id) + 1 FROM event")
            .fetch_one(pool)
            .await
    }

    fn index_names(node: &serde_json::Value, out: &mut Vec<String>) {
        match node {
            serde_json::Value::Object(map) => {
                for (key, value) in map {
                    match (key.as_str(), value) {
                        ("Index Name", serde_json::Value::String(name)) => out.push(name.clone()),
                        _ => index_names(value, out),
                    }
                }
            }
            serde_json::Value::Array(items) => items.iter().for_each(|i| index_names(i, out)),
            _ => {}
        }
    }

    /// The dedup read as it stood when the incident happened: the address bound as a literal.
    const INCIDENT_DEDUP_SQL: &str = "SELECT MAX(observed_at) FROM event \
         WHERE source_ip = $1::inet AND signal_type = $2 AND id < $3";

    /// The indexes a custom plan of `sql` reads for the hot source, with the values the append
    /// path binds.
    async fn custom_plan_indexes<'e, E>(
        exec: E,
        sql: &str,
        next_id: i64,
    ) -> sqlx::Result<Vec<String>>
    where
        E: sqlx::Executor<'e, Database = Postgres>,
    {
        let plan: serde_json::Value =
            sqlx::query_scalar(sqlx::AssertSqlSafe(format!("EXPLAIN (FORMAT JSON) {sql}")))
                .bind(HOT)
                .bind(SignalType::HoneypotCommandExec)
                .bind(next_id)
                .fetch_one(exec)
                .await?;
        let mut names = Vec::new();
        index_names(&plan, &mut names);
        Ok(names)
    }

    /// A custom plan for the incident's hot source reads the dedup index and never walks
    /// `event_observed_at_idx`. The fixture is checked to provoke that walk for the statement and
    /// schema the incident ran on, so the guard cannot pass on a ledger the planner would have
    /// handled anyway.
    #[sqlx::test(migrations = "./migrations")]
    async fn dedup_read_plan_uses_the_dedup_index_on_an_incident_shaped_ledger(
        pool: PgPool,
    ) -> sqlx::Result<()> {
        let next_id = load_incident_ledger(&pool).await?;

        let custom = custom_plan_indexes(&pool, DEDUP_PRIOR_SQL, next_id).await?;
        assert!(
            custom.iter().any(|n| n == "event_dedup_idx"),
            "the dedup read must use event_dedup_idx, plan read {custom:?}"
        );
        assert!(
            !custom.iter().any(|n| n == "event_observed_at_idx"),
            "the dedup read must not walk event_observed_at_idx, plan read {custom:?}"
        );

        let mut tx = pool.begin().await?;
        sqlx::query("DROP INDEX event_dedup_idx")
            .execute(&mut *tx)
            .await?;
        let incident = custom_plan_indexes(&mut *tx, INCIDENT_DEDUP_SQL, next_id).await?;
        tx.rollback().await?;
        assert!(
            incident.iter().any(|n| n == "event_observed_at_idx"),
            "the incident's statement and schema must walk event_observed_at_idx on this ledger, \
             or the guard above proves nothing; plan read {incident:?}"
        );
        Ok(())
    }

    /// The batched dedup read answers every (source, signal) key from `event_dedup_idx` on the
    /// same incident-shaped ledger, for the hot source and a cold one, never by walking
    /// `event_observed_at_idx`. The ledger is the one the guard above proves provokes that walk.
    #[sqlx::test(migrations = "./migrations")]
    async fn batch_dedup_read_plan_uses_the_dedup_index(pool: PgPool) -> sqlx::Result<()> {
        load_incident_ledger(&pool).await?;
        let sql = super::super::batch::DEDUP_PRIORS_SQL;
        let plan: serde_json::Value =
            sqlx::query_scalar(sqlx::AssertSqlSafe(format!("EXPLAIN (FORMAT JSON) {sql}")))
                .bind(vec![HOT.to_string(), "10.0.0.7".to_string()])
                .bind(vec![SignalType::HoneypotCommandExec; 2])
                .fetch_one(&pool)
                .await?;
        let mut names = Vec::new();
        index_names(&plan, &mut names);
        assert!(
            names.iter().any(|n| n == "event_dedup_idx"),
            "the batched dedup read must use event_dedup_idx, plan read {names:?}"
        );
        assert!(
            !names.iter().any(|n| n == "event_observed_at_idx"),
            "the batched dedup read must not walk event_observed_at_idx, plan read {names:?}"
        );
        Ok(())
    }

    /// The same statement as a generic prepared plan, the form a long-lived pooled connection
    /// switches to after five executions.
    #[sqlx::test(migrations = "./migrations")]
    async fn dedup_read_plan_generic_form_uses_the_dedup_index(pool: PgPool) -> sqlx::Result<()> {
        load_incident_ledger(&pool).await?;
        let plan: serde_json::Value = sqlx::raw_sql(sqlx::AssertSqlSafe(format!(
            "EXPLAIN (GENERIC_PLAN, FORMAT JSON) {DEDUP_PRIOR_SQL}"
        )))
        .fetch_one(&pool)
        .await?
        .try_get(0)?;
        let mut names = Vec::new();
        index_names(&plan, &mut names);
        assert!(
            names.iter().any(|n| n == "event_dedup_idx"),
            "the generic dedup plan must use event_dedup_idx, plan read {names:?}"
        );
        assert!(
            !names.iter().any(|n| n == "event_observed_at_idx"),
            "the generic dedup plan must not walk event_observed_at_idx, plan read {names:?}"
        );
        Ok(())
    }
}
