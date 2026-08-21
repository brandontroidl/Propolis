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
//! `ip_score` UPSERT all execute as one serialized critical section. Under READ
//! COMMITTED each statement takes a fresh snapshot, so once the lock is granted
//! the chain-head read sees the prior appender's committed row (under REPEATABLE
//! READ / SERIALIZABLE the snapshot would freeze before the lock and the chain
//! could fork - hence the explicit pin). This guarantees, under any number of
//! concurrent callers:
//!
//! - the tamper-evident hash chain cannot fork (no two appends can read the
//!   same `prev_hash` and both insert against it);
//! - the `ip_score` projection UPSERT cannot lose an update to a
//!   last-write-wins race;
//! - the dedup window read (`MAX(observed_at)` for the same `source_ip` +
//!   `signal_type`) cannot be bypassed by an interleaved concurrent insert.
//!
//! `pg_advisory_xact_lock` auto-releases at transaction end (commit or
//! rollback), so a failed/rolled-back append never leaves the lock held.
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

use crate::domain::enums::Category;
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
}

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
const APPEND_LOCK_KEY: i64 = 7_265_646_772_697_400_001;

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

    // 1b. Normalize the storage-lossy fields to their STORED precision BEFORE
    // both hashing and inserting, so the bytes we hash are byte-identical to the
    // bytes storage returns on read. `verify_chain` reconstructs each event FROM
    // storage and re-hashes; if we hashed a value more precise than the column
    // can hold, the re-hash would never match and an UNTAMPERED chain would
    // falsely verify as `Broken`. The principle is "hash what you store":
    //   - `observed_at` is `TIMESTAMPTZ` (microsecond precision) -> truncate the
    //     sub-µs nanoseconds so the inserted value already carries no precision
    //     the column would drop (e.g. a raw `Utc::now()` carries nanoseconds).
    //   - `confidence` is `NUMERIC(4,3)` (scale 3) -> round to 3 decimal places
    //     so the inserted value already has the scale the column returns.
    //   - `metadata` is `JSONB` and is intentionally NOT rewritten here: the
    //     documented canonical metadata form (JSON integers, strings, and nested
    //     objects/arrays thereof) round-trips unchanged, because sqlx re-parses
    //     stored `JSONB` into a `BTreeMap`-backed `serde_json::Value` whose
    //     lexicographic key order already matches the in-memory value's (this
    //     crate does not enable serde_json's `preserve_order`). Floating-point
    //     JSON numbers are NOT guaranteed stable across the `JSONB` round-trip
    //     and are outside that canonical form. Verified by
    //     `verify_chain_intact_with_rich_metadata`.
    // `canonical_bytes`/`chain_hash` stay unchanged (deterministic already);
    // normalization belongs here at the append boundary.
    // Normalize confidence to EXACTLY scale-3 to match the NUMERIC(4,3) column. `round_dp(3)`
    // only trims excess scale, it never pads (dec!(0.9).round_dp(3) stays "0.9"), so a value-equal
    // low-scale confidence would hash as "0.9" here but read back as "0.900" from storage and
    // false-break verify_chain. `rescale(3)` pads (and rounds if >3dp, unreachable after validate()).
    let mut confidence = event.confidence;
    confidence.rescale(3);
    let event = EventInput {
        observed_at: event.observed_at.trunc_subsecs(6),
        confidence,
        ..event
    };

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

    // 2a. Chain head hash (None for the first event ever).
    let prev_head: Option<Vec<u8>> =
        sqlx::query_scalar("SELECT hash FROM event ORDER BY id DESC LIMIT 1")
            .fetch_optional(&mut *tx)
            .await?;

    // 2b. Compute this event's chain hash bound to the head.
    let hash = chain_hash(prev_head.as_deref(), &event);

    // 2c. Insert the event row; RETURNING id anchors the dedup lookup below.
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
    .fetch_one(&mut *tx)
    .await?;

    // 2d. Read the UN-projected stored projection (double-decay guard: the write
    // path reads the stored raw score AS STORED, never a read-projected value).
    // A corrupt stored `category_breakdown` fails closed here rather than
    // panicking inside the engine's `.expect()`.
    let stored = read_stored_ip_score(&mut *tx, event.source_ip).await?;

    // 2e. Dedup on (source_ip, signal_type): the most recent prior observation,
    // excluding the row we just inserted (id < new_id).
    let prior_observed: Option<DateTime<Utc>> = sqlx::query_scalar(
        "SELECT MAX(observed_at) FROM event \
         WHERE source_ip = $1::inet AND signal_type = $2 AND id < $3",
    )
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

    // 2f. Breadth inputs from the ledger for this source (INCLUDING the row just
    // inserted). One vantage per distinct non-null wan_ip; `saw_authenticated_tcp`
    // is true if ANY event from this source on that wan was authenticated tcp.
    let vantage_rows = sqlx::query(
        "SELECT host(wan_ip) AS wan, \
                bool_or(protocol = 'tcp' AND authenticated) AS auth_tcp \
         FROM event \
         WHERE source_ip = $1::inet AND wan_ip IS NOT NULL \
         GROUP BY wan_ip",
    )
    .bind(event.source_ip.to_string())
    .fetch_all(&mut *tx)
    .await?;
    let mut vantages: Vec<WanVantage> = Vec::with_capacity(vantage_rows.len());
    for row in vantage_rows {
        let wan: String = row.try_get("wan")?;
        let saw_authenticated_tcp: bool =
            row.try_get::<Option<bool>, _>("auth_tcp")?.unwrap_or(false);
        let wan_ip: IpAddr = wan
            .parse()
            .map_err(|e| RepoError::Corrupt(format!("stored wan_ip {wan}: {e}")))?;
        vantages.push(WanVantage {
            wan_ip,
            saw_authenticated_tcp,
        });
    }
    let dwc = distinct_wan_count(&vantages) as i32;

    let dsc: i64 =
        sqlx::query_scalar("SELECT COUNT(DISTINCT sensor) FROM event WHERE source_ip = $1::inet")
            .bind(event.source_ip.to_string())
            .fetch_one(&mut *tx)
            .await?;
    let dsc = dsc as i32;

    // 2g. Pure projection step (no DB, no clock).
    let new_score = apply_event(stored, &event, HALF_LIFE_SECONDS, deduped, dwc, dsc);

    // 2h. Upsert the projection.
    sqlx::query(
        "INSERT INTO ip_score \
         (source_ip, raw_score, decay_anchor, max_confidence, event_count, distinct_categories, \
          category_breakdown, has_confirmed_real, distinct_wan_count, distinct_sensor_count, \
          first_seen, last_seen, eligible, recommended_for_vendor, recommended_for_blocklist, tier, delisted, \
          active_days, last_active_day) \
         VALUES ($1::inet, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19) \
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
           last_active_day = EXCLUDED.last_active_day",
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
    .execute(&mut *tx)
    .await?;

    // 2i. Commit; only now is the projection durable.
    tx.commit().await?;
    Ok(new_score)
}

/// Read the stored projection for `ip`, projected to now: `raw_score` and each category weight are
/// decayed to now and the gate flags (eligible/tier/recommendations/`max_confidence`) are
/// RE-DERIVED, so the returned facts are current rather than frozen at the last write (a category
/// that has decayed below the 0.5 floor drops eligibility/tier).
///
/// PURE read: the projected value is NEVER written back - the stored row stays un-projected so a
/// later append reads its raw score un-decayed (double-decay guard).
pub async fn read_score(pool: &PgPool, ip: IpAddr) -> Result<Option<IpScore>, RepoError> {
    let Some(stored) = read_stored_ip_score(pool, ip).await? else {
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
    let row = sqlx::query(
        "SELECT host(source_ip) AS source_ip, raw_score, decay_anchor, max_confidence, \
                event_count, distinct_categories, category_breakdown, has_confirmed_real, \
                distinct_wan_count, distinct_sensor_count, first_seen, last_seen, eligible, \
                recommended_for_vendor, recommended_for_blocklist, tier, delisted, \
                active_days, last_active_day \
         FROM ip_score WHERE source_ip = $1::inet",
    )
    .bind(ip.to_string())
    .fetch_optional(exec)
    .await?;

    let Some(row) = row else {
        return Ok(None);
    };

    let source_ip_txt: String = row.try_get("source_ip")?;
    let source_ip: IpAddr = source_ip_txt
        .parse()
        .map_err(|e| RepoError::Corrupt(format!("stored source_ip {source_ip_txt}: {e}")))?;

    let category_breakdown: serde_json::Value = row.try_get("category_breakdown")?;
    // Guard the value the engine will `.expect()` on: if it is not a valid
    // CategoryStat map, fail closed here instead of panicking downstream.
    serde_json::from_value::<BTreeMap<Category, CategoryStat>>(category_breakdown.clone())
        .map_err(|e| RepoError::Corrupt(format!("category_breakdown for {source_ip}: {e}")))?;

    Ok(Some(IpScore {
        source_ip,
        raw_score: row.try_get("raw_score")?,
        decay_anchor: row.try_get("decay_anchor")?,
        max_confidence: row.try_get("max_confidence")?,
        event_count: row.try_get("event_count")?,
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
    }))
}
