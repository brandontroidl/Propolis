//! Hourly roll-up of the event ledger by listener (`event_hour_listener`; core-scoring migration
//! 0025) that lets the dashboard and the fleet pane count a time window without grouping every
//! event in it.
//!
//! **What is stored.** Per UTC hour, the events and the newest `observed_at` of each listener
//! (sensor, protocol, port). It is derived, never authoritative: the ledger is, and nothing here
//! touches it.
//!
//! **How it is kept.** [`refresh`] folds the events past `event_rollup_cursor.last_event_id` into
//! the table and advances the cursor in one transaction, so a crash between the two cannot count an
//! event twice or skip one. It is called by the pages that read the roll-up, before they read, and
//! does nothing when the roll-up is current. Ids are assigned and committed in order (every append
//! holds the global advisory lock until it commits), so everything at or below the cursor is final.
//!
//! **Why a number is exact whether or not the roll-up is current.** A window `[S, now)` is
//! assembled from three parts that cannot overlap or leave a gap:
//!
//! 1. the roll-up rows for hours at or after `H1`, the first hour boundary at or after `S`
//!    (events with an id up to the cursor);
//! 2. the ledger's own events with `S <= observed_at < H1`, whatever their id: the partial hour at
//!    the start of the window, which an hourly row cannot split;
//! 3. the ledger's own events with `id > cursor` and `observed_at >= H1`: whatever the roll-up has
//!    not folded yet.
//!
//! An event is in part 1 or part 3 by its id and in part 2 by its time, and part 2 is exactly the
//! hours part 1 and part 3 leave out. [`listener_window_sql`] writes this once for every reader.
//!
//! **What a roll-up that is not current costs.** The page then reads more of the ledger, and how
//! much grows with how far behind the roll-up is, bounded by a window read off
//! `event_observed_at_idx` and filtered by id. Each row of that read costs more than the old
//! single-column count did (an hour function, a JSON extraction, four group keys): about four
//! times its total on the 1.5M-event seed with the cursor 7 days back (279 ms against 73 ms for
//! the sensor split), where a current roll-up takes 8.7 ms. The
//! planner picks between that and the id range past the cursor, but only if it can see how much
//! the id range keeps, and the cursor reaches the statement as a subquery it cannot evaluate. So
//! [`Health::refresh_for_page`] returns the cursor it just read and [`listener_window_sql`] repeats
//! it as a literal beside the subquery: `id > (SELECT ...) AND id > <that literal>`. The subquery
//! stays the authority (it is read in the statement's own snapshot, so part 1 and part 3 can never
//! disagree about where the cursor is, even if another page advances it in between); the literal
//! only tells the planner the selectivity. That is exact as long as the cursor never moves down,
//! which it does not in a running system: the one place it is lowered, `fold_batch` noticing a
//! ledger shorter than its cursor, is a database whose ids were reset. A statement carrying a
//! literal is not prepared for reuse (it would fill the statement cache with one entry per value).
//!
//! **Refresh that keeps failing** logs a warning each time and is counted by [`Health`]; the
//! dashboard names it in its degraded banner and `/metrics` exports the count, so a roll-up that
//! stopped being maintained is visible as that rather than as a page that slowly gets slower.
//!
//! **What it does not do.** The dashboard's most-active panel groups by source address. A roll-up
//! by (hour, source address) was built and measured for it and dropped: the hour-by-source rows of
//! a day are about half as many as its events, so summing them cost 275 ms against 535 ms for the
//! ledger, not enough for a table that holds most of an event per row. That panel is held for a
//! short while instead (`crate::read_state`).

use std::sync::atomic::{AtomicU32, Ordering};

use sqlx::PgPool;

/// Events folded per transaction. A bound on how long one refresh holds its locks and how much it
/// writes at once, not a limit: [`refresh`] runs batches until it has caught up or hit
/// [`MAX_BATCHES`].
const BATCH: i64 = 100_000;

/// Batches one [`refresh`] call runs before returning, so a page that triggers a long catch-up
/// (after downtime) is delayed by a bounded amount of work and the rest is read from the ledger.
const MAX_BATCHES: usize = 3;

/// The advisory-lock key serialising refreshes (a value no other lock in this codebase uses: the
/// append lock is a different constant). One refresher at a time; a second caller skips, because
/// the first is already doing the work.
const REFRESH_LOCK: i64 = 0x0070_726f_6c6c_7570; // "prollup"

/// How long hours are kept: the 30-day chart plus its partial days, with headroom.
const KEEP: &str = "45 days";

/// Folds the events appended since the last refresh into the roll-up. Returns how many ledger ids
/// it covered (a gap left by a rolled-back append counts). Cheap when current (three small
/// statements); a failure leaves the roll-up as it was, since each batch is one transaction, and
/// the readers fall back to the ledger for what is not folded.
pub async fn refresh(db: &PgPool) -> Result<u64, sqlx::Error> {
    refresh_with(db, BATCH, MAX_BATCHES).await
}

/// Failures of [`Health::refresh_for_page`] in a row below which nothing is reported: one failure
/// is a lost connection or a busy database, and the next page's refresh most likely folds it.
pub const FAILING_AFTER: u32 = 3;

/// Whether the pages' roll-up refresh is working, kept per console (`crate::read_state`).
#[derive(Debug, Default)]
pub struct Health {
    consecutive_failures: AtomicU32,
}

impl Health {
    /// [`refresh`] for a page that is about to read the roll-up. A failure is logged and counted
    /// and the page goes on, because every reader assembles an exact answer from the ledger for
    /// whatever is not folded. Returns the cursor to hand [`listener_window_sql`], or `0` (no
    /// narrowing, the planner's own estimate) when it cannot be read.
    pub async fn refresh_for_page(&self, db: &PgPool) -> i64 {
        match refresh(db).await {
            Ok(_) => self.consecutive_failures.store(0, Ordering::Relaxed),
            Err(error) => {
                let n = self.consecutive_failures.fetch_add(1, Ordering::Relaxed) + 1;
                tracing::warn!(%error, failures_in_a_row = n, "console: roll-up refresh failed; reading the ledger for what is not folded");
            }
        }
        cursor(db).await.unwrap_or(0)
    }

    /// Refreshes in a row that failed, since the last one that worked.
    pub fn consecutive_failures(&self) -> u32 {
        self.consecutive_failures.load(Ordering::Relaxed)
    }

    /// Whether refresh has failed [`FAILING_AFTER`] times running.
    pub fn failing(&self) -> bool {
        self.consecutive_failures() >= FAILING_AFTER
    }
}

/// The highest ledger id folded into the roll-up.
pub async fn cursor(db: &PgPool) -> Result<i64, sqlx::Error> {
    sqlx::query_scalar("SELECT last_event_id FROM event_rollup_cursor")
        .fetch_one(db)
        .await
}

/// Whether the session time zone's offset is a whole number of hours both now and 45 days ago (the
/// oldest hour the roll-up keeps), which is when a local hour or day anywhere in the span is a run
/// of the UTC hours the roll-up holds. In a zone offset by 30 or 45 minutes (India, Nepal) a local
/// day starts mid-hour, so the per-hour and per-day charts read the ledger instead; so they do in
/// a zone whose daylight-saving shift is half an hour (Lord Howe), whose offset is whole for part
/// of the year only. The rolling-window counts do not care: they bucket on the UTC hour whatever
/// the zone.
pub async fn whole_hour_zone(db: &PgPool) -> Result<bool, sqlx::Error> {
    whole_hour_zone_at(db, None).await
}

/// [`whole_hour_zone`] as of `at` (the database's `now()` when `None`), so the answer for a zone
/// and a date does not depend on the day a test happens to run.
pub async fn whole_hour_zone_at(
    db: &PgPool,
    at: Option<chrono::DateTime<chrono::Utc>>,
) -> Result<bool, sqlx::Error> {
    sqlx::query_scalar(sqlx::AssertSqlSafe(format!(
        "SELECT EXTRACT(TIMEZONE_MINUTE FROM t)::int = 0 \
            AND EXTRACT(TIMEZONE_MINUTE FROM t - interval '{KEEP}')::int = 0 \
         FROM (SELECT COALESCE($1::timestamptz, now()) AS t) x"
    )))
    .bind(at)
    .fetch_one(db)
    .await
}

/// [`refresh`] with explicit bounds, for tests that need several small batches.
pub async fn refresh_with(db: &PgPool, batch: i64, max_batches: usize) -> Result<u64, sqlx::Error> {
    let mut folded = 0u64;
    for _ in 0..max_batches {
        match fold_batch(db, batch).await? {
            Some(n) => folded += n,
            None => break,
        }
    }
    Ok(folded)
}

/// One transaction: fold up to `batch` events (ids). `None` when there is nothing to fold (caught
/// up) or another refresh holds the lock.
async fn fold_batch(db: &PgPool, batch: i64) -> Result<Option<u64>, sqlx::Error> {
    let mut tx = db.begin().await?;
    let locked: bool = sqlx::query_scalar("SELECT pg_try_advisory_xact_lock($1)")
        .bind(REFRESH_LOCK)
        .fetch_one(&mut *tx)
        .await?;
    if !locked {
        return Ok(None);
    }
    let cursor: i64 = sqlx::query_scalar("SELECT last_event_id FROM event_rollup_cursor")
        .fetch_one(&mut *tx)
        .await?;
    let newest: i64 = sqlx::query_scalar("SELECT COALESCE(max(id), 0) FROM event")
        .fetch_one(&mut *tx)
        .await?;
    if cursor > newest {
        // The ledger is shorter than the cursor claims (its ids were reset, as a test database
        // does): nothing below the cursor can be trusted, so start over from the ledger.
        sqlx::query("DELETE FROM event_hour_listener")
            .execute(&mut *tx)
            .await?;
        sqlx::query("UPDATE event_rollup_cursor SET last_event_id = 0")
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        return Ok(Some(0));
    }
    // The last id of the next `batch` events, or nothing to do.
    let upto: Option<i64> = sqlx::query_scalar(
        "SELECT max(id) FROM (SELECT id FROM event WHERE id > $1 ORDER BY id LIMIT $2) s",
    )
    .bind(cursor)
    .bind(batch)
    .fetch_one(&mut *tx)
    .await?;
    let Some(upto) = upto else {
        return Ok(None);
    };

    // Events older than the table keeps are not folded: no reader asks about them, and the delete
    // below would only remove them again.
    sqlx::query(sqlx::AssertSqlSafe(format!(
        "INSERT INTO event_hour_listener (hour, sensor, protocol, local_port, events, last_event_at) \
         SELECT event_hour(observed_at), sensor, protocol, COALESCE(metadata->>'local_port', ''), \
                count(*), max(observed_at) \
         FROM event \
         WHERE id > $1 AND id <= $2 AND observed_at >= now() - interval '{KEEP}' \
         GROUP BY 1, 2, 3, 4 \
         ON CONFLICT (hour, sensor, protocol, local_port) DO UPDATE SET \
             events = event_hour_listener.events + EXCLUDED.events, \
             last_event_at = GREATEST(event_hour_listener.last_event_at, EXCLUDED.last_event_at)"
    )))
    .bind(cursor)
    .bind(upto)
    .execute(&mut *tx)
    .await?;
    sqlx::query(sqlx::AssertSqlSafe(format!(
        "DELETE FROM event_hour_listener WHERE hour < now() - interval '{KEEP}'"
    )))
    .execute(&mut *tx)
    .await?;
    sqlx::query("UPDATE event_rollup_cursor SET last_event_id = $1")
        .bind(upto)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(Some((upto - cursor) as u64))
}

/// A statement body for the events at or after `start` (a SQL timestamptz expression), by
/// listener and hour: `WITH ..., parts AS (...)`, to be followed by the caller's own `SELECT` over
/// `parts(hour, sensor, protocol, local_port, events, last_event_at)`. Exact whether or not
/// [`refresh`] has run (the module doc comment). `local_port` is `''` when the sensor did not
/// stamp one. `cursor_hint` is [`Health::refresh_for_page`]'s return, or `0` for none; it must not
/// exceed the stored cursor, and it only informs the planner. Run the statement with
/// `.persistent(false)`, since its text changes with the hint.
pub fn listener_window_sql(start: &str, cursor_hint: i64) -> String {
    format!(
        "WITH b AS ( \
             SELECT {start} AS s, \
                    event_hour({start}) \
                      + CASE WHEN event_hour({start}) = {start} \
                             THEN interval '0' ELSE interval '1 hour' END AS h1), \
         c AS (SELECT last_event_id AS id FROM event_rollup_cursor), \
         parts AS ( \
             SELECT hour, sensor, protocol, local_port, events, last_event_at \
             FROM event_hour_listener WHERE hour >= (SELECT h1 FROM b) \
             UNION ALL \
             SELECT event_hour(observed_at), sensor, protocol, \
                    COALESCE(metadata->>'local_port', ''), count(*), max(observed_at) \
             FROM event \
             WHERE observed_at >= (SELECT s FROM b) AND observed_at < (SELECT h1 FROM b) \
             GROUP BY 1, 2, 3, 4 \
             UNION ALL \
             SELECT event_hour(observed_at), sensor, protocol, \
                    COALESCE(metadata->>'local_port', ''), count(*), max(observed_at) \
             FROM event \
             WHERE id > (SELECT id FROM c) AND id > {cursor_hint} \
               AND observed_at >= (SELECT h1 FROM b) \
             GROUP BY 1, 2, 3, 4 \
         )"
    )
}
