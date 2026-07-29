//! The review queue: surfaces IPs recommended for vendor reporting, holds
//! each one for an explicit operator decision, and never auto-fires.
//!
//! Population and withdrawal read `ip_score`'s STORED `eligible` /
//! `recommended_for_vendor` columns directly - the values `core_scoring`'s
//! append path last computed - rather than a decayed-to-now re-derivation
//! (`core_scoring::read_score`) per IP. That keeps both scans a single
//! set-based query over the whole table; the tradeoff is a view that is
//! stale by at most one scan interval, self-corrected on the next scan or the
//! next append. See `internal/design/04-review-gatekeeper-reporting.md`
//! ("Population" / "Withdrawal").

use std::net::IpAddr;

use chrono::{DateTime, Utc};
use rust_decimal::Decimal;
use sqlx::{PgPool, Row, postgres::PgRow};

use core_scoring::ReviewState;

/// Errors from the review queue. Every variant is fail-closed: the caller
/// gets an error and no partial state change is left behind (each operation
/// here is a single SQL statement).
#[derive(Debug, thiserror::Error)]
pub enum ReviewError {
    /// A database/driver error.
    #[error("database error: {0}")]
    Db(#[from] sqlx::Error),
    /// A stored value could not be parsed into the expected shape (e.g. an
    /// unparseable `source_ip`). Read paths fail closed instead of panicking.
    #[error("corrupt stored state: {0}")]
    Corrupt(String),
    /// An operator decision (approve/reject/snooze) targeted an IP with no
    /// `review_queue` row. Acting on a nonexistent entry is a caller error,
    /// not a silent no-op: the human-approval gate depends on every decision
    /// landing on a real, surfaced entry.
    #[error("no review queue entry for {0}")]
    NotFound(IpAddr),
}

/// One `review_queue` row: a surfaced IP and the operator's decision so far.
///
/// `score_at_surface` and `categories_at_surface` snapshot the projection at
/// surface time, so the operator sees what triggered the recommendation even
/// if the live score has since decayed.
#[derive(Debug, Clone, PartialEq)]
pub struct QueueEntry {
    pub source_ip: IpAddr,
    pub state: ReviewState,
    pub score_at_surface: Decimal,
    pub categories_at_surface: serde_json::Value,
    pub surfaced_at: DateTime<Utc>,
    pub decided_at: Option<DateTime<Utc>>,
    pub notes: Option<String>,
}

/// The review queue: population/withdrawal scans plus the three operator
/// decisions and the pending listing. Stateless - every method takes the
/// pool it operates against, so callers can share one instance or build a
/// fresh one per call.
#[derive(Debug, Default, Clone, Copy)]
pub struct ReviewQueue;

impl ReviewQueue {
    pub fn new() -> Self {
        ReviewQueue
    }

    /// Surface every IP that is currently `eligible` and
    /// `recommended_for_vendor` on the `ip_score` projection and not already
    /// in the queue in ANY state (a previously Rejected or Snoozed IP is not
    /// re-surfaced; see [`Self::reject`]/[`Self::snooze`]). Returns the
    /// number of newly-inserted Pending entries.
    pub async fn populate(&self, pool: &PgPool) -> Result<usize, ReviewError> {
        let result = sqlx::query(
            "INSERT INTO review_queue (source_ip, score_at_surface, categories_at_surface) \
             SELECT source_ip, raw_score, category_breakdown \
             FROM ip_score \
             WHERE recommended_for_vendor = TRUE \
               AND eligible = TRUE \
               AND source_ip NOT IN (SELECT source_ip FROM review_queue) \
             ON CONFLICT (source_ip) DO NOTHING",
        )
        .execute(pool)
        .await?;
        let inserted = result.rows_affected() as usize;
        if inserted > 0 {
            tracing::info!(inserted, "review queue: populated new pending entries");
        }
        Ok(inserted)
    }

    /// Remove every Pending entry whose IP is no longer both `eligible` and
    /// `recommended_for_vendor` on the current `ip_score` projection.
    /// Approved, Rejected, and Snoozed entries are never touched by this scan;
    /// only a still-open (Pending) decision is withdrawn when its trigger
    /// lapses. Returns the number of rows removed.
    pub async fn withdraw(&self, pool: &PgPool) -> Result<usize, ReviewError> {
        let result = sqlx::query(
            "DELETE FROM review_queue \
             WHERE state = $1 \
               AND source_ip NOT IN ( \
                 SELECT source_ip FROM ip_score \
                 WHERE recommended_for_vendor = TRUE AND eligible = TRUE \
               )",
        )
        .bind(ReviewState::Pending)
        .execute(pool)
        .await?;
        let removed = result.rows_affected() as usize;
        if removed > 0 {
            tracing::info!(removed, "review queue: withdrew lapsed pending entries");
        }
        Ok(removed)
    }

    /// Approve `ip`: the submission daemon (a later task) picks up Approved
    /// entries. Sets `decided_at = now()` and records `notes`.
    pub async fn approve(
        &self,
        pool: &PgPool,
        ip: IpAddr,
        notes: Option<&str>,
    ) -> Result<(), ReviewError> {
        self.decide(pool, ip, ReviewState::Approved, notes).await
    }

    /// Reject `ip`: never reported, and the row stays as a record so
    /// [`Self::populate`] never re-surfaces it.
    pub async fn reject(
        &self,
        pool: &PgPool,
        ip: IpAddr,
        notes: Option<&str>,
    ) -> Result<(), ReviewError> {
        self.decide(pool, ip, ReviewState::Rejected, notes).await
    }

    /// Snooze `ip`: held for later review; the row stays so it is not
    /// re-surfaced as a duplicate, but an operator can act on it again later.
    pub async fn snooze(
        &self,
        pool: &PgPool,
        ip: IpAddr,
        notes: Option<&str>,
    ) -> Result<(), ReviewError> {
        self.decide(pool, ip, ReviewState::Snoozed, notes).await
    }

    async fn decide(
        &self,
        pool: &PgPool,
        ip: IpAddr,
        state: ReviewState,
        notes: Option<&str>,
    ) -> Result<(), ReviewError> {
        let result = sqlx::query(
            "UPDATE review_queue SET state = $1, decided_at = now(), notes = $2 \
             WHERE source_ip = $3::inet",
        )
        .bind(state)
        .bind(notes)
        .bind(ip.to_string())
        .execute(pool)
        .await?;
        if result.rows_affected() == 0 {
            return Err(ReviewError::NotFound(ip));
        }
        tracing::info!(%ip, ?state, "review queue: operator decision recorded");
        Ok(())
    }

    /// List every Pending entry, oldest-surfaced first.
    pub async fn list_pending(&self, pool: &PgPool) -> Result<Vec<QueueEntry>, ReviewError> {
        let rows = sqlx::query(
            "SELECT host(source_ip) AS source_ip, state, score_at_surface, \
                    categories_at_surface, surfaced_at, decided_at, notes \
             FROM review_queue WHERE state = $1 ORDER BY surfaced_at ASC",
        )
        .bind(ReviewState::Pending)
        .fetch_all(pool)
        .await?;

        rows.into_iter().map(row_to_entry).collect()
    }
}

fn row_to_entry(row: PgRow) -> Result<QueueEntry, ReviewError> {
    let source_ip_txt: String = row.try_get("source_ip")?;
    let source_ip: IpAddr = source_ip_txt
        .parse()
        .map_err(|e| ReviewError::Corrupt(format!("stored source_ip {source_ip_txt}: {e}")))?;
    Ok(QueueEntry {
        source_ip,
        state: row.try_get("state")?,
        score_at_surface: row.try_get("score_at_surface")?,
        categories_at_surface: row.try_get("categories_at_surface")?,
        surfaced_at: row.try_get("surfaced_at")?,
        decided_at: row.try_get("decided_at")?,
        notes: row.try_get("notes")?,
    })
}
