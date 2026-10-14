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
use std::sync::Arc;

use chrono::{DateTime, Utc};
use rust_decimal::Decimal;
use sqlx::{PgPool, Row, postgres::PgRow};

use core_scoring::{OperatorAllowlist, ReviewState, is_reserved_ip};

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
#[derive(Debug, Clone)]
pub struct ReviewQueue {
    allowlist: Arc<OperatorAllowlist>,
    /// Which addresses are never offered and are resolved when found queued.
    /// [`core_scoring::is_reserved_ip`] in every default queue, so a production queue never
    /// offers or keeps a reserved address; only the test builders below replace it.
    is_reserved: fn(IpAddr) -> bool,
}

impl Default for ReviewQueue {
    fn default() -> Self {
        Self {
            allowlist: Arc::default(),
            is_reserved: is_reserved_ip,
        }
    }
}

impl ReviewQueue {
    pub fn new() -> Self {
        Self::default()
    }

    /// Replace the reserved-address test with `is_reserved`.
    ///
    /// For tests only. It lets a test of the reserved-address handling keep an ordinary
    /// "unreserved" control address inside the documentation ranges instead of writing a real
    /// public address into the repository.
    #[doc(hidden)]
    pub fn with_reserved_classifier(mut self, is_reserved: fn(IpAddr) -> bool) -> Self {
        self.is_reserved = is_reserved;
        self
    }

    /// Stop excluding reserved addresses ([`core_scoring::is_reserved_ip`]) from [`Self::populate`]
    /// and stop resolving them in [`Self::resolve_reserved`].
    ///
    /// For tests only. The repository's fixtures are written in the documentation ranges
    /// (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24), which are reserved, so a test of queue or
    /// console behaviour on such an address needs the queue to accept it. No daemon calls this:
    /// a reserved address is never reported to a vendor (the gatekeeper holds it first), so
    /// offering one to the operator only invites an approval that can never take effect.
    #[doc(hidden)]
    pub fn offering_reserved_addresses(self) -> Self {
        self.with_reserved_classifier(|_| false)
    }

    /// Honour the operator allowlist: an allowlisted address is never surfaced
    /// and a Pending one is withdrawn. Scoring is untouched - this only decides
    /// what is offered for vendor reporting. The default queue has an empty
    /// allowlist and behaves exactly as before.
    pub fn with_allowlist(mut self, allowlist: Arc<OperatorAllowlist>) -> Self {
        self.allowlist = allowlist;
        self
    }

    /// Surface every IP that is currently `eligible` and
    /// `recommended_for_vendor` on the `ip_score` projection and not already
    /// in the queue in ANY state (a previously Rejected or Snoozed IP is not
    /// re-surfaced; see [`Self::reject`]/[`Self::snooze`]). Returns the
    /// number of newly-inserted Pending entries.
    ///
    /// An address on the operator allowlist is skipped (and counted in the log
    /// line), so a declared crawler is never offered to the operator for
    /// reporting. The allowlist is checked here in Rust rather than in SQL
    /// because ASN membership needs the GeoLite2 database.
    ///
    /// A reserved address ([`core_scoring::is_reserved_ip`]: RFC 1918, loopback, documentation
    /// ranges, ...) is never surfaced either. The gatekeeper holds it as `Reserved` at submission
    /// whatever the score, so offering it only lets an operator approve something that can never
    /// be reported. Addresses already queued before this check are handled by
    /// [`Self::resolve_reserved`].
    ///
    /// A Snoozed entry therefore only comes back because an operator brings it back
    /// ([`Self::unsnooze`], or deciding it directly from the Snoozed listing). That is
    /// deliberate - an entry that re-surfaced on its own would ignore the operator's decision to
    /// defer it - but it means the Snoozed listing is the ONLY route back, so any interface that
    /// can snooze must also be able to act on what it snoozed.
    pub async fn populate(&self, pool: &PgPool) -> Result<usize, ReviewError> {
        let candidates: Vec<String> = sqlx::query_scalar(
            "SELECT host(source_ip) FROM ip_score \
             WHERE recommended_for_vendor = TRUE \
               AND eligible = TRUE \
               AND NOT delisted \
               AND source_ip NOT IN (SELECT source_ip FROM review_queue)",
        )
        .fetch_all(pool)
        .await?;
        let (candidates, reserved) = self.partition_reserved(candidates)?;
        let (allowed, allowlisted) = self.partition_allowlisted(candidates)?;
        // Steady state for as long as the address stays recommended, so debug, not info.
        if !reserved.is_empty() {
            tracing::debug!(
                skipped = reserved.len(),
                "review queue: skipped reserved addresses (never reportable to a vendor)"
            );
        }
        if !allowlisted.is_empty() {
            tracing::debug!(
                skipped = allowlisted.len(),
                "review queue: skipped allowlisted addresses (operator allowlist)"
            );
        }
        let result = sqlx::query(
            "INSERT INTO review_queue (source_ip, score_at_surface, categories_at_surface) \
             SELECT source_ip, raw_score, category_breakdown \
             FROM ip_score \
             WHERE recommended_for_vendor = TRUE \
               AND eligible = TRUE \
               AND NOT delisted \
               AND source_ip = ANY($1::text[]::inet[]) \
               AND source_ip NOT IN (SELECT source_ip FROM review_queue) \
             ON CONFLICT (source_ip) DO NOTHING",
        )
        .bind(allowed)
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
    ///
    /// A Pending entry for an address on the operator allowlist is withdrawn
    /// too, whatever its score, and each is logged with the reason
    /// (`allowlisted`). The allowlist is read once at startup, so an address
    /// added since it was queued is caught on the next scan after a restart.
    /// Withdrawal deletes the row rather than marking it Rejected: if the
    /// address later leaves the allowlist it is surfaced again by
    /// [`Self::populate`] instead of staying buried under a decision the
    /// operator never made. Approved, Rejected and Snoozed rows are left alone
    /// here; the submission runner refuses an allowlisted Approved entry.
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
        let mut removed = result.rows_affected() as usize;
        if removed > 0 {
            tracing::info!(removed, "review queue: withdrew lapsed pending entries");
        }
        if !self.allowlist.is_empty() {
            removed += self.withdraw_allowlisted(pool).await?;
        }
        Ok(removed)
    }

    async fn withdraw_allowlisted(&self, pool: &PgPool) -> Result<usize, ReviewError> {
        let pending: Vec<String> =
            sqlx::query_scalar("SELECT host(source_ip) FROM review_queue WHERE state = $1")
                .bind(ReviewState::Pending)
                .fetch_all(pool)
                .await?;
        let (_, allowlisted) = self.partition_allowlisted(pending)?;
        if allowlisted.is_empty() {
            return Ok(0);
        }
        // Re-check `state` in the DELETE: an operator may have decided the entry since the SELECT,
        // and a decision is never undone by a background scan.
        let result = sqlx::query(
            "DELETE FROM review_queue \
             WHERE state = $1 AND source_ip = ANY($2::text[]::inet[]) \
             RETURNING host(source_ip)",
        )
        .bind(ReviewState::Pending)
        .bind(&allowlisted)
        .fetch_all(pool)
        .await?;
        for row in &result {
            let ip: String = row.try_get(0)?;
            tracing::info!(%ip, reason = "allowlisted", "review queue: withdrew pending entry");
        }
        Ok(result.len())
    }

    /// Resolve every queue entry whose address is reserved, in any state but Rejected: a
    /// reserved address is never reportable, so an entry for one is a decision the operator can
    /// never see take effect. Each becomes Rejected with `decided_at = now()` and a note that
    /// records the automatic resolution, the state it was in, and any operator note it carried,
    /// so nothing is deleted and the history survives. Rejected rows are left as they are, and a
    /// row whose state changed since it was read (an operator deciding it meanwhile) is skipped
    /// and picked up next scan. Returns the number resolved.
    ///
    /// An Approved entry is resolved too, not only Pending ones: the submission runner holds an
    /// approved reserved address on every pass for as long as it stays approved, which is
    /// exactly how a live node came to count 10.x addresses among thousands of held pairs.
    pub async fn resolve_reserved(&self, pool: &PgPool) -> Result<usize, ReviewError> {
        let rows = sqlx::query(
            "SELECT host(source_ip) AS source_ip, state, notes FROM review_queue WHERE state <> $1",
        )
        .bind(ReviewState::Rejected)
        .fetch_all(pool)
        .await?;

        let mut resolved = 0;
        for row in rows {
            let text: String = row.try_get("source_ip")?;
            let ip: IpAddr = text
                .parse()
                .map_err(|e| ReviewError::Corrupt(format!("stored source_ip {text}: {e}")))?;
            if !(self.is_reserved)(ip) {
                continue;
            }
            let was: ReviewState = row.try_get("state")?;
            let prior_note: Option<String> = row.try_get("notes")?;
            let note = format!(
                "auto-rejected: reserved address, never reported to a vendor (was {}{})",
                format!("{was:?}").to_lowercase(),
                prior_note
                    .map(|n| format!(", operator note: {n}"))
                    .unwrap_or_default(),
            );
            // Re-check `state`: an operator may have decided the entry since the SELECT, and a
            // background scan does not overwrite a decision made in between.
            let updated = sqlx::query(
                "UPDATE review_queue SET state = $1, decided_at = now(), notes = $2 \
                 WHERE source_ip = $3::inet AND state = $4",
            )
            .bind(ReviewState::Rejected)
            .bind(&note)
            .bind(&text)
            .bind(was)
            .execute(pool)
            .await?;
            if updated.rows_affected() > 0 {
                tracing::info!(
                    %ip, was = ?was, reason = "reserved",
                    "review queue: resolved entry for a reserved address as rejected"
                );
                resolved += 1;
            }
        }
        Ok(resolved)
    }

    /// Split candidate addresses into (not reserved, reserved). Passes everything through when
    /// the queue was built with [`Self::offering_reserved_addresses`].
    fn partition_reserved(
        &self,
        ips: Vec<String>,
    ) -> Result<(Vec<String>, Vec<String>), ReviewError> {
        let mut kept = Vec::new();
        let mut reserved = Vec::new();
        for text in ips {
            let ip: IpAddr = text
                .parse()
                .map_err(|e| ReviewError::Corrupt(format!("stored source_ip {text}: {e}")))?;
            if (self.is_reserved)(ip) {
                reserved.push(text);
            } else {
                kept.push(text);
            }
        }
        Ok((kept, reserved))
    }

    /// Split stored/candidate addresses into (not allowlisted, allowlisted). An unparseable value
    /// is corrupt state and fails the scan rather than being silently kept or dropped.
    fn partition_allowlisted(
        &self,
        ips: Vec<String>,
    ) -> Result<(Vec<String>, Vec<String>), ReviewError> {
        let mut kept = Vec::new();
        let mut allowlisted = Vec::new();
        for text in ips {
            let ip: IpAddr = text
                .parse()
                .map_err(|e| ReviewError::Corrupt(format!("stored source_ip {text}: {e}")))?;
            if self.allowlist.contains(ip) {
                allowlisted.push(text);
            } else {
                kept.push(text);
            }
        }
        Ok((kept, allowlisted))
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
    ///
    /// "Later" is operator-driven, not scheduled: [`Self::populate`] deliberately never
    /// re-surfaces a Snoozed row, so the way back is the Snoozed listing plus
    /// [`Self::approve`]/[`Self::reject`]/[`Self::unsnooze`] - all of which operate on a row in
    /// any state. A snooze with no way to act on it afterwards would be a reject wearing a softer
    /// word, so every interface that offers snooze has to offer those too.
    pub async fn snooze(
        &self,
        pool: &PgPool,
        ip: IpAddr,
        notes: Option<&str>,
    ) -> Result<(), ReviewError> {
        self.decide(pool, ip, ReviewState::Snoozed, notes).await
    }

    /// Return `ip` to Pending and clear its decision timestamp: the operator wants it back in the
    /// working queue rather than deciding it now.
    ///
    /// The inverse of [`Self::snooze`], and the only transition here that goes BACK. It clears
    /// `decided_at` because a Pending row has not been decided - leaving a stale timestamp there
    /// would make the entry sort and read as though a decision had been taken and then ignored.
    /// `notes` are kept: they are why the operator deferred, which is exactly the context they
    /// will want when the entry comes back round.
    ///
    /// Works on any state, not just Snoozed: an approval or rejection made in error is otherwise
    /// only reversible by editing the database by hand.
    pub async fn unsnooze(&self, pool: &PgPool, ip: IpAddr) -> Result<(), ReviewError> {
        let result = sqlx::query(
            "UPDATE review_queue SET state = $1, decided_at = NULL WHERE source_ip = $2::inet",
        )
        .bind(ReviewState::Pending)
        .bind(ip.to_string())
        .execute(pool)
        .await?;
        if result.rows_affected() == 0 {
            return Err(ReviewError::NotFound(ip));
        }
        tracing::info!(%ip, "review queue: entry returned to pending");
        Ok(())
    }

    /// List every entry in `state`, most-recently-decided first. The Snoozed listing is what makes
    /// a snooze recoverable - see [`Self::snooze`].
    pub async fn list_by_state(
        &self,
        pool: &PgPool,
        state: ReviewState,
    ) -> Result<Vec<QueueEntry>, ReviewError> {
        let rows = sqlx::query(
            "SELECT host(source_ip) AS source_ip, state, score_at_surface, \
                    categories_at_surface, surfaced_at, decided_at, notes \
             FROM review_queue WHERE state = $1 ORDER BY decided_at DESC NULLS LAST",
        )
        .bind(state)
        .fetch_all(pool)
        .await?;

        rows.into_iter().map(row_to_entry).collect()
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

    /// List every Approved entry, oldest-decided first: `submit::SubmissionRunner`'s
    /// input population. Every Approved row has `decided_at` set (see
    /// [`Self::decide`]), so ordering by it is a stable FIFO over operator
    /// approvals - the runner works through a backlog in the order the
    /// operator actually approved it, not surface order.
    pub async fn list_approved(&self, pool: &PgPool) -> Result<Vec<QueueEntry>, ReviewError> {
        let rows = sqlx::query(
            "SELECT host(source_ip) AS source_ip, state, score_at_surface, \
                    categories_at_surface, surfaced_at, decided_at, notes \
             FROM review_queue WHERE state = $1 ORDER BY decided_at ASC",
        )
        .bind(ReviewState::Approved)
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
