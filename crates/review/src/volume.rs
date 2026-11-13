//! The volume review queue: holds every address the connection-volume rule would list in the
//! retention feeds for an explicit operator decision, in `volume_review`.
//!
//! The volume rule lists an address on its count of established TCP events alone, and that count
//! comes from what a sensor's own log line declares: one forged line can carry a thousand events.
//! Such an address used to be published by the feed builder with no decision at all. It now waits
//! here, and the builder publishes it only once it is Approved (`feed::builder`), unless the
//! operator has opted back in to automatic publication (`PROPOLIS_FEED_VOLUME_AUTO_PUBLISH`).
//!
//! This is a second queue beside [`ReviewQueue`], not a second kind of entry in it, because the
//! two approvals mean different things. The submission runner reports every Approved
//! `review_queue` row to the configured vendors (`crate::submit`); an approval here publishes the
//! address in the retention feeds and nothing else. Keeping the rows in separate tables means no
//! reader of `review_queue` has to know the difference, and none can get it wrong.
//!
//! Like [`ReviewQueue`], both scans read `ip_score`'s STORED columns, so each is one set-based
//! statement and the view is stale by at most one scan interval.

use std::net::IpAddr;
use std::sync::Arc;

use chrono::{DateTime, Duration, Utc};
use sqlx::{PgPool, Row, postgres::PgRow};

use core_scoring::{
    OperatorAllowlist, ReviewState, VOLUME_LIST_THRESHOLD, VOLUME_LIST_WINDOW_SECONDS,
};

use crate::queue::{ReviewError, ReviewQueue};

/// One `volume_review` row: a volume candidate and the operator's decision so far.
#[derive(Debug, Clone, PartialEq)]
pub struct VolumeEntry {
    pub source_ip: IpAddr,
    /// Pending, Approved or Rejected. A volume candidate is never Snoozed: nothing writes that
    /// state here.
    pub state: ReviewState,
    /// `ip_score.established_event_count` when the candidate was surfaced, so the operator can
    /// compare what listed it with what it has done since.
    pub established_events_at_surface: i32,
    pub surfaced_at: DateTime<Utc>,
    pub decided_at: Option<DateTime<Utc>>,
    pub notes: Option<String>,
}

/// The shortest time an address may go unseen before a Pending or Approved row about it lapses:
/// the longest retention window the feed ships with (`all-90d`). [`VolumeQueue::lapsing_after`]
/// can lengthen it and never shortens it.
pub const VOLUME_DECISION_LAPSE_DAYS: i64 = 90;

/// The volume review queue: population/withdrawal scans, the operator's decisions and the
/// listings. Stateless, like [`ReviewQueue`]: every method takes the pool it operates against.
#[derive(Debug, Clone)]
pub struct VolumeQueue {
    /// The reserved-address test and the operator allowlist. Held as a [`ReviewQueue`] so both
    /// queues filter candidates through the same two functions and cannot drift apart.
    filters: ReviewQueue,
    /// How long an address may go unseen before [`Self::withdraw`] removes its Pending or
    /// Approved row. See [`Self::lapsing_after`].
    lapse_after: Duration,
}

impl Default for VolumeQueue {
    fn default() -> Self {
        Self {
            filters: ReviewQueue::default(),
            lapse_after: Duration::days(VOLUME_DECISION_LAPSE_DAYS),
        }
    }
}

impl VolumeQueue {
    pub fn new() -> Self {
        Self::default()
    }

    /// Set how long an address may go unseen before its Pending or Approved row lapses. The
    /// daemon passes the longest retention window it publishes: past that the address is in no
    /// feed file, so an approval has nothing left to publish and the next sighting should be a
    /// new decision, not a listing nobody looked at.
    ///
    /// Never less than [`VOLUME_DECISION_LAPSE_DAYS`], whatever this node's own windows are.
    /// The lapse is a delete on a table every node of a shared database reads, so a node that
    /// publishes only short windows must not end an approval that another node, with the
    /// windows a default install has, is still publishing; a removed approval does not come
    /// back until the address floods again and is approved again. The bound also keeps the
    /// lapse outside the day within which [`Self::populate`] still offers an address, where
    /// every scan would insert a row and remove it again in the same pass.
    pub fn lapsing_after(mut self, silence: Duration) -> Self {
        self.lapse_after = silence.max(Duration::days(VOLUME_DECISION_LAPSE_DAYS));
        self
    }

    /// Replace the reserved-address test. For tests only; see
    /// [`ReviewQueue::with_reserved_classifier`].
    #[doc(hidden)]
    pub fn with_reserved_classifier(mut self, is_reserved: fn(IpAddr) -> bool) -> Self {
        self.filters = self.filters.with_reserved_classifier(is_reserved);
        self
    }

    /// Stop excluding reserved addresses from [`Self::populate`]. For tests only; see
    /// [`ReviewQueue::offering_reserved_addresses`].
    #[doc(hidden)]
    pub fn offering_reserved_addresses(mut self) -> Self {
        self.filters = self.filters.offering_reserved_addresses();
        self
    }

    /// Honour the operator allowlist: an allowlisted address is never surfaced. The feed builder
    /// excludes such an address whatever is decided here, so offering it only invites an approval
    /// that can never take effect.
    pub fn with_allowlist(mut self, allowlist: Arc<OperatorAllowlist>) -> Self {
        self.filters = self.filters.with_allowlist(allowlist);
        self
    }

    /// Surface every address the volume rule lists that has no decision to rest on yet. An
    /// address is offered when all of these hold:
    ///
    /// - it is not delisted;
    /// - its `established_event_count` is at least [`VOLUME_LIST_THRESHOLD`];
    /// - it was last seen within [`VOLUME_LIST_WINDOW_SECONDS`] of now, the rule's own recency
    ///   gate, so a flood that stopped long ago is not offered;
    /// - it has no `volume_review` row in any state (a Rejected candidate is not offered again);
    /// - it has no Approved `review_queue` row: an address the operator already approved on its
    ///   score needs no second decision, and the feed builder accepts that approval for its
    ///   volume listing too.
    ///
    /// Reserved and allowlisted addresses are skipped, exactly as [`ReviewQueue::populate`] skips
    /// them and for the same reason: the feed never publishes either. Returns the number of
    /// newly inserted Pending rows.
    pub async fn populate(&self, pool: &PgPool) -> Result<usize, ReviewError> {
        let threshold = i64::from(VOLUME_LIST_THRESHOLD);
        let seen_since = Utc::now() - Duration::seconds(VOLUME_LIST_WINDOW_SECONDS);
        let candidates: Vec<String> = sqlx::query_scalar(
            "SELECT host(s.source_ip) FROM ip_score s \
             WHERE NOT s.delisted \
               AND s.established_event_count >= $1 \
               AND s.last_seen >= $2 \
               AND NOT EXISTS (SELECT 1 FROM volume_review v WHERE v.source_ip = s.source_ip) \
               AND NOT EXISTS (SELECT 1 FROM review_queue q \
                               WHERE q.source_ip = s.source_ip AND q.state = $3)",
        )
        .bind(threshold)
        .bind(seen_since)
        .bind(ReviewState::Approved)
        .fetch_all(pool)
        .await?;
        let (candidates, reserved) = self.filters.partition_reserved(candidates)?;
        let (allowed, allowlisted) = self.filters.partition_allowlisted(candidates)?;
        // Steady state for as long as the address keeps flooding, so debug, not info.
        if !reserved.is_empty() {
            tracing::debug!(
                skipped = reserved.len(),
                "volume review: skipped reserved addresses (never published)"
            );
        }
        if !allowlisted.is_empty() {
            tracing::debug!(
                skipped = allowlisted.len(),
                "volume review: skipped allowlisted addresses (operator allowlist)"
            );
        }
        // The conditions are repeated in the INSERT: the projection may have moved, or an
        // operator may have delisted or approved the address, since the SELECT above.
        let result = sqlx::query(
            "INSERT INTO volume_review (source_ip, established_events_at_surface) \
             SELECT s.source_ip, s.established_event_count FROM ip_score s \
             WHERE NOT s.delisted \
               AND s.established_event_count >= $1 \
               AND s.last_seen >= $2 \
               AND s.source_ip = ANY($4::text[]::inet[]) \
               AND NOT EXISTS (SELECT 1 FROM volume_review v WHERE v.source_ip = s.source_ip) \
               AND NOT EXISTS (SELECT 1 FROM review_queue q \
                               WHERE q.source_ip = s.source_ip AND q.state = $3) \
             ON CONFLICT (source_ip) DO NOTHING",
        )
        .bind(threshold)
        .bind(seen_since)
        .bind(ReviewState::Approved)
        .bind(allowed)
        .execute(pool)
        .await?;
        let inserted = result.rows_affected() as usize;
        if inserted > 0 {
            tracing::info!(
                inserted,
                "volume review: surfaced new pending volume candidates"
            );
        }
        Ok(inserted)
    }

    /// Remove every row that no longer has anything to decide or to publish. Returns the number
    /// of rows removed.
    ///
    /// A Pending row goes when its address has no `ip_score` row, is delisted, has fallen below
    /// [`VOLUME_LIST_THRESHOLD`], or now has an Approved `review_queue` row (the operator's
    /// decision on its score covers the volume listing too).
    ///
    /// A Pending or an Approved row goes when its address has not been seen for
    /// [`Self::lapsing_after`]'s duration: the longest retention window, and never less than
    /// [`VOLUME_DECISION_LAPSE_DAYS`]. Short of that a candidate is NOT withdrawn for going
    /// quiet: the retention feeds carry an address for up to their longest window after its last
    /// event, so the decision still matters after the flood stops. Past it the address is in no
    /// feed file. An approval left standing there would publish the address again at its next
    /// sighting, of any kind and however long after, with nobody deciding; with the row gone
    /// that sighting is offered as a new candidate by [`Self::populate`]. So an approval covers
    /// one listing: it holds while the address keeps being seen and ends when the listing does.
    ///
    /// Apart from that lapse an Approved row is never touched, and a Rejected row is never
    /// touched at all: a background scan does not undo a decision, and a rejected address is
    /// not offered again.
    ///
    /// The lapse is noticed by this scan, so it needs the scan to run while the address is
    /// quiet. A node that was down for the whole of that time, and reads a new line for the
    /// address before its first scan, still has the approval.
    pub async fn withdraw(&self, pool: &PgPool) -> Result<usize, ReviewError> {
        let result = sqlx::query(
            "DELETE FROM volume_review v \
             WHERE v.state = $1 \
               AND (NOT EXISTS (SELECT 1 FROM ip_score s \
                                WHERE s.source_ip = v.source_ip \
                                  AND NOT s.delisted \
                                  AND s.established_event_count >= $2) \
                    OR EXISTS (SELECT 1 FROM review_queue q \
                               WHERE q.source_ip = v.source_ip AND q.state = $3))",
        )
        .bind(ReviewState::Pending)
        .bind(i64::from(VOLUME_LIST_THRESHOLD))
        .bind(ReviewState::Approved)
        .execute(pool)
        .await?;
        let mut removed = result.rows_affected() as usize;
        if removed > 0 {
            tracing::info!(removed, "volume review: withdrew pending volume candidates");
        }

        let lapsed = sqlx::query(
            "DELETE FROM volume_review v USING ip_score s \
             WHERE s.source_ip = v.source_ip AND v.state IN ($1, $2) AND s.last_seen <= $3 \
             RETURNING host(v.source_ip) AS source_ip, v.state, v.decided_at",
        )
        .bind(ReviewState::Pending)
        .bind(ReviewState::Approved)
        .bind(Utc::now() - self.lapse_after)
        .fetch_all(pool)
        .await?;
        for row in &lapsed {
            let source_ip: String = row.try_get("source_ip")?;
            let state: ReviewState = row.try_get("state")?;
            let decided_at: Option<DateTime<Utc>> = row.try_get("decided_at")?;
            // One line per row and at info: this is the only record that an approval ended
            // without an operator ending it.
            tracing::info!(
                ip = %source_ip,
                ?state,
                ?decided_at,
                silent_days = self.lapse_after.num_days(),
                "volume review: row lapsed, its address has not been seen for this long"
            );
        }
        removed += lapsed.len();
        Ok(removed)
    }

    /// Approve `ip`: the feed builder publishes it in the retention feeds from its next build,
    /// for as long as it stays inside a window, and any later event for the address, of any
    /// kind, keeps it there. The approval ends when an operator reopens it or delists the
    /// address, or when [`Self::withdraw`] finds the address unseen for the lapse duration. It
    /// is not reported to any vendor: the submission runner reads `review_queue` only. Sets
    /// `decided_at = now()` and records `notes`.
    pub async fn approve(
        &self,
        pool: &PgPool,
        ip: IpAddr,
        notes: Option<&str>,
    ) -> Result<(), ReviewError> {
        self.decide(pool, ip, ReviewState::Approved, notes).await
    }

    /// Reject `ip`: not published on volume, and the row stays as a record so
    /// [`Self::populate`] never offers it again.
    pub async fn reject(
        &self,
        pool: &PgPool,
        ip: IpAddr,
        notes: Option<&str>,
    ) -> Result<(), ReviewError> {
        self.decide(pool, ip, ReviewState::Rejected, notes).await
    }

    /// Return `ip` to Pending and clear its decision timestamp: the way to undo an approval or a
    /// rejection. An approved address leaves the retention feeds at the next build, because the
    /// builder publishes only Approved rows. `notes` are kept, as [`ReviewQueue::unsnooze`] keeps
    /// them.
    pub async fn reopen(&self, pool: &PgPool, ip: IpAddr) -> Result<(), ReviewError> {
        let result = sqlx::query(
            "UPDATE volume_review SET state = $1, decided_at = NULL WHERE source_ip = $2::inet",
        )
        .bind(ReviewState::Pending)
        .bind(ip.to_string())
        .execute(pool)
        .await?;
        if result.rows_affected() == 0 {
            return Err(ReviewError::VolumeNotFound(ip));
        }
        tracing::info!(%ip, "volume review: candidate returned to pending");
        Ok(())
    }

    async fn decide(
        &self,
        pool: &PgPool,
        ip: IpAddr,
        state: ReviewState,
        notes: Option<&str>,
    ) -> Result<(), ReviewError> {
        let result = sqlx::query(
            "UPDATE volume_review SET state = $1, decided_at = now(), notes = $2 \
             WHERE source_ip = $3::inet",
        )
        .bind(state)
        .bind(notes)
        .bind(ip.to_string())
        .execute(pool)
        .await?;
        if result.rows_affected() == 0 {
            return Err(ReviewError::VolumeNotFound(ip));
        }
        tracing::info!(%ip, ?state, "volume review: operator decision recorded");
        Ok(())
    }

    /// The row for `ip`, in whatever state it is, or `None` when the address was never offered
    /// (or was withdrawn, delisted or deleted since).
    pub async fn get(&self, pool: &PgPool, ip: IpAddr) -> Result<Option<VolumeEntry>, ReviewError> {
        let row = sqlx::query(
            "SELECT host(source_ip) AS source_ip, state, established_events_at_surface, \
                    surfaced_at, decided_at, notes \
             FROM volume_review WHERE source_ip = $1::inet",
        )
        .bind(ip.to_string())
        .fetch_optional(pool)
        .await?;

        row.map(row_to_entry).transpose()
    }

    /// List every Pending candidate, oldest-surfaced first.
    pub async fn list_pending(&self, pool: &PgPool) -> Result<Vec<VolumeEntry>, ReviewError> {
        let rows = sqlx::query(
            "SELECT host(source_ip) AS source_ip, state, established_events_at_surface, \
                    surfaced_at, decided_at, notes \
             FROM volume_review WHERE state = $1 ORDER BY surfaced_at ASC, source_ip ASC",
        )
        .bind(ReviewState::Pending)
        .fetch_all(pool)
        .await?;

        rows.into_iter().map(row_to_entry).collect()
    }

    /// List the entries in `state`, most recently decided first: the history of what was
    /// approved or rejected, and the listing [`Self::reopen`] is used from. `limit` bounds the
    /// rows read for a page that shows only the latest; `None` reads them all.
    pub async fn list_by_state(
        &self,
        pool: &PgPool,
        state: ReviewState,
        limit: Option<i64>,
    ) -> Result<Vec<VolumeEntry>, ReviewError> {
        let rows = sqlx::query(
            "SELECT host(source_ip) AS source_ip, state, established_events_at_surface, \
                    surfaced_at, decided_at, notes \
             FROM volume_review WHERE state = $1 \
             ORDER BY decided_at DESC NULLS LAST, source_ip ASC LIMIT $2",
        )
        .bind(state)
        .bind(limit)
        .fetch_all(pool)
        .await?;

        rows.into_iter().map(row_to_entry).collect()
    }

    /// How many candidates are waiting for a decision.
    pub async fn pending_count(&self, pool: &PgPool) -> Result<i64, ReviewError> {
        Ok(
            sqlx::query_scalar("SELECT COUNT(*) FROM volume_review WHERE state = $1")
                .bind(ReviewState::Pending)
                .fetch_one(pool)
                .await?,
        )
    }
}

fn row_to_entry(row: PgRow) -> Result<VolumeEntry, ReviewError> {
    let source_ip_txt: String = row.try_get("source_ip")?;
    let source_ip: IpAddr = source_ip_txt
        .parse()
        .map_err(|e| ReviewError::Corrupt(format!("stored source_ip {source_ip_txt}: {e}")))?;
    Ok(VolumeEntry {
        source_ip,
        state: row.try_get("state")?,
        established_events_at_surface: row.try_get("established_events_at_surface")?,
        surfaced_at: row.try_get("surfaced_at")?,
        decided_at: row.try_get("decided_at")?,
        notes: row.try_get("notes")?,
    })
}
