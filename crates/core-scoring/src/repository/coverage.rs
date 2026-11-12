//! Read-only query feeding the shell-emulator coverage report.
//!
//! One SELECT over the append-only `event` table; it never writes, takes no append lock, and
//! changes no projection. The row type is owned here so this crate does not depend on the
//! analysis code that consumes it.

use chrono::{DateTime, Utc};
use sqlx::{PgPool, Row};
use uuid::Uuid;

use super::events::RepoError;
use crate::domain::enums::SignalType;

/// Default cap on rows one coverage read returns. [unverified] against production volume.
pub const MAX_COVERAGE_ROWS: usize = 250_000;

/// Longest `metadata.command` read per row, in characters; the consumer normalizes at most this
/// much anyway, so the cut bounds memory without changing a report.
const COMMAND_READ_LEN: i32 = 2048;

/// One session-scoped event, reduced to the columns coverage analysis reads. The three
/// metadata-derived fields are filled for `HoneypotCommandExec` only (`None` otherwise, and
/// `None` for command events recorded before the emulator classified lines).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoverageEventRow {
    pub session_id: Uuid,
    pub signal_type: SignalType,
    pub observed_at: DateTime<Utc>,
    pub id: i64,
    pub classification: Option<String>,
    pub command_basename: Option<String>,
    pub command: Option<String>,
}

/// Result of [`coverage_events`]. `truncated` means more rows matched than `limit`; the rows are
/// then an arbitrary-prefix of the ordered result, so a caller must not report them as complete.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoverageEvents {
    pub rows: Vec<CoverageEventRow>,
    pub truncated: bool,
}

/// Read the command, download, upload and login events that carry a `session_id`, ordered by
/// `(session_id, observed_at, id)` so each session's events are contiguous and in order.
///
/// `since` and `until` bound `observed_at` inclusively (either may be open). Events with a NULL
/// `session_id` (replay and sensor-less sources) are excluded. At most `limit` rows are returned;
/// one extra row is fetched to detect truncation. There is no index on `session_id`; the read is
/// an aggregate over the matching rows either way.
pub async fn coverage_events(
    pool: &PgPool,
    since: Option<DateTime<Utc>>,
    until: Option<DateTime<Utc>>,
    limit: usize,
) -> Result<CoverageEvents, RepoError> {
    let fetch = i64::try_from(limit)
        .unwrap_or(i64::MAX - 1)
        .saturating_add(1);
    let db_rows = sqlx::query(
        "SELECT session_id, signal_type, observed_at, id, \
                CASE WHEN signal_type = 'honeypot_command_exec' \
                     THEN metadata->>'classification' END AS classification, \
                CASE WHEN signal_type = 'honeypot_command_exec' \
                     THEN metadata->>'command_basename' END AS command_basename, \
                CASE WHEN signal_type = 'honeypot_command_exec' \
                     THEN LEFT(metadata->>'command', $4) END AS command \
         FROM event \
         WHERE signal_type IN ('honeypot_command_exec', 'honeypot_file_download', \
                               'honeypot_malware_upload', 'honeypot_login_attempt') \
           AND session_id IS NOT NULL \
           AND ($1::timestamptz IS NULL OR observed_at >= $1) \
           AND ($2::timestamptz IS NULL OR observed_at <= $2) \
         ORDER BY session_id, observed_at, id \
         LIMIT $3",
    )
    .bind(since)
    .bind(until)
    .bind(fetch)
    .bind(COMMAND_READ_LEN)
    .fetch_all(pool)
    .await?;

    let truncated = db_rows.len() > limit;
    let mut rows = Vec::with_capacity(db_rows.len().min(limit));
    for row in db_rows.into_iter().take(limit) {
        rows.push(CoverageEventRow {
            session_id: row.try_get("session_id")?,
            signal_type: row.try_get("signal_type")?,
            observed_at: row.try_get("observed_at")?,
            id: row.try_get("id")?,
            classification: row.try_get("classification")?,
            command_basename: row.try_get("command_basename")?,
            command: row.try_get("command")?,
        });
    }
    Ok(CoverageEvents { rows, truncated })
}
