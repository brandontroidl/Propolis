//! Durable storage for probe results (`listener_probe`).
//!
//! Two writers, deliberately kept apart. The prober owns everything about an attempt and writes it
//! with [`upsert_probe`]. Intake owns `confirmed_at` and writes it with [`confirm_sensor`] when a
//! probe's own line arrives at the far end of the collection chain. Neither clobbers the other's
//! column, which is what lets the pane say "the socket answered but nothing reached intake" - the
//! single most useful thing it can say, because it localizes the break to the log, the shipper,
//! the gateway or intake rather than to the sensor.
//!
//! Nothing here creates a row for a configured listener. A row exists only because an attempt
//! completed; see the migration's own comment.

use chrono::{DateTime, Utc};
use sqlx::{PgPool, Row};

use crate::inventory::{Listener, Proto};

/// What one probe attempt found.
///
/// `NotProbeable` is a real third state, not a failure: a UDP listener answers nothing on a
/// connect, so calling it unreachable would be a lie and calling it reachable a worse one. It is
/// excluded from the "proven reachable" numerator and included in the denominator, so the coverage
/// figure can never flatter itself by dropping the listeners it cannot test.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProbeOutcome {
    Reachable,
    Refused,
    Timeout,
    Error,
    NotProbeable,
}

impl ProbeOutcome {
    /// The database spelling, matching the migration's `CHECK` constraint.
    pub fn as_str(self) -> &'static str {
        match self {
            ProbeOutcome::Reachable => "reachable",
            ProbeOutcome::Refused => "refused",
            ProbeOutcome::Timeout => "timeout",
            ProbeOutcome::Error => "error",
            ProbeOutcome::NotProbeable => "not_probeable",
        }
    }

    /// The word the operator reads. Distinct from [`Self::as_str`] so the wire spelling can stay a
    /// stable key while the display text is free to be prose.
    pub fn label(self) -> &'static str {
        match self {
            ProbeOutcome::Reachable => "reachable",
            ProbeOutcome::Refused => "refused",
            ProbeOutcome::Timeout => "timeout",
            ProbeOutcome::Error => "error",
            ProbeOutcome::NotProbeable => "not probeable",
        }
    }

    /// An unrecognised value read back from the database is `Error`, never a silent `Reachable`:
    /// the `CHECK` constraint makes this unreachable in practice, and if it ever fires the pane
    /// must lean toward alarming rather than reassuring.
    fn from_db(raw: &str) -> Self {
        match raw {
            "reachable" => ProbeOutcome::Reachable,
            "refused" => ProbeOutcome::Refused,
            "timeout" => ProbeOutcome::Timeout,
            "not_probeable" => ProbeOutcome::NotProbeable,
            _ => ProbeOutcome::Error,
        }
    }
}

/// One completed attempt, as the prober hands it over.
#[derive(Debug, Clone)]
pub struct ProbeRecord {
    pub listener: Listener,
    pub target: String,
    pub attempted_at: DateTime<Utc>,
    pub outcome: ProbeOutcome,
    pub detail: Option<String>,
    pub latency_ms: Option<i32>,
}

/// A stored row: a [`ProbeRecord`] plus the confirmation intake wrote against it, if any.
#[derive(Debug, Clone)]
pub struct ProbeRow {
    pub listener: Listener,
    pub target: String,
    pub attempted_at: DateTime<Utc>,
    pub outcome: ProbeOutcome,
    pub detail: Option<String>,
    pub latency_ms: Option<i32>,
    pub confirmed_at: Option<DateTime<Utc>>,
}

/// Writes one attempt, replacing any previous attempt for the same listener.
///
/// `confirmed_at` is deliberately absent from the `SET` list: a fresh attempt must not erase the
/// last time the chain was proven end to end, or the pane loses the ability to compare the two
/// ages.
pub async fn upsert_probe(pool: &PgPool, rec: &ProbeRecord) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO listener_probe \
           (collector_id, sensor, protocol, port, target, attempted_at, outcome, detail, latency_ms) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) \
         ON CONFLICT (collector_id, sensor, protocol, port) DO UPDATE \
         SET target = EXCLUDED.target, attempted_at = EXCLUDED.attempted_at, \
             outcome = EXCLUDED.outcome, detail = EXCLUDED.detail, \
             latency_ms = EXCLUDED.latency_ms",
    )
    .bind(&rec.listener.collector_id)
    .bind(&rec.listener.sensor)
    .bind(rec.listener.protocol.as_str())
    .bind(i32::from(rec.listener.port))
    .bind(&rec.target)
    .bind(rec.attempted_at)
    .bind(rec.outcome.as_str())
    .bind(rec.detail.as_deref())
    .bind(rec.latency_ms)
    .execute(pool)
    .await?;
    Ok(())
}

/// Stamps `confirmed_at` on every row for `sensor` whose attempt is recent enough to be the one
/// this sighting belongs to, and returns how many rows it touched.
///
/// The `attempted_at` guard is the point of the function: without it, a line arriving long after
/// the prober died would retro-confirm a stale row and paint a dead path green.
pub async fn confirm_sensor(
    pool: &PgPool,
    sensor: &str,
    seen_at: DateTime<Utc>,
    grace: std::time::Duration,
) -> Result<u64, sqlx::Error> {
    // The cutoff is computed here rather than as a Postgres `interval` cast so the window is
    // anchored to the caller's own `seen_at`, not to the database clock.
    let cutoff = seen_at
        - chrono::Duration::from_std(grace).unwrap_or_else(|_| chrono::Duration::seconds(0));
    let result = sqlx::query(
        "UPDATE listener_probe SET confirmed_at = $2 WHERE sensor = $1 AND attempted_at >= $3",
    )
    .bind(sensor)
    .bind(seen_at)
    .bind(cutoff)
    .execute(pool)
    .await?;
    Ok(result.rows_affected())
}

/// Every stored row, ordered so the pane's join is deterministic.
pub async fn read_all(pool: &PgPool) -> Result<Vec<ProbeRow>, sqlx::Error> {
    let rows = sqlx::query(
        "SELECT collector_id, sensor, protocol, port, target, attempted_at, outcome, detail, \
                latency_ms, confirmed_at \
         FROM listener_probe ORDER BY collector_id, sensor, protocol, port",
    )
    .fetch_all(pool)
    .await?;

    let mut out = Vec::with_capacity(rows.len());
    for row in rows {
        let protocol = match row.try_get::<String, _>("protocol")?.as_str() {
            "udp" => Proto::Udp,
            _ => Proto::Tcp,
        };
        let port: i32 = row.try_get("port")?;
        let outcome: String = row.try_get("outcome")?;
        out.push(ProbeRow {
            listener: Listener {
                collector_id: row.try_get("collector_id")?,
                sensor: row.try_get("sensor")?,
                protocol,
                port: port.clamp(0, i32::from(u16::MAX)) as u16,
            },
            target: row.try_get("target")?,
            attempted_at: row.try_get("attempted_at")?,
            outcome: ProbeOutcome::from_db(&outcome),
            detail: row.try_get("detail")?,
            latency_ms: row.try_get("latency_ms")?,
            confirmed_at: row.try_get("confirmed_at")?,
        });
    }
    Ok(out)
}
