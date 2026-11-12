//! Durable storage and staleness rules for `sensor_stats` (the `sensor_stats` table).
//!
//! Intake is the only writer ([`upsert`]); the console reads ([`read_all`]) and turns each row into
//! gauges plus an age. A row is the latest line a sensor wrote, nothing more: no history, no
//! ledger entry, no score. See the migration for why this is not an event.

use chrono::{DateTime, Utc};
use sqlx::{PgPool, Row};

/// A row is stale once its newest line is older than this: three missed 60 s intervals
/// (`sensor_framework::handoff::STATS_INTERVAL`), long enough that one slow poll or a delayed
/// shipper batch does not flap it, short enough that a dead sensor shows within minutes.
pub const STALE_AFTER_SECS: i64 = 180;

/// The latest `sensor_stats` line of one sensor. Counters are `i64` because the column is
/// `bigint`; the wire type bounds them at 2^53, so the conversion never clips.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SensorStatsRow {
    pub sensor: String,
    pub reported_at: DateTime<Utc>,
    pub received_at: DateTime<Utc>,
    pub uptime_secs: i64,
    pub is_final: bool,
    pub dropped: i64,
    pub spool_refused: i64,
    pub truncated: i64,
    pub refused: i64,
    pub budget_current: i64,
    pub budget_high_water: i64,
    pub budget_refused: i64,
}

impl SensorStatsRow {
    /// How old the newest line is at `now`, in seconds. Never negative: a sensor clock ahead of
    /// ours reads as fresh (0), not as a future age that would hide a real stall later.
    pub fn age_seconds(&self, now: DateTime<Utc>) -> i64 {
        (now - self.reported_at).num_seconds().max(0)
    }

    /// Whether the newest line is older than [`STALE_AFTER_SECS`]. A `final` row is reported as
    /// stale like any other once it ages: a stopped sensor is not a healthy one, and `is_final`
    /// is published separately so an operator can tell a clean stop from a silent death.
    pub fn is_stale(&self, now: DateTime<Utc>) -> bool {
        self.age_seconds(now) > STALE_AFTER_SECS
    }
}

/// Stores `row` unless the table already holds a newer line for the sensor. Returns whether it was
/// applied. The guard is in the statement, so two intake writers cannot move a row backwards.
pub async fn upsert(pool: &PgPool, row: &SensorStatsRow) -> Result<bool, sqlx::Error> {
    let result = sqlx::query(
        "INSERT INTO sensor_stats \
           (sensor, reported_at, received_at, uptime_secs, is_final, dropped, spool_refused, \
            truncated, refused, budget_current, budget_high_water, budget_refused) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12) \
         ON CONFLICT (sensor) DO UPDATE SET \
           reported_at = EXCLUDED.reported_at, received_at = EXCLUDED.received_at, \
           uptime_secs = EXCLUDED.uptime_secs, is_final = EXCLUDED.is_final, \
           dropped = EXCLUDED.dropped, spool_refused = EXCLUDED.spool_refused, \
           truncated = EXCLUDED.truncated, refused = EXCLUDED.refused, \
           budget_current = EXCLUDED.budget_current, \
           budget_high_water = EXCLUDED.budget_high_water, \
           budget_refused = EXCLUDED.budget_refused \
         WHERE sensor_stats.reported_at <= EXCLUDED.reported_at",
    )
    .bind(&row.sensor)
    .bind(row.reported_at)
    .bind(row.received_at)
    .bind(row.uptime_secs)
    .bind(row.is_final)
    .bind(row.dropped)
    .bind(row.spool_refused)
    .bind(row.truncated)
    .bind(row.refused)
    .bind(row.budget_current)
    .bind(row.budget_high_water)
    .bind(row.budget_refused)
    .execute(pool)
    .await?;
    Ok(result.rows_affected() == 1)
}

/// Every stored row, by sensor name.
pub async fn read_all(pool: &PgPool) -> Result<Vec<SensorStatsRow>, sqlx::Error> {
    let rows = sqlx::query(
        "SELECT sensor, reported_at, received_at, uptime_secs, is_final, dropped, spool_refused, \
                truncated, refused, budget_current, budget_high_water, budget_refused \
         FROM sensor_stats ORDER BY sensor",
    )
    .fetch_all(pool)
    .await?;
    rows.iter()
        .map(|r| {
            Ok(SensorStatsRow {
                sensor: r.try_get("sensor")?,
                reported_at: r.try_get("reported_at")?,
                received_at: r.try_get("received_at")?,
                uptime_secs: r.try_get("uptime_secs")?,
                is_final: r.try_get("is_final")?,
                dropped: r.try_get("dropped")?,
                spool_refused: r.try_get("spool_refused")?,
                truncated: r.try_get("truncated")?,
                refused: r.try_get("refused")?,
                budget_current: r.try_get("budget_current")?,
                budget_high_water: r.try_get("budget_high_water")?,
                budget_refused: r.try_get("budget_refused")?,
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(reported: &str) -> SensorStatsRow {
        SensorStatsRow {
            sensor: "ssh".into(),
            reported_at: reported.parse().unwrap(),
            received_at: reported.parse().unwrap(),
            uptime_secs: 0,
            is_final: false,
            dropped: 0,
            spool_refused: 0,
            truncated: 0,
            refused: 0,
            budget_current: 0,
            budget_high_water: 0,
            budget_refused: 0,
        }
    }

    #[test]
    fn age_counts_from_the_sensors_own_timestamp() {
        let r = row("2026-10-09T00:00:00Z");
        let now: DateTime<Utc> = "2026-10-09T00:02:30Z".parse().unwrap();
        assert_eq!(r.age_seconds(now), 150);
    }

    #[test]
    fn a_clock_ahead_of_ours_reads_as_age_zero_not_negative() {
        let r = row("2026-10-09T00:10:00Z");
        let now: DateTime<Utc> = "2026-10-09T00:00:00Z".parse().unwrap();
        assert_eq!(r.age_seconds(now), 0);
        assert!(!r.is_stale(now));
    }

    #[test]
    fn stale_means_strictly_older_than_three_intervals() {
        let r = row("2026-10-09T00:00:00Z");
        let at = |s: i64| r.reported_at + chrono::Duration::seconds(s);
        assert!(!r.is_stale(at(STALE_AFTER_SECS)));
        assert!(r.is_stale(at(STALE_AFTER_SECS + 1)));
        assert!(!r.is_stale(at(0)));
    }
}
