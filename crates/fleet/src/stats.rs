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

/// The most characters the `sensor` column holds (`CHECK (length(sensor) <= 64)` in
/// `0002_sensor_stats.sql`). The column is the table's key: a bare sensor name for a sensor on
/// this node, a [`collector_key`] for one read from a collector's spool.
pub const MAX_KEY_LEN: usize = 64;

/// The longest sensor name [`collector_key`] takes. Every shipped name is far shorter; the bound
/// leaves room for a shortened label and its hash however long the label is.
const MAX_KEY_SENSOR_LEN: usize = 32;

/// The key a row read from a log NOT bound to one sensor is stored under: on a control node, a
/// collector's spool, labelled with the collector id. A log bound to a sensor stores under the
/// bare sensor name instead, as a single box always has.
///
/// The primary key is the sensor column, so the collector has to be part of it: with the bare
/// name, the same sensor on two collectors (and on the control node itself) would share one row,
/// the freshest line would win, and a sensor that died on one collector would look alive because
/// another collector's line arrived.
///
/// `"<label>/<sensor>"` when the label fits the column ([`MAX_KEY_LEN`], counted in bytes, which
/// is never fewer than the characters the column counts) beside `/` and the longest sensor name
/// this takes (32 bytes), so for a label of up to 31 bytes. Otherwise the label is cut, on a
/// character boundary, to its first 14 bytes or fewer, followed by `~` and a 64-bit FNV-1a hash
/// of the WHOLE label in 16 hex digits, so two long labels that share a prefix still get two
/// keys. Whether to cut and where depend on the label alone, so every sensor of one collector
/// gets the same label part. The hash is
/// spelled out here rather than taken from `std`'s `DefaultHasher`, whose output may change between
/// Rust releases: a key that moved on an upgrade would leave the old row behind as a stale sensor.
///
/// `None` when `sensor` is empty, contains `/` (the reader splits the key at its last `/`, see
/// [`split_key`]) or is longer than 32 bytes. Intake passes only names from the origin table,
/// none of which is any of these.
pub fn collector_key(label: &str, sensor: &str) -> Option<String> {
    if sensor.is_empty() || sensor.contains('/') || sensor.len() > MAX_KEY_SENSOR_LEN {
        return None;
    }
    // Both the decision and the cut are made against the longest sensor name a key takes, never
    // against this sensor: `/metrics` publishes the label part as the `collector` label, and one
    // collector must show under one value for all its sensors.
    if label.len() + 1 + MAX_KEY_SENSOR_LEN <= MAX_KEY_LEN {
        return Some(format!("{label}/{sensor}"));
    }
    let hash = fnv1a_64(label.as_bytes());
    // `~` and 16 hex digits, then `/` and the longest sensor name.
    let room = MAX_KEY_LEN - (1 + 16) - (1 + MAX_KEY_SENSOR_LEN);
    let mut cut = room.min(label.len());
    while !label.is_char_boundary(cut) {
        cut -= 1;
    }
    Some(format!("{}~{hash:016x}/{sensor}", &label[..cut]))
}

/// A stored key as `(collector, sensor)`: `(None, key)` for a bare sensor name (a sensor on this
/// node), the parts on either side of the LAST `/` for a [`collector_key`]. The last, because a
/// sensor name never contains `/` while an operator's log label may.
pub fn split_key(key: &str) -> (Option<&str>, &str) {
    match key.rsplit_once('/') {
        Some((collector, sensor)) => (Some(collector), sensor),
        None => (None, key),
    }
}

fn fnv1a_64(bytes: &[u8]) -> u64 {
    bytes.iter().fold(0xcbf2_9ce4_8422_2325, |hash, &b| {
        (hash ^ u64::from(b)).wrapping_mul(0x0000_0100_0000_01b3)
    })
}

/// The latest `sensor_stats` line of one sensor. Counters are `i64` because the column is
/// `bigint`; the wire type bounds them at 2^53, so the conversion never clips.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SensorStatsRow {
    /// The row's key: the bare sensor name, or a [`collector_key`] ([`split_key`] reads it back).
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

/// Every stored row, by key.
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

    /// The column's rule (`sensor <> '' AND length(sensor) <= 64`), held in bytes, which is the
    /// stricter of the two because a character is at least one byte.
    fn column_accepts(key: &str) -> bool {
        !key.is_empty() && key.len() <= MAX_KEY_LEN
    }

    #[test]
    fn a_collector_key_that_fits_is_the_label_and_the_sensor_as_they_are() {
        assert_eq!(
            collector_key("collector-a", "ssh").as_deref(),
            Some("collector-a/ssh")
        );
        assert_eq!(split_key("collector-a/ssh"), (Some("collector-a"), "ssh"));
        // An operator's label may hold a slash; the sensor never does.
        let key = collector_key("site/a", "ssh").unwrap();
        assert_eq!(split_key(&key), (Some("site/a"), "ssh"));
    }

    /// The longest label kept whole is the one that still fits beside the longest sensor name
    /// the key takes, so it is kept whole for every sensor.
    #[test]
    fn the_longest_label_kept_whole_makes_a_64_character_key_with_the_longest_sensor_name() {
        let label = "c".repeat(MAX_KEY_LEN - 1 - MAX_KEY_SENSOR_LEN);
        let longest = "s".repeat(MAX_KEY_SENSOR_LEN);
        let key = collector_key(&label, &longest).unwrap();
        assert_eq!(key, format!("{label}/{longest}"));
        assert_eq!(key.len(), MAX_KEY_LEN);
        assert_eq!(
            collector_key(&label, "ssh").unwrap(),
            format!("{label}/ssh")
        );
    }

    /// One byte longer and the label is shortened, for a short sensor name too, although
    /// `<label>/ssh` would still fit: the label part must not depend on the sensor.
    #[test]
    fn a_label_one_byte_too_long_for_the_longest_sensor_name_is_shortened_for_every_sensor() {
        let label = "c".repeat(MAX_KEY_LEN - MAX_KEY_SENSOR_LEN);
        let short = collector_key(&label, "ssh").unwrap();
        assert_ne!(short, format!("{label}/ssh"));
        assert!(short.contains('~'), "{short}");
        let longest = collector_key(&label, &"s".repeat(MAX_KEY_SENSOR_LEN)).unwrap();
        assert_eq!(split_key(&short).0, split_key(&longest).0);
        assert_eq!(longest.len(), MAX_KEY_LEN, "{longest}");
    }

    /// `/metrics` publishes the label part as the `collector` label, and a query selects a
    /// collector across its sensors by it. So one collector has one label part, whatever the
    /// sensor and however long the label.
    #[test]
    fn every_sensor_of_one_collector_gets_the_same_label_part() {
        let sensors = [
            "s",
            "ssh",
            "telnet",
            "postgresql",
            &"s".repeat(MAX_KEY_SENSOR_LEN),
        ];
        for len in 1..=80 {
            for label in ["x".repeat(len), "\u{e9}".repeat(len)] {
                let parts: std::collections::BTreeSet<_> = sensors
                    .iter()
                    .map(|s| {
                        let key = collector_key(&label, s).unwrap();
                        split_key(&key).0.unwrap().to_string()
                    })
                    .collect();
                assert_eq!(parts.len(), 1, "{len}: {parts:?}");
            }
        }
    }

    #[test]
    fn a_collector_key_too_long_for_the_column_is_shortened_and_still_names_the_sensor() {
        let label = "c".repeat(MAX_KEY_LEN);
        let key = collector_key(&label, "postgresql").unwrap();
        assert!(column_accepts(&key), "{key}");
        let (collector, sensor) = split_key(&key);
        assert_eq!(sensor, "postgresql");
        assert!(collector.unwrap().starts_with("ccc"), "{key}");
        assert_eq!(
            collector_key(&label, "postgresql").unwrap(),
            key,
            "the key is stable, or every restart would start a new row"
        );
    }

    #[test]
    fn two_long_labels_that_share_a_prefix_get_different_keys() {
        let shared = "collector-".repeat(7);
        let a = collector_key(&format!("{shared}a"), "ssh").unwrap();
        let b = collector_key(&format!("{shared}b"), "ssh").unwrap();
        assert_ne!(a, b);
        assert!(column_accepts(&a) && column_accepts(&b), "{a} {b}");
    }

    #[test]
    fn a_long_label_is_cut_on_a_character_boundary() {
        let label = "\u{e9}".repeat(MAX_KEY_LEN);
        let key = collector_key(&label, "ssh").unwrap();
        assert!(column_accepts(&key), "{key}");
        assert!(key.ends_with("/ssh"), "{key}");
    }

    #[test]
    fn every_collector_key_passes_the_columns_rule() {
        let longest = "s".repeat(MAX_KEY_SENSOR_LEN);
        for len in 1..=MAX_KEY_LEN + 8 {
            for label in ["x".repeat(len), "\u{e9}".repeat(len)] {
                for sensor in ["ssh", "postgresql", "s", &longest] {
                    let key = collector_key(&label, sensor).unwrap();
                    assert!(column_accepts(&key), "{len} {sensor}: {key}");
                    assert_eq!(split_key(&key).1, sensor);
                }
            }
        }
    }

    #[test]
    fn a_sensor_name_that_could_not_be_split_back_out_gets_no_key() {
        assert_eq!(collector_key("collector-a", ""), None);
        assert_eq!(collector_key("collector-a", "a/b"), None);
        assert_eq!(collector_key("collector-a", &"s".repeat(40)), None);
    }

    #[test]
    fn the_label_hash_is_fnv1a_64_so_a_toolchain_upgrade_cannot_move_a_key() {
        assert_eq!(fnv1a_64(b""), 0xcbf2_9ce4_8422_2325);
        assert_eq!(fnv1a_64(b"a"), 0xaf63_dc4c_8601_ec8c);
    }

    #[test]
    fn a_bare_sensor_name_splits_to_no_collector() {
        assert_eq!(split_key("ssh"), (None, "ssh"));
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
