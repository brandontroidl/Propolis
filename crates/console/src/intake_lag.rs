//! How far each intake log is behind, as the daemon last measured it: what `/metrics` publishes
//! per log and what puts a "behind" badge on the fleet pane's listener rows.
//!
//! The daemon owns the measurement (its intake loops are the only thing that knows a log's read
//! offset), so the console only ever receives a snapshot through [`IntakeLagSource`]. A process
//! that tails nothing, such as the standalone console binary, hands over [`no_intake_lag`] and
//! the metrics are absent rather than zero: zero would claim a log nobody measured is caught up.

use std::sync::Arc;
use std::sync::atomic::AtomicU64;
use std::time::Duration;

/// Log lines the daemon's intake loops have set aside in the quarantine since process start,
/// published as `propolis_intake_lines_quarantined_total`. A process-wide counter the daemon
/// increments, like `server::STATS`, rather than a field on every `AppState`.
pub static LINES_QUARANTINED: AtomicU64 = AtomicU64::new(0);

/// One intake log's backlog after its latest poll.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IntakeLag {
    /// The `PROPOLIS_SENSOR_LOGS` label the log is tailed under; the `/metrics` `sensor` label.
    pub log: String,
    /// The `event.sensor` names the log's events carried. The fleet pane keys listeners on these,
    /// which is not the log label for every sensor (`cred-vnc` reports itself as `vnc`).
    pub sensors: Vec<String>,
    /// Unread bytes of the log, rotated-out inodes still being drained included.
    pub bytes_behind: u64,
    /// How long the oldest unread line has waited: zero when the latest poll read to the end of
    /// the complete lines, now minus the last appended event's `observed_at` when it left complete
    /// lines waiting, and `None` when lines are waiting but nothing has been appended since the
    /// daemon started, so there is no event to measure from.
    pub oldest_unread_age: Option<Duration>,
    /// Whether the daemon judges this log behind right now: lines waiting longer than its lag
    /// threshold. The `intake-lagging` ops alert adds persistence and a growth rule on top; this
    /// is the instantaneous reading the pane can show without that history.
    pub behind: bool,
}

/// Produces the current per-log snapshot; see [`IntakeLag`].
pub type IntakeLagSource = Arc<dyn Fn() -> Vec<IntakeLag> + Send + Sync>;

/// The [`IntakeLagSource`] for a process that tails no intake log.
pub fn no_intake_lag() -> IntakeLagSource {
    Arc::new(Vec::new)
}

/// "6.6 GB / 11 d": the unread bytes in decimal units and the oldest unread line's age in its
/// largest whole unit, or "age unknown" when there is no appended event to measure from.
pub fn format_backlog(bytes: u64, age: Option<Duration>) -> String {
    let age = match age {
        Some(age) => format_age(age),
        None => "age unknown".to_string(),
    };
    format!("{} / {age}", format_bytes(bytes))
}

fn format_bytes(bytes: u64) -> String {
    const UNITS: [&str; 4] = ["kB", "MB", "GB", "TB"];
    if bytes < 1000 {
        return format!("{bytes} B");
    }
    let mut value = bytes as f64 / 1000.0;
    let mut unit = 0;
    while value >= 1000.0 && unit < UNITS.len() - 1 {
        value /= 1000.0;
        unit += 1;
    }
    format!("{value:.1} {}", UNITS[unit])
}

fn format_age(age: Duration) -> String {
    let secs = age.as_secs();
    match secs {
        0..60 => format!("{secs} s"),
        60..3_600 => format!("{} min", secs / 60),
        3_600..86_400 => format!("{} h", secs / 3_600),
        _ => format!("{} d", secs / 86_400),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_incident_reads_the_way_the_badge_is_specified() {
        assert_eq!(
            format_backlog(
                6_600_000_000,
                Some(Duration::from_secs(11 * 86_400 + 3_000))
            ),
            "6.6 GB / 11 d"
        );
    }

    #[test]
    fn bytes_use_decimal_units_and_ages_their_largest_whole_unit() {
        assert_eq!(format_bytes(999), "999 B");
        assert_eq!(format_bytes(1_000), "1.0 kB");
        assert_eq!(format_bytes(42_300_000), "42.3 MB");
        assert_eq!(format_bytes(7_200_000_000_000_000), "7200.0 TB");
        assert_eq!(format_age(Duration::from_secs(59)), "59 s");
        assert_eq!(format_age(Duration::from_secs(60)), "1 min");
        assert_eq!(format_age(Duration::from_secs(3_599)), "59 min");
        assert_eq!(format_age(Duration::from_secs(3_600)), "1 h");
        assert_eq!(format_age(Duration::from_secs(86_399)), "23 h");
        assert_eq!(format_age(Duration::from_secs(86_400)), "1 d");
    }

    #[test]
    fn an_unknown_age_says_so_instead_of_reading_as_zero() {
        assert_eq!(format_backlog(2_000, None), "2.0 kB / age unknown");
    }
}
