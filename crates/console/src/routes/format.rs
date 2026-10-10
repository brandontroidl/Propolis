//! Small display-formatting helpers shared by multiple route modules. Factored out of
//! `routes::queue` (the original sole owner of both) once `routes::detail` needed the same two -
//! one shared copy rather than two that can drift on the next edit.

use chrono::{DateTime, Utc};
use core_scoring::{FeedTier, Protocol};

/// Renders a UTC timestamp the same way on every page: `2026-07-17 00:00 UTC`.
pub(crate) fn format_timestamp(dt: DateTime<Utc>) -> String {
    dt.format("%Y-%m-%d %H:%M UTC").to_string()
}

/// A count with thousands separators: `29296` as `29,296`.
pub(crate) fn group_digits(n: i64) -> String {
    let digits = n.unsigned_abs().to_string();
    let mut out = String::with_capacity(digits.len() + digits.len() / 3 + 1);
    if n < 0 {
        out.push('-');
    }
    for (i, c) in digits.chars().enumerate() {
        if i > 0 && (digits.len() - i).is_multiple_of(3) {
            out.push(',');
        }
        out.push(c);
    }
    out
}

/// A score as the whole percent its meter is drawn at (`macros.html#score_meter`, whose `pct-N`
/// classes run 0 to 100), so every page fills the same score to the same width.
pub(crate) fn score_pct(score: f64) -> u32 {
    if score.is_nan() {
        return 0;
    }
    score.clamp(0.0, 100.0).round() as u32
}

/// The lowercase display label for a feed tier, matching the CSS class suffixes in
/// `templates/base_head.html` (`.tier-aggressive` / `.tier-standard`).
pub(crate) fn tier_label(t: FeedTier) -> &'static str {
    match t {
        FeedTier::Aggressive => "aggressive",
        FeedTier::Standard => "standard",
    }
}

/// The display label for an event's transport. `Protocol`'s `Debug` output (`Tcp`) is a Rust
/// identifier, not how anyone writes the protocol's name.
pub(crate) fn protocol_label(p: Protocol) -> &'static str {
    match p {
        Protocol::Tcp => "TCP",
        Protocol::Udp => "UDP",
        Protocol::Icmp => "ICMP",
    }
}

/// Maps a raw sensor name to a display label for chart axes and table headers.
pub(crate) fn format_sensor_label(sensor: &str) -> String {
    match sensor {
        "ssh" => "SSH".into(),
        "ftp" => "FTP".into(),
        "http" => "HTTP".into(),
        "vnc" => "VNC".into(),
        "redis" => "Redis".into(),
        "mysql" => "MySQL".into(),
        "postgresql" => "PostgreSQL".into(),
        "mongodb" => "MongoDB".into(),
        // Acronyms the title-case fallback would mangle (mssql -> "Mssql", smtp -> "Smtp", adb -> "Adb").
        "mssql" => "MSSQL".into(),
        "smtp" => "SMTP".into(),
        "tftp" => "TFTP".into(),
        "mqtt" => "MQTT".into(),
        "dns" => "DNS".into(),
        "adb" => "ADB".into(),
        "catchall" | "catchall-sensor" => "General".into(),
        // The credential sensor's listeners are named for the service they imitate.
        "cred-vnc" => "VNC".into(),
        "cred-mysql" => "MySQL".into(),
        "cred-mssql" => "MSSQL".into(),
        "cred-pg" => "PostgreSQL".into(),
        "cred-mongo" => "MongoDB".into(),
        other => {
            let mut s = other.to_string();
            if let Some(first) = s.get_mut(0..1) {
                first.make_ascii_uppercase();
            }
            s
        }
    }
}

/// Combines a sensor name and signal type into a plain-language activity label. The sensor
/// provides the service context (SSH, FTP, Redis), the signal type describes what happened.
pub(crate) fn format_activity(sensor: &str, signal_type: &str) -> String {
    let service = match sensor {
        "ssh" => "SSH".to_string(),
        "ftp" => "FTP".to_string(),
        "tftp" => "TFTP".to_string(),
        "mqtt" => "MQTT".to_string(),
        "dns" => "DNS".to_string(),
        "http" => "HTTP".to_string(),
        "vnc" => "VNC".to_string(),
        "redis" => "Redis".to_string(),
        "mysql" => "MySQL".to_string(),
        "postgresql" => "PostgreSQL".to_string(),
        "mongodb" => "MongoDB".to_string(),
        "catchall" | "catchall-sensor" => String::new(),
        other => format_sensor_label(other),
    };
    let action = match signal_type {
        "honeypot_login_attempt" => "login attempt",
        "honeypot_connection" => "connection",
        "honeypot_command_exec" => "command execution",
        "honeypot_malware_upload" => "malware upload",
        // A URL the attacker told the shell to fetch: an attempt the sensor extracted, never a
        // file it received. Whether anything was retrieved is the fetcher's separate record.
        "honeypot_file_download" => "download attempt",
        // Telemetry, not an accusation: it carries no weight and never moved this address's
        // score (see docs/reference/events-and-signals.md).
        "honeypot_session_end" => "session ended",
        "ssh_brute_force" => "SSH brute force",
        "port_scan" => "port scan",
        "syn_flood" => "SYN flood",
        "blocked_connection" => "blocked connection",
        "waf_sqli_xss" => "SQLi/XSS attempt",
        "waf_generic_block" => "WAF block",
        "suricata_sev1" => "IDS alert (critical)",
        "suricata_sev2" => "IDS alert (high)",
        "suricata_sev3" => "IDS alert (medium)",
        "catchall_probe" => "probe",
        "remote_auth_failure" => "auth failure",
        other => other,
    };
    if service.is_empty() || action.starts_with("SSH") || action.starts_with("IDS") {
        action.to_string()
    } else {
        format!("{service} {action}")
    }
}

/// Maps a signal type to a severity rung for the console's temperature ramp: `crit` (malware),
/// `high` (hands-on-keyboard: command exec, download attempt), `watch` (credential attempts / IDS
/// escalations that want a look), or `low` (scans and probes - noise). Drives the `.sev--*` tags and
/// the activity strip's `.s1..s4` cells. The single source of truth for signal-to-colour, so the
/// two never disagree. An unknown signal is treated as `low` (fail-quiet: a new signal reads as
/// noise until someone classifies it, never as a false alarm).
pub(crate) fn signal_severity(signal_type: &str) -> &'static str {
    match signal_type {
        "honeypot_malware_upload" => "crit",
        "honeypot_command_exec" | "honeypot_file_download" => "high",
        "honeypot_login_attempt"
        | "ssh_brute_force"
        | "remote_auth_failure"
        | "waf_sqli_xss"
        | "suricata_sev1" => "watch",
        _ => "low",
    }
}

/// A short "what it did" label for a signal type, for the dashboard's severity tags. Shorter than
/// [`format_activity`] (no service prefix) since the tags sit in a narrow column.
pub(crate) fn signal_tag_label(signal_type: &str) -> &'static str {
    match signal_type {
        "honeypot_malware_upload" => "malware upload",
        "honeypot_command_exec" => "command exec",
        "honeypot_file_download" => "download attempt",
        "honeypot_session_end" => "session end",
        "honeypot_login_attempt" => "login attempt",
        "honeypot_connection" => "connection",
        "ssh_brute_force" => "ssh brute",
        "remote_auth_failure" => "auth failure",
        "port_scan" => "port scan",
        "syn_flood" => "syn flood",
        "blocked_connection" => "blocked",
        "waf_sqli_xss" => "sqli/xss",
        "waf_generic_block" => "waf block",
        "catchall_probe" => "probe",
        "suricata_sev1" => "ids critical",
        "suricata_sev2" => "ids high",
        "suricata_sev3" => "ids medium",
        // The signal set is a closed enum, so every real value is covered above; a future/unknown
        // one reads as generic "activity" rather than leaking a raw enum name into the UI.
        _ => "activity",
    }
}

/// Rank a severity rung so tags/cells can be ordered worst-first (higher = more severe).
pub(crate) fn severity_rank(severity: &str) -> u8 {
    match severity {
        "crit" => 4,
        "high" => 3,
        "watch" => 2,
        "low" => 1,
        _ => 0,
    }
}

/// The review queue's single "Active" cell: how long an address has been active, as text, plus
/// the exact first and last timestamps for a `title` attribute.
///
/// Within one UTC day the span reads as a clock range (`10:58-18:11 UTC`, prefixed with the date
/// unless it is `now`'s date, so an old row is not mistaken for today's). Across midnight a clock
/// range would not say how long, so it reads as a length plus recency (`2d, last 3m ago`).
/// `now` is a parameter so the boundaries can be tested.
pub(crate) fn format_active(
    first: DateTime<Utc>,
    last: DateTime<Utc>,
    now: DateTime<Utc>,
) -> (String, String) {
    let title = format!(
        "first {}, last {}",
        format_timestamp(first),
        format_timestamp(last)
    );
    if first.date_naive() == last.date_naive() {
        let clock = if first.format("%H:%M").to_string() == last.format("%H:%M").to_string() {
            format!("{} UTC", first.format("%H:%M"))
        } else {
            format!("{}-{} UTC", first.format("%H:%M"), last.format("%H:%M"))
        };
        let text = if first.date_naive() == now.date_naive() {
            clock
        } else {
            format!("{}, {clock}", first.format("%b %-d"))
        };
        return (text, title);
    }
    let span = last - first;
    let length = if span.num_hours() < 1 {
        format!("{}m", span.num_minutes().max(1))
    } else if span.num_hours() < 24 {
        format!("{}h", span.num_hours())
    } else {
        format!("{}d", span.num_days())
    };
    let ago = elapsed_ago((now - last).max(chrono::Duration::zero()));
    (format!("{length}, last {ago}"), title)
}

/// Coarsens a UTC timestamp to "how long ago", in the largest whole unit that fits - used by the
/// dashboard's recent-activity table, where an exact `format_timestamp` value is more precision
/// than an operator scanning twenty rows needs.
pub(crate) fn format_relative_time(dt: DateTime<Utc>) -> String {
    elapsed_ago(Utc::now() - dt)
}

/// The one spelling of recency on every page: `45s ago`, `5m ago`, `3h ago`, `2d ago`.
fn elapsed_ago(elapsed: chrono::Duration) -> String {
    if elapsed.num_seconds() < 60 {
        return format!("{}s ago", elapsed.num_seconds());
    }
    if elapsed.num_minutes() < 60 {
        return format!("{}m ago", elapsed.num_minutes());
    }
    if elapsed.num_hours() < 24 {
        return format!("{}h ago", elapsed.num_hours());
    }
    format!("{}d ago", elapsed.num_days())
}

/// A byte count the same way on every page (`512 B`, `4.2 KB`, `5.0 MB`, `1.3 GB`), in binary
/// steps of 1024.
pub(crate) fn format_bytes(b: u64) -> String {
    const UNITS: [&str; 3] = ["KB", "MB", "GB"];
    if b < 1024 {
        return format!("{b} B");
    }
    let mut value = b as f64 / 1024.0;
    let mut unit = 0;
    while value >= 1024.0 && unit < UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }
    format!("{value:.1} {}", UNITS[unit])
}

#[cfg(test)]
mod tests {
    use chrono::Duration;

    use super::*;

    #[test]
    fn format_relative_time_under_a_minute_shows_seconds() {
        let dt = Utc::now() - Duration::seconds(45);
        assert_eq!(format_relative_time(dt), "45s ago");
    }

    #[test]
    fn format_relative_time_under_an_hour_shows_minutes() {
        let dt = Utc::now() - Duration::seconds(90);
        assert_eq!(format_relative_time(dt), "1m ago");
    }

    #[test]
    fn format_relative_time_under_a_day_shows_hours() {
        let dt = Utc::now() - Duration::seconds(3661);
        assert_eq!(format_relative_time(dt), "1h ago");
    }

    #[test]
    fn format_relative_time_a_day_or_more_shows_days() {
        let dt = Utc::now() - Duration::seconds(90_000);
        assert_eq!(format_relative_time(dt), "1d ago");
    }

    #[test]
    fn group_digits_puts_a_comma_every_three_places() {
        assert_eq!(group_digits(0), "0");
        assert_eq!(group_digits(999), "999");
        assert_eq!(group_digits(1000), "1,000");
        assert_eq!(group_digits(29296), "29,296");
        assert_eq!(group_digits(1234567), "1,234,567");
        assert_eq!(group_digits(-1234), "-1,234");
    }

    /// The meter draws `pct-N` for N in 0..=100 only, so every score must land in that range: a
    /// live score past 100 (breadth weighting) or a NaN would name a class that does not exist and
    /// render an empty meter.
    #[test]
    fn score_pct_always_names_an_existing_meter_width() {
        assert_eq!(super::score_pct(0.0), 0);
        assert_eq!(super::score_pct(49.4), 49);
        assert_eq!(super::score_pct(89.5), 90);
        assert_eq!(super::score_pct(100.0), 100);
        assert_eq!(super::score_pct(134.2), 100);
        assert_eq!(super::score_pct(-3.0), 0);
        assert_eq!(super::score_pct(f64::NAN), 0);
    }

    fn at(s: &str) -> DateTime<Utc> {
        s.parse().unwrap()
    }

    #[test]
    fn active_same_day_today_is_a_bare_clock_range() {
        let now = at("2026-10-08T20:00:00Z");
        let (text, title) =
            format_active(at("2026-10-08T10:58:40Z"), at("2026-10-08T18:11:05Z"), now);
        assert_eq!(text, "10:58-18:11 UTC");
        assert_eq!(
            title,
            "first 2026-10-08 10:58 UTC, last 2026-10-08 18:11 UTC"
        );
    }

    #[test]
    fn active_within_one_minute_collapses_to_a_single_time() {
        let now = at("2026-10-08T20:00:00Z");
        let (text, _) = format_active(at("2026-10-08T10:58:01Z"), at("2026-10-08T10:58:59Z"), now);
        assert_eq!(text, "10:58 UTC");
    }

    #[test]
    fn active_same_day_on_an_earlier_date_carries_the_date() {
        let now = at("2026-10-08T01:00:00Z");
        let (text, _) = format_active(at("2026-10-05T10:58:00Z"), at("2026-10-05T18:11:00Z"), now);
        assert_eq!(text, "Oct 5, 10:58-18:11 UTC");
    }

    #[test]
    fn active_across_midnight_under_an_hour_is_minutes_not_zero_days() {
        let now = at("2026-10-08T00:13:30Z");
        let (text, _) = format_active(at("2026-10-07T23:50:00Z"), at("2026-10-08T00:10:00Z"), now);
        assert_eq!(text, "20m, last 3m ago");
    }

    #[test]
    fn active_length_unit_changes_at_one_hour_and_one_day() {
        // Every span below starts on the previous UTC day, so none is read as a clock range.
        let now = at("2026-10-09T01:30:00Z");
        let last = at("2026-10-09T00:30:00Z");
        assert_eq!(
            format_active(last - Duration::minutes(59), last, now).0,
            "59m, last 1h ago"
        );
        assert_eq!(
            format_active(last - Duration::minutes(60), last, now).0,
            "1h, last 1h ago"
        );
        assert_eq!(
            format_active(last - Duration::minutes(24 * 60 - 1), last, now).0,
            "23h, last 1h ago"
        );
        assert_eq!(
            format_active(last - Duration::hours(24), last, now).0,
            "1d, last 1h ago"
        );
        assert_eq!(
            format_active(last - Duration::hours(50), last, now).0,
            "2d, last 1h ago"
        );
    }

    #[test]
    fn active_recency_buckets() {
        let first = at("2026-10-01T00:00:00Z");
        let last = at("2026-10-05T12:00:00Z");
        let ago = |d: Duration| format_active(first, last, last + d).0;
        // The same spelling as `format_relative_time`, so Review's Active cell and the
        // dashboard's recent activity read alike one click apart.
        assert_eq!(ago(Duration::seconds(59)), "4d, last 59s ago");
        assert_eq!(ago(Duration::seconds(60)), "4d, last 1m ago");
        assert_eq!(ago(Duration::minutes(59)), "4d, last 59m ago");
        assert_eq!(ago(Duration::minutes(60)), "4d, last 1h ago");
        assert_eq!(ago(Duration::hours(24)), "4d, last 1d ago");
        assert_eq!(ago(Duration::seconds(-30)), "4d, last 0s ago");
    }

    #[test]
    fn bytes_read_the_same_on_every_page() {
        assert_eq!(format_bytes(512), "512 B");
        assert_eq!(format_bytes(4300), "4.2 KB");
        assert_eq!(format_bytes(5_242_880), "5.0 MB");
        assert_eq!(format_bytes(6_600_000_000), "6.1 GB");
    }

    #[test]
    fn acronym_sensor_labels_are_fully_uppercased_not_title_cased() {
        // The title-case fallback renders these as Mssql / Smtp / Adb - wrong for acronyms.
        assert_eq!(format_sensor_label("mssql"), "MSSQL");
        assert_eq!(format_sensor_label("smtp"), "SMTP");
        assert_eq!(format_sensor_label("adb"), "ADB");
        assert_eq!(format_sensor_label("tftp"), "TFTP");
        assert_eq!(format_sensor_label("mqtt"), "MQTT");
        assert!(format_activity("mqtt", "honeypot_command_exec").contains("MQTT"));
        assert_eq!(format_sensor_label("dns"), "DNS");
        assert_eq!(format_sensor_label("cred-vnc"), "VNC");
        assert_eq!(format_sensor_label("cred-pg"), "PostgreSQL");
        assert!(format_activity("dns", "honeypot_command_exec").contains("DNS"));
        // format_activity inherits the fix via its `other => format_sensor_label(other)` delegation.
        assert!(format_activity("mssql", "honeypot_login_attempt").contains("MSSQL"));
    }
}
