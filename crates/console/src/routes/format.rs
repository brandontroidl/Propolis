//! Small display-formatting helpers shared by multiple route modules. Factored out of
//! `routes::queue` (the original sole owner of both) once `routes::detail` needed the same two -
//! one shared copy rather than two that can drift on the next edit.

use chrono::{DateTime, Utc};
use core_scoring::FeedTier;

/// Renders a UTC timestamp the same way on every page: `2026-07-17 00:00 UTC`.
pub(crate) fn format_timestamp(dt: DateTime<Utc>) -> String {
    dt.format("%Y-%m-%d %H:%M UTC").to_string()
}

/// The lowercase display label for a feed tier, matching the CSS class suffixes in
/// `templates/base_head.html` (`.tier-aggressive` / `.tier-standard`).
pub(crate) fn tier_label(t: FeedTier) -> &'static str {
    match t {
        FeedTier::Aggressive => "aggressive",
        FeedTier::Standard => "standard",
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
        "adb" => "ADB".into(),
        "catchall" | "catchall-sensor" => "General".into(),
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

/// Coarsens a UTC timestamp to "how long ago", in the largest whole unit that fits - used by the
/// dashboard's recent-activity table, where an exact `format_timestamp` value is more precision
/// than an operator scanning twenty rows needs.
pub(crate) fn format_relative_time(dt: DateTime<Utc>) -> String {
    let elapsed = Utc::now() - dt;
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
    fn acronym_sensor_labels_are_fully_uppercased_not_title_cased() {
        // The title-case fallback renders these as Mssql / Smtp / Adb - wrong for acronyms.
        assert_eq!(format_sensor_label("mssql"), "MSSQL");
        assert_eq!(format_sensor_label("smtp"), "SMTP");
        assert_eq!(format_sensor_label("adb"), "ADB");
        // format_activity inherits the fix via its `other => format_sensor_label(other)` delegation.
        assert!(format_activity("mssql", "honeypot_login_attempt").contains("MSSQL"));
    }
}
