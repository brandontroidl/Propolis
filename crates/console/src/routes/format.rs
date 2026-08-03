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
        "honeypot_file_download" => "file download",
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
}
