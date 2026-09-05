//! Typed, bounded configuration for operational self-alerting, parsed from environment variables.
//!
//! Parsing takes an injectable getter (`impl Fn(&str) -> Option<String>`) rather than reading the
//! process environment directly, so it is unit-testable in isolation without mutating global env.
//! The daemon's `load_config` calls it with a getter over `std::env::var`.

use std::time::Duration;

use crate::config::ConfigError;

/// Every value is range-checked with a safe default; a zero or blank never disables a guard.
/// `enabled` defaults to false: ops-alerting is opt-in, so an existing deployment that predates it
/// keeps starting (and logs that it is off - visible, not silent). Once the operator sets
/// `PROPOLIS_OPS_ENABLED=true`, `ntfy_url` and `ntfy_topic` become REQUIRED (fail-closed: a monitor
/// that cannot page must not start silently). Thresholds are tunable operational values.
#[derive(Debug, Clone, PartialEq)]
pub struct OpsAlertConfig {
    pub enabled: bool,
    pub ntfy_url: String,
    pub ntfy_topic: String,
    pub ntfy_token: Option<String>,
    pub poll_interval: Duration,
    pub repage_cooldown: Duration,
    pub stall_for: Duration,
    pub capacity_free_pct: u8,
    pub feed_stale_multiple: u32,
    /// The operator has installed the public-repo push (`deploy/blocklist-sync.sh` in cron), so
    /// a feed that has never been pushed is a failure for `feed-push-stale`, not grace.
    pub feed_push_expected: bool,
    pub vendor_window: Duration,
    pub vendor_fail_pct: u8,
    pub vendor_min_samples: u32,
    pub backlog_max: u64,
    pub backlog_for: Duration,
    pub chain_verify_interval: Duration,
    /// A spooled body unscanned, or a VirusTotal upload unverdicted, for longer than this pages
    /// (`scan-stale`); only when VirusTotal is enabled.
    pub scan_stale: Duration,
    /// A fetch url pending for longer than this pages (`fetch-stale`); only when the fetcher is
    /// enabled. The fetcher retires a url after three attempts, so this is well past that.
    pub fetch_stale: Duration,
}

fn get_bool(get: &impl Fn(&str) -> Option<String>, name: &str, default: bool) -> bool {
    match get(name) {
        Some(v) => matches!(
            v.trim().to_ascii_lowercase().as_str(),
            "true" | "1" | "yes" | "on"
        ),
        None => default,
    }
}

fn get_secs(
    get: &impl Fn(&str) -> Option<String>,
    name: &'static str,
    default_secs: u64,
    min_secs: u64,
) -> Result<Duration, ConfigError> {
    let secs = get_u64(get, name, default_secs, min_secs)?;
    Ok(Duration::from_secs(secs))
}

fn get_u64(
    get: &impl Fn(&str) -> Option<String>,
    name: &'static str,
    default: u64,
    min: u64,
) -> Result<u64, ConfigError> {
    match get(name) {
        None => Ok(default),
        Some(raw) => {
            let n: u64 = raw.trim().parse().map_err(|_| ConfigError::Invalid {
                field: name,
                value: raw.clone(),
                reason: "must be a non-negative integer",
            })?;
            if n < min {
                return Err(ConfigError::Invalid {
                    field: name,
                    value: raw,
                    reason: "below the minimum allowed value",
                });
            }
            Ok(n)
        }
    }
}

fn get_u32(
    get: &impl Fn(&str) -> Option<String>,
    name: &'static str,
    default: u32,
    min: u32,
) -> Result<u32, ConfigError> {
    let n = get_u64(get, name, default as u64, min as u64)?;
    u32::try_from(n).map_err(|_| ConfigError::Invalid {
        field: name,
        value: n.to_string(),
        reason: "exceeds the u32 range",
    })
}

/// A percentage strictly in 1..=100: 0 would disable the guard it protects, 100+ is nonsensical.
fn get_pct(
    get: &impl Fn(&str) -> Option<String>,
    name: &'static str,
    default: u8,
) -> Result<u8, ConfigError> {
    let n = get_u64(get, name, default as u64, 1)?;
    if n > 100 {
        return Err(ConfigError::Invalid {
            field: name,
            value: n.to_string(),
            reason: "must be a percentage in 1..=100",
        });
    }
    Ok(n as u8)
}

/// Parse the ops-alert configuration from `get`. `get` should already treat a blank value as
/// absent (return `None`), matching the daemon's other env parsing.
pub fn parse_ops_alert(
    get: &impl Fn(&str) -> Option<String>,
) -> Result<OpsAlertConfig, ConfigError> {
    // Opt-in: default off so a deployment predating ops-alerting still starts. Fail-closed applies
    // once the operator turns it on.
    let enabled = get_bool(get, "PROPOLIS_OPS_ENABLED", false);

    // An alerting target is optional, but its ABSENCE is not silent: with neither ntfy value set,
    // alerts are delivered to the local log sink (`dispatch::LogPoster`) instead, and the daemon
    // says so at startup. Requiring ntfy outright was worse in practice - it made "no external
    // service" mean "no alerting at all", which is how a feed-publish failure repeated silently for
    // hours on a node whose conditions would all have fired.
    //
    // Still fail-closed on a HALF-configured target: a URL without a topic (or vice versa) is an
    // operator mistake, not a choice of the local sink, and silently downgrading it would page
    // nothing while looking configured.
    let ntfy_url = get("PROPOLIS_OPS_NTFY_URL").unwrap_or_default();
    let ntfy_topic = get("PROPOLIS_OPS_NTFY_TOPIC").unwrap_or_default();
    if enabled {
        match (ntfy_url.is_empty(), ntfy_topic.is_empty()) {
            (true, false) => return Err(ConfigError::Missing("PROPOLIS_OPS_NTFY_URL")),
            (false, true) => return Err(ConfigError::Missing("PROPOLIS_OPS_NTFY_TOPIC")),
            _ => {}
        }
    }

    Ok(OpsAlertConfig {
        enabled,
        ntfy_url,
        ntfy_topic,
        ntfy_token: get("PROPOLIS_OPS_NTFY_TOKEN"),
        poll_interval: get_secs(get, "PROPOLIS_OPS_POLL_INTERVAL_SECS", 30, 1)?,
        repage_cooldown: get_secs(get, "PROPOLIS_OPS_REPAGE_COOLDOWN_SECS", 5400, 1)?,
        stall_for: get_secs(get, "PROPOLIS_OPS_STALL_FOR_SECS", 600, 1)?,
        capacity_free_pct: get_pct(get, "PROPOLIS_OPS_CAPACITY_FREE_PCT", 15)?,
        feed_stale_multiple: get_u32(get, "PROPOLIS_OPS_FEED_STALE_MULTIPLE", 2, 1)?,
        feed_push_expected: get_bool(get, "PROPOLIS_OPS_FEED_PUSH_EXPECTED", false),
        vendor_window: get_secs(get, "PROPOLIS_OPS_VENDOR_WINDOW_SECS", 3600, 1)?,
        vendor_fail_pct: get_pct(get, "PROPOLIS_OPS_VENDOR_FAIL_PCT", 50)?,
        vendor_min_samples: get_u32(get, "PROPOLIS_OPS_VENDOR_MIN_SAMPLES", 20, 1)?,
        backlog_max: get_u64(get, "PROPOLIS_OPS_BACKLOG_MAX", 500, 1)?,
        backlog_for: get_secs(get, "PROPOLIS_OPS_BACKLOG_FOR_SECS", 900, 1)?,
        chain_verify_interval: get_secs(get, "PROPOLIS_OPS_CHAIN_VERIFY_INTERVAL_SECS", 21600, 1)?,
        scan_stale: get_secs(get, "PROPOLIS_OPS_SCAN_STALE_SECS", 21600, 1)?,
        fetch_stale: get_secs(get, "PROPOLIS_OPS_FETCH_STALE_SECS", 3600, 1)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn getter(pairs: &[(&str, &str)]) -> impl Fn(&str) -> Option<String> {
        let map: HashMap<String, String> = pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        move |k: &str| map.get(k).cloned()
    }

    #[test]
    fn disabled_does_not_require_ntfy_and_uses_defaults() {
        let cfg = parse_ops_alert(&getter(&[("PROPOLIS_OPS_ENABLED", "false")])).unwrap();
        assert!(!cfg.enabled);
        assert_eq!(cfg.poll_interval, Duration::from_secs(30));
        assert_eq!(cfg.repage_cooldown, Duration::from_secs(5400));
        assert_eq!(cfg.capacity_free_pct, 15);
        assert_eq!(cfg.backlog_max, 500);
        assert_eq!(cfg.vendor_fail_pct, 50);
        assert_eq!(cfg.vendor_min_samples, 20);
    }

    #[test]
    fn enabled_with_a_missing_ntfy_url_fails_closed() {
        let err = parse_ops_alert(&getter(&[
            ("PROPOLIS_OPS_ENABLED", "true"),
            ("PROPOLIS_OPS_NTFY_TOPIC", "propolis-ops"),
        ]))
        .unwrap_err();
        assert_eq!(err, ConfigError::Missing("PROPOLIS_OPS_NTFY_URL"));
    }

    #[test]
    fn enabled_with_no_ntfy_target_at_all_is_valid_and_uses_the_local_sink() {
        // Requiring ntfy outright made "no external service" mean "no alerting at all", which is how
        // a feed-publish failure repeated silently for hours on a node whose conditions would all
        // have fired. Enabling with no target is now valid; both ntfy fields stay empty, and the
        // caller selects the local log sink on that emptiness.
        let cfg = parse_ops_alert(&getter(&[("PROPOLIS_OPS_ENABLED", "true")])).unwrap();
        assert!(cfg.enabled);
        assert!(
            cfg.ntfy_url.is_empty(),
            "an empty ntfy url is what selects the local sink"
        );
        assert!(cfg.ntfy_topic.is_empty());
    }

    #[test]
    fn enabled_with_a_url_but_no_topic_still_fails_closed() {
        // A HALF-configured target is an operator mistake, not a choice of the local sink. Silently
        // downgrading it would page nothing while looking configured.
        let err = parse_ops_alert(&getter(&[
            ("PROPOLIS_OPS_ENABLED", "true"),
            ("PROPOLIS_OPS_NTFY_URL", "https://ntfy.example/"),
        ]))
        .unwrap_err();
        assert_eq!(err, ConfigError::Missing("PROPOLIS_OPS_NTFY_TOPIC"));
    }

    #[test]
    fn the_default_is_opt_in_off_and_needs_no_ntfy() {
        // A deployment that never set any PROPOLIS_OPS_* var still parses (does not fail closed),
        // so upgrading a daemon that predates ops-alerting does not brick its startup.
        let cfg = parse_ops_alert(&getter(&[])).unwrap();
        assert!(!cfg.enabled);
    }

    #[test]
    fn enabled_with_a_full_valid_set_parses_with_documented_defaults() {
        let cfg = parse_ops_alert(&getter(&[
            ("PROPOLIS_OPS_ENABLED", "true"),
            ("PROPOLIS_OPS_NTFY_URL", "https://ntfy.example/"),
            ("PROPOLIS_OPS_NTFY_TOPIC", "propolis-ops"),
        ]))
        .unwrap();
        assert!(cfg.enabled);
        assert_eq!(cfg.ntfy_url, "https://ntfy.example/");
        assert_eq!(cfg.ntfy_topic, "propolis-ops");
        assert_eq!(cfg.ntfy_token, None);
        assert_eq!(cfg.stall_for, Duration::from_secs(600));
        assert_eq!(cfg.chain_verify_interval, Duration::from_secs(21600));
        assert_eq!(cfg.scan_stale, Duration::from_secs(21600));
        assert_eq!(cfg.fetch_stale, Duration::from_secs(3600));
        assert!(!cfg.feed_push_expected, "pushing is opt-in to expect");
    }

    #[test]
    fn a_zero_or_over_100_percentage_is_rejected() {
        let base = [
            ("PROPOLIS_OPS_NTFY_URL", "https://ntfy.example/"),
            ("PROPOLIS_OPS_NTFY_TOPIC", "propolis-ops"),
        ];
        let mut zero = base.to_vec();
        zero.push(("PROPOLIS_OPS_CAPACITY_FREE_PCT", "0"));
        assert!(matches!(
            parse_ops_alert(&getter(&zero)),
            Err(ConfigError::Invalid { .. })
        ));
        let mut over = base.to_vec();
        over.push(("PROPOLIS_OPS_CAPACITY_FREE_PCT", "101"));
        assert!(matches!(
            parse_ops_alert(&getter(&over)),
            Err(ConfigError::Invalid { .. })
        ));
    }

    #[test]
    fn a_non_numeric_duration_is_rejected() {
        let err = parse_ops_alert(&getter(&[
            ("PROPOLIS_OPS_NTFY_URL", "https://ntfy.example/"),
            ("PROPOLIS_OPS_NTFY_TOPIC", "propolis-ops"),
            ("PROPOLIS_OPS_POLL_INTERVAL_SECS", "soon"),
        ]))
        .unwrap_err();
        assert!(matches!(err, ConfigError::Invalid { .. }));
    }
}
