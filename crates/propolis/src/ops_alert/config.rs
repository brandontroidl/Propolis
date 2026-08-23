//! Typed, bounded configuration for operational self-alerting, parsed from environment variables.
//!
//! Parsing takes an injectable getter (`impl Fn(&str) -> Option<String>`) rather than reading the
//! process environment directly, so it is unit-testable in isolation without mutating global env.
//! The daemon's `load_config` calls it with a getter over `std::env::var`.

use std::time::Duration;

use crate::config::ConfigError;

/// Every value is range-checked with a safe default; a zero or blank never disables a guard. When
/// `enabled`, `ntfy_url` and `ntfy_topic` are REQUIRED (fail-closed: a missing target means the
/// monitor cannot page, so it must not start silently). Thresholds are tunable operational values.
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
    pub vendor_window: Duration,
    pub vendor_fail_pct: u8,
    pub vendor_min_samples: u32,
    pub backlog_max: u64,
    pub backlog_for: Duration,
    pub chain_verify_interval: Duration,
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
    let enabled = get_bool(get, "PROPOLIS_OPS_ENABLED", true);

    // Fail-closed: when enabled, an alerting target is mandatory. A monitor that cannot page is
    // worse than a loud config error, because it looks healthy while paging nothing.
    let (ntfy_url, ntfy_topic) = if enabled {
        (
            get("PROPOLIS_OPS_NTFY_URL").ok_or(ConfigError::Missing("PROPOLIS_OPS_NTFY_URL"))?,
            get("PROPOLIS_OPS_NTFY_TOPIC")
                .ok_or(ConfigError::Missing("PROPOLIS_OPS_NTFY_TOPIC"))?,
        )
    } else {
        (
            get("PROPOLIS_OPS_NTFY_URL").unwrap_or_default(),
            get("PROPOLIS_OPS_NTFY_TOPIC").unwrap_or_default(),
        )
    };

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
        vendor_window: get_secs(get, "PROPOLIS_OPS_VENDOR_WINDOW_SECS", 3600, 1)?,
        vendor_fail_pct: get_pct(get, "PROPOLIS_OPS_VENDOR_FAIL_PCT", 50)?,
        vendor_min_samples: get_u32(get, "PROPOLIS_OPS_VENDOR_MIN_SAMPLES", 20, 1)?,
        backlog_max: get_u64(get, "PROPOLIS_OPS_BACKLOG_MAX", 500, 1)?,
        backlog_for: get_secs(get, "PROPOLIS_OPS_BACKLOG_FOR_SECS", 900, 1)?,
        chain_verify_interval: get_secs(get, "PROPOLIS_OPS_CHAIN_VERIFY_INTERVAL_SECS", 21600, 1)?,
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
        let err =
            parse_ops_alert(&getter(&[("PROPOLIS_OPS_NTFY_TOPIC", "propolis-ops")])).unwrap_err();
        assert_eq!(err, ConfigError::Missing("PROPOLIS_OPS_NTFY_URL"));
    }

    #[test]
    fn enabled_with_a_full_valid_set_parses_with_documented_defaults() {
        let cfg = parse_ops_alert(&getter(&[
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
