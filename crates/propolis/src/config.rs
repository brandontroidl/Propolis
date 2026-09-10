//! Unified configuration for the Propolis daemon: one `PropolisConfig` parsed from environment
//! variables at startup. Fails fast on any missing required value or malformed bound rather than
//! silently substituting a default that could disable a guard.

use std::env;
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::time::Duration;

use ipnet::IpNet;

use review::vendor::{FullVendorConfig, abuseipdb, dshield, otx};

// ---- defaults ----

const DEFAULT_DB_MAX_CONNECTIONS: u32 = 10;
const DEFAULT_CURSOR_DIR: &str = "/var/lib/propolis/cursors";
const DEFAULT_POLL_INTERVAL_MS: u64 = 1_000;
const DEFAULT_QUEUE_SCAN_INTERVAL_SECS: u64 = 60;
const DEFAULT_SUBMIT_POLL_INTERVAL_SECS: u64 = 30;
const DEFAULT_FEED_OUTPUT_DIR: &str = "/var/lib/propolis/feed/current";
const DEFAULT_FEED_BUILD_INTERVAL_SECS: u64 = 900;
const DEFAULT_AGGRESSIVE_TTL_HOURS: u64 = 24;
const DEFAULT_STANDARD_TTL_HOURS: u64 = 48;
/// Retention feeds published as `all-{label}.*` alongside the two tiered feeds. The two tiers
/// answer "block this now"; these answer "what has this address done lately", which is the
/// question a firewall operator building a long-horizon list actually asks. Nested by
/// construction, so a consumer picks exactly one file rather than merging several.
const DEFAULT_FEED_WINDOWS: &str = "24h,7d,30d,60d,90d";
const DEFAULT_CONSOLE_BIND: &str = "127.0.0.1:8080";
const DEFAULT_COOLDOWN_HOURS: u32 = 24;
const DEFAULT_RATE_LIMIT: u32 = 100;
const DEFAULT_RATE_WINDOW_HOURS: u32 = 1;
const DEFAULT_FETCH_INTERVAL_SECS: u64 = 10;
const DEFAULT_FETCH_MAX_BYTES: u64 = 10_000_000;
const DEFAULT_FETCH_MAX_PER_HOST_HOUR: u64 = 12;
const DEFAULT_FETCH_MAX_HOPS: u8 = 3;
const DEFAULT_FETCH_MAX_DEPTH: u8 = 2;
const DEFAULT_FETCH_DAILY_CAP: u64 = 200;
const DEFAULT_FETCH_BATCH_SIZE: u64 = 20;
const DEFAULT_FETCH_CONNECT_TIMEOUT_SECS: u64 = 10;
const DEFAULT_FETCH_READ_TIMEOUT_SECS: u64 = 10;
const DEFAULT_FETCH_TOTAL_TIMEOUT_SECS: u64 = 30;

// Upper clamps for the fetcher's numeric config, on top of `parse_positive_u64`'s existing
// zero-rejection - a config typo or an unbounded operator value must not be able to grow an
// in-memory buffer past what the daemon can hold, or stall the fetcher's strictly-sequential
// cycle loop for hours on one slow fetch. Fix round 1, #3.
/// A few hundred MB, per the review: large enough for any real dropper/binary this fetcher is
/// meant to capture, small enough that one attacker-influenced `Content-Length` cannot OOM the
/// daemon.
const MAX_FETCH_MAX_BYTES: u64 = 500_000_000;
/// A few minutes - past this, a single slow/stalling fetch would hold up the strictly-sequential
/// cycle loop (no overlapping `run_cycle` calls) for an unreasonable fraction of an hour.
const MAX_FETCH_TIMEOUT_SECS: u64 = 300;
const MAX_FETCH_MAX_PER_HOST_HOUR: u64 = 1_000;
const MAX_FETCH_DAILY_CAP: u64 = 10_000;
const MAX_FETCH_BATCH_SIZE: u64 = 1_000;
/// A day - past this the operator should just set `PROPOLIS_FETCH_ENABLED=false` instead.
const MAX_FETCH_INTERVAL_SECS: u64 = 86_400;
/// A common real-world wget string rather than anything naming this project, matching
/// `PROPOLIS_SSH_BANNER`'s reasoning: a fetch that identified itself as "propolis" would tip off
/// the botnet operator watching its own payload-staging server's access log.
const DEFAULT_FETCH_USER_AGENT: &str = "Wget/1.21.3";

/// One sensor log entry: a sensor's name (for logging/metrics) and the absolute path to its
/// NDJSON log file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SensorLogConfig {
    pub name: String,
    pub log_path: PathBuf,
}

/// Consolidated configuration for every Propolis subsystem.
#[derive(Debug)]
pub struct PropolisConfig {
    // Database
    pub database_url: String,
    pub db_max_connections: u32,
    // Intake
    pub sensor_logs: Vec<SensorLogConfig>,
    pub cursor_dir: PathBuf,
    pub poll_interval: Duration,
    // Review
    pub review_enabled: bool,
    pub queue_scan_interval: Duration,
    pub submit_poll_interval: Duration,
    pub vendors: Vec<FullVendorConfig>,
    // Feed
    pub feed_enabled: bool,
    pub feed_output_dir: PathBuf,
    /// Directory holding the optional GeoLite2 `.mmdb` databases for the console's offline geo/ASN
    /// enrichment (`PROPOLIS_GEOIP_DIR`). `None` disables it; a missing directory or file degrades
    /// gracefully. Grouped with the feed path as the other operator-supplied data directory.
    pub geoip_dir: Option<PathBuf>,
    /// Opt-in forward-confirmed reverse-DNS on the IP-detail page (`PROPOLIS_CONSOLE_RDNS_ENABLED`).
    /// Default off - it is the one outbound DNS lookup in the console's enrichment.
    pub console_rdns_enabled: bool,
    pub console_trusted_proxy: bool,
    pub console_metrics_token: Option<String>,
    pub feed_build_interval: Duration,
    pub feed_aggressive_ttl: Duration,
    pub feed_standard_ttl: Duration,
    pub feed_allowlist: Vec<IpNet>,
    pub feed_delist: Vec<IpAddr>,
    /// Trusted-org ASNs whose addresses are suppressed from the feed (Phase C), keyed off the
    /// GeoLite2-ASN database in [`Config::geoip_dir`]. Empty by default (opt-in). See
    /// `PROPOLIS_FEED_ASN_ALLOWLIST`.
    pub feed_asn_allowlist: std::collections::HashSet<u32>,
    /// `(label, retention)` pairs driving the `all-{label}.*` feeds. The label is both the
    /// filename suffix and the source the duration is parsed from, so the two cannot drift.
    pub feed_windows: Vec<(String, Duration)>,
    // Console
    pub console_bind: SocketAddr,
    pub console_password: String,
    pub console_session_secret: [u8; 32],
    // VirusTotal
    pub vt_enabled: bool,
    pub vt_api_key: String,
    pub vt_upload_unknown: bool,
    pub vt_scan_interval_secs: u64,
    pub vt_pending_recheck_secs: u64,
    // Malware fetcher
    pub fetch_enabled: bool,
    pub fetch_interval: Duration,
    pub fetch_max_bytes: usize,
    pub fetch_max_per_host_hour: u32,
    pub fetch_max_hops: u8,
    pub fetch_max_depth: u8,
    pub fetch_daily_cap: u32,
    pub fetch_batch_size: usize,
    pub fetch_connect_timeout: Duration,
    pub fetch_read_timeout: Duration,
    pub fetch_total_timeout: Duration,
    pub fetch_user_agent: String,
    /// Extra addresses to union into the fetcher's `own_ips` set beyond what live interface
    /// enumeration finds - e.g. a WAN IP reachable only via DNAT that never appears on any local
    /// interface. See `main.rs`'s fetcher spawn block for the fail-closed check on the combined set.
    pub fetch_own_ips: Vec<IpAddr>,
    // Operational self-alerting, read by the ops-monitor spawned in main.rs.
    pub ops_alert: crate::ops_alert::OpsAlertConfig,
    // Fleet health (the console's `/fleet` pane).
    /// The listener inventory this control plane believes exists (`PROPOLIS_FLEET_LISTENERS`,
    /// written by `deploy/fleet-listeners.sh` from the sensors' own bind variables). Empty when
    /// unconfigured; a value that is present but malformed is a startup error, never a shortened
    /// list.
    pub fleet_listeners: Vec<fleet::Listener>,
    /// Path to the deploy stamp (`PROPOLIS_FLEET_DEPLOY_STAMP`). `None` leaves the fleet pane's
    /// version panel reading "not recorded".
    pub fleet_deploy_stamp: Option<PathBuf>,
    /// Collector id to dialable address (`PROPOLIS_FLEET_COLLECTOR_ENDPOINTS`). A listener whose
    /// collector is absent here is recorded `not_probeable` with the reason named, never guessed
    /// at: a guessed address that happened to answer would put a green row on a socket nobody
    /// asked about.
    pub fleet_endpoints: std::collections::BTreeMap<String, String>,
    /// Whether the control plane runs the reachability sweep (`PROPOLIS_FLEET_PROBE_ENABLED`).
    /// Off by default: turning it on makes this node connect to the collector's listeners, which
    /// produces sensor events that MUST be filtered at intake, and that filter needs addresses
    /// only the operator knows.
    pub fleet_probe_enabled: bool,
    /// Sweep cadence (`PROPOLIS_FLEET_PROBE_INTERVAL`, seconds). Also the unit the console's
    /// staleness rule is measured in: a row older than twice this alarms.
    pub fleet_probe_interval: Duration,
    /// Per-connect deadline (`PROPOLIS_FLEET_PROBE_TIMEOUT`, seconds). Bounded so a blackholed
    /// address cannot hold a sweep open on the OS default connect timeout.
    pub fleet_probe_timeout: Duration,
    /// This node's own egress addresses (`PROPOLIS_FLEET_PROBE_SOURCE_IPS`). Intake drops lines
    /// from these before conversion. Required whenever the probe is enabled - see
    /// [`ConfigError::ProbeEnabledWithoutSources`].
    pub fleet_probe_sources: std::collections::HashSet<IpAddr>,
}

#[derive(Debug, PartialEq)]
pub enum ConfigError {
    Missing(&'static str),
    Invalid {
        field: &'static str,
        value: String,
        reason: &'static str,
    },
    /// `PROPOLIS_FLEET_LISTENERS` was set and does not parse. Carried as its own variant rather
    /// than folded into `Invalid` so the operator sees WHICH entry is wrong and why.
    FleetInventory(fleet::InventoryError),
    /// The reachability probe was enabled without naming this node's own egress addresses.
    ///
    /// This refuses to start rather than probing unfiltered. Every TCP sensor emits
    /// `honeypot_connection` on accept, weighing 40 at confidence 0.900, so an unfiltered sweep
    /// would score the control plane's own address into the review queue and out into the
    /// published blocklist within hours. There is no safe default to fall back to: only the
    /// operator knows which address this node's connects arrive from. Same shape as the fetcher's
    /// refusal to run with an empty `own_ips` set.
    ProbeEnabledWithoutSources,
}

impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConfigError::Missing(field) => write!(f, "{field} must be set"),
            ConfigError::Invalid {
                field,
                value,
                reason,
            } => {
                write!(f, "{field}: {reason}, got {value:?}")
            }
            ConfigError::FleetInventory(e) => write!(f, "PROPOLIS_FLEET_LISTENERS: {e}"),
            ConfigError::ProbeEnabledWithoutSources => write!(
                f,
                "PROPOLIS_FLEET_PROBE_ENABLED is true but PROPOLIS_FLEET_PROBE_SOURCE_IPS is \
                 empty; set it to this node's own egress address(es) so intake can drop the \
                 probe's own connections, or the probe would score this node into the blocklist"
            ),
        }
    }
}

impl std::error::Error for ConfigError {}

fn require_env(name: &'static str) -> Result<String, ConfigError> {
    env::var(name)
        .ok()
        .filter(|s| !s.is_empty())
        .ok_or(ConfigError::Missing(name))
}

fn parse_positive_u64(name: &'static str, default: u64) -> Result<u64, ConfigError> {
    let raw = match env::var(name) {
        Ok(v) if !v.is_empty() => v,
        _ => return Ok(default),
    };
    let value: u64 = raw.parse().map_err(|_| ConfigError::Invalid {
        field: name,
        value: raw.clone(),
        reason: "must be a positive integer",
    })?;
    if value == 0 {
        return Err(ConfigError::Invalid {
            field: name,
            value: raw,
            reason: "must be a positive integer (zero never means unlimited)",
        });
    }
    Ok(value)
}

/// Like `parse_positive_u64`, but also rejects a value above `max`. Every malware-fetcher numeric
/// bound that could otherwise grow an in-memory buffer or a stall window without limit goes
/// through this rather than the plain `parse_positive_u64` this file's other, pre-existing fields
/// use - those are unrelated, accepted behavior, not something this fix touches.
fn parse_bounded_positive_u64(
    name: &'static str,
    default: u64,
    max: u64,
) -> Result<u64, ConfigError> {
    let value = parse_positive_u64(name, default)?;
    if value > max {
        return Err(ConfigError::Invalid {
            field: name,
            value: format!("{value} (maximum allowed is {max})"),
            reason: "exceeds the maximum allowed value for this field",
        });
    }
    Ok(value)
}

/// A duration in seconds with BOTH ends bounded, rejected rather than clamped.
///
/// Rejection is what every other bounded value in this file and in `ops_alert::config` does, and
/// it is the right direction here: a clamp would silently run a sweep on a cadence the operator
/// did not ask for, and the console measures probe staleness in multiples of that same number, so
/// a value quietly replaced would make every row read stale for reasons nothing on the page
/// explains.
fn parse_bounded_secs(
    name: &'static str,
    default: u64,
    min: u64,
    max: u64,
) -> Result<Duration, ConfigError> {
    let raw = match env::var(name) {
        Ok(v) if !v.trim().is_empty() => v,
        _ => return Ok(Duration::from_secs(default)),
    };
    let value: u64 = raw.trim().parse().map_err(|_| ConfigError::Invalid {
        field: name,
        value: raw.clone(),
        reason: "must be a whole number of seconds",
    })?;
    if value < min || value > max {
        return Err(ConfigError::Invalid {
            field: name,
            value: format!("{value} (permitted range is {min}-{max} seconds)"),
            reason: "outside the permitted range for this field",
        });
    }
    Ok(Duration::from_secs(value))
}

fn parse_u32(name: &str, default: u32) -> Result<u32, ConfigError> {
    let raw = match env::var(name) {
        Ok(v) if !v.is_empty() => v,
        _ => return Ok(default),
    };
    raw.parse().map_err(|_| ConfigError::Invalid {
        field: "vendor bound",
        value: raw,
        reason: "must be a non-negative integer",
    })
}

fn parse_bool_flag(name: &str, default: bool) -> bool {
    match env::var(name).ok().as_deref() {
        None => default,
        Some(s) if s.eq_ignore_ascii_case("true") => true,
        Some(s) if s.eq_ignore_ascii_case("false") => false,
        Some(_) => default,
    }
}

fn parse_sensor_logs(raw: &str) -> Result<Vec<SensorLogConfig>, ConfigError> {
    let logs: Vec<SensorLogConfig> = raw
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|entry| {
            let mut parts = entry.splitn(2, ':');
            let name = parts.next().unwrap_or_default();
            let path = parts.next().unwrap_or_default();
            if name.is_empty() || path.is_empty() {
                return Err(ConfigError::Invalid {
                    field: "PROPOLIS_SENSOR_LOGS",
                    value: entry.to_string(),
                    reason: "expected name:path",
                });
            }
            Ok(SensorLogConfig {
                name: name.to_string(),
                log_path: PathBuf::from(path),
            })
        })
        .collect::<Result<_, _>>()?;
    if logs.is_empty() {
        return Err(ConfigError::Missing("PROPOLIS_SENSOR_LOGS"));
    }
    Ok(logs)
}

fn parse_cidr_list(raw: &str) -> Result<Vec<IpNet>, ConfigError> {
    raw.split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|s| {
            s.parse::<IpNet>().map_err(|_| ConfigError::Invalid {
                field: "PROPOLIS_FEED_ALLOWLIST",
                value: s.to_string(),
                reason: "not a valid CIDR",
            })
        })
        .collect()
}

/// Parse `PROPOLIS_FEED_ASN_ALLOWLIST` - a comma-separated list of AS numbers (bare, or with a
/// leading `AS`) whose addresses are suppressed from the feed. Empty by default (opt-in).
fn parse_asn_list(raw: &str) -> Result<std::collections::HashSet<u32>, ConfigError> {
    raw.split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|s| {
            let digits = s
                .strip_prefix("AS")
                .or_else(|| s.strip_prefix("as"))
                .unwrap_or(s);
            digits.parse::<u32>().map_err(|_| ConfigError::Invalid {
                field: "PROPOLIS_FEED_ASN_ALLOWLIST",
                value: s.to_string(),
                reason: "not a valid AS number",
            })
        })
        .collect()
}

/// Parse `PROPOLIS_FEED_WINDOWS` - a comma-separated list of `<count><unit>` labels such as
/// `24h,7d,30d` - into `(label, retention)` pairs.
///
/// The label IS the duration's source rather than a separate field, so a filename can never
/// advertise a window the builder does not actually apply. Only `h` and `d` are accepted and the
/// count must be a positive integer, which also makes every label filename-safe by construction:
/// no separate path sanitisation is needed before it reaches `all-{label}.txt`.
///
/// Fails closed on any malformed entry rather than skipping it - a typo that silently dropped a
/// window would publish a short list under a long window's name.
fn parse_window_list(raw: &str) -> Result<Vec<(String, Duration)>, ConfigError> {
    raw.split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|s| {
            let invalid = || ConfigError::Invalid {
                field: "PROPOLIS_FEED_WINDOWS",
                value: s.to_string(),
                reason: "expected a positive count followed by 'h' or 'd', e.g. 24h or 30d",
            };
            let (count, unit_secs) = match s.as_bytes().last() {
                Some(b'h') => (&s[..s.len() - 1], 3_600),
                Some(b'd') => (&s[..s.len() - 1], 86_400),
                _ => return Err(invalid()),
            };
            let count: u64 = count.parse().map_err(|_| invalid())?;
            if count == 0 {
                return Err(invalid());
            }
            Ok((s.to_string(), Duration::from_secs(count * unit_secs)))
        })
        .collect()
}

fn parse_ip_list(field: &'static str, raw: &str) -> Result<Vec<IpAddr>, ConfigError> {
    raw.split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|s| {
            s.parse::<IpAddr>().map_err(|_| ConfigError::Invalid {
                field,
                value: s.to_string(),
                reason: "not a valid IP address",
            })
        })
        .collect()
}

/// A small operator-tunable bound that must fit in a `u8` (the fetcher's redirect-hop and
/// recursion-depth caps): zero is a legitimate, maximally-strict value here (no redirects / no
/// recursion at all), so unlike `parse_positive_u64` this does not reject it - only a value that
/// would silently wrap past 255 is rejected, so a config typo ("300") fails startup instead of
/// truncating to a smaller-looking but wrong bound.
fn parse_bounded_u8(name: &'static str, default: u8) -> Result<u8, ConfigError> {
    let raw = match env::var(name) {
        Ok(v) if !v.is_empty() => v,
        _ => return Ok(default),
    };
    let value: u64 = raw.parse().map_err(|_| ConfigError::Invalid {
        field: name,
        value: raw.clone(),
        reason: "must be a non-negative integer",
    })?;
    if value > u8::MAX as u64 {
        return Err(ConfigError::Invalid {
            field: name,
            value: raw,
            reason: "must fit in a u8 (0-255)",
        });
    }
    Ok(value as u8)
}

fn load_session_secret() -> Result<[u8; 32], ConfigError> {
    let raw = match env::var("PROPOLIS_CONSOLE_SESSION_SECRET") {
        Ok(v) if !v.is_empty() => v,
        _ => {
            use rand::RngExt;
            return Ok(rand::rng().random::<[u8; 32]>());
        }
    };
    let bytes = hex::decode(&raw).map_err(|_| ConfigError::Invalid {
        field: "PROPOLIS_CONSOLE_SESSION_SECRET",
        value: raw.clone(),
        reason: "must be exactly 64 hex characters (32 bytes)",
    })?;
    bytes.try_into().map_err(|_| ConfigError::Invalid {
        field: "PROPOLIS_CONSOLE_SESSION_SECRET",
        value: raw,
        reason: "must be exactly 64 hex characters (32 bytes)",
    })
}

fn load_vendor_config(
    name: &str,
    api_key: String,
    api_url: String,
) -> Result<FullVendorConfig, ConfigError> {
    let prefix = format!("PROPOLIS_VENDOR_{}", name.to_uppercase());
    let enabled_field = format!("{prefix}_ENABLED");
    let mut enabled = parse_bool_flag(&enabled_field, false);
    if enabled && api_key.is_empty() {
        tracing::warn!(
            vendor = name,
            "enabled but no API key configured; treating as disabled (fail-closed)"
        );
        enabled = false;
    }

    let cooldown_field = format!("{prefix}_COOLDOWN_HOURS");
    let cooldown_hours = parse_u32(&cooldown_field, DEFAULT_COOLDOWN_HOURS)?;
    let rate_limit_field = format!("{prefix}_RATE_LIMIT");
    let rate_limit = parse_u32(&rate_limit_field, DEFAULT_RATE_LIMIT)?;
    let rate_window_field = format!("{prefix}_RATE_WINDOW_HOURS");
    let rate_window_hours = parse_u32(&rate_window_field, DEFAULT_RATE_WINDOW_HOURS)?;

    Ok(FullVendorConfig {
        name: name.to_string(),
        enabled,
        api_key,
        api_url,
        cooldown_hours,
        rate_limit,
        rate_window_hours,
        score_floor: None,
        category_filter: None,
    })
}

/// Loads and validates the unified configuration from environment variables. Fails fast on any
/// missing required value or malformed bound.
pub fn load_config() -> Result<PropolisConfig, ConfigError> {
    let database_url = require_env("DATABASE_URL")?;

    let db_max_connections = parse_positive_u64(
        "PROPOLIS_DB_MAX_CONNECTIONS",
        DEFAULT_DB_MAX_CONNECTIONS as u64,
    )? as u32;

    let sensor_logs = parse_sensor_logs(&env::var("PROPOLIS_SENSOR_LOGS").unwrap_or_default())?;
    let cursor_dir = env::var("PROPOLIS_CURSOR_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from(DEFAULT_CURSOR_DIR));
    let poll_interval_ms =
        parse_positive_u64("PROPOLIS_POLL_INTERVAL_MS", DEFAULT_POLL_INTERVAL_MS)?;

    let review_enabled = parse_bool_flag("PROPOLIS_REVIEW_ENABLED", true);
    let queue_scan_interval_secs = parse_positive_u64(
        "PROPOLIS_QUEUE_SCAN_INTERVAL_SECS",
        DEFAULT_QUEUE_SCAN_INTERVAL_SECS,
    )?;
    let submit_poll_interval_secs = parse_positive_u64(
        "PROPOLIS_SUBMIT_POLL_INTERVAL_SECS",
        DEFAULT_SUBMIT_POLL_INTERVAL_SECS,
    )?;

    let abuseipdb_key = env::var("PROPOLIS_VENDOR_ABUSEIPDB_KEY").unwrap_or_default();
    let abuseipdb_url = env::var("PROPOLIS_VENDOR_ABUSEIPDB_URL")
        .unwrap_or_else(|_| abuseipdb::DEFAULT_BASE_URL.to_string());
    let abuseipdb = load_vendor_config("abuseipdb", abuseipdb_key, abuseipdb_url)?;

    let dshield_key = env::var("PROPOLIS_VENDOR_DSHIELD_KEY").unwrap_or_default();
    let dshield_user = env::var("PROPOLIS_VENDOR_DSHIELD_USER")
        .ok()
        .filter(|s| !s.is_empty());
    let dshield_key = match dshield_user {
        Some(user) if !dshield_key.is_empty() => format!("{user}:{dshield_key}"),
        _ => dshield_key,
    };
    let dshield_url = env::var("PROPOLIS_VENDOR_DSHIELD_URL")
        .unwrap_or_else(|_| dshield::DEFAULT_BASE_URL.to_string());
    let dshield = load_vendor_config("dshield", dshield_key, dshield_url)?;

    let otx_key = env::var("PROPOLIS_VENDOR_OTX_KEY").unwrap_or_default();
    let otx_url =
        env::var("PROPOLIS_VENDOR_OTX_URL").unwrap_or_else(|_| otx::DEFAULT_BASE_URL.to_string());
    let otx = load_vendor_config("otx", otx_key, otx_url)?;

    let feed_enabled = parse_bool_flag("PROPOLIS_FEED_ENABLED", true);
    let feed_output_dir = env::var("PROPOLIS_FEED_OUTPUT_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from(DEFAULT_FEED_OUTPUT_DIR));
    let geoip_dir = env::var("PROPOLIS_GEOIP_DIR")
        .ok()
        .filter(|s| !s.is_empty())
        .map(PathBuf::from);
    let console_rdns_enabled = parse_bool_flag("PROPOLIS_CONSOLE_RDNS_ENABLED", false);
    let console_trusted_proxy = parse_bool_flag("PROPOLIS_CONSOLE_TRUSTED_PROXY", false);
    let console_metrics_token = env::var("PROPOLIS_CONSOLE_METRICS_TOKEN")
        .ok()
        .filter(|s| !s.is_empty());
    let feed_build_interval_secs = parse_positive_u64(
        "PROPOLIS_FEED_BUILD_INTERVAL_SECS",
        DEFAULT_FEED_BUILD_INTERVAL_SECS,
    )?;
    let feed_aggressive_ttl_hours = parse_positive_u64(
        "PROPOLIS_FEED_AGGRESSIVE_TTL_HOURS",
        DEFAULT_AGGRESSIVE_TTL_HOURS,
    )?;
    let feed_standard_ttl_hours = parse_positive_u64(
        "PROPOLIS_FEED_STANDARD_TTL_HOURS",
        DEFAULT_STANDARD_TTL_HOURS,
    )?;
    let feed_allowlist = parse_cidr_list(&env::var("PROPOLIS_FEED_ALLOWLIST").unwrap_or_default())?;
    let feed_asn_allowlist =
        parse_asn_list(&env::var("PROPOLIS_FEED_ASN_ALLOWLIST").unwrap_or_default())?;
    let feed_delist = parse_ip_list(
        "PROPOLIS_FEED_DELIST",
        &env::var("PROPOLIS_FEED_DELIST").unwrap_or_default(),
    )?;
    let feed_windows = parse_window_list(
        &env::var("PROPOLIS_FEED_WINDOWS").unwrap_or_else(|_| DEFAULT_FEED_WINDOWS.to_string()),
    )?;

    let bind_raw =
        env::var("PROPOLIS_CONSOLE_BIND").unwrap_or_else(|_| DEFAULT_CONSOLE_BIND.to_string());
    let console_bind = bind_raw
        .parse::<SocketAddr>()
        .map_err(|_| ConfigError::Invalid {
            field: "PROPOLIS_CONSOLE_BIND",
            value: bind_raw,
            reason: "not a valid ip:port address",
        })?;
    let console_password = require_env("PROPOLIS_CONSOLE_PASSWORD")?;
    let console_session_secret = load_session_secret()?;

    let vt_api_key = env::var("PROPOLIS_VT_KEY").unwrap_or_default();
    let vt_enabled = parse_bool_flag("PROPOLIS_VT_ENABLED", false) && !vt_api_key.is_empty();
    let vt_upload_unknown = parse_bool_flag("PROPOLIS_VT_UPLOAD", false);
    let vt_scan_interval_secs = parse_u32("PROPOLIS_VT_SCAN_INTERVAL_SECS", 300)? as u64;
    // Zero means "ask again every cycle", which is allowed but spends a budget unit per cycle
    // per pending sample.
    let vt_pending_recheck_secs = parse_u32("PROPOLIS_VT_PENDING_RECHECK_SECS", 900)? as u64;

    // Malware fetcher: opt-in egress, off by default like VT upload - see
    // internal/design/12-malware-fetcher.md section 13.
    let fetch_enabled = parse_bool_flag("PROPOLIS_FETCH_ENABLED", false);
    let fetch_interval_secs = parse_bounded_positive_u64(
        "PROPOLIS_FETCH_INTERVAL_SECS",
        DEFAULT_FETCH_INTERVAL_SECS,
        MAX_FETCH_INTERVAL_SECS,
    )?;
    let fetch_max_bytes = parse_bounded_positive_u64(
        "PROPOLIS_FETCH_MAX_BYTES",
        DEFAULT_FETCH_MAX_BYTES,
        MAX_FETCH_MAX_BYTES,
    )? as usize;
    let fetch_max_per_host_hour = parse_bounded_positive_u64(
        "PROPOLIS_FETCH_MAX_PER_HOST_HOUR",
        DEFAULT_FETCH_MAX_PER_HOST_HOUR,
        MAX_FETCH_MAX_PER_HOST_HOUR,
    )? as u32;
    let fetch_max_hops = parse_bounded_u8("PROPOLIS_FETCH_MAX_HOPS", DEFAULT_FETCH_MAX_HOPS)?;
    let fetch_max_depth = parse_bounded_u8("PROPOLIS_FETCH_MAX_DEPTH", DEFAULT_FETCH_MAX_DEPTH)?;
    let fetch_daily_cap = parse_bounded_positive_u64(
        "PROPOLIS_FETCH_DAILY_CAP",
        DEFAULT_FETCH_DAILY_CAP,
        MAX_FETCH_DAILY_CAP,
    )? as u32;
    let fetch_batch_size = parse_bounded_positive_u64(
        "PROPOLIS_FETCH_BATCH_SIZE",
        DEFAULT_FETCH_BATCH_SIZE,
        MAX_FETCH_BATCH_SIZE,
    )? as usize;
    let fetch_connect_timeout_secs = parse_bounded_positive_u64(
        "PROPOLIS_FETCH_CONNECT_TIMEOUT_SECS",
        DEFAULT_FETCH_CONNECT_TIMEOUT_SECS,
        MAX_FETCH_TIMEOUT_SECS,
    )?;
    let fetch_read_timeout_secs = parse_bounded_positive_u64(
        "PROPOLIS_FETCH_READ_TIMEOUT_SECS",
        DEFAULT_FETCH_READ_TIMEOUT_SECS,
        MAX_FETCH_TIMEOUT_SECS,
    )?;
    let fetch_total_timeout_secs = parse_bounded_positive_u64(
        "PROPOLIS_FETCH_TOTAL_TIMEOUT_SECS",
        DEFAULT_FETCH_TOTAL_TIMEOUT_SECS,
        MAX_FETCH_TIMEOUT_SECS,
    )?;
    let fetch_user_agent = env::var("PROPOLIS_FETCH_USER_AGENT")
        .ok()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| DEFAULT_FETCH_USER_AGENT.to_string());
    let fetch_own_ips = parse_ip_list(
        "PROPOLIS_FETCH_OWN_IPS",
        &env::var("PROPOLIS_FETCH_OWN_IPS").unwrap_or_default(),
    )?;

    let fleet_listeners =
        fleet::parse_listeners_env(env::var("PROPOLIS_FLEET_LISTENERS").ok().as_deref())
            .map_err(ConfigError::FleetInventory)?;
    let fleet_deploy_stamp = env::var("PROPOLIS_FLEET_DEPLOY_STAMP")
        .ok()
        .filter(|s| !s.is_empty())
        .map(PathBuf::from);
    let fleet_endpoints = fleet::parse_endpoints_env(
        env::var("PROPOLIS_FLEET_COLLECTOR_ENDPOINTS")
            .ok()
            .as_deref(),
    )
    .map_err(ConfigError::FleetInventory)?;
    let fleet_probe_enabled = parse_bool_flag("PROPOLIS_FLEET_PROBE_ENABLED", false);
    // 60s floor: the sweep opens a connection to every listener, and every one of those becomes a
    // sensor event that intake has to read and drop. 86400 ceiling so a typo cannot park the sweep
    // beyond any useful staleness window.
    let fleet_probe_interval =
        parse_bounded_secs("PROPOLIS_FLEET_PROBE_INTERVAL", 300, 60, 86_400)?;
    let fleet_probe_timeout = parse_bounded_secs("PROPOLIS_FLEET_PROBE_TIMEOUT", 5, 1, 60)?;
    let fleet_probe_sources: std::collections::HashSet<IpAddr> = parse_ip_list(
        "PROPOLIS_FLEET_PROBE_SOURCE_IPS",
        &env::var("PROPOLIS_FLEET_PROBE_SOURCE_IPS").unwrap_or_default(),
    )?
    .into_iter()
    .collect();
    // Fail closed at startup, not at first sweep: an enabled probe whose lines intake cannot
    // recognise writes the control plane's own address into the ledger, and from there into the
    // review queue and the published feed. Nothing downstream can undo that, so it must not start.
    if fleet_probe_enabled && fleet_probe_sources.is_empty() {
        return Err(ConfigError::ProbeEnabledWithoutSources);
    }

    Ok(PropolisConfig {
        database_url,
        db_max_connections,
        sensor_logs,
        cursor_dir,
        poll_interval: Duration::from_millis(poll_interval_ms),
        review_enabled,
        queue_scan_interval: Duration::from_secs(queue_scan_interval_secs),
        submit_poll_interval: Duration::from_secs(submit_poll_interval_secs),
        vendors: vec![abuseipdb, dshield, otx],
        feed_enabled,
        feed_output_dir,
        geoip_dir,
        console_rdns_enabled,
        console_trusted_proxy,
        console_metrics_token,
        feed_build_interval: Duration::from_secs(feed_build_interval_secs),
        feed_aggressive_ttl: Duration::from_secs(feed_aggressive_ttl_hours * 3600),
        feed_standard_ttl: Duration::from_secs(feed_standard_ttl_hours * 3600),
        feed_allowlist,
        feed_delist,
        feed_asn_allowlist,
        feed_windows,
        console_bind,
        console_password,
        console_session_secret,
        vt_enabled,
        vt_api_key,
        vt_upload_unknown,
        vt_scan_interval_secs,
        vt_pending_recheck_secs,
        fetch_enabled,
        fetch_interval: Duration::from_secs(fetch_interval_secs),
        fetch_max_bytes,
        fetch_max_per_host_hour,
        fetch_max_hops,
        fetch_max_depth,
        fetch_daily_cap,
        fetch_batch_size,
        fetch_connect_timeout: Duration::from_secs(fetch_connect_timeout_secs),
        fetch_read_timeout: Duration::from_secs(fetch_read_timeout_secs),
        fetch_total_timeout: Duration::from_secs(fetch_total_timeout_secs),
        fetch_user_agent,
        fetch_own_ips,
        ops_alert: crate::ops_alert::config::parse_ops_alert(&|k| {
            std::env::var(k).ok().filter(|s| !s.is_empty())
        })?,
        fleet_listeners,
        fleet_deploy_stamp,
        fleet_endpoints,
        fleet_probe_enabled,
        fleet_probe_interval,
        fleet_probe_timeout,
        fleet_probe_sources,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_sensor_logs_accepts_comma_separated_pairs() {
        let logs = parse_sensor_logs(
            "catchall:/var/log/propolis/catchall/events.jsonl,ssh:/var/log/propolis/ssh/events.jsonl",
        )
        .unwrap();
        assert_eq!(logs.len(), 2);
        assert_eq!(logs[0].name, "catchall");
        assert_eq!(logs[1].name, "ssh");
    }

    #[test]
    fn parse_sensor_logs_rejects_empty() {
        assert!(parse_sensor_logs("").is_err());
        assert!(parse_sensor_logs("   ").is_err());
    }

    #[test]
    fn parse_sensor_logs_rejects_entry_without_colon() {
        assert!(parse_sensor_logs("not-a-pair").is_err());
    }

    #[test]
    fn parse_window_list_reads_hours_and_days() {
        let windows = parse_window_list("24h, 7d,90d").unwrap();
        assert_eq!(
            windows,
            vec![
                ("24h".to_string(), Duration::from_secs(86_400)),
                ("7d".to_string(), Duration::from_secs(604_800)),
                ("90d".to_string(), Duration::from_secs(7_776_000)),
            ]
        );
    }

    #[test]
    fn parse_window_list_accepts_the_shipped_default() {
        let windows = parse_window_list(DEFAULT_FEED_WINDOWS).unwrap();
        assert_eq!(windows.len(), 5);
        // Nested by construction: each window must strictly contain the one before it, or a
        // consumer picking a single file would not get a superset of the shorter ones.
        assert!(windows.windows(2).all(|p| p[0].1 < p[1].1));
    }

    #[test]
    fn parse_window_list_fails_closed_on_bad_entries() {
        // A silently-skipped entry would publish a short list under a long window's filename.
        for raw in ["30", "30w", "0d", "-1d", "d", "thirty-d", "30 d"] {
            assert!(
                parse_window_list(raw).is_err(),
                "{raw} must be rejected, not skipped"
            );
        }
    }

    #[test]
    fn parse_window_list_empty_disables_retention_feeds() {
        assert!(parse_window_list("").unwrap().is_empty());
    }

    /// Serialises every test that drives the real `load_config`.
    ///
    /// The process environment is global, and these tests share the three variables `load_config`
    /// requires (`DATABASE_URL`, `PROPOLIS_SENSOR_LOGS`, `PROPOLIS_CONSOLE_PASSWORD`). Without
    /// this they would race under `cargo test`'s default thread-per-test parallelism: one test's
    /// cleanup removes a variable the other is mid-way through relying on, and the failure looks
    /// like a config bug rather than the test collision it is.
    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    /// The three variables `load_config` refuses to start without. Set by every test below before
    /// it exercises the field it actually cares about.
    fn set_required_env() {
        // SAFETY: every caller holds ENV_LOCK for the duration of its own set/read/remove cycle.
        unsafe {
            env::set_var("DATABASE_URL", "postgres://u:p@localhost/db");
            env::set_var("PROPOLIS_SENSOR_LOGS", "catchall:/tmp/x.jsonl");
            env::set_var("PROPOLIS_CONSOLE_PASSWORD", "test-password");
        }
    }

    fn clear_required_env() {
        // SAFETY: as above.
        unsafe {
            env::remove_var("DATABASE_URL");
            env::remove_var("PROPOLIS_SENSOR_LOGS");
            env::remove_var("PROPOLIS_CONSOLE_PASSWORD");
        }
    }

    // A zero byte cap must never be treated as "unlimited" - it must fail startup outright.
    // Exercised through the real `load_config` path (not just the underlying parse helper) so this
    // also proves `PropolisConfig` actually wires the new field.
    #[test]
    fn load_config_rejects_a_zero_fetch_max_bytes_but_accepts_a_valid_set() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        // SAFETY: ENV_LOCK is held for this test's whole set/read/remove cycle, so no other test
        // in this file can observe or clear these variables mid-run.
        unsafe {
            env::set_var("DATABASE_URL", "postgres://u:p@localhost/db");
            env::set_var("PROPOLIS_SENSOR_LOGS", "catchall:/tmp/x.jsonl");
            env::set_var("PROPOLIS_CONSOLE_PASSWORD", "test-password");
            env::set_var("PROPOLIS_FETCH_ENABLED", "true");
            env::set_var("PROPOLIS_FETCH_MAX_BYTES", "0");
        }
        assert!(
            load_config().is_err(),
            "PROPOLIS_FETCH_MAX_BYTES=0 must be rejected at parse time - a zero byte cap would \
             disable the byte guard"
        );

        // Fix round 1, #3 (minor): the upper end must be bounded too - an unbounded in-memory
        // streaming buffer could OOM the daemon on a single oversized (attacker-influenced) fetch.
        unsafe { env::set_var("PROPOLIS_FETCH_MAX_BYTES", "999999999999") };
        assert!(
            load_config().is_err(),
            "an absurdly large PROPOLIS_FETCH_MAX_BYTES must be rejected - it bounds an in-memory \
             streaming buffer, not just a lower floor"
        );

        unsafe {
            env::set_var("PROPOLIS_FETCH_MAX_BYTES", "5000000");
            env::set_var("PROPOLIS_FETCH_MAX_PER_HOST_HOUR", "12");
            env::set_var("PROPOLIS_FETCH_MAX_HOPS", "3");
            env::set_var("PROPOLIS_FETCH_MAX_DEPTH", "2");
            env::set_var("PROPOLIS_FETCH_DAILY_CAP", "200");
            env::set_var("PROPOLIS_FETCH_OWN_IPS", "203.0.113.9");
        }
        let config = load_config().expect("a fully valid fetch config must parse");
        assert!(config.fetch_enabled);
        assert_eq!(config.fetch_max_bytes, 5_000_000);
        assert_eq!(config.fetch_max_per_host_hour, 12);
        assert_eq!(config.fetch_max_hops, 3);
        assert_eq!(config.fetch_max_depth, 2);
        assert_eq!(config.fetch_daily_cap, 200);
        assert_eq!(
            config.fetch_own_ips,
            vec!["203.0.113.9".parse::<IpAddr>().unwrap()]
        );

        unsafe {
            env::remove_var("DATABASE_URL");
            env::remove_var("PROPOLIS_SENSOR_LOGS");
            env::remove_var("PROPOLIS_CONSOLE_PASSWORD");
            env::remove_var("PROPOLIS_FETCH_ENABLED");
            env::remove_var("PROPOLIS_FETCH_MAX_BYTES");
            env::remove_var("PROPOLIS_FETCH_MAX_PER_HOST_HOUR");
            env::remove_var("PROPOLIS_FETCH_MAX_HOPS");
            env::remove_var("PROPOLIS_FETCH_MAX_DEPTH");
            env::remove_var("PROPOLIS_FETCH_DAILY_CAP");
            env::remove_var("PROPOLIS_FETCH_OWN_IPS");
        }
    }

    #[test]
    fn parse_bounded_u8_allows_zero_but_rejects_overflow() {
        unsafe { env::set_var("TEST_PROPOLIS_BOUNDED_U8", "0") };
        assert_eq!(
            parse_bounded_u8("TEST_PROPOLIS_BOUNDED_U8", 9).unwrap(),
            0,
            "zero is a legitimate strict value (no hops / no recursion), not a guard bypass"
        );
        unsafe { env::set_var("TEST_PROPOLIS_BOUNDED_U8", "300") };
        assert!(
            parse_bounded_u8("TEST_PROPOLIS_BOUNDED_U8", 9).is_err(),
            "a value that would silently wrap past 255 must be rejected, not truncated"
        );
        unsafe { env::remove_var("TEST_PROPOLIS_BOUNDED_U8") };
    }

    /// The contamination guard, driven through the real startup path.
    ///
    /// An enabled probe with no source addresses would connect to every listener every sweep,
    /// each connect becoming a `honeypot_connection` that intake cannot recognise as its own. That
    /// scores the control plane's address into the review queue and out into the published
    /// blocklist, which nothing downstream can undo. There is no safe default, so startup refuses.
    #[test]
    fn probe_enabled_without_source_ips_refuses_to_start() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        set_required_env();
        // SAFETY: ENV_LOCK held for this test's whole cycle.
        unsafe {
            env::set_var("PROPOLIS_FLEET_PROBE_ENABLED", "true");
            env::remove_var("PROPOLIS_FLEET_PROBE_SOURCE_IPS");
        }
        assert_eq!(
            load_config().unwrap_err(),
            ConfigError::ProbeEnabledWithoutSources,
            "an enabled probe with no source addresses must refuse to start"
        );

        // Blank is the same as unset: an operator who left the variable in place with nothing in
        // it has named no addresses, and the guard must not read the empty string as a set of one.
        unsafe { env::set_var("PROPOLIS_FLEET_PROBE_SOURCE_IPS", "  ") };
        assert_eq!(
            load_config().unwrap_err(),
            ConfigError::ProbeEnabledWithoutSources
        );

        // The positive half: a known-good value must still pass. A guard verified only on its deny
        // branch is half verified, and one that refused every configuration would be its own bug.
        unsafe {
            env::set_var(
                "PROPOLIS_FLEET_PROBE_SOURCE_IPS",
                "198.51.100.7, 203.0.113.4",
            )
        };
        let config = load_config().expect("a probe with named source addresses must start");
        assert!(config.fleet_probe_enabled);
        assert_eq!(config.fleet_probe_sources.len(), 2);
        assert!(
            config
                .fleet_probe_sources
                .contains(&"198.51.100.7".parse::<IpAddr>().unwrap())
        );

        // And with the probe OFF, no source addresses are needed at all.
        unsafe {
            env::set_var("PROPOLIS_FLEET_PROBE_ENABLED", "false");
            env::remove_var("PROPOLIS_FLEET_PROBE_SOURCE_IPS");
        }
        let config = load_config().expect("a disabled probe needs no source addresses");
        assert!(!config.fleet_probe_enabled);

        unsafe {
            env::remove_var("PROPOLIS_FLEET_PROBE_ENABLED");
        }
        clear_required_env();
    }

    #[test]
    fn fleet_listener_parse_failure_is_a_startup_error_not_a_shortened_list() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        set_required_env();
        // SAFETY: ENV_LOCK held for this test's whole cycle.
        unsafe {
            env::set_var(
                "PROPOLIS_FLEET_LISTENERS",
                "local/ssh/tcp/22,local/telnet/tcp",
            );
        }
        assert!(
            matches!(load_config(), Err(ConfigError::FleetInventory(_))),
            "one malformed entry must reject the whole value; silently keeping the good half \
             would hide a listener rather than report it"
        );

        unsafe {
            env::set_var(
                "PROPOLIS_FLEET_LISTENERS",
                "local/ssh/tcp/22,local/catchall/udp/1024",
            );
            env::set_var("PROPOLIS_FLEET_COLLECTOR_ENDPOINTS", "local=198.51.100.7");
        }
        let config = load_config().expect("a well-formed inventory must parse");
        assert_eq!(config.fleet_listeners.len(), 2);
        assert_eq!(
            config.fleet_listeners[0].target(&config.fleet_endpoints),
            Some("198.51.100.7:22".to_string())
        );

        unsafe {
            env::remove_var("PROPOLIS_FLEET_LISTENERS");
            env::remove_var("PROPOLIS_FLEET_COLLECTOR_ENDPOINTS");
        }
        clear_required_env();
    }

    /// Both ends of both bounds, rejected rather than clamped: the console measures probe staleness
    /// in multiples of the interval, so a value silently replaced with something else would make
    /// rows read stale for a reason nothing on the page explains.
    #[test]
    fn probe_interval_and_timeout_are_rejected_outside_their_bounds() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        set_required_env();

        // SAFETY: ENV_LOCK held for this test's whole cycle.
        unsafe { env::remove_var("PROPOLIS_FLEET_PROBE_INTERVAL") };
        unsafe { env::remove_var("PROPOLIS_FLEET_PROBE_TIMEOUT") };
        let config = load_config().expect("the defaults must parse");
        assert_eq!(config.fleet_probe_interval, Duration::from_secs(300));
        assert_eq!(config.fleet_probe_timeout, Duration::from_secs(5));

        for bad in ["59", "86401", "0", "not-a-number"] {
            unsafe { env::set_var("PROPOLIS_FLEET_PROBE_INTERVAL", bad) };
            assert!(
                load_config().is_err(),
                "PROPOLIS_FLEET_PROBE_INTERVAL={bad} must be rejected, not clamped"
            );
        }
        unsafe { env::set_var("PROPOLIS_FLEET_PROBE_INTERVAL", "60") };
        assert_eq!(
            load_config().unwrap().fleet_probe_interval,
            Duration::from_secs(60),
            "the floor itself must be accepted, or the bound is off by one"
        );

        for bad in ["0", "61"] {
            unsafe { env::set_var("PROPOLIS_FLEET_PROBE_TIMEOUT", bad) };
            assert!(
                load_config().is_err(),
                "PROPOLIS_FLEET_PROBE_TIMEOUT={bad} must be rejected, not clamped"
            );
        }
        unsafe { env::set_var("PROPOLIS_FLEET_PROBE_TIMEOUT", "60") };
        assert_eq!(
            load_config().unwrap().fleet_probe_timeout,
            Duration::from_secs(60)
        );

        unsafe {
            env::remove_var("PROPOLIS_FLEET_PROBE_INTERVAL");
            env::remove_var("PROPOLIS_FLEET_PROBE_TIMEOUT");
        }
        clear_required_env();
    }
}
