//! The gatekeeper: an ordered, fail-closed per-vendor check sequence that runs
//! at submission time, after operator approval. See
//! `internal/design/04-review-gatekeeper-reporting.md` ("The gatekeeper").
//!
//! The sequence is fixed - vendor enabled, cooldown, rate limit, score floor,
//! category filter - and short-circuits on the first held check. Every check
//! is fail-closed: a check this function cannot evaluate (a database error on
//! the cooldown/rate-limit queries) holds the submission with
//! [`GateReason::DbError`] rather than propagating an error a caller might
//! mishandle as "not held".

use std::net::IpAddr;

use chrono::{DateTime, Duration, Utc};
use rust_decimal::Decimal;
use sqlx::PgPool;

use core_scoring::IpScore;

/// Per-vendor gate configuration: the fields the check sequence reads.
///
/// This is the gatekeeper-scoped subset of the spec's full per-vendor
/// configuration (`internal/design/04-review-gatekeeper-reporting.md`,
/// "Configuration"): it omits `api_key`/`api_url`, which the vendor adapters
/// (a later task) need to make the actual HTTP call but the gate checks never
/// touch.
///
/// `score_floor: None` means no additional floor beyond the recommendation
/// threshold already enforced upstream (the spec's stated default).
/// `category_filter: None` means the vendor accepts any category.
#[derive(Debug, Clone)]
pub struct VendorConfig {
    pub name: String,
    pub enabled: bool,
    pub cooldown_hours: u32,
    pub rate_limit: u32,
    pub rate_window_hours: u32,
    pub score_floor: Option<Decimal>,
    pub category_filter: Option<Vec<String>>,
}

/// The outcome of a gate check sequence for one (IP, vendor) submission.
#[derive(Debug, Clone, PartialEq)]
pub enum GateResult {
    Pass,
    Held(GateReason),
}

/// Why a submission was held.
///
/// `DbError` carries the underlying error's `Display` text rather than the
/// `sqlx::Error` itself (which implements neither `Clone` nor `PartialEq`), so
/// this enum stays comparable in tests while still being fail-closed and
/// diagnosable.
#[derive(Debug, Clone, PartialEq)]
pub enum GateReason {
    Disabled,
    Cooldown,
    RateLimit,
    ScoreFloor,
    CategoryFilter,
    DbError(String),
}

/// Run the ordered check sequence for `ip` against `config`, using
/// `current_score` as the caller-supplied projection (the caller is expected
/// to have read it via `core_scoring::read_score` so the score/category
/// checks reflect decay-to-now, not a stale snapshot).
pub async fn check(
    pool: &PgPool,
    ip: IpAddr,
    config: &VendorConfig,
    current_score: &IpScore,
) -> GateResult {
    if !config.enabled {
        return GateResult::Held(GateReason::Disabled);
    }

    if let Err(reason) = check_cooldown(pool, ip, config).await {
        return GateResult::Held(reason);
    }

    if let Err(reason) = check_rate_limit(pool, config).await {
        return GateResult::Held(reason);
    }

    if config
        .score_floor
        .is_some_and(|floor| current_score.raw_score < floor)
    {
        return GateResult::Held(GateReason::ScoreFloor);
    }

    if config
        .category_filter
        .as_ref()
        .is_some_and(|accepted| !category_matches(current_score, accepted))
    {
        return GateResult::Held(GateReason::CategoryFilter);
    }

    GateResult::Pass
}

/// Held with [`GateReason::Cooldown`] if this (ip, vendor) pair has a
/// successful submission within `config.cooldown_hours`; held with
/// [`GateReason::DbError`] if the query itself fails.
async fn check_cooldown(
    pool: &PgPool,
    ip: IpAddr,
    config: &VendorConfig,
) -> Result<(), GateReason> {
    let most_recent: Option<DateTime<Utc>> = sqlx::query_scalar(
        "SELECT submitted_at FROM vendor_submission \
         WHERE source_ip = $1::inet AND vendor = $2 AND success = TRUE \
         ORDER BY submitted_at DESC LIMIT 1",
    )
    .bind(ip.to_string())
    .bind(&config.name)
    .fetch_optional(pool)
    .await
    .map_err(|e| GateReason::DbError(e.to_string()))?;

    if most_recent
        .is_some_and(|last| Utc::now() - last < Duration::hours(config.cooldown_hours as i64))
    {
        return Err(GateReason::Cooldown);
    }
    Ok(())
}

/// Held with [`GateReason::RateLimit`] if the total successful submissions to
/// this vendor (across every IP - the limit is vendor-wide, not per-IP)
/// within `config.rate_window_hours` are already at or above
/// `config.rate_limit`; held with [`GateReason::DbError`] if the query itself
/// fails.
async fn check_rate_limit(pool: &PgPool, config: &VendorConfig) -> Result<(), GateReason> {
    let cutoff = Utc::now() - Duration::hours(config.rate_window_hours as i64);
    let count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM vendor_submission \
         WHERE vendor = $1 AND success = TRUE AND submitted_at > $2",
    )
    .bind(&config.name)
    .bind(cutoff)
    .fetch_one(pool)
    .await
    .map_err(|e| GateReason::DbError(e.to_string()))?;

    if count >= config.rate_limit as i64 {
        Err(GateReason::RateLimit)
    } else {
        Ok(())
    }
}

/// True if `current_score.category_breakdown`'s keys include at least one of
/// `accepted`.
///
/// The breakdown is a JSON object keyed by the `Category` enum's serialized
/// form (its bare variant name, e.g. `"Honeypot"` - core-scoring defines no
/// `#[serde(rename_all)]` on `Category`, so `accepted` entries must match that
/// exact casing to match). A non-object breakdown (should never occur; the
/// write path always serializes a `BTreeMap`) is treated as having no
/// categories, which fails closed to `CategoryFilter` rather than panicking.
fn category_matches(current_score: &IpScore, accepted: &[String]) -> bool {
    let Some(obj) = current_score.category_breakdown.as_object() else {
        return false;
    };
    obj.keys().any(|k| accepted.iter().any(|a| a == k))
}
