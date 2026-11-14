//! The gatekeeper: an ordered, fail-closed per-vendor check sequence that runs
//! at submission time, after operator approval. See
//! `internal/design/04-review-gatekeeper-reporting.md` ("The gatekeeper").
//!
//! The sequence is fixed - reserved address, delisted, vendor enabled, freshness, cooldown,
//! nothing new since the last report, rate limit, score floor, category filter - and
//! short-circuits on the first held check. Every check
//! is fail-closed: a check this function cannot evaluate (a database error on
//! the cooldown/rate-limit queries) holds the submission with
//! [`GateReason::DbError`] rather than propagating an error a caller might
//! mishandle as "not held".

use std::collections::{HashMap, HashSet};
use std::net::IpAddr;

use chrono::{DateTime, Duration, Utc};
use rust_decimal::Decimal;
use sqlx::{PgPool, Row};

use core_scoring::IpScore;

use crate::reserved::is_reserved_ip;

/// Do not report an IP that last EARNED a tier longer ago than this. Abuse feeds want RECENT
/// attacker activity, so re-reporting a days-old attack is both wrong and (for DShield) rejected.
/// 48h covers the daily-cooldown resubmission of a still-active IP while excluding attackers that
/// have gone quiet for days. Vendor-agnostic on purpose - reporting stale activity is wrong for any
/// of them - so it is a constant, not per-vendor config.
///
/// The clock is [`IpScore::tier_earned_at`]: the last time an established (completed-TCP) event
/// left the address eligible and holding a tier. It is not `last_seen`, which any sighting
/// moves, a datagram under a forged source included. On `last_seen` an approved address was
/// reported again every cooldown for as long as anything at all kept naming it, with no check
/// that it still merited a report.
const FRESHNESS_WINDOW_HOURS: i64 = 48;

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
    /// The address is in a reserved or special-purpose range (RFC1918, loopback, link-local,
    /// documentation, multicast, IPv6 ULA...) and must never be reported to a third party,
    /// regardless of score, approval, or configuration. Not operator-overridable.
    Reserved,
    /// The address carries the operator's delist latch. It is published nowhere and reported to
    /// no one until it is relisted.
    Delisted,
    Disabled,
    /// There is nothing current to report. Either the address has not earned a tier within
    /// [`FRESHNESS_WINDOW_HOURS`] (or ever): reporting a days-old attack as current honeypot
    /// activity is wrong, and some vendors reject a stale timestamp outright - which, because a
    /// failed submission never enters cooldown, would otherwise retry on every poll forever. Or
    /// it has earned nothing since this vendor last accepted a report about it: the same
    /// sighting is not reported twice.
    Stale,
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
    check_with(pool, ip, config, current_score, None).await
}

/// The latest successful submission of each (address, vendor) pair, read for a whole submission
/// pass in one query instead of one `SELECT ... LIMIT 1` per pair.
///
/// A pass over 5,600 approved addresses and three vendors made 17,000 cooldown lookups, each a
/// round trip whose elapsed time included any wait for a free worker or connection (backlog J10).
/// The book holds exactly what those lookups would have returned at the moment it was read, for
/// the addresses and vendors it was loaded for; [`check_with`] answers a pair outside that set
/// from the database as [`check`] does, so a pair the book does not cover can never read as
/// "never submitted".
///
/// It is a snapshot: a success another process records after the load is not seen until the next
/// pass. Nothing in this pass can make that matter for its own pairs (each is visited once, and
/// its own row is written after its check), and a pair a second node submitted in the meantime is
/// stopped by the day-scoped idempotency key at insert time (`submit::insert_pending`).
#[derive(Debug, Default)]
pub struct CooldownBook {
    covered_ips: HashSet<IpAddr>,
    covered_vendors: HashSet<String>,
    latest: HashMap<(IpAddr, String), LastReport>,
}

/// The reports a vendor has accepted about an address, as far as the gate needs them: when the
/// newest was sent, and how much of the address's activity they covered.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LastReport {
    /// When the newest accepted report was sent, by this node's clock. The cooldown runs on it.
    pub submitted_at: DateTime<Utc>,
    /// The latest earned time (`IpScore::tier_earned_at`) an accepted report was sent for, as it
    /// was stored then. `None` when every accepted report predates the column
    /// (`vendor_submission.earned_at`, migration 0010).
    pub earned_at: Option<DateTime<Utc>>,
}

/// Both queries that read a pair's accepted reports select these two columns, so the book and
/// the per-pair lookup cannot come to describe a pair differently.
const LAST_REPORT_COLUMNS: &str = "MAX(submitted_at) AS latest, MAX(earned_at) AS earned";

fn last_report(row: &sqlx::postgres::PgRow) -> Result<Option<LastReport>, sqlx::Error> {
    let latest: Option<DateTime<Utc>> = row.try_get("latest")?;
    Ok(match latest {
        Some(submitted_at) => Some(LastReport {
            submitted_at,
            earned_at: row.try_get("earned")?,
        }),
        None => None,
    })
}

impl CooldownBook {
    /// One query for every (address, vendor) pair of `ips` x `vendors`.
    pub async fn load(
        pool: &PgPool,
        ips: &[IpAddr],
        vendors: &[&str],
    ) -> Result<Self, sqlx::Error> {
        let mut book = CooldownBook {
            covered_ips: ips.iter().copied().collect(),
            covered_vendors: vendors.iter().map(|v| (*v).to_string()).collect(),
            latest: HashMap::new(),
        };
        if ips.is_empty() || vendors.is_empty() {
            return Ok(book);
        }
        let ip_texts: Vec<String> = ips.iter().map(ToString::to_string).collect();
        let vendor_names: Vec<&str> = vendors.to_vec();
        let rows = sqlx::query(sqlx::AssertSqlSafe(format!(
            "SELECT host(source_ip) AS source_ip, vendor, {LAST_REPORT_COLUMNS} \
             FROM vendor_submission \
             WHERE success = TRUE AND vendor = ANY($2) AND source_ip = ANY($1::text[]::inet[]) \
             GROUP BY source_ip, vendor"
        )))
        .bind(&ip_texts)
        .bind(&vendor_names)
        .fetch_all(pool)
        .await?;
        for row in rows {
            let text: String = row.try_get("source_ip")?;
            // An address Postgres prints that Rust cannot read back cannot be matched to the
            // pairs asked about, so the book then covers nothing and every pair is answered by
            // the per-pair query: never as "no submission".
            let Ok(ip) = text.parse::<IpAddr>() else {
                book.covered_ips.clear();
                return Ok(book);
            };
            if let Some(report) = last_report(&row)? {
                book.latest.insert((ip, row.try_get("vendor")?), report);
            }
        }
        Ok(book)
    }

    /// `Some(latest)` when the book covers the pair (`latest` is `None` for a pair with no
    /// successful submission), `None` when it does not and the database must be asked.
    pub fn latest_success(&self, ip: IpAddr, vendor: &str) -> Option<Option<LastReport>> {
        if !self.covered_ips.contains(&ip) || !self.covered_vendors.contains(vendor) {
            return None;
        }
        Some(self.latest.get(&(ip, vendor.to_string())).copied())
    }
}

/// [`check`], reading the cooldown from `book` when it covers the pair. The decisions are the
/// same as [`check`]'s for the same data: the book only replaces the query that fetches the
/// pair's latest success.
pub async fn check_with(
    pool: &PgPool,
    ip: IpAddr,
    config: &VendorConfig,
    current_score: &IpScore,
    book: Option<&CooldownBook>,
) -> GateResult {
    // FIRST, and ahead of every operator-configurable check: an address in a reserved range must
    // never leave this system, whatever the score says and whoever approved it. The blocklist feed
    // has always filtered these (twice - at build and again at publish); this path had no such
    // guard, so an operator's own RFC1918 host could earn `recommended_for_vendor` from routine
    // sensor testing and be one approval away from being reported to three public vendors as an
    // attacker. Deliberately not overridable by config: there is no legitimate reason to report
    // one of these to a third party.
    if is_reserved_ip(ip) {
        return GateResult::Held(GateReason::Reserved);
    }

    // Delisting leaves the earned times in place (relisting resumes a listing that still has
    // time to run), so the latch is checked here and not inferred from them.
    if current_score.delisted {
        return GateResult::Held(GateReason::Delisted);
    }

    if !config.enabled {
        return GateResult::Held(GateReason::Disabled);
    }

    // Never submit an IP that has not earned a tier inside the freshness window: a days-old attack
    // is not current honeypot activity, and a stale timestamp is rejected by some vendors (DShield
    // 500s on it) - which, since a failed submission never enters cooldown, would then retry every
    // poll indefinitely. Cheap in-memory check on the caller-supplied projection. A time ahead of
    // the clock (an event's own timestamp, up to intake's skew allowance) is read as now, as the
    // feed builder reads it, so it cannot widen the window.
    let now = Utc::now();
    let Some(earned) = current_score.tier_earned_at().map(|at| at.min(now)) else {
        return GateResult::Held(GateReason::Stale);
    };
    if now - earned > Duration::hours(FRESHNESS_WINDOW_HOURS) {
        return GateResult::Held(GateReason::Stale);
    }

    let last_success = match latest_success(pool, ip, config, book).await {
        Ok(last_success) => last_success,
        Err(reason) => return GateResult::Held(reason),
    };
    let cooldown = Duration::hours(config.cooldown_hours as i64);
    if last_success.is_some_and(|last| now - last.submitted_at < cooldown) {
        return GateResult::Held(GateReason::Cooldown);
    }
    // The cooldown is over. Report again only if the address has earned its tier again since the
    // last report this vendor accepted: one burst of activity is one report, not one per
    // cooldown for as long as the freshness window stays open.
    //
    // "Since" is asked of the earned time itself: the stored one against the one the accepted
    // report was sent for. Both are the same column, so both are the sensor's clock. Against
    // the time the report was sent (this node's clock) a sensor running a little fast puts the
    // very burst that was reported after its own report, and it went out again after every
    // cooldown; one running slow hid a real return. Only a report from before the earned time
    // was recorded is still compared with the time it was sent.
    if last_success.is_some_and(|last| match last.earned_at {
        Some(covered) => current_score.tier_earned_at() <= Some(covered),
        None => earned <= last.submitted_at,
    }) {
        return GateResult::Held(GateReason::Stale);
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

/// What this vendor has accepted about `ip`, from `book` when it covers the pair and from the
/// database otherwise. [`GateReason::DbError`] if the query itself fails, so the caller holds
/// rather than treating an unanswered question as "never reported".
async fn latest_success(
    pool: &PgPool,
    ip: IpAddr,
    config: &VendorConfig,
    book: Option<&CooldownBook>,
) -> Result<Option<LastReport>, GateReason> {
    match book.and_then(|b| b.latest_success(ip, &config.name)) {
        Some(latest) => Ok(latest),
        None => sqlx::query(sqlx::AssertSqlSafe(format!(
            "SELECT {LAST_REPORT_COLUMNS} FROM vendor_submission \
             WHERE source_ip = $1::inet AND vendor = $2 AND success = TRUE"
        )))
        .bind(ip.to_string())
        .bind(&config.name)
        .fetch_one(pool)
        .await
        .and_then(|row| last_report(&row))
        .map_err(|e| GateReason::DbError(e.to_string())),
    }
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
