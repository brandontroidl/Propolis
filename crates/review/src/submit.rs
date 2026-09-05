//! The submission runner: one poll pass over `review_queue`'s Approved
//! entries, submitting each to every configured, gate-passing vendor. See
//! `internal/design/04-review-gatekeeper-reporting.md` ("The gatekeeper",
//! "Vendor adapters", "Idempotency").
//!
//! [`SubmissionRunner::run_once`] is the whole algorithm, one call = one
//! pass:
//!
//! 1. [`ReviewQueue::list_approved`] - every operator-approved entry (the
//!    human-approval gate; this module never reads Pending, Rejected, or
//!    Snoozed rows).
//! 2. For each approved IP, `core_scoring::read_score` - the projection
//!    decayed to now, not the stale `score_at_surface` snapshot, so both the
//!    gate's score-floor/category-filter checks and the report's category
//!    codes reflect the IP's CURRENT state.
//! 3. For each configured vendor (an adapter + its gatekeeper-scoped
//!    config, matched by name): [`crate::gatekeeper::check`]. A held
//!    (ip, vendor) pair is skipped before anything is written - only an
//!    attempted submission ever produces a `vendor_submission` row.
//! 4. Build the [`VendorReport`] and a date-scoped idempotency key, INSERT a
//!    `success = false` row, call `adapter.submit`, then UPDATE that row
//!    with the outcome. See "Idempotency" below.
//!
//! # Where `protocol_label` comes from
//!
//! The category mapping (`vendor::build_categories` et al.) is keyed by
//! `(protocol_label, Category)`, but `ip_score.category_breakdown` (what
//! `read_score` returns) retains only the per-category accumulated weight -
//! `protocol_label` lives solely in each individual `event` row's `metadata`
//! JSONB (design spec "Category mapping"; `internal/design/
//! 02-sensor-framework.md`'s `metadata.protocol_label` contract). This
//! module queries `event` directly ([`category_protocol_labels`]) for the
//! most recently observed `protocol_label` per category this source IP has
//! ever recorded, so a real SSH/Telnet/FTP submission actually reaches the
//! vendor-specific code (`22`/`ssh`/`ssh-bruteforce`) instead of always
//! falling through to the generic per-`Category` row - without this, the
//! `PROTOCOL_TABLE` half of `vendor::resolve` would be dead code in
//! production, reachable only from `vendor_test.rs`'s direct unit calls.
//!
//! # Vendor-name dispatch
//!
//! `VendorReport.categories` needs vendor-SPECIFIC codes - AbuseIPDB wants
//! numeric strings, DShield and OTX want their own tag vocabularies - so
//! this module picks the builder function by the adapter's own `name()`
//! (the same string `vendor_submission.vendor` and
//! `gatekeeper::VendorConfig.name` use; see `vendor_test.rs`'s
//! `adapter_names_match_vendor_submission_table_convention`). An
//! unrecognized vendor name (no built-in adapter is named anything else
//! today) falls back to the AbuseIPDB-style numeric mapping rather than
//! failing the submission closed - the gatekeeper's own `category_filter`
//! has already had its say on whether this category is acceptable to this
//! vendor; this only picks which code STRING gets sent on the wire.
//!
//! # Constructing vendors (this module vs. the daemon)
//!
//! `SubmissionRunner` takes already-built `Box<dyn VendorAdapter>` trait
//! objects plus their matching gatekeeper-scoped `VendorConfig`s - not the
//! full per-vendor `FullVendorConfig` (which also carries `api_key`/
//! `api_url`) directly. That keeps this module mockable in tests
//! (`submit_test.rs`'s `MockVendor`) with no live HTTP dependency. The
//! submission daemon (a later task) is expected to build each real adapter
//! once at startup - `AbuseIpDb::new(client.clone(), config.api_key.clone(),
//! config.api_url.clone())` (and the `DShield`/`OtxAdapter` equivalents) -
//! box it, and pass `config.gate_config()` alongside it, matching Task 3's
//! carry-forward note (`task-3-report.md`, "Concerns for later tasks").
//!
//! # Idempotency
//!
//! The idempotency key is `"{source_ip}:{vendor}:{date}"` (`NaiveDate`, the
//! UTC calendar day of the poll) - the design spec's exact form. The INSERT
//! is `ON CONFLICT (idempotency_key) DO NOTHING`, so a repeat attempt within
//! the same day never creates a second row; the UPDATE that follows always
//! applies to whichever row the key identifies (just-inserted or
//! already-existing from an earlier attempt today), regardless of whether
//! the INSERT itself did anything. In normal operation (a nonzero
//! `cooldown_hours`), the gatekeeper's own cooldown check already holds a
//! repeat attempt on an IP that was successfully submitted within the
//! window, long before this code would ever re-INSERT the same key - the
//! idempotency guarantee here is what keeps the table's UNIQUE constraint
//! satisfied on the rarer paths where a still-failed attempt is
//! legitimately retried, or an operator has deliberately zeroed out
//! cooldown.
//!
//! The row makes the DATABASE idempotent; the vendor call is the side
//! effect it exists to protect, so the call only follows a claim the INSERT
//! actually won, or a retry of an attempt whose failure was recorded. A
//! conflicting row with `response_status IS NULL` means an earlier attempt
//! today inserted and then died before `record_result` - the vendor may
//! have accepted that report - and a row already marked successful means it
//! did. Neither is resubmitted (`SubmitResult::unresolved`): a repeat would
//! report the IP twice while this table showed one row, and the cooldown
//! check, which filters on `success = TRUE`, cannot see the first case.
//!
//! # Error handling
//!
//! `list_approved` failing aborts the whole pass (there is nothing to do
//! without knowing which IPs are approved). Every PER-ITEM database call
//! after that (`read_score`, the protocol-label lookup, the INSERT/UPDATE
//! pair) is logged and skips only that one IP or (IP, vendor) pair, per the
//! design spec's "Error handling": "a database error ... is logged and
//! retried on the next poll cycle. The daemon does not crash on transient
//! DB errors." A skipped IP's `review_queue` row stays Approved, so a later
//! `run_once` call reconsiders it exactly as if this pass had never run.

use std::collections::{BTreeMap, HashMap};
use std::net::IpAddr;

use chrono::{NaiveDate, Utc};
use sqlx::{PgPool, Row};

use core_scoring::{Category, IpScore, read_score};

use crate::gatekeeper::{self, GateReason, GateResult, VendorConfig};
use crate::queue::{ReviewError, ReviewQueue};
use crate::vendor::{
    VendorAdapter, VendorError, VendorReport, build_categories, build_dshield_categories,
    build_otx_categories,
};

/// Errors from the submission runner. See the module doc comment's "Error
/// handling" for which failures abort the whole pass versus which are
/// contained to a single item.
#[derive(Debug, thiserror::Error)]
pub enum SubmitError {
    /// A database/driver error.
    #[error("database error: {0}")]
    Db(#[from] sqlx::Error),
    /// Reading the approved queue itself failed.
    #[error("review queue error: {0}")]
    Review(#[from] ReviewError),
    /// A stored value could not be parsed into the expected shape (e.g. a
    /// `category_breakdown` whose keys are not valid `Category` variant
    /// names). Should not occur - `core_scoring`'s own read path already
    /// validates this JSON before returning it - but this module fails
    /// closed rather than panicking if it ever does.
    #[error("corrupt stored state: {0}")]
    Corrupt(String),
}

/// One [`SubmissionRunner::run_once`] pass's outcome, summed across every
/// (approved IP, configured vendor) pair considered.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SubmitResult {
    /// The vendor accepted the report (`VendorResponse::accepted`, which
    /// includes AbuseIPDB's "already reported" 429 carve-out).
    pub submitted: usize,
    /// The gatekeeper held this (ip, vendor) pair; no HTTP call was made and
    /// no `vendor_submission` row was written.
    pub held: usize,
    /// The gate passed but the vendor call did not succeed (a transient or
    /// permanent `VendorError`); a `vendor_submission` row records the
    /// failure.
    pub failed: usize,
    /// The gate passed but today's `vendor_submission` row shows an earlier
    /// attempt that already reached the vendor - its outcome never recorded
    /// (a crash between the call and `record_result`), or successful - so no
    /// HTTP call was made: a repeat could report the same IP twice while the
    /// table shows one row. See "Idempotency" in the module doc comment.
    pub unresolved: usize,
}

/// Polls `review_queue`'s Approved entries and submits each to every
/// configured vendor whose gate check passes. See the module doc comment
/// for the full algorithm and the design decisions behind it.
pub struct SubmissionRunner {
    pool: PgPool,
    vendors: Vec<Box<dyn VendorAdapter>>,
    gatekeeper_config: Vec<VendorConfig>,
}

impl SubmissionRunner {
    pub fn new(
        pool: PgPool,
        vendors: Vec<Box<dyn VendorAdapter>>,
        gatekeeper_config: Vec<VendorConfig>,
    ) -> Self {
        Self {
            pool,
            vendors,
            gatekeeper_config,
        }
    }

    /// Run one pass. See the module doc comment's numbered algorithm.
    pub async fn run_once(&self) -> Result<SubmitResult, SubmitError> {
        let approved = ReviewQueue::new().list_approved(&self.pool).await?;
        let today = Utc::now().date_naive();

        let mut result = SubmitResult::default();
        for entry in approved {
            let ip = entry.source_ip;

            let current_score = match read_score(&self.pool, ip).await {
                Ok(Some(score)) => score,
                Ok(None) => {
                    // An Approved entry with no projection at all cannot
                    // happen via the normal populate path (it only ever
                    // surfaces IPs that HAVE one), but there is nothing to
                    // submit without one either way. Fail closed: skip.
                    tracing::warn!(
                        %ip,
                        "approved queue entry has no ip_score projection; skipping this poll"
                    );
                    continue;
                }
                Err(e) => {
                    tracing::error!(%ip, error = %e, "read_score failed; skipping this poll");
                    continue;
                }
            };

            let protocol_labels = match category_protocol_labels(&self.pool, ip).await {
                Ok(map) => map,
                Err(e) => {
                    tracing::error!(
                        %ip, error = %e,
                        "protocol-label lookup failed; skipping this poll"
                    );
                    continue;
                }
            };

            for adapter in &self.vendors {
                let name = adapter.name();
                let Some(config) = self.gatekeeper_config.iter().find(|c| c.name == name) else {
                    tracing::warn!(
                        vendor = %name,
                        "no gatekeeper config for this vendor adapter; holding"
                    );
                    result.held += 1;
                    continue;
                };

                match gatekeeper::check(&self.pool, ip, config, &current_score).await {
                    GateResult::Held(reason) => {
                        match &reason {
                            // Expected steady state: an already-sent (cooldown), rate-limited,
                            // below-floor, category-filtered, or disabled-vendor submission is held
                            // on every poll. One INFO line per (ip, vendor) every pass drowns the
                            // log; the per-pass `held=N` summary keeps the count visible.
                            GateReason::Cooldown
                            | GateReason::RateLimit
                            | GateReason::ScoreFloor
                            | GateReason::CategoryFilter
                            | GateReason::Disabled
                            | GateReason::Stale => {
                                tracing::debug!(%ip, vendor = %name, ?reason, "submission held");
                            }
                            // Rare and worth surfacing: a reserved-range IP that reached an approved
                            // vendor submission should never have been approved, and a DbError means
                            // the gate could not be evaluated (fail-closed).
                            GateReason::Reserved | GateReason::DbError(_) => {
                                tracing::warn!(%ip, vendor = %name, ?reason, "submission held");
                            }
                        }
                        result.held += 1;
                        continue;
                    }
                    GateResult::Pass => {}
                }

                let report = match build_report(ip, &current_score, &protocol_labels, name) {
                    Ok(r) => r,
                    Err(e) => {
                        tracing::error!(
                            %ip, vendor = %name, error = %e,
                            "failed to build vendor report; skipping"
                        );
                        continue;
                    }
                };

                let key = idempotency_key(ip, name, today);
                match insert_pending(&self.pool, ip, name, &key, &report).await {
                    Ok(PendingClaim::Claimed | PendingClaim::RetryOfRecordedFailure) => {}
                    Ok(claim @ (PendingClaim::OutcomeUnknown | PendingClaim::AlreadySucceeded)) => {
                        tracing::warn!(
                            %ip, vendor = %name, ?claim,
                            "not resubmitting: today's attempt already reached the vendor \
                             (outcome unrecorded or successful); a repeat could double-report"
                        );
                        result.unresolved += 1;
                        continue;
                    }
                    Err(e) => {
                        tracing::error!(
                            %ip, vendor = %name, error = %e,
                            "failed to record pending submission; skipping HTTP call"
                        );
                        continue;
                    }
                }

                let (status, body, success) = match adapter.submit(&report).await {
                    Ok(response) => (
                        Some(response.status as i32),
                        response.body,
                        response.accepted,
                    ),
                    Err(err) => {
                        let (status, body) = vendor_error_parts(&err);
                        (status, body, false)
                    }
                };

                if let Err(e) = record_result(&self.pool, &key, status, &body, success).await {
                    tracing::error!(
                        %ip, vendor = %name, error = %e,
                        "failed to record submission result"
                    );
                }

                if success {
                    result.submitted += 1;
                } else {
                    tracing::warn!(
                        %ip, vendor = %name, ?status, body = %body.chars().take(200).collect::<String>(),
                        "vendor submission failed"
                    );
                    result.failed += 1;
                }
            }
        }
        Ok(result)
    }
}

/// `"{source_ip}:{vendor}:{date}"` - the design spec's exact idempotency key
/// shape ("Idempotency"). Date-scoped so a new UTC day allows re-reporting
/// even after a successful report the day before.
fn idempotency_key(ip: IpAddr, vendor: &str, date: NaiveDate) -> String {
    format!("{ip}:{vendor}:{date}")
}

/// For each `Category` this source IP's ledger has ever recorded an event
/// under, the `protocol_label` (if any) of the MOST RECENTLY observed such
/// event. See the module doc comment's "Where `protocol_label` comes from".
async fn category_protocol_labels(
    pool: &PgPool,
    ip: IpAddr,
) -> Result<HashMap<Category, Option<String>>, SubmitError> {
    let rows = sqlx::query(
        "SELECT DISTINCT ON (category) category, metadata->>'protocol_label' AS protocol_label \
         FROM event WHERE source_ip = $1::inet \
         ORDER BY category, observed_at DESC",
    )
    .bind(ip.to_string())
    .fetch_all(pool)
    .await?;

    let mut map = HashMap::with_capacity(rows.len());
    for row in rows {
        let category: Category = row.try_get("category")?;
        let protocol_label: Option<String> = row.try_get("protocol_label")?;
        map.insert(category, protocol_label);
    }
    Ok(map)
}

/// Resolve the vendor-specific category codes for `(protocol_label,
/// category)` by the adapter's own name. See the module doc comment's
/// "Vendor-name dispatch".
fn categories_for_vendor(
    vendor_name: &str,
    protocol_label: Option<&str>,
    category: Category,
) -> Vec<String> {
    match vendor_name {
        "dshield" => build_dshield_categories(protocol_label, category),
        "otx" => build_otx_categories(protocol_label, category),
        _ => build_categories(protocol_label, category),
    }
}

/// Build the `VendorReport` for `(ip, vendor_name)` from the live projection
/// and this IP's per-category protocol labels: one vendor-specific code per
/// live category, flattened and de-duplicated.
fn build_report(
    ip: IpAddr,
    current_score: &IpScore,
    protocol_labels: &HashMap<Category, Option<String>>,
    vendor_name: &str,
) -> Result<VendorReport, SubmitError> {
    // Deserializing into `Category`-keyed values (rather than the private
    // `core_scoring::scoring::engine::CategoryStat`) validates every key as
    // a real `Category` variant in one pass - the same
    // `serde_json::from_value::<BTreeMap<Category, _>>` shape
    // `core_scoring`'s own engine uses internally - without needing that
    // private type; the JSON `Value` payload per key is never inspected.
    let breakdown: BTreeMap<Category, serde_json::Value> =
        serde_json::from_value(current_score.category_breakdown.clone()).map_err(|e| {
            SubmitError::Corrupt(format!(
                "category_breakdown for {ip} is not a Category map: {e}"
            ))
        })?;

    let mut categories: Vec<String> = Vec::new();
    for category in breakdown.keys() {
        let protocol_label = protocol_labels.get(category).and_then(|l| l.as_deref());
        for code in categories_for_vendor(vendor_name, protocol_label, *category) {
            if !categories.contains(&code) {
                categories.push(code);
            }
        }
    }

    let comment = format!(
        "propolis: {ip} - {} event(s) across {} categor{} since {}, current score {}",
        current_score.event_count,
        breakdown.len(),
        if breakdown.len() == 1 { "y" } else { "ies" },
        current_score.first_seen.to_rfc3339(),
        // Round for the human-facing comment: the raw Decimal carries ~26 digits, which reads as a
        // bug on a public OTX pulse. One decimal place is ample for a 0-100 score.
        current_score.raw_score.round_dp(1),
    );

    Ok(VendorReport {
        source_ip: ip,
        categories,
        comment,
        evidence_window: (current_score.first_seen, current_score.last_seen),
    })
}

/// What `insert_pending` found under today's idempotency key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PendingClaim {
    /// No row existed; this attempt owns the key and the vendor call goes ahead.
    Claimed,
    /// An earlier attempt today reached the vendor and recorded a failure; retrying is what the
    /// design spec asks for.
    RetryOfRecordedFailure,
    /// An earlier attempt today inserted its row and then never recorded an outcome - the process
    /// died between `adapter.submit` and `record_result`. The vendor may well have accepted that
    /// report, so calling again risks a duplicate the table would never show. Not resubmitted.
    OutcomeUnknown,
    /// The row already records success. Normally the cooldown holds this long before here; with
    /// cooldown zeroed by an operator it is reachable, and still must not double-report.
    AlreadySucceeded,
}

/// Insert the pending attempt row before the HTTP call (`success = false`), and say whether this
/// attempt actually claimed the key. `ON CONFLICT (idempotency_key) DO NOTHING` - see the module
/// doc comment's "Idempotency". The vendor call is the side effect the row exists to make
/// idempotent, so it must only follow a claim, or a retry of an attempt whose outcome is known.
async fn insert_pending(
    pool: &PgPool,
    ip: IpAddr,
    vendor: &str,
    key: &str,
    report: &VendorReport,
) -> Result<PendingClaim, SubmitError> {
    let inserted: Option<i64> = sqlx::query_scalar(
        "INSERT INTO vendor_submission \
         (source_ip, vendor, idempotency_key, categories, comment, success) \
         VALUES ($1::inet, $2, $3, $4, $5, FALSE) \
         ON CONFLICT (idempotency_key) DO NOTHING \
         RETURNING id",
    )
    .bind(ip.to_string())
    .bind(vendor)
    .bind(key)
    .bind(&report.categories)
    .bind(&report.comment)
    .fetch_optional(pool)
    .await?;
    if inserted.is_some() {
        return Ok(PendingClaim::Claimed);
    }
    let prior: Option<(bool, Option<i32>)> = sqlx::query_as(
        "SELECT success, response_status FROM vendor_submission WHERE idempotency_key = $1",
    )
    .bind(key)
    .fetch_optional(pool)
    .await?;
    Ok(match prior {
        // Conflicted but gone by the time we looked (an operator reset between the two
        // statements): nothing recorded either way, so treat it as the unknown it is.
        None => PendingClaim::OutcomeUnknown,
        Some((true, _)) => PendingClaim::AlreadySucceeded,
        Some((false, None)) => PendingClaim::OutcomeUnknown,
        Some((false, Some(_))) => PendingClaim::RetryOfRecordedFailure,
    })
}

/// Record the HTTP call's outcome against the row `key` identifies.
async fn record_result(
    pool: &PgPool,
    key: &str,
    response_status: Option<i32>,
    response_body: &str,
    success: bool,
) -> Result<(), SubmitError> {
    sqlx::query(
        "UPDATE vendor_submission SET response_status = $1, response_body = $2, success = $3 \
         WHERE idempotency_key = $4",
    )
    .bind(response_status)
    .bind(response_body)
    .bind(success)
    .bind(key)
    .execute(pool)
    .await?;
    Ok(())
}

/// `(response_status, response_body)` from a failed `submit` call - both
/// `VendorError` variants share the same field shape, so one arm covers
/// both.
fn vendor_error_parts(err: &VendorError) -> (Option<i32>, String) {
    match err {
        VendorError::Transient { status, body } | VendorError::Permanent { status, body } => {
            (Some(*status as i32), body.clone())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn idempotency_key_matches_spec_shape() {
        let ip: IpAddr = "203.0.113.9".parse().unwrap();
        let date: NaiveDate = "2026-07-29".parse().unwrap();
        assert_eq!(
            idempotency_key(ip, "abuseipdb", date),
            "203.0.113.9:abuseipdb:2026-07-29"
        );
    }

    #[test]
    fn categories_for_vendor_dispatches_by_name() {
        assert_eq!(
            categories_for_vendor("dshield", Some("ssh"), Category::Auth),
            vec!["ssh".to_string()]
        );
        assert_eq!(
            categories_for_vendor("otx", Some("ssh"), Category::Auth),
            vec!["ssh-bruteforce".to_string()]
        );
        assert_eq!(
            categories_for_vendor("abuseipdb", Some("ssh"), Category::Auth),
            vec!["22".to_string()]
        );
        // Unrecognized vendor name falls back to the numeric mapping.
        assert_eq!(
            categories_for_vendor("future-vendor", Some("ssh"), Category::Auth),
            vec!["22".to_string()]
        );
    }
}
