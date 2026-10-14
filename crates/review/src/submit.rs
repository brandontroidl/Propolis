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
//!    An address on the operator allowlist is refused here, before anything else, and counted
//!    as held for every configured vendor (see [`SubmissionRunner::with_allowlist`]).
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
use std::sync::Arc;

use chrono::{NaiveDate, Utc};
use sqlx::{PgPool, Row};

use core_scoring::{Category, IpScore, OperatorAllowlist, read_score};

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
    /// `held`, split by why. Always sums to `held`.
    pub held_by: HeldBreakdown,
}

/// How many (ip, vendor) pairs a pass held, by reason. `held=17202` alone cannot say whether
/// every vendor is switched off or every address is in cooldown; the per-pair reason is logged at
/// debug only, so this carries it into the one line per pass.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct HeldBreakdown {
    /// The address is on the operator allowlist.
    pub allowlisted: usize,
    /// The vendor adapter has no gatekeeper configuration.
    pub no_vendor_config: usize,
    pub reserved: usize,
    pub disabled: usize,
    pub stale: usize,
    pub cooldown: usize,
    pub rate_limit: usize,
    pub score_floor: usize,
    pub category_filter: usize,
    pub db_error: usize,
}

impl HeldBreakdown {
    fn record(&mut self, reason: &GateReason) {
        let slot = match reason {
            GateReason::Reserved => &mut self.reserved,
            GateReason::Disabled => &mut self.disabled,
            GateReason::Stale => &mut self.stale,
            GateReason::Cooldown => &mut self.cooldown,
            GateReason::RateLimit => &mut self.rate_limit,
            GateReason::ScoreFloor => &mut self.score_floor,
            GateReason::CategoryFilter => &mut self.category_filter,
            GateReason::DbError(_) => &mut self.db_error,
        };
        *slot += 1;
    }

    pub fn total(&self) -> usize {
        let Self {
            allowlisted,
            no_vendor_config,
            reserved,
            disabled,
            stale,
            cooldown,
            rate_limit,
            score_floor,
            category_filter,
            db_error,
        } = *self;
        allowlisted
            + no_vendor_config
            + reserved
            + disabled
            + stale
            + cooldown
            + rate_limit
            + score_floor
            + category_filter
            + db_error
    }
}

impl std::fmt::Display for HeldBreakdown {
    /// `name=count` for each nonzero reason, space separated; `none` when nothing was held.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let parts = [
            ("allowlisted", self.allowlisted),
            ("no_vendor_config", self.no_vendor_config),
            ("reserved", self.reserved),
            ("disabled", self.disabled),
            ("stale", self.stale),
            ("cooldown", self.cooldown),
            ("rate_limit", self.rate_limit),
            ("score_floor", self.score_floor),
            ("category_filter", self.category_filter),
            ("db_error", self.db_error),
        ];
        let mut any = false;
        for (name, count) in parts.into_iter().filter(|(_, c)| *c > 0) {
            if any {
                f.write_str(" ")?;
            }
            write!(f, "{name}={count}")?;
            any = true;
        }
        if !any {
            f.write_str("none")?;
        }
        Ok(())
    }
}

/// Polls `review_queue`'s Approved entries and submits each to every
/// configured vendor whose gate check passes. See the module doc comment
/// for the full algorithm and the design decisions behind it.
pub struct SubmissionRunner {
    pool: PgPool,
    vendors: Vec<Box<dyn VendorAdapter>>,
    gatekeeper_config: Vec<VendorConfig>,
    allowlist: Arc<OperatorAllowlist>,
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
            allowlist: Arc::default(),
        }
    }

    /// Refuse to submit any address on the operator allowlist, whatever its queue state. This is
    /// the second line of defence behind [`ReviewQueue`]'s own filtering: the allowlist is read at
    /// startup and can change after an entry was queued or approved, so the check is repeated
    /// here, immediately before anything leaves the system. The default runner has an empty
    /// allowlist.
    pub fn with_allowlist(mut self, allowlist: Arc<OperatorAllowlist>) -> Self {
        self.allowlist = allowlist;
        self
    }

    /// Run one pass. See the module doc comment's numbered algorithm.
    pub async fn run_once(&self) -> Result<SubmitResult, SubmitError> {
        let approved = ReviewQueue::new().list_approved(&self.pool).await?;
        let today = Utc::now().date_naive();

        let mut result = SubmitResult::default();
        for entry in approved {
            let ip = entry.source_ip;

            if self.allowlist.contains(ip) {
                // Steady state for as long as the entry stays Approved, so debug, not warn.
                tracing::debug!(
                    %ip,
                    "approved entry is on the operator allowlist; not submitting to any vendor"
                );
                result.held += self.vendors.len();
                result.held_by.allowlisted += self.vendors.len();
                continue;
            }

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
                    result.held_by.no_vendor_config += 1;
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
                        result.held_by.record(&reason);
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

/// One index probe per category (`event_source_category_observed_idx`, core-scoring migration
/// 0020) instead of `SELECT DISTINCT ON (category) ... ORDER BY category, observed_at DESC`, which
/// reads and sorts every event the address ever produced: 1.55 s for one heavy address on the live
/// node. The categories come from the enum itself, so a new `Category` variant needs no change
/// here; a category with no event for this address yields no row, as before.
const PROTOCOL_LABELS_SQL: &str = "\
    SELECT c.category, l.protocol_label \
    FROM unnest(enum_range(NULL::category_enum)) AS c(category) \
    CROSS JOIN LATERAL ( \
        SELECT metadata->>'protocol_label' AS protocol_label FROM event \
        WHERE source_ip = $1::inet AND category = c.category \
        ORDER BY observed_at DESC LIMIT 1 \
    ) l";

/// For each `Category` this source IP's ledger has ever recorded an event
/// under, the `protocol_label` (if any) of the MOST RECENTLY observed such
/// event. See the module doc comment's "Where `protocol_label` comes from".
async fn category_protocol_labels(
    pool: &PgPool,
    ip: IpAddr,
) -> Result<HashMap<Category, Option<String>>, SubmitError> {
    let rows = sqlx::query(PROTOCOL_LABELS_SQL)
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

    // The text an operator reads in the pass summary: only nonzero reasons, in a fixed order, so
    // two passes are comparable by eye; `none` rather than an empty field when nothing was held.
    #[test]
    fn the_held_breakdown_prints_nonzero_reasons_in_a_fixed_order() {
        assert_eq!(HeldBreakdown::default().to_string(), "none");

        let mut held = HeldBreakdown::default();
        for reason in [
            GateReason::Disabled,
            GateReason::Cooldown,
            GateReason::Disabled,
            GateReason::Reserved,
            GateReason::Stale,
            GateReason::RateLimit,
            GateReason::ScoreFloor,
            GateReason::CategoryFilter,
            GateReason::DbError("connection reset".into()),
        ] {
            held.record(&reason);
        }
        held.allowlisted += 4;
        held.no_vendor_config += 1;
        assert_eq!(
            held.to_string(),
            "allowlisted=4 no_vendor_config=1 reserved=1 disabled=2 stale=1 cooldown=1 \
             rate_limit=1 score_floor=1 category_filter=1 db_error=1"
        );
        assert_eq!(held.total(), 14);
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

    use core_scoring::{EventInput, Protocol, SignalType, append_event};

    async fn migrate(pool: &PgPool) {
        sqlx::migrate!("../core-scoring/migrations")
            .run(pool)
            .await
            .unwrap();
        crate::migrator().run(pool).await.unwrap();
    }

    async fn event(
        pool: &PgPool,
        ip: &str,
        signal: SignalType,
        ts: &str,
        metadata: serde_json::Value,
    ) {
        append_event(
            pool,
            EventInput::from_signal(
                ip.parse().unwrap(),
                None,
                "sensor-labels".into(),
                signal,
                Protocol::Tcp,
                true,
                ts.parse().unwrap(),
                metadata,
                None,
            ),
        )
        .await
        .unwrap();
    }

    #[sqlx::test(migrations = false)]
    async fn the_newest_label_per_category_is_returned_for_this_address_only(pool: PgPool) {
        migrate(&pool).await;
        let ip = "198.51.100.40";
        // Honeypot: the newer event (telnet) wins over the older one (ssh).
        event(
            &pool,
            ip,
            SignalType::HoneypotLoginAttempt,
            "2026-10-01T00:00:00Z",
            serde_json::json!({"protocol_label": "ssh"}),
        )
        .await;
        event(
            &pool,
            ip,
            SignalType::HoneypotConnection,
            "2026-10-01T00:05:00Z",
            serde_json::json!({"protocol_label": "telnet"}),
        )
        .await;
        // Network: newest event carries no label, so the category maps to None, not to an older
        // label from some other category.
        event(
            &pool,
            ip,
            SignalType::CatchallProbe,
            "2026-10-01T00:06:00Z",
            serde_json::json!({}),
        )
        .await;
        // Another address, newer, with a different label: must not leak in.
        event(
            &pool,
            "198.51.100.41",
            SignalType::HoneypotConnection,
            "2026-10-01T01:00:00Z",
            serde_json::json!({"protocol_label": "ftp"}),
        )
        .await;

        let labels = category_protocol_labels(&pool, ip.parse().unwrap())
            .await
            .unwrap();
        assert_eq!(
            labels.len(),
            2,
            "only categories this address has events in"
        );
        assert_eq!(labels[&Category::Honeypot].as_deref(), Some("telnet"));
        assert_eq!(labels[&Category::Network], None);
    }

    // The live defect: DISTINCT ON read and sorted every event the address ever produced (1.55 s
    // for one address). Planner cost choices vary with table size, so this turns off the plans
    // that could hide the problem on a near-empty table and asserts the query's plan has no Sort
    // and probes the per-category index one row per category. Fails on the DISTINCT ON form (a
    // Sort, or with the index an ordered walk of every event, no Limit) and without the index.
    #[sqlx::test(migrations = false)]
    async fn the_label_lookup_probes_an_index_per_category_instead_of_sorting_the_address(
        pool: PgPool,
    ) {
        migrate(&pool).await;
        event(
            &pool,
            "198.51.100.42",
            SignalType::HoneypotConnection,
            "2026-10-01T00:00:00Z",
            serde_json::json!({"protocol_label": "ssh"}),
        )
        .await;

        let mut conn = pool.acquire().await.unwrap();
        sqlx::raw_sql("SET enable_seqscan = off; SET enable_bitmapscan = off")
            .execute(&mut *conn)
            .await
            .unwrap();
        let plan: Vec<String> = sqlx::query_scalar(sqlx::AssertSqlSafe(format!(
            "EXPLAIN {PROTOCOL_LABELS_SQL}"
        )))
        .bind("198.51.100.42")
        .fetch_all(&mut *conn)
        .await
        .unwrap();
        let plan = plan.join("\n");
        assert!(
            !plan.contains("Sort"),
            "the lookup must not sort the address's events:\n{plan}"
        );
        assert!(
            plan.contains("event_source_category_observed_idx"),
            "the lookup must probe the per-category index:\n{plan}"
        );
        // An index-ordered DISTINCT ON has no Sort either, but still walks every event the
        // address has; only a per-category top-1 stops after one row each.
        assert!(
            plan.contains("Limit"),
            "the lookup must take one row per category:\n{plan}"
        );
    }
}
