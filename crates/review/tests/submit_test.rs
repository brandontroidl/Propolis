//! Real-Postgres, mock-vendor tests for the submission runner (Task 4).
//!
//! Shares the persistent `propolis_test` database with the other crates'
//! tests (see the project's `local-gate-toolchain` note). Every test uses a
//! distinct source IP, `45.10.32.240-248`, disjoint from `queue_test.rs`'s
//! RFC5737 fixtures and from `gatekeeper_test.rs`'s `45.10.31.230-240`.
//!
//! These are ordinary public addresses, not the RFC5737 documentation ranges
//! used elsewhere, and must stay that way: the gatekeeper's first check
//! refuses every reserved range outright, so a documentation-range fixture is
//! held as `Reserved` before the runner behaviour under test is ever reached.
//! Most
//! tests use a vendor name unique to that test so no cross-run cleanup
//! beyond the per-IP `reset` below is needed; the one test that exercises
//! the REAL `"dshield"` name (to prove `submit::categories_for_vendor`'s
//! dispatch fires end-to-end, not just in `submit.rs`'s own unit tests)
//! also wipes any leftover rows under that literal name first, matching
//! `gatekeeper_test.rs`'s `reset_vendor` discipline. Run with
//! `--test-threads=1`.
//!
//! # Why every assertion here is scoped to the test's own IP
//!
//! `SubmissionRunner::run_once` (unlike `gatekeeper::check` or
//! `ReviewQueue::approve`) has no IP parameter at all - by design, it polls
//! `review_queue` for EVERY Approved entry, table-wide. Against the
//! persistent, shared `propolis_test` database, that table already holds
//! Approved rows this suite does not own: `queue_test.rs`'s own
//! `approve_sets_state_and_decided_at` (`192.0.2.212`) and
//! `withdraw_never_removes_a_decided_entry` (`198.51.100.217`) leave their
//! rows Approved forever once their test completes (verified live via
//! `psql` while writing this suite), and this file's OWN earlier tests do
//! the same for each other on any rerun. A permissively-configured mock
//! vendor (no score floor, no category filter, a fresh cooldown/rate-limit
//! history) holds nothing back from an unrelated approved IP, so it reaches
//! `adapter.submit` right alongside this test's own IP - confirmed
//! empirically: an early version of this suite asserted the raw
//! `SubmitResult` and failed with e.g. `submitted: 5` where `1` was
//! expected. Task 1's own report already named this exact class of bug
//! ("asserting a row count for a specific IP rather than trusting the
//! aggregate return value"); this file applies the same discipline
//! throughout - never assert equality on the aggregate `SubmitResult` or on
//! a mock's raw, unfiltered call count, only on `vendor_submission` rows
//! and mock submissions scoped to `(this test's ip, this test's vendor
//! name)`.
//!
//! [`MockVendor`] implements `VendorAdapter` directly (per the task brief)
//! rather than standing up a mock HTTP server like `vendor_test.rs` does for
//! the adapters themselves - the runner is tested against the trait
//! boundary, not the HTTP wire. Canned outcomes are scripted PER SOURCE IP
//! (via [`MockVendor::script`]), not as a bare call-order queue: an
//! unrelated contaminating IP must never consume the outcome a test
//! scripted for its own IP, and a source IP with nothing scripted for it
//! (every contaminating IP) gets an unconditional, harmless `Success` so it
//! never affects this test's own assertions.

use std::collections::{HashMap, VecDeque};
use std::net::IpAddr;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use chrono::{Duration, Utc};
use core_scoring::{EventInput, Protocol, SignalType, append_event};
use sqlx::{PgPool, Row};

use review::gatekeeper::VendorConfig;
use review::queue::ReviewQueue;
use review::submit::SubmissionRunner;
use review::vendor::{VendorAdapter, VendorError, VendorReport, VendorResponse};

// ---------------------------------------------------------------------
// Mock vendor
// ---------------------------------------------------------------------

/// A canned outcome for one [`MockVendor::submit`] call.
#[derive(Debug, Clone)]
enum MockOutcome {
    Success { status: u16, body: &'static str },
    Transient { status: u16, body: &'static str },
    Permanent { status: u16, body: &'static str },
}

/// Records every [`VendorReport`] it is asked to submit. Outcomes are
/// scripted per source IP (see the module doc comment for why): [`Self::script`]
/// queues outcomes for one specific IP, returned in order on successive
/// calls for THAT IP; any IP with nothing scripted (every contaminating
/// approved entry the shared database also hands this vendor) gets an
/// unconditional `Success`. `Clone` shares the same underlying
/// `Arc<Mutex<_>>` state, so a test keeps one handle for assertions while a
/// cloned `Box<dyn VendorAdapter>` is handed to the runner.
#[derive(Clone)]
struct MockVendor {
    vendor_name: &'static str,
    submissions: Arc<Mutex<Vec<VendorReport>>>,
    outcomes: Arc<Mutex<HashMap<IpAddr, VecDeque<MockOutcome>>>>,
}

impl MockVendor {
    fn new(vendor_name: &'static str) -> Self {
        Self {
            vendor_name,
            submissions: Arc::new(Mutex::new(Vec::new())),
            outcomes: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Queue `outcomes` to be returned, in order, for `submit` calls whose
    /// report's `source_ip` is exactly `ip`.
    fn script(&self, ip: IpAddr, outcomes: Vec<MockOutcome>) {
        self.outcomes
            .lock()
            .unwrap()
            .insert(ip, VecDeque::from(outcomes));
    }

    /// Every report submitted whose `source_ip` is exactly `ip` - immune to
    /// any OTHER approved IP the shared `propolis_test` database also hands
    /// this vendor.
    fn submissions_for(&self, ip: IpAddr) -> Vec<VendorReport> {
        self.submissions
            .lock()
            .unwrap()
            .iter()
            .filter(|r| r.source_ip == ip)
            .cloned()
            .collect()
    }

    /// The raw, UNFILTERED number of `submit` calls. Safe to assert `== 0`
    /// only when the gate holds unconditionally for every IP (disabled
    /// vendor, no matching gatekeeper config) - never as a stand-in for "my
    /// IP was not submitted", which a contaminating IP could still make
    /// nonzero.
    fn call_count(&self) -> usize {
        self.submissions.lock().unwrap().len()
    }
}

#[async_trait]
impl VendorAdapter for MockVendor {
    fn name(&self) -> &str {
        self.vendor_name
    }

    async fn submit(&self, report: &VendorReport) -> Result<VendorResponse, VendorError> {
        self.submissions.lock().unwrap().push(report.clone());
        let outcome = {
            let mut m = self.outcomes.lock().unwrap();
            m.get_mut(&report.source_ip)
                .and_then(|q| q.pop_front())
                .unwrap_or(MockOutcome::Success {
                    status: 200,
                    body: "ok",
                })
        };
        match outcome {
            MockOutcome::Success { status, body } => Ok(VendorResponse {
                status,
                body: body.to_string(),
                accepted: true,
            }),
            MockOutcome::Transient { status, body } => Err(VendorError::Transient {
                status,
                body: body.to_string(),
            }),
            MockOutcome::Permanent { status, body } => Err(VendorError::Permanent {
                status,
                body: body.to_string(),
            }),
        }
    }
}

// ---------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------

async fn setup_pool() -> PgPool {
    let url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://propolis:propolis@localhost:5432/propolis_test".into());
    let pool = PgPool::connect(&url).await.unwrap();
    // Run core-scoring migrations first (event/ip_score tables must exist).
    sqlx::migrate!("../core-scoring/migrations")
        .run(&pool)
        .await
        .unwrap();
    // Then this crate's own.
    review::migrator().run(&pool).await.unwrap();
    pool
}

fn ev(
    ip: &str,
    sensor: &str,
    signal: SignalType,
    protocol: Protocol,
    authenticated: bool,
    ts: &str,
    metadata: serde_json::Value,
) -> EventInput {
    EventInput::from_signal(
        ip.parse().unwrap(),
        None,
        sensor.into(),
        signal,
        protocol,
        authenticated,
        ts.parse().unwrap(),
        metadata,
        None,
    )
}

/// Seeds an eligible + vendor-recommended `ip_score` for `ip`: a confirmed-real
/// SSH honeypot login and an SSH brute-force corroboration (both tagged
/// `protocol_label: "ssh"`, matching `sensor-ssh`'s real wire contract), plus
/// a label-less catch-all probe (matching `sensor-catchall`'s real
/// contract). Raw 85 / max_confidence 0.920 clears the Standard tier floor,
/// 3 events across 3 categories clears the eligibility gates - same recipe
/// as `queue_test.rs`'s `seed_recommended`, with real `protocol_label`
/// metadata added so `submit::category_protocol_labels` has something to
/// find.
async fn seed_recommended_ssh(pool: &PgPool, ip: &str) {
    // Recent, ordered event times (a few minutes ago) so the seeded IP passes the gatekeeper's
    // freshness gate. Only recency and order matter here; no assertion references these timestamps.
    let base = Utc::now() - Duration::minutes(5);
    let t0 = base.to_rfc3339();
    let t1 = (base + Duration::seconds(10)).to_rfc3339();
    let t2 = (base + Duration::seconds(20)).to_rfc3339();
    append_event(
        pool,
        ev(
            ip,
            "honeypot-sensor",
            SignalType::HoneypotLoginAttempt,
            Protocol::Tcp,
            true,
            &t0,
            serde_json::json!({"protocol_label": "ssh"}),
        ),
    )
    .await
    .unwrap();
    append_event(
        pool,
        ev(
            ip,
            "ssh-sensor",
            SignalType::SshBruteForce,
            Protocol::Tcp,
            true,
            &t1,
            serde_json::json!({"protocol_label": "ssh"}),
        ),
    )
    .await
    .unwrap();
    append_event(
        pool,
        ev(
            ip,
            "catchall-sensor",
            SignalType::CatchallProbe,
            Protocol::Udp,
            false,
            &t2,
            serde_json::json!({}),
        ),
    )
    .await
    .unwrap();
}

/// A permissive baseline gatekeeper config: enabled, generous cooldown/rate
/// limit, no score floor or category restriction - matching
/// `gatekeeper_test.rs`'s own `permissive_config`.
fn permissive_config(vendor: &str) -> VendorConfig {
    VendorConfig {
        name: vendor.to_string(),
        enabled: true,
        cooldown_hours: 24,
        rate_limit: 1000,
        rate_window_hours: 24,
        score_floor: None,
        category_filter: None,
    }
}

/// Wipes any leftover state for `ip` (every table this suite touches) from a
/// previous run against the persistent, shared `propolis_test` database -
/// matching `queue_test.rs`'s `reset_ip` discipline.
async fn reset(pool: &PgPool, ip: &str) {
    sqlx::query("DELETE FROM vendor_submission WHERE source_ip = $1::inet")
        .bind(ip)
        .execute(pool)
        .await
        .unwrap();
    sqlx::query("DELETE FROM review_queue WHERE source_ip = $1::inet")
        .bind(ip)
        .execute(pool)
        .await
        .unwrap();
    sqlx::query("DELETE FROM ip_score WHERE source_ip = $1::inet")
        .bind(ip)
        .execute(pool)
        .await
        .unwrap();
    sqlx::query("DELETE FROM event WHERE source_ip = $1::inet")
        .bind(ip)
        .execute(pool)
        .await
        .unwrap();
}

/// Additionally wipes any leftover `vendor_submission` rows for `vendor`
/// (regardless of IP) - only needed by the one test that reuses a literal
/// vendor name (`"dshield"`) a real adapter/config would also use; see the
/// module doc comment.
async fn reset_vendor(pool: &PgPool, vendor: &str) {
    sqlx::query("DELETE FROM vendor_submission WHERE vendor = $1")
        .bind(vendor)
        .execute(pool)
        .await
        .unwrap();
}

async fn count_submissions(pool: &PgPool, ip: &str, vendor: &str) -> i64 {
    sqlx::query_scalar(
        "SELECT count(*) FROM vendor_submission WHERE source_ip = $1::inet AND vendor = $2",
    )
    .bind(ip)
    .bind(vendor)
    .fetch_one(pool)
    .await
    .unwrap()
}

struct SubmissionRow {
    success: bool,
    response_status: Option<i32>,
    response_body: Option<String>,
}

/// Fetches the ONE row for `(ip, vendor)` - scoped by both, so this is
/// unaffected by any other IP the shared database also routes through this
/// vendor's own name.
async fn fetch_submission(pool: &PgPool, ip: &str, vendor: &str) -> SubmissionRow {
    let row = sqlx::query(
        "SELECT success, response_status, response_body \
         FROM vendor_submission WHERE source_ip = $1::inet AND vendor = $2",
    )
    .bind(ip)
    .bind(vendor)
    .fetch_one(pool)
    .await
    .unwrap();
    SubmissionRow {
        success: row.get("success"),
        response_status: row.get("response_status"),
        response_body: row.get("response_body"),
    }
}

/// Seeds, populates, and approves `ip` in one call - every test needs this
/// exact sequence before constructing a `SubmissionRunner`.
async fn seed_and_approve(pool: &PgPool, ip: &str) {
    seed_recommended_ssh(pool, ip).await;
    let queue = ReviewQueue::new();
    queue.populate(pool).await.unwrap();
    queue
        .approve(pool, ip.parse().unwrap(), None)
        .await
        .unwrap();
}

// ---------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------

#[tokio::test]
async fn run_once_submits_with_real_protocol_label_mapping() {
    let pool = setup_pool().await;
    let ip = "45.10.32.240";
    let ip_addr: IpAddr = ip.parse().unwrap();
    reset(&pool, ip).await;
    reset_vendor(&pool, "dshield").await;
    seed_and_approve(&pool, ip).await;

    let mock = MockVendor::new("dshield");
    mock.script(
        ip_addr,
        vec![MockOutcome::Success {
            status: 200,
            body: "ok",
        }],
    );
    let vendors: Vec<Box<dyn VendorAdapter>> = vec![Box::new(mock.clone())];
    let runner = SubmissionRunner::new(pool.clone(), vendors, vec![permissive_config("dshield")]);

    runner.run_once().await.unwrap();

    let mine = mock.submissions_for(ip_addr);
    assert_eq!(mine.len(), 1);
    assert_eq!(mine[0].source_ip, ip_addr);
    // Honeypot and Auth both carry protocol_label "ssh" -> the DShield "ssh"
    // tag (not the generic "intrusion" Auth would fall back to without a
    // label); the label-less catch-all's Network category -> "scan". Proves
    // `category_protocol_labels` + `categories_for_vendor`'s dispatch is
    // actually wired end-to-end, not just reachable from unit tests.
    assert_eq!(
        mine[0].categories,
        vec!["ssh".to_string(), "scan".to_string()]
    );
    assert!(!mine[0].comment.is_empty());

    let row = fetch_submission(&pool, ip, "dshield").await;
    assert!(row.success);
    assert_eq!(row.response_status, Some(200));
}

#[tokio::test]
async fn run_once_holds_disabled_vendor_without_writing_a_row() {
    let pool = setup_pool().await;
    let ip = "45.10.32.241";
    reset(&pool, ip).await;
    seed_and_approve(&pool, ip).await;

    let mock = MockVendor::new("mockvendor-disabled");
    let vendors: Vec<Box<dyn VendorAdapter>> = vec![Box::new(mock.clone())];
    let config = VendorConfig {
        enabled: false,
        ..permissive_config("mockvendor-disabled")
    };
    let runner = SubmissionRunner::new(pool.clone(), vendors, vec![config]);

    runner.run_once().await.unwrap();

    // Disabled holds EVERY ip unconditionally (including any contaminating
    // one), so the raw, unfiltered call count is safe to assert here.
    assert_eq!(mock.call_count(), 0, "a held vendor must never be called");
    assert_eq!(count_submissions(&pool, ip, "mockvendor-disabled").await, 0);
}

#[tokio::test]
async fn run_once_records_failed_submission() {
    let pool = setup_pool().await;
    let ip = "45.10.32.242";
    let ip_addr: IpAddr = ip.parse().unwrap();
    reset(&pool, ip).await;
    seed_and_approve(&pool, ip).await;

    let mock = MockVendor::new("mockvendor-failed");
    mock.script(
        ip_addr,
        vec![MockOutcome::Permanent {
            status: 422,
            body: "invalid ip",
        }],
    );
    let vendors: Vec<Box<dyn VendorAdapter>> = vec![Box::new(mock.clone())];
    let runner = SubmissionRunner::new(
        pool.clone(),
        vendors,
        vec![permissive_config("mockvendor-failed")],
    );

    runner.run_once().await.unwrap();

    let row = fetch_submission(&pool, ip, "mockvendor-failed").await;
    assert!(!row.success);
    assert_eq!(row.response_status, Some(422));
    assert_eq!(row.response_body.as_deref(), Some("invalid ip"));
}

#[tokio::test]
async fn run_once_is_idempotent_across_a_failed_then_successful_retry() {
    let pool = setup_pool().await;
    let ip = "45.10.32.243";
    let ip_addr: IpAddr = ip.parse().unwrap();
    reset(&pool, ip).await;
    seed_and_approve(&pool, ip).await;

    // A transient failure never sets success = true, so neither the
    // cooldown nor the rate-limit check (both filtered to success = TRUE)
    // blocks the second attempt - it reaches the INSERT/adapter.submit
    // dance again, exactly the "retried on the next poll" scenario the
    // design spec describes.
    let mock = MockVendor::new("mockvendor-idempotent");
    mock.script(
        ip_addr,
        vec![
            MockOutcome::Transient {
                status: 503,
                body: "down",
            },
            MockOutcome::Success {
                status: 200,
                body: "ok",
            },
        ],
    );
    let vendors: Vec<Box<dyn VendorAdapter>> = vec![Box::new(mock.clone())];
    let runner = SubmissionRunner::new(
        pool.clone(),
        vendors,
        vec![permissive_config("mockvendor-idempotent")],
    );

    runner.run_once().await.unwrap();
    runner.run_once().await.unwrap();

    assert_eq!(
        mock.submissions_for(ip_addr).len(),
        2,
        "this ip is genuinely retried, not skipped, while still failed"
    );
    assert_eq!(
        count_submissions(&pool, ip, "mockvendor-idempotent").await,
        1,
        "the UNIQUE idempotency key must collapse both attempts into one row, never two"
    );
    let row = fetch_submission(&pool, ip, "mockvendor-idempotent").await;
    assert!(
        row.success,
        "the row must reflect the LATEST attempt's outcome"
    );
    assert_eq!(row.response_status, Some(200));
}

/// The crash window: an earlier attempt today inserted its pending row, called the vendor, and
/// died before `record_result` ran. Its row shows `success = false` with NO response recorded.
/// The cooldown check filters on `success = TRUE`, so it cannot hold this; the runner must
/// recognise the unrecorded outcome itself and not call the vendor again - the vendor may have
/// accepted that report, and a second call would report the IP twice.
#[tokio::test]
async fn run_once_does_not_resubmit_when_an_earlier_attempt_left_no_recorded_outcome() {
    let pool = setup_pool().await;
    let ip = "45.10.32.248";
    let ip_addr: IpAddr = ip.parse().unwrap();
    let vendor = "mockvendor-crashwindow";
    reset(&pool, ip).await;
    seed_and_approve(&pool, ip).await;

    // Today's row exactly as `insert_pending` leaves it before the vendor call.
    let key = format!("{ip}:{vendor}:{}", Utc::now().date_naive());
    sqlx::query(
        "INSERT INTO vendor_submission \
         (source_ip, vendor, idempotency_key, categories, comment, success) \
         VALUES ($1::inet, $2, $3, '{}', '', FALSE)",
    )
    .bind(ip)
    .bind(vendor)
    .bind(&key)
    .execute(&pool)
    .await
    .unwrap();

    let mock = MockVendor::new(vendor);
    mock.script(
        ip_addr,
        vec![MockOutcome::Success {
            status: 200,
            body: "ok",
        }],
    );
    let vendors: Vec<Box<dyn VendorAdapter>> = vec![Box::new(mock.clone())];
    let runner = SubmissionRunner::new(pool.clone(), vendors, vec![permissive_config(vendor)]);
    let result = runner.run_once().await.unwrap();

    assert!(
        mock.submissions_for(ip_addr).is_empty(),
        "an attempt with an unrecorded outcome must not be re-sent to the vendor"
    );
    assert!(
        result.unresolved >= 1,
        "the skip must be counted as unresolved, not silently dropped: {result:?}"
    );
    assert_eq!(count_submissions(&pool, ip, vendor).await, 1);
    let row = fetch_submission(&pool, ip, vendor).await;
    assert!(
        !row.success,
        "nothing may rewrite the unknown outcome as a result"
    );
    assert_eq!(row.response_status, None);
}

#[tokio::test]
async fn run_once_repeat_call_after_success_is_held_by_cooldown_not_resubmitted() {
    let pool = setup_pool().await;
    let ip = "45.10.32.244";
    let ip_addr: IpAddr = ip.parse().unwrap();
    reset(&pool, ip).await;
    seed_and_approve(&pool, ip).await;

    let mock = MockVendor::new("mockvendor-cooldown");
    mock.script(
        ip_addr,
        vec![MockOutcome::Success {
            status: 200,
            body: "ok",
        }],
    );
    let vendors: Vec<Box<dyn VendorAdapter>> = vec![Box::new(mock.clone())];
    let runner = SubmissionRunner::new(
        pool.clone(),
        vendors,
        vec![permissive_config("mockvendor-cooldown")],
    );

    runner.run_once().await.unwrap();
    assert_eq!(count_submissions(&pool, ip, "mockvendor-cooldown").await, 1);

    // Same day, cooldown_hours = 24 (permissive default): the gatekeeper's
    // own cooldown check now finds this IP's successful submission from
    // moments ago and holds the repeat, before this module would ever
    // re-INSERT the same idempotency key.
    runner.run_once().await.unwrap();

    assert_eq!(
        mock.submissions_for(ip_addr).len(),
        1,
        "cooldown must prevent a second real vendor call for this ip in normal operation"
    );
    assert_eq!(count_submissions(&pool, ip, "mockvendor-cooldown").await, 1);
}

#[tokio::test]
async fn run_once_ignores_entries_that_are_not_approved() {
    let pool = setup_pool().await;
    let ip = "45.10.32.245";
    let ip_addr: IpAddr = ip.parse().unwrap();
    reset(&pool, ip).await;
    seed_recommended_ssh(&pool, ip).await;
    // Populate only - left Pending, never approved.
    ReviewQueue::new().populate(&pool).await.unwrap();

    let mock = MockVendor::new("mockvendor-nonapproved");
    let vendors: Vec<Box<dyn VendorAdapter>> = vec![Box::new(mock.clone())];
    let runner = SubmissionRunner::new(
        pool.clone(),
        vendors,
        vec![permissive_config("mockvendor-nonapproved")],
    );

    // Not asserting on the returned SubmitResult: the shared database may
    // carry unrelated Approved entries (see the module doc comment), so
    // only THIS ip's own absence is the invariant under test here.
    runner.run_once().await.unwrap();

    assert!(
        mock.submissions_for(ip_addr).is_empty(),
        "the human-approval gate: a Pending entry must never be submitted"
    );
    assert_eq!(
        count_submissions(&pool, ip, "mockvendor-nonapproved").await,
        0
    );
}

#[tokio::test]
async fn run_once_gates_each_configured_vendor_independently() {
    let pool = setup_pool().await;
    let ip = "45.10.32.246";
    let ip_addr: IpAddr = ip.parse().unwrap();
    reset(&pool, ip).await;
    seed_and_approve(&pool, ip).await;

    let passing = MockVendor::new("mockvendor-multi-pass");
    passing.script(
        ip_addr,
        vec![MockOutcome::Success {
            status: 200,
            body: "ok",
        }],
    );
    let disabled = MockVendor::new("mockvendor-multi-disabled");
    let vendors: Vec<Box<dyn VendorAdapter>> =
        vec![Box::new(passing.clone()), Box::new(disabled.clone())];
    let configs = vec![
        permissive_config("mockvendor-multi-pass"),
        VendorConfig {
            enabled: false,
            ..permissive_config("mockvendor-multi-disabled")
        },
    ];
    let runner = SubmissionRunner::new(pool.clone(), vendors, configs);

    runner.run_once().await.unwrap();

    assert_eq!(passing.submissions_for(ip_addr).len(), 1);
    // Disabled holds unconditionally, so the raw count is safe here too.
    assert_eq!(disabled.call_count(), 0);
}

#[tokio::test]
async fn run_once_holds_vendor_with_no_matching_gatekeeper_config() {
    let pool = setup_pool().await;
    let ip = "45.10.32.247";
    reset(&pool, ip).await;
    seed_and_approve(&pool, ip).await;

    let mock = MockVendor::new("mockvendor-unconfigured");
    let vendors: Vec<Box<dyn VendorAdapter>> = vec![Box::new(mock.clone())];
    // No entry in gatekeeper_config matches this adapter's name, so it holds
    // unconditionally for every ip - the raw call count is safe here too.
    let runner = SubmissionRunner::new(pool.clone(), vendors, vec![]);

    runner.run_once().await.unwrap();

    assert_eq!(mock.call_count(), 0);
    assert_eq!(
        count_submissions(&pool, ip, "mockvendor-unconfigured").await,
        0
    );
}
