//! Real-Postgres, mock-vendor tests for the submission runner (Task 4).
//!
//! Each test owns a fresh database (`#[sqlx::test]`). That matters because
//! `SubmissionRunner::run_once` (unlike `gatekeeper::check` or
//! `ReviewQueue::approve`) has no IP parameter at all - by design, it polls
//! `review_queue` for EVERY Approved entry, table-wide - so on a database
//! shared with other tests or crates, rows those leave Approved would reach
//! `adapter.submit` alongside the test's own IP.
//!
//! The fixture addresses are in 203.0.113.0/24, the one documentation block the
//! `test-public-ranges` feature (`review::reserved`, enabled for this crate's
//! own test builds) treats as public, and must stay in it: the gatekeeper's
//! first check refuses every reserved range outright, so a fixture in any other
//! documentation block is held as `Reserved` before the runner behaviour under
//! test is ever reached. Assertions stay scoped to
//! `(this test's ip, this test's vendor name)` rather than the aggregate
//! `SubmitResult`, which keeps them independent of fixture count.
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
use core_scoring::{EventInput, Protocol, SignalType, append_event, append_events};
use sqlx::{PgPool, Row};

use review::gatekeeper::VendorConfig;
use review::queue::ReviewQueue;
use review::submit::SubmissionRunner;
use review::vendor::{VendorAdapter, VendorError, VendorReport, VendorResponse};
use review::volume::VolumeQueue;

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
    /// any OTHER approved IP the test's database also hands this vendor.
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

async fn migrate(pool: &PgPool) {
    // Core-scoring first (event/ip_score tables must exist), then this crate's own.
    sqlx::migrate!("../core-scoring/migrations")
        .run(pool)
        .await
        .unwrap();
    review::migrator().run(pool).await.unwrap();
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
    // freshness gate.
    seed_recommended_ssh_at(pool, ip, Utc::now() - Duration::minutes(5)).await;
}

/// [`seed_recommended_ssh`] with the first event at `base` and the last twenty seconds later,
/// which is then the address's last established sighting and the time it earned its tier.
async fn seed_recommended_ssh_at(pool: &PgPool, ip: &str, base: chrono::DateTime<Utc>) {
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
            Protocol::Tcp,
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

#[sqlx::test(migrations = false)]
async fn run_once_submits_with_real_protocol_label_mapping(pool: PgPool) {
    migrate(&pool).await;
    let ip = "203.0.113.240";
    let ip_addr: IpAddr = ip.parse().unwrap();
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

#[sqlx::test(migrations = false)]
async fn run_once_holds_disabled_vendor_without_writing_a_row(pool: PgPool) {
    migrate(&pool).await;
    let ip = "203.0.113.241";
    seed_and_approve(&pool, ip).await;

    let mock = MockVendor::new("mockvendor-disabled");
    let vendors: Vec<Box<dyn VendorAdapter>> = vec![Box::new(mock.clone())];
    let config = VendorConfig {
        enabled: false,
        ..permissive_config("mockvendor-disabled")
    };
    let runner = SubmissionRunner::new(pool.clone(), vendors, vec![config]);

    let result = runner.run_once().await.unwrap();

    // Disabled holds EVERY ip unconditionally (including any contaminating
    // one), so the raw, unfiltered call count is safe to assert here.
    assert_eq!(mock.call_count(), 0, "a held vendor must never be called");
    assert_eq!(count_submissions(&pool, ip, "mockvendor-disabled").await, 0);
    // The hold must be the disabled vendor, not the reserved-address check that runs first: a
    // reserved fixture address would pass the two asserts above for the wrong reason.
    assert!(
        result.held_by.disabled >= 1,
        "held as disabled: {:?}",
        result.held_by
    );
    assert_eq!(
        result.held_by.reserved, 0,
        "the fixture address must not be reserved"
    );
}

#[sqlx::test(migrations = false)]
async fn run_once_records_failed_submission(pool: PgPool) {
    migrate(&pool).await;
    let ip = "203.0.113.242";
    let ip_addr: IpAddr = ip.parse().unwrap();
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

#[sqlx::test(migrations = false)]
async fn run_once_is_idempotent_across_a_failed_then_successful_retry(pool: PgPool) {
    migrate(&pool).await;
    let ip = "203.0.113.243";
    let ip_addr: IpAddr = ip.parse().unwrap();
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
#[sqlx::test(migrations = false)]
async fn run_once_does_not_resubmit_when_an_earlier_attempt_left_no_recorded_outcome(pool: PgPool) {
    migrate(&pool).await;
    let ip = "203.0.113.248";
    let ip_addr: IpAddr = ip.parse().unwrap();
    let vendor = "mockvendor-crashwindow";
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

#[sqlx::test(migrations = false)]
async fn run_once_repeat_call_after_success_is_held_by_cooldown_not_resubmitted(pool: PgPool) {
    migrate(&pool).await;
    let ip = "203.0.113.244";
    let ip_addr: IpAddr = ip.parse().unwrap();
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

#[sqlx::test(migrations = false)]
async fn run_once_ignores_entries_that_are_not_approved(pool: PgPool) {
    migrate(&pool).await;
    let ip = "203.0.113.245";
    let ip_addr: IpAddr = ip.parse().unwrap();
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

/// An approval in the volume queue publishes an address in the retention feeds. It is not an
/// approval to report the address: the runner's input is `review_queue` alone. The flood here is
/// everything the gatekeeper would otherwise pass (public, seen minutes ago, never reported), so
/// only the runner never being handed it keeps it from the vendor.
#[sqlx::test(migrations = false)]
async fn run_once_never_submits_an_address_approved_only_as_a_volume_candidate(pool: PgPool) {
    migrate(&pool).await;
    let flood = "203.0.113.246";
    let flood_addr: IpAddr = flood.parse().unwrap();
    let last = Utc::now() - Duration::minutes(5);
    let connections: Vec<EventInput> = (0..1000)
        .map(|i| {
            ev(
                flood,
                "ssh-sensor",
                SignalType::HoneypotConnection,
                Protocol::Tcp,
                false,
                &(last - Duration::milliseconds(999 - i)).to_rfc3339(),
                serde_json::json!({"protocol_label": "ssh"}),
            )
        })
        .collect();
    assert!(append_events(&pool, connections).await.failure.is_none());
    let volume = VolumeQueue::new();
    assert_eq!(volume.populate(&pool).await.unwrap(), 1);
    volume
        .approve(&pool, flood_addr, Some("flooding ssh"))
        .await
        .unwrap();

    // The control: an address approved in the review queue, which the same pass must report, so
    // a runner that submitted nothing at all would not pass this test.
    let reported = "203.0.113.247";
    seed_and_approve(&pool, reported).await;

    let mock = MockVendor::new("mockvendor-volume");
    let vendors: Vec<Box<dyn VendorAdapter>> = vec![Box::new(mock.clone())];
    let runner = SubmissionRunner::new(
        pool.clone(),
        vendors,
        vec![permissive_config("mockvendor-volume")],
    );

    let result = runner.run_once().await.unwrap();

    assert_eq!(mock.submissions_for(reported.parse().unwrap()).len(), 1);
    assert!(
        mock.submissions_for(flood_addr).is_empty(),
        "a volume approval must never reach a vendor"
    );
    assert_eq!(mock.call_count(), 1);
    assert_eq!(result.submitted, 1);
    assert_eq!(
        count_submissions(&pool, flood, "mockvendor-volume").await,
        0
    );
    let any_for_flood: i64 =
        sqlx::query_scalar("SELECT count(*) FROM vendor_submission WHERE source_ip = $1::inet")
            .bind(flood)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(any_for_flood, 0);
}

#[sqlx::test(migrations = false)]
async fn run_once_gates_each_configured_vendor_independently(pool: PgPool) {
    migrate(&pool).await;
    let ip = "203.0.113.246";
    let ip_addr: IpAddr = ip.parse().unwrap();
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

// Live: "submitted=0 held=17202" every pass with the reason per (ip, vendor) at debug only, so
// nothing said WHY nothing was submitted. The pass result now carries the held count by reason.
#[sqlx::test(migrations = false)]
async fn run_once_reports_held_pairs_by_reason(pool: PgPool) {
    migrate(&pool).await;
    seed_and_approve(&pool, "203.0.113.240").await;

    let vendors: Vec<Box<dyn VendorAdapter>> = vec![
        Box::new(MockVendor::new("mockvendor-held-off")),
        Box::new(MockVendor::new("mockvendor-held-floor")),
        Box::new(MockVendor::new("mockvendor-held-noconfig")),
    ];
    let configs = vec![
        VendorConfig {
            enabled: false,
            ..permissive_config("mockvendor-held-off")
        },
        VendorConfig {
            score_floor: Some(rust_decimal::Decimal::from(100_000)),
            ..permissive_config("mockvendor-held-floor")
        },
    ];
    let result = SubmissionRunner::new(pool.clone(), vendors, configs)
        .run_once()
        .await
        .unwrap();

    assert_eq!(result.submitted, 0);
    assert_eq!(result.held, 3);
    assert_eq!(result.held_by.disabled, 1);
    assert_eq!(result.held_by.score_floor, 1);
    assert_eq!(result.held_by.no_vendor_config, 1);
    assert_eq!(
        result.held_by.total(),
        result.held,
        "every hold has a reason"
    );
    assert_eq!(
        result.held_by.to_string(),
        "no_vendor_config=1 disabled=1 score_floor=1"
    );
}

#[sqlx::test(migrations = false)]
async fn run_once_holds_vendor_with_no_matching_gatekeeper_config(pool: PgPool) {
    migrate(&pool).await;
    let ip = "203.0.113.247";
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

/// The statements sqlx logs while the guard is held: sqlx emits each at DEBUG on the
/// `sqlx::query` target with the SQL text in `db.statement`.
#[derive(Clone, Default)]
struct StatementLog(Arc<Mutex<Vec<String>>>);

struct StatementText(Option<String>);

impl tracing::field::Visit for StatementText {
    fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
        if field.name() == "db.statement" {
            self.0 = Some(value.to_string());
        }
    }
    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        if field.name() == "db.statement" {
            self.0 = Some(format!("{value:?}"));
        }
    }
}

impl<S: tracing::Subscriber> tracing_subscriber::Layer<S> for StatementLog {
    fn on_event(
        &self,
        event: &tracing::Event<'_>,
        _ctx: tracing_subscriber::layer::Context<'_, S>,
    ) {
        if event.metadata().target() == "sqlx::query" {
            let mut text = StatementText(None);
            event.record(&mut text);
            if let Some(sql) = text.0 {
                self.0.lock().unwrap().push(sql);
            }
        }
    }
}

/// Holds the capture open. Dropping it ends the capture.
struct CaptureGuard {
    _default: tracing::subscriber::DefaultGuard,
    _second: tracing::Dispatch,
}

impl StatementLog {
    /// Captures on this thread until the guard is dropped.
    ///
    /// The guard also keeps a second, do-nothing dispatcher alive. While exactly one dispatcher
    /// exists in the process, `tracing` decides whether a callsite is enabled by asking the
    /// default dispatcher of whichever thread happens to register or rebuild it. Tests run on
    /// parallel threads and only this one has the capturing subscriber, so another test's thread
    /// could mark sqlx's statement callsite as never enabled and this capture then saw no
    /// statement at all (about one run in ten). With two dispatchers registered `tracing` asks
    /// each of them instead, whatever thread it is on.
    fn capture() -> (Self, CaptureGuard) {
        use tracing_subscriber::prelude::*;
        let log = StatementLog::default();
        let subscriber = tracing_subscriber::registry()
            .with(log.clone())
            .with(tracing_subscriber::filter::LevelFilter::DEBUG);
        let second = tracing::Dispatch::new(tracing::subscriber::NoSubscriber::default());
        let guard = CaptureGuard {
            _default: tracing::subscriber::set_default(subscriber),
            _second: second,
        };
        (log, guard)
    }

    fn count(&self, needle: &str) -> usize {
        self.0
            .lock()
            .unwrap()
            .iter()
            .filter(|sql| sql.contains(needle))
            .count()
    }
}

/// A pass over many addresses that are all held by cooldown (the steady state: every approved
/// address stays Approved) used to run one cooldown lookup per address and vendor, plus one
/// protocol-label query per address that no held pair ever uses. 5,600 addresses and three vendors
/// made 17,000 of the first on the live node, each timed by sqlx as a stall.
#[sqlx::test(migrations = false)]
async fn a_pass_over_held_addresses_reads_cooldowns_in_one_query(pool: PgPool) {
    migrate(&pool).await;
    const ADDRESSES: usize = 12;
    for n in 0..ADDRESSES {
        seed_and_approve(&pool, &format!("203.0.113.{}", 20 + n)).await;
    }
    let vendors: Vec<Box<dyn VendorAdapter>> = vec![
        Box::new(MockVendor::new("dshield")),
        Box::new(MockVendor::new("otx")),
    ];
    let runner = SubmissionRunner::new(
        pool.clone(),
        vendors,
        vec![permissive_config("dshield"), permissive_config("otx")],
    );

    // The first pass submits everything and so puts every pair into cooldown.
    let first = runner.run_once().await.unwrap();
    assert_eq!(first.submitted, ADDRESSES * 2);

    let (log, guard) = StatementLog::capture();
    let second = runner.run_once().await.unwrap();
    drop(guard);

    assert_eq!(second.held, ADDRESSES * 2);
    assert_eq!(second.held_by.cooldown, ADDRESSES * 2);
    assert_eq!(second.submitted, 0);
    assert_eq!(
        log.count("ORDER BY submitted_at DESC LIMIT 1"),
        0,
        "no per-pair cooldown lookup"
    );
    assert_eq!(
        log.count("MAX(submitted_at)"),
        1,
        "one batched cooldown read for the whole pass"
    );
    assert_eq!(
        log.count("enum_range"),
        0,
        "no protocol-label read for an address every vendor held"
    );
}

// ---------------------------------------------------------------------
// What may be reported, and what a report says
// ---------------------------------------------------------------------

/// Moves everything this node knows about `ip` back by `by`: the times on its score row and its
/// vendor submissions, whose day-scoped idempotency key is rewritten so that "today" is free
/// again. What a test then does happens `by` later than what it did before.
async fn age(pool: &PgPool, ip: &str, by: Duration) {
    let secs = by.num_seconds() as f64;
    sqlx::query(
        "UPDATE ip_score SET \
             decay_anchor = decay_anchor - make_interval(secs => $2), \
             first_seen = first_seen - make_interval(secs => $2), \
             last_seen = last_seen - make_interval(secs => $2), \
             established_last_seen = established_last_seen - make_interval(secs => $2), \
             aggressive_earned_at = aggressive_earned_at - make_interval(secs => $2), \
             standard_earned_at = standard_earned_at - make_interval(secs => $2) \
         WHERE source_ip = $1::inet",
    )
    .bind(ip)
    .bind(secs)
    .execute(pool)
    .await
    .unwrap();
    sqlx::query(
        "UPDATE vendor_submission SET \
             submitted_at = submitted_at - make_interval(secs => $2), \
             idempotency_key = idempotency_key || ':aged' \
         WHERE source_ip = $1::inet",
    )
    .bind(ip)
    .bind(secs)
    .execute(pool)
    .await
    .unwrap();
}

/// What one forged packet at the DNS listener leaves in the ledger: a `honeypot_connection` over
/// UDP, in the Honeypot category, labelled `dns`.
fn dns_datagram(ip: &str) -> EventInput {
    ev(
        ip,
        "dns",
        SignalType::HoneypotConnection,
        Protocol::Udp,
        false,
        &Utc::now().to_rfc3339(),
        serde_json::json!({"protocol_label": "dns"}),
    )
}

/// An approved address was reported again every cooldown for as long as anything kept its
/// `last_seen` inside 48 hours, and one datagram a day under its address was enough: the gate
/// never asked whether the address still merited a report. It now reports what the address
/// EARNED, once.
#[sqlx::test(migrations = false)]
async fn an_address_kept_fresh_only_by_datagrams_is_reported_once_not_every_cooldown(pool: PgPool) {
    migrate(&pool).await;
    let ip = "203.0.113.60";
    let addr: IpAddr = ip.parse().unwrap();
    seed_and_approve(&pool, ip).await;
    let vendor = MockVendor::new("abuseipdb");
    let runner = SubmissionRunner::new(
        pool.clone(),
        vec![Box::new(vendor.clone())],
        vec![permissive_config("abuseipdb")],
    );

    assert_eq!(runner.run_once().await.unwrap().submitted, 1);

    // Twenty-five hours on: the cooldown is over, and a datagram names the address now.
    age(&pool, ip, Duration::hours(25)).await;
    append_event(&pool, dns_datagram(ip)).await.unwrap();
    let score = core_scoring::read_score(&pool, addr)
        .await
        .unwrap()
        .unwrap();
    assert!(
        Utc::now() - score.last_seen < Duration::minutes(1),
        "precondition: the datagram made the address look seen just now"
    );

    let second = runner.run_once().await.unwrap();
    assert_eq!(
        second.submitted, 0,
        "nothing new was earned since the report"
    );
    assert_eq!(second.held_by.stale, 1);
    assert_eq!(vendor.submissions_for(addr).len(), 1);

    // Another day of datagrams changes nothing, and past 48 hours nothing would be fresh anyway.
    age(&pool, ip, Duration::hours(25)).await;
    append_event(&pool, dns_datagram(ip)).await.unwrap();
    assert_eq!(runner.run_once().await.unwrap().submitted, 0);

    // The address comes back and earns its tier again: that is reported.
    seed_recommended_ssh_at(&pool, ip, Utc::now() - Duration::minutes(2)).await;
    let third = runner.run_once().await.unwrap();
    assert_eq!(third.submitted, 1, "{:?}", third.held_by);
    assert_eq!(vendor.submissions_for(addr).len(), 2);
}

/// Approved late: the address earned its tier more than 48 hours ago and has only been named by
/// datagrams since. Nothing is reported, however fresh `last_seen` looks.
#[sqlx::test(migrations = false)]
async fn a_tier_earned_days_ago_is_not_reported_because_a_datagram_named_the_address_today(
    pool: PgPool,
) {
    migrate(&pool).await;
    let ip = "203.0.113.61";
    seed_and_approve(&pool, ip).await;
    age(&pool, ip, Duration::hours(49)).await;
    append_event(&pool, dns_datagram(ip)).await.unwrap();

    let vendor = MockVendor::new("abuseipdb");
    let runner = SubmissionRunner::new(
        pool.clone(),
        vec![Box::new(vendor.clone())],
        vec![permissive_config("abuseipdb")],
    );
    let pass = runner.run_once().await.unwrap();
    assert_eq!(pass.submitted, 0);
    assert_eq!(pass.held_by.stale, 1);
    assert_eq!(vendor.call_count(), 0);
}

/// The report itself is built from what connections showed. A datagram under the address must
/// change neither the attack time a vendor is given nor the category codes: one forged DNS query
/// used to turn a report of an SSH session into a generic one, dated by the forged packet.
#[sqlx::test(migrations = false)]
async fn a_report_gives_the_last_connection_and_its_labels_whatever_datagrams_followed(
    pool: PgPool,
) {
    migrate(&pool).await;
    let named = "203.0.113.62";
    let control = "203.0.113.63";
    let base = Utc::now() - Duration::minutes(5);
    for ip in [named, control] {
        seed_recommended_ssh_at(&pool, ip, base).await;
    }
    let queue = ReviewQueue::new();
    queue.populate(&pool).await.unwrap();
    for ip in [named, control] {
        queue
            .approve(&pool, ip.parse().unwrap(), None)
            .await
            .unwrap();
    }
    append_event(&pool, dns_datagram(named)).await.unwrap();

    let vendor = MockVendor::new("abuseipdb");
    let runner = SubmissionRunner::new(
        pool.clone(),
        vec![Box::new(vendor.clone())],
        vec![permissive_config("abuseipdb")],
    );
    assert_eq!(runner.run_once().await.unwrap().submitted, 2);

    let report = &vendor.submissions_for(named.parse().unwrap())[0];
    let expected = &vendor.submissions_for(control.parse().unwrap())[0];
    let last_connection = base + Duration::seconds(20);
    assert!(
        (report.evidence_window.1 - last_connection)
            .num_milliseconds()
            .abs()
            < 1,
        "attack time {} is the last connection, not the datagram a few minutes later",
        report.evidence_window.1
    );
    assert_eq!(report.evidence_window.1, expected.evidence_window.1);
    assert_eq!(
        report.categories, expected.categories,
        "the datagram's `dns` label must not replace what the SSH session showed"
    );
}

/// `PROPOLIS_FEED_DELIST` took an address out of the published feed and nothing else: an approval
/// given before the operator listed it kept reporting it to every vendor.
#[sqlx::test(migrations = false)]
async fn an_approved_address_on_the_operator_delist_is_held_from_every_vendor(pool: PgPool) {
    migrate(&pool).await;
    let delisted = "203.0.113.64";
    let other = "203.0.113.65";
    for ip in [delisted, other] {
        seed_and_approve(&pool, ip).await;
    }
    let (first, second) = (MockVendor::new("abuseipdb"), MockVendor::new("otx"));
    let delist: std::collections::HashSet<IpAddr> =
        [delisted.parse().unwrap()].into_iter().collect();
    let runner = SubmissionRunner::new(
        pool.clone(),
        vec![Box::new(first.clone()), Box::new(second.clone())],
        vec![permissive_config("abuseipdb"), permissive_config("otx")],
    )
    .with_delist(Arc::new(delist));

    let pass = runner.run_once().await.unwrap();
    assert_eq!(pass.submitted, 2, "the other address goes to both vendors");
    assert_eq!(pass.held, 2);
    assert_eq!(pass.held_by.delisted, 2, "one per vendor");
    for vendor in [&first, &second] {
        assert!(vendor.submissions_for(delisted.parse().unwrap()).is_empty());
    }
    assert_eq!(count_submissions(&pool, delisted, "abuseipdb").await, 0);
}

/// The console's delist latch on the score row holds a report too. Delisting normally deletes
/// the approval; a row that still has one (another node's write, a restore) must not be
/// reported on the strength of a tier it earned before it was delisted.
#[sqlx::test(migrations = false)]
async fn an_approved_address_carrying_the_delist_latch_is_held(pool: PgPool) {
    migrate(&pool).await;
    let ip = "203.0.113.66";
    seed_and_approve(&pool, ip).await;
    sqlx::query("UPDATE ip_score SET delisted = TRUE WHERE source_ip = $1::inet")
        .bind(ip)
        .execute(&pool)
        .await
        .unwrap();
    let vendor = MockVendor::new("abuseipdb");
    let runner = SubmissionRunner::new(
        pool.clone(),
        vec![Box::new(vendor.clone())],
        vec![permissive_config("abuseipdb")],
    );
    let pass = runner.run_once().await.unwrap();
    assert_eq!(pass.submitted, 0);
    assert_eq!(pass.held_by.delisted, 1);
    assert_eq!(vendor.call_count(), 0);
}
