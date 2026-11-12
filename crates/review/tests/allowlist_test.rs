//! Real-Postgres tests for the operator allowlist in the review stage: an allowlisted address is
//! never queued, a pending one is withdrawn with its reason logged, and the submission runner
//! refuses one even if it was queued and approved before the allowlist covered it.
//!
//! Each test owns a fresh database (`#[sqlx::test]`), so `populate` and `run_once`, which act on
//! the whole table, only ever see the test's own rows. Addresses come from `45.10.33.0/24`
//! (ordinary public-looking addresses: the gatekeeper refuses reserved ranges outright, so a
//! documentation-range fixture would be held as `Reserved` before the allowlist behaviour under
//! test was reached). The allowlisted block is `45.10.33.16/29`; the control addresses sit
//! outside it.

use std::io::Write;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use chrono::{Duration, Utc};
use core_scoring::{
    EventInput, OperatorAllowlist, Protocol, ReviewState, SignalType, append_event,
};
use sqlx::PgPool;
use tracing_subscriber::fmt::MakeWriter;

use review::gatekeeper::VendorConfig;
use review::queue::ReviewQueue;
use review::submit::SubmissionRunner;
use review::vendor::{VendorAdapter, VendorError, VendorReport, VendorResponse};

fn allowlist() -> Arc<OperatorAllowlist> {
    Arc::new(OperatorAllowlist::new(vec![
        "45.10.33.16/29".parse().unwrap(),
    ]))
}

async fn migrate(pool: &PgPool) {
    sqlx::migrate!("../core-scoring/migrations")
        .run(pool)
        .await
        .unwrap();
    review::migrator().run(pool).await.unwrap();
}

/// Seeds an eligible, vendor-recommended, recently active projection for `ip`: a confirmed-real
/// honeypot login plus SSH brute force and a catch-all probe (raw 85, three categories), with
/// recent timestamps so the gatekeeper's freshness gate passes.
async fn seed_recommended(pool: &PgPool, ip: &str) {
    let base = Utc::now() - Duration::minutes(5);
    let events = [
        (SignalType::HoneypotLoginAttempt, Protocol::Tcp, true, 0),
        (SignalType::SshBruteForce, Protocol::Tcp, true, 10),
        (SignalType::CatchallProbe, Protocol::Udp, false, 20),
    ];
    for (signal, protocol, authenticated, offset) in events {
        let ts = (base + Duration::seconds(offset)).to_rfc3339();
        append_event(
            pool,
            EventInput::from_signal(
                ip.parse().unwrap(),
                None,
                "allowlist-test-sensor".into(),
                signal,
                protocol,
                authenticated,
                ts.parse().unwrap(),
                serde_json::json!({"protocol_label": "ssh"}),
                None,
            ),
        )
        .await
        .unwrap();
    }
}

async fn state_of(pool: &PgPool, ip: &str) -> Option<ReviewState> {
    sqlx::query_scalar("SELECT state FROM review_queue WHERE source_ip = $1::inet")
        .bind(ip)
        .fetch_optional(pool)
        .await
        .unwrap()
}

/// Captures formatted log output so a test can assert on the recorded withdrawal reason.
#[derive(Clone, Default)]
struct LogCapture(Arc<Mutex<Vec<u8>>>);

impl Write for LogCapture {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'a> MakeWriter<'a> for LogCapture {
    type Writer = LogCapture;
    fn make_writer(&'a self) -> Self::Writer {
        self.clone()
    }
}

impl LogCapture {
    fn text(&self) -> String {
        String::from_utf8_lossy(&self.0.lock().unwrap()).into_owned()
    }
}

#[derive(Clone)]
struct RecordingVendor {
    name: &'static str,
    seen: Arc<Mutex<Vec<IpAddr>>>,
}

#[async_trait]
impl VendorAdapter for RecordingVendor {
    fn name(&self) -> &str {
        self.name
    }

    async fn submit(&self, report: &VendorReport) -> Result<VendorResponse, VendorError> {
        self.seen.lock().unwrap().push(report.source_ip);
        Ok(VendorResponse {
            status: 200,
            body: "ok".into(),
            accepted: true,
        })
    }
}

#[sqlx::test(migrations = false)]
async fn an_allowlisted_address_meeting_the_threshold_is_not_queued(pool: PgPool) {
    migrate(&pool).await;
    let (listed, control) = ("45.10.33.17", "45.10.33.40");
    for ip in [listed, control] {
        seed_recommended(&pool, ip).await;
    }

    ReviewQueue::new()
        .with_allowlist(allowlist())
        .populate(&pool)
        .await
        .unwrap();

    assert_eq!(
        state_of(&pool, listed).await,
        None,
        "allowlisted: not queued"
    );
    assert_eq!(
        state_of(&pool, control).await,
        Some(ReviewState::Pending),
        "a non-allowlisted address is queued exactly as before"
    );
    // Scoring is untouched: the allowlisted address keeps its recommendation.
    let recommended: bool = sqlx::query_scalar(
        "SELECT recommended_for_vendor FROM ip_score WHERE source_ip = $1::inet",
    )
    .bind(listed)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert!(recommended);
}

#[sqlx::test(migrations = false)]
async fn an_already_pending_allowlisted_address_is_withdrawn_with_its_reason(pool: PgPool) {
    migrate(&pool).await;
    let (listed, approved_listed, control) = ("45.10.33.18", "45.10.33.19", "45.10.33.41");
    for ip in [listed, approved_listed, control] {
        seed_recommended(&pool, ip).await;
    }
    // Queued while no allowlist covered them.
    let plain = ReviewQueue::new();
    plain.populate(&pool).await.unwrap();
    plain
        .approve(&pool, approved_listed.parse().unwrap(), None)
        .await
        .unwrap();
    assert_eq!(state_of(&pool, listed).await, Some(ReviewState::Pending));

    let log = LogCapture::default();
    let subscriber = tracing_subscriber::fmt()
        .with_writer(log.clone())
        .with_ansi(false)
        .finish();
    let guard = tracing::subscriber::set_default(subscriber);
    let removed = ReviewQueue::new()
        .with_allowlist(allowlist())
        .withdraw(&pool)
        .await
        .unwrap();
    drop(guard);

    assert!(removed >= 1);
    assert_eq!(state_of(&pool, listed).await, None, "pending: withdrawn");
    assert_eq!(
        state_of(&pool, approved_listed).await,
        Some(ReviewState::Approved),
        "an operator decision is never undone by the scan"
    );
    assert_eq!(
        state_of(&pool, control).await,
        Some(ReviewState::Pending),
        "a non-allowlisted pending entry is untouched"
    );
    let text = log.text();
    assert!(
        text.contains("allowlisted") && text.contains(listed),
        "the withdrawal must record its reason and address, got: {text}"
    );
}

#[sqlx::test(migrations = false)]
async fn a_withdrawn_address_is_surfaced_again_when_it_leaves_the_allowlist(pool: PgPool) {
    migrate(&pool).await;
    let ip = "45.10.33.21";
    seed_recommended(&pool, ip).await;
    let listed = ReviewQueue::new().with_allowlist(allowlist());
    listed.populate(&pool).await.unwrap();
    assert_eq!(state_of(&pool, ip).await, None);

    ReviewQueue::new().populate(&pool).await.unwrap();
    assert_eq!(state_of(&pool, ip).await, Some(ReviewState::Pending));
}

#[sqlx::test(migrations = false)]
async fn the_runner_refuses_an_allowlisted_address_queued_before_the_allowlist_changed(
    pool: PgPool,
) {
    migrate(&pool).await;
    let (listed, control) = ("45.10.33.20", "45.10.33.42");
    for ip in [listed, control] {
        seed_recommended(&pool, ip).await;
    }
    // Queued and approved while the allowlist was empty.
    let plain = ReviewQueue::new();
    plain.populate(&pool).await.unwrap();
    for ip in [listed, control] {
        plain
            .approve(&pool, ip.parse().unwrap(), None)
            .await
            .unwrap();
    }

    let vendor = RecordingVendor {
        name: "allowlist-test-vendor",
        seen: Arc::default(),
    };
    let config = VendorConfig {
        name: vendor.name.to_string(),
        enabled: true,
        cooldown_hours: 24,
        rate_limit: 1000,
        rate_window_hours: 24,
        score_floor: None,
        category_filter: None,
    };
    let runner = SubmissionRunner::new(pool.clone(), vec![Box::new(vendor.clone())], vec![config])
        .with_allowlist(allowlist());

    let result = runner.run_once().await.unwrap();

    let seen = vendor.seen.lock().unwrap().clone();
    let listed_ip: IpAddr = listed.parse().unwrap();
    let control_ip: IpAddr = control.parse().unwrap();
    assert!(!seen.contains(&listed_ip), "allowlisted: never submitted");
    assert!(seen.contains(&control_ip), "control: submitted as before");
    assert!(result.held >= 1);
    let rows: i64 =
        sqlx::query_scalar("SELECT count(*) FROM vendor_submission WHERE source_ip = $1::inet")
            .bind(listed)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(
        rows, 0,
        "no vendor_submission row is written for a refused address"
    );
}
