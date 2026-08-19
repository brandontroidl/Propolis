//! Real-Postgres tests for the review queue state machine.
//!
//! Shares the persistent `propolis_test` database with other crates' tests
//! (see the project's `local-gate-toolchain` note): core-scoring's migrations
//! run first (`event`/`ip_score` tables), then this crate's own. Every test
//! uses a distinct source IP (RFC5737 documentation ranges) never reused by
//! another test in this file, so tests never interfere with each other or
//! with leftover rows from other crates' test runs. Run with
//! `--test-threads=1` (core-scoring's `append_event` serializes every append
//! through a single Postgres advisory lock).

use std::net::IpAddr;

use core_scoring::{EventInput, Protocol, ReviewState, SignalType, append_event};
use rust_decimal::Decimal;
use sqlx::{PgPool, Row};

use review::queue::{ReviewError, ReviewQueue};

async fn setup_pool() -> PgPool {
    let url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://propolis:propolis@localhost:5432/propolis_test".into());
    let pool = PgPool::connect(&url).await.unwrap();
    // Run core-scoring migrations first (ip_score table must exist).
    sqlx::migrate!("../core-scoring/migrations")
        .run(&pool)
        .await
        .unwrap();
    // Then this crate's own.
    review::migrator().run(&pool).await.unwrap();
    pool
}

/// Builds an `EventInput` via the public `from_signal` constructor, which
/// derives weight/confidence/category from the signal-weight table (matches
/// core-scoring's own test helper style).
fn ev(
    ip: &str,
    sensor: &str,
    signal: SignalType,
    protocol: Protocol,
    authenticated: bool,
    ts: &str,
) -> EventInput {
    EventInput::from_signal(
        ip.parse().unwrap(),
        None,
        sensor.into(),
        signal,
        protocol,
        authenticated,
        ts.parse().unwrap(),
        serde_json::json!({}),
        None,
    )
}

/// Seeds an eligible + vendor-recommended `ip_score` projection for `ip`: one
/// confirmed-real honeypot login (tcp + authenticated + Honeypot, weight 50)
/// plus two corroborating categories (Auth via SshBruteForce weight 20,
/// Network via CatchallProbe weight 15) - raw 85 (clears the 75 STANDARD
/// floor), max_confidence 0.920 (clears the 0.70 STANDARD floor) -> tier
/// Standard -> recommended_for_vendor. 3 events, 3 categories, so the
/// event_count>=2 / distinct_categories>=2 eligibility gates clear too.
async fn seed_recommended(pool: &PgPool, ip: &str) {
    append_event(
        pool,
        ev(
            ip,
            "honeypot-sensor",
            SignalType::HoneypotLoginAttempt,
            Protocol::Tcp,
            true,
            "2026-07-17T00:00:00Z",
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
            "2026-07-17T00:00:10Z",
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
            "2026-07-17T00:00:20Z",
        ),
    )
    .await
    .unwrap();
}

/// Reads the raw `review_queue` row for `ip` directly (bypassing the crate's
/// own API), so tests can verify write effects independently of the read path.
async fn fetch_row(
    pool: &PgPool,
    ip: &str,
) -> Option<(
    ReviewState,
    Option<chrono::DateTime<chrono::Utc>>,
    Option<String>,
)> {
    sqlx::query("SELECT state, decided_at, notes FROM review_queue WHERE source_ip = $1::inet")
        .bind(ip)
        .fetch_optional(pool)
        .await
        .unwrap()
        .map(|row| (row.get("state"), row.get("decided_at"), row.get("notes")))
}

async fn row_count(pool: &PgPool, ip: &str) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM review_queue WHERE source_ip = $1::inet")
        .bind(ip)
        .fetch_one(pool)
        .await
        .unwrap()
}

/// Wipes any leftover state for `ip` from a previous run of this same test
/// file. `propolis_test` is a persistent, shared database (not reset between
/// runs or between crates' test suites - see `setup_pool`), and
/// `core_scoring::append_event` always ADDS to a source IP's prior state
/// rather than replacing it, so re-running this suite against the same IPs
/// without cleanup would accumulate weight across runs and make a
/// newly-inserted-row count from a prior run leak into this one. Called at
/// the top of every test so each is self-contained regardless of how many
/// times this suite has already run against this database.
async fn reset_ip(pool: &PgPool, ip: &str) {
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

#[tokio::test]
async fn populate_surfaces_recommended_ip() {
    let pool = setup_pool().await;
    let test_ip = "192.0.2.210";
    reset_ip(&pool, test_ip).await;
    seed_recommended(&pool, test_ip).await;

    let queue = ReviewQueue::new();
    let count = queue.populate(&pool).await.unwrap();
    assert!(count >= 1);

    let entries = queue.list_pending(&pool).await.unwrap();
    let want: IpAddr = test_ip.parse().unwrap();
    let entry = entries
        .iter()
        .find(|e| e.source_ip == want)
        .expect("seeded IP must be pending");
    assert_eq!(entry.state, ReviewState::Pending);
    assert!(entry.score_at_surface >= Decimal::from(80));
    assert!(
        entry.categories_at_surface.is_object(),
        "categories_at_surface must snapshot the category breakdown"
    );
}

#[tokio::test]
async fn withdraw_removes_ineligible_pending_entry() {
    let pool = setup_pool().await;
    let test_ip = "192.0.2.211";
    reset_ip(&pool, test_ip).await;
    seed_recommended(&pool, test_ip).await;

    let queue = ReviewQueue::new();
    queue.populate(&pool).await.unwrap();
    let want: IpAddr = test_ip.parse().unwrap();
    assert!(
        queue
            .list_pending(&pool)
            .await
            .unwrap()
            .iter()
            .any(|e| e.source_ip == want),
        "must be pending before withdrawal"
    );

    // Simulate the projection decaying below eligibility: withdraw reads
    // ip_score's STORED columns directly, not a re-derived-to-now value, so a
    // direct update is the correct way to move the trigger out from under it.
    sqlx::query("UPDATE ip_score SET eligible = false WHERE source_ip = $1::inet")
        .bind(test_ip)
        .execute(&pool)
        .await
        .unwrap();

    let removed = queue.withdraw(&pool).await.unwrap();
    assert!(removed >= 1);
    assert!(
        !queue
            .list_pending(&pool)
            .await
            .unwrap()
            .iter()
            .any(|e| e.source_ip == want),
        "must be withdrawn once ineligible"
    );
}

#[tokio::test]
async fn approve_sets_state_and_decided_at() {
    let pool = setup_pool().await;
    let test_ip = "192.0.2.212";
    reset_ip(&pool, test_ip).await;
    seed_recommended(&pool, test_ip).await;

    let queue = ReviewQueue::new();
    queue.populate(&pool).await.unwrap();
    queue
        .approve(&pool, test_ip.parse().unwrap(), Some("looks malicious"))
        .await
        .unwrap();

    let (state, decided_at, notes) = fetch_row(&pool, test_ip).await.expect("row must exist");
    assert_eq!(state, ReviewState::Approved);
    assert!(decided_at.is_some());
    assert_eq!(notes.as_deref(), Some("looks malicious"));
}

#[tokio::test]
async fn reject_prevents_resurfacing() {
    let pool = setup_pool().await;
    let test_ip = "192.0.2.213";
    reset_ip(&pool, test_ip).await;
    seed_recommended(&pool, test_ip).await;

    let queue = ReviewQueue::new();
    queue.populate(&pool).await.unwrap();
    queue
        .reject(&pool, test_ip.parse().unwrap(), Some("known scanner"))
        .await
        .unwrap();

    // Re-run population: the rejected IP is still recommended+eligible, but
    // must not resurface as Pending.
    queue.populate(&pool).await.unwrap();

    let want: IpAddr = test_ip.parse().unwrap();
    assert!(
        !queue
            .list_pending(&pool)
            .await
            .unwrap()
            .iter()
            .any(|e| e.source_ip == want),
        "a rejected IP must never reappear as pending"
    );

    let (state, _, _) = fetch_row(&pool, test_ip)
        .await
        .expect("the rejected row must remain as a record");
    assert_eq!(state, ReviewState::Rejected);
    assert_eq!(
        row_count(&pool, test_ip).await,
        1,
        "populate must not insert a second row for an IP already in the queue"
    );
}

#[tokio::test]
async fn duplicate_populate_is_idempotent() {
    let pool = setup_pool().await;
    let test_ip = "192.0.2.214";
    reset_ip(&pool, test_ip).await;
    seed_recommended(&pool, test_ip).await;

    let queue = ReviewQueue::new();
    queue.populate(&pool).await.unwrap();
    queue.populate(&pool).await.unwrap();

    assert_eq!(row_count(&pool, test_ip).await, 1);
}

#[tokio::test]
async fn snooze_sets_state_and_decided_at() {
    let pool = setup_pool().await;
    let test_ip = "198.51.100.215";
    reset_ip(&pool, test_ip).await;
    seed_recommended(&pool, test_ip).await;

    let queue = ReviewQueue::new();
    queue.populate(&pool).await.unwrap();
    queue
        .snooze(&pool, test_ip.parse().unwrap(), None)
        .await
        .unwrap();

    let (state, decided_at, notes) = fetch_row(&pool, test_ip).await.expect("row must exist");
    assert_eq!(state, ReviewState::Snoozed);
    assert!(decided_at.is_some());
    assert_eq!(notes, None);
}

#[tokio::test]
async fn deciding_an_unknown_ip_fails_closed() {
    let pool = setup_pool().await;
    // Never seeded and never populated: no review_queue row exists for it.
    let test_ip: IpAddr = "203.0.113.216".parse().unwrap();
    reset_ip(&pool, &test_ip.to_string()).await;

    let queue = ReviewQueue::new();
    let result = queue.approve(&pool, test_ip, None).await;
    assert!(
        matches!(result, Err(ReviewError::NotFound(ip)) if ip == test_ip),
        "approving an IP with no queue entry must fail closed, not silently no-op"
    );
}

#[tokio::test]
async fn withdraw_never_removes_a_decided_entry() {
    let pool = setup_pool().await;
    let test_ip = "198.51.100.217";
    reset_ip(&pool, test_ip).await;
    seed_recommended(&pool, test_ip).await;

    let queue = ReviewQueue::new();
    queue.populate(&pool).await.unwrap();
    queue
        .approve(&pool, test_ip.parse().unwrap(), None)
        .await
        .unwrap();

    // Now drop eligibility - an Approved decision must stand regardless.
    sqlx::query("UPDATE ip_score SET eligible = false WHERE source_ip = $1::inet")
        .bind(test_ip)
        .execute(&pool)
        .await
        .unwrap();
    queue.withdraw(&pool).await.unwrap();

    let (state, _, _) = fetch_row(&pool, test_ip)
        .await
        .expect("an approved entry must survive withdrawal");
    assert_eq!(state, ReviewState::Approved);
}
