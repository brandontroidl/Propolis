//! Real-Postgres tests for the review queue state machine.
//!
//! Each test owns a fresh database (`#[sqlx::test]`): core-scoring's migrations run first
//! (`event`/`ip_score` tables), then this crate's own. `populate` and `withdraw` act on the whole
//! table, so a shared database would let another test's or crate's rows change their results.

use std::net::IpAddr;

use core_scoring::{EventInput, Protocol, ReviewState, SignalType, append_event};
use rust_decimal::Decimal;
use sqlx::{PgPool, Row};

use review::queue::{ReviewError, ReviewQueue};

async fn migrate(pool: &PgPool) {
    // Core-scoring first (ip_score table must exist), then this crate's own.
    sqlx::migrate!("../core-scoring/migrations")
        .run(pool)
        .await
        .unwrap();
    review::migrator().run(pool).await.unwrap();
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

/// A delisted address is never queued, even while its eligibility flags still read true (a
/// projection written by an append that raced the delist, say).
#[sqlx::test(migrations = false)]
async fn populate_never_queues_a_delisted_address(pool: PgPool) {
    migrate(&pool).await;
    let test_ip = "192.0.2.239";
    seed_recommended(&pool, test_ip).await;
    sqlx::query("UPDATE ip_score SET delisted = TRUE WHERE source_ip = $1::inet")
        .bind(test_ip)
        .execute(&pool)
        .await
        .unwrap();

    ReviewQueue::new()
        .offering_reserved_addresses()
        .populate(&pool)
        .await
        .unwrap();
    assert_eq!(row_count(&pool, test_ip).await, 0);
}

#[sqlx::test(migrations = false)]
async fn populate_surfaces_recommended_ip(pool: PgPool) {
    migrate(&pool).await;
    let test_ip = "192.0.2.210";
    seed_recommended(&pool, test_ip).await;

    let queue = ReviewQueue::new().offering_reserved_addresses();
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

#[sqlx::test(migrations = false)]
async fn withdraw_removes_ineligible_pending_entry(pool: PgPool) {
    migrate(&pool).await;
    let test_ip = "192.0.2.211";
    seed_recommended(&pool, test_ip).await;

    let queue = ReviewQueue::new().offering_reserved_addresses();
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

#[sqlx::test(migrations = false)]
async fn approve_sets_state_and_decided_at(pool: PgPool) {
    migrate(&pool).await;
    let test_ip = "192.0.2.212";
    seed_recommended(&pool, test_ip).await;

    let queue = ReviewQueue::new().offering_reserved_addresses();
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

#[sqlx::test(migrations = false)]
async fn reject_prevents_resurfacing(pool: PgPool) {
    migrate(&pool).await;
    let test_ip = "192.0.2.213";
    seed_recommended(&pool, test_ip).await;

    let queue = ReviewQueue::new().offering_reserved_addresses();
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

#[sqlx::test(migrations = false)]
async fn duplicate_populate_is_idempotent(pool: PgPool) {
    migrate(&pool).await;
    let test_ip = "192.0.2.214";
    seed_recommended(&pool, test_ip).await;

    let queue = ReviewQueue::new().offering_reserved_addresses();
    queue.populate(&pool).await.unwrap();
    queue.populate(&pool).await.unwrap();

    assert_eq!(row_count(&pool, test_ip).await, 1);
}

#[sqlx::test(migrations = false)]
async fn snooze_sets_state_and_decided_at(pool: PgPool) {
    migrate(&pool).await;
    let test_ip = "198.51.100.215";
    seed_recommended(&pool, test_ip).await;

    let queue = ReviewQueue::new().offering_reserved_addresses();
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

#[sqlx::test(migrations = false)]
async fn deciding_an_unknown_ip_fails_closed(pool: PgPool) {
    migrate(&pool).await;
    // Never seeded and never populated: no review_queue row exists for it.
    let test_ip: IpAddr = "203.0.113.216".parse().unwrap();

    let queue = ReviewQueue::new();
    let result = queue.approve(&pool, test_ip, None).await;
    assert!(
        matches!(result, Err(ReviewError::NotFound(ip)) if ip == test_ip),
        "approving an IP with no queue entry must fail closed, not silently no-op"
    );
}

#[sqlx::test(migrations = false)]
async fn withdraw_never_removes_a_decided_entry(pool: PgPool) {
    migrate(&pool).await;
    let test_ip = "198.51.100.217";
    seed_recommended(&pool, test_ip).await;

    let queue = ReviewQueue::new().offering_reserved_addresses();
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

/// The promise `snooze`'s own doc comment makes - "an operator can act on it again later" - has to
/// be reachable. `populate` never re-surfaces a decided entry, so the only route back is a listing
/// of what is snoozed plus a decision that works on it. This exercises that whole round trip.
#[sqlx::test(migrations = false)]
async fn a_snoozed_entry_can_be_found_again_and_decided(pool: PgPool) {
    migrate(&pool).await;
    let test_ip = "192.0.2.218";
    seed_recommended(&pool, test_ip).await;

    let queue = ReviewQueue::new().offering_reserved_addresses();
    queue.populate(&pool).await.unwrap();
    queue
        .snooze(&pool, test_ip.parse().unwrap(), Some("check the ASN first"))
        .await
        .unwrap();

    // A population scan does not bring it back on its own - that is the behaviour the listing
    // below has to compensate for, so assert it rather than assuming it.
    queue.populate(&pool).await.unwrap();
    let (state, _, _) = fetch_row(&pool, test_ip).await.expect("row must exist");
    assert_eq!(
        state,
        ReviewState::Snoozed,
        "a population scan must not silently undo an operator's decision to defer"
    );

    // Found again, with the reasoning the operator left behind.
    let snoozed = queue
        .list_by_state(&pool, ReviewState::Snoozed)
        .await
        .unwrap();
    let entry = snoozed
        .iter()
        .find(|e| e.source_ip.to_string() == test_ip)
        .expect("the snoozed listing must contain the entry that was snoozed");
    assert_eq!(entry.notes.as_deref(), Some("check the ASN first"));

    // And decided from there.
    queue
        .approve(&pool, test_ip.parse().unwrap(), Some("reviewed, real"))
        .await
        .unwrap();
    let (state, decided_at, notes) = fetch_row(&pool, test_ip).await.expect("row must exist");
    assert_eq!(state, ReviewState::Approved);
    assert!(decided_at.is_some());
    assert_eq!(notes.as_deref(), Some("reviewed, real"));
    assert!(
        !queue
            .list_by_state(&pool, ReviewState::Snoozed)
            .await
            .unwrap()
            .iter()
            .any(|e| e.source_ip.to_string() == test_ip),
        "a decided entry must leave the snoozed listing"
    );
}

/// `unsnooze` puts an entry back in the working queue rather than deciding it, and clears the
/// decision timestamp with it: a Pending row carrying a `decided_at` reads as a decision that was
/// taken and then ignored.
#[sqlx::test(migrations = false)]
async fn unsnooze_returns_an_entry_to_pending_and_clears_its_decision_timestamp(pool: PgPool) {
    migrate(&pool).await;
    let test_ip = "192.0.2.219";
    seed_recommended(&pool, test_ip).await;

    let queue = ReviewQueue::new().offering_reserved_addresses();
    queue.populate(&pool).await.unwrap();
    queue
        .snooze(&pool, test_ip.parse().unwrap(), Some("deferred once"))
        .await
        .unwrap();
    queue
        .unsnooze(&pool, test_ip.parse().unwrap())
        .await
        .unwrap();

    let (state, decided_at, notes) = fetch_row(&pool, test_ip).await.expect("row must exist");
    assert_eq!(state, ReviewState::Pending);
    assert_eq!(
        decided_at, None,
        "a pending entry has not been decided, so it must carry no decision time"
    );
    assert_eq!(
        notes.as_deref(),
        Some("deferred once"),
        "the reasoning for deferring is the context the operator wants when it comes back round"
    );

    // Back in the ordinary working queue, not just back in some state column.
    assert!(
        queue
            .list_pending(&pool)
            .await
            .unwrap()
            .iter()
            .any(|e| e.source_ip.to_string() == test_ip),
        "an unsnoozed entry must appear in the pending listing"
    );
    assert_eq!(row_count(&pool, test_ip).await, 1, "no duplicate row");
}

#[sqlx::test(migrations = false)]
async fn unsnoozing_an_entry_that_does_not_exist_fails_closed(pool: PgPool) {
    migrate(&pool).await;
    let test_ip: IpAddr = "192.0.2.220".parse().unwrap();

    let result = ReviewQueue::new().unsnooze(&pool, test_ip).await;
    assert!(
        matches!(result, Err(ReviewError::NotFound(ip)) if ip == test_ip),
        "unsnoozing an IP with no queue entry must fail closed, not silently no-op"
    );
}

/// An entry returned to pending is a live recommendation again, so a `withdraw` scan must be able
/// to retire it when its trigger lapses - exactly as it would for any other pending entry. The
/// scan skips decided rows, so this proves `unsnooze` really restored Pending rather than leaving
/// a row that merely displays as pending.
#[sqlx::test(migrations = false)]
async fn an_unsnoozed_entry_is_withdrawn_again_when_its_recommendation_lapses(pool: PgPool) {
    migrate(&pool).await;
    let test_ip = "192.0.2.221";
    seed_recommended(&pool, test_ip).await;

    let queue = ReviewQueue::new().offering_reserved_addresses();
    queue.populate(&pool).await.unwrap();
    queue
        .snooze(&pool, test_ip.parse().unwrap(), None)
        .await
        .unwrap();
    queue
        .unsnooze(&pool, test_ip.parse().unwrap())
        .await
        .unwrap();

    sqlx::query("UPDATE ip_score SET recommended_for_vendor = FALSE WHERE source_ip = $1::inet")
        .bind(test_ip)
        .execute(&pool)
        .await
        .unwrap();

    queue.withdraw(&pool).await.unwrap();
    assert_eq!(
        row_count(&pool, test_ip).await,
        0,
        "an unsnoozed entry must be an ordinary pending entry, withdrawable like any other"
    );
}

// Live: the queue offered, and the operator approved, an RFC 1918 address that the gatekeeper then
// held as Reserved on every pass. The control address is unreserved, so a populate that excluded
// everything would fail here too. The queue is given a narrower classifier than production's so
// the control can sit in a documentation range (the repository writes no real public address);
// the production classifier is wired in by default and exercised through the real daemon in
// cli_test.
fn private_and_loopback_only(ip: std::net::IpAddr) -> bool {
    match ip {
        std::net::IpAddr::V4(v4) => v4.is_private() || v4.is_loopback(),
        std::net::IpAddr::V6(_) => false,
    }
}

#[sqlx::test(migrations = false)]
async fn populate_never_offers_a_reserved_address(pool: PgPool) {
    migrate(&pool).await;
    let public = "198.51.100.230";
    let reserved = ["10.20.30.1", "192.168.7.7", "127.0.0.9"];
    seed_recommended(&pool, public).await;
    for ip in reserved {
        seed_recommended(&pool, ip).await;
    }

    let inserted = ReviewQueue::new()
        .with_reserved_classifier(private_and_loopback_only)
        .populate(&pool)
        .await
        .unwrap();

    assert_eq!(inserted, 1, "only the public address is offered");
    assert_eq!(row_count(&pool, public).await, 1);
    for ip in reserved {
        assert_eq!(row_count(&pool, ip).await, 0, "{ip} is reserved");
    }
}

// What happens to a reserved address that is already in the queue (queued before the rule, or by
// an older build): every state but Rejected becomes Rejected with decided_at set and a note that
// records the automatic resolution, the earlier state and any operator note. Nothing is deleted.
#[sqlx::test(migrations = false)]
async fn resolve_reserved_rejects_unfinished_entries_and_records_why(pool: PgPool) {
    migrate(&pool).await;
    let insert = |ip: &'static str, state: ReviewState, notes: Option<&'static str>| {
        let pool = pool.clone();
        async move {
            sqlx::query(
                "INSERT INTO review_queue \
                 (source_ip, state, score_at_surface, categories_at_surface, decided_at, notes) \
                 VALUES ($1::inet, $2, 85, '{}'::jsonb, $3, $4)",
            )
            .bind(ip)
            .bind(state)
            .bind((state != ReviewState::Pending).then(|| {
                "2026-10-01T00:00:00Z"
                    .parse::<chrono::DateTime<chrono::Utc>>()
                    .unwrap()
            }))
            .bind(notes)
            .execute(&pool)
            .await
            .unwrap();
        }
    };
    insert("10.20.30.2", ReviewState::Pending, None).await;
    insert("10.20.30.3", ReviewState::Approved, Some("looks real")).await;
    insert("192.168.1.5", ReviewState::Snoozed, None).await;
    insert("10.20.30.4", ReviewState::Rejected, Some("earlier")).await;
    insert("198.51.100.231", ReviewState::Approved, Some("keep")).await;
    let rejected_before = fetch_row(&pool, "10.20.30.4").await;
    let public_before = fetch_row(&pool, "198.51.100.231").await;

    let queue = ReviewQueue::new().with_reserved_classifier(private_and_loopback_only);
    assert_eq!(queue.resolve_reserved(&pool).await.unwrap(), 3);

    for (ip, was, operator_note) in [
        ("10.20.30.2", "pending", ""),
        ("10.20.30.3", "approved", ", operator note: looks real"),
        ("192.168.1.5", "snoozed", ""),
    ] {
        let (state, decided_at, notes) = fetch_row(&pool, ip).await.unwrap();
        assert_eq!(state, ReviewState::Rejected, "{ip}");
        let seeded_decision: chrono::DateTime<chrono::Utc> =
            "2026-10-02T00:00:00Z".parse().unwrap();
        assert!(
            decided_at.is_some_and(|t| t > seeded_decision),
            "{ip}: decided_at is stamped now, not left at the seeded value"
        );
        assert_eq!(
            notes.as_deref(),
            Some(
                format!(
                    "auto-rejected: reserved address, never reported to a vendor \
                     (was {was}{operator_note})"
                )
                .as_str()
            ),
            "{ip}"
        );
    }
    assert_eq!(fetch_row(&pool, "10.20.30.4").await, rejected_before);
    assert_eq!(fetch_row(&pool, "198.51.100.231").await, public_before);
    assert!(
        queue
            .list_approved(&pool)
            .await
            .unwrap()
            .iter()
            .all(|e| e.source_ip.to_string() == "198.51.100.231"),
        "no reserved address is left for the submission runner to hold on every pass"
    );
    assert_eq!(
        queue.resolve_reserved(&pool).await.unwrap(),
        0,
        "a second scan finds nothing left to resolve"
    );
}
