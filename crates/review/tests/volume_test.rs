//! Real-Postgres tests for the volume review queue (`review::volume`): which addresses the scan
//! offers, which pending rows it takes back, and the operator's three transitions.
//!
//! Each test owns a fresh database (`#[sqlx::test]`): core-scoring's migrations run first
//! (`event`/`ip_score`), then this crate's own. `populate` and `withdraw` act on the whole table,
//! so a shared database would let another test's rows change their results.
//!
//! Floods are seeded through the real append path with timestamps relative to `Utc::now()`:
//! `populate` offers an address only while it was last seen within a day of the wall clock.

use std::net::IpAddr;
use std::sync::Arc;

use chrono::{DateTime, Duration, Utc};
use core_scoring::{
    EventInput, OperatorAllowlist, Protocol, ReviewState, SignalType, append_event, append_events,
};
use sqlx::{PgPool, Row};

use review::queue::{ReviewError, ReviewQueue};
use review::volume::VolumeQueue;

async fn migrate(pool: &PgPool) {
    sqlx::migrate!("../core-scoring/migrations")
        .run(pool)
        .await
        .unwrap();
    review::migrator().run(pool).await.unwrap();
}

fn ev(
    ip: &str,
    signal: SignalType,
    protocol: Protocol,
    authenticated: bool,
    observed_at: DateTime<Utc>,
) -> EventInput {
    EventInput::from_signal(
        ip.parse().unwrap(),
        None,
        "volume-test-sensor".into(),
        signal,
        protocol,
        authenticated,
        observed_at,
        serde_json::json!({}),
        None,
    )
}

/// `events` unauthenticated TCP connections from `ip`, a millisecond apart, the last one at
/// `last_event`. A thousand of them is the volume rule's threshold; none of them is a
/// confirmed-real session, so the address is listed on volume and nothing else.
async fn seed_connections(pool: &PgPool, ip: &str, events: i64, last_event: DateTime<Utc>) {
    let batch: Vec<EventInput> = (0..events)
        .map(|i| {
            ev(
                ip,
                SignalType::HoneypotConnection,
                Protocol::Tcp,
                false,
                last_event - Duration::milliseconds(events - 1 - i),
            )
        })
        .collect();
    let outcome = append_events(pool, batch).await;
    assert!(outcome.failure.is_none(), "{:?}", outcome.failure);
    assert_eq!(outcome.appended as i64, events);
}

/// A flood that reached the volume threshold a few minutes ago.
async fn seed_flood(pool: &PgPool, ip: &str) {
    seed_connections(pool, ip, 1000, Utc::now() - Duration::minutes(5)).await;
}

/// The queue under test. The fixtures sit in the documentation ranges, which the production
/// classifier treats as reserved, so the queue is told to offer them (see
/// `ReviewQueue::offering_reserved_addresses`).
fn queue() -> VolumeQueue {
    VolumeQueue::new().offering_reserved_addresses()
}

async fn fetch_row(
    pool: &PgPool,
    ip: &str,
) -> Option<(ReviewState, i32, Option<DateTime<Utc>>, Option<String>)> {
    sqlx::query(
        "SELECT state, established_events_at_surface, decided_at, notes \
         FROM volume_review WHERE source_ip = $1::inet",
    )
    .bind(ip)
    .fetch_optional(pool)
    .await
    .unwrap()
    .map(|row| {
        (
            row.get("state"),
            row.get("established_events_at_surface"),
            row.get("decided_at"),
            row.get("notes"),
        )
    })
}

async fn state_of(pool: &PgPool, ip: &str) -> Option<ReviewState> {
    fetch_row(pool, ip).await.map(|row| row.0)
}

/// Queues `ip` in `review_queue` in `state`, as the operator's decision on its score.
async fn queue_on_merit(pool: &PgPool, ip: &str, state: ReviewState) {
    sqlx::query(
        "INSERT INTO review_queue \
         (source_ip, state, score_at_surface, categories_at_surface, decided_at) \
         VALUES ($1::inet, $2, 85, '{}'::jsonb, now())",
    )
    .bind(ip)
    .bind(state)
    .execute(pool)
    .await
    .unwrap();
}

// --- populate ---

#[sqlx::test(migrations = false)]
async fn populate_offers_an_address_that_reached_the_volume_threshold(pool: PgPool) {
    migrate(&pool).await;
    let flood = "192.0.2.10";
    seed_flood(&pool, flood).await;
    let stored: (bool, bool, i32) = sqlx::query_as(
        "SELECT recommended_for_blocklist, eligible, established_event_count \
         FROM ip_score WHERE source_ip = $1::inet",
    )
    .bind(flood)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(
        stored,
        (true, false, 1000),
        "precondition: listed on volume alone, the case that used to be published unreviewed"
    );

    let queue = queue();
    assert_eq!(queue.populate(&pool).await.unwrap(), 1);

    let (state, at_surface, decided_at, notes) = fetch_row(&pool, flood).await.unwrap();
    assert_eq!(state, ReviewState::Pending);
    assert_eq!(at_surface, 1000, "the count that listed it is recorded");
    assert_eq!(decided_at, None);
    assert_eq!(notes, None);

    let pending = queue.list_pending(&pool).await.unwrap();
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].source_ip.to_string(), flood);
    assert_eq!(queue.pending_count(&pool).await.unwrap(), 1);
}

#[sqlx::test(migrations = false)]
async fn populate_does_not_offer_an_address_below_the_threshold(pool: PgPool) {
    migrate(&pool).await;
    let now = Utc::now() - Duration::minutes(5);
    seed_connections(&pool, "192.0.2.11", 999, now).await;
    seed_connections(&pool, "192.0.2.12", 1000, now).await;

    assert_eq!(queue().populate(&pool).await.unwrap(), 1);
    assert_eq!(state_of(&pool, "192.0.2.11").await, None, "999 events");
    assert_eq!(
        state_of(&pool, "192.0.2.12").await,
        Some(ReviewState::Pending),
        "1000 events: the threshold itself is offered"
    );
}

/// UDP is spoofable, so it never counts toward the volume rule; a thousand datagrams offer
/// nobody, whatever the total event count says.
#[sqlx::test(migrations = false)]
async fn populate_counts_established_tcp_events_not_every_event(pool: PgPool) {
    migrate(&pool).await;
    let ip = "192.0.2.13";
    let last = Utc::now() - Duration::minutes(5);
    let batch: Vec<EventInput> = (0..1000)
        .map(|i| {
            ev(
                ip,
                SignalType::CatchallProbe,
                Protocol::Udp,
                false,
                last - Duration::milliseconds(999 - i),
            )
        })
        .collect();
    assert!(append_events(&pool, batch).await.failure.is_none());

    assert_eq!(queue().populate(&pool).await.unwrap(), 0);
    assert_eq!(state_of(&pool, ip).await, None);
}

#[sqlx::test(migrations = false)]
async fn populate_does_not_offer_a_delisted_address(pool: PgPool) {
    migrate(&pool).await;
    let ip = "192.0.2.14";
    seed_flood(&pool, ip).await;
    // Only the latch: the count and the stored recommendation stay as the flood left them, so
    // it is the delist check that keeps the address out.
    sqlx::query("UPDATE ip_score SET delisted = TRUE WHERE source_ip = $1::inet")
        .bind(ip)
        .execute(&pool)
        .await
        .unwrap();

    assert_eq!(queue().populate(&pool).await.unwrap(), 0);
    assert_eq!(state_of(&pool, ip).await, None);
}

#[sqlx::test(migrations = false)]
async fn populate_does_not_offer_a_flood_that_stopped_more_than_a_day_ago(pool: PgPool) {
    migrate(&pool).await;
    let stale = "192.0.2.15";
    let recent = "192.0.2.16";
    seed_connections(&pool, stale, 1000, Utc::now() - Duration::hours(25)).await;
    seed_connections(&pool, recent, 1000, Utc::now() - Duration::hours(23)).await;

    assert_eq!(queue().populate(&pool).await.unwrap(), 1);
    assert_eq!(state_of(&pool, stale).await, None, "last seen 25 hours ago");
    assert_eq!(
        state_of(&pool, recent).await,
        Some(ReviewState::Pending),
        "last seen 23 hours ago"
    );
}

fn private_and_loopback_only(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_private() || v4.is_loopback(),
        IpAddr::V6(_) => false,
    }
}

// The control address is unreserved, so a populate that excluded everything would fail here too.
// The queue is given a narrower classifier than production's so the control can sit in a
// documentation range, as `queue_test::populate_never_offers_a_reserved_address` does.
#[sqlx::test(migrations = false)]
async fn populate_does_not_offer_a_reserved_address(pool: PgPool) {
    migrate(&pool).await;
    let public = "198.51.100.17";
    let reserved = ["10.20.30.1", "192.168.7.7"];
    seed_flood(&pool, public).await;
    for ip in reserved {
        seed_flood(&pool, ip).await;
    }

    let inserted = VolumeQueue::new()
        .with_reserved_classifier(private_and_loopback_only)
        .populate(&pool)
        .await
        .unwrap();

    assert_eq!(inserted, 1, "only the public address is offered");
    assert_eq!(state_of(&pool, public).await, Some(ReviewState::Pending));
    for ip in reserved {
        assert_eq!(state_of(&pool, ip).await, None, "{ip} is reserved");
    }
}

/// The production classifier is the default: a queue built with `new()` and nothing else offers
/// no documentation-range address, which is what every fixture in this file is.
#[sqlx::test(migrations = false)]
async fn the_default_queue_uses_the_production_reserved_ranges(pool: PgPool) {
    migrate(&pool).await;
    seed_flood(&pool, "192.0.2.18").await;

    assert_eq!(VolumeQueue::new().populate(&pool).await.unwrap(), 0);
    assert_eq!(state_of(&pool, "192.0.2.18").await, None);
}

#[sqlx::test(migrations = false)]
async fn populate_does_not_offer_an_allowlisted_address(pool: PgPool) {
    migrate(&pool).await;
    let listed = "192.0.2.19";
    let unlisted = "192.0.2.20";
    seed_flood(&pool, listed).await;
    seed_flood(&pool, unlisted).await;
    let allowlist = Arc::new(OperatorAllowlist::new(vec![
        "192.0.2.19/32".parse().unwrap(),
    ]));

    let inserted = queue()
        .with_allowlist(allowlist)
        .populate(&pool)
        .await
        .unwrap();

    assert_eq!(inserted, 1);
    assert_eq!(state_of(&pool, listed).await, None);
    assert_eq!(state_of(&pool, unlisted).await, Some(ReviewState::Pending));
}

#[sqlx::test(migrations = false)]
async fn populate_does_not_offer_an_address_that_already_has_a_row(pool: PgPool) {
    migrate(&pool).await;
    let pending = "192.0.2.21";
    let rejected = "192.0.2.22";
    seed_flood(&pool, pending).await;
    seed_flood(&pool, rejected).await;
    let queue = queue();
    assert_eq!(queue.populate(&pool).await.unwrap(), 2);
    queue
        .reject(&pool, rejected.parse().unwrap(), Some("research scanner"))
        .await
        .unwrap();
    let rejected_before = fetch_row(&pool, rejected).await;

    // The flood goes on, and the next scan runs.
    seed_connections(&pool, rejected, 500, Utc::now() - Duration::minutes(1)).await;
    assert_eq!(
        queue.populate(&pool).await.unwrap(),
        0,
        "a second scan inserts nothing: one row per address, in any state"
    );

    assert_eq!(state_of(&pool, pending).await, Some(ReviewState::Pending));
    assert_eq!(
        fetch_row(&pool, rejected).await,
        rejected_before,
        "a rejected candidate is not offered again, and its row is left as decided"
    );
}

#[sqlx::test(migrations = false)]
async fn populate_does_not_offer_an_address_already_approved_on_its_score(pool: PgPool) {
    migrate(&pool).await;
    let approved = "192.0.2.23";
    let merit_pending = "192.0.2.24";
    let merit_rejected = "192.0.2.25";
    for ip in [approved, merit_pending, merit_rejected] {
        seed_flood(&pool, ip).await;
    }
    queue_on_merit(&pool, approved, ReviewState::Approved).await;
    queue_on_merit(&pool, merit_pending, ReviewState::Pending).await;
    queue_on_merit(&pool, merit_rejected, ReviewState::Rejected).await;

    assert_eq!(queue().populate(&pool).await.unwrap(), 2);

    assert_eq!(
        state_of(&pool, approved).await,
        None,
        "the operator already approved this address; it needs no second decision"
    );
    for ip in [merit_pending, merit_rejected] {
        assert_eq!(
            state_of(&pool, ip).await,
            Some(ReviewState::Pending),
            "{ip}: only an APPROVED review-queue entry stands in for a volume decision"
        );
    }
}

// --- withdraw ---

#[sqlx::test(migrations = false)]
async fn withdraw_removes_pending_rows_that_have_nothing_left_to_decide(pool: PgPool) {
    migrate(&pool).await;
    let kept = "192.0.2.30";
    let no_projection = "192.0.2.31";
    let delisted = "192.0.2.32";
    let below = "192.0.2.33";
    let merit_approved = "192.0.2.34";
    for ip in [kept, no_projection, delisted, below, merit_approved] {
        seed_flood(&pool, ip).await;
    }
    let queue = queue();
    assert_eq!(queue.populate(&pool).await.unwrap(), 5);

    // Each lapsed address loses exactly one thing, so each reason is shown to be enough alone.
    sqlx::query("DELETE FROM ip_score WHERE source_ip = $1::inet")
        .bind(no_projection)
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("UPDATE ip_score SET delisted = TRUE WHERE source_ip = $1::inet")
        .bind(delisted)
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("UPDATE ip_score SET established_event_count = 999 WHERE source_ip = $1::inet")
        .bind(below)
        .execute(&pool)
        .await
        .unwrap();
    queue_on_merit(&pool, merit_approved, ReviewState::Approved).await;

    assert_eq!(queue.withdraw(&pool).await.unwrap(), 4);

    assert_eq!(
        state_of(&pool, kept).await,
        Some(ReviewState::Pending),
        "a candidate that still qualifies stays for the operator"
    );
    for ip in [no_projection, delisted, below, merit_approved] {
        assert_eq!(state_of(&pool, ip).await, None, "{ip}");
    }
}

/// Nothing but the stated reasons withdraws a candidate. A flood that stopped is still carried by
/// the retention feeds for up to their longest window (forty days is inside the ninety the queue
/// allows by default), so the decision is still wanted; and a review-queue entry that is not
/// Approved decides nothing about the volume listing.
#[sqlx::test(migrations = false)]
async fn withdraw_keeps_a_pending_row_for_a_quiet_or_differently_decided_address(pool: PgPool) {
    migrate(&pool).await;
    let quiet = "192.0.2.35";
    let merit_rejected = "192.0.2.36";
    let merit_pending = "192.0.2.37";
    for ip in [quiet, merit_rejected, merit_pending] {
        seed_flood(&pool, ip).await;
    }
    let queue = queue();
    assert_eq!(queue.populate(&pool).await.unwrap(), 3);

    sqlx::query(
        "UPDATE ip_score SET last_seen = now() - interval '40 days' WHERE source_ip = $1::inet",
    )
    .bind(quiet)
    .execute(&pool)
    .await
    .unwrap();
    queue_on_merit(&pool, merit_rejected, ReviewState::Rejected).await;
    queue_on_merit(&pool, merit_pending, ReviewState::Pending).await;

    assert_eq!(queue.withdraw(&pool).await.unwrap(), 0);
    for ip in [quiet, merit_rejected, merit_pending] {
        assert_eq!(
            state_of(&pool, ip).await,
            Some(ReviewState::Pending),
            "{ip}"
        );
    }
}

#[sqlx::test(migrations = false)]
async fn withdraw_never_removes_a_decided_row(pool: PgPool) {
    migrate(&pool).await;
    // One approved and one rejected row for each reason a pending row would be withdrawn.
    let cases = [
        ("192.0.2.40", "192.0.2.41", "no projection"),
        ("192.0.2.42", "192.0.2.43", "delisted"),
        ("192.0.2.44", "192.0.2.45", "below the threshold"),
        ("192.0.2.46", "192.0.2.47", "approved on its score"),
    ];
    let queue = queue();
    for (approved, rejected, _) in cases {
        seed_flood(&pool, approved).await;
        seed_flood(&pool, rejected).await;
    }
    assert_eq!(queue.populate(&pool).await.unwrap(), 8);
    for (approved, rejected, _) in cases {
        queue
            .approve(&pool, approved.parse().unwrap(), Some("keep"))
            .await
            .unwrap();
        queue
            .reject(&pool, rejected.parse().unwrap(), Some("keep"))
            .await
            .unwrap();
    }

    for ip in [cases[0].0, cases[0].1] {
        sqlx::query("DELETE FROM ip_score WHERE source_ip = $1::inet")
            .bind(ip)
            .execute(&pool)
            .await
            .unwrap();
    }
    for ip in [cases[1].0, cases[1].1] {
        sqlx::query("UPDATE ip_score SET delisted = TRUE WHERE source_ip = $1::inet")
            .bind(ip)
            .execute(&pool)
            .await
            .unwrap();
    }
    for ip in [cases[2].0, cases[2].1] {
        sqlx::query("UPDATE ip_score SET established_event_count = 1 WHERE source_ip = $1::inet")
            .bind(ip)
            .execute(&pool)
            .await
            .unwrap();
    }
    for ip in [cases[3].0, cases[3].1] {
        queue_on_merit(&pool, ip, ReviewState::Approved).await;
    }

    assert_eq!(
        queue.withdraw(&pool).await.unwrap(),
        0,
        "a background scan does not undo a decision"
    );
    for (approved, rejected, reason) in cases {
        assert_eq!(
            state_of(&pool, approved).await,
            Some(ReviewState::Approved),
            "{reason}"
        );
        assert_eq!(
            state_of(&pool, rejected).await,
            Some(ReviewState::Rejected),
            "{reason}"
        );
    }
}

/// Moves `ip`'s stored `last_seen` to `ago` before now, as if nothing had named it since.
async fn last_seen_ago(pool: &PgPool, ip: &str, ago: Duration) {
    sqlx::query("UPDATE ip_score SET last_seen = $2 WHERE source_ip = $1::inet")
        .bind(ip)
        .bind(Utc::now() - ago)
        .execute(pool)
        .await
        .unwrap();
}

/// An approval covers one listing. Once the address has been unseen for longer than the longest
/// retention window it is in no feed file, and an approval left standing would publish it again
/// at its next sighting with nobody deciding. So the approved row goes, a pending row with it,
/// and the next flood is offered as a new candidate. A rejection stays: a rejected address is
/// not offered again. The node here publishes a window longer than the ninety days the queue
/// uses by default.
#[sqlx::test(migrations = false)]
async fn a_decision_lapses_once_its_address_is_out_of_every_window_and_is_offered_anew(
    pool: PgPool,
) {
    migrate(&pool).await;
    let approved = "192.0.2.60";
    let pending = "192.0.2.61";
    let rejected = "192.0.2.62";
    let approved_inside = "192.0.2.63";
    for ip in [approved, pending, rejected, approved_inside] {
        seed_flood(&pool, ip).await;
    }
    let longest = Duration::days(120);
    let queue = queue().lapsing_after(longest);
    assert_eq!(queue.populate(&pool).await.unwrap(), 4);
    for ip in [approved, approved_inside] {
        queue
            .approve(&pool, ip.parse().unwrap(), Some("flood"))
            .await
            .unwrap();
    }
    queue
        .reject(&pool, rejected.parse().unwrap(), Some("ours"))
        .await
        .unwrap();

    // A minute short of the limit nothing lapses.
    for ip in [approved, pending, rejected] {
        last_seen_ago(&pool, ip, longest - Duration::minutes(1)).await;
    }
    assert_eq!(queue.withdraw(&pool).await.unwrap(), 0);
    assert_eq!(state_of(&pool, approved).await, Some(ReviewState::Approved));
    assert_eq!(state_of(&pool, pending).await, Some(ReviewState::Pending));

    // A minute past it the approval and the open candidate are gone; the rejection and the
    // approval of an address still being seen are not.
    for ip in [approved, pending, rejected] {
        last_seen_ago(&pool, ip, longest + Duration::minutes(1)).await;
    }
    assert_eq!(queue.withdraw(&pool).await.unwrap(), 2);
    assert_eq!(state_of(&pool, approved).await, None);
    assert_eq!(state_of(&pool, pending).await, None);
    assert_eq!(state_of(&pool, rejected).await, Some(ReviewState::Rejected));
    assert_eq!(
        state_of(&pool, approved_inside).await,
        Some(ReviewState::Approved)
    );

    // While the address stays unseen there is nothing to offer.
    assert_eq!(queue.populate(&pool).await.unwrap(), 0);

    // One more line names each of them, months later. The two whose rows lapsed are offered
    // again and are Pending: the old approval does not speak for the new sighting. The rejected
    // one is not offered.
    for ip in [approved, pending, rejected] {
        last_seen_ago(&pool, ip, Duration::minutes(1)).await;
    }
    assert_eq!(queue.populate(&pool).await.unwrap(), 2);
    assert_eq!(state_of(&pool, approved).await, Some(ReviewState::Pending));
    assert_eq!(state_of(&pool, pending).await, Some(ReviewState::Pending));
    assert_eq!(state_of(&pool, rejected).await, Some(ReviewState::Rejected));
}

/// Without `lapsing_after` the limit is the longest window the feed ships with, ninety days.
#[sqlx::test(migrations = false)]
async fn by_default_a_decision_lapses_after_ninety_days_unseen(pool: PgPool) {
    migrate(&pool).await;
    let inside = "192.0.2.64";
    let outside = "192.0.2.65";
    for ip in [inside, outside] {
        seed_flood(&pool, ip).await;
    }
    let queue = queue();
    assert_eq!(queue.populate(&pool).await.unwrap(), 2);
    for ip in [inside, outside] {
        queue
            .approve(&pool, ip.parse().unwrap(), None)
            .await
            .unwrap();
    }
    last_seen_ago(&pool, inside, Duration::days(89)).await;
    last_seen_ago(&pool, outside, Duration::days(91)).await;

    assert_eq!(queue.withdraw(&pool).await.unwrap(), 1);
    assert_eq!(state_of(&pool, inside).await, Some(ReviewState::Approved));
    assert_eq!(state_of(&pool, outside).await, None);
}

/// The lapse is a delete on a table every node of a shared database reads. A node that publishes
/// only short windows must not end an approval another node is still publishing under the
/// windows a default install has, and a removed approval does not come back until the address
/// floods again. So a limit shorter than ninety days is raised to ninety, whatever this node
/// publishes. (It also keeps the lapse outside the day within which `populate` still offers an
/// address, where every scan would insert a row and remove it again.)
#[sqlx::test(migrations = false)]
async fn a_lapse_shorter_than_ninety_days_is_raised_to_ninety(pool: PgPool) {
    migrate(&pool).await;
    let approved = "192.0.2.66";
    let pending = "192.0.2.67";
    for ip in [approved, pending] {
        seed_flood(&pool, ip).await;
    }
    // This node's longest window is seven days.
    let queue = queue().lapsing_after(Duration::days(7));
    assert_eq!(queue.populate(&pool).await.unwrap(), 2);
    queue
        .approve(&pool, approved.parse().unwrap(), None)
        .await
        .unwrap();

    // Thirteen hours unseen, then thirty days: past this node's windows, inside ninety days.
    // Both rows stay, and a row that stays is not offered again by the next scan.
    for unseen in [Duration::hours(13), Duration::days(30), Duration::days(89)] {
        for ip in [approved, pending] {
            last_seen_ago(&pool, ip, unseen).await;
        }
        assert_eq!(queue.populate(&pool).await.unwrap(), 0, "{unseen}");
        assert_eq!(queue.withdraw(&pool).await.unwrap(), 0, "{unseen}");
        assert_eq!(state_of(&pool, approved).await, Some(ReviewState::Approved));
        assert_eq!(state_of(&pool, pending).await, Some(ReviewState::Pending));
    }

    // Past ninety days they lapse.
    for ip in [approved, pending] {
        last_seen_ago(&pool, ip, Duration::days(91)).await;
    }
    assert_eq!(queue.withdraw(&pool).await.unwrap(), 2);
    assert_eq!(state_of(&pool, approved).await, None);
    assert_eq!(state_of(&pool, pending).await, None);
    assert_eq!(queue.populate(&pool).await.unwrap(), 0);
}

// --- decisions ---

#[sqlx::test(migrations = false)]
async fn approve_and_reject_set_the_state_the_decision_time_and_the_note(pool: PgPool) {
    migrate(&pool).await;
    let approved = "192.0.2.50";
    let rejected = "192.0.2.51";
    seed_flood(&pool, approved).await;
    seed_flood(&pool, rejected).await;
    let queue = queue();
    queue.populate(&pool).await.unwrap();

    queue
        .approve(&pool, approved.parse().unwrap(), Some("flooding ssh"))
        .await
        .unwrap();
    queue
        .reject(&pool, rejected.parse().unwrap(), None)
        .await
        .unwrap();

    let (state, _, decided_at, notes) = fetch_row(&pool, approved).await.unwrap();
    assert_eq!(state, ReviewState::Approved);
    assert!(decided_at.is_some());
    assert_eq!(notes.as_deref(), Some("flooding ssh"));
    let (state, _, decided_at, notes) = fetch_row(&pool, rejected).await.unwrap();
    assert_eq!(state, ReviewState::Rejected);
    assert!(decided_at.is_some());
    assert_eq!(notes, None);

    assert!(queue.list_pending(&pool).await.unwrap().is_empty());
    assert_eq!(queue.pending_count(&pool).await.unwrap(), 0);
    let listed = queue
        .list_by_state(&pool, ReviewState::Approved, None)
        .await
        .unwrap();
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].source_ip.to_string(), approved);
    assert_eq!(listed[0].notes.as_deref(), Some("flooding ssh"));
    assert_eq!(listed[0].established_events_at_surface, 1000);
}

#[sqlx::test(migrations = false)]
async fn reopen_returns_a_decided_candidate_to_pending_and_clears_its_decision_time(pool: PgPool) {
    migrate(&pool).await;
    let was_approved = "192.0.2.52";
    let was_rejected = "192.0.2.53";
    seed_flood(&pool, was_approved).await;
    seed_flood(&pool, was_rejected).await;
    let queue = queue();
    queue.populate(&pool).await.unwrap();
    queue
        .approve(&pool, was_approved.parse().unwrap(), Some("approved once"))
        .await
        .unwrap();
    queue
        .reject(&pool, was_rejected.parse().unwrap(), Some("rejected once"))
        .await
        .unwrap();

    for (ip, note) in [
        (was_approved, "approved once"),
        (was_rejected, "rejected once"),
    ] {
        queue.reopen(&pool, ip.parse().unwrap()).await.unwrap();
        let (state, _, decided_at, notes) = fetch_row(&pool, ip).await.unwrap();
        assert_eq!(state, ReviewState::Pending, "{ip}");
        assert_eq!(decided_at, None, "{ip}: a pending row has not been decided");
        assert_eq!(notes.as_deref(), Some(note), "{ip}: the note is kept");
    }
    assert_eq!(queue.pending_count(&pool).await.unwrap(), 2);

    // A reopened row is an ordinary pending row again: the scan may take it back.
    sqlx::query("UPDATE ip_score SET delisted = TRUE WHERE source_ip = $1::inet")
        .bind(was_approved)
        .execute(&pool)
        .await
        .unwrap();
    assert_eq!(queue.withdraw(&pool).await.unwrap(), 1);
    assert_eq!(state_of(&pool, was_approved).await, None);
}

#[sqlx::test(migrations = false)]
async fn deciding_an_address_with_no_volume_row_fails_closed(pool: PgPool) {
    migrate(&pool).await;
    let ip: IpAddr = "192.0.2.54".parse().unwrap();
    // The address is queued on its score, which is a different decision: a volume approval must
    // not land on, or be satisfied by, a review-queue row.
    queue_on_merit(&pool, "192.0.2.54", ReviewState::Pending).await;
    let queue = queue();

    for result in [
        queue.approve(&pool, ip, None).await,
        queue.reject(&pool, ip, None).await,
        queue.reopen(&pool, ip).await,
    ] {
        assert!(
            matches!(result, Err(ReviewError::VolumeNotFound(found)) if found == ip),
            "a decision on an address with no volume row must fail, not silently do nothing"
        );
    }
    let merit_state: ReviewState =
        sqlx::query_scalar("SELECT state FROM review_queue WHERE source_ip = $1::inet")
            .bind("192.0.2.54")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(merit_state, ReviewState::Pending);
}

/// The two queues are separate decisions in both directions: approving an address on its score
/// leaves a volume row for another address untouched, and the review queue's own scans never
/// read or write `volume_review`.
#[sqlx::test(migrations = false)]
async fn the_review_queue_scans_leave_volume_rows_alone(pool: PgPool) {
    migrate(&pool).await;
    let flood = "192.0.2.55";
    seed_flood(&pool, flood).await;
    let volume = queue();
    volume.populate(&pool).await.unwrap();
    volume
        .approve(&pool, flood.parse().unwrap(), None)
        .await
        .unwrap();
    let before = fetch_row(&pool, flood).await;

    let merit = ReviewQueue::new().offering_reserved_addresses();
    assert_eq!(
        merit.populate(&pool).await.unwrap(),
        0,
        "a flood is not eligible, so it is never offered for vendor reporting"
    );
    merit.withdraw(&pool).await.unwrap();
    merit.resolve_reserved(&pool).await.unwrap();

    assert_eq!(fetch_row(&pool, flood).await, before);
    let merit_rows: i64 = sqlx::query_scalar("SELECT count(*) FROM review_queue")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(
        merit_rows, 0,
        "a volume approval creates no review-queue row"
    );
}

/// History is read newest decision first, and a page that shows only the latest can bound it.
#[sqlx::test(migrations = false)]
async fn list_by_state_orders_by_decision_time_and_honours_its_limit(pool: PgPool) {
    migrate(&pool).await;
    let ips = ["192.0.2.60", "192.0.2.61", "192.0.2.62"];
    for (i, ip) in ips.iter().enumerate() {
        sqlx::query(
            "INSERT INTO volume_review \
             (source_ip, state, established_events_at_surface, decided_at) \
             VALUES ($1::inet, 'rejected', 1000, now() - make_interval(hours => $2))",
        )
        .bind(ip)
        .bind(i as i32)
        .execute(&pool)
        .await
        .unwrap();
    }
    let queue = queue();

    let all = queue
        .list_by_state(&pool, ReviewState::Rejected, None)
        .await
        .unwrap();
    let order: Vec<String> = all.iter().map(|e| e.source_ip.to_string()).collect();
    assert_eq!(order, ips, "most recently decided first");

    let latest = queue
        .list_by_state(&pool, ReviewState::Rejected, Some(2))
        .await
        .unwrap();
    assert_eq!(latest.len(), 2);
    assert_eq!(latest[0].source_ip.to_string(), ips[0]);
    assert!(
        queue
            .list_by_state(&pool, ReviewState::Approved, None)
            .await
            .unwrap()
            .is_empty()
    );
}

/// A merit-eligible address that also floods is offered in BOTH queues until the operator decides
/// its score entry: the two approvals do different things, and neither is implied by the other
/// being merely pending.
#[sqlx::test(migrations = false)]
async fn an_eligible_flooding_address_is_offered_until_its_score_entry_is_approved(pool: PgPool) {
    migrate(&pool).await;
    let ip = "192.0.2.63";
    let when = Utc::now() - Duration::minutes(10);
    // A confirmed-real session and two corroborating signals: eligible and tiered.
    for (signal, protocol, authenticated) in [
        (SignalType::HoneypotLoginAttempt, Protocol::Tcp, true),
        (SignalType::SshBruteForce, Protocol::Tcp, true),
        (SignalType::CatchallProbe, Protocol::Udp, false),
    ] {
        append_event(&pool, ev(ip, signal, protocol, authenticated, when))
            .await
            .unwrap();
    }
    let merit = ReviewQueue::new().offering_reserved_addresses();
    assert_eq!(merit.populate(&pool).await.unwrap(), 1);
    seed_flood(&pool, ip).await;

    let volume = queue();
    assert_eq!(volume.populate(&pool).await.unwrap(), 1);
    assert_eq!(state_of(&pool, ip).await, Some(ReviewState::Pending));

    merit
        .approve(&pool, ip.parse().unwrap(), None)
        .await
        .unwrap();
    assert_eq!(volume.withdraw(&pool).await.unwrap(), 1);
    assert_eq!(state_of(&pool, ip).await, None);
    assert_eq!(
        volume.populate(&pool).await.unwrap(),
        0,
        "and it is not offered again while that approval stands"
    );
}
