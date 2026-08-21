//! Real-Postgres tests for `FeedBuilder::build`, sharing the persistent `propolis_test` database
//! with other crates' tests (see the project's `local-gate-toolchain` note). Every test seeds
//! distinct source IPs outside every reserved range (see `crates/feed/tests/exclusion_test.rs` for
//! why 45.10.30.0/24 and a made-up IPv6 prefix are used as "ordinary public address" fixtures
//! rather than the RFC5737 ranges other crates' tests use - this crate's own exclusion engine
//! would otherwise filter those RFC5737 fixtures straight back out). Run with
//! `--test-threads=1`, same as `intake`/`review`: `append_event` serializes via a Postgres
//! advisory lock scoped to a transaction, not a test.
//!
//! `reset_ip` wipes leftover `event`/`ip_score` rows for a test's IP before seeding, matching
//! `review`'s `reset_ip`/`reset_vendor` discipline for rerun-safety against this same persistent,
//! never-reset database: `event_count` and the raw score accumulate per source IP across every
//! `append_event` call ever made against it, so re-running this suite a second time without a
//! reset would double up on these fixed IPs and desync every count/tier assertion below.
//!
//! Event timestamps use `Utc::now()` (captured once per test), not a fixed historical string:
//! `FeedBuilder::build` reads scores via `core_scoring::read_score`, which decays to the ACTUAL
//! current wall clock, not to the event's own timestamp. A fixed past timestamp (as core-scoring's
//! own `#[sqlx::test]` scenarios use) would decay to near-zero over the real elapsed time between
//! seeding and the test run, breaking every tier/eligibility assertion below.

use std::net::IpAddr;

use chrono::{DateTime, Timelike, Utc};
use core_scoring::{EventInput, FeedTier, Protocol, SignalType, append_event, read_score};
use feed::{ExclusionEngine, FeedBuilder, FeedConfig};
use review::queue::ReviewQueue;
use sqlx::PgPool;

async fn setup_pool() -> PgPool {
    let url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://propolis:propolis@localhost:5432/propolis_test".into());
    let pool = PgPool::connect(&url).await.unwrap();
    sqlx::migrate!("../core-scoring/migrations")
        .run(&pool)
        .await
        .unwrap();
    review::migrator().run(&pool).await.unwrap();
    pool
}

/// Deletes any leftover `ip_score`/`event` rows for `ip` from a previous run of this suite. See
/// the module doc comment for why this is required for rerun-safety, not merely tidy.
async fn reset_ip(pool: &PgPool, ip: IpAddr) {
    let ip_txt = ip.to_string();
    sqlx::query("DELETE FROM review_queue WHERE source_ip = $1::inet")
        .bind(&ip_txt)
        .execute(pool)
        .await
        .unwrap();
    sqlx::query("DELETE FROM ip_score WHERE source_ip = $1::inet")
        .bind(&ip_txt)
        .execute(pool)
        .await
        .unwrap();
    sqlx::query("DELETE FROM event WHERE source_ip = $1::inet")
        .bind(&ip_txt)
        .execute(pool)
        .await
        .unwrap();
}

fn ev(
    ip: IpAddr,
    signal: SignalType,
    protocol: Protocol,
    authenticated: bool,
    observed_at: DateTime<Utc>,
) -> EventInput {
    EventInput::from_signal(
        ip,
        None,
        "feed-test-sensor".into(),
        signal,
        protocol,
        authenticated,
        observed_at,
        serde_json::json!({}),
        None,
    )
}

fn is_coarsened(dt: DateTime<Utc>) -> bool {
    dt.minute() == 0 && dt.second() == 0 && dt.nanosecond() == 0
}

/// Seeds a qualifying entry: an authenticated-TCP honeypot event (confirmed-real) plus a
/// corroborating `CatchallProbe` in a different category, both at `now` (negligible decay by the
/// time the build reads it back). `honeypot_weight` decides the tier: HoneypotMalwareUpload (80,
/// conf 0.980) plus CatchallProbe (15) gives raw 95 / conf 0.980 -> Aggressive.
/// HoneypotFileDownload (70, conf 0.960) plus CatchallProbe (15) gives raw 85 / conf 0.960 ->
/// Standard (raw < 90).
async fn seed_qualifying(
    pool: &PgPool,
    ip: IpAddr,
    honeypot_signal: SignalType,
    now: DateTime<Utc>,
) {
    reset_ip(pool, ip).await;
    append_event(pool, ev(ip, honeypot_signal, Protocol::Tcp, true, now))
        .await
        .unwrap();
    append_event(
        pool,
        ev(ip, SignalType::CatchallProbe, Protocol::Udp, false, now),
    )
    .await
    .unwrap();
    // The feed builder now requires operator approval (INNER JOIN review_queue WHERE
    // state='approved'). Populate and approve the entry so the feed can see it.
    let queue = ReviewQueue::new();
    queue.populate(pool).await.unwrap();
    queue.approve(pool, ip, None).await.unwrap();
}

#[tokio::test]
async fn aggressive_and_standard_entries_are_built_sorted_and_isolated_by_tier() {
    let pool = setup_pool().await;
    let now = Utc::now();

    // Two Aggressive-tier IPs, seeded in descending order to prove the output re-sorts ascending.
    let agg_hi: IpAddr = "45.10.30.90".parse().unwrap();
    let agg_lo: IpAddr = "45.10.30.9".parse().unwrap();
    seed_qualifying(&pool, agg_hi, SignalType::HoneypotMalwareUpload, now).await;
    seed_qualifying(&pool, agg_lo, SignalType::HoneypotMalwareUpload, now).await;

    // One Standard-tier IP: raw 85 (70+15), conf 0.96 -> Standard (raw < 90's Aggressive floor).
    let std_ip: IpAddr = "45.10.30.50".parse().unwrap();
    seed_qualifying(&pool, std_ip, SignalType::HoneypotFileDownload, now).await;

    let exclusions = ExclusionEngine::new(Vec::new(), Vec::new());
    let config = FeedConfig::default();
    let snapshot = FeedBuilder::build(&pool, &exclusions, &config)
        .await
        .unwrap();

    let agg_ips: Vec<IpAddr> = snapshot.aggressive.iter().map(|e| e.source_ip).collect();
    assert!(agg_ips.contains(&agg_hi), "{agg_ips:?}");
    assert!(agg_ips.contains(&agg_lo), "{agg_ips:?}");
    let hi_idx = agg_ips.iter().position(|ip| *ip == agg_hi).unwrap();
    let lo_idx = agg_ips.iter().position(|ip| *ip == agg_lo).unwrap();
    assert!(
        lo_idx < hi_idx,
        "expected ascending IP order within the tier: {agg_ips:?}"
    );

    for entry in snapshot
        .aggressive
        .iter()
        .filter(|e| e.source_ip == agg_hi || e.source_ip == agg_lo)
    {
        assert_eq!(entry.tier, Some(FeedTier::Aggressive));
        assert_eq!(entry.event_count, 2);
        assert_eq!(entry.distinct_categories, 2);
        assert_eq!(entry.valid_from, snapshot.build_time);
        assert_eq!(
            entry.valid_until,
            snapshot.build_time + config.aggressive_ttl
        );
    }

    let std_entry = snapshot
        .standard
        .iter()
        .find(|e| e.source_ip == std_ip)
        .expect("standard-tier IP missing from snapshot");
    assert_eq!(std_entry.tier, Some(FeedTier::Standard));
    assert_eq!(std_entry.event_count, 2);
    assert_eq!(std_entry.distinct_categories, 2);
    assert_eq!(
        std_entry.valid_until,
        snapshot.build_time + config.standard_ttl
    );

    // Cross-tier isolation: neither list leaks the other's IPs.
    assert!(
        !snapshot
            .standard
            .iter()
            .any(|e| e.source_ip == agg_hi || e.source_ip == agg_lo)
    );
    assert!(!snapshot.aggressive.iter().any(|e| e.source_ip == std_ip));
}

#[tokio::test]
async fn ineligible_single_event_ip_never_appears() {
    let pool = setup_pool().await;
    let now = Utc::now();
    let ip: IpAddr = "45.10.30.60".parse().unwrap();
    reset_ip(&pool, ip).await;

    // A single event: event_count=1 fails the eligibility floor (needs >=2) regardless of weight.
    append_event(
        &pool,
        ev(
            ip,
            SignalType::HoneypotMalwareUpload,
            Protocol::Tcp,
            true,
            now,
        ),
    )
    .await
    .unwrap();

    let score = read_score(&pool, ip).await.unwrap().unwrap();
    assert!(!score.eligible, "sanity: single event must not be eligible");
    assert!(!score.recommended_for_blocklist);

    let exclusions = ExclusionEngine::new(Vec::new(), Vec::new());
    let config = FeedConfig::default();
    let snapshot = FeedBuilder::build(&pool, &exclusions, &config)
        .await
        .unwrap();

    assert!(!snapshot.aggressive.iter().any(|e| e.source_ip == ip));
    assert!(!snapshot.standard.iter().any(|e| e.source_ip == ip));
}

#[tokio::test]
async fn recommended_but_tier_none_is_excluded_fail_closed() {
    let pool = setup_pool().await;
    let now = Utc::now();
    let ip: IpAddr = "45.10.30.70".parse().unwrap();
    reset_ip(&pool, ip).await;

    // raw = 40 (HoneypotConnection) + 15 (CatchallProbe) = 55, in [50, 75): eligible
    // (confirmed-real honeypot + a second category) and recommended_for_blocklist (effective
    // score = raw * breadth_factor >= raw >= 50), but tier is None because the STANDARD floor
    // needs raw >= 75. This mirrors core-scoring's own
    // `breadth_raises_blocklist_never_vendor_tier` end-to-end scenario - exactly the
    // "should not happen but fail-closed anyway" case the design calls out for the builder.
    append_event(
        &pool,
        ev(ip, SignalType::HoneypotConnection, Protocol::Tcp, true, now),
    )
    .await
    .unwrap();
    append_event(
        &pool,
        ev(ip, SignalType::CatchallProbe, Protocol::Udp, false, now),
    )
    .await
    .unwrap();

    // Sanity: confirm this really is the recommended-but-untiered edge case, not a vacuous setup.
    let score = read_score(&pool, ip).await.unwrap().unwrap();
    assert!(score.eligible);
    assert!(score.recommended_for_blocklist);
    assert_eq!(score.tier, None);

    let exclusions = ExclusionEngine::new(Vec::new(), Vec::new());
    let config = FeedConfig::default();
    let snapshot = FeedBuilder::build(&pool, &exclusions, &config)
        .await
        .unwrap();

    assert!(!snapshot.aggressive.iter().any(|e| e.source_ip == ip));
    assert!(!snapshot.standard.iter().any(|e| e.source_ip == ip));
}

#[tokio::test]
async fn delisted_qualifying_ip_is_excluded_from_output() {
    let pool = setup_pool().await;
    let now = Utc::now();
    let ip: IpAddr = "45.10.30.80".parse().unwrap();

    seed_qualifying(&pool, ip, SignalType::HoneypotFileDownload, now).await;
    let score = read_score(&pool, ip).await.unwrap().unwrap();
    assert!(score.eligible && score.recommended_for_blocklist && score.tier.is_some());

    // Negative control: without the delist, this IP qualifies (Standard tier).
    let permissive = ExclusionEngine::new(Vec::new(), Vec::new());
    let config = FeedConfig::default();
    let baseline = FeedBuilder::build(&pool, &permissive, &config)
        .await
        .unwrap();
    assert!(
        baseline.standard.iter().any(|e| e.source_ip == ip),
        "negative control failed: ip should qualify without a delist"
    );

    let delisted = ExclusionEngine::new(Vec::new(), vec![ip]);
    let snapshot = FeedBuilder::build(&pool, &delisted, &config).await.unwrap();
    assert!(!snapshot.aggressive.iter().any(|e| e.source_ip == ip));
    assert!(!snapshot.standard.iter().any(|e| e.source_ip == ip));
}

#[tokio::test]
async fn all_output_timestamps_are_coarsened_to_hour_boundaries() {
    let pool = setup_pool().await;
    let now = Utc::now();
    let ip: IpAddr = "45.10.30.95".parse().unwrap();

    seed_qualifying(&pool, ip, SignalType::HoneypotMalwareUpload, now).await;

    let exclusions = ExclusionEngine::new(Vec::new(), Vec::new());
    let config = FeedConfig::default();
    let snapshot = FeedBuilder::build(&pool, &exclusions, &config)
        .await
        .unwrap();

    assert!(is_coarsened(snapshot.build_time));
    let entry = snapshot
        .aggressive
        .iter()
        .find(|e| e.source_ip == ip)
        .expect("seeded ip missing from snapshot");
    assert!(is_coarsened(entry.first_seen));
    assert!(is_coarsened(entry.last_seen));
    assert!(is_coarsened(entry.valid_from));
    assert!(is_coarsened(entry.valid_until));
    assert_eq!(entry.first_seen, feed::coarsen_to_hour(now));
    assert_eq!(entry.valid_from, snapshot.build_time);
}

#[tokio::test]
async fn ipv6_source_ip_is_supported_end_to_end() {
    let pool = setup_pool().await;
    let now = Utc::now();
    let ip: IpAddr = "2003:aaaa:bbbb::42".parse().unwrap();

    seed_qualifying(&pool, ip, SignalType::HoneypotMalwareUpload, now).await;

    let exclusions = ExclusionEngine::new(Vec::new(), Vec::new());
    let config = FeedConfig::default();
    let snapshot = FeedBuilder::build(&pool, &exclusions, &config)
        .await
        .unwrap();

    let entry = snapshot
        .aggressive
        .iter()
        .find(|e| e.source_ip == ip)
        .expect("ipv6 ip missing from snapshot");
    assert_eq!(entry.tier, Some(FeedTier::Aggressive));
    assert!(matches!(entry.source_ip, IpAddr::V6(_)));
}

#[tokio::test]
async fn db_error_during_build_fails_closed() {
    let pool = setup_pool().await;
    pool.close().await;

    let exclusions = ExclusionEngine::new(Vec::new(), Vec::new());
    let config = FeedConfig::default();
    let result = FeedBuilder::build(&pool, &exclusions, &config).await;
    assert!(
        result.is_err(),
        "a closed pool must fail the build, not return a partial/empty snapshot"
    );
}

#[tokio::test]
async fn eligible_ip_without_approval_is_excluded_from_feed() {
    let pool = setup_pool().await;
    let now = Utc::now();
    let ip: IpAddr = "45.10.30.99".parse().unwrap();
    reset_ip(&pool, ip).await;

    // Seed events that cross the eligibility gate (confirmed-real + multi-category),
    // but do NOT approve through the review queue.
    append_event(
        &pool,
        ev(
            ip,
            SignalType::HoneypotMalwareUpload,
            Protocol::Tcp,
            true,
            now,
        ),
    )
    .await
    .unwrap();
    append_event(
        &pool,
        ev(ip, SignalType::CatchallProbe, Protocol::Udp, false, now),
    )
    .await
    .unwrap();

    let score = read_score(&pool, ip).await.unwrap().unwrap();
    assert!(
        score.eligible && score.recommended_for_blocklist,
        "precondition: IP must be eligible and recommended"
    );

    let exclusions = ExclusionEngine::new(Vec::new(), Vec::new());
    let config = FeedConfig::default();
    let snapshot = FeedBuilder::build(&pool, &exclusions, &config)
        .await
        .unwrap();

    assert!(
        !snapshot.aggressive.iter().any(|e| e.source_ip == ip)
            && !snapshot.standard.iter().any(|e| e.source_ip == ip),
        "an eligible IP without operator approval must NOT appear in the feed"
    );
}

#[tokio::test]
async fn entries_carry_the_distinct_signal_types_the_address_actually_triggered() {
    // `distinct_categories` is a count over five coarse sensor classes and says nothing about what
    // an address did. This is the field a consumer filters on to keep malware uploaders and drop
    // port-scan noise, so it must reflect the events actually recorded, deduplicated and sorted.
    let pool = setup_pool().await;
    let now = Utc::now();
    let ip: IpAddr = "45.10.30.77".parse().unwrap();

    reset_ip(&pool, ip).await;
    // Two events of the SAME type, so a missing DISTINCT would show up as a duplicate, plus two
    // others - seeded out of alphabetical order so the sort is proven rather than coincidental.
    append_event(
        &pool,
        ev(
            ip,
            SignalType::HoneypotMalwareUpload,
            Protocol::Tcp,
            true,
            now,
        ),
    )
    .await
    .unwrap();
    append_event(
        &pool,
        ev(
            ip,
            SignalType::HoneypotMalwareUpload,
            Protocol::Tcp,
            true,
            now,
        ),
    )
    .await
    .unwrap();
    append_event(
        &pool,
        ev(ip, SignalType::SshBruteForce, Protocol::Tcp, false, now),
    )
    .await
    .unwrap();
    append_event(
        &pool,
        ev(ip, SignalType::CatchallProbe, Protocol::Udp, false, now),
    )
    .await
    .unwrap();
    let queue = ReviewQueue::new();
    queue.populate(&pool).await.unwrap();
    queue.approve(&pool, ip, None).await.unwrap();

    let snapshot = FeedBuilder::build(
        &pool,
        &ExclusionEngine::new(Vec::new(), Vec::new()),
        &FeedConfig::default(),
    )
    .await
    .unwrap();

    let entry = snapshot
        .aggressive
        .iter()
        .chain(snapshot.standard.iter())
        .find(|e| e.source_ip == ip)
        .expect("seeded IP must be in the feed");

    assert_eq!(
        entry.categories,
        [
            "catchall_probe",
            "honeypot_malware_upload",
            "ssh_brute_force"
        ],
        "expected the deduplicated, sorted wire vocabulary"
    );
}

#[tokio::test]
async fn retention_windows_are_built_with_their_configured_label_and_duration() {
    // The window label is the published filename (`all-{label}.txt`) and the retention it carries
    // is what that file's header states, so a window whose label and duration disagree would
    // advertise a coverage it does not have.
    let pool = setup_pool().await;
    let now = Utc::now();
    let ip: IpAddr = "45.10.30.78".parse().unwrap();
    seed_qualifying(&pool, ip, SignalType::HoneypotMalwareUpload, now).await;

    let config = FeedConfig {
        windows: vec![
            ("7d".into(), chrono::Duration::days(7)),
            ("90d".into(), chrono::Duration::days(90)),
        ],
        ..FeedConfig::default()
    };
    let snapshot = FeedBuilder::build(
        &pool,
        &ExclusionEngine::new(Vec::new(), Vec::new()),
        &config,
    )
    .await
    .unwrap();

    let labels: Vec<&str> = snapshot.windows.iter().map(|w| w.label.as_str()).collect();
    assert_eq!(labels, ["7d", "90d"]);
    assert_eq!(snapshot.windows[0].retention, chrono::Duration::days(7));
    assert_eq!(snapshot.windows[1].retention, chrono::Duration::days(90));

    // A just-seeded address falls inside every window, and the windows nest.
    for window in &snapshot.windows {
        assert!(
            window.entries.iter().any(|e| e.source_ip == ip),
            "{} must contain the freshly-seeded address",
            window.label
        );
        // Validity is anchored on the entry's own last activity, carrying the window's retention.
        let entry = window.entries.iter().find(|e| e.source_ip == ip).unwrap();
        assert_eq!(entry.valid_until - entry.valid_from, window.retention);
    }
    assert!(snapshot.windows[1].entries.len() >= snapshot.windows[0].entries.len());
}
