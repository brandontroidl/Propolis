//! Real-Postgres tests for `FeedBuilder::build`. Each test owns a fresh database
//! (`#[sqlx::test]`): `event_count` and the raw score accumulate per source IP across every
//! `append_event` call, and the build and `ReviewQueue::populate` read whole tables, so a shared
//! database would let earlier runs and other crates' rows change a result. Resetting a shared one
//! meant `DELETE FROM event`, which severs the hash chain every other suite verifies. Every test
//! seeds source IPs outside every reserved range (see `crates/feed/tests/exclusion_test.rs` for
//! why 45.10.30.0/24 and a made-up IPv6 prefix are used as "ordinary public address" fixtures
//! rather than the RFC5737 ranges other crates' tests use - this crate's own exclusion engine
//! would otherwise filter those RFC5737 fixtures straight back out).
//!
//! Event timestamps use `Utc::now()` (captured once per test), not a fixed historical string:
//! `FeedBuilder::build` reads scores via `core_scoring::read_score`, which decays to the ACTUAL
//! current wall clock, not to the event's own timestamp. A fixed past timestamp (as core-scoring's
//! own `#[sqlx::test]` scenarios use) would decay to near-zero over the real elapsed time between
//! seeding and the test run, breaking every tier/eligibility assertion below.

use std::net::IpAddr;

use chrono::{DateTime, Timelike, Utc};
use core_scoring::{
    EventInput, FeedTier, Protocol, SignalType, append_event, append_events, read_score,
};
use feed::{ExclusionEngine, FeedBuilder, FeedConfig, FeedSnapshot};
use review::queue::ReviewQueue;
use review::volume::VolumeQueue;
use sqlx::PgPool;

async fn migrate(pool: &PgPool) {
    sqlx::migrate!("../core-scoring/migrations")
        .run(pool)
        .await
        .unwrap();
    review::migrator().run(pool).await.unwrap();
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

#[sqlx::test(migrations = false)]
async fn aggressive_and_standard_entries_are_built_sorted_and_isolated_by_tier(pool: PgPool) {
    migrate(&pool).await;
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

#[sqlx::test(migrations = false)]
async fn ineligible_single_event_ip_never_appears(pool: PgPool) {
    migrate(&pool).await;
    let now = Utc::now();
    let ip: IpAddr = "45.10.30.60".parse().unwrap();

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

#[sqlx::test(migrations = false)]
async fn recommended_but_tier_none_is_excluded_fail_closed(pool: PgPool) {
    migrate(&pool).await;
    let now = Utc::now();
    let ip: IpAddr = "45.10.30.70".parse().unwrap();

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

#[sqlx::test(migrations = false)]
async fn delisted_qualifying_ip_is_excluded_from_output(pool: PgPool) {
    migrate(&pool).await;
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

/// Like `seed_qualifying` but the honeypot event carries a crawler User-Agent, as the HTTP sensor
/// records it.
async fn seed_claiming_crawler(pool: &PgPool, ip: IpAddr, now: DateTime<Utc>) {
    let claimed = EventInput::from_signal(
        ip,
        None,
        "feed-test-sensor".into(),
        SignalType::HoneypotMalwareUpload,
        Protocol::Tcp,
        true,
        now,
        serde_json::json!({
            "user_agent": "Mozilla/5.0 (compatible; ClaudeBot/1.0; +claudebot@anthropic.com)",
            "claimed_crawler": "ClaudeBot",
        }),
        None,
    );
    append_event(pool, claimed).await.unwrap();
    append_event(
        pool,
        ev(ip, SignalType::CatchallProbe, Protocol::Udp, false, now),
    )
    .await
    .unwrap();
    let queue = ReviewQueue::new();
    queue.populate(pool).await.unwrap();
    queue.approve(pool, ip, None).await.unwrap();
}

#[sqlx::test(migrations = false)]
async fn a_claimed_crawler_is_published_unless_its_address_is_in_an_operator_range_file(
    pool: PgPool,
) {
    migrate(&pool).await;
    let now = Utc::now();
    let spoofer: IpAddr = "45.10.30.201".parse().unwrap();
    let listed: IpAddr = "45.10.30.202".parse().unwrap();
    seed_claiming_crawler(&pool, spoofer, now).await;
    seed_claiming_crawler(&pool, listed, now).await;

    let config = FeedConfig::default();
    let baseline = FeedBuilder::build(
        &pool,
        &ExclusionEngine::new(Vec::new(), Vec::new()),
        &config,
    )
    .await
    .unwrap();
    for ip in [spoofer, listed] {
        assert!(
            baseline.aggressive.iter().any(|e| e.source_ip == ip),
            "{ip}: a claimed crawler qualifies on its behaviour; the User-Agent exempts nothing"
        );
    }

    // The operator's file lists only the second address's range. Both addresses sent the same
    // ClaudeBot User-Agent; only the address decides.
    let nets = feed::exclusion::parse_allowlist_text(
        "# operator-verified crawler range\n45.10.30.202/32\n",
    )
    .unwrap();
    let snapshot = FeedBuilder::build(&pool, &ExclusionEngine::new(nets, Vec::new()), &config)
        .await
        .unwrap();
    assert!(
        snapshot.aggressive.iter().any(|e| e.source_ip == spoofer),
        "a User-Agent claiming ClaudeBot from an unlisted address must still be published"
    );
    assert!(
        !snapshot.aggressive.iter().any(|e| e.source_ip == listed),
        "an address in the operator's range file must be excluded"
    );
}

#[sqlx::test(migrations = false)]
async fn all_output_timestamps_are_coarsened_to_hour_boundaries(pool: PgPool) {
    migrate(&pool).await;
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

#[sqlx::test(migrations = false)]
async fn ipv6_source_ip_is_supported_end_to_end(pool: PgPool) {
    migrate(&pool).await;
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

#[sqlx::test(migrations = false)]
async fn db_error_during_build_fails_closed(pool: PgPool) {
    migrate(&pool).await;
    pool.close().await;

    let exclusions = ExclusionEngine::new(Vec::new(), Vec::new());
    let config = FeedConfig::default();
    let result = FeedBuilder::build(&pool, &exclusions, &config).await;
    assert!(
        result.is_err(),
        "a closed pool must fail the build, not return a partial/empty snapshot"
    );
}

#[sqlx::test(migrations = false)]
async fn eligible_ip_without_approval_is_excluded_from_feed(pool: PgPool) {
    migrate(&pool).await;
    let now = Utc::now();
    let ip: IpAddr = "45.10.30.99".parse().unwrap();

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

#[sqlx::test(migrations = false)]
async fn entries_carry_the_distinct_signal_types_the_address_actually_triggered(pool: PgPool) {
    // `distinct_categories` is a count over five coarse sensor classes and says nothing about what
    // an address did. This is the field a consumer filters on to keep malware uploaders and drop
    // port-scan noise, so it must reflect the events actually recorded, deduplicated and sorted.
    migrate(&pool).await;
    let now = Utc::now();
    let ip: IpAddr = "45.10.30.77".parse().unwrap();

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

#[sqlx::test(migrations = false)]
async fn retention_windows_are_built_with_their_configured_label_and_duration(pool: PgPool) {
    // The window label is the published filename (`all-{label}.txt`) and the retention it carries
    // is what that file's header states, so a window whose label and duration disagree would
    // advertise a coverage it does not have.
    migrate(&pool).await;
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

/// Rows the plan's scans of `event` produced, summed over their loops: what the statement read
/// from the ledger, which a test can bound without depending on timing.
fn event_rows_read(plan: &[String]) -> f64 {
    let number_after = |line: &str, key: &str| -> f64 {
        let at = line.find(key).expect(key) + key.len();
        let end = line[at..]
            .find(|c: char| !(c.is_ascii_digit() || c == '.'))
            .unwrap_or(line.len() - at);
        line[at..at + end].parse().unwrap()
    };
    plan.iter()
        .filter(|l| l.contains(" on event ") && l.contains("(actual"))
        .map(|l| number_after(l, "rows=") * number_after(l, "loops="))
        .sum()
}

/// A scored, approved, blocklist-recommended address with `events` ledger rows of three signal
/// types, written directly (the chain trigger is off for the test) and last seen `last_seen_ago`
/// ago.
async fn seed_heavy_approved(pool: &PgPool, ip: &str, events: i32, last_seen_ago: &str) {
    sqlx::query(
        "INSERT INTO event (source_ip, sensor, signal_type, protocol, authenticated, category, \
                            weight, confidence, observed_at, hash) \
         SELECT $1::inet, 'feed-test-sensor', \
                (ARRAY['port_scan', 'honeypot_connection', 'honeypot_session_end'])[1 + g % 3] \
                    ::signal_type_enum, \
                'tcp', false, 'honeypot', 1, 0.5, now() - g * interval '1 second', \
                sha256(convert_to($1 || g::text, 'UTF8')) \
         FROM generate_series(1, $2) g",
    )
    .bind(ip)
    .bind(events)
    .execute(pool)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO ip_score (source_ip, raw_score, decay_anchor, max_confidence, event_count, \
             distinct_categories, has_confirmed_real, distinct_wan_count, distinct_sensor_count, \
             first_seen, last_seen, eligible, recommended_for_blocklist, tier) \
         VALUES ($1::inet, 95, now(), 0.9, $2, 2, true, 1, 1, now() - interval '30 days', \
                 now() - $3::interval, true, true, 'aggressive')",
    )
    .bind(ip)
    .bind(events)
    .bind(last_seen_ago)
    .execute(pool)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO review_queue (source_ip, state, score_at_surface, categories_at_surface) \
         VALUES ($1::inet, 'approved', 95, '{}'::jsonb)",
    )
    .bind(ip)
    .execute(pool)
    .await
    .unwrap();
}

#[sqlx::test(migrations = false)]
async fn the_build_reads_signal_types_by_probe_and_only_for_addresses_a_feed_can_still_publish(
    pool: PgPool,
) {
    // The signal types of an address were `SELECT DISTINCT signal_type FROM event WHERE source_ip
    // = ...`, which reads the address's whole history (4.3 s for 5,566 approved addresses on the
    // live node), and it ran for every approved address, including those whose last event is too
    // old for any feed to carry. The statement now probes the 17 enum members and skips the
    // expired, so what it reads from the ledger is bounded by the number of live candidates.
    migrate(&pool).await;
    sqlx::query("ALTER TABLE event DISABLE TRIGGER trg_enforce_chain_linkage")
        .execute(&pool)
        .await
        .unwrap();
    // 3,000 events and seen an hour ago: published. 2,000 events and last seen ten days ago: past
    // the longest default TTL (48 h), so never published.
    seed_heavy_approved(&pool, "45.10.30.201", 3000, "1 hour").await;
    seed_heavy_approved(&pool, "45.10.30.202", 2000, "10 days").await;
    sqlx::query("ANALYZE event").execute(&pool).await.unwrap();

    let cutoff = Utc::now() - chrono::Duration::hours(48) - chrono::Duration::minutes(1);
    let mut conn = pool.acquire().await.unwrap();
    let plan: Vec<String> = sqlx::query_scalar(sqlx::AssertSqlSafe(format!(
        "EXPLAIN (ANALYZE, COSTS OFF) {}",
        feed::builder::merit_candidates_sql()
    )))
    .bind(cutoff)
    .fetch_all(&mut *conn)
    .await
    .unwrap();
    let read = event_rows_read(&plan);
    assert!(
        read < 4.0,
        "the live address has 3 signal types among 17 enum members, so its 17 probes return 3 \
         rows (the plan prints averages to two places) and the expired address none; read {read} \
         ledger rows\n{}",
        plan.join("\n")
    );

    let snapshot = FeedBuilder::build(
        &pool,
        &ExclusionEngine::new(Vec::new(), Vec::new()),
        &FeedConfig::default(),
    )
    .await
    .unwrap();
    let live = snapshot
        .aggressive
        .iter()
        .find(|e| e.source_ip == "45.10.30.201".parse::<IpAddr>().unwrap())
        .expect("the live address is published");
    assert_eq!(
        live.categories,
        ["honeypot_connection", "honeypot_session_end", "port_scan"]
    );
    assert!(
        !snapshot
            .aggressive
            .iter()
            .any(|e| e.source_ip == "45.10.30.202".parse::<IpAddr>().unwrap()),
        "an address last seen ten days ago is not published"
    );
}

// --- volume-listed addresses ---
//
// A volume candidate is an address with a thousand or more established TCP events and no
// confirmed-real session: the stored projection recommends it for the blocklist on that count
// alone. The count is whatever the sensor's log lines declared, so by default the build publishes
// such an address only once an operator has approved it.

/// A flood from `ip`: a thousand unauthenticated TCP connections, the last one at `last_event`.
/// They are a millisecond apart, so the 60 s dedup scores them as one sighting while the
/// established-event count still reaches the volume threshold, which is the case the volume rule
/// exists for. Unauthenticated, so the address never becomes eligible on these alone.
async fn seed_flood(pool: &PgPool, ip: IpAddr, last_event: DateTime<Utc>) {
    let events: Vec<EventInput> = (0..1000)
        .map(|i| {
            ev(
                ip,
                SignalType::HoneypotConnection,
                Protocol::Tcp,
                false,
                last_event - chrono::Duration::milliseconds(999 - i),
            )
        })
        .collect();
    let outcome = append_events(pool, events).await;
    assert!(outcome.failure.is_none(), "{:?}", outcome.failure);
    assert_eq!(outcome.appended, 1000);
}

/// The retention windows a default deployment publishes that matter here: the shortest and a
/// longer one, so "in the retention windows" is checked on more than one file.
fn config_with_windows(volume_auto_publish: bool) -> FeedConfig {
    FeedConfig {
        windows: vec![
            ("24h".into(), chrono::Duration::hours(24)),
            ("7d".into(), chrono::Duration::days(7)),
        ],
        volume_auto_publish,
        ..FeedConfig::default()
    }
}

async fn build(pool: &PgPool, config: &FeedConfig) -> FeedSnapshot {
    FeedBuilder::build(pool, &ExclusionEngine::new(Vec::new(), Vec::new()), config)
        .await
        .unwrap()
}

/// How many entries each retention window holds for `ip`.
fn window_entries(snapshot: &FeedSnapshot, ip: IpAddr) -> Vec<usize> {
    snapshot
        .windows
        .iter()
        .map(|w| w.entries.iter().filter(|e| e.source_ip == ip).count())
        .collect()
}

fn in_a_tier_file(snapshot: &FeedSnapshot, ip: IpAddr) -> bool {
    snapshot
        .aggressive
        .iter()
        .chain(snapshot.standard.iter())
        .any(|e| e.source_ip == ip)
}

#[sqlx::test(migrations = false)]
async fn a_volume_candidate_is_published_only_once_an_operator_approves_it(pool: PgPool) {
    migrate(&pool).await;
    let now = Utc::now();
    let undecided: IpAddr = "45.10.30.110".parse().unwrap();
    let pending: IpAddr = "45.10.30.111".parse().unwrap();
    let rejected: IpAddr = "45.10.30.112".parse().unwrap();
    let approved: IpAddr = "45.10.30.113".parse().unwrap();

    // The first address floods before the queue scan runs and never gets a row at all (a node
    // with the review subsystem off, or a build that runs before the next scan).
    seed_flood(&pool, undecided, now).await;
    let score = read_score(&pool, undecided).await.unwrap().unwrap();
    assert!(
        score.recommended_for_blocklist && !score.eligible,
        "precondition: the flood is listed on volume alone"
    );
    let config = config_with_windows(false);
    let snapshot = build(&pool, &config).await;
    assert_eq!(
        window_entries(&snapshot, undecided),
        [0, 0],
        "a volume candidate with no decision must not be published"
    );

    for ip in [pending, rejected, approved] {
        seed_flood(&pool, ip, now).await;
    }
    let queue = VolumeQueue::new();
    queue.populate(&pool).await.unwrap();
    queue.reject(&pool, rejected, None).await.unwrap();
    queue.approve(&pool, approved, None).await.unwrap();

    let snapshot = build(&pool, &config).await;
    for (ip, what) in [
        (undecided, "pending (surfaced by the scan above)"),
        (pending, "pending"),
        (rejected, "rejected"),
    ] {
        assert_eq!(
            window_entries(&snapshot, ip),
            [0, 0],
            "{ip} is {what}: it must not be published"
        );
        assert!(!in_a_tier_file(&snapshot, ip));
    }

    assert_eq!(
        window_entries(&snapshot, approved),
        [1, 1],
        "an approved volume candidate is published in every retention window it falls inside"
    );
    assert!(
        !in_a_tier_file(&snapshot, approved),
        "a volume listing never reaches the aggressive or standard file"
    );
    let entry = snapshot.windows[0]
        .entries
        .iter()
        .find(|e| e.source_ip == approved)
        .unwrap();
    assert_eq!(entry.tier, None);
    assert_eq!(entry.event_count, 1000);

    // Reopening takes it back out: publication follows the row's current state, not a decision
    // that was once made.
    queue.reopen(&pool, approved).await.unwrap();
    let snapshot = build(&pool, &config).await;
    assert_eq!(window_entries(&snapshot, approved), [0, 0]);
}

#[sqlx::test(migrations = false)]
async fn an_address_approved_on_its_score_is_published_on_volume_without_a_second_decision(
    pool: PgPool,
) {
    migrate(&pool).await;
    let now = Utc::now();
    let ip: IpAddr = "45.10.30.120".parse().unwrap();

    // Two days ago the address earned a tier and the operator approved it. Its score has since
    // decayed, and today it floods: the stored projection has no tier any more, so it is not a
    // merit candidate, but it meets the volume condition and the operator's approval stands.
    seed_qualifying(
        &pool,
        ip,
        SignalType::HoneypotMalwareUpload,
        now - chrono::Duration::days(2),
    )
    .await;
    seed_flood(&pool, ip, now).await;
    let score = read_score(&pool, ip).await.unwrap().unwrap();
    assert_eq!(score.tier, None, "precondition: no tier, so no merit entry");
    assert!(score.established_event_count >= 1000);
    let volume_rows: i64 = sqlx::query_scalar("SELECT count(*) FROM volume_review")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(volume_rows, 0, "precondition: no volume decision exists");

    let snapshot = build(&pool, &config_with_windows(false)).await;

    assert_eq!(window_entries(&snapshot, ip), [1, 1]);
    assert!(!in_a_tier_file(&snapshot, ip));
    let entry = snapshot.windows[1]
        .entries
        .iter()
        .find(|e| e.source_ip == ip)
        .unwrap();
    assert_eq!(entry.tier, None, "published as a volume entry");
}

#[sqlx::test(migrations = false)]
async fn an_approved_address_below_the_volume_threshold_is_not_a_volume_entry(pool: PgPool) {
    migrate(&pool).await;
    let now = Utc::now();
    let ip: IpAddr = "45.10.30.124".parse().unwrap();

    // The same history as the address above, except that today brings one connection instead of
    // a flood. The approval alone must not put it in the retention feeds: an approved address
    // with no tier is published only when it meets the volume condition.
    seed_qualifying(
        &pool,
        ip,
        SignalType::HoneypotMalwareUpload,
        now - chrono::Duration::days(2),
    )
    .await;
    append_event(
        &pool,
        ev(
            ip,
            SignalType::HoneypotConnection,
            Protocol::Tcp,
            false,
            now,
        ),
    )
    .await
    .unwrap();
    let score = read_score(&pool, ip).await.unwrap().unwrap();
    assert_eq!(score.tier, None, "precondition: no tier, so no merit entry");
    assert!(score.established_event_count < 1000);

    let snapshot = build(&pool, &config_with_windows(false)).await;

    assert_eq!(window_entries(&snapshot, ip), [0, 0]);
    assert!(!in_a_tier_file(&snapshot, ip));
}

#[sqlx::test(migrations = false)]
async fn a_review_queue_entry_that_is_not_approved_publishes_no_volume_listing(pool: PgPool) {
    migrate(&pool).await;
    let now = Utc::now();
    let ip: IpAddr = "45.10.30.123".parse().unwrap();

    // Eligible, offered in the review queue, and flooding. The volume statement accepts a
    // review-queue approval in place of a volume one, so every other state of that row must
    // leave the address unpublished.
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
    let queue = ReviewQueue::new();
    assert_eq!(queue.populate(&pool).await.unwrap(), 1);
    seed_flood(&pool, ip, now).await;

    let config = config_with_windows(false);
    assert_eq!(
        window_entries(&build(&pool, &config).await, ip),
        [0, 0],
        "pending"
    );
    queue.reject(&pool, ip, None).await.unwrap();
    assert_eq!(
        window_entries(&build(&pool, &config).await, ip),
        [0, 0],
        "rejected"
    );
    queue.snooze(&pool, ip, None).await.unwrap();
    assert_eq!(
        window_entries(&build(&pool, &config).await, ip),
        [0, 0],
        "snoozed"
    );

    queue.approve(&pool, ip, None).await.unwrap();
    assert_eq!(
        window_entries(&build(&pool, &config).await, ip),
        [1, 1],
        "approved: the same setup is published once the operator says so"
    );
}

#[sqlx::test(migrations = false)]
async fn an_address_that_is_a_merit_and_a_volume_candidate_is_published_once(pool: PgPool) {
    migrate(&pool).await;
    let now = Utc::now();
    let ip: IpAddr = "45.10.30.121".parse().unwrap();

    // Approved on its score and still tiered, and flooding as well. Both statements select it.
    seed_qualifying(&pool, ip, SignalType::HoneypotMalwareUpload, now).await;
    seed_flood(&pool, ip, now).await;
    let score = read_score(&pool, ip).await.unwrap().unwrap();
    assert!(
        score.eligible && score.tier.is_some() && score.established_event_count >= 1000,
        "precondition: a merit candidate that also meets the volume condition"
    );
    // A volume approval on top, so both of the volume statement's approval legs match it too.
    sqlx::query(
        "INSERT INTO volume_review (source_ip, state, established_events_at_surface, decided_at) \
         VALUES ($1::inet, 'approved', 1000, now())",
    )
    .bind(ip.to_string())
    .execute(&pool)
    .await
    .unwrap();

    let snapshot = build(&pool, &config_with_windows(false)).await;

    assert_eq!(
        window_entries(&snapshot, ip),
        [1, 1],
        "one entry per window, not a merit entry and a volume entry"
    );
    let entry = snapshot.windows[0]
        .entries
        .iter()
        .find(|e| e.source_ip == ip)
        .unwrap();
    assert!(
        entry.tier.is_some(),
        "the entry kept is the merit candidate, which carries the tier"
    );
    assert!(in_a_tier_file(&snapshot, ip));
}

#[sqlx::test(migrations = false)]
async fn a_delisted_address_is_not_published_on_volume_even_with_an_approved_row(pool: PgPool) {
    migrate(&pool).await;
    let now = Utc::now();
    let ip: IpAddr = "45.10.30.122".parse().unwrap();
    seed_flood(&pool, ip, now).await;
    let queue = VolumeQueue::new();
    queue.populate(&pool).await.unwrap();
    queue.approve(&pool, ip, None).await.unwrap();

    let config = config_with_windows(false);
    let baseline = build(&pool, &config).await;
    assert_eq!(
        window_entries(&baseline, ip),
        [1, 1],
        "negative control failed: the approved candidate is published before the delist"
    );

    // Only the latch is set, and the approved row is left in place: the console's delist removes
    // the row as well, so this is the state the builder's own check has to cover (a row approved
    // by a request that raced the delist, or restored from a dump).
    sqlx::query("UPDATE ip_score SET delisted = TRUE WHERE source_ip = $1::inet")
        .bind(ip.to_string())
        .execute(&pool)
        .await
        .unwrap();

    let snapshot = build(&pool, &config).await;
    assert_eq!(window_entries(&snapshot, ip), [0, 0]);
}

#[sqlx::test(migrations = false)]
async fn automatic_volume_publication_is_an_opt_in_that_needs_no_decision(pool: PgPool) {
    migrate(&pool).await;
    let now = Utc::now();
    let flood: IpAddr = "45.10.30.130".parse().unwrap();
    let eligible_flood: IpAddr = "45.10.30.131".parse().unwrap();

    seed_flood(&pool, flood, now).await;
    // Eligible (an authenticated session and a second event) and flooding, but never approved.
    append_event(
        &pool,
        ev(
            eligible_flood,
            SignalType::HoneypotMalwareUpload,
            Protocol::Tcp,
            true,
            now,
        ),
    )
    .await
    .unwrap();
    seed_flood(&pool, eligible_flood, now).await;
    let score = read_score(&pool, eligible_flood).await.unwrap().unwrap();
    assert!(score.eligible && score.established_event_count >= 1000);
    let decisions: i64 = sqlx::query_scalar(
        "SELECT (SELECT count(*) FROM volume_review) + (SELECT count(*) FROM review_queue)",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(decisions, 0, "precondition: no operator decision exists");

    // The default first: with no decision, nothing is published.
    let gated = build(&pool, &config_with_windows(false)).await;
    assert_eq!(window_entries(&gated, flood), [0, 0]);
    assert_eq!(window_entries(&gated, eligible_flood), [0, 0]);

    let automatic = build(&pool, &config_with_windows(true)).await;
    assert_eq!(
        window_entries(&automatic, flood),
        [1, 1],
        "with the opt-in a volume-listed address is published with no row in either queue"
    );
    assert!(!in_a_tier_file(&automatic, flood));
    assert_eq!(
        window_entries(&automatic, eligible_flood),
        [0, 0],
        "an eligible address is a merit candidate and waits for approval, opt-in or not"
    );
    assert!(!in_a_tier_file(&automatic, eligible_flood));
}

/// The opt-in adds listings and takes none away. An approved candidate that has also
/// authenticated is eligible, so the automatic condition (`eligible = false`) does not cover it;
/// read alone, that condition dropped the approved address from every retention feed the moment
/// the opt-in was set.
#[sqlx::test(migrations = false)]
async fn the_opt_in_publishes_everything_the_default_does_and_ignores_a_rejection(pool: PgPool) {
    migrate(&pool).await;
    let now = Utc::now();
    let approved_eligible: IpAddr = "45.10.30.140".parse().unwrap();
    let rejected_flood: IpAddr = "45.10.30.141".parse().unwrap();

    append_event(
        &pool,
        ev(
            approved_eligible,
            SignalType::HoneypotMalwareUpload,
            Protocol::Tcp,
            true,
            now,
        ),
    )
    .await
    .unwrap();
    seed_flood(&pool, approved_eligible, now).await;
    seed_flood(&pool, rejected_flood, now).await;
    let score = read_score(&pool, approved_eligible).await.unwrap().unwrap();
    assert!(
        score.eligible && score.established_event_count >= 1000,
        "precondition: a volume candidate that is also eligible"
    );

    let queue = VolumeQueue::new();
    assert_eq!(queue.populate(&pool).await.unwrap(), 2);
    queue.approve(&pool, approved_eligible, None).await.unwrap();
    queue.reject(&pool, rejected_flood, None).await.unwrap();

    let gated = build(&pool, &config_with_windows(false)).await;
    assert_eq!(window_entries(&gated, approved_eligible), [1, 1]);
    assert_eq!(window_entries(&gated, rejected_flood), [0, 0]);

    let automatic = build(&pool, &config_with_windows(true)).await;
    assert_eq!(
        window_entries(&automatic, approved_eligible),
        [1, 1],
        "setting the opt-in must not take an approved address out of the feeds"
    );
    assert_eq!(
        window_entries(&automatic, rejected_flood),
        [1, 1],
        "with the opt-in a bare flood is published whatever was decided"
    );
    assert!(!in_a_tier_file(&automatic, approved_eligible));
}

#[sqlx::test(migrations = false)]
async fn a_stored_last_seen_in_the_future_does_not_extend_validity_past_now_plus_the_window(
    pool: PgPool,
) {
    migrate(&pool).await;
    let now = Utc::now();
    let ip: IpAddr = "45.10.30.140".parse().unwrap();
    seed_flood(&pool, ip, now).await;
    let queue = VolumeQueue::new();
    queue.populate(&pool).await.unwrap();
    queue.approve(&pool, ip, None).await.unwrap();
    // What one log line dated ahead of the clock leaves behind: the projection takes `last_seen`
    // from the event's own timestamp.
    sqlx::query(
        "UPDATE ip_score SET last_seen = now() + interval '300 days' WHERE source_ip = $1::inet",
    )
    .bind(ip.to_string())
    .execute(&pool)
    .await
    .unwrap();

    let snapshot = build(&pool, &config_with_windows(false)).await;
    let after_build = Utc::now();

    for window in &snapshot.windows {
        let entry = window
            .entries
            .iter()
            .find(|e| e.source_ip == ip)
            .unwrap_or_else(|| panic!("{}: the address is still published", window.label));
        assert!(
            entry.valid_until <= after_build + window.retention,
            "{}: valid until {}, more than the window past now",
            window.label,
            entry.valid_until
        );
        assert!(entry.last_seen <= after_build, "{}", window.label);
        assert_eq!(entry.valid_until - entry.valid_from, window.retention);
    }
}
