//! Real-Postgres tests for the gatekeeper's per-vendor check sequence.
//!
//! Each test owns a fresh database (`#[sqlx::test]`), so no row from another test or crate can
//! reach a cooldown or rate-limit count.
//!
//! These fixtures are ordinary public addresses rather than the RFC5737
//! documentation ranges used elsewhere in the project, and must stay that way:
//! the gate's first check now refuses every reserved range outright, so a
//! documentation-range fixture is held as `Reserved` before reaching the check
//! actually under test. That is the gate working, not a fixture accident - see
//! `reserved_ranges_are_refused_ahead_of_every_configurable_check`.
//!
//! `current_score` is a caller-supplied `IpScore`, not something `check` reads
//! from the database itself, so most tests build one directly in memory via
//! `fake_score` rather than seeding `event`/`ip_score` through `core_scoring`.
//! Only the cooldown/rate-limit checks touch the database, via
//! `vendor_submission`.

use std::net::IpAddr;

use chrono::{DateTime, Duration, Utc};
use core_scoring::IpScore;
use rust_decimal::Decimal;
use sqlx::PgPool;

use review::gatekeeper::{CooldownBook, GateReason, GateResult, VendorConfig, check, check_with};

async fn migrate(pool: &PgPool) {
    // Core-scoring first (review_state_enum, etc. must exist), then this crate's own.
    sqlx::migrate!("../core-scoring/migrations")
        .run(pool)
        .await
        .unwrap();
    review::migrator().run(pool).await.unwrap();
}

/// A permissive baseline config: enabled, generous cooldown/rate limit, no
/// score floor or category restriction. Individual tests override only the
/// field(s) under test via struct-update syntax, isolating each check.
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

/// An in-memory `IpScore` the gatekeeper can check without any DB round trip:
/// `check` only reads `raw_score` and `category_breakdown` from it. Other
/// fields are filled with plausible values that are never inspected by the
/// gate.
fn fake_score(ip: IpAddr, raw_score: Decimal, categories: &[&str]) -> IpScore {
    let now = Utc::now();
    let mut breakdown = serde_json::Map::new();
    for c in categories {
        breakdown.insert(
            (*c).to_string(),
            serde_json::json!({"weight": "50.000", "max_confidence": "0.900"}),
        );
    }
    IpScore {
        source_ip: ip,
        raw_score,
        decay_anchor: now,
        max_confidence: Decimal::from(1),
        event_count: categories.len().max(1) as i32,
        established_event_count: categories.len().max(1) as i32,
        distinct_categories: categories.len() as i32,
        category_breakdown: serde_json::Value::Object(breakdown),
        has_confirmed_real: true,
        distinct_wan_count: 1,
        distinct_sensor_count: 1,
        active_days: 1,
        last_active_day: now.date_naive(),
        first_seen: now,
        last_seen: now,
        eligible: true,
        recommended_for_vendor: true,
        recommended_for_blocklist: false,
        tier: None,
        delisted: false,
    }
}

async fn insert_submission(pool: &PgPool, ip: &str, vendor: &str, submitted_at: DateTime<Utc>) {
    let key = format!(
        "{ip}:{vendor}:{}",
        submitted_at.timestamp_nanos_opt().unwrap()
    );
    sqlx::query(
        "INSERT INTO vendor_submission \
         (source_ip, vendor, idempotency_key, categories, comment, submitted_at, success) \
         VALUES ($1::inet, $2, $3, $4, $5, $6, TRUE)",
    )
    .bind(ip)
    .bind(vendor)
    .bind(key)
    .bind(vec!["test".to_string()])
    .bind("test submission")
    .bind(submitted_at)
    .execute(pool)
    .await
    .unwrap();
}

#[sqlx::test(migrations = false)]
async fn stale_last_seen_is_held(pool: PgPool) {
    migrate(&pool).await;
    let ip: IpAddr = "45.10.31.243".parse().unwrap();
    let config = permissive_config("stale-vendor");
    // Active three days ago: older than the freshness window, so it must not be submitted (a
    // days-old attack is not current honeypot activity, and vendors reject the stale timestamp).
    let mut score = fake_score(ip, Decimal::from(80), &["Honeypot"]);
    score.last_seen = Utc::now() - Duration::days(3);

    let result = check(&pool, ip, &config, &score).await;
    assert_eq!(result, GateResult::Held(GateReason::Stale));
}

#[sqlx::test(migrations = false)]
async fn recent_last_seen_passes_the_freshness_gate(pool: PgPool) {
    migrate(&pool).await;
    let vendor = "fresh-vendor";
    let ip: IpAddr = "45.10.31.244".parse().unwrap();
    let config = permissive_config(vendor);
    // Active one hour ago: comfortably inside the freshness window, so every other check applies.
    let mut score = fake_score(ip, Decimal::from(80), &["Honeypot"]);
    score.last_seen = Utc::now() - Duration::hours(1);

    let result = check(&pool, ip, &config, &score).await;
    assert_eq!(result, GateResult::Pass);
}

#[sqlx::test(migrations = false)]
async fn vendor_disabled_is_held(pool: PgPool) {
    migrate(&pool).await;
    let ip: IpAddr = "45.10.31.230".parse().unwrap();
    let config = VendorConfig {
        enabled: false,
        ..permissive_config("disabled-vendor")
    };
    let score = fake_score(ip, Decimal::from(80), &["Honeypot"]);

    let result = check(&pool, ip, &config, &score).await;
    assert_eq!(result, GateResult::Held(GateReason::Disabled));
}

#[sqlx::test(migrations = false)]
async fn within_cooldown_is_held(pool: PgPool) {
    migrate(&pool).await;
    let vendor = "cooldown-active-vendor";
    let ip = "45.10.31.231";
    // A successful submission 1 hour ago, well inside a 24-hour cooldown.
    insert_submission(&pool, ip, vendor, Utc::now() - Duration::hours(1)).await;

    let config = permissive_config(vendor);
    let score = fake_score(ip.parse().unwrap(), Decimal::from(80), &["Honeypot"]);

    let result = check(&pool, ip.parse().unwrap(), &config, &score).await;
    assert_eq!(result, GateResult::Held(GateReason::Cooldown));
}

#[sqlx::test(migrations = false)]
async fn cooldown_expired_allows_pass(pool: PgPool) {
    migrate(&pool).await;
    let vendor = "cooldown-expired-vendor";
    let ip = "45.10.31.232";
    // A successful submission 48 hours ago, outside a 24-hour cooldown.
    insert_submission(&pool, ip, vendor, Utc::now() - Duration::hours(48)).await;

    let config = permissive_config(vendor);
    let score = fake_score(ip.parse().unwrap(), Decimal::from(80), &["Honeypot"]);

    let result = check(&pool, ip.parse().unwrap(), &config, &score).await;
    assert_eq!(result, GateResult::Pass);
}

#[sqlx::test(migrations = false)]
async fn rate_limit_exceeded_is_held(pool: PgPool) {
    migrate(&pool).await;
    let vendor = "ratelimit-vendor";
    // Two successful submissions to this vendor from OTHER IPs within the
    // window - rate limit is vendor-wide, not per-IP.
    insert_submission(
        &pool,
        "45.10.31.233",
        vendor,
        Utc::now() - Duration::hours(1),
    )
    .await;
    insert_submission(
        &pool,
        "45.10.31.234",
        vendor,
        Utc::now() - Duration::hours(2),
    )
    .await;

    let config = VendorConfig {
        rate_limit: 2,
        rate_window_hours: 24,
        ..permissive_config(vendor)
    };
    let checked_ip: IpAddr = "45.10.31.235".parse().unwrap();
    let score = fake_score(checked_ip, Decimal::from(80), &["Honeypot"]);

    let result = check(&pool, checked_ip, &config, &score).await;
    assert_eq!(result, GateResult::Held(GateReason::RateLimit));
}

#[sqlx::test(migrations = false)]
async fn score_below_floor_is_held(pool: PgPool) {
    migrate(&pool).await;
    let ip: IpAddr = "45.10.31.236".parse().unwrap();
    let config = VendorConfig {
        score_floor: Some(Decimal::from(50)),
        ..permissive_config("scorefloor-vendor")
    };
    let score = fake_score(ip, Decimal::from(10), &["Honeypot"]);

    let result = check(&pool, ip, &config, &score).await;
    assert_eq!(result, GateResult::Held(GateReason::ScoreFloor));
}

#[sqlx::test(migrations = false)]
async fn no_matching_category_is_held(pool: PgPool) {
    migrate(&pool).await;
    let ip: IpAddr = "45.10.31.237".parse().unwrap();
    let config = VendorConfig {
        category_filter: Some(vec!["Waf".to_string()]),
        ..permissive_config("category-vendor")
    };
    let score = fake_score(ip, Decimal::from(80), &["Honeypot"]);

    let result = check(&pool, ip, &config, &score).await;
    assert_eq!(result, GateResult::Held(GateReason::CategoryFilter));
}

#[sqlx::test(migrations = false)]
async fn all_checks_pass(pool: PgPool) {
    migrate(&pool).await;
    let ip: IpAddr = "45.10.31.238".parse().unwrap();
    let config = VendorConfig {
        score_floor: Some(Decimal::from(50)),
        category_filter: Some(vec!["Honeypot".to_string(), "Waf".to_string()]),
        ..permissive_config("allpass-vendor")
    };
    let score = fake_score(ip, Decimal::from(80), &["Honeypot"]);

    let result = check(&pool, ip, &config, &score).await;
    assert_eq!(result, GateResult::Pass);
}

#[sqlx::test(migrations = false)]
async fn db_error_during_check_fails_closed(pool: PgPool) {
    migrate(&pool).await;
    pool.close().await;
    let ip: IpAddr = "45.10.31.239".parse().unwrap();
    let config = permissive_config("dberror-vendor");
    let score = fake_score(ip, Decimal::from(80), &["Honeypot"]);

    let result = check(&pool, ip, &config, &score).await;
    assert!(
        matches!(result, GateResult::Held(GateReason::DbError(_))),
        "a closed pool must fail closed, not panic or silently pass: got {result:?}"
    );
}

#[sqlx::test(migrations = false)]
async fn reserved_ranges_are_refused_ahead_of_every_configurable_check(pool: PgPool) {
    // The operator's own workstation, 10.20.30.109, reached eligible and recommended_for_vendor
    // purely from local SSH testing against the honeypot. Nothing in the gate stopped it: the
    // sequence ran enabled -> cooldown -> rate limit -> score floor -> category filter, all of
    // them operator-configurable, none of them about the address itself. One Approve click would
    // have reported a private LAN address to AbuseIPDB, DShield and OTX as an attacker.
    migrate(&pool).await;
    let config = permissive_config("reserved-vendor");

    for addr in [
        "10.20.30.109",
        "192.168.1.50",
        "172.16.0.1",
        "127.0.0.1",
        "169.254.1.1",
        // Not 203.0.113.0/24: the `test-public-ranges` feature (on for this crate's tests) treats
        // that block as public so the other holds are reachable; see `review::reserved`.
        "198.51.100.9",
        "192.0.2.9",
        "::1",
        "fe80::1",
        "fc00::1",
        "2001:db8::1",
        // Carrier-grade NAT space, which overlay VPNs also hand to an operator's own devices.
        "100.64.0.1",
    ] {
        let ip: IpAddr = addr.parse().unwrap();
        // A maximal score and a matching category: every other gate would pass this.
        let score = fake_score(ip, Decimal::from(100), &["Honeypot"]);
        assert_eq!(
            check(&pool, ip, &config, &score).await,
            GateResult::Held(GateReason::Reserved),
            "{addr} must never be reportable to a third party"
        );
    }

    // The check must be specific: an ordinary public address still passes. A guard verified only
    // on its deny branch is half-verified, and over-blocking real reports is its own failure.
    let public: IpAddr = "45.10.31.240".parse().unwrap();
    assert_eq!(
        check(
            &pool,
            public,
            &config,
            &fake_score(public, Decimal::from(100), &["Honeypot"])
        )
        .await,
        GateResult::Pass
    );
}

async fn insert_attempt(
    pool: &PgPool,
    ip: &str,
    vendor: &str,
    submitted_at: DateTime<Utc>,
    success: bool,
    n: usize,
) {
    sqlx::query(
        "INSERT INTO vendor_submission \
         (source_ip, vendor, idempotency_key, categories, comment, submitted_at, success) \
         VALUES ($1::inet, $2, $3, $4, 'differential', $5, $6)",
    )
    .bind(ip)
    .bind(vendor)
    .bind(format!("{ip}:{vendor}:{n}"))
    .bind(vec!["test".to_string()])
    .bind(submitted_at)
    .bind(success)
    .execute(pool)
    .await
    .unwrap();
}

/// A pass reads every pair's cooldown in one query (`CooldownBook`) instead of one per pair, and
/// must decide exactly what the per-pair query decides. Every pair of 40 addresses and three
/// vendors is checked both ways over a database seeded with each shape of history the cooldown
/// can meet: nothing, a recent success, a success older than the cooldown, a recent FAILURE only,
/// an old success beside a recent failure, a recent success beside older ones, and a vendor with
/// a zero-hour cooldown. Pairs outside what the book was loaded for must fall back to the query.
#[sqlx::test(migrations = false)]
async fn the_batched_cooldown_decides_exactly_what_the_per_pair_query_decides(pool: PgPool) {
    migrate(&pool).await;
    let vendors = ["vend-a", "vend-b", "vend-c"];
    let configs = [
        permissive_config("vend-a"),
        VendorConfig {
            cooldown_hours: 0,
            ..permissive_config("vend-b")
        },
        VendorConfig {
            cooldown_hours: 72,
            ..permissive_config("vend-c")
        },
    ];
    let now = Utc::now();
    let ips: Vec<String> = (1..=40).map(|n| format!("203.0.113.{n}")).collect();
    let mut n = 0;
    for (i, ip) in ips.iter().enumerate() {
        for (v, vendor) in vendors.iter().enumerate() {
            n += 1;
            match (i + v) % 7 {
                0 => {}
                1 => insert_attempt(&pool, ip, vendor, now - Duration::hours(1), true, n).await,
                2 => insert_attempt(&pool, ip, vendor, now - Duration::hours(30), true, n).await,
                3 => insert_attempt(&pool, ip, vendor, now - Duration::hours(1), false, n).await,
                4 => {
                    insert_attempt(&pool, ip, vendor, now - Duration::hours(40), true, n).await;
                    insert_attempt(&pool, ip, vendor, now - Duration::hours(1), false, n + 1000)
                        .await;
                }
                5 => {
                    // The newest success decides, whatever order the rows were written in.
                    insert_attempt(&pool, ip, vendor, now - Duration::hours(50), true, n).await;
                    insert_attempt(
                        &pool,
                        ip,
                        vendor,
                        now - Duration::minutes(5),
                        true,
                        n + 1000,
                    )
                    .await;
                    insert_attempt(&pool, ip, vendor, now - Duration::hours(26), true, n + 2000)
                        .await;
                }
                _ => {
                    // Just inside and just outside a 24-hour cooldown, with minutes to spare so
                    // the two checks cannot straddle the edge.
                    let age = if (i + v) % 2 == 0 {
                        Duration::hours(24) - Duration::minutes(5)
                    } else {
                        Duration::hours(24) + Duration::minutes(5)
                    };
                    insert_attempt(&pool, ip, vendor, now - age, true, n).await;
                }
            }
        }
    }
    // An address the book will not be loaded for, with a history that would hold it.
    insert_attempt(
        &pool,
        "203.0.113.200",
        "vend-a",
        now - Duration::hours(1),
        true,
        9000,
    )
    .await;

    let covered: Vec<IpAddr> = ips.iter().map(|s| s.parse().unwrap()).collect();
    let book = CooldownBook::load(&pool, &covered, &["vend-a", "vend-b", "vend-c"])
        .await
        .unwrap();

    let (mut passes, mut cooldowns) = (0, 0);
    for ip in &covered {
        let score = fake_score(*ip, Decimal::from(80), &["Honeypot"]);
        for config in &configs {
            let per_pair = check(&pool, *ip, config, &score).await;
            let batched = check_with(&pool, *ip, config, &score, Some(&book)).await;
            assert_eq!(batched, per_pair, "{ip} x {}", config.name);
            match per_pair {
                GateResult::Pass => passes += 1,
                GateResult::Held(GateReason::Cooldown) => cooldowns += 1,
                other => panic!("unexpected outcome for {ip} x {}: {other:?}", config.name),
            }
        }
    }
    // A fixture where both paths hold every pair (or pass every pair) would agree for the wrong
    // reason; the grid is built to land on both sides.
    assert!(
        passes > 20 && cooldowns > 20,
        "{passes} passes, {cooldowns} holds"
    );

    // Outside the book, the answer still comes from the database.
    let outside: IpAddr = "203.0.113.200".parse().unwrap();
    let score = fake_score(outside, Decimal::from(80), &["Honeypot"]);
    assert_eq!(book.latest_success(outside, "vend-a"), None);
    assert_eq!(
        check_with(&pool, outside, &configs[0], &score, Some(&book)).await,
        GateResult::Held(GateReason::Cooldown)
    );
    let other_vendor = permissive_config("vend-z");
    let first: IpAddr = covered[0];
    assert_eq!(book.latest_success(first, "vend-z"), None);
    insert_attempt(
        &pool,
        &ips[0],
        "vend-z",
        now - Duration::hours(1),
        true,
        9001,
    )
    .await;
    assert_eq!(
        check_with(&pool, first, &other_vendor, &score, Some(&book)).await,
        GateResult::Held(GateReason::Cooldown)
    );
}

/// The book keys on the address Postgres prints for the stored `inet`, parsed back, so every
/// spelling of an address must find its own pair: an IPv6 address Rust and Postgres both print
/// compressed, an IPv4-mapped IPv6 address, and a plain IPv4.
#[sqlx::test(migrations = false)]
async fn the_book_finds_each_pair_whatever_the_address_family(pool: PgPool) {
    migrate(&pool).await;
    let now = Utc::now();
    let spellings = [
        "203.0.113.7",
        "2001:db8::7",
        "::ffff:203.0.113.7",
        "2001:db8:0:0:1::7",
    ];
    for (n, ip) in spellings.iter().enumerate() {
        insert_attempt(
            &pool,
            ip,
            "vend-a",
            now - Duration::hours(n as i64 + 1),
            true,
            n,
        )
        .await;
    }
    let ips: Vec<IpAddr> = spellings.iter().map(|s| s.parse().unwrap()).collect();
    let book = CooldownBook::load(&pool, &ips, &["vend-a"]).await.unwrap();
    for ip in &ips {
        let per_pair: Option<DateTime<Utc>> = sqlx::query_scalar(
            "SELECT submitted_at FROM vendor_submission \
             WHERE source_ip = $1::inet AND vendor = 'vend-a' AND success = TRUE \
             ORDER BY submitted_at DESC LIMIT 1",
        )
        .bind(ip.to_string())
        .fetch_optional(&pool)
        .await
        .unwrap();
        assert!(per_pair.is_some(), "{ip} was seeded");
        assert_eq!(book.latest_success(*ip, "vend-a"), Some(per_pair), "{ip}");
    }
}
