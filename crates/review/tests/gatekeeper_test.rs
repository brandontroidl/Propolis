//! Real-Postgres tests for the gatekeeper's per-vendor check sequence.
//!
//! Shares the persistent `propolis_test` database with other crates' tests
//! (see the project's `local-gate-toolchain` note). Every test uses a distinct
//! source IP from `45.10.31.0/24` and a distinct vendor name, so tests never
//! interfere with each other or with leftover rows from other crates' test
//! runs.
//!
//! These fixtures are ordinary public addresses rather than the RFC5737
//! documentation ranges used elsewhere in the project, and must stay that way:
//! the gate's first check now refuses every reserved range outright, so a
//! documentation-range fixture is held as `Reserved` before reaching the check
//! actually under test. That is the gate working, not a fixture accident - see
//! `reserved_ranges_are_refused_ahead_of_every_configurable_check`.
//! `reset_vendor` deletes any
//! leftover `vendor_submission` rows for a test's vendor name before seeding,
//! matching `queue_test.rs`'s `reset_ip` discipline for rerun-safety against
//! the persistent, never-reset database. Run with `--test-threads=1`.
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

use review::gatekeeper::{GateReason, GateResult, VendorConfig, check};

async fn setup_pool() -> PgPool {
    let url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://propolis:propolis@localhost:5432/propolis_test".into());
    let pool = PgPool::connect(&url).await.unwrap();
    // Run core-scoring migrations first (review_state_enum, etc. must exist).
    sqlx::migrate!("../core-scoring/migrations")
        .run(&pool)
        .await
        .unwrap();
    // Then this crate's own.
    review::migrator().run(&pool).await.unwrap();
    pool
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
        distinct_categories: categories.len() as i32,
        category_breakdown: serde_json::Value::Object(breakdown),
        has_confirmed_real: true,
        distinct_wan_count: 1,
        distinct_sensor_count: 1,
        first_seen: now,
        last_seen: now,
        eligible: true,
        recommended_for_vendor: true,
        recommended_for_blocklist: false,
        tier: None,
        delisted: false,
    }
}

/// Wipes any leftover `vendor_submission` rows for `vendor` from a previous
/// run of this suite against the persistent, shared `propolis_test` database.
/// `idempotency_key` is UNIQUE, so re-inserting the same key on a second run
/// without cleanup would fail the insert rather than the intended assertion.
async fn reset_vendor(pool: &PgPool, vendor: &str) {
    sqlx::query("DELETE FROM vendor_submission WHERE vendor = $1")
        .bind(vendor)
        .execute(pool)
        .await
        .unwrap();
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

#[tokio::test]
async fn vendor_disabled_is_held() {
    let pool = setup_pool().await;
    let ip: IpAddr = "45.10.31.230".parse().unwrap();
    let config = VendorConfig {
        enabled: false,
        ..permissive_config("disabled-vendor")
    };
    let score = fake_score(ip, Decimal::from(80), &["Honeypot"]);

    let result = check(&pool, ip, &config, &score).await;
    assert_eq!(result, GateResult::Held(GateReason::Disabled));
}

#[tokio::test]
async fn within_cooldown_is_held() {
    let pool = setup_pool().await;
    let vendor = "cooldown-active-vendor";
    let ip = "45.10.31.231";
    reset_vendor(&pool, vendor).await;
    // A successful submission 1 hour ago, well inside a 24-hour cooldown.
    insert_submission(&pool, ip, vendor, Utc::now() - Duration::hours(1)).await;

    let config = permissive_config(vendor);
    let score = fake_score(ip.parse().unwrap(), Decimal::from(80), &["Honeypot"]);

    let result = check(&pool, ip.parse().unwrap(), &config, &score).await;
    assert_eq!(result, GateResult::Held(GateReason::Cooldown));
}

#[tokio::test]
async fn cooldown_expired_allows_pass() {
    let pool = setup_pool().await;
    let vendor = "cooldown-expired-vendor";
    let ip = "45.10.31.232";
    reset_vendor(&pool, vendor).await;
    // A successful submission 48 hours ago, outside a 24-hour cooldown.
    insert_submission(&pool, ip, vendor, Utc::now() - Duration::hours(48)).await;

    let config = permissive_config(vendor);
    let score = fake_score(ip.parse().unwrap(), Decimal::from(80), &["Honeypot"]);

    let result = check(&pool, ip.parse().unwrap(), &config, &score).await;
    assert_eq!(result, GateResult::Pass);
}

#[tokio::test]
async fn rate_limit_exceeded_is_held() {
    let pool = setup_pool().await;
    let vendor = "ratelimit-vendor";
    reset_vendor(&pool, vendor).await;
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

#[tokio::test]
async fn score_below_floor_is_held() {
    let pool = setup_pool().await;
    let ip: IpAddr = "45.10.31.236".parse().unwrap();
    let config = VendorConfig {
        score_floor: Some(Decimal::from(50)),
        ..permissive_config("scorefloor-vendor")
    };
    let score = fake_score(ip, Decimal::from(10), &["Honeypot"]);

    let result = check(&pool, ip, &config, &score).await;
    assert_eq!(result, GateResult::Held(GateReason::ScoreFloor));
}

#[tokio::test]
async fn no_matching_category_is_held() {
    let pool = setup_pool().await;
    let ip: IpAddr = "45.10.31.237".parse().unwrap();
    let config = VendorConfig {
        category_filter: Some(vec!["Waf".to_string()]),
        ..permissive_config("category-vendor")
    };
    let score = fake_score(ip, Decimal::from(80), &["Honeypot"]);

    let result = check(&pool, ip, &config, &score).await;
    assert_eq!(result, GateResult::Held(GateReason::CategoryFilter));
}

#[tokio::test]
async fn all_checks_pass() {
    let pool = setup_pool().await;
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

#[tokio::test]
async fn db_error_during_check_fails_closed() {
    let pool = setup_pool().await;
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

#[tokio::test]
async fn reserved_ranges_are_refused_ahead_of_every_configurable_check() {
    // The operator's own workstation, 10.20.30.109, reached eligible and recommended_for_vendor
    // purely from local SSH testing against the honeypot. Nothing in the gate stopped it: the
    // sequence ran enabled -> cooldown -> rate limit -> score floor -> category filter, all of
    // them operator-configurable, none of them about the address itself. One Approve click would
    // have reported a private LAN address to AbuseIPDB, DShield and OTX as an attacker.
    let pool = setup_pool().await;
    let config = permissive_config("reserved-vendor");

    for addr in [
        "10.20.30.109",
        "192.168.1.50",
        "172.16.0.1",
        "127.0.0.1",
        "169.254.1.1",
        "203.0.113.9",
        "198.51.100.9",
        "192.0.2.9",
        "::1",
        "fe80::1",
        "fc00::1",
        "2001:db8::1",
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
    reset_vendor(&pool, "reserved-vendor").await;
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
