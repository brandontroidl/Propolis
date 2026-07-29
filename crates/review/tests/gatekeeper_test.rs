//! Real-Postgres tests for the gatekeeper's per-vendor check sequence.
//!
//! Shares the persistent `propolis_test` database with other crates' tests
//! (see the project's `local-gate-toolchain` note). Every test uses a distinct
//! source IP (RFC5737 documentation range, disjoint from `queue_test.rs`'s
//! `192.0.2.210-214`/`198.51.100.215`/`198.51.100.217`/`203.0.113.216`) and a
//! distinct vendor name, so tests never interfere with each other or with
//! leftover rows from other crates' test runs. `reset_vendor` deletes any
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
    let ip: IpAddr = "203.0.113.230".parse().unwrap();
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
    let ip = "203.0.113.231";
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
    let ip = "203.0.113.232";
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
        "203.0.113.233",
        vendor,
        Utc::now() - Duration::hours(1),
    )
    .await;
    insert_submission(
        &pool,
        "203.0.113.234",
        vendor,
        Utc::now() - Duration::hours(2),
    )
    .await;

    let config = VendorConfig {
        rate_limit: 2,
        rate_window_hours: 24,
        ..permissive_config(vendor)
    };
    let checked_ip: IpAddr = "203.0.113.235".parse().unwrap();
    let score = fake_score(checked_ip, Decimal::from(80), &["Honeypot"]);

    let result = check(&pool, checked_ip, &config, &score).await;
    assert_eq!(result, GateResult::Held(GateReason::RateLimit));
}

#[tokio::test]
async fn score_below_floor_is_held() {
    let pool = setup_pool().await;
    let ip: IpAddr = "203.0.113.236".parse().unwrap();
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
    let ip: IpAddr = "203.0.113.237".parse().unwrap();
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
    let ip: IpAddr = "203.0.113.238".parse().unwrap();
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
    let ip: IpAddr = "203.0.113.239".parse().unwrap();
    let config = permissive_config("dberror-vendor");
    let score = fake_score(ip, Decimal::from(80), &["Honeypot"]);

    let result = check(&pool, ip, &config, &score).await;
    assert!(
        matches!(result, GateResult::Held(GateReason::DbError(_))),
        "a closed pool must fail closed, not panic or silently pass: got {result:?}"
    );
}
