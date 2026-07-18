//! Real-Postgres tests for replay rebuild + hash-chain verification (Task 13).
//!
//! Run with `DATABASE_URL` exported (see `.env`):
//!   set -a; . ./.env; set +a; cargo test -p core-scoring --test replay
//! `#[sqlx::test]` provisions a fresh, isolated database per test and applies
//! the migrations, so the tests never share state.

use core_scoring::domain::enums::{Protocol, SignalType};
use core_scoring::domain::types::EventInput;
use core_scoring::repository::{
    append_event, read_stored_score, rebuild_projection, verify_chain, ChainStatus, RepoError,
};

use chrono::Utc;
use sqlx::PgPool;

const IP: &str = "203.0.113.7";

/// Build one event for `IP`, choosing wan/sensor/protocol/auth explicitly so a
/// stream can exercise dedup, multi-WAN breadth, and multi-sensor counting.
#[allow(clippy::too_many_arguments)]
fn ev(
    ts: &str,
    signal: SignalType,
    wan: Option<&str>,
    sensor: &str,
    protocol: Protocol,
    authenticated: bool,
) -> EventInput {
    EventInput::from_signal(
        IP.parse().unwrap(),
        wan.map(|w| w.parse().unwrap()),
        sensor.into(),
        signal,
        protocol,
        authenticated,
        ts.parse().unwrap(),
        serde_json::json!({}),
    )
}

/// A multi-event stream for one source that exercises: a confirmed-real latch,
/// a within-window dedup (e1 repeats e0's signal_type inside 60s), three
/// distinct authenticated-TCP WAN vantages across three /24s (breadth), one
/// non-authenticated UDP vantage that must NOT count toward breadth, and three
/// distinct sensors.
fn sample_stream() -> Vec<EventInput> {
    vec![
        // e0: honeypot tcp+auth -> latches has_confirmed_real; wan A, sensor s1.
        ev(
            "2026-07-17T00:00:00Z",
            SignalType::HoneypotCommandExec,
            Some("198.51.100.1"),
            "s1",
            Protocol::Tcp,
            true,
        ),
        // e1: SAME signal_type 30s later -> deduped (adds no weight), wan A, s1.
        ev(
            "2026-07-17T00:00:30Z",
            SignalType::HoneypotCommandExec,
            Some("198.51.100.1"),
            "s1",
            Protocol::Tcp,
            true,
        ),
        // e2: udp portscan on wan B -> not auth-tcp, does NOT count for breadth.
        ev(
            "2026-07-17T00:05:00Z",
            SignalType::PortScan,
            Some("203.0.113.20"),
            "s2",
            Protocol::Udp,
            false,
        ),
        // e3: honeypot tcp+auth on wan B -> B now an authenticated vantage.
        ev(
            "2026-07-17T00:10:00Z",
            SignalType::HoneypotLoginAttempt,
            Some("203.0.113.20"),
            "s2",
            Protocol::Tcp,
            true,
        ),
        // e4: honeypot tcp+auth on wan C -> third distinct /24 vantage; sensor s3.
        ev(
            "2026-07-17T02:00:00Z",
            SignalType::HoneypotFileDownload,
            Some("192.0.2.5"),
            "s3",
            Protocol::Tcp,
            true,
        ),
    ]
}

/// Replaying a source's ledger from empty must reproduce EXACTLY the projection
/// the incremental append path stored (compared against the un-projected stored
/// `ip_score` row, not `read_score`, to avoid decay-anchor-to-now drift).
#[sqlx::test(migrations = "./migrations")]
async fn replay_equals_incremental(pool: PgPool) -> Result<(), RepoError> {
    for e in sample_stream() {
        append_event(&pool, e).await?;
    }
    let ip = IP.parse().unwrap();
    let stored = read_stored_score(&pool, ip).await?.expect("projection row exists");
    let replayed = rebuild_projection(&pool, ip).await?;

    // Full field equality: replay must equal the incrementally-stored row.
    assert_eq!(replayed, stored, "replay must equal the incremental projection");
    // Belt-and-suspenders on the fields the stream was designed to exercise.
    assert_eq!(replayed.raw_score, stored.raw_score);
    assert_eq!(replayed.category_breakdown, stored.category_breakdown);
    assert_eq!(replayed.event_count, stored.event_count);
    assert!(replayed.has_confirmed_real);
    assert_eq!(replayed.distinct_categories, stored.distinct_categories);
    assert_eq!(replayed.max_confidence, stored.max_confidence);
    assert_eq!(replayed.eligible, stored.eligible);
    assert_eq!(replayed.recommended_for_vendor, stored.recommended_for_vendor);
    assert_eq!(replayed.recommended_for_blocklist, stored.recommended_for_blocklist);
    assert_eq!(replayed.tier, stored.tier);
    assert_eq!(replayed.distinct_wan_count, 3, "A, B, C authenticated /24s");
    assert_eq!(replayed.distinct_sensor_count, 3, "s1, s2, s3");
    assert_eq!(replayed.first_seen, stored.first_seen);
    assert_eq!(replayed.last_seen, stored.last_seen);
    assert_eq!(replayed.decay_anchor, stored.decay_anchor);
    Ok(())
}

/// An untampered ledger verifies as `Intact` (guards against `verify_chain`
/// trivially returning `Broken`, and exercises the full hash round-trip through
/// storage: any field whose stored representation diverged from what was hashed
/// would surface here as a false break).
#[sqlx::test(migrations = "./migrations")]
async fn intact_chain_verifies(pool: PgPool) -> Result<(), RepoError> {
    for e in sample_stream() {
        append_event(&pool, e).await?;
    }
    assert_eq!(verify_chain(&pool).await?, ChainStatus::Intact);
    Ok(())
}

/// An untampered chain whose events carry SUB-MICROSECOND `observed_at`
/// precision still verifies as `Intact`.
///
/// The `observed_at` column is `TIMESTAMPTZ` (microsecond precision), so a
/// nanosecond-precision timestamp is lossily truncated on write. Before the
/// storage-normalization fix, `append_event` hashed the full-precision
/// in-memory value but stored the truncated one, so `verify_chain` (which
/// re-hashes from storage) recomputed a different hash and falsely reported
/// `Broken` on this untampered chain. The fix normalizes `observed_at` to
/// microseconds BEFORE both hashing and inserting, so the two agree.
#[sqlx::test(migrations = "./migrations")]
async fn verify_chain_intact_with_sub_microsecond_timestamps(pool: PgPool) -> Result<(), RepoError> {
    // Deterministic sub-µs value: 789 ns beyond the microsecond boundary.
    let mut e0 = ev(
        "2026-07-17T00:00:00Z",
        SignalType::HoneypotCommandExec,
        Some("198.51.100.1"),
        "s1",
        Protocol::Tcp,
        true,
    );
    e0.observed_at = "2026-07-17T00:00:00.123456789Z".parse().unwrap();
    append_event(&pool, e0).await?;

    // A realistic sub-µs source: the system clock on this platform carries
    // nanosecond resolution, so `Utc::now()` routinely has sub-µs digits.
    let mut e1 = ev(
        "2026-07-17T00:00:30Z",
        SignalType::HoneypotLoginAttempt,
        Some("198.51.100.1"),
        "s1",
        Protocol::Tcp,
        true,
    );
    e1.observed_at = Utc::now();
    append_event(&pool, e1).await?;

    assert_eq!(verify_chain(&pool).await?, ChainStatus::Intact);
    Ok(())
}

/// An untampered chain whose event carries nested / numeric / string metadata
/// still verifies as `Intact`, exercising the `JSONB` round-trip: the bytes
/// hashed at append time must equal the bytes `verify_chain` re-hashes after
/// reading the value back out of `JSONB`.
#[sqlx::test(migrations = "./migrations")]
async fn verify_chain_intact_with_rich_metadata(pool: PgPool) -> Result<(), RepoError> {
    let mut e = ev(
        "2026-07-17T00:00:00Z",
        SignalType::HoneypotCommandExec,
        Some("198.51.100.1"),
        "s1",
        Protocol::Tcp,
        true,
    );
    // Out-of-order keys, nesting, integers, strings, and an array: covers the
    // documented canonical metadata form (integers/strings/nested objects and
    // arrays thereof).
    e.metadata = serde_json::json!({"z": 1, "a": {"n": 42, "s": "x"}, "list": [3, 2, 1]});
    append_event(&pool, e).await?;
    assert_eq!(verify_chain(&pool).await?, ChainStatus::Intact);
    Ok(())
}

/// Tampering with a stored, hashed field breaks the chain at that row.
#[sqlx::test(migrations = "./migrations")]
async fn tampering_breaks_the_chain(pool: PgPool) -> Result<(), RepoError> {
    append_event(
        &pool,
        ev(
            "2026-07-17T00:00:00Z",
            SignalType::HoneypotCommandExec,
            Some("198.51.100.1"),
            "s1",
            Protocol::Tcp,
            true,
        ),
    )
    .await?;
    sqlx::query("UPDATE event SET weight = weight + 1 WHERE id = 1")
        .execute(&pool)
        .await?;
    assert_eq!(
        verify_chain(&pool).await?,
        ChainStatus::Broken { first_bad_id: 1 }
    );
    Ok(())
}
