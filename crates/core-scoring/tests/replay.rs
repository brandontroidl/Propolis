//! Real-Postgres tests for replay rebuild + hash-chain verification (Task 13).
//!
//! Run with `DATABASE_URL` exported (see `.env`):
//!   set -a; . ./.env; set +a; cargo test -p core-scoring --test replay
//! `#[sqlx::test]` provisions a fresh, isolated database per test and applies
//! the migrations, so the tests never share state.

use core_scoring::domain::enums::{Protocol, SignalType};
use core_scoring::domain::types::EventInput;
use core_scoring::repository::{
    ChainStatus, RepoError, append_event, read_score, read_stored_score, rebuild_projection,
    verify_chain,
};

use chrono::Utc;
use rust_decimal_macros::dec;
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
        None,
    )
}

/// A caller supplies confidence 0.9 (scale 1), value-equal to HoneypotConnection's table 0.900
/// (scale 3), so validate() accepts it. The append hash must normalize confidence to scale-3
/// (matching the NUMERIC(4,3) column) or verify_chain false-breaks on this untampered row.
#[sqlx::test(migrations = "./migrations")]
async fn verify_chain_intact_with_low_scale_confidence(pool: PgPool) -> Result<(), RepoError> {
    let mut e = ev(
        "2026-07-17T00:00:00Z",
        SignalType::HoneypotConnection,
        Some("198.51.100.1"),
        "s1",
        Protocol::Tcp,
        true,
    );
    e.confidence = dec!(0.9);
    append_event(&pool, e).await?;
    assert!(matches!(verify_chain(&pool).await?, ChainStatus::Intact));
    Ok(())
}

/// Two same-signal events 6h apart, appended in REVERSE chronological order (a buffered/skewed
/// sensor delivering the earlier event second). The second append is 6h from the prior
/// observation, far outside the 60s dedup window, so it must NOT be deduped - its weight must be
/// added, not silently dropped (a one-sided `elapsed <= 60` treats any negative elapsed as a dup).
#[sqlx::test(migrations = "./migrations")]
async fn out_of_order_event_outside_window_is_not_deduped(pool: PgPool) -> Result<(), RepoError> {
    let later = ev(
        "2026-07-17T06:00:00Z",
        SignalType::SuricataSev1,
        None,
        "s1",
        Protocol::Udp,
        false,
    );
    append_event(&pool, later).await?;
    let earlier = ev(
        "2026-07-17T00:00:00Z",
        SignalType::SuricataSev1,
        None,
        "s1",
        Protocol::Udp,
        false,
    );
    let s = append_event(&pool, earlier).await?;
    assert_eq!(s.event_count, 2);
    assert!(
        s.raw_score > dec!(30),
        "out-of-order event's weight was dropped: raw_score = {}",
        s.raw_score
    );
    Ok(())
}

/// An IP with no events has no projection: rebuild_projection returns Ok(None) (matching
/// read_score), never an error or a panic.
#[sqlx::test(migrations = "./migrations")]
async fn rebuild_projection_empty_source_returns_none(pool: PgPool) -> Result<(), RepoError> {
    let out = rebuild_projection(&pool, "203.0.113.250".parse().unwrap()).await?;
    assert!(out.is_none());
    Ok(())
}

/// read_score must re-derive the DECAY-DERIVED gate flags at read time. An IP tiered at write
/// whose categories have long since decayed below the 0.5 live floor must read back tier=None and
/// recommended_for_vendor=false, not the stale write-time flags - a consumer reporting off those
/// would file a vendor report for a near-zero-score address.
///
/// `eligible` is deliberately NOT in that set and must stay true. It is derived from
/// `has_confirmed_real` (a sticky latch) and `event_count` (monotonic), neither of which decays:
/// an address that genuinely authenticated to a honeypot twice did so permanently, and eligibility
/// records that fact rather than current threat level. This test previously asserted eligible
/// flipped to false, which was correct only before eligibility stopped requiring multiple live
/// categories; it kept passing nowhere because the CI gate died at the format step before ever
/// reaching the tests.
#[sqlx::test(migrations = "./migrations")]
async fn read_score_rederives_stale_flags_after_decay(pool: PgPool) -> Result<(), RepoError> {
    // Far-past events: eligible + tiered at write; by "now" (years later, thousands of
    // half-lives) every category weight has decayed to ~0.
    let e0 = ev(
        "2020-01-01T00:00:00Z",
        SignalType::HoneypotCommandExec,
        Some("198.51.100.1"),
        "s1",
        Protocol::Tcp,
        true,
    );
    append_event(&pool, e0).await?;
    let e1 = ev(
        "2020-01-01T00:00:10Z",
        SignalType::SuricataSev1,
        None,
        "s2",
        Protocol::Udp,
        false,
    );
    let stored = append_event(&pool, e1).await?;
    assert!(stored.eligible, "should be eligible at write");
    assert!(stored.tier.is_some(), "should be tiered at write");

    let now = read_score(&pool, IP.parse().unwrap())
        .await?
        .expect("row exists");
    assert!(now.tier.is_none(), "read_score returned a stale tier");
    assert!(
        !now.recommended_for_vendor,
        "a fully-decayed address must not be recommended to vendors"
    );
    assert!(
        !now.recommended_for_blocklist,
        "a fully-decayed address must not be recommended for the blocklist"
    );
    assert!(now.has_confirmed_real, "sticky latch must not decay");
    assert!(
        now.eligible,
        "eligibility records a fact about the past and must not decay away"
    );
    Ok(())
}

/// verify_chain must detect tampering of EVERY canonical field, not just `weight`. Especially the
/// three anti-spoof-critical columns is_confirmed_real gates on (protocol, authenticated, category):
/// flipping any of them post-insert must break the chain. Each field is tampered (-> Broken) then
/// restored (-> Intact) so all are exercised on one row.
#[sqlx::test(migrations = "./migrations")]
async fn tampering_any_canonical_field_breaks_the_chain(pool: PgPool) -> Result<(), RepoError> {
    let e = ev(
        "2026-07-17T00:00:00Z",
        SignalType::HoneypotCommandExec,
        Some("198.51.100.1"),
        "s1",
        Protocol::Tcp,
        true,
    );
    append_event(&pool, e).await?;

    let cases: &[(&str, &str)] = &[
        (
            "UPDATE event SET authenticated = false WHERE id = 1",
            "UPDATE event SET authenticated = true WHERE id = 1",
        ),
        (
            "UPDATE event SET category = 'ids' WHERE id = 1",
            "UPDATE event SET category = 'honeypot' WHERE id = 1",
        ),
        (
            "UPDATE event SET protocol = 'udp' WHERE id = 1",
            "UPDATE event SET protocol = 'tcp' WHERE id = 1",
        ),
        (
            "UPDATE event SET signal_type = 'port_scan' WHERE id = 1",
            "UPDATE event SET signal_type = 'honeypot_command_exec' WHERE id = 1",
        ),
        (
            "UPDATE event SET source_ip = '203.0.113.99'::inet WHERE id = 1",
            "UPDATE event SET source_ip = '203.0.113.7'::inet WHERE id = 1",
        ),
        (
            "UPDATE event SET wan_ip = '198.51.100.9'::inet WHERE id = 1",
            "UPDATE event SET wan_ip = '198.51.100.1'::inet WHERE id = 1",
        ),
        (
            "UPDATE event SET observed_at = '2026-07-18T00:00:00Z' WHERE id = 1",
            "UPDATE event SET observed_at = '2026-07-17T00:00:00Z' WHERE id = 1",
        ),
        (
            "UPDATE event SET confidence = 0.111 WHERE id = 1",
            "UPDATE event SET confidence = 0.950 WHERE id = 1",
        ),
        (
            "UPDATE event SET sensor = 'tampered' WHERE id = 1",
            "UPDATE event SET sensor = 's1' WHERE id = 1",
        ),
        (
            "UPDATE event SET metadata = '{\"x\":1}'::jsonb WHERE id = 1",
            "UPDATE event SET metadata = '{}'::jsonb WHERE id = 1",
        ),
    ];
    for &(tamper, restore) in cases {
        // raw_sql: these are audited, test-controlled static literals (no injection surface);
        // sqlx::query()'s lint rejects non-literal &str.
        sqlx::raw_sql(tamper).execute(&pool).await?;
        assert!(
            matches!(verify_chain(&pool).await?, ChainStatus::Broken { .. }),
            "tamper not detected: {tamper}"
        );
        sqlx::raw_sql(restore).execute(&pool).await?;
        assert!(
            matches!(verify_chain(&pool).await?, ChainStatus::Intact),
            "restore not clean: {restore}"
        );
    }
    Ok(())
}

/// The corrupt-`category_breakdown` fail-closed path must return `RepoError::Corrupt`, never panic,
/// when the stored JSON is not a valid CategoryStat map. Guards the guard the "never panics on
/// corrupt data" invariant depends on.
#[sqlx::test(migrations = "./migrations")]
async fn corrupt_category_breakdown_fails_closed(pool: PgPool) -> Result<(), RepoError> {
    let e = ev(
        "2026-07-17T00:00:00Z",
        SignalType::HoneypotCommandExec,
        None,
        "s1",
        Protocol::Tcp,
        true,
    );
    append_event(&pool, e).await?;
    sqlx::query(
        "UPDATE ip_score SET category_breakdown = '{\"garbage\": true}'::jsonb \
         WHERE source_ip = $1::inet",
    )
    .bind(IP)
    .execute(&pool)
    .await?;
    let r = read_score(&pool, IP.parse().unwrap()).await;
    assert!(
        matches!(r, Err(RepoError::Corrupt(_))),
        "expected Corrupt, got {r:?}"
    );
    Ok(())
}

/// Breadth requires tcp AND authenticated on the SAME event per WAN (bool_or over the conjunction),
/// not "some tcp" OR "some authenticated" separately. A WAN with only a tcp-unauthenticated event
/// and a udp-authenticated event must NOT count as an authenticated vantage. Exercises the real SQL
/// aggregation (the engine-level proptest feeds arbitrary counts and can't catch a decomposed-OR bug).
#[sqlx::test(migrations = "./migrations")]
async fn breadth_requires_tcp_and_auth_on_same_event(pool: PgPool) -> Result<(), RepoError> {
    // WAN A: honeypot tcp+auth -> a real authenticated vantage.
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
    // WAN B: tcp but NOT authenticated.
    append_event(
        &pool,
        ev(
            "2026-07-17T00:00:01Z",
            SignalType::PortScan,
            Some("203.0.113.20"),
            "s2",
            Protocol::Tcp,
            false,
        ),
    )
    .await?;
    // WAN B again: authenticated but UDP (not tcp). WAN B never had a tcp+auth event.
    let s = append_event(
        &pool,
        ev(
            "2026-07-17T00:00:02Z",
            SignalType::CatchallProbe,
            Some("203.0.113.20"),
            "s2",
            Protocol::Udp,
            true,
        ),
    )
    .await?;
    assert_eq!(
        s.distinct_wan_count, 1,
        "WAN B (tcp-unauth + udp-auth) must not count as an authenticated vantage"
    );
    Ok(())
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
    let stored = read_stored_score(&pool, ip)
        .await?
        .expect("projection row exists");
    let replayed = rebuild_projection(&pool, ip)
        .await?
        .expect("appended stream yields a projection");

    // Full field equality: replay must equal the incrementally-stored row.
    assert_eq!(
        replayed, stored,
        "replay must equal the incremental projection"
    );
    // Belt-and-suspenders on the fields the stream was designed to exercise.
    assert_eq!(replayed.raw_score, stored.raw_score);
    assert_eq!(replayed.category_breakdown, stored.category_breakdown);
    assert_eq!(replayed.event_count, stored.event_count);
    assert!(replayed.has_confirmed_real);
    assert_eq!(replayed.distinct_categories, stored.distinct_categories);
    assert_eq!(replayed.max_confidence, stored.max_confidence);
    assert_eq!(replayed.eligible, stored.eligible);
    assert_eq!(
        replayed.recommended_for_vendor,
        stored.recommended_for_vendor
    );
    assert_eq!(
        replayed.recommended_for_blocklist,
        stored.recommended_for_blocklist
    );
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
async fn verify_chain_intact_with_sub_microsecond_timestamps(
    pool: PgPool,
) -> Result<(), RepoError> {
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
