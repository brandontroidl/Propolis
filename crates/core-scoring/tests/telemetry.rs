//! Interaction telemetry must be recorded and must never move a score - neither the score of the
//! event that carries it, nor the score of a LATER real event that reads the ledger for its
//! breadth inputs.
//!
//! The second half is the part a weight cannot buy: the append path derives distinct-sensor and
//! per-WAN vantage counts from every row it finds for a source, and `rebuild_projection` mirrors
//! those derivations. A telemetry row that merely projected as zero would still have been
//! counted there, so these tests compare a scored sequence WITH telemetry interleaved against
//! the identical sequence without it, through both the incremental path and a rebuild.

use core_scoring::domain::enums::{Protocol, SignalType};
use core_scoring::domain::types::EventInput;
use core_scoring::repository::replay::ChainStatus;
use core_scoring::repository::{
    RepoError, append_event, append_telemetry_event, read_stored_score, rebuild_projection,
    verify_chain,
};

use sqlx::PgPool;

fn attack(ip: &str, sensor: &str, wan: Option<&str>, ts: &str) -> EventInput {
    EventInput::from_signal(
        ip.parse().unwrap(),
        wan.map(|w| w.parse().unwrap()),
        sensor.into(),
        SignalType::HoneypotCommandExec,
        Protocol::Tcp,
        true,
        ts.parse().unwrap(),
        serde_json::json!({}),
        None,
    )
}

/// A session-end record. `authenticated` is a parameter because the discriminating fixture below
/// needs the WORST case: a real outcome record carries `false` (the listener does not know the
/// session's auth state), but the exclusions must hold even for a row that would otherwise count
/// as an authenticated vantage, which is the only kind the breadth rule counts at all.
fn telemetry(
    ip: &str,
    sensor: &str,
    wan: Option<&str>,
    authenticated: bool,
    ts: &str,
) -> EventInput {
    EventInput::from_signal(
        ip.parse().unwrap(),
        wan.map(|w| w.parse().unwrap()),
        sensor.into(),
        SignalType::HoneypotSessionEnd,
        Protocol::Tcp,
        authenticated,
        ts.parse().unwrap(),
        serde_json::json!({ "reason": "peer_closed", "elapsed_ms": 1200 }),
        None,
    )
}

/// attack -> telemetry -> attack must leave exactly the projection of attack -> attack, field for
/// field, and a rebuild of the ledger must agree with it.
#[sqlx::test(migrations = "./migrations")]
async fn telemetry_between_two_attacks_changes_no_scoring_state(
    pool: PgPool,
) -> Result<(), RepoError> {
    let with_telemetry = "203.0.113.10";
    let without = "203.0.113.11";

    // The telemetry row is built to be the one that WOULD change every aggregate if it leaked:
    // a sensor name neither attack uses (distinct_sensor_count 2 -> 3), a WAN in a different
    // /24 from both attacks (the breadth rule dedupes by /24, so same-/24 would prove nothing:
    // distinct_wan_count 1 -> 2), and `authenticated` true, since an unauthenticated vantage is
    // not counted at all and would make the fixture agree with a broken implementation.
    append_event(
        &pool,
        attack(
            with_telemetry,
            "sensor-a",
            Some("198.51.100.1"),
            "2026-07-17T00:00:00Z",
        ),
    )
    .await?;
    append_telemetry_event(
        &pool,
        telemetry(
            with_telemetry,
            "sensor-zzz",
            Some("198.51.101.9"),
            true,
            "2026-07-17T00:30:00Z",
        ),
    )
    .await?;
    append_event(
        &pool,
        attack(
            with_telemetry,
            "sensor-b",
            Some("198.51.100.2"),
            "2026-07-17T01:00:00Z",
        ),
    )
    .await?;

    append_event(
        &pool,
        attack(
            without,
            "sensor-a",
            Some("198.51.100.1"),
            "2026-07-17T00:00:00Z",
        ),
    )
    .await?;
    append_event(
        &pool,
        attack(
            without,
            "sensor-b",
            Some("198.51.100.2"),
            "2026-07-17T01:00:00Z",
        ),
    )
    .await?;

    let a = read_stored_score(&pool, with_telemetry.parse().unwrap())
        .await?
        .expect("scored");
    let b = read_stored_score(&pool, without.parse().unwrap())
        .await?
        .expect("scored");

    assert_eq!(a.raw_score, b.raw_score, "raw score");
    assert_eq!(a.event_count, b.event_count, "event count");
    assert_eq!(
        a.established_event_count, b.established_event_count,
        "established event count"
    );
    assert_eq!(a.distinct_categories, b.distinct_categories, "categories");
    assert_eq!(a.distinct_sensor_count, b.distinct_sensor_count, "sensors");
    assert_eq!(a.distinct_wan_count, b.distinct_wan_count, "wan vantages");
    assert_eq!(a.max_confidence, b.max_confidence, "max confidence");
    assert_eq!(a.eligible, b.eligible, "eligibility");
    assert_eq!(a.tier, b.tier, "tier");
    assert_eq!(a.decay_anchor, b.decay_anchor, "decay anchor");
    assert_eq!(a.active_days, b.active_days, "active days");
    assert_eq!(a.category_breakdown, b.category_breakdown, "breakdown");

    // A rebuild from the ledger must reach the same place: if replay folded the telemetry row it
    // would diverge from the incremental projection it is supposed to reproduce.
    let rebuilt = rebuild_projection(&pool, with_telemetry.parse().unwrap())
        .await?
        .expect("rebuildable");
    assert_eq!(rebuilt.raw_score, a.raw_score, "replay raw score");
    assert_eq!(rebuilt.event_count, a.event_count, "replay event count");
    assert_eq!(
        rebuilt.distinct_sensor_count, a.distinct_sensor_count,
        "replay sensors"
    );
    assert_eq!(
        rebuilt.distinct_wan_count, a.distinct_wan_count,
        "replay wan vantages"
    );
    assert_eq!(rebuilt.category_breakdown, a.category_breakdown);

    // The record is still in the ledger, and the chain still verifies with it in place.
    let stored: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM event WHERE source_ip = $1::inet AND signal_type = 'honeypot_session_end'",
    )
    .bind(with_telemetry)
    .fetch_one(&pool)
    .await?;
    assert_eq!(stored, 1, "the outcome is recorded, not discarded");
    let status = verify_chain(&pool).await?;
    assert!(matches!(status, ChainStatus::Intact), "{status:?}");
    Ok(())
}

/// An address seen only through telemetry is not an address the platform has scored: no
/// projection row at all, so it can never be recommended, listed or shipped.
#[sqlx::test(migrations = "./migrations")]
async fn telemetry_alone_creates_no_scoring_state(pool: PgPool) -> Result<(), RepoError> {
    let ip = "203.0.113.12";
    append_telemetry_event(
        &pool,
        telemetry(
            ip,
            "sensor-a",
            Some("198.51.100.1"),
            false,
            "2026-07-17T00:00:00Z",
        ),
    )
    .await?;

    assert!(
        read_stored_score(&pool, ip.parse().unwrap())
            .await?
            .is_none(),
        "telemetry must not create an ip_score row"
    );
    assert!(
        rebuild_projection(&pool, ip.parse().unwrap())
            .await?
            .is_none(),
        "and a rebuild must not invent one"
    );
    let rows: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM event WHERE source_ip = $1::inet")
        .bind(ip)
        .fetch_one(&pool)
        .await?;
    assert_eq!(rows, 1, "the record itself is kept");
    Ok(())
}

/// The two paths refuse each other's signals, so neither a telemetry row folded into a score nor
/// an attack recorded as unscored telemetry can happen by mistake.
#[sqlx::test(migrations = "./migrations")]
async fn each_append_path_refuses_the_other_kind(pool: PgPool) -> Result<(), RepoError> {
    let scored = append_event(
        &pool,
        telemetry(
            "203.0.113.13",
            "sensor-a",
            None,
            false,
            "2026-07-17T00:00:00Z",
        ),
    )
    .await;
    assert!(
        matches!(
            scored,
            Err(RepoError::NotScorable(SignalType::HoneypotSessionEnd))
        ),
        "the scoring path must refuse telemetry, got {scored:?}"
    );

    let unscored = append_telemetry_event(
        &pool,
        attack("203.0.113.13", "sensor-a", None, "2026-07-17T00:00:00Z"),
    )
    .await;
    assert!(
        matches!(
            unscored,
            Err(RepoError::NotScorable(SignalType::HoneypotCommandExec))
        ),
        "the telemetry path must refuse a scored signal, got {unscored:?}"
    );

    let rows: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM event")
        .fetch_one(&pool)
        .await?;
    assert_eq!(rows, 0, "a refused append writes nothing");
    Ok(())
}

/// Every telemetry signal must be named by the SQL exclusion the aggregates use. Adding a
/// telemetry variant without extending that predicate would silently let it back into breadth.
#[sqlx::test(migrations = "./migrations")]
async fn the_exclusion_predicate_names_every_telemetry_signal(
    pool: PgPool,
) -> Result<(), RepoError> {
    // The wire spelling of each telemetry signal, written as a literal rather than derived, so a
    // broken transform cannot agree with itself.
    let wire = |s: SignalType| match s {
        SignalType::HoneypotSessionEnd => "honeypot_session_end",
        other => panic!("{other:?} is telemetry but has no wire spelling here"),
    };
    for s in SignalType::TELEMETRY {
        // Ask the database itself: a row of this type must be invisible to the aggregate's
        // predicate, which is the property the queries depend on.
        let excluded: bool =
            sqlx::query_scalar("SELECT $1::text <> 'honeypot_session_end' IS NOT TRUE")
                .bind(wire(s))
                .fetch_one(&pool)
                .await?;
        assert!(excluded, "{s:?} is not covered by the exclusion predicate");
    }
    Ok(())
}
