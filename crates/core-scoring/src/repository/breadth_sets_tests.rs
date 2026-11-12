//! The `ip_vantage` / `ip_sensor` sets (migration 0014) against the whole-history aggregates they
//! replaced. The oracle statements below are those aggregates verbatim, run on the same database
//! the append path just wrote, so any divergence between the sets and the ledger they summarize
//! shows up at the append that caused it.

use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;

use chrono::{DateTime, Duration, Utc};
use proptest::prelude::*;
use proptest::strategy::ValueTree;
use proptest::test_runner::TestRunner;
use sqlx::{PgPool, Row};

use crate::domain::enums::{Protocol, SignalType};
use crate::domain::types::{EventInput, IpScore};
use crate::scoring::breadth::{WanVantage, distinct_wan_count};

use super::events::{
    RepoError, append_event, append_telemetry_event, insert_chained, read_stored_score,
};
use super::replay::rebuild_projection;

/// The vantage aggregate `append_event` ran over the source's history before migration 0014.
const OLD_VANTAGES_SQL: &str = "SELECT host(wan_ip) AS wan, \
            bool_or(protocol = 'tcp' AND authenticated) AS auth_tcp \
     FROM event \
     WHERE source_ip = $1::inet AND wan_ip IS NOT NULL AND signal_type <> 'honeypot_session_end' \
     GROUP BY wan_ip";

/// The distinct-sensor aggregate it ran, as a set rather than `COUNT(DISTINCT sensor)` so the
/// comparison names the sensor that differs; the count is its length.
const OLD_SENSORS_SQL: &str = "SELECT DISTINCT sensor FROM event \
     WHERE source_ip = $1::inet AND signal_type <> 'honeypot_session_end'";

const SOURCES: [&str; 3] = ["192.0.2.10", "192.0.2.11", "2001:db8:1::5"];
/// Two addresses in one /24, so the prefix dedupe of `distinct_wan_count` is exercised, an IPv6
/// WAN, and `None` for a sensor with no bindable WAN address.
const WANS: [Option<&str>; 5] = [
    Some("198.51.100.1"),
    Some("198.51.100.77"),
    Some("203.0.113.5"),
    Some("2001:db8::1"),
    None,
];
const SENSORS: [&str; 3] = ["ssh", "telnet", "vnc"];
/// Five scored signals and the telemetry signal, which takes `append_telemetry_event`.
const SIGNALS: [SignalType; 6] = [
    SignalType::HoneypotConnection,
    SignalType::HoneypotLoginAttempt,
    SignalType::HoneypotCommandExec,
    SignalType::PortScan,
    SignalType::CatchallProbe,
    SignalType::HoneypotSessionEnd,
];

type Vantages = BTreeSet<(String, bool)>;

/// What the replaced aggregates return for `ip` on the ledger as it stands.
async fn old_aggregates(
    pool: &PgPool,
    ip: &str,
) -> Result<(Vantages, BTreeSet<String>), RepoError> {
    let vantages = sqlx::query(OLD_VANTAGES_SQL)
        .bind(ip)
        .fetch_all(pool)
        .await?
        .iter()
        .map(|r| -> Result<(String, bool), sqlx::Error> {
            Ok((
                r.try_get("wan")?,
                r.try_get::<Option<bool>, _>("auth_tcp")?.unwrap_or(false),
            ))
        })
        .collect::<Result<_, _>>()?;
    let sensors: Vec<String> = sqlx::query_scalar(OLD_SENSORS_SQL)
        .bind(ip)
        .fetch_all(pool)
        .await?;
    Ok((vantages, sensors.into_iter().collect()))
}

/// The rows the sets hold for `ip`.
async fn set_rows(pool: &PgPool, ip: &str) -> Result<(Vantages, BTreeSet<String>), RepoError> {
    let vantages = sqlx::query(
        "SELECT host(wan_ip) AS wan, saw_authenticated_tcp FROM ip_vantage WHERE source_ip = $1::inet",
    )
    .bind(ip)
    .fetch_all(pool)
    .await?
    .iter()
    .map(|r| -> Result<(String, bool), sqlx::Error> {
        Ok((r.try_get("wan")?, r.try_get("saw_authenticated_tcp")?))
    })
    .collect::<Result<_, _>>()?;
    let sensors: Vec<String> =
        sqlx::query_scalar("SELECT sensor FROM ip_sensor WHERE source_ip = $1::inet")
            .bind(ip)
            .fetch_all(pool)
            .await?;
    Ok((vantages, sensors.into_iter().collect()))
}

fn dwc_of(vantages: &Vantages) -> i32 {
    let list: Vec<WanVantage> = vantages
        .iter()
        .map(|(wan, auth)| WanVantage {
            wan_ip: wan.parse().expect("stored wan parses"),
            saw_authenticated_tcp: *auth,
        })
        .collect();
    distinct_wan_count(&list) as i32
}

#[allow(clippy::too_many_arguments)]
fn event(
    ip: &str,
    wan: Option<&str>,
    sensor: &str,
    signal: SignalType,
    tcp: bool,
    authenticated: bool,
    at: DateTime<Utc>,
) -> EventInput {
    EventInput::from_signal(
        ip.parse().expect("fixture source"),
        wan.map(|w| w.parse().expect("fixture wan")),
        sensor.into(),
        signal,
        if tcp { Protocol::Tcp } else { Protocol::Udp },
        authenticated,
        at,
        serde_json::json!({}),
        None,
    )
}

/// One generated append: source, WAN, sensor and signal by index, TCP or UDP, authenticated or
/// not, and the step from the previous event's `observed_at` in seconds. Steps run from -90 to
/// 900, so a sequence holds out-of-order events inside the 60 s dedup window and outside it.
type Spec = (usize, usize, usize, usize, bool, bool, i64);

/// Sequences drawn per run. Each is checked after every append, so this is about 900 appends.
const CASES: usize = 48;

fn sequence() -> impl Strategy<Value = Vec<Spec>> {
    prop::collection::vec(
        (
            0..SOURCES.len(),
            0..WANS.len(),
            0..SENSORS.len(),
            0..SIGNALS.len(),
            any::<bool>(),
            any::<bool>(),
            -90i64..900,
        ),
        1..40,
    )
}

/// Appends `specs` in order and checks, after every append, that the sets hold exactly what the
/// replaced aggregates return and that the projection was given the inputs those aggregates
/// would have produced. Returns the sources that got a projection.
async fn run_sequence(pool: &PgPool, specs: &[Spec]) -> Result<BTreeSet<&'static str>, RepoError> {
    let base: DateTime<Utc> = "2026-09-01T00:00:00Z".parse().expect("literal");
    let mut at = base;
    let mut scored = BTreeSet::new();
    for (step, &(src, wan, sensor, signal, tcp, auth, dt)) in specs.iter().enumerate() {
        at += Duration::seconds(dt);
        let ip = SOURCES[src];
        let e = event(
            ip,
            WANS[wan],
            SENSORS[sensor],
            SIGNALS[signal],
            tcp,
            auth,
            at,
        );
        if SIGNALS[signal].is_telemetry() {
            let before = set_rows(pool, ip).await?;
            append_telemetry_event(pool, e).await?;
            assert_eq!(
                set_rows(pool, ip).await?,
                before,
                "step {step}: telemetry changed the sets of {ip}"
            );
        } else {
            let score: IpScore = append_event(pool, e).await?;
            scored.insert(ip);
            let (old_vantages, old_sensors) = old_aggregates(pool, ip).await?;
            assert_eq!(
                score.distinct_wan_count,
                dwc_of(&old_vantages),
                "step {step}: distinct WAN vantages of {ip} differ from the whole-history aggregate"
            );
            assert_eq!(
                score.distinct_sensor_count,
                old_sensors.len() as i32,
                "step {step}: distinct sensors of {ip} differ from the whole-history aggregate"
            );
        }
        for ip in SOURCES {
            assert_eq!(
                set_rows(pool, ip).await?,
                old_aggregates(pool, ip).await?,
                "step {step}: the sets of {ip} differ from the ledger they summarize"
            );
        }
    }
    Ok(scored)
}

/// Random interleavings of three sources, five WANs (two sharing a /24, one IPv6, one absent),
/// three sensors, scored and telemetry signals, and out-of-order timestamps: after every append
/// the sets equal the whole-history aggregates, and at the end every projection replays from the
/// ledger. The runner is deterministic so the gate sees the same sequences on every run.
#[sqlx::test(migrations = "./migrations")]
async fn breadth_sets_match_the_whole_history_aggregates_after_every_append(
    pool: PgPool,
) -> Result<(), RepoError> {
    let mut runner = TestRunner::deterministic();
    let strategy = sequence();
    for case in 0..CASES {
        let specs = strategy
            .new_tree(&mut runner)
            .expect("strategy yields a sequence")
            .current();
        sqlx::query("TRUNCATE event, ip_score, ip_vantage, ip_sensor RESTART IDENTITY")
            .execute(&pool)
            .await?;
        let scored = run_sequence(&pool, &specs).await?;
        for ip in scored {
            let ip: IpAddr = ip.parse().expect("fixture source");
            assert_eq!(
                rebuild_projection(&pool, ip).await?,
                read_stored_score(&pool, ip).await?,
                "case {case}: replay of {ip} differs from the incremental projection; sequence {specs:?}"
            );
        }
    }
    Ok(())
}

/// A session-end record on a WAN in a /24 the source has never been seen on, from a sensor it has
/// never used, flagged authenticated TCP: every property that would add a counted vantage and a
/// sensor if it leaked. Neither set moves, and the next scored event is counted as if the record
/// were not there.
#[sqlx::test(migrations = "./migrations")]
async fn telemetry_on_a_new_wan_and_sensor_changes_neither_set(
    pool: PgPool,
) -> Result<(), RepoError> {
    let ip = "192.0.2.20";
    let t0: DateTime<Utc> = "2026-09-01T00:00:00Z".parse().expect("literal");
    let first = append_event(
        &pool,
        event(
            ip,
            Some("198.51.100.1"),
            "ssh",
            SignalType::HoneypotCommandExec,
            true,
            true,
            t0,
        ),
    )
    .await?;
    assert_eq!(
        (first.distinct_wan_count, first.distinct_sensor_count),
        (1, 1)
    );
    let before = set_rows(&pool, ip).await?;

    append_telemetry_event(
        &pool,
        event(
            ip,
            Some("203.0.113.9"),
            "telnet",
            SignalType::HoneypotSessionEnd,
            true,
            true,
            t0 + Duration::minutes(5),
        ),
    )
    .await?;
    assert_eq!(set_rows(&pool, ip).await?, before, "telemetry wrote a set");

    let next = append_event(
        &pool,
        event(
            ip,
            Some("198.51.100.1"),
            "ssh",
            SignalType::HoneypotLoginAttempt,
            true,
            true,
            t0 + Duration::minutes(10),
        ),
    )
    .await?;
    assert_eq!(
        (next.distinct_wan_count, next.distinct_sensor_count),
        (1, 1),
        "the telemetry record's WAN or sensor reached the breadth inputs"
    );
    Ok(())
}

/// The breadth inputs come from the sets alone: no whole-history read of the ledger is left on
/// the append path. A row planted in the ledger without going through `append_event` (nothing in
/// the product does this) carries a new authenticated WAN and a new sensor; a scan of the ledger
/// would count both, the sets do not.
#[sqlx::test(migrations = "./migrations")]
async fn breadth_inputs_are_read_from_the_sets_not_the_ledger(
    pool: PgPool,
) -> Result<(), RepoError> {
    let ip = "192.0.2.30";
    let t0: DateTime<Utc> = "2026-09-01T00:00:00Z".parse().expect("literal");
    append_event(
        &pool,
        event(
            ip,
            Some("198.51.100.1"),
            "ssh",
            SignalType::HoneypotCommandExec,
            true,
            true,
            t0,
        ),
    )
    .await?;

    let mut tx = pool.begin().await?;
    insert_chained(
        &mut tx,
        &event(
            ip,
            Some("203.0.113.9"),
            "vnc",
            SignalType::HoneypotLoginAttempt,
            true,
            true,
            t0 + Duration::minutes(1),
        ),
    )
    .await?;
    tx.commit().await?;

    let score = append_event(
        &pool,
        event(
            ip,
            Some("198.51.100.1"),
            "ssh",
            SignalType::HoneypotLoginAttempt,
            true,
            true,
            t0 + Duration::minutes(2),
        ),
    )
    .await?;
    let (ledger_vantages, ledger_sensors) = old_aggregates(&pool, ip).await?;
    assert_eq!(
        (dwc_of(&ledger_vantages), ledger_sensors.len()),
        (2, 2),
        "the planted row must be visible to a ledger scan, or this test proves nothing"
    );
    assert_eq!(
        score.distinct_wan_count, 1,
        "distinct WAN vantages were read from the ledger"
    );
    assert_eq!(
        score.distinct_sensor_count, 1,
        "distinct sensors were read from the ledger"
    );
    Ok(())
}

/// Source, WAN, sensor, signal, TCP, authenticated.
type LedgerRow = (
    &'static str,
    Option<&'static str>,
    &'static str,
    SignalType,
    bool,
    bool,
);

/// Migration 0014 applied to a ledger written before it existed fills the sets with exactly the
/// whole-history truth. The expected rows are computed here from the fixture, not by SQL, and the
/// fixture holds each case a backfill can get wrong: a WAN whose only authenticated event was UDP
/// and whose only TCP event was unauthenticated (false), a WAN whose authenticated TCP event came
/// after an unauthenticated one (true), a sensor seen only on events with no WAN, telemetry on a
/// new WAN and sensor flagged authenticated TCP, and a source seen only through telemetry.
#[sqlx::test(migrations = false)]
async fn migration_0014_backfills_the_sets_from_the_ledger(pool: PgPool) -> Result<(), RepoError> {
    let migrator = sqlx::migrate!("./migrations");
    migrator
        .run_to(13, &pool)
        .await
        .map_err(sqlx::Error::from)?;

    let a = "192.0.2.40";
    let b = "192.0.2.41";
    let c = "192.0.2.42";
    use SignalType::*;
    let fixture: [LedgerRow; 10] = [
        (
            a,
            Some("198.51.100.1"),
            "ssh",
            HoneypotCommandExec,
            true,
            true,
        ),
        (a, Some("203.0.113.5"), "ssh", PortScan, true, false),
        (a, Some("203.0.113.5"), "telnet", CatchallProbe, false, true),
        (a, Some("2001:db8::1"), "vnc", PortScan, false, false),
        (
            a,
            Some("2001:db8::1"),
            "vnc",
            HoneypotLoginAttempt,
            true,
            true,
        ),
        (a, None, "adb", HoneypotConnection, true, false),
        (
            a,
            Some("192.0.2.200"),
            "zzz",
            HoneypotSessionEnd,
            true,
            true,
        ),
        (
            b,
            Some("198.51.100.1"),
            "telnet",
            HoneypotCommandExec,
            true,
            true,
        ),
        (b, None, "qqq", HoneypotSessionEnd, true, true),
        (
            c,
            Some("198.51.100.9"),
            "ssh",
            HoneypotSessionEnd,
            true,
            true,
        ),
    ];
    let t0: DateTime<Utc> = "2026-09-01T00:00:00Z".parse().expect("literal");
    let mut tx = pool.begin().await?;
    for (i, &(ip, wan, sensor, signal, tcp, auth)) in fixture.iter().enumerate() {
        let at = t0 + Duration::minutes(i as i64);
        insert_chained(&mut tx, &event(ip, wan, sensor, signal, tcp, auth, at)).await?;
    }
    tx.commit().await?;

    let mut expected_vantages: BTreeMap<&str, BTreeMap<String, bool>> = BTreeMap::new();
    let mut expected_sensors: BTreeMap<&str, BTreeSet<String>> = BTreeMap::new();
    for &(ip, wan, sensor, signal, tcp, auth) in &fixture {
        if signal.is_telemetry() {
            continue;
        }
        expected_sensors
            .entry(ip)
            .or_default()
            .insert(sensor.to_string());
        if let Some(wan) = wan {
            *expected_vantages
                .entry(ip)
                .or_default()
                .entry(wan.to_string())
                .or_insert(false) |= tcp && auth;
        }
    }

    migrator.run(&pool).await.map_err(sqlx::Error::from)?;

    for ip in [a, b, c] {
        let (vantages, sensors) = set_rows(&pool, ip).await?;
        let want_vantages: Vantages = expected_vantages
            .get(ip)
            .map(|m| m.iter().map(|(w, f)| (w.clone(), *f)).collect())
            .unwrap_or_default();
        let want_sensors = expected_sensors.get(ip).cloned().unwrap_or_default();
        assert_eq!(vantages, want_vantages, "backfilled vantages of {ip}");
        assert_eq!(sensors, want_sensors, "backfilled sensors of {ip}");
    }
    let total_vantages: i64 = sqlx::query_scalar("SELECT count(*) FROM ip_vantage")
        .fetch_one(&pool)
        .await?;
    let total_sensors: i64 = sqlx::query_scalar("SELECT count(*) FROM ip_sensor")
        .fetch_one(&pool)
        .await?;
    assert_eq!(
        (total_vantages, total_sensors),
        (4, 5),
        "rows beyond the fixture's sources"
    );

    // The backfilled sets carry on: the next append counts the pre-migration history.
    let score = append_event(
        &pool,
        event(
            a,
            Some("198.51.100.1"),
            "ssh",
            SignalType::HoneypotLoginAttempt,
            true,
            true,
            t0 + Duration::hours(1),
        ),
    )
    .await?;
    let (old_vantages, old_sensors) = old_aggregates(&pool, a).await?;
    assert_eq!(score.distinct_wan_count, dwc_of(&old_vantages));
    assert_eq!(score.distinct_sensor_count, old_sensors.len() as i32);
    assert_eq!(
        (score.distinct_wan_count, score.distinct_sensor_count),
        (2, 4)
    );
    Ok(())
}
