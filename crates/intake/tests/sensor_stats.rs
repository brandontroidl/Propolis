//! A sensor's own `sensor_stats` line is not evidence: it must reach `sensor_stats` and nothing
//! else. Driven across the real producer-to-consumer boundary (a line on disk, `LogTailer`,
//! `IntakeRunner::run_batch`, a real database), because a unit test over the intercept would pass
//! while the ledger still filled up.
//!
//! The exclusion is proved over the whole schema, not over the tables someone remembered: every
//! other table is counted before and after the stats lines go through, and none may change. The
//! feed, the review queue, the campaigns, the console's score views and the vendor path all read
//! the ledger (`event`, `ip_score` and what derives from them) and nothing else, so a table that
//! does not move cannot feed any of them. Intake is the only consumer of sensor logs
//! (`SensorEvent` is deserialized nowhere else outside tests), which makes this the one place the
//! signal could leak.

use std::collections::{BTreeMap, HashSet};
use std::sync::Arc;
use std::time::Duration;

use chrono::Utc;
use intake::runner::IntakeRunner;
use log_tailer::LogTailer;
use sensor_wire::*;
use sqlx::{PgPool, Row};

async fn migrate(pool: &PgPool) {
    sqlx::migrate!("../core-scoring/migrations")
        .run(pool)
        .await
        .unwrap();
    fleet::migrator().run(pool).await.unwrap();
}

fn write_line(path: &std::path::Path, event: &SensorEvent) {
    use std::io::Write;
    let mut f = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .unwrap();
    writeln!(f, "{}", serde_json::to_string(event).unwrap()).unwrap();
}

fn attacker_line(sensor: &str) -> SensorEvent {
    SensorEvent {
        v: WIRE_VERSION,
        source_ip: "203.0.113.55".parse().unwrap(),
        wan_ip: None,
        sensor: sensor.into(),
        signal_type: SIGNAL_HONEYPOT_CONNECTION.into(),
        protocol: PROTO_TCP.into(),
        authenticated: false,
        observed_at: Utc::now(),
        metadata: serde_json::json!({"protocol_label": sensor}),
        sample: None,
        session_id: None,
        occurrence_id: None,
        reply: None,
    }
}

fn stats(sensor: &str, dropped: u64) -> SensorStats {
    SensorStats {
        sensor: sensor.into(),
        uptime_secs: 120,
        is_final: false,
        dropped,
        spool_refused: 2,
        truncated: 3,
        refused: 4,
        budget_current: 5,
        budget_high_water: 6,
        budget_refused: 7,
    }
}

fn runner(pool: &PgPool, dir: &std::path::Path, label: &str) -> IntakeRunner {
    IntakeRunner::new(
        LogTailer::new(dir.join("events.jsonl"), dir.join("cursors")),
        pool.clone(),
        label.into(),
        Arc::new(HashSet::new()),
        Duration::from_secs(60),
    )
}

/// Row count of every table except `sensor_stats` and sqlx's own bookkeeping.
async fn ledger_counts(pool: &PgPool) -> BTreeMap<String, i64> {
    let tables: Vec<String> = sqlx::query_scalar(
        "SELECT table_name::text FROM information_schema.tables \
         WHERE table_schema = 'public' AND table_type = 'BASE TABLE' \
           AND table_name <> 'sensor_stats' AND table_name NOT LIKE '\\_sqlx%' \
         ORDER BY table_name",
    )
    .fetch_all(pool)
    .await
    .unwrap();
    assert!(
        tables.iter().any(|t| t == "event") && tables.iter().any(|t| t == "ip_score"),
        "the schema walk must see the ledger tables: {tables:?}"
    );
    let mut out = BTreeMap::new();
    for table in tables {
        // Names come from the catalog, quoted as identifiers.
        let n: i64 = sqlx::query(sqlx::AssertSqlSafe(format!(
            "SELECT count(*) AS n FROM \"{table}\""
        )))
        .fetch_one(pool)
        .await
        .unwrap()
        .try_get("n")
        .unwrap();
        out.insert(table, n);
    }
    out
}

async fn stored(pool: &PgPool) -> Vec<fleet::stats::SensorStatsRow> {
    fleet::stats::read_all(pool).await.unwrap()
}

#[sqlx::test(migrations = false)]
async fn good_stats_are_stored_and_no_other_table_in_the_schema_changes(pool: PgPool) {
    migrate(&pool).await;
    let dir = tempfile::tempdir().unwrap();
    let log = dir.path().join("events.jsonl");
    write_line(&log, &attacker_line("ssh"));
    let mut runner = runner(&pool, dir.path(), "ssh");
    let first = runner.run_batch().await;
    assert_eq!((first.ingested, first.stats_updates), (1, 0));
    let before = ledger_counts(&pool).await;
    assert!(before["event"] >= 1 && before["ip_score"] >= 1);

    write_line(
        &log,
        &stats("ssh", 9).to_event("2026-10-09T00:00:00Z".parse().unwrap()),
    );
    write_line(
        &log,
        &stats("ssh", 10).to_event("2026-10-09T00:01:00Z".parse().unwrap()),
    );
    let result = runner.run_batch().await;

    assert_eq!(result.stats_updates, 2);
    assert_eq!(result.ingested, 0, "a stats line is not an ingest");
    assert_eq!(result.rejected, 0);
    assert_eq!(result.errors, 0);
    assert_eq!(
        ledger_counts(&pool).await,
        before,
        "a sensor_stats line changed a table other than sensor_stats"
    );
    let ip_zero: i64 =
        sqlx::query_scalar("SELECT count(*) FROM event WHERE source_ip = '0.0.0.0'::inet")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(ip_zero, 0);

    let rows = stored(&pool).await;
    assert_eq!(rows.len(), 1);
    assert_eq!((rows[0].sensor.as_str(), rows[0].dropped), ("ssh", 10));
    assert_eq!(rows[0].spool_refused, 2);
    assert_eq!(rows[0].budget_high_water, 6);
    assert!(!rows[0].is_final);
}

#[sqlx::test(migrations = false)]
async fn malformed_stats_lines_are_refused_and_stored_nowhere(pool: PgPool) {
    migrate(&pool).await;
    let dir = tempfile::tempdir().unwrap();
    let log = dir.path().join("events.jsonl");
    let when = "2026-10-09T00:00:00Z".parse().unwrap();
    let ok = stats("ssh", 1).to_event(when);

    // Wrong source: an attacker address on a stats line.
    write_line(
        &log,
        &SensorEvent {
            source_ip: "203.0.113.9".parse().unwrap(),
            ..ok.clone()
        },
    );
    // Another sensor's name in this log (and consistent inside the event).
    write_line(&log, &stats("telnet", 1).to_event(when));
    // An extra field smuggled into the metadata.
    let mut extra = ok.clone();
    extra.metadata["command"] = "x".into();
    write_line(&log, &extra);
    // A value past the bound.
    let mut huge = ok.clone();
    huge.metadata["dropped"] = (SENSOR_STATS_MAX_VALUE + 1).into();
    write_line(&log, &huge);
    // The event's own sensor disagrees with the metadata's.
    write_line(
        &log,
        &SensorEvent {
            sensor: "telnet".into(),
            ..ok.clone()
        },
    );

    let before = ledger_counts(&pool).await;
    let mut runner = runner(&pool, dir.path(), "ssh");
    let result = runner.run_batch().await;

    assert_eq!(
        result.rejected, 5,
        "every malformed line is counted refused"
    );
    assert_eq!(result.stats_updates, 0);
    assert_eq!(result.ingested, 0);
    assert!(
        stored(&pool).await.is_empty(),
        "a refused line must not be stored"
    );
    assert_eq!(ledger_counts(&pool).await, before);
}

#[sqlx::test(migrations = false)]
async fn one_logs_stats_cannot_write_another_sensors_row(pool: PgPool) {
    migrate(&pool).await;
    let when = "2026-10-09T00:00:00Z".parse().unwrap();
    // The telnet log carries a line claiming to be ssh: refused, so the ssh row is not forged.
    let telnet_dir = tempfile::tempdir().unwrap();
    write_line(
        &telnet_dir.path().join("events.jsonl"),
        &stats("ssh", 1).to_event(when),
    );
    let result = runner(&pool, telnet_dir.path(), "telnet").run_batch().await;
    assert_eq!((result.rejected, result.stats_updates), (1, 0));
    assert!(stored(&pool).await.is_empty());

    // The same line in the ssh log is that sensor's own, and is stored.
    let ssh_dir = tempfile::tempdir().unwrap();
    write_line(
        &ssh_dir.path().join("events.jsonl"),
        &stats("ssh", 1).to_event(when),
    );
    let result = runner(&pool, ssh_dir.path(), "ssh").run_batch().await;
    assert_eq!((result.rejected, result.stats_updates), (0, 1));
    assert_eq!(stored(&pool).await.len(), 1);
}

#[test]
fn the_converter_would_refuse_a_stats_line_even_if_the_intercept_failed() {
    let event = stats("ssh", 1).to_event("2026-10-09T00:00:00Z".parse().unwrap());
    assert!(matches!(
        intake::converter::convert_event(event),
        Err(intake::converter::ConvertError::UnknownSignalType(_))
    ));
}
