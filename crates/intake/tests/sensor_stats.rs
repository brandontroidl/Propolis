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

#[sqlx::test(migrations = false)]
async fn a_stats_line_in_a_collector_spool_is_stored_under_the_collector_and_the_sensor(
    pool: PgPool,
) {
    migrate(&pool).await;
    let dir = tempfile::tempdir().unwrap();
    write_line(
        &dir.path().join("events.jsonl"),
        &stats("ssh", 9).to_event("2026-10-09T00:00:00Z".parse().unwrap()),
    );
    let before = ledger_counts(&pool).await;
    let result = runner(&pool, dir.path(), "collector-a").run_batch().await;

    assert_eq!(result.stats_updates, 1);
    assert_eq!((result.rejected, result.ingested, result.errors), (0, 0, 0));
    assert_eq!(ledger_counts(&pool).await, before);
    let rows = stored(&pool).await;
    assert_eq!(rows.len(), 1);
    assert_eq!(
        (rows[0].sensor.as_str(), rows[0].dropped),
        ("collector-a/ssh", 9)
    );
}

#[sqlx::test(migrations = false)]
async fn the_same_sensor_on_two_collectors_and_on_the_control_node_is_three_rows(pool: PgPool) {
    migrate(&pool).await;
    // Each line is newer than the one before, so a shared key would leave only the last.
    let lines = [
        ("ssh", 1, "2026-10-09T00:00:00Z"),
        ("collector-a", 2, "2026-10-09T00:01:00Z"),
        ("collector-b", 3, "2026-10-09T00:02:00Z"),
    ];
    for (label, dropped, when) in lines {
        let dir = tempfile::tempdir().unwrap();
        write_line(
            &dir.path().join("events.jsonl"),
            &stats("ssh", dropped).to_event(when.parse().unwrap()),
        );
        let result = runner(&pool, dir.path(), label).run_batch().await;
        assert_eq!((result.rejected, result.stats_updates), (0, 1), "{label}");
    }

    let rows: Vec<(String, i64)> = stored(&pool)
        .await
        .into_iter()
        .map(|r| (r.sensor, r.dropped))
        .collect();
    assert_eq!(
        rows,
        vec![
            ("collector-a/ssh".to_string(), 2),
            ("collector-b/ssh".to_string(), 3),
            ("ssh".to_string(), 1),
        ],
        "no row overwrote another"
    );
}

#[sqlx::test(migrations = false)]
async fn a_collector_label_cannot_write_a_row_for_a_sensor_this_system_does_not_know(pool: PgPool) {
    migrate(&pool).await;
    let dir = tempfile::tempdir().unwrap();
    let log = dir.path().join("events.jsonl");
    let when = "2026-10-09T00:00:00Z".parse().unwrap();
    write_line(&log, &stats("nosuchsensor", 1).to_event(when));
    // A slash in the claimed name would otherwise move the split between collector and sensor.
    write_line(&log, &stats("evil/ssh", 1).to_event(when));
    let result = runner(&pool, dir.path(), "collector-a").run_batch().await;

    assert_eq!((result.rejected, result.stats_updates), (2, 0));
    assert!(stored(&pool).await.is_empty());
}

#[sqlx::test(migrations = false)]
async fn a_64_character_collector_label_is_stored_under_a_key_the_column_accepts(pool: PgPool) {
    migrate(&pool).await;
    let label = "c".repeat(64);
    let dir = tempfile::tempdir().unwrap();
    write_line(
        &dir.path().join("events.jsonl"),
        &stats("postgresql", 1).to_event("2026-10-09T00:00:00Z".parse().unwrap()),
    );
    let result = runner(&pool, dir.path(), &label).run_batch().await;

    assert_eq!((result.rejected, result.stats_updates), (0, 1));
    let rows = stored(&pool).await;
    assert_eq!(
        rows.len(),
        1,
        "the insert was refused by the column's bound"
    );
    assert!(rows[0].sensor.chars().count() <= 64, "{}", rows[0].sensor);
    assert!(
        rows[0].sensor.ends_with("/postgresql"),
        "{}",
        rows[0].sensor
    );
}

/// Every event logged while it is the thread's default subscriber, as `name=value` pairs. The
/// `sqlx::test` runtime is single-threaded, so the runner's warnings land here.
#[derive(Clone, Default)]
struct Captured(Arc<std::sync::Mutex<Vec<String>>>);

impl Captured {
    /// The logged events whose text contains `needle`.
    fn with(&self, needle: &str) -> Vec<String> {
        let events = self.0.lock().unwrap();
        events
            .iter()
            .filter(|e| e.contains(needle))
            .cloned()
            .collect()
    }
}

impl tracing::Subscriber for Captured {
    fn enabled(&self, _: &tracing::Metadata<'_>) -> bool {
        true
    }
    fn new_span(&self, _: &tracing::span::Attributes<'_>) -> tracing::span::Id {
        tracing::span::Id::from_u64(1)
    }
    fn record(&self, _: &tracing::span::Id, _: &tracing::span::Record<'_>) {}
    fn record_follows_from(&self, _: &tracing::span::Id, _: &tracing::span::Id) {}
    fn event(&self, event: &tracing::Event<'_>) {
        struct Fields(String);
        impl tracing::field::Visit for Fields {
            fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
                self.0.push_str(&format!("{}={value:?} ", field.name()));
            }
        }
        let mut fields = Fields(String::new());
        event.record(&mut fields);
        self.0.lock().unwrap().push(fields.0);
    }
    fn enter(&self, _: &tracing::span::Id) {}
    fn exit(&self, _: &tracing::span::Id) {}
}

/// The operator reads why a stats line was refused from the WARN alone, and health-and-observability
/// quotes both texts, so each refusal must log its own text, against the line that caused it.
#[sqlx::test(migrations = false)]
async fn each_stats_refusal_logs_its_own_reason_against_the_line_it_refused(pool: PgPool) {
    migrate(&pool).await;
    let captured = Captured::default();
    let _guard = tracing::subscriber::set_default(captured.clone());
    let when = "2026-10-09T00:00:00Z".parse().unwrap();

    let bound = tempfile::tempdir().unwrap();
    write_line(
        &bound.path().join("events.jsonl"),
        &stats("telnet", 1).to_event(when),
    );
    let result = runner(&pool, bound.path(), "ssh").run_batch().await;
    assert_eq!(result.rejected, 1);

    let spool = tempfile::tempdir().unwrap();
    write_line(
        &spool.path().join("events.jsonl"),
        &stats("nosuchsensor", 1).to_event(when),
    );
    let result = runner(&pool, spool.path(), "collector-a").run_batch().await;
    assert_eq!(result.rejected, 1);

    let other = captured.with("names a different sensor than this log's label");
    assert_eq!(other.len(), 1, "{other:?}");
    assert!(
        other[0].contains("sensor=ssh ") && other[0].contains("claimed=telnet "),
        "{other:?}"
    );
    let unknown = captured.with("names a sensor this system does not know");
    assert_eq!(unknown.len(), 1, "{unknown:?}");
    assert!(
        unknown[0].contains("sensor=collector-a ") && unknown[0].contains("claimed=nosuchsensor "),
        "{unknown:?}"
    );
}

#[test]
fn the_converter_would_refuse_a_stats_line_even_if_the_intercept_failed() {
    let event = stats("ssh", 1).to_event("2026-10-09T00:00:00Z".parse().unwrap());
    assert!(matches!(
        intake::converter::convert_event(event),
        Err(intake::converter::ConvertError::UnknownSignalType(_))
    ));
}
