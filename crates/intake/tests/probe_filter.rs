//! The reachability probe's own connections must never become evidence.
//!
//! This is the contamination guard driven across the REAL producer-to-consumer boundary: a sensor
//! line on disk, through `LogTailer`, through `IntakeRunner::run_batch`, against a real database,
//! with the assertion made on `event` and `listener_probe` rather than on the runner's return
//! value alone. A unit test over the filter expression would pass while the ledger still filled up.
//!
//! What is at stake. Every TCP sensor emits `honeypot_connection` immediately on accept, before
//! reading a byte, and that signal weighs 40 at confidence 0.900. A five-minute sweep against a
//! dozen listeners is ~3,500 such events a day from one address: the control plane's own. Unless
//! they are dropped, this node scores itself into the review queue and out into the published
//! blocklist, and nothing downstream can take that back.
//!
//! Each test runs against its own ephemeral database (`#[sqlx::test(migrations = false)]`) because
//! every assertion here is a COUNT, and counts do not survive a database shared with other tests.

use std::collections::HashSet;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use chrono::Utc;
use fleet::inventory::{Listener, Proto};
use fleet::store::{ProbeOutcome, ProbeRecord, read_all, upsert_probe};
use intake::runner::IntakeRunner;
use log_tailer::LogTailer;
use sensor_wire::*;
use sqlx::{PgPool, Row};

/// The control plane's own egress address, as `PROPOLIS_FLEET_PROBE_SOURCE_IPS` would name it.
const PROBER: &str = "198.51.100.7";
/// An address that is not the prober. Its lines must be ingested exactly as before.
const ATTACKER: &str = "203.0.113.55";

const PROBE_GRACE: Duration = Duration::from_secs(600);

async fn migrate(pool: &PgPool) {
    sqlx::migrate!("../core-scoring/migrations")
        .run(pool)
        .await
        .unwrap();
    fleet::migrator().run(pool).await.unwrap();
}

fn probe_sources() -> Arc<HashSet<IpAddr>> {
    Arc::new(HashSet::from([PROBER.parse::<IpAddr>().unwrap()]))
}

/// The row a completed sweep leaves behind, which intake's confirmation stamps.
async fn seed_probe_row(pool: &PgPool, sensor: &str) {
    upsert_probe(
        pool,
        &ProbeRecord {
            listener: Listener {
                collector_id: "local".into(),
                sensor: sensor.into(),
                protocol: Proto::Tcp,
                port: 22,
            },
            target: "198.51.100.7:22".into(),
            attempted_at: Utc::now(),
            outcome: ProbeOutcome::Reachable,
            detail: None,
            latency_ms: Some(3),
        },
    )
    .await
    .unwrap();
}

fn connection_line(source_ip: &str, sensor: &str) -> SensorEvent {
    SensorEvent {
        v: WIRE_VERSION,
        source_ip: source_ip.parse().unwrap(),
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
    }
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

async fn events_from(pool: &PgPool, ip: &str) -> i64 {
    sqlx::query("SELECT count(*) AS n FROM event WHERE source_ip = $1::inet")
        .bind(ip)
        .fetch_one(pool)
        .await
        .unwrap()
        .try_get::<i64, _>("n")
        .unwrap()
}

#[sqlx::test(migrations = false)]
async fn a_line_from_a_configured_probe_source_never_reaches_the_ledger(pool: PgPool) {
    migrate(&pool).await;
    seed_probe_row(&pool, "ssh").await;

    let dir = tempfile::tempdir().unwrap();
    let log_path = dir.path().join("events.jsonl");
    write_line(&log_path, &connection_line(PROBER, "ssh"));

    let tailer = LogTailer::new(log_path, dir.path().join("cursors"));
    let mut runner = IntakeRunner::new(
        tailer,
        pool.clone(),
        "ssh".into(),
        probe_sources(),
        PROBE_GRACE,
    );
    let result = runner.run_batch().await;

    assert_eq!(
        events_from(&pool, PROBER).await,
        0,
        "the prober's own connection reached the ledger; it would be scored and published"
    );
    assert_eq!(result.probe_confirmations, 1);
    // Counted apart from both, because ops_alert derives its stall verdict from ingested+rejected
    // and a steady drip of probe lines must not make a wedged tailer look like it is working.
    assert_eq!(result.ingested, 0, "a probe line is not an ingest");
    assert_eq!(result.rejected, 0, "a probe line is not a rejection either");
    assert_eq!(result.errors, 0);

    let rows = read_all(&pool).await.unwrap();
    assert_eq!(rows.len(), 1);
    assert!(
        rows[0].confirmed_at.is_some(),
        "the sighting must be recorded against the probe row: intake seeing this line is the only \
         proof that socket, sensor, log, shipper, gateway and intake all work"
    );
}

#[sqlx::test(migrations = false)]
async fn a_line_from_any_other_address_is_ingested_normally(pool: PgPool) {
    migrate(&pool).await;
    seed_probe_row(&pool, "ssh").await;

    let dir = tempfile::tempdir().unwrap();
    let log_path = dir.path().join("events.jsonl");
    write_line(&log_path, &connection_line(ATTACKER, "ssh"));

    let tailer = LogTailer::new(log_path, dir.path().join("cursors"));
    let mut runner = IntakeRunner::new(
        tailer,
        pool.clone(),
        "ssh".into(),
        probe_sources(),
        PROBE_GRACE,
    );
    let result = runner.run_batch().await;

    assert_eq!(
        result.ingested, 1,
        "the filter must not swallow real events"
    );
    assert_eq!(result.probe_confirmations, 0);
    assert_eq!(events_from(&pool, ATTACKER).await, 1);

    let rows = read_all(&pool).await.unwrap();
    assert!(
        rows[0].confirmed_at.is_none(),
        "an attacker's connection must not confirm the probe's own chain"
    );
}

/// A batch holding both kinds, so the two paths are exercised against one another rather than each
/// against an empty case: the probe line drops and the attacker line lands, in one pass.
#[sqlx::test(migrations = false)]
async fn a_mixed_batch_drops_only_the_probe_line_and_advances_the_cursor(pool: PgPool) {
    migrate(&pool).await;
    seed_probe_row(&pool, "ssh").await;

    let dir = tempfile::tempdir().unwrap();
    let log_path = dir.path().join("events.jsonl");
    let cursor_dir = dir.path().join("cursors");
    write_line(&log_path, &connection_line(PROBER, "ssh"));
    write_line(&log_path, &connection_line(ATTACKER, "ssh"));
    write_line(&log_path, &connection_line(PROBER, "ssh"));

    let mut runner = IntakeRunner::new(
        LogTailer::new(log_path.clone(), cursor_dir.clone()),
        pool.clone(),
        "ssh".into(),
        probe_sources(),
        PROBE_GRACE,
    );
    let result = runner.run_batch().await;
    assert_eq!(result.probe_confirmations, 2);
    assert_eq!(result.ingested, 1);
    assert_eq!(events_from(&pool, PROBER).await, 0);
    assert_eq!(events_from(&pool, ATTACKER).await, 1);

    // Consuming a probe line IS cursor progress: it was read, and re-reading it forever would
    // block every line behind it. A fresh runner over the persisted cursor must see nothing left.
    runner.persist_cursor().unwrap();
    let mut resumed = IntakeRunner::new(
        LogTailer::new(log_path, cursor_dir),
        pool.clone(),
        "ssh".into(),
        probe_sources(),
        PROBE_GRACE,
    );
    let second = resumed.run_batch().await;
    assert_eq!(second.probe_confirmations, 0);
    assert_eq!(second.ingested, 0);
    assert_eq!(
        events_from(&pool, ATTACKER).await,
        1,
        "the attacker line must not be re-ingested after the cursor advanced past a probe line"
    );
}

/// The confirmation is scoped to the sensor that produced the line. A probe line from telnet must
/// not stamp the ssh row, or one working listener would paint every other one green.
#[sqlx::test(migrations = false)]
async fn a_probe_line_confirms_only_its_own_sensor(pool: PgPool) {
    migrate(&pool).await;
    seed_probe_row(&pool, "ssh").await;
    seed_probe_row(&pool, "telnet").await;

    let dir = tempfile::tempdir().unwrap();
    let log_path = dir.path().join("events.jsonl");
    write_line(&log_path, &connection_line(PROBER, "telnet"));

    let tailer = LogTailer::new(log_path, dir.path().join("cursors"));
    let mut runner = IntakeRunner::new(
        tailer,
        pool.clone(),
        "telnet".into(),
        probe_sources(),
        PROBE_GRACE,
    );
    runner.run_batch().await;

    let rows = read_all(&pool).await.unwrap();
    let confirmed: Vec<&str> = rows
        .iter()
        .filter(|r| r.confirmed_at.is_some())
        .map(|r| r.listener.sensor.as_str())
        .collect();
    assert_eq!(confirmed, vec!["telnet"]);
}
