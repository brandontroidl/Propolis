//! What a line says about itself is not evidence of it.
//!
//! Each sensor runs as its own user and writes its own log, so the file a line was read from
//! proves which sensor wrote it; the line's `sensor`, `signal_type`, `protocol`, `authenticated`
//! and `observed_at` are whatever that process put there. These tests drive the refusals across
//! the real boundary (a line on disk, `LogTailer`, `IntakeRunner::run_batch`, a real database)
//! and assert on the ledger, the score and the probe rows, because the harm is what a forged line
//! leaves there: a low-interaction sensor's log claiming another sensor's authenticated upload, a
//! summary worth a thousand events, a confirmation for a listener it cannot see, or a timestamp
//! that pins a listing. The policy itself is tested exhaustively, without a database, in
//! `sensor_wire::origin`.

use std::collections::HashSet;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use chrono::{DateTime, Utc};
use core_scoring::read_score;
use fleet::inventory::{Listener, Proto};
use fleet::store::{ProbeOutcome, ProbeRecord, upsert_probe};
use intake::runner::{IntakeRunner, MAX_FUTURE_SKEW, RunBatchResult};
use log_tailer::LogTailer;
use sensor_wire::*;
use sqlx::{PgPool, Row};

/// The control plane's own egress address, as `PROPOLIS_FLEET_PROBE_SOURCE_IPS` would name it.
const PROBER: &str = "198.51.100.7";
/// The address a forged line tries to incriminate.
const VICTIM: &str = "203.0.113.80";
/// An address whose lines are honest and must be ingested as before.
const ATTACKER: &str = "203.0.113.55";

async fn migrate(pool: &PgPool) {
    sqlx::migrate!("../core-scoring/migrations")
        .run(pool)
        .await
        .unwrap();
    fleet::migrator().run(pool).await.unwrap();
}

fn line(source_ip: &str, sensor: &str, signal_type: &str) -> SensorEvent {
    SensorEvent {
        v: WIRE_VERSION,
        source_ip: source_ip.parse().unwrap(),
        wan_ip: None,
        sensor: sensor.into(),
        signal_type: signal_type.into(),
        protocol: PROTO_TCP.into(),
        authenticated: false,
        observed_at: Utc::now(),
        metadata: serde_json::json!({ "protocol_label": sensor }),
        sample: None,
        session_id: None,
        occurrence_id: None,
        reply: None,
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

fn runner(pool: &PgPool, dir: &std::path::Path, label: &str) -> IntakeRunner {
    IntakeRunner::new(
        LogTailer::new(dir.join("events.jsonl"), dir.join("cursors")),
        pool.clone(),
        label.into(),
        Arc::new(HashSet::from([PROBER.parse::<IpAddr>().unwrap()])),
        Duration::from_secs(600),
    )
}

/// Writes `lines` to a fresh log and runs one batch over it under `label`.
async fn ingest(pool: &PgPool, label: &str, lines: &[SensorEvent]) -> RunBatchResult {
    let dir = tempfile::tempdir().unwrap();
    for event in lines {
        write_line(&dir.path().join("events.jsonl"), event);
    }
    runner(pool, dir.path(), label).run_batch().await
}

/// `(sensor, signal_type)` of every ledger row for `ip`, in ledger order.
async fn ledger(pool: &PgPool, ip: &str) -> Vec<(String, String)> {
    sqlx::query(
        "SELECT sensor, signal_type::text AS signal_type FROM event \
         WHERE source_ip = $1::inet ORDER BY id",
    )
    .bind(ip)
    .fetch_all(pool)
    .await
    .unwrap()
    .iter()
    .map(|row| (row.get("sensor"), row.get("signal_type")))
    .collect()
}

/// No ledger row and no score: nothing a later reader could act on.
async fn assert_untouched(pool: &PgPool, ip: &str) {
    let rows = ledger(pool, ip).await;
    assert!(rows.is_empty(), "{ip} reached the ledger: {rows:?}");
    assert!(
        read_score(pool, ip.parse().unwrap())
            .await
            .unwrap()
            .is_none(),
        "{ip} has a score"
    );
}

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

async fn confirmed_sensors(pool: &PgPool) -> Vec<String> {
    fleet::store::read_all(pool)
        .await
        .unwrap()
        .into_iter()
        .filter(|row| row.confirmed_at.is_some())
        .map(|row| row.listener.sensor)
        .collect()
}

/// A line dated further ahead than the allowed skew would pin its address: the score would not
/// decay and the listing would not leave a feed window until the clock caught up. It is refused,
/// the lines around it are ingested, and the cursor passes it for good.
#[sqlx::test(migrations = false)]
async fn a_line_dated_beyond_the_skew_is_refused_and_one_within_it_is_ingested(pool: PgPool) {
    migrate(&pool).await;
    let dir = tempfile::tempdir().unwrap();
    let log = dir.path().join("events.jsonl");
    let at = |ip: &str, observed_at: DateTime<Utc>| SensorEvent {
        observed_at,
        ..line(ip, "ssh", SIGNAL_HONEYPOT_CONNECTION)
    };
    let now = Utc::now();
    write_line(&log, &at("203.0.113.1", now - chrono::Duration::days(11)));
    write_line(&log, &at(VICTIM, now + chrono::Duration::days(3 * 365)));
    write_line(
        &log,
        &at(
            "203.0.113.2",
            now + MAX_FUTURE_SKEW + chrono::Duration::minutes(5),
        ),
    );
    // Clock drift an honest collector can have: well inside the bound, ingested as written.
    let drifted = now + MAX_FUTURE_SKEW - chrono::Duration::minutes(5);
    write_line(&log, &at("203.0.113.3", drifted));
    write_line(&log, &at(ATTACKER, now));

    let mut runner = runner(&pool, dir.path(), "ssh");
    let result = runner.run_batch().await;
    assert_eq!((result.ingested, result.rejected, result.errors), (3, 2, 0));
    assert!(result.cursor_moved());

    assert_untouched(&pool, VICTIM).await;
    assert_untouched(&pool, "203.0.113.2").await;
    for ip in ["203.0.113.1", "203.0.113.3", ATTACKER] {
        assert_eq!(ledger(&pool, ip).await.len(), 1, "{ip}");
    }
    let stored: DateTime<Utc> =
        sqlx::query_scalar("SELECT last_seen FROM ip_score WHERE source_ip = '203.0.113.3'::inet")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert!(
        (stored - drifted).num_seconds().abs() <= 1,
        "a line within the skew keeps its own time: {stored} vs {drifted}"
    );
    let newest: DateTime<Utc> = sqlx::query_scalar("SELECT max(observed_at) FROM event")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert!(newest <= now + MAX_FUTURE_SKEW, "{newest}");

    // The refused lines are behind the cursor: a restart does not read them again.
    runner.persist_cursor().unwrap();
    let again = self::runner(&pool, dir.path(), "ssh").run_batch().await;
    assert_eq!(again, RunBatchResult::default());
}

/// The future bound covers every kind of line, not only evidence: a stats row or a probe
/// confirmation stamped from the future would read as the freshest thing known about a sensor.
#[sqlx::test(migrations = false)]
async fn a_future_dated_stats_or_probe_line_is_refused_too(pool: PgPool) {
    migrate(&pool).await;
    seed_probe_row(&pool, "ssh").await;
    let ahead = Utc::now() + MAX_FUTURE_SKEW + chrono::Duration::hours(1);
    let stats = SensorStats {
        sensor: "ssh".into(),
        uptime_secs: 120,
        is_final: false,
        dropped: 0,
        spool_refused: 0,
        truncated: 0,
        refused: 0,
        budget_current: 0,
        budget_high_water: 0,
        budget_refused: 0,
    };
    let probe = SensorEvent {
        observed_at: ahead,
        ..line(PROBER, "ssh", SIGNAL_HONEYPOT_CONNECTION)
    };
    let result = ingest(&pool, "ssh", &[stats.to_event(ahead), probe]).await;
    assert_eq!(
        (
            result.rejected,
            result.stats_updates,
            result.probe_confirmations
        ),
        (2, 0, 0)
    );
    assert!(fleet::stats::read_all(&pool).await.unwrap().is_empty());
    assert_eq!(confirmed_sensors(&pool).await, Vec::<String>::new());

    // The same two lines dated now are what they always were.
    let probe = line(PROBER, "ssh", SIGNAL_HONEYPOT_CONNECTION);
    let result = ingest(&pool, "ssh", &[stats.to_event(Utc::now()), probe]).await;
    assert_eq!(
        (
            result.rejected,
            result.stats_updates,
            result.probe_confirmations
        ),
        (0, 1, 1)
    );
}

/// The case the policy exists for: sensor-catchall emits only `catchall_probe` (weight 15, never
/// confirmed-real). Compromised, it must not be able to write another sensor's authenticated
/// malware upload into the ledger from its own log.
#[sqlx::test(migrations = false)]
async fn the_catchall_log_cannot_speak_for_the_ssh_sensor(pool: PgPool) {
    migrate(&pool).await;
    let forged = SensorEvent {
        authenticated: true,
        ..line(VICTIM, "ssh", SIGNAL_HONEYPOT_MALWARE_UPLOAD)
    };
    // Honest in every field but the name: an ssh line is not this log's to write.
    let borrowed_name = line(VICTIM, "ssh", SIGNAL_HONEYPOT_CONNECTION);
    let honest = line(ATTACKER, "catchall", SIGNAL_CATCHALL_PROBE);

    let result = ingest(&pool, "catchall", &[forged.clone(), borrowed_name, honest]).await;
    assert_eq!((result.ingested, result.rejected, result.errors), (1, 2, 0));
    assert_untouched(&pool, VICTIM).await;
    assert_eq!(
        ledger(&pool, ATTACKER).await,
        [("catchall".to_string(), "catchall_probe".to_string())]
    );

    // The same line from the log that is ssh's own is evidence.
    let result = ingest(&pool, "ssh", &[forged]).await;
    assert_eq!((result.ingested, result.rejected), (1, 0));
    let score = read_score(&pool, VICTIM.parse().unwrap())
        .await
        .unwrap()
        .unwrap();
    assert!(score.has_confirmed_real);
}

/// Under its own name the catchall sensor is still held to what it can observe: it never
/// authenticates anyone and never captures a payload.
#[sqlx::test(migrations = false)]
async fn a_catchall_line_that_is_authenticated_or_an_upload_is_refused(pool: PgPool) {
    migrate(&pool).await;
    let authenticated = SensorEvent {
        authenticated: true,
        ..line(VICTIM, "catchall", SIGNAL_CATCHALL_PROBE)
    };
    let upload = line(VICTIM, "catchall", SIGNAL_HONEYPOT_MALWARE_UPLOAD);
    let login = line(VICTIM, "catchall", SIGNAL_HONEYPOT_LOGIN_ATTEMPT);
    let over_icmp = SensorEvent {
        protocol: PROTO_ICMP.into(),
        ..line(VICTIM, "catchall", SIGNAL_CATCHALL_PROBE)
    };
    let honest_udp = SensorEvent {
        protocol: PROTO_UDP.into(),
        ..line(ATTACKER, "catchall", SIGNAL_CATCHALL_PROBE)
    };

    let result = ingest(
        &pool,
        "catchall",
        &[authenticated, upload, login, over_icmp, honest_udp],
    )
    .await;
    assert_eq!((result.ingested, result.rejected, result.errors), (1, 4, 0));
    assert_untouched(&pool, VICTIM).await;
    let score = read_score(&pool, ATTACKER.parse().unwrap())
        .await
        .unwrap()
        .unwrap();
    assert!(!score.has_confirmed_real);
    assert_eq!(score.event_count, 1);
}

/// A control plane tails one spool per collector, and that stream interleaves every sensor of
/// the collector. Its label is not a sensor's, so the log is not bound: it carries any known
/// sensor's lines, each still held to its own sensor's row, and no line under a name no sensor
/// writes.
#[sqlx::test(migrations = false)]
async fn a_collector_stream_carries_every_known_sensor_and_no_unknown_one(pool: PgPool) {
    migrate(&pool).await;
    let telnet = SensorEvent {
        authenticated: true,
        ..line(ATTACKER, "telnet", SIGNAL_HONEYPOT_LOGIN_ATTEMPT)
    };
    let ssh = SensorEvent {
        authenticated: true,
        ..line(ATTACKER, "ssh", SIGNAL_HONEYPOT_COMMAND_EXEC)
    };
    let unknown = line(VICTIM, "backdoor", SIGNAL_HONEYPOT_CONNECTION);
    let label_as_sensor = line(VICTIM, "collector-01", SIGNAL_HONEYPOT_CONNECTION);
    let outside_its_row = line(VICTIM, "catchall", SIGNAL_HONEYPOT_MALWARE_UPLOAD);

    let result = ingest(
        &pool,
        "collector-01",
        &[telnet, unknown, ssh, label_as_sensor, outside_its_row],
    )
    .await;
    assert_eq!((result.ingested, result.rejected, result.errors), (2, 3, 0));
    assert_eq!(
        ledger(&pool, ATTACKER).await,
        [
            ("telnet".to_string(), "honeypot_login_attempt".to_string()),
            ("ssh".to_string(), "honeypot_command_exec".to_string()),
        ]
    );
    assert_untouched(&pool, VICTIM).await;
}

/// A probe line is not evidence, but its sensor name decides which listener is marked reachable.
/// The catchall log must not be able to keep the ssh listener's row green.
#[sqlx::test(migrations = false)]
async fn a_probe_line_in_the_catchall_log_naming_ssh_confirms_nothing(pool: PgPool) {
    migrate(&pool).await;
    seed_probe_row(&pool, "ssh").await;
    seed_probe_row(&pool, "catchall").await;

    let forged = line(PROBER, "ssh", SIGNAL_HONEYPOT_CONNECTION);
    let result = ingest(&pool, "catchall", std::slice::from_ref(&forged)).await;
    assert_eq!((result.probe_confirmations, result.rejected), (0, 1));
    assert_eq!(confirmed_sensors(&pool).await, Vec::<String>::new());
    assert_untouched(&pool, PROBER).await;

    // Its own probe line confirms its own listener, and the ssh log confirms ssh.
    let own = line(PROBER, "catchall", SIGNAL_CATCHALL_PROBE);
    let result = ingest(&pool, "catchall", &[own]).await;
    assert_eq!((result.probe_confirmations, result.rejected), (1, 0));
    assert_eq!(confirmed_sensors(&pool).await, ["catchall"]);
    let result = ingest(&pool, "ssh", &[forged]).await;
    assert_eq!((result.probe_confirmations, result.rejected), (1, 0));
    assert_untouched(&pool, PROBER).await;
}

/// One summary line stands for as many events as it says (scoring credits its
/// `suppressed_count`), so a thousand in one line takes an address past the volume threshold
/// on its own. Only the sensor-cred sensors sit behind the budget that folds events into
/// summaries; from any other log the line is refused.
#[sqlx::test(migrations = false)]
async fn a_forged_event_summary_in_the_ssh_log_is_refused(pool: PgPool) {
    migrate(&pool).await;
    let summary = |ip: &str, sensor: &str| {
        let mut event = SensorEvent {
            authenticated: true,
            ..line(ip, sensor, SIGNAL_HONEYPOT_LOGIN_ATTEMPT)
        };
        event.metadata["event_summary"] = true.into();
        event.metadata["suppressed_count"] = 1000.into();
        event
    };

    let result = ingest(&pool, "ssh", &[summary(VICTIM, "ssh")]).await;
    assert_eq!((result.ingested, result.rejected), (0, 1));
    assert_untouched(&pool, VICTIM).await;

    // Without the marker the same line is an ordinary ssh login, counted once.
    let mut plain = summary(VICTIM, "ssh");
    plain.metadata["event_summary"] = false.into();
    let result = ingest(&pool, "ssh", &[plain]).await;
    assert_eq!((result.ingested, result.rejected), (1, 0));
    let score = read_score(&pool, VICTIM.parse().unwrap())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(score.established_event_count, 1);
    assert!(!score.recommended_for_blocklist);

    // A sensor-cred log may summarize, and its summary counts for what it folded.
    let result = ingest(&pool, "cred-vnc", &[summary(ATTACKER, "vnc")]).await;
    assert_eq!((result.ingested, result.rejected), (1, 0));
    let score = read_score(&pool, ATTACKER.parse().unwrap())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(score.established_event_count, 1000);
}

/// A line of a sensor's own kind passes the origin policy whatever else it carries, and two
/// things it could carry used to break ledger chain verification for good: a timestamp with
/// second 60, which PostgreSQL stores as the next minute while the hash was taken over the
/// `:60` form, and a floating-point number in metadata that JSONB does not hand back as
/// written (a negative zero, a fraction, an exponent). Verification stops at the first row that
/// fails, so one such line also hid any later tampering. Driven from raw text, because that is
/// what a compromised sensor controls. A whole-number float, the form real summaries carry
/// (`"window_secs": 600.0`), is ingested like any other line.
#[sqlx::test(migrations = false)]
async fn a_leap_second_is_ingested_and_an_unstable_number_is_refused_and_the_chain_stays_intact(
    pool: PgPool,
) {
    migrate(&pool).await;
    let dir = tempfile::tempdir().unwrap();
    let log = dir.path().join("events.jsonl");
    let raw = |ip: &str, observed_at: &str, metadata: &str| {
        format!(
            r#"{{"v":1,"source_ip":"{ip}","wan_ip":null,"sensor":"catchall","signal_type":"catchall_probe","protocol":"tcp","authenticated":false,"observed_at":"{observed_at}","metadata":{metadata},"sample":null}}"#
        )
    };
    let now = Utc::now().to_rfc3339();
    let lines = [
        raw(ATTACKER, &now, r#"{"payload_len":0}"#),
        // 2016-12-31T23:59:60Z was a real leap second.
        raw(
            "203.0.113.81",
            "2016-12-31T23:59:60Z",
            r#"{"payload_len":0}"#,
        ),
        raw(VICTIM, &now, r#"{"payload_len":-0.0}"#),
        raw("203.0.113.82", &now, r#"{"payload_len":0,"ratio":0.5}"#),
        raw("203.0.113.83", &now, r#"{"nested":[{"n":1e16}]}"#),
        raw(
            "203.0.113.84",
            &now,
            r#"{"payload_len":18446744073709551615}"#,
        ),
        raw(
            "203.0.113.85",
            &now,
            r#"{"payload_len":0,"window_secs":600.0}"#,
        ),
    ];
    std::fs::write(&log, lines.join("\n") + "\n").unwrap();

    let result = runner(&pool, dir.path(), "catchall").run_batch().await;
    assert_eq!(
        (result.ingested, result.rejected, result.errors),
        (4, 3, 0),
        "the honest line, the leap second, the largest integer and the whole-number float are \
         ingested; the negative zero, the fraction and the exponent are rejected like any other \
         line that fails validation"
    );
    for ip in [VICTIM, "203.0.113.82", "203.0.113.83"] {
        assert_untouched(&pool, ip).await;
    }
    let stored: DateTime<Utc> =
        sqlx::query_scalar("SELECT observed_at FROM event WHERE source_ip = '203.0.113.81'::inet")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(stored.to_rfc3339(), "2017-01-01T00:00:00+00:00");
    assert_eq!(
        core_scoring::verify_chain(&pool).await.unwrap(),
        core_scoring::ChainStatus::Intact
    );
}
