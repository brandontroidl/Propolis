//! The runner's batching end to end: file, tailer, adaptive batch size, one transaction per batch.

use std::collections::HashSet;
use std::io::Write;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use core_scoring::{ChainStatus, verify_chain};
use intake::runner::{IntakeRunner, MIN_BATCH_LINES};
use log_tailer::LogTailer;
use sensor_wire::*;
use sqlx::PgPool;

const PROBE_GRACE: Duration = Duration::from_secs(600);

fn line(n: usize, signal: &str, metadata: serde_json::Value) -> String {
    let event = SensorEvent {
        v: WIRE_VERSION,
        source_ip: format!("192.0.2.{}", 10 + n % 3).parse().unwrap(),
        wan_ip: Some("198.51.100.4".parse().unwrap()),
        sensor: "telnet".into(),
        signal_type: signal.into(),
        protocol: PROTO_TCP.into(),
        authenticated: true,
        observed_at: "2026-09-01T00:00:00Z"
            .parse::<chrono::DateTime<chrono::Utc>>()
            .unwrap()
            + chrono::Duration::seconds(n as i64 * 7),
        metadata,
        sample: None,
        session_id: None,
        occurrence_id: None,
    };
    serde_json::to_string(&event).unwrap()
}

fn runner(pool: &PgPool, dir: &std::path::Path) -> IntakeRunner {
    IntakeRunner::new(
        LogTailer::new(dir.join("events.jsonl"), dir.join("cursors")),
        pool.clone(),
        "telnet".into(),
        Arc::new(HashSet::<IpAddr>::new()),
        PROBE_GRACE,
    )
}

fn write_lines(dir: &std::path::Path, lines: &[String]) {
    let mut file = std::fs::File::create(dir.join("events.jsonl")).unwrap();
    for l in lines {
        writeln!(file, "{l}").unwrap();
    }
}

async fn migrate(pool: &PgPool) {
    sqlx::migrate!("../core-scoring/migrations")
        .run(pool)
        .await
        .unwrap();
}

async fn ledger_rows(pool: &PgPool) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM event")
        .fetch_one(pool)
        .await
        .unwrap()
}

/// 451 lines (scored, telemetry and one junk line) drain in batches of 100, 200 and the 151 left,
/// each one transaction: nothing is lost or duplicated, the junk line is rejected once, and the
/// chain verifies.
#[sqlx::test(migrations = false)]
async fn a_backlog_drains_in_growing_batches_and_the_chain_verifies(pool: PgPool) {
    migrate(&pool).await;
    let dir = tempfile::tempdir().unwrap();
    let mut lines = Vec::new();
    for n in 0..450 {
        let signal = match n % 5 {
            0 => SIGNAL_HONEYPOT_SESSION_END,
            1 | 2 => SIGNAL_HONEYPOT_COMMAND_EXEC,
            3 => SIGNAL_HONEYPOT_LOGIN_ATTEMPT,
            _ => SIGNAL_HONEYPOT_CONNECTION,
        };
        lines.push(line(n, signal, serde_json::json!({ "n": n })));
        if n == 9 {
            lines.push("{ not json".into());
        }
    }
    write_lines(dir.path(), &lines);

    let mut runner = runner(&pool, dir.path());
    let mut outcomes = Vec::new();
    loop {
        let r = runner.run_batch().await;
        assert_eq!(r.errors, 0);
        if r.ingested == 0 && r.rejected == 0 {
            break;
        }
        outcomes.push((r.ingested, r.rejected));
    }
    assert_eq!(
        outcomes,
        [(99, 1), (200, 0), (151, 0)],
        "first batch reads {MIN_BATCH_LINES} lines, then 200, then what is left"
    );
    assert_eq!(ledger_rows(&pool).await, 450);
    assert_eq!(verify_chain(&pool).await.unwrap(), ChainStatus::Intact);
}

/// A line the database refuses (a NUL in metadata, which `jsonb` cannot hold) stops the batch at
/// that line. The lines before it are committed, the failed batch is rewound so the next poll
/// reads it again from the start, and `rejected` counts only lines up to the failure. This is the
/// one-at-a-time contract, unchanged: at-least-once, replayed lines absorbed by dedup.
#[sqlx::test(migrations = false)]
async fn a_line_the_database_refuses_stops_the_batch_and_it_is_read_again(pool: PgPool) {
    migrate(&pool).await;
    let dir = tempfile::tempdir().unwrap();
    let mut lines: Vec<String> = (0..20)
        .map(|n| {
            line(
                n,
                SIGNAL_HONEYPOT_COMMAND_EXEC,
                serde_json::json!({ "n": n }),
            )
        })
        .collect();
    lines[12] = line(
        12,
        SIGNAL_HONEYPOT_COMMAND_EXEC,
        serde_json::json!({ "command": "echo \u{0}" }),
    );
    lines.push("{ not json".into());
    write_lines(dir.path(), &lines);

    let mut runner = runner(&pool, dir.path());
    let first = runner.run_batch().await;
    assert_eq!((first.ingested, first.errors, first.rejected), (12, 1, 0));
    assert_eq!(
        ledger_rows(&pool).await,
        12,
        "the lines before the bad one are durable"
    );

    let second = runner.run_batch().await;
    assert_eq!(
        (second.ingested, second.errors),
        (12, 1),
        "the whole batch is offered again; nothing was skipped"
    );
    assert_eq!(verify_chain(&pool).await.unwrap(), ChainStatus::Intact);
}
