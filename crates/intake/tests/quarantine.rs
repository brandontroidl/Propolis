//! Automatic quarantine of a line the database always refuses, end to end: real files, a real
//! tailer and cursor, a real database. The refused line is the one the batching tests use: a NUL
//! in metadata, which `jsonb` cannot hold (SQLSTATE 22P05).

use std::collections::HashSet;
use std::io::Write;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use intake::quarantine::Quarantine;
use intake::runner::{IntakeRunner, WEDGE_POLLS};
use log_tailer::LogTailer;
use sensor_wire::*;
use sqlx::PgPool;

const PROBE_GRACE: Duration = Duration::from_secs(600);
const POISON_AT: usize = 12;

fn event_line(n: usize, metadata: serde_json::Value) -> String {
    let event = SensorEvent {
        v: WIRE_VERSION,
        source_ip: format!("192.0.2.{}", 10 + n % 3).parse().unwrap(),
        wan_ip: Some("198.51.100.4".parse().unwrap()),
        sensor: "telnet".into(),
        signal_type: SIGNAL_HONEYPOT_COMMAND_EXEC.into(),
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
        reply: None,
    };
    serde_json::to_string(&event).unwrap()
}

/// `count` ordinary lines with a refused one at each index in `poison`.
fn lines(count: usize, poison: &[usize]) -> Vec<String> {
    (0..count)
        .map(|n| {
            let metadata = if poison.contains(&n) {
                serde_json::json!({ "command": "echo \u{0}" })
            } else {
                serde_json::json!({ "n": n })
            };
            event_line(n, metadata)
        })
        .collect()
}

fn write_lines(dir: &Path, lines: &[String]) {
    let mut file = std::fs::File::create(dir.join("events.jsonl")).unwrap();
    for l in lines {
        writeln!(file, "{l}").unwrap();
    }
}

fn runner_with(pool: &PgPool, dir: &Path, quarantine: Quarantine) -> IntakeRunner {
    IntakeRunner::new(
        LogTailer::new(dir.join("events.jsonl"), dir.join("cursors")),
        pool.clone(),
        "telnet".into(),
        Arc::new(HashSet::<IpAddr>::new()),
        PROBE_GRACE,
    )
    .with_quarantine(quarantine)
}

fn quarantine_dir(dir: &Path) -> PathBuf {
    dir.join("quarantine")
}

fn runner(pool: &PgPool, dir: &Path) -> IntakeRunner {
    runner_with(pool, dir, Quarantine::new(quarantine_dir(dir)))
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

fn records(dir: &Path) -> Vec<serde_json::Value> {
    match std::fs::read_to_string(quarantine_dir(dir).join("telnet.jsonl")) {
        Ok(text) => text
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect(),
        Err(_) => Vec::new(),
    }
}

/// Bytes the first `n` lines take in the file, newlines included.
fn offset_of(lines: &[String], n: usize) -> u64 {
    lines[..n].iter().map(|l| l.len() as u64 + 1).sum()
}

/// A line refused on three polls in a row is retried, then set aside and passed: the lines behind
/// it ingest, the quarantine file holds exactly that line with its offset and SQLSTATE, the cursor
/// was persisted past it, and a restart resumes after it without quarantining it again.
#[sqlx::test(migrations = false)]
async fn a_line_refused_three_polls_running_is_quarantined_and_intake_moves_on(pool: PgPool) {
    migrate(&pool).await;
    let dir = tempfile::tempdir().unwrap();
    let all = lines(20, &[POISON_AT]);
    write_lines(dir.path(), &all);

    let mut runner = runner(&pool, dir.path());
    let first = runner.run_batch().await;
    assert_eq!(
        (first.ingested, first.errors, first.quarantined),
        (12, 1, 0)
    );
    for poll in 2..WEDGE_POLLS {
        let again = runner.run_batch().await;
        assert_eq!(
            (again.ingested, again.errors, again.quarantined),
            (0, 1, 0),
            "poll {poll}: retried, not yet given up on"
        );
        assert!(
            records(dir.path()).is_empty(),
            "poll {poll}: nothing set aside yet"
        );
    }
    let third = runner.run_batch().await;
    assert_eq!(
        (third.ingested, third.errors, third.quarantined),
        (0, 1, 1),
        "the third refusal quarantines the line"
    );
    assert!(
        third.cursor_moved(),
        "the loop must persist after a quarantine"
    );
    assert!(runner.wedged().is_none(), "nothing is stuck any more");
    assert_eq!(runner.quarantined_total(), 1);
    assert_eq!(ledger_rows(&pool).await, 12);

    let found = records(dir.path());
    assert_eq!(found.len(), 1);
    let record = &found[0];
    assert_eq!(record["line"], all[POISON_AT].as_str());
    assert_eq!(record["line_encoding"], "utf8");
    assert_eq!(record["sensor"], "telnet");
    assert_eq!(record["sqlstate"], "22P05");
    assert_eq!(record["byte_offset"], offset_of(&all, POISON_AT));
    assert_eq!(
        record["line_sha256"],
        log_tailer::sha256_hex(all[POISON_AT].as_bytes())
    );
    assert!(record["error"].as_str().unwrap().len() <= 515);
    let notice = runner.last_quarantine().unwrap();
    assert_eq!(notice.byte_offset, offset_of(&all, POISON_AT));
    assert_eq!(notice.sqlstate.as_deref(), Some("22P05"));
    assert_eq!(notice.file, quarantine_dir(dir.path()).join("telnet.jsonl"));

    // The cursor was persisted by the quarantine itself: this runner is dropped without the loop
    // ever calling persist_cursor, and the restart starts behind the poisoned line, not at it.
    drop(runner);
    let mut restarted = self::runner(&pool, dir.path());
    let rest = restarted.run_batch().await;
    assert_eq!((rest.ingested, rest.errors, rest.quarantined), (7, 0, 0));
    assert_eq!(ledger_rows(&pool).await, 19);
    assert_eq!(
        records(dir.path()).len(),
        1,
        "not quarantined a second time"
    );
}

/// When the record cannot be written the line is NOT skipped: intake stays on it, the report says
/// why, and nothing behind it is ingested. Once the directory is usable the next poll quarantines
/// the line and the log drains, with no restart.
#[sqlx::test(migrations = false)]
async fn a_failed_quarantine_write_keeps_intake_on_the_line_and_says_why(pool: PgPool) {
    migrate(&pool).await;
    let dir = tempfile::tempdir().unwrap();
    write_lines(dir.path(), &lines(20, &[POISON_AT]));
    // A regular file where the directory should be: unwritable for any user, root included.
    std::fs::write(quarantine_dir(dir.path()), b"in the way").unwrap();

    let mut runner = runner(&pool, dir.path());
    for _ in 0..WEDGE_POLLS + 2 {
        let r = runner.run_batch().await;
        assert_eq!(r.quarantined, 0);
    }
    let why = runner.wedged().expect("still wedged");
    assert!(
        why.contains("NOT quarantined") && why.contains("quarantine write failed"),
        "the report carries the write error: {why}"
    );
    assert_eq!(runner.quarantined_total(), 0);
    assert_eq!(
        ledger_rows(&pool).await,
        12,
        "no line behind the wedge was skipped"
    );

    std::fs::remove_file(quarantine_dir(dir.path())).unwrap();
    let healed = runner.run_batch().await;
    assert_eq!(healed.quarantined, 1);
    assert!(runner.wedged().is_none());
    let rest = runner.run_batch().await;
    assert_eq!((rest.ingested, rest.errors), (7, 0));
    assert_eq!(ledger_rows(&pool).await, 19);
    assert_eq!(records(dir.path()).len(), 1);
}

/// At the cap nothing more is quarantined: the next refused line wedges intake and the report
/// names the cap, while the record that fit is intact.
#[sqlx::test(migrations = false)]
async fn the_cap_stops_quarantining_and_the_report_says_the_store_is_full(pool: PgPool) {
    migrate(&pool).await;
    let dir = tempfile::tempdir().unwrap();
    write_lines(dir.path(), &lines(20, &[5, 14]));
    let store = Quarantine::with_limits(quarantine_dir(dir.path()), u64::MAX, 1);
    let mut runner = runner_with(&pool, dir.path(), store);

    let mut quarantined = 0;
    for _ in 0..10 {
        quarantined += runner.run_batch().await.quarantined;
    }
    assert_eq!(quarantined, 1, "only the first refused line fit");
    let why = runner.wedged().expect("wedged on the second refused line");
    assert!(why.contains("quarantine is full"), "{why}");
    assert_eq!(records(dir.path()).len(), 1);
    assert_eq!(
        ledger_rows(&pool).await,
        14 - 1,
        "everything up to the second refused line went in, and nothing past it"
    );
}

/// A failure that is not about the line (the database is unreachable) never quarantines, however
/// many polls it lasts.
#[tokio::test]
async fn a_database_that_is_down_never_quarantines_anything() {
    let dir = tempfile::tempdir().unwrap();
    write_lines(dir.path(), &lines(5, &[]));
    let pool = sqlx::postgres::PgPoolOptions::new()
        .acquire_timeout(Duration::from_millis(200))
        .connect_lazy("postgres://nobody@127.0.0.1:1/none")
        .unwrap();
    let mut runner = runner_with(
        &pool,
        dir.path(),
        Quarantine::new(quarantine_dir(dir.path())),
    );
    for _ in 0..WEDGE_POLLS + 3 {
        let r = runner.run_batch().await;
        assert_eq!((r.ingested, r.errors, r.quarantined), (0, 1, 0));
    }
    assert!(
        runner.wedged().is_none(),
        "a connection error is not a wedge"
    );
    assert!(!quarantine_dir(dir.path()).exists(), "not even created");
}

/// A `copytruncate` that lands while the append is in flight (here: right after it returns, on the
/// poll that quarantines) must not make the runner step over a line of the NEW file. The record of
/// the refused line is kept, the batch is read again from the start of the new file, and every
/// line of it is ingested.
#[sqlx::test(migrations = false)]
async fn a_copytruncate_between_the_refusal_and_the_quarantine_skips_nothing(pool: PgPool) {
    migrate(&pool).await;
    let dir = tempfile::tempdir().unwrap();
    write_lines(dir.path(), &lines(20, &[POISON_AT]));

    let polls = Arc::new(AtomicUsize::new(0));
    let log = dir.path().join("events.jsonl");
    let fresh: Vec<String> = (100..110)
        .map(|n| event_line(n, serde_json::json!({ "new": n })))
        .collect();
    let mut runner = runner(&pool, dir.path());
    runner.set_after_append_hook({
        let polls = polls.clone();
        move || {
            if polls.fetch_add(1, Ordering::SeqCst) + 1 == WEDGE_POLLS as usize {
                // copytruncate: the same inode is emptied and refilled.
                std::fs::write(&log, "").unwrap();
                let mut file = std::fs::OpenOptions::new().append(true).open(&log).unwrap();
                for l in &fresh {
                    writeln!(file, "{l}").unwrap();
                }
            }
        }
    });

    for _ in 0..WEDGE_POLLS {
        let r = runner.run_batch().await;
        assert_eq!(
            r.quarantined, 0,
            "the log changed, so the position must not move"
        );
    }
    assert_eq!(
        records(dir.path()).len(),
        1,
        "the refused line is on record"
    );
    assert_eq!(ledger_rows(&pool).await, 12);

    let rest = runner.run_batch().await;
    assert_eq!(
        (rest.ingested, rest.errors),
        (10, 0),
        "all ten lines of the new file, none stepped over"
    );
    assert_eq!(ledger_rows(&pool).await, 22);
    assert!(runner.wedged().is_none());
}

fn unbase64(text: &str) -> Vec<u8> {
    let value = |c: u8| match c {
        b'A'..=b'Z' => c - b'A',
        b'a'..=b'z' => c - b'a' + 26,
        b'0'..=b'9' => c - b'0' + 52,
        b'+' => 62,
        b'/' => 63,
        _ => 0,
    };
    let bytes: Vec<u8> = text.bytes().filter(|&c| c != b'=').collect();
    let mut out = Vec::new();
    for chunk in bytes.chunks(4) {
        let n = chunk.iter().enumerate().fold(0u32, |acc, (i, &c)| {
            acc | u32::from(value(c)) << (18 - 6 * i)
        });
        for i in 0..chunk.len() - 1 {
            out.push((n >> (16 - 8 * i)) as u8);
        }
    }
    out
}

/// A refused line holding bytes that are not UTF-8 is kept exactly: the tailer hands the runner a
/// lossy string, and the record must still carry the file's own bytes.
#[sqlx::test(migrations = false)]
async fn a_refused_line_with_invalid_utf8_is_kept_byte_for_byte(pool: PgPool) {
    migrate(&pool).await;
    let dir = tempfile::tempdir().unwrap();
    let mut file = std::fs::File::create(dir.path().join("events.jsonl")).unwrap();
    let ordinary = lines(3, &[]);
    for l in &ordinary[..2] {
        writeln!(file, "{l}").unwrap();
    }
    let marked = event_line(2, serde_json::json!({ "command": "echo \u{0} @@" }));
    let mut raw = marked.clone().into_bytes();
    let at = marked.find("@@").unwrap();
    raw.splice(at..at + 2, [0xffu8, 0xfe]);
    file.write_all(&raw).unwrap();
    file.write_all(b"\n").unwrap();
    writeln!(file, "{}", ordinary[2]).unwrap();
    drop(file);

    let mut runner = runner(&pool, dir.path());
    for _ in 0..WEDGE_POLLS {
        runner.run_batch().await;
    }
    let found = records(dir.path());
    assert_eq!(found.len(), 1);
    assert_eq!(found[0]["line_encoding"], "base64");
    assert_eq!(unbase64(found[0]["line"].as_str().unwrap()), raw);
    assert_eq!(found[0]["line_sha256"], log_tailer::sha256_hex(&raw));
    assert_eq!(
        found[0]["byte_offset"],
        offset_of(&ordinary, 2),
        "offset counts the original bytes"
    );
    let rest = runner.run_batch().await;
    assert_eq!(rest.ingested, 1, "the line after it goes in");
}
