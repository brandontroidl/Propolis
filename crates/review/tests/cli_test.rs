//! Real-Postgres integration tests for the `review` binary (Task 5): every
//! operator subcommand invoked as a real subprocess via
//! `env!("CARGO_BIN_EXE_review")`, plus a daemon smoke test. This is the
//! "tested via the binary with `--help` and integration tests" coverage the
//! task brief calls for - `cli.rs`'s own unit tests (in `src/cli.rs`) already
//! cover argument parsing; this file proves the compiled binary's actual
//! wiring end to end: env config -> `PgPool::connect` -> `cli::execute`/
//! `run_daemon` -> real database rows.
//!
//! Each test owns a fresh database (`#[sqlx::test]`); the subprocess is pointed at it by
//! `database_url`, which swaps the test database's name into the caller's `DATABASE_URL` so
//! the credentials and host carry over. The `daemon` test in particular populates from the whole
//! `ip_score` table, so a shared database would let other tests' rows reach it.
//!
//! The subprocess inherits the test process's environment plus whatever this file explicitly
//! overrides via `Command::env`. No vendor API key is ever set, so every vendor stays disabled
//! (`load_vendor_config`'s fail-closed default) - the daemon smoke test below never attempts a
//! real outbound HTTP call.

use std::process::Command;
use std::time::{Duration, Instant};

use core_scoring::{EventInput, Protocol, SignalType, append_event};
use sqlx::{PgPool, Row};

use review::queue::ReviewQueue;

/// The connection string for the subprocess: the caller's `DATABASE_URL` with `pool`'s own
/// database substituted.
fn database_url(pool: &PgPool) -> String {
    let base = std::env::var("DATABASE_URL").expect("DATABASE_URL must be set for DB tests");
    let mut url = url::Url::parse(&base).unwrap();
    let database = pool.connect_options().get_database().unwrap().to_string();
    url.set_path(&database);
    url.to_string()
}

async fn migrate(pool: &PgPool) {
    sqlx::migrate!("../core-scoring/migrations")
        .run(pool)
        .await
        .unwrap();
    review::migrator().run(pool).await.unwrap();
}

/// Builds an `EventInput` via the public `from_signal` constructor, matching
/// every other test file in this crate.
fn ev(
    ip: &str,
    sensor: &str,
    signal: SignalType,
    protocol: Protocol,
    authenticated: bool,
) -> EventInput {
    EventInput::from_signal(
        ip.parse().unwrap(),
        None,
        sensor.into(),
        signal,
        protocol,
        authenticated,
        "2026-07-17T00:00:00Z".parse().unwrap(),
        serde_json::json!({}),
        None,
    )
}

/// Seeds an eligible + vendor-recommended `ip_score` projection for `ip` -
/// identical shape to `queue_test.rs`'s `seed_recommended`: one confirmed-real
/// honeypot login plus two corroborating categories, clearing every
/// eligibility/recommendation floor.
async fn seed_recommended(pool: &PgPool, ip: &str) {
    append_event(
        pool,
        ev(
            ip,
            "honeypot-sensor",
            SignalType::HoneypotLoginAttempt,
            Protocol::Tcp,
            true,
        ),
    )
    .await
    .unwrap();
    append_event(
        pool,
        ev(
            ip,
            "ssh-sensor",
            SignalType::SshBruteForce,
            Protocol::Tcp,
            true,
        ),
    )
    .await
    .unwrap();
    append_event(
        pool,
        ev(
            ip,
            "catchall-sensor",
            SignalType::CatchallProbe,
            Protocol::Udp,
            false,
        ),
    )
    .await
    .unwrap();
}

async fn queue_state(pool: &PgPool, ip: &str) -> Option<String> {
    sqlx::query("SELECT state::text FROM review_queue WHERE source_ip = $1::inet")
        .bind(ip)
        .fetch_optional(pool)
        .await
        .unwrap()
        .map(|row| row.get::<String, _>("state"))
}

fn review_bin() -> &'static str {
    env!("CARGO_BIN_EXE_review")
}

/// `--help` never touches `DATABASE_URL`/PostgreSQL at all: clap's derived
/// `Parser::parse()` intercepts `--help` and exits before `main`'s own config
/// loading ever runs. This is the one test in this file that needs no
/// database setup.
#[test]
fn help_exits_zero_and_lists_every_subcommand() {
    let output = Command::new(review_bin()).arg("--help").output().unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    for sub in ["daemon", "approve", "reject", "snooze", "list", "history"] {
        assert!(
            stdout.contains(sub),
            "--help output must list the {sub} subcommand:\n{stdout}"
        );
    }
}

/// No subcommand at all is a usage error (clap requires one, per
/// `cli.rs`'s `cli_rejects_missing_subcommand` unit test) - confirms that
/// contract holds through the real compiled binary, not just the parser
/// in isolation.
#[test]
fn no_subcommand_exits_nonzero() {
    let output = Command::new(review_bin()).output().unwrap();
    assert!(!output.status.success());
}

#[sqlx::test(migrations = false)]
async fn list_shows_seeded_pending_entry(pool: PgPool) {
    migrate(&pool).await;
    let test_ip = "203.0.113.248";
    seed_recommended(&pool, test_ip).await;
    ReviewQueue::new().populate(&pool).await.unwrap();

    let output = Command::new(review_bin())
        .arg("list")
        .env("DATABASE_URL", database_url(&pool))
        .output()
        .unwrap();
    assert!(output.status.success(), "{:?}", output);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains(test_ip),
        "list output must show the seeded pending IP:\n{stdout}"
    );
}

#[sqlx::test(migrations = false)]
async fn approve_transitions_state_and_records_notes(pool: PgPool) {
    migrate(&pool).await;
    let test_ip = "203.0.113.249";
    seed_recommended(&pool, test_ip).await;
    ReviewQueue::new().populate(&pool).await.unwrap();

    let output = Command::new(review_bin())
        .args(["approve", test_ip, "--notes", "confirmed malicious scan"])
        .env("DATABASE_URL", database_url(&pool))
        .output()
        .unwrap();
    assert!(output.status.success(), "{:?}", output);
    assert_eq!(
        queue_state(&pool, test_ip).await.as_deref(),
        Some("approved")
    );

    let notes: Option<String> =
        sqlx::query("SELECT notes FROM review_queue WHERE source_ip = $1::inet")
            .bind(test_ip)
            .fetch_one(&pool)
            .await
            .unwrap()
            .get("notes");
    assert_eq!(notes.as_deref(), Some("confirmed malicious scan"));
}

#[sqlx::test(migrations = false)]
async fn reject_transitions_state(pool: PgPool) {
    migrate(&pool).await;
    let test_ip = "203.0.113.250";
    seed_recommended(&pool, test_ip).await;
    ReviewQueue::new().populate(&pool).await.unwrap();

    let output = Command::new(review_bin())
        .args(["reject", test_ip])
        .env("DATABASE_URL", database_url(&pool))
        .output()
        .unwrap();
    assert!(output.status.success(), "{:?}", output);
    assert_eq!(
        queue_state(&pool, test_ip).await.as_deref(),
        Some("rejected")
    );
}

#[sqlx::test(migrations = false)]
async fn snooze_transitions_state(pool: PgPool) {
    migrate(&pool).await;
    let test_ip = "203.0.113.251";
    seed_recommended(&pool, test_ip).await;
    ReviewQueue::new().populate(&pool).await.unwrap();

    let output = Command::new(review_bin())
        .args(["snooze", test_ip])
        .env("DATABASE_URL", database_url(&pool))
        .output()
        .unwrap();
    assert!(output.status.success(), "{:?}", output);
    assert_eq!(
        queue_state(&pool, test_ip).await.as_deref(),
        Some("snoozed")
    );
}

/// The human-approval gate depends on every decision landing on a real,
/// surfaced entry (`ReviewError::NotFound`'s own doc comment) - acting on an
/// IP with no queue row must fail loudly, not silently no-op. Confirms
/// `main.rs` surfaces that as a nonzero exit plus a stderr message, not a
/// panic or a silent success.
#[sqlx::test(migrations = false)]
async fn approve_nonexistent_ip_fails_loudly(pool: PgPool) {
    migrate(&pool).await;
    let test_ip = "203.0.113.252";
    assert!(queue_state(&pool, test_ip).await.is_none());

    let output = Command::new(review_bin())
        .args(["approve", test_ip])
        .env("DATABASE_URL", database_url(&pool))
        .output()
        .unwrap();
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains(test_ip),
        "stderr must name the IP that had no queue entry:\n{stderr}"
    );
}

#[sqlx::test(migrations = false)]
async fn history_shows_submission_row(pool: PgPool) {
    migrate(&pool).await;
    let test_ip = "203.0.113.253";

    sqlx::query(
        "INSERT INTO vendor_submission \
         (source_ip, vendor, idempotency_key, categories, comment, response_status, success) \
         VALUES ($1::inet, 'abuseipdb', $2, ARRAY['22'], 'test submission', 200, TRUE)",
    )
    .bind(test_ip)
    .bind(format!("{test_ip}:abuseipdb:2026-07-17"))
    .execute(&pool)
    .await
    .unwrap();

    let output = Command::new(review_bin())
        .args(["history", test_ip])
        .env("DATABASE_URL", database_url(&pool))
        .output()
        .unwrap();
    assert!(output.status.success(), "{:?}", output);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("abuseipdb"),
        "history must show the vendor:\n{stdout}"
    );
    assert!(
        stdout.contains("200"),
        "history must show the response status:\n{stdout}"
    );
}

#[sqlx::test(migrations = false)]
async fn history_reports_no_history_for_unsubmitted_ip(pool: PgPool) {
    migrate(&pool).await;
    let test_ip = "203.0.113.254";

    let output = Command::new(review_bin())
        .args(["history", test_ip])
        .env("DATABASE_URL", database_url(&pool))
        .output()
        .unwrap();
    assert!(output.status.success(), "{:?}", output);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("no submission history"));
}

/// End-to-end smoke test for `review daemon`: a real subprocess, a real
/// `PgPool::connect`, and a real `ReviewQueue::populate` pass reaching a
/// seeded IP - the one path no other test in this crate exercises through
/// the actual binary (`queue_test.rs` calls `ReviewQueue::populate` directly
/// as a library, never through `main.rs`'s config loading + daemon loop
/// wiring). All three vendors stay disabled (no API key env vars set), so
/// `run_submission_loop` never attempts a real outbound HTTP call - this
/// test only proves the queue-scan side of the daemon loop.
///
/// Polls for up to 5s rather than a single fixed sleep, to stay robust
/// against a loaded test machine: `PROPOLIS_QUEUE_SCAN_INTERVAL_SECS=1` means
/// the first populate pass should land well within that window.
#[sqlx::test(migrations = false)]
async fn daemon_populates_seeded_ip_into_pending_queue(pool: PgPool) {
    migrate(&pool).await;
    let test_ip = "203.0.113.255";
    seed_recommended(&pool, test_ip).await;
    assert!(queue_state(&pool, test_ip).await.is_none());

    let mut child = Command::new(review_bin())
        .arg("daemon")
        .env("DATABASE_URL", database_url(&pool))
        .env("PROPOLIS_QUEUE_SCAN_INTERVAL_SECS", "1")
        .env("PROPOLIS_SUBMIT_POLL_INTERVAL_SECS", "1")
        .spawn()
        .unwrap();

    let deadline = Instant::now() + Duration::from_secs(5);
    let mut seen = false;
    while Instant::now() < deadline {
        if queue_state(&pool, test_ip).await.as_deref() == Some("pending") {
            seen = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }

    let _ = child.kill();
    let _ = child.wait();

    assert!(
        seen,
        "daemon must populate the seeded IP into review_queue within 5s"
    );
}
