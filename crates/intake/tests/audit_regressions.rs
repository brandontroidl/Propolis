// Regression cover for the 2026-09-17 audit finding "intake can permanently skip events after a
// temporary database failure".
//
// Like `end_to_end.rs`, these require a running PostgreSQL instance and share ONE database across
// the test binary, so the suite must run with `--test-threads=1` and every test uses its own
// source IP.
//
// The database failure is injected with a BEFORE INSERT trigger on `event` that raises. The
// trigger is installed and dropped inside the test; a panic between the two would leave it behind
// and fail every later insert in the shared database, so the drop runs through a guard rather
// than an assertion-ordered statement.

use std::collections::HashSet;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use chrono::Utc;
use intake::runner::IntakeRunner;
use log_tailer::LogTailer;
use sensor_wire::*;
use sqlx::PgPool;

const PROBE_GRACE: Duration = Duration::from_secs(600);

async fn setup_pool() -> PgPool {
    let url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://propolis:propolis@localhost:5432/propolis_test".into());
    let pool = PgPool::connect(&url).await.unwrap();
    sqlx::migrate!("../core-scoring/migrations")
        .run(&pool)
        .await
        .unwrap();
    pool
}

fn event(source_ip: &str) -> SensorEvent {
    SensorEvent {
        v: WIRE_VERSION,
        source_ip: source_ip.parse().unwrap(),
        wan_ip: None,
        sensor: "ssh".into(),
        signal_type: SIGNAL_HONEYPOT_LOGIN_ATTEMPT.into(),
        protocol: PROTO_TCP.into(),
        authenticated: true,
        observed_at: Utc::now(),
        metadata: serde_json::json!({ "protocol_label": "ssh" }),
        sample: None,
        session_id: None,
        occurrence_id: None,
    }
}

/// Installs the raising trigger for as long as it is held, and removes it on drop so a failing
/// assertion cannot poison the shared database for the rest of the binary.
struct FailingInserts(PgPool);

impl FailingInserts {
    async fn install(pool: &PgPool) -> Self {
        sqlx::query(
            "CREATE OR REPLACE FUNCTION audit_fail() RETURNS trigger LANGUAGE plpgsql AS \
             $$ BEGIN RAISE EXCEPTION 'audit transient failure'; END $$",
        )
        .execute(pool)
        .await
        .unwrap();
        sqlx::query(
            "CREATE TRIGGER audit_fail BEFORE INSERT ON event \
             FOR EACH ROW EXECUTE FUNCTION audit_fail()",
        )
        .execute(pool)
        .await
        .unwrap();
        Self(pool.clone())
    }

    async fn remove(self) {
        drop_trigger(&self.0).await;
        std::mem::forget(self);
    }
}

impl Drop for FailingInserts {
    fn drop(&mut self) {
        let pool = self.0.clone();
        // Only reached on the panic path; the happy path goes through `remove`.
        std::thread::spawn(move || {
            tokio::runtime::Runtime::new()
                .unwrap()
                .block_on(async move { drop_trigger(&pool).await });
        })
        .join()
        .ok();
    }
}

async fn drop_trigger(pool: &PgPool) {
    let _ = sqlx::query("DROP TRIGGER IF EXISTS audit_fail ON event")
        .execute(pool)
        .await;
}

/// A transient database error must not cost the event, and recovery must not require a restart.
///
/// The failure mode this locks: `read_batch` advances the tailer's in-memory offset over the whole
/// batch, so a runner that merely declines to persist on error still starts the NEXT poll past the
/// failed line. That poll reads nothing, reports `errors == 0`, and persists the advanced cursor -
/// permanently skipping an event the ledger never received, with no crash and no restart involved.
#[tokio::test]
async fn database_error_is_retried_without_a_process_restart() {
    let pool = setup_pool().await;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("events.jsonl");
    let cursor_dir = dir.path().join("cursor");
    let source_ip = "203.0.113.55";

    std::fs::write(
        &path,
        format!("{}\n", serde_json::to_string(&event(source_ip)).unwrap()),
    )
    .unwrap();

    let mut runner = IntakeRunner::new(
        LogTailer::new(path.clone(), cursor_dir.clone()),
        pool.clone(),
        "ssh".into(),
        Arc::new(HashSet::<IpAddr>::new()),
        PROBE_GRACE,
    );

    let before: i64 = sqlx::query_scalar("SELECT count(*) FROM event WHERE source_ip = $1::inet")
        .bind(source_ip)
        .fetch_one(&pool)
        .await
        .unwrap();

    let failing = FailingInserts::install(&pool).await;
    let failed = runner.run_batch().await;
    failing.remove().await;
    assert_eq!(failed.errors, 1, "the injected failure should surface");
    assert_eq!(failed.ingested, 0);

    // The same long-running runner polls again. This is the poll that used to start past the
    // failed line and return an empty, error-free batch.
    let recovered = runner.run_batch().await;
    assert_eq!(
        recovered.ingested, 1,
        "the failed line must be offered again to the same runner"
    );
    assert_eq!(recovered.errors, 0);
    runner.persist_cursor().unwrap();

    // A restart must not replay it a second time now that it is durably committed.
    let mut restarted = IntakeRunner::new(
        LogTailer::new(path, cursor_dir),
        pool.clone(),
        "ssh".into(),
        Arc::new(HashSet::<IpAddr>::new()),
        PROBE_GRACE,
    );
    let after_restart = restarted.run_batch().await;
    assert_eq!(after_restart.ingested, 0, "the cursor should be past it");

    let after: i64 = sqlx::query_scalar("SELECT count(*) FROM event WHERE source_ip = $1::inet")
        .bind(source_ip)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(
        after - before,
        1,
        "exactly one ledger event: a transient failure must cost neither the event nor a duplicate"
    );
}
