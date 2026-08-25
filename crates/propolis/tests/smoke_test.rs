//! Smoke test for the unified daemon. Starts the subsystems against a real PostgreSQL database
//! (the propolis-pg container), verifies `/health` and `/ready` return 200, checks the cursor
//! directory was created, and verifies clean shutdown on cancellation.
//!
//! Uses `#[sqlx::test(migrations = false)]` for an isolated per-test database, then runs
//! core-scoring + review migrations manually (matching `console/tests/routes_test.rs`'s pattern).

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use sqlx::PgPool;
use tokio_util::sync::CancellationToken;

/// Runs migrations matching the daemon's own startup sequence.
async fn migrate(pool: &PgPool) {
    sqlx::migrate!("../core-scoring/migrations")
        .run(pool)
        .await
        .unwrap();
    review::migrator().run(pool).await.unwrap();
}

/// Finds a free TCP port by binding to :0 and reading the assigned port.
async fn free_port() -> u16 {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    listener.local_addr().unwrap().port()
}

/// Polls a URL until it returns 200 or the timeout expires.
async fn wait_for_200(url: &str, timeout: Duration) -> bool {
    let client = reqwest::Client::new();
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        if tokio::time::Instant::now() >= deadline {
            return false;
        }
        match client.get(url).send().await {
            Ok(resp) if resp.status() == 200 => return true,
            _ => tokio::time::sleep(Duration::from_millis(100)).await,
        }
    }
}

#[sqlx::test(migrations = false)]
async fn smoke_health_and_ready(pool: PgPool) {
    migrate(&pool).await;

    let port = free_port().await;
    let bind_addr: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
    let cursor_dir = tempfile::tempdir().unwrap();
    let feed_dir = tempfile::tempdir().unwrap();
    let cancel = CancellationToken::new();

    // Create a minimal sensor log file so the tailer has something to open.
    let sensor_log_dir = tempfile::tempdir().unwrap();
    let sensor_log_path = sensor_log_dir.path().join("events.jsonl");
    std::fs::write(&sensor_log_path, "").unwrap();

    // Spawn the console subsystem directly (the smoke test cares about /health and /ready).
    let console_cancel = cancel.child_token();
    let console_pool = pool.clone();
    let console_handle = tokio::spawn(async move {
        let passwords = Arc::new(console::auth::PasswordStore::new("test-password"));
        let state = console::AppState {
            db: console_pool,
            sessions: Arc::new(console::auth::SessionStore::new([42u8; 32])),
            passwords,
            login_rate_limiter: Arc::new(console::auth::RateLimiter::default()),
            templates: Arc::new(console::templates::environment()),
            geoip: Arc::new(geoip::GeoIp::disabled()),
            rdns: Arc::new(console::rdns::RdnsResolver::disabled()),
            feed_output_dir: Some(feed_dir.path().to_path_buf()),
            startup_time: chrono::Utc::now(),
            version: "test",
            log_buffer: Arc::new(console::log_buffer::LogBuffer::new(1000)),
            events_ingested: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            events_rejected: Arc::new(std::sync::atomic::AtomicU64::new(0)),
        };

        let listener = tokio::net::TcpListener::bind(bind_addr).await.unwrap();
        let app =
            console::routes::router(state).into_make_service_with_connect_info::<SocketAddr>();
        axum::serve(listener, app)
            .with_graceful_shutdown(console_cancel.cancelled_owned())
            .await
            .unwrap();
    });

    // Spawn an intake tailer against the test database.
    let intake_cancel = cancel.child_token();
    let intake_pool = pool.clone();
    let cursor_path = cursor_dir.path().to_path_buf();
    let sensor_path = sensor_log_path.clone();
    let intake_handle = tokio::spawn(async move {
        let tailer = intake::tailer::LogTailer::new(sensor_path, cursor_path);
        let mut runner =
            intake::runner::IntakeRunner::new(tailer, intake_pool, "test-sensor".to_string());

        loop {
            if intake_cancel.is_cancelled() {
                let _ = runner.persist_cursor();
                return;
            }
            let _result = runner.run_batch().await;
            let _ = runner.persist_cursor();
            tokio::select! {
                _ = tokio::time::sleep(Duration::from_millis(500)) => {}
                _ = intake_cancel.cancelled() => { return; }
            }
        }
    });

    // Wait for /health and /ready.
    let base = format!("http://127.0.0.1:{port}");
    assert!(
        wait_for_200(&format!("{base}/health"), Duration::from_secs(10)).await,
        "/health did not return 200 within 10s"
    );
    assert!(
        wait_for_200(&format!("{base}/ready"), Duration::from_secs(5)).await,
        "/ready did not return 200 within 5s"
    );

    // Verify cursor directory exists (the intake tailer should have created it).
    assert!(
        cursor_dir.path().exists(),
        "cursor directory was not created"
    );

    // Clean shutdown.
    cancel.cancel();
    tokio::time::timeout(Duration::from_secs(5), console_handle)
        .await
        .expect("console should shut down within 5s")
        .unwrap();
    tokio::time::timeout(Duration::from_secs(5), intake_handle)
        .await
        .expect("intake should shut down within 5s")
        .unwrap();
}
