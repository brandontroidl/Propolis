//! One record, produced by a real sensor, carried all the way to the page an operator reads.
//!
//! The sensor suites assert what a capture writes; the console suite asserts what a hand-written
//! metadata object renders as. Neither covers the join between them: the key names. A sensor that
//! renamed `complete`, or a console query that read a key nobody writes, would leave both suites
//! green and the panel wrong - and the panel silently reporting a fragment as a whole sample is
//! exactly the failure this pipeline exists to avoid.
//!
//! So this drives a real telnet session that streams a binary payload and then stalls, and reads
//! the status out of the rendered HTML: sensor -> events.jsonl -> log-tailer -> intake -> ledger
//! -> console.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use sensor_framework::{ConnectionBounds, WanResolver};
use sqlx::PgPool;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_util::sync::CancellationToken;

async fn migrate(pool: &PgPool) {
    sqlx::migrate!("../core-scoring/migrations")
        .run(pool)
        .await
        .unwrap();
    review::migrator().run(pool).await.unwrap();
    fleet::migrator().run(pool).await.unwrap();
}

async fn free_port() -> u16 {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    listener.local_addr().unwrap().port()
}

/// Read until `needle` appears, so the login exchange does not depend on how the negotiation and
/// prompt bytes happen to be split across TCP segments.
async fn read_until(stream: &mut TcpStream, needle: &[u8]) {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 1024];
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let n = stream.read(&mut chunk).await.expect("read failed");
            assert!(n > 0, "connection closed before {needle:?}");
            buf.extend_from_slice(&chunk[..n]);
            if buf.windows(needle.len()).any(|w| w == needle) {
                return;
            }
        }
    })
    .await
    .unwrap_or_else(|_| panic!("timed out waiting for {needle:?}"));
}

/// The malware panel's own markup, so an assertion cannot be satisfied by a word appearing in the
/// page's stylesheet or bundled script.
fn malware_panel(body: &str) -> &str {
    let start = body
        .find("Malware from this IP")
        .expect("the malware panel must render");
    let panel = &body[start..];
    &panel[..panel.find("</table>").unwrap_or(panel.len())]
}

#[sqlx::test(migrations = false)]
async fn a_stalled_capture_reaches_the_console_reading_as_incomplete(pool: PgPool) {
    migrate(&pool).await;

    let dir = tempfile::tempdir().unwrap();
    let sensor_log = dir.path().join("events.jsonl");
    std::fs::write(&sensor_log, "").unwrap();
    let cancel = CancellationToken::new();

    // ---- the sensor, with an idle timeout short enough to cut the transfer short ----
    let (sensor_addr, sensor_handle) = sensor_telnet::start_test_server(
        "127.0.0.1:0".parse().unwrap(),
        sensor_log.clone(),
        dir.path().join("spool"),
        Arc::new(WanResolver::new(HashMap::new())),
        ConnectionBounds {
            read_timeout: Duration::from_secs(5),
            idle_timeout: Duration::from_millis(600),
            max_duration: Duration::from_secs(30),
            max_captured_bytes: 1_000_000,
            max_concurrent: 16,
        },
        "test".to_string(),
        dir.path().join("outbox"),
    )
    .await
    .unwrap();

    // ---- the console, on the same database intake writes to ----
    let port = free_port().await;
    let bind_addr: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
    let sessions = Arc::new(console::auth::SessionStore::new([42u8; 32]));
    let (_, cookie) = sessions.create();
    let console_cancel = cancel.child_token();
    let console_pool = pool.clone();
    let console_sessions = sessions.clone();
    let feed_dir = tempfile::tempdir().unwrap();
    let console_handle = tokio::spawn(async move {
        let state = console::AppState {
            db: console_pool,
            sessions: console_sessions,
            passwords: Arc::new(console::auth::PasswordStore::new("test-password")),
            login_rate_limiter: Arc::new(console::auth::RateLimiter::default()),
            templates: Arc::new(console::templates::environment()),
            geoip: Arc::new(geoip::GeoIp::disabled()),
            rdns: Arc::new(console::rdns::RdnsResolver::disabled()),
            feed_output_dir: Some(feed_dir.path().to_path_buf()),
            fleet_listeners: Arc::new(Vec::new()),
            fleet_probe_interval: std::time::Duration::from_secs(300),
            deploy_stamp_path: None,
            startup_time: chrono::Utc::now(),
            version: "test",
            log_buffer: Arc::new(console::log_buffer::LogBuffer::new(1000)),
            events_ingested: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            events_rejected: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            trusted_proxy: false,
            metrics_token: None,
            gave_up_subsystems: console::no_subsystem_health(),
        };
        let listener = tokio::net::TcpListener::bind(bind_addr).await.unwrap();
        let app =
            console::routes::router(state).into_make_service_with_connect_info::<SocketAddr>();
        axum::serve(listener, app)
            .with_graceful_shutdown(console_cancel.cancelled_owned())
            .await
            .unwrap();
    });

    // ---- the tailer and intake, exactly as the daemon runs them ----
    let intake_cancel = cancel.child_token();
    let intake_pool = pool.clone();
    let cursor_dir = dir.path().join("cursor");
    let tailed_log = sensor_log.clone();
    let intake_handle = tokio::spawn(async move {
        let tailer = log_tailer::LogTailer::new(tailed_log, cursor_dir);
        let mut runner = intake::runner::IntakeRunner::new(
            tailer,
            intake_pool,
            "test-sensor".to_string(),
            // No probe configured in this test: nothing is filtered, which is the
            // shape a node without the reachability sweep runs in.
            std::sync::Arc::new(std::collections::HashSet::new()),
            std::time::Duration::from_secs(600),
        );
        loop {
            if intake_cancel.is_cancelled() {
                let _ = runner.persist_cursor();
                return;
            }
            let _ = runner.run_batch().await;
            let _ = runner.persist_cursor();
            tokio::select! {
                _ = tokio::time::sleep(Duration::from_millis(200)) => {}
                _ = intake_cancel.cancelled() => return,
            }
        }
    });

    // ---- a dropper that streams a payload and then stops, with no newline and no logout ----
    let mut conn = TcpStream::connect(sensor_addr).await.unwrap();
    read_until(&mut conn, b"login: ").await;
    conn.write_all(b"root\r\n").await.unwrap();
    read_until(&mut conn, b"Password: ").await;
    conn.write_all(b"pass\r\n").await.unwrap();
    read_until(&mut conn, b"# ").await;
    conn.write_all(&vec![0xAAu8; 256]).await.unwrap();

    // ---- what the operator sees ----
    let client = reqwest::Client::new();
    let url = format!("http://127.0.0.1:{port}/ip/127.0.0.1");
    let deadline = tokio::time::Instant::now() + Duration::from_secs(25);
    let body = loop {
        if let Ok(resp) = client
            .get(&url)
            .header(
                "Cookie",
                format!("{}={cookie}", console::auth::SESSION_COOKIE),
            )
            .send()
            .await
            && resp.status() == 200
        {
            let page = resp.text().await.unwrap();
            // Wait for the panel to stop saying it has nothing. Waiting on the presence of table
            // markup instead would be satisfied before the capture ever arrives: the page
            // carries other tables, and an empty panel has no `</table>` to bound the slice.
            if page.contains("Malware from this IP")
                && !malware_panel(&page).contains("no samples linked")
            {
                break page;
            }
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "the capture never reached the console page"
        );
        tokio::time::sleep(Duration::from_millis(200)).await;
    };

    let panel = malware_panel(&body);
    assert!(
        panel.contains("incomplete"),
        "a capture the sensor recorded as cut short must not read as a whole sample: {panel}"
    );

    cancel.cancel();
    sensor_handle.abort();
    drop(conn);
    let _ = tokio::time::timeout(Duration::from_secs(5), console_handle).await;
    let _ = tokio::time::timeout(Duration::from_secs(5), intake_handle).await;
}
