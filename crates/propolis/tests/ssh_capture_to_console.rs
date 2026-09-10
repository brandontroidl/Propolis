//! The SSH half of `capture_to_console`: one record, produced by the real SSH sensor, carried all
//! the way to the page an operator reads.
//!
//! `capture_to_console.rs` does this for telnet. The two sensors write their capture metadata from
//! different code, and the console reads it with one query, so a key the SSH side renamed would
//! leave the sensor suite and the console suite both green and only this join wrong. SSH now also
//! writes `end_reason`, which the panel captions the status with, so that key needs the same
//! cover in both directions.
//!
//! Two endings, because the interesting failure is not "nothing renders" but "a fragment renders
//! as a whole sample": an idle timeout must reach the page as incomplete AND say what cut it, and
//! a client DISCONNECT must still read as captured.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use sensor_framework::{ConnectionBounds, WanResolver};
use sqlx::PgPool;
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

/// The malware panel's own markup, so an assertion cannot be satisfied by a word appearing in the
/// page's stylesheet or bundled script.
fn malware_panel(body: &str) -> &str {
    let start = body
        .find("Malware from this IP")
        .expect("the malware panel must render");
    let panel = &body[start..];
    &panel[..panel.find("</table>").unwrap_or(panel.len())]
}

/// Accepts the honeypot's own host key: this is a test against our own sensor, not a connection to
/// a third party.
struct TestHandler;

impl russh::client::Handler for TestHandler {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        _key: &russh::keys::PublicKey,
    ) -> Result<bool, Self::Error> {
        Ok(true)
    }
}

/// How the client ends the session. The sensor has no protocol-defined end of file for a shell
/// capture, so this is the only thing that decides whether the page shows a whole sample.
enum Ending {
    /// Stop sending and let `idle_timeout` elapse with the session still open.
    GoQuiet,
    /// Send SSH_MSG_DISCONNECT. The peer finished and said so.
    Disconnect,
}

/// Drive a real SSH session that streams an unterminated binary payload, run it through the same
/// tailer/intake the daemon runs, and return the malware panel's markup from the rendered page.
async fn panel_after_session(pool: PgPool, ending: Ending) -> String {
    migrate(&pool).await;

    let dir = tempfile::tempdir().unwrap();
    let sensor_log = dir.path().join("events.jsonl");
    std::fs::write(&sensor_log, "").unwrap();
    let cancel = CancellationToken::new();

    let idle_timeout = match ending {
        // Short enough to cut the transfer short while the payload is still arriving.
        Ending::GoQuiet => Duration::from_millis(600),
        Ending::Disconnect => Duration::from_secs(60),
    };

    let (sensor_addr, sensor_handle) = sensor_ssh::serve(
        "127.0.0.1:0".parse().unwrap(),
        sensor_log.clone(),
        dir.path().join("spool"),
        dir.path().join("host_key"),
        Arc::new(WanResolver::new(HashMap::new())),
        ConnectionBounds {
            read_timeout: Duration::from_secs(30),
            idle_timeout,
            max_duration: Duration::from_secs(120),
            max_captured_bytes: 1_000_000,
            max_concurrent: 16,
        },
        "OpenSSH_9.6p1".to_string(),
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
            git_sha: "abc123abc123",
            built_at: "2026-09-09T00:00:00Z",
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

    // ---- a dropper that streams a payload over the shell channel ----
    let config = Arc::new(russh::client::Config::default());
    let mut session = russh::client::connect(config, sensor_addr, TestHandler)
        .await
        .unwrap();
    session
        .authenticate_password("attacker", "password123")
        .await
        .unwrap();
    let channel = session.channel_open_session().await.unwrap();
    channel.request_shell(false).await.unwrap();
    tokio::time::sleep(Duration::from_millis(200)).await;
    // Every byte high-bit set, so none is CR or LF: no line ever reaches the shell, nothing raises
    // the per-line flood flag, and the raw bytes are the only evidence there is.
    let payload: Vec<u8> = (0u8..200).map(|i| 0x80u8 | (i & 0x3f)).collect();
    channel.data(&payload[..]).await.unwrap();

    if let Ending::Disconnect = ending {
        session
            .disconnect(russh::Disconnect::ByApplication, "", "")
            .await
            .unwrap();
    }

    // ---- what the operator sees ----
    let client = reqwest::Client::new();
    let url = format!("http://127.0.0.1:{port}/ip/127.0.0.1");
    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
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
            // Wait for the panel to stop saying it has nothing. Waiting on table markup instead
            // would be satisfied before the capture ever arrives: the page carries other tables,
            // and an empty panel has no `</table>` to bound the slice. This predicate is false
            // when armed - the panel renders its empty state first.
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

    let panel = malware_panel(&body).to_string();

    cancel.cancel();
    sensor_handle.abort();
    drop(channel);
    drop(session);
    let _ = tokio::time::timeout(Duration::from_secs(5), console_handle).await;
    let _ = tokio::time::timeout(Duration::from_secs(5), intake_handle).await;
    panel
}

/// A payload the sensor recorded as cut short must not read as a whole sample, and the page must
/// say what cut it. Both the `complete` and the `end_reason` key have to survive the trip for this
/// to hold: renaming either on either side breaks it.
#[sqlx::test(migrations = false)]
async fn a_stalled_ssh_capture_reaches_the_console_as_incomplete_with_its_reason(pool: PgPool) {
    let panel = panel_after_session(pool, Ending::GoQuiet).await;

    assert!(
        panel.contains("incomplete"),
        "a capture the sensor recorded as cut short must not read as a whole sample: {panel}"
    );
    assert!(
        panel.contains("idle timeout"),
        "the page must say what cut the capture short, in words: {panel}"
    );
}

/// The positive case, without which "label everything incomplete" would satisfy the test above.
#[sqlx::test(migrations = false)]
async fn an_ssh_capture_the_client_finished_reaches_the_console_as_captured(pool: PgPool) {
    let panel = panel_after_session(pool, Ending::Disconnect).await;

    assert!(
        panel.contains("captured"),
        "the client disconnected of its own accord, so the sample is whole: {panel}"
    );
    assert!(
        !panel.contains("incomplete"),
        "a finished transfer must not be labelled a fragment: {panel}"
    );
}
