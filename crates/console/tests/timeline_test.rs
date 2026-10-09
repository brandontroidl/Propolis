//! The IP evidence page's timeline: what the review fetcher did with each URL a shell asked to
//! download (`routes::detail`'s `attach_fetch_outcomes`), and how a multi-line command is laid out.
//!
//! Every address here is RFC 5737 documentation space. Each test runs on its own database
//! (`#[sqlx::test(migrations = false)]`), migrated the way `routes_test.rs` migrates.

use std::net::SocketAddr;
use std::sync::Arc;

use axum::Router;
use axum::body::Body;
use axum::extract::connect_info::MockConnectInfo;
use axum::http::{Request, StatusCode};
use axum::response::Response;
use console::auth::{self, PasswordStore, RateLimiter, SessionStore};
use console::{AppState, routes};
use core_scoring::{EventInput, Protocol, SignalType, append_event};
use http_body_util::BodyExt;
use sqlx::PgPool;
use tower::ServiceExt;
use uuid::Uuid;

const PEER: SocketAddr =
    SocketAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST), 55555);

async fn migrate(pool: &PgPool) {
    sqlx::migrate!("../core-scoring/migrations")
        .run(pool)
        .await
        .unwrap();
    review::migrator().run(pool).await.unwrap();
    fleet::migrator().run(pool).await.unwrap();
}

fn state(db: PgPool) -> AppState {
    AppState {
        db,
        sessions: Arc::new(SessionStore::new([11u8; 32])),
        passwords: Arc::new(PasswordStore::new("timeline-test-password")),
        login_rate_limiter: Arc::new(RateLimiter::default()),
        templates: Arc::new(console::templates::environment()),
        geoip: Arc::new(geoip::GeoIp::disabled()),
        rdns: Arc::new(console::rdns::RdnsResolver::disabled()),
        feed_output_dir: None,
        fleet_listeners: Arc::new(Vec::new()),
        fleet_probe_interval: std::time::Duration::from_secs(300),
        deploy_stamp_path: None,
        startup_time: chrono::Utc::now(),
        binary_name: "console",
        version: "test",
        git_sha: "abc123abc123",
        built_at: "2026-09-09T00:00:00Z",
        log_buffer: Arc::new(console::log_buffer::LogBuffer::new(100)),
        events_ingested: Arc::new(std::sync::atomic::AtomicU64::new(0)),
        events_rejected: Arc::new(std::sync::atomic::AtomicU64::new(0)),
        trusted_proxy: false,
        metrics_token: None,
        gave_up_subsystems: console::no_subsystem_health(),
        intake_lag: console::intake_lag::no_intake_lag(),
    }
}

fn app(state: AppState) -> Router {
    routes::router(state).layer(MockConnectInfo(PEER))
}

async fn page(pool: PgPool, uri: &str) -> String {
    let state = state(pool);
    let (_, cookie) = state.sessions.create();
    let response: Response = app(state)
        .oneshot(
            Request::builder()
                .uri(uri)
                .header("cookie", format!("{}={cookie}", auth::SESSION_COOKIE))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK, "{uri}");
    String::from_utf8(
        response
            .into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes()
            .to_vec(),
    )
    .unwrap()
}

/// Appends one event for `ip`, `seconds_ago` before now, in `session` when given.
async fn event(
    pool: &PgPool,
    ip: &str,
    signal: SignalType,
    seconds_ago: i64,
    metadata: serde_json::Value,
    session: Option<Uuid>,
) {
    let at = chrono::Utc::now() - chrono::Duration::seconds(seconds_ago);
    append_event(
        pool,
        EventInput::from_signal(
            ip.parse().unwrap(),
            None,
            "telnet".into(),
            signal,
            Protocol::Tcp,
            true,
            at,
            metadata,
            session,
        ),
    )
    .await
    .unwrap();
}

/// A scored address, so `/ip/{ip}` is not a 404: one login is enough for a projection row.
async fn scored(pool: &PgPool, ip: &str) {
    event(
        pool,
        ip,
        SignalType::HoneypotLoginAttempt,
        600,
        serde_json::json!({ "username": "root" }),
        None,
    )
    .await;
}

/// The page from the evidence timeline's heading on, so a URL that also appears in the URL panel
/// above it is found where the timeline shows it.
fn timeline(body: &str) -> &str {
    let at = body
        .find("Evidence timeline")
        .expect("timeline heading renders");
    &body[at..]
}

/// The `<tr>` of `section` that holds `needle`.
fn row<'a>(section: &'a str, needle: &str) -> &'a str {
    let at = section
        .find(needle)
        .unwrap_or_else(|| panic!("{needle} not found in: {section}"));
    let start = section[..at].rfind("<tr").expect("row start");
    let end = at + section[at..].find("</tr>").expect("row end");
    &section[start..end]
}

#[allow(clippy::too_many_arguments)]
async fn fetch_row(
    pool: &PgPool,
    url: &str,
    scheme: &str,
    status: &str,
    reason: Option<&str>,
    attempts: i32,
    sha256: Option<&str>,
    bytes: Option<i32>,
    source_ip: &str,
) {
    sqlx::query(
        "INSERT INTO fetch_attempt \
            (url_hash, url, host, scheme, source_ip, status, reject_reason, sha256, bytes, \
             attempts, last_attempt) \
         VALUES (sha256(convert_to(btrim($1), 'UTF8')), btrim($1), 'h', $2, $3::inet, $4, $5, $6, \
                 $7, $8, now())",
    )
    .bind(url)
    .bind(scheme)
    .bind(source_ip)
    .bind(status)
    .bind(reason)
    .bind(sha256.map(|s| hex::decode(s).unwrap()))
    .bind(bytes)
    .bind(attempts)
    .execute(pool)
    .await
    .unwrap();
}

fn download(url: &str) -> serde_json::Value {
    serde_json::json!({ "url": url })
}

#[sqlx::test(migrations = false)]
async fn each_download_shows_what_the_fetcher_did_with_its_url(pool: PgPool) {
    migrate(&pool).await;
    let ip = "203.0.113.50";
    let other = "203.0.113.51";
    scored(&pool, ip).await;
    let session = Uuid::now_v7();
    let sha = format!("{:064x}", 0xc0ffee_u64);
    let long_reason = "a".repeat(300);

    // One URL per outcome, each on its own documentation host.
    fetch_row(
        &pool,
        "http://198.51.100.21/ok.sh",
        "http",
        "success",
        None,
        1,
        Some(&sha),
        Some(4300),
        other,
    )
    .await;
    fetch_row(
        &pool,
        "http://198.51.100.22/in.sh",
        "http",
        "rejected",
        Some("PrivateAddress"),
        1,
        None,
        None,
        ip,
    )
    .await;
    fetch_row(
        &pool,
        "tftp://198.51.100.23/x",
        "tftp",
        "dead",
        Some("no response from the TFTP server"),
        3,
        None,
        None,
        ip,
    )
    .await;
    fetch_row(
        &pool,
        "http://198.51.100.24/slow",
        "http",
        "timeout",
        Some("<script>alert(1)</script>"),
        1,
        None,
        None,
        ip,
    )
    .await;
    fetch_row(
        &pool,
        "http://198.51.100.25/new",
        "http",
        "pending",
        None,
        0,
        None,
        None,
        ip,
    )
    .await;
    fetch_row(
        &pool,
        "http://198.51.100.26/long",
        "http",
        "dead",
        Some(&long_reason),
        3,
        None,
        None,
        ip,
    )
    .await;

    for (i, url) in [
        // The event's URL carries stray whitespace; the fetcher keys on the trimmed text.
        " http://198.51.100.21/ok.sh ",
        "http://198.51.100.22/in.sh",
        "tftp://198.51.100.23/x",
        "http://198.51.100.24/slow",
        "http://198.51.100.25/new",
        "http://198.51.100.26/long",
        " ftp://198.51.100.27/x",
        "http://198.51.100.28/never-queued",
    ]
    .into_iter()
    .enumerate()
    {
        event(
            &pool,
            ip,
            SignalType::HoneypotFileDownload,
            100 - i as i64,
            download(url),
            Some(session),
        )
        .await;
    }
    // Not in a session: the "ungrouped" table renders outcomes too.
    event(
        &pool,
        ip,
        SignalType::HoneypotFileDownload,
        5,
        download("http://198.51.100.22/in.sh"),
        None,
    )
    .await;

    let body = page(pool, &format!("/ip/{ip}")).await;
    let t = timeline(&body);

    let ok = row(t, "198.51.100.21");
    assert!(ok.contains("fetched"), "{ok}");
    assert!(
        ok.contains(&format!(r#"href="/samples/{sha}""#)),
        "the sample hash links to its page: {ok}"
    );
    assert!(ok.contains(&sha[..12]) && ok.contains("4.2 KB"), "{ok}");
    assert!(!ok.contains("refused") && !ok.contains("failed"), "{ok}");

    let refused = row(t, "198.51.100.22");
    assert!(refused.contains("refused"), "{refused}");
    assert!(refused.contains("PrivateAddress"), "the reason: {refused}");
    assert!(
        !refused.contains("fetched") && !refused.contains("/samples/"),
        "{refused}"
    );

    let dead = row(t, "198.51.100.23");
    assert!(dead.contains("gave up after 3 attempts"), "{dead}");
    assert!(dead.contains("no response from the TFTP server"), "{dead}");
    assert!(!dead.contains("refused"), "{dead}");

    let timeout = row(t, "198.51.100.24");
    assert!(
        timeout.contains("failed: timed out, will retry"),
        "{timeout}"
    );
    assert!(
        timeout.contains("&lt;script&gt;alert(1)&lt;&#x2f;script&gt;")
            && !timeout.contains("<script>alert"),
        "a fetcher reason is escaped: {timeout}"
    );

    let pending = row(t, "198.51.100.25");
    assert!(pending.contains("pending, 0 attempts so far"), "{pending}");

    let long = row(t, "198.51.100.26");
    assert!(
        long.contains(&"a".repeat(160)) && !long.contains(&"a".repeat(161)),
        "a reason is capped at 160 characters: {long}"
    );

    let ftp = row(t, "198.51.100.27");
    assert!(
        ftp.contains("not fetched") && ftp.contains("unsupported scheme (ftp)"),
        "{ftp}"
    );

    let never = row(t, "198.51.100.28");
    assert!(never.contains("not queued"), "{never}");

    // The ungrouped copy of the refused download carries its own outcome.
    let ungrouped = &t[t.find("Ungrouped events").expect("ungrouped table")..];
    assert!(
        row(ungrouped, "198.51.100.22").contains("refused"),
        "{ungrouped}"
    );
}

#[sqlx::test(migrations = false)]
async fn only_download_events_get_an_outcome_line(pool: PgPool) {
    migrate(&pool).await;
    let ip = "203.0.113.52";
    scored(&pool, ip).await;
    let session = Uuid::now_v7();
    fetch_row(
        &pool,
        "http://198.51.100.31/a",
        "http",
        "rejected",
        Some("Loopback"),
        1,
        None,
        None,
        ip,
    )
    .await;
    // A command that merely names the URL, and an upload that carries a `url` key: neither is a
    // download attempt, so the fetcher's record is not theirs to show.
    event(
        &pool,
        ip,
        SignalType::HoneypotCommandExec,
        50,
        serde_json::json!({ "command": "echo http://198.51.100.31/a", "url": "http://198.51.100.31/a" }),
        Some(session),
    )
    .await;

    let body = page(pool, &format!("/ip/{ip}")).await;
    let t = timeline(&body);
    let command = row(t, "echo http");
    assert!(
        !command.contains("c-sub") && !command.contains("refused"),
        "{command}"
    );
}

#[sqlx::test(migrations = false)]
async fn the_load_more_fragment_carries_outcomes_too(pool: PgPool) {
    migrate(&pool).await;
    let ip = "203.0.113.53";
    scored(&pool, ip).await;
    fetch_row(
        &pool,
        "http://198.51.100.41/a",
        "http",
        "rejected",
        Some("Loopback"),
        1,
        None,
        None,
        ip,
    )
    .await;
    event(
        &pool,
        ip,
        SignalType::HoneypotFileDownload,
        50,
        download("http://198.51.100.41/a"),
        Some(Uuid::now_v7()),
    )
    .await;

    let fragment = page(
        pool,
        &format!("/ip/{ip}/events?cursor=2099-01-01T00:00:00.000000Z,9223372036854775807"),
    )
    .await;
    let r = row(&fragment, "198.51.100.41");
    assert!(r.contains("refused") && r.contains("Loopback"), "{r}");
}

/// The timeline header's count line.
fn header(body: &str) -> String {
    let at = body.find("Evidence timeline").expect("heading");
    let from = &body[at..];
    let open =
        from.find("<span class=\"dim\">").expect("count span") + "<span class=\"dim\">".len();
    let close = from[open..].find("</span>").expect("count span end");
    from[open..open + close].to_string()
}

#[sqlx::test(migrations = false)]
async fn the_timeline_header_names_events_commands_and_sessions(pool: PgPool) {
    migrate(&pool).await;
    let ip = "203.0.113.54";
    scored(&pool, ip).await; // one event outside any session
    let (a, b) = (Uuid::now_v7(), Uuid::now_v7());
    for (i, s) in [a, a, a, b].into_iter().enumerate() {
        event(
            &pool,
            ip,
            SignalType::HoneypotCommandExec,
            300 - i as i64,
            serde_json::json!({ "command": format!("id {i}") }),
            Some(s),
        )
        .await;
    }
    event(
        &pool,
        ip,
        SignalType::HoneypotConnection,
        290,
        serde_json::json!({}),
        Some(a),
    )
    .await;
    event(
        &pool,
        ip,
        SignalType::CatchallProbe,
        280,
        serde_json::json!({}),
        None,
    )
    .await;

    let body = page(pool, &format!("/ip/{ip}")).await;
    assert_eq!(
        header(&body),
        "7 events: 4 commands, 2 sessions, 2 outside any session"
    );
}

#[sqlx::test(migrations = false)]
async fn a_full_first_page_says_it_is_the_newest_events_and_uses_singulars(pool: PgPool) {
    migrate(&pool).await;
    let ip = "203.0.113.55";
    scored(&pool, ip).await;
    let s = Uuid::now_v7();
    for i in 0..199 {
        event(
            &pool,
            ip,
            SignalType::HoneypotCommandExec,
            500 - (i % 400),
            serde_json::json!({ "command": format!("echo {i}") }),
            Some(s),
        )
        .await;
    }
    let body = page(pool, &format!("/ip/{ip}")).await;
    assert_eq!(
        header(&body),
        "newest 200 events: 199 commands, 1 session, 1 outside any session"
    );
}
