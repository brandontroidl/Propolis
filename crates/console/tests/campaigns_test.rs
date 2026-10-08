//! The campaign pages, the campaign context on the review queue, the IP and Samples pages, and the
//! two-step campaign approval, against a database the real campaign indexer filled.
//!
//! A test binary of its own because the sample pages read `PROPOLIS_SPOOL_ROOT`, a process
//! environment variable, and nothing else in this binary reads the environment.

use std::net::SocketAddr;
use std::sync::Arc;

use axum::Router;
use axum::body::Body;
use axum::extract::connect_info::MockConnectInfo;
use axum::http::{Request, StatusCode};
use chrono::{DateTime, Duration, TimeZone, Utc};
use console::auth::{self, PasswordStore, RateLimiter, SessionStore};
use console::{AppState, routes};
use core_scoring::{EventInput, Protocol, SignalType, append_event};
use http_body_util::BodyExt;
use review::campaign::{self, BatchOutcome};
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use tower::ServiceExt;
use uuid::Uuid;

fn state(db: PgPool) -> AppState {
    AppState {
        db,
        sessions: Arc::new(SessionStore::new([9u8; 32])),
        passwords: Arc::new(PasswordStore::new("campaigns-test")),
        login_rate_limiter: Arc::new(RateLimiter::default()),
        templates: Arc::new(console::templates::environment()),
        geoip: Arc::new(geoip::GeoIp::disabled()),
        rdns: Arc::new(console::rdns::RdnsResolver::disabled()),
        feed_output_dir: None,
        fleet_listeners: Arc::new(Vec::new()),
        fleet_probe_interval: std::time::Duration::from_secs(300),
        deploy_stamp_path: None,
        startup_time: Utc::now(),
        binary_name: "console",
        version: "test",
        git_sha: "abc123abc123",
        built_at: "2026-10-07T00:00:00Z",
        log_buffer: Arc::new(console::log_buffer::LogBuffer::new(10)),
        events_ingested: Arc::new(std::sync::atomic::AtomicU64::new(0)),
        events_rejected: Arc::new(std::sync::atomic::AtomicU64::new(0)),
        trusted_proxy: false,
        metrics_token: None,
        gave_up_subsystems: console::no_subsystem_health(),
        intake_lag: console::intake_lag::no_intake_lag(),
    }
}

struct Console {
    state: AppState,
    session: String,
    cookie: String,
}

impl Console {
    fn new(pool: PgPool) -> Self {
        let state = state(pool);
        let (session, cookie) = state.sessions.create();
        Self {
            state,
            session,
            cookie: format!("{}={cookie}", auth::SESSION_COOKIE),
        }
    }

    fn app(&self) -> Router {
        routes::router(self.state.clone())
            .layer(MockConnectInfo(SocketAddr::from(([127, 0, 0, 1], 5555))))
    }

    fn csrf(&self) -> String {
        self.state.sessions.generate_csrf(&self.session).unwrap()
    }

    async fn get(&self, uri: &str) -> (StatusCode, String) {
        let response = self
            .app()
            .oneshot(
                Request::builder()
                    .uri(uri)
                    .header("cookie", &self.cookie)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let status = response.status();
        let body = response.into_body().collect().await.unwrap().to_bytes();
        (status, readable(&body))
    }

    async fn post(&self, uri: &str, form: &[(&str, &str)]) -> (StatusCode, String) {
        let body: String = form
            .iter()
            .map(|(k, v)| format!("{k}={}", urlencode(v)))
            .collect::<Vec<_>>()
            .join("&");
        let response = self
            .app()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(uri)
                    .header("cookie", &self.cookie)
                    .header("content-type", "application/x-www-form-urlencoded")
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();
        let status = response.status();
        let body = response.into_body().collect().await.unwrap().to_bytes();
        (status, readable(&body))
    }
}

/// The page with minijinja's escaped slash turned back into a slash, so assertions can name
/// paths and commands as written. No other entity is touched, so an escaped `<` stays escaped and
/// the escaping assertions keep their meaning.
fn readable(body: &[u8]) -> String {
    String::from_utf8(body.to_vec())
        .unwrap()
        .replace("&#x2f;", "/")
}

fn urlencode(s: &str) -> String {
    s.bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' => (b as char).to_string(),
            _ => format!("%{b:02X}"),
        })
        .collect()
}

async fn migrate(pool: &PgPool) {
    sqlx::migrate!("../core-scoring/migrations")
        .run(pool)
        .await
        .unwrap();
    review::migrator().run(pool).await.unwrap();
    fleet::migrator().run(pool).await.unwrap();
}

/// Six hours ago, on the hour, so the few minutes of fixture events never straddle a day.
fn t0() -> DateTime<Utc> {
    let hour = (Utc::now() - Duration::hours(6)).timestamp() / 3600 * 3600;
    Utc.timestamp_opt(hour, 0).unwrap()
}

async fn append(
    pool: &PgPool,
    ip: &str,
    sensor: &str,
    signal: SignalType,
    at: DateTime<Utc>,
    metadata: serde_json::Value,
    session: Option<Uuid>,
) {
    append_event(
        pool,
        EventInput::from_signal(
            ip.parse().unwrap(),
            None,
            sensor.into(),
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

async fn index_all(pool: &PgPool) {
    while campaign::index_batch(pool, 500).await.unwrap() != BatchOutcome::Indexed(0) {}
}

async fn pend(pool: &PgPool, ip: &str) {
    sqlx::query(
        "INSERT INTO review_queue (source_ip, score_at_surface, categories_at_surface) \
         VALUES ($1::inet, 50, '{}'::jsonb) ON CONFLICT (source_ip) DO NOTHING",
    )
    .bind(ip)
    .execute(pool)
    .await
    .unwrap();
}

async fn review_state(pool: &PgPool, ip: &str) -> String {
    sqlx::query_scalar("SELECT state::text FROM review_queue WHERE source_ip = $1::inet")
        .bind(ip)
        .fetch_one(pool)
        .await
        .unwrap()
}

/// Five hosts upload the same body (a sample campaign); three of them run the same command
/// script (a command-sequence campaign). Returns the sample's digest.
async fn seed(pool: &PgPool, worm_body: &[u8]) -> String {
    let sha: String = Sha256::digest(worm_body)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    for i in 1..=5 {
        let ip = format!("192.0.2.{i}");
        let session = Uuid::now_v7();
        let start = t0() + Duration::minutes(i);
        if i <= 3 {
            for (n, c) in [
                "uname -a",
                "cat /proc/cpuinfo | grep name",
                "cd /tmp; cat > w.sh",
            ]
            .iter()
            .enumerate()
            {
                append(
                    pool,
                    &ip,
                    "ssh",
                    SignalType::HoneypotCommandExec,
                    start + Duration::seconds(n as i64),
                    serde_json::json!({ "command": c }),
                    Some(session),
                )
                .await;
            }
        }
        append(
            pool,
            &ip,
            "ssh",
            SignalType::HoneypotMalwareUpload,
            start + Duration::seconds(5),
            serde_json::json!({ "sample_sha256": sha, "sample_orig_name": "w.sh" }),
            Some(session),
        )
        .await;
    }
    // Later ssh traffic ends the sessions' runs.
    append(
        pool,
        "198.51.100.200",
        "ssh",
        SignalType::HoneypotConnection,
        t0() + Duration::hours(2),
        serde_json::json!({}),
        None,
    )
    .await;
    index_all(pool).await;
    sha
}

async fn campaign_id(pool: &PgPool, kind: &str) -> i64 {
    sqlx::query_scalar("SELECT id FROM campaign WHERE kind = $1")
        .bind(kind)
        .fetch_one(pool)
        .await
        .unwrap()
}

#[sqlx::test(migrations = false)]
async fn the_campaign_list_shows_each_campaign_with_its_hosts_and_activity(pool: PgPool) {
    migrate(&pool).await;
    let sha = seed(&pool, b"#!/bin/sh\necho worm\n").await;
    let console = Console::new(pool.clone());
    let (status, page) = console.get("/campaigns").await;
    assert_eq!(status, StatusCode::OK);
    let sample = campaign_id(&pool, "sample").await;
    let sequence = campaign_id(&pool, "command_sequence").await;
    assert!(
        page.contains(&format!("href=\"/campaigns/{sample}\"")),
        "{page}"
    );
    assert!(page.contains(&format!("href=\"/campaigns/{sequence}\"")));
    assert!(page.contains(&format!("sample {} (w.sh)", &sha[..12])));
    assert!(
        page.contains(
            "3 commands: uname -a ; cat /proc/cpuinfo | grep name ; cd /tmp; cat &gt; w.sh"
        ),
        "{page}"
    );
    // The sample campaign's five hosts, all seen today, make one full-height bar.
    assert!(page.contains("<td class=\"count\">5</td>"));
    assert!(
        page.contains(&format!("<title>{}: 5</title>", t0().date_naive())),
        "{page}"
    );
    assert!(page.contains(&format!("href=\"/samples/{sha}\"")));

    let (_, filtered) = console.get("/campaigns?kind=scanner").await;
    assert!(!filtered.contains(&format!("href=\"/campaigns/{sample}\"")));
    assert!(filtered.contains("no campaigns of this kind yet"));
}

#[sqlx::test(migrations = false)]
async fn attacker_text_is_rendered_escaped_and_never_as_a_link(pool: PgPool) {
    migrate(&pool).await;
    let sha = seed(&pool, b"#!/bin/sh\necho worm two\n").await;
    let sample = campaign_id(&pool, "sample").await;
    sqlx::query("UPDATE campaign SET label = '<script>alert(1)</script>' WHERE id = $1")
        .bind(sample)
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query(
        "INSERT INTO ioc (kind, value, detail, artifact_sha256, first_seen, last_seen) \
         VALUES ('url', 'http://198.51.100.9/\"><img src=x onerror=alert(2)>', '<b>bold</b>', $1, now(), now())",
    )
    .bind(&sha)
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query("INSERT INTO ioc_artifact_scan (sha256, state) VALUES ($1, 'done') ON CONFLICT (sha256) DO UPDATE SET state = 'done'")
        .bind(&sha)
        .execute(&pool)
        .await
        .unwrap();
    let console = Console::new(pool.clone());
    for uri in [
        "/campaigns".to_string(),
        format!("/campaigns/{sample}"),
        format!("/samples/{sha}"),
    ] {
        let (status, page) = console.get(&uri).await;
        assert_eq!(status, StatusCode::OK, "{uri}");
        assert!(!page.contains("<script>alert(1)"), "{uri}: unescaped label");
        assert!(!page.contains("<img src=x"), "{uri}: unescaped indicator");
        assert!(!page.contains("<b>bold"), "{uri}: unescaped detail");
        assert!(
            !page.contains("href=\"http://198.51.100.9"),
            "{uri}: an indicator became a link"
        );
    }
    let (_, detail) = console.get(&format!("/campaigns/{sample}")).await;
    assert!(detail.contains("&lt;script&gt;alert(1)&lt;/script&gt;"));
    assert!(
        detail.contains("&lt;img src=x onerror=alert(2)&gt;"),
        "{detail}"
    );
}

#[sqlx::test(migrations = false)]
async fn the_campaign_page_shows_members_representative_and_indicators(pool: PgPool) {
    migrate(&pool).await;
    let sha = seed(
        &pool,
        b"#!/bin/sh\necho \"127.0.0.1 rival.example.net\" >> /etc/hosts\n",
    )
    .await;
    let spool = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(spool.path().join("ssh")).unwrap();
    std::fs::write(
        spool.path().join("ssh").join(&sha),
        b"#!/bin/sh\necho \"127.0.0.1 rival.example.net\" >> /etc/hosts\n",
    )
    .unwrap();
    campaign::scan_artifacts(&pool, &[("ssh", spool.path().join("ssh"))])
        .await
        .unwrap();
    pend(&pool, "192.0.2.2").await;
    let sequence = campaign_id(&pool, "command_sequence").await;
    let sample = campaign_id(&pool, "sample").await;
    let console = Console::new(pool.clone());

    let (status, page) = console.get(&format!("/campaigns/{sequence}")).await;
    assert_eq!(status, StatusCode::OK);
    for ip in ["192.0.2.1", "192.0.2.2", "192.0.2.3"] {
        assert!(page.contains(&format!("href=\"/ip/{ip}\"")), "{ip}");
    }
    assert!(!page.contains("href=\"/ip/192.0.2.4\""));
    assert!(
        page.contains("<li>cat /proc/cpuinfo | grep name</li>"),
        "{page}"
    );
    assert!(
        page.contains(&format!("href=\"/samples/{sha}\"")),
        "the uploaded sample is linked"
    );
    assert!(page.contains("1 member is pending review"), "{page}");
    assert!(page.contains(&format!("href=\"/campaigns/{sequence}/approve\"")));

    let (_, page) = console.get(&format!("/campaigns/{sample}")).await;
    assert!(page.contains("127.0.0.1 rival.example.net"), "{page}");
    assert!(page.contains("hosts entry"));

    let (status, _) = console.get("/campaigns/999999").await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

/// The approval is two steps and approves exactly the confirmed, still-pending members: never a
/// member that became pending after the confirmation was shown, never a confirmed address that is
/// not a member, never without the CSRF token.
#[sqlx::test(migrations = false)]
async fn approving_a_campaign_confirms_the_list_first_and_approves_only_it(pool: PgPool) {
    migrate(&pool).await;
    seed(&pool, b"#!/bin/sh\necho worm three\n").await;
    let sample = campaign_id(&pool, "sample").await;
    for ip in ["192.0.2.1", "192.0.2.2", "192.0.2.3"] {
        pend(&pool, ip).await;
    }
    // Pending, but not a member of the campaign.
    pend(&pool, "203.0.113.77").await;
    let console = Console::new(pool.clone());

    let (status, page) = console.get(&format!("/campaigns/{sample}/approve")).await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        page.contains("These 3 pending addresses will be approved"),
        "{page}"
    );
    assert!(
        page.contains("value=\"192.0.2.1,192.0.2.2,192.0.2.3\""),
        "{page}"
    );
    assert!(!page.contains("203.0.113.77"));
    // Showing the confirmation decided nothing.
    for ip in ["192.0.2.1", "192.0.2.2", "192.0.2.3"] {
        assert_eq!(review_state(&pool, ip).await, "pending");
    }

    // A member that becomes pending after the page was rendered.
    pend(&pool, "192.0.2.4").await;

    let uri = format!("/campaigns/{sample}/approve");
    let confirmed = "192.0.2.1,192.0.2.2,192.0.2.3,203.0.113.77";
    let (status, _) = console
        .post(&uri, &[("csrf_token", "forged"), ("ips", confirmed)])
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(review_state(&pool, "192.0.2.1").await, "pending");

    let (status, _) = console
        .post(
            &uri,
            &[
                ("csrf_token", &console.csrf()),
                ("ips", "192.0.2.1,not-an-address"),
            ],
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(review_state(&pool, "192.0.2.1").await, "pending");

    let (status, page) = console
        .post(
            &uri,
            &[
                ("csrf_token", &console.csrf()),
                ("ips", confirmed),
                ("notes", "worm wave"),
            ],
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert!(page.contains("Approved 3 addresses"), "{page}");
    assert!(page.contains("Skipped 1"), "{page}");
    for ip in ["192.0.2.1", "192.0.2.2", "192.0.2.3"] {
        assert_eq!(review_state(&pool, ip).await, "approved", "{ip}");
    }
    assert_eq!(
        review_state(&pool, "192.0.2.4").await,
        "pending",
        "joined after confirmation"
    );
    assert_eq!(
        review_state(&pool, "203.0.113.77").await,
        "pending",
        "not a member"
    );
    let notes: String =
        sqlx::query_scalar("SELECT notes FROM review_queue WHERE source_ip = '192.0.2.1'")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(notes, "worm wave");
}

#[sqlx::test(migrations = false)]
async fn queue_ip_and_samples_pages_link_to_the_campaign(pool: PgPool) {
    migrate(&pool).await;
    let root = tempfile::tempdir().unwrap();
    // SAFETY: set before anything reads it, and nothing else in this binary reads the environment.
    unsafe { std::env::set_var("PROPOLIS_SPOOL_ROOT", root.path()) };
    let body = b"#!/bin/sh\necho worm four\n";
    let sha = seed(&pool, body).await;
    std::fs::create_dir_all(root.path().join("ssh")).unwrap();
    std::fs::write(root.path().join("ssh").join(&sha), body).unwrap();
    for ip in ["192.0.2.1", "192.0.2.2"] {
        pend(&pool, ip).await;
    }
    let sample = campaign_id(&pool, "sample").await;
    let console = Console::new(pool.clone());

    let (status, queue) = console.get("/queue").await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        queue.contains(&format!(
            "part of <a href=\"/campaigns/{sample}\">campaign {sample}</a>, 5 hosts"
        )),
        "{queue}"
    );
    assert!(queue.contains(&format!(
        "<a href=\"/campaigns/{sample}/approve\">approve all 2 pending"
    )));

    let (status, ip_page) = console.get("/ip/192.0.2.1").await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        ip_page.contains(&format!("<a href=\"/campaigns/{sample}\">")),
        "{ip_page}"
    );
    assert!(ip_page.contains("5 hosts"));

    let (status, samples) = console.get("/samples").await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        samples.contains(&format!("<a href=\"/campaigns/{sample}\">5 hosts</a>")),
        "{samples}"
    );
    assert!(samples.contains(&format!("href=\"/samples/{sha}\"")));

    let (status, detail) = console.get(&format!("/samples/{sha}")).await;
    assert_eq!(status, StatusCode::OK);
    assert!(detail.contains("in the ssh spool"), "{detail}");
    assert!(detail.contains("queued for scanning"));
    let (status, _) = console.get("/samples/not-a-digest").await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[sqlx::test(migrations = false)]
async fn a_self_propagating_sample_calls_its_members_infected_hosts(pool: PgPool) {
    migrate(&pool).await;
    seed(&pool, b"zmap; sshpass scp self\n").await;
    let sample = campaign_id(&pool, "sample").await;
    let console = Console::new(pool.clone());
    let (_, page) = console.get(&format!("/campaigns/{sample}")).await;
    assert!(
        page.contains("treated as: <strong>attacker</strong>"),
        "{page}"
    );
    sqlx::query("UPDATE campaign SET self_propagating = TRUE WHERE id = $1")
        .bind(sample)
        .execute(&pool)
        .await
        .unwrap();
    let (_, page) = console.get(&format!("/campaigns/{sample}")).await;
    assert!(
        page.contains("treated as: <strong>infected host</strong>"),
        "{page}"
    );
    let (_, list) = console.get("/campaigns").await;
    assert!(list.contains(">worm</span>"));
}
