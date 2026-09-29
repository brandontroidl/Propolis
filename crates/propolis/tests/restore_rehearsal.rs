//! Populated restore rehearsal (audit finding P-14, recovery half). An empty-database dump proves
//! the schema restores; it says nothing about whether evidence does. This builds a node's worth of
//! state, backs it up with the documented commands, throws the original away, and restores it
//! into a PostgreSQL cluster that has never seen it:
//!
//! 1. A fresh cluster gets the `propolis` role and database, the daemon's three migration sets in
//!    startup order, and a few hundred hash-chained events plus review, vendor, fetch, verdict and
//!    probe rows - written through the crates' own write paths wherever a public one exists.
//! 2. Sample bodies go into the `ssh`, `telnet` and `fetched` spools under a scratch root through
//!    `QuarantineSpool`, so every file name is the digest the database references.
//! 3. `pg_dump --format=custom` and the documented `tar` inputs (read from
//!    docs/operations/backup-and-restore.md and re-rooted under the scratch root) take the backup.
//!    The source cluster is stopped and its data directory and spool tree are deleted.
//! 4. A second fresh cluster gets the role and an empty database, `pg_restore --exit-on-error`
//!    loads the dump, and `tar` unpacks the archive into a new root.
//! 5. The restored database must match the source table by table (row counts and a digest of
//!    every row), in named aggregates, sequence positions, schema objects and the `event`
//!    privileges. The daemon's migrations must then apply and change nothing, the whole ledger
//!    must verify `Intact`, every projection must replay to its stored value, a new event must
//!    chain onto the restored head, and every sample reference must resolve to a restored body
//!    that re-hashes to its name.
//!
//! Not covered: physical base backups, WAL archiving and point-in-time recovery; file ownership
//! after extraction (the rehearsal runs unprivileged); restoring onto a different PostgreSQL major
//! version.
//!
//! Ignored by default because it needs PostgreSQL server binaries and a `pg_dump`/`pg_restore` of
//! the same major version, which CI does not install. Run it with `RESTORE_REHEARSAL_PG_BIN`
//! naming that bin directory; the exact command is in the backup page's "Restore rehearsal".

mod doc_commands;

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::Write;
use std::net::IpAddr;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration as StdDuration;

use chrono::{DateTime, Duration, Utc};
use core_scoring::{ChainStatus, EventInput, Protocol, SignalType};
use review::fetcher::store::{
    AttemptResult, Candidate, ClaimLimits, NewPendingRow, claim_candidates,
    insert_pending_if_absent, parse_url_parts, upsert_attempt, url_hash,
};
use review::fetcher::{FetchStatus, TransportAuth};
use sensor_framework::QuarantineSpool;
use sqlx::postgres::{PgConnection, PgPoolOptions};
use sqlx::{Connection, PgPool, Row};

const PG_BIN_VAR: &str = "RESTORE_REHEARSAL_PG_BIN";
const BACKUP_DOC: &str = "docs/operations/backup-and-restore.md";
/// The spool root the documented archive command names.
const SPOOL_ROOT: &str = "var/spool/propolis";
/// Largest body any spool may hold (`review::spool::MAX_SAMPLE_BYTES`); readers enforce it.
const MAX_SAMPLE_BYTES: u64 = 500_000_000;

// The options the rehearsal passes to each command the backup page documents. It cannot run the
// page's commands verbatim (it supplies its own paths, cluster and database), so
// `the_rehearsal_runs_the_options_the_backup_page_documents` holds the page to these instead.
const PG_DUMP_FORMAT: &str = "--format=custom";
const PG_RESTORE_STOP_ON_ERROR: &str = "--exit-on-error";
const TAR_CREATE: &str = "-czf";
const TAR_EXTRACT: &str = "-xzpf";

/// The rehearsal proves the documented procedure only while the two pass the same options, in both
/// directions. An option the page adds, such as `--no-privileges` on the restore or an `--exclude`
/// on the archive, would change what the real procedure saves or restores. One the page drops, such
/// as `--format=custom` (a plain dump `pg_restore` refuses) or `--exit-on-error` (a restore that
/// continues past a missing role), would break it. Either way the rehearsal, running its own
/// options, would still pass. `-C` on the archive is the rehearsal's own: it re-roots the documented
/// absolute paths under a scratch directory. Needs no PostgreSQL, so it is not ignored.
#[test]
fn the_rehearsal_runs_the_options_the_backup_page_documents() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let doc = fs::read_to_string(root.join(BACKUP_DOC)).expect("backup page");
    let check = |program: &str, commands: Vec<Vec<String>>, rehearsed: &[&str]| {
        assert_eq!(
            commands.len(),
            1,
            "{BACKUP_DOC} should document one {program} command, found {commands:?}"
        );
        let rehearsed: BTreeSet<String> = rehearsed.iter().map(|o| option_key(o)).collect();
        let documented: BTreeSet<String> = commands[0]
            .iter()
            .filter(|w| w.starts_with('-'))
            .map(|o| option_key(o))
            .collect();
        assert_eq!(
            documented,
            rehearsed,
            "{BACKUP_DOC}'s `{program} {}` and populated_backup_restores_into_a_fresh_cluster \
             must pass the same options",
            commands[0].join(" ")
        );
    };
    check(
        "pg_dump",
        doc_commands::commands_running(&doc, "pg_dump"),
        &[PG_DUMP_FORMAT, "--file"],
    );
    check(
        "pg_restore",
        doc_commands::commands_running(&doc, "pg_restore"),
        &[PG_RESTORE_STOP_ON_ERROR, "--dbname"],
    );
    let (create, extract): (Vec<_>, Vec<_>) = doc_commands::commands_running(&doc, "tar")
        .into_iter()
        .partition(|c| {
            c.first()
                .is_some_and(|o| o.starts_with('-') && o.contains('c'))
        });
    check("tar (create)", create, &[TAR_CREATE]);
    check("tar (extract)", extract, &[TAR_EXTRACT, "-C"]);
}

/// An option as the comparison sees it. A long option is its name, except `--format`, whose value
/// is the point. A short group is its letters as a set (`-czf` and `-zcf` agree), but only when any
/// value-taking letter ends the group: `-xfpz` makes `pz` the archive name, so it is kept as written
/// and matches nothing.
fn option_key(option: &str) -> String {
    match option.strip_prefix("--") {
        Some(long) => match long.split_once('=') {
            Some(("format", _)) | None => option.to_string(),
            Some((name, _)) => format!("--{name}"),
        },
        None => {
            let group = &option[1..];
            match group.find(doc_commands::SHORT_WITH_VALUE) {
                Some(at) if at + 1 != group.len() => option.to_string(),
                _ => {
                    let mut letters: Vec<char> = group.chars().collect();
                    letters.sort_unstable();
                    format!("-{}", letters.into_iter().collect::<String>())
                }
            }
        }
    }
}

#[tokio::test]
#[ignore = "needs PostgreSQL server binaries: set RESTORE_REHEARSAL_PG_BIN (docs/operations/backup-and-restore.md)"]
async fn populated_backup_restores_into_a_fresh_cluster() {
    let bin = pg_bin();
    let server_version = run(Command::new(bin.join("postgres")).arg("--version"));
    let dump_version = run(Command::new(bin.join("pg_dump")).arg("--version"));
    let work = tempfile::Builder::new()
        .prefix("restore-rehearsal-")
        .tempdir_in(env!("CARGO_TARGET_TMPDIR"))
        .expect("scratch directory under the target dir");
    let source_root = work.path().join("source-root");
    let restored_root = work.path().join("restored-root");
    let dump = work.path().join("propolis.dump");
    let archive = work.path().join("propolis-state.tgz");

    // --- The node being backed up -----------------------------------------------------------
    let source = Cluster::start(&bin, work.path().join("source-cluster"), free_port(&[]));
    provision(&source).await;
    let source_url = source.url("propolis", "propolis");
    let pool = connect(&source_url).await;
    migrate(&pool).await;
    populate(&pool, &source_root.join(SPOOL_ROOT)).await;
    assert_eq!(
        core_scoring::verify_chain(&pool)
            .await
            .expect("verify source chain"),
        ChainStatus::Intact,
        "the source ledger must verify before it is backed up"
    );
    let before = snapshot(&source_url).await;
    let empty: Vec<&String> = before
        .tables
        .iter()
        .filter(|(_, t)| t.0 == 0)
        .map(|(n, _)| n)
        .collect();
    assert!(
        empty.is_empty(),
        "every table must hold rows for the rehearsal to test its restore; extend populate() for \
         {empty:?}"
    );
    pool.close().await;

    // --- Backup, as documented ---------------------------------------------------------------
    run(Command::new(bin.join("pg_dump"))
        .arg(PG_DUMP_FORMAT)
        .arg(format!("--file={}", dump.display()))
        .arg(&source_url));
    let inputs = documented_archive_inputs();
    for input in &inputs {
        let dir = source_root.join(input);
        if !dir.exists() {
            // Config and the host key are not part of this dataset; a placeholder keeps every
            // documented input present so tar archives the command exactly as written.
            fs::create_dir_all(&dir).unwrap();
            fs::write(
                dir.join("rehearsal-placeholder"),
                "not real configuration\n",
            )
            .unwrap();
        }
    }
    let source_files = tree(&source_root.join(SPOOL_ROOT));
    run(Command::new("tar")
        .arg(TAR_CREATE)
        .arg(&archive)
        .arg("-C")
        .arg(&source_root)
        .args(&inputs));
    let members = run(Command::new("tar").arg("-tzf").arg(&archive));
    let mut seen = BTreeSet::new();
    let repeated: Vec<&str> = members.lines().filter(|m| !seen.insert(*m)).collect();
    assert!(
        repeated.is_empty(),
        "the documented archive stores these members more than once: {repeated:?}"
    );

    // Lose the node: nothing below may read the source cluster or tree.
    source.stop();
    fs::remove_dir_all(&source.data).unwrap();
    fs::remove_dir_all(&source_root).unwrap();

    // --- Restore into a cluster that has never seen this database ----------------------------
    let target = Cluster::start(
        &bin,
        work.path().join("restored-cluster"),
        free_port(&[source.port]),
    );
    provision(&target).await;
    run(Command::new(bin.join("pg_restore"))
        .arg(PG_RESTORE_STOP_ON_ERROR)
        .arg(format!("--dbname={}", target.url("postgres", "propolis")))
        .arg(&dump));
    fs::create_dir_all(&restored_root).unwrap();
    run(Command::new("tar")
        .arg(TAR_EXTRACT)
        .arg(&archive)
        .arg("-C")
        .arg(&restored_root));

    let target_url = target.url("propolis", "propolis");
    let restored = snapshot(&target_url).await;
    let drift = differences(&before, &restored);
    assert!(
        drift.is_empty(),
        "restored database differs from the source:\n{}",
        drift.join("\n")
    );
    assert_eq!(
        restored.aggregates["event.privileges"].as_deref(),
        Some("DELETE=false,INSERT=true,SELECT=true,TRUNCATE=false,UPDATE=false"),
        "the append-only REVOKE on event must survive the restore"
    );

    // The daemon migrates at startup; against a restored database that must be a no-op.
    let pool = connect(&target_url).await;
    migrate(&pool).await;
    let drift = differences(&before, &snapshot(&target_url).await);
    assert!(
        drift.is_empty(),
        "startup migrations changed the restored database:\n{}",
        drift.join("\n")
    );

    // --- Evidence integrity -----------------------------------------------------------------
    let events_before: i64 = scalar(&pool, "SELECT count(*) FROM event").await;
    assert_eq!(
        core_scoring::verify_chain(&pool)
            .await
            .expect("verify restored chain"),
        ChainStatus::Intact,
        "the restored ledger must verify end to end"
    );
    let sources: Vec<String> =
        sqlx::query_scalar("SELECT host(source_ip) FROM ip_score ORDER BY 1")
            .fetch_all(&pool)
            .await
            .unwrap();
    for ip in &sources {
        let ip: IpAddr = ip.parse().unwrap();
        let stored = core_scoring::repository::read_stored_score(&pool, ip)
            .await
            .unwrap();
        let replayed = core_scoring::rebuild_projection(&pool, ip).await.unwrap();
        assert!(stored.is_some(), "{ip} lost its projection");
        assert_eq!(
            replayed, stored,
            "{ip}: restored projection does not replay from the restored ledger"
        );
    }

    // --- Sequences continue from the restored position --------------------------------------
    let sequences = sequences_cover_their_columns(&pool).await;
    let old_max: i64 = scalar(&pool, "SELECT max(id) FROM event").await;
    let old_head: Vec<u8> = scalar(&pool, "SELECT hash FROM event ORDER BY id DESC LIMIT 1").await;
    core_scoring::append_event(
        &pool,
        EventInput::from_signal(
            attacker(0),
            Some(wan(0)),
            "ssh".into(),
            SignalType::HoneypotCommandExec,
            Protocol::Tcp,
            true,
            "2026-09-28T12:00:00Z".parse().unwrap(),
            r#"{"protocol_label":"ssh","command":"id"}"#.parse().unwrap(),
            None,
        ),
    )
    .await
    .expect("the first append after a restore must succeed");
    let row = sqlx::query("SELECT id, prev_hash FROM event ORDER BY id DESC LIMIT 1")
        .fetch_one(&pool)
        .await
        .unwrap();
    let (new_id, new_prev): (i64, Option<Vec<u8>>) = (row.get("id"), row.get("prev_hash"));
    assert!(
        new_id > old_max,
        "event id {new_id} does not continue past the restored {old_max}"
    );
    assert_eq!(
        new_prev.as_deref(),
        Some(old_head.as_slice()),
        "the new event must chain onto the restored head"
    );
    assert_eq!(
        core_scoring::verify_chain(&pool).await.unwrap(),
        ChainStatus::Intact,
        "the ledger must still verify after a post-restore append"
    );
    let vendor_max: i64 = scalar(&pool, "SELECT max(id) FROM vendor_submission").await;
    let vendor_id: i64 = sqlx::query_scalar(
        "INSERT INTO vendor_submission (source_ip, vendor, idempotency_key, categories, comment) \
         VALUES ('203.0.113.10', 'abuseipdb', 'post-restore', ARRAY['18'], 'post-restore') RETURNING id",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert!(
        vendor_id > vendor_max,
        "vendor_submission id {vendor_id} collides with the restored range"
    );

    // The linkage trigger and the REVOKE came back as enforcement, not just as catalog rows.
    let forged = sqlx::query(
        "INSERT INTO event (source_ip, sensor, signal_type, protocol, authenticated, category, \
         weight, confidence, observed_at, prev_hash, hash) \
         VALUES ('203.0.113.99', 'ssh', 'honeypot_connection', 'tcp', false, 'honeypot', 40, 0.9, \
         now(), $1, $1)",
    )
    .bind(vec![0u8; 32])
    .execute(&pool)
    .await
    .expect_err("an event with a forged prev_hash must be refused");
    assert!(
        forged
            .to_string()
            .contains("prev_hash does not match chain head"),
        "{forged}"
    );
    let rewrite = sqlx::query("UPDATE event SET sensor = sensor WHERE id = 1")
        .execute(&pool)
        .await
        .expect_err("the daemon role must not be able to rewrite the ledger");
    assert!(
        rewrite.to_string().contains("permission denied"),
        "{rewrite}"
    );

    // --- Sample custody ----------------------------------------------------------------------
    let spool = restored_root.join(SPOOL_ROOT);
    let restored_files = tree(&spool);
    assert_eq!(
        restored_files, source_files,
        "the restored spool tree differs from the source"
    );
    for (path, (_, mode)) in &restored_files {
        assert_eq!(
            mode & 0o777,
            0o640,
            "{path} came back as {mode:o}, not 0640"
        );
    }
    let event_refs = sqlx::query(
        "SELECT sensor, metadata->>'sample_sha256' AS sha, (metadata->>'sample_size')::bigint AS size \
         FROM event WHERE metadata ? 'sample_sha256'",
    )
    .fetch_all(&pool)
    .await
    .unwrap();
    for row in &event_refs {
        let (sensor, sha, size): (String, String, i64) =
            (row.get("sensor"), row.get("sha"), row.get("size"));
        let body =
            sensor_framework::spool::read_verified(&spool.join(&sensor), &sha, MAX_SAMPLE_BYTES)
                .unwrap_or_else(|e| panic!("event sample {sha} from {sensor}: {e}"));
        assert_eq!(
            body.len() as i64,
            size,
            "event sample {sha} restored at the wrong size"
        );
    }
    let fetch_refs = sqlx::query(
        "SELECT encode(sha256, 'hex') AS sha, bytes FROM fetch_attempt WHERE sha256 IS NOT NULL",
    )
    .fetch_all(&pool)
    .await
    .unwrap();
    for row in &fetch_refs {
        let (sha, bytes): (String, i32) = (row.get("sha"), row.get("bytes"));
        let body =
            sensor_framework::spool::read_verified(&spool.join("fetched"), &sha, MAX_SAMPLE_BYTES)
                .unwrap_or_else(|e| panic!("fetched sample {sha}: {e}"));
        assert_eq!(
            body.len() as i64,
            i64::from(bytes),
            "fetched sample {sha} restored at the wrong size"
        );
    }
    let verdicts: Vec<(String, String)> =
        sqlx::query_as("SELECT sha256, source_sensor FROM sample_analysis")
            .fetch_all(&pool)
            .await
            .unwrap();
    for (sha, sensor) in &verdicts {
        sensor_framework::spool::read_verified(&spool.join(sensor), sha, MAX_SAMPLE_BYTES)
            .unwrap_or_else(|e| {
                panic!("sample_analysis row {sha} ({sensor}) has no restored body: {e}")
            });
    }
    assert!(!event_refs.is_empty() && !fetch_refs.is_empty() && !verdicts.is_empty());
    pool.close().await;

    // --- Record ------------------------------------------------------------------------------
    let distinct_event_samples: BTreeSet<String> =
        event_refs.iter().map(|r| r.get("sha")).collect();
    println!(
        "restore rehearsal: {}",
        Utc::now().format("%Y-%m-%d %H:%M UTC")
    );
    println!("tools: {}; {}", server_version.trim(), dump_version.trim());
    println!(
        "target: fresh cluster (initdb) on 127.0.0.1:{}; source cluster on :{} stopped and its data \
         directory and spool tree deleted before the restore",
        target.port, source.port
    );
    println!(
        "dump: {} bytes custom format; archive: {} bytes, {} members, none repeated",
        fs::metadata(&dump).unwrap().len(),
        fs::metadata(&archive).unwrap().len(),
        members.lines().count()
    );
    println!("tables compared (rows, digest of every row):");
    for (table, (rows, _)) in &before.tables {
        println!("  {table}: {rows}");
    }
    println!("aggregates compared:");
    for (name, value) in &before.aggregates {
        let value = value.as_deref().unwrap_or("NULL");
        if !name.starts_with("schema.") {
            println!("  {name}: {value}");
        }
    }
    println!("  schema.*: indexes, constraints, enum labels, triggers, functions (digests equal)");
    println!("sequences compared: {sequences:?}");
    println!(
        "chain: verify_chain Intact over {events_before} restored events; Intact again after a \
         post-restore append (id {new_id}, prev_hash = restored head)"
    );
    println!(
        "replay: {} projections rebuilt from the restored ledger equal their stored rows",
        sources.len()
    );
    println!(
        "samples: {} spool files restored at 0640 and identical to the source; {} event references \
         ({} distinct), {} fetch_attempt references and {} sample_analysis rows re-hash to their names",
        restored_files.len(),
        event_refs.len(),
        distinct_event_samples.len(),
        fetch_refs.len(),
        verdicts.len()
    );
}

// ---------------------------------------------------------------------------------------------
// Dataset
// ---------------------------------------------------------------------------------------------

/// One step of an attacker's interaction: sensor, signal, protocol, authenticated, protocol label.
type Step = (&'static str, SignalType, Protocol, bool, &'static str);

/// Cycled with a per-address offset so sources interleave different sensors, signals and
/// protocols, and every address reaches the authenticated TCP honeypot events that make it
/// eligible for review.
const PATTERN: [Step; 14] = {
    use Protocol::{Icmp, Tcp, Udp};
    use SignalType::*;
    [
        ("ssh", HoneypotConnection, Tcp, false, "ssh"),
        ("ssh", HoneypotLoginAttempt, Tcp, true, "ssh"),
        ("ssh", HoneypotCommandExec, Tcp, true, "ssh"),
        ("ssh", HoneypotMalwareUpload, Tcp, true, "ssh"),
        ("ssh", HoneypotFileDownload, Tcp, true, "ssh"),
        ("telnet", HoneypotLoginAttempt, Tcp, true, "telnet"),
        ("telnet", HoneypotMalwareUpload, Tcp, true, "telnet"),
        ("catchall", CatchallProbe, Udp, false, "sip"),
        ("suricata", SuricataSev2, Tcp, false, ""),
        ("suricata", SynFlood, Tcp, false, ""),
        ("http", WafSqliXss, Tcp, false, "http"),
        ("firewall", PortScan, Tcp, false, ""),
        ("firewall", BlockedConnection, Icmp, false, ""),
        ("sshd", SshBruteForce, Tcp, false, "ssh"),
    ]
};

const ATTACKERS: usize = 16;
const ROUNDS: usize = 24;

/// Payload URLs the file-download events cite. Several addresses cite the same URL, as botnets
/// do, so `fetch_attempt` dedups them to one row each.
const URLS: [&str; 6] = [
    "http://dl1.example.net/bins/x86",
    "http://dl1.example.net/bins/arm7",
    "http://dl2.example.net/bins/mips",
    "https://cdn.example.org/a.sh",
    "http://dl3.example.net:8080/b",
    "tftp://192.0.2.77/mipsel",
];

/// Documentation-range addresses only (RFC 5737, RFC 3849).
fn attacker(i: usize) -> IpAddr {
    match i % 3 {
        0 => format!("203.0.113.{}", 10 + i),
        1 => format!("198.51.100.{}", 10 + i),
        _ => format!("2001:db8:bad::{}", 10 + i),
    }
    .parse()
    .unwrap()
}

fn wan(i: usize) -> IpAddr {
    format!("192.0.2.{}", 1 + i % 2).parse().unwrap()
}

async fn populate(pool: &PgPool, spool_root: &Path) {
    let spool = |name: &str| {
        let dir = spool_root.join(name);
        fs::create_dir_all(&dir).unwrap();
        QuarantineSpool::new(dir, 1_000_000, 100_000_000)
    };
    let (ssh, telnet, fetched) = (spool("ssh"), spool("telnet"), spool("fetched"));
    let base: DateTime<Utc> = "2026-09-20T00:00:00Z".parse().unwrap();

    let mut uploads = 0usize;
    let mut downloads = 0usize;
    for round in 0..ROUNDS {
        for i in 0..ATTACKERS {
            // Uneven lengths, 14 to 24 events per address.
            if round >= 14 + i % 11 {
                continue;
            }
            let (sensor, signal, protocol, authenticated, label) =
                PATTERN[(round + i) % PATTERN.len()];
            // A new UTC day every eighth round, so active_days varies; rounds are minutes apart,
            // so the dedup window both applies and does not.
            let observed_at = base
                + Duration::days((round / 8) as i64)
                + Duration::seconds((round * 190 + i * 7) as i64);
            let session =
                sensor_framework::Uuid::from_u128(((i as u128) << 64) | (round / 4) as u128);
            let mut fields = vec![format!(r#""rehearsal_round":{round}"#)];
            if !label.is_empty() {
                fields.push(format!(r#""protocol_label":"{label}""#));
            }
            match signal {
                SignalType::HoneypotCommandExec => fields.push(r#""command":"uname -a""#.into()),
                SignalType::HoneypotFileDownload => {
                    fields.push(format!(r#""url":"{}""#, URLS[downloads % URLS.len()]));
                    downloads += 1;
                }
                _ => {}
            }
            let mut event = EventInput::from_signal(
                attacker(i),
                (sensor != "suricata").then(|| wan(i)),
                sensor.into(),
                signal,
                protocol,
                authenticated,
                observed_at,
                format!("{{{}}}", fields.join(",")).parse().unwrap(),
                Some(session),
            );
            if signal == SignalType::HoneypotMalwareUpload {
                // Nine distinct bodies across more uploads than that: repeats dedup to one file.
                let variant = uploads % 9;
                uploads += 1;
                let body = format!("#!/bin/sh\n# restore rehearsal sample {variant}\n")
                    + &"echo rehearsal\n".repeat(16 * (variant + 1));
                let target = if sensor == "telnet" { &telnet } else { &ssh };
                let sample = target.store(body.as_bytes()).expect("spool a sample body");
                event.metadata =
                    intake::converter::fold_sample_metadata(event.metadata, Some(sample));
            }
            core_scoring::append_event(pool, event)
                .await
                .expect("append event");

            if round % 5 == 4 {
                core_scoring::append_telemetry_event(
                    pool,
                    EventInput::from_signal(
                        attacker(i),
                        Some(wan(i)),
                        "ssh".into(),
                        SignalType::HoneypotSessionEnd,
                        Protocol::Tcp,
                        false,
                        observed_at + Duration::seconds(30),
                        format!(
                            r#"{{"reason":"client_closed","elapsed_ms":{}}}"#,
                            900 + round * 40
                        )
                        .parse()
                        .unwrap(),
                        Some(session),
                    ),
                )
                .await
                .expect("append telemetry");
            }
        }
    }

    // Review queue through its own state machine.
    let queue = review::ReviewQueue::new();
    queue.populate(pool).await.expect("populate review queue");
    let pending = queue.list_pending(pool).await.unwrap();
    assert!(
        pending.len() >= 4,
        "dataset surfaced only {} review entries",
        pending.len()
    );
    let approved = pending[0].source_ip;
    queue
        .approve(pool, approved, Some("confirmed dropper"))
        .await
        .unwrap();
    queue
        .reject(pool, pending[1].source_ip, Some("scanner of a partner"))
        .await
        .unwrap();
    queue
        .snooze(pool, pending[2].source_ip, Some("waiting on more evidence"))
        .await
        .unwrap();

    // Vendor submissions: written directly because the submission runner's gatekeeper refuses
    // every documentation-range address, which is all this dataset uses. Columns and key shape
    // follow review::submit.
    let day = "2026-09-22";
    for (vendor, categories, status, body, success) in [
        (
            "abuseipdb",
            vec!["18", "22"],
            Some(200),
            Some(r#"{"data":{"abuseConfidenceScore":100}}"#),
            true,
        ),
        (
            "dshield",
            vec!["ssh"],
            Some(503),
            Some("service unavailable"),
            false,
        ),
        ("otx", vec!["ssh-bruteforce"], None, None, false),
    ] {
        sqlx::query(
            "INSERT INTO vendor_submission (source_ip, vendor, idempotency_key, categories, comment, \
             submitted_at, response_status, response_body, success) \
             VALUES ($1::inet, $2, $3, $4, $5, $6, $7, $8, $9)",
        )
        .bind(approved.to_string())
        .bind(vendor)
        .bind(format!("{approved}:{vendor}:{day}"))
        .bind(categories.iter().map(|c| c.to_string()).collect::<Vec<_>>())
        .bind(format!("propolis: {approved} - rehearsal report"))
        .bind(format!("{day}T09:00:00Z").parse::<DateTime<Utc>>().unwrap())
        .bind(status)
        .bind(body)
        .bind(success)
        .execute(pool)
        .await
        .unwrap();
    }

    // Fetcher state through its own store: sync and claim the cited URLs, then record a spread
    // of outcomes. The last outcome class is left claimed, as a crash mid-cycle would.
    let claim = claim_candidates(
        pool,
        ClaimLimits {
            batch: 50,
            per_host_hour: 50,
            daily_cap: 500,
            lease: StdDuration::from_secs(600),
        },
    )
    .await
    .expect("claim fetch candidates");
    assert!(
        claim.candidates.len() >= 4,
        "only {} fetch candidates",
        claim.candidates.len()
    );
    for (n, candidate) in claim.candidates.iter().enumerate() {
        let mut attempt = attempt_from(candidate);
        match n % 4 {
            0 => {
                let body = format!(
                    "#!/bin/sh\n# fetched from {}\ncd /tmp && ./x\n",
                    candidate.url
                );
                let sample = fetched
                    .store(body.as_bytes())
                    .expect("spool a fetched body");
                attempt.status = FetchStatus::Success;
                attempt.sha256 = Some(hex::decode(&sample.sha256).unwrap());
                attempt.bytes = Some(body.len() as i32);
                attempt.content_type = Some("text/x-shellscript".into());
                // Both non-default custody states, so the restore carries the error column too.
                attempt.transport_auth = Some(if n == 0 {
                    TransportAuth::Unverified {
                        error: "invalid peer certificate: UnknownIssuer".into(),
                    }
                } else {
                    TransportAuth::Plaintext
                });
                if n == 0 {
                    let child = "http://dl9.example.net/stage2";
                    let (scheme, host, port) = parse_url_parts(child).unwrap();
                    insert_pending_if_absent(
                        pool,
                        &NewPendingRow {
                            url_hash: url_hash(child),
                            url: child.into(),
                            host,
                            scheme,
                            port,
                            source_ip: candidate.source_ip,
                            parent_hash: Some(candidate.url_hash.clone()),
                            depth: candidate.depth + 1,
                        },
                    )
                    .await
                    .unwrap();
                }
            }
            1 => {
                attempt.status = FetchStatus::Rejected;
                attempt.reject_reason = Some("resolved_to_reserved".into());
                attempt.next_attempt = Some(base + Duration::days(4));
            }
            2 => {
                attempt.status = FetchStatus::Timeout;
                attempt.next_attempt = Some(base + Duration::days(4));
            }
            _ => continue,
        }
        upsert_attempt(pool, &attempt)
            .await
            .expect("record fetch outcome");
    }

    // Verdicts: written directly, since the VirusTotal path writes them only from a live lookup.
    // Statement and the -1/-1 pending contract follow review::virustotal.
    let mut verdicts: Vec<(String, &str, i32, i32)> = Vec::new();
    // One row per digest: the same body can arrive through both sensors.
    let shas: Vec<(String, String)> = sqlx::query_as(
        "SELECT metadata->>'sample_sha256', min(sensor) FROM event \
         WHERE metadata ? 'sample_sha256' GROUP BY 1 ORDER BY 1 LIMIT 3",
    )
    .fetch_all(pool)
    .await
    .unwrap();
    for (n, (sha, sensor)) in shas.into_iter().enumerate() {
        verdicts.push((
            sha,
            if sensor == "telnet" { "telnet" } else { "ssh" },
            41 - n as i32 * 20,
            67,
        ));
    }
    let fetched_sha: String =
        scalar(pool, "SELECT min(encode(sha256, 'hex')) FROM fetch_attempt").await;
    verdicts.push((fetched_sha, "fetched", -1, -1));
    for (sha, sensor, detected, total) in verdicts {
        sqlx::query(
            "INSERT INTO sample_analysis (sha256, detected, total, vt_link, source_sensor, analyzed_at) \
             VALUES ($1, $2, $3, $4, $5, $6)",
        )
        .bind(&sha)
        .bind(detected)
        .bind(total)
        .bind(format!("https://www.virustotal.com/gui/file/{sha}"))
        .bind(sensor)
        .bind(base + Duration::days(3))
        .execute(pool)
        .await
        .unwrap();
    }

    // Fleet probe results through the prober's and intake's own writers.
    let probed_at = base + Duration::days(3);
    for (sensor, protocol, port, outcome) in [
        ("ssh", fleet::Proto::Tcp, 22, fleet::ProbeOutcome::Reachable),
        (
            "telnet",
            fleet::Proto::Tcp,
            23,
            fleet::ProbeOutcome::Refused,
        ),
        (
            "catchall",
            fleet::Proto::Udp,
            5060,
            fleet::ProbeOutcome::NotProbeable,
        ),
    ] {
        fleet::store::upsert_probe(
            pool,
            &fleet::ProbeRecord {
                listener: fleet::Listener {
                    collector_id: "node-a".into(),
                    sensor: sensor.into(),
                    protocol,
                    port,
                },
                target: format!("192.0.2.1:{port}"),
                attempted_at: probed_at,
                outcome,
                detail: None,
                latency_ms: Some(3),
            },
        )
        .await
        .unwrap();
    }
    fleet::store::confirm_sensor(
        pool,
        "ssh",
        probed_at + Duration::seconds(5),
        StdDuration::from_secs(600),
    )
    .await
    .unwrap();
}

fn attempt_from(c: &Candidate) -> AttemptResult {
    AttemptResult {
        url_hash: c.url_hash.clone(),
        url: c.url.clone(),
        host: c.host.clone(),
        scheme: c.scheme.clone(),
        port: c.port,
        source_ip: c.source_ip,
        parent_hash: c.parent_hash.clone(),
        depth: c.depth,
        status: FetchStatus::Pending,
        reject_reason: None,
        sha256: None,
        bytes: None,
        content_type: None,
        pinned_ip: Some("192.0.2.80".into()),
        attempts: c.attempts + 1,
        next_attempt: None,
        transport_auth: None,
    }
}

// ---------------------------------------------------------------------------------------------
// Comparison
// ---------------------------------------------------------------------------------------------

/// What must survive a restore unchanged, each value exactly as PostgreSQL renders it.
#[derive(Debug, PartialEq)]
struct Snapshot {
    /// Every table in `public`: row count and an md5 over every row's text form, sorted.
    tables: BTreeMap<String, (i64, String)>,
    aggregates: BTreeMap<&'static str, Option<String>>,
    /// Every sequence's `last_value`.
    sequences: BTreeMap<String, Option<i64>>,
}

/// Named figures an operator would check by hand after a restore, plus schema-object digests
/// that catch a partially restored schema the row digests cannot see.
const AGGREGATES: &[(&str, &str)] = &[
    ("event.max_id", "SELECT max(id)::text FROM event"),
    (
        "event.head_hash",
        "SELECT encode(hash, 'hex') FROM event ORDER BY id DESC LIMIT 1",
    ),
    ("event.sum_weight", "SELECT sum(weight)::text FROM event"),
    (
        "event.sources",
        "SELECT count(DISTINCT source_ip)::text FROM event",
    ),
    (
        "event.sensors",
        "SELECT count(DISTINCT sensor)::text FROM event",
    ),
    (
        "event.sample_refs",
        "SELECT count(*)::text FROM event WHERE metadata ? 'sample_sha256'",
    ),
    (
        "event.by_signal",
        "SELECT string_agg(k || '=' || n, ',' ORDER BY k) \
         FROM (SELECT signal_type::text AS k, count(*) AS n FROM event GROUP BY 1) s",
    ),
    (
        "ip_score.sum_raw_score",
        "SELECT sum(raw_score)::text FROM ip_score",
    ),
    (
        "ip_score.sum_event_count",
        "SELECT sum(event_count)::text FROM ip_score",
    ),
    (
        "ip_score.sum_established_event_count",
        "SELECT sum(established_event_count)::text FROM ip_score",
    ),
    (
        "ip_score.sum_active_days",
        "SELECT sum(active_days)::text FROM ip_score",
    ),
    (
        "ip_score.eligible",
        "SELECT count(*) FILTER (WHERE eligible)::text FROM ip_score",
    ),
    (
        "ip_score.recommended_for_vendor",
        "SELECT count(*) FILTER (WHERE recommended_for_vendor)::text FROM ip_score",
    ),
    (
        "ip_score.by_tier",
        "SELECT string_agg(k || '=' || n, ',' ORDER BY k) \
         FROM (SELECT coalesce(tier::text, 'none') AS k, count(*) AS n FROM ip_score GROUP BY 1) s",
    ),
    (
        "review_queue.by_state",
        "SELECT string_agg(k || '=' || n, ',' ORDER BY k) \
         FROM (SELECT state::text AS k, count(*) AS n FROM review_queue GROUP BY 1) s",
    ),
    (
        "fetch_attempt.by_status",
        "SELECT string_agg(k || '=' || n, ',' ORDER BY k) \
         FROM (SELECT status AS k, count(*) AS n FROM fetch_attempt GROUP BY 1) s",
    ),
    (
        "fetch_attempt.captured",
        "SELECT count(sha256)::text FROM fetch_attempt",
    ),
    (
        "fetch_attempt.claimed",
        "SELECT count(claim_expires)::text FROM fetch_attempt",
    ),
    (
        "vendor_submission.succeeded",
        "SELECT count(*) FILTER (WHERE success)::text FROM vendor_submission",
    ),
    (
        "event.privileges",
        "SELECT string_agg(p || '=' || has_table_privilege('propolis', 'public.event', p), ',' ORDER BY p) \
         FROM unnest(ARRAY['SELECT', 'INSERT', 'UPDATE', 'DELETE', 'TRUNCATE']) AS p",
    ),
    (
        "schema.indexes",
        "SELECT md5(string_agg(indexdef, E'\\n' ORDER BY indexdef)) FROM pg_indexes \
         WHERE schemaname = 'public'",
    ),
    (
        "schema.constraints",
        "SELECT md5(string_agg(conrelid::regclass::text || ' ' || conname || ' ' || \
         pg_get_constraintdef(oid), E'\\n' ORDER BY conrelid::regclass::text, conname)) \
         FROM pg_constraint WHERE connamespace = 'public'::regnamespace",
    ),
    (
        "schema.enums",
        "SELECT md5(string_agg(t.typname || ':' || e.enumlabel, ',' ORDER BY t.typname, e.enumsortorder)) \
         FROM pg_enum e JOIN pg_type t ON t.oid = e.enumtypid",
    ),
    (
        "schema.triggers",
        "SELECT string_agg(tgrelid::regclass::text || ':' || tgname || ':' || tgenabled::text, ',' \
         ORDER BY tgrelid::regclass::text, tgname) FROM pg_trigger WHERE NOT tgisinternal",
    ),
    (
        "schema.functions",
        "SELECT md5(string_agg(proname || ':' || prosrc, E'\\n' ORDER BY proname)) FROM pg_proc \
         WHERE pronamespace = 'public'::regnamespace",
    ),
];

async fn snapshot(url: &str) -> Snapshot {
    let mut conn = PgConnection::connect(url)
        .await
        .expect("connect for snapshot");
    // Row digests hash timestamps as text, which follows the session time zone.
    sqlx::query("SET TIME ZONE 'UTC'")
        .execute(&mut conn)
        .await
        .unwrap();

    let mut tables = BTreeMap::new();
    let names: Vec<String> = sqlx::query_scalar(
        "SELECT tablename::text FROM pg_tables WHERE schemaname = 'public' ORDER BY 1",
    )
    .fetch_all(&mut conn)
    .await
    .unwrap();
    for name in names {
        let row = sqlx::query(sqlx::AssertSqlSafe(format!(
            "SELECT count(*) AS n, md5(coalesce(string_agg(t::text, E'\\n' ORDER BY t::text), '')) AS digest \
             FROM public.{} t",
            quote_ident(&name)
        )))
        .fetch_one(&mut conn)
        .await
        .unwrap();
        tables.insert(name, (row.get("n"), row.get("digest")));
    }

    let mut aggregates = BTreeMap::new();
    for (name, sql) in AGGREGATES {
        let value: Option<Option<String>> = sqlx::query_scalar(*sql)
            .fetch_optional(&mut conn)
            .await
            .unwrap();
        aggregates.insert(*name, value.flatten());
    }

    let sequences = sqlx::query_as::<_, (String, Option<i64>)>(
        "SELECT schemaname || '.' || sequencename, last_value FROM pg_sequences ORDER BY 1",
    )
    .fetch_all(&mut conn)
    .await
    .unwrap()
    .into_iter()
    .collect();

    conn.close().await.unwrap();
    Snapshot {
        tables,
        aggregates,
        sequences,
    }
}

fn differences(a: &Snapshot, b: &Snapshot) -> Vec<String> {
    fn diff<K: Ord + std::fmt::Debug, V: PartialEq + std::fmt::Debug>(
        what: &str,
        a: &BTreeMap<K, V>,
        b: &BTreeMap<K, V>,
        out: &mut Vec<String>,
    ) {
        let keys: BTreeSet<&K> = a.keys().chain(b.keys()).collect();
        for key in keys {
            if a.get(key) != b.get(key) {
                out.push(format!(
                    "{what} {key:?}: source {:?}, restored {:?}",
                    a.get(key),
                    b.get(key)
                ));
            }
        }
    }
    let mut out = Vec::new();
    diff("table", &a.tables, &b.tables, &mut out);
    diff("aggregate", &a.aggregates, &b.aggregates, &mut out);
    diff("sequence", &a.sequences, &b.sequences, &mut out);
    out
}

/// Every sequence-owned column's maximum must sit at or below its sequence's `last_value`, or the
/// next insert collides with a restored row. Returns `sequence >= max(column)` for the record.
async fn sequences_cover_their_columns(pool: &PgPool) -> Vec<String> {
    let owned = sqlx::query_as::<_, (String, String, String)>(
        "SELECT s.relname::text, t.relname::text, a.attname::text \
         FROM pg_class s \
         JOIN pg_depend d ON d.objid = s.oid AND d.classid = 'pg_class'::regclass \
              AND d.refclassid = 'pg_class'::regclass AND d.deptype IN ('a', 'i') \
         JOIN pg_class t ON t.oid = d.refobjid \
         JOIN pg_attribute a ON a.attrelid = t.oid AND a.attnum = d.refobjsubid \
         WHERE s.relkind = 'S' ORDER BY 1",
    )
    .fetch_all(pool)
    .await
    .unwrap();
    assert!(
        !owned.is_empty(),
        "no sequence-owned columns found; the catalog query is wrong"
    );
    let mut record = Vec::new();
    for (sequence, table, column) in owned {
        let last: i64 = scalar(
            pool,
            &format!("SELECT last_value FROM public.{}", quote_ident(&sequence)),
        )
        .await;
        let max: i64 = scalar(
            pool,
            &format!(
                "SELECT coalesce(max({}), 0)::bigint FROM public.{}",
                quote_ident(&column),
                quote_ident(&table)
            ),
        )
        .await;
        assert!(
            last >= max,
            "{sequence} is at {last} but {table}.{column} already holds {max}"
        );
        record.push(format!("{sequence}={last}>={table}.{column}={max}"));
    }
    record
}

// ---------------------------------------------------------------------------------------------
// Clusters, commands, files
// ---------------------------------------------------------------------------------------------

/// A throwaway PostgreSQL cluster: its own data directory, TCP on loopback only, trust auth.
/// Stopped on drop, so a failed assertion does not leave a postmaster running.
struct Cluster {
    pg_ctl: PathBuf,
    data: PathBuf,
    port: u16,
}

impl Cluster {
    fn start(bin: &Path, data: PathBuf, port: u16) -> Cluster {
        run(Command::new(bin.join("initdb")).arg("-D").arg(&data).args([
            "-U",
            "postgres",
            "--auth=trust",
            "--encoding=UTF8",
            "--locale=C",
            "--no-sync",
        ]));
        // No Unix socket: a data directory under target/ can exceed the socket path length
        // limit, and loopback TCP is all the rehearsal needs.
        let mut conf = fs::OpenOptions::new()
            .append(true)
            .open(data.join("postgresql.conf"))
            .unwrap();
        writeln!(
            conf,
            "port = {port}\nlisten_addresses = '127.0.0.1'\nunix_socket_directories = ''"
        )
        .unwrap();
        let cluster = Cluster {
            pg_ctl: bin.join("pg_ctl"),
            data,
            port,
        };
        run(Command::new(&cluster.pg_ctl)
            .arg("-D")
            .arg(&cluster.data)
            .arg("-l")
            .arg(cluster.data.with_extension("log"))
            .args(["-w", "-t", "60", "start"]));
        cluster
    }

    fn url(&self, user: &str, database: &str) -> String {
        format!("postgresql://{user}@127.0.0.1:{}/{database}", self.port)
    }

    fn stop(&self) {
        let _ = Command::new(&self.pg_ctl)
            .arg("-D")
            .arg(&self.data)
            .args(["-m", "fast", "-w", "stop"])
            .output();
    }
}

impl Drop for Cluster {
    fn drop(&mut self) {
        self.stop();
    }
}

/// The production shape the daemon expects: a `propolis` login role owning a `propolis`
/// database. Migration 0004 revokes ledger mutation from that role only under exactly these
/// names, and `pg_dump` records ownership and grants but not roles, so the target needs the role
/// before the dump can be restored as it was taken.
async fn provision(cluster: &Cluster) {
    let mut admin = PgConnection::connect(&cluster.url("postgres", "postgres"))
        .await
        .expect("connect as superuser");
    sqlx::query("CREATE ROLE propolis LOGIN")
        .execute(&mut admin)
        .await
        .unwrap();
    sqlx::query("CREATE DATABASE propolis OWNER propolis TEMPLATE template0")
        .execute(&mut admin)
        .await
        .unwrap();
    admin.close().await.unwrap();
}

async fn connect(url: &str) -> PgPool {
    PgPoolOptions::new()
        .max_connections(4)
        .connect(url)
        .await
        .expect("connect as the daemon role")
}

/// The daemon's startup order (`crates/propolis/src/main.rs`).
async fn migrate(pool: &PgPool) {
    sqlx::migrate!("../core-scoring/migrations")
        .run(pool)
        .await
        .unwrap();
    review::migrator().run(pool).await.unwrap();
    fleet::migrator().run(pool).await.unwrap();
}

async fn scalar<T>(pool: &PgPool, sql: &str) -> T
where
    T: for<'r> sqlx::Decode<'r, sqlx::Postgres> + sqlx::Type<sqlx::Postgres> + Send + Unpin,
{
    sqlx::query_scalar(sqlx::AssertSqlSafe(sql.to_string()))
        .fetch_one(pool)
        .await
        .unwrap_or_else(|e| panic!("{sql}: {e}"))
}

fn quote_ident(name: &str) -> String {
    format!("\"{}\"", name.replace('"', "\"\""))
}

/// The input paths of the backup page's archive command, relative to `/`.
fn documented_archive_inputs() -> Vec<PathBuf> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let doc = fs::read_to_string(root.join(BACKUP_DOC)).expect("backup page");
    let commands = doc_commands::tar_create_inputs(&doc);
    assert_eq!(
        commands.len(),
        1,
        "expected one archive command in {BACKUP_DOC}, found {commands:?}"
    );
    let inputs: Vec<PathBuf> = commands[0]
        .iter()
        .map(|p| {
            Path::new(p)
                .strip_prefix("/")
                .unwrap_or_else(|_| panic!("{BACKUP_DOC} archives {p}, which is not absolute"))
                .to_path_buf()
        })
        .collect();
    assert!(
        inputs.iter().any(|p| Path::new(SPOOL_ROOT).starts_with(p)),
        "{BACKUP_DOC}'s archive command no longer covers /{SPOOL_ROOT}"
    );
    inputs
}

/// Regular files under `dir` by relative path, with size and mode.
fn tree(dir: &Path) -> BTreeMap<String, (u64, u32)> {
    fn walk(dir: &Path, root: &Path, out: &mut BTreeMap<String, (u64, u32)>) {
        for entry in fs::read_dir(dir).unwrap().flatten() {
            let path = entry.path();
            let meta = entry.metadata().unwrap();
            if meta.is_dir() {
                walk(&path, root, out);
            } else {
                let rel = path.strip_prefix(root).unwrap().display().to_string();
                out.insert(rel, (meta.len(), meta.permissions().mode()));
            }
        }
    }
    let mut out = BTreeMap::new();
    walk(dir, dir, &mut out);
    out
}

/// Runs `command`, failing with its output if it exits non-zero; returns stdout.
fn run(command: &mut Command) -> String {
    let output = command
        .output()
        .unwrap_or_else(|e| panic!("could not run {command:?}: {e}"));
    assert!(
        output.status.success(),
        "{command:?} failed ({}):\n{}{}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout).into_owned()
}

/// Fails rather than skips when unset: the test only runs when asked for, and a rehearsal that
/// passes without restoring anything would be recorded as one that worked.
fn pg_bin() -> PathBuf {
    let Some(dir) = std::env::var_os(PG_BIN_VAR) else {
        panic!(
            "{PG_BIN_VAR} is not set. The rehearsal starts two scratch PostgreSQL clusters and needs \
             initdb, pg_ctl and postgres plus pg_dump and pg_restore of the same major version, \
             e.g. {PG_BIN_VAR}=/usr/lib/postgresql/18/bin. See {BACKUP_DOC}."
        );
    };
    let dir = PathBuf::from(dir);
    for tool in ["initdb", "pg_ctl", "postgres", "pg_dump", "pg_restore"] {
        assert!(
            dir.join(tool).is_file(),
            "{PG_BIN_VAR}={} has no {tool}",
            dir.display()
        );
    }
    dir
}

/// A free loopback port in 56001-56999. A fixed band keeps the rehearsal's postmasters easy to
/// spot (`ss -ltnp`) if a killed run ever leaves one behind.
fn free_port(taken: &[u16]) -> u16 {
    let offset = (std::process::id() % 999) as u16;
    (0..999u16)
        .map(|n| 56001 + (offset + n) % 999)
        .find(|p| !taken.contains(p) && std::net::TcpListener::bind(("127.0.0.1", *p)).is_ok())
        .expect("no free loopback port in 56001-56999")
}
