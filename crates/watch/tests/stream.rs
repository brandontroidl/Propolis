//! The real binary against real files: what it streams, in what order, how it refuses bad
//! arguments, and that it leaves the log directory exactly as it found it.

use std::collections::BTreeMap;
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc::{self, Receiver};
use std::time::{Duration, Instant, SystemTime};

use serde_json::Value;

const BIN: &str = env!("CARGO_BIN_EXE_propolis-watch");
const WAIT: Duration = Duration::from_secs(10);

struct Watcher {
    child: Child,
    records: Receiver<Value>,
}

impl Drop for Watcher {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn command(logs: &str) -> Command {
    let mut cmd = Command::new(BIN);
    cmd.env("PROPOLIS_SENSOR_LOGS", logs)
        .env_remove("SSH_ORIGINAL_COMMAND")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    cmd
}

fn start(mut cmd: Command) -> Watcher {
    let mut child = cmd.spawn().unwrap();
    let stdout = child.stdout.take().unwrap();
    let (tx, records) = mpsc::channel();
    std::thread::spawn(move || {
        for line in BufReader::new(stdout).lines() {
            let Ok(line) = line else { return };
            let record: Value = serde_json::from_str(&line)
                .unwrap_or_else(|e| panic!("not one JSON object per line ({e}): {line}"));
            if tx.send(record).is_err() {
                return;
            }
        }
    });
    Watcher { child, records }
}

impl Watcher {
    /// The next record that is not a heartbeat.
    fn next(&self) -> Value {
        let deadline = Instant::now() + WAIT;
        loop {
            let left = deadline.saturating_duration_since(Instant::now());
            let record = self
                .records
                .recv_timeout(left)
                .expect("a record within the deadline");
            if record["kind"] != "heartbeat" {
                return record;
            }
        }
    }

    fn next_heartbeat(&self) -> Value {
        let deadline = Instant::now() + WAIT + WAIT;
        loop {
            let left = deadline.saturating_duration_since(Instant::now());
            let record = self.records.recv_timeout(left).expect("a heartbeat");
            if record["kind"] == "heartbeat" {
                return record;
            }
        }
    }

    /// Asserts nothing but heartbeats arrives for `quiet`.
    fn assert_quiet(&self, quiet: Duration) {
        let deadline = Instant::now() + quiet;
        while let Some(left) = deadline.checked_duration_since(Instant::now()) {
            match self.records.recv_timeout(left) {
                Ok(r) if r["kind"] == "heartbeat" => {}
                Ok(r) => panic!("unexpected record {r}"),
                Err(_) => return,
            }
        }
    }
}

fn append(path: &Path, text: &str) {
    let mut f = std::fs::OpenOptions::new()
        .append(true)
        .create(true)
        .open(path)
        .unwrap();
    f.write_all(text.as_bytes()).unwrap();
}

fn event(signal: &str, ip: &str, n: u32) -> String {
    format!(r#"{{"v":1,"source_ip":"{ip}","sensor":"s","signal_type":"{signal}","n":{n}}}"#)
}

type Listing = BTreeMap<String, (u64, SystemTime)>;

fn listing(dir: &Path) -> Listing {
    std::fs::read_dir(dir)
        .unwrap()
        .map(|e| {
            let e = e.unwrap();
            let m = e.metadata().unwrap();
            (
                e.file_name().to_string_lossy().into_owned(),
                (m.len(), m.modified().unwrap()),
            )
        })
        .collect()
}

struct Logs {
    dir: tempfile::TempDir,
}

impl Logs {
    fn new() -> Self {
        Self {
            dir: tempfile::tempdir().unwrap(),
        }
    }
    fn path(&self, name: &str) -> PathBuf {
        self.dir.path().join(name)
    }
    fn spec(&self, labels: &[(&str, &str)]) -> String {
        labels
            .iter()
            .map(|(label, file)| format!("{label}:{}", self.path(file).display()))
            .collect::<Vec<_>>()
            .join(",")
    }
}

#[test]
fn streams_each_kind_of_line_in_order_follows_copytruncate_and_never_touches_the_logs() {
    let logs = Logs::new();
    let a = logs.path("a.jsonl");
    let b = logs.path("b.jsonl");
    let c = logs.path("c.jsonl");
    std::fs::write(&a, format!("{}\n", event("old", "192.0.2.1", 0))).unwrap();
    std::fs::write(&b, "").unwrap();
    let w = start(command(&logs.spec(&[
        ("a", "a.jsonl"),
        ("b", "b.jsonl"),
        ("c", "c.jsonl"),
    ])));

    let start_record = w.records.recv_timeout(WAIT).unwrap();
    assert_eq!(start_record["kind"], "start");
    assert_eq!(start_record["version"], env!("CARGO_PKG_VERSION"));
    assert_eq!(start_record["start_at"], "end");
    let labels: Vec<&str> = start_record["sources"]
        .as_array()
        .unwrap()
        .iter()
        .map(|s| s["label"].as_str().unwrap())
        .collect();
    assert_eq!(labels, ["a", "b", "c"]);

    // The first heartbeat is immediate and names the misconfigured path.
    let hb = w.records.recv_timeout(WAIT).unwrap();
    assert_eq!(hb["kind"], "heartbeat");
    let status: Vec<(&str, &str)> = hb["files"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| (f["label"].as_str().unwrap(), f["status"].as_str().unwrap()))
        .collect();
    assert_eq!(
        status,
        [("a", "following"), ("b", "following"), ("c", "missing")]
    );
    assert_eq!(hb["files"][2]["size"], Value::Null);

    // Started at the end: the old line is never streamed.
    let e1 = event("honeypot_connection", "192.0.2.7", 1);
    let e2 = event("honeypot_login_attempt", "192.0.2.7", 2);
    let giant = "x".repeat(log_tailer::MAX_LINE_BYTES as usize + 1);
    append(&a, &format!("{e1}\n{giant}\n{e2}\n"));
    append(&b, "not json at all\n");

    let mut by_label: BTreeMap<String, Vec<Value>> = BTreeMap::new();
    for _ in 0..4 {
        let r = w.next();
        by_label
            .entry(r["label"].as_str().unwrap().to_string())
            .or_default()
            .push(r);
    }
    let from_a = &by_label["a"];
    assert_eq!(from_a[0]["kind"], "event");
    assert_eq!(from_a[0]["event"]["n"], 1);
    assert_eq!(from_a[0]["path"], a.display().to_string());
    assert_eq!(from_a[1]["kind"], "dropped");
    assert_eq!(from_a[1]["reason"], "line_too_long");
    assert_eq!(from_a[1]["bytes"], giant.len() + 1);
    assert_eq!(from_a[2]["kind"], "event");
    assert_eq!(from_a[2]["event"]["n"], 2);
    assert_eq!(by_label["b"][0]["raw"], "not json at all");

    // copytruncate, as deploy/logrotate-sensors.conf rotates: copy aside, truncate in place.
    std::fs::copy(&a, logs.path("a.jsonl.1")).unwrap();
    std::fs::OpenOptions::new()
        .write(true)
        .open(&a)
        .unwrap()
        .set_len(0)
        .unwrap();
    append(
        &a,
        &format!("{}\n", event("after_rotation", "192.0.2.7", 3)),
    );
    let rotated = w.next();
    assert_eq!(rotated["label"], "a");
    assert_eq!(rotated["event"]["n"], 3);

    // The missing file appears: everything in it is new, so all of it is streamed.
    append(&c, &format!("{}\n", event("late", "192.0.2.9", 4)));
    let late = w.next();
    assert_eq!(late["label"], "c");
    assert_eq!(late["event"]["n"], 4);

    // Everything in the directory is what this test wrote, unchanged since its last write.
    let after_our_writes = listing(logs.dir.path());
    w.assert_quiet(Duration::from_millis(800));
    assert_eq!(listing(logs.dir.path()), after_our_writes);
    let names: Vec<&String> = after_our_writes.keys().collect();
    assert_eq!(names, ["a.jsonl", "a.jsonl.1", "b.jsonl", "c.jsonl"]);
}

#[test]
fn since_start_replays_the_current_file() {
    let logs = Logs::new();
    std::fs::write(
        logs.path("a.jsonl"),
        format!("{}\n", event("old", "192.0.2.1", 7)),
    )
    .unwrap();
    let mut cmd = command(&logs.spec(&[("a", "a.jsonl")]));
    cmd.arg("--since-start");
    let w = start(cmd);
    assert_eq!(w.next()["start_at"], "beginning");
    assert_eq!(w.next()["event"]["n"], 7);
}

#[test]
fn filters_from_the_ssh_command_narrow_the_stream() {
    let logs = Logs::new();
    let a = logs.path("a.jsonl");
    let b = logs.path("b.jsonl");
    let mut cmd = command(&logs.spec(&[("a", "a.jsonl"), ("b", "b.jsonl")]));
    cmd.env(
        "SSH_ORIGINAL_COMMAND",
        "--sensor a --signal honeypot_login_attempt --source-ip 192.0.2.7",
    );
    let w = start(cmd);
    let start_record = w.next();
    assert_eq!(start_record["filters"]["sensor"][0], "a");
    append(
        &b,
        &format!("{}\n", event("honeypot_login_attempt", "192.0.2.7", 1)),
    );
    append(
        &a,
        &format!("{}\n", event("honeypot_connection", "192.0.2.7", 2)),
    );
    append(
        &a,
        &format!("{}\n", event("honeypot_login_attempt", "192.0.2.8", 3)),
    );
    append(&a, "raw text\n");
    append(
        &a,
        &format!("{}\n", event("honeypot_login_attempt", "192.0.2.7", 4)),
    );
    let kept = w.next();
    assert_eq!(
        (kept["label"].as_str(), &kept["event"]["n"]),
        (Some("a"), &4.into())
    );
    w.assert_quiet(Duration::from_millis(600));
}

/// Runs a command that must exit on its own, failing (not hanging) if it is still streaming after
/// the deadline: a refusal that regresses into acceptance would otherwise follow the logs forever.
/// Everything these runs print is far below a pipe buffer, so reading after exit cannot deadlock.
fn run_to_exit(cmd: &mut Command) -> std::process::Output {
    cmd.stdout(Stdio::piped()).stderr(Stdio::piped());
    let mut child = cmd.spawn().unwrap();
    let deadline = Instant::now() + WAIT;
    while child.try_wait().unwrap().is_none() {
        if Instant::now() > deadline {
            let _ = child.kill();
            let _ = child.wait();
            panic!("the watcher was expected to exit, and it kept running");
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    child.wait_with_output().unwrap()
}

#[test]
fn a_refused_argument_exits_2_before_reading_anything() {
    let logs = Logs::new();
    let spec = logs.spec(&[("a", "a.jsonl")]);
    for ssh in [
        "--sensor a; rm -rf /",
        "--sensor $(id)",
        "--sensor `id`",
        "--sensor a\nid",
        "--bogus",
        "--sensor b",
    ] {
        let mut cmd = command(&spec);
        cmd.env("SSH_ORIGINAL_COMMAND", ssh);
        let out = run_to_exit(&mut cmd);
        assert_eq!(out.status.code(), Some(2), "{ssh:?}");
        assert!(out.stdout.is_empty(), "{ssh:?} streamed something");
        assert!(String::from_utf8_lossy(&out.stderr).contains("usage:"));
    }
    let mut cmd = command(&spec);
    cmd.arg("--follow");
    assert_eq!(run_to_exit(&mut cmd).status.code(), Some(2));
}

#[test]
fn a_missing_or_invalid_log_list_exits_1_with_an_error_record() {
    for value in [None, Some(""), Some("no-colon")] {
        let mut cmd = command("unused");
        match value {
            None => cmd.env_remove("PROPOLIS_SENSOR_LOGS"),
            Some(v) => cmd.env("PROPOLIS_SENSOR_LOGS", v),
        };
        let out = run_to_exit(&mut cmd);
        assert_eq!(out.status.code(), Some(1), "{value:?}");
        let record: Value = serde_json::from_slice(&out.stdout).unwrap();
        assert_eq!(record["kind"], "error");
        assert_eq!(record["source"], "config");
    }
}

#[test]
fn the_watcher_exits_cleanly_when_its_reader_goes_away() {
    // The remote case: the SSH session closes, the next write fails, and the watcher stops its
    // journal child and exits 0. The heartbeat guarantees that next write within its interval.
    let logs = Logs::new();
    let mut cmd = command(&logs.spec(&[("a", "a.jsonl")]));
    cmd.arg("--journal");
    let mut child = cmd.spawn().unwrap();
    let mut stdout = BufReader::new(child.stdout.take().unwrap());
    let mut first = String::new();
    stdout.read_line(&mut first).unwrap();
    assert!(first.contains(r#""kind":"start""#), "{first}");
    drop(stdout);
    let deadline = Instant::now() + WAIT + WAIT;
    let status = loop {
        if let Some(status) = child.try_wait().unwrap() {
            break status;
        }
        if Instant::now() > deadline {
            let _ = child.kill();
            let _ = child.wait();
            panic!("the watcher kept running after its stdout closed");
        }
        std::thread::sleep(Duration::from_millis(100));
    };
    assert!(status.success());
}

#[test]
fn a_heartbeat_follows_within_its_interval() {
    let logs = Logs::new();
    let w = start(command(&logs.spec(&[("a", "a.jsonl")])));
    let first = w.next_heartbeat();
    let t0 = Instant::now();
    let second = w.next_heartbeat();
    assert!(t0.elapsed() <= Duration::from_secs(12));
    assert_eq!(second["files"][0]["status"], "missing");
    assert_ne!(first["ts"], second["ts"]);
}
