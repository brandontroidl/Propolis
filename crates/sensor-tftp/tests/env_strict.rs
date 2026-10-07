//! A non-UTF-8 value on any env var the sensor reads is a startup error, never read as unset or
//! defaulted: exit 1, naming the variable, before the sensor reports listening.

use std::ffi::OsStr;
use std::os::unix::ffi::OsStrExt;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

/// Every variable `load_config_from` reads.
const VARS: &[&str] = &[
    "PROPOLIS_TFTP_BIND",
    "PROPOLIS_TFTP_WAN_MAP",
    "PROPOLIS_TFTP_LOG_PATH",
    "PROPOLIS_TFTP_SPOOL_DIR",
    "PROPOLIS_TFTP_OUTBOX_DIR",
    "PROPOLIS_TFTP_READ_TIMEOUT_MS",
    "PROPOLIS_TFTP_IDLE_TIMEOUT_MS",
    "PROPOLIS_TFTP_MAX_DURATION_SECS",
    "PROPOLIS_TFTP_MAX_CAPTURED_BYTES",
    "PROPOLIS_TFTP_MAX_CONCURRENT",
    "PROPOLIS_TFTP_CAPTURE_MEMORY_BYTES",
    "PROPOLIS_TFTP_REPLY_RATE_PER_SOURCE",
    "PROPOLIS_TFTP_REPLY_BURST_PER_SOURCE",
    "PROPOLIS_TFTP_REPLY_RATE_GLOBAL",
    "PROPOLIS_TFTP_REPLY_BURST_GLOBAL",
    "PROPOLIS_COLLECTOR_ID",
];

const RATE_VARS: &[&str] = &[
    "PROPOLIS_TFTP_REPLY_RATE_PER_SOURCE",
    "PROPOLIS_TFTP_REPLY_BURST_PER_SOURCE",
    "PROPOLIS_TFTP_REPLY_RATE_GLOBAL",
    "PROPOLIS_TFTP_REPLY_BURST_GLOBAL",
];

/// Runs the sensor with a valid minimal config plus `bad` set to non-UTF-8 bytes (if given), and
/// returns its exit code (`None` if still running after `wait`) and combined output.
fn run(bad: Option<&str>, wait: Duration) -> (Option<i32>, String) {
    run_with(bad.map(|var| (var, OsStr::from_bytes(b"\xff\xfe"))), wait)
}

fn run_with(set: Option<(&str, &OsStr)>, wait: Duration) -> (Option<i32>, String) {
    let dir = tempfile::tempdir().unwrap();
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_sensor-tftp"));
    cmd.env_clear()
        .env("NO_COLOR", "1")
        .env("PROPOLIS_TFTP_BIND", "127.0.0.1:0")
        .env("PROPOLIS_TFTP_LOG_PATH", dir.path().join("events.jsonl"))
        .env("PROPOLIS_TFTP_SPOOL_DIR", dir.path().join("spool"))
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if let Some((var, value)) = set {
        cmd.env(var, value);
    }
    let mut child = cmd.spawn().unwrap();
    let deadline = Instant::now() + wait;
    while child.try_wait().unwrap().is_none() && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(25));
    }
    let _ = child.kill();
    let out = child.wait_with_output().unwrap();
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    (out.status.code(), text)
}

#[test]
fn a_non_utf8_value_exits_1_before_any_listener_binds() {
    for var in VARS {
        let (code, text) = run(Some(var), Duration::from_secs(10));
        assert_eq!(code, Some(1), "{var}: {text}");
        assert!(
            text.contains(var) && text.contains("UTF-8"),
            "{var}: {text}"
        );
        assert!(!text.contains("listening"), "{var}: bound first: {text}");
    }
}

/// A reply rate can never be configured off: zero or a non-number refuses to start.
#[test]
fn a_zero_or_garbage_reply_rate_exits_1_before_any_listener_binds() {
    for var in RATE_VARS {
        for bad in ["0", "fast"] {
            let (code, text) = run_with(Some((var, OsStr::new(bad))), Duration::from_secs(10));
            assert_eq!(code, Some(1), "{var}={bad}: {text}");
            assert!(text.contains(var), "{var}={bad}: {text}");
            assert!(
                !text.contains("listening"),
                "{var}={bad}: bound first: {text}"
            );
        }
    }
}

#[test]
fn the_same_config_without_a_bad_value_keeps_running() {
    let (code, text) = run(None, Duration::from_millis(1500));
    assert_eq!(
        code, None,
        "a valid config must start and keep running: {text}"
    );
}
