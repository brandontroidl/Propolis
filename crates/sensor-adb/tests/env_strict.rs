//! A non-UTF-8 value on any env var the sensor reads is a startup error, never read as unset or
//! defaulted: exit 1, naming the variable, before the sensor reports listening.

use std::ffi::OsStr;
use std::os::unix::ffi::OsStrExt;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

/// Every variable `load_config_from_env` reads, legacy spellings included.
const VARS: &[&str] = &[
    "PROPOLIS_ADB_BIND",
    "PROPOLIS_ADB_WAN_MAP",
    "PROPOLIS_ADB_LOG_PATH",
    "PROPOLIS_ADB_SPOOL_DIR",
    "PROPOLIS_ADB_OUTBOX_DIR",
    "PROPOLIS_ADB_READ_TIMEOUT_MS",
    "PROPOLIS_ADB_IDLE_TIMEOUT_MS",
    "PROPOLIS_ADB_MAX_DURATION_SECS",
    "PROPOLIS_ADB_MAX_CAPTURED_BYTES",
    "PROPOLIS_ADB_MAX_CONCURRENT",
    "PROPOLIS_ADB_CAPTURE_MEMORY_BYTES",
    "PROPOLIS_COLLECTOR_ID",
    "COLLECTOR_ID",
];

/// Runs the sensor with a valid minimal config plus `bad` set to non-UTF-8 bytes (if given), and
/// returns its exit code (`None` if still running after `wait`) and combined output.
fn run(bad: Option<&str>, wait: Duration) -> (Option<i32>, String) {
    let dir = tempfile::tempdir().unwrap();
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_sensor-adb"));
    cmd.env_clear()
        .env("NO_COLOR", "1")
        .env("PROPOLIS_ADB_BIND", "127.0.0.1:0")
        .env("PROPOLIS_ADB_LOG_PATH", dir.path().join("events.jsonl"))
        .env("PROPOLIS_ADB_SPOOL_DIR", dir.path().join("spool"))
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if let Some(var) = bad {
        cmd.env(var, OsStr::from_bytes(b"\xff\xfe"));
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

#[test]
fn the_same_config_without_a_bad_value_keeps_running() {
    let (code, text) = run(None, Duration::from_millis(1500));
    assert_eq!(
        code, None,
        "a valid config must start and keep running: {text}"
    );
}
