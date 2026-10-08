//! A non-UTF-8 value on any env var the sensor reads is a startup error, never read as unset or
//! defaulted: exit 1, naming the variable, before the sensor reports listening.

use std::ffi::OsStr;
use std::os::unix::ffi::OsStrExt;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

/// Every variable `load_config_from_env` reads, legacy spellings included.
const VARS: &[&str] = &[
    "PROPOLIS_TELNET_BIND",
    "PROPOLIS_TELNET_WAN_MAP",
    "PROPOLIS_TELNET_LOG_PATH",
    "PROPOLIS_TELNET_SPOOL_DIR",
    "PROPOLIS_TELNET_OUTBOX_DIR",
    "PROPOLIS_TELNET_READ_TIMEOUT_MS",
    "PROPOLIS_TELNET_IDLE_TIMEOUT_MS",
    "PROPOLIS_TELNET_MAX_DURATION_SECS",
    "PROPOLIS_TELNET_MAX_CAPTURED_BYTES",
    "PROPOLIS_TELNET_MAX_CONCURRENT",
    "PROPOLIS_TELNET_CAPTURE_MEMORY_BYTES",
    "PROPOLIS_TELNET_COMMAND_EVENT_RATE_PER_MIN",
    "PROPOLIS_TELNET_COMMAND_EVENT_BURST",
    "PROPOLIS_COLLECTOR_ID",
    "COLLECTOR_ID",
];

/// Runs the sensor with a valid minimal config plus `bad` set to the given bytes (if given), and
/// returns its exit code (`None` if still running after `wait`) and combined output.
fn run(bad: Option<(&str, &[u8])>, wait: Duration) -> (Option<i32>, String) {
    let dir = tempfile::tempdir().unwrap();
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_sensor-telnet"));
    cmd.env_clear()
        .env("NO_COLOR", "1")
        .env("PROPOLIS_TELNET_BIND", "127.0.0.1:0")
        .env("PROPOLIS_TELNET_LOG_PATH", dir.path().join("events.jsonl"))
        .env("PROPOLIS_TELNET_SPOOL_DIR", dir.path().join("spool"))
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if let Some((var, value)) = bad {
        cmd.env(var, OsStr::from_bytes(value));
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
        let (code, text) = run(Some((var, &b"\xff\xfe"[..])), Duration::from_secs(10));
        assert_eq!(code, Some(1), "{var}: {text}");
        assert!(
            text.contains(var) && text.contains("UTF-8"),
            "{var}: {text}"
        );
        assert!(!text.contains("listening"), "{var}: bound first: {text}");
    }
}

#[test]
fn a_zero_or_garbage_command_event_budget_exits_1_before_any_listener_binds() {
    for var in [
        "PROPOLIS_TELNET_COMMAND_EVENT_RATE_PER_MIN",
        "PROPOLIS_TELNET_COMMAND_EVENT_BURST",
    ] {
        for bad in ["0", "-1", "lots", "4294967296"] {
            let (code, text) = run(Some((var, bad.as_bytes())), Duration::from_secs(10));
            assert_eq!(code, Some(1), "{var}={bad}: {text}");
            assert!(
                text.contains(var) && text.contains("positive integer"),
                "{var}={bad}: {text}"
            );
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
