//! The daemon's log lines under a service manager. The daemon builds its own registry (the
//! console's log-buffer layer rides on it), so it needs its own end-to-end check: stdout is a
//! pipe, so no ANSI escape, and when `$JOURNAL_STREAM` names that stream the line carries
//! journald's `<N>` priority prefix (sd-daemon(3)). With an empty environment the daemon logs
//! one ERROR ("invalid configuration") and exits before it touches the database.

use std::io::Read;
use std::os::fd::AsRawFd;
use std::os::unix::fs::MetadataExt;
use std::process::{Command, Stdio};

fn run_daemon(journal: bool) -> Vec<u8> {
    let (mut reader, writer) = std::io::pipe().expect("pipe");
    let meta = std::fs::metadata(format!("/proc/self/fd/{}", reader.as_raw_fd())).expect("stat");
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_propolis"));
    cmd.env_clear().stdout(writer).stderr(Stdio::null());
    if journal {
        cmd.env("JOURNAL_STREAM", format!("{}:{}", meta.dev(), meta.ino()));
    }
    let mut child = cmd.spawn().expect("spawn propolis");
    drop(cmd);
    let mut out = Vec::new();
    reader.read_to_end(&mut out).expect("read");
    assert!(
        !child.wait().expect("wait").success(),
        "daemon must refuse to start"
    );
    out
}

#[test]
fn piped_output_has_no_ansi_escape() {
    let out = run_daemon(false);
    assert!(!out.is_empty(), "the refuse-to-start error must be logged");
    assert!(
        !out.contains(&0x1b),
        "escape byte in piped log output: {:?}",
        String::from_utf8_lossy(&out)
    );
}

#[test]
fn journal_output_carries_the_error_priority_prefix() {
    let out = run_daemon(true);
    let text = String::from_utf8_lossy(&out);
    let line = text.lines().next().expect("a log line");
    assert!(
        line.starts_with("<3>"),
        "ERROR must map to priority 3: {line:?}"
    );
    assert!(line.contains("invalid configuration"), "{line:?}");
    assert!(!out.contains(&0x1b), "{text:?}");
}
