//! The gateway binary's log lines as a service manager sees them: stdout is a pipe, never a
//! terminal, so no ANSI escape may appear, and when stdout is the journal stream (systemd's
//! `$JOURNAL_STREAM` names its device and inode) each line carries the `<N>` priority prefix
//! journald parses (sd-daemon(3)), so `journalctl -p err` can see it. Without any
//! `PROPOLIS_GATEWAY_*` variables the binary logs one ERROR ("invalid configuration") and exits.

use std::io::Read;
use std::os::fd::AsRawFd;
use std::os::unix::fs::MetadataExt;
use std::process::{Command, Stdio};

/// Runs the gateway with a clean environment and stdout on a fresh pipe. `journal` makes the
/// pipe look like the journal stream by naming its own device and inode in `JOURNAL_STREAM`,
/// exactly the check a process makes against a real journal socket.
fn run_gateway(journal: bool) -> Vec<u8> {
    let (mut reader, writer) = std::io::pipe().expect("pipe");
    let meta = std::fs::metadata(format!("/proc/self/fd/{}", reader.as_raw_fd())).expect("stat");
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_gateway"));
    cmd.env_clear()
        .stdout(writer.try_clone().expect("clone"))
        .stderr(Stdio::null());
    if journal {
        cmd.env("JOURNAL_STREAM", format!("{}:{}", meta.dev(), meta.ino()));
    }
    let mut child = cmd.spawn().expect("spawn gateway");
    drop(cmd);
    drop(writer);
    let mut out = Vec::new();
    reader.read_to_end(&mut out).expect("read");
    assert!(
        !child.wait().expect("wait").success(),
        "gateway must refuse to start"
    );
    out
}

#[test]
fn piped_output_has_no_ansi_escape() {
    let out = run_gateway(false);
    assert!(!out.is_empty(), "the refuse-to-start error must be logged");
    assert!(
        !out.contains(&0x1b),
        "escape byte in piped log output: {:?}",
        String::from_utf8_lossy(&out)
    );
    assert!(
        !out.starts_with(b"<"),
        "no priority prefix outside the journal: {:?}",
        String::from_utf8_lossy(&out)
    );
}

#[test]
fn journal_output_carries_the_error_priority_prefix() {
    let out = run_gateway(true);
    let text = String::from_utf8_lossy(&out);
    assert!(
        !out.contains(&0x1b),
        "escape byte in journal log output: {text:?}"
    );
    let line = text.lines().next().expect("a log line");
    assert!(
        line.starts_with("<3>"),
        "ERROR must map to priority 3: {line:?}"
    );
    assert!(line.contains("gateway: invalid configuration"), "{line:?}");
    assert_eq!(text.lines().count(), 1, "one event is one line: {text:?}");
}
