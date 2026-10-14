//! The real path: a built program with stdout on a pipe, with and without `$JOURNAL_STREAM`
//! naming that pipe the way systemd names the journal socket.

use std::io::Read;
use std::os::fd::AsRawFd;
use std::os::unix::fs::MetadataExt;
use std::path::PathBuf;
use std::process::{Command, Stdio};

/// `cargo test` builds the crate's examples next to the test executable (`target/<profile>/deps`
/// holds the test, `target/<profile>/examples` the example).
fn emit_binary() -> PathBuf {
    let mut dir = std::env::current_exe().unwrap();
    dir.pop();
    if dir.ends_with("deps") {
        dir.pop();
    }
    let path = dir.join("examples").join("emit");
    // `cargo test --test process` does not build examples; build it so a targeted run on a clean
    // target directory works and a stale binary is never used.
    let mut build = Command::new(std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into()));
    build.args(["build", "--example", "emit", "-p", "log-format"]);
    if dir.ends_with("release") {
        build.arg("--release");
    }
    let status = build.status().unwrap();
    assert!(status.success());
    assert!(path.exists(), "example not built: {}", path.display());
    path
}

fn run(env: &[(&str, String)], journal_names_pipe: bool) -> String {
    let (mut reader, writer) = std::io::pipe().unwrap();
    let meta = std::fs::metadata(format!("/proc/self/fd/{}", reader.as_raw_fd())).unwrap();
    let mut cmd = Command::new(emit_binary());
    cmd.env_clear().stdout(writer).stderr(Stdio::null());
    for (k, v) in env {
        cmd.env(k, v);
    }
    if journal_names_pipe {
        cmd.env("JOURNAL_STREAM", format!("{}:{}", meta.dev(), meta.ino()));
    }
    let mut child = cmd.spawn().unwrap();
    drop(cmd);
    let mut out = String::new();
    reader.read_to_string(&mut out).unwrap();
    assert!(child.wait().unwrap().success());
    out
}

#[test]
fn piped_stdout_is_plain_text_without_a_journal_stream() {
    let out = run(&[], false);
    assert_eq!(out.lines().count(), 7, "one line per event: {out:?}");
    assert!(!out.contains('\x1b'), "{out:?}");
    assert!(!out.starts_with('<'), "{out:?}");
}

#[test]
fn journal_stream_naming_stdout_prefixes_every_level() {
    let out = run(&[], true);
    let prefixes: Vec<&str> = out.lines().map(|l| &l[..3]).collect();
    assert_eq!(
        prefixes,
        ["<3>", "<4>", "<6>", "<7>", "<7>", "<6>", "<6>"],
        "{out:?}"
    );
    assert!(!out.contains('\x1b'), "{out:?}");
    assert!(!out.contains("\n<0>"), "forged priority line: {out:?}");
}

#[test]
fn stale_journal_stream_is_ignored() {
    // Inherited by a child whose stdout was redirected elsewhere: the numbers do not match.
    let out = run(&[("JOURNAL_STREAM", "1:1".to_string())], false);
    assert!(!out.starts_with('<'), "{out:?}");
}

#[test]
fn rust_log_still_filters() {
    let out = run(&[("RUST_LOG", "warn".to_string())], true);
    let prefixes: Vec<&str> = out.lines().map(|l| &l[..3]).collect();
    assert_eq!(prefixes, ["<3>", "<4>"], "{out:?}");
}

#[test]
fn a_field_past_journald_line_max_stays_one_capped_line() {
    for journal in [true, false] {
        let out = run(&[("EMIT_LONG", "1".to_string())], journal);
        let long: Vec<&str> = out.lines().filter(|l| l.contains("AAAA")).collect();
        assert_eq!(
            long.len(),
            1,
            "journal={journal}: {} lines",
            out.lines().count()
        );
        let line = long[0];
        assert!(line.len() < 20 * 1024, "line not capped: {}", line.len());
        assert!(
            line.contains("...[truncated "),
            "{:?}",
            &line[line.len() - 40..]
        );
        assert!(!line.contains("<0>"), "boundary text survived the cap");
        assert!(!out.contains("\n<0>"), "forged priority line");
    }
}
