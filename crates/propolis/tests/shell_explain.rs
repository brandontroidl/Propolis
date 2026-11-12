//! `propolis shell explain` runs offline: it replays a fixture and prints the decision trace
//! without config, a database or a listener. The binary runs with an empty environment, so a
//! path that fell through to daemon startup would fail on missing configuration instead of
//! printing a trace and exiting 0.

use std::path::Path;
use std::process::{Command, Output};

fn explain(path: &Path) -> Output {
    Command::new(env!("CARGO_BIN_EXE_propolis"))
        .args(["shell", "explain"])
        .arg(path)
        .env_clear()
        .output()
        .unwrap()
}

#[test]
fn explain_prints_a_trace_for_the_public_fixture_and_exits_cleanly() {
    let fixture = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../sensor-framework/tests/fixtures/sessions/ubuntu-probe-basics.session");
    let out = explain(&fixture);
    let stdout = String::from_utf8(out.stdout).unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(stdout.starts_with("fixture: source="), "{stdout}");
    assert!(stdout.contains("persona=Ubuntu"), "{stdout}");
    assert!(stdout.contains("  class: supported"), "{stdout}");
    assert!(stdout.contains("  command_basename: enable"), "{stdout}");
    assert!(stdout.contains("\"segments\""), "{stdout}");
}

#[test]
fn explain_classifies_an_unknown_command() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("probe.session");
    std::fs::write(
        &path,
        "# source: test\n# date: 2026-10-03\n# protocol: ssh\n# persona: ubuntu\n\
         $ id\n$ definitely-not-a-command\n",
    )
    .unwrap();
    let out = explain(&path);
    assert!(out.status.success());
    let stdout = String::from_utf8(out.stdout).unwrap();
    assert!(stdout.contains("  class: supported"), "{stdout}");
    assert!(stdout.contains("  class: unknown"), "{stdout}");
    assert!(stdout.contains("  status: 127"), "{stdout}");
}

#[test]
fn explain_reports_a_missing_file_and_a_bad_fixture_on_stderr() {
    let dir = tempfile::tempdir().unwrap();

    let out = explain(&dir.path().join("absent.session"));
    assert_eq!(out.status.code(), Some(1));
    assert!(out.stdout.is_empty());
    assert!(String::from_utf8_lossy(&out.stderr).contains("cannot read"));

    let bad = dir.path().join("bad.session");
    std::fs::write(&bad, "# source: test\n$ id\n").unwrap();
    let out = explain(&bad);
    assert_eq!(out.status.code(), Some(1));
    assert!(out.stdout.is_empty());
    assert!(String::from_utf8_lossy(&out.stderr).contains("missing `# date:` header"));

    let out = Command::new(env!("CARGO_BIN_EXE_propolis"))
        .args(["shell", "explain"])
        .env_clear()
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2));
}
