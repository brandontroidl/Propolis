//! `propolis shell shadow-diff` runs offline and gates a behavior change by exit code. The binary
//! runs with an empty environment, so a path that fell through to daemon startup would die on
//! missing configuration and never print the diff summary these tests read.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

const HEAD: &str = "# source: test\n# date: 2026-10-04\n# protocol: ssh\n# persona: ubuntu\n";

fn shadow_diff(args: &[&Path]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_propolis"))
        .args(["shell", "shadow-diff"])
        .args(args)
        .env_clear()
        .output()
        .unwrap()
}

fn public_fixture() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../sensor-framework/tests/fixtures/sessions/ubuntu-probe-basics.session")
}

fn write(dir: &Path, name: &str, body: &str) -> PathBuf {
    let path = dir.join(name);
    std::fs::write(&path, format!("{HEAD}{body}")).unwrap();
    path
}

#[test]
fn the_public_fixture_has_no_diffs() {
    let out = shadow_diff(&[&public_fixture()]);
    let stdout = String::from_utf8(out.stdout).unwrap();
    assert_eq!(
        out.status.code(),
        Some(0),
        "{stdout}{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        stdout.ends_with(" diffs\n") && stdout.contains(", 0 diffs"),
        "{stdout}"
    );
    assert!(!stdout.contains("expected"), "{stdout}");
}

#[test]
fn a_wrong_expectation_exits_1_and_prints_the_diff() {
    let dir = tempfile::tempdir().unwrap();
    let path = write(
        dir.path(),
        "drift.session",
        "$ whoami\n> nobody\n@class supported\n$ id\n> uid=0(root) gid=0(root) groups=0(root)\n@class unknown\n",
    );
    let out = shadow_diff(&[&path]);
    let stdout = String::from_utf8(out.stdout).unwrap();
    assert_eq!(out.status.code(), Some(1), "{stdout}");
    assert!(stdout.contains("$ whoami"), "{stdout}");
    assert!(stdout.contains("reply expected: nobody"), "{stdout}");
    assert!(stdout.contains("reply actual:   root"), "{stdout}");
    assert!(stdout.contains("class expected: unknown"), "{stdout}");
    assert!(stdout.contains("class actual:   supported"), "{stdout}");
    assert!(stdout.ends_with("2 steps, 2 diffs\n"), "{stdout}");
}

#[test]
fn a_class_only_change_is_a_diff() {
    let dir = tempfile::tempdir().unwrap();
    let path = write(
        dir.path(),
        "class.session",
        "$ id\n> uid=0(root) gid=0(root) groups=0(root)\n@class partial\n",
    );
    let out = shadow_diff(&[&path]);
    assert_eq!(out.status.code(), Some(1));
    let stdout = String::from_utf8(out.stdout).unwrap();
    assert!(stdout.contains("class expected: partial"), "{stdout}");
    assert!(stdout.ends_with("1 steps, 1 diffs\n"), "{stdout}");
}

#[test]
fn json_lists_every_step_as_valid_json() {
    let dir = tempfile::tempdir().unwrap();
    let path = write(
        dir.path(),
        "j.session",
        "$ whoami\n> root\n@class supported\n$ whoami\n> nobody\n",
    );
    let out = Command::new(env!("CARGO_BIN_EXE_propolis"))
        .args(["shell", "shadow-diff", "--json"])
        .arg(&path)
        .env_clear()
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1));
    let json: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    let steps = &json[0]["steps"];
    assert_eq!(steps.as_array().unwrap().len(), 2);
    assert_eq!(steps[0]["matched"], true);
    assert_eq!(steps[0]["class_expected"], "supported");
    assert_eq!(steps[1]["matched"], false);
    assert_eq!(steps[1]["class_expected"], serde_json::Value::Null);
    assert_eq!(steps[1]["reply_actual"], "root\\n");
}

#[test]
fn a_directory_replays_every_session_and_ignores_other_files() {
    let dir = tempfile::tempdir().unwrap();
    write(dir.path(), "a.session", "$ whoami\n> root\n");
    write(dir.path(), "b.session", "$ whoami\n> nobody\n");
    std::fs::write(dir.path().join("notes.txt"), "not a fixture").unwrap();
    let out = shadow_diff(&[dir.path()]);
    assert_eq!(out.status.code(), Some(1));
    let stdout = String::from_utf8(out.stdout).unwrap();
    assert!(stdout.contains("b.session:"), "{stdout}");
    assert!(!stdout.contains("a.session:"), "{stdout}");
    assert!(stdout.ends_with("2 steps, 1 diffs\n"), "{stdout}");
}

#[test]
fn usage_read_and_parse_errors_exit_2_on_stderr() {
    let dir = tempfile::tempdir().unwrap();

    let out = Command::new(env!("CARGO_BIN_EXE_propolis"))
        .args(["shell", "shadow-diff"])
        .env_clear()
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&out.stderr).contains("usage:"));

    let out = shadow_diff(&[&dir.path().join("absent.session")]);
    assert_eq!(out.status.code(), Some(2));
    assert!(out.stdout.is_empty());
    assert!(String::from_utf8_lossy(&out.stderr).contains("cannot read"));

    let bad = dir.path().join("bad.session");
    std::fs::write(&bad, "# source: test\n$ id\n").unwrap();
    let out = shadow_diff(&[&bad]);
    assert_eq!(out.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&out.stderr).contains("missing `# date:` header"));

    let empty = tempfile::tempdir().unwrap();
    let out = shadow_diff(&[empty.path()]);
    assert_eq!(out.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&out.stderr).contains("no .session fixtures"));
}
