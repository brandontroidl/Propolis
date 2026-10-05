//! Replays recorded attacker sessions through the fake shell and checks every reply byte for
//! byte, together with the state and evidence a later line depends on. A unit test of one verb
//! cannot show that status, files and the working directory survive a chain; these can.
//!
//! Each `tests/fixtures/sessions/*.session` file is one session, answered by one shell. The file
//! format, with every directive, is documented on `sensor_framework::replay`, which also holds
//! the parser this test and `propolis shell explain` share.
//!
//! A line's output directives are concatenated and must equal its whole reply, unless the line
//! uses `>prefix-x` or `>len`, which check only what they state. A line with no output
//! directive must produce no output at all.
//!
//! The fixtures in this repository hold only replies checked against the persona's real system.
//! Sessions drawn from sensor telemetry stay in a private corpus outside the repository; point
//! `PROPOLIS_PRIVATE_SESSIONS` at it and run the ignored test to replay them.

use std::path::{Path, PathBuf};

use sensor_framework::replay::{self, Fixture};
use sensor_framework::shell::FakeShell;
use sensor_wire::{SIGNAL_HONEYPOT_FILE_DOWNLOAD, SensorEvent};

/// A fixture and the file it came from, for failure messages.
struct Loaded {
    path: PathBuf,
    fixture: Fixture,
}

fn parse_fixture(path: &Path) -> Loaded {
    let text = std::fs::read_to_string(path).unwrap();
    let fixture = replay::parse(&text).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    Loaded {
        path: path.to_path_buf(),
        fixture,
    }
}

/// The shell's reply to one line, as the bytes a transport would send before its own line
/// discipline, and the events it emitted.
fn run(shell: &mut FakeShell, input: &str) -> (Vec<u8>, Vec<SensorEvent>) {
    let (output, events) = shell.handle_input(input);
    (output.into_bytes(), events)
}

/// Bytes shown so a mismatch is readable: printable ASCII as is, everything else escaped.
fn show(bytes: &[u8]) -> String {
    let head = &bytes[..bytes.len().min(512)];
    let mut s: String = head.escape_ascii().to_string();
    if bytes.len() > head.len() {
        s.push_str(&format!("... ({} bytes)", bytes.len()));
    }
    s
}

fn check(loaded: &Loaded) -> Vec<String> {
    let mut shell = loaded.fixture.shell();
    let mut failures = Vec::new();
    for step in &loaded.fixture.steps {
        let at = format!("{}:{}", loaded.path.display(), step.line_no);
        let (out, events) = run(&mut shell, &step.input);
        let e = &step.expect;
        if e.prefix.is_none() && e.len.is_none() {
            if out != e.output {
                failures.push(format!(
                    "{at}: `{}`\n  expected: {}\n  actual:   {}",
                    step.input,
                    show(&e.output),
                    show(&out)
                ));
            }
        } else {
            if let Some(prefix) = &e.prefix
                && !out.starts_with(prefix)
            {
                failures.push(format!(
                    "{at}: `{}` must start with {}\n  actual: {}",
                    step.input,
                    show(prefix),
                    show(&out)
                ));
            }
            if let Some(len) = e.len
                && out.len() != len
            {
                failures.push(format!(
                    "{at}: `{}` must be {len} bytes, was {}",
                    step.input,
                    out.len()
                ));
            }
        }
        if let Some(cwd) = &e.cwd
            && shell.cwd() != cwd
        {
            failures.push(format!("{at}: cwd {:?}, expected {cwd:?}", shell.cwd()));
        }
        if let Some(expected) = &e.downloads {
            let urls: Vec<String> = events
                .iter()
                .filter(|ev| ev.signal_type == SIGNAL_HONEYPOT_FILE_DOWNLOAD)
                .map(|ev| ev.metadata["url"].as_str().unwrap_or_default().to_string())
                .collect();
            if &urls != expected {
                failures.push(format!("{at}: downloads {urls:?}, expected {expected:?}"));
            }
        }
        if let Some(n) = e.events
            && events.len() != n
        {
            failures.push(format!("{at}: {} events, expected {n}", events.len()));
        }
        if let Some(class) = e.class {
            let actual = shell.last_trace().classify();
            if actual != class {
                failures.push(format!(
                    "{at}: `{}` class {}, expected {}",
                    step.input,
                    actual.as_str(),
                    class.as_str()
                ));
            }
        }
    }
    failures
}

fn session_files(dir: &Path) -> Vec<PathBuf> {
    let mut paths: Vec<PathBuf> = std::fs::read_dir(dir)
        .unwrap_or_else(|e| panic!("{}: {e}", dir.display()))
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|x| x == "session"))
        .collect();
    paths.sort();
    paths
}

/// Replays every fixture in `dir`. Each file's `$` lines are counted from the raw text as well,
/// so a parser that silently skipped lines could not pass.
fn replay_dir(dir: &Path) {
    let paths = session_files(dir);
    assert!(!paths.is_empty(), "{}: no session fixtures", dir.display());
    let mut failures = Vec::new();
    for path in &paths {
        let loaded = parse_fixture(path);
        let inputs = std::fs::read_to_string(path)
            .unwrap()
            .lines()
            .filter(|l| l.starts_with("$ "))
            .count();
        assert!(inputs > 0, "{}: no `$` lines", path.display());
        assert_eq!(
            loaded.fixture.steps.len(),
            inputs,
            "{}: parsed steps differ from `$` lines",
            path.display()
        );
        failures.extend(check(&loaded));
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

#[test]
fn recorded_sessions_replay_byte_for_byte() {
    replay_dir(&Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/sessions"));
}

#[test]
#[ignore = "replays the private corpus named by PROPOLIS_PRIVATE_SESSIONS"]
fn private_sessions_replay_byte_for_byte() {
    let dir = std::env::var_os("PROPOLIS_PRIVATE_SESSIONS")
        .expect("set PROPOLIS_PRIVATE_SESSIONS to the private session directory");
    replay_dir(Path::new(&dir));
}

/// `@class` pins the classification: a correct word passes, a wrong one fails, and a step with
/// no `@class` is not checked (the private corpus predates the directive).
#[test]
fn the_replay_checker_pins_the_command_class() {
    let dir = tempfile::tempdir().unwrap();
    let head =
        "# source: harness self-test\n# date: 2026-10-04\n# protocol: ssh\n# persona: ubuntu\n";
    let write = |name: &str, body: &str| {
        let path = dir.path().join(name);
        std::fs::write(&path, format!("{head}{body}")).unwrap();
        path
    };

    let right = write(
        "right.session",
        "$ id\n> uid=0(root) gid=0(root) groups=0(root)\n@class supported\n\
         $ nosuchcmd-xyz\n> nosuchcmd-xyz: command not found\n@class unknown\n\
         $ whoami\n> root\n",
    );
    assert_eq!(check(&parse_fixture(&right)), Vec::<String>::new());

    let wrong = write(
        "wrong.session",
        "$ id\n> uid=0(root) gid=0(root) groups=0(root)\n@class unknown\n\
         $ whoami\n> root\n",
    );
    let failures = check(&parse_fixture(&wrong));
    assert_eq!(failures.len(), 1, "{failures:#?}");
    assert!(
        failures[0].contains("class supported, expected unknown"),
        "{}",
        failures[0]
    );
}

/// The harness must catch a wrong reply, a wrong length, a wrong directory and a wrong event
/// count; a checker that passes everything would make every fixture decoration.
#[test]
fn the_replay_checker_rejects_a_wrong_reply() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("wrong.session");
    std::fs::write(
        &path,
        "# source: harness self-test\n# date: 2026-09-29\n# protocol: ssh\n# persona: ubuntu\n\
         $ pwd\n> /nowhere\n$ echo hi\n>len 99\n$ cd /tmp\n@cwd /var\n\
         $ id\n> uid=0(root) gid=0(root) groups=0(root)\n@events 5\n$ whoami\n",
    )
    .unwrap();
    let failures = check(&parse_fixture(&path));
    let expected = [
        "`pwd`",
        "must be 99 bytes",
        "expected \"/var\"",
        "expected 5",
        "`whoami`",
    ];
    assert_eq!(failures.len(), expected.len(), "{failures:#?}");
    for (failure, needle) in failures.iter().zip(expected) {
        assert!(
            failure.contains(needle),
            "{failure} should mention {needle}"
        );
    }
}
