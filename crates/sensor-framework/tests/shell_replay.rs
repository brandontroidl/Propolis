//! Replays recorded attacker sessions through the fake shell and checks every reply byte for
//! byte, together with the state and evidence a later line depends on. A unit test of one verb
//! cannot show that status, files and the working directory survive a chain; these can.
//!
//! Each `tests/fixtures/sessions/*.session` file is one session, answered by one shell:
//!
//! ```text
//! # source: where the lines were observed        (required)
//! # date: YYYY-MM-DD                              (required)
//! # protocol: ssh | telnet | adb                  (required)
//! # persona: ubuntu | android                     (required)
//! $ an input line, exactly as sent
//! > an output line, compared with a trailing LF
//! >~ output text with no trailing LF
//! >e a\tb                                         an output line with escapes (\t \r \n \\
//!                                                 \0 \xHH), compared with a trailing LF
//! >x 7f 45 4c 46                                  raw output bytes, in hex
//! >prefix-x 7f 45 4c 46                           the output starts with these bytes
//! >prefix-e PING localhost (                      the same, as escaped text
//! >len 2193272                                    the output is exactly this long
//! @cwd /tmp                                       the working directory after the line
//! @downloads http://example.invalid/a             the line's download events, in order
//! @events 1                                       every event the line emitted
//! ```
//!
//! A line's output directives are concatenated and must equal its whole reply, unless the line
//! uses `>prefix-x` or `>len`, which check only what they state. A line with no output
//! directive must produce no output at all.
//!
//! The fixtures in this repository hold only replies checked against the persona's real system.
//! Sessions drawn from sensor telemetry stay in a private corpus outside the repository; point
//! `PROPOLIS_PRIVATE_SESSIONS` at it and run the ignored test to replay them.

use std::net::IpAddr;
use std::path::{Path, PathBuf};

use sensor_framework::fakefs::FakeFs;
use sensor_framework::shell::{EmitContext, FakeShell};
use sensor_wire::{SIGNAL_HONEYPOT_FILE_DOWNLOAD, SensorEvent};

/// What one input line must produce.
#[derive(Default)]
struct Expect {
    output: Vec<u8>,
    prefix: Option<Vec<u8>>,
    len: Option<usize>,
    cwd: Option<String>,
    downloads: Option<Vec<String>>,
    events: Option<usize>,
}

struct Step {
    line_no: usize,
    input: String,
    expect: Expect,
}

struct Fixture {
    path: PathBuf,
    persona: String,
    protocol: String,
    steps: Vec<Step>,
}

fn parse_hex(field: &str, at: &str) -> Vec<u8> {
    field
        .split_whitespace()
        .map(|h| u8::from_str_radix(h, 16).unwrap_or_else(|_| panic!("{at}: bad hex byte {h:?}")))
        .collect()
}

fn unescape(text: &str, at: &str) -> Vec<u8> {
    let mut out = Vec::new();
    let mut bytes = text.bytes();
    while let Some(b) = bytes.next() {
        if b != b'\\' {
            out.push(b);
            continue;
        }
        match bytes.next() {
            Some(b't') => out.push(b'\t'),
            Some(b'r') => out.push(b'\r'),
            Some(b'n') => out.push(b'\n'),
            Some(b'0') => out.push(0),
            Some(b'\\') => out.push(b'\\'),
            Some(b'x') => {
                let hex: Vec<u8> = bytes.by_ref().take(2).collect();
                let hex = std::str::from_utf8(&hex).unwrap_or("");
                out.push(
                    u8::from_str_radix(hex, 16)
                        .unwrap_or_else(|_| panic!("{at}: bad \\x escape {hex:?}")),
                );
            }
            other => panic!("{at}: unknown escape \\{:?}", other.map(char::from)),
        }
    }
    out
}

fn parse_fixture(path: &Path) -> Fixture {
    let text = std::fs::read_to_string(path).unwrap();
    let mut meta = std::collections::BTreeMap::new();
    let mut steps: Vec<Step> = Vec::new();
    for (i, line) in text.lines().enumerate() {
        let at = format!("{}:{}", path.display(), i + 1);
        if let Some(rest) = line.strip_prefix("# ") {
            if let Some((key, value)) = rest.split_once(':') {
                meta.insert(key.trim().to_string(), value.trim().to_string());
            }
            continue;
        }
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some(input) = line.strip_prefix("$ ") {
            steps.push(Step {
                line_no: i + 1,
                input: input.to_string(),
                expect: Expect::default(),
            });
            continue;
        }
        let step = steps
            .last_mut()
            .unwrap_or_else(|| panic!("{at}: a directive before any `$` line"));
        let e = &mut step.expect;
        if let Some(hex) = line.strip_prefix(">prefix-x ") {
            e.prefix = Some(parse_hex(hex, &at));
        } else if let Some(text) = line.strip_prefix(">prefix-e ") {
            e.prefix = Some(unescape(text, &at));
        } else if let Some(text) = line.strip_prefix(">e ") {
            e.output.extend(unescape(text, &at));
            e.output.push(b'\n');
        } else if let Some(hex) = line.strip_prefix(">x ") {
            e.output.extend(parse_hex(hex, &at));
        } else if let Some(n) = line.strip_prefix(">len ") {
            e.len = Some(
                n.trim()
                    .parse()
                    .unwrap_or_else(|_| panic!("{at}: bad length")),
            );
        } else if let Some(text) = line.strip_prefix(">~ ") {
            e.output.extend_from_slice(text.as_bytes());
        } else if line == ">" {
            e.output.push(b'\n');
        } else if let Some(text) = line.strip_prefix("> ") {
            e.output.extend_from_slice(text.as_bytes());
            e.output.push(b'\n');
        } else if let Some(cwd) = line.strip_prefix("@cwd ") {
            e.cwd = Some(cwd.to_string());
        } else if let Some(urls) = line.strip_prefix("@downloads") {
            e.downloads = Some(urls.split_whitespace().map(str::to_string).collect());
        } else if let Some(n) = line.strip_prefix("@events ") {
            e.events = Some(
                n.trim()
                    .parse()
                    .unwrap_or_else(|_| panic!("{at}: bad count")),
            );
        } else {
            panic!("{at}: unrecognised line {line:?}");
        }
    }
    for key in ["source", "date", "protocol", "persona"] {
        assert!(
            meta.contains_key(key),
            "{}: missing `# {key}:` header",
            path.display()
        );
    }
    Fixture {
        path: path.to_path_buf(),
        persona: meta["persona"].clone(),
        protocol: meta["protocol"].clone(),
        steps,
    }
}

fn shell_for(fixture: &Fixture) -> FakeShell {
    let ctx = EmitContext {
        source_ip: "192.0.2.10".parse::<IpAddr>().unwrap(),
        wan_ip: None,
        authenticated: true,
        protocol_label: fixture.protocol.clone(),
        session_id: None,
    };
    match fixture.persona.as_str() {
        "ubuntu" => FakeShell::new(FakeFs::new(), ctx),
        "android" => FakeShell::android(FakeFs::android(), ctx),
        other => panic!("{}: unknown persona {other:?}", fixture.path.display()),
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

fn check(fixture: &Fixture) -> Vec<String> {
    let mut shell = shell_for(fixture);
    let mut failures = Vec::new();
    for step in &fixture.steps {
        let at = format!("{}:{}", fixture.path.display(), step.line_no);
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
        let fixture = parse_fixture(path);
        let inputs = std::fs::read_to_string(path)
            .unwrap()
            .lines()
            .filter(|l| l.starts_with("$ "))
            .count();
        assert!(inputs > 0, "{}: no `$` lines", path.display());
        assert_eq!(
            fixture.steps.len(),
            inputs,
            "{}: parsed steps differ from `$` lines",
            path.display()
        );
        failures.extend(check(&fixture));
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
