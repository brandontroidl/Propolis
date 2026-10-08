//! bash's `time` keyword and `history` builtin through `handle_input`, against the 2026-10-07
//! Ubuntu 22.04 reference session (bash 5.1).

use super::{CommandResult, EmitContext, FakeShell, OutputFd};
use crate::fakefs::FakeFs;

fn ctx() -> EmitContext {
    EmitContext {
        source_ip: "203.0.113.7".parse().unwrap(),
        wan_ip: None,
        authenticated: true,
        protocol_label: "ssh".to_string(),
        session_id: None,
    }
}

fn stream(out: &CommandResult, fd: OutputFd) -> String {
    let bytes: Vec<u8> = out
        .output
        .iter()
        .filter(|segment| segment.fd == fd)
        .flat_map(|segment| segment.bytes.iter().copied())
        .collect();
    String::from_utf8_lossy(&bytes).into_owned()
}

fn answer(sh: &mut FakeShell, line: &str) -> (String, String, u8) {
    let out = sh.handle_input(line).0;
    (
        stream(&out, OutputFd::Stdout),
        stream(&out, OutputFd::Stderr),
        out.status,
    )
}

/// `real\t0m0.019s` and the like, as milliseconds.
fn millis(report: &str, label: &str) -> u64 {
    let line = report
        .lines()
        .find(|l| l.starts_with(label))
        .unwrap_or_else(|| panic!("{label} in {report:?}"));
    let value = line.split('\t').nth(1).unwrap();
    let (minutes, rest) = value.split_once('m').unwrap();
    let seconds = rest.trim_end_matches('s');
    let (whole, fraction) = seconds.split_once('.').unwrap();
    minutes.parse::<u64>().unwrap() * 60_000
        + whole.parse::<u64>().unwrap() * 1_000
        + fraction.parse::<u64>().unwrap()
}

#[test]
fn time_reports_on_standard_error_in_bash_format() {
    let mut sh = FakeShell::exec(FakeFs::new(), ctx());
    // A builtin starts no process: the recorded zeros.
    assert_eq!(
        answer(&mut sh, "time true"),
        (
            "".into(),
            "\nreal\t0m0.000s\nuser\t0m0.000s\nsys\t0m0.000s\n".into(),
            0
        )
    );
    assert_eq!(
        answer(&mut sh, "time -p true"),
        ("".into(), "real 0.00\nuser 0.00\nsys 0.00\n".into(), 0)
    );
    assert_eq!(
        answer(&mut sh, "time"),
        (
            "".into(),
            "\nreal\t0m0.000s\nuser\t0m0.000s\nsys\t0m0.000s\n".into(),
            0
        )
    );
    // The command's own redirection does not catch the report.
    let (out, err, _) = answer(&mut sh, "time echo hi 2>/dev/null");
    assert_eq!(out, "hi\n");
    assert!(err.starts_with("\nreal\t"), "{err:?}");
    // A group's redirection does.
    let (out, err, _) = answer(&mut sh, "{ time true; } 2>&1");
    assert_eq!(err, "");
    assert!(out.starts_with("\nreal\t0m0.000s\n"), "{out:?}");
    // The status is the timed pipeline's.
    assert_eq!(answer(&mut sh, "time false").2, 1);
    assert_eq!(answer(&mut sh, "time ! true").2, 1);
    let (_, _, status) = answer(&mut sh, "type time");
    assert_eq!(status, 0);
    assert_eq!(answer(&mut sh, "type time").0, "time is a shell keyword\n");
}

#[test]
fn time_agrees_with_what_the_timed_commands_claim() {
    let mut sh = FakeShell::exec(FakeFs::new(), ctx());
    let (_, err, _) = answer(&mut sh, "time sleep 1");
    let real = millis(&err, "real");
    assert!((1_000..1_100).contains(&real), "{err:?}");
    let (out, err, status) = answer(
        &mut sh,
        "time dd if=/dev/zero of=/tmp/test bs=1M count=10 2>&1",
    );
    assert_eq!(status, 0, "{out}{err}");
    assert!(
        out.starts_with(
            "10+0 records in\n10+0 records out\n10485760 bytes (10 MB, 10 MiB) copied, "
        ),
        "{out:?}"
    );
    // The `copied, S s` figure can be no longer than the `real` that times it.
    let seconds: f64 = out
        .split("copied, ")
        .nth(1)
        .and_then(|rest| rest.split(' ').next())
        .unwrap()
        .parse()
        .unwrap();
    let real = millis(&err, "real");
    assert!(
        (seconds * 1000.0) as u64 <= real,
        "dd {seconds} s within real {real} ms"
    );
    assert!(millis(&err, "sys") <= real && millis(&err, "user") <= real);
}

#[test]
fn time_is_no_keyword_in_dash() {
    let mut sh = FakeShell::exec(FakeFs::new(), ctx());
    assert_eq!(
        answer(&mut sh, "sh -c 'time true'"),
        ("".into(), "sh: 1: time: not found\n".into(), 127)
    );
}

#[test]
fn history_lists_the_interactive_lines_and_nothing_on_exec() {
    let mut exec = FakeShell::exec(FakeFs::new(), ctx());
    assert_eq!(
        answer(&mut exec, "history | tail -5"),
        ("".into(), "".into(), 0)
    );
    assert_eq!(
        answer(&mut exec, "history foo"),
        (
            "".into(),
            "bash: line 1: history: foo: numeric argument required\n".into(),
            1
        )
    );

    let mut login = FakeShell::new(FakeFs::new(), ctx());
    answer(&mut login, "echo one");
    assert_eq!(
        answer(&mut login, "history").0,
        "    1  echo one\n    2  history\n"
    );
    assert_eq!(
        answer(&mut login, "history 2").0,
        "    2  history\n    3  history 2\n"
    );
    // Ubuntu's `HISTCONTROL=ignoreboth`: a leading space and an immediate repeat are not kept.
    answer(&mut login, " echo hidden");
    answer(&mut login, "history 2");
    assert_eq!(
        answer(&mut login, "history 1").0,
        "    4  history 1\n",
        "the repeat of `history 2` and the spaced line were dropped"
    );
    answer(&mut login, "history -c");
    assert_eq!(answer(&mut login, "history").0, "    1  history\n");
    // dash has none.
    answer(&mut login, "sh");
    assert_eq!(
        answer(&mut login, "history"),
        ("".into(), "sh: 1: history: not found\n".into(), 127)
    );
}
