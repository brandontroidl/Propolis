//! `env` and `printenv` through `handle_input`. The variables they print are the session's own, so
//! the expectations are compared with `export`, `$HOME` and a nested shell rather than with a
//! second copy of the persona's values. Ordering is by name on purpose: GNU prints in process
//! environment order, and the replay harness compares bytes. The wording of the error lines is
//! coreutils 8.32 and toybox as remembered, not captured, and the cases that pin it say so.

use super::{CommandResult, EmitContext, FakeShell, HandlerId, OutputFd};
use crate::fakefs::FakeFs;

fn ctx() -> EmitContext {
    EmitContext {
        source_ip: "203.0.113.7".parse().unwrap(),
        wan_ip: None,
        authenticated: true,
        protocol_label: "telnet".to_string(),
        session_id: None,
    }
}

fn shell() -> FakeShell {
    FakeShell::new(FakeFs::new(), ctx())
}

fn phone() -> FakeShell {
    FakeShell::android(FakeFs::android(), ctx())
}

fn stream(out: &CommandResult, fd: OutputFd) -> String {
    let bytes: Vec<u8> = out
        .output
        .iter()
        .filter(|segment| segment.fd == fd)
        .flat_map(|segment| segment.bytes.iter().copied())
        .collect();
    String::from_utf8(bytes).unwrap()
}

/// `(stdout, stderr, status)` of one line.
fn answer(sh: &mut FakeShell, line: &str) -> (String, String, u8) {
    let out = sh.handle_input(line).0;
    (
        stream(&out, OutputFd::Stdout),
        stream(&out, OutputFd::Stderr),
        out.status,
    )
}

fn out(sh: &mut FakeShell, line: &str) -> String {
    answer(sh, line).0
}

fn names(listing: &str) -> Vec<&str> {
    listing
        .lines()
        .map(|line| line.split_once('=').unwrap().0)
        .collect()
}

#[test]
fn env_lists_the_exported_variables_sorted_by_name() {
    let mut sh = shell();
    let listing = out(&mut sh, "env");
    let found = names(&listing);
    let mut sorted = found.clone();
    sorted.sort_unstable();
    assert_eq!(found, sorted, "{listing}");
    for expected in [
        "HOME=/root\n",
        "USER=root\n",
        "LOGNAME=root\n",
        "SHELL=/bin/bash\n",
        "PWD=/root\n",
    ] {
        assert!(listing.contains(expected), "{expected:?} in {listing}");
    }
    assert!(listing.contains("\nPATH=/usr/local/sbin:"), "{listing}");
    // Shell variables that are not exported are not in the environment.
    for hidden in ["IFS=", "UID=", "HOSTNAME="] {
        assert!(!listing.contains(hidden), "{hidden} leaked into {listing}");
    }
}

#[test]
fn the_order_is_by_name_whatever_order_the_variables_were_set_in() {
    let mut sh = shell();
    sh.handle_input("export Zed=1; export alpha=2; export Mid=3; export _x=4");
    let listing = out(&mut sh, "env");
    let found = names(&listing);
    let position = |name: &str| found.iter().position(|n| *n == name).unwrap();
    // Bytewise: upper case before `_` before lower case.
    assert!(position("Mid") < position("Zed"));
    assert!(position("Zed") < position("_x"));
    assert!(position("_x") < position("alpha"));
    let mut sorted = found.clone();
    sorted.sort_unstable();
    assert_eq!(found, sorted);
}

#[test]
fn the_output_is_byte_stable_across_runs_and_shells() {
    let setup = "export B=2; export A=1; export C='x y'";
    let mut first = shell();
    first.handle_input(setup);
    let mut second = shell();
    second.handle_input(setup);
    let env = out(&mut first, "env");
    assert_eq!(env, out(&mut first, "env"));
    assert_eq!(env, out(&mut second, "env"));
    let printenv = out(&mut first, "printenv");
    assert_eq!(printenv, out(&mut first, "printenv"));
    assert_eq!(printenv, out(&mut second, "printenv"));
    assert_eq!(env, printenv, "no operand: the two print the same list");
}

#[test]
fn printenv_prints_the_value_of_a_name_and_fails_on_an_unset_one() {
    let mut sh = shell();
    assert_eq!(
        answer(&mut sh, "printenv HOME"),
        ("/root\n".into(), "".into(), 0)
    );
    assert_eq!(
        answer(&mut sh, "printenv NOPE_NOT_SET"),
        ("".into(), "".into(), 1)
    );
    assert_eq!(out(&mut sh, "printenv HOME"), out(&mut sh, "echo $HOME"));
}

#[test]
fn printenv_with_several_names_prints_each_and_fails_if_any_is_unset() {
    let mut sh = shell();
    assert_eq!(
        answer(&mut sh, "printenv HOME USER"),
        ("/root\nroot\n".into(), "".into(), 0)
    );
    assert_eq!(
        answer(&mut sh, "printenv HOME NOPE USER"),
        ("/root\nroot\n".into(), "".into(), 1)
    );
    // A name holding `=` is never a variable.
    assert_eq!(
        answer(&mut sh, "printenv HOME=/root"),
        ("".into(), "".into(), 1)
    );
}

#[test]
fn a_shell_variable_that_is_not_exported_is_not_in_the_environment() {
    let mut sh = shell();
    sh.handle_input("FOO=bar");
    assert_eq!(answer(&mut sh, "printenv FOO"), ("".into(), "".into(), 1));
    assert!(!out(&mut sh, "env").contains("FOO="));
    sh.handle_input("export FOO");
    assert_eq!(out(&mut sh, "printenv FOO"), "bar\n");
    assert!(out(&mut sh, "env").contains("FOO=bar\n"));
}

#[test]
fn an_exported_variable_shows_in_env_and_printenv() {
    let mut sh = shell();
    sh.handle_input("export FOO=bar");
    assert!(out(&mut sh, "env").contains("FOO=bar\n"));
    assert!(out(&mut sh, "printenv").contains("FOO=bar\n"));
    assert_eq!(out(&mut sh, "printenv FOO"), "bar\n");
    sh.handle_input("unset FOO");
    assert!(!out(&mut sh, "env").contains("FOO="));
    assert_eq!(answer(&mut sh, "printenv FOO").2, 1);
}

#[test]
fn an_assignment_is_the_commands_environment_and_does_not_leak() {
    let mut sh = shell();
    assert_eq!(
        answer(&mut sh, "env FOO=baz printenv FOO"),
        ("baz\n".into(), "".into(), 0)
    );
    assert_eq!(answer(&mut sh, "printenv FOO"), ("".into(), "".into(), 1));
    assert!(!out(&mut sh, "env").contains("FOO="));
    // A value the session already had comes back after the command.
    sh.handle_input("export FOO=old");
    assert_eq!(out(&mut sh, "env FOO=new printenv FOO"), "new\n");
    assert_eq!(out(&mut sh, "printenv FOO"), "old\n");
    // The assignment is also visible to a nested `env`, and `=` in a value is kept.
    assert_eq!(out(&mut sh, "env A=b=c env printenv A"), "b=c\n");
    assert_eq!(
        answer(&mut sh, "env A= printenv A"),
        ("\n".into(), "".into(), 0)
    );
}

#[test]
fn assignments_without_a_command_print_the_edited_environment_and_leave_the_session_alone() {
    let mut sh = shell();
    let listing = out(&mut sh, "env ZZ=1 AA=2");
    assert!(listing.contains("AA=2\n") && listing.contains("ZZ=1\n"));
    assert!(listing.contains("HOME=/root\n"));
    let found = names(&listing);
    let mut sorted = found.clone();
    sorted.sort_unstable();
    assert_eq!(found, sorted);
    assert_eq!(answer(&mut sh, "printenv AA").2, 1);
    assert_eq!(answer(&mut sh, "printenv ZZ").2, 1);
}

#[test]
fn dash_i_starts_from_an_empty_environment() {
    let mut sh = shell();
    assert_eq!(
        answer(&mut sh, "env -i printenv HOME"),
        ("".into(), "".into(), 1)
    );
    assert_eq!(answer(&mut sh, "env -i"), ("".into(), "".into(), 0));
    assert_eq!(out(&mut sh, "env -i FOO=1 env"), "FOO=1\n");
    assert_eq!(out(&mut sh, "env - FOO=1"), "FOO=1\n");
    assert_eq!(
        out(&mut sh, "env --ignore-environment FOO=1 BAR=2"),
        "BAR=2\nFOO=1\n"
    );
    // The session's own environment is untouched afterwards.
    assert_eq!(out(&mut sh, "printenv HOME"), "/root\n");
}

#[test]
fn dash_u_drops_a_name_from_the_commands_environment() {
    let mut sh = shell();
    let whole = out(&mut sh, "env");
    for line in [
        "env -u HOME env",
        "env -uHOME env",
        "env --unset=HOME env",
        "env --unset HOME env",
        "env -u HOME",
    ] {
        let listing = out(&mut sh, line);
        assert!(!listing.contains("HOME="), "{line}: {listing}");
        assert!(listing.contains("USER=root\n"), "{line}: {listing}");
        let without_home: String = whole
            .lines()
            .filter(|l| !l.starts_with("HOME="))
            .map(|l| format!("{l}\n"))
            .collect();
        assert_eq!(listing, without_home, "{line}");
    }
    assert_eq!(
        answer(&mut sh, "env -u HOME printenv HOME"),
        ("".into(), "".into(), 1)
    );
    assert_eq!(out(&mut sh, "printenv HOME"), "/root\n");
    // Options apply before the assignments, so an assignment wins over a `-u` of the same name.
    assert_eq!(out(&mut sh, "env -i -u X Y=1"), "Y=1\n");
    let kept = out(&mut sh, "env -u Y Y=1");
    assert!(
        kept.contains("Y=1\n") && kept.contains("HOME=/root\n"),
        "{kept}"
    );
}

#[test]
fn a_nested_shell_inherits_the_edited_environment() {
    let mut sh = shell();
    assert_eq!(out(&mut sh, "env FOO=1 sh -c 'printenv FOO'"), "1\n");
    assert_eq!(
        answer(&mut sh, "env -i sh -c 'printenv HOME'"),
        ("".into(), "".into(), 1)
    );
    assert_eq!(answer(&mut sh, "printenv FOO").2, 1);
    assert_eq!(out(&mut sh, "printenv HOME"), "/root\n");
}

#[test]
fn the_environment_is_restored_when_the_command_fails_or_is_refused() {
    let mut sh = shell();
    sh.handle_input("env FOO=1 nosuchcommand; env -i cd /tmp; env -u HOME cd /tmp");
    assert_eq!(answer(&mut sh, "printenv FOO").2, 1);
    assert_eq!(out(&mut sh, "printenv HOME"), "/root\n");
    sh.handle_input("env FOO=1 sh -c 'exit 3'");
    assert_eq!(answer(&mut sh, "printenv FOO").2, 1);
    assert_eq!(out(&mut sh, "printenv HOME"), "/root\n");
    // And a command that opens a shell level leaves the login shell's variables as they were.
    sh.handle_input("env FOO=1 su");
    sh.handle_input("exit");
    assert_eq!(answer(&mut sh, "printenv FOO").2, 1);
    assert_eq!(out(&mut sh, "printenv HOME"), "/root\n");
}

#[test]
fn only_env_options_before_the_command_are_env_options() {
    let mut sh = shell();
    assert_eq!(out(&mut sh, "env echo -i -u HOME"), "-i -u HOME\n");
    assert_eq!(out(&mut sh, "env -- FOO=1 printenv FOO"), "1\n");
    assert_eq!(out(&mut sh, "env FOO=1 -- printenv FOO"), "");
}

#[test]
fn env_runs_the_command_the_shell_models_and_records_it_nested() {
    let mut sh = shell();
    assert_eq!(out(&mut sh, "env uname"), out(&mut sh, "uname"));
    assert_eq!(out(&mut sh, "env /bin/echo hi"), "hi\n");
    assert_eq!(out(&mut sh, "env echo hi"), "hi\n");
    assert_eq!(answer(&mut sh, "env false").2, 1);
    assert_eq!(out(&mut sh, "env env env printenv USER"), "root\n");
    sh.handle_input("env FOO=1 printenv FOO");
    let command = sh.last_trace().segments[0].command.as_ref().unwrap();
    assert_eq!(command.resolved, HandlerId::Env);
    assert_eq!(command.reentry.len(), 1);
    assert_eq!(command.reentry[0].resolved, HandlerId::Printenv);
    sh.handle_input("printenv HOME");
    let command = sh.last_trace().segments[0].command.as_ref().unwrap();
    assert_eq!(command.resolved, HandlerId::Printenv);
}

#[test]
fn a_command_that_is_not_a_file_is_env_s_not_found() {
    let mut sh = shell();
    for (line, wrong) in [
        (
            "env nosuchcmd",
            "env: 'nosuchcmd': No such file or directory\n",
        ),
        // Builtins that change the shell are not files.
        ("env cd /tmp", "env: 'cd': No such file or directory\n"),
        (
            "env export A=1",
            "env: 'export': No such file or directory\n",
        ),
        (
            "env /tmp/nothing-here",
            "env: '/tmp/nothing-here': No such file or directory\n",
        ),
    ] {
        assert_eq!(
            answer(&mut sh, line),
            ("".into(), wrong.into(), 127),
            "{line}"
        );
    }
    assert_eq!(
        out(&mut sh, "pwd"),
        "/root\n",
        "`env cd` did not move the shell"
    );
    sh.handle_input("echo > /tmp/plain");
    assert_eq!(
        answer(&mut sh, "env /tmp/plain"),
        (
            "".into(),
            "env: '/tmp/plain': Permission denied\n".into(),
            126
        )
    );
    assert_eq!(
        answer(&mut sh, "env /tmp"),
        ("".into(), "env: '/tmp': Permission denied\n".into(), 126)
    );
}

#[test]
fn a_bad_option_is_the_usage_error_with_status_125() {
    let mut sh = shell();
    let try_help = "Try 'env --help' for more information.\n";
    for (line, wrong) in [
        ("env -x", format!("env: invalid option -- 'x'\n{try_help}")),
        ("env -ix", format!("env: invalid option -- 'x'\n{try_help}")),
        (
            "env --bogus",
            format!("env: unrecognized option '--bogus'\n{try_help}"),
        ),
        (
            "env -u",
            format!("env: option requires an argument -- 'u'\n{try_help}"),
        ),
        (
            "env --unset",
            format!("env: option '--unset' requires an argument\n{try_help}"),
        ),
        (
            "env -u A=B",
            "env: cannot unset 'A=B': Invalid argument\n".to_string(),
        ),
        (
            "env -0 echo hi",
            format!("env: cannot specify --null (-0) with command\n{try_help}"),
        ),
    ] {
        assert_eq!(answer(&mut sh, line), ("".into(), wrong, 125), "{line}");
    }
    assert_eq!(out(&mut sh, "printenv HOME"), "/root\n");
}

#[test]
fn null_terminates_each_entry_with_nul() {
    let mut sh = shell();
    assert_eq!(out(&mut sh, "printenv -0 HOME USER"), "/root\0root\0");
    assert_eq!(out(&mut sh, "printenv --null HOME"), "/root\0");
    let listing = out(&mut sh, "env -0 -i A=1 B=2");
    assert_eq!(listing, "A=1\0B=2\0");
}

#[test]
fn printenv_rejects_an_unknown_option_with_status_2() {
    let mut sh = shell();
    let try_help = "Try 'printenv --help' for more information.\n";
    assert_eq!(
        answer(&mut sh, "printenv -x"),
        (
            "".into(),
            format!("printenv: invalid option -- 'x'\n{try_help}"),
            2
        )
    );
    assert_eq!(
        answer(&mut sh, "printenv --bogus"),
        (
            "".into(),
            format!("printenv: unrecognized option '--bogus'\n{try_help}"),
            2
        )
    );
    // After `--` a dash-led word is a name, and no such variable is set.
    assert_eq!(answer(&mut sh, "printenv -- -x"), ("".into(), "".into(), 1));
}

#[test]
fn ubuntu_has_both_and_the_phone_has_only_env() {
    let mut ubuntu = shell();
    for name in ["env", "printenv"] {
        assert_eq!(
            answer(&mut ubuntu, &format!("command -v {name}")),
            (format!("/usr/bin/{name}\n"), "".into(), 0),
            "{name}"
        );
    }
    let mut sh = phone();
    assert_eq!(
        answer(&mut sh, "command -v env"),
        ("/system/bin/env\n".into(), "".into(), 0)
    );
    assert_eq!(answer(&mut sh, "type env").0, "env is /system/bin/env\n");
    assert!(sh.fs.is_executable("/system/bin/env"));
    assert!(
        out(&mut sh, "ls /system/bin")
            .split_whitespace()
            .any(|l| l == "env")
    );
    let (stdout, stderr, status) = answer(&mut sh, "printenv HOME");
    assert_eq!((stdout.as_str(), status), ("", 127));
    assert!(stderr.contains("not found"), "{stderr}");
    assert_ne!(answer(&mut sh, "command -v printenv").2, 0);
}

#[test]
fn the_phone_s_env_reads_the_phone_s_environment() {
    let mut sh = phone();
    let listing = out(&mut sh, "env");
    assert!(listing.contains("SHELL=/system/bin/sh\n"), "{listing}");
    assert!(
        listing.contains("PATH=/sbin:/vendor/bin:/system/sbin:/system/bin:/system/xbin\n"),
        "{listing}"
    );
    assert!(!listing.contains("HOME="), "{listing}");
    let found = names(&listing);
    let mut sorted = found.clone();
    sorted.sort_unstable();
    assert_eq!(found, sorted);
    let mut expected: Vec<String> = listing.lines().map(str::to_string).collect();
    expected.push("FOO=1".to_string());
    expected.sort();
    let expected: String = expected.iter().map(|l| format!("{l}\n")).collect();
    assert_eq!(out(&mut sh, "env FOO=1 env"), expected);
    assert!(!out(&mut sh, "env -u PATH env").contains("PATH="));
    assert_eq!(out(&mut sh, "env -i A=1"), "A=1\n");
    assert_eq!(out(&mut sh, "export Q=1; toybox env -i Q=2"), "Q=2\n");
    assert_eq!(
        answer(&mut sh, "env nosuch"),
        (
            "".into(),
            "env: exec nosuch: No such file or directory\n".into(),
            127
        )
    );
    assert_eq!(
        answer(&mut sh, "env -x"),
        ("".into(), "env: Unknown option 'x'\n".into(), 1)
    );
}

#[test]
fn busybox_and_toybox_route_to_the_same_env() {
    let mut ubuntu = shell();
    assert_eq!(
        out(&mut ubuntu, "busybox env -i A=1 env"),
        out(&mut ubuntu, "env -i A=1 env")
    );
    assert_eq!(
        answer(&mut ubuntu, "busybox printenv HOME").1,
        "printenv: applet not found\n"
    );
    let mut sh = phone();
    assert_eq!(out(&mut sh, "toybox env -i A=1"), "A=1\n");
    assert_eq!(out(&mut sh, "busybox env -i A=2"), "A=2\n");
}

#[test]
fn it_reads_only_the_session_and_never_the_host() {
    // The test process has these set, and neither is visible to the session.
    assert!(std::env::var_os("CARGO_MANIFEST_DIR").is_some());
    let mut sh = shell();
    assert_eq!(
        answer(&mut sh, "printenv CARGO_MANIFEST_DIR"),
        ("".into(), "".into(), 1)
    );
    assert!(!out(&mut sh, "env").contains("CARGO"));
    assert_eq!(out(&mut sh, "printenv HOME"), "/root\n");
    // The module holds no process, socket, host-file or host-environment API of its own.
    let source = include_str!("envtools.rs");
    let spawn = ["Command", "::new"].concat();
    let host_env = ["std::", "env"].concat();
    for banned in [
        "process::",
        spawn.as_str(),
        "std::fs",
        "std::net",
        host_env.as_str(),
        "libc",
        "TcpStream",
    ] {
        assert!(!source.contains(banned), "envtools.rs uses {banned}");
    }
}
