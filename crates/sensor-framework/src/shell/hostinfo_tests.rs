//! `hostname`, `arch`, `nproc`, `date` and `uptime` through `handle_input`. Every time is read
//! from a fixed clock, so the expected strings are exact and a replay prints the same bytes. The
//! persona facts (host name, machine, core count) are compared with the commands and files that
//! already state them, not with a second copy of the constants. Layouts beyond the persona are
//! procps and GNU coreutils as remembered, not captured, and the cases leaning on them say so.

use chrono::{DateTime, TimeZone, Utc};

use super::{CommandResult, EmitContext, FakeShell, OutputFd};
use crate::fakefs::FakeFs;
use crate::persona;

fn ctx() -> EmitContext {
    EmitContext {
        source_ip: "203.0.113.7".parse().unwrap(),
        wan_ip: None,
        authenticated: true,
        protocol_label: "telnet".to_string(),
        session_id: None,
    }
}

/// Friday 2026-10-02 12:34:56 UTC, epoch second 1790944496.
fn friday() -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 10, 2, 12, 34, 56).unwrap()
}

/// Ninety seconds after [`friday`].
fn friday_later() -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 10, 2, 12, 36, 26).unwrap()
}

fn shell() -> FakeShell {
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

fn out(sh: &mut FakeShell, line: &str) -> String {
    answer(sh, line).0
}

#[test]
fn hostname_is_the_etc_hostname_content_and_the_uname_nodename() {
    let mut sh = shell();
    let etc = out(&mut sh, "cat /etc/hostname");
    assert_eq!(out(&mut sh, "hostname"), etc);
    assert_eq!(etc, format!("{}\n", persona::hostname()));
    assert_eq!(out(&mut sh, "hostname"), out(&mut sh, "uname -n"));
    // The short, long and address forms all resolve through the persona's own host and hosts file.
    assert_eq!(out(&mut sh, "hostname -s"), etc);
    assert_eq!(out(&mut sh, "hostname -f"), etc);
    assert_eq!(out(&mut sh, "hostname --fqdn"), etc);
    assert!(out(&mut sh, "cat /etc/hosts").contains("127.0.1.1 server01"));
    assert_eq!(out(&mut sh, "hostname -i"), "127.0.1.1\n");
}

#[test]
fn hostname_on_the_phone_is_what_its_uname_says() {
    let mut sh = phone();
    assert_eq!(out(&mut sh, "hostname"), out(&mut sh, "uname -n"));
    assert_eq!(
        out(&mut sh, "hostname"),
        format!("{}\n", persona::ANDROID_HOSTNAME)
    );
    assert_eq!(out(&mut sh, "toybox hostname"), out(&mut sh, "uname -n"));
}

#[test]
fn setting_the_hostname_succeeds_and_changes_nothing() {
    let mut sh = shell();
    let before = out(&mut sh, "hostname");
    assert_eq!(answer(&mut sh, "hostname web01"), ("".into(), "".into(), 0));
    assert_eq!(out(&mut sh, "hostname"), before);
    assert_eq!(out(&mut sh, "cat /etc/hostname"), before);
    assert_eq!(answer(&mut sh, "hostname -d"), ("\n".into(), "".into(), 0));
    let (stdout, stderr, status) = answer(&mut sh, "hostname -Z");
    assert_eq!((stdout.as_str(), status), ("", 1));
    assert!(
        stderr.starts_with("hostname: invalid option -- 'Z'"),
        "{stderr}"
    );
}

#[test]
fn arch_equals_uname_m_on_ubuntu_and_the_phone_has_none() {
    let mut sh = shell();
    assert_eq!(out(&mut sh, "arch"), out(&mut sh, "uname -m"));
    assert_eq!(out(&mut sh, "arch"), format!("{}\n", persona::ARCH));
    assert_eq!(out(&mut sh, "/bin/busybox arch"), "x86_64\n");
    let (_, stderr, status) = answer(&mut sh, "arch -x");
    assert_eq!(status, 1);
    assert!(
        stderr.starts_with("arch: invalid option -- 'x'"),
        "{stderr}"
    );
    assert_eq!(answer(&mut sh, "arch extra").2, 1);

    let mut phone = phone();
    let (stdout, stderr, status) = answer(&mut phone, "arch");
    assert_eq!((stdout.as_str(), status), ("", 127), "{stderr}");
    assert_eq!(answer(&mut phone, "command -v arch").2, 1);
    assert_eq!(
        out(&mut phone, "uname -m"),
        format!("{}\n", persona::ANDROID_ARCH)
    );
}

#[test]
fn nproc_equals_the_processor_entries_of_cpuinfo() {
    let mut sh = shell();
    let cpuinfo = out(&mut sh, "cat /proc/cpuinfo");
    let cores = cpuinfo
        .lines()
        .filter(|line| line.starts_with("processor"))
        .count();
    assert!(cores >= 1);
    assert_eq!(out(&mut sh, "nproc"), format!("{cores}\n"));
    assert_eq!(out(&mut sh, "nproc --all"), format!("{cores}\n"));
    // `--ignore` never takes the answer below one, as in coreutils.
    assert_eq!(out(&mut sh, "nproc --ignore=5"), "1\n");
    assert_eq!(out(&mut sh, "nproc --ignore 0"), format!("{cores}\n"));
    let (_, stderr, status) = answer(&mut sh, "nproc --ignore=x");
    assert_eq!(
        (stderr.as_str(), status),
        ("nproc: invalid number: 'x'\n", 1)
    );
    assert_eq!(answer(&mut sh, "nproc -q").2, 1);
}

#[test]
fn nproc_follows_the_filesystem_it_reads() {
    let mut sh = shell();
    sh.fs
        .write_file(
            "/proc/cpuinfo",
            b"processor\t: 0\nprocessor\t: 1\nprocessor\t: 2\n",
        )
        .unwrap();
    assert_eq!(out(&mut sh, "nproc"), "3\n");
    assert_eq!(out(&mut sh, "nproc --ignore=2"), "1\n");
}

#[test]
fn the_phone_has_no_nproc() {
    let mut sh = phone();
    let (stdout, _, status) = answer(&mut sh, "nproc");
    assert_eq!((stdout.as_str(), status), ("", 127));
    assert_eq!(answer(&mut sh, "toybox nproc").2, 1);
}

#[test]
fn date_prints_the_fixed_clock_in_the_gnu_default_layout() {
    let mut sh = shell();
    assert_eq!(out(&mut sh, "date"), "Fri Oct  2 12:34:56 UTC 2026\n");
    assert_eq!(out(&mut sh, "date -u"), "Fri Oct  2 12:34:56 UTC 2026\n");
    assert_eq!(out(&mut sh, "date --utc"), "Fri Oct  2 12:34:56 UTC 2026\n");
    // Run again: a fixed clock is a fixed answer.
    assert_eq!(out(&mut sh, "date"), out(&mut sh, "date"));
    let mut sh = phone();
    assert_eq!(out(&mut sh, "date"), "Fri Oct  2 12:34:56 UTC 2026\n");
    assert_eq!(
        out(&mut sh, "toybox date -u"),
        "Fri Oct  2 12:34:56 UTC 2026\n"
    );
}

#[test]
fn date_formats_are_exact_and_replay_stable() {
    let mut sh = shell();
    for (line, want) in [
        ("date +%Y-%m-%d", "2026-10-02\n"),
        ("date +%F", "2026-10-02\n"),
        ("date +%T", "12:34:56\n"),
        ("date '+%H:%M:%S'", "12:34:56\n"),
        ("date +%s", "1790944496\n"),
        ("date +%Z", "UTC\n"),
        ("date +%a-%b-%e", "Fri-Oct- 2\n"),
        ("date +%A,%B", "Friday,October\n"),
        ("date +%j-%u-%w-%y-%C", "275-5-5-26-20\n"),
        ("date '+%d/%m/%Y %I:%M %p'", "02/10/2026 12:34 PM\n"),
        ("date +%-d.%-m", "2.10\n"),
        ("date +%_m", "10\n"),
        ("date +%N", "000000000\n"),
        (
            "date '+backup-%Y%m%d-%H%M%S.tar'",
            "backup-20261002-123456.tar\n",
        ),
        ("date +%%", "%\n"),
        ("date +%Q", "%Q\n"),
        ("date -R", "Fri, 02 Oct 2026 12:34:56 +0000\n"),
        ("date -I", "2026-10-02\n"),
        ("date -Iseconds", "2026-10-02T12:34:56+00:00\n"),
        ("date --iso-8601=minutes", "2026-10-02T12:34+00:00\n"),
        ("date --rfc-3339=seconds", "2026-10-02 12:34:56+00:00\n"),
    ] {
        assert_eq!(out(&mut sh, line), want, "{line}");
    }
    // The same line under the same clock in a second shell is the same bytes.
    assert_eq!(out(&mut shell(), "date +%s"), out(&mut shell(), "date +%s"));
}

#[test]
fn date_reads_the_shell_clock_and_not_the_system_one() {
    let mut sh = shell().with_clock(friday_later);
    assert_eq!(out(&mut sh, "date +%T"), "12:36:26\n");
    assert_eq!(out(&mut sh, "date +%s"), "1790944586\n");
    // A year in the output that the real clock cannot be at proves it is not read.
    assert_eq!(out(&mut sh, "date +%Y"), "2026\n");
}

#[test]
fn date_dash_d_takes_a_small_grammar_and_refuses_the_rest() {
    let mut sh = shell();
    for (line, want) in [
        ("date -d now +%T", "12:34:56\n"),
        ("date -d @0 -u +%F", "1970-01-01\n"),
        ("date --date=@86400 +%F", "1970-01-02\n"),
        ("date -d 2020-02-29 +%a", "Sat\n"),
        ("date -d '2020-02-29 01:02:03' +%T", "01:02:03\n"),
        ("date -d yesterday +%F", "2026-10-01\n"),
        ("date -d '1 hour ago' +%T", "11:34:56\n"),
        ("date -d '2 days' +%F", "2026-10-04\n"),
        ("date -dtomorrow +%F", "2026-10-03\n"),
    ] {
        assert_eq!(out(&mut sh, line), want, "{line}");
    }
    for text in [
        "next friday",
        "id",
        "$(id)",
        "3 fortnights",
        "@9999999999999999999",
    ] {
        let (stdout, stderr, status) = answer(&mut sh, &format!("date -d '{text}'"));
        assert_eq!((stdout.as_str(), status), ("", 1), "{text}");
        assert!(
            stderr.starts_with("date: invalid date '"),
            "{text}: {stderr}"
        );
    }
}

#[test]
fn date_refuses_to_set_the_clock_and_rejects_bad_options() {
    let mut sh = shell();
    let (stdout, stderr, status) = answer(&mut sh, "date -s '2020-01-01 00:00:00'");
    assert_eq!((stdout.as_str(), status), ("", 1));
    assert_eq!(stderr, "date: cannot set date: Operation not permitted\n");
    assert_eq!(out(&mut sh, "date +%Y"), "2026\n", "the clock did not move");
    assert_eq!(answer(&mut sh, "date 100212342026").2, 1);
    let (_, stderr, status) = answer(&mut sh, "date -Z");
    assert_eq!(status, 1);
    assert!(
        stderr.starts_with("date: invalid option -- 'Z'"),
        "{stderr}"
    );
    assert_eq!(answer(&mut sh, "date --nope").2, 1);
    assert_eq!(answer(&mut sh, "date -d").2, 1);
    assert_eq!(answer(&mut sh, "date +%Y +%m").2, 1);
}

#[test]
fn date_dash_r_reads_a_files_modification_time() {
    let mut sh = shell();
    let (stdout, stderr, status) = answer(&mut sh, "date -r /nonexistent");
    assert_eq!((stdout.as_str(), status), ("", 1));
    assert_eq!(stderr, "date: /nonexistent: No such file or directory\n");
    sh.fs.write_file("/tmp/x", b"x").unwrap();
    let (stdout, _, status) = answer(&mut sh, "date -r /tmp/x +%Y");
    assert_eq!(status, 0);
    assert_eq!(
        stdout.len(),
        5,
        "a four digit year and a newline: {stdout:?}"
    );
}

#[test]
fn date_output_is_bounded() {
    let mut sh = shell();
    let wide = out(&mut sh, "date +%999999999999Y%999999999999Y%999999999999Y");
    assert!(wide.len() <= 4096 + 64 + 1, "{}", wide.len());
    let long = format!("date +'{}'", "%a".repeat(5000));
    assert!(out(&mut sh, &long).len() <= 4097);
}

#[test]
fn uptime_is_the_procps_line_and_stable_under_a_fixed_clock() {
    let mut sh = shell();
    // Epoch second 1790944496 is 744517 s into the box's boot window: 8 days, 14:48.
    let line = " 12:34:56 up 8 days, 14:48,  1 user,  load average: 0.07, 0.10, 0.01\n";
    assert_eq!(out(&mut sh, "uptime"), line);
    assert_eq!(out(&mut sh, "uptime"), line);
    assert_eq!(out(&mut shell(), "uptime"), line);
    assert_eq!(
        out(&mut sh, "uptime -p"),
        "up 1 week, 1 day, 14 hours, 48 minutes\n"
    );
    assert_eq!(out(&mut sh, "uptime -s"), "2026-09-23 21:46:19\n");
    assert_eq!(out(&mut phone(), "uptime"), line);
    assert_eq!(out(&mut phone(), "toybox uptime"), line);
}

#[test]
fn uptime_advances_with_the_clock() {
    let mut sh = shell().with_clock(friday_later);
    assert_eq!(
        out(&mut sh, "uptime"),
        " 12:36:26 up 8 days, 14:50,  1 user,  load average: 0.11, 0.03, 0.02\n"
    );
    // The boot instant is the same from both readings.
    assert_eq!(out(&mut sh, "uptime -s"), "2026-09-23 21:46:19\n");
}

#[test]
fn the_busybox_applets_route_to_the_same_handlers() {
    let mut sh = shell();
    for name in ["date +%F", "uptime -s", "hostname", "nproc", "arch"] {
        assert_eq!(
            out(&mut sh, &format!("/bin/busybox {name}")),
            out(&mut sh, name),
            "{name}"
        );
    }
}

#[test]
fn the_commands_run_nothing_and_read_nothing_of_the_host() {
    let mut sh = shell();
    let before = sh.fs.list_dir("/tmp").unwrap();
    for line in [
        "date -d '$(touch /tmp/pwn)'",
        "date '+%Y; touch /tmp/pwn2'",
        "hostname 'touch /tmp/pwn3'",
        "date -s 'touch /tmp/pwn4'",
    ] {
        let _ = answer(&mut sh, line);
    }
    let after = sh.fs.list_dir("/tmp").unwrap();
    assert_eq!(before, after, "no command created a file");
    // A format string is text: nothing in it is run.
    assert_eq!(out(&mut sh, "date '+$(id)'"), "$(id)\n");
}
