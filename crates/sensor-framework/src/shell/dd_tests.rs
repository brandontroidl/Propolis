//! `dd` through `handle_input`, over the F1 images. Expected data bytes are the images read
//! directly, not through the command under test (the generator has its own tests). The
//! record lines and the GNU summary layout are the ones in the ground-truth capture ("dd"
//! section); the summary's elapsed time is synthesized, so only its layout is asserted for a run
//! and the captured (bytes, time) pairs are asserted through `summary_line`.

use std::sync::Arc;

use super::dd::summary_line;
use super::{CommandResult, EmitContext, FakeShell, OutputFd};
use crate::binaries;
use crate::budget::{BudgetLimits, ConnectionBudget};
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

fn run(sh: &mut FakeShell, line: &str) -> CommandResult {
    sh.handle_input(line).0
}

/// The first 4096 bytes of the modeled image of `name`, the most the tests reach.
fn image(name: &str) -> Vec<u8> {
    binaries::find(name).unwrap().blob().read_range(0, 4096)
}

fn stdout_of(out: &CommandResult) -> Vec<u8> {
    out.output
        .iter()
        .filter(|segment| segment.fd == OutputFd::Stdout)
        .flat_map(|segment| segment.bytes.iter().copied())
        .collect()
}

fn stderr_of(out: &CommandResult) -> String {
    let bytes: Vec<u8> = out
        .output
        .iter()
        .filter(|segment| segment.fd == OutputFd::Stderr)
        .flat_map(|segment| segment.bytes.iter().copied())
        .collect();
    String::from_utf8(bytes).unwrap()
}

const ONE_RECORD: &str = "1+0 records in\n1+0 records out\n";

/// A GNU summary: `N bytes copied, T s, R unit/s`, whatever T and R are.
fn assert_gnu_summary(report: &str, records: &str, summary_start: &str) {
    let tail = report.strip_prefix(records).expect("record lines first");
    assert!(tail.starts_with(summary_start), "{tail:?}");
    assert!(tail.ends_with("/s\n") && tail.contains(" s, "), "{tail:?}");
    assert_eq!(tail.matches('\n').count(), 1, "{tail:?}");
}

#[test]
fn the_52_byte_ls_read_is_the_header_then_the_gnu_records_and_summary() {
    let expected = &image("ls")[..52];
    let out = run(&mut shell(), "dd bs=52 count=1 if=/bin/ls");
    assert_eq!(out.status, 0);
    assert_eq!(stdout_of(&out), expected);
    assert_eq!(&out.bytes()[..52], expected, "data first, then the report");
    assert_gnu_summary(&stderr_of(&out), ONE_RECORD, "52 bytes copied, ");
}

#[test]
fn the_busybox_dd_prints_two_record_lines_and_no_summary() {
    let expected = &image("ls")[..52];
    for line in [
        "/bin/busybox dd bs=52 count=1 if=/bin/ls",
        "busybox dd if=/bin/ls bs=52 count=1",
    ] {
        let out = run(&mut shell(), line);
        assert_eq!(out.status, 0, "{line}");
        let mut want = expected.to_vec();
        want.extend_from_slice(ONE_RECORD.as_bytes());
        assert_eq!(out.bytes(), want.as_slice(), "{line}");
    }
}

#[test]
fn summary_lines_match_every_captured_run() {
    // (bytes, elapsed ns, the captured GNU summary line).
    for (moved, ns, want) in [
        (22, 165_584, "22 bytes copied, 0.000165584 s, 133 kB/s\n"),
        (22, 88_379, "22 bytes copied, 8.8379e-05 s, 249 kB/s\n"),
        (52, 404_895, "52 bytes copied, 0.000404895 s, 128 kB/s\n"),
        (3, 264_003, "3 bytes copied, 0.000264003 s, 11.4 kB/s\n"),
        (1, 92_276, "1 byte copied, 9.2276e-05 s, 10.8 kB/s\n"),
        (4, 237_402, "4 bytes copied, 0.000237402 s, 16.8 kB/s\n"),
        (8, 218_881, "8 bytes copied, 0.000218881 s, 36.5 kB/s\n"),
    ] {
        assert_eq!(summary_line(moved, ns), want);
    }
}

#[test]
fn a_run_is_deterministic_for_a_session() {
    let first = run(&mut shell(), "dd bs=22 count=1 if=/bin/ls");
    let again = run(&mut shell(), "dd bs=22 count=1 if=/bin/ls");
    assert_eq!(first.bytes(), again.bytes());
}

#[test]
fn skip_and_count_pick_blocks_by_arithmetic() {
    let ls = image("ls");
    // Captured: `dd if=/bin/echo bs=4 skip=1 count=1` printed `02 01 01 00`, the same four bytes.
    let out = run(
        &mut shell(),
        "/bin/busybox dd if=/bin/ls bs=4 skip=1 count=1",
    );
    assert_eq!(stdout_of(&out), &ls[4..8]);
    assert_eq!(stderr_of(&out), ONE_RECORD);
    for (line, from, len, records) in [
        ("dd if=/bin/ls bs=8 skip=3 count=2", 24, 16, "2+0"),
        ("dd if=/bin/ls bs=1K count=1", 0, 1024, "1+0"),
        ("dd if=/bin/ls bs=1 skip=7 count=5", 7, 5, "5+0"),
        ("dd if=/bin/ls skip=1 count=1", 512, 512, "1+0"),
        ("dd if=/bin/ls ibs=16 obs=16 count=2", 0, 32, "2+0"),
        ("dd if=/bin/ls bs=52 count=0", 0, 0, "0+0"),
    ] {
        let out = run(&mut shell(), line);
        assert_eq!(stdout_of(&out), &ls[from..from + len], "{line}");
        assert!(
            stderr_of(&out).starts_with(&format!("{records} records in\n{records} records out\n")),
            "{line}: {}",
            stderr_of(&out)
        );
    }
}

#[test]
fn a_short_input_is_a_partial_record() {
    let mut sh = shell();
    run(&mut sh, "echo -n abc > /tmp/s3");
    // Captured (busybox): `0+1 records in` / `0+1 records out`.
    let out = run(&mut sh, "/bin/busybox dd if=/tmp/s3 bs=22 count=1");
    assert_eq!(out.bytes(), b"abc0+1 records in\n0+1 records out\n");
    let out = run(&mut sh, "dd if=/tmp/s3 bs=22 count=1");
    assert_eq!(stdout_of(&out), b"abc");
    assert_gnu_summary(
        &stderr_of(&out),
        "0+1 records in\n0+1 records out\n",
        "3 bytes copied, ",
    );
    // A read starting past the end moves nothing.
    let out = run(&mut sh, "/bin/busybox dd if=/tmp/s3 bs=22 skip=5 count=1");
    assert_eq!(out.bytes(), b"0+0 records in\n0+0 records out\n");
}

#[test]
fn a_device_input_and_a_two_record_read() {
    let out = run(&mut shell(), "/bin/busybox dd if=/dev/zero bs=4 count=2");
    let mut want = vec![0u8; 8];
    want.extend_from_slice(b"2+0 records in\n2+0 records out\n");
    assert_eq!(out.bytes(), want.as_slice());
}

#[test]
fn proc_self_exe_is_the_image_of_the_process_that_opens_it() {
    let dd = image("dd");
    let busybox = image("busybox");
    let bash = image("bash");
    let out = run(&mut shell(), "dd if=/proc/self/exe bs=22 count=1");
    assert_eq!(stdout_of(&out), &dd[..22]);
    let out = run(
        &mut shell(),
        "/bin/busybox dd if=/proc/self/exe bs=22 count=1",
    );
    assert_eq!(stdout_of(&out), &busybox[..22]);
    assert_eq!(stdout_of(&out)[7], 0x03, "OS/ABI byte of the BusyBox build");
    for line in [
        "dd if=$SHELL bs=22 count=1",
        "/bin/busybox dd if=\"$SHELL\" bs=22 count=1",
    ] {
        let out = run(&mut shell(), line);
        assert_eq!(stdout_of(&out), &bash[..22], "{line}");
    }
    let out = run(
        &mut shell(),
        "/bin/busybox dd if=/bin/busybox bs=22 count=1",
    );
    assert_eq!(stdout_of(&out), &busybox[..22]);
}

#[test]
fn of_writes_the_file_and_leaves_standard_output_empty() {
    let ls = image("ls");
    let mut sh = shell();
    let out = run(&mut sh, "dd if=/bin/ls of=/tmp/dd.out bs=22 count=1");
    assert_eq!(out.status, 0);
    assert!(stdout_of(&out).is_empty());
    assert_gnu_summary(&stderr_of(&out), ONE_RECORD, "22 bytes copied, ");
    assert_eq!(run(&mut sh, "cat /tmp/dd.out").bytes(), &ls[..22]);
    // Truncated by the next write.
    run(&mut sh, "dd if=/bin/ls of=/tmp/dd.out bs=4 count=1");
    assert_eq!(run(&mut sh, "cat /tmp/dd.out").bytes(), &ls[..4]);
    // conv=notrunc keeps the tail; seek writes at an offset with a zero gap before it.
    run(
        &mut sh,
        "dd if=/bin/ls of=/tmp/dd.out bs=2 count=1 conv=notrunc",
    );
    assert_eq!(run(&mut sh, "cat /tmp/dd.out").bytes(), &ls[..4]);
    run(&mut sh, "echo -n abcdef > /tmp/seek");
    run(
        &mut sh,
        "echo -n XY | dd of=/tmp/seek bs=2 seek=1 conv=notrunc status=none",
    );
    assert_eq!(run(&mut sh, "cat /tmp/seek"), "abXYef");
    run(
        &mut sh,
        "echo -n XY | dd of=/tmp/seek2 bs=2 seek=2 status=none",
    );
    assert_eq!(run(&mut sh, "cat /tmp/seek2").bytes(), b"\0\0\0\0XY");
}

#[test]
fn standard_input_is_the_default_input() {
    let ls = image("ls");
    let out = run(
        &mut shell(),
        "/bin/busybox cat /bin/ls | /bin/busybox dd bs=52 count=1",
    );
    assert_eq!(stdout_of(&out), &ls[..52]);
    assert_eq!(stderr_of(&out), ONE_RECORD);
    let out = run(
        &mut shell(),
        "/bin/busybox dd bs=8 skip=1 count=1 < /bin/ls",
    );
    assert_eq!(stdout_of(&out), &ls[8..16]);
    // Reading standard input to its end: a piped 3 bytes is one partial record.
    let out = run(&mut shell(), "echo -n abc | /bin/busybox dd");
    assert_eq!(out.bytes(), b"abc0+1 records in\n0+1 records out\n");
}

#[test]
fn status_selects_which_report_lines_print() {
    let mut sh = shell();
    let out = run(&mut sh, "dd if=/bin/ls bs=22 count=1 status=none");
    assert_eq!(out.bytes(), &image("ls")[..22]);
    let out = run(&mut sh, "dd if=/bin/ls bs=22 count=1 status=noxfer");
    let mut want = image("ls")[..22].to_vec();
    want.extend_from_slice(ONE_RECORD.as_bytes());
    assert_eq!(out.bytes(), want.as_slice());
}

#[test]
fn a_successful_dd_stops_the_fallbacks_and_a_failed_one_runs_them() {
    let mut sh = shell();
    // The recorded chain shape: dd succeeds, so neither `cat` nor the `while read` loops run.
    let out = run(
        &mut sh,
        "dd bs=52 count=1 if=/bin/ls || cat /bin/ls || while read i; do echo $i; done < /bin/ls",
    );
    assert_eq!(out.status, 0);
    assert!(out.bytes().len() < 200, "{}", out.bytes().len());
    let out = run(&mut sh, "dd if=/nope || echo FALLBACK");
    assert!(out.contains("FALLBACK"));
    assert!(!run(&mut sh, "dd if=/bin/ls count=1 || echo FALLBACK").contains("FALLBACK"));
}

#[test]
fn errors_are_the_captured_wordings() {
    let mut sh = shell();
    for (line, want) in [
        (
            "dd if=/nope bs=22 count=1",
            "dd: failed to open '/nope': No such file or directory\n",
        ),
        (
            "/bin/busybox dd if=/nope bs=22 count=1",
            "dd: can't open '/nope': No such file or directory\n",
        ),
        (
            "dd foo=bar",
            "dd: unrecognized operand 'foo=bar'\nTry 'dd --help' for more information.\n",
        ),
        (
            "dd if=/bin/ls of=/nodir/x bs=22 count=1",
            "dd: failed to open '/nodir/x': No such file or directory\n",
        ),
    ] {
        let out = run(&mut sh, line);
        assert_eq!((out.status, out.to_string().as_str()), (1, want), "{line}");
    }
    for line in ["dd bs=0", "dd bs=x", "dd count=-1", "dd skip=1q"] {
        let out = run(&mut sh, line);
        assert_eq!(out.status, 1, "{line}");
        assert!(out.contains("invalid number"), "{line}: {out}");
    }
}

#[test]
fn the_phone_has_no_dd() {
    let mut sh = FakeShell::android(FakeFs::android(), ctx());
    let out = run(&mut sh, "dd if=/default.prop bs=4 count=1");
    assert_eq!(out.status, 127);
    assert!(out.contains("not found"), "{out}");
}

#[test]
fn a_huge_block_and_count_moves_no_more_than_the_line_allows() {
    let allowance = BudgetLimits::standard().work_per_line;
    let cap = usize::try_from(allowance).unwrap();
    for line in [
        "dd if=/dev/zero bs=1G count=1G status=none",
        "dd if=/dev/zero bs=4294967296 count=4294967296 status=none",
        "dd if=/dev/zero bs=18446744073709551615 count=18446744073709551615 status=none",
        "dd if=/bin/busybox bs=1G count=1 status=none",
        "dd if=/dev/zero bs=1 count=18446744073709551615 status=none",
    ] {
        let out = run(&mut shell(), line);
        assert_eq!(out.status, 0, "{line}");
        assert!(
            out.bytes().len() <= cap,
            "{line}: {} bytes",
            out.bytes().len()
        );
    }
    // A skip past any file, however large, moves nothing and never overflows.
    let out = run(
        &mut shell(),
        "/bin/busybox dd if=/bin/ls bs=1G skip=18446744073709551615 count=1",
    );
    assert_eq!(out.bytes(), b"0+0 records in\n0+0 records out\n");
    // A tighter allowance bounds the read the same way, whatever the operands ask for.
    let mut limits = BudgetLimits::standard();
    limits.work_per_line = 50_000;
    let budget = ConnectionBudget::new(limits);
    let mut sh = FakeShell::new(FakeFs::new(), ctx()).with_budget(Arc::clone(&budget));
    let out = run(&mut sh, "dd if=/dev/zero bs=1G count=1G status=none");
    assert!(out.bytes().len() <= 50_000, "{}", out.bytes().len());
    // What earlier commands of the line already spent is not available to dd: the whole line,
    // not each command, stays inside one allowance.
    let mut limits = BudgetLimits::standard();
    limits.work_per_line = 200_000;
    let budget = ConnectionBudget::new(limits);
    let mut sh = FakeShell::new(FakeFs::new(), ctx()).with_budget(Arc::clone(&budget));
    let out = run(
        &mut sh,
        "cat /bin/ls; dd if=/dev/zero bs=1G count=1G status=none",
    );
    assert!(out.bytes().len() <= 200_000, "{}", out.bytes().len());
    assert!(out.bytes().len() > 138_216, "cat's image is there first");
}
