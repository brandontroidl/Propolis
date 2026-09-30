//! The byte readers (`cat`, `head`, `more`, `hexdump`) through `handle_input`, over the F1
//! `/bin/ls` image. The expected bytes are built here from the recorded 64-byte header and the
//! filler rule, not read back through the code under test, and the pty capture pins the three
//! lengths: `head -n 1` is `/bin/ls` up to its first `0x0a` at offset 409 (411 wire bytes once
//! the terminal turns that LF into CR LF), `hexdump ... -n 52` is 52 raw bytes.

use std::sync::Arc;

use super::{CommandResult, EmitContext, FakeShell, onlcr};
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

/// `/bin/ls` as Ubuntu 22.04 has it, rebuilt from the recorded header: bytes 64 onward are
/// `0x80 | (offset & 0x3f)` except the newline planted at 409.
fn ls_image() -> Vec<u8> {
    let ls = binaries::find("ls").unwrap();
    let mut image = ls.header().to_vec();
    for offset in 64..ls.size {
        image.push(if offset == 409 {
            0x0a
        } else {
            0x80 | u8::try_from(offset & 0x3f).unwrap()
        });
    }
    image
}

#[test]
fn head_of_a_piped_ls_is_the_image_up_to_its_first_newline() {
    let expected = &ls_image()[..=409];
    for line in [
        "/bin/busybox cat /bin/ls|head -n 1",
        "cat /bin/ls | head -n 1",
        "cat /bin/ls | head -1",
        "cat /bin/ls | head -n1",
        "head -n 1 /bin/ls",
        "head -n 1 < /bin/ls",
    ] {
        let out = run(&mut shell(), line);
        assert_eq!(out.status, 0, "{line}");
        assert_eq!(out.bytes(), expected, "{line}");
    }
    let out = run(&mut shell(), "/bin/busybox cat /bin/ls|head -n 1");
    assert_eq!(out.bytes().len(), 410);
    assert_eq!(out.bytes().last(), Some(&0x0a));
    // The wire form the pty recorded: the trailing LF sent as CR LF.
    assert_eq!(onlcr(out.bytes()).len(), 411);
}

#[test]
fn hexdump_of_the_raw_character_format_is_the_first_52_bytes_and_no_newline() {
    let expected = &ls_image()[..52];
    for line in [
        "/bin/busybox hexdump -e '16/1 \"%c\"' -n 52 /bin/ls",
        "hexdump -e '16/1 \"%c\"' -n 52 /bin/ls",
        "hexdump -n 52 -e '16/1 \"%c\"' /bin/ls",
        "hexdump -n52 -e'16/1 \"%c\"' /bin/ls",
        "cat /bin/ls | hexdump -e '16/1 \"%c\"' -n 52",
    ] {
        let out = run(&mut shell(), line);
        assert_eq!(out.status, 0, "{line}");
        assert_eq!(out.bytes(), expected, "{line}");
    }
    // Without -n the format prints the whole file, still raw.
    let out = run(&mut shell(), "hexdump -e '16/1 \"%c\"' /bin/ls");
    assert_eq!(out.bytes(), ls_image().as_slice());
}

#[test]
fn a_hexdump_format_that_is_not_modeled_prints_no_dump() {
    for line in [
        "hexdump -C /bin/ls",
        "hexdump /bin/ls",
        "hexdump -e '16/1 \"%02x \"' -n 52 /bin/ls",
        "hexdump -e '16/1 \"%c\"' -e '16/1 \"%c\"' /bin/ls",
        "hexdump -e '16/1 \"%c\"' -s 4 /bin/ls",
        "hexdump -e '16/1 \"%c\"' -n x /bin/ls",
    ] {
        let out = run(&mut shell(), line);
        assert_eq!((out.status, out.bytes()), (0, &b""[..]), "{line}");
    }
    // Identical 16-byte groups would be squeezed to `*` by the real tool; not modeled either.
    let out = run(&mut shell(), "hexdump -e '16/1 \"%c\"' -n 64 /dev/zero");
    assert_eq!((out.status, out.bytes()), (0, &b""[..]));
    let out = run(&mut shell(), "hexdump -v -e '16/1 \"%c\"' -n 64 /dev/zero");
    assert_eq!(out.bytes(), vec![0u8; 64].as_slice());
}

#[test]
fn more_without_a_terminal_copies_its_input_through() {
    let image = ls_image();
    for line in [
        "/bin/busybox cat /bin/ls|more",
        "cat /bin/ls | more",
        "more /bin/ls",
        "more < /bin/ls",
    ] {
        let out = run(&mut shell(), line);
        assert_eq!(out.status, 0, "{line}");
        assert_eq!(out.bytes().len(), image.len(), "{line}");
        assert_eq!(out.bytes(), image.as_slice(), "{line}");
    }
    assert_eq!(run(&mut shell(), "echo hi | more"), "hi\n");
}

#[test]
fn cat_streams_the_whole_image_and_concatenates_operands() {
    let image = ls_image();
    assert_eq!(
        run(&mut shell(), "cat /bin/ls").bytes(),
        image.as_slice(),
        "one operand"
    );
    let mut sh = shell();
    run(&mut sh, "echo one > /tmp/a; echo two > /tmp/b");
    assert_eq!(run(&mut sh, "cat /tmp/a /tmp/b"), "one\ntwo\n");
    assert_eq!(
        run(&mut sh, "cat /tmp/a - /tmp/b < /tmp/b"),
        "one\ntwo\ntwo\n"
    );
    let missing = run(&mut sh, "cat /tmp/a /nosuch /tmp/b");
    assert_eq!(
        (missing.status, missing.to_string().as_str()),
        (1, "one\ncat: /nosuch: No such file or directory\ntwo\n")
    );
    assert_eq!(run(&mut sh, "cat /tmp"), "cat: /tmp: Is a directory\n");
}

#[test]
fn head_counts_lines_and_bytes_of_files_and_of_standard_input() {
    let mut sh = shell();
    run(&mut sh, "echo -e 'a\\nb\\nc' > /tmp/t; echo -n xy > /tmp/u");
    for (line, want) in [
        ("head -n 2 /tmp/t", "a\nb\n"),
        ("head -n 2 < /tmp/t", "a\nb\n"),
        ("cat /tmp/t | head -n 2", "a\nb\n"),
        ("head /tmp/t", "a\nb\nc\n"),
        ("head -n 0 /tmp/t", ""),
        ("head -n 99 /tmp/t", "a\nb\nc\n"),
        ("head -n -1 /tmp/t", "a\nb\n"),
        ("head -n -5 /tmp/t", ""),
        ("head -2 /tmp/t", "a\nb\n"),
        ("head --lines=1 /tmp/t", "a\n"),
        ("head -c 3 /tmp/t", "a\nb"),
        ("head -c3 /tmp/t", "a\nb"),
        ("head -c -2 /tmp/t", "a\nb\n"),
        ("head --bytes 1 /tmp/t", "a"),
        ("head -c 1K /tmp/t", "a\nb\nc\n"),
        ("head -n 1 /tmp/u", "xy"),
        ("cat /tmp/u | head -n 3", "xy"),
        (
            "head -n 1 /tmp/t /tmp/u",
            "==> /tmp/t <==\na\n\n==> /tmp/u <==\nxy",
        ),
        ("head -q -n 1 /tmp/t /tmp/u", "a\nxy"),
        ("head -v -n 1 /tmp/t", "==> /tmp/t <==\na\n"),
        ("cat /tmp/t | head -v -n 1", "==> standard input <==\na\n"),
    ] {
        let out = run(&mut sh, line);
        assert_eq!(out, want, "{line}");
        assert_eq!(out.status, 0, "{line}");
    }
    // Reading only what it needs leaves the rest of standard input for the next reader.
    assert_eq!(run(&mut sh, "(head -n 1; cat) < /tmp/t"), "a\nb\nc\n");
    assert_eq!(run(&mut sh, "(head -c 2; cat) < /tmp/t"), "a\nb\nc\n");
}

#[test]
fn head_reports_what_the_real_tool_does() {
    let mut sh = shell();
    for (line, want) in [
        (
            "head /nosuch",
            "head: cannot open '/nosuch' for reading: No such file or directory\n",
        ),
        ("head /tmp", "head: error reading '/tmp': Is a directory\n"),
        (
            "/bin/busybox head /nosuch",
            "head: /nosuch: No such file or directory\n",
        ),
        ("head -n x /tmp", "head: invalid number of lines: 'x'\n"),
        ("head -c 1q /tmp", "head: invalid number of bytes: '1q'\n"),
        (
            "head -n",
            "head: option requires an argument -- 'n'\nTry 'head --help' for more information.\n",
        ),
        (
            "head -z /tmp",
            "head: invalid option -- 'z'\nTry 'head --help' for more information.\n",
        ),
        (
            "head --nope /tmp",
            "head: unrecognized option '--nope'\nTry 'head --help' for more information.\n",
        ),
    ] {
        let out = run(&mut sh, line);
        assert_eq!(out, want, "{line}");
        assert_eq!(out.status, 1, "{line}");
    }
    let mixed = run(&mut sh, "echo z > /tmp/z; head -n 1 /nosuch /tmp/z");
    assert_eq!(
        mixed,
        "head: cannot open '/nosuch' for reading: No such file or directory\n==> /tmp/z <==\nz\n"
    );
    assert_eq!(mixed.status, 1);
}

#[test]
fn hexdump_and_more_report_a_missing_file_and_fail() {
    let mut sh = shell();
    let out = run(&mut sh, "hexdump -e '16/1 \"%c\"' /nosuch");
    assert_eq!(
        (out.status, out.to_string().as_str()),
        (1, "hexdump: /nosuch: No such file or directory\n")
    );
    let out = run(&mut sh, "more /nosuch");
    assert_eq!(
        (out.status, out.to_string().as_str()),
        (1, "more: cannot open /nosuch: No such file or directory\n")
    );
}

#[test]
fn a_reader_of_proc_self_cmdline_sees_its_own_argument_vector() {
    assert_eq!(
        run(&mut shell(), "head -c 100 /proc/self/cmdline").bytes(),
        b"head\x00-c\x00100\x00/proc/self/cmdline\x00"
    );
    assert_eq!(
        run(&mut shell(), "cat /proc/self/cmdline").bytes(),
        b"cat\0/proc/self/cmdline\0"
    );
}

#[test]
fn readers_work_the_same_in_a_nested_dash() {
    let mut sh = shell();
    run(&mut sh, "sh");
    let out = run(&mut sh, "cat /bin/ls|head -n 1");
    assert_eq!(out.bytes(), &ls_image()[..=409]);
}

#[test]
fn a_reader_stops_taking_operands_once_the_line_allowance_is_spent() {
    let mut limits = BudgetLimits::standard();
    limits.work_per_line = 200_000;
    let budget = ConnectionBudget::new(limits);
    let mut sh = FakeShell::new(FakeFs::new(), ctx()).with_budget(Arc::clone(&budget));
    // The second copy starts inside the allowance, the third after it is spent.
    let out = run(&mut sh, "cat /bin/ls /bin/ls /bin/ls");
    assert_eq!(out.bytes().len(), 2 * 138_216);
}

#[test]
fn the_phone_has_none_of_these_readers() {
    let mut sh = FakeShell::android(FakeFs::android(), ctx());
    for name in [
        "head -n 1 /system/build.prop",
        "more /default.prop",
        "hexdump /default.prop",
    ] {
        let out = run(&mut sh, name);
        assert_eq!(out.status, 127, "{name}");
        assert!(out.contains("not found"), "{name}: {out}");
    }
}
