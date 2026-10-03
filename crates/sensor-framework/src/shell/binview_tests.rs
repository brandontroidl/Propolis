//! `xxd` and `strings` through `handle_input`, as BusyBox applets: neither is a bare command on
//! any persona. The canonical `xxd` line (`00000000: 7f45 4c46 ... .ELF....` with two spaces
//! before the characters) and binutils' `strings` are as run on a current host, not captured on
//! the reference box, so the layouts beyond that line, the padding of a short line and every error
//! wording are [unverified] and pinned here as the modeled answer.

use super::{CommandResult, EmitContext, FakeShell, OutputFd};
use crate::binaries;
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

fn put(sh: &mut FakeShell, path: &str, bytes: &[u8]) {
    sh.fs.write_file(path, bytes).unwrap();
}

fn file(sh: &FakeShell, path: &str) -> Vec<u8> {
    sh.fs.read_all(path, 1 << 20).unwrap()
}

/// One default-layout line: the hex cells, `gap` spaces, then the characters.
fn dump_line(offset: &str, cells: &str, gap: usize, text: &str) -> String {
    format!("{offset}: {cells}{}{text}\n", " ".repeat(gap))
}

fn counting() -> Vec<u8> {
    (0u8..40).collect()
}

#[test]
fn xxd_of_a_modeled_binary_shows_the_elf_magic_and_its_characters() {
    let ls = binaries::find("ls").unwrap();
    let header = ls.header();
    let first = out(&mut shell(), "busybox xxd -l 16 /bin/ls");
    assert!(
        first.starts_with("00000000: 7f45 4c46 0201 0100 "),
        "{first}"
    );
    let cells: Vec<String> = header[..16]
        .chunks(2)
        .map(|pair| format!("{:02x}{:02x}", pair[0], pair[1]))
        .collect();
    let text: String = header[..16]
        .iter()
        .map(|b| {
            if (0x20..=0x7e).contains(b) {
                *b as char
            } else {
                '.'
            }
        })
        .collect();
    assert_eq!(first, format!("00000000: {}  {text}\n", cells.join(" ")));
    assert!(first.ends_with("  .ELF............\n"), "{first}");
    // The second line carries on at offset 0x10.
    let two = out(&mut shell(), "busybox xxd -l 32 /bin/ls");
    assert!(
        two.lines().nth(1).unwrap().starts_with("00000010: "),
        "{two}"
    );
}

#[test]
fn xxd_pads_a_short_last_line_and_dots_what_is_not_printable() {
    let mut sh = shell();
    put(&mut sh, "/tmp/h", b"Hello\n");
    // Six bytes fill three groups; ten bytes (twenty digits and five group spaces) are padding,
    // between the closing space of the last group and the one before the characters.
    assert_eq!(
        out(&mut sh, "busybox xxd /tmp/h"),
        dump_line("00000000", "4865 6c6c 6f0a", 27, "Hello.")
    );
    put(&mut sh, "/tmp/c", &[0x41, 0x00, 0x7e, 0x7f, 0x20]);
    assert!(
        out(&mut sh, "busybox xxd /tmp/c").ends_with("  A.~. \n"),
        "{}",
        out(&mut sh, "busybox xxd /tmp/c")
    );
}

#[test]
fn xxd_plain_is_continuous_hex_without_offsets_or_characters() {
    let mut sh = shell();
    put(&mut sh, "/tmp/n", &counting());
    let want: String = (0u8..40).map(|b| format!("{b:02x}")).collect();
    // Thirty bytes (sixty digits) to a line.
    assert_eq!(
        out(&mut sh, "busybox xxd -p /tmp/n"),
        format!("{}\n{}\n", &want[..60], &want[60..])
    );
    assert_eq!(
        out(&mut sh, "busybox xxd -p -c 4 -l 8 /tmp/n"),
        "00010203\n04050607\n"
    );
}

#[test]
fn xxd_limit_seek_columns_group_and_case_follow_their_options() {
    let mut sh = shell();
    put(&mut sh, "/tmp/n", &counting());
    assert_eq!(
        out(&mut sh, "busybox xxd -l 4 /tmp/n"),
        dump_line("00000000", "0001 0203", 32, "....")
    );
    assert_eq!(
        out(&mut sh, "busybox xxd -l4 /tmp/n"),
        out(&mut sh, "busybox xxd -l 0x4 /tmp/n")
    );
    // A seek shows the offset it began at.
    assert_eq!(
        out(&mut sh, "busybox xxd -s 4 -l 4 /tmp/n"),
        dump_line("00000004", "0405 0607", 32, "....")
    );
    assert_eq!(
        out(&mut sh, "busybox xxd -s +36 /tmp/n"),
        out(&mut sh, "busybox xxd -s -4 /tmp/n")
    );
    assert_eq!(
        out(&mut sh, "busybox xxd -s -4 /tmp/n"),
        dump_line("00000024", "2425 2627", 32, "$%&'")
    );
    assert_eq!(
        out(&mut sh, "busybox xxd -c 4 -g 1 -l 8 /tmp/n"),
        "00000000: 00 01 02 03  ....\n00000004: 04 05 06 07  ....\n"
    );
    // A group of zero joins the digits.
    assert_eq!(
        out(&mut sh, "busybox xxd -g 0 -c 4 -l 4 /tmp/n"),
        "00000000: 00010203 ....\n"
    );
    put(&mut sh, "/tmp/u", &[0xab, 0xcd]);
    let upper = out(&mut sh, "busybox xxd -u /tmp/u");
    assert!(upper.starts_with("00000000: ABCD "), "{upper}");
    assert!(upper.ends_with("  ..\n"), "{upper}");
    assert_eq!(upper.len(), 10 + 40 + 1 + 2 + 1, "{upper}");
}

#[test]
fn xxd_reads_standard_input() {
    let mut sh = shell();
    put(&mut sh, "/tmp/h", b"Hello\n");
    assert_eq!(
        out(&mut sh, "cat /tmp/h | busybox xxd"),
        out(&mut sh, "busybox xxd /tmp/h")
    );
    assert_eq!(
        out(&mut sh, "cat /tmp/h | busybox xxd -p"),
        "48656c6c6f0a\n"
    );
    assert_eq!(
        out(&mut sh, "cat /tmp/h | busybox xxd -s 1 -l 2 -p"),
        "656c\n"
    );
}

#[test]
fn xxd_reverse_rebuilds_the_bytes_of_a_dump_and_of_plain_hex() {
    let mut sh = shell();
    put(&mut sh, "/tmp/n", &counting());
    sh.handle_input("busybox xxd /tmp/n > /tmp/dump");
    sh.handle_input("busybox xxd -r /tmp/dump /tmp/back");
    assert_eq!(file(&sh, "/tmp/back"), counting());
    sh.handle_input("busybox xxd -p /tmp/n > /tmp/plain");
    sh.handle_input("busybox xxd -r -p /tmp/plain /tmp/back2");
    assert_eq!(file(&sh, "/tmp/back2"), counting());
    // To standard output the bytes are the file's own.
    put(&mut sh, "/tmp/t", b"48656c6c6f0a");
    assert_eq!(out(&mut sh, "busybox xxd -r -p /tmp/t"), "Hello\n");
    // A dump with a gap is filled with zeros up to the next offset.
    put(
        &mut sh,
        "/tmp/gap",
        b"00000000: 4141  AA\n00000004: 4242  BB\n",
    );
    sh.handle_input("busybox xxd -r /tmp/gap /tmp/gapped");
    assert_eq!(file(&sh, "/tmp/gapped"), b"AA\0\0BB");
}

#[test]
fn xxd_reports_a_missing_file_and_a_directory_and_writes_nothing() {
    let mut sh = shell();
    assert_eq!(
        answer(&mut sh, "busybox xxd /tmp/nope"),
        (
            "".into(),
            "xxd: /tmp/nope: No such file or directory\n".into(),
            1
        )
    );
    assert_eq!(
        answer(&mut sh, "busybox xxd /tmp"),
        ("".into(), "xxd: /tmp: Is a directory\n".into(), 1)
    );
    assert_eq!(answer(&mut sh, "busybox xxd -r /tmp/nope /tmp/out").2, 1);
    assert!(sh.fs.read_all("/tmp/out", 16).is_err());
}

#[test]
fn xxd_and_strings_formats_and_options_they_do_not_model_print_nothing() {
    let mut sh = shell();
    put(&mut sh, "/tmp/h", b"Hello world\n");
    for line in [
        "busybox xxd -i /tmp/h",
        "busybox xxd -b /tmp/h",
        "busybox xxd -a /tmp/h",
        "busybox xxd -c 0 /tmp/h",
        "busybox xxd -c 999 /tmp/h",
        "busybox xxd -l abc /tmp/h",
        "busybox xxd -l",
        "busybox strings -e l /tmp/h",
        "busybox strings -f /tmp/h",
        "busybox strings -t z /tmp/h",
        "busybox strings --help",
    ] {
        assert_eq!(answer(&mut sh, line), ("".into(), "".into(), 0), "{line}");
    }
}

#[test]
fn xxd_dumps_only_up_to_what_the_line_has_left() {
    let mut sh = shell();
    let (dump, _, _) = answer(&mut sh, "busybox xxd /bin/busybox");
    // The 2 MiB image would dump to about 2.1x its length, past the 4 MiB allowance.
    assert!(dump.len() as u64 <= 4 * 1024 * 1024, "{}", dump.len());
    assert!(
        dump.starts_with("00000000: 7f45 4c46 0201 0103"),
        "{dump:.40}"
    );
    assert!(dump.len() > 1024 * 1024, "{}", dump.len());
    // One byte a line costs the most text per byte, and is bounded the same way.
    let (narrow, _, _) = answer(&mut sh, "busybox xxd -c 1 -g 1 /bin/busybox");
    assert!(narrow.len() as u64 <= 4 * 1024 * 1024, "{}", narrow.len());
    assert!(
        narrow.starts_with("00000000: 7f  .\n00000001: 45  E\n"),
        "{narrow:.40}"
    );
}

const SAMPLE: &[u8] =
    b"\x7fELF\x00\x00hello\x00ab\x00/bin/sh -c\x00\x01xy\x02longer text\tTAB\x00end";

#[test]
fn strings_finds_the_printable_runs_of_a_binary() {
    let mut sh = shell();
    put(&mut sh, "/tmp/bin", SAMPLE);
    assert_eq!(
        out(&mut sh, "busybox strings /tmp/bin"),
        "hello\n/bin/sh -c\nlonger text\tTAB\n"
    );
    // `-a` and `--all` change nothing: the whole file is read anyway.
    assert_eq!(
        out(&mut sh, "busybox strings -a /tmp/bin"),
        out(&mut sh, "busybox strings --all /tmp/bin")
    );
    assert_eq!(
        out(&mut sh, "busybox strings -a /tmp/bin"),
        out(&mut sh, "busybox strings /tmp/bin")
    );
}

#[test]
fn strings_min_length_moves_the_threshold_both_ways() {
    let mut sh = shell();
    put(&mut sh, "/tmp/bin", SAMPLE);
    assert_eq!(
        out(&mut sh, "busybox strings -n 3 /tmp/bin"),
        "ELF\nhello\n/bin/sh -c\nlonger text\tTAB\nend\n"
    );
    assert_eq!(
        out(&mut sh, "busybox strings -n2 /tmp/bin"),
        "ELF\nhello\nab\n/bin/sh -c\nxy\nlonger text\tTAB\nend\n"
    );
    assert_eq!(
        out(&mut sh, "busybox strings -8 /tmp/bin"),
        "/bin/sh -c\nlonger text\tTAB\n"
    );
    assert_eq!(
        out(&mut sh, "busybox strings --bytes=11 /tmp/bin"),
        "longer text\tTAB\n"
    );
    assert_eq!(
        answer(&mut sh, "busybox strings -n 0 /tmp/bin"),
        (
            "".into(),
            "strings: invalid minimum string length 0\n".into(),
            1
        )
    );
}

#[test]
fn strings_prefixes_the_offset_in_the_radix_asked_for() {
    let mut sh = shell();
    put(&mut sh, "/tmp/bin", SAMPLE);
    assert_eq!(
        out(&mut sh, "busybox strings -t d /tmp/bin"),
        "      6 hello\n     15 /bin/sh -c\n     30 longer text\tTAB\n"
    );
    assert_eq!(
        out(&mut sh, "busybox strings -t x /tmp/bin"),
        "      6 hello\n      f /bin/sh -c\n     1e longer text\tTAB\n"
    );
    assert_eq!(
        out(&mut sh, "busybox strings -t o /tmp/bin"),
        "      6 hello\n     17 /bin/sh -c\n     36 longer text\tTAB\n"
    );
    assert_eq!(
        out(&mut sh, "busybox strings -o /tmp/bin"),
        out(&mut sh, "busybox strings -t o /tmp/bin")
    );
    assert_eq!(
        out(&mut sh, "busybox strings --radix=x /tmp/bin"),
        out(&mut sh, "busybox strings -tx /tmp/bin")
    );
}

#[test]
fn strings_of_a_text_file_lists_its_lines_and_reads_standard_input() {
    let mut sh = shell();
    put(&mut sh, "/tmp/t", b"alpha\nbeta12\nxy\ngamma\n");
    assert_eq!(
        out(&mut sh, "busybox strings /tmp/t"),
        "alpha\nbeta12\ngamma\n"
    );
    assert_eq!(
        out(&mut sh, "cat /tmp/t | busybox strings"),
        "alpha\nbeta12\ngamma\n"
    );
    assert_eq!(
        out(&mut sh, "cat /tmp/t | busybox strings -"),
        "alpha\nbeta12\ngamma\n"
    );
    // Several files read in order.
    put(&mut sh, "/tmp/u", b"zeta-one\n");
    assert_eq!(
        out(&mut sh, "busybox strings /tmp/u /tmp/t"),
        "zeta-one\nalpha\nbeta12\ngamma\n"
    );
}

#[test]
fn strings_agrees_with_an_independent_scan_of_a_modeled_binary() {
    let mut sh = shell();
    let image = file(&sh, "/usr/bin/ls");
    let mut want = String::new();
    let mut at = 0usize;
    for piece in image.split(|b| !((0x20..=0x7e).contains(b) || *b == b'\t')) {
        if piece.len() >= 4 {
            want.push_str(&format!("{at:>7} {}\n", String::from_utf8_lossy(piece)));
        }
        at += piece.len() + 1;
    }
    assert_eq!(out(&mut sh, "busybox strings -t d /bin/ls"), want);
}

#[test]
fn strings_reports_a_missing_file_with_status_1_and_keeps_reading_the_rest() {
    let mut sh = shell();
    put(&mut sh, "/tmp/t", b"alpha\n");
    assert_eq!(
        answer(&mut sh, "busybox strings /tmp/nope"),
        (
            "".into(),
            "strings: /tmp/nope: No such file or directory\n".into(),
            1
        )
    );
    assert_eq!(
        answer(&mut sh, "busybox strings /tmp/nope /tmp/t"),
        (
            "alpha\n".into(),
            "strings: /tmp/nope: No such file or directory\n".into(),
            1
        )
    );
    assert_eq!(
        answer(&mut sh, "busybox strings /tmp"),
        ("".into(), "strings: /tmp: Is a directory\n".into(), 1)
    );
}

#[test]
fn strings_output_stays_inside_what_the_line_has_left() {
    let mut sh = shell();
    let (found, _, status) = answer(&mut sh, "busybox strings -n 1 -t d /bin/busybox");
    assert_eq!(status, 0);
    assert!(
        found.len() as u64 <= 4 * 1024 * 1024 + 64,
        "{}",
        found.len()
    );
}

#[test]
fn xxd_and_strings_are_applets_of_the_modeled_busybox() {
    let mut sh = shell();
    put(&mut sh, "/tmp/g", b"a b c d\n");
    assert_eq!(
        out(&mut sh, "/bin/busybox xxd -p /tmp/g"),
        "612062206320640a\n"
    );
    assert_eq!(out(&mut sh, "busybox xxd -p /tmp/g"), "612062206320640a\n");
    assert_eq!(out(&mut sh, "busybox strings /tmp/g"), "a b c d\n");
    let banner = out(&mut sh, "/bin/busybox");
    let listed: Vec<&str> = banner
        .lines()
        .skip_while(|line| !line.starts_with("Currently defined"))
        .skip(1)
        .flat_map(|line| line.split(','))
        .map(str::trim)
        .collect();
    for applet in ["strings", "xxd"] {
        assert!(listed.contains(&applet), "{applet} advertised: {banner}");
    }
}

#[test]
fn xxd_and_strings_are_not_found_bare_on_either_persona() {
    let mut sh = shell();
    for name in ["xxd", "strings"] {
        let (stdout, stderr, status) = answer(&mut sh, &format!("{name} /etc/hostname"));
        assert_eq!((stdout.as_str(), status), ("", 127), "{name}");
        assert!(stderr.contains("not found"), "{name}: {stderr}");
        assert_eq!(
            answer(&mut sh, &format!("command -v {name}")).2,
            1,
            "{name}"
        );
    }
    let mut phone = FakeShell::android(FakeFs::android(), ctx());
    for name in ["xxd", "strings"] {
        let (stdout, stderr, status) = answer(&mut phone, name);
        assert_eq!(
            (stdout.as_str(), stderr.as_str(), status),
            ("", format!("sh: {name}: not found\n").as_str(), 127),
            "{name}"
        );
        assert_eq!(
            answer(&mut phone, &format!("command -v {name}")).2,
            1,
            "{name}"
        );
    }
}

#[test]
fn nothing_xxd_or_strings_reads_or_writes_becomes_runnable() {
    let mut sh = shell();
    // The bytes of an ELF header, rebuilt from hex into a file, are data, not a program.
    put(&mut sh, "/tmp/hex", b"7f454c46\n");
    sh.handle_input("busybox xxd -r -p /tmp/hex /tmp/rebuilt");
    assert_eq!(file(&sh, "/tmp/rebuilt"), b"\x7fELF");
    assert!(!sh.fs.is_executable("/tmp/rebuilt"));
    // Reading an image to the end leaves it as it was.
    let before = file(&sh, "/usr/bin/ls");
    sh.handle_input("busybox xxd /bin/ls > /dev/null; busybox strings /bin/ls > /dev/null");
    assert_eq!(file(&sh, "/usr/bin/ls"), before);
}
