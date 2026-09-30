//! `wc`, `grep -F` and `od` through `handle_input`. The `.fxcat` inspection line is pinned by pty
//! README finding 7 (`wc -c .fxcat` is `1 .fxcat`, `od -An -tx1 .fxcat` is ` 0a`, the file being
//! the single newline `echo > FILE` wrote). Layouts beyond that are GNU coreutils/grep as run on
//! a current host, not captured on the reference box, so the cases that lean on them say so.

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

#[test]
fn the_fxcat_inspection_line_is_finding_7() {
    let mut sh = shell();
    // The sweep's write, then the last line of the recorded session.
    sh.handle_input("/bin/busybox echo > /home/.fxcat && sh /home/.fxcat && cd /home/");
    assert_eq!(
        answer(&mut sh, "pwd; wc -c .fxcat; od -An -tx1 .fxcat"),
        ("/home\n1 .fxcat\n 0a\n".into(), "".into(), 0)
    );
}

#[test]
fn the_fxcat_forms_agree_under_busybox_and_dash() {
    for prefix in ["/bin/busybox ", ""] {
        let mut sh = shell();
        sh.handle_input("echo > /tmp/.fxcat");
        assert_eq!(
            answer(&mut sh, &format!("{prefix}wc -c /tmp/.fxcat")),
            ("1 /tmp/.fxcat\n".into(), "".into(), 0),
            "{prefix}"
        );
        assert_eq!(
            answer(&mut sh, &format!("{prefix}od -An -tx1 /tmp/.fxcat")),
            (" 0a\n".into(), "".into(), 0),
            "{prefix}"
        );
    }
    let mut sh = shell();
    sh.handle_input("sh");
    sh.handle_input("echo > /tmp/.fxcat");
    assert_eq!(out(&mut sh, "wc -c /tmp/.fxcat"), "1 /tmp/.fxcat\n");
    assert_eq!(out(&mut sh, "od -An -tx1 /tmp/.fxcat"), " 0a\n");
}

#[test]
fn wc_counts_lines_words_and_bytes_of_a_file() {
    let mut sh = shell();
    put(&mut sh, "/tmp/t", b"one two\nthree\n");
    assert_eq!(out(&mut sh, "wc -l /tmp/t"), "2 /tmp/t\n");
    assert_eq!(out(&mut sh, "wc -w /tmp/t"), "3 /tmp/t\n");
    assert_eq!(out(&mut sh, "wc -c /tmp/t"), "14 /tmp/t\n");
    assert_eq!(out(&mut sh, "wc -m /tmp/t"), "14 /tmp/t\n");
    // With more than one count the columns are as wide as the file's length (two digits here),
    // as GNU wc 9.10 prints them.
    assert_eq!(out(&mut sh, "wc /tmp/t"), " 2  3 14 /tmp/t\n");
    // The columns come out in the tool's own order whatever order the flags were given.
    assert_eq!(out(&mut sh, "wc -cl /tmp/t"), " 2 14 /tmp/t\n");
    assert_eq!(out(&mut sh, "wc -c -w -l /tmp/t"), " 2  3 14 /tmp/t\n");
    assert_eq!(out(&mut sh, "wc -mc /tmp/t"), "14 14 /tmp/t\n");
}

#[test]
fn wc_splits_words_on_c_locale_whitespace_and_counts_only_newlines_as_lines() {
    let mut sh = shell();
    put(&mut sh, "/tmp/w", b"a\tb\x0bc\x0cd\re\n\nf");
    // Tab, VT, FF and CR all separate: a b c d e f is six words in twelve bytes, two newlines.
    assert_eq!(out(&mut sh, "wc /tmp/w"), " 2  6 12 /tmp/w\n");
    put(&mut sh, "/tmp/nul", b"a\0b c\n");
    assert_eq!(out(&mut sh, "wc /tmp/nul"), "1 2 6 /tmp/nul\n");
    put(&mut sh, "/tmp/empty", b"");
    assert_eq!(out(&mut sh, "wc /tmp/empty"), "0 0 0 /tmp/empty\n");
}

#[test]
fn wc_pads_to_seven_columns_for_standard_input_and_unpadded_for_one_count() {
    let mut sh = shell();
    assert_eq!(
        out(&mut sh, "echo -e 'a b\\nc' | wc"),
        "      2       3       6\n"
    );
    assert_eq!(
        out(&mut sh, "echo -e 'a b\\nc' | wc -lw"),
        "      2       3\n"
    );
    assert_eq!(out(&mut sh, "echo hi | wc -c"), "3\n");
    assert_eq!(out(&mut sh, "echo hi | wc -l -"), "1 -\n");
    put(&mut sh, "/tmp/t", b"x\n");
    assert_eq!(out(&mut sh, "wc -l < /tmp/t"), "1\n");
}

#[test]
fn wc_with_several_files_sizes_the_columns_by_their_total_and_adds_a_total_row() {
    let mut sh = shell();
    put(&mut sh, "/tmp/a", b"x");
    put(&mut sh, "/tmp/b", &[b'y'; 100]);
    assert_eq!(
        out(&mut sh, "wc -c /tmp/a /tmp/b"),
        "  1 /tmp/a\n100 /tmp/b\n101 total\n"
    );
    assert_eq!(
        out(&mut sh, "wc /tmp/a /tmp/b"),
        "  0   1   1 /tmp/a\n  0   1 100 /tmp/b\n  0   2 101 total\n"
    );
    // Standard input among the operands widens the columns to seven.
    assert_eq!(
        out(&mut sh, "echo z | wc -c /tmp/a -"),
        "      1 /tmp/a\n      2 -\n      3 total\n"
    );
}

#[test]
fn wc_reports_a_missing_file_and_a_directory_as_the_tool_does() {
    let mut sh = shell();
    assert_eq!(
        answer(&mut sh, "wc -c /nonexistent"),
        (
            "".into(),
            "wc: /nonexistent: No such file or directory\n".into(),
            1
        )
    );
    // The failed operand adds nothing, but a second operand still earns a total.
    put(&mut sh, "/tmp/a", b"x");
    assert_eq!(
        answer(&mut sh, "wc -c /tmp/a /nonexistent"),
        (
            "1 /tmp/a\n1 total\n".into(),
            "wc: /nonexistent: No such file or directory\n".into(),
            1
        )
    );
    assert_eq!(
        answer(&mut sh, "wc /tmp"),
        (
            "      0       0       0 /tmp\n".into(),
            "wc: /tmp: Is a directory\n".into(),
            1
        )
    );
}

#[test]
fn wc_sizes_the_modeled_binaries_by_their_recorded_length() {
    let mut sh = shell();
    for name in ["ls", "busybox", "cat"] {
        let binary = binaries::find(name).unwrap();
        assert_eq!(
            out(&mut sh, &format!("wc -c {}", binary.path)),
            format!("{} {}\n", binary.size, binary.path),
            "{name}"
        );
    }
    // Through the `/bin` link, and reading standard input rather than a file.
    assert_eq!(out(&mut sh, "wc -c /bin/ls"), "138216 /bin/ls\n");
    assert_eq!(out(&mut sh, "cat /bin/ls | wc -c"), "138216\n");
    // `head -n 1` of `/bin/ls` is the 410 bytes through the newline at offset 409 (pty finding 6).
    assert_eq!(out(&mut sh, "cat /bin/ls | head -n 1 | wc -c"), "410\n");
}

#[test]
fn wc_counts_the_ls_image_the_way_an_independent_scan_does() {
    let ls = binaries::find("ls").unwrap();
    let mut image = ls.header().to_vec();
    for offset in 64..ls.size {
        image.push(if offset == 409 {
            0x0a
        } else {
            0x80 | u8::try_from(offset & 0x3f).unwrap()
        });
    }
    let is_space = |b: &u8| *b == b' ' || (0x09..=0x0d).contains(b);
    let lines = image.iter().filter(|b| **b == b'\n').count();
    let words = image
        .split(is_space)
        .filter(|word| !word.is_empty())
        .count();
    let width = image.len().to_string().len();
    assert_eq!(
        out(&mut shell(), "wc /bin/ls"),
        format!("{lines:>width$} {words:>width$} {} /bin/ls\n", image.len())
    );
}

#[test]
fn wc_flags_the_tool_does_not_have_are_its_own_errors() {
    let mut sh = shell();
    assert_eq!(
        answer(&mut sh, "wc -z /tmp"),
        (
            "".into(),
            "wc: invalid option -- 'z'\nTry 'wc --help' for more information.\n".into(),
            1
        )
    );
    assert_eq!(
        answer(&mut sh, "wc --nosuch /tmp"),
        (
            "".into(),
            "wc: unrecognized option '--nosuch'\nTry 'wc --help' for more information.\n".into(),
            1
        )
    );
    // Real options this shell does not model print nothing rather than a made-up figure.
    put(&mut sh, "/tmp/t", b"abc\n");
    assert_eq!(answer(&mut sh, "wc -L /tmp/t"), ("".into(), "".into(), 0));
}

#[test]
fn od_of_the_one_byte_file_is_the_recorded_line() {
    let mut sh = shell();
    put(&mut sh, "/tmp/nl", b"\n");
    assert_eq!(out(&mut sh, "od -An -tx1 /tmp/nl"), " 0a\n");
    assert_eq!(out(&mut sh, "od -An -t x1 /tmp/nl"), " 0a\n");
    assert_eq!(out(&mut sh, "od -A n -t x1 /tmp/nl"), " 0a\n");
    assert_eq!(out(&mut sh, "od -An -v -tx1 /tmp/nl"), " 0a\n");
    assert_eq!(out(&mut sh, "echo | od -An -tx1"), " 0a\n");
}

#[test]
fn od_prints_sixteen_bytes_a_line_and_the_address_column_on_request() {
    let mut sh = shell();
    let bytes: Vec<u8> = (0u8..20).collect();
    put(&mut sh, "/tmp/n", &bytes);
    assert_eq!(
        out(&mut sh, "od -An -tx1 /tmp/n"),
        " 00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f\n 10 11 12 13\n"
    );
    assert_eq!(
        out(&mut sh, "od -Ax -tx1 /tmp/n"),
        "000000 00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f\n000010 10 11 12 13\n000014\n"
    );
    assert_eq!(
        out(&mut sh, "od -Ad -tx1 /tmp/n"),
        "0000000 00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f\n0000016 10 11 12 13\n0000020\n"
    );
}

#[test]
fn od_defaults_to_octal_words_with_an_octal_address() {
    let mut sh = shell();
    put(&mut sh, "/tmp/nl", b"\n");
    assert_eq!(out(&mut sh, "od /tmp/nl"), "0000000 000012\n0000001\n");
    put(&mut sh, "/tmp/abc", b"abc");
    assert_eq!(out(&mut sh, "od -An /tmp/abc"), " 061141 000143\n");
    assert_eq!(
        out(&mut sh, "od /tmp/abc"),
        "0000000 061141 000143\n0000003\n"
    );
    assert_eq!(
        out(&mut sh, "od -o /tmp/abc"),
        "0000000 061141 000143\n0000003\n"
    );
    put(&mut sh, "/tmp/empty", b"");
    assert_eq!(out(&mut sh, "od /tmp/empty"), "0000000\n");
    assert_eq!(out(&mut sh, "od -An -tx1 /tmp/empty"), "");
}

#[test]
fn od_collapses_repeated_lines_unless_asked_not_to() {
    let mut sh = shell();
    put(&mut sh, "/tmp/z", &[0u8; 80]);
    let zero_line = format!("{}\n", " 00".repeat(16));
    assert_eq!(
        out(&mut sh, "od -An -tx1 /tmp/z"),
        format!("{zero_line}*\n")
    );
    assert_eq!(out(&mut sh, "od -An -tx1 -v /tmp/z"), zero_line.repeat(5));
    assert_eq!(
        out(&mut sh, "od -Ax -tx1 /tmp/z"),
        format!("000000{zero_line}*\n000050\n")
    );
    // A short final line is never a repeat, even of zeros.
    put(&mut sh, "/tmp/z2", &[0u8; 36]);
    assert_eq!(
        out(&mut sh, "od -An -tx1 /tmp/z2"),
        format!("{zero_line}*\n 00 00 00 00\n")
    );
}

#[test]
fn od_reads_the_modeled_binary_header() {
    let ls = binaries::find("ls").unwrap();
    let header = ls.header();
    let want: String = header[..20]
        .chunks(16)
        .map(|line| {
            let cells: String = line.iter().map(|b| format!(" {b:02x}")).collect();
            format!("{cells}\n")
        })
        .collect();
    assert_eq!(out(&mut shell(), "head -c 20 /bin/ls | od -An -tx1"), want);
    // `/proc/self/exe` of the reading `od` is the `od` image, not `ls`.
    let od = binaries::find("od").unwrap();
    let first: String = od.header()[..16]
        .iter()
        .map(|b| format!(" {b:02x}"))
        .collect();
    assert_eq!(
        out(&mut shell(), "od -An -tx1 /proc/self/exe | head -n 1"),
        format!("{first}\n")
    );
}

#[test]
fn od_reports_a_missing_file_and_a_directory_as_the_tool_does() {
    let mut sh = shell();
    assert_eq!(
        answer(&mut sh, "od -An -tx1 /nonexistent"),
        (
            "".into(),
            "od: /nonexistent: No such file or directory\n".into(),
            1
        )
    );
    assert_eq!(
        answer(&mut sh, "od /tmp"),
        ("0000000\n".into(), "od: /tmp: Is a directory\n".into(), 1)
    );
    // Files are one stream: the second's bytes continue the first's line.
    put(&mut sh, "/tmp/a", b"ab");
    put(&mut sh, "/tmp/b", b"cd");
    assert_eq!(out(&mut sh, "od -An -tx1 /tmp/a /tmp/b"), " 61 62 63 64\n");
}

#[test]
fn od_formats_and_options_it_does_not_model_print_nothing() {
    let mut sh = shell();
    put(&mut sh, "/tmp/n", b"abc\n");
    for line in [
        "od -c /tmp/n",
        "od -An -td1 /tmp/n",
        "od -An -tx2 /tmp/n",
        "od -An -tx1z /tmp/n",
        "od -An -tx1 -N 2 /tmp/n",
        "od -x /tmp/n",
        "od -Aq /tmp/n",
        "od --format=x1 /tmp/n",
        "od -tx1 -to1 /tmp/n",
    ] {
        assert_eq!(answer(&mut sh, line), ("".into(), "".into(), 0), "{line}");
    }
}

#[test]
fn od_output_stays_inside_what_the_line_has_left() {
    let mut sh = shell();
    let (dump, _, _) = answer(&mut sh, "od -An -tx1 /bin/busybox");
    // 2 MiB of image would dump to more than the 4 MiB allowance; the dump stops short of it.
    assert!(dump.len() as u64 <= 4 * 1024 * 1024, "{}", dump.len());
    assert!(dump.starts_with(" 7f 45 4c 46 02 01 01 03"), "{dump:.40}");
}

#[test]
fn grep_f_prints_matching_lines_and_sets_the_status() {
    let mut sh = shell();
    put(&mut sh, "/tmp/g", b"alpha\nBeta\nalphabet\ngamma\n");
    assert_eq!(
        answer(&mut sh, "grep -F alpha /tmp/g"),
        ("alpha\nalphabet\n".into(), "".into(), 0)
    );
    assert_eq!(
        answer(&mut sh, "grep -F zzz /tmp/g"),
        ("".into(), "".into(), 1)
    );
    assert_eq!(
        answer(&mut sh, "grep -F -c alpha /tmp/g"),
        ("2\n".into(), "".into(), 0)
    );
    // -c of no match still prints the count, and the status says none matched.
    assert_eq!(
        answer(&mut sh, "grep -Fc zzz /tmp/g"),
        ("0\n".into(), "".into(), 1)
    );
    assert_eq!(
        answer(&mut sh, "grep -Fv alpha /tmp/g"),
        ("Beta\ngamma\n".into(), "".into(), 0)
    );
    assert_eq!(
        answer(&mut sh, "grep -Fvc alpha /tmp/g"),
        ("2\n".into(), "".into(), 0)
    );
    assert_eq!(
        answer(&mut sh, "grep -Fi beta /tmp/g"),
        ("Beta\n".into(), "".into(), 0)
    );
    assert_eq!(
        answer(&mut sh, "grep -F beta /tmp/g"),
        ("".into(), "".into(), 1)
    );
    assert_eq!(
        answer(&mut sh, "grep --fixed-strings --ignore-case ALPHA /tmp/g"),
        ("alpha\nalphabet\n".into(), "".into(), 0)
    );
}

#[test]
fn grep_f_reads_standard_input_and_takes_a_literal_pattern() {
    let mut sh = shell();
    assert_eq!(
        answer(&mut sh, "echo -e 'a.c\\nabc\\na*c' | grep -F 'a.c'"),
        ("a.c\n".into(), "".into(), 0)
    );
    assert_eq!(
        answer(&mut sh, "echo -e 'a.c\\nabc\\na*c' | grep -F 'a*'"),
        ("a*c\n".into(), "".into(), 0)
    );
    // The empty pattern matches every line, `--` ends the options, `-` is standard input.
    assert_eq!(
        answer(&mut sh, "echo -e 'x\\ny' | grep -Fc ''"),
        ("2\n".into(), "".into(), 0)
    );
    assert_eq!(
        answer(&mut sh, "echo -e '-v\\ny' | grep -F -- -v"),
        ("-v\n".into(), "".into(), 0)
    );
    assert_eq!(
        answer(&mut sh, "echo hi | grep -F hi -"),
        ("hi\n".into(), "".into(), 0)
    );
    // Each line of the pattern text is a pattern of its own.
    assert_eq!(
        answer(
            &mut sh,
            "echo -e 'a\\nb\\nc' | grep -F \"$(echo -e 'a\\nc')\""
        ),
        ("a\nc\n".into(), "".into(), 0)
    );
}

#[test]
fn grep_f_ends_an_unterminated_last_line_and_reads_an_empty_input_as_no_lines() {
    let mut sh = shell();
    put(&mut sh, "/tmp/u", b"a\nb");
    assert_eq!(out(&mut sh, "grep -F b /tmp/u"), "b\n");
    put(&mut sh, "/tmp/e", b"");
    assert_eq!(
        answer(&mut sh, "grep -Fc x /tmp/e"),
        ("0\n".into(), "".into(), 1)
    );
    assert_eq!(
        answer(&mut sh, "grep -F '' /tmp/e"),
        ("".into(), "".into(), 1)
    );
}

#[test]
fn grep_f_with_several_files_names_each_and_reports_errors_with_status_2() {
    let mut sh = shell();
    put(&mut sh, "/tmp/a", b"hit\nmiss\n");
    put(&mut sh, "/tmp/b", b"miss\nhit again\n");
    assert_eq!(
        out(&mut sh, "grep -F hit /tmp/a /tmp/b"),
        "/tmp/a:hit\n/tmp/b:hit again\n"
    );
    assert_eq!(
        out(&mut sh, "grep -Fc hit /tmp/a /tmp/b"),
        "/tmp/a:1\n/tmp/b:1\n"
    );
    assert_eq!(
        out(&mut sh, "echo hit | grep -F hit /tmp/a -"),
        "/tmp/a:hit\n(standard input):hit\n"
    );
    // An unreadable operand makes the status 2 even when another operand matched.
    assert_eq!(
        answer(&mut sh, "grep -F hit /tmp/a /nonexistent"),
        (
            "/tmp/a:hit\n".into(),
            "grep: /nonexistent: No such file or directory\n".into(),
            2
        )
    );
    assert_eq!(
        answer(&mut sh, "grep -F hit /tmp"),
        ("".into(), "grep: /tmp: Is a directory\n".into(), 2)
    );
}

#[test]
fn grep_without_a_pattern_is_a_usage_error_and_a_regex_search_is_not_modeled() {
    let mut sh = shell();
    for line in ["grep", "grep -F"] {
        assert_eq!(
            answer(&mut sh, line),
            (
                "".into(),
                "Usage: grep [OPTION]... PATTERNS [FILE]...\nTry 'grep --help' for more information.\n"
                    .into(),
                2
            ),
            "{line}"
        );
    }
    put(&mut sh, "/tmp/g", b"root\nuser\n");
    // No regular expression engine: these print nothing and succeed instead of guessing.
    for line in [
        "grep root /tmp/g",
        "grep -E 'root|user' /tmp/g",
        "grep -c root /tmp/g",
        "grep -Fn root /tmp/g",
        "grep -Fe root /tmp/g",
        "grep -q root /tmp/g",
    ] {
        assert_eq!(answer(&mut sh, line), ("".into(), "".into(), 0), "{line}");
    }
}

#[test]
fn grep_f_reports_a_binary_match_instead_of_printing_the_bytes() {
    let mut sh = shell();
    // The image opens with the ELF magic, so it matches `ELF` and holds NULs.
    assert_eq!(
        answer(&mut sh, "grep -F ELF /bin/ls"),
        ("".into(), "grep: /bin/ls: binary file matches\n".into(), 0)
    );
    assert_eq!(
        answer(&mut sh, "cat /bin/ls | grep -F ELF"),
        (
            "".into(),
            "grep: (standard input): binary file matches\n".into(),
            0
        )
    );
    // The BusyBox applet reports on standard output.
    assert_eq!(
        answer(&mut sh, "/bin/busybox grep -F ELF /bin/ls"),
        ("Binary file /bin/ls matches\n".into(), "".into(), 0)
    );
    // A count is still a count, and no match is still status 1.
    assert_eq!(
        answer(&mut sh, "grep -Fc ELF /bin/ls"),
        ("1\n".into(), "".into(), 0)
    );
    assert_eq!(
        answer(&mut sh, "grep -F NOSUCHTEXT /bin/ls"),
        ("".into(), "".into(), 1)
    );
}

#[test]
fn the_text_tools_are_applets_of_the_modeled_busybox_and_absent_on_the_phone() {
    let mut sh = shell();
    put(&mut sh, "/tmp/g", b"a b\n");
    assert_eq!(out(&mut sh, "/bin/busybox wc -w /tmp/g"), "2 /tmp/g\n");
    assert_eq!(out(&mut sh, "busybox od -An -tx1 /tmp/g"), " 61 20 62 0a\n");
    assert_eq!(out(&mut sh, "busybox grep -F b /tmp/g"), "a b\n");
    let banner = out(&mut sh, "/bin/busybox");
    let listed: Vec<&str> = banner
        .lines()
        .skip_while(|line| !line.starts_with("Currently defined"))
        .skip(1)
        .flat_map(|line| line.trim().split(", "))
        .collect();
    for applet in ["grep", "od", "wc"] {
        assert!(listed.contains(&applet), "{applet} advertised: {banner}");
    }

    let mut phone = FakeShell::android(FakeFs::android(), ctx());
    for name in ["wc", "grep", "od"] {
        let (stdout, stderr, status) = answer(&mut phone, name);
        assert_eq!(
            (stdout.as_str(), stderr.as_str(), status),
            ("", format!("sh: {name}: not found\n").as_str(), 127),
            "{name}"
        );
    }
}
