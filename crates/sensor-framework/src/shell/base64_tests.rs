//! `base64` through `handle_input`. The layout is GNU coreutils as run on a current Ubuntu host,
//! not captured on the reference box; the cases that lean on an uncaptured detail say so.

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

const INVALID: &str = "base64: invalid input\n";

#[test]
fn encoding_standard_input_pads_and_ends_with_a_newline() {
    let mut sh = shell();
    assert_eq!(
        answer(&mut sh, "printf '%s' hi | base64"),
        ("aGk=\n".into(), "".into(), 0)
    );
    assert_eq!(out(&mut sh, "printf '%s' hello | base64"), "aGVsbG8=\n");
    assert_eq!(out(&mut sh, "printf '%s' abc | base64"), "YWJj\n");
    assert_eq!(out(&mut sh, "printf '' | base64"), "");
}

#[test]
fn a_file_operand_and_dash_are_read_like_cat() {
    let mut sh = shell();
    put(&mut sh, "/tmp/g", b"hi");
    assert_eq!(out(&mut sh, "base64 /tmp/g"), "aGk=\n");
    assert_eq!(out(&mut sh, "printf '%s' hi | base64 -"), "aGk=\n");
    assert_eq!(
        answer(&mut sh, "base64 /tmp/nope"),
        (
            "".into(),
            "base64: /tmp/nope: No such file or directory\n".into(),
            1
        )
    );
    assert_eq!(answer(&mut sh, "base64 /tmp/g /tmp/g").2, 1);
}

#[test]
fn output_wraps_at_76_columns_by_default() {
    let mut sh = shell();
    put(&mut sh, "/tmp/a", &[b'a'; 60]);
    let row = "YWFh".repeat(19);
    assert_eq!(out(&mut sh, "base64 /tmp/a"), format!("{row}\nYWFh\n"));
    // A last line that fills the width exactly is not followed by an empty one.
    put(&mut sh, "/tmp/b", &[b'a'; 57]);
    assert_eq!(out(&mut sh, "base64 /tmp/b"), format!("{row}\n"));
}

#[test]
fn wrap_width_option_forms_and_zero_for_one_line() {
    let mut sh = shell();
    put(&mut sh, "/tmp/h", b"hello world");
    let flat = "aGVsbG8gd29ybGQ=\n";
    for line in [
        "base64 -w 0 /tmp/h",
        "base64 -w0 /tmp/h",
        "base64 --wrap=0 /tmp/h",
        "base64 --wrap 0 /tmp/h",
    ] {
        assert_eq!(out(&mut sh, line), flat, "{line}");
    }
    assert_eq!(
        out(&mut sh, "base64 -w 4 /tmp/h"),
        "aGVs\nbG8g\nd29y\nbGQ=\n"
    );
    let (stdout, stderr, status) = answer(&mut sh, "base64 -w x /tmp/h");
    assert_eq!((stdout.as_str(), status), ("", 1));
    assert_eq!(stderr, "base64: invalid wrap size: 'x'\n");
}

#[test]
fn decoding_rebuilds_the_bytes_without_adding_a_newline() {
    let mut sh = shell();
    assert_eq!(
        answer(&mut sh, "printf '%s' aGk= | base64 -d"),
        ("hi".into(), "".into(), 0)
    );
    assert_eq!(out(&mut sh, "printf '%s' aGk= | base64 --decode"), "hi");
    // The wrapped form's newlines are skipped.
    assert_eq!(
        out(&mut sh, "printf 'aGVs\\nbG8g\\nd29y\\nbGQ=\\n' | base64 -d"),
        "hello world"
    );
}

#[test]
fn the_dropper_payload_decodes_to_the_staged_script() {
    let mut sh = shell();
    assert_eq!(
        out(&mut sh, "printf '%s' 'IyEvYmluL3NoCg==' | base64 -d"),
        "#!/bin/sh\n"
    );
    // The usual shape: decoded into a file the line then reads back.
    assert_eq!(
        answer(
            &mut sh,
            "printf '%s' 'IyEvYmluL3NoCg==' | base64 -d > /tmp/p && cat /tmp/p"
        ),
        ("#!/bin/sh\n".into(), "".into(), 0)
    );
}

#[test]
fn input_outside_the_alphabet_is_invalid_unless_garbage_is_ignored() {
    let mut sh = shell();
    assert_eq!(
        answer(&mut sh, "printf '%s' '!!!!' | base64 -d"),
        ("".into(), INVALID.into(), 1)
    );
    // A space is not a newline.
    assert_eq!(answer(&mut sh, "printf '%s' 'aG k=' | base64 -d").2, 1);
    assert_eq!(
        answer(&mut sh, "printf '%s' 'aG!k=' | base64 -di"),
        ("hi".into(), "".into(), 0)
    );
    assert_eq!(
        out(&mut sh, "printf '%s' 'aG!k=' | base64 --ignore-garbage -d"),
        "hi"
    );
}

#[test]
fn a_truncated_or_misplaced_padding_group_is_invalid() {
    let mut sh = shell();
    for line in [
        "printf '%s' aGk | base64 -d",
        "printf '%s' 'a=Gk' | base64 -d",
        "printf '%s' 'aG=k' | base64 -d",
    ] {
        let (stdout, stderr, status) = answer(&mut sh, line);
        assert_eq!(
            (stdout.as_str(), stderr.as_str(), status),
            ("", INVALID, 1),
            "{line}"
        );
    }
}

#[test]
fn encode_then_decode_round_trips_every_byte_value() {
    let mut sh = shell();
    let all: Vec<u8> = (0u8..=127).collect();
    put(&mut sh, "/tmp/all", &all);
    let encoded = out(&mut sh, "base64 /tmp/all");
    assert!(encoded.lines().all(|line| line.len() <= 76));
    put(&mut sh, "/tmp/enc", encoded.as_bytes());
    let decoded = out(&mut sh, "base64 -d /tmp/enc");
    assert_eq!(decoded.as_bytes(), all.as_slice());
}

#[test]
fn unknown_options_and_help_follow_the_tools_convention() {
    let mut sh = shell();
    let (stdout, stderr, status) = answer(&mut sh, "base64 -z");
    assert_eq!((stdout.as_str(), status), ("", 1));
    assert!(stderr.starts_with("base64: invalid option -- 'z'\n"));
    assert_eq!(answer(&mut sh, "base64 --help"), ("".into(), "".into(), 0));
}

#[test]
fn it_is_an_ubuntu_binary_and_not_a_busybox_applet() {
    let mut sh = shell();
    assert_eq!(
        answer(&mut sh, "busybox base64 /tmp/g"),
        ("".into(), "base64: applet not found\n".into(), 127)
    );
    // The phone has toybox's applet, not BusyBox's.
    let mut phone = FakeShell::android(FakeFs::android(), ctx());
    assert_eq!(
        answer(&mut phone, "busybox base64 /system/build.prop").2,
        127
    );
    assert_eq!(answer(&mut phone, "base64 /system/build.prop").2, 0);
}

fn phone() -> FakeShell {
    FakeShell::android(FakeFs::android(), ctx())
}

/// Bytes a shell's filesystem holds at `path`.
fn file(sh: &FakeShell, path: &str) -> Vec<u8> {
    sh.fs.read_all(path, 1 << 20).unwrap()
}

/// A decoded byte above 0x7f is that byte, not the two UTF-8 bytes of its code point: an APK or an
/// ELF is nothing but such bytes.
#[test]
fn decoded_binary_bytes_are_written_as_they_are() {
    for (mut sh, dir) in [(shell(), "/tmp"), (phone(), "/data/local/tmp")] {
        sh.handle_input(format!("printf '%s' '//6AAAEC' | base64 -d > {dir}/bin"));
        assert_eq!(
            file(&sh, &format!("{dir}/bin")),
            [0xff, 0xfe, 0x80, 0x00, 0x01, 0x02]
        );
    }
}

#[test]
fn toybox_encodes_like_gnu_until_the_padding_quirk() {
    let mut sh = phone();
    sh.handle_input("echo -n hi > /data/local/tmp/h");
    assert_eq!(
        answer(&mut sh, "base64 /data/local/tmp/h"),
        ("aGk=\n".into(), "".into(), 0)
    );
    sh.handle_input("echo -n abc > /data/local/tmp/h3");
    assert_eq!(out(&mut sh, "base64 /data/local/tmp/h3"), "YWJj\n");
    sh.handle_input("echo -n '' > /data/local/tmp/e");
    assert_eq!(out(&mut sh, "base64 /data/local/tmp/e"), "");
    // A full 76-column line is followed by its newline once, not twice.
    sh.handle_input(format!("echo -n {} > /data/local/tmp/b", "a".repeat(57)));
    assert_eq!(
        out(&mut sh, "base64 /data/local/tmp/b"),
        format!("{}\n", "YWFh".repeat(19))
    );
}

/// `do_base64` pads by the column it stopped at, not by the group of four, so a wrap width that is
/// not a multiple of four pads a short last line to four: ported from the 6.0.1 source, not seen
/// on a device.
#[test]
fn toybox_pads_by_the_column_it_stopped_at() {
    let mut sh = phone();
    sh.handle_input("echo -n hello > /data/local/tmp/h");
    assert_eq!(
        out(&mut sh, "base64 -w 5 /data/local/tmp/h"),
        "aGVsb\nG8==\n"
    );
    assert_eq!(
        out(&mut sh, "base64 -w 4 /data/local/tmp/h"),
        "aGVs\nbG8=\n"
    );
}

#[test]
fn toybox_decodes_leniently_and_says_nothing() {
    let mut sh = phone();
    let mut decode = |text: &str, flags: &str| {
        put(&mut sh, "/data/local/tmp/in", text.as_bytes());
        answer(&mut sh, &format!("base64 {flags} /data/local/tmp/in"))
    };
    assert_eq!(decode("aGk=", "-d"), ("hi".into(), "".into(), 0));
    // A newline is skipped; any other byte outside the alphabet ends the read it came in, with no
    // complaint and status 0 (GNU reports `invalid input` and exits 1).
    assert_eq!(decode("aG\nk=", "-d"), ("hi".into(), "".into(), 0));
    assert_eq!(decode("aGk$QUJD", "-d"), ("hi".into(), "".into(), 0));
    // `-i` drops the stray byte and carries on.
    assert_eq!(decode("aG k=", "-d"), ("h".into(), "".into(), 0));
    assert_eq!(decode("aG k=", "-di"), ("hi".into(), "".into(), 0));
    // `=` ends the decode at once, whatever follows it.
    assert_eq!(decode("aGk=QUJD", "-d"), ("hi".into(), "".into(), 0));
    // Bits left over short of a byte are dropped.
    assert_eq!(decode("aGk", "-d"), ("hi".into(), "".into(), 0));
    assert_eq!(decode("a", "-d"), ("".into(), "".into(), 0));
}

/// A bad byte drops only the rest of the `read` it arrived in; the next read decodes on. A decode
/// that stopped for good, or ignored the bad byte, would give a different answer here.
#[test]
fn toybox_loses_only_the_rest_of_the_read_a_bad_byte_arrived_in() {
    let mut sh = phone();
    // One full read of 3968 bytes opening with a bad byte, then the next read.
    let text = format!("!{}aGk=", "A".repeat(3967));
    put(&mut sh, "/data/local/tmp/in", text.as_bytes());
    assert_eq!(
        answer(&mut sh, "base64 -d /data/local/tmp/in"),
        ("hi".into(), "".into(), 0)
    );
}

#[test]
fn toybox_refuses_options_it_does_not_have_in_its_own_words() {
    let mut sh = phone();
    for (line, want) in [
        ("base64 --decode /x", "base64: Unknown option decode\n"),
        ("base64 -z /x", "base64: Unknown option z\n"),
        ("base64 -w", "base64: Missing argument to -w\n"),
        ("base64 -w x /x", "base64: not integer: x\n"),
        ("base64 -d -w 5 /x", "base64: No 'w' with 'd'\n"),
    ] {
        // An option-parsing refusal is preceded by the applet's help text (`toyopt::help_text`).
        let want = format!("{}{want}", super::toyopt::help_text("base64"));
        assert_eq!(answer(&mut sh, line), ("".into(), want, 1), "{line}");
    }
    assert_eq!(
        answer(&mut sh, "base64 -d /nope"),
        (
            "".into(),
            "base64: /nope: No such file or directory\n".into(),
            1
        )
    );
}

/// The decode of a file or pipe the attacker typed is itself a typed file; one that came from a
/// system file is not.
#[test]
fn only_a_decode_of_typed_input_is_noted_as_an_assembly() {
    let mut sh = phone();
    sh.handle_input("echo -n 'aGk=' > /data/local/tmp/t");
    sh.handle_input("base64 -d /data/local/tmp/t > /data/local/tmp/typed");
    // Different text from the file above: the same text would be found by content alone.
    sh.handle_input("echo -n aGkh | base64 -d > /data/local/tmp/piped");
    sh.handle_input("base64 /system/build.prop | base64 -d > /data/local/tmp/system");
    assert!(sh.is_assembled("/data/local/tmp/typed"));
    assert!(sh.is_assembled("/data/local/tmp/piped"));
    assert!(!sh.is_assembled("/data/local/tmp/system"));
}

#[test]
fn a_shell_metacharacter_in_the_data_is_only_bytes() {
    let mut sh = shell();
    assert_eq!(
        out(
            &mut sh,
            "printf '%s' '$(touch /tmp/x)' | base64 | base64 -d"
        ),
        "$(touch /tmp/x)"
    );
    assert_eq!(answer(&mut sh, "ls /tmp/x").2, 2);
}
