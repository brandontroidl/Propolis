//! `printf` through `handle_input`: the format forms a loader uses to emit payloads and bytes.

use super::{CommandResult, EmitContext, FakeShell};
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

fn run(sh: &mut FakeShell, line: &str) -> CommandResult {
    sh.handle_input(line).0
}

fn text(sh: &mut FakeShell, line: &str) -> (u8, String) {
    let out = run(sh, line);
    (
        out.status,
        String::from_utf8_lossy(out.bytes()).into_owned(),
    )
}

#[test]
fn a_string_conversion_prints_the_operand_and_no_newline() {
    let mut sh = shell();
    assert_eq!(text(&mut sh, "printf '%s' hi"), (0, "hi".into()));
    assert_eq!(text(&mut sh, "printf '%s\\n' hi"), (0, "hi\n".into()));
}

#[test]
fn format_escapes_are_decoded_without_a_trailing_newline() {
    let mut sh = shell();
    assert_eq!(text(&mut sh, "printf 'a\\tb\\n'"), (0, "a\tb\n".into()));
    assert_eq!(text(&mut sh, "printf '\\x41\\x42'"), (0, "AB".into()));
    assert_eq!(text(&mut sh, "printf '\\101\\0102'"), (0, "AB".into()));
    assert_eq!(text(&mut sh, "printf 'ab\\cde'"), (0, "ab".into()));
    assert_eq!(text(&mut sh, "printf '100%%'"), (0, "100%".into()));
}

#[test]
fn the_format_is_reused_while_operands_remain() {
    let mut sh = shell();
    assert_eq!(
        text(&mut sh, "printf '%s\\n' a b c"),
        (0, "a\nb\nc\n".into())
    );
    assert_eq!(
        text(&mut sh, "printf '%s-%s;' 1 2 3"),
        (0, "1-2;3-;".into())
    );
}

#[test]
fn extra_operands_are_ignored_when_the_format_has_no_conversion() {
    let mut sh = shell();
    assert_eq!(text(&mut sh, "printf 'x\\n' a b"), (0, "x\n".into()));
}

#[test]
fn a_missing_operand_is_empty_or_zero() {
    let mut sh = shell();
    assert_eq!(text(&mut sh, "printf '%s'"), (0, String::new()));
    assert_eq!(text(&mut sh, "printf '[%d]'"), (0, "[0]".into()));
}

#[test]
fn integer_conversions_apply_width_flags_and_bases() {
    let mut sh = shell();
    for (line, want) in [
        ("printf '%d\\n' 42", "42\n"),
        ("printf '%05d' -42", "-0042"),
        ("printf '%x %X %o' 255 255 8", "ff FF 10"),
        ("printf '%#x' 255", "0xff"),
        ("printf '%+d' 5", "+5"),
        ("printf '%-4d|' 7", "7   |"),
        ("printf '%d' 0x10", "16"),
        ("printf '%d' \"'A\"", "65"),
        ("printf '%5s|%.2s' ab xyz", "   ab|xy"),
    ] {
        assert_eq!(text(&mut sh, line), (0, want.into()), "{line}");
    }
}

#[test]
fn b_and_c_conversions_decode_and_truncate_the_operand() {
    let mut sh = shell();
    assert_eq!(text(&mut sh, "printf '%b' 'a\\tb'"), (0, "a\tb".into()));
    assert_eq!(text(&mut sh, "printf '%c' hello"), (0, "h".into()));
    // The format's escapes apply, the operand's do not under %s.
    assert_eq!(text(&mut sh, "printf '%s' 'a\\tb'"), (0, "a\\tb".into()));
}

#[test]
fn a_non_numeric_operand_reports_and_prints_zero() {
    let mut sh = shell();
    let out = run(&mut sh, "printf '%d' abc");
    assert_eq!(out.status, 1);
    assert!(String::from_utf8_lossy(out.bytes()).starts_with('0'));
}

#[test]
fn no_format_or_a_bad_conversion_fails() {
    let mut sh = shell();
    let (status, out) = text(&mut sh, "printf");
    assert_eq!(status, 2);
    assert!(out.contains("usage: printf"));
    assert_eq!(text(&mut sh, "printf '%z'").0, 2);
    assert_eq!(text(&mut sh, "printf --").0, 2);
    assert_eq!(text(&mut sh, "printf -- '%s' x"), (0, "x".into()));
}

#[test]
fn a_huge_width_or_recycle_is_bounded() {
    let mut sh = shell();
    let (_, out) = text(&mut sh, "printf '%99999999d' 1");
    assert!(out.len() <= 65536);
    assert!(!out.is_empty());
}

#[test]
fn the_busybox_applet_runs_the_same_handler() {
    let mut sh = shell();
    assert_eq!(text(&mut sh, "busybox printf '%s' hi"), (0, "hi".into()));
}

#[test]
fn a_shell_metacharacter_in_an_operand_is_only_text() {
    let mut sh = shell();
    assert_eq!(
        text(&mut sh, "printf '%s' '$(touch /tmp/x)'"),
        (0, "$(touch /tmp/x)".into())
    );
    assert_eq!(text(&mut sh, "ls /tmp/x").0, 2);
}
