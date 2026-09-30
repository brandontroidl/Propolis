//! `test` and `[` through `handle_input`. String, integer and grouping cases carry the status and
//! wording of bash 5 run on real operands (the `Ubuntu 22.04` ground truth captured `-w`, `-f`,
//! `-d`, `-x` and `[ 3 -gt 2 ]`); file cases are the layout and mount table of the filesystem
//! model, which is what the predicate must agree with.

use super::{CommandResult, EmitContext, FakeShell, OutputFd};
use crate::fakefs::{Blob, FakeFs};

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

fn android() -> FakeShell {
    FakeShell::android(FakeFs::android(), ctx())
}

fn run(sh: &mut FakeShell, line: &str) -> CommandResult {
    sh.handle_input(line).0
}

fn exit_of(sh: &mut FakeShell, line: &str) -> u8 {
    run(sh, line).status
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

/// Each `(line, status)` on one shell, with the failing line named.
fn check(sh: &mut FakeShell, table: &[(&str, u8)]) {
    for (line, want) in table {
        assert_eq!(exit_of(sh, line), *want, "{line}");
    }
}

#[test]
fn every_file_predicate_is_true_and_false_over_the_model() {
    let mut sh = shell();
    check(
        &mut sh,
        &[
            ("test -e /etc/passwd", 0),
            ("test -e /etc", 0),
            ("test -e /no/such/path", 1),
            ("test -a /etc/passwd", 0),
            ("test -f /etc/passwd", 0),
            ("test -f /etc", 1),
            ("test -f /dev/null", 1),
            ("test -d /etc", 0),
            ("test -d /etc/passwd", 1),
            ("test -d /var/run", 0),
            ("test -r /etc/passwd", 0),
            ("test -r /no/such/path", 1),
            ("test -x /usr/bin/ls", 0),
            ("test -x /bin/ls", 0),
            ("test -x /etc/passwd", 1),
            ("test -x /etc", 0),
            ("test -x /dev/null", 1),
            ("test -s /etc/passwd", 0),
            ("test -s /dev/null", 1),
            ("test -s /no/such/path", 1),
            ("test -L /bin", 0),
            ("test -h /bin", 0),
            ("test -L /var/run", 0),
            ("test -L /etc", 1),
            ("test -L /no/such/path", 1),
            ("test -c /dev/null", 0),
            ("test -c /etc", 1),
            ("test -b /dev/null", 1),
            ("test -p /etc", 1),
            ("test -S /etc", 1),
            ("test -O /etc/passwd", 0),
            ("test -G /etc/passwd", 0),
        ],
    );
}

#[test]
fn a_symlink_is_followed_except_by_l_and_h_and_a_trailing_slash_follows_it() {
    let mut sh = shell();
    check(
        &mut sh,
        &[
            ("test -d /bin", 0),
            ("test -f /bin/sh", 0),
            ("test -L /bin/sh", 0),
            ("test -L /bin/", 1),
            ("test -h /bin/", 1),
            ("test -d /bin/", 0),
        ],
    );
}

#[test]
fn an_empty_operand_names_nothing_rather_than_the_working_directory() {
    let mut sh = shell();
    check(
        &mut sh,
        &[
            ("test -e ''", 1),
            ("test -d ''", 1),
            ("test -w ''", 1),
            ("cd /etc; test -d ''", 1),
        ],
    );
}

#[test]
fn a_relative_operand_starts_at_the_working_directory() {
    let mut sh = shell();
    check(
        &mut sh,
        &[
            ("cd /etc; test -f passwd", 0),
            ("test -f ./passwd", 0),
            ("test -f ../etc/passwd", 0),
            ("test -f hostname && test ! -f nonesuch", 0),
        ],
    );
}

#[test]
fn size_follows_what_was_written_and_a_directory_or_device_is_by_kind() {
    let mut sh = shell();
    check(
        &mut sh,
        &[
            (": > /tmp/e", 0),
            ("test -e /tmp/e", 0),
            ("test -s /tmp/e", 1),
            ("echo x > /tmp/f", 0),
            ("test -s /tmp/f", 0),
            ("test -s /tmp", 0),
        ],
    );
}

#[test]
fn a_file_created_this_session_is_executable_only_once_chmodded() {
    let mut sh = shell();
    check(
        &mut sh,
        &[
            ("echo x > /tmp/p", 0),
            ("test -x /tmp/p", 1),
            ("chmod 755 /tmp/p", 0),
            ("test -x /tmp/p", 0),
            ("rm /tmp/p", 0),
            ("test -e /tmp/p", 1),
        ],
    );
}

#[test]
fn mode_bits_answer_sticky_setuid_and_setgid() {
    let mut sh = shell();
    for (path, mode) in [
        ("/tmp/sticky", 0o101_755),
        ("/tmp/suid", 0o104_755),
        ("/tmp/sgid", 0o102_755),
        ("/tmp/plain", 0o100_755),
    ] {
        sh.fs.write_blob(path, Blob::from_bytes("x"), mode).unwrap();
    }
    for (flag, path, want) in [
        ("-k", "/tmp/sticky", 0),
        ("-u", "/tmp/sticky", 1),
        ("-g", "/tmp/sticky", 1),
        ("-u", "/tmp/suid", 0),
        ("-k", "/tmp/suid", 1),
        ("-g", "/tmp/sgid", 0),
        ("-u", "/tmp/sgid", 1),
        ("-k", "/tmp/plain", 1),
        ("-u", "/tmp/plain", 1),
        ("-g", "/tmp/plain", 1),
    ] {
        let line = format!("test {flag} {path}");
        assert_eq!(exit_of(&mut sh, &line), want, "{line}");
    }
}

#[test]
fn writable_is_the_mount_not_the_mode_and_a_missing_path_is_not_writable() {
    let mut sh = shell();
    check(
        &mut sh,
        &[
            ("test -w /tmp", 0),
            ("test -w /var/run", 0),
            ("test -w /mnt", 0),
            ("test -w /dev/shm", 0),
            ("test -w /etc/passwd", 0),
            ("test -w /dev/null", 0),
            // Absent, even in a directory a write would succeed in.
            ("test -w /tmp/absent", 1),
            ("test -w /no/such/dir/file", 1),
        ],
    );
}

#[test]
fn writable_is_false_under_a_read_only_mount() {
    let mut sh = android();
    check(
        &mut sh,
        &[
            ("test -w /data/local/tmp", 0),
            ("test -w /sdcard", 0),
            ("test -w /system", 1),
            ("test -w /system/bin", 1),
            ("test -w /system/build.prop", 1),
            ("test -w /", 1),
            ("test -w /no/such/path", 1),
            // Readable and present all the same.
            ("test -e /system/build.prop", 0),
            ("test -r /system/build.prop", 0),
            ("test -d /system/bin", 0),
        ],
    );
}

#[test]
fn writable_agrees_with_what_a_write_does_on_both_personas() {
    for (mut sh, dirs) in [
        (
            shell(),
            &["/tmp", "/var/run", "/mnt", "/dev/shm", "/root", "/etc"][..],
        ),
        (
            android(),
            &[
                "/data/local/tmp",
                "/sdcard",
                "/system",
                "/system/bin",
                "/cache",
                "/",
            ][..],
        ),
    ] {
        for dir in dirs {
            let probe = format!("{}/probe", dir.trim_end_matches('/'));
            let writable = sh.fs.write_file(&probe, b"x").is_ok();
            let line = format!("test -w {dir}");
            assert_eq!(exit_of(&mut sh, &line) == 0, writable, "{line}");
        }
    }
}

#[test]
fn a_directory_on_a_noexec_mount_is_searchable_but_its_files_are_not_executable() {
    let mut sh = android();
    sh.fs
        .write_blob("/sdcard/run", Blob::from_bytes("x"), 0o100_755)
        .unwrap();
    check(
        &mut sh,
        &[
            ("test -f /sdcard/run", 0),
            ("test -x /sdcard/run", 1),
            ("test -x /sdcard", 0),
        ],
    );
}

#[test]
fn the_shells_own_proc_self_exe_is_a_link_to_its_binary() {
    let mut sh = shell();
    check(
        &mut sh,
        &[
            ("test -e /proc/self/exe", 0),
            ("test -L /proc/self/exe", 0),
            ("test -f /proc/self/exe", 0),
            ("test -x /proc/self/exe", 0),
            ("test -s /proc/self/exe", 0),
        ],
    );
}

#[test]
fn file_comparisons_are_by_identity_and_existence() {
    let mut sh = shell();
    check(
        &mut sh,
        &[
            ("test /bin/ls -ef /usr/bin/ls", 0),
            ("test /bin/ls -ef /bin/cat", 1),
            ("test /bin/ls -ef /no/such/path", 1),
            ("test /etc/passwd -nt /no/such/path", 0),
            ("test /no/such/path -nt /etc/passwd", 1),
            ("test /no/such/path -ot /etc/passwd", 0),
            ("test /etc/passwd -ot /no/such/path", 1),
            // Baked nodes share one timestamp, so neither is newer.
            ("test /etc/passwd -nt /etc/hostname", 1),
            ("test /etc/passwd -ot /etc/hostname", 1),
        ],
    );
}

#[test]
fn string_tests() {
    let mut sh = shell();
    check(
        &mut sh,
        &[
            ("test -z ''", 0),
            ("test -z a", 1),
            ("test -n a", 0),
            ("test -n ''", 1),
            ("test a", 0),
            ("test ''", 1),
            ("[ a = a ]", 0),
            ("[ a = b ]", 1),
            ("[ a == a ]", 0),
            ("[ a != b ]", 0),
            ("[ a != a ]", 1),
            ("[ -z \"$UNSET_X\" ]", 0),
            ("[ a '<' b ]", 0),
            ("[ b '<' a ]", 1),
            ("[ a '<' a ]", 1),
            ("[ b '>' a ]", 0),
            ("[ a '>' b ]", 1),
            // Bytewise: 'Z' (0x5a) before 'a' (0x61), and a two-byte UTF-8 letter after 'z'.
            ("[ Z '<' a ]", 0),
            ("[ é '>' z ]", 0),
            ("x=1; [ -v x ]", 0),
            ("[ -v not_set_anywhere ]", 1),
        ],
    );
}

#[test]
fn integer_tests_hold_for_every_operator_both_ways() {
    let mut sh = shell();
    check(
        &mut sh,
        &[
            ("[ 3 -eq 3 ]", 0),
            ("[ 3 -eq 2 ]", 1),
            ("[ 3 -ne 2 ]", 0),
            ("[ 3 -ne 3 ]", 1),
            ("[ 2 -lt 3 ]", 0),
            ("[ 3 -lt 3 ]", 1),
            ("[ 3 -le 3 ]", 0),
            ("[ 4 -le 3 ]", 1),
            ("[ 3 -gt 2 ]", 0),
            ("[ 3 -gt 3 ]", 1),
            ("[ 3 -ge 3 ]", 0),
            ("[ 2 -ge 3 ]", 1),
            ("[ -1 -lt 0 ]", 0),
            ("[ +1 -eq 1 ]", 0),
            ("[ 01 -eq 1 ]", 0),
            ("[ ' 1 ' -eq 1 ]", 0),
            ("[ 9223372036854775807 -gt 0 ]", 0),
            ("[ -9223372036854775808 -lt 0 ]", 0),
        ],
    );
}

#[test]
fn a_non_numeric_integer_operand_is_a_usage_error_naming_it() {
    let mut sh = shell();
    for (line, operand) in [
        ("test x -eq 1", "x"),
        ("test 1 -eq x", "x"),
        ("[ x -eq y ]", "x"),
        ("[ '' -eq 0 ]", ""),
        ("[ 99999999999999999999 -eq 1 ]", "99999999999999999999"),
        ("[ 1.5 -gt 1 ]", "1.5"),
        ("[ 1 -gt 0x10 ]", "0x10"),
    ] {
        let out = run(&mut sh, line);
        assert_eq!(out.status, 2, "{line}");
        let name = if line.starts_with('[') { "[" } else { "test" };
        assert_eq!(
            stderr_of(&out),
            format!("-bash: {name}: {operand}: integer expression expected\n"),
            "{line}"
        );
    }
}

#[test]
fn a_test_writes_nothing_to_standard_output() {
    let mut sh = shell();
    for line in [
        "test -f /etc/passwd",
        "test -f /nope",
        "[ a = a ]",
        "[ a = b ]",
        "[ ]",
        "test",
    ] {
        let out = run(&mut sh, line);
        assert!(out.bytes().is_empty(), "{line}: {:?}", out.bytes());
    }
}

#[test]
fn the_argument_count_forms_follow_posix_test() {
    let mut sh = shell();
    check(
        &mut sh,
        &[
            // Zero and one operand.
            ("test", 1),
            ("[ ]", 1),
            ("test a", 0),
            ("test ''", 1),
            ("test -n", 0),
            ("test -f", 0),
            ("test '!'", 0),
            ("[ ! ]", 0),
            // Two: negation and unary operators.
            ("test ! a", 1),
            ("test ! ''", 0),
            ("test -z ''", 0),
            ("test ! -n", 1),
            // Three: binary operator, negated two, and/or, grouping.
            ("test a = a", 0),
            ("test ! -n a", 1),
            ("test ! -z a", 0),
            ("test a -a b", 0),
            ("test '' -a b", 1),
            ("test '' -o b", 0),
            ("test '' -o ''", 1),
            ("test '(' a ')'", 0),
            ("test '(' '' ')'", 1),
            // Four: negated three, grouped two, and the general grammar.
            ("test ! a = a", 1),
            ("test ! a = b", 0),
            ("test '(' -n a ')'", 0),
            ("test '(' -z a ')'", 1),
            ("test -z a -o -z", 0),
            ("test ! ! ! a", 1),
            ("test a -o b -a", 2),
            // Five and more.
            ("test a = a -a b = b", 0),
            ("test a = a -a b = c", 1),
            ("test a = b -o b = b", 0),
            ("test a -a b -o c", 0),
            ("test a -o b -a c", 0),
            ("test '' -a b -o c", 0),
            ("test '' -a b -o ''", 1),
            ("test ! a -o b -o c", 0),
            ("test 1 -eq 1 -a '(' 2 -lt 3 ')'", 0),
            ("test 1 -eq 1 -a '(' 3 -lt 2 ')'", 1),
            ("test '(' -f /etc/passwd -o -d /nope ')' -a 1 -lt 2", 0),
            ("test '(' -f /nope -o -d /nope ')' -a 1 -lt 2", 1),
            ("test 1 -eq 1 -a ! -z", 1),
            ("test x -a -z", 0),
            ("test ! -f /nope -a ! -d /nope", 0),
            ("test -n a -a -n b -a -n c -a -n d", 0),
            ("test -n a -a -n b -a -n c -a -n ''", 1),
        ],
    );
}

#[test]
fn a_malformed_expression_is_status_2_with_the_shells_wording() {
    let mut sh = shell();
    for (line, wording) in [
        ("test a b", "test: a: unary operator expected"),
        ("test -Q x", "test: -Q: unary operator expected"),
        ("test a b c", "test: b: binary operator expected"),
        ("test '(' a b", "test: a: binary operator expected"),
        ("test a = a b", "test: too many arguments"),
        ("[ a b c d e ]", "[: too many arguments"),
        ("test 1 -lt 2 -a", "test: argument expected"),
        ("test a -o b -a c -a", "test: argument expected"),
        ("test '(' a -a b", "test: `)' expected"),
        ("test '(' a -a b x", "test: `)' expected, found x"),
        ("test '(' a b c", "test: `)' expected, found b"),
        ("test '(' '(' a ')'", "test: (: unary operator expected"),
        ("[ 1 -eq ]", "[: 1: unary operator expected"),
        ("[ a = ]", "[: a: unary operator expected"),
    ] {
        let out = run(&mut sh, line);
        assert_eq!(out.status, 2, "{line}");
        assert_eq!(stderr_of(&out), format!("-bash: {wording}\n"), "{line}");
    }
}

#[test]
fn a_bracket_needs_its_closing_bracket_and_test_does_not() {
    let mut sh = shell();
    for line in ["[", "[ a", "[ -e /etc/passwd", "[ ] x", "[ ]]"] {
        let out = run(&mut sh, line);
        assert_eq!(out.status, 2, "{line}");
        assert_eq!(stderr_of(&out), "-bash: [: missing `]'\n", "{line}");
    }
    check(
        &mut sh,
        &[
            ("[ -f /etc/passwd ]", 0),
            ("[ -d /etc/passwd ]", 1),
            ("[ -x /bin/sh ]", 0),
            ("[ a = a ]", 0),
            ("[ 3 -gt 2 ]", 0),
            ("[ ]", 1),
            // The bracket is one operand of `test`, not a terminator.
            ("test ]", 0),
            ("test -n ]", 0),
            // A second `]` is an operand of the expression.
            ("[ a ] ]", 2),
        ],
    );
}

#[test]
fn the_status_drives_and_or_and_the_last_status() {
    let mut sh = shell();
    let out = run(
        &mut sh,
        "test -f /nope || echo no; test -f /etc/passwd && echo yes",
    );
    assert_eq!(out, "no\nyes\n");
    let out = run(
        &mut sh,
        "[ 1 -eq 2 ]; echo $?; [ 1 -eq 1 ]; echo $?; [ 1 -eq x ]; echo $?",
    );
    assert_eq!(
        String::from_utf8_lossy(out.bytes()),
        "1\n0\n-bash: [: x: integer expression expected\n2\n"
    );
}

#[test]
fn the_double_bracket_form_is_not_this_builtin() {
    let mut sh = shell();
    let out = run(&mut sh, "[[ -f /nope ]]");
    assert_eq!((out.status, out.bytes().len()), (0, 0));
}

#[test]
fn both_names_resolve_including_by_path() {
    let mut sh = shell();
    check(
        &mut sh,
        &[
            ("test -f /etc/passwd", 0),
            ("/usr/bin/test -f /etc/passwd", 0),
            ("/usr/bin/[ -f /etc/passwd ]", 0),
            ("/bin/[ -f /nope ]", 1),
        ],
    );
    for name in ["test", "["] {
        assert!(
            super::registry::Registry::builtin()
                .node_facts(name)
                .is_some(),
            "{name}"
        );
    }
}

#[test]
fn an_exec_shell_words_the_diagnostic_with_its_own_prefix() {
    let mut sh = FakeShell::exec(FakeFs::new(), ctx());
    let out = run(&mut sh, "[ 1 -eq x ]");
    assert_eq!(out.status, 2);
    assert_eq!(
        stderr_of(&out),
        "bash: line 1: [: x: integer expression expected\n"
    );
}

#[test]
fn a_nested_dash_shell_reports_usage_errors_with_status_2() {
    let mut sh = shell();
    run(&mut sh, "sh");
    for line in ["test a b", "[ 1 -eq x ]", "[ a"] {
        let out = run(&mut sh, line);
        assert_eq!(out.status, 2, "{line}");
        assert!(stderr_of(&out).starts_with("sh: "), "{line}");
    }
    assert_eq!(exit_of(&mut sh, "[ -f /etc/passwd ]"), 0);
}

#[test]
fn the_first_writable_directory_ends_the_probe_loop_in_var_run() {
    let mut sh = shell();
    run(&mut sh, "cd /dev/shm");
    let out = run(
        &mut sh,
        "for d in /var/run /mnt /dev/shm /tmp; do test -w \"$d\" && cd \"$d\" && break; done",
    );
    assert!(out.bytes().is_empty(), "{:?}", out.bytes());
    assert_eq!(sh.cwd(), "/var/run");
}

#[test]
fn the_probe_loop_skips_read_only_directories_and_can_run_out() {
    let mut sh = android();
    run(&mut sh, "cd /sdcard");
    let out = run(
        &mut sh,
        "for d in /system /system/bin /data/local/tmp /sdcard; do test -w \"$d\" && cd \"$d\" && break; done",
    );
    assert!(out.bytes().is_empty(), "{:?}", out.bytes());
    assert_eq!(sh.cwd(), "/data/local/tmp");

    run(&mut sh, "cd /data");
    run(
        &mut sh,
        "for d in /system /system/bin /; do test -w \"$d\" && cd \"$d\" && break; done",
    );
    assert_eq!(sh.cwd(), "/data");
}

#[test]
fn a_very_long_or_deeply_nested_expression_ends_without_a_panic() {
    let mut sh = shell();
    let chain = format!("test a{}", " -o a".repeat(20_000));
    assert!(exit_of(&mut sh, &chain) <= 2);

    let nested = format!("test {} a {}", "'('".repeat(200), "')'".repeat(200));
    assert!(exit_of(&mut sh, &nested) <= 2);
    let out = run(&mut sh, &nested);
    assert_eq!(out.status, 2);
    assert_eq!(exit_of(&mut sh, "echo alive"), 0);
}
