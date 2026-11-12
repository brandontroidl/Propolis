//! `readlink` through `handle_input`. The expected paths are the layout of Ubuntu 22.04's merged
//! `/usr` (`/bin -> usr/bin`, `/bin/sh -> dash`, `/var/run -> /run`) and the `/proc/self/exe`
//! rule of the `/proc/self` resolver: the link names the executable of the process reading it.

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
fn a_symlink_reads_as_its_stored_target_one_level_deep() {
    let mut sh = shell();
    for (line, want) in [
        ("readlink /bin", "usr/bin\n"),
        ("readlink /bin/sh", "dash\n"),
        ("readlink /var/run", "/run\n"),
        ("readlink /etc/mtab", "/proc/self/mounts\n"),
        ("readlink /dev/stdin", "/proc/self/fd/0\n"),
        // The directories leading to the link resolve; only the last component is read.
        ("readlink /usr/bin/sh", "dash\n"),
    ] {
        assert_eq!(text(&mut sh, line), (0, want.into()), "{line}");
    }
}

#[test]
fn a_relative_operand_starts_at_the_working_directory() {
    let mut sh = shell();
    assert_eq!(text(&mut sh, "cd /var; readlink run"), (0, "/run\n".into()));
}

#[test]
fn a_non_symlink_or_missing_path_prints_nothing_and_fails() {
    let mut sh = shell();
    for line in [
        "readlink /etc/hostname",
        "readlink /tmp",
        "readlink /usr/bin/ls",
        "readlink /no/such/path",
        "readlink /bin/",
        "readlink ''",
        // The last component after `..` is /run itself, a directory, not the link /var/run.
        "readlink /var/run/../run",
    ] {
        assert_eq!(text(&mut sh, line), (1, String::new()), "{line}");
    }
    // A failing readlink stops an `&&` chain and starts an `||` one, as it does for a script.
    assert_eq!(
        text(&mut sh, "readlink /etc/hostname || echo no-link"),
        (0, "no-link\n".into())
    );
    assert_eq!(
        text(&mut sh, "readlink /bin && echo link"),
        (0, "usr/bin\nlink\n".into())
    );
}

#[test]
fn verbose_names_why_a_path_gave_nothing() {
    let mut sh = shell();
    assert_eq!(
        text(&mut sh, "readlink -v /etc/hostname"),
        (1, "readlink: /etc/hostname: Invalid argument\n".into())
    );
    assert_eq!(
        text(&mut sh, "readlink -v /no/such"),
        (1, "readlink: /no/such: No such file or directory\n".into())
    );
}

#[test]
fn proc_self_exe_is_the_executable_of_the_reading_process() {
    let mut sh = shell();
    for (line, want) in [
        ("readlink /proc/self/exe", "/usr/bin/readlink\n"),
        ("/bin/readlink /proc/self/exe", "/usr/bin/readlink\n"),
        ("/usr/bin/readlink /proc/self/exe", "/usr/bin/readlink\n"),
        // The applet is the busybox process, whatever name it was started by.
        ("/bin/busybox readlink /proc/self/exe", "/usr/bin/busybox\n"),
        ("busybox readlink /proc/self/exe", "/usr/bin/busybox\n"),
        ("readlink -f /proc/self/exe", "/usr/bin/readlink\n"),
        (
            "/bin/busybox readlink -f /proc/self/exe",
            "/usr/bin/busybox\n",
        ),
    ] {
        assert_eq!(text(&mut sh, line), (0, want.into()), "{line}");
    }
    // The reader is readlink, not the login shell.
    assert_ne!(
        text(&mut sh, "readlink /proc/self/exe").1,
        "/usr/bin/bash\n"
    );
}

#[test]
fn a_shells_proc_pid_exe_is_that_shell() {
    let mut sh = shell();
    let (_, pid) = text(&mut sh, "echo $$");
    let pid = pid.trim();
    assert_eq!(
        text(&mut sh, &format!("readlink /proc/{pid}/exe")),
        (0, "/usr/bin/bash\n".into())
    );
}

#[test]
fn canonical_modes_print_the_physical_path() {
    let mut sh = shell();
    for (line, want) in [
        ("readlink -f /bin/ls", "/usr/bin/ls\n"),
        ("readlink -f /bin/sh", "/usr/bin/dash\n"),
        ("readlink -e /bin/sh", "/usr/bin/dash\n"),
        ("readlink -m /bin/sh", "/usr/bin/dash\n"),
        ("readlink -f /var/run", "/run\n"),
        ("readlink --canonicalize /bin/../bin/sh", "/usr/bin/dash\n"),
        // A regular file canonicalizes to itself.
        ("readlink -f /etc/hostname", "/etc/hostname\n"),
        ("readlink -f /etc/./../etc//hostname", "/etc/hostname\n"),
    ] {
        assert_eq!(text(&mut sh, line), (0, want.into()), "{line}");
    }
    // A relative operand starts at the working directory, which may itself be reached by a link.
    assert_eq!(
        text(&mut sh, "cd /bin; readlink -f sh"),
        (0, "/usr/bin/dash\n".into())
    );
}

#[test]
fn the_canonical_modes_differ_only_in_what_must_exist() {
    let mut sh = shell();
    // -f: the last component may be missing, the directories may not.
    assert_eq!(
        text(&mut sh, "readlink -f /bin/nosuch"),
        (0, "/usr/bin/nosuch\n".into())
    );
    assert_eq!(
        text(&mut sh, "readlink -f /nodir/nosuch"),
        (1, String::new())
    );
    // -e: everything.
    assert_eq!(text(&mut sh, "readlink -e /bin/nosuch"), (1, String::new()));
    // -m: nothing, and `..` still climbs the part that exists.
    assert_eq!(
        text(&mut sh, "readlink -m /bin/x/y/../z"),
        (0, "/usr/bin/x/z\n".into())
    );
    assert_eq!(
        text(&mut sh, "readlink -m /nodir/nosuch"),
        (0, "/nodir/nosuch\n".into())
    );
    // The last mode given wins.
    assert_eq!(
        text(&mut sh, "readlink -e -m /nodir/nosuch"),
        (0, "/nodir/nosuch\n".into())
    );
    // A file is not a directory, so nothing can lie under it.
    assert_eq!(
        text(&mut sh, "readlink -f /etc/hostname/x"),
        (1, String::new())
    );
}

#[test]
fn no_newline_and_several_operands() {
    let mut sh = shell();
    assert_eq!(text(&mut sh, "readlink -n /bin"), (0, "usr/bin".into()));
    assert_eq!(
        text(&mut sh, "readlink -nf /bin/sh"),
        (0, "/usr/bin/dash".into())
    );
    // With more than one operand the newline stays, and the status is 1 if any operand failed.
    assert_eq!(
        text(&mut sh, "readlink -n /bin /etc/hostname /var/run"),
        (1, "usr/bin\n/run\n".into())
    );
    assert_eq!(text(&mut sh, "readlink -z /bin"), (0, "usr/bin\0".into()));
}

#[test]
fn bad_invocations_print_the_gnu_diagnostics() {
    let mut sh = shell();
    assert_eq!(
        text(&mut sh, "readlink"),
        (
            1,
            "readlink: missing operand\nTry 'readlink --help' for more information.\n".into()
        )
    );
    assert_eq!(
        text(&mut sh, "readlink -x /bin"),
        (
            1,
            "readlink: invalid option -- 'x'\nTry 'readlink --help' for more information.\n".into()
        )
    );
    assert_eq!(
        text(&mut sh, "readlink --nope /bin"),
        (
            1,
            "readlink: unrecognized option '--nope'\nTry 'readlink --help' for more information.\n"
                .into()
        )
    );
    // After `--` a leading dash is an operand.
    assert_eq!(text(&mut sh, "readlink -- -f"), (1, String::new()));
}

#[test]
fn readlink_reads_the_same_in_a_pipeline_and_a_substitution() {
    let mut sh = shell();
    assert_eq!(
        text(&mut sh, "echo $(readlink -f /bin/sh)"),
        (0, "/usr/bin/dash\n".into())
    );
    assert_eq!(
        text(&mut sh, "readlink /bin | cat"),
        (0, "usr/bin\n".into())
    );
}

#[test]
fn the_phone_has_no_readlink() {
    let mut sh = FakeShell::android(FakeFs::android(), ctx());
    let (status, out) = text(&mut sh, "readlink /proc/self/exe");
    assert_eq!(status, 127);
    assert!(out.contains("not found"), "{out}");
}
