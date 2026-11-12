//! `basename`, `dirname` and `realpath` through `handle_input`. The splitting rules are GNU
//! coreutils' (a current host, not captured on the reference box); `realpath` resolves through the
//! same modeled filesystem as `readlink -f`, so its expected paths are Ubuntu 22.04's merged `/usr`.

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

#[test]
fn basename_drops_the_directory_and_an_optional_suffix() {
    let mut sh = shell();
    for (line, want) in [
        ("basename /usr/bin/wget", "wget\n"),
        ("basename wget", "wget\n"),
        ("basename /a/b.tar.gz .gz", "b.tar\n"),
        // The suffix must be a proper suffix: not the whole name, and not elsewhere in it.
        ("basename /a/.gz .gz", ".gz\n"),
        ("basename /a/b.gz .tar", "b.gz\n"),
        ("basename /a/b.gz b", "b.gz\n"),
        // Trailing slashes are not part of the name.
        ("basename /usr/bin/", "bin\n"),
        ("basename /usr/bin///", "bin\n"),
        ("basename /", "/\n"),
        ("basename ///", "/\n"),
        ("basename ''", "\n"),
        ("basename /a/b.x/ .x", "b\n"),
        // A name that is only slashes keeps them as the root, and no suffix applies to it.
        ("basename / /", "/\n"),
    ] {
        assert_eq!(out(&mut sh, line), want, "{line}");
    }
}

#[test]
fn basename_multiple_and_suffix_options() {
    let mut sh = shell();
    for (line, want) in [
        ("basename -a /x/y /p/q", "y\nq\n"),
        ("basename --multiple /x/y /p/q", "y\nq\n"),
        ("basename -s .txt a.txt b.txt", "a\nb\n"),
        ("basename -s.txt /d/a.txt /d/b.txt", "a\nb\n"),
        ("basename --suffix=.txt a.txt", "a\n"),
        ("basename --suffix .txt a.txt", "a\n"),
        // -a takes every operand as a name: no positional suffix.
        ("basename -a /x/y.z .z", "y.z\n.z\n"),
        ("basename -z /usr/bin/wget", "wget\0"),
        ("basename -az /x/y /p/q", "y\0q\0"),
        ("basename --zero /x/y", "y\0"),
        // After `--` a leading dash is a name.
        ("basename -- -a", "-a\n"),
    ] {
        assert_eq!(out(&mut sh, line), want, "{line}");
    }
}

#[test]
fn basename_usage_errors_print_the_gnu_diagnostics() {
    let mut sh = shell();
    let try_help = "Try 'basename --help' for more information.\n";
    assert_eq!(
        answer(&mut sh, "basename"),
        (
            String::new(),
            format!("basename: missing operand\n{try_help}"),
            1
        )
    );
    assert_eq!(
        answer(&mut sh, "basename a b c"),
        (
            String::new(),
            format!("basename: extra operand 'c'\n{try_help}"),
            1
        )
    );
    assert_eq!(
        answer(&mut sh, "basename -x a"),
        (
            String::new(),
            format!("basename: invalid option -- 'x'\n{try_help}"),
            1
        )
    );
    assert_eq!(
        answer(&mut sh, "basename -s"),
        (
            String::new(),
            format!("basename: option requires an argument -- 's'\n{try_help}"),
            1
        )
    );
}

#[test]
fn dirname_keeps_everything_before_the_last_component() {
    let mut sh = shell();
    for (line, want) in [
        ("dirname /usr/bin/wget", "/usr/bin\n"),
        ("dirname wget", ".\n"),
        ("dirname /", "/\n"),
        ("dirname ///", "/\n"),
        ("dirname /wget", "/\n"),
        ("dirname ''", ".\n"),
        ("dirname a/", ".\n"),
        ("dirname a/b/", "a\n"),
        ("dirname /a/b/", "/a\n"),
        ("dirname a//b", "a\n"),
        ("dirname ./x", ".\n"),
        ("dirname /usr/bin/wget /tmp/x y", "/usr/bin\n/tmp\n.\n"),
        ("dirname -z /usr/bin/wget /tmp/x", "/usr/bin\0/tmp\0"),
        ("dirname --zero /a/b", "/a\0"),
    ] {
        assert_eq!(out(&mut sh, line), want, "{line}");
    }
    let try_help = "Try 'dirname --help' for more information.\n";
    assert_eq!(
        answer(&mut sh, "dirname"),
        (
            String::new(),
            format!("dirname: missing operand\n{try_help}"),
            1
        )
    );
    // -a and -s are basename's.
    assert_eq!(
        answer(&mut sh, "dirname -a /x/y"),
        (
            String::new(),
            format!("dirname: invalid option -- 'a'\n{try_help}"),
            1
        )
    );
}

#[test]
fn the_split_tools_never_touch_the_filesystem() {
    let mut sh = shell();
    // The operand names no node, and the answer is the same as for one that exists.
    assert_eq!(out(&mut sh, "basename /no/such/dir/file"), "file\n");
    assert_eq!(out(&mut sh, "dirname /no/such/dir/file"), "/no/such/dir\n");
    // They run inside a script's usual substitutions.
    assert_eq!(
        out(
            &mut sh,
            "echo $(dirname /usr/bin/wget)/$(basename /usr/bin/wget)"
        ),
        "/usr/bin/wget\n"
    );
    assert_eq!(out(&mut sh, "echo /usr/bin/wget | basename /x/y"), "y\n");
}

#[test]
fn realpath_resolves_links_through_the_modeled_filesystem() {
    let mut sh = shell();
    for (line, want) in [
        ("realpath /var/run", "/run\n"),
        ("realpath /bin/sh", "/usr/bin/dash\n"),
        ("realpath /bin/../bin/ls", "/usr/bin/ls\n"),
        ("realpath /etc/./../etc//hostname", "/etc/hostname\n"),
        ("realpath /var/run /etc/hostname", "/run\n/etc/hostname\n"),
        ("realpath -z /var/run", "/run\0"),
    ] {
        assert_eq!(out(&mut sh, line), want, "{line}");
    }
    assert_eq!(out(&mut sh, "cd /bin; realpath sh"), "/usr/bin/dash\n");
    // With no operand the tool says so; it does not default to the working directory.
    assert_eq!(
        answer(&mut sh, "realpath"),
        (
            String::new(),
            "realpath: missing operand\nTry 'realpath --help' for more information.\n".into(),
            1
        )
    );
}

#[test]
fn realpath_agrees_with_readlink_f() {
    let mut sh = shell();
    for path in [
        "/bin/sh",
        "/var/run",
        "/etc/hostname",
        "/bin/nosuch",
        "/nodir/nosuch",
    ] {
        let real = answer(&mut sh, &format!("realpath {path}"));
        let link = answer(&mut sh, &format!("readlink -f {path}"));
        assert_eq!((real.0, real.2), (link.0, link.2), "{path}");
    }
}

#[test]
fn realpath_proc_self_exe_is_the_executable_of_the_reading_process() {
    let mut sh = shell();
    for (line, want) in [
        ("realpath /proc/self/exe", "/usr/bin/realpath\n"),
        ("/bin/realpath /proc/self/exe", "/usr/bin/realpath\n"),
        ("busybox realpath /proc/self/exe", "/usr/bin/busybox\n"),
        ("/bin/busybox realpath /proc/self/exe", "/usr/bin/busybox\n"),
    ] {
        assert_eq!(out(&mut sh, line), want, "{line}");
    }
}

#[test]
fn realpath_modes_differ_in_what_must_exist() {
    let mut sh = shell();
    let nothing = |status| (String::new(), status);
    // Default: the last component may be missing, the directories may not.
    assert_eq!(out(&mut sh, "realpath /bin/nosuch"), "/usr/bin/nosuch\n");
    let (stdout, stderr, status) = answer(&mut sh, "realpath /nodir/nosuch");
    assert_eq!((stdout, status), nothing(1));
    assert_eq!(
        stderr,
        "realpath: /nodir/nosuch: No such file or directory\n"
    );
    // -e: everything, and each failure is reported while the rest still print.
    let (stdout, stderr, status) = answer(&mut sh, "realpath -e /bin/nosuch /var/run");
    assert_eq!((stdout, status), ("/run\n".to_string(), 1));
    assert_eq!(stderr, "realpath: /bin/nosuch: No such file or directory\n");
    // -m: nothing, and `..` still climbs the part that exists.
    assert_eq!(
        answer(&mut sh, "realpath -m /nodir/nosuch"),
        ("/nodir/nosuch\n".into(), String::new(), 0)
    );
    assert_eq!(out(&mut sh, "realpath -m /bin/x/y/../z"), "/usr/bin/x/z\n");
    // -q keeps the status and drops the message.
    assert_eq!(
        answer(&mut sh, "realpath -q /nodir/nosuch"),
        (String::new(), String::new(), 1)
    );
    // The last mode given wins.
    assert_eq!(out(&mut sh, "realpath -e -m /nodir/x"), "/nodir/x\n");
}

#[test]
fn realpath_s_collapses_the_text_and_follows_no_link() {
    let mut sh = shell();
    for (line, want) in [
        ("realpath -s /var/run", "/var/run\n"),
        ("realpath -s /bin/../etc/./hostname", "/etc/hostname\n"),
        ("realpath --no-symlinks /var//run/", "/var/run\n"),
        ("realpath -sm /nodir/a/../b", "/nodir/b\n"),
        ("cd /var; realpath -s run", "/var/run\n"),
    ] {
        assert_eq!(out(&mut sh, line), want, "{line}");
    }
    // The mode's existence rule still applies.
    assert_eq!(
        answer(&mut sh, "realpath -s /nodir/x"),
        (
            String::new(),
            "realpath: /nodir/x: No such file or directory\n".into(),
            1
        )
    );
    assert_eq!(out(&mut sh, "realpath -s /bin/nosuch"), "/bin/nosuch\n");
}

#[test]
fn realpath_bad_options_print_the_gnu_diagnostics() {
    let mut sh = shell();
    let try_help = "Try 'realpath --help' for more information.\n";
    assert_eq!(
        answer(&mut sh, "realpath -x /bin"),
        (
            String::new(),
            format!("realpath: invalid option -- 'x'\n{try_help}"),
            1
        )
    );
    assert_eq!(
        answer(&mut sh, "realpath --nope /bin"),
        (
            String::new(),
            format!("realpath: unrecognized option '--nope'\n{try_help}"),
            1
        )
    );
    // An empty operand names nothing.
    assert_eq!(
        answer(&mut sh, "realpath ''"),
        (
            String::new(),
            "realpath: '': No such file or directory\n".into(),
            1
        )
    );
    // Options this shell does not model print nothing and succeed, never a path it made up.
    assert_eq!(
        answer(&mut sh, "realpath --relative-to=/usr /usr/bin"),
        (String::new(), String::new(), 0)
    );
}

#[test]
fn the_path_tools_are_applets_of_the_modeled_busybox_and_absent_on_the_phone() {
    let mut sh = shell();
    assert_eq!(out(&mut sh, "busybox basename /usr/bin/wget"), "wget\n");
    assert_eq!(out(&mut sh, "/bin/busybox basename /a/b.gz .gz"), "b\n");
    assert_eq!(out(&mut sh, "busybox dirname /usr/bin/wget"), "/usr/bin\n");
    assert_eq!(out(&mut sh, "busybox realpath /var/run"), "/run\n");
    let banner = out(&mut sh, "/bin/busybox");
    let listed: Vec<&str> = banner
        .lines()
        .skip_while(|line| !line.starts_with("Currently defined"))
        .skip(1)
        .flat_map(|line| line.split(','))
        .map(str::trim)
        .collect();
    for applet in ["basename", "dirname", "realpath"] {
        assert!(listed.contains(&applet), "{applet} advertised: {banner}");
    }

    let mut phone = FakeShell::android(FakeFs::android(), ctx());
    for name in ["basename", "dirname", "realpath"] {
        let (stdout, stderr, status) = answer(&mut phone, &format!("{name} /a/b"));
        assert_eq!((stdout.as_str(), status), ("", 127), "{name}");
        assert!(stderr.contains("not found"), "{name}: {stderr}");
    }
}
