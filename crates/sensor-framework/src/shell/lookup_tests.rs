//! `command -v`/`-V`, `type` and `which` through `handle_input`. Bash cases carry the bytes and
//! statuses recorded on Ubuntu 22.04 (`command -v cat` is `/usr/bin/cat`, `type cd` is
//! `cd is a shell builtin`, an absent `type` name goes to standard error with status 1, `which cat`
//! is `/usr/bin/cat`); the dash cases carry the recorded dash-family answers (`type` of an absent
//! name on standard output, status 127). The agreement test is the design invariant: the lookup
//! commands and dispatch answer every registered name the same way.

use super::registry::Registry;
use super::{CommandResult, EmitContext, FakeShell, HandlerId, OutputFd};
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

fn exec_shell() -> FakeShell {
    FakeShell::exec(FakeFs::new(), ctx())
}

fn android() -> FakeShell {
    FakeShell::android(FakeFs::android(), ctx())
}

/// A login shell that has run a bare `sh`, so the level answering is dash.
fn dash() -> FakeShell {
    let mut sh = shell();
    sh.handle_input("sh");
    sh
}

fn run(sh: &mut FakeShell, line: &str) -> CommandResult {
    sh.handle_input(line).0
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
    let out = run(sh, line);
    (
        stream(&out, OutputFd::Stdout),
        stream(&out, OutputFd::Stderr),
        out.status,
    )
}

fn only_command(sh: &FakeShell) -> &super::CommandTrace {
    let trace = sh.last_trace();
    assert_eq!(trace.segments.len(), 1, "{trace:?}");
    trace.segments[0].command.as_ref().expect("segment ran")
}

#[test]
fn command_v_prints_a_builtin_by_name_a_file_by_path_and_a_missing_name_not_at_all() {
    let mut sh = shell();
    assert_eq!(
        answer(&mut sh, "command -v cd"),
        ("cd\n".into(), "".into(), 0)
    );
    assert_eq!(
        answer(&mut sh, "command -v cat"),
        ("/usr/bin/cat\n".into(), "".into(), 0)
    );
    // `echo` is a builtin and a file: the builtin wins, as in the recording.
    assert_eq!(
        answer(&mut sh, "command -v echo"),
        ("echo\n".into(), "".into(), 0)
    );
    assert_eq!(
        answer(&mut sh, "command -v nosuch"),
        ("".into(), "".into(), 1)
    );
    // Sbin and merged-usr layout: the first `$PATH` directory holding the file names it.
    assert_eq!(
        answer(&mut sh, "command -v useradd"),
        ("".into(), "".into(), 1),
        "useradd is not something dispatch runs"
    );
    assert_eq!(
        answer(&mut sh, "command -v sh"),
        ("/usr/bin/sh\n".into(), "".into(), 0)
    );
    // bash describes every name and succeeds when any was found.
    assert_eq!(
        answer(&mut sh, "command -v nosuch cat"),
        ("/usr/bin/cat\n".into(), "".into(), 0)
    );
    assert_eq!(
        answer(&mut sh, "command -v cat nosuch"),
        ("/usr/bin/cat\n".into(), "".into(), 0)
    );
}

#[test]
fn command_v_of_a_path_and_of_a_reserved_word() {
    let mut sh = shell();
    assert_eq!(
        answer(&mut sh, "command -v /bin/ls"),
        ("/bin/ls\n".into(), "".into(), 0)
    );
    assert_eq!(
        answer(&mut sh, "command -v /no/such/thing"),
        ("".into(), "".into(), 1)
    );
    assert_eq!(
        answer(&mut sh, "command -v if"),
        ("if\n".into(), "".into(), 0)
    );
    // A file the session made and marked executable is a path that runs.
    run(&mut sh, ">/tmp/x");
    assert_eq!(answer(&mut sh, "command -v /tmp/x").2, 1);
    run(&mut sh, "chmod +x /tmp/x");
    assert_eq!(
        answer(&mut sh, "command -v /tmp/x"),
        ("/tmp/x\n".into(), "".into(), 0)
    );
}

#[test]
fn command_capital_v_prints_a_sentence_and_reports_a_missing_name() {
    let mut sh = shell();
    assert_eq!(
        answer(&mut sh, "command -V cd"),
        ("cd is a shell builtin\n".into(), "".into(), 0)
    );
    assert_eq!(
        answer(&mut sh, "command -V ls"),
        ("ls is /usr/bin/ls\n".into(), "".into(), 0)
    );
    assert_eq!(
        answer(&mut sh, "command -V while"),
        ("while is a shell keyword\n".into(), "".into(), 0)
    );
    assert_eq!(
        answer(&mut sh, "command -V nosuch"),
        ("".into(), "-bash: command: nosuch: not found\n".into(), 1)
    );
    assert_eq!(
        answer(&mut sh, "command -pv ls"),
        ("/usr/bin/ls\n".into(), "".into(), 0)
    );
}

#[test]
fn command_without_v_runs_the_name_through_dispatch() {
    let mut sh = shell();
    assert_eq!(
        answer(&mut sh, "command echo hi"),
        ("hi\n".into(), "".into(), 0)
    );
    assert_eq!(only_command(&sh).resolved, HandlerId::CommandBuiltin);
    assert_eq!(only_command(&sh).reentry[0].resolved, HandlerId::Echo);
    assert_eq!(answer(&mut sh, "command -p -- pwd").0, "/root\n");
    assert_eq!(answer(&mut sh, "command"), ("".into(), "".into(), 0));
    let (out, err, status) = answer(&mut sh, "command nosuchcmd");
    assert_eq!((out.as_str(), status), ("", 127));
    assert!(err.ends_with("nosuchcmd: command not found\n"), "{err:?}");
    // It skips nothing dispatch would not: a builtin that acts on the shell still acts.
    run(&mut sh, "command cd /tmp");
    assert_eq!(sh.cwd(), "/tmp");
}

#[test]
fn command_rejects_an_unknown_option_the_way_each_shell_words_it() {
    let mut sh = shell();
    let (out, err, status) = answer(&mut sh, "command -x ls");
    assert_eq!((out.as_str(), status), ("", 2));
    assert_eq!(
        err,
        "-bash: command: -x: invalid option\ncommand: usage: command [-pVv] command [arg ...]\n"
    );
    let mut sh = dash();
    let (out, err, status) = answer(&mut sh, "command -x ls");
    assert_eq!((out.as_str(), status), ("", 2));
    assert_eq!(err, "sh: 1: command: Illegal option -x\n");
}

#[test]
fn type_words_a_builtin_a_file_and_a_missing_name() {
    let mut sh = shell();
    assert_eq!(
        answer(&mut sh, "type cat"),
        ("cat is /usr/bin/cat\n".into(), "".into(), 0)
    );
    assert_eq!(
        answer(&mut sh, "type cd"),
        ("cd is a shell builtin\n".into(), "".into(), 0)
    );
    assert_eq!(
        answer(&mut sh, "type echo"),
        ("echo is a shell builtin\n".into(), "".into(), 0)
    );
    assert_eq!(
        answer(&mut sh, "type nosuch"),
        ("".into(), "-bash: type: nosuch: not found\n".into(), 1)
    );
    assert_eq!(
        answer(&mut sh, "type if"),
        ("if is a shell keyword\n".into(), "".into(), 0)
    );
    // The recorded sequence, one shell: found, found, found, then the failure.
    assert_eq!(
        answer(&mut sh, "type cat cd nosuch"),
        (
            "cat is /usr/bin/cat\ncd is a shell builtin\n".into(),
            "-bash: type: nosuch: not found\n".into(),
            1
        )
    );
    assert_eq!(answer(&mut sh, "type"), ("".into(), "".into(), 0));
}

#[test]
fn type_prefix_follows_how_bash_was_started() {
    let mut sh = exec_shell();
    assert_eq!(
        answer(&mut sh, "type nosuch"),
        (
            "".into(),
            "bash: line 1: type: nosuch: not found\n".into(),
            1
        )
    );
    let mut sh = shell();
    sh.handle_input("su");
    assert_eq!(
        answer(&mut sh, "type nosuch"),
        ("".into(), "bash: type: nosuch: not found\n".into(), 1)
    );
}

#[test]
fn type_flags_pick_the_word_the_path_or_every_form() {
    let mut sh = shell();
    assert_eq!(answer(&mut sh, "type -t cat").0, "file\n");
    assert_eq!(answer(&mut sh, "type -t cd").0, "builtin\n");
    assert_eq!(answer(&mut sh, "type -t if").0, "keyword\n");
    assert_eq!(answer(&mut sh, "type -t nosuch"), ("".into(), "".into(), 1));
    // -p prints a path only for a file; a builtin prints nothing and still succeeds.
    assert_eq!(answer(&mut sh, "type -p cat").0, "/usr/bin/cat\n");
    assert_eq!(answer(&mut sh, "type -p echo"), ("".into(), "".into(), 0));
    assert_eq!(answer(&mut sh, "type -p nosuch"), ("".into(), "".into(), 1));
    // -P searches `$PATH` even for a builtin, and fails for one that has no file.
    assert_eq!(answer(&mut sh, "type -P echo").0, "/usr/bin/echo\n");
    assert_eq!(answer(&mut sh, "type -P cd"), ("".into(), "".into(), 1));
    // -a lists every form: the builtin, then each `$PATH` directory holding the file.
    assert_eq!(
        answer(&mut sh, "type -a echo").0,
        "echo is a shell builtin\necho is /usr/bin/echo\necho is /bin/echo\n"
    );
    assert_eq!(answer(&mut sh, "type -at echo").0, "builtin\nfile\nfile\n");
    assert_eq!(
        answer(&mut sh, "type -a ls").0,
        "ls is /usr/bin/ls\nls is /bin/ls\n"
    );
    assert_eq!(answer(&mut sh, "type -- cat").0, "cat is /usr/bin/cat\n");
    let (out, err, status) = answer(&mut sh, "type -z cat");
    assert_eq!((out.as_str(), status), ("", 2));
    assert_eq!(
        err,
        "-bash: type: -z: invalid option\ntype: usage: type [-afptP] name [name ...]\n"
    );
}

#[test]
fn which_prints_the_first_path_match_and_fails_for_a_missing_name() {
    let mut sh = shell();
    assert_eq!(
        answer(&mut sh, "which cat"),
        ("/usr/bin/cat\n".into(), "".into(), 0)
    );
    assert_eq!(answer(&mut sh, "which nosuch"), ("".into(), "".into(), 1));
    // Every name on its own line; the status is 1 when any is missing.
    assert_eq!(
        answer(&mut sh, "which cat nosuch ls"),
        ("/usr/bin/cat\n/usr/bin/ls\n".into(), "".into(), 1)
    );
    // `which` is a file, so it finds itself; the shell builtins have no file to find.
    assert_eq!(
        answer(&mut sh, "which which"),
        ("/usr/bin/which\n".into(), "".into(), 0)
    );
    assert_eq!(answer(&mut sh, "which cd"), ("".into(), "".into(), 1));
    assert_eq!(answer(&mut sh, "which echo").0, "/usr/bin/echo\n");
    assert_eq!(answer(&mut sh, "which if"), ("".into(), "".into(), 1));
    assert_eq!(answer(&mut sh, "which"), ("".into(), "".into(), 1));
    assert_eq!(answer(&mut sh, "which -a ls").0, "/usr/bin/ls\n/bin/ls\n");
    assert_eq!(answer(&mut sh, "which -- ls").0, "/usr/bin/ls\n");
    assert_eq!(answer(&mut sh, "which /bin/ls").0, "/bin/ls\n");
    assert_eq!(answer(&mut sh, "which ''"), ("".into(), "".into(), 1));
    assert_eq!(
        answer(&mut sh, "type which"),
        ("which is /usr/bin/which\n".into(), "".into(), 0)
    );
    assert_eq!(answer(&mut sh, "type -t which").0, "file\n");
    let (out, err, status) = answer(&mut sh, "which -x ls");
    assert_eq!(status, 2);
    assert_eq!(err, "Illegal option -x\n");
    assert_eq!(out, "Usage: /usr/bin/which [-a] args\n");
}

#[test]
fn which_and_command_follow_the_session_path() {
    let mut sh = shell();
    // The search order is the session's `$PATH`, and the printed path is the entry as written.
    run(&mut sh, "PATH=/bin:/usr/bin");
    assert_eq!(answer(&mut sh, "which ls").0, "/bin/ls\n");
    assert_eq!(answer(&mut sh, "command -v ls").0, "/bin/ls\n");
    assert_eq!(answer(&mut sh, "type ls").0, "ls is /bin/ls\n");
    // A directory with no such file falls through to the next.
    run(&mut sh, "PATH=/nonexistent:/usr/bin");
    assert_eq!(answer(&mut sh, "which ls").0, "/usr/bin/ls\n");
    // Dispatch does not consult `$PATH`, so a name it runs is still reported with none.
    run(&mut sh, "PATH=/nonexistent");
    assert_eq!(answer(&mut sh, "which ls").0, "/usr/bin/ls\n");
    assert_eq!(answer(&mut sh, "echo hi").0, "hi\n");
    // A name it does not run stays absent, whatever `$PATH` holds.
    run(&mut sh, "PATH=/usr/bin");
    assert_eq!(answer(&mut sh, "which nosuch"), ("".into(), "".into(), 1));
}

#[test]
fn dash_words_the_lookups_as_the_recording_did() {
    let mut sh = dash();
    assert_eq!(
        answer(&mut sh, "command -v cat"),
        ("/usr/bin/cat\n".into(), "".into(), 0)
    );
    assert_eq!(
        answer(&mut sh, "command -v cd"),
        ("cd\n".into(), "".into(), 0)
    );
    assert_eq!(
        answer(&mut sh, "command -v nosuch"),
        ("".into(), "".into(), 127)
    );
    assert_eq!(
        answer(&mut sh, "type cat cd nosuch"),
        (
            "cat is /usr/bin/cat\ncd is a shell builtin\nnosuch: not found\n".into(),
            "".into(),
            127
        )
    );
    // dash has no flags on `type`: they are names, and are not found.
    assert_eq!(
        answer(&mut sh, "type -t cat"),
        (
            "-t: not found\ncat is /usr/bin/cat\n".into(),
            "".into(),
            127
        )
    );
    // bash's `source` and `enable` are not dash's.
    assert_eq!(
        answer(&mut sh, "command -v source"),
        ("".into(), "".into(), 127)
    );
    assert_eq!(answer(&mut sh, "type enable").0, "enable: not found\n");
    assert_eq!(answer(&mut sh, "type logout").0, "logout: not found\n");
    assert_eq!(answer(&mut sh, "which cat").0, "/usr/bin/cat\n");
}

#[test]
fn the_phone_answers_from_its_own_shell_and_filesystem() {
    let mut sh = android();
    assert_eq!(answer(&mut sh, "command -v cd").0, "cd\n");
    assert_eq!(answer(&mut sh, "command -v ls").0, "/system/bin/ls\n");
    // The phone has no `which` file and no `dd`: dispatch says not found, so do the lookups.
    assert_eq!(answer(&mut sh, "command -v dd").2, 1);
    assert_eq!(answer(&mut sh, "type dd").0, "dd: not found\n");
    // A name dispatch runs that the phone's directories hold no file for is reported in
    // `/system/bin`, where its answer would come from.
    assert_eq!(answer(&mut sh, "command -v wget").0, "/system/bin/wget\n");
}

#[test]
fn a_lookup_charges_the_line_budget_for_a_long_path() {
    let mut sh = shell();
    let long = vec!["/nonexistent"; 64].join(":");
    run(&mut sh, &format!("PATH={long}:/usr/bin"));
    let out = run(&mut sh, "which ls");
    assert_eq!(out.bytes(), b"/usr/bin/ls\n");
    assert!(sh.last_trace().budget.work_charged >= 64);
}

#[test]
fn the_which_script_is_a_modeled_file_with_the_recorded_first_bytes() {
    let fs = FakeFs::new();
    assert!(fs.is_executable("/usr/bin/which"));
    assert!(fs.is_executable("/bin/which"));
    let head = fs.read_range("/usr/bin/which", 0, 64).unwrap();
    let hex: String = head.iter().map(|byte| format!("{byte:02x}")).collect();
    assert_eq!(
        hex,
        "2321202f62696e2f73680a736574202d65660a0a69662074657374202d6e2022244b53485f56455253494f4e223b207468656e0a09707574732829207b0a0909"
    );
    assert!(!FakeFs::android().is_executable("/usr/bin/which"));
}

#[test]
fn the_lookups_are_dispatch_arms_of_their_own() {
    for (line, want) in [
        ("command -v ls", HandlerId::CommandBuiltin),
        ("type ls", HandlerId::Type),
        ("which ls", HandlerId::Which),
    ] {
        let mut sh = shell();
        sh.handle_input(line);
        assert_eq!(only_command(&sh).resolved, want, "{line}");
    }
}

/// What the shell does with the bare name `name`, as an observer sees it: whether the reply is its
/// own "command not found". Running the name, not asking the registry, so the check has no
/// definition in common with the code it checks.
fn dispatch_runs(sh: &mut FakeShell, name: &str) -> bool {
    // dash counts input lines in its message (`sh: 3: x: not found`), so the reply is matched by
    // its ending, and the login shell's suggestion texts by the shell's own rendering.
    let rendered = sh.not_found(name);
    let out = run(sh, name);
    let text = String::from_utf8_lossy(out.bytes()).into_owned();
    let refused = text == rendered
        || text.ends_with(&format!("{name}: not found\n"))
        || text.ends_with(&format!("{name}: command not found\n"));
    !(out.status == 127 && refused)
}

/// The design invariant (registry section 2.3): for every name the registry holds, in every shell
/// the sensors present, `command -v`, `type` and `which` say what dispatch does.
#[test]
fn every_registered_name_is_looked_up_the_way_dispatch_runs_it() {
    type Make = fn() -> FakeShell;
    let shells: [(&str, Make); 4] = [
        ("bash login", shell),
        ("bash exec", exec_shell),
        ("dash", dash),
        ("android mksh", android),
    ];
    let names = Registry::builtin().names();
    assert!(
        names.len() > 50,
        "the table is walked, not a stub: {}",
        names.len()
    );
    let mut ran = 0;
    let mut gone = 0;
    for (label, make) in shells {
        for name in &names {
            let runs = dispatch_runs(&mut make(), name);
            let mut sh = make();
            let (cv, _, cv_status) = answer(&mut sh, &format!("command -v -- '{name}'"));
            let (ty_out, ty_err, ty_status) = answer(&mut sh, &format!("type '{name}'"));
            let (which, _, which_status) = answer(&mut sh, &format!("which '{name}'"));
            let (sentence, _, _) = answer(&mut sh, &format!("command -V '{name}'"));
            let context = format!("{label}: {name}");
            // The phone has no `which` file, so there is no `which` to ask there.
            let has_which = label != "android mksh";
            assert_eq!(cv_status == 0, runs, "command -v {context}");
            assert_eq!(ty_status == 0, runs, "type {context}");
            if runs {
                ran += 1;
                assert!(!cv.is_empty(), "command -v prints something for {context}");
                assert!(ty_err.is_empty(), "{context}: {ty_err:?}");
                assert!(
                    ty_out.starts_with(&format!("{name} is ")),
                    "{context}: {ty_out:?}"
                );
                // `which` finds files. A builtin has one only when the filesystem holds it.
                let builtin_only =
                    sentence.ends_with("is a shell builtin\n") && !sh_holds_file(&mut make(), name);
                if has_which {
                    assert_eq!(which_status == 0, !builtin_only, "which {context}");
                    if which_status == 0 {
                        assert!(
                            which.ends_with(&format!("/{name}\n")),
                            "{context}: {which:?}"
                        );
                    }
                }
                // A file answers with the same path from all three.
                if sentence.starts_with(&format!("{name} is /")) {
                    let path = sentence.trim_start_matches(&format!("{name} is "));
                    assert_eq!(cv, path, "{context}");
                    assert_eq!(ty_out, sentence, "{context}");
                    if has_which {
                        assert_eq!(which, path, "{context}");
                    }
                }
            } else {
                gone += 1;
                assert!(cv.is_empty(), "{context}");
                assert!(
                    !ty_err.is_empty() || ty_out.ends_with("not found\n"),
                    "{context}"
                );
                assert_ne!(which_status, 0, "which {context}");
            }
        }
    }
    // Both branches were exercised: names that run and names a shell lacks (`enable` in dash,
    // `dd` on the phone).
    assert!(ran > 150 && gone > 5, "ran {ran}, gone {gone}");
}

/// The other direction of the invariant: a name dispatch does not run is not advertised, even
/// when the filesystem holds an executable of that name in a `$PATH` directory (the recorded
/// Ubuntu binaries no handler answers yet, or a file the session dropped there itself).
#[test]
fn a_file_dispatch_does_not_run_is_not_advertised() {
    let mut sh = shell();
    assert!(
        sh_holds_file(&mut sh, "sed"),
        "the premise: the file is there"
    );
    assert!(!dispatch_runs(&mut shell(), "sed"));
    run(&mut sh, "PATH=/tmp:$PATH");
    run(&mut sh, ">/tmp/dropped");
    run(&mut sh, "chmod +x /tmp/dropped");
    assert!(
        sh_holds_file(&mut sh, "dropped"),
        "the premise: on `$PATH` and executable"
    );
    assert!(!dispatch_runs(&mut sh, "dropped"));
    for name in ["sed", "lsattr", "dropped"] {
        assert_eq!(
            answer(&mut sh, &format!("which {name}")),
            ("".into(), "".into(), 1),
            "which {name}"
        );
        assert_eq!(
            answer(&mut sh, &format!("command -v {name}")).2,
            1,
            "{name}"
        );
        assert_eq!(answer(&mut sh, &format!("type {name}")).2, 1, "{name}");
    }
}

/// Whether the filesystem holds an executable of this name in one of the `$PATH` directories.
fn sh_holds_file(sh: &mut FakeShell, name: &str) -> bool {
    !sh.path_matches(name, false).is_empty()
}

/// The names dispatch runs that no `$PATH` directory holds a file for are reported at the standard
/// directory. They are pinned so a filesystem change that adds or drops one is a decision: on the
/// 2026-09-29 Ubuntu 22.04 recording `tftp`, `ftpget`, `hexdump` and `ash` are absent, and `more` is
/// a util-linux file the modeled filesystem does not hold yet, as is `arch` (a coreutils file no
/// capture has the image of).
#[test]
fn the_names_reported_without_a_file_are_the_pinned_ones() {
    let mut sh = shell();
    let mut without_file = Vec::new();
    for name in Registry::builtin().names() {
        let (_, _, status) = answer(&mut sh, &format!("command -v '{name}'"));
        let described = answer(&mut sh, &format!("command -V '{name}'")).0;
        if status == 0
            && !described.ends_with("is a shell builtin\n")
            && !sh_holds_file(&mut sh, name)
        {
            without_file.push(name);
        }
    }
    assert_eq!(
        without_file,
        ["arch", "ash", "ftpget", "hexdump", "more", "tftp"]
    );
}
