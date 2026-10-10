//! `trap` end to end: what it stores and lists in each shell, the `EXIT` handler and where it runs,
//! `DEBUG` and `ERR`, a signal a shell sends itself, and the bounds on handlers an attacker sets.
//! Every reply asserted here was produced by Ubuntu 22.04's bash 5.1.16 or dash 0.5.11 in the
//! `propolis-survey-ref:jammy` container (see `ubuntu-bash-traps.session`,
//! `ubuntu-dash-traps.session`); a test that says `[inferred]` has no reference shell (mksh).

use crate::fakefs::FakeFs;
use crate::shell::{EmitContext, FakeShell};

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

fn exec() -> FakeShell {
    FakeShell::exec(FakeFs::new(), ctx())
}

fn android() -> FakeShell {
    FakeShell::android(FakeFs::android(), ctx())
}

fn run(sh: &mut FakeShell, line: &str) -> String {
    sh.handle_input(line).0.to_string()
}

fn status(sh: &mut FakeShell, line: &str) -> u8 {
    sh.handle_input(line).0.status
}

#[test]
fn a_handler_is_set_listed_ignored_and_reset_in_signal_order() {
    let mut sh = shell();
    assert_eq!(run(&mut sh, "trap"), "");
    run(
        &mut sh,
        "trap 'echo bye' EXIT; trap 'echo int' INT; trap 'echo hup' 1; trap '' TERM",
    );
    assert_eq!(
        run(&mut sh, "trap"),
        "trap -- 'echo bye' EXIT\ntrap -- 'echo hup' SIGHUP\ntrap -- 'echo int' SIGINT\n\
         trap -- '' SIGTERM\n"
    );
    assert_eq!(
        run(&mut sh, "trap -p HUP INT"),
        "trap -- 'echo hup' SIGHUP\ntrap -- 'echo int' SIGINT\n"
    );
    run(&mut sh, "trap - INT; trap TERM");
    assert_eq!(
        run(&mut sh, "trap"),
        "trap -- 'echo bye' EXIT\ntrap -- 'echo hup' SIGHUP\n"
    );
    // `trap ARG SIG...` with a first operand that is a number resets the signals.
    run(&mut sh, "trap 0 1");
    assert_eq!(run(&mut sh, "trap"), "");
    // A quote inside a handler is closed around, as bash lists it.
    run(&mut sh, "trap \"echo it's\" EXIT");
    assert_eq!(run(&mut sh, "trap"), "trap -- 'echo it'\\''s' EXIT\n");
}

#[test]
fn a_signal_is_read_by_number_by_name_and_by_name_with_sig_in_any_case() {
    let mut sh = shell();
    run(
        &mut sh,
        "trap x SIGINT sigterm usr1 32 33 RTMIN+1 RTMAX-1 64",
    );
    assert_eq!(
        run(&mut sh, "trap"),
        "trap -- 'x' SIGINT\ntrap -- 'x' SIGUSR1\ntrap -- 'x' SIGTERM\ntrap -- 'x' 32\n\
         trap -- 'x' 33\ntrap -- 'x' SIGRTMIN+1\ntrap -- 'x' SIGRTMAX-1\ntrap -- 'x' SIGRTMAX\n"
    );
    for bad in ["NOSUCH", "65", "-1", "99", "sigfoo"] {
        assert_eq!(
            run(&mut sh, &format!("trap x {bad}")),
            format!("-bash: trap: {bad}: invalid signal specification\n"),
            "{bad}"
        );
        assert_eq!(status(&mut sh, &format!("trap x {bad}")), 1);
    }
    // The signals that cannot be caught are stored all the same.
    assert_eq!(status(&mut sh, "trap x KILL STOP 9"), 0);
}

#[test]
fn bash_has_the_pseudo_signals_and_dash_does_not() {
    let mut sh = shell();
    run(
        &mut sh,
        "trap a ERR; trap b RETURN; trap : DEBUG; trap d EXIT",
    );
    assert_eq!(
        run(&mut sh, "trap -p"),
        "trap -- 'd' EXIT\ntrap -- ':' DEBUG\ntrap -- 'a' ERR\ntrap -- 'b' RETURN\n"
    );
    let mut dash = shell();
    run(&mut dash, "sh");
    for pseudo in ["DEBUG", "ERR", "RETURN", "SIGINT", "STKFLT", "POLL"] {
        assert_eq!(
            run(&mut dash, &format!("trap x {pseudo}")),
            format!("trap: {pseudo}: bad trap\n"),
            "{pseudo}"
        );
    }
}

#[test]
fn the_options_are_bashs_and_dash_refuses_them_by_ending_the_shell() {
    let mut sh = shell();
    assert_eq!(
        run(&mut sh, "trap -x"),
        "-bash: trap: -x: invalid option\ntrap: usage: trap [-lp] [[arg] signal_spec ...]\n"
    );
    assert_eq!(status(&mut sh, "trap -x"), 2);
    assert_eq!(
        run(&mut sh, "trap -"),
        "trap: usage: trap [-lp] [[arg] signal_spec ...]\n"
    );
    assert_eq!(
        run(&mut sh, "trap - -"),
        "-bash: trap: -: invalid signal specification\n"
    );
    let names = run(&mut sh, "trap -l");
    assert!(
        names.starts_with(" 1) SIGHUP\t 2) SIGINT\t 3) SIGQUIT"),
        "{names}"
    );
    assert!(
        names.ends_with("63) SIGRTMAX-1\t64) SIGRTMAX\t\n"),
        "{names}"
    );
    assert_eq!(run(&mut sh, "trap -lp"), names);
    assert_eq!(run(&mut sh, "echo a; trap -p; echo b"), "a\nb\n");
    assert_eq!(
        run(&mut sh, "sh -c 'trap -p; echo after'"),
        "sh: 1: trap: Illegal option -p\n"
    );
    assert_eq!(
        run(&mut sh, "sh -c 'trap -l'; echo $?"),
        "sh: 1: trap: Illegal option -l\n2\n"
    );
}

#[test]
fn dash_stops_at_the_first_signal_it_cannot_read_and_names_them_bare() {
    let mut sh = shell();
    assert_eq!(
        run(&mut sh, "sh -c 'trap x EXIT INT bogus TERM; trap'"),
        "trap: bogus: bad trap\ntrap -- 'x' EXIT\ntrap -- 'x' INT\nsh: 1: x: not found\n"
    );
    assert_eq!(
        run(&mut sh, "sh -c 'trap x 16 32 RTMAX 17 int; trap'"),
        "trap -- 'x' INT\ntrap -- 'x' 16\ntrap -- 'x' CHLD\ntrap -- 'x' 32\ntrap -- 'x' RTMAX\n"
    );
    // A quote in a handler is reopened inside double quotes (verified: `trap -- 'echo
    // it'"'"'s' EXIT`).
    run(&mut sh, "sh");
    run(&mut sh, "trap \"echo it's\" INT");
    assert_eq!(run(&mut sh, "trap"), "trap -- 'echo it'\"'\"'s' INT\n");
    // [inferred] mksh lists like dash.
    let mut phone = android();
    run(&mut phone, "trap x INT");
    assert_eq!(run(&mut phone, "trap"), "trap -- 'x' INT\n");
}

#[test]
fn the_exit_handler_runs_after_logout_and_keeps_the_status() {
    let mut sh = shell();
    run(&mut sh, "trap 'echo bye $?' EXIT");
    let (reply, _) = sh.handle_input("false; exit");
    assert_eq!(reply.to_string(), "logout\nbye 1\n");
    assert!(reply.close_session);
    assert_eq!(reply.status, 1);
    // An `exit` inside the handler ends it with that status, and prints nothing more.
    let mut sh = shell();
    run(&mut sh, "trap 'echo A; exit 7' EXIT");
    let (reply, _) = sh.handle_input("exit 3");
    assert_eq!(reply.to_string(), "logout\nA\n");
    assert_eq!(reply.status, 7);
    // It runs once.
    let mut sh = shell();
    run(&mut sh, "trap 'echo once' EXIT");
    assert_eq!(run(&mut sh, "exit"), "logout\nonce\n");
}

#[test]
fn a_nested_interactive_shell_runs_its_own_handler_after_its_exit() {
    let mut sh = shell();
    run(&mut sh, "trap 'echo outer' EXIT");
    run(&mut sh, "bash");
    run(&mut sh, "trap 'echo inner' EXIT");
    assert_eq!(run(&mut sh, "exit"), "exit\ninner\n");
    assert_eq!(run(&mut sh, "exit"), "logout\nouter\n");
}

#[test]
fn a_script_an_exec_request_a_subshell_and_a_substitution_run_their_handler_at_their_end() {
    let mut sh = shell();
    assert_eq!(
        run(&mut sh, "bash -c 'trap \"echo bye\" EXIT; echo body'"),
        "body\nbye\n"
    );
    assert_eq!(
        run(
            &mut sh,
            "bash -c 'trap \"echo bye; exit 5\" EXIT; exit 3'; echo $?"
        ),
        "bye\n5\n"
    );
    assert_eq!(
        run(
            &mut sh,
            "bash -c 'trap \"echo A\" EXIT; trap \"echo B\" EXIT'"
        ),
        "B\n"
    );
    assert_eq!(
        run(&mut sh, "bash -c 'trap \"echo bye\" EXIT; (trap)'"),
        "trap -- 'echo bye' EXIT\nbye\n"
    );
    assert_eq!(
        run(
            &mut sh,
            "(trap 'echo S1' EXIT; (trap 'echo S2' EXIT; echo in); echo mid)"
        ),
        "in\nS2\nmid\nS1\n"
    );
    assert_eq!(
        run(&mut sh, "echo $(trap 'echo S' EXIT; echo body)"),
        "body S\n"
    );
    assert_eq!(
        run(&mut sh, "echo body | (trap 'echo S' EXIT; cat)"),
        "body\nS\n"
    );
    assert_eq!(
        run(&mut sh, "trap 'echo parent' EXIT; (echo child)"),
        "child\n"
    );
    let mut ssh = exec();
    assert_eq!(
        run(&mut ssh, "trap 'echo bye' EXIT\necho body"),
        "body\nbye\n"
    );
    let mut ssh = exec();
    let (reply, _) = ssh.handle_input("trap 'echo bye' EXIT; exit 4");
    assert_eq!(reply.to_string(), "bye\n");
    assert_eq!(reply.status, 4);
}

#[test]
fn a_subshell_lists_its_parents_handlers_until_it_sets_one_and_runs_none() {
    let mut sh = shell();
    run(&mut sh, "trap 'echo p' INT; trap 'echo parent' EXIT");
    assert_eq!(
        run(&mut sh, "(trap)"),
        "trap -- 'echo parent' EXIT\ntrap -- 'echo p' SIGINT\n"
    );
    assert_eq!(
        run(&mut sh, "echo $(trap)"),
        "trap -- 'echo parent' EXIT trap -- 'echo p' SIGINT\n"
    );
    assert_eq!(run(&mut sh, "(trap - INT; trap)"), "");
    assert_eq!(
        run(&mut sh, "(trap 'echo q' HUP; trap)"),
        "trap -- 'echo q' SIGHUP\n"
    );
    // Ignored signals stay ignored in a subshell and in a bash started from this one; dash lists none.
    run(&mut sh, "trap - INT EXIT; trap '' USR1");
    assert_eq!(run(&mut sh, "(trap)"), "trap -- '' SIGUSR1\n");
    assert_eq!(run(&mut sh, "bash -c trap"), "trap -- '' SIGUSR1\n");
    assert_eq!(run(&mut sh, "sh -c trap"), "");
    assert_eq!(
        run(&mut sh, "sh -c 'trap \"echo bye\" EXIT; (trap)'"),
        "bye\n"
    );
}

#[test]
fn a_signal_a_shell_sends_itself_runs_its_handler() {
    let mut sh = shell();
    assert_eq!(
        run(
            &mut sh,
            "bash -c 'trap \"echo got\" USR1; kill -USR1 $$; echo after'"
        ),
        "got\nafter\n"
    );
    assert_eq!(
        run(
            &mut sh,
            "sh -c 'trap \"echo got\" TERM; kill $$; echo after'"
        ),
        "got\nafter\n"
    );
    assert_eq!(
        run(&mut sh, "sh -c 'trap \"\" TERM; kill $$; echo after'"),
        "after\n"
    );
    assert_eq!(
        run(&mut sh, "bash -c 'trap \"echo got\" USR1; kill -0 $$'"),
        ""
    );
}

#[test]
fn err_follows_a_failure_nothing_tests_and_debug_goes_before_each_simple_command() {
    let mut sh = shell();
    run(&mut sh, "trap 'echo ERR $?' ERR");
    for (line, want) in [
        ("false", "ERR 1\n"),
        ("true | false", "ERR 1\n"),
        ("false | true", ""),
        ("{ false; }", "ERR 1\n"),
        ("( false )", "ERR 1\n"),
        ("f() { false; }; f", "ERR 1\n"),
        ("! false", ""),
        ("false && true", ""),
        ("true && false", "ERR 1\n"),
        ("false || false", "ERR 1\n"),
        ("if true; then false; fi", "ERR 1\n"),
        ("if false; then :; fi", ""),
        ("while false; do :; done", ""),
        ("echo a; false; echo b", "a\nERR 1\nb\n"),
        ("for i in 1; do false; done", "ERR 1\n"),
        ("x=$(false)", "ERR 1\n"),
        ("(exit 3)", "ERR 3\n"),
    ] {
        assert_eq!(run(&mut sh, line), want, "{line}");
    }
    run(&mut sh, "trap - ERR; trap 'echo D' DEBUG");
    for (line, want) in [
        ("true", "D\n"),
        ("true | true", "D\nD\n"),
        ("echo $(echo cs)", "D\ncs\n"),
        ("(echo sub)", "sub\n"),
        ("for i in 1 2; do :; done", "D\nD\nD\nD\n"),
        ("case x in x) :;; esac", "D\nD\n"),
        ("f() { :; }", ""),
        ("f", "D\n"),
    ] {
        assert_eq!(run(&mut sh, line), want, "{line}");
    }
    // The handler does not change $?.
    run(&mut sh, "trap - DEBUG");
    run(&mut sh, "trap 'echo D' DEBUG");
    assert_eq!(run(&mut sh, "false; echo $?"), "D\nD\n1\n");
}

#[test]
fn the_pseudo_signals_are_not_run_by_dash_or_by_a_function_body() {
    let mut sh = shell();
    run(&mut sh, "trap 'echo ERR' ERR");
    assert_eq!(run(&mut sh, "f() { false; true; }; f"), "");
    let mut dash = shell();
    run(&mut dash, "sh");
    assert_eq!(run(&mut dash, "false"), "");
}

#[test]
fn a_handler_is_bounded() {
    let mut sh = shell();
    let long = "x".repeat(5000);
    assert_eq!(run(&mut sh, &format!("trap '{long}' INT")), "");
    assert_eq!(status(&mut sh, &format!("trap '{long}' INT")), 1);
    assert_eq!(run(&mut sh, "trap"), "");
    let ok = "y".repeat(4096);
    run(&mut sh, &format!("trap '{ok}' INT"));
    assert_eq!(
        run(&mut sh, "trap -p INT").len(),
        "trap -- '' SIGINT\n".len() + 4096
    );
    // One handler per signal, so the table cannot grow past the signals there are.
    for n in 0..=200 {
        run(&mut sh, &format!("trap 'echo {n}' {n}"));
    }
    assert!(run(&mut sh, "trap").lines().count() <= 68);
    // A handler that runs itself again through a signal stops at the depth cap.
    let mut sh = shell();
    run(&mut sh, "trap 'kill -USR1 $$' USR1");
    let (reply, _) = sh.handle_input("kill -USR1 $$; echo done");
    assert!(reply.to_string().ends_with("done\n"));
}

#[test]
fn trap_is_a_builtin_to_type_and_command() {
    let mut sh = shell();
    assert_eq!(run(&mut sh, "type trap"), "trap is a shell builtin\n");
    assert_eq!(run(&mut sh, "command -v trap"), "trap\n");
    let mut dash = shell();
    run(&mut dash, "sh");
    assert_eq!(
        run(&mut dash, "type trap"),
        "trap is a special shell builtin\n"
    );
}

#[test]
fn a_subshell_keeps_the_handlers_its_parent_ignores() {
    // bash and dash: `trap '' HUP` is inherited by a subshell, which lists it with its own.
    let mut sh = shell();
    run(&mut sh, "trap '' HUP");
    assert_eq!(
        run(&mut sh, "(trap 'echo a' INT; trap)"),
        "trap -- '' SIGHUP\ntrap -- 'echo a' SIGINT\n"
    );
    run(&mut sh, "sh");
    run(&mut sh, "trap '' HUP");
    assert_eq!(
        run(&mut sh, "(trap 'echo a' INT; trap)"),
        "trap -- '' HUP\ntrap -- 'echo a' INT\n"
    );
}
