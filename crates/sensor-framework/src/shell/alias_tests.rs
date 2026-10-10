//! `alias`, `unalias` and `shopt` end to end: the table, the listing in each shell's order, the
//! expansion the lexer does at command position, where it does none, and the bounds on a table an
//! attacker fills. Every reply asserted here was produced by Ubuntu 22.04's bash 5.1.16 or dash
//! 0.5.11 in the `propolis-survey-ref:jammy` container (see `ubuntu-bash-aliases.session`,
//! `ubuntu-dash-aliases.session`); a test that says `[inferred]` has no reference shell (mksh).

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

/// A nested dash reading the lines typed to it.
fn dash_level() -> FakeShell {
    let mut sh = shell();
    run(&mut sh, "sh");
    sh
}

#[test]
fn an_alias_takes_effect_from_the_next_line_not_the_one_that_defines_it() {
    let mut sh = shell();
    assert_eq!(
        run(&mut sh, "alias y='echo yo'; y"),
        "y: command not found\n"
    );
    assert_eq!(run(&mut sh, "y"), "yo\n");
    let mut dash = dash_level();
    assert_eq!(
        run(&mut dash, "alias y='echo yo'; y"),
        "sh: 1: y: not found\n"
    );
    assert_eq!(run(&mut dash, "y"), "yo\n");
}

#[test]
fn only_a_word_at_command_position_is_expanded() {
    let mut sh = shell();
    run(&mut sh, "alias nn=echo");
    for (line, want) in [
        ("true && nn a", "a\n"),
        ("false || nn b", "b\n"),
        ("echo x | nn c", "c\n"),
        ("(nn d)", "d\n"),
        ("{ nn e; }", "e\n"),
        ("if nn f; then nn g; fi", "f\ng\n"),
        ("for i in 1; do nn h; done", "h\n"),
        ("X=1 nn i", "i\n"),
        ("2>&1 nn j", "j\n"),
        ("echo $(nn k)", "k\n"),
        ("echo `nn l`", "l\n"),
        ("case nn in nn) nn m;; esac", "m\n"),
        ("echo nn", "nn\n"),
    ] {
        assert_eq!(run(&mut sh, line), want, "{line}");
    }
    // A quote, a backslash or an expansion in the word makes it no alias.
    for line in ["'nn' q", "\\nn q", "n\\n q", "\"nn\" q"] {
        assert_eq!(run(&mut sh, line), "nn: command not found\n", "{line}");
    }
}

#[test]
fn a_value_ending_in_a_blank_lets_the_next_word_be_an_alias() {
    let mut sh = shell();
    run(&mut sh, "alias e=echo w=world");
    assert_eq!(run(&mut sh, "e w"), "w\n");
    run(&mut sh, "alias e='echo '");
    assert_eq!(run(&mut sh, "e w w"), "world w\n");
    // Chains of aliases: each value's first word is read for an alias, and the trailing blank of
    // an earlier one reaches into the later ones (bash 5.1.16: `L1 echo L1 -d l1`).
    run(&mut sh, "alias l1=ls l2='l1 -d'");
    run(&mut sh, "alias l1='echo L1 '");
    run(&mut sh, "alias l3='l1 l2'");
    assert_eq!(run(&mut sh, "l3 l1"), "L1 echo L1 -d l1\n");
}

#[test]
fn a_name_is_not_expanded_again_inside_its_own_value() {
    let mut sh = shell();
    run(&mut sh, "alias ls='ls -d'");
    assert_eq!(run(&mut sh, "ls /"), "/\n");
    run(&mut sh, "alias r=r p=q q=p");
    assert_eq!(run(&mut sh, "r"), "r: command not found\n");
    assert_eq!(run(&mut sh, "p"), "p: command not found\n");
    run(&mut sh, "alias f1=f2 f2='f3 x' f3='echo f3'");
    assert_eq!(run(&mut sh, "f1"), "f3 x\n");
}

#[test]
fn a_value_is_text_so_it_may_hold_operators_quotes_and_a_here_document() {
    let mut sh = shell();
    run(&mut sh, "alias k='echo K; echo L' m='echo M |' s='echo S;'");
    assert_eq!(run(&mut sh, "k"), "K\nL\n");
    assert_eq!(run(&mut sh, "m cat"), "M\n");
    assert_eq!(run(&mut sh, "s echo T"), "S\nT\n");
    run(&mut sh, "alias q4=\"echo '\"");
    assert_eq!(run(&mut sh, "q4 four'"), " four\n");
    run(&mut sh, "alias t6='(echo six'");
    assert_eq!(run(&mut sh, "t6 )"), "six\n");
    run(&mut sh, "alias t8='cat <<EOF'");
    run(&mut sh, "t8");
    run(&mut sh, "body line");
    assert_eq!(run(&mut sh, "EOF"), "body line\n");
    run(&mut sh, "alias c1=case");
    assert_eq!(run(&mut sh, "c1 a in a) echo caseA;; esac"), "caseA\n");
}

#[test]
fn a_function_keeps_the_text_its_aliases_had_when_it_was_defined() {
    let mut sh = shell();
    run(&mut sh, "alias hi='echo hello'");
    run(&mut sh, "f() { hi; }");
    run(&mut sh, "alias hi='echo hello2'");
    assert_eq!(run(&mut sh, "f"), "hello\n");
    let listed = run(&mut sh, "type f");
    assert!(listed.contains("echo hello\n"), "{listed}");
}

#[test]
fn a_word_that_is_a_reserved_word_is_an_alias_in_bash_and_not_in_dash() {
    let mut sh = shell();
    run(&mut sh, "alias if='echo IF'");
    assert_eq!(
        run(&mut sh, "if true; then echo y; fi"),
        "-bash: syntax error near unexpected token `then'\n"
    );
    let mut dash = dash_level();
    run(&mut dash, "alias if='echo IF'");
    assert_eq!(run(&mut dash, "if true; then echo y; fi"), "y\n");
}

#[test]
fn the_listing_is_sorted_in_bash_and_in_hash_order_in_dash() {
    let mut sh = shell();
    run(&mut sh, "alias B=1 a=2 Z=3 _u=4 9n=5 ab=6 ba=7 zz=8 aa=9");
    assert_eq!(
        run(&mut sh, "alias"),
        "alias 9n='5'\nalias B='1'\nalias Z='3'\nalias _u='4'\nalias a='2'\nalias aa='9'\n\
         alias ab='6'\nalias ba='7'\nalias zz='8'\n"
    );
    let mut dash = dash_level();
    run(&mut dash, "alias B=1 a=2 Z=3 _u=4 9n=5 ab=6 ba=7 zz=8 aa=9");
    // Verified in the reference container: dash's bucket order.
    assert_eq!(
        run(&mut dash, "alias"),
        "ba='7'\nZ='3'\na='2'\nzz='8'\n_u='4'\n9n='5'\nB='1'\naa='9'\nab='6'\n"
    );
}

#[test]
fn bash_quotes_a_quote_one_way_and_dash_another_and_a_dash_name_gets_two_hyphens() {
    let mut sh = shell();
    run(&mut sh, "alias q='it'\"'\"'s'");
    assert_eq!(run(&mut sh, "alias q"), "alias q='it'\\''s'\n");
    run(&mut sh, "alias -- -x=y");
    assert_eq!(
        run(&mut sh, "alias -x"),
        "-bash: alias: -x: invalid option\nalias: usage: alias [-p] [name[=value] ... ]\n"
    );
    assert_eq!(run(&mut sh, "alias -- -x"), "alias -- -x='y'\n");
    let mut dash = dash_level();
    run(&mut dash, "alias q='it'\"'\"'s'");
    assert_eq!(run(&mut dash, "alias q"), "q='it'\"'\"'s'\n");
}

#[test]
fn bash_refuses_names_it_cannot_expand_and_dash_takes_any() {
    let mut sh = shell();
    for name in [
        "a/b", "a$b", "a\"b", "a'b", "a;b", "a&b", "a|b", "a(b", "a<b", "a`b", "x y",
    ] {
        let line = format!(
            "alias \"{}=1\"",
            name.replace('"', "\\\"")
                .replace('$', "\\$")
                .replace('`', "\\`")
        );
        let shown = run(&mut sh, &line);
        assert_eq!(
            shown,
            format!("-bash: alias: `{name}': invalid alias name\n"),
            "{name}"
        );
    }
    for name in [
        "a!b", "a*b", "a-b", "a.b", "a#b", "a~b", "a?b", "a%b", "a:b", "a,b", "a+b", "a@b", "a^b",
    ] {
        assert_eq!(run(&mut sh, &format!("alias 'x{name}=1'")), "", "{name}");
    }
    let mut dash = dash_level();
    assert_eq!(run(&mut dash, "alias 'x y=1' a/b=2"), "");
    assert_eq!(run(&mut dash, "alias 'x y'"), "x y='1'\n");
}

#[test]
fn alias_p_lists_first_and_an_empty_table_ends_it_there() {
    let mut sh = shell();
    // Empty: bash returns before it reads the operands, so nothing is defined.
    assert_eq!(run(&mut sh, "alias -p v1=x"), "");
    assert_eq!(run(&mut sh, "alias v1"), "-bash: alias: v1: not found\n");
    run(&mut sh, "alias v1=y");
    assert_eq!(
        run(&mut sh, "alias -p v2"),
        "alias v1='y'\n-bash: alias: v2: not found\n"
    );
    assert_eq!(run(&mut sh, "echo $?"), "1\n");
    // dash has no -p: it is a name to look up.
    let mut dash = dash_level();
    assert_eq!(run(&mut dash, "alias -p"), "alias: -p not found\n");
    assert_eq!(run(&mut dash, "alias -- -x=y"), "alias: -- not found\n");
    assert_eq!(run(&mut dash, "alias =x=y"), "");
    assert_eq!(run(&mut dash, "alias '=x'"), "=x='y'\n");
}

#[test]
fn unalias_removes_one_all_or_complains() {
    let mut sh = shell();
    run(&mut sh, "alias a=1 b=2");
    assert_eq!(
        run(&mut sh, "unalias a nosuch b"),
        "-bash: unalias: nosuch: not found\n"
    );
    assert_eq!(run(&mut sh, "echo $?"), "1\n");
    assert_eq!(run(&mut sh, "alias"), "");
    assert_eq!(
        run(&mut sh, "unalias"),
        "unalias: usage: unalias [-a] name [name ...]\n"
    );
    assert_eq!(run(&mut sh, "echo $?"), "2\n");
    assert_eq!(
        run(&mut sh, "unalias -x"),
        "-bash: unalias: -x: invalid option\nunalias: usage: unalias [-a] name [name ...]\n"
    );
    run(&mut sh, "alias a=1");
    assert_eq!(run(&mut sh, "unalias -a nosuch"), "");
    assert_eq!(run(&mut sh, "alias"), "");
    let mut dash = dash_level();
    assert_eq!(run(&mut dash, "unalias"), "");
    assert_eq!(run(&mut dash, "echo $?"), "0\n");
    assert_eq!(run(&mut dash, "unalias nope"), "unalias: nope not found\n");
    assert_eq!(
        run(&mut dash, "unalias -x"),
        "sh: 4: unalias: Illegal option -x\n"
    );
}

#[test]
fn type_and_command_name_an_alias_before_anything_else() {
    let mut sh = shell();
    run(&mut sh, "alias x='echo hi' ls='ls -d'");
    assert_eq!(run(&mut sh, "type x"), "x is aliased to `echo hi'\n");
    assert_eq!(run(&mut sh, "command -v x"), "alias x='echo hi'\n");
    assert_eq!(run(&mut sh, "command -V x"), "x is aliased to `echo hi'\n");
    assert_eq!(run(&mut sh, "type -t x"), "alias\n");
    let all = run(&mut sh, "type -a ls");
    assert!(
        all.starts_with("ls is aliased to `ls -d'\nls is /"),
        "{all}"
    );
    let mut dash = dash_level();
    run(&mut dash, "alias x='echo hi'");
    assert_eq!(run(&mut dash, "type x"), "x is an alias for echo hi\n");
    assert_eq!(run(&mut dash, "command -v x"), "alias x='echo hi'\n");
}

#[test]
fn a_bash_that_runs_a_script_expands_none_until_expand_aliases_and_dash_always_does() {
    let mut sh = shell();
    assert_eq!(
        run(&mut sh, "bash -c 'alias gg=echo\ngg hi'"),
        "bash: line 2: gg: command not found\n"
    );
    assert_eq!(
        run(
            &mut sh,
            "bash -c 'shopt -s expand_aliases; alias gg=echo\ngg hi'"
        ),
        "hi\n"
    );
    assert_eq!(
        run(&mut sh, "sh -c 'alias gg=echo; gg hi'"),
        "sh: 1: gg: not found\n"
    );
    assert_eq!(run(&mut sh, "sh -c 'alias gg=echo\ngg hi'"), "hi\n");
    // An SSH exec is the same bash.
    let mut ssh = exec();
    assert_eq!(
        run(&mut ssh, "alias gg=echo\ngg hi"),
        "bash: line 2: gg: command not found\n"
    );
    let mut ssh = exec();
    assert_eq!(
        run(&mut ssh, "shopt -s expand_aliases\nalias gg=echo\ngg hi"),
        "hi\n"
    );
}

#[test]
fn a_shell_started_from_this_one_has_none_and_a_subshell_copies_the_table() {
    let mut sh = shell();
    run(&mut sh, "alias nn=echo");
    assert_eq!(run(&mut sh, "sh -c 'nn z'"), "sh: 1: nn: not found\n");
    assert_eq!(
        run(&mut sh, "bash -c 'nn z'"),
        "bash: line 1: nn: command not found\n"
    );
    assert_eq!(
        run(&mut sh, "(nn sub; alias other=1; alias)"),
        "sub\nalias nn='echo'\nalias other='1'\n"
    );
    assert_eq!(run(&mut sh, "alias"), "alias nn='echo'\n");
}

#[test]
fn the_table_and_the_expansion_are_bounded() {
    let mut sh = shell();
    for n in 0..140 {
        run(&mut sh, &format!("alias a{n}=x"));
    }
    let count = run(&mut sh, "alias").lines().count();
    assert_eq!(count, 128);
    let long = "x".repeat(5000);
    run(&mut sh, &format!("alias big={long}"));
    assert_eq!(run(&mut sh, "alias big"), "-bash: alias: big: not found\n");
    // A value that doubles itself through a chain stops at the cap on expansions.
    let mut sh = shell();
    for n in 0..30 {
        run(
            &mut sh,
            &format!("alias c{n}='c{} c{} c{}'", n + 1, n + 1, n + 1),
        );
    }
    run(&mut sh, "alias c30=echo");
    let (reply, _) = sh.handle_input("c0");
    assert!(reply.bytes().len() < 262_144);
}

#[test]
fn the_phone_lists_like_dash_but_sorted() {
    // [inferred] mksh: no reference shell.
    let mut sh = android();
    run(&mut sh, "alias zz=1 aa='b c'");
    assert_eq!(run(&mut sh, "alias"), "aa='b c'\nzz='1'\n");
    assert_eq!(run(&mut sh, "alias zz"), "zz='1'\n");
}

#[test]
fn shopt_lists_sets_and_unsets_as_bash_does() {
    let mut sh = shell();
    assert_eq!(
        run(&mut sh, "shopt expand_aliases"),
        "expand_aliases \ton\n"
    );
    assert_eq!(
        run(&mut sh, "shopt -p expand_aliases"),
        "shopt -s expand_aliases\n"
    );
    assert_eq!(
        run(&mut sh, "shopt -u expand_aliases; shopt extglob"),
        "extglob        \toff\n"
    );
    assert_eq!(run(&mut sh, "shopt -q extglob; echo $?"), "1\n");
    assert_eq!(
        run(&mut sh, "shopt -s nosuch"),
        "-bash: shopt: nosuch: invalid shell option name\n"
    );
    assert_eq!(
        run(&mut sh, "shopt -x"),
        "-bash: shopt: -x: invalid option\nshopt: usage: shopt [-pqsu] [-o] [optname ...]\n"
    );
    assert_eq!(
        run(&mut sh, "shopt -s -u extglob"),
        "-bash: shopt: cannot set and unset shell options simultaneously\n"
    );
    let all = run(&mut sh, "shopt");
    assert_eq!(all.lines().count(), 53);
    assert!(all.starts_with("autocd         \toff\nassoc_expand_once\toff\n"));
    let set = run(&mut sh, "shopt -s");
    assert!(set.contains("login_shell    \ton\n") && !set.contains("\toff"));
    assert_eq!(run(&mut sh, "shopt -po noclobber"), "set +o noclobber\n");
    assert_eq!(run(&mut sh, "shopt -o").lines().count(), 27);
    // A script's bash starts with it off and is not a login shell.
    assert!(run(&mut sh, "bash -c 'shopt'").contains("expand_aliases \toff\n"));
    assert!(run(&mut sh, "bash -c 'shopt'").contains("login_shell    \toff\n"));
}

#[test]
fn shopt_is_not_found_in_dash_and_on_the_phone() {
    let mut dash = dash_level();
    assert_eq!(run(&mut dash, "shopt"), "sh: 1: shopt: not found\n");
    let mut sh = android();
    assert_eq!(run(&mut sh, "shopt"), "sh: shopt: not found\n");
}
