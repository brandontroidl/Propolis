//! `grep` (regular expressions), `cut`, `tee`, `awk` and `od -c` through `handle_input`.
//!
//! Every expected answer here was recorded on Ubuntu 22.04 (grep 3.7, coreutils 8.32, mawk 1.3.4
//! 20200120) in the 2026-10-07 reference session, over files with the same content as the ones
//! the cases write first.

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
    let mut sh = FakeShell::exec(FakeFs::new(), ctx());
    sh.fs
        .write_file(
            "/tmp/passwd",
            b"root:x:0:0:root:/root:/bin/bash\n\
              daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n\
              bin:x:2:2:bin:/bin:/usr/sbin/nologin\n\
              sys:x:3:3:sys:/dev:/usr/sbin/nologin\n",
        )
        .unwrap();
    sh
}

fn stream(out: &CommandResult, fd: OutputFd) -> String {
    let bytes: Vec<u8> = out
        .output
        .iter()
        .filter(|segment| segment.fd == fd)
        .flat_map(|segment| segment.bytes.iter().copied())
        .collect();
    String::from_utf8_lossy(&bytes).into_owned()
}

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
fn grep_reads_basic_and_extended_patterns() {
    let mut sh = shell();
    assert_eq!(out(&mut sh, "grep -c ^root /tmp/passwd"), "1\n");
    assert_eq!(
        out(&mut sh, "grep -n -H root /tmp/passwd"),
        "/tmp/passwd:1:root:x:0:0:root:/root:/bin/bash\n"
    );
    assert_eq!(
        out(&mut sh, "grep -w bin /tmp/passwd"),
        "root:x:0:0:root:/root:/bin/bash\nbin:x:2:2:bin:/bin:/usr/sbin/nologin\n"
    );
    assert_eq!(answer(&mut sh, "grep -x root /tmp/passwd").2, 1);
    assert_eq!(
        out(&mut sh, "grep -E '^(root|sys):' /tmp/passwd | cut -d: -f1"),
        "root\nsys\n"
    );
    assert_eq!(out(&mut sh, "grep -o 'r[a-z]*' /etc/hostname"), "rver\n");
    assert_eq!(out(&mut sh, "grep -v -c root /tmp/passwd"), "3\n");
    assert_eq!(out(&mut sh, "grep -P '\\d+' /etc/hostname"), "server01\n");
    assert_eq!(
        out(&mut sh, "grep -e root -e daemon /tmp/passwd | wc -l"),
        "2\n"
    );
    assert_eq!(
        out(&mut sh, "grep -B1 -n daemon /tmp/passwd"),
        "1-root:x:0:0:root:/root:/bin/bash\n2:daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
    );
    assert_eq!(
        out(&mut sh, "printf 'a\\nb\\na\\n' | grep -n a"),
        "1:a\n3:a\n"
    );
}

#[test]
fn grep_reports_what_gnu_grep_reports() {
    let mut sh = shell();
    for (pattern, message) in [
        ("'\\('", "Unmatched ( or \\("),
        ("'['", "Invalid regular expression"),
        ("'[abc'", "Unmatched [, [^, [:, [., or [="),
        ("'a\\{1'", "Unmatched \\{"),
        ("'[[:foo:]]'", "Invalid character class name"),
        ("'[z-a]'", "Invalid range end"),
        ("'\\)'", "Unmatched ) or \\)"),
        ("'\\1'", "Invalid back reference"),
    ] {
        assert_eq!(
            answer(&mut sh, &format!("grep {pattern} /etc/hostname")),
            ("".into(), format!("grep: {message}\n"), 2),
            "{pattern}"
        );
    }
    assert_eq!(answer(&mut sh, "grep -E 'a{1' /etc/hostname").2, 1);
    assert_eq!(
        answer(&mut sh, "grep nope /nonexist"),
        (
            "".into(),
            "grep: /nonexist: No such file or directory\n".into(),
            2
        )
    );
    assert_eq!(
        answer(&mut sh, "grep -s nope /nonexist"),
        ("".into(), "".into(), 2)
    );
    assert_eq!(answer(&mut sh, "grep -q root /tmp/passwd /nonexist").2, 0);
    assert_eq!(
        answer(&mut sh, "grep -X x"),
        ("".into(), "grep: invalid matcher x\n".into(), 2)
    );
    assert_eq!(
        answer(&mut sh, "grep --foo x").1,
        "grep: unrecognized option '--foo'\nUsage: grep [OPTION]... PATTERNS [FILE]...\nTry 'grep --help' for more information.\n"
    );
    assert_eq!(
        answer(&mut sh, "grep -L root /tmp/passwd /etc/hostname"),
        ("/etc/hostname\n".into(), "".into(), 0)
    );
}

#[test]
fn cut_selects_fields_bytes_and_reports_misuse() {
    let mut sh = shell();
    assert_eq!(
        out(&mut sh, "cut -d: -f1 /tmp/passwd | head -3"),
        "root\ndaemon\nbin\n"
    );
    assert_eq!(out(&mut sh, "cut -c1-4 /etc/hostname"), "serv\n");
    assert_eq!(out(&mut sh, "echo 'a:b:c' | cut -d: -f2-"), "b:c\n");
    assert_eq!(out(&mut sh, "echo abc | cut -b2"), "b\n");
    assert_eq!(out(&mut sh, "echo a | cut -d: -f3"), "a\n");
    assert_eq!(
        answer(&mut sh, "echo a:b | cut -s -d, -f1"),
        ("".into(), "".into(), 0)
    );
    let missing = (
        "".to_string(),
        "cut: you must specify a list of bytes, characters, or fields\nTry 'cut --help' for more information.\n"
            .to_string(),
        1,
    );
    assert_eq!(answer(&mut sh, "cut"), missing);
    assert_eq!(answer(&mut sh, "cut -d: /etc/hostname"), missing);
    assert_eq!(
        answer(&mut sh, "cut -d: -f0"),
        (
            "".into(),
            "cut: fields are numbered from 1\nTry 'cut --help' for more information.\n".into(),
            1
        )
    );
    assert_eq!(
        answer(&mut sh, "cut -d: -x"),
        (
            "".into(),
            "cut: invalid option -- 'x'\nTry 'cut --help' for more information.\n".into(),
            1
        )
    );
    // The survey's model-name line: the field keeps its leading space.
    assert!(
        out(
            &mut sh,
            "grep 'model name' /proc/cpuinfo | head -1 | cut -d: -f2"
        )
        .starts_with(' ')
    );
}

#[test]
fn tee_copies_to_its_files_and_standard_output() {
    let mut sh = shell();
    assert_eq!(
        out(&mut sh, "echo hi | tee /tmp/t1 /tmp/t2; cat /tmp/t1"),
        "hi\nhi\n"
    );
    assert_eq!(
        out(
            &mut sh,
            "tee -a /tmp/t1 < /etc/hostname > /dev/null; cat /tmp/t1"
        ),
        "hi\nserver01\n"
    );
    assert_eq!(
        answer(&mut sh, "tee /nonexist/x < /dev/null"),
        (
            "".into(),
            "tee: /nonexist/x: No such file or directory\n".into(),
            1
        )
    );
    assert_eq!(
        answer(&mut sh, "tee -x"),
        (
            "".into(),
            "tee: invalid option -- 'x'\nTry 'tee --help' for more information.\n".into(),
            1
        )
    );
}

#[test]
fn awk_computes_as_mawk_does() {
    let mut sh = shell();
    for (program, expected) in [
        ("echo a b c | awk '{print $2}'", "b\n"),
        (
            "awk -F: '{print $1, $3}' /tmp/passwd | head -2",
            "root 0\ndaemon 1\n",
        ),
        ("awk 'BEGIN{printf \"%.1f\\n\", 3/7*100}'", "42.9\n"),
        (
            "echo 1 | awk '{print $1+1, NR, NF, length($0)}'",
            "2 1 1 1\n",
        ),
        ("awk 'BEGIN{print 1/3}'", "0.333333\n"),
        ("awk 'BEGIN{print 100000000000000000000}'", "1e+20\n"),
        (
            "awk 'BEGIN{x=1e6; print x, x*1000}'",
            "1000000 1000000000\n",
        ),
        ("echo 'a b' | awk '{print NF; print $NF}'", "2\nb\n"),
        ("awk '/root/{print $1}' FS=: /tmp/passwd", "root\n"),
        (
            "echo 5 3 | awk '{ if ($1 > $2) print \"gt\"; else print \"le\" }'",
            "gt\n",
        ),
        (
            "awk 'BEGIN { for (i=0;i<3;i++) printf \"%d,\", i; print \"\" }'",
            "0,1,2,\n",
        ),
        ("echo foo | awk '{ gsub(/o/, \"0\"); print }'", "f00\n"),
        (
            "echo foo bar | awk '{ print toupper($1), substr($2,2), index($0,\"bar\") }'",
            "FOO ar 5\n",
        ),
        (
            "awk 'BEGIN{printf \"%5.2f|%-4s|%x|%c|%e\\n\", 3.14159, \"ab\", 255, 65, 12345.678}'",
            " 3.14|ab  |ff|A|1.234568e+04\n",
        ),
        (
            "echo 1 2 3 | awk '{s=0; for(i=1;i<=NF;i++) s+=$i; print s}'",
            "6\n",
        ),
        ("echo 3 | awk '{print $1^2, $1 % 2, -$1}'", "9 1 -3\n"),
        (
            "awk 'BEGIN{a[\"x\"]=1; for (k in a) print k, a[k]; print length(a)}'",
            "x 1\n1\n",
        ),
        ("echo 'x y' | awk -v OFS=- '{$1=$1; print}'", "x-y\n"),
        (
            "awk 'BEGIN { getline line < \"/etc/hostname\"; print line }'",
            "server01\n",
        ),
        (
            "awk 'BEGIN{print substr(\"hello\", 0, 2), int(3.9), sprintf(\"%03d\", 7)}'",
            "he 3 007\n",
        ),
        ("echo a,b | awk -F, '{print $2}'", "b\n"),
        ("awk 'END{print NR}' /tmp/passwd", "4\n"),
        (
            "awk 'NR==2' /tmp/passwd",
            "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n",
        ),
        ("awk 'BEGIN{x = 10; x += 5; x++; print x--, x}'", "16 15\n"),
        ("echo 'a b' | awk '{print $1 $2}'", "ab\n"),
        (
            "awk 'BEGIN{print 2==2, \"a\"<\"b\", 1&&0, !1}'",
            "1 1 0 0\n",
        ),
        (
            "awk 'BEGIN{print split(\"a:b:c\", arr, \":\"), arr[3]}'",
            "3 c\n",
        ),
        (
            "awk 'BEGIN{s=\"abc\"; sub(/b/, \"[&]\", s); print s; print match(\"foobar\", /ob/), RSTART, RLENGTH}'",
            "a[b]c\n3 3 2\n",
        ),
        (
            "awk 'BEGIN { printf \"%d %d\\n\", \"3abc\", 2.9 }'",
            "3 2\n",
        ),
        (
            "awk 'BEGIN { print 0.1+0.2, 1e300*10, -0 }'",
            "0.3 1e+301 0\n",
        ),
        ("echo 7 | awk '$1 ~ /^[0-9]+$/ {print \"num\"}'", "num\n"),
        (
            "printf 'a\\nb\\n' | awk 'NR>1{print prev\"-\"$0} {prev=$0}'",
            "a-b\n",
        ),
        ("awk 'BEGIN{print ENVIRON[\"HOME\"]}'", "/root\n"),
        ("echo a | awk '{print $0; next; print \"no\"}'", "a\n"),
        (
            "awk 'BEGIN { while (i < 3) { i++ }; print i; do { i-- } while (i > 0); print i }'",
            "3\n0\n",
        ),
        ("awk 'BEGIN{print (1,2) in a}'", "0\n"),
        ("awk 'function f(x){return x*2} BEGIN{print f(21)}'", "42\n"),
        (
            "awk 'BEGIN{while ((\"echo a; echo b\" | getline line) > 0) n++; print n, line}'",
            "2 b\n",
        ),
        (
            "awk 'BEGIN{system(\"echo from-system\"); print \"after\"}'",
            "from-system\nafter\n",
        ),
        ("echo x | awk '{print | \"cat\"; print \"y\"}'", "x\ny\n"),
        (
            "awk 'BEGIN{printf \"%*d|%-*d|\\n\", 5, 42, 4, 7}'",
            "   42|7   |\n",
        ),
        ("echo '  a   b  ' | awk '{print NF, $1}'", "2 a\n"),
        ("echo a:b::c | awk -F: '{print NF, $3}'", "4 \n"),
        ("echo a1b22c | awk -F'[0-9]+' '{print $3}'", "c\n"),
        (
            "echo '3 4' | awk '{print $1 < $2, $1 \"\" < $2, \"10\" < \"9\", $1+0 == 3}'",
            "1 1 1 1\n",
        ),
        ("echo '10 9' | awk '{print ($1 < $2)}'", "0\n"),
    ] {
        assert_eq!(
            answer(&mut sh, program),
            (expected.to_string(), "".into(), 0),
            "{program}"
        );
    }
}

#[test]
fn awk_reports_what_mawk_reports() {
    let mut sh = shell();
    assert_eq!(answer(&mut sh, "awk 'BEGIN{exit 3}'").2, 3);
    assert_eq!(
        answer(&mut sh, "awk '{'"),
        (
            "".into(),
            "awk: line 2: missing } near end of file\n".into(),
            2
        )
    );
    assert_eq!(
        answer(&mut sh, "awk '{print $1' /dev/null"),
        (
            "".into(),
            "awk: line 2: missing } near end of file\n".into(),
            2
        )
    );
    assert_eq!(
        answer(&mut sh, "awk 'BEGIN { printf \"%s\" }'"),
        (
            "".into(),
            "awk: run time error: not enough arguments passed to printf(\"%s\")\n\tFILENAME=\"\" FNR=0 NR=0\n".into(),
            2
        )
    );
    assert_eq!(
        answer(&mut sh, "awk -f /nonexist"),
        (
            "".into(),
            "awk: cannot open /nonexist (No such file or directory)\n".into(),
            2
        )
    );
    assert_eq!(
        answer(&mut sh, "awk '/[/' /dev/null"),
        (
            "".into(),
            "awk: line 1: runaway regular expression /[/ ...\n".into(),
            2
        )
    );
    assert_eq!(
        answer(&mut sh, "awk 'BEGIN{print match(\"a\", /(/)}'"),
        (
            "".into(),
            "awk: line 1: regular expression compile failed (missing ')')\n(\n".into(),
            2
        )
    );
    let (usage, _, status) = answer(&mut sh, "awk");
    assert!(
        usage.starts_with("Usage: mawk [Options] [Program] [file ...]\n"),
        "{usage}"
    );
    assert_eq!(status, 0);
    assert!(
        out(&mut sh, "awk -W version")
            .starts_with("mawk 1.3.4 20200120\nCopyright 2008-2019,2020, Thomas E. Dickey\n")
    );
}

#[test]
fn awk_cannot_run_away_with_the_line() {
    let mut sh = shell();
    let (_, _, status) = answer(&mut sh, "awk 'BEGIN { while (1) x++ }'");
    assert_ne!(status, 0, "the line's allowance stops the loop");
    // The shell is still usable afterwards.
    assert_eq!(out(&mut sh, "echo ok"), "ok\n");
}

#[test]
fn od_c_shows_characters_escapes_and_octal() {
    let mut sh = shell();
    assert_eq!(
        out(&mut sh, "od -c /etc/hostname"),
        "0000000   s   e   r   v   e   r   0   1  \\n\n0000011\n"
    );
    assert_eq!(
        out(&mut sh, "od -An -c /etc/hostname"),
        "   s   e   r   v   e   r   0   1  \\n\n"
    );
    assert_eq!(
        out(&mut sh, "od -c /bin/true | head -1"),
        "0000000 177   E   L   F 002 001 001  \\0  \\0  \\0  \\0  \\0  \\0  \\0  \\0  \\0\n"
    );
    assert_eq!(out(&mut sh, "od -c /dev/null"), "0000000\n");
}

/// The survey's two text-tool lines, end to end over the modeled host.
#[test]
fn the_survey_text_tool_lines_answer() {
    let mut sh = shell();
    let used = out(
        &mut sh,
        "free 2>/dev/null | grep -i '^Mem:' | awk '{printf \"%.1f\", ($3/$2)*100}'",
    );
    let value: f64 = used.parse().expect("a percentage");
    assert!((0.0..100.0).contains(&value), "{used}");
    assert!(!used.ends_with('\n'), "printf without a newline");
    let mem = out(&mut sh, "free -h 2>/dev/null | grep -i '^Mem:'");
    assert!(mem.starts_with("Mem:"), "{mem}");
    let cpu = out(
        &mut sh,
        "top -bn1 2>/dev/null | grep -i '^%Cpu\\|^Cpu' | head -1",
    );
    assert!(cpu.starts_with("%Cpu(s):"), "{cpu}");
}
