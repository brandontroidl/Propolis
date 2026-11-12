//! A line that reads the session's own input: `start_line` decides it waits by running it, leaves
//! nothing behind when it does, and `finish_line` runs it on the input that arrived, through the
//! filesystem every later command reads.

use md5::{Digest, Md5};

use super::{EmitContext, FakeShell, InputEnd, LineStep, RESUME_ATTEMPTS};
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

/// Whether an `ls -l` row dates its file in the recent form (`Oct  7 12:00`, a time of day where an
/// old file shows its year), as it does for a file the session wrote.
fn recent_stamp(row: &str) -> bool {
    row.split_whitespace()
        .nth(7)
        .is_some_and(|field| field.len() == 5 && field.as_bytes()[2] == b':')
}

/// One connection's filesystem, and an exec shell on it per channel, as sensor-ssh builds them.
struct Connection {
    fs: FakeFs,
}

impl Connection {
    fn new() -> Self {
        Self { fs: FakeFs::new() }
    }

    fn exec(&self) -> FakeShell {
        FakeShell::exec(self.fs.share(), ctx())
    }

    /// Run a stdin-free exec command and return (stdout+stderr, status).
    fn run(&self, line: &str) -> (String, u8) {
        let mut sh = self.exec();
        match sh.start_line(line).0 {
            LineStep::Ran(result) => (result.to_string(), result.status),
            LineStep::AwaitingInput => panic!("`{line}` waited for input"),
        }
    }

    /// Run an exec command that reads its input, feeding it `body` and then EOF.
    fn upload(&self, line: &str, body: &[u8]) -> (String, u8) {
        let mut sh = self.exec();
        assert!(
            matches!(sh.start_line(line).0, LineStep::AwaitingInput),
            "`{line}` should wait for its input"
        );
        let result = sh.finish_line(body, InputEnd::Eof);
        (result.to_string(), result.status)
    }
}

fn md5_hex(bytes: &[u8]) -> String {
    Md5::digest(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// 70000 bytes that start like an ELF and cover every byte value.
fn payload() -> Vec<u8> {
    let mut body = b"\x7fELF\x02\x01\x01".to_vec();
    body.extend((0..70_000 - 7).map(|i| (i % 251) as u8));
    body
}

#[test]
fn a_streamed_binary_lands_whole_and_every_reader_agrees_on_it() {
    let conn = Connection::new();
    let body = payload();
    let (out, status) = conn.upload(
        "cd /dev/shm || cd /tmp || cd /var/run || cd /mnt || cd /root || cd / && cat > astats",
        &body,
    );
    assert_eq!((out.as_str(), status), ("", 0));

    let (out, status) = conn.run("cd /dev/shm && wc -c astats; md5sum astats");
    assert_eq!(status, 0);
    assert_eq!(
        out,
        format!("70000 astats\n{}  astats\n", md5_hex(&body)),
        "the size and digest the bot reads back are those of what it sent"
    );
    let (out, _) = conn.run("cd /dev/shm && head -c 4 astats | od -An -tx1");
    assert_eq!(out, " 7f 45 4c 46\n");
    let (out, status) = conn.run("ls -la /dev/shm/astats");
    assert_eq!(status, 0, "{out}");
    assert!(
        out.starts_with("-rw-r--r-- 1 root root 70000 ") && out.ends_with(" /dev/shm/astats\n"),
        "ls sees the file wc and md5sum read: {out:?}"
    );
    let (out, _) = conn.run("cd /dev/shm && ls -la astats");
    assert!(
        out.ends_with(" astats\n") && out.contains(" 70000 "),
        "{out:?}"
    );
    let (out, status) = conn.run("ls /dev/shm");
    assert_eq!((out.as_str(), status), ("astats\n", 0));
    // The file was written just now, so ls shows the time of day rather than a year.
    let listed = conn
        .run("test -f /dev/shm/astats && chmod +x /dev/shm/astats && ls -l /dev/shm/astats")
        .0;
    assert!(
        listed.starts_with("-rwxr-xr-x 1 root root 70000 ")
            && listed.ends_with(" /dev/shm/astats\n")
            && recent_stamp(&listed),
        "{listed:?}"
    );
    // Nothing was ever run, so the bot's liveness check finds no process.
    assert_eq!(
        conn.run("ps aux | grep astats | grep -v grep | wc -l"),
        ("0\n".to_string(), 0)
    );
}

#[test]
fn a_waiting_line_leaves_nothing_behind_until_its_input_ends() {
    let conn = Connection::new();
    let budget = conn.fs.budget().clone();
    let before = (budget.owned_bytes_used(), budget.overlay_nodes_used());
    let mut sh = conn.exec();
    let (step, events) = sh.start_line(
        "sh -lc 'mkdir -p ~/.config/systemd/user && cat > ~/.config/systemd/user/w.service && echo done'",
    );
    assert!(matches!(step, LineStep::AwaitingInput));
    assert!(sh.is_awaiting_input());
    // The command is on record now, without the status only the real run can give it.
    assert_eq!(events.len(), 1);
    assert!(
        events[0].metadata["command"]
            .as_str()
            .unwrap()
            .contains("cat >")
    );
    assert!(events[0].metadata.get("status").is_none());
    // The run that found the wait made the directory and the file; both are undone.
    assert_eq!(
        conn.run("test -d /root/.config/systemd/user; echo $?").0,
        "1\n"
    );
    assert_eq!(
        (budget.owned_bytes_used(), budget.overlay_nodes_used()),
        before
    );

    let out = sh.finish_line(b"[Unit]\nDescription=x\n", InputEnd::Eof);
    assert_eq!((out.to_string().as_str(), out.status), ("done\n", 0));
    assert!(!sh.is_awaiting_input());
    assert_eq!(
        sh.input_destination(),
        Some("/root/.config/systemd/user/w.service")
    );
    assert_eq!(
        conn.run("cat /root/.config/systemd/user/w.service").0,
        "[Unit]\nDescription=x\n"
    );
}

#[test]
fn a_command_that_does_not_read_its_input_runs_at_once() {
    let conn = Connection::new();
    for line in [
        "uname -a",
        "echo hi > /tmp/x",
        "cat /etc/hostname",
        "cat < /etc/hostname",
        "sh -c 'echo nested'",
    ] {
        let mut sh = conn.exec();
        assert!(
            matches!(sh.start_line(line).0, LineStep::Ran(_)),
            "`{line}` does not read standard input"
        );
    }
    // `-c` clustered with other options still names the script.
    assert_eq!(
        conn.run("sh -lc 'echo clustered $0' name"),
        ("clustered name\n".to_string(), 0)
    );
    assert_eq!(conn.run("bash -ec 'echo e'"), ("e\n".to_string(), 0));
    // A heredoc and a pipe give the reader its input; the session input is not touched.
    assert_eq!(conn.run("cat <<EOF\nfrom heredoc\nEOF").0, "from heredoc\n");
    assert_eq!(conn.run("echo piped | cat").0, "piped\n");
}

#[test]
fn the_dropper_script_is_written_once_and_the_retry_branch_reads_nothing() {
    let conn = Connection::new();
    let line = r#"cd "/dev/shm" && if [ ! -f "w.sh" ]; then cat > "w.sh" && chmod +x w.sh; fi"#;
    let script = b"#!/bin/sh\necho dropper-script-marker\n";
    assert_eq!(conn.upload(line, script), (String::new(), 0));
    assert_eq!(
        conn.run("cat /dev/shm/w.sh").0.as_bytes(),
        script.as_slice()
    );
    assert_eq!(conn.run("test -x /dev/shm/w.sh; echo $?").0, "0\n");
    // The file is there now, so the same line takes the other branch and reads no input.
    assert_eq!(conn.run(line), (String::new(), 0));
}

#[test]
fn every_reader_of_standard_input_waits_and_writes_where_it_says() {
    let conn = Connection::new();
    let cases: [(&str, &[u8], Option<&str>, &str); 6] = [
        ("cat >> /tmp/a", b"one\n", Some("/tmp/a"), "one\n"),
        ("cat - > /tmp/b", b"two\n", Some("/tmp/b"), "two\n"),
        (
            "base64 -d > /tmp/c",
            b"aGVsbG8K\n",
            Some("/tmp/c"),
            "hello\n",
        ),
        (
            "dd of=/tmp/d 2>/dev/null",
            b"dd-body",
            Some("/tmp/d"),
            "dd-body",
        ),
        ("head -c 3 > /tmp/e", b"abcdef", Some("/tmp/e"), "abc"),
        ("{ cat; } > /tmp/f", b"grouped", Some("/tmp/f"), "grouped"),
    ];
    for (line, body, destination, content) in cases {
        let mut sh = conn.exec();
        assert!(
            matches!(sh.start_line(line).0, LineStep::AwaitingInput),
            "`{line}` reads its input"
        );
        sh.finish_line(body, InputEnd::Eof);
        assert_eq!(sh.input_destination(), destination, "`{line}`");
        let file = destination.unwrap();
        assert_eq!(conn.run(&format!("cat {file}")).0, content, "`{line}`");
    }
}

#[test]
fn a_script_on_standard_input_runs_and_is_stored_nowhere() {
    let conn = Connection::new();
    for line in ["sh", "bash", "cat | sh"] {
        let mut sh = conn.exec();
        assert!(
            matches!(sh.start_line(line).0, LineStep::AwaitingInput),
            "`{line}`"
        );
        let out = sh.finish_line(b"echo from-stdin\n", InputEnd::Eof);
        assert_eq!(out.to_string(), "from-stdin\n", "`{line}`");
        assert_eq!(sh.input_destination(), None, "`{line}`");
    }
}

#[test]
fn a_terminal_reads_lines_for_cat_but_a_bare_sh_opens_a_level_on_it() {
    let mut sh = FakeShell::new(FakeFs::new(), ctx());
    assert!(matches!(
        sh.start_line("cat > notes").0,
        LineStep::AwaitingInput
    ));
    assert_eq!(sh.finish_line(b"a\nb\n", InputEnd::Eof).to_string(), "");
    assert_eq!(sh.handle_input("cat notes").0, "a\nb\n");
    // On a terminal a bare `sh` is an interactive shell, not a reader of a script.
    assert!(matches!(sh.start_line("sh").0, LineStep::Ran(_)));
    assert_eq!(sh.prompt(), "# ");
}

#[test]
fn ctrl_c_kills_the_reader_and_the_rest_of_the_line_but_keeps_what_it_wrote() {
    let mut sh = FakeShell::new(FakeFs::new(), ctx());
    assert!(matches!(
        sh.start_line("cat > f; echo after").0,
        LineStep::AwaitingInput
    ));
    let out = sh.finish_line(b"line1\n", InputEnd::Interrupt);
    assert_eq!((out.to_string().as_str(), out.status), ("\n", 130));
    assert_eq!(sh.handle_input("echo $?").0, "130\n");
    assert_eq!(sh.handle_input("cat f").0, "line1\n");
}

#[test]
fn a_hangup_ends_an_exec_reader_with_what_arrived() {
    let conn = Connection::new();
    let mut sh = conn.exec();
    assert!(matches!(
        sh.start_line("cat > /tmp/part && echo whole").0,
        LineStep::AwaitingInput
    ));
    let out = sh.finish_line(b"partial", InputEnd::Hangup);
    assert_eq!((out.to_string().as_str(), out.status), ("", 129));
    assert_eq!(conn.run("cat /tmp/part").0, "partial");
}

#[test]
fn handle_input_still_reads_the_terminal_as_empty() {
    let mut sh = FakeShell::exec(FakeFs::new(), ctx());
    let (out, _) = sh.handle_input("cat > /tmp/x; echo next");
    assert_eq!((out.to_string().as_str(), out.status), ("next\n", 0));
    assert!(!sh.is_awaiting_input());
}

#[test]
fn ls_lists_a_file_operand_and_reports_a_missing_one() {
    let conn = Connection::new();
    conn.run("echo hi > /tmp/one");
    assert_eq!(conn.run("ls /tmp/one"), ("/tmp/one\n".to_string(), 0));
    let (out, status) = conn.run("ls /tmp/one /nope");
    assert_eq!(status, 2);
    assert_eq!(
        out,
        "ls: cannot access '/nope': No such file or directory\n/tmp/one\n"
    );
    let (out, status) = conn.run("ls -l /tmp");
    assert_eq!(status, 0);
    let (total, row) = out.split_once('\n').unwrap();
    assert_eq!(total, "total 4");
    assert!(
        row.starts_with("-rw-r--r-- 1 root root 3 ")
            && row.ends_with(" one\n")
            && recent_stamp(row),
        "{out:?}"
    );
    let (out, _) = conn.run("ls /tmp/one /tmp");
    assert_eq!(out, "/tmp/one\n\n/tmp:\none\n");
}

/// At a terminal a line reader answers once Enter hands it its line, as a real one does in
/// canonical mode: `read x` and `head -n 1` finish on the first line, without waiting for
/// Ctrl-D. A reader that wants more stays waiting, and nothing it did is kept until it finishes.
#[test]
fn a_terminal_line_reader_finishes_on_its_line_and_a_whole_input_reader_waits() {
    let fs = FakeFs::new();
    let mut sh = FakeShell::new(fs.share(), ctx());
    assert!(matches!(
        sh.start_line("read x; echo got=$x").0,
        LineStep::AwaitingInput
    ));
    assert!(sh.try_finish_line(b"").is_none(), "no line yet");
    assert!(sh.try_finish_line(b"hel").is_none(), "no Enter yet");
    let done = sh
        .try_finish_line(b"hello\n")
        .expect("a whole line is enough");
    assert_eq!((done.to_string().as_str(), done.status), ("got=hello\n", 0));
    assert!(!sh.is_awaiting_input());
    assert_eq!(sh.handle_input("echo $x").0.to_string(), "hello\n");

    assert!(matches!(
        sh.start_line("head -n 1").0,
        LineStep::AwaitingInput
    ));
    assert_eq!(
        sh.try_finish_line(b"line1\n").map(|r| r.to_string()),
        Some("line1\n".to_string())
    );

    // Two reads want two lines: the first alone leaves the line waiting, unchanged.
    assert!(matches!(
        sh.start_line("read a; read b; echo $a-$b").0,
        LineStep::AwaitingInput
    ));
    assert!(sh.try_finish_line(b"one\n").is_none());
    assert!(sh.is_awaiting_input());
    assert_eq!(
        sh.try_finish_line(b"one\ntwo\n").map(|r| r.to_string()),
        Some("one-two\n".to_string())
    );

    // `cat > f` reads to the end: no line finishes it, and the file it would write is not there
    // until the input ends.
    assert!(matches!(
        sh.start_line("cat > /tmp/typed").0,
        LineStep::AwaitingInput
    ));
    assert!(sh.try_finish_line(b"a\n").is_none());
    assert!(
        !fs.share().file_exists("/tmp/typed"),
        "the waiting run was undone"
    );
    let done = sh.finish_line(b"a\nb\n", InputEnd::Eof);
    assert_eq!(done.status, 0);
    assert_eq!(fs.read_all("/tmp/typed", 64).unwrap(), b"a\nb\n");
}

/// Each try reruns the line, so a line is tried a bounded number of times and on bounded input;
/// past either it waits for the input to end, as before.
#[test]
fn a_waiting_line_is_retried_a_bounded_number_of_times() {
    let mut sh = FakeShell::new(FakeFs::new(), ctx());
    assert!(matches!(
        sh.start_line("read a; read b; echo $a-$b").0,
        LineStep::AwaitingInput
    ));
    for _ in 0..RESUME_ATTEMPTS {
        assert!(sh.try_finish_line(b"one\n").is_none());
    }
    assert!(
        sh.try_finish_line(b"one\ntwo\n").is_none(),
        "no tries left, though the input would do"
    );
    assert_eq!(
        sh.finish_line(b"one\ntwo\n", InputEnd::Eof).to_string(),
        "one-two\n"
    );
    // The byte bound: a line handed more than it reruns on waits for the end.
    assert!(matches!(sh.start_line("read a").0, LineStep::AwaitingInput));
    let big = format!("{}\n", "x".repeat(super::RESUME_BYTES));
    assert!(sh.try_finish_line(big.as_bytes()).is_none());
    assert!(sh.is_awaiting_input());
}

/// A login shell whose input is a pipe (an SSH shell request without a pty) is not interactive:
/// a bare `sh` reads the rest of that input as its script, history keeps nothing, and the
/// terminal and `.bashrc` variables are absent.
#[test]
fn a_shell_without_a_terminal_hands_its_input_to_a_bare_sh_as_a_script() {
    let mut sh = FakeShell::new(FakeFs::new(), ctx()).with_terminal_input(false);
    assert!(matches!(sh.start_line("sh").0, LineStep::AwaitingInput));
    let ran = sh.finish_line(b"echo in-script\nexit 3\n", InputEnd::Eof);
    assert_eq!((ran.to_string().as_str(), ran.status), ("in-script\n", 3));
    assert_eq!(sh.last_status(), 3);
    assert_eq!(sh.handle_input("history").0.to_string(), "");
    let env = sh.handle_input("env").0.to_string();
    for name in ["TERM=", "SSH_TTY=", "LS_COLORS=", "LESSOPEN="] {
        assert!(!env.contains(name), "{name}: {env}");
    }
    // With a terminal the same `sh` opens an interactive level instead.
    let mut tty = FakeShell::new(FakeFs::new(), ctx());
    assert!(matches!(tty.start_line("sh").0, LineStep::Ran(_)));
}
