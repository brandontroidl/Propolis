//! The optional `--journal` source: the sensor units' and the daemon's own journal, read from a
//! journalctl child. This is the watcher's only child process and its argument vector is the
//! constant [`JOURNAL_ARGS`]: nothing from the command line, the environment or the logs ever
//! reaches it, and no shell is involved.
//!
//! journalctl failing is reported, never fatal: a missing binary or a spawn refusal becomes one
//! `error` record, each line journalctl writes to stderr (its "you are not seeing messages from
//! other users" hint when this user is not in `systemd-journal`) becomes an `error` record, and
//! so does its exit. The event logs keep streaming regardless.

use std::io::{self, BufRead, BufReader, Read};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc::Sender;
use std::thread;

use serde_json::Value;

use crate::record;

/// Absolute, so no `PATH` lookup decides what runs.
pub const JOURNAL_PROGRAM: &str = "/usr/bin/journalctl";

pub const JOURNAL_ARGS: [&str; 8] = [
    "-f",
    "-o",
    "json",
    "--no-pager",
    "-u",
    "sensor-*",
    "-u",
    "propolis",
];

/// journald's own stream line limit (`LineMax=`) defaults to 48 KiB, so a real entry is far below
/// this; it only bounds what one read from the pipe can allocate.
const MAX_JOURNAL_LINE_BYTES: u64 = 1_048_576;

/// How many stderr lines are relayed. journalctl writes a hint or two, not a stream; the cap
/// keeps a misbehaving one from flooding the output.
const MAX_STDERR_LINES: usize = 16;

/// Starts journalctl and two reader threads that send finished records to `out`. Returns the
/// child so the caller can kill it on the way out, or the spawn error.
pub fn spawn(out: Sender<Value>) -> io::Result<Child> {
    let mut child = Command::new(JOURNAL_PROGRAM)
        .args(JOURNAL_ARGS)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;

    if let Some(stdout) = child.stdout.take() {
        let out = out.clone();
        thread::spawn(move || {
            for_each_line(stdout, |line| {
                let record = match serde_json::from_slice::<Value>(line) {
                    Ok(entry) => record::journal_record(&entry),
                    Err(_) => record::error(
                        "journal",
                        &format!(
                            "journalctl wrote a line that is not JSON: {}",
                            String::from_utf8_lossy(line)
                        ),
                    ),
                };
                out.send(record).is_ok()
            });
            let _ = out.send(record::error(
                "journal",
                "journalctl stopped producing output",
            ));
        });
    }
    if let Some(stderr) = child.stderr.take() {
        thread::spawn(move || {
            let mut relayed = 0;
            for_each_line(stderr, |line| {
                relayed += 1;
                let text = String::from_utf8_lossy(line);
                out.send(record::error("journal", &format!("journalctl: {text}")))
                    .is_ok()
                    && relayed < MAX_STDERR_LINES
            });
        });
    }
    Ok(child)
}

/// Calls `f` with each `\n`-terminated line (without the `\n`) until EOF, a read error, or `f`
/// returns false. A line longer than [`MAX_JOURNAL_LINE_BYTES`] is passed truncated.
fn for_each_line(source: impl Read, mut f: impl FnMut(&[u8]) -> bool) {
    let mut reader = BufReader::new(source);
    loop {
        let mut buf = Vec::new();
        match (&mut reader)
            .take(MAX_JOURNAL_LINE_BYTES)
            .read_until(b'\n', &mut buf)
        {
            Ok(0) | Err(_) => return,
            Ok(_) => {}
        }
        if buf.last() == Some(&b'\n') {
            buf.pop();
        } else if buf.len() as u64 >= MAX_JOURNAL_LINE_BYTES {
            // Skip the rest of the over-long line, in bounded chunks, so the next call starts on a
            // line boundary.
            loop {
                let mut rest = Vec::new();
                match (&mut reader)
                    .take(MAX_JOURNAL_LINE_BYTES)
                    .read_until(b'\n', &mut rest)
                {
                    Ok(0) | Err(_) => return,
                    Ok(_) if rest.last() == Some(&b'\n') => break,
                    Ok(_) => {}
                }
            }
        }
        if !f(&buf) {
            return;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_argument_vector_is_the_fixed_one_the_docs_name() {
        assert_eq!(JOURNAL_PROGRAM, "/usr/bin/journalctl");
        assert_eq!(
            JOURNAL_ARGS.join(" "),
            "-f -o json --no-pager -u sensor-* -u propolis"
        );
    }

    #[test]
    fn lines_are_split_on_newline_and_stop_when_asked() {
        let mut seen = Vec::new();
        for_each_line(&b"one\ntwo\nthree\n"[..], |l| {
            seen.push(String::from_utf8_lossy(l).into_owned());
            seen.len() < 2
        });
        assert_eq!(seen, vec!["one", "two"]);
    }
}
