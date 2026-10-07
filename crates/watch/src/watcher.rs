//! The follow loop: poll every configured log through a cursorless tailer, interleave journal
//! records when `--journal` is on, and write a heartbeat on a fixed cadence so a reader can tell
//! a quiet honeypot from a dead stream. Returns only when stdout can no longer be written, which
//! is how a closed SSH session ends it.

use std::io::{self, Write};
use std::path::PathBuf;
use std::sync::mpsc::{self, Receiver, RecvTimeoutError};
use std::time::{Duration, Instant};

use log_tailer::{LogTailer, SensorLogConfig, StartAt, TailEntry};
use serde_json::Value;

use crate::args::Options;
use crate::journal;
use crate::record::{self, FileReport, Filter};
use crate::status::file_status;

/// How often the logs are polled when nothing else wakes the loop.
const POLL_INTERVAL: Duration = Duration::from_millis(250);
/// How often a heartbeat is written. A reader that sees none for longer than this knows the
/// stream, not the honeypot, has gone quiet.
pub const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(10);
/// Lines read from one log per tailer call; a backlog larger than this is read over several calls
/// within the same poll.
const BATCH_LINES: usize = 1_000;

struct Source {
    label: String,
    path: PathBuf,
    tailer: LogTailer,
    lines_seen: u64,
}

/// Streams until writing to `out` fails, then returns that error.
pub fn run(
    logs: Vec<SensorLogConfig>,
    options: &Options,
    version: &str,
    out: &mut impl Write,
) -> io::Error {
    let start_at = if options.since_start {
        StartAt::Beginning
    } else {
        StartAt::End
    };
    let filter = Filter::from_options(options);
    let mut sources: Vec<Source> = logs
        .into_iter()
        .map(|log| Source {
            tailer: LogTailer::without_cursor(log.log_path.clone(), start_at),
            label: log.name,
            path: log.log_path,
            lines_seen: 0,
        })
        .collect();

    let listed: Vec<(String, &std::path::Path)> = sources
        .iter()
        .map(|s| (s.label.clone(), s.path.as_path()))
        .collect();
    if let Err(e) = emit(out, record::start(version, &listed, options), None) {
        return e;
    }

    let (journal, mut child) = if options.journal {
        let (tx, rx) = mpsc::channel();
        match journal::spawn(tx) {
            Ok(child) => (Some(rx), Some(child)),
            Err(e) => {
                let message = format!("could not start {}: {e}", journal::JOURNAL_PROGRAM);
                if let Err(e) = emit(out, record::error("journal", &message), None) {
                    return e;
                }
                (None, None)
            }
        }
    } else {
        (None, None)
    };

    let error = follow(&mut sources, &filter, journal, out);
    if let Some(child) = child.as_mut() {
        let _ = child.kill();
        let _ = child.wait();
    }
    error
}

fn follow(
    sources: &mut [Source],
    filter: &Filter,
    mut journal: Option<Receiver<Value>>,
    out: &mut impl Write,
) -> io::Error {
    // Due immediately, so a misconfigured path shows as `missing` in the first second, not ten
    // seconds in.
    let mut next_heartbeat = Instant::now();
    loop {
        for source in sources.iter_mut() {
            if let Err(e) = drain(source, filter, out) {
                return e;
            }
        }
        if Instant::now() >= next_heartbeat {
            if let Err(e) = emit(out, heartbeat(sources), None) {
                return e;
            }
            next_heartbeat = Instant::now() + HEARTBEAT_INTERVAL;
        }
        if let Err(e) = out.flush() {
            return e;
        }

        let Some(rx) = journal.as_ref() else {
            std::thread::sleep(POLL_INTERVAL);
            continue;
        };
        match rx.recv_timeout(POLL_INTERVAL) {
            Ok(first) => {
                for record in std::iter::once(first).chain(rx.try_iter()) {
                    if let Err(e) = emit(out, record, None) {
                        return e;
                    }
                }
            }
            Err(RecvTimeoutError::Timeout) => {}
            Err(RecvTimeoutError::Disconnected) => journal = None,
        }
    }
}

fn drain(source: &mut Source, filter: &Filter, out: &mut impl Write) -> io::Result<()> {
    loop {
        let entries = source.tailer.read_batch_entries(BATCH_LINES);
        // Nothing here can fail after the read, and nothing is ever persisted, so accepting the
        // batch only releases the rotated-out descriptors it drained.
        source.tailer.commit_batch();
        let mut lines = 0;
        for entry in &entries {
            source.lines_seen += 1;
            match entry {
                TailEntry::Line(line) => {
                    lines += 1;
                    if let Some(text) =
                        record::event_line(&source.label, &source.path, line, filter)
                    {
                        write_line(out, record::bounded(text, Some(&source.label)))?;
                    }
                }
                TailEntry::Discarded { bytes } => {
                    if filter.keeps_label(&source.label) {
                        let dropped = record::dropped_line(&source.label, &source.path, *bytes);
                        emit(out, dropped, Some(&source.label))?;
                    }
                }
            }
        }
        if lines < BATCH_LINES {
            return Ok(());
        }
    }
}

fn heartbeat(sources: &[Source]) -> Value {
    let reports: Vec<FileReport<'_>> = sources
        .iter()
        .map(|s| {
            let (status, size) = file_status(&s.path);
            FileReport {
                label: &s.label,
                path: &s.path,
                status,
                size,
                lines_seen: s.lines_seen,
            }
        })
        .collect();
    record::heartbeat(&reports)
}

fn emit(out: &mut impl Write, record: Value, label: Option<&str>) -> io::Result<()> {
    write_line(out, record::bounded(record.to_string(), label))
}

fn write_line(out: &mut impl Write, line: String) -> io::Result<()> {
    out.write_all(line.as_bytes())?;
    out.write_all(b"\n")
}
