//! `propolis-watch`: a read-only live view of everything the sensors record, streamed as JSON
//! Lines on stdout so a remote reader (the owner over SSH, or an assistant reading the same
//! stream) can spot missing fidelity and defects while they happen.
//!
//! Read-only by construction: it opens the event logs read-only through the cursorless
//! `log_tailer::LogTailer::without_cursor`, persists nothing, opens no socket, needs no database
//! or credential, and its one child process is journalctl with a fixed argument vector
//! (`journal::JOURNAL_ARGS`). `tests/read_only.rs` fails if the source grows a way to do more.
//! See `docs/operations/live-watch.md`.

pub mod args;
pub mod config;
pub mod journal;
pub mod record;
pub mod status;
pub mod watcher;
