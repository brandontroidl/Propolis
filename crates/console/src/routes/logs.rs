//! `GET /logs` and `GET /logs/stream` - the live system log viewer
//! (`internal/design/11-console-forensics.md`, task 7 "Live system log"). Session-gated: mounted
//! under the `protected` group in `routes::mod`.
//!
//! `/logs` renders the terminal-style viewer with `AppState::log_buffer`'s current snapshot
//! (everything held in the ring buffer, oldest first) so a freshly loaded page already shows
//! recent history rather than a blank pane waiting on the first live event. `/logs/stream` is a
//! Server-Sent-Events endpoint (`text/event-stream`) that the page's own `<script>` connects to
//! via `EventSource`: each broadcast `LogEntry` is serialized to JSON and sent as one SSE `data:`
//! event, appended client-side with level-based coloring - see `templates/logs.html`.
//!
//! Each row shows the entry's structured fields and expands to all of them. Adjacent identical
//! INFO entries fold into one row with a count ([`fold_entries`] for the first render,
//! `assets/logs.js` for live lines, by the same rule), and the view opens filtered to warnings
//! and errors, saying how many lower-level rows it hides, so a per-batch INFO line cannot bury
//! a WARN.
//!
//! `logs_stream` subscribes fresh on every request (`LogBuffer::subscribe`), so a reconnecting
//! client - `EventSource` auto-reconnects on a dropped connection - simply misses whatever
//! happened while disconnected rather than replaying it; the page's initial snapshot on a full
//! reload is the recovery path for that gap, matching `log_buffer`'s own module doc comment. A
//! `Lagged` receiver error (the subscriber fell behind the broadcast channel's internal buffer) is
//! skipped rather than treated as end-of-stream, so a burst of log volume thins the client's view
//! instead of silently closing its connection.

use axum::extract::State;
use axum::response::Html;
use axum::response::sse::{Event, KeepAlive, Sse};
use axum::routing::get;
use axum::{Extension, Router};
use futures::stream::Stream;
use minijinja::context;
use serde::Serialize;
use tokio::sync::broadcast::error::RecvError;

use crate::AppState;
use crate::auth::Session;
use crate::log_buffer::{LogEntry, LogField};
use crate::routes::context::{BaseContext, base_context};
use crate::routes::error::AppError;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/logs", get(logs_page))
        .route("/logs/stream", get(logs_stream))
}

async fn logs_page(
    State(state): State<AppState>,
    Extension(session): Extension<Session>,
) -> Result<Html<String>, AppError> {
    let rows = fold_entries(&state.log_buffer.snapshot());
    let below_warn = rows
        .iter()
        .filter(|r| level_rank(&r.level) < level_rank("WARN"))
        .count();
    let csrf_token = state
        .sessions
        .generate_csrf(&session.id)
        .unwrap_or_default();
    let BaseContext {
        pending_count,
        uptime,
        version,
        degraded,
    } = base_context(&state.db, state.startup_time, state.version).await;

    let tmpl = state.templates.get_template("logs.html")?;
    let html = tmpl.render(context! {
        csrf_token,
        active_nav => "logs",
        pending_count,
        uptime,
        version,
        degraded => degraded.names(),
        rows,
        below_warn,
    })?;
    Ok(Html(html))
}

/// How many distinct values a folded row's summary names per field before it says "+N".
const SUMMARY_VALUES: usize = 4;

/// One row of the log view: a single entry, or a run of identical INFO entries folded together.
#[derive(Debug, Serialize)]
struct LogRow {
    level: String,
    level_slug: &'static str,
    target: String,
    message: String,
    /// The newest entry's timestamp, and its `HH:MM:SS` part for the row.
    timestamp: String,
    time: String,
    /// The oldest entry's timestamp; equal to `timestamp` for a single entry.
    first_timestamp: String,
    count: usize,
    /// A single entry's own fields, or, for a fold, each field's distinct values.
    fields: Vec<FieldSummary>,
    /// Every folded entry's time and fields, oldest first; empty for a single entry.
    members: Vec<LogMember>,
}

/// One field of a row: its key and the distinct values it took (one for a single entry), at most
/// [`SUMMARY_VALUES`] of them, with `more` counting the distinct values not listed. Kept as a
/// list rather than one joined string because values are often paths, which contain `/`.
#[derive(Debug, Serialize)]
struct FieldSummary {
    key: String,
    values: Vec<String>,
    more: usize,
}

#[derive(Debug, Serialize)]
struct LogMember {
    time: String,
    fields: Vec<LogField>,
}

/// Severity order for the level filter: higher is more severe. Unknown levels rank with INFO,
/// matching the badge colour `logs.js` falls back to.
fn level_rank(level: &str) -> u8 {
    match level.to_ascii_uppercase().as_str() {
        "ERROR" => 5,
        "WARN" => 4,
        "DEBUG" => 2,
        "TRACE" => 1,
        _ => 3,
    }
}

fn level_slug(level: &str) -> &'static str {
    match level.to_ascii_uppercase().as_str() {
        "ERROR" => "error",
        "WARN" => "warn",
        "DEBUG" => "debug",
        "TRACE" => "trace",
        _ => "info",
    }
}

/// The `HH:MM:SS` part of an RFC 3339 timestamp, or the whole string if it is not one.
fn clock_time(timestamp: &str) -> String {
    timestamp
        .get(11..19)
        .filter(|t| t.as_bytes().get(2) == Some(&b':'))
        .unwrap_or(timestamp)
        .to_string()
}

/// Folds consecutive INFO entries that share a target and a message into one row with a count,
/// so a per-batch line repeated hundreds of times takes one row and a WARN between two runs
/// still stands on its own. Only adjacent entries fold: a run interrupted by anything else
/// starts a new row, so the view never reorders what happened. Other levels never fold; a
/// repeated warning is worth seeing each time.
fn fold_entries(entries: &[LogEntry]) -> Vec<LogRow> {
    let mut rows: Vec<(LogRow, Vec<&LogEntry>)> = Vec::new();
    for entry in entries {
        let folds = entry.level.eq_ignore_ascii_case("INFO")
            && rows.last().is_some_and(|(row, _)| {
                row.level.eq_ignore_ascii_case("INFO")
                    && row.target == entry.target
                    && row.message == entry.message
            });
        if folds {
            let (_, members) = rows.last_mut().expect("checked above");
            members.push(entry);
            continue;
        }
        rows.push((
            LogRow {
                level: entry.level.clone(),
                level_slug: level_slug(&entry.level),
                target: entry.target.clone(),
                message: entry.message.clone(),
                timestamp: entry.timestamp.clone(),
                time: clock_time(&entry.timestamp),
                first_timestamp: entry.timestamp.clone(),
                count: 1,
                fields: summarize_fields(&[entry]),
                members: Vec::new(),
            },
            vec![entry],
        ));
    }
    rows.into_iter()
        .map(|(mut row, members)| {
            if members.len() > 1 {
                let last = members[members.len() - 1];
                row.count = members.len();
                row.timestamp = last.timestamp.clone();
                row.time = clock_time(&last.timestamp);
                row.fields = summarize_fields(&members);
                row.members = members
                    .iter()
                    .map(|m| LogMember {
                        time: clock_time(&m.timestamp),
                        fields: m.fields.clone(),
                    })
                    .collect();
            }
            row
        })
        .collect()
}

/// Each field key across `members`, in first-seen order, with its distinct values in first-seen
/// order (at most [`SUMMARY_VALUES`] of them, the rest counted in `more`).
fn summarize_fields(members: &[&LogEntry]) -> Vec<FieldSummary> {
    let mut keys: Vec<(&str, Vec<&str>)> = Vec::new();
    for m in members {
        for f in &m.fields {
            let idx = match keys.iter().position(|(k, _)| *k == f.key) {
                Some(i) => i,
                None => {
                    keys.push((f.key.as_str(), Vec::new()));
                    keys.len() - 1
                }
            };
            let values = &mut keys[idx].1;
            if !values.contains(&f.value.as_str()) {
                values.push(f.value.as_str());
            }
        }
    }
    keys.into_iter()
        .map(|(key, values)| FieldSummary {
            key: key.to_string(),
            more: values.len().saturating_sub(SUMMARY_VALUES),
            values: values
                .iter()
                .take(SUMMARY_VALUES)
                .map(|v| v.to_string())
                .collect(),
        })
        .collect()
}

/// Streams every `LogEntry` broadcast after this request connects, as newline-delimited SSE
/// `data:` events carrying one JSON object each. `KeepAlive::default()` sends a periodic comment
/// so an idle connection (no log activity) does not look dead to an intermediary proxy or get
/// timed out client-side.
async fn logs_stream(
    State(state): State<AppState>,
) -> Sse<impl Stream<Item = Result<Event, std::convert::Infallible>>> {
    let rx = state.log_buffer.subscribe();
    let stream = futures::stream::unfold(rx, |mut rx| async move {
        loop {
            match rx.recv().await {
                Ok(entry) => {
                    let json = serde_json::to_string(&entry).unwrap_or_default();
                    return Some((Ok(Event::default().data(json)), rx));
                }
                // The channel filled up faster than this subscriber drained it - drop the gap
                // and keep reading rather than ending the stream over it (module doc comment).
                Err(RecvError::Lagged(_)) => continue,
                // The sender side is gone (the process is shutting down); end the stream.
                Err(RecvError::Closed) => return None,
            }
        }
    });
    Sse::new(stream).keep_alive(KeepAlive::default())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn e(level: &str, target: &str, message: &str, fields: &[(&str, &str)]) -> LogEntry {
        LogEntry {
            timestamp: "2026-10-07T22:31:04.512+00:00".to_string(),
            level: level.to_string(),
            target: target.to_string(),
            message: message.to_string(),
            fields: fields
                .iter()
                .map(|(k, v)| LogField {
                    key: k.to_string(),
                    value: v.to_string(),
                })
                .collect(),
        }
    }

    #[test]
    fn only_adjacent_identical_info_entries_fold() {
        let batch = |sensor| e("INFO", "intake", "batch processed", &[("sensor", sensor)]);
        let entries = vec![
            batch("telnet"),
            batch("vnc"),
            batch("telnet"),
            e("WARN", "intake", "slow statement", &[("elapsed", "1.5s")]),
            batch("ssh"),
            batch("ssh"),
            e("INFO", "intake", "batch skipped", &[]),
            e("INFO", "review", "batch processed", &[]),
            e("DEBUG", "x", "tick", &[]),
            e("DEBUG", "x", "tick", &[]),
            e("WARN", "x", "held", &[]),
            e("WARN", "x", "held", &[]),
        ];

        let rows = fold_entries(&entries);

        let shape: Vec<(&str, &str, usize)> = rows
            .iter()
            .map(|r| (r.level.as_str(), r.message.as_str(), r.count))
            .collect();
        assert_eq!(
            shape,
            [
                ("INFO", "batch processed", 3),
                ("WARN", "slow statement", 1),
                ("INFO", "batch processed", 2),
                ("INFO", "batch skipped", 1),
                ("INFO", "batch processed", 1),
                ("DEBUG", "tick", 1),
                ("DEBUG", "tick", 1),
                ("WARN", "held", 1),
                ("WARN", "held", 1),
            ]
        );
        assert_eq!(rows[0].fields[0].values, ["telnet", "vnc"]);
        assert_eq!(rows[0].members.len(), 3);
        assert_eq!(rows[1].fields[0].values, ["1.5s"]);
        assert!(rows[1].members.is_empty());
    }

    #[test]
    fn a_fold_summary_names_at_most_four_values_then_counts_the_rest() {
        let entries: Vec<LogEntry> = (0..7)
            .map(|n| e("INFO", "t", "m", &[("n", &n.to_string()), ("same", "x")]))
            .collect();
        let rows = fold_entries(&entries);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].fields[0].values, ["0", "1", "2", "3"]);
        assert_eq!(rows[0].fields[0].more, 3);
        assert_eq!(rows[0].fields[1].values, ["x"]);
        assert_eq!(rows[0].fields[1].more, 0);
    }

    #[test]
    fn clock_time_takes_the_time_of_day_or_keeps_what_it_cannot_read() {
        assert_eq!(clock_time("2026-10-07T22:31:04.512+00:00"), "22:31:04");
        assert_eq!(clock_time("yesterday"), "yesterday");
    }
}
