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
use tokio::sync::broadcast::error::RecvError;

use crate::AppState;
use crate::auth::Session;
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
    let entries = state.log_buffer.snapshot();
    let csrf_token = state
        .sessions
        .generate_csrf(&session.id)
        .unwrap_or_default();
    let BaseContext {
        pending_count,
        uptime,
        version,
        degraded: _,
    } = base_context(&state.db, state.startup_time, state.version).await;

    let tmpl = state.templates.get_template("logs.html")?;
    let html = tmpl.render(context! {
        csrf_token,
        active_nav => "logs",
        pending_count,
        uptime,
        version,
        entries,
    })?;
    Ok(Html(html))
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
