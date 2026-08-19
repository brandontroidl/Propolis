//! In-memory ring buffer of recent tracing events plus a live broadcast channel, backing
//! `routes::logs`'s viewer page and its `/logs/stream` SSE endpoint
//! (`internal/design/11-console-forensics.md`, task 7 "Live system log"). `propolis::main` builds
//! one `Arc<LogBuffer>` at startup, installs a `tracing_subscriber::Layer` that pushes every event
//! the process logs into it, and hands the same `Arc` to `AppState::log_buffer` - so the buffer is
//! the single shared sink between the tracing pipeline and the console.
//!
//! `snapshot()` backs the page's initial render (everything currently held, oldest first, capped
//! at `capacity`); `subscribe()` backs the SSE stream (every entry pushed *after* the subscriber
//! attaches). A subscriber that falls behind the broadcast channel's internal buffer sees a
//! `Lagged` error on `recv()` - `routes::logs::logs_stream` skips those and keeps reading rather
//! than treating them as a stream-ending failure, since the ring buffer (not the broadcast
//! channel) is the durable record; a slow browser tab missing a few live lines is an acceptable
//! trade-off for not blocking the writer side.

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

use serde::Serialize;
use tokio::sync::broadcast;
use tracing::field::Visit;
use tracing_subscriber::Layer;
use tracing_subscriber::layer::Context;

/// One captured tracing event, already formatted for display - never re-parsed from the original
/// `tracing::Event`, which does not outlive its callback.
#[derive(Debug, Clone, Serialize)]
pub struct LogEntry {
    pub timestamp: String,
    pub level: String,
    pub target: String,
    pub message: String,
}

/// Bounded ring buffer (`capacity` entries, oldest evicted first) plus a broadcast channel for
/// live tailing. The ring and the channel are independent: a value pushed lands in both, but a
/// broadcast subscriber that started after the push never sees it via the channel - only
/// `snapshot()` recovers history, matching the page-load/live-stream split above.
pub struct LogBuffer {
    ring: Mutex<VecDeque<LogEntry>>,
    tx: broadcast::Sender<LogEntry>,
    capacity: usize,
}

/// Broadcast channel capacity - how many not-yet-received live entries a lagging subscriber may
/// fall behind by before `recv()` reports `Lagged`. Independent of the ring buffer's `capacity`
/// (which bounds *history*, not the live channel's backlog).
const CHANNEL_CAPACITY: usize = 256;

impl LogBuffer {
    pub fn new(capacity: usize) -> Self {
        let (tx, _) = broadcast::channel(CHANNEL_CAPACITY);
        Self {
            ring: Mutex::new(VecDeque::with_capacity(capacity)),
            tx,
            capacity,
        }
    }

    /// Appends `entry` to the ring (evicting the oldest entry once `capacity` is reached) and
    /// broadcasts it to every live subscriber. `send` returning `Err` just means no subscriber is
    /// currently attached (no SSE client connected) - not a failure worth logging, since logging
    /// it would itself push another entry through this same path.
    pub fn push(&self, entry: LogEntry) {
        let mut ring = self.ring.lock().unwrap_or_else(|e| e.into_inner());
        if ring.len() >= self.capacity {
            ring.pop_front();
        }
        ring.push_back(entry.clone());
        drop(ring);
        let _ = self.tx.send(entry);
    }

    /// Every entry currently held, oldest first.
    pub fn snapshot(&self) -> Vec<LogEntry> {
        self.ring
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .iter()
            .cloned()
            .collect()
    }

    /// A fresh receiver that sees every entry pushed from this point on.
    pub fn subscribe(&self) -> broadcast::Receiver<LogEntry> {
        self.tx.subscribe()
    }
}

/// A `tracing_subscriber::Layer` that pushes every event it sees into the wrapped [`LogBuffer`].
/// Applies no filtering of its own - whatever reaches `on_event` gets captured - so the process's
/// binary (`console::main`, `propolis::main`) controls what the console's `/logs` viewer sees by
/// placing an `EnvFilter` (or any other filtering layer) *above* this one in the same
/// `tracing_subscriber::registry()` stack, exactly as it already does for the `fmt` layer: a
/// filtering layer added via `.with()` gates every layer beneath it in the stack, not just the
/// one immediately after it, so `LogBufferLayer` ends up seeing precisely what `fmt` prints.
pub struct LogBufferLayer {
    buffer: Arc<LogBuffer>,
}

impl LogBufferLayer {
    pub fn new(buffer: Arc<LogBuffer>) -> Self {
        Self { buffer }
    }
}

impl<S> Layer<S> for LogBufferLayer
where
    S: tracing::Subscriber,
{
    fn on_event(&self, event: &tracing::Event<'_>, _ctx: Context<'_, S>) {
        let mut visitor = MessageVisitor::default();
        event.record(&mut visitor);
        let metadata = event.metadata();
        self.buffer.push(LogEntry {
            timestamp: chrono::Utc::now().to_rfc3339(),
            level: metadata.level().to_string(),
            target: metadata.target().to_string(),
            message: visitor.message,
        });
    }
}

/// Extracts the formatted `message` field off a tracing event. `Visit::record_debug` receives
/// `&dyn Debug`; for the well-known `message` field, that value is always a
/// `std::fmt::Arguments`, whose `Debug` impl is defined (in `core::fmt`) to delegate straight to
/// its `Display` impl - so this yields the same plain text `tracing_subscriber::fmt`'s own
/// formatter would print, never a `{:?}`-quoted debug rendering. Non-`message` fields (structured
/// key-value pairs recorded alongside the event) are not captured here; the brief's "formatted
/// message" is this field alone.
#[derive(Default)]
struct MessageVisitor {
    message: String,
}

impl Visit for MessageVisitor {
    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        if field.name() == "message" {
            self.message = format!("{value:?}");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(message: &str) -> LogEntry {
        LogEntry {
            timestamp: "2026-08-19T00:00:00Z".to_string(),
            level: "INFO".to_string(),
            target: "test".to_string(),
            message: message.to_string(),
        }
    }

    #[test]
    fn snapshot_returns_pushed_entries_oldest_first() {
        let buf = LogBuffer::new(10);
        buf.push(entry("first"));
        buf.push(entry("second"));

        let snap = buf.snapshot();

        assert_eq!(snap.len(), 2);
        assert_eq!(snap[0].message, "first");
        assert_eq!(snap[1].message, "second");
    }

    #[test]
    fn ring_evicts_oldest_once_capacity_reached() {
        let buf = LogBuffer::new(2);
        buf.push(entry("a"));
        buf.push(entry("b"));
        buf.push(entry("c"));

        let snap = buf.snapshot();

        assert_eq!(snap.len(), 2);
        assert_eq!(snap[0].message, "b");
        assert_eq!(snap[1].message, "c");
    }

    #[tokio::test]
    async fn subscriber_receives_entries_pushed_after_it_attaches() {
        let buf = LogBuffer::new(10);
        buf.push(entry("before"));
        let mut rx = buf.subscribe();
        buf.push(entry("after"));

        let received = rx.recv().await.unwrap();

        assert_eq!(received.message, "after");
    }

    #[test]
    fn push_with_no_subscribers_does_not_panic() {
        let buf = LogBuffer::new(10);
        buf.push(entry("no one is listening"));
        assert_eq!(buf.snapshot().len(), 1);
    }
}
