//! In-memory ring buffer of recent tracing events plus a live broadcast channel, backing
//! `routes::logs`'s viewer page and its `/logs/stream` SSE endpoint
//! (`internal/design/11-console-forensics.md`, task 7 "Live system log"). `propolis::main` builds
//! one `Arc<LogBuffer>` at startup, installs a `tracing_subscriber::Layer` that pushes every event
//! the process logs into it, and hands the same `Arc` to `AppState::log_buffer` - so the buffer is
//! the single shared sink between the tracing pipeline and the console.
//!
//! `snapshot()` backs the page's initial render (everything currently held, oldest first);
//! `subscribe()` backs the SSE stream (every entry pushed *after* the subscriber attaches). A
//! subscriber that falls behind the broadcast channel's internal buffer sees a `Lagged` error on
//! `recv()` - `routes::logs::logs_stream` skips those and keeps reading rather than treating them
//! as a stream-ending failure, since the ring buffer (not the broadcast channel) is the durable
//! record; a slow browser tab missing a few live lines is an acceptable trade-off for not blocking
//! the writer side.
//!
//! Each entry keeps the event's structured fields (`sensor`, `ingested`, `statement`, `elapsed`,
//! `reason`, ...) next to its message: the message alone ("slow statement", "submission held") says
//! that something happened but not to what. What one entry may hold is capped when it is captured
//! ([`MAX_MESSAGE_BYTES`], [`MAX_FIELD_VALUE_BYTES`], [`MAX_FIELDS`]), and the ring is held to a
//! byte budget charged from the strings' real allocated capacity ([`RING_BYTE_BUDGET`]) as well as
//! to its entry count, so a process that logs large fields keeps fewer entries rather than more
//! memory.

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

use serde::Serialize;
use tokio::sync::broadcast;
use tracing::field::Visit;
use tracing_subscriber::Layer;
use tracing_subscriber::layer::Context;

/// Longest message kept, in bytes; a longer one is cut at a character boundary and marked.
pub const MAX_MESSAGE_BYTES: usize = 2048;
/// Longest field value kept, in bytes; a longer one is cut at a character boundary and marked.
pub const MAX_FIELD_VALUE_BYTES: usize = 512;
/// Most fields kept per entry. Further fields are counted into one `fields_dropped` field.
pub const MAX_FIELDS: usize = 32;
/// The ring's total charge (see [`LogEntry::charged_bytes`]): oldest entries are evicted until a
/// new one fits. 2 MiB holds the full 1000-entry history at ordinary record sizes, and caps it
/// when records are large.
pub const RING_BYTE_BUDGET: usize = 2 * 1024 * 1024;

/// Appended to a value or message that was cut to its cap.
const TRUNCATION_MARK: &str = " [truncated]";

/// One structured key=value pair recorded on a tracing event, its value already rendered as text.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct LogField {
    pub key: String,
    pub value: String,
}

/// One captured tracing event, already formatted for display - never re-parsed from the original
/// `tracing::Event`, which does not outlive its callback.
#[derive(Debug, Clone, Serialize)]
pub struct LogEntry {
    pub timestamp: String,
    pub level: String,
    pub target: String,
    pub message: String,
    /// The event's fields other than `message`, in the order the event recorded them.
    pub fields: Vec<LogField>,
}

impl LogEntry {
    /// Bytes this entry holds on the heap plus its own size: the allocated capacity of every
    /// string and of the field vector, not their lengths, since capacity is what is allocated.
    pub fn charged_bytes(&self) -> usize {
        std::mem::size_of::<LogEntry>()
            + self.timestamp.capacity()
            + self.level.capacity()
            + self.target.capacity()
            + self.message.capacity()
            + self.fields.capacity() * std::mem::size_of::<LogField>()
            + self
                .fields
                .iter()
                .map(|f| f.key.capacity() + f.value.capacity())
                .sum::<usize>()
    }
}

/// Bounded ring buffer (at most `capacity` entries and [`RING_BYTE_BUDGET`] charged bytes, oldest
/// evicted first) plus a broadcast channel for live tailing. The ring and the channel are
/// independent: a value pushed lands in both, but a broadcast subscriber that started after the
/// push never sees it via the channel - only `snapshot()` recovers history, matching the
/// page-load/live-stream split above.
pub struct LogBuffer {
    ring: Mutex<Ring>,
    tx: broadcast::Sender<LogEntry>,
    capacity: usize,
    byte_budget: usize,
}

struct Ring {
    entries: VecDeque<LogEntry>,
    charged: usize,
}

/// Broadcast channel capacity - how many not-yet-received live entries a lagging subscriber may
/// fall behind by before `recv()` reports `Lagged`. Independent of the ring buffer's `capacity`
/// (which bounds *history*, not the live channel's backlog). Each entry is capped at capture, so
/// this bounds the channel's memory too.
const CHANNEL_CAPACITY: usize = 256;

impl LogBuffer {
    pub fn new(capacity: usize) -> Self {
        Self::with_byte_budget(capacity, RING_BYTE_BUDGET)
    }

    /// [`LogBuffer::new`] with an explicit byte budget, for tests that need eviction to happen
    /// at a size they can reach.
    pub fn with_byte_budget(capacity: usize, byte_budget: usize) -> Self {
        let (tx, _) = broadcast::channel(CHANNEL_CAPACITY);
        Self {
            ring: Mutex::new(Ring {
                entries: VecDeque::with_capacity(capacity),
                charged: 0,
            }),
            tx,
            capacity,
            byte_budget,
        }
    }

    /// Appends `entry` to the ring (evicting the oldest entries until both the entry count and the
    /// byte budget allow it) and broadcasts it to every live subscriber. `send` returning `Err`
    /// just means no subscriber is currently attached (no SSE client connected) - not a failure
    /// worth logging, since logging it would itself push another entry through this same path.
    pub fn push(&self, entry: LogEntry) {
        let charge = entry.charged_bytes();
        let mut ring = self.ring.lock().unwrap_or_else(|e| e.into_inner());
        while let Some(oldest) = ring.entries.front() {
            if ring.entries.len() < self.capacity && ring.charged + charge <= self.byte_budget {
                break;
            }
            let freed = oldest.charged_bytes();
            ring.entries.pop_front();
            ring.charged -= freed;
        }
        if self.capacity > 0 && charge <= self.byte_budget {
            ring.entries.push_back(entry.clone());
            ring.charged += charge;
        }
        drop(ring);
        let _ = self.tx.send(entry);
    }

    /// Every entry currently held, oldest first.
    pub fn snapshot(&self) -> Vec<LogEntry> {
        self.ring
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .entries
            .iter()
            .cloned()
            .collect()
    }

    /// The ring's current charge in bytes, never above the budget it was built with.
    pub fn charged_bytes(&self) -> usize {
        self.ring.lock().unwrap_or_else(|e| e.into_inner()).charged
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
        let mut visitor = FieldVisitor::default();
        event.record(&mut visitor);
        let metadata = event.metadata();
        let mut fields = visitor.fields;
        if visitor.dropped > 0 {
            fields.push(LogField {
                key: "fields_dropped".to_string(),
                value: visitor.dropped.to_string(),
            });
        }
        fields.shrink_to_fit();
        self.buffer.push(LogEntry {
            timestamp: chrono::Utc::now().to_rfc3339(),
            level: metadata.level().to_string(),
            target: metadata.target().to_string(),
            message: capped(visitor.message, MAX_MESSAGE_BYTES),
            fields,
        });
    }
}

/// `text` cut to at most `max` bytes at a character boundary, marked when cut, with its
/// allocation shrunk to what it holds.
fn capped(mut text: String, max: usize) -> String {
    if text.len() > max {
        let mut cut = max;
        while !text.is_char_boundary(cut) {
            cut -= 1;
        }
        text.truncate(cut);
        text.push_str(TRUNCATION_MARK);
    }
    text.shrink_to_fit();
    text
}

/// Collects a tracing event's `message` and its other fields. `Visit::record_debug` receives
/// `&dyn Debug`; for the well-known `message` field, that value is always a
/// `std::fmt::Arguments`, whose `Debug` impl is defined (in `core::fmt`) to delegate straight to
/// its `Display` impl - so this yields the same plain text `tracing_subscriber::fmt`'s own
/// formatter would print, never a `{:?}`-quoted debug rendering. String fields arrive through
/// `record_str` and are kept unquoted for the same reason; every other value is its `Debug` text,
/// which is what `fmt` prints for it too.
#[derive(Default)]
struct FieldVisitor {
    message: String,
    fields: Vec<LogField>,
    dropped: usize,
}

impl FieldVisitor {
    fn push(&mut self, key: &str, value: String) {
        if self.fields.len() >= MAX_FIELDS {
            self.dropped += 1;
            return;
        }
        self.fields.push(LogField {
            key: key.to_string(),
            value: capped(value, MAX_FIELD_VALUE_BYTES),
        });
    }
}

impl Visit for FieldVisitor {
    fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
        if field.name() == "message" {
            self.message = value.to_string();
        } else {
            // Copy at most one character past the cap, so a huge value is never cloned whole and
            // `capped` still sees that it ran over and marks the cut.
            let mut end = value.len().min(MAX_FIELD_VALUE_BYTES + 4);
            while !value.is_char_boundary(end) {
                end -= 1;
            }
            self.push(field.name(), value[..end].to_string());
        }
    }

    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        if field.name() == "message" {
            self.message = format!("{value:?}");
        } else {
            self.push(field.name(), format!("{value:?}"));
        }
    }
}

#[cfg(test)]
mod tests {
    use tracing_subscriber::prelude::*;

    use super::*;

    fn entry(message: &str) -> LogEntry {
        LogEntry {
            timestamp: "2026-08-19T00:00:00Z".to_string(),
            level: "INFO".to_string(),
            target: "test".to_string(),
            message: message.to_string(),
            fields: Vec::new(),
        }
    }

    /// Runs `f` with a subscriber whose only layer captures into a fresh buffer, and returns
    /// what it captured.
    fn capture(f: impl FnOnce()) -> Vec<LogEntry> {
        let buffer = Arc::new(LogBuffer::new(100));
        let subscriber = tracing_subscriber::registry().with(LogBufferLayer::new(buffer.clone()));
        tracing::subscriber::with_default(subscriber, f);
        buffer.snapshot()
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

    #[test]
    fn the_layer_keeps_structured_fields_unquoted_and_in_order() {
        let captured = capture(|| {
            tracing::warn!(
                statement = "SELECT 1",
                elapsed = ?std::time::Duration::from_millis(1500),
                rows = 3u64,
                ok = false,
                "slow statement"
            );
        });

        assert_eq!(captured.len(), 1);
        let e = &captured[0];
        assert_eq!(e.level, "WARN");
        assert_eq!(e.message, "slow statement");
        let pairs: Vec<(&str, &str)> = e
            .fields
            .iter()
            .map(|f| (f.key.as_str(), f.value.as_str()))
            .collect();
        assert_eq!(
            pairs,
            [
                ("statement", "SELECT 1"),
                ("elapsed", "1.5s"),
                ("rows", "3"),
                ("ok", "false"),
            ]
        );
    }

    #[test]
    fn the_layer_caps_message_values_and_field_count() {
        let long = "é".repeat(MAX_FIELD_VALUE_BYTES);
        let message = "m".repeat(MAX_MESSAGE_BYTES * 2);
        let captured = capture(|| {
            tracing::info!(value = long.as_str(), debugged = ?long, "{message}");
        });
        let e = &captured[0];
        assert!(e.message.len() <= MAX_MESSAGE_BYTES + TRUNCATION_MARK.len());
        assert!(e.message.ends_with(TRUNCATION_MARK));
        for f in &e.fields {
            assert!(
                f.value.len() <= MAX_FIELD_VALUE_BYTES + TRUNCATION_MARK.len(),
                "{} kept {} bytes",
                f.key,
                f.value.len()
            );
            assert!(f.value.ends_with(TRUNCATION_MARK), "{}", f.key);
        }

        let many = capture(|| {
            tracing::info!(
                a0 = 0,
                a1 = 1,
                a2 = 2,
                a3 = 3,
                a4 = 4,
                a5 = 5,
                a6 = 6,
                a7 = 7,
                a8 = 8,
                a9 = 9,
                b0 = 0,
                b1 = 1,
                b2 = 2,
                b3 = 3,
                b4 = 4,
                b5 = 5,
                b6 = 6,
                b7 = 7,
                b8 = 8,
                b9 = 9,
                c0 = 0,
                c1 = 1,
                c2 = 2,
                c3 = 3,
                c4 = 4,
                c5 = 5,
                c6 = 6,
                c7 = 7,
                c8 = 8,
                c9 = 9,
                d0 = 0,
                d1 = 1,
                d2 = 2,
                d3 = 3,
                d4 = 4,
                "wide"
            );
        });
        let fields = &many[0].fields;
        assert_eq!(fields.len(), MAX_FIELDS + 1);
        assert_eq!(fields[MAX_FIELDS].key, "fields_dropped");
        assert_eq!(fields[MAX_FIELDS].value, "3");
    }

    #[test]
    fn the_ring_holds_to_its_byte_budget_by_evicting_oldest() {
        let one = {
            let mut e = entry("x");
            e.fields.push(LogField {
                key: "k".into(),
                value: "v".repeat(400),
            });
            e
        };
        // Charged from a clone: cloning drops the spare capacity `push` gave the field vector,
        // and every pushed entry below is a clone.
        let charge = one.clone().charged_bytes();
        // Room for exactly three such entries, far fewer than the entry cap.
        let buf = LogBuffer::with_byte_budget(1000, charge * 3 + charge / 2);
        for n in 0..10 {
            let mut e = one.clone();
            e.message = format!("{n}");
            e.message.shrink_to_fit();
            buf.push(e);
        }

        let snap = buf.snapshot();
        let kept: Vec<&str> = snap.iter().map(|e| e.message.as_str()).collect();
        assert_eq!(kept, ["7", "8", "9"]);
        assert!(buf.charged_bytes() <= charge * 3 + charge / 2);
        assert_eq!(
            buf.charged_bytes(),
            snap.iter().map(LogEntry::charged_bytes).sum::<usize>()
        );
    }
}
