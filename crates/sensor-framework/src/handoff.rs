//! Off-response-path capture hand-off: the bounded in-process queue and single worker task that
//! turn a captured body into a spooled file and an emitted event, without the connection's reply
//! path ever waiting on either. See "Off-response-path capture hand-off" in
//! `internal/design/02-sensor-framework.md`: the reason this exists is covertness, not
//! throughput - an attacker measuring response latency is measuring exactly the work that only
//! happens when something is worth capturing, so doing it inline announces the capture. A
//! sensor's handler therefore does no more than build a `CaptureJob` and `submit` it once it has
//! read enough to answer the protocol; hashing the body, writing it to the spool, and appending
//! the event all happen later, off that path, in the worker `start_worker` spawns.
//!
//! **A full queue drops the job and increments a counter; `submit` never blocks the caller.**
//! `submit` is backed by `mpsc::Sender::try_send`, which returns immediately either way, so there
//! is no path by which enqueuing can stall a connection's response even under the exact
//! saturation an attacker can induce on purpose.
//!
//! **Exactly one worker ever drains the queue, and it does so strictly sequentially.**
//! `mpsc::channel` hands out exactly one `Receiver`; `start_worker` moves it out of a
//! `Mutex<Option<_>>` on its first call and panics on any later call (see its doc), so at most
//! one task ever calls `recv()`. That task's loop processes one job to completion - including its
//! synchronous call into `QuarantineSpool::store` - before it calls `recv().await` again, so
//! `store` is never invoked concurrently with itself by this component, no matter how many
//! producer tasks race `submit` concurrently. This confirms, rather than merely repeats, the
//! assumption `spool.rs`'s own doc comment carries forward from Task 4: the narrow `create_new`
//! race in `store`'s dedup path (two callers racing to store identical content) is not this
//! system's real access pattern.
//!
//! `orig_name` is sanitized here, not by each sensor, before it is written onto the `SampleRef` -
//! see `spool.rs`'s `store` doc, which places that obligation on whoever calls `store` and then
//! fills in the returned ref's `orig_name`. In this system that caller is always this worker (no
//! other code ever calls `QuarantineSpool::store`), so the framework enforces the requirement
//! structurally here rather than trusting every current and future sensor to remember it
//! independently - matching this crate's standing pattern (`sanitize.rs`, `bounds.rs`,
//! `config.rs`): a sensor has no route to a record that bypasses it.
//!
//! A job whose `event_builder` panics - a bug in a sensor's own closure, working on
//! attacker-influenced data - is isolated the same way `listener.rs` isolates a panicking
//! per-connection handler: caught, logged, and dropped, with the worker's loop continuing to
//! drain later jobs. Unlike the listener, this is a synchronous `std::panic::catch_unwind` around
//! the non-async portion of the work rather than a per-job `tokio::spawn`, specifically so that
//! isolating a panic does not reintroduce concurrent `store` calls and undo the previous
//! paragraph's guarantee.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use sensor_wire::{SampleRef, SensorEvent};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

use crate::emit::EventEmitter;
use crate::outbox::{CustodyDisposition, CustodyState, ManifestRow, OutboxManifest};
use crate::sanitize::sanitize_value;
use crate::spool::QuarantineSpool;

/// POSIX `NAME_MAX`: the conventional ceiling on one filename component on Linux (ext4, btrfs,
/// xfs, ...). `orig_name` is attacker-supplied free text carried purely as an indicator (see
/// `spool.rs`'s `store` doc and the design doc's "Sample side channel": "never used as a path
/// component"), so this bounds it to what a real filename could plausibly be rather than an
/// arbitrary cap.
const MAX_ORIG_NAME_LEN: usize = 255;

/// One capture awaiting hand-off: a body already fully read off the wire, the attacker-supplied
/// filename if the protocol carries one (SCP/SFTP; empty where it does not, e.g. the catch-all's
/// raw payload), and the closure that builds the sensor's own `SensorEvent` once the `SampleRef`
/// is known - deferred because the ref's `sha256`/`size` do not exist until the worker has
/// actually hashed and stored the body.
pub struct CaptureJob {
    pub body: Vec<u8>,
    pub orig_name: String,
    pub event_builder: Box<dyn FnOnce(SampleRef) -> SensorEvent + Send>,
}

/// The `honeypot_malware_upload` metadata object every body-capturing sensor emits, built in one
/// place so the keys cannot drift between sensors. `wire_size` is how many body bytes the client
/// actually sent; `sample.size` is how many were retained. Sensors cap the body they keep (SCP,
/// SFTP and ADB retain a 10 MB prefix and drain the rest to keep the protocol aligned), and an
/// analysis of the prefix must never be read as an analysis of the file: `truncated` says the
/// hash and size describe a prefix, and `wire_size` says how big the real upload was.
/// `complete` says whether the transfer ended the way its protocol defines the end of a file
/// (SCP's trailer, SFTP's CLOSE, ADB's DONE, FTP's data-connection close); false means the
/// session ended, stalled or was cut off with the transfer still open, so the body is a fragment
/// of whatever was being sent, kept because a fragment of a dropper is still evidence.
pub fn upload_metadata(
    protocol_label: &str,
    sample: &SampleRef,
    wire_size: u64,
    complete: bool,
) -> serde_json::Value {
    serde_json::json!({
        "protocol_label": protocol_label,
        "sha256": sample.sha256,
        "size": sample.size,
        "orig_name": sample.orig_name,
        "wire_size": wire_size,
        "truncated": wire_size > sample.size,
        "complete": complete,
    })
}

/// `submit` could not enqueue the job because the queue was already at capacity. `submit` never
/// waits for room (see the module doc), so this is the immediate, synchronous outcome of a full
/// queue, not a timeout or a retry-later signal.
#[derive(Debug)]
pub struct CaptureDropped;

impl std::fmt::Display for CaptureDropped {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "capture queue full; job dropped")
    }
}

impl std::error::Error for CaptureDropped {}

/// Owns the queue, the drop counter, and the spool/emitter every enqueued job is eventually
/// processed against. Cheap to share: construct one per sensor process, wrap it in an `Arc`, and
/// clone that into every connection handler - `submit` and `dropped_count` take `&self`, and
/// `start_worker` is meant to be called exactly once regardless of how many handlers share the
/// `Arc`.
pub struct CaptureHandoff {
    tx: mpsc::Sender<CaptureJob>,
    rx: Mutex<Option<mpsc::Receiver<CaptureJob>>>,
    dropped: AtomicU64,
    /// Captures the worker discarded because the spool refused the body (per-file cap or exhausted
    /// global budget). Behind an `Arc` because the worker task increments it; `submit` touches only
    /// `dropped`. Its counterpart accessor is `spool_refused_count`.
    spool_refused: Arc<AtomicU64>,
    spool: Arc<QuarantineSpool>,
    emitter: Arc<EventEmitter>,
    /// Stamped onto every manifest row this hand-off's worker writes - see `new`'s doc for why
    /// this must equal the cert CommonName the shipper on this box validates.
    collector_id: String,
    /// Durable per-capture custody record store (SP-B-1b). See `process_job`'s doc for the
    /// ordering guarantee this exists to provide.
    outbox: Arc<OutboxManifest>,
}

impl CaptureHandoff {
    /// `queue_size` is the operator-configured `SensorConfig::capture_queue_size`: the number of
    /// jobs the in-process channel holds before `submit` starts dropping. Constructing a
    /// `CaptureHandoff` does not spawn a worker - call `start_worker` separately - so a caller
    /// that wants to observe drop behavior in isolation (as `full_queue_drops_and_counts` and
    /// `producer_never_blocks` below do) can simply not start one.
    ///
    /// `collector_id` is stamped onto every outbox manifest row the worker writes. It MUST equal
    /// the CommonName of the mTLS client certificate the shipper on this box presents to the
    /// gateway (`shipper::config::validate_collector_id` enforces the matching constraint on that
    /// side), because a later stage joins the gateway's cert-derived collector_id against this
    /// manifest on `(collector_id, occurrence_id)` - a divergent or hardcoded value here would
    /// silently break that join. In a single-node deployment with no shipper configured, pass
    /// `"local"` so the record is still well-formed. `outbox` is the durable manifest store the
    /// worker writes a `pending` row to for every captured body.
    pub fn new(
        spool: QuarantineSpool,
        emitter: EventEmitter,
        queue_size: usize,
        collector_id: String,
        outbox: OutboxManifest,
    ) -> Self {
        let (tx, rx) = mpsc::channel(queue_size);
        Self {
            tx,
            rx: Mutex::new(Some(rx)),
            dropped: AtomicU64::new(0),
            spool_refused: Arc::new(AtomicU64::new(0)),
            spool: Arc::new(spool),
            emitter: Arc::new(emitter),
            collector_id,
            outbox: Arc::new(outbox),
        }
    }

    /// Enqueue a capture job. Never blocks: backed by `try_send`, which returns immediately
    /// whether or not the queue had room. A full queue is reported as `Err(CaptureDropped)` and
    /// counted against `dropped_count`, never waited out - see the module doc for why blocking
    /// here would defeat the hand-off's entire reason for existing.
    pub fn submit(&self, job: CaptureJob) -> Result<(), CaptureDropped> {
        self.tx.try_send(job).map_err(|_| {
            let dropped = self.dropped.fetch_add(1, Ordering::Relaxed) + 1;
            // The drop is deliberate (covertness over completeness), but it must not be SILENT: an
            // attacker can induce it by flooding uploads past the single worker's drain rate, and
            // every caller discards this Err. Log at power-of-two totals so the first drop is loud
            // and a sustained flood degrades to logarithmic noise rather than spamming - and
            // filling - the very log partition the operator relies on.
            if dropped.is_power_of_two() {
                tracing::warn!(
                    dropped_total = dropped,
                    "capture hand-off: queue full, sample dropped (no spool, no event)"
                );
            }
            CaptureDropped
        })
    }

    /// Total jobs `submit` has rejected for a full queue since construction: the operator-visible
    /// metric the design doc calls for - "under overload this layer loses a sample rather than
    /// its covertness, and the drop is a metric the operator can see."
    pub fn dropped_count(&self) -> u64 {
        self.dropped.load(Ordering::Relaxed)
    }

    /// Total captures the worker discarded because the spool refused the body - the per-file cap or
    /// the exhausted global budget (`spool.rs`). Unlike a queue drop, a spool refusal yields neither
    /// a stored sample nor an event, so this counter is the only in-process record that a capture
    /// was lost there; surfaced (alongside a per-refusal WARN) so the loss is a metric the operator
    /// can read rather than a silent gap.
    pub fn spool_refused_count(&self) -> u64 {
        self.spool_refused.load(Ordering::Relaxed)
    }

    /// Spawn the single task that drains the queue: for each job, hash and store its body,
    /// sanitize and fill in `orig_name`, build the event, and append it. See the module doc for
    /// why this runs each job synchronously (no per-job spawn) and why that is exactly what keeps
    /// `store` calls serialized.
    ///
    /// `mpsc::channel` hands out exactly one `Receiver`, held here behind a `Mutex<Option<_>>` so
    /// this method can take `&self` rather than `&mut self` (every handler sharing this hand-off
    /// via `Arc` only ever gets `&self`). Calling it again finds the option already empty and
    /// panics, rather than silently spawning a second worker that would race the first for jobs
    /// and break the single-worker guarantee the module doc describes.
    ///
    /// # Panics
    /// If called more than once on the same `CaptureHandoff`.
    pub fn start_worker(&self) -> JoinHandle<()> {
        let mut rx = self
            .rx
            .lock()
            .unwrap()
            .take()
            .expect("CaptureHandoff::start_worker called more than once");
        let spool = self.spool.clone();
        let emitter = self.emitter.clone();
        let spool_refused = self.spool_refused.clone();
        let collector_id = self.collector_id.clone();
        let outbox = self.outbox.clone();

        tokio::spawn(async move {
            while let Some(job) = rx.recv().await {
                process_job(
                    &spool,
                    &emitter,
                    &spool_refused,
                    &collector_id,
                    &outbox,
                    job,
                )
                .await;
            }
        })
    }
}

/// Process exactly one job to completion: store, sanitize `orig_name`, build the event, write the
/// event's durable outbox manifest row, then emit. Never propagates a panic - see the module doc
/// for why a panicking `event_builder` (a bug in a sensor's own closure) must not end the worker
/// loop every later job still depends on.
///
/// Ordering (SP-B-1b): by the time this reaches the `Ok(Ok(event))` arm, `store` has already
/// sealed and fsynced the body (`spool.rs`). The manifest row is written fsync-durable BEFORE
/// `append`, deliberately: a body's custody record must exist as soon as the body itself is
/// durable, not only once the event has also been logged. A crash between the manifest write and
/// `append` leaves a `pending` orphan manifest whose `occurrence_id` never reaches the event
/// stream - that is the intended safe failure (body + custody record both retained; a later
/// reconciliation flags the orphan), not a case this function tries to make transactional. A
/// crash between `store` and the manifest write leaves a body with no custody record at all -
/// identical to today's behavior, handled by the existing spool orphan sweep; no regression.
async fn process_job(
    spool: &QuarantineSpool,
    emitter: &EventEmitter,
    spool_refused: &AtomicU64,
    collector_id: &str,
    outbox: &OutboxManifest,
    job: CaptureJob,
) {
    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        spool.store(&job.body).map(|mut sample_ref| {
            sample_ref.orig_name = sanitize_value(&job.orig_name, MAX_ORIG_NAME_LEN);
            (job.event_builder)(sample_ref)
        })
    }));

    let mut event = match outcome {
        Ok(Ok(event)) => event,
        Ok(Err(e)) => {
            let refused = spool_refused.fetch_add(1, Ordering::Relaxed) + 1;
            tracing::warn!(
                error = %e,
                spool_refused_total = refused,
                "capture hand-off: spool refused body; sample not retained, no event emitted"
            );
            return;
        }
        Err(payload) => {
            tracing::error!(
                panic = %panic_message(&*payload),
                "capture hand-off: job processing panicked; job dropped, worker continues"
            );
            return;
        }
    };

    // Mint the per-event id here, once, so the manifest and the emitted event share it:
    // `EventEmitter::append` preserves an already-present `occurrence_id` rather than re-minting
    // one, so this is the single point of truth both records agree on.
    let occurrence_id = uuid::Uuid::now_v7();
    event.occurrence_id = Some(occurrence_id);

    // Body-bearing events always carry a sample; if for some reason one does not, skip the
    // manifest but still emit - defensively, since the manifest is a body-custody record and
    // there is no body to record custody of.
    if let Some(sample) = event.sample.clone()
        && let Some(capture_id) = sample.capture_id
    {
        let row = ManifestRow {
            collector_id: collector_id.to_string(),
            capture_id,
            occurrence_id,
            sha256: sample.sha256.clone(),
            size: sample.size,
            body_key: sample.sha256.clone(),
            gateway_spool_state: CustodyState::Pending,
            cas_state: CustodyState::Pending,
            custody_state: CustodyDisposition::Pending,
        };
        if let Err(e) = outbox.write(&row) {
            tracing::error!(
                error = %e,
                %occurrence_id,
                "capture hand-off: outbox manifest write failed; body retained, event still emitted"
            );
            // The event is not lost for this: it still emits below. The body and its bytes stay
            // on disk regardless (store already succeeded), so no data is destroyed - only the
            // custody record is missing until reconciliation notices.
        }
    }

    if let Err(e) = emitter.append(&event).await {
        tracing::error!(
            error = %e,
            "capture hand-off: event emit failed after spool store succeeded"
        );
    }
}

/// Best-effort extraction of a human-readable message from a caught panic payload, for the log
/// line only - `panic!`/`.unwrap()`/`.expect()` payloads are almost always `&str` or `String`; any
/// other payload type still gets logged, just without its own text.
fn panic_message(payload: &(dyn std::any::Any + Send)) -> &str {
    if let Some(s) = payload.downcast_ref::<&str>() {
        s
    } else if let Some(s) = payload.downcast_ref::<String>() {
        s.as_str()
    } else {
        "non-string panic payload"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sensor_wire::*;
    use std::time::Duration;

    fn sample(size: u64) -> SampleRef {
        SampleRef {
            sha256: "ab".repeat(32),
            size,
            orig_name: "payload.bin".into(),
            capture_id: None,
        }
    }

    #[test]
    fn upload_metadata_marks_a_capped_body_as_truncated_with_the_real_wire_size() {
        let m = upload_metadata("ssh", &sample(10_000_000), 12_000_000, true);
        assert_eq!(m["truncated"], true);
        assert_eq!(m["wire_size"], 12_000_000u64);
        assert_eq!(m["size"], 10_000_000u64);
        assert_eq!(m["protocol_label"], "ssh");
        assert_eq!(m["sha256"], "ab".repeat(32));
        assert_eq!(m["orig_name"], "payload.bin");
        assert_eq!(m["complete"], true);
    }

    #[test]
    fn upload_metadata_marks_a_complete_body_as_not_truncated() {
        let m = upload_metadata("adb", &sample(4096), 4096, true);
        assert_eq!(m["truncated"], false);
        assert_eq!(m["wire_size"], 4096u64);
    }

    /// A fragment below the cap is not truncated by the sensor, but it is not the file either.
    #[test]
    fn upload_metadata_keeps_incomplete_distinct_from_truncated() {
        let m = upload_metadata("ssh", &sample(4096), 4096, false);
        assert_eq!(m["truncated"], false);
        assert_eq!(m["complete"], false);
    }

    /// Builds a `CaptureHandoff` wired to an `OutboxManifest` under `base_dir.join("outbox")`,
    /// with `"test"` as its `collector_id` - used by every test below that does not itself care
    /// about the manifest, so none has to spell out the SP-B-1b arguments `CaptureHandoff::new`
    /// grew on top of the pre-existing `(spool, emitter, queue_size)`.
    fn test_handoff(
        spool: crate::spool::QuarantineSpool,
        emitter: crate::emit::EventEmitter,
        queue_size: usize,
        base_dir: &std::path::Path,
    ) -> CaptureHandoff {
        CaptureHandoff::new(
            spool,
            emitter,
            queue_size,
            "test".to_string(),
            crate::outbox::OutboxManifest::new(base_dir.join("outbox")),
        )
    }

    /// Waits until the event log holds `n` lines, failing after a generous deadline. The worker
    /// hashes, stores and fsyncs each body before it appends the event, and a fixed sleep raced
    /// that on a loaded CI runner (14 of 20 events had landed when the 300 ms sleep expired).
    async fn wait_for_lines(path: &std::path::Path, n: usize) {
        let deadline = std::time::Instant::now() + Duration::from_secs(15);
        loop {
            let count = tokio::fs::read_to_string(path)
                .await
                .map(|c| c.lines().count())
                .unwrap_or(0);
            if count >= n {
                return;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "timed out waiting for {n} event line(s); the worker had written {count}"
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }

    fn test_event(sample: Option<SampleRef>) -> SensorEvent {
        SensorEvent {
            v: WIRE_VERSION,
            source_ip: "203.0.113.7".parse().unwrap(),
            wan_ip: None,
            sensor: "test".into(),
            signal_type: SIGNAL_HONEYPOT_MALWARE_UPLOAD.into(),
            protocol: PROTO_TCP.into(),
            authenticated: true,
            observed_at: chrono::Utc::now(),
            metadata: serde_json::json!({}),
            sample,
            session_id: None,
            occurrence_id: None,
        }
    }

    #[tokio::test]
    async fn submit_and_worker_processes() {
        let dir = tempfile::tempdir().unwrap();
        let spool_dir = dir.path().join("spool");
        std::fs::create_dir(&spool_dir).unwrap();
        let log_path = dir.path().join("events.jsonl");
        let spool = crate::spool::QuarantineSpool::new(spool_dir, 4096, 1_000_000);
        let emitter = crate::emit::EventEmitter::new(log_path.clone());
        let handoff = test_handoff(spool, emitter, 16, dir.path());
        let worker = handoff.start_worker();

        let body = b"malware payload".to_vec();
        handoff
            .submit(CaptureJob {
                body,
                orig_name: "evil.bin".into(),
                event_builder: Box::new(|sample| test_event(Some(sample))),
            })
            .unwrap();

        // Give worker time to process.
        wait_for_lines(&log_path, 1).await;
        worker.abort();

        let content = tokio::fs::read_to_string(&log_path).await.unwrap();
        let lines: Vec<&str> = content.lines().collect();
        assert_eq!(lines.len(), 1);
        let event: SensorEvent = serde_json::from_str(lines[0]).unwrap();
        assert!(event.sample.is_some());
        let sample = event.sample.unwrap();
        assert!(!sample.sha256.is_empty());
        assert_eq!(sample.size, b"malware payload".len() as u64);
    }

    #[tokio::test]
    async fn full_queue_drops_and_counts() {
        let dir = tempfile::tempdir().unwrap();
        let spool_dir = dir.path().join("spool");
        std::fs::create_dir(&spool_dir).unwrap();
        let spool = crate::spool::QuarantineSpool::new(spool_dir, 4096, 1_000_000);
        let emitter = crate::emit::EventEmitter::new(dir.path().join("events.jsonl"));
        // Queue size 1, no worker draining - so second submit should drop.
        let handoff = test_handoff(spool, emitter, 1, dir.path());

        let job = || CaptureJob {
            body: b"data".to_vec(),
            orig_name: String::new(),
            event_builder: Box::new(|s| test_event(Some(s))),
        };
        handoff.submit(job()).unwrap();
        let result = handoff.submit(job());
        assert!(result.is_err());
        assert_eq!(handoff.dropped_count(), 1);
    }

    #[tokio::test]
    async fn producer_never_blocks() {
        let dir = tempfile::tempdir().unwrap();
        let spool_dir = dir.path().join("spool");
        std::fs::create_dir(&spool_dir).unwrap();
        let spool = crate::spool::QuarantineSpool::new(spool_dir, 4096, 1_000_000);
        let emitter = crate::emit::EventEmitter::new(dir.path().join("events.jsonl"));
        let handoff = test_handoff(spool, emitter, 1, dir.path());
        // Fill the queue, then verify submit returns immediately (does not block).
        handoff
            .submit(CaptureJob {
                body: b"first".to_vec(),
                orig_name: String::new(),
                event_builder: Box::new(|s| test_event(Some(s))),
            })
            .unwrap();
        let start = std::time::Instant::now();
        let _ = handoff.submit(CaptureJob {
            body: b"second".to_vec(),
            orig_name: String::new(),
            event_builder: Box::new(|s| test_event(Some(s))),
        });
        assert!(
            start.elapsed() < Duration::from_millis(50),
            "submit must not block"
        );
    }

    // The tests below are not in the task brief's given suite. Each closes a gap the given three
    // tests, or the brief's literal sample implementation, do not exercise or would fail against -
    // see each test's own comment for the specific wrong-but-plausible implementation it rules
    // out, mirroring how Tasks 3-5 documented their own added coverage.

    #[tokio::test]
    async fn orig_name_is_sanitized_before_reaching_the_event() {
        // spool.rs's `store` doc places an explicit obligation on "the caller [that] fills
        // [orig_name] in on the returned SampleRef": it "must route it through sanitize_value
        // first, same as every other attacker-controlled value entering an event." The brief's
        // literal sample skips this entirely (`sample_ref.orig_name = job.orig_name;` with no
        // sanitization), which would let an attacker-chosen filename carrying a CR/LF or an ANSI
        // escape reach the NDJSON log unsanitized - exactly the log-injection threat
        // `sanitize.rs`'s module doc and ADR-0010 exist to close. This test fails against that
        // literal sample and passes here.
        let dir = tempfile::tempdir().unwrap();
        let spool_dir = dir.path().join("spool");
        std::fs::create_dir(&spool_dir).unwrap();
        let log_path = dir.path().join("events.jsonl");
        let spool = crate::spool::QuarantineSpool::new(spool_dir, 4096, 1_000_000);
        let emitter = crate::emit::EventEmitter::new(log_path.clone());
        let handoff = test_handoff(spool, emitter, 16, dir.path());
        let worker = handoff.start_worker();

        let raw_name = "evil\r\n\x1b[31mname\x1b[0m.bin";
        handoff
            .submit(CaptureJob {
                body: b"payload".to_vec(),
                orig_name: raw_name.into(),
                event_builder: Box::new(|sample| test_event(Some(sample))),
            })
            .unwrap();
        wait_for_lines(&log_path, 1).await;
        worker.abort();

        let content = tokio::fs::read_to_string(&log_path).await.unwrap();
        let lines: Vec<&str> = content.lines().collect();
        assert_eq!(lines.len(), 1);
        let event: SensorEvent = serde_json::from_str(lines[0]).unwrap();
        let sample = event.sample.unwrap();
        assert_eq!(
            sample.orig_name,
            crate::sanitize::sanitize_value(raw_name, MAX_ORIG_NAME_LEN)
        );
        assert!(!sample.orig_name.contains('\r'));
        assert!(!sample.orig_name.contains('\n'));
        assert!(!sample.orig_name.contains('\x1b'));
    }

    #[tokio::test]
    async fn start_worker_called_twice_panics() {
        // This is the mechanism that guarantees the module doc's "exactly one worker ever drains
        // the queue" claim rather than just asserting it: only one `Receiver` ever exists, and
        // `start_worker` can only hand it out once. Proving the second call panics closes the
        // loop Task 4's report asked Task 6 to confirm (that `store` calls are truly serialized),
        // instead of leaving it as an unverified assumption.
        let dir = tempfile::tempdir().unwrap();
        let spool_dir = dir.path().join("spool");
        std::fs::create_dir(&spool_dir).unwrap();
        let spool = crate::spool::QuarantineSpool::new(spool_dir, 4096, 1_000_000);
        let emitter = crate::emit::EventEmitter::new(dir.path().join("events.jsonl"));
        let handoff = test_handoff(spool, emitter, 4, dir.path());
        let _first = handoff.start_worker();

        let second =
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| handoff.start_worker()));
        assert!(
            second.is_err(),
            "a second start_worker call must panic, not spawn a second worker"
        );
    }

    #[tokio::test]
    async fn worker_survives_event_builder_panic_and_keeps_processing_later_jobs() {
        // A sensor's `event_builder` closure runs on attacker-influenced data (the SampleRef it
        // builds a metadata-bearing event around) and is caller-supplied, not framework code - a
        // bug in it must not behave like the brief's literal sample, where an uncaught panic
        // unwinds through `tokio::spawn`'s future and ends the worker task for the rest of the
        // sensor's uptime. Job 1's builder panics; job 2 is well-behaved and submitted right
        // after. Under the brief's literal sample the log ends up with 0 lines (the worker died
        // on job 1, job 2 is never drained); with panic isolation it ends up with exactly 1 (job
        // 2's).
        let dir = tempfile::tempdir().unwrap();
        let spool_dir = dir.path().join("spool");
        std::fs::create_dir(&spool_dir).unwrap();
        let log_path = dir.path().join("events.jsonl");
        let spool = crate::spool::QuarantineSpool::new(spool_dir, 4096, 1_000_000);
        let emitter = crate::emit::EventEmitter::new(log_path.clone());
        let handoff = test_handoff(spool, emitter, 16, dir.path());
        let worker = handoff.start_worker();

        handoff
            .submit(CaptureJob {
                body: b"first-panics".to_vec(),
                orig_name: String::new(),
                event_builder: Box::new(|_sample| panic!("simulated buggy sensor closure")),
            })
            .unwrap();
        handoff
            .submit(CaptureJob {
                body: b"second-ok".to_vec(),
                orig_name: String::new(),
                event_builder: Box::new(|sample| test_event(Some(sample))),
            })
            .unwrap();

        wait_for_lines(&log_path, 1).await;
        worker.abort();

        let content = tokio::fs::read_to_string(&log_path).await.unwrap();
        let lines: Vec<&str> = content.lines().collect();
        assert_eq!(
            lines.len(),
            1,
            "job 1's panic must not prevent job 2 from being processed"
        );
        let event: SensorEvent = serde_json::from_str(lines[0]).unwrap();
        let sample = event.sample.unwrap();
        assert_eq!(sample.size, b"second-ok".len() as u64);
    }

    #[tokio::test]
    async fn spool_store_failure_does_not_crash_worker_and_does_not_emit() {
        // A job whose body exceeds the spool's per-file cap makes `store` return `Err`. The
        // worker must log and move on (proving the `Ok(Err(e))` branch does not panic or wedge
        // the loop), and - documenting current, deliberate behavior rather than leaving it a
        // silent gap - no event is emitted for the refused capture, since `CaptureJob`'s frozen
        // `event_builder: FnOnce(SampleRef) -> SensorEvent` shape has no way to build an event
        // without a real `SampleRef` (see the task report's Concerns re: the design doc's "still
        // a recorded sighting" line). A well-behaved job submitted right after still succeeds.
        let dir = tempfile::tempdir().unwrap();
        let spool_dir = dir.path().join("spool");
        std::fs::create_dir(&spool_dir).unwrap();
        let log_path = dir.path().join("events.jsonl");
        let spool = crate::spool::QuarantineSpool::new(spool_dir, 8, 1_000_000);
        let emitter = crate::emit::EventEmitter::new(log_path.clone());
        let handoff = test_handoff(spool, emitter, 16, dir.path());
        let worker = handoff.start_worker();

        handoff
            .submit(CaptureJob {
                body: b"this body exceeds the eight byte limit".to_vec(),
                orig_name: String::new(),
                event_builder: Box::new(|sample| test_event(Some(sample))),
            })
            .unwrap();
        handoff
            .submit(CaptureJob {
                body: b"ok".to_vec(),
                orig_name: String::new(),
                event_builder: Box::new(|sample| test_event(Some(sample))),
            })
            .unwrap();

        wait_for_lines(&log_path, 1).await;
        worker.abort();

        // The spool refusal is now counted (previously it was only a log line with no metric),
        // giving parity with the queue-drop `dropped_count`.
        assert_eq!(handoff.spool_refused_count(), 1);
        assert_eq!(
            handoff.dropped_count(),
            0,
            "neither submit was queue-dropped"
        );

        let content = tokio::fs::read_to_string(&log_path).await.unwrap();
        let lines: Vec<&str> = content.lines().collect();
        assert_eq!(lines.len(), 1, "only the well-behaved job is emitted");
        let event: SensorEvent = serde_json::from_str(lines[0]).unwrap();
        assert_eq!(event.sample.unwrap().size, 2);
    }

    #[test]
    fn dropped_count_exact_under_concurrent_contention() {
        // `submit`/`dropped_count`/`new` are all synchronous - no tokio runtime is needed to
        // exercise them - so this uses real `std::thread::spawn` OS threads, exactly like
        // spool.rs's own `concurrent_stores_respect_budget_and_never_corrupt_content`, rather
        // than tokio tasks cooperatively scheduled on one thread (which a bare `#[tokio::test]`
        // would have been, and would not have actually exercised real parallelism despite
        // looking like a concurrency test). No worker draining; a small fixed capacity. The
        // admitted/dropped split is a hard deterministic bound regardless of scheduling (capacity
        // is fixed at 4; nothing ever drains it), so this is not flaky.
        let dir = tempfile::tempdir().unwrap();
        let spool_dir = dir.path().join("spool");
        std::fs::create_dir(&spool_dir).unwrap();
        let spool = crate::spool::QuarantineSpool::new(spool_dir, 4096, 1_000_000);
        let emitter = crate::emit::EventEmitter::new(dir.path().join("events.jsonl"));
        let handoff = Arc::new(test_handoff(spool, emitter, 4, dir.path()));

        const TASKS: usize = 50;
        let handles: Vec<_> = (0..TASKS)
            .map(|_| {
                let handoff = handoff.clone();
                std::thread::spawn(move || {
                    handoff
                        .submit(CaptureJob {
                            body: b"x".to_vec(),
                            orig_name: String::new(),
                            event_builder: Box::new(|s| test_event(Some(s))),
                        })
                        .is_ok()
                })
            })
            .collect();
        let admitted = handles
            .into_iter()
            .map(|h| h.join().unwrap())
            .filter(|&ok| ok)
            .count();

        assert_eq!(admitted, 4, "exactly the queue's capacity must be admitted");
        assert_eq!(handoff.dropped_count(), (TASKS - 4) as u64);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 8)]
    async fn concurrent_producers_all_delivered_through_one_worker() {
        // The real production access pattern (design doc: every sensor connection is its own
        // task, all sharing one `CaptureHandoff`). Ten distinct bodies plus ten concurrent
        // submissions of one *duplicate* body, racing against the one live worker. Proves, end to
        // end: no event is lost or corrupted under concurrent producers; the dedup path is safe
        // even when many producers race identical content (empirically - the module doc's
        // structural argument is what proves it can never actually race); and total on-disk bytes
        // match real dedup (11 distinct files, not 20).
        let dir = tempfile::tempdir().unwrap();
        let spool_dir = dir.path().join("spool");
        std::fs::create_dir(&spool_dir).unwrap();
        let log_path = dir.path().join("events.jsonl");
        let spool = crate::spool::QuarantineSpool::new(spool_dir.clone(), 4096, 1_000_000);
        let emitter = crate::emit::EventEmitter::new(log_path.clone());
        let handoff = Arc::new(test_handoff(spool, emitter, 64, dir.path()));
        let worker = handoff.start_worker();

        const UNIQUE: usize = 10;
        const DUP_SUBMITTERS: usize = 10;
        const DUP_BODY: &[u8] = b"duplicate-payload";

        let mut handles = Vec::with_capacity(UNIQUE + DUP_SUBMITTERS);
        for i in 0..UNIQUE {
            let handoff = handoff.clone();
            let body = format!("unique-body-{i}").into_bytes();
            handles.push(tokio::spawn(async move {
                handoff
                    .submit(CaptureJob {
                        body,
                        orig_name: String::new(),
                        event_builder: Box::new(|s| test_event(Some(s))),
                    })
                    .unwrap();
            }));
        }
        for _ in 0..DUP_SUBMITTERS {
            let handoff = handoff.clone();
            handles.push(tokio::spawn(async move {
                handoff
                    .submit(CaptureJob {
                        body: DUP_BODY.to_vec(),
                        orig_name: String::new(),
                        event_builder: Box::new(|s| test_event(Some(s))),
                    })
                    .unwrap();
            }));
        }
        for handle in handles {
            handle.await.unwrap();
        }

        wait_for_lines(&log_path, UNIQUE + DUP_SUBMITTERS).await;
        worker.abort();

        let content = tokio::fs::read_to_string(&log_path).await.unwrap();
        let lines: Vec<&str> = content.lines().collect();
        assert_eq!(
            lines.len(),
            UNIQUE + DUP_SUBMITTERS,
            "every submitted job must produce exactly one event, none lost or merged"
        );

        let events: Vec<SensorEvent> = lines
            .iter()
            .map(|l| serde_json::from_str(l).unwrap_or_else(|e| panic!("corrupted line: {e}")))
            .collect();
        let samples: Vec<SampleRef> = events.into_iter().map(|e| e.sample.unwrap()).collect();

        let dup_sha256 = {
            use sha2::{Digest, Sha256};
            crate::sanitize::to_hex_bounded(&Sha256::digest(DUP_BODY), 32)
        };
        let dup_matches = samples.iter().filter(|s| s.sha256 == dup_sha256).count();
        assert_eq!(
            dup_matches, DUP_SUBMITTERS,
            "all ten duplicate submissions must resolve to the same sha256"
        );
        for s in samples.iter().filter(|s| s.sha256 == dup_sha256) {
            assert_eq!(s.size, DUP_BODY.len() as u64);
        }

        let unique_hashes: std::collections::HashSet<&str> = samples
            .iter()
            .filter(|s| s.sha256 != dup_sha256)
            .map(|s| s.sha256.as_str())
            .collect();
        assert_eq!(
            unique_hashes.len(),
            UNIQUE,
            "the ten distinct bodies must resolve to ten distinct sha256 values"
        );

        // Real dedup on disk: 10 unique files + 1 deduplicated file, never 20.
        let on_disk_count = std::fs::read_dir(&spool_dir).unwrap().count();
        assert_eq!(on_disk_count, UNIQUE + 1);
    }

    #[tokio::test]
    async fn capture_writes_pending_manifest_matching_the_event() {
        // The correctness-critical guard for SP-B-1b Task 4: the manifest row and the emitted
        // event must carry the identical occurrence_id, minted exactly once in process_job. A
        // wrong-but-plausible implementation that mints a *second* id for the manifest (or lets
        // `EventEmitter::append` mint its own because `process_job` never stamped one) would
        // still write a manifest and still emit an event, but the two ids would disagree - this
        // test is the one place that equality is actually checked end to end.
        let dir = tempfile::tempdir().unwrap();
        let spool_dir = dir.path().join("spool");
        std::fs::create_dir(&spool_dir).unwrap();
        let outbox_dir = dir.path().join("outbox");
        let log_path = dir.path().join("events.jsonl");
        let spool = crate::spool::QuarantineSpool::new(spool_dir, 4096, 1_000_000);
        let emitter = crate::emit::EventEmitter::new(log_path.clone());
        let handoff = CaptureHandoff::new(
            spool,
            emitter,
            16,
            "collector-1".to_string(),
            crate::outbox::OutboxManifest::new(outbox_dir.clone()),
        );
        let worker = handoff.start_worker();

        handoff
            .submit(CaptureJob {
                body: b"malware payload".to_vec(),
                orig_name: "evil.bin".into(),
                event_builder: Box::new(|sample| test_event(Some(sample))),
            })
            .unwrap();
        wait_for_lines(&log_path, 1).await;
        worker.abort();

        // The event carries an occurrence_id.
        let line = tokio::fs::read_to_string(&log_path).await.unwrap();
        let event: SensorEvent = serde_json::from_str(line.trim()).unwrap();
        let oid = event.occurrence_id.expect("event has occurrence_id");
        let cid = event
            .sample
            .as_ref()
            .unwrap()
            .capture_id
            .expect("capture_id");

        // Exactly one manifest row exists, pending, and matches the event's ids + content.
        let files: Vec<_> = std::fs::read_dir(&outbox_dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .collect();
        assert_eq!(files.len(), 1, "one manifest row per capture");
        let m = crate::outbox::OutboxManifest::new(outbox_dir);
        let row = m.load(cid).unwrap().expect("manifest present for capture");
        assert_eq!(
            row.occurrence_id, oid,
            "manifest and event share the occurrence_id"
        );
        assert_eq!(row.collector_id, "collector-1");
        assert_eq!(row.size, b"malware payload".len() as u64);
        assert_eq!(row.body_key, row.sha256);
        assert_eq!(
            row.gateway_spool_state,
            crate::outbox::CustodyState::Pending
        );
        assert_eq!(
            row.custody_state,
            crate::outbox::CustodyDisposition::Pending
        );
    }
}
