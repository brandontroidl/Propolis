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
    spool: Arc<QuarantineSpool>,
    emitter: Arc<EventEmitter>,
}

impl CaptureHandoff {
    /// `queue_size` is the operator-configured `SensorConfig::capture_queue_size`: the number of
    /// jobs the in-process channel holds before `submit` starts dropping. Constructing a
    /// `CaptureHandoff` does not spawn a worker - call `start_worker` separately - so a caller
    /// that wants to observe drop behavior in isolation (as `full_queue_drops_and_counts` and
    /// `producer_never_blocks` below do) can simply not start one.
    pub fn new(spool: QuarantineSpool, emitter: EventEmitter, queue_size: usize) -> Self {
        let (tx, rx) = mpsc::channel(queue_size);
        Self {
            tx,
            rx: Mutex::new(Some(rx)),
            dropped: AtomicU64::new(0),
            spool: Arc::new(spool),
            emitter: Arc::new(emitter),
        }
    }

    /// Enqueue a capture job. Never blocks: backed by `try_send`, which returns immediately
    /// whether or not the queue had room. A full queue is reported as `Err(CaptureDropped)` and
    /// counted against `dropped_count`, never waited out - see the module doc for why blocking
    /// here would defeat the hand-off's entire reason for existing.
    pub fn submit(&self, job: CaptureJob) -> Result<(), CaptureDropped> {
        self.tx.try_send(job).map_err(|_| {
            self.dropped.fetch_add(1, Ordering::Relaxed);
            CaptureDropped
        })
    }

    /// Total jobs `submit` has rejected for a full queue since construction: the operator-visible
    /// metric the design doc calls for - "under overload this layer loses a sample rather than
    /// its covertness, and the drop is a metric the operator can see."
    pub fn dropped_count(&self) -> u64 {
        self.dropped.load(Ordering::Relaxed)
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

        tokio::spawn(async move {
            while let Some(job) = rx.recv().await {
                process_job(&spool, &emitter, job).await;
            }
        })
    }
}

/// Process exactly one job to completion: store, sanitize `orig_name`, build the event, emit.
/// Never propagates a panic - see the module doc for why a panicking `event_builder` (a bug in a
/// sensor's own closure) must not end the worker loop every later job still depends on.
async fn process_job(spool: &QuarantineSpool, emitter: &EventEmitter, job: CaptureJob) {
    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        spool.store(&job.body).map(|mut sample_ref| {
            sample_ref.orig_name = sanitize_value(&job.orig_name, MAX_ORIG_NAME_LEN);
            (job.event_builder)(sample_ref)
        })
    }));

    let event = match outcome {
        Ok(Ok(event)) => event,
        Ok(Err(e)) => {
            tracing::warn!(
                error = %e,
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
        let handoff = CaptureHandoff::new(spool, emitter, 16);
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
        tokio::time::sleep(Duration::from_millis(200)).await;
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
        let handoff = CaptureHandoff::new(spool, emitter, 1);

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
        let handoff = CaptureHandoff::new(spool, emitter, 1);
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
        let handoff = CaptureHandoff::new(spool, emitter, 16);
        let worker = handoff.start_worker();

        let raw_name = "evil\r\n\x1b[31mname\x1b[0m.bin";
        handoff
            .submit(CaptureJob {
                body: b"payload".to_vec(),
                orig_name: raw_name.into(),
                event_builder: Box::new(|sample| test_event(Some(sample))),
            })
            .unwrap();
        tokio::time::sleep(Duration::from_millis(200)).await;
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
        let handoff = CaptureHandoff::new(spool, emitter, 4);
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
        let handoff = CaptureHandoff::new(spool, emitter, 16);
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

        tokio::time::sleep(Duration::from_millis(200)).await;
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
        let handoff = CaptureHandoff::new(spool, emitter, 16);
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

        tokio::time::sleep(Duration::from_millis(200)).await;
        worker.abort();

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
        let handoff = Arc::new(CaptureHandoff::new(spool, emitter, 4));

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
        let handoff = Arc::new(CaptureHandoff::new(spool, emitter, 64));
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

        tokio::time::sleep(Duration::from_millis(300)).await;
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
}
