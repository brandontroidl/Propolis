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
//! producer tasks race `submit` concurrently. The review crate's malware fetcher is the one other
//! caller: it stores into its own spool from several concurrent fetches, which is safe because
//! `store` gives a body its digest name only once it is complete (`spool.rs`'s `publish`).
//!
//! `orig_name` is sanitized here, not by each sensor, before it is written onto the `SampleRef` -
//! see `spool.rs`'s `store` doc, which places that obligation on whoever calls `store` and then
//! fills in the returned ref's `orig_name`. Every sensor's store goes through this worker (the
//! fetcher never fills in `orig_name`), so the framework enforces the requirement structurally
//! here rather than trusting every current and future sensor to remember it independently -
//! matching this crate's standing pattern (`sanitize.rs`, `bounds.rs`, `config.rs`): a sensor has
//! no route to a record that bypasses it.
//!
//! A job whose `event_builder` panics - a bug in a sensor's own closure, working on
//! attacker-influenced data - is isolated the same way `listener.rs` isolates a panicking
//! per-connection handler: caught, logged, and dropped, with the worker's loop continuing to
//! drain later jobs. Unlike the listener, this is a synchronous `std::panic::catch_unwind` around
//! the non-async portion of the work rather than a per-job `tokio::spawn`, specifically so that
//! isolating a panic does not reintroduce concurrent `store` calls and undo the previous
//! paragraph's guarantee.
//!
//! **Shutdown drains the queue, bounded by a deadline.** `start_worker` keeps the worker's
//! `JoinHandle` inside the `CaptureHandoff`, and `drain` is the one call a sensor's `main` makes on
//! SIGTERM: it stops `submit` from enqueuing, tells the worker to close the channel and finish what
//! is already buffered, and waits for it up to a timeout so a wedged spool cannot hold the process
//! past the service manager's stop timeout. Without it the runtime teardown killed the detached
//! worker with accepted captures still queued. This drains the QUEUE only: a connection task that
//! the runtime cancels at teardown never runs its Drop-time `submit`, so a capture still being
//! assembled on a live connection at SIGTERM is lost (a documented residual; closing it needs
//! per-connection task tracking in the listener, which is out of scope here).

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use sensor_wire::{SampleRef, SensorEvent};
use tokio::sync::{Notify, mpsc};
use tokio::task::JoinHandle;

use crate::capture_budget::{CaptureBody, CaptureMemoryBudget};
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

/// The bound each sensor's `main` passes to `CaptureHandoff::drain`. Well under systemd's default
/// 90 s `TimeoutStopSec`, so a wedged spool costs a bounded stop delay rather than a SIGKILL.
pub const SHUTDOWN_DRAIN_TIMEOUT: Duration = Duration::from_secs(10);

/// The `end_reason` stamped on a capture whose body stopped growing because the process-wide
/// [`CaptureMemoryBudget`] had no room. It overrides whatever end the sensor itself recorded: the
/// transfer was cut by this sensor's memory ceiling, not by anything the peer did.
pub const END_REASON_CAPTURE_MEMORY_BUDGET: &str = "capture_memory_budget";

/// One capture awaiting hand-off: a body already fully read off the wire, the attacker-supplied
/// filename if the protocol carries one (SCP/SFTP; empty where it does not, e.g. the catch-all's
/// raw payload), and the closure that builds the sensor's own `SensorEvent` once the `SampleRef`
/// is known - deferred because the ref's `sha256`/`size` do not exist until the worker has
/// actually hashed and stored the body.
///
/// The body is a budget-charged [`CaptureBody`]: its memory counts against the sensor's
/// process-wide ceiling from the first byte until the worker has spooled it (see `process_job`).
pub struct CaptureJob {
    pub body: CaptureBody,
    pub orig_name: String,
    pub event_builder: Box<dyn FnOnce(SampleRef) -> SensorEvent + Send>,
}

/// Why a session-scoped capture stopped, and therefore whether its bytes are the whole of what
/// the peer was sending.
///
/// A shell capture has no protocol-defined end of file the way SCP's trailer or ADB's DONE does,
/// so the only thing that can say whether the bytes are whole is how the session itself ended.
/// "The session loop returned" is not that: an idle timeout, a socket error, malformed input and
/// an exhausted capture budget all end the loop with a payload still arriving, and labelling
/// those complete tells an analyst a fragment is a whole sample.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CaptureEnd {
    /// Nothing recorded an end: the listener dropped the handler future at `max_duration`. It is
    /// the initial value because a cancelled future runs no code that could set anything else.
    Cancelled,
    /// The peer closed the connection (or, for a file transfer, the channel or stream carrying
    /// it). Whatever it meant to send on the session, it finished sending.
    PeerClosed,
    /// The peer asked to end the session (`exit`/`logout`, SSH's DISCONNECT).
    ClientLogout,
    /// No byte arrived within `idle_timeout` (or `read_timeout`, for the first read).
    IdleTimeout,
    /// The socket failed mid-session - a read error, or a response that could not be written.
    TransportError,
    /// The peer sent something the protocol could not parse, so the session could not continue.
    MalformedInput,
    /// The session hit a sensor-side read bound (`max_captured_bytes`, or a per-transfer limit
    /// derived from it); the rest of the payload was never read off the wire.
    CaptureBudget,
    /// The peer aborted the transfer with its protocol's own error message (a TFTP ERROR).
    PeerAborted,
}

impl CaptureEnd {
    /// Whether a session-scoped capture's bytes are the whole of what the peer sent. Only an end
    /// the PEER chose to reach qualifies: every other variant cut a payload still in progress. A
    /// file transfer does not use this - its own end-of-file marker decides, see [`UploadEnd`].
    pub fn is_complete(self) -> bool {
        matches!(self, Self::PeerClosed | Self::ClientLogout)
    }

    /// The value stored in the event's `end_reason`, so an operator reading a fragment can see
    /// what cut it short rather than only that it is short.
    pub fn label(self) -> &'static str {
        match self {
            Self::Cancelled => "session_cancelled",
            Self::PeerClosed => "peer_closed",
            Self::ClientLogout => "client_logout",
            Self::IdleTimeout => "idle_timeout",
            Self::TransportError => "transport_error",
            Self::MalformedInput => "malformed_input",
            Self::CaptureBudget => "capture_budget",
            Self::PeerAborted => "peer_aborted",
        }
    }
}

/// How a captured upload ended: the one value [`upload_metadata`] derives both `complete` and
/// `end_reason` from, so the two keys cannot disagree and no capture can leave the reason out.
///
/// A session-scoped capture (a binary payload streamed at a shell) has no end-of-file of its own,
/// so how the session ended decides whether it is whole. A file transfer does have one, and only
/// that marker makes it whole: an SCP body whose peer closed the connection before the trailer is
/// a fragment even though `PeerClosed` would make a shell capture complete. Hence the transfer
/// variants rather than a bare [`CaptureEnd`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UploadEnd {
    /// A session-scoped capture, ended the way the session ended.
    Session(CaptureEnd),
    /// The transfer reached its protocol's end of file: SCP's trailer, SFTP's CLOSE, ADB's DONE,
    /// FTP's data-connection close, TFTP's short final block, a whole MQTT PUBLISH.
    TransferComplete,
    /// The transfer was cut off before its end of file, by this.
    TransferCut(CaptureEnd),
}

impl UploadEnd {
    /// The event's `complete`.
    pub fn is_complete(self) -> bool {
        match self {
            Self::Session(end) => end.is_complete(),
            Self::TransferComplete => true,
            Self::TransferCut(_) => false,
        }
    }

    /// The event's `end_reason`. A cut-off transfer carries the label of what cut it, the same
    /// strings a session-scoped capture uses.
    pub fn label(self) -> &'static str {
        match self {
            Self::Session(end) | Self::TransferCut(end) => end.label(),
            Self::TransferComplete => "transfer_complete",
        }
    }
}

/// The `honeypot_malware_upload` metadata object every body-capturing sensor emits, built in one
/// place so the keys cannot drift between sensors. `wire_size` is how many body bytes the client
/// actually sent; `sample.size` is how many were retained. Sensors cap the body they keep (SCP,
/// SFTP and ADB retain a 10 MB prefix and drain the rest to keep the protocol aligned), and an
/// analysis of the prefix must never be read as an analysis of the file: `truncated` says the
/// hash and size describe a prefix, and `wire_size` says how big the real upload was.
/// `complete` and `end_reason` both come from `end` (see [`UploadEnd`]): false means the session
/// ended, stalled or was cut off with the transfer still open, so the body is a fragment of
/// whatever was being sent, kept because a fragment of a dropper is still evidence, and
/// `end_reason` says what cut it.
pub fn upload_metadata(
    protocol_label: &str,
    sample: &SampleRef,
    wire_size: u64,
    end: UploadEnd,
) -> serde_json::Value {
    serde_json::json!({
        "protocol_label": protocol_label,
        "sha256": sample.sha256,
        "size": sample.size,
        "orig_name": sample.orig_name,
        "wire_size": wire_size,
        "truncated": wire_size > sample.size,
        "complete": end.is_complete(),
        "end_reason": end.label(),
    })
}

/// `submit` could not enqueue the job because the queue was already at capacity, or because the
/// hand-off is shutting down (`drain` was called). `submit` never waits for room (see the module
/// doc), so this is the immediate, synchronous outcome, not a timeout or a retry-later signal.
#[derive(Debug)]
pub struct CaptureDropped;

impl std::fmt::Display for CaptureDropped {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "capture queue full or closing; job dropped")
    }
}

impl std::error::Error for CaptureDropped {}

/// How `CaptureHandoff::drain` ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DrainOutcome {
    /// The worker processed every buffered job and exited before the deadline.
    Drained,
    /// The deadline passed with the worker still running (a wedged spool or emitter); it was
    /// aborted and whatever was still queued is lost.
    TimedOut,
    /// The worker task ended abnormally (it panicked or was cancelled) rather than finishing.
    WorkerFailed,
    /// No worker was running: `start_worker` was never called, or `drain` already ran.
    NotRunning,
}

impl DrainOutcome {
    /// Whether nothing buffered was left behind.
    pub fn is_clean(self) -> bool {
        matches!(self, Self::Drained | Self::NotRunning)
    }
}

/// Owns the queue, the drop counter, and the spool/emitter every enqueued job is eventually
/// processed against. Cheap to share: construct one per sensor process, wrap it in an `Arc`, and
/// clone that into every connection handler - `submit` and `dropped_count` take `&self`, and
/// `start_worker` is meant to be called exactly once regardless of how many handlers share the
/// `Arc`.
pub struct CaptureHandoff {
    tx: mpsc::Sender<CaptureJob>,
    rx: Mutex<Option<mpsc::Receiver<CaptureJob>>>,
    dropped: AtomicU64,
    /// The process-wide ceiling on capture bodies buffered in memory. Sensors build every capture
    /// buffer from it (`new_capture_body`), and the worker refunds a body once it is spooled.
    budget: Arc<CaptureMemoryBudget>,
    /// Submitted captures whose body kept only a prefix because the budget ran out.
    truncated_captures: AtomicU64,
    /// Submitted captures that got zero bytes (the budget was already full), so no sample exists.
    refused_captures: AtomicU64,
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
    /// Set by `drain`; `submit` refuses once it is true. `tx` lives in this struct, which every
    /// connection handler holds an `Arc` of, so the channel never closes by dropping senders -
    /// this flag plus `Receiver::close` in the worker is what ends the queue.
    closing: AtomicBool,
    /// Wakes the worker to close the channel and drain. `notify_one` stores a permit, so a signal
    /// sent while the worker is mid-job is not lost.
    stop: Arc<Notify>,
    /// The worker task, retained so `drain` can await it (a detached handle is killed by runtime
    /// teardown before it empties the queue).
    worker: Mutex<Option<JoinHandle<()>>>,
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
    ///
    /// `capture_budget` is the sensor process's one [`CaptureMemoryBudget`]; every capture buffer
    /// is charged to it, so concurrent connections cannot together outgrow the unit's memory
    /// limit.
    pub fn new(
        spool: QuarantineSpool,
        emitter: EventEmitter,
        queue_size: usize,
        collector_id: String,
        outbox: OutboxManifest,
        capture_budget: Arc<CaptureMemoryBudget>,
    ) -> Self {
        let (tx, rx) = mpsc::channel(queue_size);
        Self {
            tx,
            rx: Mutex::new(Some(rx)),
            dropped: AtomicU64::new(0),
            budget: capture_budget,
            truncated_captures: AtomicU64::new(0),
            refused_captures: AtomicU64::new(0),
            spool_refused: Arc::new(AtomicU64::new(0)),
            spool: Arc::new(spool),
            emitter: Arc::new(emitter),
            collector_id,
            outbox: Arc::new(outbox),
            closing: AtomicBool::new(false),
            stop: Arc::new(Notify::new()),
            worker: Mutex::new(None),
        }
    }

    /// Enqueue a capture job. Never blocks: backed by `try_send`, which returns immediately
    /// whether or not the queue had room. A full queue is reported as `Err(CaptureDropped)` and
    /// counted against `dropped_count`, never waited out - see the module doc for why blocking
    /// here would defeat the hand-off's entire reason for existing.
    ///
    /// After `drain` has been called this refuses without enqueuing and without touching the
    /// full-queue counter: a closing worker must not be handed new work, and a shutdown refusal is
    /// not the overload the counter measures.
    ///
    /// A body that is empty because the very first reservation was refused is not a capture: no
    /// sample or `malware_upload` event is produced (the sensor's ordinary connection and probe
    /// events are unaffected), the refusal counter is bumped, and this returns `Err`. A body that
    /// kept a prefix is enqueued normally and counted as truncated; `process_job` marks it.
    pub fn submit(&self, job: CaptureJob) -> Result<(), CaptureDropped> {
        if job.body.is_exhausted() && job.body.is_empty() {
            let refused = self.refused_captures.fetch_add(1, Ordering::Relaxed) + 1;
            if refused.is_power_of_two() {
                tracing::warn!(
                    refused_total = refused,
                    "capture hand-off: capture memory budget full, empty capture refused (no sample)"
                );
            }
            return Err(CaptureDropped);
        }
        let truncated_body = job.body.is_exhausted();
        if self.closing.load(Ordering::SeqCst) {
            return Err(CaptureDropped);
        }
        let sent = self.tx.try_send(job).map_err(|e| {
            // A receiver closed by a concurrent `drain` that raced the check above: refuse the
            // same way, uncounted.
            if matches!(e, mpsc::error::TrySendError::Closed(_)) {
                return CaptureDropped;
            }
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
        });
        // Counted only once actually enqueued: a truncated job refused for shutdown or a full
        // queue is not a submitted sample.
        if sent.is_ok() && truncated_body {
            let truncated = self.truncated_captures.fetch_add(1, Ordering::Relaxed) + 1;
            if truncated.is_power_of_two() {
                tracing::warn!(
                    truncated_total = truncated,
                    "capture hand-off: capture memory budget exhausted, sample truncated to its prefix"
                );
            }
        }
        sent
    }

    /// Total jobs `submit` has rejected for a full queue since construction: the operator-visible
    /// metric the design doc calls for - "under overload this layer loses a sample rather than
    /// its covertness, and the drop is a metric the operator can see."
    pub fn dropped_count(&self) -> u64 {
        self.dropped.load(Ordering::Relaxed)
    }

    /// A fresh, empty capture buffer charged to this hand-off's budget. Every sensor builds its
    /// capture buffers here so no body is buffered outside the process-wide ceiling.
    pub fn new_capture_body(&self) -> CaptureBody {
        CaptureBody::with_budget(self.budget.clone())
    }

    /// The process-wide capture budget, for its `current`/`high_water`/`refused` diagnostics.
    pub fn capture_budget(&self) -> &CaptureMemoryBudget {
        &self.budget
    }

    /// Captures submitted with only a prefix of their body because the budget ran out.
    pub fn truncated_capture_count(&self) -> u64 {
        self.truncated_captures.load(Ordering::Relaxed)
    }

    /// Captures refused outright (zero bytes buffered, so no sample) because the budget was full.
    pub fn refused_capture_count(&self) -> u64 {
        self.refused_captures.load(Ordering::Relaxed)
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
    /// The task's handle is retained in `self` for `drain`; callers do not hold it.
    ///
    /// # Panics
    /// If called more than once on the same `CaptureHandoff`.
    pub fn start_worker(&self) {
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
        let stop = self.stop.clone();

        let handle = tokio::spawn(async move {
            loop {
                let job = tokio::select! {
                    job = rx.recv() => job,
                    _ = stop.notified() => {
                        // Refuse further sends, then keep receiving until the buffer is empty:
                        // `recv` returns the already-queued jobs after `close` and `None` once
                        // they are gone.
                        rx.close();
                        while let Some(job) = rx.recv().await {
                            process_job(&spool, &emitter, &spool_refused, &collector_id, &outbox, job)
                                .await;
                        }
                        return;
                    }
                };
                let Some(job) = job else { return };
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
        });
        *self.worker.lock().unwrap() = Some(handle);
    }

    /// Stop accepting captures and finish the ones already queued, waiting at most `timeout`.
    /// Call once at shutdown, after the listeners are stopped. `submit` refuses from the moment
    /// this is called. On timeout the worker is aborted (a wedged spool or emitter must not hold
    /// the process past the service manager's stop timeout) and the unprocessed jobs are lost; the
    /// outcome says which happened so the caller can log it.
    pub async fn drain(&self, timeout: Duration) -> DrainOutcome {
        self.closing.store(true, Ordering::SeqCst);
        let handle = self.worker.lock().unwrap().take();
        let Some(mut handle) = handle else {
            return DrainOutcome::NotRunning;
        };
        self.stop.notify_one();
        let outcome = match tokio::time::timeout(timeout, &mut handle).await {
            Ok(Ok(())) => DrainOutcome::Drained,
            Ok(Err(_)) => DrainOutcome::WorkerFailed,
            Err(_) => {
                handle.abort();
                DrainOutcome::TimedOut
            }
        };
        match outcome {
            DrainOutcome::Drained => tracing::info!("capture hand-off: queue drained on shutdown"),
            _ => tracing::warn!(
                ?outcome,
                timeout_ms = timeout.as_millis() as u64,
                "capture hand-off: shutdown drain incomplete; queued captures may be lost"
            ),
        }
        outcome
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
    let CaptureJob {
        body,
        orig_name,
        event_builder,
    } = job;
    let budget_truncated = body.is_exhausted();
    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
        let stored = spool.store(body.as_slice());
        // `store` has copied the bytes to a synced file (or refused them) by the time it returns,
        // so the in-memory body is dead weight from here: refund its budget now, before the
        // manifest write and the event append (both can block on slow I/O) rather than at the end
        // of the job. Unwinding out of `store` drops `body` the same way.
        drop(body);
        stored.map(|mut sample_ref| {
            sample_ref.orig_name = sanitize_value(&orig_name, MAX_ORIG_NAME_LEN);
            event_builder(sample_ref)
        })
    }));

    let mut event = match outcome {
        Ok(Ok(mut event)) => {
            if budget_truncated {
                mark_budget_truncated(&mut event.metadata);
            }
            event
        }
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

/// Stamps a capture that the memory budget cut short: the retained bytes are a prefix
/// (`truncated`), the transfer did not finish (`complete` false) and the cause is ours
/// (`end_reason`). Done here, once, so no sensor can forget one of the three keys.
fn mark_budget_truncated(metadata: &mut serde_json::Value) {
    if let Some(map) = metadata.as_object_mut() {
        map.insert("truncated".into(), serde_json::Value::Bool(true));
        map.insert("complete".into(), serde_json::Value::Bool(false));
        map.insert(
            "end_reason".into(),
            serde_json::Value::String(END_REASON_CAPTURE_MEMORY_BUDGET.into()),
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
        let m = upload_metadata(
            "ssh",
            &sample(10_000_000),
            12_000_000,
            UploadEnd::TransferComplete,
        );
        assert_eq!(m["truncated"], true);
        assert_eq!(m["wire_size"], 12_000_000u64);
        assert_eq!(m["size"], 10_000_000u64);
        assert_eq!(m["protocol_label"], "ssh");
        assert_eq!(m["sha256"], "ab".repeat(32));
        assert_eq!(m["orig_name"], "payload.bin");
        assert_eq!(m["complete"], true);
        assert_eq!(m["end_reason"], "transfer_complete");
    }

    #[test]
    fn upload_metadata_marks_a_complete_body_as_not_truncated() {
        let m = upload_metadata("adb", &sample(4096), 4096, UploadEnd::TransferComplete);
        assert_eq!(m["truncated"], false);
        assert_eq!(m["wire_size"], 4096u64);
    }

    /// A fragment below the cap is not truncated by the sensor, but it is not the file either.
    #[test]
    fn upload_metadata_keeps_incomplete_distinct_from_truncated() {
        let m = upload_metadata(
            "ssh",
            &sample(4096),
            4096,
            UploadEnd::TransferCut(CaptureEnd::IdleTimeout),
        );
        assert_eq!(m["truncated"], false);
        assert_eq!(m["complete"], false);
        assert_eq!(m["end_reason"], "idle_timeout");
    }

    /// Every end, as every kind of capture, writes both keys, and `complete` is exactly what the
    /// end says. The same `PeerClosed` is whole for a shell capture and a fragment for a file
    /// transfer that never reached its end-of-file marker; the labels stay the strings the shell
    /// sensors have always written.
    #[test]
    fn upload_metadata_derives_complete_and_end_reason_from_one_end() {
        let all = [
            (CaptureEnd::Cancelled, "session_cancelled", false),
            (CaptureEnd::PeerClosed, "peer_closed", true),
            (CaptureEnd::ClientLogout, "client_logout", true),
            (CaptureEnd::IdleTimeout, "idle_timeout", false),
            (CaptureEnd::TransportError, "transport_error", false),
            (CaptureEnd::MalformedInput, "malformed_input", false),
            (CaptureEnd::CaptureBudget, "capture_budget", false),
            (CaptureEnd::PeerAborted, "peer_aborted", false),
        ];
        for (end, label, session_complete) in all {
            let m = upload_metadata("ssh", &sample(8), 8, UploadEnd::Session(end));
            assert_eq!(m["end_reason"], label, "{end:?}");
            assert_eq!(m["complete"], session_complete, "{end:?}");
            let m = upload_metadata("ssh", &sample(8), 8, UploadEnd::TransferCut(end));
            assert_eq!(m["end_reason"], label, "{end:?}");
            assert_eq!(
                m["complete"], false,
                "a cut transfer is a fragment: {end:?}"
            );
        }
        let m = upload_metadata("ftp", &sample(8), 8, UploadEnd::TransferComplete);
        assert_eq!(
            (&m["complete"], &m["end_reason"]),
            (
                &serde_json::json!(true),
                &serde_json::json!("transfer_complete")
            )
        );
    }

    /// The non-test source of every `.rs` file under `dir`, keyed by path: everything before the
    /// file's `#[cfg(test)] mod`, so a test fixture building an event by hand is not counted.
    fn production_sources(dir: &std::path::Path, out: &mut Vec<(std::path::PathBuf, String)>) {
        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };
        for path in entries.flatten().map(|e| e.path()) {
            if path.is_dir() {
                production_sources(&path, out);
            } else if path.extension().is_some_and(|e| e == "rs") {
                let text = std::fs::read_to_string(&path).unwrap();
                let live = text
                    .find("\n#[cfg(test)]\nmod ")
                    .map_or(text.as_str(), |cut| &text[..cut]);
                out.push((path, live.to_string()));
            }
        }
    }

    /// The fleet pane read `end_reason` as "unrecorded" for most captures because only three call
    /// sites added the key by hand. `upload_metadata` now always writes it; what is left to hold
    /// is that every `honeypot_malware_upload` event a sensor builds gets its metadata there.
    ///
    /// The population is derived, not listed: every workspace crate whose production code builds
    /// a `CaptureJob` captures bodies (this crate only defines it). In each, every construction of
    /// an upload event must be matched by an `upload_metadata` call in the same file, and no file
    /// may write `end_reason` itself, so a hand-rolled or hand-patched event fails here.
    #[test]
    fn every_body_capturing_sensor_builds_its_upload_events_through_upload_metadata() {
        let crates_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap();
        let mut capturing = std::collections::BTreeSet::new();
        let mut entries: Vec<_> = std::fs::read_dir(crates_dir)
            .unwrap()
            .flatten()
            .map(|e| e.path())
            .collect();
        entries.sort();
        for krate in entries {
            let name = krate.file_name().unwrap().to_string_lossy().into_owned();
            if name == "sensor-framework" {
                continue;
            }
            let mut files = Vec::new();
            production_sources(&krate.join("src"), &mut files);
            if !files.iter().any(|(_, src)| src.contains("CaptureJob {")) {
                continue;
            }
            capturing.insert(name.clone());
            let mut built = 0;
            for (path, src) in &files {
                let events = src
                    .matches("signal_type: SIGNAL_HONEYPOT_MALWARE_UPLOAD")
                    .count()
                    + src.matches("\"honeypot_malware_upload\"").count();
                let through_framework = src.matches("upload_metadata(").count();
                assert_eq!(
                    events,
                    through_framework,
                    "{}: {events} upload event(s) but {through_framework} upload_metadata call(s)",
                    path.display()
                );
                assert!(
                    !src.contains("\"end_reason\""),
                    "{} writes end_reason itself; pass an UploadEnd to upload_metadata",
                    path.display()
                );
                built += events;
            }
            assert!(
                built > 0,
                "{name} builds CaptureJobs but no upload event was found"
            );
        }
        // Six crates capture bodies today; an empty or tiny set means the scan broke, not that
        // the workspace stopped capturing.
        assert!(
            capturing.len() >= 6,
            "body-capturing crates found: {capturing:?}"
        );
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
            Arc::new(CaptureMemoryBudget::new(u64::MAX)),
        )
    }

    /// A job body charged to a private never-refusing budget, for tests that are not about it.
    fn body_of(bytes: &[u8]) -> CaptureBody {
        let mut body = CaptureBody::unbudgeted();
        body.extend_from_slice(bytes).unwrap();
        body
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
        handoff.start_worker();

        let body = body_of(b"malware payload");
        handoff
            .submit(CaptureJob {
                body,
                orig_name: "evil.bin".into(),
                event_builder: Box::new(|sample| test_event(Some(sample))),
            })
            .unwrap();

        // Give worker time to process.
        wait_for_lines(&log_path, 1).await;

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
            body: body_of(b"data"),
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
                body: body_of(b"first"),
                orig_name: String::new(),
                event_builder: Box::new(|s| test_event(Some(s))),
            })
            .unwrap();
        let start = std::time::Instant::now();
        let _ = handoff.submit(CaptureJob {
            body: body_of(b"second"),
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
        handoff.start_worker();

        let raw_name = "evil\r\n\x1b[31mname\x1b[0m.bin";
        handoff
            .submit(CaptureJob {
                body: body_of(b"payload"),
                orig_name: raw_name.into(),
                event_builder: Box::new(|sample| test_event(Some(sample))),
            })
            .unwrap();
        wait_for_lines(&log_path, 1).await;

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
        handoff.start_worker();

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
        handoff.start_worker();

        handoff
            .submit(CaptureJob {
                body: body_of(b"first-panics"),
                orig_name: String::new(),
                event_builder: Box::new(|_sample| panic!("simulated buggy sensor closure")),
            })
            .unwrap();
        handoff
            .submit(CaptureJob {
                body: body_of(b"second-ok"),
                orig_name: String::new(),
                event_builder: Box::new(|sample| test_event(Some(sample))),
            })
            .unwrap();

        wait_for_lines(&log_path, 1).await;

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
        handoff.start_worker();

        handoff
            .submit(CaptureJob {
                body: body_of(b"this body exceeds the eight byte limit"),
                orig_name: String::new(),
                event_builder: Box::new(|sample| test_event(Some(sample))),
            })
            .unwrap();
        handoff
            .submit(CaptureJob {
                body: body_of(b"ok"),
                orig_name: String::new(),
                event_builder: Box::new(|sample| test_event(Some(sample))),
            })
            .unwrap();

        wait_for_lines(&log_path, 1).await;

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
                            body: body_of(b"x"),
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
        handoff.start_worker();

        const UNIQUE: usize = 10;
        const DUP_SUBMITTERS: usize = 10;
        const DUP_BODY: &[u8] = b"duplicate-payload";

        let mut handles = Vec::with_capacity(UNIQUE + DUP_SUBMITTERS);
        for i in 0..UNIQUE {
            let handoff = handoff.clone();
            let body = body_of(format!("unique-body-{i}").as_bytes());
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
                        body: body_of(DUP_BODY),
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

        // Real dedup on disk: 10 unique files + 1 deduplicated file, never 20. Only digest-named
        // entries are stored bodies; the spool's staging directory sits beside them.
        let on_disk_count = std::fs::read_dir(&spool_dir)
            .unwrap()
            .flatten()
            .filter(|e| crate::spool::is_canonical_sha256_hex(&e.file_name().to_string_lossy()))
            .count();
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
            Arc::new(CaptureMemoryBudget::new(u64::MAX)),
        );
        handoff.start_worker();

        handoff
            .submit(CaptureJob {
                body: body_of(b"malware payload"),
                orig_name: "evil.bin".into(),
                event_builder: Box::new(|sample| test_event(Some(sample))),
            })
            .unwrap();
        wait_for_lines(&log_path, 1).await;

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

    fn drain_job(body: Vec<u8>) -> CaptureJob {
        CaptureJob {
            body: body_of(&body),
            orig_name: String::new(),
            event_builder: Box::new(|s| test_event(Some(s))),
        }
    }

    #[tokio::test]
    async fn drain_returns_only_after_every_queued_job_is_stored_and_emitted() {
        // The shutdown loss this exists to close: jobs accepted into the queue but not yet
        // processed. The worker is started and N distinct bodies are submitted back to back, then
        // `drain` is called with no wait in between, so most are still buffered. The assertions
        // read the event log and spool directly after `drain` returns, with no polling: an
        // implementation that returned before the queue emptied (or aborted the worker) would see
        // fewer than N lines and files.
        const N: usize = 40;
        let dir = tempfile::tempdir().unwrap();
        let spool_dir = dir.path().join("spool");
        std::fs::create_dir(&spool_dir).unwrap();
        let log_path = dir.path().join("events.jsonl");
        let spool = crate::spool::QuarantineSpool::new(spool_dir.clone(), 4096, 1_000_000);
        let emitter = crate::emit::EventEmitter::new(log_path.clone());
        let handoff = test_handoff(spool, emitter, 64, dir.path());
        handoff.start_worker();

        for i in 0..N {
            handoff
                .submit(drain_job(format!("queued-body-{i}").into_bytes()))
                .unwrap();
        }
        let outcome = handoff.drain(Duration::from_secs(15)).await;
        assert_eq!(outcome, DrainOutcome::Drained);

        let lines = std::fs::read_to_string(&log_path).unwrap().lines().count();
        assert_eq!(
            lines, N,
            "every queued job must be emitted before drain returns"
        );
        let stored = std::fs::read_dir(&spool_dir)
            .unwrap()
            .flatten()
            .filter(|e| crate::spool::is_canonical_sha256_hex(&e.file_name().to_string_lossy()))
            .count();
        assert_eq!(stored, N, "every queued body must be in the spool");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn drain_gives_up_at_its_timeout_when_the_worker_is_wedged() {
        // A job whose event builder blocks stands in for a wedged spool or emitter: the worker is
        // stuck inside `process_job`, so it can never see the stop signal. `drain` must still
        // return near its deadline, not wait for the stall, and say it timed out.
        let dir = tempfile::tempdir().unwrap();
        let spool_dir = dir.path().join("spool");
        std::fs::create_dir(&spool_dir).unwrap();
        let spool = crate::spool::QuarantineSpool::new(spool_dir, 4096, 1_000_000);
        let emitter = crate::emit::EventEmitter::new(dir.path().join("events.jsonl"));
        let handoff = test_handoff(spool, emitter, 4, dir.path());
        handoff.start_worker();

        handoff
            .submit(CaptureJob {
                body: body_of(b"wedges-the-worker"),
                orig_name: String::new(),
                event_builder: Box::new(|s| {
                    std::thread::sleep(Duration::from_millis(1500));
                    test_event(Some(s))
                }),
            })
            .unwrap();
        // Let the worker pick the job up so it is wedged mid-job rather than still queued.
        tokio::time::sleep(Duration::from_millis(100)).await;

        let started = std::time::Instant::now();
        let outcome = handoff.drain(Duration::from_millis(200)).await;
        let elapsed = started.elapsed();
        assert_eq!(outcome, DrainOutcome::TimedOut);
        assert!(!outcome.is_clean());
        assert!(
            elapsed < Duration::from_millis(1000),
            "drain must return near its deadline, took {elapsed:?}"
        );
    }

    #[tokio::test]
    async fn submit_after_drain_does_not_enqueue() {
        // A closing worker must not be handed new work. The queue has room (capacity 4, nothing
        // submitted), so an implementation that only checked fullness would enqueue; the channel's
        // remaining capacity shows whether anything was actually placed in it. The refusal is not
        // a queue-full drop, so that counter stays at zero.
        let dir = tempfile::tempdir().unwrap();
        let spool_dir = dir.path().join("spool");
        std::fs::create_dir(&spool_dir).unwrap();
        let spool = crate::spool::QuarantineSpool::new(spool_dir, 4096, 1_000_000);
        let emitter = crate::emit::EventEmitter::new(dir.path().join("events.jsonl"));
        let handoff = test_handoff(spool, emitter, 4, dir.path());
        handoff.start_worker();
        assert_eq!(
            handoff.drain(Duration::from_secs(5)).await,
            DrainOutcome::Drained
        );

        assert!(handoff.submit(drain_job(b"late".to_vec())).is_err());
        assert_eq!(
            handoff.tx.capacity(),
            4,
            "a refused submit must not enqueue"
        );
        assert_eq!(handoff.dropped_count(), 0);
    }

    #[tokio::test]
    async fn drain_without_a_running_worker_reports_not_running_and_still_closes_submit() {
        let dir = tempfile::tempdir().unwrap();
        let spool_dir = dir.path().join("spool");
        std::fs::create_dir(&spool_dir).unwrap();
        let spool = crate::spool::QuarantineSpool::new(spool_dir, 4096, 1_000_000);
        let emitter = crate::emit::EventEmitter::new(dir.path().join("events.jsonl"));
        let handoff = test_handoff(spool, emitter, 4, dir.path());

        let outcome = handoff.drain(Duration::from_secs(1)).await;
        assert_eq!(outcome, DrainOutcome::NotRunning);
        assert!(outcome.is_clean());
        assert!(handoff.submit(drain_job(b"x".to_vec())).is_err());
        // A second drain after a real one is also a no-op.
        handoff.start_worker();
        assert_eq!(
            handoff.drain(Duration::from_secs(5)).await,
            DrainOutcome::Drained
        );
        assert_eq!(
            handoff.drain(Duration::from_secs(5)).await,
            DrainOutcome::NotRunning
        );
    }

    use crate::capture_budget::CAPTURE_CHUNK_BYTES;

    struct BudgetRig {
        handoff: Arc<CaptureHandoff>,
        budget: Arc<CaptureMemoryBudget>,
        log_path: std::path::PathBuf,
        _dir: tempfile::TempDir,
    }

    fn budget_rig(ceiling: u64) -> BudgetRig {
        let dir = tempfile::tempdir().unwrap();
        let spool_dir = dir.path().join("spool");
        std::fs::create_dir(&spool_dir).unwrap();
        let log_path = dir.path().join("events.jsonl");
        let budget = Arc::new(CaptureMemoryBudget::new(ceiling));
        let handoff = Arc::new(CaptureHandoff::new(
            crate::spool::QuarantineSpool::new(spool_dir, 10_000_000, 100_000_000),
            crate::emit::EventEmitter::new(log_path.clone()),
            16,
            "test".to_string(),
            crate::outbox::OutboxManifest::new(dir.path().join("outbox")),
            budget.clone(),
        ));
        handoff.start_worker();
        BudgetRig {
            handoff,
            budget,
            log_path,
            _dir: dir,
        }
    }

    fn events(path: &std::path::Path) -> Vec<SensorEvent> {
        std::fs::read_to_string(path)
            .unwrap()
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect()
    }

    #[tokio::test]
    async fn reservation_is_released_after_spool_store_before_the_event_is_built() {
        let rig = budget_rig(4 * CAPTURE_CHUNK_BYTES);
        let mut body = rig.handoff.new_capture_body();
        body.extend_from_slice(b"whole sample").unwrap();
        assert_eq!(rig.budget.current_bytes(), CAPTURE_CHUNK_BYTES);

        // The event builder runs inside the worker after `store` and before the manifest write
        // and append, so what it observes is the budget at the moment the reservation is released.
        let seen = Arc::new(AtomicU64::new(u64::MAX));
        let (seen_in, budget_in) = (seen.clone(), rig.budget.clone());
        rig.handoff
            .submit(CaptureJob {
                body,
                orig_name: String::new(),
                event_builder: Box::new(move |s| {
                    seen_in.store(budget_in.current_bytes(), Ordering::SeqCst);
                    test_event(Some(s))
                }),
            })
            .unwrap();
        wait_for_lines(&rig.log_path, 1).await;

        assert_eq!(
            seen.load(Ordering::SeqCst),
            0,
            "refunded before event build"
        );
        assert_eq!(rig.budget.current_bytes(), 0);
        assert_eq!(rig.budget.high_water_bytes(), CAPTURE_CHUNK_BYTES);
        let ev = &events(&rig.log_path)[0];
        assert_eq!(ev.sample.as_ref().unwrap().size, 12);
        assert!(
            ev.metadata.get("end_reason").is_none(),
            "within budget is untouched"
        );
        assert_eq!(rig.handoff.truncated_capture_count(), 0);
    }

    #[tokio::test]
    async fn exhausted_capture_keeps_prefix_is_marked_and_later_capture_succeeds() {
        // Room for exactly one chunk: a body of 1.5 chunks keeps one chunk of prefix.
        let rig = budget_rig(CAPTURE_CHUNK_BYTES);
        let chunk = CAPTURE_CHUNK_BYTES as usize;
        let data: Vec<u8> = (0..chunk + chunk / 2).map(|i| (i % 251) as u8).collect();
        let mut body = rig.handoff.new_capture_body();
        assert!(body.extend_from_slice(&data).is_err());
        assert!(body.is_exhausted());
        rig.handoff
            .submit(CaptureJob {
                body,
                orig_name: "big.bin".into(),
                event_builder: Box::new(|s| {
                    let mut e = test_event(Some(s));
                    // what a sensor would have said had the budget not intervened
                    e.metadata = serde_json::json!({"complete": true, "end_reason": "peer_closed"});
                    e
                }),
            })
            .unwrap();
        wait_for_lines(&rig.log_path, 1).await;

        let ev = &events(&rig.log_path)[0];
        assert_eq!(
            ev.sample.as_ref().unwrap().size,
            chunk as u64,
            "prefix kept"
        );
        assert_eq!(ev.metadata["truncated"], true);
        assert_eq!(ev.metadata["complete"], false);
        assert_eq!(ev.metadata["end_reason"], "capture_memory_budget");
        assert_eq!(rig.handoff.truncated_capture_count(), 1);
        assert_eq!(rig.handoff.refused_capture_count(), 0);
        assert_eq!(
            rig.budget.current_bytes(),
            0,
            "spooled, so the room is back"
        );

        // The freed room serves the next capture in full.
        let mut again = rig.handoff.new_capture_body();
        again.extend_from_slice(b"second").unwrap();
        assert!(!again.is_exhausted());
        rig.handoff
            .submit(CaptureJob {
                body: again,
                orig_name: String::new(),
                event_builder: Box::new(|s| test_event(Some(s))),
            })
            .unwrap();
        wait_for_lines(&rig.log_path, 2).await;
        let ev = &events(&rig.log_path)[1];
        assert_eq!(ev.sample.as_ref().unwrap().size, 6);
        assert!(ev.metadata.get("truncated").is_none());
    }

    #[tokio::test]
    async fn zero_byte_exhausted_capture_submits_no_sample_and_counts_a_refusal() {
        let rig = budget_rig(CAPTURE_CHUNK_BYTES);
        let mut hog = rig.handoff.new_capture_body();
        hog.extend_from_slice(b"x").unwrap();

        let mut starved = rig.handoff.new_capture_body();
        assert!(starved.extend_from_slice(b"never kept").is_err());
        assert!(starved.is_empty());
        let result = rig.handoff.submit(CaptureJob {
            body: starved,
            orig_name: String::new(),
            event_builder: Box::new(|_| unreachable!("no sample for an empty refused capture")),
        });
        assert!(result.is_err());
        assert_eq!(rig.handoff.refused_capture_count(), 1);
        assert_eq!(rig.handoff.truncated_capture_count(), 0);
        assert_eq!(rig.handoff.dropped_count(), 0, "not a queue drop");
        assert_eq!(rig.budget.refused_reservations(), 1);

        // Nothing was queued: drain finishes with an empty event log.
        drop(hog);
        assert_eq!(
            rig.handoff.drain(Duration::from_secs(5)).await,
            DrainOutcome::Drained
        );
        assert!(!rig.log_path.exists() || events(&rig.log_path).is_empty());
    }

    #[tokio::test]
    async fn truncated_job_refused_by_full_queue_or_shutdown_is_not_counted_truncated() {
        let dir = tempfile::tempdir().unwrap();
        let spool_dir = dir.path().join("spool");
        std::fs::create_dir(&spool_dir).unwrap();
        let budget = Arc::new(CaptureMemoryBudget::new(8 * CAPTURE_CHUNK_BYTES));
        // Queue of one and no worker: the first job fills it, the second finds it full.
        let handoff = CaptureHandoff::new(
            crate::spool::QuarantineSpool::new(spool_dir, 10_000_000, 100_000_000),
            crate::emit::EventEmitter::new(dir.path().join("events.jsonl")),
            1,
            "test".to_string(),
            crate::outbox::OutboxManifest::new(dir.path().join("outbox")),
            budget.clone(),
        );
        // A body that kept a one-chunk prefix then hit exhaustion: a hog leaves exactly one chunk
        // free while the body fills, and is released afterwards.
        let mk = |budget: &Arc<CaptureMemoryBudget>| {
            let free = budget.ceiling_bytes() - budget.current_bytes();
            let hog = budget
                .try_reserve(free - CAPTURE_CHUNK_BYTES)
                .expect("hog fits");
            let mut body = CaptureBody::with_budget(budget.clone());
            let data = vec![9u8; CAPTURE_CHUNK_BYTES as usize + 5];
            assert!(body.extend_from_slice(&data).is_err());
            drop(hog);
            assert!(body.is_exhausted() && !body.is_empty());
            body
        };

        let job = |body| CaptureJob {
            body,
            orig_name: String::new(),
            event_builder: Box::new(|s| test_event(Some(s))),
        };
        assert!(handoff.submit(job(mk(&budget))).is_ok());
        assert_eq!(handoff.truncated_capture_count(), 1, "enqueued, so counted");

        assert!(handoff.submit(job(mk(&budget))).is_err());
        assert_eq!(handoff.dropped_count(), 1, "full queue is a drop");
        assert_eq!(
            handoff.truncated_capture_count(),
            1,
            "a refused truncated job is not a submitted sample"
        );

        // After drain begins, a shutdown refusal is not counted either.
        assert_eq!(
            handoff.drain(Duration::from_secs(1)).await,
            DrainOutcome::NotRunning
        );
        assert!(handoff.submit(job(mk(&budget))).is_err());
        assert_eq!(handoff.truncated_capture_count(), 1);
        assert_eq!(handoff.dropped_count(), 1);
    }

    #[tokio::test]
    async fn dropped_or_refused_jobs_still_refund_their_reservation() {
        let rig = budget_rig(8 * CAPTURE_CHUNK_BYTES);
        assert_eq!(
            rig.handoff.drain(Duration::from_secs(5)).await,
            DrainOutcome::Drained
        );
        // After drain `submit` refuses; the refused job's body must still give its room back.
        let mut body = rig.handoff.new_capture_body();
        body.extend_from_slice(b"late").unwrap();
        assert_eq!(rig.budget.current_bytes(), CAPTURE_CHUNK_BYTES);
        assert!(
            rig.handoff
                .submit(CaptureJob {
                    body,
                    orig_name: String::new(),
                    event_builder: Box::new(|s| test_event(Some(s))),
                })
                .is_err()
        );
        assert_eq!(rig.budget.current_bytes(), 0);
    }
}
