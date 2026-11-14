//! mTLS ship client and one-cycle ship loop: dials the gateway, ships each sequenced batch
//! `batcher::Batcher` builds, and advances both the confirmed-seq state and the tailer cursor
//! only once the gateway has durably acked a batch `Accepted` or `Duplicate`.
//!
//! Ordering guarantee: because cursor persistence follows a confirmed ack, a crash mid-cycle
//! re-reads and re-ships the unconfirmed batch on the next cycle; the gateway's idempotent
//! `Duplicate` path absorbs a re-ship of an already-accepted seq. At-least-once end to end
//! (with the one exception under "Residual the guard cannot close" below), converging on the ledger dedup
//! window - matching the contract `log_tailer` and `gateway::verify::GatewaySink` already
//! document on their own sides of this exact boundary.
//!
//! F1 guard: a `Duplicate` ack is only ever a safe crash-retry echo when the gateway reports
//! `next_expected_seq == batch.seq + 1` (it has exactly this batch and nothing past our own
//! expectation). If `next_expected_seq > batch.seq + 1`, the gateway's chain for this collector
//! id is AHEAD of ours - e.g. a rebuilt collector reusing an old cert CN with its shipper state
//! reset to fresh while the gateway still remembers a later confirmed seq for that id. Treating
//! that as an ordinary confirm would advance both the confirmed state and the tailer cursor past
//! records the gateway will keep silently `Duplicate`-dropping, losing them for good (the
//! opposite of at-least-once). `ship_cycle` stops with [`StopReason::ChainDiverged`] instead;
//! see `crates/shipper/src/state.rs`'s `load_or_fresh` doc and `deploy/collector.env.example`
//! for the operator-facing side of this contract.
//!
//! One batch per seq: the gateway answers `Duplicate` by seq alone, so a batch REBUILT under a
//! seq whose ack was lost (the same log with more lines, or another log, since the seq and hash
//! chain belong to the collector) would be taken as confirmed while the gateway holds the first
//! one, and its tailer's cursor would move past lines the gateway never stored. So before a
//! batch is first sent, `crate::pending::PendingBatch` keeps it durably, frame and all, and until
//! that batch is confirmed nothing else is built or sent under the chain: every pass, for every
//! log, starts by resending the stored frame (a cycle for another log sends nothing), across
//! reconnects and restarts. On confirmation the owning tailer moves past exactly the lines that
//! batch consumed: read again from the saved position the batch was read from and checked
//! against the stored batch hash and the position the first read ended at (see `ship_cycle`).
//!
//! Residual the guard cannot close: if an operator rebuilds a collector reusing an old CN
//! WITHOUT resetting the gateway state, and the gateway's remembered `last_seq` happens to
//! equal the rebuilt collector's very first post-rebuild `batch.seq`, the ack reports
//! `next_expected_seq == batch.seq + 1` and is indistinguishable from a genuine crash-retry, so
//! that one batch is silently dropped. Closing it needs a per-incarnation epoch in the identity
//! or chain (so a rebuild starts a chain the gateway recognizes as new) - deferred to SP-D
//! collector enrollment. The documented fresh-CN-or-reset procedure avoids it entirely.

use std::io;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use collector_wire::ack::{ACK_LEN, Ack, AckReason, AckStatus, decode_ack};
use collector_wire::frame::encode_frame;
use log_tailer::LogTailer;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tokio_rustls::client::TlsStream;
use tokio_rustls::rustls::ClientConfig;
use tokio_rustls::rustls::pki_types::ServerName;

use crate::batcher::Batcher;
use crate::pending::{Loaded, PendingBatch, Standing};
use crate::state::ConfirmedState;

/// TCP connect plus TLS handshake. Generous for a WAN link with packet loss, short next to "never".
const CONNECT_TIMEOUT: Duration = Duration::from_secs(20);
/// One framed batch written and its fixed-size ack read back. The gateway acks after a durable
/// spool write, so this is well above a loaded disk and far below an unbounded wait.
const BATCH_TIMEOUT: Duration = Duration::from_secs(60);

/// The connected, handshake-complete transport `ship_cycle` ships batches over.
pub type ShipperStream = TlsStream<TcpStream>;

/// Dials the gateway and reads/writes the collector/control-plane wire protocol on the
/// resulting mutual-TLS stream. Stateless: both methods are free functions grouped under this
/// type purely as a namespace, since the connection itself (not this type) is what carries
/// state across calls.
pub struct ShipperClient;

impl ShipperClient {
    /// Opens a TCP connection to `gateway_addr` and completes a mutual-TLS handshake: `tls`
    /// presents this collector's client certificate, and the gateway's server certificate is
    /// verified against `server_dns` (its SAN, per `provision_certs::provision`'s
    /// `gateway_dns`).
    pub async fn connect(
        gateway_addr: SocketAddr,
        tls: Arc<ClientConfig>,
        server_dns: &str,
    ) -> io::Result<ShipperStream> {
        Self::connect_within(gateway_addr, tls, server_dns, CONNECT_TIMEOUT).await
    }

    /// [`connect`](Self::connect) with an explicit deadline over the TCP connect and the TLS
    /// handshake together. A gateway host that accepts the connection and never answers the
    /// handshake would otherwise hold the single ship loop, and with it every log's shipping,
    /// until the kernel gives up (minutes to never) with nothing in the journal.
    pub async fn connect_within(
        gateway_addr: SocketAddr,
        tls: Arc<ClientConfig>,
        server_dns: &str,
        limit: Duration,
    ) -> io::Result<ShipperStream> {
        let domain = ServerName::try_from(server_dns)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?
            .to_owned();
        let dial = async {
            let tcp = TcpStream::connect(gateway_addr).await?;
            TlsConnector::from(tls).connect(domain, tcp).await
        };
        tokio::time::timeout(limit, dial).await.unwrap_or_else(|_| {
            Err(io::Error::new(
                io::ErrorKind::TimedOut,
                format!(
                    "gateway connect and handshake exceeded {}s",
                    limit.as_secs_f32()
                ),
            ))
        })
    }

    /// Sends one length-prefixed frame and reads back its ack: a `u32` big-endian byte length
    /// followed by the frame bytes, flushed, then a blocking `read_exact` of the fixed
    /// [`ACK_LEN`]-byte ack. Mirrors `gateway::server::handle_connection`'s read side exactly, so
    /// the two ends agree on the wire shape without either importing the other.
    pub async fn send_batch(stream: &mut ShipperStream, frame_bytes: &[u8]) -> io::Result<Ack> {
        Self::send_batch_within(stream, frame_bytes, BATCH_TIMEOUT).await
    }

    /// [`send_batch`](Self::send_batch) with an explicit deadline over the write and the ack. On
    /// expiry the caller gets `TimedOut`, `ship_cycle` rewinds the tailer over the unconfirmed
    /// batch, and the next pass redials: the same path as any other dead connection.
    pub async fn send_batch_within(
        stream: &mut ShipperStream,
        frame_bytes: &[u8],
        limit: Duration,
    ) -> io::Result<Ack> {
        tokio::time::timeout(limit, Self::exchange(stream, frame_bytes))
            .await
            .unwrap_or_else(|_| {
                Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    format!("gateway ack not received within {}s", limit.as_secs_f32()),
                ))
            })
    }

    async fn exchange(stream: &mut ShipperStream, frame_bytes: &[u8]) -> io::Result<Ack> {
        let len = frame_bytes.len() as u32;
        stream.write_all(&len.to_be_bytes()).await?;
        stream.write_all(frame_bytes).await?;
        stream.flush().await?;

        let mut ack_bytes = [0u8; ACK_LEN];
        stream.read_exact(&mut ack_bytes).await?;
        decode_ack(&ack_bytes)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))
    }
}

/// Bounds retry behavior for one ship cycle: how long to sleep between consecutive `Retry` acks
/// for the same batch, and how many consecutive retries to tolerate before giving up on this
/// batch and stopping the cycle - a gateway stuck returning `Busy`/`SpoolWriteFailed` forever must
/// not spin this collector in a tight resend loop indefinitely.
#[derive(Debug, Clone, Copy)]
pub struct RetryPolicy {
    pub backoff: Duration,
    pub max_consecutive_retries: u32,
}

impl RetryPolicy {
    pub fn new(backoff: Duration, max_consecutive_retries: u32) -> Self {
        Self {
            backoff,
            max_consecutive_retries,
        }
    }
}

/// Why `ship_cycle` stopped before `Batcher::next_batch` ran dry on its own.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StopReason {
    /// The gateway permanently rejected a batch (a broken hash chain, a seq gap, or malformed
    /// content). Not retried: an alert-worthy condition the operator must resolve, not a
    /// transient one blind-retrying could paper over.
    Rejected { reason: AckReason },
    /// The gateway returned `Retry` more than `RetryPolicy::max_consecutive_retries` times in a
    /// row for the same batch.
    RetriesExhausted,
    /// The gateway's `Duplicate` ack reports it is already ahead of what this batch would
    /// confirm (`gateway_next_expected > our_seq + 1`): this collector's local chain has
    /// diverged from the gateway's, most likely a rebuilt/re-provisioned collector reusing an
    /// old collector id (cert CN) whose shipper state was reset to fresh while the gateway still
    /// remembers a later confirmed seq for that id, or a lost/restored `ConfirmedState`. Not a
    /// crash-retry (that case is `gateway_next_expected == our_seq + 1` and is absorbed as a
    /// normal confirm) - treating it as one would silently drop every new record from `our_seq`
    /// onward, since the gateway will keep echoing `Duplicate` for seqs it already has. An
    /// operator must resync: reset the gateway's per-collector state for this collector id, or
    /// re-provision this collector under a FRESH collector id (CN).
    ChainDiverged {
        our_seq: u64,
        gateway_next_expected: u64,
    },
    /// The record of an earlier batch in flight was unreadable (set aside as
    /// `<key>.pending.damaged`), and the gateway answered `Duplicate` for this seq: it holds a
    /// batch under it, which may be the lost one rather than this one. Taking that as
    /// confirmation could move a cursor past lines the gateway never stored, so nothing is
    /// advanced and the lines stay in the log. An operator resets the chain on both sides.
    UnprovenDuplicate { seq: u64 },
}

/// What one `ship_cycle` call accomplished.
#[derive(Debug, Clone, Copy, Default)]
pub struct CycleReport {
    /// How many batches were shipped and durably confirmed (`Accepted` or `Duplicate`) this
    /// cycle. `0` with `stopped == None` means the tailer had nothing new to offer - the signal
    /// Task 12's outer loop uses to decide whether to sleep `POLL_INTERVAL_MS` before the next
    /// cycle.
    pub batches_shipped: u64,
    /// How many lines this cycle read and did not ship because the origin policy refused them
    /// for this log (see `Batcher::next_batch`). A batch that is rewound and read again counts
    /// its refused lines again.
    pub refused: u64,
    pub stopped: Option<StopReason>,
}

/// Runs one ship cycle to completion: loads the confirmed state for `key`, then repeatedly
/// builds the next batch from `tailer` and ships it over `stream` until `Batcher::next_batch`
/// returns no batch (nothing left to ship) or the cycle stops early (see [`StopReason`]).
/// `label` is the `PROPOLIS_SHIPPER_SENSOR_LOGS` name of the log `tailer` reads: the batcher
/// holds each line to the origin policy for it, and a read whose lines were all refused is
/// passed (cursor persisted) without ending the cycle.
///
/// Per batch: `Accepted`, and a `Duplicate` that is exactly this batch's own crash-retry echo
/// (`ack.next_expected_seq == batch.seq + 1`), advance the confirmed state, persist it, THEN
/// persist the tailer cursor (in that order - see the module doc's ordering guarantee); a
/// `Duplicate` reporting the gateway ahead of that (`ack.next_expected_seq > batch.seq + 1`)
/// stops the cycle with [`StopReason::ChainDiverged`] instead of advancing anything (see F1 in
/// the module doc); `Retry` sleeps `retry.backoff` and resends the SAME batch, bounded by
/// `retry.max_consecutive_retries`; `Reject` logs the reason and stops the cycle immediately
/// without advancing anything.
///
/// Every path that stops without a confirmed ack - divergence, retry exhaustion, rejection, or
/// a dead connection - rewinds the tailer over the unconfirmed batch. Leaving the cursor
/// unpersisted is not enough on its own: `run_ship_loop` reuses this tailer for the next pass,
/// so an un-rewound read means the next pass starts past records the gateway never took, and
/// the first batch it does get accepted persists a cursor beyond them.
///
/// The batch in flight (see the module doc and `crate::pending`): before its first send each
/// batch is recorded durably, and a record that cannot be written stops the cycle with an error
/// and nothing sent. A cycle that finds a record settles it before building anything: for
/// another log's batch it returns at once with nothing sent; for this log's it resends the
/// stored frame and, once the gateway confirms it, stores the confirmed state, then moves this
/// tailer past exactly the lines the batch consumed by reading them again from the saved read
/// position the batch was read from and checking that they make the stored batch and end where
/// the first read ended. If the saved position has moved on (it was already persisted past the
/// batch) the cursor is left alone; if the lines read there no longer make the batch or end
/// elsewhere (the log was rotated away, truncated or replaced, or the batch came from a rotated
/// file a restart no longer drains) the cursor is left where it was too, so lines are sent twice
/// rather than skipped.
/// Only then is the record dropped. A confirmed batch persists the cursor before committing the
/// read, so a failed persist rewinds instead of leaving memory ahead of disk.
///
/// What each stop does with the record: every one keeps it. `Retry` exhaustion, a dead
/// connection and `ChainDiverged` leave the gateway possibly holding the batch, and so does a
/// `Reject`: the answer is not final, since a gateway that lost or could not read its state for
/// this collector answers from a fresh chain and rejects a frame it holds in its spool. Once its
/// state is put back, the same frame is confirmed; a batch rebuilt under the seq would instead be
/// confirmed by the `Duplicate` for the one held, and its lines lost. The stop stays permanent
/// until an operator acts, and the reset on both sides deletes the record (a record it leaves
/// behind does not block the new chain, see below). A record that does not fit the confirmed
/// state (left from before a chain reset or a rollback) is dropped with a warning and the cursor
/// left where it is; a confirmed state file that exists and cannot be read fails the pass
/// instead, record kept, since a fresh chain would make every record look like that. An
/// unreadable record is set aside as `<key>.pending.damaged`; until a batch is `Accepted` after
/// that, a `Duplicate` for the next seq stops the cycle with [`StopReason::UnprovenDuplicate`]
/// instead of confirming anything.
pub async fn ship_cycle(
    stream: &mut ShipperStream,
    tailer: &mut LogTailer,
    label: &str,
    state_dir: &Path,
    key: &str,
    max_records: usize,
    retry: RetryPolicy,
) -> io::Result<CycleReport> {
    let mut report = CycleReport::default();

    let loaded = PendingBatch::load(state_dir, key)?;
    let mut confirmed = confirmed_state_for(&loaded, state_dir, key)?;
    if let Loaded::Unreadable(why) = &loaded {
        tracing::error!(
            key,
            reason = %why,
            "shipper: the record of the batch in flight cannot be read; setting it aside as \
             <collector id>.pending.damaged in the state directory. The next batch is built from \
             the saved read positions, and if the gateway already holds a batch under its \
             sequence number the shipper stops instead of taking that as confirmation"
        );
        PendingBatch::set_aside_unreadable(state_dir, key)?;
    }
    let mut unproven = PendingBatch::unreadable_set_aside(state_dir, key);
    if let Loaded::Found(pending) = loaded {
        if !pending.is_for(label, tailer.log_path()) {
            // Another log's batch is in flight. Nothing may go out under the chain until it is
            // settled, and only that log's own cycle can move its cursor.
            tracing::debug!(
                key,
                sensor = label,
                in_flight_from = %pending.label,
                seq = pending.seq,
                "shipper: another log's batch is in flight; this log waits for it"
            );
            return Ok(report);
        }
        let ctx = Settle {
            state_dir,
            key,
            retry,
            unproven,
        };
        match settle(
            stream,
            Some((tailer, label)),
            false,
            &pending,
            &mut confirmed,
            ctx,
        )
        .await?
        {
            Settled::Confirmed => {
                report.batches_shipped += 1;
                unproven = false;
            }
            Settled::Stale => {}
            Settled::Stopped(reason) => {
                report.stopped = Some(reason);
                return Ok(report);
            }
        }
    }

    loop {
        // The record names the saved position the batch is read from, so that position must be
        // the one this read starts at. It already is unless an earlier persist failed.
        let start = tailer.cursor_to_persist();
        if tailer.saved_cursor()? != Some(start) {
            tailer.persist_cursor()?;
        }
        let next = Batcher::next_batch(
            tailer,
            label,
            confirmed.last_seq,
            confirmed.last_batch_hash,
            max_records,
        );
        report.refused += next.refused;
        let Some(batch) = next.batch else {
            if next.refused == 0 {
                break;
            }
            // Every line of this read was refused by the origin policy. Like a line intake
            // rejects, they are passed for good: every batch before them in this cycle was
            // confirmed, so nothing unshipped sits behind the cursor, and a log that carried
            // nothing else would otherwise be read from the same place after every restart.
            // More lines may follow, so the cycle carries on.
            tailer.commit_batch();
            tailer.persist_cursor()?;
            continue;
        };
        let pending = PendingBatch {
            label: label.to_string(),
            log_path: tailer.log_path().to_path_buf(),
            seq: batch.seq,
            prev_batch_hash: batch.prev_batch_hash,
            batch_hash: batch.batch_hash,
            lines_read: next.lines_read,
            cursor_before: Some(start),
            cursor_after: Some(tailer.cursor_to_persist()),
            frame: encode_frame(&batch),
        };
        if let Err(e) = pending.store(state_dir, key) {
            // Without the record a lost ack would let another batch go out under this seq, so
            // this one does not go out at all. Its lines stay in the log for the next pass.
            tailer.rewind_batch();
            tracing::error!(
                key,
                sensor = label,
                seq = batch.seq,
                error = %e,
                "shipper: cannot record the batch about to be sent in the state directory; not \
                 sending it. Its lines stay in the log and are tried again next pass; check that \
                 the state directory's filesystem is writable and not full"
            );
            return Err(e);
        }
        let ctx = Settle {
            state_dir,
            key,
            retry,
            unproven,
        };
        match settle(
            stream,
            Some((tailer, label)),
            true,
            &pending,
            &mut confirmed,
            ctx,
        )
        .await?
        {
            Settled::Confirmed => {
                report.batches_shipped += 1;
                unproven = false;
            }
            Settled::Stale => {}
            Settled::Stopped(reason) => {
                report.stopped = Some(reason);
                return Ok(report);
            }
        }
    }

    Ok(report)
}

/// Settles a batch in flight whose log is no longer one this shipper tails (its entry left
/// `PROPOLIS_SHIPPER_SENSOR_LOGS`, or was renamed): resends the stored frame so the seq is
/// settled by the batch the gateway may hold, then drops the record. There is no cursor to move;
/// a log that comes back is read from its saved position, so its lines are sent again rather
/// than skipped. `CycleReport::batches_shipped` is 1 when the batch was confirmed.
pub async fn settle_orphaned(
    stream: &mut ShipperStream,
    state_dir: &Path,
    key: &str,
    retry: RetryPolicy,
) -> io::Result<CycleReport> {
    let mut report = CycleReport::default();
    let loaded = PendingBatch::load(state_dir, key)?;
    let mut confirmed = confirmed_state_for(&loaded, state_dir, key)?;
    let Loaded::Found(pending) = loaded else {
        return Ok(report);
    };
    let ctx = Settle {
        state_dir,
        key,
        retry,
        unproven: PendingBatch::unreadable_set_aside(state_dir, key),
    };
    match settle(stream, None, false, &pending, &mut confirmed, ctx).await? {
        Settled::Confirmed => report.batches_shipped = 1,
        Settled::Stale => {}
        Settled::Stopped(reason) => report.stopped = Some(reason),
    }
    Ok(report)
}

/// The confirmed state a pass works against. With a batch in flight, a state file that exists
/// and cannot be read is an error for this pass rather than a fresh chain: against a fresh chain
/// the record would stand stale and be dropped, and the batch rebuilt under its seq would then be
/// confirmed by the gateway's `Duplicate` for the first one. A missing or unparseable file still
/// counts as fresh, as it always has (a record of seq 2 or later is then stale, and the batch
/// built for seq 1 meets `ChainDiverged` if the gateway is ahead).
fn confirmed_state_for(loaded: &Loaded, state_dir: &Path, key: &str) -> io::Result<ConfirmedState> {
    Ok(match loaded {
        Loaded::Found(_) => {
            ConfirmedState::load(state_dir, key)?.unwrap_or_else(ConfirmedState::fresh)
        }
        Loaded::Nothing | Loaded::Unreadable(_) => ConfirmedState::load_or_fresh(state_dir, key),
    })
}

/// What became of a recorded batch on one attempt.
enum Settled {
    /// The gateway holds it, the confirmed state says so and the record is gone.
    Confirmed,
    /// The record fitted no position of the chain and was dropped.
    Stale,
    Stopped(StopReason),
}

/// The parts of one settle attempt that do not change during it.
#[derive(Clone, Copy)]
struct Settle<'a> {
    state_dir: &'a Path,
    key: &'a str,
    retry: RetryPolicy,
    /// An unreadable record was set aside and nothing has been accepted since: a `Duplicate`
    /// cannot prove the gateway holds this batch.
    unproven: bool,
}

/// Takes the recorded batch `pending` to a confirmed state, or to a stop. `owner` is the log the
/// batch was read from and its label, `None` when no tailer reads that log any more; `held` says
/// the owner still holds the batch's read uncommitted (a batch built in this cycle), so it is
/// committed or rewound rather than read again.
async fn settle(
    stream: &mut ShipperStream,
    mut owner: Option<(&mut LogTailer, &str)>,
    held: bool,
    pending: &PendingBatch,
    confirmed: &mut ConfirmedState,
    ctx: Settle<'_>,
) -> io::Result<Settled> {
    let Settle { state_dir, key, .. } = ctx;
    let rewind = |owner: &mut Option<(&mut LogTailer, &str)>| {
        if held && let Some((tailer, _)) = owner {
            tailer.rewind_batch();
        }
    };
    match pending.standing(confirmed) {
        Standing::Stale => {
            tracing::warn!(
                key,
                seq = pending.seq,
                confirmed_seq = confirmed.last_seq,
                "shipper: dropping a record of a batch in flight that does not follow the \
                 confirmed state (left from before a chain reset or a rollback); read positions \
                 are left where they are, so its lines are sent again if they are still in the log"
            );
            PendingBatch::remove(state_dir, key)?;
            return Ok(Settled::Stale);
        }
        Standing::Confirmed => {}
        Standing::Unconfirmed => {
            let outcome = match send_until_answered(stream, pending, ctx).await {
                Ok(outcome) => outcome,
                Err(e) => {
                    // The connection died mid-batch. A held read is rewound, or the caller's
                    // next pass on this tailer would start past lines the gateway may not hold.
                    // The record stays: the next pass resends this frame.
                    rewind(&mut owner);
                    return Err(e);
                }
            };
            if let Some(reason) = outcome {
                // Every stop keeps the record, a `Reject` included: a gateway that lost or could
                // not read its state for this collector answers from a fresh chain and rejects a
                // frame it holds in its spool. Once its state is put back, only this exact frame
                // may go out under the seq; a batch rebuilt in its place would be confirmed by
                // the `Duplicate` for this one. The reset on both sides deletes the record.
                rewind(&mut owner);
                return Ok(Settled::Stopped(reason));
            }
            let now = ConfirmedState {
                last_seq: pending.seq,
                last_batch_hash: pending.batch_hash,
            };
            // The confirmed state first: until it is stored, the record is what says this seq is
            // taken, and a failure here leaves it to be resent and confirmed again.
            if let Err(e) = now.store(state_dir, key) {
                rewind(&mut owner);
                return Err(e);
            }
            *confirmed = now;
        }
    }

    if let Some((tailer, label)) = owner {
        if held {
            // Persist before committing, so a failed persist can still rewind and memory never
            // runs ahead of the saved position the next record will name.
            if let Err(e) = tailer.persist_cursor() {
                tailer.rewind_batch();
                return Err(e);
            }
            tailer.commit_batch();
        } else {
            move_past_settled(tailer, label, pending, key)?;
        }
    }
    PendingBatch::remove(state_dir, key)?;
    if ctx.unproven {
        // A batch was confirmed under the seq after the unreadable record's, so the gateway's
        // chain and this one agree again and the set-aside record is no longer needed.
        PendingBatch::clear_unreadable(state_dir, key)?;
        tracing::info!(
            key,
            seq = pending.seq,
            "shipper: the chain is confirmed past the unreadable record; deleted \
             <collector id>.pending.damaged"
        );
    }
    Ok(Settled::Confirmed)
}

/// Moves `tailer` past the lines of a confirmed batch it no longer holds in memory: after a
/// reconnect it was rewound to the batch's start, and after a restart it starts from the saved
/// position. Either way, if that saved position is still the one the batch was read from, the
/// same number of lines is read again and must make the same batch (same records, so the same
/// hash) and end at the position the first read ended at before the cursor is moved; a log that
/// has grown since does not matter, as only `lines_read` lines are read.
///
/// The end position is what tells a batch drained from a rename-rotated file apart from lines in
/// the new file that repeat it: the saved position names the new file at its start before and
/// after every drained batch but the first, and after a restart the drain is gone, so reading
/// again takes the new file's lines and moves along it, where the drain left the position where
/// it was. Without that check those new lines would be committed unsent.
fn move_past_settled(
    tailer: &mut LogTailer,
    label: &str,
    pending: &PendingBatch,
    key: &str,
) -> io::Result<()> {
    if tailer.saved_cursor()? != pending.cursor_before {
        // Saved past the batch after it was confirmed, before the record was dropped.
        return Ok(());
    }
    let again = Batcher::next_batch(
        tailer,
        label,
        pending.seq.saturating_sub(1),
        pending.prev_batch_hash,
        pending.lines_read,
    );
    // Only the file and offset: the tailer widens a short fingerprint as a small file grows,
    // without moving the position, so the rest may differ for the same stretch of the same file.
    let ended_where_it_did = match (tailer.cursor_to_persist(), pending.cursor_after) {
        (now, Some(then)) => now.inode == then.inode && now.offset == then.offset,
        (_, None) => false,
    };
    if again.batch.map(|b| b.batch_hash) != Some(pending.batch_hash) || !ended_where_it_did {
        tailer.rewind_batch();
        tracing::warn!(
            key,
            sensor = label,
            seq = pending.seq,
            "shipper: the gateway holds the batch that was in flight, but this log no longer has \
             its lines where they were read (rotated away, truncated or replaced in between); the \
             read position is left where it was, so any of those lines still in the log are sent \
             again"
        );
        return Ok(());
    }
    if let Err(e) = tailer.persist_cursor() {
        tailer.rewind_batch();
        return Err(e);
    }
    tailer.commit_batch();
    Ok(())
}

/// Sends the recorded frame until the gateway answers it for good: `None` when it is confirmed
/// (`Accepted`, or the `Duplicate` echo of this exact seq), the stop otherwise. `Retry` resends
/// the same bytes after `retry.backoff`, at most `retry.max_consecutive_retries` times.
async fn send_until_answered(
    stream: &mut ShipperStream,
    pending: &PendingBatch,
    ctx: Settle<'_>,
) -> io::Result<Option<StopReason>> {
    let Settle {
        key,
        retry,
        unproven,
        ..
    } = ctx;
    let seq = pending.seq;
    let mut consecutive_retries: u32 = 0;
    loop {
        let ack = ShipperClient::send_batch(stream, &pending.frame).await?;
        match ack.status {
            AckStatus::Accepted => return Ok(None),
            AckStatus::Duplicate if ack.next_expected_seq == seq + 1 && unproven => {
                tracing::error!(
                    key,
                    seq,
                    "shipper: the gateway already holds a batch under this sequence number, and \
                     since the record of the batch in flight was unreadable it may not be this \
                     one; stopping without moving any read position, so no line is skipped. \
                     Reset the chain on both sides to continue"
                );
                return Ok(Some(StopReason::UnprovenDuplicate { seq }));
            }
            AckStatus::Duplicate if ack.next_expected_seq == seq + 1 => {
                // The gateway's chain for this collector id ends with this seq, and the only
                // frame ever sent under it is this one (the record guarantees that), so this is
                // the echo of an earlier attempt whose ack was lost. Same as Accepted.
                return Ok(None);
            }
            AckStatus::Duplicate => {
                // ack.next_expected_seq > seq + 1 (a Duplicate can never report less): the
                // gateway is ahead of this collector's local chain by more than this batch. Not
                // a crash retry - state divergence. Advancing confirmed or the tailer cursor here
                // would silently drop every record from seq onward, since the gateway will keep
                // echoing Duplicate for seqs it already has.
                tracing::error!(
                    key,
                    our_seq = seq,
                    gateway_next_expected = ack.next_expected_seq,
                    "shipper: this collector's local chain has diverged from the gateway's \
                     (likely a rebuilt collector reusing an identity, or a lost/restored \
                     shipper state); stopping ship cycle WITHOUT advancing confirmed state \
                     or the tailer cursor - an operator must resync by resetting the \
                     gateway's per-collector state for this collector id, or by \
                     re-provisioning this collector with a FRESH collector id (CN)"
                );
                return Ok(Some(StopReason::ChainDiverged {
                    our_seq: seq,
                    gateway_next_expected: ack.next_expected_seq,
                }));
            }
            AckStatus::Retry => {
                consecutive_retries += 1;
                if consecutive_retries > retry.max_consecutive_retries {
                    tracing::error!(
                        key,
                        seq,
                        attempts = consecutive_retries,
                        "gateway kept returning Retry past the consecutive-retry bound; \
                         stopping ship cycle"
                    );
                    return Ok(Some(StopReason::RetriesExhausted));
                }
                tracing::warn!(
                    key,
                    seq,
                    attempt = consecutive_retries,
                    reason = ?ack.reason,
                    "gateway asked for retry; backing off and resending the same batch"
                );
                tokio::time::sleep(retry.backoff).await;
            }
            AckStatus::Reject => {
                tracing::error!(
                    key,
                    seq,
                    reason = ?ack.reason,
                    "gateway rejected batch; stopping ship cycle without advancing state. The \
                     record of the batch in flight is kept, since a gateway whose chain state \
                     was lost or unreadable rejects a batch it may hold; the reset on both sides \
                     clears it"
                );
                return Ok(Some(StopReason::Rejected { reason: ack.reason }));
            }
        }
    }
}
