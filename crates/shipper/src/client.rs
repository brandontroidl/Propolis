//! mTLS ship client and one-cycle ship loop: dials the gateway, ships each sequenced batch
//! `batcher::Batcher` builds, and advances both the confirmed-seq state and the tailer cursor
//! only once the gateway has durably acked a batch `Accepted` or `Duplicate`.
//!
//! Ordering guarantee: because cursor persistence follows a confirmed ack, a crash mid-cycle
//! re-reads and re-ships the unconfirmed batch on the next cycle; the gateway's idempotent
//! `Duplicate` path absorbs a re-ship of an already-accepted seq. At-least-once end to end,
//! converging on the ledger dedup window - matching the contract `log_tailer` and
//! `gateway::verify::GatewaySink` already document on their own sides of this exact boundary.
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
use crate::state::ConfirmedState;

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
        let tcp = TcpStream::connect(gateway_addr).await?;
        let domain = ServerName::try_from(server_dns)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?
            .to_owned();
        let connector = TlsConnector::from(tls);
        connector.connect(domain, tcp).await
    }

    /// Sends one length-prefixed frame and reads back its ack: a `u32` big-endian byte length
    /// followed by the frame bytes, flushed, then a blocking `read_exact` of the fixed
    /// [`ACK_LEN`]-byte ack. Mirrors `gateway::server::handle_connection`'s read side exactly, so
    /// the two ends agree on the wire shape without either importing the other.
    pub async fn send_batch(stream: &mut ShipperStream, frame_bytes: &[u8]) -> io::Result<Ack> {
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
}

/// What one `ship_cycle` call accomplished.
#[derive(Debug, Clone, Copy, Default)]
pub struct CycleReport {
    /// How many batches were shipped and durably confirmed (`Accepted` or `Duplicate`) this
    /// cycle. `0` with `stopped == None` means the tailer had nothing new to offer - the signal
    /// Task 12's outer loop uses to decide whether to sleep `POLL_INTERVAL_MS` before the next
    /// cycle.
    pub batches_shipped: u64,
    pub stopped: Option<StopReason>,
}

/// Runs one ship cycle to completion: loads the confirmed state for `key`, then repeatedly
/// builds the next batch from `tailer` and ships it over `stream` until `Batcher::next_batch`
/// returns `None` (nothing left to ship) or the cycle stops early (see [`StopReason`]).
///
/// Per batch: `Accepted`, and a `Duplicate` that is exactly this batch's own crash-retry echo
/// (`ack.next_expected_seq == batch.seq + 1`), advance the confirmed state, persist it, THEN
/// persist the tailer cursor (in that order - see the module doc's ordering guarantee); a
/// `Duplicate` reporting the gateway ahead of that (`ack.next_expected_seq > batch.seq + 1`)
/// stops the cycle with [`StopReason::ChainDiverged`] instead of advancing anything (see F1 in
/// the module doc); `Retry` sleeps `retry.backoff` and resends the SAME batch, bounded by
/// `retry.max_consecutive_retries`; `Reject` logs the reason and stops the cycle immediately
/// without advancing anything.
pub async fn ship_cycle(
    stream: &mut ShipperStream,
    tailer: &mut LogTailer,
    state_dir: &Path,
    key: &str,
    max_records: usize,
    retry: RetryPolicy,
) -> io::Result<CycleReport> {
    let mut confirmed = ConfirmedState::load_or_fresh(state_dir, key);
    let mut report = CycleReport::default();

    while let Some(batch) = Batcher::next_batch(
        tailer,
        confirmed.last_seq,
        confirmed.last_batch_hash,
        max_records,
    ) {
        let frame = encode_frame(&batch);
        let mut consecutive_retries: u32 = 0;

        loop {
            let ack = ShipperClient::send_batch(stream, &frame).await?;
            match ack.status {
                AckStatus::Accepted => {
                    confirmed = ConfirmedState {
                        last_seq: batch.seq,
                        last_batch_hash: batch.batch_hash,
                    };
                    // Only now is the batch durably on the control plane: persist the
                    // confirmed-seq state first, then the tailer cursor. Advancing the cursor
                    // before a confirmed ack would lose unconfirmed lines on a crash.
                    confirmed.store(state_dir, key)?;
                    tailer.persist_cursor()?;
                    report.batches_shipped += 1;
                    break;
                }
                AckStatus::Duplicate if ack.next_expected_seq == batch.seq + 1 => {
                    // The gateway's chain for this collector id has exactly this batch as its
                    // last confirmed seq and nothing beyond it: a benign crash-retry echo (this
                    // exact batch was accepted on a prior attempt whose ack this shipper never
                    // saw). Safe to confirm and advance, same as Accepted.
                    confirmed = ConfirmedState {
                        last_seq: batch.seq,
                        last_batch_hash: batch.batch_hash,
                    };
                    confirmed.store(state_dir, key)?;
                    tailer.persist_cursor()?;
                    report.batches_shipped += 1;
                    break;
                }
                AckStatus::Duplicate => {
                    // ack.next_expected_seq > batch.seq + 1 (a Duplicate can never report less):
                    // the gateway is ahead of this collector's local chain by more than this
                    // batch. Not a crash retry - state divergence. Advancing confirmed or the
                    // tailer cursor here would silently drop every record from batch.seq onward,
                    // since the gateway will keep echoing Duplicate for seqs it already has.
                    tracing::error!(
                        key,
                        our_seq = batch.seq,
                        gateway_next_expected = ack.next_expected_seq,
                        "shipper: this collector's local chain has diverged from the gateway's \
                         (likely a rebuilt collector reusing an identity, or a lost/restored \
                         shipper state); stopping ship cycle WITHOUT advancing confirmed state \
                         or the tailer cursor - an operator must resync by resetting the \
                         gateway's per-collector state for this collector id, or by \
                         re-provisioning this collector with a FRESH collector id (CN)"
                    );
                    report.stopped = Some(StopReason::ChainDiverged {
                        our_seq: batch.seq,
                        gateway_next_expected: ack.next_expected_seq,
                    });
                    return Ok(report);
                }
                AckStatus::Retry => {
                    consecutive_retries += 1;
                    if consecutive_retries > retry.max_consecutive_retries {
                        tracing::error!(
                            key,
                            seq = batch.seq,
                            attempts = consecutive_retries,
                            "gateway kept returning Retry past the consecutive-retry bound; \
                             stopping ship cycle"
                        );
                        report.stopped = Some(StopReason::RetriesExhausted);
                        return Ok(report);
                    }
                    tracing::warn!(
                        key,
                        seq = batch.seq,
                        attempt = consecutive_retries,
                        reason = ?ack.reason,
                        "gateway asked for retry; backing off and resending the same batch"
                    );
                    tokio::time::sleep(retry.backoff).await;
                    // Loop again without rebuilding the batch: the SAME frame is resent.
                }
                AckStatus::Reject => {
                    tracing::error!(
                        key,
                        seq = batch.seq,
                        reason = ?ack.reason,
                        "gateway rejected batch; stopping ship cycle without advancing state"
                    );
                    report.stopped = Some(StopReason::Rejected { reason: ack.reason });
                    return Ok(report);
                }
            }
        }
    }

    Ok(report)
}
