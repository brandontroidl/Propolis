//! Assembles the next sequenced, hash-chained [`Batch`] from whole lines read off a
//! [`LogTailer`]. Pure with respect to the network: this module only reads the tailer and builds
//! frames in memory, it never ships anything.
use collector_wire::frame::{Batch, MAX_FRAME_LEN, MAX_RECORD_LEN};
use log_tailer::LogTailer;

/// Default cap on records per batch, chosen so a batch built at this cap can never exceed
/// [`MAX_FRAME_LEN`] under the tailer's own per-line bound.
///
/// A record can be at most `MAX_RECORD_LEN` (1 MiB) - `log-tailer::tailer::MAX_LINE_BYTES` is
/// set to the identical value and discards anything longer, so a tailed line can never actually
/// exceed it. `16 * MAX_RECORD_LEN` is exactly `MAX_FRAME_LEN` (16 MiB); the frame's own header,
/// per-record length prefixes, and trailer add roughly 145 bytes of overhead on top, so a batch
/// of 16 records that are EACH simultaneously at the exact 1 MiB cap would slip past
/// `MAX_FRAME_LEN` by that margin. In practice this is not reachable: sensors bound their
/// captured fields far below 1 MiB (see the `log-tailer` module doc), so real records never
/// approach the per-record cap, let alone all 16 at once. This constant is therefore a strong
/// practical bound, not a byte-exact mathematical guarantee; if that residual margin ever
/// matters, split-by-bytes accounting belongs at the call site (or `encode_frame`'s own
/// `MAX_FRAME_LEN` check on the shipping path), not here.
pub const DEFAULT_MAX_RECORDS: usize = 16;

/// Builds a [`Batch`] out of up to `max_records` whole lines tailed from a sensor log.
pub struct Batcher;

impl Batcher {
    /// Reads up to `max_records` complete lines from `tailer` and, if any were available, wraps
    /// them in the next batch: `seq = last_seq + 1`, `prev_batch_hash = last_hash`.
    ///
    /// Returns `None` when the tailer has nothing new to offer (an empty batch cannot be built:
    /// `Batch::new` requires at least one record).
    ///
    /// Does NOT call `tailer.persist_cursor()`. `read_batch` already advances the tailer's
    /// in-memory cursor for the lines it returns, but persisting that cursor is deliberately
    /// deferred to ack time (Task 11): if this batch is built but never confirmed by the
    /// gateway's `Accepted`/`Duplicate` response, the unpersisted cursor means a restart re-reads
    /// and re-ships it rather than silently dropping it.
    pub fn next_batch(
        tailer: &mut LogTailer,
        last_seq: u64,
        last_hash: [u8; 32],
        max_records: usize,
    ) -> Option<Batch> {
        let lines = tailer.read_batch(max_records);
        if lines.is_empty() {
            return None;
        }

        let records: Vec<Vec<u8>> = lines
            .into_iter()
            .map(|line| {
                // `read_batch` only ever returns complete, `\n`-stripped lines split on `\n`, so
                // a returned line cannot itself contain an embedded newline - `Batch::new`'s wire
                // encoding could not round-trip one (see `collector_wire::frame::FrameError::RecordNewline`).
                debug_assert!(
                    !line.as_bytes().contains(&b'\n'),
                    "log-tailer must never return a line containing an embedded newline"
                );
                debug_assert!(
                    line.len() as u32 <= MAX_RECORD_LEN,
                    "log-tailer must never return a line longer than MAX_RECORD_LEN"
                );
                line.into_bytes()
            })
            .collect();

        Some(Batch::new(last_seq + 1, last_hash, records))
    }
}

const _: () = assert!(
    (DEFAULT_MAX_RECORDS as u64) * (MAX_RECORD_LEN as u64) <= MAX_FRAME_LEN as u64,
    "DEFAULT_MAX_RECORDS * MAX_RECORD_LEN must stay within MAX_FRAME_LEN (see the doc comment \
     above for the remaining framing-overhead margin this does not account for)"
);
