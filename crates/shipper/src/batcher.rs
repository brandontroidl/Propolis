//! Assembles the next sequenced, hash-chained [`Batch`] from whole lines read off a
//! [`LogTailer`]. Pure with respect to the network: this module only reads the tailer and builds
//! frames in memory, it never ships anything.
use collector_wire::frame::{Batch, MAX_FRAME_LEN, MAX_RECORD_LEN};
use log_tailer::LogTailer;

/// Largest record count for which a batch is GUARANTEED to encode within [`MAX_FRAME_LEN`], no
/// matter how large the individual records are (up to their own [`MAX_RECORD_LEN`] cap).
///
/// A record can be at most `MAX_RECORD_LEN` (1 MiB): `log-tailer::tailer::MAX_LINE_BYTES` is set
/// to the identical value and discards anything longer, so a tailed line can never actually
/// exceed it - and a compromised or malfunctioning collector writing many near-max-size lines
/// is a real, not merely theoretical, way to hit this worst case. The wire encoding
/// (`collector_wire::frame`) costs, per record, its `MAX_RECORD_LEN` bytes plus a 4-byte length
/// prefix; the frame overall costs a 49-byte header and a 32-byte trailer on top of that (see
/// `HEADER_LEN`/`TRAILER_LEN` in `collector_wire::frame`, not public, so this bounds them with a
/// generous 128-byte allowance instead of importing the exact figures). `n` records this large is
/// safe only while `n * (MAX_RECORD_LEN + 4) + 128 <= MAX_FRAME_LEN`; the compile-time assertion
/// below checks the exact value chosen here against that inequality, so a future change to either
/// `collector-wire` constant that breaks the bound fails the build instead of silently shipping
/// an unshippable batch (a batch the gateway would drop as `FrameTooLarge` and Task 11's ship
/// loop would then retry forever).
pub const MAX_RECORDS_FRAME_SAFE: usize = 15;

const _: () = assert!(
    MAX_RECORDS_FRAME_SAFE * (MAX_RECORD_LEN as usize + 4) + 128 <= MAX_FRAME_LEN,
    "MAX_RECORDS_FRAME_SAFE no longer guarantees every batch fits MAX_FRAME_LEN - recompute it \
     against the current MAX_RECORD_LEN/MAX_FRAME_LEN before changing this constant"
);

/// Default cap on records per batch. Set to [`MAX_RECORDS_FRAME_SAFE`] so the default itself
/// carries the frame-fit guarantee; `next_batch` also clamps any caller-supplied `max_records`
/// to the same ceiling, so a larger configured value (e.g. the shipper config's own default of
/// 16) can never produce an oversized frame either.
pub const DEFAULT_MAX_RECORDS: usize = MAX_RECORDS_FRAME_SAFE;

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
        // Clamp at the read, not after: reading MAX_RECORDS_FRAME_SAFE+1 lines and then
        // dropping the last one would still advance the tailer's cursor past it (`read_batch`
        // consumes what it returns), permanently losing that line. Clamping the count passed
        // into `read_batch` means the tailer only ever consumes what this batch will actually
        // carry, and this also holds even when `max_records` is a caller-configured value
        // larger than the frame-safe ceiling (see `DEFAULT_MAX_RECORDS`'s doc comment).
        let n = max_records.min(MAX_RECORDS_FRAME_SAFE);
        let lines = tailer.read_batch(n);
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
