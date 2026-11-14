//! Assembles the next sequenced, hash-chained [`Batch`] from whole lines read off a
//! [`LogTailer`]. Pure with respect to the network: this module only reads the tailer and builds
//! frames in memory, it never ships anything.
//!
//! It is also the last place a line's origin is known. Each sensor on a collector writes its own
//! log as its own user, and the batches built here from all of them become one stream at the
//! gateway, where nothing says which log a record came from. So a line is held to the origin
//! policy for the log it was read from (`sensor_wire::origin::check`) before it is batched, and a
//! line the policy refuses is not shipped.
use collector_wire::frame::{Batch, MAX_FRAME_LEN, MAX_RECORD_LEN};
use log_tailer::LogTailer;
use sensor_wire::origin::{self, OriginError, Violation};
use sensor_wire::{SIGNAL_SENSOR_STATS, SensorEvent, SensorStats, StatsRejected};

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

/// What one [`Batcher::next_batch`] call made of the lines it read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NextBatch {
    /// The next batch, or `None` when the tailer had nothing new to offer or none of the lines
    /// it read may be shipped (an empty batch cannot be built: `Batch::new` requires at least one
    /// record).
    pub batch: Option<Batch>,
    /// Lines read and left out because the origin policy refused them for this log.
    pub refused: u64,
    /// Every line the tailer handed out for this call, refused and over-length ones included:
    /// how far reading the same place again must go to cover exactly what this batch consumed.
    pub lines_read: usize,
}

/// Why [`admit`] refused a line.
#[derive(Debug)]
enum Refusal {
    /// The line broke the origin policy for its log.
    Origin(OriginError),
    /// The line is a `sensor_stats` line that is not well formed, so it names no sensor this
    /// check could hold to the log.
    Stats(StatsRejected),
}

impl std::fmt::Display for Refusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Origin(e) => e.fmt(f),
            Self::Stats(e) => write!(f, "malformed sensor_stats line: {e}"),
        }
    }
}

/// Whether a line read from the log labelled `label` may be shipped.
///
/// Only a line that parses as a sensor event is judged. Anything else is shipped as it is: the
/// control plane rejects and counts a line it cannot parse, as it does on a single node, and
/// dropping it here would hide it from that count.
///
/// A sensor's own `sensor_stats` line has no row in the policy (`origin::check` would refuse it
/// from every log), but the control plane reads this collector's whole stream under one label
/// that is bound to no sensor, and so stores a stats line under whatever sensor it names. Here is
/// the last place that can stop the telnet log writing ssh's counters, so a stats line is held to
/// the two rules of the policy that concern it: it must name a sensor the table knows, and, on a
/// log bound to a sensor, that sensor. A stats line that is not well formed names nothing that
/// can be checked and is refused too; the control plane would refuse it as well.
fn admit(label: &str, line: &str) -> Result<(), Refusal> {
    let Ok(event) = serde_json::from_str::<SensorEvent>(line) else {
        return Ok(());
    };
    if event.signal_type == SIGNAL_SENSOR_STATS {
        let stats = SensorStats::from_event(&event).map_err(Refusal::Stats)?;
        let refused = |violation| {
            Refusal::Origin(OriginError {
                label: label.to_string(),
                violation,
            })
        };
        let Some(row) = origin::row(&stats.sensor) else {
            return Err(refused(Violation::UnknownSensor {
                sensor: stats.sensor,
            }));
        };
        if let Some(bound) = origin::bound_sensor(label)
            && bound != row.sensor
        {
            return Err(refused(Violation::OtherSensor {
                sensor: row.sensor.to_string(),
                bound,
            }));
        }
        return Ok(());
    }
    origin::check(label, &event).map_err(Refusal::Origin)
}

/// Builds a [`Batch`] out of up to `max_records` whole lines tailed from a sensor log.
pub struct Batcher;

impl Batcher {
    /// Reads up to `max_records` complete lines from `tailer`, the log labelled `label` in
    /// `PROPOLIS_SHIPPER_SENSOR_LOGS`, and, if any may be shipped, wraps them in the next batch:
    /// `seq = last_seq + 1`, `prev_batch_hash = last_hash`.
    ///
    /// A line that parses as a sensor event and fails the origin policy for `label` is dropped
    /// with a warning and counted in [`NextBatch::refused`]: a sensor's log may only carry what
    /// that sensor is able to write, under its own name. A `sensor_stats` line is held to the
    /// same log the same way (see [`admit`]).
    ///
    /// Does NOT call `tailer.persist_cursor()`. `read_batch` already advances the tailer's
    /// in-memory cursor for the lines it returns, but persisting that cursor is deliberately
    /// deferred to ack time (Task 11): if this batch is built but never confirmed by the
    /// gateway's `Accepted`/`Duplicate` response, the unpersisted cursor means a restart re-reads
    /// and re-ships it rather than silently dropping it.
    pub fn next_batch(
        tailer: &mut LogTailer,
        label: &str,
        last_seq: u64,
        last_hash: [u8; 32],
        max_records: usize,
    ) -> NextBatch {
        // Clamp at the read, not after: reading MAX_RECORDS_FRAME_SAFE+1 lines and then
        // dropping the last one would still advance the tailer's cursor past it (`read_batch`
        // consumes what it returns), permanently losing that line. Clamping the count passed
        // into `read_batch` means the tailer only ever consumes what this batch will actually
        // carry, and this also holds even when `max_records` is a caller-configured value
        // larger than the frame-safe ceiling (see `DEFAULT_MAX_RECORDS`'s doc comment).
        let n = max_records.min(MAX_RECORDS_FRAME_SAFE);
        let lines = tailer.read_batch(n);
        let lines_read = lines.len();
        let mut refused = 0u64;
        if lines.is_empty() {
            return NextBatch {
                batch: None,
                refused,
                lines_read,
            };
        }

        // log-tailer bounds a raw tailed LINE to MAX_LINE_BYTES (== MAX_RECORD_LEN), but it
        // decodes that line with `String::from_utf8_lossy`, which can expand invalid UTF-8 up to
        // 3x (each bad byte becomes a 3-byte U+FFFD): a raw line at the cap can therefore surface
        // here as a record over MAX_RECORD_LEN. `Batch::new` only bounds record COUNT, not
        // per-record length, so an over-length record would build an unshippable frame the
        // gateway rejects - and because a rejected/stalled cycle never advances the tailer
        // cursor, re-reading the same pathological line forever would wedge this collector's
        // whole serial chain. Enforce the real bound here and skip anything that violates it,
        // rather than merely asserting it in debug builds.
        let records: Vec<Vec<u8>> = lines
            .into_iter()
            .filter_map(|line| {
                // `read_batch` only ever returns complete, `\n`-stripped lines split on `\n`, so
                // a returned line cannot itself contain an embedded newline - `Batch::new`'s wire
                // encoding could not round-trip one (see `collector_wire::frame::FrameError::RecordNewline`).
                debug_assert!(
                    !line.as_bytes().contains(&b'\n'),
                    "log-tailer must never return a line containing an embedded newline"
                );
                if line.len() as u32 > MAX_RECORD_LEN {
                    tracing::warn!(
                        bytes = line.len(),
                        max_bytes = MAX_RECORD_LEN,
                        "shipper: dropping an over-length record that cannot fit a frame"
                    );
                    return None;
                }
                // Dropped the same way, and for good: the gateway spools every log of this
                // collector into one stream, so past this point nothing can tell that the line
                // came from a log that had no business carrying it.
                if let Err(e) = admit(label, &line) {
                    tracing::warn!(
                        sensor = %label,
                        error = %e,
                        "shipper: dropping a line the origin policy refuses for this log"
                    );
                    refused += 1;
                    return None;
                }
                Some(line.into_bytes())
            })
            .collect();

        if records.is_empty() {
            // Every line this read produced was over-length or refused, and skipped: nothing to
            // ship this round, but the tailer's cursor already advanced past them (read_batch
            // consumes what it returns), so the next call reads whatever follows rather than
            // re-reading these forever.
            return NextBatch {
                batch: None,
                refused,
                lines_read,
            };
        }

        NextBatch {
            batch: Some(Batch::new(last_seq + 1, last_hash, records)),
            refused,
            lines_read,
        }
    }
}
