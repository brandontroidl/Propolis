//! The intake runner: wires `LogTailer` (Task 3) to `converter::convert` (Task 1) to
//! `core_scoring::append_event`, the per-poll unit of work a sensor's intake loop repeats. See
//! "The runner" in `internal/design/03-event-intake-aggregation.md`.

use std::collections::{BTreeSet, HashSet};
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use crate::converter::convert;
use chrono::{DateTime, Utc};
use core_scoring::{EventInput, append_events};
use log_tailer::LogTailer;
use sensor_wire::SensorEvent;
use sqlx::PgPool;

/// Outcome of one [`IntakeRunner::run_batch`] call.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct RunBatchResult {
    /// Lines that parsed, converted, and were appended to the ledger.
    pub ingested: usize,
    /// Lines that failed NDJSON parsing or `convert` (unknown signal type/protocol, unsupported
    /// wire version, domain validation) - permanently unprocessable, so they are dropped rather
    /// than retried.
    pub rejected: usize,
    /// Lines dropped because they came from a configured reachability-probe source, each recorded
    /// against its `listener_probe` row instead of the ledger.
    ///
    /// Kept SEPARATE from `ingested` and `rejected` on purpose: `ops_alert::conditions::intake`
    /// derives its stall verdict from those two, and a steady drip of probe lines counting as
    /// ingestion would keep a wedged tailer looking healthy. It still counts as cursor progress -
    /// see `progress_from_batch`.
    pub probe_confirmations: usize,
    /// Non-zero only when `append_event` itself failed (a database error) partway through the
    /// batch; the batch stops at the first one, so this is 0 or 1 under the current stop-on-first
    /// policy, never a running count of every failure. See `run_batch`'s doc comment for why the
    /// batch stops instead of skipping past it.
    pub errors: usize,
}

/// Polls one sensor's NDJSON log via `LogTailer` and appends each valid line to the
/// `core-scoring` ledger.
pub struct IntakeRunner {
    tailer: LogTailer,
    pool: PgPool,
    sensor_name: String,
    probe_sources: Arc<HashSet<IpAddr>>,
    probe_grace: Duration,
    last_ingested_observed_at: Option<DateTime<Utc>>,
    reported_sensors: BTreeSet<String>,
    /// Lines the next `run_batch` reads; see [`next_batch_size`].
    batch_size: usize,
}

/// The fewest lines a batch reads, and what every runner starts at and returns to once it has
/// caught up: a quiet sensor keeps the small transactions it always had.
pub const MIN_BATCH_LINES: usize = 100;

/// The most lines a batch reads. The append lock is held for the whole batch's transaction, so
/// this bounds how long one sensor's backlog can make every other writer wait; at the measured
/// per-event cost it keeps that to under 0.1 s (`docs/architecture/storage.md`, "Batched append").
pub const MAX_BATCH_LINES: usize = 1000;

/// Upper bound on the bytes one batch holds in memory, so lines far larger than the typical
/// 1 KB cannot make a full-size batch large. It limits growth above [`MIN_BATCH_LINES`] only; the
/// floor is the size the runner always read.
const MAX_BATCH_BYTES: usize = 8 * 1024 * 1024;

/// The line count for the batch after one that read `lines_read` of `current` lines (`bytes_read`
/// bytes) and did or did not fail.
///
/// A full batch means more is waiting, so double it, up to [`MAX_BATCH_LINES`] and the byte
/// budget: a backlog is cleared in fewer, larger transactions (each saves a lock acquisition and
/// a commit). A short batch means the log is drained, so return to [`MIN_BATCH_LINES`]. A failed
/// batch also returns to the floor: the retry should be small, and a failure that is one event's
/// fault costs fewer rolled-back rows that way.
pub fn next_batch_size(
    current: usize,
    lines_read: usize,
    bytes_read: usize,
    failed: bool,
) -> usize {
    if failed || lines_read < current {
        return MIN_BATCH_LINES;
    }
    let average_line = (bytes_read / lines_read.max(1)).max(1);
    let by_bytes = MAX_BATCH_BYTES / average_line;
    current
        .saturating_mul(2)
        .min(MAX_BATCH_LINES)
        .min(by_bytes)
        .max(MIN_BATCH_LINES)
}

/// How many distinct `event.sensor` names one log's runner remembers. A log carries one sensor's
/// events, so a handful is generous; the bound only stops a misbehaving sensor writing a fresh
/// name per line from growing the set without limit.
const MAX_REPORTED_SENSORS: usize = 8;

impl IntakeRunner {
    /// `probe_sources` are the control plane's own egress addresses, from
    /// `PROPOLIS_FLEET_PROBE_SOURCE_IPS`. An EMPTY set means no probe is configured on this node
    /// and nothing is filtered, which is why the set is a constructor parameter rather than an
    /// optional builder step: every construction site has to state which it is, and a node that
    /// turns the probe on without telling intake about it cannot happen by omission.
    ///
    /// `probe_grace` is how far back a probe attempt may be and still be the one a sighting
    /// belongs to. The daemon passes twice the sweep interval, the same window
    /// `fleet::health::reach_level` calls fresh, so the two cannot come to disagree about what
    /// "recent" means.
    pub fn new(
        tailer: LogTailer,
        pool: PgPool,
        sensor_name: String,
        probe_sources: Arc<HashSet<IpAddr>>,
        probe_grace: Duration,
    ) -> Self {
        Self {
            tailer,
            pool,
            sensor_name,
            probe_sources,
            probe_grace,
            last_ingested_observed_at: None,
            reported_sensors: BTreeSet::new(),
            batch_size: MIN_BATCH_LINES,
        }
    }

    /// How many bytes of this sensor's log are still unread; see
    /// [`LogTailer::backlog_bytes`] for exactly what is counted.
    pub fn backlog_bytes(&self) -> u64 {
        self.tailer.backlog_bytes()
    }

    /// `observed_at` of the last event this runner appended, in log order; `None` until it has
    /// appended one. While the log is behind, the next unread line was written after this one, so
    /// `now` minus this bounds how long that line has waited.
    pub fn last_ingested_observed_at(&self) -> Option<DateTime<Utc>> {
        self.last_ingested_observed_at
    }

    /// The `event.sensor` names this log's appended events carried, the first eight distinct
    /// ones. The fleet pane keys listeners on that name, not on the
    /// `PROPOLIS_SENSOR_LOGS` label this runner was started under, so this is how a log's state
    /// finds its listener rows.
    pub fn reported_sensors(&self) -> &BTreeSet<String> {
        &self.reported_sensors
    }

    /// Reads and processes one batch from the tailer: [`MIN_BATCH_LINES`] lines when caught up,
    /// growing to [`MAX_BATCH_LINES`] while the log keeps filling a whole batch (see
    /// [`next_batch_size`]).
    ///
    /// A line that is not valid JSON, or that `convert` rejects, is counted in `rejected` and
    /// skipped: both are permanent failures, so retrying them next poll would just re-reject them
    /// forever while blocking every line behind them.
    ///
    /// Every convertible line is appended in ONE transaction (`core_scoring::append_events`),
    /// which holds the ledger's append lock once for the batch. A database error from it is
    /// treated differently from a rejected line: it may be transient (a dropped connection, lock
    /// contention), and every subsequent call is likely to fail the same way, so the batch STOPS
    /// at the first failing event, and events before it are already committed. `read_batch`
    /// has already advanced the tailer's in-memory offset past every line in this batch
    /// (including the ones left unprocessed after the failure), so the batch is REWOUND here:
    /// the next poll re-reads the failed line and everything behind it.
    ///
    /// Declining to persist the cursor is not sufficient on its own. This runner outlives any
    /// one batch, so an un-rewound offset means the next poll simply starts past the failed
    /// line - and the first later batch that succeeds (an empty one is enough, since it reports
    /// `errors == 0`) persists that advanced position, making the skip durable without any
    /// restart. Rewinding is what makes the at-least-once guarantee hold in-process; not
    /// persisting is what makes it hold across a crash.
    ///
    /// Lines that succeeded before the failure are replayed on the retry. That is the intended
    /// trade: the ledger's dedup window absorbs a duplicate, and nothing absorbs a skip.
    pub async fn run_batch(&mut self) -> RunBatchResult {
        let lines = self.tailer.read_batch(self.batch_size);
        let mut result = RunBatchResult::default();
        // Converted events in log order, each with the rejected and probe counts as they stood
        // just before it, so a failure can report only the lines that were actually reached.
        let mut pending: Vec<(EventInput, usize, usize)> = Vec::with_capacity(lines.len());
        let mut bytes_read = 0usize;

        for line in &lines {
            bytes_read += line.len();
            let event: SensorEvent = match serde_json::from_str(line) {
                Ok(event) => event,
                Err(e) => {
                    tracing::warn!(
                        sensor = %self.sensor_name,
                        error = %e,
                        "malformed event JSON, dropping line"
                    );
                    result.rejected += 1;
                    continue;
                }
            };

            // A synthetic reachability probe from this control plane's own egress address is not
            // attacker evidence. It is dropped BEFORE conversion, so it can never reach the ledger
            // or a score: every TCP sensor emits `honeypot_connection` on accept, which weighs 40
            // at confidence 0.900, and a five-minute sweep would otherwise score the control
            // plane's own address into the review queue and the published blocklist.
            //
            // The sighting is recorded against the probe row instead. Intake is the far end of the
            // collection chain, so a probe line arriving HERE is the proof that socket, sensor,
            // log, shipper, gateway and intake all work - the half of the question a connect
            // alone cannot answer.
            if self.probe_sources.contains(&event.source_ip) {
                if let Err(e) = fleet::store::confirm_sensor(
                    &self.pool,
                    &event.sensor,
                    Utc::now(),
                    self.probe_grace,
                )
                .await
                {
                    // Logged, not fatal, and not counted as an error: the line is dropped either
                    // way, and failing to record the confirmation leaves the row unconfirmed,
                    // which the pane already renders as a warning rather than as health.
                    tracing::warn!(
                        sensor = %event.sensor,
                        error = %e,
                        "probe confirmation could not be recorded"
                    );
                }
                result.probe_confirmations += 1;
                continue;
            }

            let input = match convert(event) {
                Ok(input) => input,
                Err(e) => {
                    tracing::warn!(
                        sensor = %self.sensor_name,
                        error = ?e,
                        "event rejected by converter, dropping line"
                    );
                    result.rejected += 1;
                    continue;
                }
            };

            pending.push((input, result.rejected, result.probe_confirmations));
        }

        // One transaction for the whole batch (telemetry and scored events alike, in log order).
        // `append_events` routes each event to the scored or telemetry path the way the
        // single-event functions do, and on failure reports how many leading events are durable.
        let inputs: Vec<EventInput> = pending.iter().map(|(input, _, _)| input.clone()).collect();
        let outcome = append_events(&self.pool, &inputs).await;
        for (input, _, _) in &pending[..outcome.appended] {
            result.ingested += 1;
            self.last_ingested_observed_at = Some(input.observed_at);
            if self.reported_sensors.len() < MAX_REPORTED_SENSORS {
                self.reported_sensors.insert(input.sensor.clone());
            }
        }
        if let Some(e) = outcome.failure {
            tracing::error!(
                sensor = %self.sensor_name,
                error = ?e,
                appended = outcome.appended,
                "append failed, stopping batch"
            );
            result.errors += 1;
            // Lines after the failed one are rewound and read again, so they are not counted yet.
            if let Some(&(_, rejected, probes)) = pending.get(outcome.appended) {
                result.rejected = rejected;
                result.probe_confirmations = probes;
            }
            self.tailer.rewind_batch();
        } else {
            self.tailer.commit_batch();
        }

        self.batch_size =
            next_batch_size(self.batch_size, lines.len(), bytes_read, result.errors > 0);
        result
    }

    /// Durably saves the tailer's current read position.
    ///
    /// Safe to call after any batch: `run_batch` rewinds the tailer when it reports errors, so
    /// the position this saves never sits past a line that failed to reach the ledger. Callers
    /// that still gate on `errors == 0` lose nothing by it, and a shutdown path that persists
    /// unconditionally is correct for the same reason.
    pub fn persist_cursor(&self) -> std::io::Result<()> {
        self.tailer.persist_cursor()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const LINE: usize = 1000;

    #[test]
    fn a_full_batch_doubles_up_to_the_cap() {
        let mut size = MIN_BATCH_LINES;
        let mut seen = vec![size];
        for _ in 0..6 {
            size = next_batch_size(size, size, size * LINE, false);
            seen.push(size);
        }
        assert_eq!(seen, [100, 200, 400, 800, 1000, 1000, 1000]);
        assert_eq!(MAX_BATCH_LINES, 1000);
    }

    #[test]
    fn a_short_batch_returns_to_the_floor() {
        assert_eq!(
            next_batch_size(800, 799, 799 * LINE, false),
            MIN_BATCH_LINES
        );
        assert_eq!(next_batch_size(1000, 0, 0, false), MIN_BATCH_LINES);
    }

    #[test]
    fn a_failed_batch_returns_to_the_floor_even_when_full() {
        assert_eq!(next_batch_size(800, 800, 800 * LINE, true), MIN_BATCH_LINES);
    }

    #[test]
    fn large_lines_stop_growth_at_the_byte_budget_but_never_below_the_floor() {
        // 100 KiB lines: 8 MiB holds 80, below the floor, so growth stalls at the floor.
        assert_eq!(
            next_batch_size(100, 100, 100 * 100 * 1024, false),
            MIN_BATCH_LINES
        );
        // 16 KiB lines: 8 MiB holds 512.
        assert_eq!(next_batch_size(400, 400, 400 * 16 * 1024, false), 512);
    }

    #[test]
    fn every_bound_holds_for_any_input() {
        for current in [0usize, 1, 99, 100, 101, 999, 1000, usize::MAX] {
            for lines in [0usize, 1, 100, 1000, usize::MAX / 2] {
                for bytes in [0usize, 1, 1 << 20, usize::MAX / 2] {
                    for failed in [false, true] {
                        let next = next_batch_size(current, lines, bytes, failed);
                        assert!(
                            (MIN_BATCH_LINES..=MAX_BATCH_LINES).contains(&next),
                            "{current} {lines} {bytes} {failed} -> {next}"
                        );
                    }
                }
            }
        }
    }
}
