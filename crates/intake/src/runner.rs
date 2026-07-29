//! The intake runner: wires `LogTailer` (Task 3) to `converter::convert` (Task 1) to
//! `core_scoring::append_event`, the per-poll unit of work a sensor's intake loop repeats. See
//! "The runner" in `internal/design/03-event-intake-aggregation.md`.

use crate::converter::convert;
use crate::tailer::LogTailer;
use core_scoring::append_event;
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
}

impl IntakeRunner {
    pub fn new(tailer: LogTailer, pool: PgPool, sensor_name: String) -> Self {
        Self {
            tailer,
            pool,
            sensor_name,
        }
    }

    /// Reads and processes one batch (up to 100 lines) from the tailer.
    ///
    /// A line that is not valid JSON, or that `convert` rejects, is counted in `rejected` and
    /// skipped: both are permanent failures, so retrying them next poll would just re-reject them
    /// forever while blocking every line behind them.
    ///
    /// A database error from `append_event` is treated differently: it may be transient (a
    /// dropped connection, lock contention), and every subsequent call is likely to fail the same
    /// way, so the batch STOPS at the first one instead of plowing through the rest. `read_batch`
    /// has already advanced the tailer's in-memory offset past every line in this batch
    /// (including the ones left unprocessed after the failure) - that is only durable once
    /// `persist_cursor` is called, which callers should do only when `errors == 0`. An unpersisted
    /// advance is lost on restart, so the failed line (and anything after it) is re-read from the
    /// last persisted position - the at-least-once guarantee.
    pub async fn run_batch(&mut self) -> RunBatchResult {
        let lines = self.tailer.read_batch(100);
        let mut result = RunBatchResult::default();

        for line in &lines {
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

            match append_event(&self.pool, input).await {
                Ok(_score) => result.ingested += 1,
                Err(e) => {
                    tracing::error!(
                        sensor = %self.sensor_name,
                        error = ?e,
                        "append_event failed, stopping batch"
                    );
                    result.errors += 1;
                    break;
                }
            }
        }

        result
    }

    /// Durably saves the tailer's current read position.
    ///
    /// Callers should only call this after a batch with `errors == 0`: persisting past a line
    /// that never reached the ledger would drop it permanently instead of re-reading it on the
    /// next poll or restart.
    pub fn persist_cursor(&self) -> std::io::Result<()> {
        self.tailer.persist_cursor()
    }
}
