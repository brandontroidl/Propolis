//! The intake runner: wires `LogTailer` (Task 3) to `converter::convert` (Task 1) to
//! `core_scoring::append_event`, the per-poll unit of work a sensor's intake loop repeats. See
//! "The runner" in `internal/design/03-event-intake-aggregation.md`.

use std::collections::HashSet;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use crate::converter::convert;
use chrono::Utc;
use core_scoring::{append_event, append_telemetry_event};
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
}

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

            // Telemetry takes the unscored append path. The two are separate functions that
            // refuse each other's signals (see `core_scoring::repository`), so routing on the
            // signal's own classification here is what lets a sensor emit an outcome record at
            // all: handing one to `append_event` is a hard error, by design.
            let appended = if input.signal_type.is_telemetry() {
                append_telemetry_event(&self.pool, input).await
            } else {
                append_event(&self.pool, input).await.map(|_score| ())
            };
            match appended {
                Ok(()) => result.ingested += 1,
                Err(e) => {
                    tracing::error!(
                        sensor = %self.sensor_name,
                        error = ?e,
                        "append failed, stopping batch"
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
