//! The intake runner: wires `LogTailer` (Task 3) to `converter::convert_event` (Task 1) to
//! `core_scoring::append_events`, the per-poll unit of work a sensor's intake loop repeats. See
//! "The runner" in `internal/design/03-event-intake-aggregation.md`.

use std::collections::hash_map::DefaultHasher;
use std::collections::{BTreeSet, HashSet};
use std::hash::{Hash, Hasher};
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use crate::converter::convert_event;
use crate::quarantine::{Quarantine, QuarantinedLine};
use chrono::{DateTime, Utc};
use core_scoring::{EventInput, append_events};
use log_tailer::LogTailer;
use sensor_wire::{SIGNAL_SENSOR_STATS, SensorEvent, SensorStats};
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
    /// `sensor_stats` lines accepted and stored in `sensor_stats` instead of the ledger. Separate
    /// from `ingested` for the reason `probe_confirmations` is: a sensor's own health line is not
    /// ingestion, and counting it as such would make a wedged tailer look healthy. It still moves
    /// the cursor (see `cursor_moved`). A refused `sensor_stats` line is counted in `rejected`.
    pub stats_updates: usize,
    /// Non-zero only when the append itself failed (a database error) partway through the batch;
    /// the batch stops at the first failing event, so this is 0 or 1, never a running count of
    /// every failure. See `run_batch`'s doc comment for why the batch stops instead of skipping
    /// past it.
    pub errors: usize,
    /// 1 when the line this batch failed on had been refused on [`WEDGE_POLLS`] polls in a row and
    /// was set aside in the quarantine, so the tailer moved past it. Counts as forward progress
    /// but not as ingestion or rejection. The batch still reports the database error in `errors`.
    pub quarantined: usize,
}

impl RunBatchResult {
    /// Whether the intake loop should persist the cursor after this batch. The runner leaves the
    /// tailer at the first line that failed to reach the ledger (or at the batch start if it could
    /// not tell), so persisting is always safe; it is worth doing whenever the position moved,
    /// including after a partial commit, so a restart (an operator's response to a wedge page)
    /// does not replay what already committed. An idle failure moved nothing and is skipped.
    pub fn cursor_moved(&self) -> bool {
        self.errors == 0
            || self.ingested > 0
            || self.rejected > 0
            || self.probe_confirmations > 0
            || self.stats_updates > 0
            || self.quarantined > 0
    }
}

/// A line set aside in the quarantine, for the operator-facing alert.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QuarantineNotice {
    pub sensor: String,
    /// The log the line was read from.
    pub log_path: PathBuf,
    /// Offset of the line in the file it was read from.
    pub byte_offset: u64,
    pub sqlstate: Option<String>,
    /// The quarantine file holding the record.
    pub file: PathBuf,
}

impl std::fmt::Display for QuarantineNotice {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}: the line at byte offset {} of {} was refused by the database (SQLSTATE {}) and quarantined to {}",
            self.sensor,
            self.byte_offset,
            self.log_path.display(),
            self.sqlstate.as_deref().unwrap_or("none"),
            self.file.display()
        )
    }
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
    /// Which line the last failed poll stopped at, how many polls in a row it has, and why.
    wedge: Option<Wedge>,
    /// Where a wedged line is set aside; `None` leaves it to the operator (reported, not skipped).
    quarantine: Option<Quarantine>,
    /// Why the wedged line could not be quarantined on the latest attempt.
    quarantine_block: Option<String>,
    quarantined_total: u64,
    last_quarantine: Option<QuarantineNotice>,
    /// Runs right after the append returns, before anything is decided from its outcome. Lets a
    /// test land a `copytruncate` at the one moment production can: while the append is in flight.
    after_append: Option<Box<dyn FnMut() + Send>>,
}

/// The same line refused on consecutive polls.
#[derive(Debug, Clone)]
struct Wedge {
    line_hash: u64,
    polls: u32,
    /// `observed_at` of the refused event, to find it in the log.
    observed_at: DateTime<Utc>,
    sqlstate: Option<String>,
    error: String,
}

/// Consecutive polls the same line must be refused before [`IntakeRunner::wedged`] reports it.
/// One failure is a blip; three, a poll apart, is a line that will not go in.
pub const WEDGE_POLLS: u32 = 3;

/// The fewest lines a batch reads, and what every runner starts at and returns to once it has
/// caught up: a quiet sensor keeps the small transactions it always had.
pub const MIN_BATCH_LINES: usize = 100;

/// The most lines a batch reads. The append lock is held for the whole batch's transaction, so
/// this bounds how long one sensor's backlog can make every other writer wait; at the measured
/// per-event cost it keeps that to under 0.1 s (`docs/architecture/storage.md`, "Batched append").
pub const MAX_BATCH_LINES: usize = 1000;

/// The most bytes of line content one batch reads. Enforced by the read itself
/// (`LogTailer::read_batch_bounded`), which stops before the line that would pass it, so a burst
/// of near-1 MiB lines cannot make a thousand-line batch a gigabyte. The first line of a batch
/// always goes through, so a batch can exceed this by one line (at most `MAX_LINE_BYTES`).
pub const MAX_BATCH_BYTES: usize = 8 * 1024 * 1024;

/// The line count for the batch after one that read `lines_read` of `current` lines (`bytes_read`
/// bytes) and did or did not fail.
///
/// A full batch means more is waiting, so double it, up to [`MAX_BATCH_LINES`] and the byte
/// budget: a backlog is cleared in fewer, larger transactions (each saves a lock acquisition and
/// a commit). A short batch means the log is drained (or the byte budget stopped the read), so
/// return to [`MIN_BATCH_LINES`]. A failed batch also returns to the floor: the retry should be
/// small, and a failure that is one event's fault costs fewer rolled-back rows that way.
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

/// What `run_batch` keeps of a converted line until the append says how far it got.
struct Pending {
    /// Position of the line in the batch the tailer returned.
    line: usize,
    observed_at: DateTime<Utc>,
    sensor: String,
    line_hash: u64,
}

fn hash_line(line: &str) -> u64 {
    let mut hasher = DefaultHasher::new();
    line.hash(&mut hasher);
    hasher.finish()
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
            last_ingested_observed_at: None,
            reported_sensors: BTreeSet::new(),
            batch_size: MIN_BATCH_LINES,
            wedge: None,
            quarantine: None,
            quarantine_block: None,
            quarantined_total: 0,
            last_quarantine: None,
            after_append: None,
        }
    }

    /// Sets aside a line the database refuses on [`WEDGE_POLLS`] polls in a row, in `quarantine`,
    /// and moves past it. Without this a wedged line is only reported (`wedged`). Both production
    /// binaries call it; it is a builder step, not a constructor parameter, because the many
    /// test and tool callers of `new` have no directory to write to and must not skip lines.
    pub fn with_quarantine(mut self, quarantine: Quarantine) -> Self {
        self.quarantine = Some(quarantine);
        self
    }

    /// Lines this runner has quarantined since it started.
    pub fn quarantined_total(&self) -> u64 {
        self.quarantined_total
    }

    /// The most recent line this runner quarantined.
    pub fn last_quarantine(&self) -> Option<&QuarantineNotice> {
        self.last_quarantine.as_ref()
    }

    #[doc(hidden)]
    pub fn set_after_append_hook(&mut self, hook: impl FnMut() + Send + 'static) {
        self.after_append = Some(Box::new(hook));
    }

    /// How many bytes of this sensor's log are still unread; see
    /// [`LogTailer::backlog_bytes`] for exactly what is counted.
    pub fn backlog_bytes(&self) -> u64 {
        self.tailer.backlog_bytes()
    }

    /// Input a `copytruncate` rotation took from this log that the rotated copy could not supply;
    /// see [`LogTailer::rotation_loss`].
    pub fn rotation_loss(&self) -> log_tailer::RotationLoss {
        self.tailer.rotation_loss()
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

    /// A description of the line this log is stuck on, once the database has refused the SAME
    /// line on [`WEDGE_POLLS`] consecutive polls for a reason that is the line's own (not a lost
    /// connection). With a quarantine configured the runner sets such a line aside and moves on
    /// in the same batch that reaches the threshold, so this stays `Some` only while that could
    /// not be done, and then says why. Without one, the line is only reported: skipping it is an
    /// operator decision. Either way the stall that follows has a cause attached.
    pub fn wedged(&self) -> Option<String> {
        let w = self.wedge.as_ref().filter(|w| w.polls >= WEDGE_POLLS)?;
        let blocked = self
            .quarantine_block
            .as_deref()
            .map(|why| format!("; the line was NOT quarantined, so intake stays on it: {why}"))
            .unwrap_or_default();
        Some(format!(
            "intake wedged at {}: the line observed {} was refused on {} consecutive polls (SQLSTATE {}): {}{blocked}",
            self.sensor_name,
            w.observed_at.to_rfc3339(),
            w.polls,
            w.sqlstate.as_deref().unwrap_or("none"),
            w.error
        ))
    }

    /// Reads and processes one batch from the tailer: [`MIN_BATCH_LINES`] lines when caught up,
    /// growing to [`MAX_BATCH_LINES`] while the log keeps filling a whole batch (see
    /// [`next_batch_size`]), and never more than [`MAX_BATCH_BYTES`] of line content.
    ///
    /// A line that is not valid JSON, or that `convert` rejects, is counted in `rejected` and
    /// skipped: both are permanent failures, so retrying them next poll would just re-reject them
    /// forever while blocking every line behind them.
    ///
    /// Every convertible line is appended in ONE transaction (`core_scoring::append_events`),
    /// which holds the ledger's append lock once for the batch. A database error from it is
    /// treated differently from a rejected line: it may be transient (a dropped connection, lock
    /// contention), and every subsequent call is likely to fail the same way, so the batch STOPS
    /// at the first failing event. `append_events` reports how many leading events are already
    /// committed, and this commits the tailer past exactly those lines (and any rejected or
    /// probe lines among them): the next poll starts AT the failed line. Re-reading the committed
    /// prefix would append it again as new ledger rows on every poll, and since a failure at its
    /// own line never advances, each pass would also add to the source's event counters.
    ///
    /// A failure at the first line therefore reports `ingested == 0` and the loops sleep, which is
    /// what keeps a refused line from being retried in a tight loop.
    ///
    /// Declining to persist the cursor is not sufficient on its own. This runner outlives any
    /// one batch, so an un-rewound offset means the next poll simply starts past the failed
    /// line - and the first later batch that succeeds (an empty one is enough, since it reports
    /// `errors == 0`) persists that advanced position, making the skip durable without any
    /// restart. The tailer is rewound to the start of the batch and then moved forward over the
    /// committed prefix only; not persisting after an error is what makes it hold across a crash,
    /// where the prefix is read again (at-least-once).
    ///
    /// The one case that still re-appends events is an ambiguous commit: the connection drops
    /// after Postgres committed a batch but before the acknowledgement arrives. The batch is then
    /// reported as failed and read again, so its events enter the ledger twice and the dedup
    /// window absorbs their weight but not their ledger rows or event counters. That is the
    /// at-least-once guarantee's price and the only duplicate source on a healthy database.
    pub async fn run_batch(&mut self) -> RunBatchResult {
        let lines = self
            .tailer
            .read_batch_bounded(self.batch_size, MAX_BATCH_BYTES as u64);
        let lines_read = lines.len();
        let mut result = RunBatchResult::default();
        let mut events: Vec<EventInput> = Vec::with_capacity(lines_read);
        let mut pending: Vec<Pending> = Vec::with_capacity(lines_read);
        // Lines that are not events, by position, so a failure counts only those it reached.
        let mut rejected_at: Vec<usize> = Vec::new();
        let mut probes: Vec<(usize, String)> = Vec::new();
        // (index into `pending`, digest, text) of each reply in the batch, stored before the append.
        let mut replies: Vec<(usize, String, String)> = Vec::new();
        let mut stats_lines: Vec<(usize, SensorStats, DateTime<Utc>)> = Vec::new();
        let mut bytes_read = 0usize;

        for (index, line) in lines.iter().enumerate() {
            bytes_read += line.len();
            let event: SensorEvent = match serde_json::from_str(line) {
                Ok(event) => event,
                Err(e) => {
                    tracing::warn!(
                        sensor = %self.sensor_name,
                        error = %e,
                        "malformed event JSON, dropping line"
                    );
                    rejected_at.push(index);
                    continue;
                }
            };

            // A sensor's own health counters are not evidence. They are taken out here, BEFORE
            // conversion, so they cannot reach the ledger, a score, the feed, a campaign or a
            // vendor submission, and are stored in `sensor_stats` after the append (below). The
            // intercept keys on the signal type alone; the sentinel source, the fixed field set,
            // the bounds and the log's own sensor label are then ALL required
            // (`SensorStats::from_event`), and a line that fails any of them is refused, never
            // stored and never handed on to `convert`.
            if event.signal_type == SIGNAL_SENSOR_STATS {
                match SensorStats::from_event(&event) {
                    Ok(stats) if stats.sensor == self.sensor_name => {
                        stats_lines.push((index, stats, event.observed_at));
                    }
                    Ok(stats) => {
                        tracing::warn!(
                            sensor = %self.sensor_name,
                            claimed = %stats.sensor,
                            "sensor_stats line names a different sensor than this log's label, refused"
                        );
                        rejected_at.push(index);
                    }
                    Err(e) => {
                        tracing::warn!(
                            sensor = %self.sensor_name,
                            error = %e,
                            "malformed sensor_stats line, refused"
                        );
                        rejected_at.push(index);
                    }
                }
                continue;
            }

            // A synthetic reachability probe from this control plane's own egress address is not
            // attacker evidence. It is dropped BEFORE conversion, so it can never reach the ledger
            // or a score: every TCP sensor emits `honeypot_connection` on accept, which weighs 40
            // at confidence 0.900, and a five-minute sweep would otherwise score the control
            // plane's own address into the review queue and the published blocklist.
            //
            // The sighting is recorded against the probe row after the append says this line was
            // reached (below): intake is the far end of the collection chain, so a probe line
            // arriving HERE is the proof that socket, sensor, log, shipper, gateway and intake all
            // work, and confirming one that sits behind a refused line would mark a wedged
            // sensor healthy on every poll.
            if self.probe_sources.contains(&event.source_ip) {
                probes.push((index, event.sensor));
                continue;
            }

            let input = match convert_event(event) {
                Ok(converted) => {
                    if let Some((sha, text)) = converted.reply {
                        replies.push((pending.len(), sha, text));
                    }
                    converted.input
                }
                Err(e) => {
                    tracing::warn!(
                        sensor = %self.sensor_name,
                        error = ?e,
                        "event rejected by converter, dropping line"
                    );
                    rejected_at.push(index);
                    continue;
                }
            };

            pending.push(Pending {
                line: index,
                observed_at: input.observed_at,
                sensor: input.sensor.clone(),
                line_hash: hash_line(line),
            });
            events.push(input);
        }

        // The reply text goes in BEFORE the events that name it, so a committed event never points
        // at a missing row; a row stored for a line that then did not append is harmless
        // (content-addressed, and stored again as a no-op).
        //
        // A store that fails is isolated to the first reply the database refuses on its own: the
        // events before that line are still appended, and the refusal is then accounted exactly as
        // an append refusal of that line is (`note_failure`, the wedge report, quarantine), so a
        // line whose reply can never be stored does not hold the sensor's whole log behind it. A
        // failure that does not reproduce reply by reply (a dropped connection) appends nothing
        // and the batch is read again.
        let mut store_failure: Option<(usize, core_scoring::RepoError)> = None;
        if !replies.is_empty() {
            let all: Vec<(String, String)> = replies
                .iter()
                .map(|(_, sha, text)| (sha.clone(), text.clone()))
                .collect();
            if let Err(batch_error) = core_scoring::store_outputs(&self.pool, &all).await {
                for (at, sha, text) in &replies {
                    if let Err(e) =
                        core_scoring::store_outputs(&self.pool, &[(sha.clone(), text.clone())])
                            .await
                    {
                        store_failure = Some((*at, core_scoring::RepoError::Db(e)));
                        break;
                    }
                }
                if store_failure.is_none() {
                    tracing::error!(
                        sensor = %self.sensor_name,
                        error = %batch_error,
                        "shell replies could not be stored, batch will be read again"
                    );
                    result.errors += 1;
                    self.tailer.rewind_batch();
                    self.batch_size =
                        next_batch_size(self.batch_size, lines_read, bytes_read, true);
                    return result;
                }
            }
        }
        if let Some((at, _)) = &store_failure {
            events.truncate(*at);
        }

        // One transaction for the whole batch (telemetry and scored events alike, in log order).
        // `append_events` routes each event to the scored or telemetry path the way the
        // single-event functions do, and on failure reports how many leading events are durable.
        let outcome = append_events(&self.pool, events).await;
        if let Some(hook) = self.after_append.as_mut() {
            hook();
        }
        for p in &pending[..outcome.appended] {
            result.ingested += 1;
            self.last_ingested_observed_at = Some(p.observed_at);
            if self.reported_sensors.len() < MAX_REPORTED_SENSORS {
                self.reported_sensors.insert(p.sensor.clone());
            }
        }

        // Every line before the failed event was reached; the failed line and all after it were
        // not. With no failure the whole batch was reached.
        let failure = outcome
            .failure
            .or_else(|| store_failure.map(|(_, error)| error));
        let reached = match &failure {
            Some(_) => pending.get(outcome.appended).map_or(lines_read, |p| p.line),
            None => lines_read,
        };
        result.rejected = rejected_at.iter().filter(|&&i| i < reached).count();
        for (_, sensor) in probes.iter().filter(|(i, _)| *i < reached) {
            if let Err(e) =
                fleet::store::confirm_sensor(&self.pool, sensor, Utc::now(), self.probe_grace).await
            {
                // Logged, not fatal, and not counted as an error: the line is dropped either way,
                // and failing to record the confirmation leaves the row unconfirmed, which the
                // pane already renders as a warning rather than as health.
                tracing::warn!(
                    sensor = %sensor,
                    error = %e,
                    "probe confirmation could not be recorded"
                );
            }
            result.probe_confirmations += 1;
        }

        for (_, stats, observed_at) in stats_lines.iter().filter(|(i, _, _)| *i < reached) {
            let row = fleet::stats::SensorStatsRow {
                sensor: stats.sensor.clone(),
                reported_at: *observed_at,
                received_at: Utc::now(),
                uptime_secs: stats.uptime_secs as i64,
                is_final: stats.is_final,
                dropped: stats.dropped as i64,
                spool_refused: stats.spool_refused as i64,
                truncated: stats.truncated as i64,
                refused: stats.refused as i64,
                budget_current: stats.budget_current as i64,
                budget_high_water: stats.budget_high_water as i64,
                budget_refused: stats.budget_refused as i64,
            };
            // Logged, not fatal: the next line supersedes this one, and the console reads a row
            // that stops updating as stale.
            if let Err(e) = fleet::stats::upsert(&self.pool, &row).await {
                tracing::warn!(
                    sensor = %self.sensor_name,
                    error = %e,
                    "sensor_stats could not be stored"
                );
            }
            result.stats_updates += 1;
        }

        match failure {
            None => {
                self.wedge = None;
                self.quarantine_block = None;
                self.tailer.commit_batch();
            }
            Some(e) => {
                result.errors += 1;
                tracing::error!(
                    sensor = %self.sensor_name,
                    error = ?e,
                    appended = outcome.appended,
                    "append (or the store of a reply it names) failed, stopping batch"
                );
                let failed = pending.get(outcome.appended);
                let wedged_now = self.note_failure(&e, failed);
                // A line refused on enough polls in a row is set aside and passed in this same
                // call: the record is durable before the tailer moves (`quarantine_line`).
                let quarantined = match failed {
                    Some(p) if wedged_now => self.quarantine_line(p, &lines[p.line], &e),
                    _ => false,
                };
                if quarantined {
                    result.quarantined += 1;
                }
                // Otherwise accept exactly the lines reached, computed from the lengths recorded
                // when they were read; never by reading them again, which would go through
                // rotation handling and could return a different file's lines (a `copytruncate`
                // landing while the append was in flight). If the tailer cannot do that safely,
                // the whole batch is read again: replayed, never skipped.
                if !quarantined && (reached == 0 || !self.tailer.commit_batch_through(reached)) {
                    if reached > 0 {
                        tracing::warn!(
                            sensor = %self.sensor_name,
                            "the log changed under a failed batch; it will be read again from the start"
                        );
                    }
                    self.tailer.rewind_batch();
                }
            }
        }

        self.batch_size =
            next_batch_size(self.batch_size, lines_read, bytes_read, result.errors > 0);
        result
    }

    /// Tracks how many polls in a row the same line was refused for a reason of its own, and
    /// says whether THIS failure is one of those at or past [`WEDGE_POLLS`]. Only such a failure
    /// may lead to quarantining: a connection error on the same line is not evidence about it.
    fn note_failure(&mut self, error: &core_scoring::RepoError, at: Option<&Pending>) -> bool {
        // A failure that is not about one line (a dropped connection) says nothing about whether
        // the wedged line is still refused, so it neither counts toward nor clears the streak:
        // a database that blips between refusals must not keep the report from ever appearing.
        let Some(p) = at.filter(|_| error.is_event_specific()) else {
            return false;
        };
        let polls = match &self.wedge {
            Some(w) if w.line_hash == p.line_hash => w.polls + 1,
            _ => {
                self.quarantine_block = None;
                1
            }
        };
        let wedge = Wedge {
            line_hash: p.line_hash,
            polls,
            observed_at: p.observed_at,
            sqlstate: error.sqlstate(),
            error: error.to_string(),
        };
        self.wedge = Some(wedge);
        if let Some(description) = self.wedged() {
            tracing::error!(sensor = %self.sensor_name, "{description}");
        }
        polls >= WEDGE_POLLS
    }

    /// Writes the wedged line to the quarantine, then moves the tailer past exactly that line.
    /// Returns whether it did both.
    ///
    /// The order is the guarantee: the record is fsynced (`Quarantine::append`) before the
    /// tailer's position moves, and the position is persisted only after that, so no crash leaves
    /// the cursor past a line that is not on disk. A write that fails leaves everything as it
    /// was, wedged, with the reason in [`Self::wedged`] (fail closed); it is retried on the next
    /// poll, so fixing the directory or freeing space unsticks intake without a restart.
    ///
    /// The tailer moves by the lengths recorded when the batch was read
    /// (`LogTailer::commit_batch_through`), never by reading again: a read goes through rotation
    /// handling, and a `copytruncate` that landed while the append was in flight would return the
    /// new file's first line in place of this one. If the tailer refuses because the log changed
    /// under the batch, the record already written stays (it is a true record of a refused line),
    /// the batch is read again, and nothing is skipped.
    fn quarantine_line(
        &mut self,
        p: &Pending,
        line: &str,
        error: &core_scoring::RepoError,
    ) -> bool {
        let Some(store) = self.quarantine.clone() else {
            return false;
        };
        let Some(at) = self.tailer.uncommitted_line(p.line) else {
            self.quarantine_block =
                Some("the tailer cannot say where the line sits in its batch".into());
            return false;
        };
        let sqlstate = error.sqlstate();
        let text = error.to_string();
        let written = store.append(&QuarantinedLine {
            sensor: &self.sensor_name,
            log_path: self.tailer.log_path(),
            byte_offset: at.offset,
            sqlstate: sqlstate.as_deref(),
            error: &text,
            raw: at.raw.as_deref().unwrap_or(line.as_bytes()),
        });
        let file = match written {
            Ok(file) => file,
            Err(e) => {
                tracing::error!(
                    sensor = %self.sensor_name,
                    error = %e,
                    "intake: wedged line could not be quarantined; staying on it"
                );
                self.quarantine_block = Some(e.to_string());
                return false;
            }
        };
        if !self.tailer.commit_batch_through(p.line + 1) {
            tracing::warn!(
                sensor = %self.sensor_name,
                "the log changed under the batch after its line was quarantined; it will be read again from the start"
            );
            return false;
        }
        if let Err(e) = self.tailer.persist_cursor() {
            tracing::error!(
                sensor = %self.sensor_name,
                error = %e,
                "intake: cursor persist after quarantining a line failed"
            );
        }
        let notice = QuarantineNotice {
            sensor: self.sensor_name.clone(),
            log_path: self.tailer.log_path().to_path_buf(),
            byte_offset: at.offset,
            sqlstate,
            file,
        };
        tracing::warn!(sensor = %self.sensor_name, "intake: line quarantined, {notice}");
        self.wedge = None;
        self.quarantine_block = None;
        self.quarantined_total += 1;
        self.last_quarantine = Some(notice);
        true
    }

    /// Durably saves the tailer's current read position.
    ///
    /// Safe to call after any batch: `run_batch` leaves the tailer at the first line that failed
    /// to reach the ledger when it reports errors, so the position this saves never sits past
    /// one. Callers that still gate on `errors == 0` lose nothing by it, and a shutdown path that
    /// persists unconditionally is correct for the same reason.
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

    fn lazy_runner() -> IntakeRunner {
        let pool = sqlx::postgres::PgPoolOptions::new()
            .connect_lazy("postgres://nobody@127.0.0.1:1/none")
            .unwrap();
        let dir = std::env::temp_dir().join("intake-runner-unit-no-io");
        IntakeRunner::new(
            LogTailer::new(dir.join("none.jsonl"), dir.join("cursors")),
            pool,
            "telnet".into(),
            Arc::new(HashSet::new()),
            Duration::from_secs(1),
        )
    }

    fn pending(hash: u64) -> Pending {
        Pending {
            line: 0,
            observed_at: "2026-09-01T00:00:00Z".parse().unwrap(),
            sensor: "telnet".into(),
            line_hash: hash,
        }
    }

    fn refused() -> core_scoring::RepoError {
        core_scoring::RepoError::Invalid(core_scoring::ValidationError::SensorEmpty)
    }

    fn blip() -> core_scoring::RepoError {
        core_scoring::RepoError::Db(sqlx::Error::PoolTimedOut)
    }

    /// A database that drops a connection between refusals of the same line must not keep the
    /// wedge report from ever appearing: a blip neither counts toward the streak nor clears it.
    /// A different refused line starts a new streak.
    #[tokio::test]
    async fn a_connection_blip_neither_counts_toward_nor_clears_the_wedge_streak() {
        let mut runner = lazy_runner();
        let line = pending(7);
        runner.note_failure(&refused(), Some(&line));
        runner.note_failure(&refused(), Some(&line));
        runner.note_failure(&blip(), Some(&line));
        assert!(
            runner.wedged().is_none(),
            "two refusals are not yet a wedge"
        );
        runner.note_failure(&blip(), None);
        runner.note_failure(&refused(), Some(&line));
        assert!(
            runner.wedged().is_some(),
            "the blips must not have reset the streak"
        );

        runner.note_failure(&refused(), Some(&pending(8)));
        assert!(
            runner.wedged().is_none(),
            "a different line starts a new streak"
        );
    }

    #[test]
    fn the_cursor_is_persisted_whenever_the_position_moved() {
        let moved = |ingested, rejected, probe_confirmations, errors, quarantined| {
            RunBatchResult {
                ingested,
                rejected,
                probe_confirmations,
                errors,
                quarantined,
                ..Default::default()
            }
            .cursor_moved()
        };
        assert!(
            RunBatchResult {
                stats_updates: 1,
                ..Default::default()
            }
            .cursor_moved(),
            "a batch of nothing but stats lines moved the position"
        );
        assert!(
            RunBatchResult {
                stats_updates: 1,
                errors: 1,
                ..Default::default()
            }
            .cursor_moved(),
            "stats lines reached before a refused line moved the position, like probe lines"
        );
        assert!(moved(0, 0, 0, 0, 0), "a clean empty batch");
        assert!(moved(5, 0, 0, 0, 0));
        assert!(
            moved(12, 0, 0, 1, 0),
            "a partial commit before a refused line"
        );
        assert!(
            moved(0, 3, 0, 1, 0),
            "rejected lines committed before a refused line"
        );
        assert!(!moved(0, 0, 0, 1, 0), "an idle failure moved nothing");
        assert!(
            moved(0, 0, 0, 1, 1),
            "a quarantined line moved the position past it"
        );
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
