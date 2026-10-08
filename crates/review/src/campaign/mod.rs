//! Campaigns: one row for many addresses running the same thing, and the indicators their
//! artifacts carry (docs/operations/campaigns.md).
//!
//! Three grouping rules, cheapest first:
//! - **sample**: every address that uploaded a captured sample, or reported a URL the fetcher
//!   retrieved it from, is a member of that sample's campaign (a worm copies itself byte for byte).
//! - **command_sequence**: a shell session's run of commands, reduced to its [`fingerprint`] (the
//!   normalized shapes, consecutive repeats collapsed), joins the campaign of that fingerprint once
//!   the run ends: at a gap of [`SESSION_IDLE_SECS`] between two of its commands, once its sensor
//!   has logged events [`SESSION_SWEEP_SECS`] newer than its last command, or at
//!   [`MAX_RUN_SHAPES`] shapes. A run shorter than [`MIN_RUN_CHARS`] characters of shapes (a bare
//!   `enable; sh`) joins nothing.
//! - **scanner**: an address that reaches [`SCANNER_MIN_SENSORS`] distinct sensors within one
//!   [`SCANNER_WINDOW_SECS`] window joins the campaign of that sensor set.
//!
//! # Where the work happens
//!
//! Nothing here runs on the append path. [`run_tick`] reads the ledger past a cursor in id order,
//! [`BATCH_EVENTS`] rows at a time, and folds each batch into the migration 0015 tables in one
//! transaction that also advances the cursor, so a batch is applied exactly once and the per-append
//! cost is unchanged. Each batch touches only the rows its events name (one session, one window,
//! one campaign, one member per key) and never reads a source's history, so its cost is bounded
//! by the batch, not by the ledger. A transaction-scoped advisory lock keeps two nodes sharing one
//! database from indexing at once.
//!
//! The folds are written so the result does not depend on where batch boundaries fall: every
//! decision an event makes reads only state derived from the events before it in id order, a
//! campaign's label and representative come from its lowest event id, and counts are sums. The
//! property test in `crates/review/tests/campaign_test.rs` holds an incrementally indexed ledger
//! equal to the same ledger indexed in one pass. The one decision taken at a batch boundary is the
//! sweep that ends quiet runs; it agrees with one pass as long as a session's next command never
//! arrives more than [`SESSION_SWEEP_SECS`] of its sensor's clock after its previous one while
//! being under [`SESSION_IDLE_SECS`] after it in its own time, which takes one node feeding a
//! sensor name lagging another by most of an hour.
//!
//! Two passes per tick read other state: [`resolve_pending_fetches`] links a download to the
//! sample the fetcher later captured from its URL, and [`scan_artifacts`] extracts indicators from
//! captured text bodies in the spools (`crate::ioc`).

pub mod fingerprint;

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::path::PathBuf;

use chrono::{DateTime, NaiveDate, TimeZone, Utc};
use serde_json::{Value, json};
use sqlx::{PgPool, Postgres, Row, Transaction};

use crate::fetcher::store::{parse_url_parts, url_hash};
use crate::ioc::{self, Indicator};
use fingerprint::RunDigest;

/// Ledger rows read per batch.
pub const BATCH_EVENTS: i64 = 2000;
/// Batches per tick, so one tick of a large catch-up stays a bounded amount of work.
pub const MAX_BATCHES_PER_TICK: usize = 25;
/// A session's run ends at a gap this long between two of its own commands.
pub const SESSION_IDLE_SECS: i64 = 600;
/// A run that is still open is ended once its sensor has logged events this much newer than its
/// last command: the session went quiet. Longer than [`SESSION_IDLE_SECS`] so the sensor clock,
/// which several nodes can feed with different lags, only decides for sessions that are long over.
pub const SESSION_SWEEP_SECS: i64 = 3600;
/// A run is grouped on its first this many collapsed shapes.
pub const MAX_RUN_SHAPES: i32 = 64;
/// A run whose shapes total fewer characters than this joins no campaign.
pub const MIN_RUN_CHARS: i32 = 20;
/// The scanner rule's window.
pub const SCANNER_WINDOW_SECS: i64 = 3600;
/// Distinct sensors within one window that make an address a multi-service scanner.
pub const SCANNER_MIN_SENSORS: usize = 3;
/// Closed sessions and scanner windows are dropped once their sensor's clock is this far past.
pub const STATE_RETAIN_SECS: i64 = 2 * 86_400;
/// Samples a not-yet-grouped run remembers for the campaign it may join.
pub const MAX_SESSION_SAMPLES: usize = 8;
/// Command-derived indicators kept per source address.
pub const MAX_IOCS_PER_SOURCE: i64 = 256;
/// Captured artifacts scanned for indicators per tick.
pub const ARTIFACT_SCANS_PER_TICK: i64 = 16;
/// Pending download links looked at per tick.
pub const PENDING_FETCHES_PER_TICK: i64 = 500;
/// A download link whose URL the fetcher never resolved is dropped after this many days.
pub const PENDING_FETCH_TTL_DAYS: i64 = 7;
/// Attempts to find a queued artifact in the spools before it is recorded as missing.
pub const ARTIFACT_ATTEMPTS: i32 = 6;

/// Serializes indexers sharing one database. Distinct from core-scoring's append lock.
const CAMPAIGN_LOCK_KEY: i64 = 7_265_646_772_697_400_015;

/// A campaign's grouping rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Kind {
    Sample,
    CommandSequence,
    Scanner,
}

impl Kind {
    pub const ALL: [Kind; 3] = [Kind::Sample, Kind::CommandSequence, Kind::Scanner];

    /// The stored `campaign.kind`.
    pub fn as_str(self) -> &'static str {
        match self {
            Kind::Sample => "sample",
            Kind::CommandSequence => "command_sequence",
            Kind::Scanner => "scanner",
        }
    }

    pub fn parse(s: &str) -> Option<Kind> {
        Kind::ALL.into_iter().find(|k| k.as_str() == s)
    }

    /// The console's label for the kind.
    pub fn label(self) -> &'static str {
        match self {
            Kind::Sample => "same sample",
            Kind::CommandSequence => "same commands",
            Kind::Scanner => "multi-service scan",
        }
    }
}

/// What one call to [`run_tick`] did.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct TickStats {
    pub batches: usize,
    pub events: usize,
    pub caught_up: bool,
    pub fetch_links: usize,
    pub artifacts_scanned: usize,
    pub locked_out: bool,
}

/// One tick: index up to [`MAX_BATCHES_PER_TICK`] batches, resolve pending download links, scan
/// queued artifacts in `spool_dirs`, and drop working state past its retention.
pub async fn run_tick(pool: &PgPool, spool_dirs: &[(&'static str, PathBuf)]) -> TickStats {
    let mut stats = TickStats::default();
    for _ in 0..MAX_BATCHES_PER_TICK {
        match index_batch(pool, BATCH_EVENTS).await {
            Ok(BatchOutcome::Indexed(n)) => {
                stats.batches += 1;
                stats.events += n;
                if (n as i64) < BATCH_EVENTS {
                    stats.caught_up = true;
                    break;
                }
            }
            Ok(BatchOutcome::LockedOut) => {
                stats.locked_out = true;
                return stats;
            }
            Err(e) => {
                tracing::warn!(error = %e, "campaigns: indexing batch failed; retried next tick");
                return stats;
            }
        }
    }
    match resolve_pending_fetches(pool).await {
        Ok(n) => stats.fetch_links = n,
        Err(e) => tracing::warn!(error = %e, "campaigns: resolving download links failed"),
    }
    match scan_artifacts(pool, spool_dirs).await {
        Ok(n) => stats.artifacts_scanned = n,
        Err(e) => tracing::warn!(error = %e, "campaigns: artifact indicator scan failed"),
    }
    if let Err(e) = prune(pool).await {
        tracing::warn!(error = %e, "campaigns: pruning working state failed");
    }
    stats
}

/// The result of [`index_batch`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BatchOutcome {
    /// This many ledger rows were folded in and the cursor moved past them.
    Indexed(usize),
    /// Another indexer holds the lock; nothing was read.
    LockedOut,
}

/// Fold the next `limit` ledger rows past the cursor into the campaign tables, in one transaction.
pub async fn index_batch(pool: &PgPool, limit: i64) -> Result<BatchOutcome, sqlx::Error> {
    let mut tx = pool.begin().await?;
    if !try_lock(&mut tx).await? {
        return Ok(BatchOutcome::LockedOut);
    }
    let cursor: i64 =
        sqlx::query_scalar("SELECT last_event_id FROM campaign_cursor WHERE singleton FOR UPDATE")
            .fetch_one(&mut *tx)
            .await?;
    let rows = sqlx::query(
        "SELECT id, host(source_ip) AS source_ip, sensor, signal_type::text AS signal, \
                observed_at, metadata, session_id::text AS session_id \
         FROM event WHERE id > $1 ORDER BY id LIMIT $2",
    )
    .bind(cursor)
    .bind(limit)
    .fetch_all(&mut *tx)
    .await?;
    let mut events = Vec::with_capacity(rows.len());
    for row in rows {
        events.push(EventRow {
            id: row.try_get("id")?,
            source_ip: row.try_get("source_ip")?,
            sensor: row.try_get("sensor")?,
            signal: row.try_get("signal")?,
            observed_at: row.try_get("observed_at")?,
            metadata: row.try_get("metadata")?,
            session_id: row.try_get("session_id")?,
        });
    }
    let Some(last_id) = events.last().map(|e| e.id) else {
        tx.commit().await?;
        return Ok(BatchOutcome::Indexed(0));
    };

    let mut batch = Batch::load(&mut tx).await?;
    for event in &events {
        batch.process(&mut tx, event).await?;
    }
    batch.sweep_idle_runs(&mut tx).await?;
    batch.flush(&mut tx).await?;
    sqlx::query(
        "UPDATE campaign_cursor SET last_event_id = $1, updated_at = now() WHERE singleton",
    )
    .bind(last_id)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(BatchOutcome::Indexed(events.len()))
}

async fn try_lock(tx: &mut Transaction<'_, Postgres>) -> Result<bool, sqlx::Error> {
    sqlx::query_scalar("SELECT pg_try_advisory_xact_lock($1)")
        .bind(CAMPAIGN_LOCK_KEY)
        .fetch_one(&mut **tx)
        .await
}

#[derive(Debug)]
struct EventRow {
    id: i64,
    source_ip: String,
    sensor: String,
    signal: String,
    observed_at: DateTime<Utc>,
    metadata: Value,
    session_id: Option<String>,
}

/// A plain command line from a command event: not a flood marker, not a summary of suppressed
/// commands.
fn command_of(metadata: &Value) -> Option<&str> {
    if metadata.get("flood").is_some()
        || metadata
            .get(sensor_framework::command_flood::COMMAND_SUMMARY_KEY)
            .is_some()
    {
        return None;
    }
    metadata.get("command").and_then(Value::as_str)
}

fn is_sha256_hex(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn text_field(metadata: &Value, key: &str, max: usize) -> String {
    metadata
        .get(key)
        .and_then(Value::as_str)
        .map(|s| ioc::sanitize_field(s, max))
        .unwrap_or_default()
}

fn window_start(at: DateTime<Utc>) -> DateTime<Utc> {
    let secs = at.timestamp().div_euclid(SCANNER_WINDOW_SECS) * SCANNER_WINDOW_SECS;
    Utc.timestamp_opt(secs, 0).single().unwrap_or(at)
}

/// One shell session's current run.
#[derive(Debug, Clone)]
struct Session {
    source_ip: String,
    sensor: String,
    run: i32,
    first_seen: DateTime<Utc>,
    last_seen: DateTime<Utc>,
    first_event_id: i64,
    last_event_id: i64,
    digest: RunDigest,
    campaign_key: Option<String>,
    closed: bool,
    pending_samples: Vec<String>,
}

impl Session {
    fn start(event: &EventRow, run: i32, shape: &str) -> Self {
        let mut digest = RunDigest::default();
        digest.fold(shape);
        Self {
            source_ip: event.source_ip.clone(),
            sensor: event.sensor.clone(),
            run,
            first_seen: event.observed_at,
            last_seen: event.observed_at,
            first_event_id: event.id,
            last_event_id: event.id,
            digest,
            campaign_key: None,
            closed: false,
            pending_samples: Vec::new(),
        }
    }
}

#[derive(Debug, Clone)]
struct Window {
    sensors: Vec<String>,
    crossed: bool,
}

/// Where a campaign's label and representative come from: the lowest event id that named it.
#[derive(Debug, Clone)]
enum RepSource {
    Ready {
        label: String,
        representative: Value,
    },
    /// A command-sequence run, whose shapes are read back from the ledger only if it wins.
    Run {
        source_ip: String,
        session_id: String,
        first_event_id: i64,
        last_event_id: i64,
    },
}

#[derive(Debug, Clone)]
struct Rep {
    event_id: i64,
    source: RepSource,
}

#[derive(Debug, Clone)]
struct MemberDelta {
    first_seen: DateTime<Utc>,
    last_seen: DateTime<Utc>,
    sightings: i64,
    uploaded: bool,
}

#[derive(Debug, Clone)]
struct CampaignDelta {
    rep: Rep,
    first_seen: DateTime<Utc>,
    last_seen: DateTime<Utc>,
    sightings: i64,
    members: BTreeMap<String, MemberDelta>,
    days: BTreeSet<(NaiveDate, String)>,
    sensors: BTreeMap<String, i64>,
}

/// One sighting of a source in a campaign.
struct Sighting<'a> {
    kind: Kind,
    key: &'a str,
    rep: Rep,
    source_ip: &'a str,
    sensors: &'a [String],
    first_seen: DateTime<Utc>,
    last_seen: DateTime<Utc>,
    sightings: i64,
    uploaded: bool,
}

#[derive(Debug, Clone)]
struct IocDelta {
    detail: String,
    event_id: i64,
    first_seen: DateTime<Utc>,
    last_seen: DateTime<Utc>,
    sightings: i64,
}

#[derive(Debug, Clone)]
struct PendingFetch {
    sensor: String,
    event_id: i64,
    first_seen: DateTime<Utc>,
    last_seen: DateTime<Utc>,
    sightings: i64,
}

/// The working set of one batch: state loaded on first touch, changes accumulated in memory and
/// written once by [`Batch::flush`].
#[derive(Default)]
struct Batch {
    watermarks: HashMap<String, DateTime<Utc>>,
    watermarks_dirty: BTreeSet<String>,
    sessions: HashMap<String, Session>,
    sessions_dirty: BTreeSet<String>,
    windows: HashMap<(String, DateTime<Utc>), Window>,
    windows_dirty: BTreeSet<(String, DateTime<Utc>)>,
    campaigns: BTreeMap<(Kind, String), CampaignDelta>,
    links: BTreeSet<(Kind, String, String)>,
    iocs: BTreeMap<(String, ioc::IocKind, String), IocDelta>,
    ioc_room: HashMap<String, i64>,
    pending_fetches: BTreeMap<(Vec<u8>, String), PendingFetch>,
    artifact_scans: BTreeSet<String>,
}

impl Batch {
    async fn load(tx: &mut Transaction<'_, Postgres>) -> Result<Self, sqlx::Error> {
        let rows = sqlx::query("SELECT sensor, observed FROM campaign_watermark")
            .fetch_all(&mut **tx)
            .await?;
        let mut batch = Batch::default();
        for row in rows {
            batch
                .watermarks
                .insert(row.try_get("sensor")?, row.try_get("observed")?);
        }
        Ok(batch)
    }

    async fn process(
        &mut self,
        tx: &mut Transaction<'_, Postgres>,
        event: &EventRow,
    ) -> Result<(), sqlx::Error> {
        // Telemetry describes an interaction, not an address's activity.
        if event.signal == "honeypot_session_end" {
            return Ok(());
        }
        self.scan_window(tx, event).await?;
        match event.signal.as_str() {
            "honeypot_command_exec" => {
                if let Some(command) = command_of(&event.metadata) {
                    self.command(tx, event, command).await?;
                    self.record_iocs(tx, event, &ioc::extract_from_command(command))
                        .await?;
                }
            }
            "honeypot_malware_upload" => {
                if let Some(sha) = event
                    .metadata
                    .get("sample_sha256")
                    .and_then(Value::as_str)
                    .filter(|s| is_sha256_hex(s))
                {
                    self.upload(tx, event, sha).await?;
                }
            }
            "honeypot_file_download" => {
                if let Some(url) = event.metadata.get("url").and_then(Value::as_str) {
                    self.record_iocs(tx, event, &ioc::extract_from_command(url))
                        .await?;
                    self.download(tx, event, url).await?;
                }
            }
            _ => {}
        }
        let mark = self
            .watermarks
            .entry(event.sensor.clone())
            .or_insert(event.observed_at);
        if event.observed_at >= *mark {
            *mark = event.observed_at;
            self.watermarks_dirty.insert(event.sensor.clone());
        }
        Ok(())
    }

    fn sight(&mut self, s: Sighting<'_>) {
        let delta = self
            .campaigns
            .entry((s.kind, s.key.to_string()))
            .or_insert_with(|| CampaignDelta {
                rep: s.rep.clone(),
                first_seen: s.first_seen,
                last_seen: s.last_seen,
                sightings: 0,
                members: BTreeMap::new(),
                days: BTreeSet::new(),
                sensors: BTreeMap::new(),
            });
        if s.rep.event_id < delta.rep.event_id {
            delta.rep = s.rep;
        }
        delta.first_seen = delta.first_seen.min(s.first_seen);
        delta.last_seen = delta.last_seen.max(s.last_seen);
        delta.sightings += s.sightings;
        let member = delta
            .members
            .entry(s.source_ip.to_string())
            .or_insert(MemberDelta {
                first_seen: s.first_seen,
                last_seen: s.last_seen,
                sightings: 0,
                uploaded: false,
            });
        member.first_seen = member.first_seen.min(s.first_seen);
        member.last_seen = member.last_seen.max(s.last_seen);
        member.sightings += s.sightings;
        member.uploaded |= s.uploaded;
        delta
            .days
            .insert((s.first_seen.date_naive(), s.source_ip.to_string()));
        for sensor in s.sensors {
            *delta.sensors.entry(sensor.clone()).or_default() += s.sightings;
        }
    }

    async fn session(
        &mut self,
        tx: &mut Transaction<'_, Postgres>,
        session_id: &str,
    ) -> Result<Option<Session>, sqlx::Error> {
        if let Some(s) = self.sessions.remove(session_id) {
            return Ok(Some(s));
        }
        let row = sqlx::query(
            "SELECT host(source_ip) AS source_ip, sensor, run, first_seen, last_seen, \
                    first_event_id, last_event_id, shapes, shape_chars, last_shape, chain, \
                    campaign_key, closed, pending_samples \
             FROM campaign_session WHERE session_id = $1::uuid",
        )
        .bind(session_id)
        .fetch_optional(&mut **tx)
        .await?;
        row.map(|r| session_from_row(&r)).transpose()
    }

    fn put_session(&mut self, session_id: &str, session: Session) {
        self.sessions_dirty.insert(session_id.to_string());
        self.sessions.insert(session_id.to_string(), session);
    }

    async fn command(
        &mut self,
        tx: &mut Transaction<'_, Postgres>,
        event: &EventRow,
        command: &str,
    ) -> Result<(), sqlx::Error> {
        let Some(session_id) = event.session_id.as_deref() else {
            return Ok(());
        };
        let shape = fingerprint::normalize(command);
        if shape.is_empty() {
            return Ok(());
        }
        let session = match self.session(tx, session_id).await? {
            None => Session::start(event, 0, &shape),
            Some(mut s) => {
                // The session's own gap, not its sensor's clock: several nodes can feed one sensor
                // name with different lags, and a lagging node's session must not be cut into
                // one-command runs because another node's events are newer.
                if !s.closed && (event.observed_at - s.last_seen).num_seconds() > SESSION_IDLE_SECS
                {
                    self.close_run(session_id, &mut s);
                }
                if s.closed {
                    Session::start(event, s.run + 1, &shape)
                } else {
                    s.last_seen = s.last_seen.max(event.observed_at);
                    s.last_event_id = event.id;
                    if s.campaign_key.is_none() {
                        s.digest.fold(&shape);
                        if s.digest.shapes >= MAX_RUN_SHAPES {
                            self.materialize(session_id, &mut s);
                        }
                    }
                    s
                }
            }
        };
        self.put_session(session_id, session);
        Ok(())
    }

    /// End a run: a run long enough to mean something joins its fingerprint's campaign.
    fn close_run(&mut self, session_id: &str, s: &mut Session) {
        if s.campaign_key.is_none() && s.digest.shape_chars >= MIN_RUN_CHARS {
            self.materialize(session_id, s);
        }
        s.closed = true;
        s.pending_samples.clear();
    }

    fn materialize(&mut self, session_id: &str, s: &mut Session) {
        let key = s.digest.key();
        let sensors = [s.sensor.clone()];
        self.sight(Sighting {
            kind: Kind::CommandSequence,
            key: &key,
            rep: Rep {
                event_id: s.first_event_id,
                source: RepSource::Run {
                    source_ip: s.source_ip.clone(),
                    session_id: session_id.to_string(),
                    first_event_id: s.first_event_id,
                    last_event_id: s.last_event_id,
                },
            },
            source_ip: &s.source_ip,
            sensors: &sensors,
            first_seen: s.first_seen,
            last_seen: s.last_seen,
            sightings: 1,
            uploaded: false,
        });
        for sha in s.pending_samples.drain(..) {
            self.links.insert((Kind::CommandSequence, key.clone(), sha));
        }
        s.campaign_key = Some(key);
    }

    /// Close every open run whose sensor's clock has moved [`SESSION_SWEEP_SECS`] past it.
    async fn sweep_idle_runs(
        &mut self,
        tx: &mut Transaction<'_, Postgres>,
    ) -> Result<(), sqlx::Error> {
        let marks: Vec<(String, DateTime<Utc>)> = self
            .watermarks
            .iter()
            .map(|(s, t)| (s.clone(), *t))
            .collect();
        for (sensor, mark) in marks {
            let cutoff = mark - chrono::Duration::seconds(SESSION_SWEEP_SECS);
            let rows = sqlx::query(
                "SELECT session_id::text AS session_id FROM campaign_session \
                 WHERE NOT closed AND sensor = $1 AND last_seen < $2",
            )
            .bind(&sensor)
            .bind(cutoff)
            .fetch_all(&mut **tx)
            .await?;
            let mut idle: BTreeSet<String> = BTreeSet::new();
            for row in rows {
                let id: String = row.try_get("session_id")?;
                // A session this batch touched is judged on its in-memory state below.
                if !self.sessions.contains_key(&id) {
                    idle.insert(id);
                }
            }
            idle.extend(
                self.sessions
                    .iter()
                    .filter(|(_, s)| s.sensor == sensor && !s.closed && s.last_seen < cutoff)
                    .map(|(id, _)| id.clone()),
            );
            for id in idle {
                if let Some(mut s) = self.session(tx, &id).await? {
                    self.close_run(&id, &mut s);
                    self.put_session(&id, s);
                }
            }
        }
        Ok(())
    }

    async fn upload(
        &mut self,
        tx: &mut Transaction<'_, Postgres>,
        event: &EventRow,
        sha: &str,
    ) -> Result<(), sqlx::Error> {
        let orig_name = text_field(&event.metadata, "sample_orig_name", 64);
        let label = if orig_name.is_empty() {
            format!("sample {}", &sha[..12])
        } else {
            format!("sample {} ({orig_name})", &sha[..12])
        };
        let representative = json!({
            "sha256": sha,
            "origin": "uploaded",
            "orig_name": orig_name,
            "capture_reason": text_field(&event.metadata, "capture_reason", 32),
            "size": event.metadata.get("sample_size").and_then(Value::as_u64),
            "sensor": event.sensor,
            "source_ip": event.source_ip,
        });
        let sensors = [event.sensor.clone()];
        self.sight(Sighting {
            kind: Kind::Sample,
            key: sha,
            rep: Rep {
                event_id: event.id,
                source: RepSource::Ready {
                    label,
                    representative,
                },
            },
            source_ip: &event.source_ip,
            sensors: &sensors,
            first_seen: event.observed_at,
            last_seen: event.observed_at,
            sightings: 1,
            uploaded: true,
        });
        self.links
            .insert((Kind::Sample, sha.to_string(), sha.to_string()));
        self.artifact_scans.insert(sha.to_string());

        let Some(session_id) = event.session_id.as_deref() else {
            return Ok(());
        };
        if let Some(mut s) = self.session(tx, session_id).await? {
            match (&s.campaign_key, s.closed) {
                (Some(key), _) => {
                    self.links
                        .insert((Kind::CommandSequence, key.clone(), sha.to_string()));
                }
                (None, false) => {
                    if s.pending_samples.len() < MAX_SESSION_SAMPLES
                        && !s.pending_samples.iter().any(|p| p == sha)
                    {
                        s.pending_samples.push(sha.to_string());
                    }
                }
                (None, true) => {}
            }
            self.put_session(session_id, s);
        }
        Ok(())
    }

    async fn download(
        &mut self,
        tx: &mut Transaction<'_, Postgres>,
        event: &EventRow,
        url: &str,
    ) -> Result<(), sqlx::Error> {
        if parse_url_parts(url).is_none() {
            return Ok(());
        }
        let hash = url_hash(url);
        let fetched = sqlx::query(
            "SELECT status, encode(sha256, 'hex') AS sha FROM fetch_attempt WHERE url_hash = $1",
        )
        .bind(&hash)
        .fetch_optional(&mut **tx)
        .await?;
        let (status, sha): (Option<String>, Option<String>) = match fetched {
            Some(row) => (Some(row.try_get("status")?), row.try_get("sha")?),
            None => (None, None),
        };
        match (status.as_deref(), sha) {
            (Some("success"), Some(sha)) if is_sha256_hex(&sha) => {
                self.fetched_sample(
                    &sha,
                    url,
                    &event.source_ip,
                    &event.sensor,
                    event.id,
                    (event.observed_at, event.observed_at),
                    1,
                );
            }
            (Some("dead" | "rejected" | "empty" | "success"), _) => {}
            _ => {
                let pending = self
                    .pending_fetches
                    .entry((hash, event.source_ip.clone()))
                    .or_insert(PendingFetch {
                        sensor: event.sensor.clone(),
                        event_id: event.id,
                        first_seen: event.observed_at,
                        last_seen: event.observed_at,
                        sightings: 0,
                    });
                pending.event_id = pending.event_id.min(event.id);
                pending.first_seen = pending.first_seen.min(event.observed_at);
                pending.last_seen = pending.last_seen.max(event.observed_at);
                pending.sightings += 1;
            }
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn fetched_sample(
        &mut self,
        sha: &str,
        url: &str,
        source_ip: &str,
        sensor: &str,
        event_id: i64,
        (first_seen, last_seen): (DateTime<Utc>, DateTime<Utc>),
        sightings: i64,
    ) {
        let sensors = [sensor.to_string()];
        self.sight(Sighting {
            kind: Kind::Sample,
            key: sha,
            rep: Rep {
                event_id,
                source: RepSource::Ready {
                    label: format!("sample {} (fetched)", &sha[..12]),
                    representative: json!({
                        "sha256": sha,
                        "origin": "fetched",
                        "url": ioc::sanitize_field(url, ioc::MAX_IOC_VALUE_BYTES),
                        "sensor": sensor,
                        "source_ip": source_ip,
                    }),
                },
            },
            source_ip,
            sensors: &sensors,
            first_seen,
            last_seen,
            sightings,
            uploaded: false,
        });
        self.links
            .insert((Kind::Sample, sha.to_string(), sha.to_string()));
        self.artifact_scans.insert(sha.to_string());
    }

    async fn scan_window(
        &mut self,
        tx: &mut Transaction<'_, Postgres>,
        event: &EventRow,
    ) -> Result<(), sqlx::Error> {
        let start = window_start(event.observed_at);
        let key = (event.source_ip.clone(), start);
        let mut window = match self.windows.remove(&key) {
            Some(w) => w,
            None => {
                let row = sqlx::query(
                    "SELECT sensors, crossed FROM campaign_scan_window \
                     WHERE source_ip = $1::inet AND window_start = $2",
                )
                .bind(&event.source_ip)
                .bind(start)
                .fetch_optional(&mut **tx)
                .await?;
                match row {
                    Some(r) => Window {
                        sensors: r.try_get("sensors")?,
                        crossed: r.try_get("crossed")?,
                    },
                    None => Window {
                        sensors: Vec::new(),
                        crossed: false,
                    },
                }
            }
        };
        if !window.crossed && !window.sensors.contains(&event.sensor) {
            window.sensors.push(event.sensor.clone());
            window.sensors.sort();
            if window.sensors.len() >= SCANNER_MIN_SENSORS {
                window.crossed = true;
                let key_text = window.sensors.join(",");
                self.sight(Sighting {
                    kind: Kind::Scanner,
                    key: &key_text,
                    rep: Rep {
                        event_id: event.id,
                        source: RepSource::Ready {
                            label: ioc::sanitize_field(
                                &format!("multi-service scan: {}", window.sensors.join(", ")),
                                200,
                            ),
                            representative: json!({
                                "sensors": window.sensors,
                                "window_start": start,
                                "window_secs": SCANNER_WINDOW_SECS,
                                "source_ip": event.source_ip,
                            }),
                        },
                    },
                    source_ip: &event.source_ip,
                    sensors: &window.sensors.clone(),
                    first_seen: event.observed_at,
                    last_seen: event.observed_at,
                    sightings: 1,
                    uploaded: false,
                });
            }
            self.windows_dirty.insert(key.clone());
        }
        self.windows.insert(key, window);
        Ok(())
    }

    async fn record_iocs(
        &mut self,
        tx: &mut Transaction<'_, Postgres>,
        event: &EventRow,
        found: &[Indicator],
    ) -> Result<(), sqlx::Error> {
        for indicator in found {
            let key = (
                event.source_ip.clone(),
                indicator.kind,
                indicator.value.clone(),
            );
            if let Some(delta) = self.iocs.get_mut(&key) {
                delta.last_seen = delta.last_seen.max(event.observed_at);
                delta.first_seen = delta.first_seen.min(event.observed_at);
                delta.sightings += 1;
                continue;
            }
            let stored: bool = sqlx::query_scalar(
                "SELECT EXISTS (SELECT 1 FROM ioc WHERE source_ip = $1::inet AND kind = $2 \
                 AND value = $3 AND artifact_sha256 IS NULL)",
            )
            .bind(&event.source_ip)
            .bind(indicator.kind.as_str())
            .bind(&indicator.value)
            .fetch_one(&mut **tx)
            .await?;
            if !stored {
                let room = match self.ioc_room.get(&event.source_ip) {
                    Some(r) => *r,
                    None => {
                        let used: i64 = sqlx::query_scalar(
                            "SELECT count(*) FROM ioc WHERE source_ip = $1::inet \
                             AND artifact_sha256 IS NULL",
                        )
                        .bind(&event.source_ip)
                        .fetch_one(&mut **tx)
                        .await?;
                        MAX_IOCS_PER_SOURCE - used
                    }
                };
                if room <= 0 {
                    self.ioc_room.insert(event.source_ip.clone(), room);
                    continue;
                }
                self.ioc_room.insert(event.source_ip.clone(), room - 1);
            }
            self.iocs.insert(
                key,
                IocDelta {
                    detail: indicator.detail.clone(),
                    event_id: event.id,
                    first_seen: event.observed_at,
                    last_seen: event.observed_at,
                    sightings: 1,
                },
            );
        }
        Ok(())
    }

    async fn flush(self, tx: &mut Transaction<'_, Postgres>) -> Result<(), sqlx::Error> {
        for id in &self.sessions_dirty {
            if let Some(s) = self.sessions.get(id) {
                write_session(tx, id, s).await?;
            }
        }
        for key in &self.windows_dirty {
            if let Some(w) = self.windows.get(key) {
                sqlx::query(
                    "INSERT INTO campaign_scan_window (source_ip, window_start, sensors, crossed) \
                     VALUES ($1::inet, $2, $3, $4) \
                     ON CONFLICT (source_ip, window_start) \
                     DO UPDATE SET sensors = EXCLUDED.sensors, crossed = EXCLUDED.crossed",
                )
                .bind(&key.0)
                .bind(key.1)
                .bind(&w.sensors)
                .bind(w.crossed)
                .execute(&mut **tx)
                .await?;
            }
        }
        for sensor in &self.watermarks_dirty {
            if let Some(mark) = self.watermarks.get(sensor) {
                sqlx::query(
                    "INSERT INTO campaign_watermark (sensor, observed) VALUES ($1, $2) \
                     ON CONFLICT (sensor) DO UPDATE \
                     SET observed = GREATEST(campaign_watermark.observed, EXCLUDED.observed)",
                )
                .bind(sensor)
                .bind(mark)
                .execute(&mut **tx)
                .await?;
            }
        }
        for ((kind, key), delta) in &self.campaigns {
            write_campaign(tx, *kind, key, delta).await?;
        }
        for (kind, key, sha) in &self.links {
            sqlx::query(
                "INSERT INTO campaign_sample (campaign_id, sha256) \
                 SELECT id, $3 FROM campaign WHERE kind = $1 AND key = $2 \
                 ON CONFLICT DO NOTHING",
            )
            .bind(kind.as_str())
            .bind(key)
            .bind(sha)
            .execute(&mut **tx)
            .await?;
        }
        for ((source_ip, kind, value), d) in &self.iocs {
            sqlx::query(
                "INSERT INTO ioc (kind, value, detail, event_id, source_ip, first_seen, last_seen, \
                                  sightings) \
                 VALUES ($1, $2, $3, $4, $5::inet, $6, $7, $8) \
                 ON CONFLICT (source_ip, kind, value) WHERE artifact_sha256 IS NULL DO UPDATE SET \
                   detail = CASE WHEN EXCLUDED.event_id < ioc.event_id THEN EXCLUDED.detail \
                                 ELSE ioc.detail END, \
                   event_id = LEAST(ioc.event_id, EXCLUDED.event_id), \
                   first_seen = LEAST(ioc.first_seen, EXCLUDED.first_seen), \
                   last_seen = GREATEST(ioc.last_seen, EXCLUDED.last_seen), \
                   sightings = ioc.sightings + EXCLUDED.sightings",
            )
            .bind(kind.as_str())
            .bind(value)
            .bind(&d.detail)
            .bind(d.event_id)
            .bind(source_ip)
            .bind(d.first_seen)
            .bind(d.last_seen)
            .bind(d.sightings)
            .execute(&mut **tx)
            .await?;
        }
        for ((hash, source_ip), p) in &self.pending_fetches {
            sqlx::query(
                "INSERT INTO campaign_pending_fetch \
                     (url_hash, source_ip, sensor, event_id, first_seen, last_seen, sightings) \
                 VALUES ($1, $2::inet, $3, $4, $5, $6, $7) \
                 ON CONFLICT (url_hash, source_ip) DO UPDATE SET \
                   event_id = LEAST(campaign_pending_fetch.event_id, EXCLUDED.event_id), \
                   first_seen = LEAST(campaign_pending_fetch.first_seen, EXCLUDED.first_seen), \
                   last_seen = GREATEST(campaign_pending_fetch.last_seen, EXCLUDED.last_seen), \
                   sightings = campaign_pending_fetch.sightings + EXCLUDED.sightings",
            )
            .bind(hash)
            .bind(source_ip)
            .bind(&p.sensor)
            .bind(p.event_id)
            .bind(p.first_seen)
            .bind(p.last_seen)
            .bind(p.sightings)
            .execute(&mut **tx)
            .await?;
        }
        for sha in &self.artifact_scans {
            sqlx::query(
                "INSERT INTO ioc_artifact_scan (sha256) VALUES ($1) ON CONFLICT DO NOTHING",
            )
            .bind(sha)
            .execute(&mut **tx)
            .await?;
        }
        Ok(())
    }
}

fn session_from_row(r: &sqlx::postgres::PgRow) -> Result<Session, sqlx::Error> {
    let bytes32 = |name: &str| -> Result<[u8; 32], sqlx::Error> {
        let v: Vec<u8> = r.try_get(name)?;
        v.try_into().map_err(|_| sqlx::Error::ColumnDecode {
            index: name.to_string(),
            source: "expected 32 bytes".into(),
        })
    };
    Ok(Session {
        source_ip: r.try_get("source_ip")?,
        sensor: r.try_get("sensor")?,
        run: r.try_get("run")?,
        first_seen: r.try_get("first_seen")?,
        last_seen: r.try_get("last_seen")?,
        first_event_id: r.try_get("first_event_id")?,
        last_event_id: r.try_get("last_event_id")?,
        digest: RunDigest {
            chain: bytes32("chain")?,
            last_shape: bytes32("last_shape")?,
            shapes: r.try_get("shapes")?,
            shape_chars: r.try_get("shape_chars")?,
        },
        campaign_key: r.try_get("campaign_key")?,
        closed: r.try_get("closed")?,
        pending_samples: r.try_get("pending_samples")?,
    })
}

async fn write_session(
    tx: &mut Transaction<'_, Postgres>,
    session_id: &str,
    s: &Session,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO campaign_session (session_id, source_ip, sensor, run, first_seen, last_seen, \
             first_event_id, last_event_id, shapes, shape_chars, last_shape, chain, campaign_key, \
             closed, pending_samples) \
         VALUES ($1::uuid, $2::inet, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15) \
         ON CONFLICT (session_id) DO UPDATE SET \
           run = EXCLUDED.run, first_seen = EXCLUDED.first_seen, last_seen = EXCLUDED.last_seen, \
           first_event_id = EXCLUDED.first_event_id, last_event_id = EXCLUDED.last_event_id, \
           shapes = EXCLUDED.shapes, shape_chars = EXCLUDED.shape_chars, \
           last_shape = EXCLUDED.last_shape, chain = EXCLUDED.chain, \
           campaign_key = EXCLUDED.campaign_key, closed = EXCLUDED.closed, \
           pending_samples = EXCLUDED.pending_samples",
    )
    .bind(session_id)
    .bind(&s.source_ip)
    .bind(&s.sensor)
    .bind(s.run)
    .bind(s.first_seen)
    .bind(s.last_seen)
    .bind(s.first_event_id)
    .bind(s.last_event_id)
    .bind(s.digest.shapes)
    .bind(s.digest.shape_chars)
    .bind(s.digest.last_shape.as_slice())
    .bind(s.digest.chain.as_slice())
    .bind(&s.campaign_key)
    .bind(s.closed)
    .bind(&s.pending_samples)
    .execute(&mut **tx)
    .await?;
    Ok(())
}

/// The label and representative of a command-sequence run, read back from the ledger rows of its
/// session between its first and last event: one session's commands, at most a few hundred rows.
async fn run_representative(
    tx: &mut Transaction<'_, Postgres>,
    source_ip: &str,
    session_id: &str,
    first_event_id: i64,
    last_event_id: i64,
) -> Result<(String, Value), sqlx::Error> {
    let rows = sqlx::query(
        "SELECT metadata FROM event \
         WHERE source_ip = $1::inet AND session_id = $2::uuid AND id BETWEEN $3 AND $4 \
           AND signal_type = 'honeypot_command_exec' \
         ORDER BY id LIMIT 2048",
    )
    .bind(source_ip)
    .bind(session_id)
    .bind(first_event_id)
    .bind(last_event_id)
    .fetch_all(&mut **tx)
    .await?;
    let mut metadata = Vec::with_capacity(rows.len());
    for row in rows {
        metadata.push(row.try_get::<Value, _>("metadata")?);
    }
    let shapes = fingerprint::collapsed_shapes(
        metadata.iter().filter_map(command_of),
        MAX_RUN_SHAPES as usize,
    );
    let shapes: Vec<String> = shapes
        .iter()
        .map(|s| ioc::sanitize_field(s, fingerprint::MAX_SHAPE_CHARS))
        .collect();
    let label = ioc::sanitize_field(&fingerprint::label(&shapes), 200);
    Ok((
        label,
        json!({
            "source_ip": source_ip,
            "session_id": session_id,
            "shapes": shapes,
        }),
    ))
}

async fn write_campaign(
    tx: &mut Transaction<'_, Postgres>,
    kind: Kind,
    key: &str,
    delta: &CampaignDelta,
) -> Result<(), sqlx::Error> {
    let stored_rep: Option<i64> =
        sqlx::query_scalar("SELECT rep_event_id FROM campaign WHERE kind = $1 AND key = $2")
            .bind(kind.as_str())
            .bind(key)
            .fetch_optional(&mut **tx)
            .await?;
    let wins = stored_rep.is_none_or(|stored| delta.rep.event_id < stored);
    let (label, representative) = match (&delta.rep.source, wins) {
        (_, false) => (String::new(), Value::Null),
        (
            RepSource::Ready {
                label,
                representative,
            },
            true,
        ) => (label.clone(), representative.clone()),
        (
            RepSource::Run {
                source_ip,
                session_id,
                first_event_id,
                last_event_id,
            },
            true,
        ) => run_representative(tx, source_ip, session_id, *first_event_id, *last_event_id).await?,
    };
    let id: i64 = sqlx::query_scalar(
        "INSERT INTO campaign (kind, key, label, representative, rep_event_id, first_seen, \
                               last_seen, sightings) \
         VALUES ($1, $2, $3, COALESCE($4, '{}'::jsonb), $5, $6, $7, $8) \
         ON CONFLICT (kind, key) DO UPDATE SET \
           label = CASE WHEN EXCLUDED.rep_event_id < campaign.rep_event_id \
                        THEN EXCLUDED.label ELSE campaign.label END, \
           representative = CASE WHEN EXCLUDED.rep_event_id < campaign.rep_event_id \
                                 THEN EXCLUDED.representative ELSE campaign.representative END, \
           rep_event_id = LEAST(campaign.rep_event_id, EXCLUDED.rep_event_id), \
           first_seen = LEAST(campaign.first_seen, EXCLUDED.first_seen), \
           last_seen = GREATEST(campaign.last_seen, EXCLUDED.last_seen), \
           sightings = campaign.sightings + EXCLUDED.sightings \
         RETURNING id",
    )
    .bind(kind.as_str())
    .bind(key)
    .bind(&label)
    .bind((!representative.is_null()).then_some(&representative))
    .bind(delta.rep.event_id)
    .bind(delta.first_seen)
    .bind(delta.last_seen)
    .bind(delta.sightings)
    .fetch_one(&mut **tx)
    .await?;

    let (mut ips, mut firsts, mut lasts, mut counts, mut uploads) =
        (Vec::new(), Vec::new(), Vec::new(), Vec::new(), Vec::new());
    for (ip, m) in &delta.members {
        ips.push(ip.clone());
        firsts.push(m.first_seen);
        lasts.push(m.last_seen);
        counts.push(m.sightings);
        uploads.push(m.uploaded);
    }
    let inserted: Vec<bool> = sqlx::query_scalar(
        "INSERT INTO campaign_member (campaign_id, source_ip, first_seen, last_seen, sightings, \
                                      uploaded) \
         SELECT $1, ip::inet, f, l, n, u \
         FROM UNNEST($2::text[], $3::timestamptz[], $4::timestamptz[], $5::bigint[], $6::bool[]) \
              AS m(ip, f, l, n, u) \
         ON CONFLICT (campaign_id, source_ip) DO UPDATE SET \
           first_seen = LEAST(campaign_member.first_seen, EXCLUDED.first_seen), \
           last_seen = GREATEST(campaign_member.last_seen, EXCLUDED.last_seen), \
           sightings = campaign_member.sightings + EXCLUDED.sightings, \
           uploaded = campaign_member.uploaded OR EXCLUDED.uploaded \
         RETURNING (xmax = 0)",
    )
    .bind(id)
    .bind(&ips)
    .bind(&firsts)
    .bind(&lasts)
    .bind(&counts)
    .bind(&uploads)
    .fetch_all(&mut **tx)
    .await?;
    let added = inserted.iter().filter(|new| **new).count() as i32;
    if added > 0 {
        sqlx::query("UPDATE campaign SET member_count = member_count + $2 WHERE id = $1")
            .bind(id)
            .bind(added)
            .execute(&mut **tx)
            .await?;
    }

    let (days, day_ips): (Vec<NaiveDate>, Vec<String>) = delta.days.iter().cloned().unzip();
    sqlx::query(
        "INSERT INTO campaign_member_day (campaign_id, day, source_ip) \
         SELECT $1, d, ip::inet FROM UNNEST($2::date[], $3::text[]) AS m(d, ip) \
         ON CONFLICT DO NOTHING",
    )
    .bind(id)
    .bind(&days)
    .bind(&day_ips)
    .execute(&mut **tx)
    .await?;

    let (sensors, sightings): (Vec<String>, Vec<i64>) =
        delta.sensors.iter().map(|(s, n)| (s.clone(), *n)).unzip();
    sqlx::query(
        "INSERT INTO campaign_sensor (campaign_id, sensor, sightings) \
         SELECT $1, s, n FROM UNNEST($2::text[], $3::bigint[]) AS m(s, n) \
         ON CONFLICT (campaign_id, sensor) \
         DO UPDATE SET sightings = campaign_sensor.sightings + EXCLUDED.sightings",
    )
    .bind(id)
    .bind(&sensors)
    .bind(&sightings)
    .execute(&mut **tx)
    .await?;
    Ok(())
}

/// Link the downloads still waiting on the fetcher to the sample it captured from their URL, drop
/// the ones whose fetch ended without a body or has waited past [`PENDING_FETCH_TTL_DAYS`], and
/// leave the rest for a later tick. Returns the number of links made.
pub async fn resolve_pending_fetches(pool: &PgPool) -> Result<usize, sqlx::Error> {
    let mut tx = pool.begin().await?;
    if !try_lock(&mut tx).await? {
        return Ok(0);
    }
    let rows = sqlx::query(
        "SELECT p.url_hash, host(p.source_ip) AS source_ip, p.sensor, p.event_id, p.first_seen, \
                p.last_seen, p.sightings, p.queued_at < now() - make_interval(days => $2) AS stale, \
                fa.status, encode(fa.sha256, 'hex') AS sha, fa.url \
         FROM campaign_pending_fetch p LEFT JOIN fetch_attempt fa ON fa.url_hash = p.url_hash \
         ORDER BY p.queued_at LIMIT $1",
    )
    .bind(PENDING_FETCHES_PER_TICK)
    .bind(PENDING_FETCH_TTL_DAYS as i32)
    .fetch_all(&mut *tx)
    .await?;
    let mut batch = Batch::default();
    let mut linked = 0;
    let mut done: Vec<(Vec<u8>, String)> = Vec::new();
    for row in rows {
        let hash: Vec<u8> = row.try_get("url_hash")?;
        let source_ip: String = row.try_get("source_ip")?;
        let status: Option<String> = row.try_get("status")?;
        let sha: Option<String> = row.try_get("sha")?;
        let stale: bool = row.try_get("stale")?;
        match (status.as_deref(), sha) {
            (Some("success"), Some(sha)) if is_sha256_hex(&sha) => {
                let url: String = row.try_get("url")?;
                batch.fetched_sample(
                    &sha,
                    &url,
                    &source_ip,
                    &row.try_get::<String, _>("sensor")?,
                    row.try_get("event_id")?,
                    (row.try_get("first_seen")?, row.try_get("last_seen")?),
                    row.try_get("sightings")?,
                );
                linked += 1;
                done.push((hash, source_ip));
            }
            (Some("dead" | "rejected" | "empty" | "success"), _) => done.push((hash, source_ip)),
            _ if stale => done.push((hash, source_ip)),
            _ => {}
        }
    }
    batch.flush(&mut tx).await?;
    for (hash, source_ip) in done {
        sqlx::query(
            "DELETE FROM campaign_pending_fetch WHERE url_hash = $1 AND source_ip = $2::inet",
        )
        .bind(hash)
        .bind(source_ip)
        .execute(&mut *tx)
        .await?;
    }
    tx.commit().await?;
    Ok(linked)
}

/// What scanning one queued artifact found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ArtifactScan {
    Done {
        indicators: usize,
        self_propagating: bool,
    },
    NotText,
    TooBig,
    Missing,
}

/// Read `sha256` from whichever spool holds it, verified and bounded, and extract its indicators.
pub fn scan_artifact(
    spool_dirs: &[(&'static str, PathBuf)],
    sha256: &str,
) -> (ArtifactScan, Vec<Indicator>) {
    for (bucket, dir) in spool_dirs {
        match sensor_framework::spool::read_verified(
            dir,
            sha256,
            ioc::MAX_ARTIFACT_TEXT_BYTES as u64,
        ) {
            Ok(bytes) => {
                return match ioc::extract_from_artifact(&bytes) {
                    Some(found) => {
                        let text = String::from_utf8_lossy(&bytes);
                        (
                            ArtifactScan::Done {
                                indicators: found.len(),
                                self_propagating: ioc::self_propagating(&text),
                            },
                            found,
                        )
                    }
                    None => (ArtifactScan::NotText, Vec::new()),
                };
            }
            Err(sensor_framework::SpoolError::FileSizeExceeded { .. }) => {
                return (ArtifactScan::TooBig, Vec::new());
            }
            Err(sensor_framework::SpoolError::Io(e))
                if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => {
                tracing::warn!(bucket, sha256, error = %e, "campaigns: refused a spool entry that failed verification");
            }
        }
    }
    (ArtifactScan::Missing, Vec::new())
}

/// Extract indicators from up to [`ARTIFACT_SCANS_PER_TICK`] queued artifacts. Returns how many
/// were scanned (found in a spool, text or not).
pub async fn scan_artifacts(
    pool: &PgPool,
    spool_dirs: &[(&'static str, PathBuf)],
) -> Result<usize, sqlx::Error> {
    let due: Vec<(String, i32)> = sqlx::query_as(
        "SELECT sha256, attempts FROM ioc_artifact_scan \
         WHERE state = 'pending' AND next_attempt <= now() ORDER BY next_attempt LIMIT $1",
    )
    .bind(ARTIFACT_SCANS_PER_TICK)
    .fetch_all(pool)
    .await?;
    let mut scanned = 0;
    for (sha, attempts) in due {
        let dirs = spool_dirs.to_vec();
        let sha_owned = sha.clone();
        let (outcome, found) =
            tokio::task::spawn_blocking(move || scan_artifact(&dirs, &sha_owned))
                .await
                .unwrap_or((ArtifactScan::Missing, Vec::new()));
        let mut tx = pool.begin().await?;
        if !try_lock(&mut tx).await? {
            return Ok(scanned);
        }
        match outcome {
            ArtifactScan::Done {
                indicators,
                self_propagating,
            } => {
                scanned += 1;
                for i in &found {
                    sqlx::query(
                        "INSERT INTO ioc (kind, value, detail, artifact_sha256, first_seen, last_seen) \
                         SELECT $1, $2, $3, $4, t, t FROM (SELECT COALESCE( \
                             (SELECT first_seen FROM campaign WHERE kind = 'sample' AND key = $4), \
                             now()) AS t) seen \
                         ON CONFLICT (artifact_sha256, kind, value) WHERE artifact_sha256 IS NOT NULL \
                         DO NOTHING",
                    )
                    .bind(i.kind.as_str())
                    .bind(&i.value)
                    .bind(&i.detail)
                    .bind(&sha)
                    .execute(&mut *tx)
                    .await?;
                }
                if self_propagating {
                    sqlx::query(
                        "UPDATE campaign SET self_propagating = TRUE \
                         WHERE kind = 'sample' AND key = $1",
                    )
                    .bind(&sha)
                    .execute(&mut *tx)
                    .await?;
                }
                finish_scan(&mut tx, &sha, "done", indicators as i32).await?;
            }
            ArtifactScan::NotText => {
                scanned += 1;
                finish_scan(&mut tx, &sha, "not_text", 0).await?;
            }
            ArtifactScan::TooBig => {
                scanned += 1;
                finish_scan(&mut tx, &sha, "too_big", 0).await?;
            }
            ArtifactScan::Missing if attempts + 1 >= ARTIFACT_ATTEMPTS => {
                finish_scan(&mut tx, &sha, "missing", 0).await?;
            }
            ArtifactScan::Missing => {
                // A body can reach the spool after its event (a split deployment ships it
                // separately), so a miss is retried with a growing delay before it is recorded.
                sqlx::query(
                    "UPDATE ioc_artifact_scan SET attempts = attempts + 1, \
                         next_attempt = now() + make_interval(mins => 10 * (attempts + 1)) \
                     WHERE sha256 = $1",
                )
                .bind(&sha)
                .execute(&mut *tx)
                .await?;
            }
        }
        tx.commit().await?;
    }
    Ok(scanned)
}

async fn finish_scan(
    tx: &mut Transaction<'_, Postgres>,
    sha: &str,
    state: &str,
    indicators: i32,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "UPDATE ioc_artifact_scan SET state = $2, indicators = $3, scanned_at = now(), \
             attempts = attempts + 1 WHERE sha256 = $1",
    )
    .bind(sha)
    .bind(state)
    .bind(indicators)
    .execute(&mut **tx)
    .await?;
    Ok(())
}

/// Drop closed sessions and scanner windows their sensor's clock passed [`STATE_RETAIN_SECS`]
/// ago. A command arriving for a dropped session later starts a new run, which is what an idle gap
/// that long does anyway.
pub async fn prune(pool: &PgPool) -> Result<(), sqlx::Error> {
    let mut tx = pool.begin().await?;
    if !try_lock(&mut tx).await? {
        return Ok(());
    }
    sqlx::query(
        "DELETE FROM campaign_session s USING campaign_watermark w \
         WHERE s.sensor = w.sensor AND s.closed \
           AND s.last_seen < w.observed - make_interval(secs => $1)",
    )
    .bind(STATE_RETAIN_SECS as f64)
    .execute(&mut *tx)
    .await?;
    sqlx::query(
        "DELETE FROM campaign_scan_window \
         WHERE window_start < (SELECT max(observed) FROM campaign_watermark) \
                              - make_interval(secs => $1)",
    )
    .bind(STATE_RETAIN_SECS as f64)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn windows_are_aligned_hours() {
        let at = Utc.with_ymd_and_hms(2026, 10, 7, 4, 41, 9).unwrap();
        assert_eq!(
            window_start(at),
            Utc.with_ymd_and_hms(2026, 10, 7, 4, 0, 0).unwrap()
        );
    }

    #[test]
    fn flood_markers_and_summaries_are_not_commands() {
        assert_eq!(
            command_of(&json!({"command": "uname -a"})),
            Some("uname -a")
        );
        assert_eq!(
            command_of(&json!({"command": "<binary channel data>", "flood": "binary"})),
            None
        );
        assert_eq!(
            command_of(&json!({"command": "<summary>", "command_summary": true})),
            None
        );
    }

    #[test]
    fn kinds_round_trip_through_their_stored_names() {
        for k in Kind::ALL {
            assert_eq!(Kind::parse(k.as_str()), Some(k));
        }
        assert!(is_sha256_hex(&"a".repeat(64)));
        assert!(!is_sha256_hex(&"A".repeat(64)));
        assert!(!is_sha256_hex("abc"));
    }
}
