//! `GET /fleet` - the fleet pane: one page that answers "is anything broken", per listener.
//!
//! Session-gated (mounted under the `protected` group in `routes::mod`).
//!
//! WHY IT EXISTS. The dashboard's pipeline-health cell is the only honest health signal shipped
//! before this: `max(observed_at)` across the WHOLE ledger, rendered as fresh or not. That is
//! fleet-wide by construction, so one busy sensor masks twelve silent ones, and it says nothing at
//! all about a sensor unit that was never enabled after a deploy. `/ready` knows only the
//! subsystems this process supervises, and the daemon does not launch the sensors. `/metrics` has
//! no per-listener series. Between them, the single most common failure on this box - a listener
//! that stopped answering - was invisible.
//!
//! **The inventory is the row set, not the ledger.** Rows are built by walking the configured
//! listeners and joining the ledger onto them, never the other way round: a listener with no
//! events must appear, saying `none in 30d`, because "produced nothing" is exactly the state worth
//! seeing. A listener present in the ledger but absent from the inventory gets its own row flagged
//! `undeclared listener`, which catches the inventory drifting after a port was added on the box
//! but not at the control plane.
//!
//! **A listener is `(sensor, transport, port)` on both sides.** The ledger's side is
//! `event.sensor`, `event.protocol` and the `metadata.local_port` the sensor framework stamps on
//! every event (`sensor_framework::arrival`). Events from before that stamp existed are given to
//! their sensor's listener when it declares exactly one, and otherwise shown on one `port not
//! recorded` row per sensor rather than guessed onto a port. Activity is read from two ranges on
//! `observed_at` (the last 24 hours, and the 30 days before), never the whole ledger.
//!
//! **Every panel soft-fails; nothing here returns a 503.** On this page a hard error would hide
//! the very failure the operator came to see, and a query error rendering as "0" would be worse
//! still - it would read as good news. Each panel goes through `Degraded`, and the failed panel
//! names are rendered in the standard `.degraded` banner. The banner is rendered by the FRAGMENT
//! rather than by `base.html`'s chrome, so the 30-second refresh keeps it current instead of
//! freezing whatever was true when the page first loaded.
//!
//! **Reachability is what the prober found, with its vantage point named.** A listener the prober
//! has not reached yet reads `never probed` in unknown styling rather than being left blank, and on
//! a single box - control plane and collector on the same host - the connect is a HAIRPIN that
//! never leaves the machine. The prober detects that at the socket level and stores it as the row's
//! detail, which is rendered next to the verdict, so nothing here presents a same-host connect as
//! evidence that anything outside can reach the listener.

use std::collections::{HashMap, HashSet};
use std::path::Path;

use axum::extract::State;
use axum::response::Html;
use axum::routing::get;
use axum::{Extension, Router};
use chrono::{DateTime, Utc};
use fleet::health::{Level, combine, event_age_level, headline, reach_level};
use minijinja::context;
use serde::Serialize;
use sqlx::{PgPool, Row};

use crate::AppState;
use crate::auth::Session;
use crate::routes::context::{BaseContext, base_context};
use crate::routes::degraded::Degraded;
use crate::routes::error::AppError;
use crate::routes::feed::read_manifest;
use crate::routes::format::{format_relative_time, format_sensor_label, format_timestamp};
use crate::routes::rowcount::{Count, capped_total};

/// How far back the capture-completeness panel looks. Long enough that a low-traffic sensor still
/// has a denominator, short enough that a fix made this week is visible in the rate.
const CAPTURE_WINDOW_DAYS: &str = "7 days";

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/fleet", get(fleet_page))
        .route("/fleet/status", get(fleet_status_fragment))
}

/// One listener: what we were told exists, what the ledger has seen from it, and what the probe
/// found. Every state is carried as a WORD as well as a colour class, so nothing on this page is
/// legible only to someone who can distinguish red from green.
#[derive(Debug, Serialize)]
struct ListenerRow {
    collector: String,
    sensor: String,
    sensor_label: String,
    protocol: String,
    port: String,
    /// Where the probe dialled, with its vantage point named. Empty until a probe has run: the
    /// hairpin on a single box is not external reachability and the page must not imply it is.
    vantage: String,
    reach: String,
    reach_level: &'static str,
    reach_dot: &'static str,
    reach_detail: Option<String>,
    probe_ago: String,
    confirmed_ago: Option<String>,
    last_event_ago: String,
    last_event_dot: &'static str,
    /// "behind: 6.6 GB / 11 d" while the intake log carrying this sensor's events is behind, and
    /// `None` otherwise. It sits under LAST EVENT because a backlog is what makes that column lie:
    /// the sensor is busy, and its events are still waiting in the log.
    behind: Option<String>,
    events_24h: i64,
    state_level: &'static str,
    /// False for a sensor seen in the ledger that the inventory does not know about.
    declared: bool,
}

/// The badge text for every `event.sensor` name a behind intake log carried. A log whose state is
/// not behind contributes nothing, so a caught-up or idle sensor shows no badge.
fn behind_by_sensor(logs: &[crate::intake_lag::IntakeLag]) -> HashMap<String, String> {
    let mut out = HashMap::new();
    for log in logs.iter().filter(|l| l.behind) {
        let text = format!(
            "behind: {}",
            crate::intake_lag::format_backlog(log.bytes_behind, log.oldest_unread_age)
        );
        for sensor in &log.sensors {
            out.entry(sensor.clone()).or_insert_with(|| text.clone());
        }
    }
    out
}

/// Capture completeness for one sensor over the recent window.
#[derive(Debug, Serialize)]
struct CaptureRow {
    sensor: String,
    sensor_label: String,
    captures: i64,
    complete: i64,
    incomplete: i64,
    unlabelled: i64,
    truncated: i64,
    /// `None` when every capture in the window is unlabelled, so there is no honest denominator.
    rate_pct: Option<i64>,
    top_end_reason: Option<String>,
    top_end_reason_count: i64,
    /// True when the end-reason query itself failed, so `top_end_reason` being `None` says nothing
    /// about this sensor. Without it a row with incomplete captures renders as "nothing
    /// incomplete" the moment that one query errors - the cell contradicting the count beside it.
    end_reason_unavailable: bool,
    /// Pill colour for `top_end_reason`, matching this row's own completion-rate severity - the
    /// dominant reason for an alarm-level row alarms too, rather than every reason reading as the
    /// same amber regardless of how bad the rate actually is.
    end_reason_sev: &'static str,
    state_level: &'static str,
    meter_class: &'static str,
}

#[derive(Debug, Serialize)]
struct FeedFreshness {
    build_time: Option<String>,
    build_ago: Option<String>,
    expires_in: Option<String>,
    entries: i64,
    disabled: bool,
    note: &'static str,
    dot: &'static str,
}

#[derive(Debug, Serialize)]
struct LedgerStatus {
    events: Option<i64>,
    /// `events` is the planner's estimate, not a count: the ledger is past the counting cap.
    events_estimate: bool,
    newest_ingested_ago: Option<String>,
    dot: &'static str,
}

#[derive(Debug, Serialize)]
struct VersionStatus {
    running_version: String,
    /// The revision this PROCESS was built from, which is not the same question as what is
    /// checked out on the box. `unknown` when the build could not identify itself.
    running_sha: String,
    built_at: String,
    /// Which executable this page is being served by, so the panel names whose installed revision
    /// it is reporting rather than leaving the reader to assume.
    binary_name: String,
    /// The revision of the file the last deploy actually left on disk for THIS binary, read back
    /// from it by `deploy/deploy-stamp.sh`. `None` for a stamp written before that field existed,
    /// for a binary that was not installed, or for a recorded value that is not a revision - all
    /// of which the panel renders as not recorded, never as agreement.
    installed_sha: Option<String>,
    stamp_head_sha: Option<String>,
    stamp_origin_main_sha: Option<String>,
    stamp_age: Option<String>,
    verdict: &'static str,
    /// Pill colour for `verdict`, and the panel's only rendering of its `Level`: neutral grey for
    /// `current`, amber for `not recorded`, attention amber-orange for `restart required` /
    /// `behind main`, red for `install incomplete`.
    verdict_sev: &'static str,
    note: &'static str,
}

#[derive(Debug, Serialize)]
struct FleetSummary {
    total: usize,
    proven: usize,
    alarm: usize,
    unknown: usize,
    headline: &'static str,
    headline_level: &'static str,
}

/// The existing dot classes, chosen so the page introduces no new colour and no new component.
///
/// `Ok` is deliberately the plain grey dot. The console's design thesis is temperature equals
/// attention: warmth is spent only on what wants the operator, and a grey row is a fine row.
/// Painting healthy listeners green would put a wall of colour on the calm case and leave nothing
/// left to spend on the one row that matters.
fn dot_class(level: Level) -> &'static str {
    match level {
        Level::Ok => "dot dot--low",
        Level::Warn => "dot dot--high",
        Level::Alarm => "dot dot--crit",
        Level::Unknown => "dot dot--watch",
    }
}

/// The `.sev` pill classes, mapped from `Level` with the same colour semantics as `dot_class`
/// above (`Ok`->low/grey, `Warn`->high/amber, `Alarm`->crit/red, `Unknown`->watch/amber-adjacent).
/// A word-carrying panel (the version verdict, a capture's dominant end reason) uses this instead
/// of a bare dot so the state reads without relying on colour alone.
fn sev_class(level: Level) -> &'static str {
    match level {
        Level::Ok => "sev sev--low",
        Level::Warn => "sev sev--high",
        Level::Alarm => "sev sev--crit",
        Level::Unknown => "sev sev--watch",
    }
}

/// How far back the LAST EVENT column looks. The ledger is never scanned whole on a page load: a
/// listener whose newest event is older than this reads `none in 30d`, which is true whether it
/// went quiet a month ago or never produced anything. `ACTIVITY_LOOKBACK_LABEL` is the same window
/// in the page's words; the two are kept side by side so they cannot describe different windows.
const ACTIVITY_LOOKBACK: &str = "30 days";
const ACTIVITY_LOOKBACK_LABEL: &str = "none in 30d";

/// One listener as the ledger names it: the sensor's OWN reported name (`event.sensor`, which is
/// what the inventory is keyed on too - see `fleet::inventory`'s note on why the
/// `PROPOLIS_SENSOR_LOGS` label is the wrong key), the transport (`event.protocol`), and the port
/// the framework stamped as `metadata.local_port`. `None` for an event written before sensors
/// recorded their port.
type ActivityKey = (String, String, Option<u16>);

/// Ledger activity for one [`ActivityKey`] within the lookback.
#[derive(Debug, Default, Clone, Copy, PartialEq)]
struct Activity {
    last_event_at: Option<DateTime<Utc>>,
    events_24h: i64,
}

impl Activity {
    fn merge(&mut self, other: Activity) {
        self.last_event_at = self.last_event_at.max(other.last_event_at);
        self.events_24h += other.events_24h;
    }
}

/// Per-listener activity from two range-bounded reads, neither of which touches the ledger
/// outside the lookback: the last 24 hours (the count and the newest event), then the rest of the
/// lookback (the newest event only, for listeners quiet today). Both are ranges on `observed_at`,
/// which `event_observed_at_idx` serves.
///
/// The two statements see different `now()`s, a few milliseconds apart. That can only make an
/// event fall in both ranges, never in neither, and the second read contributes nothing but a
/// `max`, so the overlap changes no number.
async fn listener_activity(db: &PgPool) -> Result<HashMap<ActivityKey, Activity>, sqlx::Error> {
    let recent = sqlx::query(
        "SELECT sensor, protocol::text AS protocol, metadata->>'local_port' AS local_port, \
                count(*) AS events_24h, max(observed_at) AS last_event_at \
         FROM event \
         WHERE observed_at >= now() - interval '24 hours' \
         GROUP BY 1, 2, 3",
    )
    .fetch_all(db)
    .await?;
    // Audited: interpolates only the `ACTIVITY_LOOKBACK` constant, never user input.
    let earlier = sqlx::query(sqlx::AssertSqlSafe(format!(
        "SELECT sensor, protocol::text AS protocol, metadata->>'local_port' AS local_port, \
                0::bigint AS events_24h, max(observed_at) AS last_event_at \
         FROM event \
         WHERE observed_at >= now() - interval '{ACTIVITY_LOOKBACK}' \
           AND observed_at < now() - interval '24 hours' \
         GROUP BY 1, 2, 3"
    )))
    .fetch_all(db)
    .await?;

    let mut out: HashMap<ActivityKey, Activity> = HashMap::new();
    for row in recent.iter().chain(earlier.iter()) {
        // A value that is not a port number (absent, or written by something other than the
        // framework) cannot name a listener, so it is filed with the unrecorded ones rather than
        // dropped: the events still happened and still count.
        let port = row
            .try_get::<Option<String>, _>("local_port")?
            .and_then(|p| p.parse::<u16>().ok());
        let key = (row.try_get("sensor")?, row.try_get("protocol")?, port);
        out.entry(key).or_default().merge(Activity {
            last_event_at: row.try_get("last_event_at")?,
            events_24h: row.try_get("events_24h")?,
        });
    }
    Ok(out)
}

/// The ledger's activity, attributed to listener rows.
#[derive(Debug, Default, PartialEq)]
struct Attributed {
    /// Keyed by `(sensor, protocol, port)`, declared or not.
    by_listener: HashMap<(String, String, u16), Activity>,
    /// Events with no recorded port from a sensor that does not have exactly one declared
    /// listener, so they cannot be given to one. One entry per sensor.
    unrecorded: HashMap<String, Activity>,
}

/// Attribute each key's activity to a listener. An event with no recorded port goes to its
/// sensor's listener when the inventory declares exactly one (every pre-upgrade event of a
/// single-port sensor came in on that port, whatever transport it names); otherwise it is kept
/// apart, per sensor, rather than guessed onto one of several ports. Two collectors declaring the
/// same `(protocol, port)` for a sensor are one listener here, since the ledger does not record
/// which collector an event came from.
fn attribute(
    activity: HashMap<ActivityKey, Activity>,
    inventory: &[fleet::Listener],
) -> Attributed {
    let mut declared: HashMap<&str, HashSet<(&'static str, u16)>> = HashMap::new();
    for l in inventory {
        declared
            .entry(l.sensor.as_str())
            .or_default()
            .insert((l.protocol.as_str(), l.port));
    }
    let mut out = Attributed::default();
    for ((sensor, protocol, port), seen) in activity {
        let key = match port {
            Some(port) => (sensor, protocol, port),
            None => match declared.get(sensor.as_str()) {
                Some(only) if only.len() == 1 => {
                    let &(protocol, port) = only.iter().next().expect("one element");
                    (sensor, protocol.to_string(), port)
                }
                _ => {
                    out.unrecorded.entry(sensor).or_default().merge(seen);
                    continue;
                }
            },
        };
        out.by_listener.entry(key).or_default().merge(seen);
    }
    out
}

/// The ledger panel's two facts without scanning the ledger: how many events (counted up to the
/// cap, then the planner's estimate, flagged as one) and when the newest was ingested. `count(*)`
/// and `max(ingested_at)` each read every row of a table that only grows, on a panel that polls;
/// the newest ingest is read off the newest row by `id` (the primary key, assigned in append
/// order under the chain lock), which is the newest ingest.
async fn ledger_head(db: &PgPool) -> Result<(Count, Option<DateTime<Utc>>), sqlx::Error> {
    let count = capped_total(db, "event").await?;
    let newest: Option<DateTime<Utc>> =
        sqlx::query_scalar("SELECT ingested_at FROM event ORDER BY id DESC LIMIT 1")
            .fetch_optional(db)
            .await?;
    Ok((count, newest))
}

/// The LAST EVENT cell's words.
fn last_event_text(last_event_at: Option<DateTime<Utc>>) -> String {
    last_event_at
        .map(format_relative_time)
        .unwrap_or_else(|| ACTIVITY_LOOKBACK_LABEL.to_string())
}

/// Capture completeness per sensor.
///
/// Two deliberate departures from `routes::detail`'s malware query, each wrong for the other's
/// purpose:
///
/// 1. `detail.rs` uses `coalesce((metadata->>'complete')::boolean, true)`, reading a MISSING
///    `complete` key as complete. That is right there (captures recorded before the field existed,
///    and protocols whose completeness the sensor cannot judge) and wrong for a RATE, which it
///    would flatter. Here `unlabelled` is its own column and the rate excludes it from the
///    denominator, with the page stating how many were excluded.
/// 2. `metadata->'complete' = 'true'::jsonb` is a jsonb comparison rather than a `::boolean` cast,
///    so a malformed value can never raise inside the aggregate and take the panel down.
async fn capture_rows(db: &PgPool) -> Result<Vec<CaptureRow>, sqlx::Error> {
    // Audited: interpolates only the `CAPTURE_WINDOW_DAYS` constant, never user input. It is a
    // constant rather than two literals so this query and `top_end_reasons` cannot come to
    // describe two different windows while the page presents them as one reading.
    let rows = sqlx::query(sqlx::AssertSqlSafe(format!(
        "SELECT sensor, \
                count(*) AS captures, \
                count(*) FILTER (WHERE metadata->'complete' = 'true'::jsonb) AS complete, \
                count(*) FILTER (WHERE metadata->'complete' = 'false'::jsonb) AS incomplete, \
                count(*) FILTER (WHERE metadata->'complete' IS NULL) AS unlabelled, \
                count(*) FILTER (WHERE metadata->'truncated' = 'true'::jsonb) AS truncated \
         FROM event \
         WHERE signal_type = 'honeypot_malware_upload' \
           AND observed_at >= now() - interval '{CAPTURE_WINDOW_DAYS}' \
         GROUP BY sensor ORDER BY sensor"
    )))
    .fetch_all(db)
    .await?;

    let mut out = Vec::with_capacity(rows.len());
    for row in rows {
        let sensor: String = row.try_get("sensor")?;
        let captures: i64 = row.try_get("captures")?;
        let complete: i64 = row.try_get("complete")?;
        let unlabelled: i64 = row.try_get("unlabelled")?;
        let denominator = captures - unlabelled;
        let rate_pct = (denominator > 0).then(|| complete * 100 / denominator);
        let (state_level, meter_class) = match rate_pct {
            None => (Level::Unknown, "meter-fill"),
            Some(p) if p >= 90 => (Level::Ok, "meter-fill"),
            Some(p) if p >= 70 => (Level::Warn, "meter-fill meter-fill--warn"),
            Some(p) if p >= 40 => (Level::Warn, "meter-fill meter-fill--high"),
            Some(_) => (Level::Alarm, "meter-fill meter-fill--crit"),
        };
        out.push(CaptureRow {
            sensor_label: format_sensor_label(&sensor),
            sensor,
            captures,
            complete,
            incomplete: row.try_get("incomplete")?,
            unlabelled,
            truncated: row.try_get("truncated")?,
            rate_pct,
            top_end_reason: None,
            top_end_reason_count: 0,
            // Set by the caller once the end-reason query has been attempted.
            end_reason_unavailable: false,
            end_reason_sev: sev_class(state_level),
            state_level: state_level.class(),
            meter_class,
        });
    }
    Ok(out)
}

/// The dominant reason captures did NOT finish, per sensor. A rate alone says a sensor is losing
/// samples; this says why, and `capture_budget` or `idle_timeout` dominating points straight at a
/// bound set too low rather than at a flaky attacker.
async fn top_end_reasons(db: &PgPool) -> Result<HashMap<String, (String, i64)>, sqlx::Error> {
    // Audited: interpolates only the `CAPTURE_WINDOW_DAYS` constant, never user input.
    let rows = sqlx::query(sqlx::AssertSqlSafe(format!(
        "SELECT sensor, \
                coalesce(metadata->>'end_reason', 'unrecorded') AS end_reason, \
                count(*) AS n \
         FROM event \
         WHERE signal_type = 'honeypot_malware_upload' \
           AND observed_at >= now() - interval '{CAPTURE_WINDOW_DAYS}' \
           AND metadata->'complete' IS DISTINCT FROM 'true'::jsonb \
         GROUP BY sensor, coalesce(metadata->>'end_reason', 'unrecorded') \
         ORDER BY sensor, n DESC"
    )))
    .fetch_all(db)
    .await?;

    let mut out: HashMap<String, (String, i64)> = HashMap::new();
    for row in rows {
        let sensor: String = row.try_get("sensor")?;
        // Ordered by count descending within each sensor, so the first row per sensor wins.
        if out.contains_key(&sensor) {
            continue;
        }
        let reason: String = row.try_get("end_reason")?;
        out.insert(sensor, (reason.replace('_', " "), row.try_get("n")?));
    }
    Ok(out)
}

/// The deploy stamp `deploy/upgrade.sh` will write, read defensively: a missing, unreadable, or
/// malformed file is `None` and the panel says "not recorded", never "current".
fn read_stamp(path: &Path) -> Option<serde_json::Value> {
    let bytes = std::fs::read(path).ok()?;
    serde_json::from_slice(&bytes).ok()
}

/// The git commit id format both producers of these strings use: hex digits only, at least as
/// long as git's traditional default abbreviation. A shorter or non-hex string is not a revision
/// this function can compare against anything - it is malformed stamp data, not a mismatch, and
/// blaming it on "restart required" or "behind main" would point the operator at the wrong fix.
fn looks_like_git_sha(s: &str) -> bool {
    s.len() >= 7 && s.chars().all(|c| c.is_ascii_hexdigit())
}

/// The version verdict, as a pure function of the identities involved.
///
/// FOUR different things get confused here and the panel exists to keep them apart: what this
/// PROCESS is running, what the last deploy actually INSTALLED on disk for this binary, what was
/// CHECKED OUT when that deploy built, and what `origin/main` held when that deploy last fetched.
/// A deploy that built and installed new binaries without restarting the service leaves the first
/// two apart; an install that did not finish leaves the second and third apart. Those two failures
/// want opposite responses, and neither is visible anywhere else on the box.
///
/// Every uncertain case lands on `not recorded`, never on `current`. The failure this guards is a
/// panel that says the box is up to date because it could not tell that it was not.
///
/// `installed` is what separates a not-yet-restarted process from an install that failed partway
/// through and left the old binary in place while the stamp still names the new commit. Without it
/// (a stamp written before that field existed, or a binary this box does not install) a mismatch is
/// still reported, but as an observed fact with both explanations named, never as a diagnosis -
/// and an AGREEMENT is not reported as `current` at all. `current` is a claim about the file on
/// disk as much as about this process, and an absent, empty, dirty or malformed installed identity
/// means that file was never observed. Three identities agreeing is not the fourth one agreeing,
/// so the missing observation reads `not recorded`.
///
/// Every note below is bound to the DEPLOY STAMP's own observation, not to now: `stamp_origin` is
/// whatever `origin/main` looked like at the last fetch a deploy happened to make
/// (`deploy-stamp.sh`'s own header), never a live query, so "behind main" and "current" both
/// describe a moment in the past, not a live comparison - the page renders `stamp_age` next to
/// these words for exactly that reason, and the wording here must not read as more current than
/// that age admits.
fn version_verdict(
    running_sha: &str,
    installed: Option<&str>,
    stamp_head: Option<&str>,
    stamp_origin: Option<&str>,
) -> (&'static str, Level, &'static str) {
    // A build from a modified working tree matches no commit, so no comparison against the stamp
    // means anything. Same for a build that could not run git at all.
    if running_sha == "unknown" || running_sha.contains("+dirty") {
        return (
            "not recorded",
            Level::Unknown,
            "this binary does not name a clean commit, so it cannot be compared with the deploy \
             stamp",
        );
    }
    let Some(head) = stamp_head else {
        return (
            "not recorded",
            Level::Unknown,
            "no deploy stamp was found, so there is nothing to compare the running binary with",
        );
    };
    if !looks_like_git_sha(head) {
        return (
            "not recorded",
            Level::Unknown,
            "the deploy stamp's recorded commit id is not a valid revision, so it cannot be \
             compared",
        );
    }
    // A recorded install identity is usable only when it names a clean revision: `+dirty` describes
    // bytes no commit describes, and anything else is stamp damage. Either way this falls back to
    // the two-way comparison below rather than being compared as though it were a real revision.
    // The raw presence is kept because the two cases want different words: a stamp that recorded
    // nothing for this binary versus one that recorded something unusable.
    let installed_recorded = installed.is_some();
    let installed = installed.filter(|s| looks_like_git_sha(s));

    // Checked before the running process, because it decides what a mismatch MEANS. An install
    // that did not land is not a restart away from being fixed, and reporting it as one sends the
    // operator to `systemctl restart` instead of to the deploy log.
    if let Some(installed) = installed
        && !head.starts_with(installed)
    {
        return (
            "install incomplete",
            Level::Alarm,
            "the binary this deploy left on disk is not the commit it recorded building, so the \
             install did not replace it; restarting would not load that commit",
        );
    }

    // The stamp carries the full 40-character id and the binary a short prefix of it, so a prefix
    // match is the comparison, not equality.
    if !head.starts_with(running_sha) {
        if installed.is_some() {
            return (
                "restart required",
                Level::Warn,
                "the commit this deploy recorded is the one on disk, and this process is not \
                 running it, so it keeps serving the previous build until the service restarts",
            );
        }
        return (
            "restart required",
            Level::Warn,
            "the running process's build does not match the commit the deploy stamp recorded as \
             built; that stamp does not record which binary was installed, so this does not say \
             whether the process merely has not been restarted yet or the install itself did not \
             finish - a restart is not guaranteed to resolve it",
        );
    }
    let Some(origin) = stamp_origin else {
        return (
            "not recorded",
            Level::Unknown,
            "the deploy stamp names no origin/main revision, so it cannot say whether this box \
             was behind as of that deploy",
        );
    };
    if !looks_like_git_sha(origin) {
        return (
            "not recorded",
            Level::Unknown,
            "the deploy stamp's recorded origin/main commit id is not a valid revision, so it \
             cannot be compared",
        );
    }
    if origin != head {
        return (
            "behind main",
            Level::Warn,
            "as of the last deploy's fetch, main had already moved past the commit this box \
             deployed; main may have moved further since",
        );
    }
    // Everything comparable agrees, which is three of the four identities. `current` also asserts
    // the fourth - that the file this deploy left on disk is that commit - and only a usable
    // installed identity observes it. Without one, the install is unobserved, not confirmed: a box
    // whose install silently no-opped looks exactly like this until it restarts, which is the
    // moment the pane would have been most wrong to have said `current`.
    if installed.is_none() {
        return (
            "not recorded",
            Level::Unknown,
            if installed_recorded {
                "the running process matches the deployed checkout, but the revision this deploy \
                 stamp recorded for the binary on disk is not a clean commit id, so what an \
                 install actually left there was never observed"
            } else {
                "the running process matches the deployed checkout, but this deploy stamp records \
                 no revision for the binary on disk, so what an install actually left there was \
                 never observed; redeploying writes that identity"
            },
        );
    }

    (
        "current",
        Level::Ok,
        "as of the last deploy, the running binary, the binary installed on disk, the deployed \
         checkout and the fetched main were the same commit",
    )
}

fn version_status(state: &AppState) -> VersionStatus {
    let stamp = state.deploy_stamp_path.as_deref().and_then(read_stamp);
    let field = |key: &str| -> Option<String> {
        stamp
            .as_ref()
            .and_then(|v| v.get(key))
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty())
            .map(str::to_string)
    };
    let stamp_head_sha = field("head_sha");
    let stamp_origin_main_sha = field("origin_main_sha");
    // Keyed by the executable actually serving this page: the stamp records one entry per
    // installed binary (`deploy/deploy-stamp.sh`), and the other one's revision would say nothing
    // about this process. A stamp predating that field has no `installed` object at all, which
    // lands here as `None` and reads as not recorded.
    let installed_sha = stamp
        .as_ref()
        .and_then(|v| v.get("installed"))
        .and_then(|v| v.get(state.binary_name))
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .map(str::to_string);
    let stamp_age = field("built_at")
        .or_else(|| field("pulled_at"))
        .and_then(|t| DateTime::parse_from_rfc3339(&t).ok())
        .map(|t| format_relative_time(t.with_timezone(&Utc)));

    let (verdict, level, note) = version_verdict(
        state.git_sha,
        installed_sha.as_deref(),
        stamp_head_sha.as_deref(),
        stamp_origin_main_sha.as_deref(),
    );

    VersionStatus {
        running_version: state.version.to_string(),
        running_sha: state.git_sha.to_string(),
        built_at: state.built_at.to_string(),
        binary_name: state.binary_name.to_string(),
        installed_sha,
        stamp_head_sha,
        stamp_origin_main_sha,
        stamp_age,
        verdict,
        verdict_sev: sev_class(level),
        note,
    }
}

fn feed_freshness(state: &AppState) -> FeedFreshness {
    if state.feed_output_dir.is_none() {
        return FeedFreshness {
            build_time: None,
            build_ago: None,
            expires_in: None,
            entries: 0,
            disabled: true,
            note: "builder disabled on this node",
            dot: dot_class(Level::Unknown),
        };
    }
    let Some(manifest) = state.feed_output_dir.as_deref().and_then(read_manifest) else {
        return FeedFreshness {
            build_time: None,
            build_ago: None,
            expires_in: None,
            entries: 0,
            disabled: false,
            note: "feed enabled, awaiting first build",
            dot: dot_class(Level::Unknown),
        };
    };

    let now = Utc::now();
    let built = DateTime::parse_from_rfc3339(&manifest.build_time)
        .ok()
        .map(|t| t.with_timezone(&Utc));
    // Staleness is decided against the expiry the build itself published, not against a threshold
    // this page invents: the build is the authority on how long its own output is good for.
    let valid_until = DateTime::parse_from_rfc3339(&manifest.tiers.standard.valid_until)
        .ok()
        .map(|t| t.with_timezone(&Utc));
    let (expires_in, level, note) = match valid_until {
        // Beside the "Expires in" label: a past expiry reads "expired 5m ago", never "Expires in
        // 5m ago".
        Some(until) if until <= now => (
            Some(format!("expired {}", format_relative_time(until))),
            Level::Alarm,
            "the published feed has expired",
        ),
        Some(until) => (
            Some(format!("{}h", (until - now).num_hours().max(0))),
            Level::Ok,
            "published and current",
        ),
        None => (None, Level::Unknown, "the manifest carries no expiry"),
    };

    FeedFreshness {
        build_time: built.map(format_timestamp),
        build_ago: built.map(format_relative_time),
        expires_in,
        entries: (manifest.tiers.aggressive.count + manifest.tiers.standard.count) as i64,
        disabled: false,
        note,
        dot: dot_class(level),
    }
}

/// Everything the page and the fragment both render. Built once so the two can never drift into
/// two different readings of the same fleet.
struct FleetView {
    summary: FleetSummary,
    listeners: Vec<ListenerRow>,
    captures: Vec<CaptureRow>,
    feed: FeedFreshness,
    ledger: LedgerStatus,
    version: VersionStatus,
    last_event_ago: String,
    last_event_level: &'static str,
    /// Whether the capture query FAILED, as opposed to returning nothing. The two produce the same
    /// empty `captures` list and must not produce the same sentence: "no malware captures in the
    /// last 7 days" is a finding about the fleet, and printing it because a query errored tells
    /// the operator something the console does not know. The degraded banner names the panel, but
    /// a reader who takes the panel's own words at face value is reading a fabricated all-clear.
    captures_unavailable: bool,
    /// Same distinction for the event ledger: a failed count is not a count of zero.
    ledger_unavailable: bool,
    degraded: Vec<&'static str>,
}

async fn build_view(state: &AppState, mut degraded: Degraded) -> FleetView {
    let now = Utc::now();
    // The staleness rules are measured in sweep intervals, so they follow the prober's configured
    // cadence rather than a constant here: with a constant, an operator who slowed the sweep down
    // would get a page on which every row read stale, and one who sped it up would keep a rule
    // looser than the evidence allows.
    let probe_interval = state.fleet_probe_interval;
    let behind = behind_by_sensor(&(state.intake_lag)());

    let probe_rows = degraded.soft("listener probes", fleet::store::read_all(&state.db).await);
    let probes: HashMap<(String, String, String, u16), fleet::ProbeRow> = probe_rows
        .into_iter()
        .map(|r| {
            (
                (
                    r.listener.collector_id.clone(),
                    r.listener.sensor.clone(),
                    r.listener.protocol.as_str().to_string(),
                    r.listener.port,
                ),
                r,
            )
        })
        .collect();

    let activity = attribute(
        degraded.soft("listener activity", listener_activity(&state.db).await),
        &state.fleet_listeners,
    );

    let mut listeners = Vec::with_capacity(state.fleet_listeners.len());
    let mut levels = Vec::with_capacity(state.fleet_listeners.len());
    // Kept apart from `levels` so the headline can say WHICH check is unhappy. Folding them
    // together first loses that, and the sentence then guesses - see `fleet::health::headline`.
    let mut reach_levels = Vec::with_capacity(state.fleet_listeners.len());
    let mut event_levels = Vec::with_capacity(state.fleet_listeners.len());
    let mut proven = 0usize;
    let mut alarm = 0usize;
    let mut unknown = 0usize;

    for listener in state.fleet_listeners.iter() {
        let key = (
            listener.collector_id.clone(),
            listener.sensor.clone(),
            listener.protocol.as_str().to_string(),
            listener.port,
        );
        let probe = probes.get(&key);
        let reach = reach_level(probe, now, probe_interval);
        // A row too old to trust must SAY it is stale. Showing its last recorded outcome alone
        // would put the word "reachable" on a listener nothing has checked since the prober died,
        // which is the exact failure the staleness rule exists to catch.
        let stale = probe.is_some_and(|p| {
            now - p.attempted_at
                > chrono::Duration::from_std(probe_interval.saturating_mul(2)).unwrap_or_default()
        });
        // A warning on this column has a specific meaning the outcome word alone does not carry:
        // the socket answered and the line it produced never arrived at the far end. That is the
        // most useful thing this page can say, because it puts the break in the log, logrotate,
        // shipper, gateway or intake path and takes the sensor itself off the list. Whatever the
        // prober recorded (the hairpin note, the refusal reason) is kept alongside it.
        let mut detail_parts: Vec<String> = Vec::new();
        if reach == Level::Warn
            && probe.is_some_and(|p| p.outcome == fleet::ProbeOutcome::Reachable)
        {
            detail_parts.push("socket answered, no line reached intake".to_string());
        }
        if let Some(recorded) = probe.and_then(|p| p.detail.as_ref()) {
            detail_parts.push(recorded.clone());
        }
        let reach_detail = (!detail_parts.is_empty()).then(|| detail_parts.join("; "));

        let seen = activity.by_listener.get(&(
            listener.sensor.clone(),
            listener.protocol.as_str().to_string(),
            listener.port,
        ));
        let last_event_at = seen.and_then(|a| a.last_event_at);
        let event_level = event_age_level(last_event_at, now);
        let state_level = combine(&[reach, event_level]);

        if reach == Level::Ok {
            proven += 1;
        }
        match state_level {
            Level::Alarm => alarm += 1,
            Level::Unknown => unknown += 1,
            _ => {}
        }
        levels.push(state_level);
        reach_levels.push(reach);
        event_levels.push(event_level);

        listeners.push(ListenerRow {
            collector: listener.collector_id.clone(),
            sensor: listener.sensor.clone(),
            sensor_label: format_sensor_label(&listener.sensor),
            protocol: listener.protocol.as_str().to_string(),
            port: listener.port.to_string(),
            vantage: probe
                .map(|p| format!("control plane to {}", p.target))
                .unwrap_or_default(),
            reach: match probe {
                None => "never probed".to_string(),
                Some(p) if stale => format!("stale, last {}", p.outcome.label()),
                Some(p) => p.outcome.label().to_string(),
            },
            reach_level: reach.class(),
            reach_dot: dot_class(reach),
            reach_detail,
            probe_ago: probe
                .map(|p| format_relative_time(p.attempted_at))
                .unwrap_or_else(|| "never".to_string()),
            confirmed_ago: probe.and_then(|p| p.confirmed_at).map(format_relative_time),
            last_event_ago: last_event_text(last_event_at),
            last_event_dot: dot_class(event_level),
            behind: behind.get(&listener.sensor).cloned(),
            events_24h: seen.map(|a| a.events_24h).unwrap_or(0),
            state_level: state_level.class(),
            declared: true,
        });
    }

    let declared_sensors: HashSet<&str> = state
        .fleet_listeners
        .iter()
        .map(|l| l.sensor.as_str())
        .collect();

    // Events with no recorded port, from a sensor the inventory declares several listeners for.
    // They cannot be given to any one of those rows, and dropping them would make the page's
    // numbers quietly smaller than the ledger's, so they get one row per sensor that says so. It
    // is not a listener: it counts toward no total and no headline, and its dots stay neutral,
    // because nothing about it wants the operator. It disappears once that history is older than
    // the lookback.
    let mut unrecorded: Vec<(&String, &Activity)> = activity
        .unrecorded
        .iter()
        .filter(|(sensor, _)| declared_sensors.contains(sensor.as_str()))
        .collect();
    unrecorded.sort_by_key(|(sensor, _)| sensor.as_str());
    let mut unrecorded_rows = Vec::with_capacity(unrecorded.len());
    for (sensor, seen) in unrecorded {
        unrecorded_rows.push(ListenerRow {
            collector: "unknown".into(),
            sensor: sensor.clone(),
            sensor_label: format_sensor_label(sensor),
            protocol: "--".into(),
            port: "--".into(),
            vantage: String::new(),
            reach: "port not recorded".into(),
            reach_level: Level::Ok.class(),
            reach_dot: dot_class(Level::Ok),
            reach_detail: Some(
                "events recorded before sensors stamped their listener port, so they cannot be \
                 attributed to one of this sensor's listeners"
                    .into(),
            ),
            probe_ago: "--".into(),
            confirmed_ago: None,
            last_event_ago: last_event_text(seen.last_event_at),
            last_event_dot: dot_class(Level::Ok),
            // Old history, not a listener: the sensor's own rows carry its badge.
            behind: None,
            events_24h: seen.events_24h,
            state_level: Level::Ok.class(),
            declared: true,
        });
    }

    // A listener the ledger has seen but the inventory does not name: a port a declared sensor
    // was never declared on, or a sensor the inventory does not know at all (whose pre-upgrade
    // events have no port to show). The events are real, so the pane must show them, and it must
    // say plainly that the control plane was never told this listener exists rather than quietly
    // folding it in as if it had been.
    let declared_keys: HashSet<(&str, &str, u16)> = state
        .fleet_listeners
        .iter()
        .map(|l| (l.sensor.as_str(), l.protocol.as_str(), l.port))
        .collect();
    let mut undeclared: Vec<_> = activity
        .by_listener
        .iter()
        .filter(|((s, p, port), _)| !declared_keys.contains(&(s.as_str(), p.as_str(), *port)))
        .map(|((s, p, port), seen)| (s.as_str(), Some((p.as_str(), *port)), seen))
        .chain(
            activity
                .unrecorded
                .iter()
                .filter(|(sensor, _)| !declared_sensors.contains(sensor.as_str()))
                .map(|(sensor, seen)| (sensor.as_str(), None, seen)),
        )
        .collect();
    undeclared.sort_by_key(|&(sensor, listener, _)| (sensor, listener));
    for (sensor, listener, seen) in undeclared {
        let event_level = event_age_level(seen.last_event_at, now);
        unknown += 1;
        levels.push(Level::Unknown);
        // Nothing probed it, because it is not in the inventory: an unproven reach, not a quiet
        // one. The headline says "reachability unproven", which is exactly this row's problem.
        reach_levels.push(Level::Unknown);
        event_levels.push(event_level);
        listeners.push(ListenerRow {
            collector: "unknown".into(),
            sensor: sensor.to_string(),
            sensor_label: format_sensor_label(sensor),
            protocol: listener.map_or("--", |(p, _)| p).to_string(),
            port: listener.map_or("--".to_string(), |(_, port)| port.to_string()),
            vantage: String::new(),
            reach: "undeclared listener".into(),
            reach_level: Level::Unknown.class(),
            reach_dot: dot_class(Level::Unknown),
            reach_detail: Some(match listener {
                Some(_) => {
                    "this listener is producing events but is not in PROPOLIS_FLEET_LISTENERS"
                        .into()
                }
                None => "this sensor is producing events but is not in \
                         PROPOLIS_FLEET_LISTENERS; they were recorded before sensors stamped \
                         their listener port"
                    .into(),
            }),
            probe_ago: "never".into(),
            confirmed_ago: None,
            last_event_ago: last_event_text(seen.last_event_at),
            last_event_dot: dot_class(event_level),
            behind: behind.get(sensor).cloned(),
            events_24h: seen.events_24h,
            state_level: Level::Unknown.class(),
            declared: false,
        });
    }

    let capture_result = capture_rows(&state.db).await;
    let captures_unavailable = capture_result.is_err();
    let mut captures = degraded.soft("capture completeness", capture_result);
    let reason_result = top_end_reasons(&state.db).await;
    // Carried onto every row, because `soft` turns the failure into an empty map and an empty map
    // is indistinguishable from "this sensor has nothing incomplete". The completeness counts can
    // succeed while this query fails, and then a row showing incomplete captures has to say the
    // reason is unavailable rather than claim there is nothing to explain.
    let reasons_unavailable = reason_result.is_err();
    let reasons = degraded.soft("capture end reasons", reason_result);
    for row in &mut captures {
        row.end_reason_unavailable = reasons_unavailable;
        // Matched on the RAW sensor name, not the display label: two raw names can share a label
        // (`catchall` and `catchall-sensor` both render as "General"), and joining on the label
        // would attach one sensor's end reason to another's rate.
        if let Some((reason, n)) = reasons.get(&row.sensor) {
            row.top_end_reason = Some(reason.clone());
            row.top_end_reason_count = *n;
        }
    }

    let ledger_result = ledger_head(&state.db).await;
    let ledger_unavailable = ledger_result.is_err();
    let ledger_row = degraded.soft_or(
        "ledger head",
        ledger_result,
        (
            Count {
                value: 0,
                exact: true,
            },
            None,
        ),
    );
    let (ledger_count, ledger_newest) = ledger_row;
    let ledger_row = (ledger_count.value, ledger_newest);
    let ledger_level = match ledger_row.1 {
        // A failed query and an empty ledger are both `Unknown`, which is right - neither proves
        // health - but the WORDS beside the dot have to differ, hence `ledger_unavailable`.
        None => Level::Unknown,
        Some(t) if (now - t).num_minutes() < 60 => Level::Ok,
        Some(_) => Level::Warn,
    };
    let ledger = LedgerStatus {
        // `None` for a failed count: rendering the `0` placeholder as a number is the console
        // asserting an empty ledger it never managed to read.
        events: (!ledger_unavailable).then_some(ledger_row.0),
        events_estimate: !ledger_unavailable && !ledger_count.exact,
        newest_ingested_ago: ledger_row.1.map(format_relative_time),
        dot: dot_class(ledger_level),
    };

    // The band's "Last event" cell is the same fleet-wide number the dashboard shows, kept here so
    // the two pages cannot disagree; the per-listener column beside it is what this page adds.
    let overall_last_event = match (ledger_unavailable, ledger_row.1) {
        (true, _) => "unavailable".to_string(),
        (false, Some(t)) => format_relative_time(t),
        (false, None) => "never".to_string(),
    };

    // Counted before the unrecorded-port rows join the table: they are not listeners.
    let total = listeners.len();
    listeners.extend(unrecorded_rows);
    let headline_level = combine(&levels);
    // From the two checks separately, not from their combined severity: a fleet that is fully
    // probed and confirmed but has one quiet listener also combines to `Warn`, and describing that
    // as an unconfirmed evidence path contradicts the confirmations on the rows right below it.
    let headline = headline(combine(&reach_levels), combine(&event_levels));

    FleetView {
        summary: FleetSummary {
            total,
            proven,
            alarm,
            unknown,
            headline,
            headline_level: headline_level.class(),
        },
        listeners,
        captures,
        feed: feed_freshness(state),
        ledger,
        version: version_status(state),
        last_event_ago: overall_last_event,
        last_event_level: ledger_level.class(),
        captures_unavailable,
        ledger_unavailable,
        degraded: degraded.names(),
    }
}

fn render(
    state: &AppState,
    template: &str,
    view: &FleetView,
    page: minijinja::Value,
) -> Result<Html<String>, AppError> {
    let tmpl = state.templates.get_template(template)?;
    let ctx = context! {
        summary => &view.summary,
        listeners => &view.listeners,
        captures => &view.captures,
        feed => &view.feed,
        ledger => &view.ledger,
        version_status => &view.version,
        last_event_ago => &view.last_event_ago,
        last_event_level => view.last_event_level,
        captures_unavailable => view.captures_unavailable,
        ledger_unavailable => view.ledger_unavailable,
        // Deliberately NOT named `degraded`: `base.html` renders a banner from that name, and this
        // page's banner lives inside the refreshing fragment instead so it stays current.
        degraded_panels => &view.degraded,
        ..page
    };
    Ok(Html(tmpl.render(ctx)?))
}

async fn fleet_page(
    State(state): State<AppState>,
    Extension(session): Extension<Session>,
) -> Result<Html<String>, AppError> {
    let BaseContext {
        pending_count,
        uptime,
        version,
        degraded,
    } = base_context(&state.db, state.startup_time, state.version).await;
    let view = build_view(&state, degraded).await;
    let csrf_token = state
        .sessions
        .generate_csrf(&session.id)
        .unwrap_or_default();

    render(
        &state,
        "fleet.html",
        &view,
        context! {
            active_nav => "fleet",
            pending_count,
            uptime,
            version,
            csrf_token,
        },
    )
}

/// The same rows without the page chrome, for the 30-second HTMX refresh.
async fn fleet_status_fragment(
    State(state): State<AppState>,
    Extension(_session): Extension<Session>,
) -> Result<Html<String>, AppError> {
    let view = build_view(&state, Degraded::new()).await;
    render(&state, "fleet_status_fragment.html", &view, context! {})
}

#[cfg(test)]
mod tests {
    use super::*;

    fn inv(entries: &[(&str, &str, fleet::Proto, u16)]) -> Vec<fleet::Listener> {
        entries
            .iter()
            .map(|&(collector, sensor, protocol, port)| fleet::Listener {
                collector_id: collector.into(),
                sensor: sensor.into(),
                protocol,
                port,
            })
            .collect()
    }

    fn seen(events_24h: i64) -> Activity {
        Activity {
            last_event_at: Some(Utc::now()),
            events_24h,
        }
    }

    fn key(sensor: &str, protocol: &str, port: Option<u16>) -> ActivityKey {
        (sensor.into(), protocol.into(), port)
    }

    /// Unstamped history goes to the one listener a sensor declares, whatever transport it names:
    /// a pre-upgrade single-port sensor received every event there. Two collectors declaring the
    /// same listener are still one listener to the ledger, which records no collector.
    #[test]
    fn unstamped_events_join_the_only_declared_listener() {
        let inventory = inv(&[
            ("a", "ssh", fleet::Proto::Tcp, 22),
            ("b", "ssh", fleet::Proto::Tcp, 22),
        ]);
        let activity = HashMap::from([
            (key("ssh", "tcp", Some(22)), seen(1)),
            (key("ssh", "tcp", None), seen(2)),
            (key("ssh", "udp", None), seen(4)),
        ]);
        let got = attribute(activity, &inventory);
        assert_eq!(
            got.by_listener[&("ssh".into(), "tcp".into(), 22)].events_24h,
            7
        );
        assert!(got.unrecorded.is_empty());
    }

    /// With several declared listeners there is no right port to guess, and with none there is no
    /// listener at all: both keep the unstamped events apart, one entry per sensor.
    #[test]
    fn unstamped_events_of_a_multi_listener_or_undeclared_sensor_stay_apart() {
        let inventory = inv(&[
            ("a", "smtp", fleet::Proto::Tcp, 25),
            ("a", "smtp", fleet::Proto::Tcp, 587),
        ]);
        let activity = HashMap::from([
            (key("smtp", "tcp", Some(25)), seen(1)),
            (key("smtp", "tcp", None), seen(2)),
            (key("smtp", "udp", None), seen(3)),
            (key("redis", "tcp", None), seen(4)),
        ]);
        let got = attribute(activity, &inventory);
        assert_eq!(got.unrecorded["smtp"].events_24h, 5);
        assert_eq!(got.unrecorded["redis"].events_24h, 4);
        assert_eq!(got.by_listener.len(), 1);
        assert!(
            !got.by_listener
                .contains_key(&("smtp".into(), "tcp".into(), 587))
        );
    }

    /// The badge follows the sensor names a log's events carried, and only a log judged behind
    /// produces one: a caught-up log with bytes in flight, or an idle one, shows nothing.
    #[test]
    fn behind_badges_key_on_the_reported_sensor_names_of_behind_logs_only() {
        use crate::intake_lag::IntakeLag;
        use std::time::Duration;
        let logs = vec![
            IntakeLag {
                log: "cred-vnc".into(),
                sensors: vec!["vnc".into()],
                bytes_behind: 6_600_000_000,
                oldest_unread_age: Some(Duration::from_secs(11 * 86_400)),
                behind: true,
            },
            IntakeLag {
                log: "ssh".into(),
                sensors: vec!["ssh".into()],
                bytes_behind: 900,
                oldest_unread_age: Some(Duration::ZERO),
                behind: false,
            },
        ];
        let got = behind_by_sensor(&logs);
        assert_eq!(
            got.get("vnc").map(String::as_str),
            Some("behind: 6.6 GB / 11 d")
        );
        assert!(
            !got.contains_key("cred-vnc"),
            "the log label is not a listener name"
        );
        assert!(!got.contains_key("ssh"));
    }

    #[test]
    fn merging_activity_sums_counts_and_keeps_the_newest_event() {
        let older = Utc::now() - chrono::Duration::days(2);
        let mut a = Activity {
            last_event_at: Some(older),
            events_24h: 0,
        };
        a.merge(seen(3));
        assert_eq!(a.events_24h, 3);
        assert!(a.last_event_at > Some(older));
        a.merge(Activity::default());
        assert!(a.last_event_at > Some(older));
    }

    const RUNNING: &str = "abc123abc123";
    const HEAD: &str = "abc123abc123def456def456def456def456def4";
    const OTHER: &str = "999999999999aaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    #[test]
    fn a_binary_matching_a_stamp_that_matches_main_is_current() {
        let (verdict, level, _) = version_verdict(RUNNING, Some(RUNNING), Some(HEAD), Some(HEAD));
        assert_eq!(verdict, "current");
        assert_eq!(level, Level::Ok);
    }

    /// A stamp written before the installed identity existed cannot say what is on disk, so it
    /// cannot say the box is current. The running process matching the deployed checkout is still
    /// real evidence about THIS process and is still rendered, but the verdict word is the honest
    /// unknown rather than an agreement nothing observed: an install that silently no-opped
    /// produces exactly this stamp, and `current` would be the wrong answer on that box.
    #[test]
    fn an_older_stamp_without_an_installed_identity_is_not_recorded_not_current() {
        let (verdict, level, note) = version_verdict(RUNNING, None, Some(HEAD), Some(HEAD));
        assert_eq!(verdict, "not recorded");
        assert_eq!(level, Level::Unknown);
        assert!(
            note.contains("records no revision for the binary on disk"),
            "the note must name the missing observation, not imply a fault: {note}"
        );
    }

    /// The failure this whole panel exists for: `upgrade.sh` built and installed new binaries, and
    /// the running process is still the old one.
    #[test]
    fn a_binary_older_than_the_deployed_commit_needs_a_restart() {
        let (verdict, level, note) = version_verdict(RUNNING, None, Some(OTHER), Some(OTHER));
        assert_eq!(verdict, "restart required");
        assert_eq!(level, Level::Warn);
        assert!(note.contains("does not match the commit the deploy stamp recorded"));
        // The regression this guards: a mismatch used to be reported as "a newer build was
        // installed" and promise a restart would fix it, neither of which a bare SHA comparison
        // can actually prove - see `version_verdict`'s own doc comment.
        assert!(!note.contains("a newer build was installed"));
        assert!(!note.contains("not the code on disk"));
    }

    #[test]
    fn a_deployed_commit_behind_origin_main_says_so() {
        let (verdict, level, _) = version_verdict(RUNNING, Some(RUNNING), Some(HEAD), Some(OTHER));
        assert_eq!(verdict, "behind main");
        assert_eq!(level, Level::Warn);
        // Checkout versus fetched main is an observation the installed identity has no part in, so
        // an absent one must not swallow it: the box is behind whatever the install did.
        assert_eq!(
            version_verdict(RUNNING, None, Some(HEAD), Some(OTHER)).0,
            "behind main"
        );
    }

    /// The failure a checkout SHA alone cannot see: the deploy built a commit, the install did not
    /// replace the file, and the old binary is still on disk. Reporting that as "restart required"
    /// would send the operator to `systemctl restart`, which reloads the same old bytes.
    #[test]
    fn an_install_that_did_not_replace_the_binary_is_not_a_restart_problem() {
        // The stamp says HEAD was built; the binary on disk still reports the previous commit, and
        // so does this process, because it is that binary.
        let (verdict, level, note) = version_verdict(OTHER, Some(OTHER), Some(HEAD), Some(HEAD));
        assert_eq!(verdict, "install incomplete");
        assert_eq!(level, Level::Alarm);
        assert!(
            note.contains("did not replace it") && note.contains("restarting would not load"),
            "the note must say a restart is not the fix: {note}"
        );
    }

    /// The same mismatch with the process already restarted into the new build: what is on disk is
    /// still wrong, so the next restart would move the box BACKWARDS. The install is the defect
    /// either way, and the verdict must not soften just because the current process looks right.
    #[test]
    fn an_install_that_did_not_land_is_reported_even_when_the_process_is_current() {
        let (verdict, level, _) = version_verdict(RUNNING, Some(OTHER), Some(HEAD), Some(HEAD));
        assert_eq!(verdict, "install incomplete");
        assert_eq!(level, Level::Alarm);
    }

    /// With the installed identity present and matching the deploy, a mismatch on the RUNNING
    /// process has exactly one explanation left, and the note is allowed to name it.
    #[test]
    fn a_recorded_install_that_matches_the_deploy_makes_restart_the_named_fix() {
        let (verdict, level, note) = version_verdict(OTHER, Some(RUNNING), Some(HEAD), Some(HEAD));
        assert_eq!(verdict, "restart required");
        assert_eq!(level, Level::Warn);
        assert!(
            note.contains("until the service restarts"),
            "with the install proven, the note must name the restart: {note}"
        );
        assert!(
            !note.contains("not guaranteed"),
            "and must not keep hedging about an install that is now established: {note}"
        );
    }

    /// An installed identity that is not a clean revision proves nothing about what landed, so it
    /// must neither be compared as if it were real nor stand in for the observation it is not. A
    /// mismatching running binary falls back to the hedged, undiagnosed `restart required`; a
    /// matching one reads `not recorded`, because the disk was still never looked at.
    #[test]
    fn an_unusable_installed_identity_is_never_treated_as_an_observation() {
        for installed in [
            Some("abc123abc123+dirty"),
            Some("not-a-git-sha-at-all"),
            Some("abc12"),
            None,
        ] {
            let (verdict, level, _) = version_verdict(RUNNING, installed, Some(HEAD), Some(HEAD));
            assert_eq!(verdict, "not recorded", "installed={installed:?}");
            assert_eq!(level, Level::Unknown, "installed={installed:?}");
            let (verdict, _, note) = version_verdict(OTHER, installed, Some(HEAD), Some(HEAD));
            assert_eq!(verdict, "restart required", "installed={installed:?}");
            assert!(
                note.contains("not guaranteed to resolve it"),
                "an unusable installed identity must leave the hedge in place: {note}"
            );
        }
    }

    /// A recorded-but-unusable installed identity and an absent one are both unknown, and the two
    /// notes must not be swapped: one points at stamp damage, the other at a box that simply has
    /// not been redeployed since the field existed.
    #[test]
    fn a_damaged_installed_identity_says_so_rather_than_reading_as_an_old_stamp() {
        let (verdict, _, note) =
            version_verdict(RUNNING, Some("abc123abc123+dirty"), Some(HEAD), Some(HEAD));
        assert_eq!(verdict, "not recorded");
        assert!(
            note.contains("is not a clean commit id"),
            "a damaged installed entry must be named as damage: {note}"
        );
    }

    /// Every uncertain input lands here rather than on `current`. A panel that says the box is up
    /// to date because it could not tell otherwise is worse than one that says nothing.
    #[test]
    fn every_unknown_input_reads_not_recorded_rather_than_current() {
        for (running, installed, head, origin) in [
            // No stamp file, or one that parsed to nothing useful.
            (RUNNING, None, None, None),
            (RUNNING, None, None, Some(HEAD)),
            // A stamp with no origin revision cannot answer "behind main", so it must not claim
            // the box is current either.
            (RUNNING, None, Some(HEAD), None),
            // A build that could not run git, and a build from a modified working tree: neither
            // names a commit, and a recorded install identity cannot rescue that - this process
            // still cannot say what it is.
            ("unknown", None, Some(HEAD), Some(HEAD)),
            ("unknown", Some(RUNNING), Some(HEAD), Some(HEAD)),
            ("abc123abc123+dirty", None, Some(HEAD), Some(HEAD)),
            ("abc123abc123+dirty", Some(RUNNING), Some(HEAD), Some(HEAD)),
            // Everything else agreeing does not make an unobserved install an observed one: with
            // no usable identity for the binary on disk, the fourth identity is simply missing.
            (RUNNING, None, Some(HEAD), Some(HEAD)),
            (RUNNING, Some("abc123abc123+dirty"), Some(HEAD), Some(HEAD)),
            (
                RUNNING,
                Some("not-a-git-sha-at-all"),
                Some(HEAD),
                Some(HEAD),
            ),
            // A stamp whose recorded id is not a valid revision at all - too short, or not hex -
            // must read as unrecorded, not be compared as if it were a real (mismatching) SHA.
            (RUNNING, None, Some("abc12"), Some(HEAD)),
            (RUNNING, None, Some("not-a-git-sha-at-all"), Some(HEAD)),
            (RUNNING, None, Some(HEAD), Some("abc12")),
            (RUNNING, None, Some(HEAD), Some("not-a-git-sha-at-all")),
        ] {
            let (verdict, level, _) = version_verdict(running, installed, head, origin);
            assert_eq!(
                verdict, "not recorded",
                "running={running} installed={installed:?} head={head:?} origin={origin:?}"
            );
            assert_eq!(level, Level::Unknown);
        }
    }

    /// A malformed stamp field is reported as unrecorded, distinctly from a real mismatch, so the
    /// operator is pointed at the deploy stamp file itself rather than at a phantom "restart" or
    /// "behind main" fix.
    #[test]
    fn a_malformed_stamp_sha_is_not_recorded_rather_than_a_mismatch() {
        let (verdict, _, note) = version_verdict(RUNNING, None, Some("not-hex"), Some(HEAD));
        assert_eq!(verdict, "not recorded");
        assert!(note.contains("not a valid revision"));
    }

    /// The stamp holds the full 40-character id and the binary a 12-character prefix of it, so
    /// comparing them for equality would report "restart required" on every healthy box.
    #[test]
    fn the_short_sha_is_matched_as_a_prefix_of_the_stamps_full_one() {
        assert_eq!(
            version_verdict(RUNNING, Some(RUNNING), Some(HEAD), Some(HEAD)).0,
            "current"
        );
        // And a prefix that does not match must not be waved through, on either identity.
        assert_eq!(
            version_verdict("abc123abc124", Some(RUNNING), Some(HEAD), Some(HEAD)).0,
            "restart required"
        );
        assert_eq!(
            version_verdict(RUNNING, Some("abc123abc124"), Some(HEAD), Some(HEAD)).0,
            "install incomplete"
        );
    }
}
