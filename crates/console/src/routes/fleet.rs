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
//! events must appear, saying `never`, because "produced nothing" is exactly the state worth
//! seeing. A sensor present in the ledger but absent from the inventory gets its own row flagged
//! `undeclared listener`, which catches the inventory drifting after a port was added on the box
//! but not at the control plane.
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
use fleet::health::{Level, combine, event_age_level, reach_level};
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
    last_event_level: &'static str,
    events_24h: i64,
    state_level: &'static str,
    /// False for a sensor seen in the ledger that the inventory does not know about.
    declared: bool,
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
    state_level: &'static str,
}

#[derive(Debug, Serialize)]
struct LedgerStatus {
    events: Option<i64>,
    newest_ingested_ago: Option<String>,
    state_level: &'static str,
}

#[derive(Debug, Serialize)]
struct VersionStatus {
    running_version: String,
    /// The revision this PROCESS was built from, which is not the same question as what is
    /// checked out on the box. `unknown` when the build could not identify itself.
    running_sha: String,
    built_at: String,
    stamp_head_sha: Option<String>,
    stamp_origin_main_sha: Option<String>,
    stamp_age: Option<String>,
    verdict: &'static str,
    note: &'static str,
    state_level: &'static str,
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

/// Per-sensor ledger activity, keyed by the sensor's OWN reported name (`event.sensor`), which is
/// what the inventory is keyed on too. See `fleet::inventory`'s note on why the
/// `PROPOLIS_SENSOR_LOGS` label is the wrong key.
struct SensorActivity {
    last_event_at: Option<DateTime<Utc>>,
    events_24h: i64,
}

async fn sensor_activity(db: &PgPool) -> Result<HashMap<String, SensorActivity>, sqlx::Error> {
    let rows = sqlx::query(
        "SELECT sensor, \
                max(observed_at) AS last_event_at, \
                count(*) FILTER (WHERE observed_at >= now() - interval '24 hours') AS events_24h \
         FROM event GROUP BY sensor",
    )
    .fetch_all(db)
    .await?;
    let mut out = HashMap::with_capacity(rows.len());
    for row in rows {
        out.insert(
            row.try_get::<String, _>("sensor")?,
            SensorActivity {
                last_event_at: row.try_get("last_event_at")?,
                events_24h: row.try_get("events_24h")?,
            },
        );
    }
    Ok(out)
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

/// The version verdict, as a pure function of the three revisions involved.
///
/// Three different things get confused here and the panel exists to keep them apart: what this
/// PROCESS is running, what was last BUILT and installed on this box, and what is on `main`. A
/// deploy that built new binaries without restarting the service leaves the first two apart, and
/// that is invisible from anywhere else on the box.
///
/// Every uncertain case lands on `not recorded`, never on `current`. The failure this guards is a
/// panel that says the box is up to date because it could not tell that it was not.
fn version_verdict(
    running_sha: &str,
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
    // The stamp carries the full 40-character id and the binary a short prefix of it, so a prefix
    // match is the comparison, not equality.
    if !head.starts_with(running_sha) {
        return (
            "restart required",
            Level::Warn,
            "a newer build was installed after this process started; the running code is not the \
             code on disk",
        );
    }
    let Some(origin) = stamp_origin else {
        return (
            "not recorded",
            Level::Unknown,
            "the deploy stamp names no origin/main revision, so it cannot say whether this box is \
             behind",
        );
    };
    if origin != head {
        return (
            "behind main",
            Level::Warn,
            "this box is running the commit it deployed, but main has moved on since",
        );
    }
    (
        "current",
        Level::Ok,
        "the running binary, the deployed checkout and main are the same commit",
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
    let stamp_age = field("built_at")
        .or_else(|| field("pulled_at"))
        .and_then(|t| DateTime::parse_from_rfc3339(&t).ok())
        .map(|t| format_relative_time(t.with_timezone(&Utc)));

    let (verdict, level, note) = version_verdict(
        state.git_sha,
        stamp_head_sha.as_deref(),
        stamp_origin_main_sha.as_deref(),
    );

    VersionStatus {
        running_version: state.version.to_string(),
        running_sha: state.git_sha.to_string(),
        built_at: state.built_at.to_string(),
        stamp_head_sha,
        stamp_origin_main_sha,
        stamp_age,
        verdict,
        note,
        state_level: level.class(),
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
            state_level: Level::Unknown.class(),
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
            state_level: Level::Unknown.class(),
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
        Some(until) if until <= now => (
            Some(format_relative_time(until)),
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
        state_level: level.class(),
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
    degraded: Vec<&'static str>,
}

async fn build_view(state: &AppState, mut degraded: Degraded) -> FleetView {
    let now = Utc::now();
    // The staleness rules are measured in sweep intervals, so they follow the prober's configured
    // cadence rather than a constant here: with a constant, an operator who slowed the sweep down
    // would get a page on which every row read stale, and one who sped it up would keep a rule
    // looser than the evidence allows.
    let probe_interval = state.fleet_probe_interval;

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

    let activity = degraded.soft("sensor activity", sensor_activity(&state.db).await);

    let mut listeners = Vec::with_capacity(state.fleet_listeners.len());
    let mut levels = Vec::with_capacity(state.fleet_listeners.len());
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

        let seen = activity.get(&listener.sensor);
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
            last_event_ago: last_event_at
                .map(format_relative_time)
                .unwrap_or_else(|| "never".to_string()),
            last_event_level: event_level.class(),
            events_24h: seen.map(|a| a.events_24h).unwrap_or(0),
            state_level: state_level.class(),
            declared: true,
        });
    }

    // A sensor the ledger has seen but the inventory does not name. The events are real, so the
    // pane must show them, and it must say plainly that the control plane was never told this
    // listener exists rather than quietly folding it in as if it had been.
    let declared: HashSet<&str> = state
        .fleet_listeners
        .iter()
        .map(|l| l.sensor.as_str())
        .collect();
    let mut undeclared: Vec<&String> = activity
        .keys()
        .filter(|s| !declared.contains(s.as_str()))
        .collect();
    undeclared.sort();
    for sensor in undeclared {
        let seen = &activity[sensor];
        let event_level = event_age_level(seen.last_event_at, now);
        unknown += 1;
        levels.push(Level::Unknown);
        listeners.push(ListenerRow {
            collector: "unknown".into(),
            sensor: sensor.clone(),
            sensor_label: format_sensor_label(sensor),
            protocol: "--".into(),
            port: "--".into(),
            vantage: String::new(),
            reach: "undeclared listener".into(),
            reach_level: Level::Unknown.class(),
            reach_dot: dot_class(Level::Unknown),
            reach_detail: Some(
                "this sensor is producing events but is not in PROPOLIS_FLEET_LISTENERS".into(),
            ),
            probe_ago: "never".into(),
            confirmed_ago: None,
            last_event_ago: seen
                .last_event_at
                .map(format_relative_time)
                .unwrap_or_else(|| "never".to_string()),
            last_event_level: event_level.class(),
            events_24h: seen.events_24h,
            state_level: Level::Unknown.class(),
            declared: false,
        });
    }

    let mut captures = degraded.soft("capture completeness", capture_rows(&state.db).await);
    let reasons = degraded.soft("capture end reasons", top_end_reasons(&state.db).await);
    for row in &mut captures {
        // Matched on the RAW sensor name, not the display label: two raw names can share a label
        // (`catchall` and `catchall-sensor` both render as "General"), and joining on the label
        // would attach one sensor's end reason to another's rate.
        if let Some((reason, n)) = reasons.get(&row.sensor) {
            row.top_end_reason = Some(reason.clone());
            row.top_end_reason_count = *n;
        }
    }

    let ledger_row = degraded.soft_or(
        "ledger head",
        sqlx::query("SELECT count(*) AS events, max(ingested_at) AS newest_ingested_at FROM event")
            .fetch_one(&state.db)
            .await
            .and_then(|r| {
                Ok((
                    r.try_get::<i64, _>("events")?,
                    r.try_get::<Option<DateTime<Utc>>, _>("newest_ingested_at")?,
                ))
            }),
        (0, None),
    );
    let ledger_level = match ledger_row.1 {
        None => Level::Unknown,
        Some(t) if (now - t).num_minutes() < 60 => Level::Ok,
        Some(_) => Level::Warn,
    };
    let ledger = LedgerStatus {
        events: Some(ledger_row.0),
        newest_ingested_ago: ledger_row.1.map(format_relative_time),
        state_level: ledger_level.class(),
    };

    // The band's "Last event" cell is the same fleet-wide number the dashboard shows, kept here so
    // the two pages cannot disagree; the per-listener column beside it is what this page adds.
    let overall_last_event = ledger_row
        .1
        .map(format_relative_time)
        .unwrap_or_else(|| "never".to_string());

    let total = listeners.len();
    let headline_level = combine(&levels);
    let headline = match headline_level {
        Level::Ok => "every listener proven",
        Level::Warn => "listeners answering, evidence path unconfirmed",
        Level::Alarm => "a listener is not answering",
        Level::Unknown => "reachability unproven",
    };

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

    const RUNNING: &str = "abc123abc123";
    const HEAD: &str = "abc123abc123def456def456def456def456def4";
    const OTHER: &str = "999999999999aaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    #[test]
    fn a_binary_matching_a_stamp_that_matches_main_is_current() {
        let (verdict, level, _) = version_verdict(RUNNING, Some(HEAD), Some(HEAD));
        assert_eq!(verdict, "current");
        assert_eq!(level, Level::Ok);
    }

    /// The failure this whole panel exists for: `upgrade.sh` built and installed new binaries, and
    /// the running process is still the old one.
    #[test]
    fn a_binary_older_than_the_deployed_commit_needs_a_restart() {
        let (verdict, level, note) = version_verdict(RUNNING, Some(OTHER), Some(OTHER));
        assert_eq!(verdict, "restart required");
        assert_eq!(level, Level::Warn);
        assert!(note.contains("not the code on disk"));
    }

    #[test]
    fn a_deployed_commit_behind_origin_main_says_so() {
        let (verdict, level, _) = version_verdict(RUNNING, Some(HEAD), Some(OTHER));
        assert_eq!(verdict, "behind main");
        assert_eq!(level, Level::Warn);
    }

    /// Every uncertain input lands here rather than on `current`. A panel that says the box is up
    /// to date because it could not tell otherwise is worse than one that says nothing.
    #[test]
    fn every_unknown_input_reads_not_recorded_rather_than_current() {
        for (running, head, origin) in [
            // No stamp file, or one that parsed to nothing useful.
            (RUNNING, None, None),
            (RUNNING, None, Some(HEAD)),
            // A stamp with no origin revision cannot answer "behind main", so it must not claim
            // the box is current either.
            (RUNNING, Some(HEAD), None),
            // A build that could not run git.
            ("unknown", Some(HEAD), Some(HEAD)),
            // A build from a modified working tree matches no commit at all.
            ("abc123abc123+dirty", Some(HEAD), Some(HEAD)),
        ] {
            let (verdict, level, _) = version_verdict(running, head, origin);
            assert_eq!(
                verdict, "not recorded",
                "running={running} head={head:?} origin={origin:?}"
            );
            assert_eq!(level, Level::Unknown);
        }
    }

    /// The stamp holds the full 40-character id and the binary a 12-character prefix of it, so
    /// comparing them for equality would report "restart required" on every healthy box.
    #[test]
    fn the_short_sha_is_matched_as_a_prefix_of_the_stamps_full_one() {
        assert_eq!(
            version_verdict(RUNNING, Some(HEAD), Some(HEAD)).0,
            "current"
        );
        // And a prefix that does not match must not be waved through.
        assert_eq!(
            version_verdict("abc123abc124", Some(HEAD), Some(HEAD)).0,
            "restart required"
        );
    }
}
