//! Per-source command-event budget and flood summaries for the shared fake shell.
//!
//! A Mirai-family echo loader runs the same fifty-odd commands per session, several sessions at
//! once from one address, around the clock. Every command was one `honeypot_command_exec` line:
//! one bot wrote 2,555 events in ten minutes, telnet reached 97% of all events, and the intake
//! fell eleven days behind its log. The per-connection command cap
//! (`crate::shell::MAX_COMMANDS_PER_SESSION`) cannot see it, because each session stays far under
//! it; the flood is many sessions, so the budget belongs to the source.
//!
//! [`CommandEventGate`] holds one token bucket per source network (the [`SourceKey`] /24 or /56,
//! as the UDP reply limiter keys it) charged by command events only. A command event within the
//! budget is written exactly as before. One over it is not written; it is counted into a summary
//! of that network's suppressed commands over a [`COMMAND_SUMMARY_WINDOW`], written as one
//! `honeypot_command_exec` carrying `command_summary: true` when the window ends or the sensor
//! shuts down. The shell answers every command the same either way: only the logging is summarized.
//!
//! Some events are never summarized. Everything that is not a plain command event
//! ([`summarizable`]): logins, connections, downloads and derived URLs, capture uploads, the
//! per-session flood markers, and summaries themselves. The first time each distinct command
//! shape ([`command_shape`]: the line with escapes, hex and base64 runs taken out) is seen from a
//! source network in a window: a new kind of command always appears in full, whatever the budget
//! says. And each address's first command event in a window, because scoring is per address: a
//! host whose commands all repeat a neighbour's would otherwise have none. An echo-loader chunk
//! (a command event carrying `assembled_file`) is never either kind of first: its bytes are in
//! the capture, and the summary keeps the file and its highest chunk number.
//!
//! Memory is fixed. The bucket table is the limiter's (bounded with eviction); the window table
//! holds at most [`DEFAULT_SUMMARY_CAPACITY`] networks, each tracking at most
//! [`MAX_TRACKED_COMMANDS`] command digests, [`MAX_SUMMARY_SAMPLES`] samples of at most
//! [`MAX_COMMAND_SAMPLE_LEN`] bytes and [`MAX_SUMMARY_SESSIONS`] session ids. A network that
//! arrives while the window table is full gets no first-sighting tracking and is summarized into
//! one overflow summary. The lock is a plain mutex held for a few map updates, never across an
//! `.await`; time is `tokio::time::Instant`, so tests drive it with a paused clock.

use std::collections::HashMap;
use std::collections::hash_map::RandomState;
use std::fmt;
use std::hash::BuildHasher;
use std::net::IpAddr;
use std::num::{NonZeroU32, NonZeroUsize};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use chrono::{DateTime, SecondsFormat, Utc};
use sensor_wire::{PROTO_TCP, SIGNAL_HONEYPOT_COMMAND_EXEC, SensorEvent, WIRE_VERSION};
use serde_json::{Value, json};
use tokio::task::JoinHandle;
use tokio::time::Instant;
use uuid::Uuid;

use crate::arrival::{self, Arrival};
use crate::emit::EventEmitter;
use crate::env::EnvError;
use crate::rate_limit::{
    DEFAULT_RATE_TABLE_CAPACITY, DEFAULT_SUMMARY_CAPACITY, MAX_SUMMARY_SAMPLES, Rate, RateDecision,
    RateLimitConfig, ReplyRateLimiter, SourceKey,
};
use crate::sanitize_value;

/// Command events a source network may write per minute once its burst is spent.
pub const DEFAULT_COMMAND_EVENTS_PER_MIN: u32 = 12;
/// Command events a source network may write at once. Several whole loader sessions fit, so an
/// ordinary interactive attacker is never summarized.
pub const DEFAULT_COMMAND_EVENT_BURST: u32 = 200;
/// How long one network's suppressed commands accumulate before their summary is written, and
/// how long a command's first sighting lasts.
pub const COMMAND_SUMMARY_WINDOW: Duration = Duration::from_secs(60);
/// Distinct commands one network's window remembers having seen.
pub const MAX_TRACKED_COMMANDS: usize = 128;
/// Addresses of one network whose first command event in a window is always written.
pub const MAX_TRACKED_ADDRESSES: usize = 64;
/// Longest sample command kept in a summary, after sanitization. Shorter than a command event's
/// own cap: a sample shows what was repeated, the first sighting already carries the whole line.
pub const MAX_COMMAND_SAMPLE_LEN: usize = 256;
/// Distinct session ids counted per summary; beyond this the count is reported as capped.
pub const MAX_SUMMARY_SESSIONS: usize = 32;
/// The metadata key that marks a summary event.
pub const COMMAND_SUMMARY_KEY: &str = "command_summary";
/// The shortest and longest wait between looks for ended windows.
const MIN_EMIT_INTERVAL: Duration = Duration::from_millis(10);
const MAX_EMIT_INTERVAL: Duration = Duration::from_secs(1);

/// A sensor's command-event budget: the per-network rate and burst, the summary window, and the
/// number of networks summarized at once.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CommandEventConfig {
    pub rate: Rate,
    pub window: Duration,
    pub window_capacity: NonZeroUsize,
}

impl Default for CommandEventConfig {
    fn default() -> Self {
        Self {
            rate: Rate::per_minute(
                NonZeroU32::new(DEFAULT_COMMAND_EVENTS_PER_MIN).unwrap_or(NonZeroU32::MIN),
                NonZeroU32::new(DEFAULT_COMMAND_EVENT_BURST).unwrap_or(NonZeroU32::MIN),
            ),
            window: COMMAND_SUMMARY_WINDOW,
            window_capacity: NonZeroUsize::new(DEFAULT_SUMMARY_CAPACITY)
                .unwrap_or(NonZeroUsize::MIN),
        }
    }
}

/// A command-event setting the sensor refuses to start with.
#[derive(Debug, PartialEq, Eq)]
pub enum CommandEventConfigError {
    /// The variable held bytes that are not UTF-8.
    Env(EnvError),
    /// The value was zero or not a whole number that fits in a `u32`.
    Invalid { var: String, value: String },
}

impl fmt::Display for CommandEventConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Env(e) => write!(f, "{e}"),
            Self::Invalid { var, value } => write!(
                f,
                "{var} must be a positive integer, got {value:?} (zero never means unlimited)"
            ),
        }
    }
}

impl std::error::Error for CommandEventConfigError {}

impl From<EnvError> for CommandEventConfigError {
    fn from(e: EnvError) -> Self {
        Self::Env(e)
    }
}

/// The two variables `PROPOLIS_<SENSOR>_COMMAND_EVENT_RATE_PER_MIN` and `..._BURST`.
pub fn command_event_vars(sensor: &str) -> (String, String) {
    let prefix = format!("PROPOLIS_{}_COMMAND_EVENT", sensor.to_ascii_uppercase());
    (format!("{prefix}_RATE_PER_MIN"), format!("{prefix}_BURST"))
}

impl CommandEventConfig {
    /// Read the rate and burst for `sensor` (`telnet`, `ssh`, `adb`) from the process environment.
    pub fn from_env(sensor: &str) -> Result<Self, CommandEventConfigError> {
        Self::from_lookup(sensor, crate::env::strict_env_var)
    }

    /// [`Self::from_env`] over any variable lookup. Unset takes the default; zero, a negative
    /// number, garbage or a value past `u32` is an error, never a default and never "unlimited".
    pub fn from_lookup(
        sensor: &str,
        get: impl Fn(&str) -> Result<Option<String>, EnvError>,
    ) -> Result<Self, CommandEventConfigError> {
        let (rate_var, burst_var) = command_event_vars(sensor);
        let read = |var: &str, default: u32| -> Result<NonZeroU32, CommandEventConfigError> {
            let Some(raw) = get(var)? else {
                return Ok(NonZeroU32::new(default).unwrap_or(NonZeroU32::MIN));
            };
            raw.parse::<u32>()
                .ok()
                .and_then(NonZeroU32::new)
                .ok_or_else(|| CommandEventConfigError::Invalid {
                    var: var.to_string(),
                    value: raw.clone(),
                })
        };
        Ok(Self {
            rate: Rate::per_minute(
                read(&rate_var, DEFAULT_COMMAND_EVENTS_PER_MIN)?,
                read(&burst_var, DEFAULT_COMMAND_EVENT_BURST)?,
            ),
            ..Self::default()
        })
    }
}

/// What makes two commands the same for a first sighting: the line with its payload taken out.
/// A loader's echo chunks differ only in their `\xNN` bytes and its markers only in their
/// escapes or random hex, so each kind is one shape. Runs of `\xNN` or `\NNN` escapes, runs of
/// 16 or more hex digits and base64-looking runs of 24 or more characters become placeholders,
/// and whitespace runs collapse to one space.
pub fn command_shape(command: &str) -> String {
    let chars: Vec<char> = command.chars().collect();
    let mut out = String::with_capacity(command.len().min(MAX_COMMAND_SAMPLE_LEN));
    let mut i = 0;
    while let Some(&c) = chars.get(i) {
        let escapes = escape_run_len(chars.get(i..).unwrap_or_default());
        if escapes > 0 {
            out.push_str("<esc>");
            i += escapes;
        } else if c.is_whitespace() {
            while chars.get(i).is_some_and(|c| c.is_whitespace()) {
                i += 1;
            }
            if !out.is_empty() && i < chars.len() {
                out.push(' ');
            }
        } else if is_base64_char(c) {
            let start = i;
            while chars.get(i).is_some_and(|&c| is_base64_char(c)) {
                i += 1;
            }
            let run = chars.get(start..i).unwrap_or_default();
            if run.len() >= 16 && run.iter().all(char::is_ascii_hexdigit) {
                out.push_str("<hex>");
            } else if run.len() >= 24 && looks_base64(run) {
                out.push_str("<b64>");
            } else {
                out.extend(run);
            }
        } else {
            out.push(c);
            i += 1;
        }
    }
    out
}

fn is_base64_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, '+' | '/' | '=')
}

/// At least two of upper case, lower case and digits: an encoded blob, not a long path or word.
fn looks_base64(run: &[char]) -> bool {
    let upper = run.iter().any(char::is_ascii_uppercase);
    let lower = run.iter().any(char::is_ascii_lowercase);
    let digit = run.iter().any(char::is_ascii_digit);
    usize::from(upper) + usize::from(lower) + usize::from(digit) >= 2
}

/// The length of the run of `\xN`/`\xNN` and `\N`/`\NN`/`\NNN` (octal) escapes `chars` starts
/// with; zero when it starts with none.
fn escape_run_len(chars: &[char]) -> usize {
    let mut at = 0;
    loop {
        let rest = chars.get(at..).unwrap_or_default();
        let unit = match rest {
            ['\\', 'x', h, ..] if h.is_ascii_hexdigit() => {
                2 + 1 + usize::from(rest.get(3).is_some_and(char::is_ascii_hexdigit))
            }
            ['\\', d, ..] if d.is_digit(8) => {
                1 + rest
                    .iter()
                    .skip(1)
                    .take(3)
                    .take_while(|c| c.is_digit(8))
                    .count()
            }
            _ => 0,
        };
        if unit == 0 {
            return at;
        }
        at += unit;
    }
}

/// Whether an event may be summarized at all: a plain command event and nothing else. Logins,
/// connections, downloads, derived URLs, capture uploads, the per-session flood markers and
/// summaries themselves always keep their own event.
pub fn summarizable(event: &SensorEvent) -> bool {
    event.signal_type == SIGNAL_HONEYPOT_COMMAND_EXEC
        && event.metadata.get("command").is_some_and(Value::is_string)
        && event.metadata.get("flood").is_none()
        && event.metadata.get(COMMAND_SUMMARY_KEY).is_none()
}

/// What the gate decided for one command event.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Admission {
    /// Written as its own event.
    Logged,
    /// Counted into its network's summary instead.
    Summarized,
}

/// One source network's (or the overflow's) suppressed command events over one window.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommandSummary {
    /// `None` for the overflow summary: networks that arrived while the window table was full.
    pub key: Option<SourceKey>,
    /// The source address, sensor, WAN address and authentication of the first suppressed event.
    pub first_source: IpAddr,
    pub sensor: String,
    pub wan_ip: Option<IpAddr>,
    pub authenticated: bool,
    pub count: u64,
    /// Distinct commands among the suppressed ones.
    pub distinct_commands: u64,
    /// More distinct commands arrived than the window could tell apart.
    pub distinct_commands_capped: bool,
    /// At most [`MAX_SUMMARY_SAMPLES`] distinct commands, sanitized and at most
    /// [`MAX_COMMAND_SAMPLE_LEN`] bytes each.
    pub samples: Vec<String>,
    pub first_seen: Instant,
    pub last_seen: Instant,
    /// Distinct sessions the suppressed commands came from, at most [`MAX_SUMMARY_SESSIONS`].
    pub sessions: usize,
    pub sessions_capped: bool,
    /// The echo-loader file the highest suppressed chunk was written to, and that chunk's number.
    pub assembled_file: Option<String>,
    pub max_chunk_index: Option<u64>,
}

#[derive(Debug)]
struct Pending {
    summary: CommandSummary,
    session_ids: Vec<Uuid>,
}

/// One network's window: when it began, the commands seen in it, and what it has suppressed.
#[derive(Debug)]
struct Window {
    started: Instant,
    /// Digest of each command seen this window, and how many of its events were suppressed.
    /// `None` for the overflow, which tracks no sightings.
    seen: Option<HashMap<u64, u64>>,
    /// The addresses of the network that have had a command event written this window.
    addresses: Vec<IpAddr>,
    pending: Option<Pending>,
}

impl Window {
    fn new(now: Instant, tracking: bool) -> Self {
        Self {
            started: now,
            seen: tracking.then(HashMap::new),
            addresses: Vec::new(),
            pending: None,
        }
    }

    /// True for an address's first command event this window, while there is room to remember
    /// it. Scoring is per address and the budget per network: without this, a host whose every
    /// command repeats one a neighbour in its /24 already ran would have no command event at all.
    fn first_from_address(&mut self, address: IpAddr) -> bool {
        if self.seen.is_none()
            || self.addresses.contains(&address)
            || self.addresses.len() >= MAX_TRACKED_ADDRESSES
        {
            return false;
        }
        self.addresses.push(address);
        true
    }

    /// True the first time `digest` is seen this window, while there is room to remember it.
    fn first_sighting(&mut self, digest: u64) -> bool {
        let Some(seen) = self.seen.as_mut() else {
            return false;
        };
        if seen.contains_key(&digest) || seen.len() >= MAX_TRACKED_COMMANDS {
            return false;
        }
        seen.insert(digest, 0);
        true
    }

    fn fold(
        &mut self,
        key: Option<SourceKey>,
        event: &SensorEvent,
        command: &str,
        digest: u64,
        now: Instant,
    ) {
        let pending = self.pending.get_or_insert_with(|| Pending {
            summary: CommandSummary {
                key,
                first_source: event.source_ip,
                sensor: event.sensor.clone(),
                wan_ip: event.wan_ip,
                authenticated: event.authenticated,
                count: 0,
                distinct_commands: 0,
                distinct_commands_capped: false,
                samples: Vec::with_capacity(MAX_SUMMARY_SAMPLES),
                first_seen: now,
                last_seen: now,
                sessions: 0,
                sessions_capped: false,
                assembled_file: None,
                max_chunk_index: None,
            },
            session_ids: Vec::with_capacity(MAX_SUMMARY_SESSIONS),
        });
        let s = &mut pending.summary;
        s.count = s.count.saturating_add(1);
        s.last_seen = now;
        // A sample is taken only when a command is new to the summary, so a flood of one repeated
        // command allocates nothing per event.
        // A loader chunk was never offered as a first sighting, so its shape may be new here.
        if let Some(seen) = self.seen.as_mut()
            && !seen.contains_key(&digest)
            && seen.len() < MAX_TRACKED_COMMANDS
        {
            seen.insert(digest, 0);
        }
        let new_command = match self.seen.as_mut().and_then(|seen| seen.get_mut(&digest)) {
            Some(suppressed) => {
                *suppressed = suppressed.saturating_add(1);
                if *suppressed == 1 {
                    s.distinct_commands = s.distinct_commands.saturating_add(1);
                }
                *suppressed == 1
            }
            // A command the window could not remember may repeat one already counted.
            None => {
                s.distinct_commands_capped = true;
                true
            }
        };
        if new_command && s.samples.len() < MAX_SUMMARY_SAMPLES {
            let sample = sanitize_value(command, MAX_COMMAND_SAMPLE_LEN);
            if !s.samples.contains(&sample) {
                s.samples.push(sample);
            }
        }
        if let Some(id) = event.session_id
            && !pending.session_ids.contains(&id)
        {
            if pending.session_ids.len() < MAX_SUMMARY_SESSIONS {
                pending.session_ids.push(id);
            } else {
                s.sessions_capped = true;
            }
        }
        s.sessions = pending.session_ids.len();
        if let (Some(file), Some(index)) = (
            event.metadata.get("assembled_file").and_then(Value::as_str),
            event.metadata.get("chunk_index").and_then(Value::as_u64),
        ) && s.max_chunk_index.is_none_or(|max| index > max)
        {
            s.max_chunk_index = Some(index);
            s.assembled_file = Some(file.to_string());
        }
    }

    fn into_summary(self) -> Option<CommandSummary> {
        self.pending.map(|p| p.summary)
    }
}

#[derive(Debug)]
struct GateState {
    windows: HashMap<SourceKey, Window>,
    overflow: Option<Window>,
    /// Summaries of windows that ended while a command arrived, before the writer took them.
    ready: Vec<CommandSummary>,
    /// Summaries that found `ready` full (only when no writer runs); logged, never unbounded.
    dropped: u64,
}

/// A sensor's per-source command-event budget and the summaries of what it suppressed. One per
/// sensor process, shared by every connection through its `ConnectionBudget`.
#[derive(Debug)]
pub struct CommandEventGate {
    limiter: ReplyRateLimiter,
    state: Mutex<GateState>,
    /// Keyed per process, so an attacker cannot craft a command that collides with another's
    /// digest.
    hasher: RandomState,
    window: Duration,
    capacity: usize,
}

impl CommandEventGate {
    pub fn new(config: CommandEventConfig) -> Self {
        let capacity = config.window_capacity.get();
        // Command events have no total budget across networks: the global bucket is set past any
        // reachable rate, so only the per-network one ever refuses.
        let unlimited = Rate::new(NonZeroU32::MAX, NonZeroU32::MAX);
        let mut limits = RateLimitConfig::new(config.rate, unlimited);
        limits.table_capacity =
            NonZeroUsize::new(DEFAULT_RATE_TABLE_CAPACITY).unwrap_or(NonZeroUsize::MIN);
        Self {
            limiter: ReplyRateLimiter::new(&limits),
            state: Mutex::new(GateState {
                windows: HashMap::with_capacity(capacity),
                overflow: None,
                ready: Vec::new(),
                dropped: 0,
            }),
            hasher: RandomState::new(),
            window: config.window,
            capacity,
        }
    }

    pub fn window(&self) -> Duration {
        self.window
    }

    /// How often the writer looks for ended windows: a tenth of the window, clamped.
    pub fn emit_interval(&self) -> Duration {
        (self.window / 10).clamp(MIN_EMIT_INTERVAL, MAX_EMIT_INTERVAL)
    }

    /// Keep the events of one shell line that are to be written, folding the command events over
    /// their network's budget into its summary. Events that are not [`summarizable`] pass
    /// untouched and spend nothing.
    pub fn filter(&self, events: &mut Vec<SensorEvent>) {
        self.filter_at(events, Instant::now());
    }

    pub fn filter_at(&self, events: &mut Vec<SensorEvent>, now: Instant) {
        events
            .retain(|event| !summarizable(event) || self.admit_at(event, now) == Admission::Logged);
    }

    /// Decide one command event: write it when it is its network's first sighting of the command
    /// this window, its address's first command event this window, or the network has a token;
    /// otherwise count it into the summary. A first also spends a token when one is left.
    pub fn admit_at(&self, event: &SensorEvent, now: Instant) -> Admission {
        let command = event
            .metadata
            .get("command")
            .and_then(Value::as_str)
            .unwrap_or_default();
        let digest = self.hasher.hash_one(command_shape(command));
        // An echo-loader chunk is never a first: its bytes are in the capture, and the summary
        // keeps the file and the highest chunk number.
        let loader_chunk = event.metadata.get("assembled_file").is_some();
        let key = SourceKey::of_ip(event.source_ip);
        let mut guard = self.state.lock().unwrap_or_else(|e| e.into_inner());
        let state = &mut *guard;
        let window_ended = |w: &Window| w.started + self.window <= now;
        if state.windows.get(&key).is_some_and(window_ended)
            && let Some(ended) = state.windows.remove(&key)
        {
            Self::park(state, self.capacity, ended);
        }
        if state.overflow.as_ref().is_some_and(window_ended)
            && let Some(ended) = state.overflow.take()
        {
            Self::park(state, self.capacity, ended);
        }
        let tracked = state.windows.len() < self.capacity || state.windows.contains_key(&key);
        let first = tracked && {
            let window = state
                .windows
                .entry(key)
                .or_insert_with(|| Window::new(now, true));
            if loader_chunk {
                false
            } else {
                // Both are recorded whatever the other says.
                let new_command = window.first_sighting(digest);
                let new_address = window.first_from_address(event.source_ip);
                new_command || new_address
            }
        };
        let token = self.limiter.check_at(key, now) == RateDecision::Allow;
        if first || token {
            return Admission::Logged;
        }
        let (window, summary_key) = match state.windows.get_mut(&key) {
            Some(window) => (window, Some(key)),
            None => (
                state
                    .overflow
                    .get_or_insert_with(|| Window::new(now, false)),
                None,
            ),
        };
        window.fold(summary_key, event, command, digest, now);
        Admission::Summarized
    }

    /// Keep an ended window's summary for the writer.
    fn park(state: &mut GateState, capacity: usize, ended: Window) {
        let Some(summary) = ended.into_summary() else {
            return;
        };
        if state.ready.len() <= capacity {
            state.ready.push(summary);
        } else {
            state.dropped = state.dropped.saturating_add(1);
            if state.dropped.is_power_of_two() {
                tracing::warn!(
                    dropped_total = state.dropped,
                    "command summaries dropped: no summary writer is taking them"
                );
            }
        }
    }

    /// Remove every window that has ended at `now` and return the summaries of those that
    /// suppressed anything, with any parked since the last call.
    pub fn take_due(&self, now: Instant) -> Vec<CommandSummary> {
        let window = self.window;
        let ended = |w: &Window| w.started + window <= now;
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        let mut out = std::mem::take(&mut state.ready);
        let mut due = Vec::new();
        state.windows.retain(|_, w| {
            if ended(w) {
                due.push(std::mem::replace(w, Window::new(now, false)));
                false
            } else {
                true
            }
        });
        if state.overflow.as_ref().is_some_and(ended) {
            due.extend(state.overflow.take());
        }
        out.extend(due.into_iter().filter_map(Window::into_summary));
        out
    }

    /// Remove every window and return every summary, ended or not (shutdown).
    pub fn drain(&self) -> Vec<CommandSummary> {
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        let mut out = std::mem::take(&mut state.ready);
        let windows: Vec<Window> = state.windows.drain().map(|(_, w)| w).collect();
        out.extend(windows.into_iter().filter_map(Window::into_summary));
        out.extend(state.overflow.take().and_then(Window::into_summary));
        out
    }

    /// Networks with a window open right now, the overflow included.
    pub fn open_windows(&self) -> usize {
        let state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        state.windows.len() + usize::from(state.overflow.is_some())
    }

    async fn write(&self, emitter: &EventEmitter, summaries: Vec<CommandSummary>) {
        if summaries.is_empty() {
            return;
        }
        let (now, now_utc) = (Instant::now(), Utc::now());
        for summary in &summaries {
            let event = command_summary_event(summary, self.window, now, now_utc);
            if let Err(e) = emitter.append(&event).await {
                tracing::error!(error = %e, sensor = %summary.sensor, "failed to append command summary");
            }
        }
    }

    /// Write every summary still accumulating, ended or not, stamped with `arrival`. Called at
    /// shutdown once the listener has stopped; bounded by the window table's capacity.
    pub async fn flush(&self, emitter: &EventEmitter, arrival: Arrival) {
        let summaries = self.drain();
        arrival::scope(arrival, self.write(emitter, summaries)).await;
    }

    /// Start the task that writes each summary once its window ends, stamped with `arrival` (the
    /// sensor's listener port; a summary is written outside every connection's scope).
    pub fn spawn_writer(
        self: &Arc<Self>,
        emitter: Arc<EventEmitter>,
        arrival: Arrival,
    ) -> JoinHandle<()> {
        let gate = self.clone();
        tokio::spawn(arrival::scope(arrival, async move {
            let mut ticker = tokio::time::interval(gate.emit_interval());
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                ticker.tick().await;
                let due = gate.take_due(Instant::now());
                gate.write(&emitter, due).await;
            }
        }))
    }
}

/// One handle for a listener and the summary writer that serves it: aborting it, or the listener
/// ending, stops both.
pub fn with_writer(listener: JoinHandle<()>, writer: JoinHandle<()>) -> JoinHandle<()> {
    struct AbortOnDrop([tokio::task::AbortHandle; 2]);
    impl Drop for AbortOnDrop {
        fn drop(&mut self) {
            for handle in &self.0 {
                handle.abort();
            }
        }
    }
    let guard = AbortOnDrop([listener.abort_handle(), writer.abort_handle()]);
    tokio::spawn(async move {
        let _guard = guard;
        let _ = listener.await;
    })
}

/// One network's suppressed command events over one window, as one `honeypot_command_exec`
/// marked `command_summary: true`. The source, sensor, WAN address and authentication are the
/// first suppressed event's; `command` is a readable line for the timeline, `suppressed_count`
/// the events it stands for. `first_seen` and `last_seen` are wall-clock times reconstructed
/// from the monotonic instants at emission. The session id is fresh: the commands came from up to
/// `session_count` sessions, none of which the summary belongs to alone.
pub fn command_summary_event(
    s: &CommandSummary,
    window: Duration,
    now: Instant,
    now_utc: DateTime<Utc>,
) -> SensorEvent {
    let wall = |at: Instant| {
        let ago = chrono::Duration::from_std(now.saturating_duration_since(at)).unwrap_or_default();
        (now_utc - ago).to_rfc3339_opts(SecondsFormat::Millis, true)
    };
    let source_prefix = match s.key {
        Some(key) => key.to_string(),
        None => "overflow".to_string(),
    };
    let mut metadata = json!({
        "protocol_label": s.sensor,
        "command": format!(
            "<{} repeated commands from {source_prefix} summarized; the first of each command \
             shape is logged in full>",
            s.count
        ),
        COMMAND_SUMMARY_KEY: true,
        "source_prefix": source_prefix,
        "suppressed_count": s.count,
        "distinct_commands": s.distinct_commands,
        "distinct_commands_capped": s.distinct_commands_capped,
        "samples": s.samples,
        "first_seen": wall(s.first_seen),
        "last_seen": wall(s.last_seen),
        "window_secs": window.as_secs_f64(),
        "session_count": s.sessions as u64,
        "session_count_capped": s.sessions_capped,
    });
    if let (Some(file), Some(index), Some(obj)) = (
        &s.assembled_file,
        s.max_chunk_index,
        metadata.as_object_mut(),
    ) {
        obj.insert("assembled_file".to_string(), json!(file));
        obj.insert("max_chunk_index".to_string(), json!(index));
    }
    SensorEvent {
        v: WIRE_VERSION,
        source_ip: s.first_source,
        wan_ip: s.wan_ip,
        sensor: s.sensor.clone(),
        signal_type: SIGNAL_HONEYPOT_COMMAND_EXEC.into(),
        protocol: PROTO_TCP.into(),
        authenticated: s.authenticated,
        observed_at: now_utc,
        metadata,
        sample: None,
        session_id: Some(Uuid::now_v7()),
        occurrence_id: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sensor_wire::{
        SIGNAL_HONEYPOT_CONNECTION, SIGNAL_HONEYPOT_FILE_DOWNLOAD, SIGNAL_HONEYPOT_LOGIN_ATTEMPT,
        SIGNAL_HONEYPOT_MALWARE_UPLOAD,
    };

    fn gate(rate: u32, burst: u32) -> CommandEventGate {
        CommandEventGate::new(CommandEventConfig {
            rate: Rate::new(
                NonZeroU32::new(rate).unwrap(),
                NonZeroU32::new(burst).unwrap(),
            ),
            ..CommandEventConfig::default()
        })
    }

    fn event(source: &str, signal: &str, metadata: Value, session: Uuid) -> SensorEvent {
        SensorEvent {
            v: WIRE_VERSION,
            source_ip: source.parse().unwrap(),
            wan_ip: Some("192.0.2.10".parse().unwrap()),
            sensor: "telnet".into(),
            signal_type: signal.into(),
            protocol: PROTO_TCP.into(),
            authenticated: true,
            observed_at: Utc::now(),
            metadata,
            sample: None,
            session_id: Some(session),
            occurrence_id: None,
        }
    }

    fn command(source: &str, line: &str, session: Uuid) -> SensorEvent {
        event(
            source,
            SIGNAL_HONEYPOT_COMMAND_EXEC,
            json!({"protocol_label": "telnet", "command": line}),
            session,
        )
    }

    fn logged(gate: &CommandEventGate, e: &SensorEvent, now: Instant) -> bool {
        gate.admit_at(e, now) == Admission::Logged
    }

    #[test]
    fn a_repeated_command_gets_the_burst_then_the_rate() {
        let g = gate(2, 10);
        let s = Uuid::now_v7();
        let t0 = Instant::now();
        let e = command("198.51.100.7", "uname -a", s);
        let got = (0..50).filter(|_| logged(&g, &e, t0)).count();
        assert_eq!(got, 10, "the burst, the first sighting among it");
        assert!(!logged(&g, &e, t0 + Duration::from_millis(499)));
        assert!(logged(&g, &e, t0 + Duration::from_millis(500)));
        assert!(!logged(&g, &e, t0 + Duration::from_millis(500)));
        let summaries = g.drain();
        assert_eq!(summaries.len(), 1);
        assert_eq!(summaries[0].count, 40 + 1 + 1);
        assert_eq!(summaries[0].distinct_commands, 1);
        assert_eq!(summaries[0].samples, vec!["uname -a".to_string()]);
    }

    #[test]
    fn a_new_command_is_logged_in_full_even_over_budget_once_per_window() {
        let g = gate(1, 1);
        let s = Uuid::now_v7();
        let t0 = Instant::now();
        assert!(logged(&g, &command("198.51.100.7", "id", s), t0));
        assert!(!logged(&g, &command("198.51.100.7", "id", s), t0));
        // The bucket is empty, and still each new command shows once.
        for line in ["uname -a", "cat /proc/cpuinfo", "busybox BOTNET"] {
            assert!(logged(&g, &command("198.51.100.7", line, s), t0), "{line}");
            assert!(!logged(&g, &command("198.51.100.7", line, s), t0), "{line}");
        }
        // A new window forgets the sightings: each command shows once more.
        let next = t0 + COMMAND_SUMMARY_WINDOW;
        assert!(logged(&g, &command("198.51.100.7", "id", s), next));
        assert!(!logged(&g, &command("198.51.100.7", "id", s), next));
    }

    #[test]
    fn nothing_but_a_plain_command_event_is_ever_summarized_or_charged() {
        let g = gate(1, 1);
        let s = Uuid::now_v7();
        let t0 = Instant::now();
        let src = "198.51.100.7";
        let never = [
            event(
                src,
                SIGNAL_HONEYPOT_CONNECTION,
                json!({"protocol_label": "telnet"}),
                s,
            ),
            event(
                src,
                SIGNAL_HONEYPOT_LOGIN_ATTEMPT,
                json!({"protocol_label": "telnet", "username": "root"}),
                s,
            ),
            event(
                src,
                SIGNAL_HONEYPOT_FILE_DOWNLOAD,
                json!({"protocol_label": "telnet", "url": "http://198.51.100.23/x"}),
                s,
            ),
            event(
                src,
                SIGNAL_HONEYPOT_FILE_DOWNLOAD,
                json!({"url": "http://198.51.100.23:3912/Mozi.6", "derived_from": "echo_loader_args"}),
                s,
            ),
            event(
                src,
                SIGNAL_HONEYPOT_MALWARE_UPLOAD,
                json!({"capture_reason": "echo_loader", "command": "echo"}),
                s,
            ),
            event(
                src,
                SIGNAL_HONEYPOT_MALWARE_UPLOAD,
                json!({"capture_reason": "exec_stdin"}),
                s,
            ),
            event(
                src,
                SIGNAL_HONEYPOT_MALWARE_UPLOAD,
                json!({"capture_reason": "shell_stdin"}),
                s,
            ),
            event(
                src,
                SIGNAL_HONEYPOT_COMMAND_EXEC,
                json!({"command": "<binary channel data>", "flood": "binary"}),
                s,
            ),
            event(
                src,
                SIGNAL_HONEYPOT_COMMAND_EXEC,
                json!({"command": "<cap>", "flood": "command_cap"}),
                s,
            ),
            event(
                src,
                SIGNAL_HONEYPOT_COMMAND_EXEC,
                json!({"command": "<summary>", COMMAND_SUMMARY_KEY: true}),
                s,
            ),
        ];
        // Spend the one token, then the over-budget source sends each kind many times.
        assert!(logged(&g, &command(src, "id", s), t0));
        for e in &never {
            assert!(!summarizable(e), "{e:?}");
            let mut line = vec![e.clone(); 20];
            g.filter_at(&mut line, t0);
            assert_eq!(line.len(), 20, "{e:?}");
        }
        assert!(g.drain().is_empty(), "none of them reached a summary");
        // And none spent a token: a fresh bucket after the window still has its one.
        let g = gate(1, 1);
        let mut many: Vec<SensorEvent> = never.iter().cycle().take(100).cloned().collect();
        g.filter_at(&mut many, t0);
        assert!(logged(&g, &command(src, "id", s), t0));
        assert!(!logged(&g, &command(src, "id", s), t0));
    }

    #[test]
    fn another_network_has_its_own_budget() {
        let g = gate(1, 3);
        let s = Uuid::now_v7();
        let t0 = Instant::now();
        let flood = command("198.51.100.7", "id", s);
        assert_eq!((0..100).filter(|_| logged(&g, &flood, t0)).count(), 3);
        // A neighbour in the same /24 shares the empty bucket: past its own first event it gets
        // nothing. A different /24 has its own.
        let neighbour = command("198.51.100.200", "id", s);
        assert_eq!((0..100).filter(|_| logged(&g, &neighbour, t0)).count(), 1);
        let other = command("203.0.113.5", "id", s);
        assert_eq!((0..100).filter(|_| logged(&g, &other, t0)).count(), 3);
    }

    #[test]
    fn every_address_of_a_network_gets_its_first_command_event_of_a_window() {
        let g = gate(1, 1);
        let s = Uuid::now_v7();
        let t0 = Instant::now();
        assert!(logged(&g, &command("198.51.100.1", "id", s), t0));
        // Each neighbour repeats a command the network has seen, with the bucket empty.
        for host in 2..=(MAX_TRACKED_ADDRESSES as u8 + 10) {
            let e = command(&format!("198.51.100.{host}"), "id", s);
            let within = (host as usize) <= MAX_TRACKED_ADDRESSES;
            assert_eq!(logged(&g, &e, t0), within, "host .{host}");
            assert!(!logged(&g, &e, t0), "only the first, host .{host}");
        }
        // The next window starts over.
        let next = t0 + COMMAND_SUMMARY_WINDOW;
        assert!(logged(&g, &command("198.51.100.2", "id", s), next));
        assert!(logged(&g, &command("198.51.100.3", "id", s), next));
    }

    #[test]
    fn a_summary_counts_sessions_samples_and_the_highest_loader_chunk() {
        let g = gate(1, 1);
        let t0 = Instant::now();
        let src = "198.51.100.7";
        assert!(logged(&g, &command(src, "id", Uuid::now_v7()), t0));
        let sessions: Vec<Uuid> = (0..40).map(|_| Uuid::now_v7()).collect();
        let chunk = |s: Uuid, index: u64| {
            let mut e = command(src, &format!("echo -ne '\\x{index:02x}' >> .i"), s);
            e.metadata["assembled_file"] = json!("/tmp/.i");
            e.metadata["chunk_index"] = json!(index);
            e
        };
        // Each command's first sighting is logged and every repeat folds; every chunk folds.
        for (n, s) in sessions.iter().enumerate() {
            let at = t0 + Duration::from_millis(n as u64);
            for line in ["uname -a", "id -u", "cat /proc/cpuinfo"] {
                assert_eq!(logged(&g, &command(src, line, *s), at), n == 0, "{line}");
            }
            let index = [7u64, 40, 12][n % 3];
            assert!(!logged(&g, &chunk(*s, index), at));
        }
        let s = g.take_due(t0 + COMMAND_SUMMARY_WINDOW);
        assert_eq!(s.len(), 1);
        let s = &s[0];
        assert_eq!(s.key, Some(SourceKey::V4([198, 51, 100])));
        assert_eq!(s.count, 39 * 3 + 40);
        assert_eq!(s.distinct_commands, 4, "three commands and one chunk shape");
        assert!(!s.distinct_commands_capped);
        assert_eq!(s.samples.len(), 4);
        assert_eq!(s.sessions, MAX_SUMMARY_SESSIONS);
        assert!(s.sessions_capped, "40 sessions counted to the cap");
        assert_eq!(s.max_chunk_index, Some(40));
        assert_eq!(s.assembled_file.as_deref(), Some("/tmp/.i"));
        assert_eq!(s.first_seen, t0);
        assert_eq!(s.last_seen, t0 + Duration::from_millis(39));
        assert_eq!(g.open_windows(), 0);
    }

    #[test]
    fn samples_are_distinct_sanitized_bounded_and_eight_at_most() {
        let g = gate(1, 1);
        let s = Uuid::now_v7();
        let t0 = Instant::now();
        let src = "198.51.100.7";
        assert!(logged(&g, &command(src, "warmup", s), t0));
        let long = format!("echo {}\r\nforged", "A".repeat(2000));
        for i in 0..20 {
            let line = if i == 0 {
                long.clone()
            } else {
                format!("cmd{i}")
            };
            assert!(logged(&g, &command(src, &line, s), t0), "first sighting");
            assert!(!logged(&g, &command(src, &line, s), t0));
            assert!(!logged(&g, &command(src, &line, s), t0));
        }
        let s = &g.drain()[0];
        assert_eq!(s.count, 40);
        assert_eq!(s.distinct_commands, 20);
        assert_eq!(s.samples.len(), MAX_SUMMARY_SAMPLES);
        assert!(s.samples[0].len() <= MAX_COMMAND_SAMPLE_LEN);
        assert!(!s.samples[0].contains('\r') && !s.samples[0].contains('\n'));
    }

    #[test]
    fn take_due_keeps_open_windows_and_skips_windows_that_suppressed_nothing() {
        let g = gate(1, 100);
        let s = Uuid::now_v7();
        let t0 = Instant::now();
        assert!(logged(&g, &command("192.0.2.1", "id", s), t0));
        assert_eq!(g.open_windows(), 1);
        assert!(g.take_due(t0 + COMMAND_SUMMARY_WINDOW).is_empty());
        assert_eq!(g.open_windows(), 0, "an ended window is forgotten");

        let g = gate(1, 1);
        assert!(logged(&g, &command("192.0.2.1", "id", s), t0));
        assert!(!logged(&g, &command("192.0.2.1", "id", s), t0));
        assert!(logged(
            &g,
            &command("198.51.100.1", "id", s),
            t0 + Duration::from_secs(30)
        ));
        assert!(!logged(
            &g,
            &command("198.51.100.1", "id", s),
            t0 + Duration::from_secs(30)
        ));
        assert!(g.take_due(t0 + Duration::from_secs(59)).is_empty());
        let due = g.take_due(t0 + COMMAND_SUMMARY_WINDOW);
        assert_eq!(due.len(), 1);
        assert_eq!(due[0].key, Some(SourceKey::V4([192, 0, 2])));
        assert_eq!(g.open_windows(), 1);
        assert_eq!(g.drain().len(), 1, "shutdown takes the open one");
        assert_eq!(g.open_windows(), 0);
    }

    #[test]
    fn a_window_that_ends_under_traffic_parks_its_summary_for_the_writer() {
        let g = gate(1, 1);
        let s = Uuid::now_v7();
        let t0 = Instant::now();
        let e = command("192.0.2.1", "id", s);
        assert!(logged(&g, &e, t0));
        assert!(!logged(&g, &e, t0));
        // No writer ran; the next command after the window rolls it.
        let next = t0 + COMMAND_SUMMARY_WINDOW + Duration::from_secs(5);
        assert!(logged(&g, &e, next), "a first sighting of the new window");
        assert!(!logged(&g, &e, next));
        let due = g.take_due(next);
        assert_eq!(due.len(), 1, "the parked summary, not the open one");
        assert_eq!(due[0].count, 1);
        assert_eq!(g.drain()[0].count, 1);
    }

    #[test]
    fn a_full_window_table_folds_new_networks_into_one_overflow_summary() {
        let mut config = CommandEventConfig {
            rate: Rate::new(NonZeroU32::MIN, NonZeroU32::MIN),
            ..CommandEventConfig::default()
        };
        config.window_capacity = NonZeroUsize::new(4).unwrap();
        let g = CommandEventGate::new(config);
        let s = Uuid::now_v7();
        let t0 = Instant::now();
        for net in 0..10u8 {
            let src = format!("10.0.{net}.1");
            assert!(logged(&g, &command(&src, "id", s), t0));
            for _ in 0..5 {
                assert!(!logged(&g, &command(&src, "id", s), t0));
            }
        }
        assert_eq!(g.open_windows(), 5);
        let mut all = g.drain();
        all.sort_by_key(|s| s.key.is_none());
        let overflow = all.last().unwrap();
        assert_eq!(overflow.key, None);
        assert_eq!(overflow.count, 30);
        assert!(overflow.distinct_commands_capped);
        assert_eq!(all.iter().map(|s| s.count).sum::<u64>(), 50);
    }

    #[test]
    fn the_seen_set_is_bounded_and_says_so() {
        let g = gate(1, 1);
        let s = Uuid::now_v7();
        let t0 = Instant::now();
        let src = "198.51.100.7";
        let firsts = (0..MAX_TRACKED_COMMANDS + 50)
            .filter(|i| logged(&g, &command(src, &format!("c{i}"), s), t0))
            .count();
        assert_eq!(
            firsts, MAX_TRACKED_COMMANDS,
            "past the bound a new command goes by the budget"
        );
        let s = &g.drain()[0];
        assert_eq!(s.count, 50);
        assert!(s.distinct_commands_capped);
    }

    /// `\xNN` escapes of `bytes`, as the loader types them.
    fn escaped(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("\\x{b:02x}")).collect()
    }

    /// The observed Mozi echo-loader session, 53 lines, with its stage-2 address replaced by an
    /// RFC 5737 one. `marker` is the session's echo marker (fixed in the sample, random in other
    /// loaders of the family). Each line comes with the chunk number it writes, if any.
    fn observed_session(marker: &[u8]) -> Vec<(String, Option<u64>)> {
        let marker = escaped(marker);
        let mut lines: Vec<(String, Option<u64>)> = [
            "start",
            "enable",
            "config terminal",
            "system",
            "linuxshell",
            "su",
            "shell",
            "sh",
        ]
        .iter()
        .map(|s| (s.to_string(), None))
        .collect();
        let mut push = |line: String, chunk: Option<u64>| lines.push((line, chunk));
        push(
            format!(
                ">/var/run/.x&&cd /var/run;>/mnt/.x&&cd /mnt;>/usr/.x&&cd /usr;>/dev/.x&&cd /dev;\
                 >/dev/shm/.x&&cd /dev/shm;>/tmp/.x&&cd /tmp;>/var/.x&&cd /var;\
                 /bin/busybox echo -e '{marker}'"
            ),
            None,
        );
        push(
            format!("/bin/busybox wget;/bin/busybox echo -ne '{marker}'"),
            None,
        );
        push("/bin/busybox cat /bin/ls|head -n 1".to_string(), None);
        push(
            "/bin/busybox hexdump -e '16/1 \"%c\"' -n 52 /bin/ls".to_string(),
            None,
        );
        for chunk in 1..=40u64 {
            let body: Vec<u8> = (0..50u8)
                .map(|b| b.wrapping_mul(31).wrapping_add(chunk as u8))
                .collect();
            let body = escaped(&body);
            let line = match chunk {
                1 => format!(
                    "/bin/busybox echo -ne '{body}' > .i; >.x && /bin/busybox echo -en '{marker}'"
                ),
                40 => format!(
                    "/bin/busybox echo -ne '{body}' >> .i; /bin/busybox chmod 777 .i || \
                     (cp /bin/ls .j && cat .i>.j &&rm .i && cp .j .i &&rm .j) && \
                     /bin/busybox echo -en '{marker}'"
                ),
                _ => format!(
                    "/bin/busybox echo -ne '{body}' >> .i; >.x && /bin/busybox echo -en '{marker}'"
                ),
            };
            push(line, Some(chunk));
        }
        push(
            "./.i 198 51 100 23 3912;./Runn;/bin/busybox echo -e \
             '\\x4d\\x4f\\x57\\x48\\x4c\\x42\\x58\\x54'"
                .to_string(),
            None,
        );
        assert_eq!(lines.len(), 53);
        lines
    }

    fn loader_event(line: &str, chunk: Option<u64>, session: Uuid) -> SensorEvent {
        let mut e = command("198.51.100.7", line, session);
        if let Some(index) = chunk {
            e.metadata["assembled_file"] = json!("/var/.i");
            e.metadata["chunk_index"] = json!(index);
        }
        e
    }

    #[test]
    fn the_shape_takes_out_escapes_hex_and_base64_and_collapses_whitespace() {
        assert_eq!(
            command_shape("busybox echo -ne '\\x7f\\x45\\x4c\\x46\\x02' >> .i"),
            "busybox echo -ne '<esc>' >> .i"
        );
        assert_eq!(
            command_shape("printf '\\177\\105\\114F' > a"),
            "printf '<esc>F' > a"
        );
        assert_eq!(command_shape("echo -e '\\x4\\x41'"), "echo -e '<esc>'");
        assert_eq!(
            command_shape("echo 9f86d081884c7d659a2feaa0c55ad015 > /tmp/id"),
            "echo <hex> > /tmp/id"
        );
        assert_eq!(
            command_shape("echo dGhpcyBpcyBhIHRlc3Qgb2YgYmFzZTY0IQ== | base64 -d"),
            "echo <b64> | base64 -d"
        );
        assert_eq!(command_shape("  uname   -a\t\n"), "uname -a");
        // Short hex, words, paths and plain escapes stay: they are what tells commands apart.
        for kept in [
            "echo deadbeef",
            "cat /usr/share/doc/something/changelog",
            "/bin/busybox ECCHI",
            "echo -e 'a\\nb'",
            "cd /tmp; ls -la",
        ] {
            assert_eq!(command_shape(kept), kept);
        }
    }

    #[test]
    fn the_observed_session_is_sixteen_shapes_whatever_its_marker() {
        use std::collections::BTreeSet;
        let shapes = |marker: &[u8]| -> BTreeSet<String> {
            observed_session(marker)
                .iter()
                .map(|(line, _)| command_shape(line))
                .collect()
        };
        let observed = shapes(b"BKTKER");
        let random = shapes(&[0x9c, 0x13, 0x55, 0xe0, 0x7a, 0x21]);
        assert_eq!(observed, random, "a per-session marker is the same shape");
        // Eight one-word preamble commands, four probes, three chunk forms and the run.
        assert_eq!(observed.len(), 16, "{observed:#?}");
        let chunk_shapes: BTreeSet<String> = observed_session(b"BKTKER")
            .iter()
            .filter(|(_, chunk)| chunk.is_some())
            .map(|(line, _)| command_shape(line))
            .collect();
        assert_eq!(
            chunk_shapes.len(),
            3,
            "40 chunks, first, middle and last form"
        );
    }

    #[test]
    fn a_loader_chunk_is_never_a_first_sighting_and_still_feeds_the_summary() {
        let g = gate(1, 1);
        let s = Uuid::now_v7();
        let t0 = Instant::now();
        assert!(
            logged(&g, &command("198.51.100.7", "id", s), t0),
            "the token"
        );
        let chunk = |index: u64| {
            loader_event(
                &format!("/bin/busybox echo -ne '\\x{index:02x}' >> .i"),
                Some(index),
                s,
            )
        };
        assert!(!logged(&g, &chunk(2), t0), "a new shape, but a chunk");
        assert!(!logged(&g, &chunk(7), t0));
        // From a new address too: a chunk is not that address's first.
        let mut neighbour = chunk(3);
        neighbour.source_ip = "198.51.100.8".parse().unwrap();
        assert!(!logged(&g, &neighbour, t0));
        // The summarized chunks made their shape seen: the same form untagged is no first either.
        assert!(!logged(
            &g,
            &command("198.51.100.7", "/bin/busybox echo -ne '\\x09' >> .i", s),
            t0
        ));
        // A new shape untagged is.
        assert!(logged(&g, &command("198.51.100.7", "uname -a", s), t0));
        let s = &g.drain()[0];
        assert_eq!(s.count, 4);
        assert_eq!(s.max_chunk_index, Some(7));
        assert_eq!(s.assembled_file.as_deref(), Some("/var/.i"));
        assert_eq!(s.distinct_commands, 1, "one shape");
        assert!(!s.distinct_commands_capped);
    }

    /// The observed loop: the 53-line session, four at once from one address, a new round every
    /// 30 s for ten minutes, each session with its own random marker.
    #[test]
    fn the_observed_loader_loop_is_bounded_by_burst_rate_shapes_and_addresses() {
        let g = CommandEventGate::new(CommandEventConfig::default());
        let t0 = Instant::now();
        let (mut logged_count, mut total) = (0u64, 0u64);
        let minutes = 10u64;
        let mut at = Duration::ZERO;
        let mut round = 0u8;
        while at < Duration::from_secs(60 * minutes) {
            for parallel in 0..4u8 {
                let id = Uuid::now_v7();
                let marker = [
                    round,
                    parallel,
                    0x5a,
                    round ^ 0xa5,
                    parallel.wrapping_mul(17),
                    0x42,
                ];
                for (i, (line, chunk)) in observed_session(&marker).iter().enumerate() {
                    // About 29 s per session, as observed.
                    let now = t0 + at + Duration::from_millis(i as u64 * 550);
                    let mut events = vec![loader_event(line, *chunk, id)];
                    g.filter_at(&mut events, now);
                    total += 1;
                    logged_count += events.len() as u64;
                }
            }
            at += Duration::from_secs(30);
            round = round.wrapping_add(1);
        }
        let mut summaries = g.take_due(t0 + Duration::from_secs(60 * minutes + 60));
        summaries.extend(g.drain());
        let summarized: u64 = summaries.iter().map(|s| s.count).sum();
        assert_eq!(
            logged_count + summarized,
            total,
            "every command counted once"
        );
        let windows = minutes + 1;
        // Sixteen shapes, of which the three chunk forms are never firsts; one address.
        let (shapes, addresses) = (13u64, 1u64);
        let bound = u64::from(DEFAULT_COMMAND_EVENT_BURST)
            + u64::from(DEFAULT_COMMAND_EVENTS_PER_MIN) * (minutes + 1)
            + shapes * windows
            + addresses * windows;
        eprintln!(
            "observed loop, {minutes} min: {total} command events ungated, {logged_count} \
             individual with the gate, {} summaries, bound {bound}",
            summaries.len()
        );
        assert_eq!(total, 20 * 4 * 53);
        assert!(
            logged_count <= bound,
            "{logged_count} individual events past the bound {bound}"
        );
        assert!(
            summaries.len() as u64 <= windows,
            "{} summaries",
            summaries.len()
        );
        assert!(summaries.iter().all(|s| s.max_chunk_index.is_some()));
        assert!(summaries.iter().any(|s| s.max_chunk_index == Some(40)));
    }

    #[test]
    fn config_reads_rate_and_burst_strictly() {
        let lookup = |pairs: &'static [(&'static str, &'static str)]| {
            move |var: &str| -> Result<Option<String>, EnvError> {
                Ok(pairs
                    .iter()
                    .find(|(k, _)| *k == var)
                    .map(|(_, v)| v.to_string()))
            }
        };
        assert_eq!(
            command_event_vars("telnet"),
            (
                "PROPOLIS_TELNET_COMMAND_EVENT_RATE_PER_MIN".to_string(),
                "PROPOLIS_TELNET_COMMAND_EVENT_BURST".to_string()
            )
        );
        let default = CommandEventConfig::from_lookup("ssh", lookup(&[])).unwrap();
        assert_eq!(default, CommandEventConfig::default());
        assert_eq!(default.rate.count(), 12);
        assert_eq!(default.rate.period(), Duration::from_secs(60));
        assert_eq!(default.rate.burst(), 200);
        let set = CommandEventConfig::from_lookup(
            "adb",
            lookup(&[
                ("PROPOLIS_ADB_COMMAND_EVENT_RATE_PER_MIN", "5"),
                ("PROPOLIS_ADB_COMMAND_EVENT_BURST", "50"),
                // The per-second spelling never shipped and is not read.
                ("PROPOLIS_ADB_COMMAND_EVENT_RATE", "0"),
            ]),
        )
        .unwrap();
        assert_eq!(
            (set.rate.count(), set.rate.period(), set.rate.burst()),
            (5, Duration::from_secs(60), 50)
        );
        for bad in ["0", "-1", "two", "4294967296", "1.5"] {
            for var in [
                "PROPOLIS_TELNET_COMMAND_EVENT_RATE_PER_MIN",
                "PROPOLIS_TELNET_COMMAND_EVENT_BURST",
            ] {
                let pairs: &'static [(&'static str, &'static str)] =
                    Box::leak(vec![(var, bad)].into_boxed_slice());
                let err = CommandEventConfig::from_lookup("telnet", lookup(pairs)).unwrap_err();
                assert_eq!(
                    err,
                    CommandEventConfigError::Invalid {
                        var: var.to_string(),
                        value: bad.to_string()
                    }
                );
                assert!(err.to_string().contains(var));
            }
        }
        let not_unicode = |var: &str| -> Result<Option<String>, EnvError> {
            Err(EnvError::NotUnicode {
                var: var.to_string(),
            })
        };
        assert!(matches!(
            CommandEventConfig::from_lookup("telnet", not_unicode),
            Err(CommandEventConfigError::Env(_))
        ));
    }

    #[test]
    fn summary_event_shape() {
        let now = Instant::now();
        let now_utc: DateTime<Utc> = "2026-10-07T12:01:00Z".parse().unwrap();
        let mut s = CommandSummary {
            key: Some(SourceKey::V4([198, 51, 100])),
            first_source: "198.51.100.7".parse().unwrap(),
            sensor: "telnet".into(),
            wan_ip: Some("192.0.2.10".parse().unwrap()),
            authenticated: true,
            count: 1834,
            distinct_commands: 53,
            distinct_commands_capped: false,
            samples: vec!["enable".into()],
            first_seen: now - Duration::from_secs(60),
            last_seen: now - Duration::from_millis(500),
            sessions: 9,
            sessions_capped: false,
            assembled_file: Some("/tmp/.i".into()),
            max_chunk_index: Some(41),
        };
        let e = command_summary_event(&s, COMMAND_SUMMARY_WINDOW, now, now_utc);
        assert_eq!(e.signal_type, SIGNAL_HONEYPOT_COMMAND_EXEC);
        assert_eq!(e.protocol, PROTO_TCP);
        assert_eq!(e.sensor, "telnet");
        assert!(e.authenticated);
        assert_eq!(e.source_ip, s.first_source);
        assert_eq!(e.wan_ip, s.wan_ip);
        assert!(e.session_id.is_some() && e.sample.is_none());
        assert!(!summarizable(&e), "a summary is never summarized again");
        let md = &e.metadata;
        let mut keys: Vec<&str> = md.as_object().unwrap().keys().map(String::as_str).collect();
        keys.sort_unstable();
        let mut want = vec![
            "protocol_label",
            "command",
            "command_summary",
            "source_prefix",
            "suppressed_count",
            "distinct_commands",
            "distinct_commands_capped",
            "samples",
            "first_seen",
            "last_seen",
            "window_secs",
            "session_count",
            "session_count_capped",
            "assembled_file",
            "max_chunk_index",
        ];
        want.sort_unstable();
        assert_eq!(keys, want);
        assert_eq!(md["command_summary"], true);
        assert_eq!(
            md["command"],
            "<1834 repeated commands from 198.51.100.0/24 summarized; the first of each command \
             shape is logged in full>"
        );
        assert_eq!(md["suppressed_count"], 1834);
        assert_eq!(md["distinct_commands"], 53);
        assert_eq!(md["first_seen"], "2026-10-07T12:00:00.000Z");
        assert_eq!(md["last_seen"], "2026-10-07T12:00:59.500Z");
        assert_eq!(md["window_secs"], 60.0);
        assert_eq!(md["session_count"], 9);
        assert_eq!(md["assembled_file"], "/tmp/.i");
        assert_eq!(md["max_chunk_index"], 41);

        s.key = None;
        s.assembled_file = None;
        s.max_chunk_index = None;
        let e = command_summary_event(&s, COMMAND_SUMMARY_WINDOW, now, now_utc);
        assert_eq!(e.metadata["source_prefix"], "overflow");
        assert!(e.metadata.get("assembled_file").is_none());
        assert!(e.metadata.get("max_chunk_index").is_none());
    }

    #[tokio::test]
    async fn the_writer_emits_at_window_end_and_flush_takes_the_rest() {
        let dir = tempfile::tempdir().unwrap();
        let log = dir.path().join("events.jsonl");
        let emitter = Arc::new(EventEmitter::new(log.clone()));
        let g = Arc::new(CommandEventGate::new(CommandEventConfig {
            rate: Rate::new(NonZeroU32::MIN, NonZeroU32::MIN),
            window: Duration::from_millis(400),
            ..CommandEventConfig::default()
        }));
        let writer = g.spawn_writer(emitter.clone(), Arrival::new(23));
        let s = Uuid::now_v7();
        for _ in 0..5 {
            let mut line = vec![command("198.51.100.7", "id", s)];
            g.filter(&mut line);
        }
        let read = || -> Vec<SensorEvent> {
            std::fs::read_to_string(&log)
                .unwrap_or_default()
                .lines()
                .map(|l| serde_json::from_str(l).unwrap())
                .collect()
        };
        tokio::time::sleep(Duration::from_millis(150)).await;
        assert!(read().is_empty(), "not before the window ends");
        let deadline = Instant::now() + Duration::from_secs(5);
        while read().is_empty() && Instant::now() < deadline {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        let written = read();
        assert_eq!(written.len(), 1);
        assert_eq!(written[0].metadata["suppressed_count"], 4);
        assert_eq!(
            written[0].metadata["local_port"], 23,
            "stamped with the listener"
        );

        // A window still open at shutdown is flushed.
        let mut line = vec![
            command("203.0.113.9", "id", s),
            command("203.0.113.9", "id", s),
        ];
        g.filter(&mut line);
        assert_eq!(line.len(), 1);
        writer.abort();
        g.flush(&emitter, Arrival::new(23)).await;
        let written = read();
        assert_eq!(written.len(), 2);
        assert_eq!(written[1].metadata["source_prefix"], "203.0.113.0/24");
        assert_eq!(written[1].metadata["local_port"], 23);
    }

    #[tokio::test]
    async fn aborting_the_joined_handle_stops_the_listener_and_the_writer() {
        let listener = tokio::spawn(std::future::pending::<()>());
        let writer = tokio::spawn(std::future::pending::<()>());
        let (l, w) = (listener.abort_handle(), writer.abort_handle());
        let joined = with_writer(listener, writer);
        tokio::task::yield_now().await;
        joined.abort();
        let _ = joined.await;
        tokio::task::yield_now().await;
        assert!(l.is_finished() && w.is_finished());
    }
}
