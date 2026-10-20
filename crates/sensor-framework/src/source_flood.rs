//! Per-source budget for connection and login events, and the summaries of what it suppressed.
//!
//! A credential sensor writes two events per probe (`honeypot_connection`, then
//! `honeypot_login_attempt`) and a scanner fleet probes without end: the VNC listener wrote about
//! ten thousand lines an hour for forty-two hours, 392,838 events from 1,629 addresses, and filled
//! the log volume. A VNC attempt is a DES challenge-response, so each carries little beyond the
//! source, the client version and the count. The command-event budget
//! ([`crate::command_flood`]) cannot see these events, and the per-source connection cap bounds
//! concurrency, not volume.
//!
//! [`SourceEventGate`] counts, per tumbling [`SourceEventConfig::window`], how many connection
//! events and how many login events were written for each source address, each source network
//! (the [`SourceKey`] /24 or /56) and in total. An event is written verbatim while all three are
//! under their budget, except that an address's first event of each kind in a window skips the
//! total: the listener budget caps repeats, so an address's first event of a kind is not folded
//! for others' volume (its own address and network budgets and the table still apply). Past any of
//! them it is not written: it is folded into the pending summary
//! of its own address, and when the window ends each address with anything folded gets one
//! `honeypot_login_attempt` (when an attempt was folded) or `honeypot_connection` event marked
//! `event_summary: true`, carrying the connection and attempt counts, the distinct client versions
//! and usernames seen (a bounded sample), the sessions and the first and last time. The summary is
//! keyed by address, not network, because scoring is per address: the summary is the only record
//! of an address whose events all folded, and it scores as the events it replaces
//! (`core_scoring::scoring::engine::represented_events`).
//!
//! Only `tcp` connection and login events are gated. Everything else (commands, uploads, other
//! summaries) passes untouched and spends nothing.
//!
//! Memory is fixed: at most [`SourceEventConfig::address_capacity`] addresses are tracked per
//! window, each holding at most [`MAX_SUMMARY_VALUES`] versions, as many usernames and
//! [`MAX_SUMMARY_SESSIONS`] session ids. One network holds at most
//! [`SourceEventConfig::network_address_cap`] of them, so one network cannot take the table; its
//! further addresses fold into one per-network summary, and an address that arrives with the table
//! full folds into one overflow summary. Both stand for many addresses, so each is written as a
//! `honeypot_connection` that authenticated nothing, marked `overflow_summary: true`, and scoring
//! counts it as one event with no weight and no confirmed-real latch. The lock is a plain mutex
//! held for a few map updates, never across an `.await`; time is `tokio::time::Instant`, so tests
//! drive it with a paused clock.

use std::collections::HashMap;
use std::net::IpAddr;
use std::num::{NonZeroU32, NonZeroUsize};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use chrono::{DateTime, SecondsFormat, Utc};
use sensor_wire::{
    PROTO_TCP, SIGNAL_HONEYPOT_CONNECTION, SIGNAL_HONEYPOT_LOGIN_ATTEMPT, SensorEvent, WIRE_VERSION,
};
use serde_json::{Value, json};
use tokio::task::JoinHandle;
use tokio::time::Instant;
use uuid::Uuid;

use crate::arrival::{self, Arrival};
use crate::command_flood::MAX_SUMMARY_SESSIONS;
use crate::emit::EventEmitter;
use crate::rate_limit::{DEFAULT_SUMMARY_CAPACITY, SourceKey};
use crate::sanitize_value;

/// The metadata key that marks a connection or login summary event.
pub const EVENT_SUMMARY_KEY: &str = "event_summary";
/// The metadata key set to `true` on the overflow and per-network summaries only. They are
/// attributed to one address but stand for many, so scoring must count one event, not the
/// `suppressed_count`, and must neither weight it nor latch confirmed-real from it.
pub const OVERFLOW_SUMMARY_KEY: &str = "overflow_summary";
/// How long the budgets and the pending summaries last. A source whose events are all folded is
/// seen in the log at most this late.
pub const SOURCE_EVENT_WINDOW: Duration = Duration::from_secs(600);
/// Events of each kind (connection, login) written verbatim per source address per window. The
/// live VNC flood's heaviest address sent about 70 of each per ten minutes, so it costs 20 lines
/// and a summary instead of 140, about 126 lines an hour. Under this budget an event is still
/// folded when its network budget or the table is spent, or, unless it is the address's first of
/// its kind in the window, when the listener budget is.
pub const DEFAULT_ADDRESS_BUDGET: u32 = 10;
/// Events of each kind written verbatim per source network per window, so a /24 of hosts cannot
/// multiply the address budget by 254.
pub const DEFAULT_NETWORK_BUDGET: u32 = 40;
/// Repeat events of each kind written verbatim per window across every source. An address's first
/// event of each kind does not spend it, so it bounds repeats only: a flood spread over many
/// networks writes at most two first sightings per tracked address (2 x 1,024 lines) plus
/// 2 x 200 repeats and up to 1,041 summaries (one per tracked address, one per network at its
/// address cap, one overflow) per window: 3,489 lines at the worst. Measured on the live
/// distribution (5 heavy sources, 1,624 tail sources) that is about 5,800 lines an hour against
/// the 9,300 an hour of the incident, summaries included; a summary line is about twice a verbatim
/// line's size.
pub const DEFAULT_TOTAL_BUDGET: u32 = 200;
/// Addresses one source network (the [`SourceKey`] /24 or /56) may hold in the table per window.
/// Without it one /24, or one IPv6 /64 whose addresses cost nothing, takes the whole 1,024-address
/// table with about 1,024 connections and every later source of the window folds into the single
/// overflow summary, which scoring cannot attribute. 64 is a quarter of a /24 and a sixteenth of
/// the table: a network that large is a scanner fleet, not a few hosts, and filling the table then
/// takes sixteen such networks. Addresses past it fold into one per-network summary.
pub const DEFAULT_NETWORK_ADDRESS_CAP: usize = 64;
/// Distinct client versions and usernames one summary names.
pub const MAX_SUMMARY_VALUES: usize = 8;
/// Longest version or username kept in a summary, after sanitization.
pub const MAX_SUMMARY_VALUE_LEN: usize = 128;
/// The shortest window a config can ask for: a zero window would end on every event and disable
/// the budget.
const MIN_WINDOW: Duration = Duration::from_millis(50);
/// The shortest and longest wait between looks for an ended window.
const MIN_EMIT_INTERVAL: Duration = Duration::from_millis(10);
const MAX_EMIT_INTERVAL: Duration = Duration::from_secs(1);

/// A sensor's connection and login event budget.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SourceEventConfig {
    pub window: Duration,
    pub address_budget: NonZeroU32,
    pub network_budget: NonZeroU32,
    pub total_budget: NonZeroU32,
    pub address_capacity: NonZeroUsize,
    /// Addresses one source network may hold in the table per window.
    pub network_address_cap: NonZeroUsize,
}

impl Default for SourceEventConfig {
    fn default() -> Self {
        let nz = |n: u32| NonZeroU32::new(n).unwrap_or(NonZeroU32::MIN);
        Self {
            window: SOURCE_EVENT_WINDOW,
            address_budget: nz(DEFAULT_ADDRESS_BUDGET),
            network_budget: nz(DEFAULT_NETWORK_BUDGET),
            total_budget: nz(DEFAULT_TOTAL_BUDGET),
            address_capacity: NonZeroUsize::new(DEFAULT_SUMMARY_CAPACITY)
                .unwrap_or(NonZeroUsize::MIN),
            network_address_cap: NonZeroUsize::new(DEFAULT_NETWORK_ADDRESS_CAP)
                .unwrap_or(NonZeroUsize::MIN),
        }
    }
}

/// Which budget an event is charged to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    Connection,
    Login,
}

impl Kind {
    fn of(event: &SensorEvent) -> Option<Self> {
        if event.protocol != PROTO_TCP || event.metadata.get(EVENT_SUMMARY_KEY).is_some() {
            return None;
        }
        match event.signal_type.as_str() {
            SIGNAL_HONEYPOT_CONNECTION => Some(Kind::Connection),
            SIGNAL_HONEYPOT_LOGIN_ATTEMPT => Some(Kind::Login),
            _ => None,
        }
    }

    fn slot(self) -> usize {
        match self {
            Kind::Connection => 0,
            Kind::Login => 1,
        }
    }
}

/// What the gate decided for one event.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SourceAdmission {
    /// Written as its own event (also: an event the gate does not govern).
    Logged,
    /// Counted into its address's summary instead.
    Summarized,
}

/// Whom a summary is about.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SummaryScope {
    /// One tracked address; scoring attributes it to that address.
    Address(SourceKey),
    /// Addresses that arrived after their network already held its share of the table.
    Network(SourceKey),
    /// Addresses that arrived while the table was full.
    Overflow,
}

impl SummaryScope {
    /// Whether the summary stands for many addresses and so belongs to none of them.
    pub fn is_unattributed(self) -> bool {
        !matches!(self, SummaryScope::Address(_))
    }
}

/// One address's (or a network's, or the overflow's) suppressed connection and login events over
/// one window.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceSummary {
    /// What the summary stands for.
    pub scope: SummaryScope,
    /// The address the summary is about; for a network or overflow summary, the first address
    /// folded into it.
    pub source: IpAddr,
    pub sensor: String,
    pub wan_ip: Option<IpAddr>,
    pub connections: u64,
    pub attempts: u64,
    /// Distinct client versions and usernames, at most [`MAX_SUMMARY_VALUES`] each.
    pub client_versions: Vec<String>,
    pub client_versions_capped: bool,
    pub usernames: Vec<String>,
    pub usernames_capped: bool,
    pub first_seen: Instant,
    pub last_seen: Instant,
    /// Distinct sessions folded, at most [`MAX_SUMMARY_SESSIONS`].
    pub sessions: usize,
    pub sessions_capped: bool,
}

impl SourceSummary {
    /// The events this summary stands for.
    pub fn count(&self) -> u64 {
        self.connections.saturating_add(self.attempts)
    }
}

#[derive(Debug)]
struct Pending {
    summary: SourceSummary,
    session_ids: Vec<Uuid>,
}

impl Pending {
    fn new(scope: SummaryScope, event: &SensorEvent, now: Instant) -> Self {
        Self {
            summary: SourceSummary {
                scope,
                source: event.source_ip,
                sensor: event.sensor.clone(),
                wan_ip: event.wan_ip,
                connections: 0,
                attempts: 0,
                client_versions: Vec::new(),
                client_versions_capped: false,
                usernames: Vec::new(),
                usernames_capped: false,
                first_seen: now,
                last_seen: now,
                sessions: 0,
                sessions_capped: false,
            },
            session_ids: Vec::new(),
        }
    }

    fn fold(&mut self, kind: Kind, event: &SensorEvent, now: Instant) {
        let s = &mut self.summary;
        match kind {
            Kind::Connection => s.connections = s.connections.saturating_add(1),
            Kind::Login => s.attempts = s.attempts.saturating_add(1),
        }
        s.last_seen = now;
        note_value(
            &mut s.client_versions,
            &mut s.client_versions_capped,
            event.metadata.get("client_version"),
        );
        note_value(
            &mut s.usernames,
            &mut s.usernames_capped,
            event.metadata.get("username"),
        );
        if let Some(id) = event.session_id
            && !self.session_ids.contains(&id)
        {
            if self.session_ids.len() < MAX_SUMMARY_SESSIONS {
                self.session_ids.push(id);
            } else {
                s.sessions_capped = true;
            }
        }
        s.sessions = self.session_ids.len();
    }
}

/// Keep `value` in `into` when it is a non-empty string not already there and there is room;
/// otherwise remember that the list is incomplete.
fn note_value(into: &mut Vec<String>, capped: &mut bool, value: Option<&Value>) {
    let Some(text) = value.and_then(Value::as_str).filter(|t| !t.is_empty()) else {
        return;
    };
    let text = sanitize_value(text, MAX_SUMMARY_VALUE_LEN);
    if into.contains(&text) {
        return;
    }
    if into.len() < MAX_SUMMARY_VALUES {
        into.push(text);
    } else {
        *capped = true;
    }
}

#[derive(Debug, Default)]
struct Address {
    written: [u32; 2],
    pending: Option<Pending>,
}

#[derive(Debug, Default)]
struct Network {
    written: [u32; 2],
    /// Tracked addresses of this network in the window.
    addresses: usize,
    /// Addresses refused a table slot because the network already held its share.
    pending: Option<Pending>,
}

#[derive(Debug)]
struct State {
    started: Instant,
    total: [u32; 2],
    networks: HashMap<SourceKey, Network>,
    addresses: HashMap<IpAddr, Address>,
    overflow: Option<Pending>,
    /// Summaries of windows that ended while an event arrived, before the writer took them.
    ready: Vec<SourceSummary>,
    /// Summaries that found `ready` full (only when no writer runs); logged, never unbounded.
    dropped: u64,
}

/// A sensor's per-source connection and login budget and the summaries of what it suppressed. One
/// per listener, attached to its [`EventEmitter`] so every handler is covered by the one
/// chokepoint.
#[derive(Debug)]
pub struct SourceEventGate {
    state: Mutex<State>,
    window: Duration,
    address_budget: u32,
    network_budget: u32,
    total_budget: u32,
    capacity: usize,
    network_address_cap: usize,
}

impl SourceEventGate {
    pub fn new(config: SourceEventConfig) -> Self {
        Self::new_at(config, Instant::now())
    }

    /// A gate whose first window began at `now`.
    pub fn new_at(config: SourceEventConfig, now: Instant) -> Self {
        let capacity = config.address_capacity.get();
        Self {
            state: Mutex::new(State {
                started: now,
                total: [0; 2],
                networks: HashMap::with_capacity(capacity),
                addresses: HashMap::with_capacity(capacity),
                overflow: None,
                ready: Vec::new(),
                dropped: 0,
            }),
            window: config.window.max(MIN_WINDOW),
            address_budget: config.address_budget.get(),
            network_budget: config.network_budget.get(),
            total_budget: config.total_budget.get(),
            capacity,
            network_address_cap: config.network_address_cap.get(),
        }
    }

    pub fn window(&self) -> Duration {
        self.window
    }

    /// How often the writer looks for an ended window: a tenth of the window, clamped.
    pub fn emit_interval(&self) -> Duration {
        (self.window / 10).clamp(MIN_EMIT_INTERVAL, MAX_EMIT_INTERVAL)
    }

    /// Decide one event now.
    pub fn admit(&self, event: &SensorEvent) -> SourceAdmission {
        self.admit_at(event, Instant::now())
    }

    pub fn admit_at(&self, event: &SensorEvent, now: Instant) -> SourceAdmission {
        let Some(kind) = Kind::of(event) else {
            return SourceAdmission::Logged;
        };
        let slot = kind.slot();
        let key = SourceKey::of_ip(event.source_ip);
        let mut guard = self.state.lock().unwrap_or_else(|e| e.into_inner());
        let state = &mut *guard;
        self.rotate(state, now);

        if !state.addresses.contains_key(&event.source_ip) {
            if state.addresses.len() >= self.capacity {
                state
                    .overflow
                    .get_or_insert_with(|| Pending::new(SummaryScope::Overflow, event, now))
                    .fold(kind, event, now);
                return SourceAdmission::Summarized;
            }
            let network = state.networks.entry(key).or_default();
            if network.addresses >= self.network_address_cap {
                network
                    .pending
                    .get_or_insert_with(|| Pending::new(SummaryScope::Network(key), event, now))
                    .fold(kind, event, now);
                return SourceAdmission::Summarized;
            }
            network.addresses += 1;
        }
        let address = state.addresses.entry(event.source_ip).or_default();
        let network = state.networks.entry(key).or_default();
        // An address's first event of each kind in a window is written whenever its own budgets
        // allow, without spending the listener budget: a source seen once is the one a summary
        // serves worst (743 B against 366 B verbatim, and scoring waits a window for it), and the
        // listener budget exists to cap repeats. First sightings are bounded by the address table.
        let first = address.written[slot] == 0;
        if address.written[slot] < self.address_budget
            && network.written[slot] < self.network_budget
            && (first || state.total[slot] < self.total_budget)
        {
            address.written[slot] += 1;
            network.written[slot] += 1;
            if !first {
                state.total[slot] += 1;
            }
            return SourceAdmission::Logged;
        }
        address
            .pending
            .get_or_insert_with(|| Pending::new(SummaryScope::Address(key), event, now))
            .fold(kind, event, now);
        SourceAdmission::Summarized
    }

    /// End the window if `now` is past it: park every pending summary for the writer and start the
    /// budgets over.
    fn rotate(&self, state: &mut State, now: Instant) {
        if state.started + self.window > now {
            return;
        }
        state.started = now;
        state.total = [0; 2];
        let ended: Vec<Pending> = state
            .addresses
            .drain()
            .filter_map(|(_, a)| a.pending)
            .chain(state.networks.drain().filter_map(|(_, n)| n.pending))
            .chain(state.overflow.take())
            .collect();
        for pending in ended {
            if state.ready.len() <= self.ready_limit() {
                state.ready.push(pending.summary);
            } else {
                state.dropped = state.dropped.saturating_add(1);
                if state.dropped.is_power_of_two() {
                    tracing::warn!(
                        dropped_total = state.dropped,
                        "event summaries dropped: no summary writer is taking them"
                    );
                }
            }
        }
    }

    /// The most summaries parked for the writer: one per tracked address, one per network that
    /// reached its share (at most `capacity / network_address_cap` of them), and the overflow.
    fn ready_limit(&self) -> usize {
        self.capacity + self.capacity / self.network_address_cap + 1
    }

    /// The summaries of every window that has ended at `now`.
    pub fn take_due(&self, now: Instant) -> Vec<SourceSummary> {
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        self.rotate(&mut state, now);
        std::mem::take(&mut state.ready)
    }

    /// Every summary, ended or not (shutdown). The budgets stay as they are: the window is not
    /// over, so a source that already spent its budget does not get it back from a flush.
    pub fn drain(&self) -> Vec<SourceSummary> {
        let mut guard = self.state.lock().unwrap_or_else(|e| e.into_inner());
        let state = &mut *guard;
        let mut out = std::mem::take(&mut state.ready);
        out.extend(
            state
                .addresses
                .values_mut()
                .filter_map(|a| a.pending.take())
                .chain(state.networks.values_mut().filter_map(|n| n.pending.take()))
                .chain(state.overflow.take())
                .map(|p| p.summary),
        );
        out
    }

    async fn write(&self, emitter: &EventEmitter, summaries: Vec<SourceSummary>) {
        if summaries.is_empty() {
            return;
        }
        let (now, now_utc) = (Instant::now(), Utc::now());
        for summary in &summaries {
            let event = source_summary_event(summary, self.window, now, now_utc);
            if let Err(e) = emitter.append(&event).await {
                tracing::error!(error = %e, sensor = %summary.sensor, "failed to append event summary");
            }
        }
    }

    /// Write every summary still accumulating, ended or not, stamped with `arrival`. Called at
    /// shutdown once the listener has stopped; bounded by the address table's capacity.
    pub async fn flush(&self, emitter: &EventEmitter, arrival: Arrival) {
        let summaries = self.drain();
        arrival::scope(arrival, self.write(emitter, summaries)).await;
    }

    /// Start the task that writes each window's summaries once it ends, stamped with `arrival`
    /// (the sensor's listener port; a summary is written outside every connection's scope).
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

/// One address's suppressed connection and login events over one window, as the
/// `honeypot_login_attempt` (when an attempt was folded) or `honeypot_connection` one of them
/// would have been, marked `event_summary: true`. `suppressed_count` is the events it stands for:
/// scoring counts that many. A network or overflow summary is always a `honeypot_connection` with
/// `authenticated: false` (the folded attempts stay in `suppressed_attempts`). `first_seen` and
/// `last_seen` are wall-clock times reconstructed from the monotonic instants at emission. The
/// session id is fresh: the events came from up to `session_count` sessions, none of which the
/// summary belongs to alone.
pub fn source_summary_event(
    s: &SourceSummary,
    window: Duration,
    now: Instant,
    now_utc: DateTime<Utc>,
) -> SensorEvent {
    let wall = |at: Instant| {
        let ago = chrono::Duration::from_std(now.saturating_duration_since(at)).unwrap_or_default();
        (now_utc - ago).to_rfc3339_opts(SecondsFormat::Millis, true)
    };
    let source_prefix = match s.scope {
        SummaryScope::Address(key) | SummaryScope::Network(key) => key.to_string(),
        SummaryScope::Overflow => "overflow".to_string(),
    };
    // A summary that stands for many addresses is a connection that authenticated nothing: it is
    // attributed to the first address folded into it, which may only have connected, and a login
    // here would latch that address as confirmed-real. The folded attempt count stays a field.
    let login = s.attempts > 0 && !s.scope.is_unattributed();
    let mut metadata = json!({
            "protocol_label": s.sensor,
            EVENT_SUMMARY_KEY: true,
            "source_prefix": source_prefix,
            "suppressed_count": s.count(),
            "suppressed_connections": s.connections,
            "suppressed_attempts": s.attempts,
            "client_versions": s.client_versions,
            "client_versions_capped": s.client_versions_capped,
            "usernames": s.usernames,
            "usernames_capped": s.usernames_capped,
            "first_seen": wall(s.first_seen),
            "last_seen": wall(s.last_seen),
            "window_secs": window.as_secs_f64(),
            "session_count": s.sessions as u64,
            "session_count_capped": s.sessions_capped,
    });
    if s.scope.is_unattributed() {
        metadata[OVERFLOW_SUMMARY_KEY] = Value::Bool(true);
    }
    SensorEvent {
        v: WIRE_VERSION,
        source_ip: s.source,
        wan_ip: s.wan_ip,
        sensor: s.sensor.clone(),
        signal_type: if login {
            SIGNAL_HONEYPOT_LOGIN_ATTEMPT
        } else {
            SIGNAL_HONEYPOT_CONNECTION
        }
        .into(),
        protocol: PROTO_TCP.into(),
        authenticated: login,
        observed_at: now_utc,
        metadata,
        sample: None,
        session_id: Some(Uuid::now_v7()),
        occurrence_id: None,
        reply: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A gate whose window began at the `Instant` the tests call `t0`.
    fn gate_at(
        t0: Instant,
        address: u32,
        network: u32,
        total: u32,
        capacity: usize,
    ) -> SourceEventGate {
        SourceEventGate::new_at(
            SourceEventConfig {
                address_budget: NonZeroU32::new(address).unwrap(),
                network_budget: NonZeroU32::new(network).unwrap(),
                total_budget: NonZeroU32::new(total).unwrap(),
                address_capacity: NonZeroUsize::new(capacity).unwrap(),
                ..SourceEventConfig::default()
            },
            t0,
        )
    }

    fn event(source: &str, signal: &str, metadata: Value, session: Uuid) -> SensorEvent {
        SensorEvent {
            v: WIRE_VERSION,
            source_ip: source.parse().unwrap(),
            wan_ip: Some("192.0.2.10".parse().unwrap()),
            sensor: "vnc".into(),
            signal_type: signal.into(),
            protocol: PROTO_TCP.into(),
            authenticated: signal == SIGNAL_HONEYPOT_LOGIN_ATTEMPT,
            observed_at: Utc::now(),
            metadata,
            sample: None,
            session_id: Some(session),
            occurrence_id: None,
            reply: None,
        }
    }

    fn connection(source: &str) -> SensorEvent {
        event(
            source,
            SIGNAL_HONEYPOT_CONNECTION,
            json!({"protocol_label": "vnc"}),
            Uuid::now_v7(),
        )
    }

    fn login(source: &str, version: &str) -> SensorEvent {
        event(
            source,
            SIGNAL_HONEYPOT_LOGIN_ATTEMPT,
            json!({"protocol_label": "vnc", "client_version": version}),
            Uuid::now_v7(),
        )
    }

    fn logged(g: &SourceEventGate, e: &SensorEvent, now: Instant) -> bool {
        g.admit_at(e, now) == SourceAdmission::Logged
    }

    #[test]
    fn one_address_gets_its_budget_of_each_kind_then_a_summary_with_exact_totals() {
        let t0 = Instant::now();
        let g = gate_at(t0, 3, 100, 100, 16);
        let written_c = (0..50)
            .filter(|_| logged(&g, &connection("198.51.100.7"), t0))
            .count();
        let written_l = (0..40)
            .filter(|i| {
                let v = if i % 2 == 0 {
                    "RFB 003.008"
                } else {
                    "RFB 003.003"
                };
                logged(&g, &login("198.51.100.7", v), t0)
            })
            .count();
        assert_eq!((written_c, written_l), (3, 3));
        let summaries = g.drain();
        assert_eq!(summaries.len(), 1);
        let s = &summaries[0];
        assert_eq!((s.connections, s.attempts, s.count()), (47, 37, 84));
        assert_eq!(s.source, "198.51.100.7".parse::<IpAddr>().unwrap());
        assert_eq!(s.client_versions, vec!["RFB 003.003", "RFB 003.008"]);
        assert!(!s.client_versions_capped);
        assert_eq!(s.sessions, 32);
        assert!(s.sessions_capped);
    }

    #[test]
    fn another_address_in_another_network_is_unaffected_by_a_flooder() {
        let t0 = Instant::now();
        let g = gate_at(t0, 2, 2, 100, 16);
        for _ in 0..100 {
            g.admit_at(&connection("198.51.100.7"), t0);
        }
        assert!(logged(&g, &connection("203.0.113.9"), t0));
        assert!(logged(&g, &connection("203.0.113.9"), t0));
        assert!(!logged(&g, &connection("203.0.113.9"), t0));
    }

    #[test]
    fn a_network_shares_one_budget_but_each_address_keeps_its_own_summary() {
        let t0 = Instant::now();
        let g = gate_at(t0, 10, 4, 100, 16);
        let a = (0..10)
            .filter(|_| logged(&g, &connection("198.51.100.1"), t0))
            .count();
        let b = (0..10)
            .filter(|_| logged(&g, &connection("198.51.100.2"), t0))
            .count();
        assert_eq!(a + b, 4, "the /24 budget, not 2 x the address budget");
        let mut summaries = g.drain();
        summaries.sort_by_key(|s| s.source);
        assert_eq!(summaries.len(), 2);
        assert_eq!(summaries[0].connections + summaries[1].connections, 16);
    }

    #[test]
    fn the_total_budget_bounds_repeats_but_never_an_addresss_first_event() {
        let t0 = Instant::now();
        let g = gate_at(t0, 10, 10, 5, 64);
        // 20 addresses in 20 networks, each sending a first event: all written.
        for n in 0..20u8 {
            assert!(logged(&g, &connection(&format!("10.0.{n}.1")), t0));
        }
        // Their repeats spend the total: 5 written, the other 15 folded, one summary each.
        let repeats = (0..20u8)
            .filter(|n| logged(&g, &connection(&format!("10.0.{n}.1")), t0))
            .count();
        assert_eq!(repeats, 5);
        assert_eq!(g.drain().len(), 15, "one summary per folded address");
    }

    #[test]
    fn a_first_event_still_obeys_the_address_and_network_budgets() {
        let t0 = Instant::now();
        let g = gate_at(t0, 10, 2, 100, 64);
        assert!(logged(&g, &connection("198.51.100.1"), t0));
        assert!(logged(&g, &connection("198.51.100.2"), t0));
        assert!(
            !logged(&g, &connection("198.51.100.3"), t0),
            "a third address's first event is past the /24 budget"
        );
    }

    #[test]
    fn a_first_login_is_written_even_when_the_connection_budget_is_spent() {
        let t0 = Instant::now();
        let g = gate_at(t0, 10, 100, 1, 64);
        for _ in 0..5 {
            g.admit_at(&connection("198.51.100.1"), t0);
        }
        assert!(logged(&g, &login("198.51.100.1", "RFB 003.008"), t0));
        assert!(logged(&g, &login("198.51.100.2", "RFB 003.008"), t0));
    }

    /// Small deterministic generator (xorshift) so the replay needs no dev-dependency.
    struct Rng(u64);
    impl Rng {
        fn next(&mut self) -> u64 {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 7;
            self.0 ^= self.0 << 17;
            self.0
        }
    }

    fn v4(n: u32) -> String {
        // Loopback only; one /24 per source, as the incident's sources were spread.
        format!("127.{}.{}.1", (n >> 8) & 255, n & 255)
    }

    /// The live VNC distribution: 5 heavy sources at 70 connections and 70 logins per window and
    /// 1,624 tail sources at about 3.2 events an hour (about 0.53 per ten minutes, per kind half).
    /// Through the real gate with the default config: no tail source's first sighting is folded and
    /// the lines written per window stay far under the unbounded count.
    #[test]
    fn the_live_distribution_loses_no_tail_first_sighting() {
        let t0 = Instant::now();
        let g = SourceEventGate::new_at(SourceEventConfig::default(), t0);
        let mut rng = Rng(0x9e37_79b9_7f4a_7c15);
        let (mut folded_first, mut tail_events, mut written) = (0u32, 0u32, 0u32);
        let windows = 6u32;
        for w in 0..windows {
            let base = t0 + g.window() * w;
            let mut seen = std::collections::HashSet::new();
            // An event exactly on the boundary rotates the gate's window onto the replay's.
            let mut events: Vec<(u64, u32, bool)> = vec![(0, 0, false)];
            for heavy in 0..5u32 {
                for _ in 0..70 {
                    events.push((rng.next() % 600_000, heavy, false));
                    events.push((rng.next() % 600_000, heavy, true));
                }
            }
            for tail in 5..(5 + 1624u32) {
                // 3.2 events an hour is 0.53 per window: one probe (a connection and a login)
                // with probability 0.27, two with a few percent more.
                let probes = match rng.next() % 100 {
                    0..=26 => 1,
                    27..=29 => 2,
                    _ => 0,
                };
                for _ in 0..probes {
                    let at = rng.next() % 600_000;
                    events.push((at, tail, false));
                    events.push((at + 1, tail, true));
                }
            }
            events.sort();
            for (ms, src, is_login) in events {
                let now = base + Duration::from_millis(ms);
                let ip = v4(src);
                let e = if is_login {
                    login(&ip, "RFB 003.008")
                } else {
                    connection(&ip)
                };
                let first_of_kind = seen.insert((src, is_login));
                let admitted = logged(&g, &e, now);
                if admitted {
                    written += 1;
                }
                if src >= 5 {
                    tail_events += 1;
                    if first_of_kind && !admitted {
                        folded_first += 1;
                    }
                }
            }
        }
        assert!(tail_events > 1000, "the replay must exercise the tail");
        assert_eq!(folded_first, 0, "of {tail_events} tail events");
        // 5 heavy sources write 2 x 10 each and the tail about 400 first sightings a window; the
        // bound is the gate's worst case, not a tuned figure.
        assert!(
            written / windows <= 5 * 20 + 2 * 1024 + 2 * 200,
            "{written}"
        );
    }

    /// A flood from more addresses than the table holds, each sending a connection and a login
    /// many times: lines per window are bounded by two first sightings per tracked address, the
    /// listener budget for repeats and one summary per tracked address plus the overflow.
    #[test]
    fn a_distributed_flood_is_bounded_per_window() {
        let t0 = Instant::now();
        let config = SourceEventConfig::default();
        let capacity = config.address_capacity.get();
        let g = SourceEventGate::new_at(config, t0);
        let sources = (capacity as u32) + 500;
        let mut written = 0usize;
        for round in 0..30 {
            for n in 0..sources {
                let ip = v4(n);
                if logged(&g, &connection(&ip), t0 + Duration::from_millis(round)) {
                    written += 1;
                }
                if logged(
                    &g,
                    &login(&ip, "RFB 003.008"),
                    t0 + Duration::from_millis(round),
                ) {
                    written += 1;
                }
            }
        }
        let summaries = g.drain().len();
        let bound = 2 * capacity + 2 * DEFAULT_TOTAL_BUDGET as usize;
        assert!(written <= bound, "{written} verbatim lines, bound {bound}");
        assert!(summaries <= capacity + 1, "{summaries} summaries");
        assert!(written + summaries <= bound + capacity + 1);
        let events = (30 * sources * 2) as usize;
        assert!(
            written + summaries < events / 10,
            "{} lines for {events} events",
            written + summaries
        );
    }

    #[test]
    fn only_the_overflow_summary_carries_the_overflow_flag() {
        let t0 = Instant::now();
        let g = gate_at(t0, 1, 100, 100, 1);
        for src in ["198.51.100.1", "198.51.100.2", "198.51.100.3"] {
            g.admit_at(&connection(src), t0);
            g.admit_at(&connection(src), t0);
        }
        let mut flagged = 0;
        for s in g.drain() {
            let e = source_summary_event(&s, g.window(), t0, Utc::now());
            let overflow = e.metadata.get(OVERFLOW_SUMMARY_KEY) == Some(&Value::Bool(true));
            assert_eq!(overflow, s.scope == SummaryScope::Overflow);
            flagged += usize::from(overflow);
        }
        assert_eq!(flagged, 1);
    }

    #[test]
    fn a_new_window_restores_every_budget_and_hands_over_the_summaries() {
        let t0 = Instant::now();
        let g = gate_at(t0, 1, 1, 1, 16);
        assert!(logged(&g, &connection("198.51.100.7"), t0));
        assert!(!logged(&g, &connection("198.51.100.7"), t0));
        assert!(
            g.take_due(t0 + g.window() - Duration::from_millis(1))
                .is_empty()
        );
        let due = g.take_due(t0 + g.window());
        assert_eq!(due.len(), 1);
        assert_eq!(due[0].connections, 1);
        assert!(logged(
            &g,
            &connection("198.51.100.7"),
            t0 + g.window() + Duration::from_millis(1)
        ));
        assert!(g.take_due(t0 + g.window()).is_empty(), "taken once");
    }

    #[test]
    fn a_full_address_table_folds_new_addresses_into_one_overflow_summary() {
        let t0 = Instant::now();
        let g = gate_at(t0, 5, 5, 100, 2);
        assert!(logged(&g, &connection("198.51.100.1"), t0));
        assert!(logged(&g, &connection("198.51.100.2"), t0));
        for n in 3..=9 {
            assert!(!logged(&g, &connection(&format!("198.51.100.{n}")), t0));
        }
        // A tracked address still has its budget.
        assert!(logged(&g, &connection("198.51.100.1"), t0));
        let summaries = g.drain();
        assert_eq!(summaries.len(), 1);
        assert_eq!(summaries[0].scope, SummaryScope::Overflow);
        assert_eq!(summaries[0].connections, 7);
        let event = source_summary_event(&summaries[0], g.window(), t0, Utc::now());
        assert_eq!(event.metadata["source_prefix"], "overflow");
    }

    /// A summary that stands for many addresses is attributed to the first of them, which may only
    /// have connected: it must never be an authenticated login, whatever attempts were folded.
    #[test]
    fn an_unattributed_summary_is_a_connection_that_authenticated_nothing() {
        let t0 = Instant::now();
        // Table of one: the first address is tracked, so A's connection is the overflow's first.
        let g = gate_at(t0, 5, 5, 100, 1);
        assert!(logged(&g, &connection("198.51.100.1"), t0));
        assert!(!logged(&g, &connection("198.51.100.2"), t0)); // A: connects only
        for _ in 0..3 {
            assert!(!logged(&g, &login("198.51.100.3", "RFB 003.008"), t0)); // B: logs in
        }
        let summaries = g.drain();
        assert_eq!(summaries.len(), 1);
        let s = &summaries[0];
        assert_eq!(s.source, "198.51.100.2".parse::<IpAddr>().unwrap());
        assert_eq!((s.connections, s.attempts), (1, 3));
        let event = source_summary_event(s, g.window(), t0, Utc::now());
        assert_eq!(event.signal_type, SIGNAL_HONEYPOT_CONNECTION);
        assert!(!event.authenticated);
        assert_eq!(event.metadata["suppressed_attempts"], 3);
        assert_eq!(event.metadata["suppressed_count"], 4);
        assert_eq!(event.metadata[OVERFLOW_SUMMARY_KEY], true);
    }

    #[test]
    fn an_address_first_event_is_written_after_the_listener_budget_is_spent() {
        let t0 = Instant::now();
        let g = gate_at(t0, 1000, 1000, 200, 64);
        // One address spends the whole listener budget of repeats.
        let written = (0..400)
            .filter(|_| logged(&g, &connection("198.51.100.1"), t0))
            .count();
        assert_eq!(written, 201, "its first event plus 200 repeats");
        // Another address's first event of that kind is still written; its second is a repeat.
        assert!(logged(&g, &connection("203.0.113.9"), t0));
        assert!(!logged(&g, &connection("203.0.113.9"), t0));
    }

    #[test]
    fn one_network_cannot_take_more_than_its_share_of_the_table() {
        let t0 = Instant::now();
        let config = SourceEventConfig::default();
        let (cap, capacity) = (
            config.network_address_cap.get(),
            config.address_capacity.get(),
        );
        let g = SourceEventGate::new_at(config, t0);
        // 2,000 addresses of one IPv6 /64, two events each.
        let mut written = 0;
        for n in 0..2000u32 {
            let ip = format!("2001:db8:0:1::{n:x}");
            for _ in 0..2 {
                written += usize::from(logged(&g, &connection(&ip), t0));
            }
        }
        // Fifty sources from other networks keep their first events.
        for n in 0..50u32 {
            assert!(
                logged(&g, &connection(&format!("127.{n}.0.1")), t0),
                "source {n}"
            );
        }
        let summaries = g.drain();
        assert!(
            written <= 40,
            "the network budget bounds the verbatim lines: {written}"
        );
        let by_scope =
            |f: fn(&SummaryScope) -> bool| summaries.iter().filter(|s| f(&s.scope)).count();
        assert!(by_scope(|s| matches!(s, SummaryScope::Address(_))) <= cap);
        assert_eq!(by_scope(|s| matches!(s, SummaryScope::Network(_))), 1);
        assert_eq!(by_scope(|s| matches!(s, SummaryScope::Overflow)), 0);
        assert!(capacity - cap >= 50, "the table kept room for the others");
        let network = summaries
            .iter()
            .find(|s| matches!(s.scope, SummaryScope::Network(_)))
            .unwrap();
        let event = source_summary_event(network, g.window(), t0, Utc::now());
        assert_eq!(event.metadata[OVERFLOW_SUMMARY_KEY], true);
        assert!(!event.authenticated);
        assert_eq!(event.metadata["suppressed_count"], 2 * (2000 - cap as u64));
    }

    /// The worst case the docs state: 2 x capacity first sightings, 2 x total repeats and a summary
    /// per tracked address, per capped network and the overflow.
    #[test]
    fn the_worst_case_line_count_with_the_network_cap_matches_the_documented_bound() {
        let t0 = Instant::now();
        let config = SourceEventConfig::default();
        let (cap, capacity) = (
            config.network_address_cap.get(),
            config.address_capacity.get(),
        );
        let g = SourceEventGate::new_at(config, t0);
        let mut written = 0usize;
        // 40 IPv6 /64s of 100 addresses (the cap is 64), then 600 more single-address networks.
        for round in 0..30 {
            let now = t0 + Duration::from_millis(round);
            for net in 0..40u32 {
                for host in 0..100u32 {
                    let ip = format!("2001:db8:{net:x}::{host:x}");
                    written += usize::from(logged(&g, &connection(&ip), now));
                    written += usize::from(logged(&g, &login(&ip, "RFB 003.008"), now));
                }
            }
            for n in 0..600u32 {
                let ip = v4(n);
                written += usize::from(logged(&g, &connection(&ip), now));
                written += usize::from(logged(&g, &login(&ip, "RFB 003.008"), now));
            }
        }
        let summaries = g.drain().len();
        let bound = 2 * capacity + 2 * DEFAULT_TOTAL_BUDGET as usize;
        assert!(written <= bound, "{written} verbatim lines, bound {bound}");
        let summary_bound = capacity + capacity / cap + 1;
        assert!(summaries <= summary_bound, "{summaries} summaries");
        assert_eq!(bound + summary_bound, 3489);
    }

    #[test]
    fn only_tcp_connection_and_login_events_are_governed() {
        let t0 = Instant::now();
        let g = gate_at(t0, 1, 1, 1, 16);
        let src = "198.51.100.7";
        assert!(logged(&g, &connection(src), t0));
        let other = [
            event(
                src,
                "honeypot_command_exec",
                json!({"command": "id"}),
                Uuid::now_v7(),
            ),
            event(src, "honeypot_malware_upload", json!({}), Uuid::now_v7()),
            event(
                src,
                SIGNAL_HONEYPOT_CONNECTION,
                json!({EVENT_SUMMARY_KEY: true}),
                Uuid::now_v7(),
            ),
            {
                let mut udp = connection(src);
                udp.protocol = "udp".into();
                udp
            },
        ];
        for e in &other {
            for _ in 0..20 {
                assert!(logged(&g, e, t0), "{e:?}");
            }
        }
        assert!(g.drain().is_empty());
    }

    #[test]
    fn a_summary_is_a_login_when_an_attempt_was_folded_and_a_connection_otherwise() {
        let t0 = Instant::now();
        let g = gate_at(t0, 1, 10, 10, 16);
        for _ in 0..3 {
            g.admit_at(&connection("198.51.100.7"), t0);
        }
        let mut summaries = g.drain();
        let event = source_summary_event(&summaries.remove(0), g.window(), t0, Utc::now());
        assert_eq!(event.signal_type, SIGNAL_HONEYPOT_CONNECTION);
        assert!(!event.authenticated);
        assert_eq!(event.metadata["suppressed_count"], 2);

        for _ in 0..3 {
            g.admit_at(&login("198.51.100.7", "RFB 003.008"), t0);
        }
        let mut summaries = g.drain();
        let event = source_summary_event(&summaries.remove(0), g.window(), t0, Utc::now());
        assert_eq!(event.signal_type, SIGNAL_HONEYPOT_LOGIN_ATTEMPT);
        assert!(event.authenticated);
        assert_eq!(event.metadata["suppressed_attempts"], 2);
        assert_eq!(event.metadata["suppressed_connections"], 0);
        assert_eq!(event.metadata[EVENT_SUMMARY_KEY], true);
    }

    #[test]
    fn usernames_and_versions_are_bounded_samples() {
        let t0 = Instant::now();
        let g = gate_at(t0, 1, 1000, 1000, 16);
        for n in 0..(MAX_SUMMARY_VALUES + 5) {
            let mut e = login("198.51.100.7", "RFB 003.008");
            e.metadata["username"] = json!(format!("user{n}"));
            g.admit_at(&e, t0);
        }
        let s = g.drain().remove(0);
        assert_eq!(s.usernames.len(), MAX_SUMMARY_VALUES);
        assert!(s.usernames_capped);
        assert_eq!(s.client_versions, vec!["RFB 003.008"]);
    }
}
