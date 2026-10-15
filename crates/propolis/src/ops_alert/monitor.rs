//! The poll loop: on each interval it evaluates every condition, runs each result through that
//! condition's own debounce/re-page state machine, and dispatches the resulting page, re-page, or
//! recovered notice. Every condition is independent - one that errors (`Unknown`) or panics cannot
//! stop the others, and a probe stuck `Unknown` too long raises its own `probe-stale` warning.

use std::time::{Duration, Instant};

use tokio_util::sync::CancellationToken;

use super::condition::{Condition, MonitorCtx, Outcome};
use super::debounce::{Action, DebounceMachine};
use super::dispatch::{Dispatcher, OpsAlert, Poster, Severity};

/// How long a probe may stay `Unknown` (cannot read its source) before the monitor pages a
/// `probe-stale` warning about the probe itself. Longer than any single transient blip.
const PROBE_STALE_AFTER: Duration = Duration::from_secs(1800);

/// Per-condition running state.
struct Tracked {
    condition: Box<dyn Condition>,
    machine: DebounceMachine,
    /// When this probe first started returning `Unknown` continuously (reset on any non-Unknown).
    unknown_since: Option<Instant>,
    /// Whether a `probe-stale` warning is currently outstanding for this probe.
    probe_stale_active: bool,
}

/// Deliver one alert, logging (never propagating) a delivery failure - a failed page must be loud
/// but must not stop the monitor.
async fn deliver<P: Poster>(dispatcher: &Dispatcher<P>, alert: OpsAlert, now: Instant) {
    let key = alert.key.clone();
    if let Err(e) = dispatcher.dispatch(alert, now).await {
        tracing::error!(key = %key, error = %e, "ops-alert: delivery failed");
    }
}

/// Requests a dead-man's switch URL. Behind a trait so tests count pings without a server.
#[async_trait::async_trait]
pub trait Pinger: Send + Sync {
    async fn ping(&self, url: &str) -> Result<(), String>;
}

/// The production pinger: one GET, bounded, over the already-vetted rustls client.
pub struct ReqwestPinger(reqwest::Client);

impl ReqwestPinger {
    pub fn new() -> Result<Self, String> {
        reqwest::Client::builder()
            .timeout(Duration::from_secs(15))
            .connect_timeout(Duration::from_secs(10))
            .build()
            .map(Self)
            .map_err(|e| format!("http client build failed: {e}"))
    }
}

#[async_trait::async_trait]
impl Pinger for ReqwestPinger {
    async fn ping(&self, url: &str) -> Result<(), String> {
        // without_url: the URL is the check's secret and must not reach the journal.
        let resp = self
            .0
            .get(url)
            .send()
            .await
            .map_err(|e| e.without_url().to_string())?;
        if resp.status().is_success() {
            Ok(())
        } else {
            Err(format!("status {}", resp.status().as_u16()))
        }
    }
}

/// The dead-man's switch: pinged after a complete evaluation round, at most once per interval.
/// Only a round that finished counts, so a monitor wedged in a probe stops pinging and the service
/// on the other end raises the alarm this daemon cannot raise about itself.
struct Heartbeat {
    url: String,
    interval: Duration,
    last_sent: Option<Instant>,
    pinger: Box<dyn Pinger>,
}

impl Heartbeat {
    async fn after_round(&mut self, now: Instant) {
        if self
            .last_sent
            .is_some_and(|t| now.duration_since(t) < self.interval)
        {
            return;
        }
        match self.pinger.ping(&self.url).await {
            // A failed ping is retried on the next round, not after a full interval.
            Ok(()) => self.last_sent = Some(now),
            Err(why) => tracing::warn!(error = %why, "ops-monitor: heartbeat ping failed"),
        }
    }
}

/// The operational monitor. Generic over the dispatcher's `Poster` so tests inject a recorder.
pub struct Monitor<P: Poster> {
    tracked: Vec<Tracked>,
    ctx: MonitorCtx,
    dispatcher: Dispatcher<P>,
    probe_stale_after: Duration,
    heartbeat: Option<Heartbeat>,
}

impl<P: Poster> Monitor<P> {
    pub fn new(
        conditions: Vec<Box<dyn Condition>>,
        ctx: MonitorCtx,
        dispatcher: Dispatcher<P>,
    ) -> Self {
        let repage = ctx.cfg.repage_cooldown;
        let tracked = conditions
            .into_iter()
            .map(|c| {
                let for_dur = c.for_dur(&ctx.cfg);
                Tracked {
                    machine: DebounceMachine::new(for_dur, repage),
                    condition: c,
                    unknown_since: None,
                    probe_stale_active: false,
                }
            })
            .collect();
        Self {
            tracked,
            ctx,
            dispatcher,
            probe_stale_after: PROBE_STALE_AFTER,
            heartbeat: None,
        }
    }

    /// The heartbeat `cfg` configures (`PROPOLIS_OPS_HEARTBEAT_URL`), if any. A client that cannot
    /// be built is logged and the monitor runs without one: the alerts still go out.
    pub fn with_configured_heartbeat(self, cfg: &super::config::OpsAlertConfig) -> Self {
        let Some(url) = cfg.heartbeat_url.clone() else {
            return self;
        };
        match ReqwestPinger::new() {
            Ok(pinger) => {
                tracing::info!(
                    interval_secs = cfg.heartbeat_interval.as_secs(),
                    "ops-monitor: heartbeat enabled"
                );
                self.with_heartbeat(url, cfg.heartbeat_interval, Box::new(pinger))
            }
            Err(e) => {
                tracing::error!(error = %e, "ops-monitor: heartbeat disabled, client build failed");
                self
            }
        }
    }

    /// Ping `url` after every complete round, at most once per `interval`.
    pub fn with_heartbeat(
        mut self,
        url: String,
        interval: Duration,
        pinger: Box<dyn Pinger>,
    ) -> Self {
        self.heartbeat = Some(Heartbeat {
            url,
            interval,
            last_sent: None,
            pinger,
        });
        self
    }

    /// Evaluate every condition once and dispatch the resulting actions. Extracted from `run` so it
    /// is unit-testable with an injected `now` and no sleeping.
    pub async fn process_tick(&mut self, now: Instant) {
        // Disjoint field borrows: iterate `tracked` mutably while reading `ctx`/`dispatcher`.
        let Self {
            tracked,
            ctx,
            dispatcher,
            probe_stale_after,
            heartbeat,
        } = self;

        for t in tracked.iter_mut() {
            let outcome = t.condition.evaluate(ctx).await;
            let id = t.condition.id();

            // Probe-stale meta-condition: a probe that cannot read its source for too long is itself
            // a (separate) warning, so a silently broken probe does not hide behind its fail-open.
            if outcome.is_unknown() {
                let since = *t.unknown_since.get_or_insert(now);
                if !t.probe_stale_active && now.duration_since(since) > *probe_stale_after {
                    t.probe_stale_active = true;
                    let why = match &outcome {
                        Outcome::Unknown { why } => why.clone(),
                        _ => String::new(),
                    };
                    deliver(
                        dispatcher,
                        OpsAlert {
                            key: format!("probe-stale:{id}"),
                            severity: Severity::Warning,
                            title: format!("propolis: probe {id} stalled"),
                            body: format!(
                                "probe {id} could not read its source for over {}s: {why}{}",
                                probe_stale_after.as_secs(),
                                // An unreadable probe holds an open incident open; say so, or the
                                // silence reads as "still firing, still handled".
                                if t.machine.is_open() {
                                    ". An earlier page for it is still open: it cannot be \
                                     confirmed cleared until the probe reads again"
                                } else {
                                    ""
                                }
                            ),
                            recovered: false,
                        },
                        now,
                    )
                    .await;
                }
            } else {
                if t.probe_stale_active {
                    t.probe_stale_active = false;
                    deliver(
                        dispatcher,
                        OpsAlert {
                            key: format!("probe-stale:{id}"),
                            severity: Severity::Warning,
                            title: format!("propolis: probe {id} reading again"),
                            body: format!("probe {id} is reading its source again"),
                            recovered: true,
                        },
                        now,
                    )
                    .await;
                }
                t.unknown_since = None;
            }

            // Primary condition: drive its debounce machine and act on the transition.
            let action = t.machine.step(outcome.to_signal(), now);
            match action {
                Action::None => {}
                Action::Page | Action::RePage => {
                    if let Outcome::Firing { severity, detail } = &outcome {
                        deliver(
                            dispatcher,
                            OpsAlert {
                                key: id.to_string(),
                                severity: *severity,
                                title: format!("propolis: {id}"),
                                body: detail.clone(),
                                recovered: false,
                            },
                            now,
                        )
                        .await;
                    } else {
                        // A Page/RePage only follows a Firing signal, which only Outcome::Firing
                        // produces; reaching here would be a logic error, so surface it.
                        tracing::warn!(condition = %id, ?action, "ops-alert: page action without a firing outcome");
                    }
                }
                Action::Recovered => {
                    deliver(
                        dispatcher,
                        OpsAlert {
                            key: id.to_string(),
                            severity: Severity::Warning,
                            title: format!("propolis: {id} recovered"),
                            body: format!("{id} cleared"),
                            recovered: true,
                        },
                        now,
                    )
                    .await;
                }
            }
        }

        dispatcher.prune_expired(now);

        // Last, after every condition was evaluated: the ping says "a whole round finished".
        if let Some(heartbeat) = heartbeat {
            heartbeat.after_round(now).await;
        }
    }

    /// Run until cancelled. A clean return on cancel (the supervisor treats it as intentional
    /// shutdown, not a crash to restart).
    pub async fn run(mut self, cancel: CancellationToken) {
        tracing::info!("ops-monitor: started");
        let poll = self.ctx.cfg.poll_interval;
        loop {
            if cancel.is_cancelled() {
                tracing::info!("ops-monitor: cancelled, stopping");
                return;
            }
            self.process_tick(Instant::now()).await;
            tokio::select! {
                _ = tokio::time::sleep(poll) => {}
                _ = cancel.cancelled() => {
                    tracing::info!("ops-monitor: cancelled, stopping");
                    return;
                }
            }
        }
    }
}

/// All seventeen operational conditions, in a stable order. Built fresh on each (re)start so per-
/// condition state (backlog history, the chain-verify cache, intake lag tracks) resets cleanly
/// after a supervised restart.
pub fn default_conditions() -> Vec<Box<dyn Condition>> {
    use super::conditions::{
        backlog, backup, capacity, chain, feed, intake, intake_lag, intake_quarantine, malware,
        sensor_log, subsystem, vendor,
    };
    vec![
        Box::new(subsystem::SubsystemGaveUp),
        Box::new(subsystem::SensorDown),
        Box::new(capacity::Capacity),
        Box::new(backlog::Backlog::new()),
        Box::new(chain::ChainVerify::new()),
        Box::new(intake::IntakeStalled),
        Box::new(intake_lag::IntakeLagging::new()),
        Box::new(intake_quarantine::IntakeLineQuarantined),
        Box::new(feed::FeedStale),
        Box::new(feed::FeedPushStale::new()),
        Box::new(vendor::VendorFailures),
        Box::new(malware::ScanStale),
        Box::new(malware::FetchStale),
        Box::new(sensor_log::SensorLogOversized::new()),
        Box::new(sensor_log::RotationStale),
        Box::new(intake::IntakeRotationLoss),
        Box::new(backup::BackupStale),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ops_alert::config::parse_ops_alert;
    use crate::ops_alert::dispatch::{PostErr, PostReq};
    use async_trait::async_trait;
    use std::collections::HashMap;
    use std::sync::{Arc, Mutex};

    /// Records every dispatched request; always returns 200.
    struct Recorder {
        sent: Mutex<Vec<PostReq>>,
    }
    impl Recorder {
        fn new() -> Self {
            Self {
                sent: Mutex::new(Vec::new()),
            }
        }
        fn count(&self) -> usize {
            self.sent.lock().unwrap().len()
        }
        fn last_priority(&self) -> String {
            let sent = self.sent.lock().unwrap();
            let req = sent.last().expect("a request was sent");
            req.headers
                .iter()
                .find(|(k, _)| k == "X-Priority")
                .map(|(_, v)| v.clone())
                .expect("X-Priority present")
        }
    }
    impl Poster for &Recorder {
        async fn post(&self, req: PostReq) -> Result<u16, PostErr> {
            self.sent.lock().unwrap().push(req);
            Ok(200)
        }
    }

    /// A condition whose outcome the test controls between ticks.
    struct StubCond {
        id: &'static str,
        for_dur: Duration,
        out: Arc<Mutex<Outcome>>,
    }
    #[async_trait]
    impl Condition for StubCond {
        fn id(&self) -> &'static str {
            self.id
        }
        fn for_dur(&self, _cfg: &crate::ops_alert::config::OpsAlertConfig) -> Duration {
            self.for_dur
        }
        async fn evaluate(&self, _ctx: &MonitorCtx) -> Outcome {
            self.out.lock().unwrap().clone()
        }
    }

    fn test_ctx() -> MonitorCtx {
        let pool = sqlx::postgres::PgPoolOptions::new()
            .connect_lazy("postgres://unused/unused")
            .unwrap();
        let cfg = parse_ops_alert(&|k: &str| match k {
            "PROPOLIS_OPS_NTFY_URL" => Some("https://ntfy.example".into()),
            "PROPOLIS_OPS_NTFY_TOPIC" => Some("propolis-ops".into()),
            "PROPOLIS_OPS_REPAGE_COOLDOWN_SECS" => Some("300".into()),
            _ => None,
        })
        .unwrap();
        MonitorCtx {
            pool,
            pg_data_volume: "/".into(),
            spool_dir: "/".into(),
            spool_dirs: Vec::new(),
            vt_enabled: false,
            fetch_enabled: false,
            supervisor: Arc::new(Mutex::new(HashMap::new())),
            intake_progress: Arc::new(Mutex::new(HashMap::new())),
            intake_poll_interval: Duration::from_secs(1),
            feed_marker_path: "/nonexistent".into(),
            feed_push_marker_path: "/nonexistent".into(),
            feed_build_interval: Duration::from_secs(300),
            rotation: crate::ops_alert::condition::RotationCtx::production(Vec::new()),
            backup_status_dir: "/nonexistent".into(),
            cfg,
        }
    }

    fn dispatcher(rec: &Recorder) -> Dispatcher<&Recorder> {
        Dispatcher::with_poster(
            rec,
            "https://ntfy.example",
            "propolis-ops",
            None,
            Duration::from_secs(300),
        )
    }

    /// The real condition against the map the intake loops write: a log whose tailer reported a
    /// rotation loss pages once, a log that lost nothing does not.
    #[tokio::test]
    async fn a_reported_rotation_loss_pages_and_a_clean_log_does_not() {
        use crate::ops_alert::condition::SensorIntake;
        use crate::ops_alert::conditions::intake::IntakeRotationLoss;

        let rec = Recorder::new();
        let ctx = test_ctx();
        let progress = ctx.intake_progress.clone();
        let mut clean = SensorIntake::started(Instant::now());
        clean.bytes_behind = Some(0);
        progress.lock().unwrap().insert("ssh", clean);
        let mut m = Monitor::new(vec![Box::new(IntakeRotationLoss)], ctx, dispatcher(&rec));
        let base = Instant::now();

        m.process_tick(base).await;
        assert_eq!(rec.count(), 0, "no loss, no page");

        let mut lossy = SensorIntake::started(Instant::now());
        lossy.rotation_loss = log_tailer::RotationLoss {
            events: 1,
            bytes_estimated: 4096,
        };
        lossy.rotation_loss_at = Some(Instant::now());
        progress.lock().unwrap().insert("telnet", lossy);
        m.process_tick(base + Duration::from_secs(1)).await;
        assert_eq!(rec.count(), 1, "a reported loss pages immediately");
        let sent = rec.sent.lock().unwrap();
        let body = &sent[0].body;
        assert!(
            body.contains("telnet (1 rotation, at least 4096 bytes)"),
            "{body}"
        );
        assert!(!body.contains("ssh"), "{body}");
    }

    /// Counts pings; fails while `fail` is set.
    struct CountingPinger {
        pings: Arc<Mutex<Vec<String>>>,
        fail: Arc<Mutex<bool>>,
    }

    #[async_trait]
    impl Pinger for CountingPinger {
        async fn ping(&self, url: &str) -> Result<(), String> {
            self.pings.lock().unwrap().push(url.to_string());
            if *self.fail.lock().unwrap() {
                Err("status 503".into())
            } else {
                Ok(())
            }
        }
    }

    /// A round pings once per interval, a failed ping is retried on the very next round, and a
    /// round that never finishes never pings.
    #[tokio::test]
    async fn the_heartbeat_follows_complete_rounds_at_most_once_per_interval() {
        let rec = Recorder::new();
        let pings = Arc::new(Mutex::new(Vec::new()));
        let fail = Arc::new(Mutex::new(false));
        let mut m = Monitor::new(Vec::new(), test_ctx(), dispatcher(&rec)).with_heartbeat(
            "https://hc.example/abc".into(),
            Duration::from_secs(300),
            Box::new(CountingPinger {
                pings: pings.clone(),
                fail: fail.clone(),
            }),
        );
        let base = Instant::now();
        m.process_tick(base).await;
        assert_eq!(pings.lock().unwrap().len(), 1, "the first round pings");
        m.process_tick(base + Duration::from_secs(30)).await;
        assert_eq!(
            pings.lock().unwrap().len(),
            1,
            "not again within the interval"
        );

        *fail.lock().unwrap() = true;
        m.process_tick(base + Duration::from_secs(301)).await;
        assert_eq!(pings.lock().unwrap().len(), 2, "due again, attempted");
        *fail.lock().unwrap() = false;
        m.process_tick(base + Duration::from_secs(331)).await;
        assert_eq!(
            pings.lock().unwrap().len(),
            3,
            "a failed ping is retried on the next round, not an interval later"
        );
        assert!(
            pings
                .lock()
                .unwrap()
                .iter()
                .all(|u| u == "https://hc.example/abc")
        );
    }

    /// A probe that never returns: the round never completes, so no ping is ever sent.
    struct HangingCond;

    #[async_trait]
    impl Condition for HangingCond {
        fn id(&self) -> &'static str {
            "hang"
        }
        fn for_dur(&self, _cfg: &crate::ops_alert::config::OpsAlertConfig) -> Duration {
            Duration::ZERO
        }
        async fn evaluate(&self, _ctx: &MonitorCtx) -> Outcome {
            std::future::pending().await
        }
    }

    #[tokio::test]
    async fn a_wedged_round_sends_no_heartbeat() {
        let rec = Recorder::new();
        let pings = Arc::new(Mutex::new(Vec::new()));
        let mut m = Monitor::new(vec![Box::new(HangingCond)], test_ctx(), dispatcher(&rec))
            .with_heartbeat(
                "https://hc.example/abc".into(),
                Duration::from_secs(300),
                Box::new(CountingPinger {
                    pings: pings.clone(),
                    fail: Arc::new(Mutex::new(false)),
                }),
            );
        let wedged =
            tokio::time::timeout(Duration::from_millis(200), m.process_tick(Instant::now())).await;
        assert!(wedged.is_err(), "the round is stuck in the probe");
        assert!(
            pings.lock().unwrap().is_empty(),
            "so the dead-man's switch hears nothing"
        );
    }

    #[tokio::test]
    async fn firing_pages_once_then_repages_after_cooldown_then_recovers() {
        let rec = Recorder::new();
        let out = Arc::new(Mutex::new(Outcome::Firing {
            severity: Severity::Critical,
            detail: "db 4% free".into(),
        }));
        let cond = Box::new(StubCond {
            id: "stub",
            for_dur: Duration::ZERO,
            out: out.clone(),
        });
        let mut m = Monitor::new(vec![cond], test_ctx(), dispatcher(&rec));
        let base = Instant::now();

        m.process_tick(base).await; // for_dur 0 -> Page immediately
        assert_eq!(rec.count(), 1, "first firing tick pages");

        m.process_tick(base + Duration::from_secs(60)).await; // within cooldown -> no re-page
        assert_eq!(rec.count(), 1, "no re-page inside the cooldown");

        m.process_tick(base + Duration::from_secs(300)).await; // cooldown elapsed -> RePage
        assert_eq!(rec.count(), 2, "re-pages after the cooldown");

        *out.lock().unwrap() = Outcome::Ok;
        m.process_tick(base + Duration::from_secs(310)).await; // clears -> one Recovered
        assert_eq!(rec.count(), 3, "recovered notice sent");
        assert_eq!(rec.last_priority(), "2", "recovered maps to priority 2");
    }

    #[tokio::test]
    async fn unknown_never_pages_the_primary_but_eventually_fires_probe_stale() {
        let rec = Recorder::new();
        let out = Arc::new(Mutex::new(Outcome::Unknown {
            why: "db unreachable".into(),
        }));
        let cond = Box::new(StubCond {
            id: "stub",
            for_dur: Duration::ZERO,
            out: out.clone(),
        });
        let mut m = Monitor::new(vec![cond], test_ctx(), dispatcher(&rec));
        m.probe_stale_after = Duration::from_secs(600);
        let base = Instant::now();

        m.process_tick(base).await; // Unknown -> primary Ok signal, not stale yet
        assert_eq!(rec.count(), 0, "Unknown does not page the primary");

        m.process_tick(base + Duration::from_secs(601)).await; // Unknown too long -> probe-stale
        assert_eq!(rec.count(), 1, "probe-stale fires once past the threshold");

        m.process_tick(base + Duration::from_secs(602)).await; // still Unknown -> no repeat
        assert_eq!(rec.count(), 1, "probe-stale is not repeated while active");

        // Recovering the probe emits one probe-stale recovered notice.
        *out.lock().unwrap() = Outcome::Ok;
        m.process_tick(base + Duration::from_secs(603)).await;
        assert_eq!(rec.count(), 2, "probe-stale recovered notice sent");
        assert_eq!(rec.last_priority(), "2");
    }

    /// The false-recovery path: an open incident whose probe then cannot read must not send a
    /// "recovered", must say after the bounded time that it can no longer vouch for the incident,
    /// and must recover exactly once, when a probe reads healthy.
    #[tokio::test]
    async fn unknown_never_recovers_an_open_incident_and_the_stale_alert_says_so() {
        let rec = Recorder::new();
        let out = Arc::new(Mutex::new(Outcome::Firing {
            severity: Severity::Critical,
            detail: "db 4% free".into(),
        }));
        let cond = Box::new(StubCond {
            id: "stub",
            for_dur: Duration::ZERO,
            out: out.clone(),
        });
        let mut m = Monitor::new(vec![cond], test_ctx(), dispatcher(&rec));
        m.probe_stale_after = Duration::from_secs(600);
        let base = Instant::now();

        m.process_tick(base).await;
        assert_eq!(rec.count(), 1, "the page");

        *out.lock().unwrap() = Outcome::Unknown {
            why: "db unreachable".into(),
        };
        m.process_tick(base + Duration::from_secs(30)).await;
        m.process_tick(base + Duration::from_secs(60)).await;
        assert_eq!(rec.count(), 1, "unknown sends no recovered notice");
        assert!(
            !rec.sent.lock().unwrap().iter().any(|r| r
                .headers
                .iter()
                .any(|(k, v)| k == "X-Title" && v.contains("recovered"))),
            "no [recovered] title was sent"
        );

        m.process_tick(base + Duration::from_secs(700)).await;
        assert_eq!(rec.count(), 2, "unknown past the bound alerts on its own");
        {
            let sent = rec.sent.lock().unwrap();
            let stale = sent.last().unwrap();
            assert!(
                stale.body.contains("could not read its source"),
                "{}",
                stale.body
            );
            assert!(
                stale.body.contains("earlier page for it is still open"),
                "{}",
                stale.body
            );
        }

        // The probe reads again and the condition really is clear: the probe-stale notice and the
        // incident's own recovered notice, once each.
        *out.lock().unwrap() = Outcome::Ok;
        m.process_tick(base + Duration::from_secs(730)).await;
        assert_eq!(rec.count(), 4, "probe-stale recovered + incident recovered");
        m.process_tick(base + Duration::from_secs(760)).await;
        assert_eq!(rec.count(), 4, "nothing further once clear");
    }

    /// A probe that stays unknown with no incident open alerts after the bound without the
    /// open-incident sentence, and a Firing reading that follows an unknown gap pages normally.
    #[tokio::test]
    async fn unknown_with_nothing_open_alerts_after_the_bound_and_then_pages_normally() {
        let rec = Recorder::new();
        let out = Arc::new(Mutex::new(Outcome::Unknown {
            why: "no marker".into(),
        }));
        let cond = Box::new(StubCond {
            id: "stub",
            for_dur: Duration::ZERO,
            out: out.clone(),
        });
        let mut m = Monitor::new(vec![cond], test_ctx(), dispatcher(&rec));
        m.probe_stale_after = Duration::from_secs(600);
        let base = Instant::now();

        m.process_tick(base).await;
        m.process_tick(base + Duration::from_secs(601)).await;
        assert_eq!(rec.count(), 1);
        assert!(
            !rec.sent.lock().unwrap()[0].body.contains("still open"),
            "no incident was open"
        );

        *out.lock().unwrap() = Outcome::Firing {
            severity: Severity::Warning,
            detail: "stale".into(),
        };
        m.process_tick(base + Duration::from_secs(602)).await;
        // probe-stale recovered + the page.
        assert_eq!(rec.count(), 3);
    }

    #[tokio::test]
    async fn e2e_a_gaveup_subsystem_pages_critical_then_repages_then_recovers() {
        use crate::ops_alert::condition::SubsysState;
        use crate::ops_alert::conditions::subsystem::SubsystemGaveUp;

        let rec = Recorder::new();
        let ctx = test_ctx();
        // A clone of the shared handle so the test can flip subsystem state after ctx moves in.
        let handle = ctx.supervisor.clone();
        handle.lock().unwrap().insert("feed", SubsysState::GaveUp);

        // The real condition, real debounce, real dispatcher - only the HTTP poster is recorded.
        let mut m = Monitor::new(vec![Box::new(SubsystemGaveUp)], ctx, dispatcher(&rec));
        let base = Instant::now();

        m.process_tick(base).await;
        assert_eq!(rec.count(), 1, "a gave-up subsystem pages immediately");
        assert_eq!(rec.last_priority(), "5", "subsystem-gaveup is Critical");

        m.process_tick(base + Duration::from_secs(300)).await;
        assert_eq!(
            rec.count(),
            2,
            "re-pages after the cooldown while still down"
        );

        // The subsystem recovers (a restart republishes Running).
        handle.lock().unwrap().insert("feed", SubsysState::Running);
        m.process_tick(base + Duration::from_secs(310)).await;
        assert_eq!(rec.count(), 3, "one recovered notice when it comes back");
        assert_eq!(rec.last_priority(), "2", "recovered maps to priority 2");
    }

    #[tokio::test]
    async fn default_conditions_are_the_seventeen_expected_ids() {
        let ids: Vec<&str> = default_conditions().iter().map(|c| c.id()).collect();
        assert_eq!(
            ids,
            vec![
                "subsystem-gaveup",
                "sensor-down",
                "capacity",
                "fetcher-backlog",
                "chain-verify",
                "intake-stalled",
                "intake-lagging",
                "intake-line-quarantined",
                "feed-stale",
                "feed-push-stale",
                "vendor-failures",
                "scan-stale",
                "fetch-stale",
                "sensor-log-oversized",
                "rotation-stale",
                "intake-rotation-loss",
                "backup-stale",
            ]
        );
    }
}
