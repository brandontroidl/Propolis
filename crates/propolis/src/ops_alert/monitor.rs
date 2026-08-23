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
        tracing::error!(key = %key, error = ?e, "ops-alert: delivery failed");
    }
}

/// The operational monitor. Generic over the dispatcher's `Poster` so tests inject a recorder.
pub struct Monitor<P: Poster> {
    tracked: Vec<Tracked>,
    ctx: MonitorCtx,
    dispatcher: Dispatcher<P>,
    probe_stale_after: Duration,
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
        }
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
                                "probe {id} could not read its source for over {}s: {why}",
                                probe_stale_after.as_secs()
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

/// All eight operational conditions, in a stable order. Built fresh on each (re)start so per-
/// condition state (backlog history, the chain-verify cache) resets cleanly after a supervised
/// restart.
pub fn default_conditions() -> Vec<Box<dyn Condition>> {
    use super::conditions::{backlog, capacity, chain, feed, intake, subsystem, vendor};
    vec![
        Box::new(subsystem::SubsystemGaveUp),
        Box::new(subsystem::SensorDown),
        Box::new(capacity::Capacity),
        Box::new(backlog::Backlog::new()),
        Box::new(chain::ChainVerify::new()),
        Box::new(intake::IntakeStalled),
        Box::new(feed::FeedStale),
        Box::new(vendor::VendorFailures),
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
            supervisor: Arc::new(Mutex::new(HashMap::new())),
            intake_progress: Arc::new(Mutex::new(HashMap::new())),
            feed_marker_path: "/nonexistent".into(),
            feed_build_interval: Duration::from_secs(300),
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

    #[tokio::test]
    async fn default_conditions_are_the_eight_expected_ids() {
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
                "feed-stale",
                "vendor-failures",
            ]
        );
    }
}
