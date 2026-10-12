//! Condition #7: the event ledger's hash chain fails verification. Delegates to core-scoring's
//! `verify_chain` (the single source of chain semantics - this does NOT re-implement hashing) and
//! distinguishes a real integrity break (Firing) from an infrastructure read error (Unknown).
//!
//! The full-ledger scan is expensive, so it runs at most once per `chain_verify_interval` and
//! serves the cached verdict between runs. A break is definitive, so `for_dur` is zero: page now.
//!
//! The scan runs as its own task, never inside `evaluate`: on a ledger of tens of millions of rows
//! it takes minutes, and while the monitor awaited it every other condition went unevaluated and
//! the heartbeat stopped, so the dead-man's switch reported a healthy node as down. `evaluate`
//! starts a scan when one is due and returns the last verdict at once.

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use core_scoring::{ChainStatus, verify_chain};
use sqlx::PgPool;

use crate::ops_alert::condition::{Condition, MonitorCtx, Outcome};
use crate::ops_alert::config::OpsAlertConfig;
use crate::ops_alert::dispatch::Severity;

/// The ledger verification call, abstracted so tests need no corrupt ledger. Returns `Err(String)`
/// only for an infrastructure failure (cannot read the ledger); a real tamper shows as
/// `Ok(ChainStatus::Broken)`.
#[async_trait]
pub trait ChainVerifier: Send + Sync {
    async fn verify(&self, pool: &PgPool) -> Result<ChainStatus, String>;
}

/// Production verifier: core-scoring's whole-ledger `verify_chain`.
pub struct RealVerifier;

#[async_trait]
impl ChainVerifier for RealVerifier {
    async fn verify(&self, pool: &PgPool) -> Result<ChainStatus, String> {
        verify_chain(pool).await.map_err(|e| e.to_string())
    }
}

/// Map a verification result to a condition outcome. A `Broken` chain is a critical integrity
/// alert; an infrastructure error fails open to `Unknown` (a broken probe must not mask the rest).
fn outcome_from_verify(result: Result<ChainStatus, String>) -> Outcome {
    match result {
        Ok(ChainStatus::Intact) => Outcome::Ok,
        Ok(ChainStatus::Broken { first_bad_id }) => Outcome::Firing {
            severity: Severity::Critical,
            detail: format!("event ledger hash-chain broken at event id {first_bad_id}"),
        },
        Err(why) => Outcome::Unknown {
            why: format!("chain verify: {why}"),
        },
    }
}

/// Whether the verification pass is due (never run, or the interval has elapsed).
fn is_due(last_run: Option<Instant>, now: Instant, interval: Duration) -> bool {
    match last_run {
        None => true,
        Some(t) => now.duration_since(t) >= interval,
    }
}

/// What the background scan and `evaluate` share.
#[derive(Default)]
struct ScanState {
    /// When the last scan started.
    started: Option<Instant>,
    /// Whether a scan is running now.
    running: bool,
    /// The last finished scan's verdict.
    verdict: Option<Outcome>,
}

/// Clears `running` when the scan task ends, a panic included, so one failed scan cannot stop
/// every later one.
struct RunningGuard(Arc<Mutex<ScanState>>);

impl Drop for RunningGuard {
    fn drop(&mut self) {
        self.0.lock().unwrap_or_else(|p| p.into_inner()).running = false;
    }
}

/// #7: hash-chain verification.
pub struct ChainVerify {
    verifier: Arc<dyn ChainVerifier>,
    state: Arc<Mutex<ScanState>>,
}

impl ChainVerify {
    pub fn new() -> Self {
        Self::with_verifier(Arc::new(RealVerifier))
    }

    fn with_verifier(verifier: Arc<dyn ChainVerifier>) -> Self {
        Self {
            verifier,
            state: Arc::new(Mutex::new(ScanState::default())),
        }
    }
}

impl Default for ChainVerify {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Condition for ChainVerify {
    fn id(&self) -> &'static str {
        "chain-verify"
    }
    fn for_dur(&self, _cfg: &OpsAlertConfig) -> Duration {
        // A verified integrity break is definitive; page on the first firing tick.
        Duration::ZERO
    }
    async fn evaluate(&self, ctx: &MonitorCtx) -> Outcome {
        let now = Instant::now();
        let mut state = self.state.lock().unwrap_or_else(|p| p.into_inner());
        if !state.running && is_due(state.started, now, ctx.cfg.chain_verify_interval) {
            state.running = true;
            state.started = Some(now);
            let shared = self.state.clone();
            let verifier = self.verifier.clone();
            let pool = ctx.pool.clone();
            tokio::spawn(async move {
                let _guard = RunningGuard(shared.clone());
                let outcome = outcome_from_verify(verifier.verify(&pool).await);
                shared.lock().unwrap_or_else(|p| p.into_inner()).verdict = Some(outcome);
            });
        }
        // A scan that has run for a whole interval is hung (a lock wait, a dead connection): its
        // last verdict is no longer news, and serving it would hide that no scan completes.
        // Unknown lets the monitor's probe-stale warning say so.
        if state.running
            && let Some(started) = state.started
            && now.duration_since(started) > ctx.cfg.chain_verify_interval
        {
            return Outcome::Unknown {
                why: format!(
                    "a hash-chain verification has been running for {} min without finishing",
                    now.duration_since(started).as_secs() / 60
                ),
            };
        }
        state.verdict.clone().unwrap_or_else(|| Outcome::Unknown {
            why: "the first hash-chain verification since startup is still running".to_string(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn intact_is_ok_broken_is_critical_error_is_unknown() {
        assert_eq!(outcome_from_verify(Ok(ChainStatus::Intact)), Outcome::Ok);
        match outcome_from_verify(Ok(ChainStatus::Broken { first_bad_id: 42 })) {
            Outcome::Firing { severity, detail } => {
                assert_eq!(severity, Severity::Critical);
                assert!(detail.contains("42"), "detail names the bad id: {detail}");
            }
            other => panic!("expected Firing/Critical, got {other:?}"),
        }
        assert!(outcome_from_verify(Err("db down".into())).is_unknown());
    }

    #[test]
    fn is_due_is_true_until_the_interval_elapses() {
        let base = Instant::now();
        let interval = Duration::from_secs(600);
        assert!(is_due(None, base, interval)); // never run
        assert!(!is_due(
            Some(base),
            base + Duration::from_secs(100),
            interval
        )); // too soon
        assert!(is_due(
            Some(base),
            base + Duration::from_secs(600),
            interval
        )); // exactly due
    }

    #[test]
    fn for_dur_is_zero() {
        let cfg = crate::ops_alert::config::parse_ops_alert(&|k: &str| match k {
            "PROPOLIS_OPS_NTFY_URL" => Some("https://ntfy.example/".to_string()),
            "PROPOLIS_OPS_NTFY_TOPIC" => Some("propolis-ops".to_string()),
            _ => None,
        })
        .unwrap();
        assert_eq!(ChainVerify::new().for_dur(&cfg), Duration::ZERO);
    }

    /// Copyable descriptor of what the stub should return (ChainStatus is not Clone).
    #[derive(Clone, Copy)]
    enum Stub {
        Intact,
        Broken(i64),
        Err(&'static str),
    }

    struct StubVerifier(Stub);

    #[async_trait]
    impl ChainVerifier for StubVerifier {
        async fn verify(&self, _pool: &PgPool) -> Result<ChainStatus, String> {
            match self.0 {
                Stub::Intact => Ok(ChainStatus::Intact),
                Stub::Broken(id) => Ok(ChainStatus::Broken { first_bad_id: id }),
                Stub::Err(m) => Err(m.to_string()),
            }
        }
    }

    #[tokio::test]
    async fn an_injected_stub_drives_the_verdict() {
        // A lazy pool never connects (the stub ignores it), so the real trait path is exercised
        // without a corrupt ledger or a live database.
        let pool = sqlx::postgres::PgPoolOptions::new()
            .connect_lazy("postgres://unused/unused")
            .expect("lazy pool builds without connecting");

        let broken = StubVerifier(Stub::Broken(7));
        assert!(matches!(
            outcome_from_verify(broken.verify(&pool).await),
            Outcome::Firing {
                severity: Severity::Critical,
                ..
            }
        ));
        let ok = StubVerifier(Stub::Intact);
        assert_eq!(outcome_from_verify(ok.verify(&pool).await), Outcome::Ok);
        let err = StubVerifier(Stub::Err("ledger unreadable"));
        assert!(outcome_from_verify(err.verify(&pool).await).is_unknown());
        assert_eq!(
            ChainVerify::with_verifier(Arc::new(StubVerifier(Stub::Intact))).id(),
            "chain-verify"
        );
    }

    /// A scan that takes as long as the test says: `release` lets it finish.
    struct GatedVerifier {
        release: Arc<tokio::sync::Notify>,
        result: Stub,
        scans: Arc<std::sync::atomic::AtomicUsize>,
    }

    #[async_trait]
    impl ChainVerifier for GatedVerifier {
        async fn verify(&self, _pool: &PgPool) -> Result<ChainStatus, String> {
            self.scans.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            self.release.notified().await;
            StubVerifier(self.result).verify(_pool).await
        }
    }

    fn monitor_ctx(interval_secs: &str) -> MonitorCtx {
        let cfg = crate::ops_alert::config::parse_ops_alert(&|k: &str| match k {
            "PROPOLIS_OPS_CHAIN_VERIFY_INTERVAL_SECS" => Some(interval_secs.to_string()),
            _ => None,
        })
        .unwrap();
        MonitorCtx {
            pool: sqlx::postgres::PgPoolOptions::new()
                .connect_lazy("postgres://unused/unused")
                .unwrap(),
            pg_data_volume: "/".into(),
            spool_dir: "/".into(),
            spool_dirs: Vec::new(),
            vt_enabled: false,
            fetch_enabled: false,
            supervisor: Default::default(),
            intake_progress: Default::default(),
            intake_poll_interval: Duration::from_secs(1),
            feed_marker_path: "/nonexistent".into(),
            feed_push_marker_path: "/nonexistent".into(),
            feed_build_interval: Duration::from_secs(300),
            rotation: crate::ops_alert::condition::RotationCtx::production(Vec::new()),
            backup_status_dir: "/nonexistent".into(),
            cfg,
        }
    }

    async fn settle() {
        for _ in 0..20 {
            tokio::task::yield_now().await;
        }
    }

    /// The monitor never waits for a scan: evaluate returns at once while the scan runs, starts no
    /// second one meanwhile, and serves the verdict once it lands.
    #[tokio::test]
    async fn evaluate_never_waits_for_the_scan_and_serves_its_verdict_when_it_lands() {
        let release = Arc::new(tokio::sync::Notify::new());
        let scans = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let cond = ChainVerify::with_verifier(Arc::new(GatedVerifier {
            release: release.clone(),
            result: Stub::Broken(9),
            scans: scans.clone(),
        }));
        let ctx = monitor_ctx("1");

        let first = tokio::time::timeout(Duration::from_secs(1), cond.evaluate(&ctx))
            .await
            .expect("evaluate returns while the scan is still running");
        assert!(
            first.is_unknown(),
            "no verdict before the first scan ends: {first:?}"
        );
        settle().await;
        tokio::time::sleep(Duration::from_millis(1100)).await;
        assert!(cond.evaluate(&ctx).await.is_unknown());
        settle().await;
        assert_eq!(
            scans.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "no second scan starts while one is running, even past the interval"
        );

        release.notify_one();
        settle().await;
        tokio::time::sleep(Duration::from_millis(50)).await;
        match cond.evaluate(&ctx).await {
            Outcome::Firing { severity, .. } => assert_eq!(severity, Severity::Critical),
            other => panic!("the scan's Broken verdict must be served, got {other:?}"),
        }
    }

    /// A scan that never finishes stops serving its predecessor's verdict once it has run for a
    /// whole interval, so the monitor's probe-stale warning reports it.
    #[tokio::test]
    async fn a_scan_running_longer_than_the_interval_reads_as_unknown() {
        let release = Arc::new(tokio::sync::Notify::new());
        let scans = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let cond = ChainVerify::with_verifier(Arc::new(GatedVerifier {
            release: release.clone(),
            result: Stub::Intact,
            scans: scans.clone(),
        }));
        let ctx = monitor_ctx("1");
        // A first scan finishes Intact.
        cond.evaluate(&ctx).await;
        release.notify_one();
        settle().await;
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert_eq!(cond.evaluate(&ctx).await, Outcome::Ok);
        // The next one starts once due, and never finishes.
        tokio::time::sleep(Duration::from_millis(1100)).await;
        assert_eq!(
            cond.evaluate(&ctx).await,
            Outcome::Ok,
            "fresh: the last verdict still stands"
        );
        tokio::time::sleep(Duration::from_millis(1100)).await;
        assert!(
            cond.evaluate(&ctx).await.is_unknown(),
            "a scan running past a whole interval is no longer hidden"
        );
        assert_eq!(scans.load(std::sync::atomic::Ordering::SeqCst), 2);
    }

    struct PanickingVerifier(Arc<std::sync::atomic::AtomicUsize>);

    #[async_trait]
    impl ChainVerifier for PanickingVerifier {
        async fn verify(&self, _pool: &PgPool) -> Result<ChainStatus, String> {
            self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            panic!("a scan that dies");
        }
    }

    /// A scan that panics does not leave the condition believing one is still running forever.
    #[tokio::test]
    async fn a_scan_that_panics_does_not_stop_later_scans() {
        let scans = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let cond = ChainVerify::with_verifier(Arc::new(PanickingVerifier(scans.clone())));
        let ctx = monitor_ctx("1");
        cond.evaluate(&ctx).await;
        settle().await;
        tokio::time::sleep(Duration::from_millis(1100)).await;
        cond.evaluate(&ctx).await;
        settle().await;
        assert_eq!(scans.load(std::sync::atomic::Ordering::SeqCst), 2);
    }
}
