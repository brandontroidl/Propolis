//! Condition #7: the event ledger's hash chain fails verification. Delegates to core-scoring's
//! `verify_chain` (the single source of chain semantics - this does NOT re-implement hashing) and
//! distinguishes a real integrity break (Firing) from an infrastructure read error (Unknown).
//!
//! The full-ledger scan is expensive, so it runs at most once per `chain_verify_interval` and
//! serves the cached verdict between runs. A break is definitive, so `for_dur` is zero: page now.

use std::sync::Mutex;
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

/// #7: hash-chain verification.
pub struct ChainVerify {
    verifier: Box<dyn ChainVerifier>,
    /// The last (run time, verdict). Between intervals `evaluate` returns the cached verdict rather
    /// than re-scanning the whole ledger.
    state: Mutex<Option<(Instant, Outcome)>>,
}

impl ChainVerify {
    pub fn new() -> Self {
        Self {
            verifier: Box::new(RealVerifier),
            state: Mutex::new(None),
        }
    }

    #[cfg(test)]
    fn with_verifier(verifier: Box<dyn ChainVerifier>) -> Self {
        Self {
            verifier,
            state: Mutex::new(None),
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
        // Serve the cached verdict if the last scan is still within the interval.
        {
            let guard = self.state.lock().unwrap_or_else(|p| p.into_inner());
            if let Some((last, cached)) = guard.as_ref()
                && !is_due(Some(*last), now, ctx.cfg.chain_verify_interval)
            {
                return cached.clone();
            }
        }
        // Do the scan without holding the lock (it awaits I/O).
        let outcome = outcome_from_verify(self.verifier.verify(&ctx.pool).await);
        {
            let mut guard = self.state.lock().unwrap_or_else(|p| p.into_inner());
            *guard = Some((now, outcome.clone()));
        }
        outcome
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
            ChainVerify::with_verifier(Box::new(StubVerifier(Stub::Intact))).id(),
            "chain-verify"
        );
    }
}
