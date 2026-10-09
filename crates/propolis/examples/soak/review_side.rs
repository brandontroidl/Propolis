//! The review and submission side the daemon runs next to intake: the queue scan, an operator
//! stand-in that approves what surfaces, and the real `SubmissionRunner` against a vendor that
//! only counts calls (nothing leaves the machine).
//!
//! The gatekeeper holds every reserved address before any vendor call, and the harness's sources
//! are all documentation ranges (RFC 5737, 2001:db8::/32), so the fake vendor is not expected to
//! be called. What this loop proves is that the pass keeps completing on schedule while intake
//! writes: each pass still runs `read_score` and the per-category protocol-label query on `event`
//! for every approved address, which is the part that contends with the append path.

use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use chrono::Utc;
use review::gatekeeper::VendorConfig;
use review::queue::ReviewQueue;
use review::submit::SubmissionRunner;
use review::vendor::{VendorAdapter, VendorError, VendorReport, VendorResponse};
use sqlx::PgPool;
use tokio_util::sync::CancellationToken;

#[derive(Default)]
pub struct ReviewStats {
    pub passes: AtomicU64,
    pub pass_errors: AtomicU64,
    pub submitted: AtomicU64,
    pub held: AtomicU64,
    pub failed: AtomicU64,
    pub unresolved: AtomicU64,
    pub vendor_calls: AtomicU64,
    pub approved: AtomicU64,
    pub populated: AtomicU64,
    pub last_pass_done_ms: AtomicU64,
    pub last_pass_ms: AtomicU64,
    /// Longest pass since the sampler last read it.
    pub max_pass_ms_window: AtomicU64,
}

const VENDOR: &str = "soak-vendor";

struct CountingVendor {
    stats: Arc<ReviewStats>,
}

#[async_trait::async_trait]
impl VendorAdapter for CountingVendor {
    fn name(&self) -> &str {
        VENDOR
    }

    async fn submit(&self, _report: &VendorReport) -> Result<VendorResponse, VendorError> {
        self.stats.vendor_calls.fetch_add(1, Ordering::Relaxed);
        Ok(VendorResponse {
            status: 200,
            body: "soak: not sent".into(),
            accepted: true,
        })
    }
}

type Task = Pin<Box<dyn std::future::Future<Output = ()> + Send>>;

pub struct ReviewCfg {
    pub queue_interval: Duration,
    pub submit_interval: Duration,
    pub approve_interval: Duration,
    pub approve_max: u64,
}

pub fn spawn(
    pool: PgPool,
    stats: Arc<ReviewStats>,
    cancel: CancellationToken,
    cfg: ReviewCfg,
) -> Vec<tokio::task::JoinHandle<()>> {
    let mut tasks: Vec<Task> = Vec::new();

    {
        let (pool, stats, cancel) = (pool.clone(), stats.clone(), cancel.clone());
        let interval = cfg.queue_interval;
        tasks.push(Box::pin(async move {
            let queue = ReviewQueue::new();
            while !cancel.is_cancelled() {
                match queue.populate(&pool).await {
                    Ok(n) => {
                        stats.populated.fetch_add(n as u64, Ordering::Relaxed);
                    }
                    Err(e) => eprintln!("review: populate failed: {e}"),
                }
                if let Err(e) = queue.withdraw(&pool).await {
                    eprintln!("review: withdraw failed: {e}");
                }
                tokio::select! {
                    _ = tokio::time::sleep(interval) => {}
                    _ = cancel.cancelled() => {}
                }
            }
        }));
    }

    {
        let (pool, stats, cancel) = (pool.clone(), stats.clone(), cancel.clone());
        let (interval, max) = (cfg.approve_interval, cfg.approve_max);
        tasks.push(Box::pin(async move {
            let queue = ReviewQueue::new();
            while !cancel.is_cancelled() {
                let approved = stats.approved.load(Ordering::Relaxed);
                if approved < max
                    && let Ok(pending) = queue.list_pending(&pool).await
                {
                    for entry in pending.into_iter().take((max - approved) as usize) {
                        if queue
                            .approve(&pool, entry.source_ip, Some("soak operator stand-in"))
                            .await
                            .is_ok()
                        {
                            stats.approved.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                }
                tokio::select! {
                    _ = tokio::time::sleep(interval) => {}
                    _ = cancel.cancelled() => {}
                }
            }
        }));
    }

    {
        let interval = cfg.submit_interval;
        tasks.push(Box::pin(async move {
            let runner = SubmissionRunner::new(
                pool,
                vec![Box::new(CountingVendor {
                    stats: stats.clone(),
                })],
                vec![VendorConfig {
                    name: VENDOR.into(),
                    enabled: true,
                    cooldown_hours: 24,
                    rate_limit: 1_000_000,
                    rate_window_hours: 1,
                    score_floor: None,
                    category_filter: None,
                }],
            );
            while !cancel.is_cancelled() {
                let started = Instant::now();
                match runner.run_once().await {
                    Ok(r) => {
                        stats
                            .submitted
                            .fetch_add(r.submitted as u64, Ordering::Relaxed);
                        stats.held.fetch_add(r.held as u64, Ordering::Relaxed);
                        stats.failed.fetch_add(r.failed as u64, Ordering::Relaxed);
                        stats
                            .unresolved
                            .fetch_add(r.unresolved as u64, Ordering::Relaxed);
                    }
                    Err(e) => {
                        eprintln!("review: submission pass failed: {e}");
                        stats.pass_errors.fetch_add(1, Ordering::Relaxed);
                    }
                }
                let ms = started.elapsed().as_millis() as u64;
                stats.passes.fetch_add(1, Ordering::Relaxed);
                stats.last_pass_ms.store(ms, Ordering::Relaxed);
                stats.max_pass_ms_window.fetch_max(ms, Ordering::Relaxed);
                stats
                    .last_pass_done_ms
                    .store(Utc::now().timestamp_millis() as u64, Ordering::Relaxed);
                tokio::select! {
                    _ = tokio::time::sleep(interval) => {}
                    _ = cancel.cancelled() => {}
                }
            }
        }));
    }

    tasks.into_iter().map(tokio::spawn).collect()
}
