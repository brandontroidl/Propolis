pub mod extract;
pub mod guard;
pub mod http;
pub mod store;
pub mod tftp;

use std::collections::HashMap;
use std::collections::HashSet;
use std::net::IpAddr;
use std::panic::AssertUnwindSafe;
use std::sync::Mutex;

use chrono::Utc;
use futures_util::FutureExt;
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use tokio::sync::Semaphore;

use guard::HostResolver;
use http::FetchLimits;

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum FetchStatus {
    Pending,
    Success,
    Dead,
    Rejected,
    TooBig,
    Timeout,
    Empty,
}

impl FetchStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Success => "success",
            Self::Dead => "dead",
            Self::Rejected => "rejected",
            Self::TooBig => "too_big",
            Self::Timeout => "timeout",
            Self::Empty => "empty",
        }
    }
}

/// Everything one `run_cycle` needs: the DB pool the `store` module reads/writes, the quarantine
/// spool captured bytes are written to, the SSRF-guard `own_ips` set and resolver every fetch is
/// vetted against, the shared byte/time limits, and the three tunables that bound the fetcher's
/// blast radius - redirect hops per fetch, recursion depth into extracted dropper-script URLs,
/// and fetches per host per hour.
pub struct FetchDeps {
    pub pool: PgPool,
    pub spool: sensor_framework::QuarantineSpool,
    pub own_ips: HashSet<IpAddr>,
    pub limits: FetchLimits,
    pub resolver: Box<dyn HostResolver + Send + Sync>,
    pub max_hops: u8,
    pub max_depth: u8,
    pub per_host_hour: u32,
}

/// Outcome counters for one `run_cycle` call - purely observational (logging/metrics), never
/// consulted to make a decision within the cycle itself.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CycleStats {
    pub selected: usize,
    pub succeeded: usize,
    pub rejected: usize,
    pub too_big: usize,
    pub timeout: usize,
    pub empty: usize,
    pub dead: usize,
    pub skipped_bucket: usize,
    pub enqueued_children: usize,
    pub errors: usize,
}

/// Failed attempts (`rejected`/`too_big`/`timeout`/`empty`) at which a row is marked terminal
/// (`dead`) and excluded from `select_candidates` forever after, regardless of `next_attempt`.
const MAX_ATTEMPTS: i32 = 3;

/// Fetches in flight at once within a single `run_cycle` call. Not part of `FetchDeps`: it
/// bounds this process's own resource usage (open sockets, buffered bytes), not an
/// operator-tunable fetch policy like `per_host_hour`.
const CONCURRENCY: usize = 8;

/// Backoff delay after the `attempts`-th failure (1-indexed): 5 min, then 20 min, doubling the
/// exponent each additional failure. Only ever called with `attempts < MAX_ATTEMPTS`, since the
/// `MAX_ATTEMPTS`-th failure goes straight to `dead` with no `next_attempt` at all.
fn backoff_delay(attempts: i32) -> chrono::Duration {
    let exp = (attempts - 1).clamp(0, 6);
    chrono::Duration::minutes(5i64 * 4i64.pow(exp as u32))
}

/// One fetch attempt's raw, scheme-agnostic result - the seam `run_cycle`'s orchestration
/// (dedup, backoff, bucket, spool, recursion) is driven through, mirroring `http.rs`'s
/// `HopFetcher` pattern. `RealFetcher` wires it to `guard::vet` + `fetch_http`/`fetch_tftp` for
/// production; tests substitute a scripted mock, since no address a hermetic test can bind a
/// listener to also clears `guard::vet`'s forbidden-address check (see `http.rs`'s redirect-loop
/// tests for the same constraint on the HTTP side) - there is no way to hermetically exercise a
/// real `Captured` outcome through the actual network path.
#[derive(Debug, Clone)]
enum RawOutcome {
    Captured {
        bytes: Vec<u8>,
        content_type: Option<String>,
        pinned_ip: Option<String>,
    },
    Failed {
        status: FetchStatus,
        reason: Option<String>,
    },
}

trait Fetcher {
    async fn fetch(&self, deps: &FetchDeps, candidate: &store::Candidate) -> RawOutcome;
}

/// The production `Fetcher`: dispatches by scheme. HTTP/HTTPS go through `fetch_http`, which
/// re-vets every redirect hop internally - it is never vetted here first. TFTP is vetted here
/// (`allow_tftp: true`) to obtain the `Pinned` target `fetch_tftp` requires, since TFTP has no
/// analogous internal re-vet loop of its own (it never redirects).
struct RealFetcher;

impl Fetcher for RealFetcher {
    async fn fetch(&self, deps: &FetchDeps, candidate: &store::Candidate) -> RawOutcome {
        match candidate.scheme.as_str() {
            "http" | "https" => match http::fetch_http(
                &candidate.url,
                &deps.own_ips,
                deps.resolver.as_ref(),
                &deps.limits,
                deps.max_hops,
            )
            .await
            {
                Ok(http::HttpOutcome::Captured(f)) => RawOutcome::Captured {
                    bytes: f.bytes,
                    content_type: f.content_type,
                    // fetch_http does not expose the pinned IP of whichever hop finally
                    // succeeded; re-deriving it here would mean a second, redundant vet/resolve
                    // against attacker-controlled state after the fact, so pinned_ip is left
                    // unset for HTTP captures (nullable in the schema).
                    pinned_ip: None,
                },
                Ok(http::HttpOutcome::Rejected(r)) => RawOutcome::Failed {
                    status: FetchStatus::Rejected,
                    reason: Some(format!("{r:?}")),
                },
                Ok(http::HttpOutcome::Empty) => RawOutcome::Failed {
                    status: FetchStatus::Empty,
                    reason: None,
                },
                Ok(http::HttpOutcome::TooBig) => RawOutcome::Failed {
                    status: FetchStatus::TooBig,
                    reason: None,
                },
                Ok(http::HttpOutcome::TooManyHops) => RawOutcome::Failed {
                    status: FetchStatus::Rejected,
                    reason: Some("too_many_hops".into()),
                },
                Err(e) => RawOutcome::Failed {
                    status: FetchStatus::Timeout,
                    reason: Some(e.to_string()),
                },
            },
            "tftp" => {
                let path = url::Url::parse(&candidate.url)
                    .map(|u| u.path().to_string())
                    .unwrap_or_default();
                match guard::vet(&candidate.url, &deps.own_ips, deps.resolver.as_ref(), true) {
                    Err(reject) => RawOutcome::Failed {
                        status: FetchStatus::Rejected,
                        reason: Some(format!("{reject:?}")),
                    },
                    Ok(pinned) => match tftp::fetch_tftp(&pinned, &path, &deps.limits).await {
                        Ok(tftp::TftpOutcome::Captured(bytes)) => RawOutcome::Captured {
                            bytes,
                            content_type: None,
                            pinned_ip: Some(pinned.ip.to_string()),
                        },
                        Ok(tftp::TftpOutcome::Empty) => RawOutcome::Failed {
                            status: FetchStatus::Empty,
                            reason: None,
                        },
                        Ok(tftp::TftpOutcome::TooBig) => RawOutcome::Failed {
                            status: FetchStatus::TooBig,
                            reason: None,
                        },
                        Ok(tftp::TftpOutcome::Oack) => RawOutcome::Failed {
                            status: FetchStatus::Rejected,
                            reason: Some("oack".into()),
                        },
                        Ok(tftp::TftpOutcome::Timeout) => RawOutcome::Failed {
                            status: FetchStatus::Timeout,
                            reason: None,
                        },
                        Err(e) => RawOutcome::Failed {
                            status: FetchStatus::Timeout,
                            reason: Some(e.to_string()),
                        },
                    },
                }
            }
            other => RawOutcome::Failed {
                status: FetchStatus::Rejected,
                reason: Some(format!("unsupported_scheme:{other}")),
            },
        }
    }
}

/// Run one selection+fetch cycle against the real network (`RealFetcher`). See `run_cycle_with`
/// for the orchestration itself.
pub async fn run_cycle(deps: &FetchDeps, batch: usize) -> CycleStats {
    run_cycle_with(deps, batch, &RealFetcher).await
}

/// Select up to `batch` candidates and process them with bounded concurrency: gate each on its
/// host's per-cycle budget, dispatch through `fetcher`, then record the outcome (spool + upsert
/// on success, backoff-or-terminal upsert on failure) and, on a successful capture still under
/// `max_depth`, enqueue any URLs `extract::extract_urls` finds in the body as depth+1 pending
/// rows. Every candidate's processing is isolated behind `catch_unwind`, so one panicking or
/// erroring URL never aborts the rest of the batch.
async fn run_cycle_with<F: Fetcher>(deps: &FetchDeps, batch: usize, fetcher: &F) -> CycleStats {
    let stats = Mutex::new(CycleStats::default());

    let candidates = match store::select_candidates(&deps.pool, batch as i64).await {
        Ok(c) => c,
        Err(e) => {
            tracing::error!(error = %e, "fetcher: select_candidates failed");
            stats.lock().unwrap().errors += 1;
            return stats.into_inner().unwrap();
        }
    };
    stats.lock().unwrap().selected = candidates.len();
    if candidates.is_empty() {
        return stats.into_inner().unwrap();
    }

    // Seed each distinct host's remaining budget for this cycle from one real last-hour count,
    // rather than re-checking per URL: this is what makes the per-host cap exact under bounded
    // concurrency (N tasks racing a fresh `host_count_last_hour` read of a not-yet-committed
    // count could all observe "under budget" and all proceed). A DB error on the check fails
    // closed - treat the host as already at capacity, never as unlimited.
    let mut hosts: Vec<&str> = candidates.iter().map(|c| c.host.as_str()).collect();
    hosts.sort_unstable();
    hosts.dedup();
    let mut budgets = HashMap::new();
    for host in hosts {
        let used = match store::host_count_last_hour(&deps.pool, host).await {
            Ok(n) => n,
            Err(e) => {
                tracing::warn!(host, error = %e, "fetcher: host_count_last_hour failed, treating host as at capacity");
                deps.per_host_hour as i64
            }
        };
        let remaining = (deps.per_host_hour as i64 - used).max(0);
        budgets.insert(host.to_string(), remaining);
    }
    let budgets = Mutex::new(budgets);

    let semaphore = Semaphore::new(CONCURRENCY);

    let tasks = candidates.iter().map(|candidate| {
        let sem = &semaphore;
        let budgets = &budgets;
        let stats = &stats;
        async move {
            let Ok(_permit) = sem.acquire().await else {
                return;
            };
            let outcome = AssertUnwindSafe(process_one(deps, fetcher, candidate, budgets, stats))
                .catch_unwind()
                .await;
            if outcome.is_err() {
                tracing::error!(url = %candidate.url, "fetcher: candidate processing panicked, isolated");
                stats.lock().unwrap().errors += 1;
            }
        }
    });
    futures_util::future::join_all(tasks).await;

    stats.into_inner().unwrap()
}

async fn process_one<F: Fetcher>(
    deps: &FetchDeps,
    fetcher: &F,
    candidate: &store::Candidate,
    budgets: &Mutex<HashMap<String, i64>>,
    stats: &Mutex<CycleStats>,
) {
    {
        let mut b = budgets.lock().unwrap();
        let remaining = b.entry(candidate.host.clone()).or_insert(0);
        if *remaining <= 0 {
            stats.lock().unwrap().skipped_bucket += 1;
            return;
        }
        *remaining -= 1;
    }

    match fetcher.fetch(deps, candidate).await {
        RawOutcome::Captured {
            bytes,
            content_type,
            pinned_ip,
        } if !bytes.is_empty() => {
            record_success(deps, candidate, bytes, content_type, pinned_ip, stats).await;
        }
        // Defense in depth: production never produces this (both HttpOutcome and TftpOutcome
        // have their own explicit Empty variant, mapped above before this ever runs), but a
        // zero-byte body must never reach the spool regardless of which layer detected it.
        RawOutcome::Captured { .. } => {
            record_failure(deps, candidate, FetchStatus::Empty, None, stats).await;
        }
        RawOutcome::Failed { status, reason } => {
            record_failure(deps, candidate, status, reason, stats).await;
        }
    }
}

async fn record_success(
    deps: &FetchDeps,
    candidate: &store::Candidate,
    bytes: Vec<u8>,
    content_type: Option<String>,
    pinned_ip: Option<String>,
    stats: &Mutex<CycleStats>,
) {
    let sha = Sha256::digest(&bytes).to_vec();

    if let Err(e) = deps.spool.store(&bytes) {
        tracing::warn!(url = %candidate.url, error = ?e, "fetcher: spool store failed, recording as a failed attempt");
        record_failure(
            deps,
            candidate,
            FetchStatus::Timeout,
            Some(format!("spool: {e:?}")),
            stats,
        )
        .await;
        return;
    }

    let result = store::AttemptResult {
        url_hash: candidate.url_hash.clone(),
        url: candidate.url.clone(),
        host: candidate.host.clone(),
        scheme: candidate.scheme.clone(),
        port: candidate.port,
        source_ip: candidate.source_ip,
        parent_hash: candidate.parent_hash.clone(),
        depth: candidate.depth,
        status: FetchStatus::Success,
        reject_reason: None,
        sha256: Some(sha),
        bytes: Some(bytes.len() as i32),
        content_type,
        pinned_ip,
        attempts: candidate.attempts,
        next_attempt: None,
    };
    if let Err(e) = store::upsert_attempt(&deps.pool, &result).await {
        tracing::error!(url = %candidate.url, error = %e, "fetcher: failed to record a successful attempt");
        stats.lock().unwrap().errors += 1;
        return;
    }
    stats.lock().unwrap().succeeded += 1;

    if candidate.depth < deps.max_depth as i32 {
        for child_url in extract::extract_urls(&bytes) {
            let Some((scheme, host, port)) = store::parse_url_parts(&child_url) else {
                continue;
            };
            let child = store::NewPendingRow {
                url_hash: store::url_hash(&child_url),
                url: child_url,
                host,
                scheme,
                port,
                source_ip: candidate.source_ip,
                parent_hash: Some(candidate.url_hash.clone()),
                depth: candidate.depth + 1,
            };
            // `insert_pending_if_absent`, never `upsert_attempt`: a child url that already has a
            // row - at any status - must be left completely untouched. Using an upsert here is
            // exactly what let a script cycle (A references B, B references A) or a script that
            // re-lists an already-`dead`/`success` url reset that row back to a fresh `pending`
            // depth-0-relative-to-nothing state, defeating both the recursion depth cap and the
            // terminal-after-3-attempts guarantee.
            match store::insert_pending_if_absent(&deps.pool, &child).await {
                Ok(true) => stats.lock().unwrap().enqueued_children += 1,
                Ok(false) => {}
                Err(e) => {
                    tracing::warn!(error = %e, "fetcher: failed to enqueue a recursion child url")
                }
            }
        }
    }
}

async fn record_failure(
    deps: &FetchDeps,
    candidate: &store::Candidate,
    outcome_status: FetchStatus,
    reason: Option<String>,
    stats: &Mutex<CycleStats>,
) {
    let attempts = candidate.attempts + 1;
    let (status, next_attempt) = if attempts >= MAX_ATTEMPTS {
        (FetchStatus::Dead, None)
    } else {
        (outcome_status, Some(Utc::now() + backoff_delay(attempts)))
    };

    let result = store::AttemptResult {
        url_hash: candidate.url_hash.clone(),
        url: candidate.url.clone(),
        host: candidate.host.clone(),
        scheme: candidate.scheme.clone(),
        port: candidate.port,
        source_ip: candidate.source_ip,
        parent_hash: candidate.parent_hash.clone(),
        depth: candidate.depth,
        status,
        reject_reason: reason,
        sha256: None,
        bytes: None,
        content_type: None,
        pinned_ip: None,
        attempts,
        next_attempt,
    };
    if let Err(e) = store::upsert_attempt(&deps.pool, &result).await {
        tracing::error!(url = %candidate.url, error = %e, "fetcher: failed to record a failed attempt");
        stats.lock().unwrap().errors += 1;
        return;
    }

    let mut s = stats.lock().unwrap();
    match status {
        FetchStatus::Dead => s.dead += 1,
        FetchStatus::Rejected => s.rejected += 1,
        FetchStatus::TooBig => s.too_big += 1,
        FetchStatus::Timeout => s.timeout += 1,
        FetchStatus::Empty => s.empty += 1,
        FetchStatus::Pending | FetchStatus::Success => {}
    }
}

/// DB-backed `run_cycle` orchestration tests: dedup/sync, reject/spool, backoff/terminal,
/// per-host bucket, recursion depth cap, empty-body handling, and panic isolation.
///
/// Shares the persistent `propolis_test` database with other crates' tests (see
/// `queue_test.rs`/`gatekeeper_test.rs`'s module docs for the same convention). Because
/// `select_candidates` is deliberately GLOBAL - it selects across the whole `fetch_attempt`
/// table, not scoped to any one test - these tests MUST run serially:
/// `cargo test -p review --lib fetcher::orchestration_tests -- --test-threads=1`. Run in
/// parallel, one test's `reset_all` wipe (or its `run_cycle_with` call, which can select rows
/// another concurrently-running test just inserted) races another test's fixtures and produces
/// spurious counts - verified empirically (three consecutive default-parallelism runs each
/// failed with different, non-reproducible mismatched counts; three consecutive
/// `--test-threads=1` runs were all clean). `--test-threads=1` is required for this crate's
/// existing DB-backed integration tests for the identical reason.
#[cfg(test)]
mod orchestration_tests {
    use super::*;
    use std::collections::{HashMap, HashSet};
    use std::net::IpAddr;

    use chrono::Utc;
    use core_scoring::{EventInput, Protocol, SignalType, append_event};
    use sha2::{Digest, Sha256};
    use sqlx::PgPool;
    use tempfile::TempDir;

    use crate::fetcher::guard::HostResolver;
    use crate::fetcher::http::FetchLimits;

    async fn test_pool() -> PgPool {
        let url = std::env::var("DATABASE_URL")
            .unwrap_or_else(|_| "postgres://propolis:propolis@localhost:5432/propolis_test".into());
        let pool = PgPool::connect(&url).await.unwrap();
        sqlx::migrate!("../core-scoring/migrations")
            .run(&pool)
            .await
            .unwrap();
        crate::migrator().run(&pool).await.unwrap();
        pool
    }

    /// Wipes every row this whole test suite could have left behind, from THIS run or a prior
    /// one - not just the calling test's own host. `propolis_test` is a persistent shared
    /// database (matches `queue_test.rs`'s `reset_ip` convention), and `select_candidates` is
    /// deliberately GLOBAL (it has to be, to serve the whole table each cycle) - so a row any
    /// other test in this file leaves non-terminal (still `pending`, or backed off with an
    /// elapsed `next_attempt`) is visible to every later `select_candidates` call in the same
    /// process, not just its own test. Two concrete leaks this closes: the per-host-bucket test
    /// intentionally leaves 40 of its 50 rows `pending` (only `per_host_hour` get attempted),
    /// and the panic-isolation test's "boom" row never reaches an upsert at all (the panic fires
    /// before `record_failure`/`record_success` runs), so it too stays `pending` forever. Both
    /// are exactly the kind of row a later test's own `select_candidates` batch would otherwise
    /// scoop up ahead of its own freshly-seeded one (`ORDER BY first_seen` sorts the older,
    /// leaked-in row first). Called at the start of every test so each is self-contained
    /// regardless of run order or which tests ran before it.
    async fn reset_all(pool: &PgPool) {
        sqlx::query("DELETE FROM fetch_attempt WHERE host LIKE 'fetch8%.example'")
            .execute(pool)
            .await
            .unwrap();
        sqlx::query("DELETE FROM event WHERE source_ip::text LIKE '203.0.113.%'")
            .execute(pool)
            .await
            .unwrap();
    }

    fn download_event(ip: &str, sensor: &str, url: &str, ts: &str) -> EventInput {
        EventInput::from_signal(
            ip.parse().unwrap(),
            None,
            sensor.into(),
            SignalType::HoneypotFileDownload,
            Protocol::Tcp,
            true,
            ts.parse().unwrap(),
            serde_json::json!({ "url": url }),
            None,
        )
    }

    struct DummyResolver;
    impl HostResolver for DummyResolver {
        fn resolve(&self, _host: &str) -> std::io::Result<Vec<IpAddr>> {
            panic!("orchestration tests never dispatch through the real resolver/fetch path")
        }
    }

    fn test_limits() -> FetchLimits {
        FetchLimits {
            max_bytes: 10_000_000,
            connect_timeout: std::time::Duration::from_secs(1),
            read_timeout: std::time::Duration::from_secs(1),
            total_timeout: std::time::Duration::from_secs(1),
            user_agent: "propolis-fetcher-test".into(),
        }
    }

    fn test_deps(pool: PgPool, spool_dir: &TempDir, per_host_hour: u32) -> FetchDeps {
        FetchDeps {
            pool,
            spool: sensor_framework::QuarantineSpool::new(
                spool_dir.path().to_path_buf(),
                10_000_000,
                1_000_000_000,
            ),
            own_ips: HashSet::new(),
            limits: test_limits(),
            resolver: Box::new(DummyResolver),
            max_hops: 3,
            max_depth: 2,
            per_host_hour,
        }
    }

    /// A scripted [`Fetcher`] test double: returns a fixed outcome per exact URL (or a shared
    /// default for a whole batch), and can be told to panic for one URL to prove `run_cycle`
    /// isolates a per-candidate panic rather than aborting the whole batch. Panics on an
    /// unscripted, non-defaulted URL - a loop bug that fetches something unexpected shows up as a
    /// test failure rather than silently passing (matches `http.rs`'s `MockHopFetcher`).
    struct MockFetcher {
        scripted: HashMap<String, RawOutcome>,
        default: Option<RawOutcome>,
        panic_on: HashSet<String>,
    }

    impl MockFetcher {
        fn new() -> Self {
            Self {
                scripted: HashMap::new(),
                default: None,
                panic_on: HashSet::new(),
            }
        }
        fn on(mut self, url: &str, outcome: RawOutcome) -> Self {
            self.scripted.insert(url.to_string(), outcome);
            self
        }
        fn default_outcome(mut self, outcome: RawOutcome) -> Self {
            self.default = Some(outcome);
            self
        }
        fn panic_on_url(mut self, url: &str) -> Self {
            self.panic_on.insert(url.to_string());
            self
        }
    }

    impl Fetcher for MockFetcher {
        async fn fetch(&self, _deps: &FetchDeps, candidate: &store::Candidate) -> RawOutcome {
            if self.panic_on.contains(&candidate.url) {
                panic!("scripted panic for {}", candidate.url);
            }
            self.scripted
                .get(&candidate.url)
                .cloned()
                .or_else(|| self.default.clone())
                .unwrap_or_else(|| panic!("unscripted url in MockFetcher: {}", candidate.url))
        }
    }

    // (a) a honeypot_file_download event with a public-resolving URL -> spool gets the sample,
    // fetch_attempt.status='success'.
    #[tokio::test]
    async fn captured_body_is_spooled_and_recorded_success() {
        let pool = test_pool().await;
        let host = "fetch8a.example";
        let ip = "203.0.113.10";
        let url = format!("http://{host}/mal.bin");
        reset_all(&pool).await;

        append_event(
            &pool,
            download_event(ip, "sensor-a", &url, "2026-08-22T00:00:00Z"),
        )
        .await
        .unwrap();

        let spool_dir = TempDir::new().unwrap();
        let deps = test_deps(pool.clone(), &spool_dir, 100);
        let bytes = b"totally-a-malware-sample".to_vec();
        let fetcher = MockFetcher::new().on(
            &url,
            RawOutcome::Captured {
                bytes: bytes.clone(),
                content_type: Some("application/octet-stream".into()),
                pinned_ip: Some("93.184.216.34".into()),
            },
        );

        let stats = run_cycle_with(&deps, 10, &fetcher).await;
        assert_eq!(stats.succeeded, 1);

        let row = sqlx::query(
            "SELECT status, sha256, bytes, content_type, pinned_ip, attempts \
             FROM fetch_attempt WHERE url_hash = $1",
        )
        .bind(store::url_hash(&url))
        .fetch_one(&pool)
        .await
        .unwrap();
        use sqlx::Row;
        let status: String = row.get("status");
        let sha256: Vec<u8> = row.get("sha256");
        let stored_bytes: i32 = row.get("bytes");
        let content_type: String = row.get("content_type");
        let pinned_ip: String = row.get("pinned_ip");
        assert_eq!(status, "success");
        assert_eq!(sha256, Sha256::digest(&bytes).to_vec());
        assert_eq!(stored_bytes, bytes.len() as i32);
        assert_eq!(content_type, "application/octet-stream");
        assert_eq!(pinned_ip, "93.184.216.34");

        let hex = to_hex(&sha256);
        let spooled = spool_dir.path().join(&hex);
        assert!(spooled.exists(), "spool file {hex} was not written");
        assert_eq!(std::fs::read(&spooled).unwrap(), bytes);
    }

    // (b) a forbidden URL -> status='rejected', reject_reason set, no spool write.
    #[tokio::test]
    async fn rejected_url_is_recorded_with_no_spool_write() {
        let pool = test_pool().await;
        let host = "fetch8b.example";
        let ip = "203.0.113.11";
        let url = format!("http://{host}/x");
        reset_all(&pool).await;

        append_event(
            &pool,
            download_event(ip, "sensor-b", &url, "2026-08-22T00:00:00Z"),
        )
        .await
        .unwrap();

        let spool_dir = TempDir::new().unwrap();
        let deps = test_deps(pool.clone(), &spool_dir, 100);
        let fetcher = MockFetcher::new().on(
            &url,
            RawOutcome::Failed {
                status: FetchStatus::Rejected,
                reason: Some("Forbidden(Reserved)".into()),
            },
        );

        let stats = run_cycle_with(&deps, 10, &fetcher).await;
        assert_eq!(stats.rejected, 1);

        use sqlx::Row;
        let row = sqlx::query(
            "SELECT status, reject_reason, sha256, attempts, next_attempt \
             FROM fetch_attempt WHERE url_hash = $1",
        )
        .bind(store::url_hash(&url))
        .fetch_one(&pool)
        .await
        .unwrap();
        let status: String = row.get("status");
        let reject_reason: Option<String> = row.get("reject_reason");
        let sha256: Option<Vec<u8>> = row.get("sha256");
        let attempts: i32 = row.get("attempts");
        let next_attempt: Option<chrono::DateTime<Utc>> = row.get("next_attempt");
        assert_eq!(status, "rejected");
        assert!(reject_reason.is_some());
        assert!(sha256.is_none());
        assert_eq!(attempts, 1);
        assert!(next_attempt.is_some());

        // Directory holds nothing: never wrote a sample for a rejected fetch.
        let entries: Vec<_> = std::fs::read_dir(spool_dir.path()).unwrap().collect();
        assert!(entries.is_empty());
    }

    // (c) a failed URL writes a backoff row and is not re-selected before next_attempt; terminal
    // after 3 attempts.
    #[tokio::test]
    async fn backoff_row_is_not_reselected_early_and_goes_terminal_after_three() {
        let pool = test_pool().await;
        let host = "fetch8c.example";
        let url = format!("http://{host}/y");
        reset_all(&pool).await;

        store::upsert_attempt(
            &pool,
            &store::AttemptResult {
                url_hash: store::url_hash(&url),
                url: url.clone(),
                host: host.to_string(),
                scheme: "http".into(),
                port: Some(80),
                source_ip: None,
                parent_hash: None,
                depth: 0,
                status: FetchStatus::Pending,
                reject_reason: None,
                sha256: None,
                bytes: None,
                content_type: None,
                pinned_ip: None,
                attempts: 0,
                next_attempt: None,
            },
        )
        .await
        .unwrap();

        let spool_dir = TempDir::new().unwrap();
        let deps = test_deps(pool.clone(), &spool_dir, 100);
        let fetcher = MockFetcher::new().on(
            &url,
            RawOutcome::Failed {
                status: FetchStatus::Rejected,
                reason: Some("boom".into()),
            },
        );

        async fn attempts_and_status(pool: &PgPool, url: &str) -> (i32, String) {
            use sqlx::Row;
            let row = sqlx::query("SELECT attempts, status FROM fetch_attempt WHERE url_hash = $1")
                .bind(store::url_hash(url))
                .fetch_one(pool)
                .await
                .unwrap();
            (row.get("attempts"), row.get("status"))
        }
        async fn expire_backoff(pool: &PgPool, url: &str) {
            sqlx::query(
                "UPDATE fetch_attempt SET next_attempt = now() - interval '1 minute' \
                 WHERE url_hash = $1",
            )
            .bind(store::url_hash(url))
            .execute(pool)
            .await
            .unwrap();
        }

        // 1st cycle: selected, fails, attempts=1, backed off into the future.
        run_cycle_with(&deps, 10, &fetcher).await;
        let (attempts, status) = attempts_and_status(&pool, &url).await;
        assert_eq!((attempts, status.as_str()), (1, "rejected"));

        // 2nd cycle, immediately: next_attempt is still in the future -> not reselected.
        run_cycle_with(&deps, 10, &fetcher).await;
        let (attempts, _) = attempts_and_status(&pool, &url).await;
        assert_eq!(attempts, 1, "must not be reselected before next_attempt");

        // Expire the backoff, retry -> attempts=2.
        expire_backoff(&pool, &url).await;
        run_cycle_with(&deps, 10, &fetcher).await;
        let (attempts, status) = attempts_and_status(&pool, &url).await;
        assert_eq!((attempts, status.as_str()), (2, "rejected"));

        // Expire again, retry a 3rd time -> terminal (dead).
        expire_backoff(&pool, &url).await;
        run_cycle_with(&deps, 10, &fetcher).await;
        let (attempts, status) = attempts_and_status(&pool, &url).await;
        assert_eq!((attempts, status.as_str()), (3, "dead"));

        // Dead is never reselected again, regardless of next_attempt (which is NULL here).
        run_cycle_with(&deps, 10, &fetcher).await;
        let (attempts, status) = attempts_and_status(&pool, &url).await;
        assert_eq!((attempts, status.as_str()), (3, "dead"));
    }

    // (d) 50 URLs on one host -> at most per_host_hour fetched.
    #[tokio::test]
    async fn per_host_hourly_bucket_caps_fetches() {
        let pool = test_pool().await;
        let host = "fetch8d.example";
        reset_all(&pool).await;

        for i in 0..50 {
            let url = format!("http://{host}/f{i}");
            store::upsert_attempt(
                &pool,
                &store::AttemptResult {
                    url_hash: store::url_hash(&url),
                    url,
                    host: host.to_string(),
                    scheme: "http".into(),
                    port: Some(80),
                    source_ip: None,
                    parent_hash: None,
                    depth: 0,
                    status: FetchStatus::Pending,
                    reject_reason: None,
                    sha256: None,
                    bytes: None,
                    content_type: None,
                    pinned_ip: None,
                    attempts: 0,
                    next_attempt: None,
                },
            )
            .await
            .unwrap();
        }

        let spool_dir = TempDir::new().unwrap();
        let deps = test_deps(pool.clone(), &spool_dir, 10);
        let fetcher = MockFetcher::new().default_outcome(RawOutcome::Failed {
            status: FetchStatus::Timeout,
            reason: None,
        });

        let stats = run_cycle_with(&deps, 50, &fetcher).await;
        assert_eq!(stats.selected, 50);
        assert_eq!(stats.timeout, 10, "must fetch exactly per_host_hour urls");
        assert_eq!(stats.skipped_bucket, 40);

        let attempted: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM fetch_attempt WHERE host = $1 AND status != 'pending'",
        )
        .bind(host)
        .fetch_one(&pool)
        .await
        .unwrap();
        let still_pending: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM fetch_attempt WHERE host = $1 AND status = 'pending'",
        )
        .bind(host)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(attempted, 10);
        assert_eq!(still_pending, 40);
    }

    // (e) a fetched script body enqueues depth-1 synthetic rows; depth 3 is never enqueued.
    #[tokio::test]
    async fn recursion_enqueues_children_but_never_past_max_depth() {
        let pool = test_pool().await;
        let host = "fetch8e.example";
        let ip = "203.0.113.12";
        reset_all(&pool).await;

        // Depth 0 -> 1: a real event-sourced download whose body is a dropper script.
        let loader_url = format!("http://{host}/loader.sh");
        append_event(
            &pool,
            download_event(ip, "sensor-e", &loader_url, "2026-08-22T00:00:00Z"),
        )
        .await
        .unwrap();
        let payload_url = format!("http://{host}/payload.arm");
        let script = format!("#!/bin/sh\nwget {payload_url}\n");

        // Depth 2 -> would-be 3: a synthetic row already at max_depth, seeded directly the way
        // two prior recursive cycles would have produced it.
        let stage3_url = format!("http://{host}/stage3.sh");
        store::upsert_attempt(
            &pool,
            &store::AttemptResult {
                url_hash: store::url_hash(&stage3_url),
                url: stage3_url.clone(),
                host: host.to_string(),
                scheme: "http".into(),
                port: Some(80),
                source_ip: None,
                parent_hash: None,
                depth: 2,
                status: FetchStatus::Pending,
                reject_reason: None,
                sha256: None,
                bytes: None,
                content_type: None,
                pinned_ip: None,
                attempts: 0,
                next_attempt: None,
            },
        )
        .await
        .unwrap();
        let final_url = format!("http://{host}/final.arm");
        let stage3_script = format!("#!/bin/sh\nwget {final_url}\n");

        let spool_dir = TempDir::new().unwrap();
        let deps = test_deps(pool.clone(), &spool_dir, 100);
        let fetcher = MockFetcher::new()
            .on(
                &loader_url,
                RawOutcome::Captured {
                    bytes: script.into_bytes(),
                    content_type: None,
                    pinned_ip: None,
                },
            )
            .on(
                &stage3_url,
                RawOutcome::Captured {
                    bytes: stage3_script.into_bytes(),
                    content_type: None,
                    pinned_ip: None,
                },
            );

        run_cycle_with(&deps, 10, &fetcher).await;

        use sqlx::Row;
        let depth1 =
            sqlx::query("SELECT depth, parent_hash FROM fetch_attempt WHERE url_hash = $1")
                .bind(store::url_hash(&payload_url))
                .fetch_one(&pool)
                .await
                .unwrap();
        let depth1_depth: i32 = depth1.get("depth");
        let depth1_parent: Vec<u8> = depth1.get("parent_hash");
        assert_eq!(depth1_depth, 1);
        assert_eq!(depth1_parent, store::url_hash(&loader_url));

        let depth3_count: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM fetch_attempt WHERE host = $1 AND depth = 3")
                .bind(host)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(depth3_count, 0, "depth 3 must never be enqueued");

        let stage3_status: String =
            sqlx::query_scalar("SELECT status FROM fetch_attempt WHERE url_hash = $1")
                .bind(store::url_hash(&stage3_url))
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(
            stage3_status, "success",
            "the depth-2 row itself still succeeds; only its children are capped"
        );
    }

    // Fix round 1, #1 (critical): a recursion child whose url_hash already has a row must never
    // reset that row - regardless of its current status. A -> B -> A must settle after both
    // succeed once, not ping-pong forever (the depth cap alone cannot stop a cycle if
    // re-discovering an already-`success` url resets it back to `pending`/depth 0).
    #[tokio::test]
    async fn recursion_cycle_a_to_b_to_a_terminates_without_perpetual_repending() {
        let pool = test_pool().await;
        let host = "fetch8i.example";
        reset_all(&pool).await;

        let url_a = format!("http://{host}/a.sh");
        let url_b = format!("http://{host}/b.sh");

        store::upsert_attempt(
            &pool,
            &store::AttemptResult {
                url_hash: store::url_hash(&url_a),
                url: url_a.clone(),
                host: host.to_string(),
                scheme: "http".into(),
                port: Some(80),
                source_ip: None,
                parent_hash: None,
                depth: 0,
                status: FetchStatus::Pending,
                reject_reason: None,
                sha256: None,
                bytes: None,
                content_type: None,
                pinned_ip: None,
                attempts: 0,
                next_attempt: None,
            },
        )
        .await
        .unwrap();

        let spool_dir = TempDir::new().unwrap();
        let deps = test_deps(pool.clone(), &spool_dir, 100);
        let script_a = format!("#!/bin/sh\nwget {url_b}\n").into_bytes();
        let script_b = format!("#!/bin/sh\nwget {url_a}\n").into_bytes();
        let fetcher = MockFetcher::new()
            .on(
                &url_a,
                RawOutcome::Captured {
                    bytes: script_a,
                    content_type: None,
                    pinned_ip: None,
                },
            )
            .on(
                &url_b,
                RawOutcome::Captured {
                    bytes: script_b,
                    content_type: None,
                    pinned_ip: None,
                },
            );

        // Cycle 1: selects A, captures it, enqueues B fresh at depth 1.
        let s1 = run_cycle_with(&deps, 10, &fetcher).await;
        assert_eq!(s1.succeeded, 1);
        assert_eq!(s1.enqueued_children, 1);

        // Cycle 2: selects B, captures it, and its script re-references A - which already has a
        // row (now `success`). That must be a no-op, not a reset back to `pending`.
        let s2 = run_cycle_with(&deps, 10, &fetcher).await;
        assert_eq!(s2.succeeded, 1);
        assert_eq!(
            s2.enqueued_children, 0,
            "re-discovering A must not create a new row or reset the existing one"
        );

        use sqlx::Row;
        let a_row = sqlx::query("SELECT status, depth FROM fetch_attempt WHERE url_hash = $1")
            .bind(store::url_hash(&url_a))
            .fetch_one(&pool)
            .await
            .unwrap();
        let a_status: String = a_row.get("status");
        let a_depth: i32 = a_row.get("depth");
        assert_eq!(
            a_status, "success",
            "A must stay success, not reset to pending"
        );
        assert_eq!(
            a_depth, 0,
            "A's depth must never be rewritten by being re-discovered"
        );

        // Cycle 3: both A and B are `success` - nothing eligible. If the bug were still present,
        // A would have been reset to `pending` in cycle 2 and would be selected again here,
        // ping-ponging forever.
        let s3 = run_cycle_with(&deps, 10, &fetcher).await;
        assert_eq!(
            s3.selected, 0,
            "the cycle must have terminated, nothing left to select"
        );

        let rows: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM fetch_attempt WHERE host = $1")
            .bind(host)
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(rows, 2, "must never grow past the two real urls");
    }

    // Fix round 1, #1 (critical): a script that lists an already-`dead` url as a child must not
    // resurrect it - defeats the terminal-after-3-attempts guarantee otherwise.
    #[tokio::test]
    async fn recursion_never_resurrects_an_already_dead_child() {
        let pool = test_pool().await;
        let host = "fetch8j.example";
        reset_all(&pool).await;

        let dead_url = format!("http://{host}/dead.bin");
        let loader_url = format!("http://{host}/loader.sh");

        store::upsert_attempt(
            &pool,
            &store::AttemptResult {
                url_hash: store::url_hash(&dead_url),
                url: dead_url.clone(),
                host: host.to_string(),
                scheme: "http".into(),
                port: Some(80),
                source_ip: None,
                parent_hash: None,
                depth: 0,
                status: FetchStatus::Dead,
                reject_reason: Some("boom".into()),
                sha256: None,
                bytes: None,
                content_type: None,
                pinned_ip: None,
                attempts: 3,
                next_attempt: None,
            },
        )
        .await
        .unwrap();

        store::upsert_attempt(
            &pool,
            &store::AttemptResult {
                url_hash: store::url_hash(&loader_url),
                url: loader_url.clone(),
                host: host.to_string(),
                scheme: "http".into(),
                port: Some(80),
                source_ip: None,
                parent_hash: None,
                depth: 0,
                status: FetchStatus::Pending,
                reject_reason: None,
                sha256: None,
                bytes: None,
                content_type: None,
                pinned_ip: None,
                attempts: 0,
                next_attempt: None,
            },
        )
        .await
        .unwrap();

        let spool_dir = TempDir::new().unwrap();
        let deps = test_deps(pool.clone(), &spool_dir, 100);
        let script = format!("#!/bin/sh\nwget {dead_url}\n").into_bytes();
        let fetcher = MockFetcher::new().on(
            &loader_url,
            RawOutcome::Captured {
                bytes: script,
                content_type: None,
                pinned_ip: None,
            },
        );

        let stats = run_cycle_with(&deps, 10, &fetcher).await;
        assert_eq!(stats.succeeded, 1);
        assert_eq!(
            stats.enqueued_children, 0,
            "the already-dead url must not be re-enqueued"
        );

        use sqlx::Row;
        let row = sqlx::query(
            "SELECT status, attempts, reject_reason FROM fetch_attempt WHERE url_hash = $1",
        )
        .bind(store::url_hash(&dead_url))
        .fetch_one(&pool)
        .await
        .unwrap();
        let status: String = row.get("status");
        let attempts: i32 = row.get("attempts");
        let reason: Option<String> = row.get("reject_reason");
        assert_eq!(status, "dead");
        assert_eq!(attempts, 3);
        assert_eq!(reason.as_deref(), Some("boom"));

        let next = store::select_candidates(&pool, 100).await.unwrap();
        assert!(
            !next.iter().any(|c| c.url == dead_url),
            "a dead row must never be reselected"
        );
    }

    // Fix round 1, #1 (critical): a script that lists an already-`success` url as a child must
    // not reset it back to pending - would wipe sha256/bytes/content_type/pinned_ip for a sample
    // already safely spooled.
    #[tokio::test]
    async fn recursion_never_resets_an_already_successful_child() {
        let pool = test_pool().await;
        let host = "fetch8k.example";
        reset_all(&pool).await;

        let done_url = format!("http://{host}/done.bin");
        let loader_url = format!("http://{host}/loader2.sh");
        let existing_sha = vec![0xABu8; 32];

        store::upsert_attempt(
            &pool,
            &store::AttemptResult {
                url_hash: store::url_hash(&done_url),
                url: done_url.clone(),
                host: host.to_string(),
                scheme: "http".into(),
                port: Some(80),
                source_ip: None,
                parent_hash: None,
                depth: 0,
                status: FetchStatus::Success,
                reject_reason: None,
                sha256: Some(existing_sha.clone()),
                bytes: Some(1234),
                content_type: Some("application/octet-stream".into()),
                pinned_ip: Some("93.184.216.34".into()),
                attempts: 0,
                next_attempt: None,
            },
        )
        .await
        .unwrap();

        store::upsert_attempt(
            &pool,
            &store::AttemptResult {
                url_hash: store::url_hash(&loader_url),
                url: loader_url.clone(),
                host: host.to_string(),
                scheme: "http".into(),
                port: Some(80),
                source_ip: None,
                parent_hash: None,
                depth: 0,
                status: FetchStatus::Pending,
                reject_reason: None,
                sha256: None,
                bytes: None,
                content_type: None,
                pinned_ip: None,
                attempts: 0,
                next_attempt: None,
            },
        )
        .await
        .unwrap();

        let spool_dir = TempDir::new().unwrap();
        let deps = test_deps(pool.clone(), &spool_dir, 100);
        let script = format!("#!/bin/sh\nwget {done_url}\n").into_bytes();
        let fetcher = MockFetcher::new().on(
            &loader_url,
            RawOutcome::Captured {
                bytes: script,
                content_type: None,
                pinned_ip: None,
            },
        );

        let stats = run_cycle_with(&deps, 10, &fetcher).await;
        assert_eq!(stats.succeeded, 1);
        assert_eq!(stats.enqueued_children, 0);

        use sqlx::Row;
        let row =
            sqlx::query("SELECT status, sha256, bytes FROM fetch_attempt WHERE url_hash = $1")
                .bind(store::url_hash(&done_url))
                .fetch_one(&pool)
                .await
                .unwrap();
        let status: String = row.get("status");
        let sha256: Vec<u8> = row.get("sha256");
        let bytes: i32 = row.get("bytes");
        assert_eq!(status, "success");
        assert_eq!(sha256, existing_sha);
        assert_eq!(bytes, 1234);
    }

    // (f) a zero-byte body -> status='empty', no spool write, not re-fetched.
    #[tokio::test]
    async fn empty_body_is_recorded_with_no_spool_write_and_backs_off() {
        let pool = test_pool().await;
        let host = "fetch8f.example";
        let ip = "203.0.113.13";
        let url = format!("http://{host}/empty.bin");
        reset_all(&pool).await;

        append_event(
            &pool,
            download_event(ip, "sensor-f", &url, "2026-08-22T00:00:00Z"),
        )
        .await
        .unwrap();

        let spool_dir = TempDir::new().unwrap();
        let deps = test_deps(pool.clone(), &spool_dir, 100);
        let fetcher = MockFetcher::new().on(
            &url,
            RawOutcome::Failed {
                status: FetchStatus::Empty,
                reason: None,
            },
        );

        let stats = run_cycle_with(&deps, 10, &fetcher).await;
        assert_eq!(stats.empty, 1);

        use sqlx::Row;
        let row =
            sqlx::query("SELECT status, sha256, attempts FROM fetch_attempt WHERE url_hash = $1")
                .bind(store::url_hash(&url))
                .fetch_one(&pool)
                .await
                .unwrap();
        let status: String = row.get("status");
        let sha256: Option<Vec<u8>> = row.get("sha256");
        let attempts: i32 = row.get("attempts");
        assert_eq!(status, "empty");
        assert!(sha256.is_none());
        assert_eq!(attempts, 1);

        let entries: Vec<_> = std::fs::read_dir(spool_dir.path()).unwrap().collect();
        assert!(
            entries.is_empty(),
            "an empty body must never reach the spool"
        );

        // Not re-fetched immediately: next_attempt is still in the future.
        run_cycle_with(&deps, 10, &fetcher).await;
        let attempts_again: i32 =
            sqlx::query_scalar("SELECT attempts FROM fetch_attempt WHERE url_hash = $1")
                .bind(store::url_hash(&url))
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(
            attempts_again, 1,
            "must not be re-fetched before next_attempt elapses"
        );
    }

    // Bonus: one URL's fetcher panic never aborts the batch (never-panic-the-caller requirement).
    #[tokio::test]
    async fn a_panicking_fetch_is_isolated_and_the_batch_continues() {
        let pool = test_pool().await;
        let host = "fetch8g.example";
        reset_all(&pool).await;

        let boom_url = format!("http://{host}/boom");
        let ok_url = format!("http://{host}/ok");
        for u in [&boom_url, &ok_url] {
            store::upsert_attempt(
                &pool,
                &store::AttemptResult {
                    url_hash: store::url_hash(u),
                    url: u.clone(),
                    host: host.to_string(),
                    scheme: "http".into(),
                    port: Some(80),
                    source_ip: None,
                    parent_hash: None,
                    depth: 0,
                    status: FetchStatus::Pending,
                    reject_reason: None,
                    sha256: None,
                    bytes: None,
                    content_type: None,
                    pinned_ip: None,
                    attempts: 0,
                    next_attempt: None,
                },
            )
            .await
            .unwrap();
        }

        let spool_dir = TempDir::new().unwrap();
        let deps = test_deps(pool.clone(), &spool_dir, 100);
        let fetcher = MockFetcher::new().panic_on_url(&boom_url).on(
            &ok_url,
            RawOutcome::Failed {
                status: FetchStatus::Timeout,
                reason: None,
            },
        );

        let stats = run_cycle_with(&deps, 10, &fetcher).await;
        assert!(stats.errors >= 1);
        assert_eq!(
            stats.timeout, 1,
            "the other url in the batch must still be processed"
        );

        let ok_attempts: i32 =
            sqlx::query_scalar("SELECT attempts FROM fetch_attempt WHERE url_hash = $1")
                .bind(store::url_hash(&ok_url))
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(ok_attempts, 1);
    }

    fn to_hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }
}
