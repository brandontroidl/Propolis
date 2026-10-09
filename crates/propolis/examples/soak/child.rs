//! The intake process under test: one `IntakeRunner` per sensor log, driven by the same loop the
//! daemon runs (`run_intake_sensor` in `crates/propolis/src/main.rs`: read a batch, publish
//! progress, persist the cursor when the position moved, sleep only when idle). It is a separate
//! process so the orchestrator can SIGKILL it, measure its resident memory alone, and restart it
//! on the same cursor directory exactly as systemd would restart the daemon.
//!
//! Progress is published as a small JSON status file, replaced atomically once a second.

use std::collections::{BTreeMap, HashSet};
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use chrono::{DateTime, Utc};
use intake::runner::IntakeRunner;
use log_tailer::LogTailer;
use serde_json::json;
use sqlx::postgres::PgPoolOptions;
use tokio_util::sync::CancellationToken;

use crate::Args;

#[derive(Default, Clone)]
struct SensorStatus {
    ingested: u64,
    rejected: u64,
    errors: u64,
    batches: u64,
    batch_ns_total: u64,
    /// Longest batch since the last status write; the writer folds it into `recent_max`.
    batch_ns_max_window: u64,
    /// The longest batch of each of the last 60 status writes, so a reader sampling every few
    /// seconds still sees the worst batch of the interval.
    recent_max: std::collections::VecDeque<u64>,
    last_batch_lines: u64,
    bytes_behind: u64,
    last_ingested_observed_at: Option<DateTime<Utc>>,
    wedged: Option<String>,
}

type Shared = Arc<Mutex<BTreeMap<String, SensorStatus>>>;

fn lock(shared: &Shared) -> std::sync::MutexGuard<'_, BTreeMap<String, SensorStatus>> {
    shared.lock().unwrap_or_else(|p| p.into_inner())
}

async fn run_sensor(
    name: String,
    log_path: PathBuf,
    cursor_dir: PathBuf,
    pool: sqlx::PgPool,
    poll: Duration,
    cancel: CancellationToken,
    shared: Shared,
) {
    let tailer = LogTailer::new(log_path, cursor_dir);
    let mut runner = IntakeRunner::new(
        tailer,
        pool,
        name.clone(),
        Arc::new(HashSet::<IpAddr>::new()),
        Duration::from_secs(600),
    );
    loop {
        if cancel.is_cancelled() {
            if let Err(e) = runner.persist_cursor() {
                eprintln!("{name}: cursor persist on shutdown failed: {e}");
            }
            return;
        }
        let started = Instant::now();
        let result = runner.run_batch().await;
        let took = started.elapsed().as_nanos() as u64;
        let bytes_behind = runner.backlog_bytes();
        {
            let mut map = lock(&shared);
            let entry = map.entry(name.clone()).or_default();
            entry.ingested += result.ingested as u64;
            entry.rejected += result.rejected as u64;
            entry.errors += result.errors as u64;
            entry.batches += 1;
            entry.batch_ns_total += took;
            entry.batch_ns_max_window = entry.batch_ns_max_window.max(took);
            entry.last_batch_lines = (result.ingested + result.rejected) as u64;
            entry.bytes_behind = bytes_behind;
            entry.last_ingested_observed_at = runner.last_ingested_observed_at();
            entry.wedged = runner.wedged();
        }
        if result.cursor_moved()
            && let Err(e) = runner.persist_cursor()
        {
            eprintln!("{name}: cursor persist failed: {e}");
        }
        if result.ingested == 0 && result.rejected == 0 && result.probe_confirmations == 0 {
            tokio::select! {
                _ = tokio::time::sleep(poll) => {}
                _ = cancel.cancelled() => {}
            }
        }
    }
}

fn write_status(path: &PathBuf, shared: &Shared, pid: u32, started_at: DateTime<Utc>) {
    let mut sensors = serde_json::Map::new();
    {
        let mut map = lock(shared);
        for (name, s) in map.iter_mut() {
            s.recent_max.push_back(s.batch_ns_max_window);
            if s.recent_max.len() > 60 {
                s.recent_max.pop_front();
            }
            sensors.insert(
                name.clone(),
                json!({
                    "ingested": s.ingested,
                    "rejected": s.rejected,
                    "errors": s.errors,
                    "batches": s.batches,
                    "batch_ns_total": s.batch_ns_total,
                    "batch_ns_max_60s": s.recent_max.iter().max().copied().unwrap_or(0),
                    "last_batch_lines": s.last_batch_lines,
                    "bytes_behind": s.bytes_behind,
                    "last_ingested_observed_at": s.last_ingested_observed_at.map(|t| t.to_rfc3339()),
                    "wedged": s.wedged,
                }),
            );
            s.batch_ns_max_window = 0;
        }
    }
    let doc = json!({
        "pid": pid,
        "started_at": started_at.to_rfc3339(),
        "written_at": Utc::now().to_rfc3339(),
        "sensors": sensors,
    });
    let tmp = path.with_extension("tmp");
    if std::fs::write(&tmp, doc.to_string()).is_ok() {
        let _ = std::fs::rename(&tmp, path);
    }
}

pub async fn run(args: &Args) -> i32 {
    let url = args.need("database-url");
    let cursor_dir = PathBuf::from(args.need("cursor-dir"));
    let status_file = PathBuf::from(args.need("status-file"));
    let stop_file = PathBuf::from(args.need("stop-file"));
    let poll = Duration::from_millis(args.get_or("poll-ms", 1000u64));
    let pool_size: u32 = args.get_or("pool-size", 10);
    let logs: Vec<(String, PathBuf)> = args
        .need("logs")
        .split(',')
        .filter_map(|pair| pair.split_once(':'))
        .map(|(n, p)| (n.to_string(), PathBuf::from(p)))
        .collect();

    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::new("warn"))
        .with_writer(std::io::stderr)
        .init();

    if let Err(e) = std::fs::create_dir_all(&cursor_dir) {
        eprintln!("cannot create the cursor directory: {e}");
        return 2;
    }
    let pool = match PgPoolOptions::new()
        .max_connections(pool_size)
        .connect(&url)
        .await
    {
        Ok(pool) => pool,
        Err(e) => {
            eprintln!("cannot connect to the database: {e}");
            return 2;
        }
    };

    let shared: Shared = Arc::new(Mutex::new(BTreeMap::new()));
    let cancel = CancellationToken::new();
    let mut tasks = Vec::new();
    for (name, path) in logs {
        lock(&shared).entry(name.clone()).or_default();
        tasks.push(tokio::spawn(run_sensor(
            name,
            path,
            cursor_dir.clone(),
            pool.clone(),
            poll,
            cancel.clone(),
            shared.clone(),
        )));
    }

    let started_at = Utc::now();
    let pid = std::process::id();
    loop {
        write_status(&status_file, &shared, pid, started_at);
        if stop_file.exists() {
            break;
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
    cancel.cancel();
    for task in tasks {
        let _ = task.await;
    }
    write_status(&status_file, &shared, pid, started_at);
    0
}
