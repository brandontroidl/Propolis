//! Intake soak harness (T11): sustained synthetic sensor traffic through the real intake path,
//! with rotation, a review/submission loop, and a PASS/FAIL report. Procedure, thresholds and
//! the meaning of every check: `docs/development/intake-soak.md`.
//!
//! ```text
//! DATABASE_URL=postgres://.../propolis_scratch cargo run --release -p propolis --example soak -- \
//!     run --dir /path/to/out --rate 750 --duration 600
//! ```
//!
//! It WRITES to the ledger and to `--dir`: point it at a scratch database (the name must contain
//! `soak`, `scratch` or `test`) and a directory outside the repository.
//!
//! `run` is the orchestrator. It starts the sensor writers and the rotator as threads, the intake
//! as a child process (`intake-child`, this same binary), and the review loop in-process.

mod child;
mod report;
mod review_side;
mod sample;
mod traffic;

use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::str::FromStr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use chrono::{DateTime, Utc};
use core_scoring::{ChainStatus, verify_chain};
use serde_json::Value;
use sqlx::PgPool;
use sqlx::postgres::PgPoolOptions;
use tokio_util::sync::CancellationToken;

use report::{RunFacts, Thresholds};
use review_side::{ReviewCfg, ReviewStats};
use sample::{Point, SensorPoint};
use traffic::{RotateCfg, RotationMode, WriterCfg, WriterShared};

pub struct Args(HashMap<String, String>);

fn die(msg: &str) -> ! {
    eprintln!("soak: {msg}");
    std::process::exit(2)
}

impl Args {
    fn parse(argv: &[String]) -> Args {
        let mut map = HashMap::new();
        let mut it = argv.iter();
        while let Some(arg) = it.next() {
            let Some(key) = arg.strip_prefix("--") else {
                die(&format!("unexpected argument {arg}"))
            };
            let Some(value) = it.next() else {
                die(&format!("--{key} needs a value"))
            };
            map.insert(key.to_string(), value.clone());
        }
        Args(map)
    }

    pub fn get(&self, key: &str) -> Option<&str> {
        self.0.get(key).map(String::as_str)
    }

    pub fn need(&self, key: &str) -> String {
        self.get(key)
            .map(str::to_string)
            .unwrap_or_else(|| die(&format!("--{key} is required")))
    }

    pub fn get_or<T: FromStr>(&self, key: &str, default: T) -> T {
        match self.get(key) {
            None => default,
            Some(v) => v
                .parse()
                .unwrap_or_else(|_| die(&format!("--{key}: cannot parse {v:?}"))),
        }
    }

    fn size(&self, key: &str, default: u64) -> u64 {
        let Some(text) = self.get(key) else {
            return default;
        };
        let t = text.trim();
        let (digits, shift) = match t.chars().last() {
            Some('K' | 'k') => (&t[..t.len() - 1], 10),
            Some('M' | 'm') => (&t[..t.len() - 1], 20),
            Some('G' | 'g') => (&t[..t.len() - 1], 30),
            _ => (t, 0),
        };
        digits
            .parse::<u64>()
            .map(|n| n << shift)
            .unwrap_or_else(|_| die(&format!("--{key}: cannot parse size {text:?}")))
    }
}

fn usage() -> ! {
    eprintln!(
        "usage: soak run --dir <out dir> [--database-url URL] [--rate LINES_PER_S] [--duration SECS]\n\
         \x20      [--mix ssh=0.08,http=0.06,cred=0.03,adb=0.02] [--prefill-bytes 1G] [--sample-secs N]\n\
         \x20      [--rotate-secs N] [--rotate-min-bytes 100M] [--rotation copytruncate|rename|alternate]\n\
         \x20      [--fault kill@60,cursor-loss@90,poison@120] [--verify-every-secs N] [--keep-logs 1]\n\
         \x20      and the threshold flags named in docs/development/intake-soak.md\n\
         (the intake-child role is started by `run`, not by hand)"
    );
    std::process::exit(2)
}

#[tokio::main]
async fn main() {
    let argv: Vec<String> = std::env::args().skip(1).collect();
    let Some(role) = argv.first() else { usage() };
    let args = Args::parse(&argv[1..]);
    let code = match role.as_str() {
        "run" => orchestrate(&args).await,
        "intake-child" => child::run(&args).await,
        _ => usage(),
    };
    std::process::exit(code);
}

fn thresholds(a: &Args) -> Thresholds {
    Thresholds {
        lag_p95_secs: a.get_or("lag-p95-secs", 10.0),
        lag_max_secs: a.get_or("lag-max-secs", 60.0),
        catchup_secs: a.get_or("catchup-secs", 600.0),
        keep_up_ratio: a.get_or("keep-up-ratio", 0.9),
        rss_max_mb: a.get_or("rss-max-mb", 1024.0),
        rss_growth_factor: a.get_or("rss-growth-factor", 1.5),
        rss_growth_slack_mb: a.get_or("rss-growth-slack-mb", 64.0),
        lock_p95_ms: a.get_or("lock-p95-ms", 500.0),
        lock_max_ms: a.get_or("lock-max-ms", 2000.0),
        rotation_loss_secs: a.get_or("rotation-loss-secs", 5.0),
        submit_gap_secs: a.get_or("submit-gap-secs", 120.0),
        dup_per_restart: a.get_or("dup-per-restart", 1000),
        drain_secs: a.get_or("drain-secs", 120.0),
    }
}

struct Fault {
    kind: String,
    at: f64,
    fired: bool,
}

fn parse_faults(text: Option<&str>) -> Vec<Fault> {
    let mut faults: Vec<Fault> = text
        .unwrap_or("")
        .split(',')
        .filter(|s| !s.trim().is_empty())
        .map(|item| {
            let (kind, at) = item
                .split_once('@')
                .unwrap_or_else(|| die(&format!("--fault {item}: expected kind@seconds")));
            if !["kill", "cursor-loss", "poison"].contains(&kind) {
                die(&format!(
                    "--fault {item}: kind must be kill, cursor-loss or poison"
                ));
            }
            Fault {
                kind: kind.to_string(),
                at: at
                    .parse()
                    .unwrap_or_else(|_| die(&format!("--fault {item}: bad seconds"))),
                fired: false,
            }
        })
        .collect();
    faults.sort_by(|a, b| a.at.total_cmp(&b.at));
    faults
}

fn parse_mix(text: Option<&str>) -> Vec<(String, f64)> {
    let mut mix: Vec<(String, f64)> = [
        ("telnet", 1.0),
        ("ssh", 0.08),
        ("http", 0.06),
        ("cred", 0.03),
        ("adb", 0.02),
    ]
    .iter()
    .map(|(n, s)| (n.to_string(), *s))
    .collect();
    for item in text
        .unwrap_or("")
        .split(',')
        .filter(|s| !s.trim().is_empty())
    {
        let (name, share) = item
            .split_once('=')
            .unwrap_or_else(|| die(&format!("--mix {item}: expected name=share")));
        let share: f64 = share
            .parse()
            .unwrap_or_else(|_| die(&format!("--mix {item}: bad share")));
        if name == "telnet" {
            die("--mix: telnet is the reference rate, set it with --rate");
        }
        mix.retain(|(n, _)| n != name);
        if share > 0.0 {
            mix.push((name.to_string(), share));
        }
    }
    mix
}

struct ChildProc {
    exe: PathBuf,
    argv: Vec<String>,
    log: PathBuf,
    status_file: PathBuf,
    proc: Option<Child>,
    restart_at: Option<Instant>,
    restarts: u32,
    unexpected_exit: bool,
    /// Set once the stop file is written: the process is expected to exit from then on.
    stopping: bool,
}

impl ChildProc {
    fn start(&mut self) -> std::io::Result<()> {
        let _ = std::fs::remove_file(&self.status_file);
        let log = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.log)?;
        let child = Command::new(&self.exe)
            .arg("intake-child")
            .args(&self.argv)
            .stdout(Stdio::null())
            .stderr(log)
            .spawn()?;
        self.proc = Some(child);
        Ok(())
    }

    fn kill(&mut self) {
        if let Some(mut child) = self.proc.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }

    /// Reaps an exit nobody asked for and reports whether the process is running.
    fn alive(&mut self) -> bool {
        let Some(child) = self.proc.as_mut() else {
            return false;
        };
        match child.try_wait() {
            Ok(None) => true,
            _ => {
                self.proc = None;
                self.unexpected_exit |= !self.stopping;
                false
            }
        }
    }

    fn pid(&self) -> Option<u32> {
        self.proc.as_ref().map(Child::id)
    }
}

/// Totals across intake incarnations: a restart zeroes the child's own counters, so each
/// incarnation's last reading is folded into `base` when its pid changes.
#[derive(Default)]
struct StatusAcc {
    pid: u32,
    base: BTreeMap<String, (u64, u64, u64)>,
    last: BTreeMap<String, (u64, u64, u64)>,
    prev_batches: BTreeMap<String, (u64, u64)>,
    last_obs: BTreeMap<String, DateTime<Utc>>,
}

impl StatusAcc {
    fn totals(&self, name: &str) -> (u64, u64, u64) {
        let b = self.base.get(name).copied().unwrap_or_default();
        let l = self.last.get(name).copied().unwrap_or_default();
        (b.0 + l.0, b.1 + l.1, b.2 + l.2)
    }

    fn fold_incarnation(&mut self) {
        for (name, l) in std::mem::take(&mut self.last) {
            let b = self.base.entry(name).or_default();
            b.0 += l.0;
            b.1 += l.1;
            b.2 += l.2;
        }
        self.prev_batches.clear();
    }
}

fn read_json(path: &Path) -> Option<Value> {
    serde_json::from_str(&std::fs::read_to_string(path).ok()?).ok()
}

/// The append lock the ledger serializes every writer on (`core_scoring`'s `APPEND_LOCK_KEY`),
/// repeated so a probe can queue on the same lock; the same duplication `append_bench` carries.
const APPEND_LOCK_KEY: i64 = 7_265_646_772_697_400_001;

async fn lock_probe(pool: PgPool, waits: Arc<Mutex<Vec<f64>>>, cancel: CancellationToken) {
    while !cancel.is_cancelled() {
        let Ok(mut tx) = pool.begin().await else {
            tokio::time::sleep(Duration::from_millis(500)).await;
            continue;
        };
        let started = Instant::now();
        let locked = sqlx::query("SELECT pg_advisory_xact_lock($1)")
            .bind(APPEND_LOCK_KEY)
            .execute(&mut *tx)
            .await
            .is_ok();
        let waited = started.elapsed().as_secs_f64() * 1e3;
        let _ = tx.rollback().await;
        if locked {
            waits.lock().unwrap_or_else(|p| p.into_inner()).push(waited);
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
}

fn database_name_is_scratch(url: &str) -> bool {
    let name = url
        .rsplit('/')
        .next()
        .unwrap_or("")
        .split('?')
        .next()
        .unwrap_or("");
    ["soak", "scratch", "test"].iter().any(|k| name.contains(k))
}

struct Orch {
    names: Vec<String>,
    writers: Vec<Arc<WriterShared>>,
    child: ChildProc,
    acc: StatusAcc,
    review: Arc<ReviewStats>,
    lock_waits: Arc<Mutex<Vec<f64>>>,
    pool: PgPool,
    started: Instant,
    prev_at: Instant,
    prev_done: u64,
    prev_written: u64,
    prev_ticks: Option<(u32, u64)>,
}

impl Orch {
    async fn sample(&mut self) -> Point {
        let now = Instant::now();
        let dt = now.duration_since(self.prev_at).as_secs_f64().max(1e-6);
        self.prev_at = now;
        let wall = Utc::now();
        let alive = self.child.alive();

        if let Some(status) = read_json(&self.child.status_file) {
            let pid = status["pid"].as_u64().unwrap_or(0) as u32;
            if pid != self.acc.pid {
                self.acc.fold_incarnation();
                self.acc.pid = pid;
            }
            if let Some(sensors) = status["sensors"].as_object() {
                for (name, s) in sensors {
                    let n = |k: &str| s[k].as_u64().unwrap_or(0);
                    self.acc
                        .last
                        .insert(name.clone(), (n("ingested"), n("rejected"), n("errors")));
                    if let Some(t) = s["last_ingested_observed_at"]
                        .as_str()
                        .and_then(|t| t.parse::<DateTime<Utc>>().ok())
                    {
                        self.acc.last_obs.insert(name.clone(), t);
                    }
                }
            }
        }
        let status = read_json(&self.child.status_file);

        let mut point = Point {
            t: self.started.elapsed().as_secs_f64(),
            at: Some(wall),
            child_alive: alive,
            restarts: self.child.restarts,
            ..Default::default()
        };
        let mut done_total = 0u64;
        for (i, name) in self.names.iter().enumerate() {
            let (ingested, rejected, errors) = self.acc.totals(name);
            done_total += ingested + rejected;
            let live = status.as_ref().and_then(|s| s["sensors"].get(name));
            let (mut mean_ms, mut max_ms, mut behind, mut wedged) = (0.0, 0.0, 0, None);
            if let Some(s) = live {
                let batches = s["batches"].as_u64().unwrap_or(0);
                let ns = s["batch_ns_total"].as_u64().unwrap_or(0);
                let prev = self
                    .acc
                    .prev_batches
                    .insert(name.clone(), (batches, ns))
                    .unwrap_or((0, 0));
                if batches > prev.0 {
                    mean_ms = (ns - prev.1) as f64 / (batches - prev.0) as f64 / 1e6;
                }
                max_ms = s["batch_ns_max_60s"].as_u64().unwrap_or(0) as f64 / 1e6;
                behind = s["bytes_behind"].as_u64().unwrap_or(0);
                wedged = s["wedged"].as_str().map(str::to_string);
            }
            point.sensors.insert(
                name.clone(),
                SensorPoint {
                    ingested,
                    rejected,
                    errors,
                    bytes_behind: behind,
                    lag_secs: self
                        .acc
                        .last_obs
                        .get(name)
                        .map(|t| (wall - *t).num_milliseconds() as f64 / 1e3),
                    wedged,
                    batch_mean_ms: mean_ms,
                    batch_max_ms: max_ms,
                    log_bytes: std::fs::metadata(&self.writers[i].path)
                        .map(|m| m.len())
                        .unwrap_or(0),
                },
            );
        }
        point.ingest_eps = done_total.saturating_sub(self.prev_done) as f64 / dt;
        self.prev_done = done_total;
        let written: u64 = self
            .writers
            .iter()
            .map(|w| w.next_seq.load(Ordering::SeqCst))
            .sum();
        point.written_lps = written.saturating_sub(self.prev_written) as f64 / dt;
        self.prev_written = written;

        if let Some(pid) = self.child.pid() {
            let p = pid.to_string();
            point.rss_kb = sample::proc_status_kb(&p, "VmRSS");
            point.hwm_kb = sample::proc_status_kb(&p, "VmHWM");
            if let Some(ticks) = sample::proc_cpu_ticks(pid) {
                if let Some((prev_pid, prev)) = self.prev_ticks
                    && prev_pid == pid
                {
                    point.cpu_pct = Some(ticks.saturating_sub(prev) as f64 / 100.0 / dt * 100.0);
                }
                self.prev_ticks = Some((pid, ticks));
            }
        }
        point.orch_rss_kb = sample::proc_status_kb("self", "VmRSS");

        let waits = sample::sorted(std::mem::take(
            &mut *self.lock_waits.lock().unwrap_or_else(|p| p.into_inner()),
        ));
        point.lock_n = waits.len();
        point.lock_p50_ms = sample::percentile(&waits, 0.5);
        point.lock_p95_ms = sample::percentile(&waits, 0.95);
        point.lock_max_ms = sample::percentile(&waits, 1.0);

        if let Ok((bytes, max_id)) = sqlx::query_as::<_, (i64, i64)>(
            "SELECT pg_total_relation_size('event'), COALESCE((SELECT max(id) FROM event), 0)",
        )
        .fetch_one(&self.pool)
        .await
        {
            point.ledger_bytes = bytes;
            point.ledger_max_id = max_id;
        }

        let r = &self.review;
        point.passes = r.passes.load(Ordering::Relaxed);
        let done_ms = r.last_pass_done_ms.load(Ordering::Relaxed);
        point.secs_since_pass = (done_ms > 0)
            .then(|| (wall.timestamp_millis() as u64).saturating_sub(done_ms) as f64 / 1e3);
        point.pass_ms_max = r.max_pass_ms_window.swap(0, Ordering::Relaxed);
        point.submitted = r.submitted.load(Ordering::Relaxed);
        point.held = r.held.load(Ordering::Relaxed);
        point.vendor_calls = r.vendor_calls.load(Ordering::Relaxed);
        point.approved = r.approved.load(Ordering::Relaxed);
        point
    }
}

async fn orchestrate(args: &Args) -> i32 {
    let url = args
        .get("database-url")
        .map(str::to_string)
        .or_else(|| std::env::var("DATABASE_URL").ok())
        .unwrap_or_else(|| die("--database-url or DATABASE_URL is required"));
    if !database_name_is_scratch(&url) && args.get("allow-any-database").is_none() {
        die(
            "the database name must contain soak, scratch or test (or pass --allow-any-database 1)",
        );
    }
    let dir = PathBuf::from(args.need("dir"));
    if dir.join("logs").exists() {
        die("--dir already holds a run; pass an empty or new directory");
    }
    let th = thresholds(args);
    let rate: f64 = args.get_or("rate", 750.0);
    let duration: f64 = args.get_or("duration", 600.0);
    let sample_secs: f64 = args.get_or("sample-secs", 10.0);
    let poll_ms: u64 = args.get_or("poll-ms", 1000);
    let seed: u64 = args.get_or("seed", 1);
    let prefill_bytes = args.size("prefill-bytes", 0);
    let mut faults = parse_faults(args.get("fault"));
    let mix = parse_mix(args.get("mix"));
    let verify_every: f64 = args.get_or("verify-every-secs", 0.0);
    let restart_delay = Duration::from_secs_f64(args.get_or("restart-delay-secs", 5.0));
    let mode = match args.get("rotation").unwrap_or("alternate") {
        "copytruncate" => RotationMode::Copytruncate,
        "rename" => RotationMode::Rename,
        "alternate" => RotationMode::Alternate,
        other => die(&format!(
            "--rotation {other}: copytruncate, rename or alternate"
        )),
    };

    let run_id = format!("{:x}", Utc::now().timestamp_millis());
    let names: Vec<String> = mix.iter().map(|(n, _)| n.clone()).collect();
    let mut sensor_rate: BTreeMap<String, f64> = BTreeMap::new();
    let mut writers: Vec<Arc<WriterShared>> = Vec::new();
    let cursor_dir = dir.join("cursors");
    for (name, share) in &mix {
        let sensor_dir = dir.join("logs").join(name);
        std::fs::create_dir_all(&sensor_dir).unwrap_or_else(|e| die(&format!("mkdir: {e}")));
        sensor_rate.insert(name.clone(), rate * share);
        writers.push(WriterShared::new(name, sensor_dir.join("events.jsonl")));
    }
    std::fs::create_dir_all(&cursor_dir).unwrap_or_else(|e| die(&format!("mkdir: {e}")));

    let pool = PgPoolOptions::new()
        .max_connections(6)
        .connect(&url)
        .await
        .unwrap_or_else(|e| die(&format!("cannot connect to the database: {e}")));
    if let Err(e) = sqlx::migrate!("../core-scoring/migrations")
        .run(&pool)
        .await
    {
        die(&format!("core-scoring migrations: {e}"));
    }
    if let Err(e) = review::migrator().run(&pool).await {
        die(&format!("review migrations: {e}"));
    }
    if let Err(e) = fleet::migrator().run(&pool).await {
        die(&format!("fleet migrations: {e}"));
    }
    let pre_existing: i64 = sqlx::query_scalar("SELECT count(*) FROM event")
        .fetch_one(&pool)
        .await
        .unwrap_or(0);
    println!(
        "soak run {run_id}: rate {rate}/s telnet, sensors {names:?}, duration {duration}s, prefill {prefill_bytes} B, \
         ledger already holds {pre_existing} rows, out dir {}",
        dir.display()
    );

    let writer_cfg = |name: &str| WriterCfg {
        run: run_id.clone(),
        rate: sensor_rate[name],
        seed,
        malformed_every: args.get_or("malformed-every", 5000),
        overlength_every: args.get_or("overlength-every", 50_000),
        nearmax_every: args.get_or("nearmax-every", 100_000),
        spike_every_secs: args.get_or("spike-every-secs", 0),
        spike_secs: args.get_or("spike-secs", 0),
        spike_x: args.get_or("spike-x", 1.0),
    };

    if prefill_bytes > 0 {
        let total_share: f64 = mix.iter().map(|(_, s)| s).sum();
        let began = Instant::now();
        for (w, (name, share)) in writers.iter().zip(&mix) {
            let bytes = (prefill_bytes as f64 * share / total_share) as u64;
            if let Err(e) = traffic::prefill(&writer_cfg(name), w, bytes) {
                die(&format!("prefill {name}: {e}"));
            }
        }
        println!("prefilled in {:.0}s", began.elapsed().as_secs_f64());
    }

    let status_file = dir.join("status.json");
    let stop_file = dir.join("stop");
    let logs_arg = writers
        .iter()
        .map(|w| format!("{}:{}", w.name, w.path.display()))
        .collect::<Vec<_>>()
        .join(",");
    let mut child = ChildProc {
        exe: std::env::current_exe().unwrap_or_else(|e| die(&format!("current_exe: {e}"))),
        argv: [
            ("--database-url", url.clone()),
            ("--cursor-dir", cursor_dir.display().to_string()),
            ("--status-file", status_file.display().to_string()),
            ("--stop-file", stop_file.display().to_string()),
            ("--logs", logs_arg),
            ("--poll-ms", poll_ms.to_string()),
            ("--pool-size", args.get_or("pool-size", 10u32).to_string()),
        ]
        .into_iter()
        .flat_map(|(k, v)| [k.to_string(), v])
        .collect(),
        log: dir.join("child.log"),
        status_file: status_file.clone(),
        proc: None,
        restart_at: None,
        restarts: 0,
        unexpected_exit: false,
        stopping: false,
    };

    let stop = Arc::new(AtomicBool::new(false));
    let cancel = CancellationToken::new();
    let review_stats = Arc::new(ReviewStats::default());
    let lock_waits = Arc::new(Mutex::new(Vec::new()));
    let mid_chain: Arc<Mutex<Vec<(f64, bool, f64)>>> = Arc::new(Mutex::new(Vec::new()));

    let started = Instant::now();
    child
        .start()
        .unwrap_or_else(|e| die(&format!("cannot start the intake process: {e}")));
    let mut writer_threads = Vec::new();
    for w in &writers {
        let (cfg, w, stop) = (writer_cfg(&w.name), w.clone(), stop.clone());
        writer_threads.push(std::thread::spawn(move || {
            traffic::run_writer(cfg, w, stop)
        }));
    }
    let rotator = {
        let cfg = RotateCfg {
            every: Duration::from_secs_f64(args.get_or("rotate-secs", 3600.0)),
            min_bytes: args.size("rotate-min-bytes", 100 << 20),
            mode,
            keep: args.get_or("keep", 2usize),
        };
        let (logs, stop) = (writers.clone(), stop.clone());
        std::thread::spawn(move || traffic::run_rotator(cfg, logs, stop))
    };
    let mut background = review_side::spawn(
        pool.clone(),
        review_stats.clone(),
        cancel.clone(),
        ReviewCfg {
            queue_interval: Duration::from_secs(args.get_or("queue-secs", 60)),
            submit_interval: Duration::from_secs(args.get_or("submit-secs", 30)),
            approve_interval: Duration::from_secs(args.get_or("approve-secs", 10)),
            approve_max: args.get_or("approve-max", 500),
        },
    );
    {
        let probe_pool = PgPoolOptions::new()
            .max_connections(1)
            .connect(&url)
            .await
            .unwrap_or_else(|e| die(&format!("probe connection: {e}")));
        background.push(tokio::spawn(lock_probe(
            probe_pool,
            lock_waits.clone(),
            cancel.clone(),
        )));
    }
    if verify_every > 0.0 {
        let (pool, cancel, out) = (pool.clone(), cancel.clone(), mid_chain.clone());
        background.push(tokio::spawn(async move {
            let began = Instant::now();
            loop {
                tokio::select! {
                    _ = tokio::time::sleep(Duration::from_secs_f64(verify_every)) => {}
                    _ = cancel.cancelled() => return,
                }
                let at = began.elapsed().as_secs_f64();
                let walk = Instant::now();
                let ok = matches!(verify_chain(&pool).await, Ok(ChainStatus::Intact));
                out.lock().unwrap_or_else(|p| p.into_inner()).push((
                    at,
                    ok,
                    walk.elapsed().as_secs_f64(),
                ));
            }
        }));
    }

    let mut orch = Orch {
        names: names.clone(),
        writers: writers.clone(),
        child,
        acc: StatusAcc::default(),
        review: review_stats.clone(),
        lock_waits,
        pool: pool.clone(),
        started,
        prev_at: started,
        prev_done: 0,
        prev_written: writers
            .iter()
            .map(|w| w.next_seq.load(Ordering::SeqCst))
            .sum(),
        prev_ticks: None,
    };
    let mut points: Vec<Point> = Vec::new();
    let mut samples_out = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(dir.join("samples.jsonl"))
        .unwrap_or_else(|e| die(&format!("samples.jsonl: {e}")));
    let mut fired: Vec<String> = Vec::new();
    let mut harness_errors: Vec<String> = Vec::new();
    let mut next_sample = sample_secs;
    let mut tick = tokio::time::interval(Duration::from_secs(1));
    tick.tick().await;

    let mut record = |orch_point: Point, points: &mut Vec<Point>| {
        use std::io::Write;
        println!("{}", orch_point.line());
        let _ = writeln!(samples_out, "{}", orch_point.to_json());
        points.push(orch_point);
    };

    loop {
        tick.tick().await;
        let t = started.elapsed().as_secs_f64();

        for fault in faults.iter_mut().filter(|f| !f.fired && t >= f.at) {
            fault.fired = true;
            fired.push(format!("{}@{:.0}", fault.kind, t));
            println!("FAULT {} at {t:.0}s", fault.kind);
            match fault.kind.as_str() {
                "poison" => {
                    if let Some(w) = writers.iter().find(|w| w.name == "telnet") {
                        w.poison_requested.store(true, Ordering::SeqCst);
                    }
                }
                kind => {
                    orch.child.kill();
                    if kind == "cursor-loss"
                        && let Ok(entries) = std::fs::read_dir(&cursor_dir)
                    {
                        for entry in entries.flatten() {
                            let _ = std::fs::remove_file(entry.path());
                        }
                    }
                    orch.child.restart_at = Some(Instant::now() + restart_delay);
                }
            }
        }
        if orch.child.proc.is_none()
            && let Some(at) = orch.child.restart_at
            && Instant::now() >= at
        {
            orch.child.restart_at = None;
            match orch.child.start() {
                Ok(()) => orch.child.restarts += 1,
                Err(e) => {
                    harness_errors.push(format!("restart failed: {e}"));
                    break;
                }
            }
        }
        orch.child.alive();
        if orch.child.unexpected_exit {
            break;
        }
        for w in &writers {
            if let Some(e) = w.failed.lock().unwrap_or_else(|p| p.into_inner()).clone() {
                harness_errors.push(format!("{}: {e}", w.name));
            }
        }
        if !harness_errors.is_empty() {
            break;
        }

        if t >= next_sample {
            next_sample += sample_secs;
            let p = orch.sample().await;
            record(p, &mut points);
        }
        if t >= duration {
            break;
        }
    }

    // Stop the load, let the intake finish what is on disk, then take the final reading.
    stop.store(true, Ordering::SeqCst);
    for t in writer_threads {
        let _ = t.join();
    }
    let _ = rotator.join();
    let duration_secs = started.elapsed().as_secs_f64();
    let drain_began = Instant::now();
    let mut drained = false;
    let needed_quiet = (poll_ms / 1000) * 2 + 3;
    let mut quiet = 0;
    while orch.child.proc.is_some() && drain_began.elapsed().as_secs_f64() < th.drain_secs {
        tokio::time::sleep(Duration::from_secs(1)).await;
        orch.child.alive();
        let status = read_json(&status_file);
        let all_zero = status.as_ref().is_some_and(|s| {
            s["sensors"]
                .as_object()
                .is_some_and(|m| !m.is_empty() && m.values().all(|v| v["bytes_behind"] == 0))
        });
        quiet = if all_zero { quiet + 1 } else { 0 };
        if quiet >= needed_quiet {
            drained = true;
            break;
        }
    }
    let drain_took_secs = drain_began.elapsed().as_secs_f64();
    // The reading after the writers stopped is kept out of the steady-state series (its lag is
    // the idle gap, not a delay) but is where the final totals come from.
    let mut tail: Vec<Point> = Vec::new();
    record(orch.sample().await, &mut tail);
    let final_point = tail.pop();

    orch.child.stopping = true;
    let _ = std::fs::write(&stop_file, b"stop");
    let stop_wait = Instant::now();
    while orch.child.alive() && stop_wait.elapsed() < Duration::from_secs(30) {
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    orch.child.kill();
    // A last reading folds the final counters of the stopped incarnation into the totals.
    let rejected_final: BTreeMap<String, u64> = {
        let _ = orch.sample().await;
        names
            .iter()
            .map(|n| (n.clone(), orch.acc.totals(n).1))
            .collect()
    };

    cancel.cancel();
    for task in background {
        let _ = tokio::time::timeout(Duration::from_secs(10), task).await;
    }

    println!("accounting ledger rows against written lines ...");
    let summaries: Vec<(String, u64, traffic::WriterLedger, f64)> = writers
        .iter()
        .map(|w| {
            let ledger = std::mem::take(&mut *w.ledger.lock().unwrap_or_else(|p| p.into_inner()));
            let written = w.next_seq.load(Ordering::SeqCst);
            (
                w.name.clone(),
                written,
                ledger,
                written as f64 / duration_secs.max(1.0),
            )
        })
        .collect();
    let rotations_copytruncate = summaries
        .iter()
        .flat_map(|s| s.2.rotations.iter())
        .filter(|r| r.copytruncate)
        .count();
    let rotations_rename = summaries
        .iter()
        .flat_map(|s| s.2.rotations.iter())
        .filter(|r| !r.copytruncate)
        .count();
    let mut accounts = match report::account(&pool, &run_id, &summaries).await {
        Ok(a) => a,
        Err(e) => {
            eprintln!("soak: accounting query failed: {e}");
            return 2;
        }
    };
    for a in &mut accounts {
        a.rejected_by_runner = rejected_final.get(&a.name).copied().unwrap_or(0);
    }

    println!("verifying the hash chain ...");
    let walk = Instant::now();
    let chain_status = verify_chain(&pool).await;
    let (chain_ok, chain) = match &chain_status {
        Ok(status) => (
            matches!(status, ChainStatus::Intact),
            format!("{status:?} in {:.0}s", walk.elapsed().as_secs_f64()),
        ),
        Err(e) => (false, format!("verification failed: {e}")),
    };

    let facts = RunFacts {
        points,
        final_point,
        sensors: names,
        restarts: orch.child.restarts,
        accounts,
        chain,
        chain_ok,
        mid_chain: mid_chain.lock().unwrap_or_else(|p| p.into_inner()).clone(),
        child_unexpected_exit: orch.child.unexpected_exit,
        harness_errors,
        drained,
        drain_took_secs,
        faults: fired,
        duration_secs,
        generated_lps: summaries.iter().map(|s| s.1).sum::<u64>() as f64 / duration_secs.max(1.0),
        rotations_copytruncate,
        rotations_rename,
    };
    let checks = report::evaluate(&th, &facts);
    let text = report::render(&th, &facts, &checks);
    println!("{text}");
    let _ = std::fs::write(dir.join("report.txt"), &text);
    if args.get("keep-logs").is_none() {
        let _ = std::fs::remove_dir_all(dir.join("logs"));
    }
    if checks.iter().all(|c| c.pass) { 0 } else { 1 }
}
