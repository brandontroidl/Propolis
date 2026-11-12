//! Append-path latency and throughput probe against a disposable database.
//!
//! Drives `core_scoring::append_event` exactly as the intake runner does (one call per event, a
//! shared pool), so the numbers it prints are the production per-event cost for the ledger it is
//! pointed at. It WRITES to the ledger: point `DATABASE_URL` at a scratch database, never a live one.
//!
//! ```text
//! DATABASE_URL=postgres://.../scratch cargo run --release -p intake --example append_bench -- \
//!     latency <n> <lag_secs> <source_ip>...
//! DATABASE_URL=postgres://.../scratch cargo run --release -p intake --example append_bench -- \
//!     throughput <seconds> <pool_size> <source_ip>...
//! ```
//!
//! `latency` appends `n` events per source, sequentially, each observed `lag_secs` before now (an
//! intake working through a backlog appends old `observed_at` values), and prints
//! mean/p50/p95/max per source.
//! `batched` appends `batch` events per `append_events` call from one writer for the given wall
//! time (events round-robin over the sources) and prints the event rate, the per-batch time, and
//! how long a probe queueing on the append lock waited:
//! `... -- batched <seconds> <batch> <source_ip>...`.
//! `throughput` runs one task per source (one source standing in for one sensor's intake loop) for
//! the given wall time on a pool of the given size, and prints the aggregate append rate.

use std::net::IpAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};

use chrono::Utc;
use core_scoring::{EventInput, Protocol, SignalType, append_event, append_events};
use sqlx::postgres::PgPoolOptions;

fn event_for(ip: IpAddr, seq: u64, lag: chrono::Duration) -> EventInput {
    // A telnet command_exec line of roughly the size the live sensor writes.
    let command = format!("{seq:016x}").repeat(24);
    EventInput::from_signal(
        ip,
        Some("203.0.113.10".parse().expect("literal address")),
        "telnet".into(),
        SignalType::HoneypotCommandExec,
        Protocol::Tcp,
        true,
        Utc::now() - lag,
        serde_json::json!({ "command": command, "local_port": 23, "shell": "busybox" }),
        None,
    )
}

fn percentile(sorted: &[Duration], p: f64) -> Duration {
    let idx = ((sorted.len() as f64 - 1.0) * p).round() as usize;
    sorted[idx.min(sorted.len() - 1)]
}

fn parse_ips(args: &[String]) -> Vec<IpAddr> {
    args.iter()
        .map(|s| {
            s.parse()
                .unwrap_or_else(|_| panic!("not an IP address: {s}"))
        })
        .collect()
}

async fn latency(url: &str, n: usize, lag: chrono::Duration, ips: Vec<IpAddr>) {
    let pool = PgPoolOptions::new()
        .max_connections(2)
        .connect(url)
        .await
        .expect("connect");
    for ip in ips {
        let mut samples = Vec::with_capacity(n);
        for seq in 0..n {
            let event = event_for(ip, seq as u64, lag);
            let start = Instant::now();
            append_event(&pool, event).await.expect("append_event");
            samples.push(start.elapsed());
        }
        samples.sort();
        let mean = samples.iter().sum::<Duration>() / n as u32;
        println!(
            "latency ip={ip} n={n} mean_ms={:.2} p50_ms={:.2} p95_ms={:.2} max_ms={:.2}",
            mean.as_secs_f64() * 1e3,
            percentile(&samples, 0.50).as_secs_f64() * 1e3,
            percentile(&samples, 0.95).as_secs_f64() * 1e3,
            samples[n - 1].as_secs_f64() * 1e3,
        );
    }
}

async fn throughput(url: &str, seconds: u64, pool_size: u32, ips: Vec<IpAddr>) {
    let pool = PgPoolOptions::new()
        .max_connections(pool_size)
        .connect(url)
        .await
        .expect("connect");
    let stop = Arc::new(AtomicBool::new(false));
    let mut handles = Vec::new();
    for ip in ips.iter().copied() {
        let pool = pool.clone();
        let stop = stop.clone();
        let count = Arc::new(AtomicU64::new(0));
        let task_count = count.clone();
        handles.push((
            ip,
            count,
            tokio::spawn(async move {
                let mut seq = 0u64;
                while !stop.load(Ordering::Relaxed) {
                    append_event(&pool, event_for(ip, seq, chrono::Duration::zero()))
                        .await
                        .expect("append_event");
                    seq += 1;
                    task_count.fetch_add(1, Ordering::Relaxed);
                }
            }),
        ));
    }
    let start = Instant::now();
    tokio::time::sleep(Duration::from_secs(seconds)).await;
    stop.store(true, Ordering::Relaxed);
    let mut total = 0u64;
    for (ip, count, handle) in handles {
        handle.await.expect("task");
        let n = count.load(Ordering::Relaxed);
        total += n;
        println!("throughput ip={ip} events={n}");
    }
    let elapsed = start.elapsed().as_secs_f64();
    println!(
        "throughput tasks={} pool={pool_size} seconds={elapsed:.1} events={total} events_per_s={:.2}",
        ips.len(),
        total as f64 / elapsed
    );
}

/// The key `core_scoring` serializes every append on (`APPEND_LOCK_KEY`), repeated here so a probe
/// can queue on the same lock the appenders hold. The bench is a measuring tool for a scratch
/// database; if the key ever changes the probe reads near zero, which the printed batch times
/// would contradict.
const APPEND_LOCK_KEY: i64 = 7_265_646_772_697_400_001;

/// One writer appending `batch` events per `append_events` call for `seconds`, while a probe on a
/// second connection repeatedly queues on the append lock and times how long it waits. The probe
/// is what another sensor's writer would experience: its wait is the time the batch holds the lock
/// from the moment the probe arrives, so its maximum is bounded by one batch's hold time.
async fn batched(url: &str, seconds: u64, batch: usize, ips: Vec<IpAddr>) {
    let pool = PgPoolOptions::new()
        .max_connections(4)
        .connect(url)
        .await
        .expect("connect");
    let stop = Arc::new(AtomicBool::new(false));

    let probe_pool = pool.clone();
    let probe_stop = stop.clone();
    let probe = tokio::spawn(async move {
        let mut waits = Vec::new();
        while !probe_stop.load(Ordering::Relaxed) {
            let mut tx = probe_pool.begin().await.expect("probe begin");
            let start = Instant::now();
            sqlx::query("SELECT pg_advisory_xact_lock($1)")
                .bind(APPEND_LOCK_KEY)
                .execute(&mut *tx)
                .await
                .expect("probe lock");
            waits.push(start.elapsed());
            tx.rollback().await.expect("probe rollback");
            tokio::time::sleep(Duration::from_millis(7)).await;
        }
        waits
    });

    let begin = Instant::now();
    let mut times = Vec::new();
    let mut total = 0u64;
    let mut seq = 0u64;
    while begin.elapsed() < Duration::from_secs(seconds) {
        let events: Vec<EventInput> = (0..batch)
            .map(|i| {
                let ip = ips[(seq as usize + i) % ips.len()];
                event_for(ip, seq + i as u64, chrono::Duration::zero())
            })
            .collect();
        let start = Instant::now();
        let outcome = append_events(&pool, events).await;
        times.push(start.elapsed());
        assert!(outcome.failure.is_none(), "{:?}", outcome.failure);
        total += outcome.appended as u64;
        seq += batch as u64;
    }
    let elapsed = begin.elapsed().as_secs_f64();
    stop.store(true, Ordering::Relaxed);
    let mut waits = probe.await.expect("probe task");
    waits.sort();
    times.sort();
    let ms = |d: Duration| d.as_secs_f64() * 1e3;
    println!(
        "batched batch={batch} seconds={elapsed:.1} events={total} events_per_s={:.1} \
         batch_ms_mean={:.1} p50={:.1} p95={:.1} max={:.1} \
         lock_wait_probe_n={} wait_ms_p50={:.1} p95={:.1} max={:.1}",
        total as f64 / elapsed,
        ms(times.iter().sum::<Duration>() / times.len() as u32),
        ms(percentile(&times, 0.50)),
        ms(percentile(&times, 0.95)),
        ms(times[times.len() - 1]),
        waits.len(),
        ms(percentile(&waits, 0.50)),
        ms(percentile(&waits, 0.95)),
        ms(waits[waits.len() - 1]),
    );
}

#[tokio::main]
async fn main() {
    let url = std::env::var("DATABASE_URL").expect("DATABASE_URL must name a scratch database");
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("latency") if args.len() >= 4 => {
            let n: usize = args[1].parse().expect("n");
            assert!(n > 0, "n must be positive");
            let lag_secs: i64 = args[2].parse().expect("lag_secs");
            latency(
                &url,
                n,
                chrono::Duration::seconds(lag_secs),
                parse_ips(&args[3..]),
            )
            .await;
        }
        Some("throughput") if args.len() >= 4 => {
            let seconds: u64 = args[1].parse().expect("seconds");
            let pool_size: u32 = args[2].parse().expect("pool_size");
            throughput(&url, seconds, pool_size, parse_ips(&args[3..])).await;
        }
        Some("batched") if args.len() >= 4 => {
            let seconds: u64 = args[1].parse().expect("seconds");
            let batch: usize = args[2].parse().expect("batch");
            assert!(batch > 0, "batch must be positive");
            batched(&url, seconds, batch, parse_ips(&args[3..])).await;
        }
        _ => {
            eprintln!(
                "usage: append_bench latency <n> <lag_secs> <ip>... | throughput <seconds> <pool> <ip>... \
                 | batched <seconds> <batch> <ip>..."
            );
            std::process::exit(2);
        }
    }
}
