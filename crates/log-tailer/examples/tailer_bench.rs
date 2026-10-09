//! Per-batch cost of `LogTailer` at a given read offset into a large log.
//!
//! ```text
//! cargo run --release -p log-tailer --example tailer_bench -- <log> <cursor_dir> <offset> <batches>
//! ```
//!
//! Seeds a cursor at `offset` (which must sit on a line boundary) stamped with the file's real
//! inode and fingerprint, then runs `batches` rounds of read_batch(100) + commit + persist_cursor,
//! the exact sequence the intake loop runs, and prints the mean cost of each step.

use std::path::PathBuf;
use std::time::{Duration, Instant};

use log_tailer::{CursorState, DurableCursor, LogTailer, compute_fingerprint, get_inode};

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.len() != 4 {
        eprintln!("usage: tailer_bench <log> <cursor_dir> <offset> <batches>");
        std::process::exit(2);
    }
    let log = PathBuf::from(&args[0]);
    let cursor_dir = PathBuf::from(&args[1]);
    let offset: u64 = args[2].parse().expect("offset");
    let batches: usize = args[3].parse().expect("batches");

    DurableCursor::new(log.clone(), cursor_dir.clone())
        .save(&CursorState {
            inode: get_inode(&log),
            offset,
            fingerprint: compute_fingerprint(&log),
            fingerprint_len: None,
        })
        .expect("seed cursor");

    let start = Instant::now();
    let mut tailer = LogTailer::new(log, cursor_dir);
    let construct = start.elapsed();

    let (mut read, mut persist) = (Duration::ZERO, Duration::ZERO);
    let mut lines = 0usize;
    for _ in 0..batches {
        let t = Instant::now();
        let batch = tailer.read_batch(100);
        tailer.commit_batch();
        read += t.elapsed();
        lines += batch.len();
        let t = Instant::now();
        tailer.persist_cursor().expect("persist");
        persist += t.elapsed();
    }
    println!(
        "offset={offset} batches={batches} lines={lines} construct_us={} read_batch_mean_us={:.1} persist_mean_us={:.1}",
        construct.as_micros(),
        read.as_secs_f64() * 1e6 / batches as f64,
        persist.as_secs_f64() * 1e6 / batches as f64,
    );
}
