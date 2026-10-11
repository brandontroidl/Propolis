//! The worst-case memory of `sensor-ssh`, summed from the places that hold it and held under the
//! unit's `MemoryMax`, so a change to a budget, a concurrency default, a worker count or the
//! per-upload capture limit that the memory cannot back fails the build instead of the service.
//!
//! Each term is bounded where the bytes are allocated and released, not by arithmetic on
//! configuration:
//!
//! 1. Capture bodies (uploads, shell payloads, held stdin) are `CaptureBody`s charged in 64 KiB
//!    chunks to one `CaptureMemoryBudget`, whose compare-exchange never lets the total pass the
//!    ceiling, and refunded by RAII. The per-upload limit decides how many uploads fill it, not
//!    how much it can hold.
//! 2. Output queued for peers, and the input waiting behind it, is charged to a second
//!    `CaptureMemoryBudget`, with an allowance reserved before any line runs.
//! 3. Per-connection shell and filesystem state is capped by `ConnectionBudget`; the sensor
//!    admits `max_concurrent` connections.
//! 4. A shell line runs synchronously on a worker thread and holds, outside any budget, at most
//!    `LINE_WORKING_SET_BYTES` (measured in the framework's `finish_line_overhead` test). Only a
//!    worker thread can be inside one, so the term is that figure times the worker count.
//!
//! What is left of `MemoryMax` is the runtime's own: code, task stacks, packet buffers, the
//! hand-off queue, allocator overhead and socket memory. The 64 MiB set aside for it is an
//! estimate, not a measurement (docs/operations/capacity-planning.md says so too).
//!
//! The worker count, the concurrency default and `MemoryMax` are read from the sources that set
//! them, not restated here.

use sensor_framework::budget::ConnectionBudget;
use sensor_framework::{
    ConnectionBounds, LINE_WORKING_SET_BYTES, default_capture_budget_bytes, limits_from,
};
use sensor_ssh::server::{
    DEFAULT_CAPTURE_BUDGET_BYTES, OUTPUT_BUDGET_BYTES, OUTPUT_UNIT_BYTES, SPOOL_MAX_FILE_BYTES,
    UNIT_MEMORY_MAX_BYTES,
};

/// Room kept for everything the budgets do not charge. An estimate.
const RUNTIME_ALLOWANCE_BYTES: u64 = 64 * 1024 * 1024;

fn workspace_file(relative: &str) -> String {
    let path = format!("{}/../../{relative}", env!("CARGO_MANIFEST_DIR"));
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{path}: {e}"))
}

fn main_source() -> String {
    workspace_file("crates/sensor-ssh/src/main.rs")
}

/// `N` from `#[tokio::main(worker_threads = N)]`.
fn worker_threads() -> u64 {
    let source = main_source();
    let tail = source
        .split("#[tokio::main(worker_threads = ")
        .nth(1)
        .expect("main sets its worker threads explicitly");
    tail.split(')')
        .next()
        .and_then(|n| n.trim().parse().ok())
        .expect("a worker count")
}

/// `DEFAULT_MAX_CONCURRENT: u32 = N;`
fn default_max_concurrent() -> u64 {
    let source = main_source();
    let line = source
        .lines()
        .find(|l| l.contains("const DEFAULT_MAX_CONCURRENT: u32 ="))
        .expect("a concurrency default");
    line.split('=')
        .nth(1)
        .and_then(|v| v.trim().trim_end_matches(';').replace('_', "").parse().ok())
        .expect("a number")
}

/// `MemoryMax=512M`, in bytes.
fn unit_memory_max() -> u64 {
    let unit = workspace_file("deploy/sensor-ssh.service");
    let value = unit
        .lines()
        .find_map(|l| l.strip_prefix("MemoryMax="))
        .expect("a MemoryMax")
        .trim();
    let (digits, suffix) = value.split_at(value.len() - 1);
    let n: u64 = digits.parse().expect("digits");
    n * match suffix {
        "K" => 1 << 10,
        "M" => 1 << 20,
        "G" => 1 << 30,
        other => panic!("MemoryMax unit {other:?}"),
    }
}

fn terms() -> [(&'static str, u64); 4] {
    let max_concurrent = default_max_concurrent();
    let bounds = ConnectionBounds {
        read_timeout: std::time::Duration::from_secs(30),
        idle_timeout: std::time::Duration::from_secs(60),
        max_duration: std::time::Duration::from_secs(600),
        max_captured_bytes: SPOOL_MAX_FILE_BYTES,
        max_concurrent: u32::try_from(max_concurrent).expect("a u32"),
    };
    let resident = ConnectionBudget::new(limits_from(&bounds)).max_resident_bytes();
    [
        (
            "capture budget",
            default_capture_budget_bytes(unit_memory_max()),
        ),
        ("output budget", OUTPUT_BUDGET_BYTES),
        ("per-connection state", max_concurrent * resident),
        (
            "shell line working sets",
            worker_threads() * LINE_WORKING_SET_BYTES,
        ),
    ]
}

#[test]
fn the_worst_case_sum_plus_the_runtime_allowance_stays_under_memorymax() {
    let memory_max = unit_memory_max();
    let terms = terms();
    let sum: u64 = terms.iter().map(|(_, bytes)| bytes).sum();
    let report: Vec<String> = terms.iter().map(|(n, b)| format!("{n} {b}")).collect();
    assert!(
        sum + RUNTIME_ALLOWANCE_BYTES < memory_max,
        "{} = {sum}, plus the {RUNTIME_ALLOWANCE_BYTES} runtime allowance, is not under MemoryMax \
         {memory_max}",
        report.join(" + ")
    );
}

#[test]
fn the_inputs_are_the_real_sources() {
    assert_eq!(unit_memory_max(), UNIT_MEMORY_MAX_BYTES);
    assert_eq!(
        default_capture_budget_bytes(unit_memory_max()),
        DEFAULT_CAPTURE_BUDGET_BYTES
    );
    assert_eq!(default_max_concurrent(), 256);
    assert_eq!(worker_threads(), 2);
}

#[test]
fn the_capture_limit_is_the_spool_cap_and_the_budgets_hold_many_of_them() {
    let main = main_source();
    assert!(
        main.contains(
            "const DEFAULT_MAX_CAPTURED_BYTES: u64 = sensor_ssh::server::SPOOL_MAX_FILE_BYTES;"
        ),
        "the default capture limit must be the spool's per-file cap, not a number of its own"
    );
    assert_eq!(SPOOL_MAX_FILE_BYTES, 10_000_000);
    // Every spooling sensor's per-file cap is the same literal, so the ssh limit agrees with them.
    for sensor in ["adb", "ftp"] {
        let lib = workspace_file(&format!("crates/sensor-{sensor}/src/lib.rs"));
        assert!(
            lib.contains("const SPOOL_MAX_FILE_SIZE: u64 = 10_000_000;"),
            "sensor-{sensor}'s per-file cap is not 10_000_000"
        );
    }
    // Room for at least ten maximum-size uploads at once, so one large upload never decides
    // whether another is kept whole.
    const {
        assert!(DEFAULT_CAPTURE_BUDGET_BYTES >= 10 * SPOOL_MAX_FILE_BYTES);
    }
    // And the output budget covers the allowance of every worker running a line at once, with
    // room left to queue.
    assert!(OUTPUT_BUDGET_BYTES >= (worker_threads() + 2) * OUTPUT_UNIT_BYTES);
}
