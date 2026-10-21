//! The worst-case memory of `sensor-ssh`, summed from the places that hold it and held under the
//! unit's `MemoryMax`, so a change to a budget, the session pool's share or the per-upload capture
//! limit that the memory cannot back fails the build instead of the service.
//!
//! Each term is bounded where the bytes are allocated and released, not by arithmetic on
//! configuration:
//!
//! 1. Capture bodies (uploads, shell payloads, held stdin) are `CaptureBody`s charged in 64 KiB
//!    chunks to one `CaptureMemoryBudget`, whose compare-exchange never lets the total pass the
//!    ceiling, and refunded by RAII. The per-upload limit decides how many uploads fill it, not
//!    how much it can hold.
//! 2. What client sessions hold: every allocation made while a connection's future runs is
//!    charged to that session by `AccountingAlloc`, and the sessions share one pool. A shell line
//!    runs synchronously inside that future, so its working set is charged to the session too:
//!    the session's peak limit is its retained limit plus one line's working set.
//! 3. Output queued for peers, and the input waiting behind it, is charged to a second
//!    `CaptureMemoryBudget`, with an allowance reserved before any line runs.
//!
//! What is left of `MemoryMax` is the runtime's own: code, task stacks, packet buffers, the
//! hand-off queue, allocation headers and socket memory. Not the blocks a growing capture body
//! frees: the sensor pins glibc's mmap threshold so those go back to the kernel, and
//! `capture_heap_test.rs` measures that they do. The 64 MiB set aside for it is an
//! estimate, not a measurement (docs/operations/capacity-planning.md says so too). The overshoot
//! the pool allows while asked sessions end is a term of its own: sessions within their floor may
//! hold room past a full pool, but the sensor caps that (`SESSION_OVERDRAFT_CAP_BYTES`, half the
//! spare under `MemoryMax`), so it is bounded in the sum below.
//!
//! `MemoryMax` is read from the unit file, not restated here.

use sensor_framework::session_memory::{PEAK_LIMIT_BYTES, RETAINED_LIMIT_BYTES, pool_bytes};
use sensor_framework::{LINE_WORKING_SET_BYTES, default_capture_budget_bytes};
use sensor_ssh::server::{
    DEFAULT_CAPTURE_BUDGET_BYTES, OUTPUT_BUDGET_BYTES, OUTPUT_UNIT_BYTES, RUNTIME_ALLOWANCE_BYTES,
    SESSION_OVERDRAFT_CAP_BYTES, SPOOL_MAX_FILE_BYTES, UNIT_MEMORY_MAX_BYTES,
};

fn workspace_file(relative: &str) -> String {
    let path = format!("{}/../../{relative}", env!("CARGO_MANIFEST_DIR"));
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{path}: {e}"))
}

fn main_source() -> String {
    workspace_file("crates/sensor-ssh/src/main.rs")
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
    let memory_max = unit_memory_max();
    [
        ("capture budget", default_capture_budget_bytes(memory_max)),
        ("session pool", pool_bytes(memory_max)),
        ("output budget", OUTPUT_BUDGET_BYTES),
        ("session pool overdraft cap", SESSION_OVERDRAFT_CAP_BYTES),
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

/// The cap is derived from the other terms, not a number of its own, and leaves real room: it is
/// half the spare, so the sum stays under `MemoryMax` by the other half.
#[test]
fn the_overdraft_cap_is_half_the_spare_under_memorymax() {
    let memory_max = unit_memory_max();
    let others: u64 = terms()
        .iter()
        .filter(|(name, _)| *name != "session pool overdraft cap")
        .map(|(_, bytes)| bytes)
        .sum();
    let spare = memory_max - others - RUNTIME_ALLOWANCE_BYTES;
    assert_eq!(SESSION_OVERDRAFT_CAP_BYTES, spare / 2);
    const {
        assert!(SESSION_OVERDRAFT_CAP_BYTES > 0);
    }
}

/// A line's working set is not a term of its own because the session pays for it: the limit a
/// session may reach while a line runs is its retained limit plus that working set.
#[test]
fn a_shell_lines_working_set_is_inside_the_session_limit() {
    assert_eq!(
        PEAK_LIMIT_BYTES,
        RETAINED_LIMIT_BYTES + LINE_WORKING_SET_BYTES
    );
    let server = workspace_file("crates/sensor-ssh/src/server.rs");
    assert!(
        server.contains("session_memory::scope("),
        "each connection runs inside its session's accounted scope"
    );
    assert!(
        !server.contains("spawn_blocking"),
        "a line moved off the connection's future would allocate outside its session"
    );
}

/// The capture budget charges a body's capacity, not the copies the allocator leaves behind as
/// the body grows; the sensor keeps those out by pinning glibc's mmap threshold before it serves
/// (measured in `capture_heap_test.rs`). This reads `main.rs` and proves only that the call is
/// there and ahead of the serve call in source order; that the setting takes effect is
/// `capture_heap_test.rs`.
#[test]
fn main_calls_pin_mmap_threshold_ahead_of_serving_in_source_order() {
    let main = main_source();
    let pinned = main
        .find("session_memory::pin_mmap_threshold()")
        .expect("main pins the mmap threshold");
    let served = main
        .find("sensor_ssh::serve_with_handoff(")
        .expect("main serves");
    assert!(
        pinned < served,
        "the threshold is pinned before the first connection"
    );
}

#[test]
fn the_inputs_are_the_real_sources() {
    assert_eq!(unit_memory_max(), UNIT_MEMORY_MAX_BYTES);
    assert_eq!(
        default_capture_budget_bytes(unit_memory_max()),
        DEFAULT_CAPTURE_BUDGET_BYTES
    );
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
    assert_eq!(SPOOL_MAX_FILE_BYTES, 16 * 1024 * 1024);
    // The framework's largest kept body, which is the indicator scan's size limit, so the scan
    // reads every body this sensor keeps.
    assert_eq!(SPOOL_MAX_FILE_BYTES, sensor_framework::SPOOL_MAX_FILE_BYTES);
    // The other spooling sensors keep 10 MB, under it, so the scan reads theirs too.
    for sensor in ["adb", "ftp"] {
        let lib = workspace_file(&format!("crates/sensor-{sensor}/src/lib.rs"));
        assert!(
            lib.contains("const SPOOL_MAX_FILE_SIZE: u64 = 10_000_000;"),
            "sensor-{sensor}'s per-file cap is not 10_000_000"
        );
    }
    const {
        assert!(10_000_000 < SPOOL_MAX_FILE_BYTES);
    }
    // Room for at least ten maximum-size uploads at once (twelve fit), so one large upload never
    // decides whether another is kept whole.
    const {
        assert!(DEFAULT_CAPTURE_BUDGET_BYTES >= 10 * SPOOL_MAX_FILE_BYTES);
    }
    // And the output budget covers a line's allowance on each of two workers, with room left to
    // queue.
    const {
        assert!(OUTPUT_BUDGET_BYTES >= 4 * OUTPUT_UNIT_BYTES);
    }
}
