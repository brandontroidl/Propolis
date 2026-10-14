//! Capture bodies must not leave freed copies of themselves resident.
//!
//! A `CaptureBody` grows 64 KiB at a time, so a payload at the capture limit is a few hundred
//! reallocations. glibc raises its mmap threshold to the size of the largest mapped block freed so
//! far (up to 32 MiB), so once the hand-off has stored and dropped one large body, later bodies
//! below that size grow on the heap: a realloc that cannot extend in place copies, and the block it
//! frees stays resident between the other bodies. None of that is charged to the capture budget,
//! and with several bodies growing at once it reached several times the capture limit (a probe of
//! eight interleaved 16 MiB bodies: 118 MB resident past what the bodies held). The sensor pins the
//! threshold at startup, so a body past it is its own mapping, grown by `mremap` and returned to
//! the kernel when freed.
//!
//! One test in its own binary: the threshold and the resident set are process-wide.

use std::sync::Arc;

use sensor_framework::session_memory::{AccountingAlloc, pin_mmap_threshold};
use sensor_framework::{CaptureBody, CaptureMemoryBudget};
use sensor_ssh::server::SPOOL_MAX_FILE_BYTES;

/// The allocator the sensor binary runs on.
#[global_allocator]
static ALLOCATOR: AccountingAlloc = AccountingAlloc;

/// Bodies growing at once: more than the two runtime workers, as connections interleave.
const BODIES: usize = 8;
/// One SSH channel data packet's worth, the size a body grows by per read.
const PACKET: usize = 32 * 1024;
/// What the allocator may hold past the live bytes: its own bookkeeping, not a body's size.
const SLACK_BYTES: u64 = 8 * 1024 * 1024;

fn resident_bytes() -> u64 {
    let status = std::fs::read_to_string("/proc/self/status").expect("/proc/self/status");
    let kib: u64 = status
        .lines()
        .find_map(|l| l.strip_prefix("VmRSS:"))
        .and_then(|v| v.split_whitespace().next())
        .and_then(|v| v.parse().ok())
        .expect("a VmRSS line");
    kib * 1024
}

#[test]
fn growing_capture_bodies_leave_no_freed_copies_resident() {
    assert!(pin_mmap_threshold(), "the allocator refused the threshold");
    let cap = SPOOL_MAX_FILE_BYTES as usize;

    // One body at the limit, stored and dropped, as the hand-off does after the first large
    // capture: without the pinned threshold this raises glibc's to the limit.
    drop(std::hint::black_box(vec![1u8; cap]));

    let budget = Arc::new(CaptureMemoryBudget::new(u64::MAX));
    let mut bodies: Vec<CaptureBody> = (0..BODIES)
        .map(|_| CaptureBody::with_budget(Arc::clone(&budget)))
        .collect();
    let packet = vec![0x5au8; PACKET];
    // Small allocations that outlive each read (packet buffers, events), so no body stays at the
    // top of the heap where a realloc could extend in place.
    let mut kept: Vec<Vec<u8>> = Vec::new();
    let base = resident_bytes();
    let mut worst = 0u64;
    while bodies.iter().all(|b| b.len() < cap) {
        for body in &mut bodies {
            body.extend_from_slice(&packet).expect("an unbounded budget");
            kept.push(vec![1u8; 4096]);
        }
        let live = budget.current_bytes() + (kept.len() * 4096) as u64;
        worst = worst.max(resident_bytes().saturating_sub(base + live));
    }
    assert!(
        worst < SLACK_BYTES,
        "{BODIES} bodies growing to {cap} bytes left {worst} bytes resident past what they hold"
    );
}
