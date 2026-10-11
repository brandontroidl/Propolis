//! Running a held line on a large input must not copy the input. `HeldInput` lends its charged
//! buffer to the shell, and the shell's readers copy no more than the line's work budget, so the
//! heap a finishing line adds on top of the (already charged) input is bounded by a constant
//! that does not grow with the input. Before this was pinned the shell copied the whole input
//! once on entry and again in each reader: about 3x a 10 MB body, uncharged, per worker thread.
//!
//! Measured twice: on the shell alone, and through `HeldInput::finish`, the path production
//! takes (a copy added there is invisible to a test that calls the shell directly). Every size is
//! asserted, not only the largest.
//!
//! One test in this binary, because the counting allocator is process-global.

use sensor_framework::fakefs::FakeFs;
use sensor_framework::shell::{EmitContext, FakeShell, InputEnd, LineStep};
use sensor_framework::{
    CaptureHandoff, CaptureMemoryBudget, CaptureSource, EventEmitter, HeldEnd, HeldInput,
    InputMode, LINE_WORKING_SET_BYTES, OutboxManifest, QuarantineSpool, StdinCaptures,
};
use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

struct Counting;
static CURRENT: AtomicUsize = AtomicUsize::new(0);
static PEAK: AtomicUsize = AtomicUsize::new(0);

fn grow(by: usize) {
    let now = CURRENT.fetch_add(by, Ordering::SeqCst) + by;
    PEAK.fetch_max(now, Ordering::SeqCst);
}

// SAFETY: every call forwards to `System` with the caller's own layout and pointer.
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        grow(layout.size());
        unsafe { System.alloc(layout) }
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        CURRENT.fetch_sub(layout.size(), Ordering::SeqCst);
        unsafe { System.dealloc(ptr, layout) }
    }
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        if new_size >= layout.size() {
            grow(new_size - layout.size());
        } else {
            CURRENT.fetch_sub(layout.size() - new_size, Ordering::SeqCst);
        }
        unsafe { System.realloc(ptr, layout, new_size) }
    }
}

#[global_allocator]
static ALLOC: Counting = Counting;

fn ctx() -> EmitContext {
    EmitContext {
        source_ip: "203.0.113.7".parse().unwrap(),
        wan_ip: None,
        authenticated: true,
        protocol_label: "ssh".to_string(),
        session_id: None,
    }
}

/// Heap a line adds while the shell runs it on `size` bytes of input, beyond the input itself.
fn extra_heap_shell(line: &str, size: usize) -> usize {
    let mut shell = FakeShell::exec(FakeFs::new(), ctx());
    assert!(matches!(shell.start_line(line).0, LineStep::AwaitingInput));
    let body = Arc::new(vec![b'A'; size]);
    let base = CURRENT.load(Ordering::SeqCst);
    PEAK.store(base, Ordering::SeqCst);
    let out = shell.finish_line_shared(body.clone(), InputEnd::Eof);
    let peak = PEAK.load(Ordering::SeqCst);
    assert_eq!(body.len(), size, "{line}: the input is still whole");
    drop(out);
    peak.saturating_sub(base)
}

/// The same, through `HeldInput::finish`: the input is fed in as a connection would feed it, then
/// the line is finished and recorded. Only `finish` is measured.
fn extra_heap_held(line: &str, size: usize) -> usize {
    let dir = tempfile::tempdir().unwrap();
    let spool_dir = dir.path().join("spool");
    std::fs::create_dir(&spool_dir).unwrap();
    let handoff = Arc::new(CaptureHandoff::new(
        QuarantineSpool::new(spool_dir, 100_000_000, 1_000_000_000),
        EventEmitter::new(dir.path().join("events.jsonl")),
        4,
        "test".to_string(),
        OutboxManifest::new(dir.path().join("outbox")),
        Arc::new(CaptureMemoryBudget::new(u64::MAX)),
    ));
    let captures = StdinCaptures::new(
        handoff,
        CaptureSource {
            sensor: "ssh",
            source_ip: "203.0.113.7".parse().unwrap(),
            wan_ip: None,
            session_id: uuid::Uuid::now_v7(),
            authenticated: true,
        },
    );
    let mut shell = FakeShell::exec(FakeFs::new(), ctx());
    assert!(matches!(shell.start_line(line).0, LineStep::AwaitingInput));
    let mut input = HeldInput::new(
        &shell,
        InputMode::Pipe,
        &captures,
        "exec_stdin",
        size as u64,
    );
    input.feed(&vec![b'A'; size]);
    assert_eq!(input.len(), size, "{line}: the whole input was kept");
    let base = CURRENT.load(Ordering::SeqCst);
    PEAK.store(base, Ordering::SeqCst);
    let out = input.finish(&mut shell, HeldEnd::Eof);
    let peak = PEAK.load(Ordering::SeqCst);
    drop(out);
    peak.saturating_sub(base)
}

/// The line's working allowance, a figure of its work budget and not of the input's size.
const BOUND: usize = LINE_WORKING_SET_BYTES as usize;

/// Assert, at every size, that the overhead is within the bound, and that quadrupling the input
/// from 10 MB moves it by no more than a megabyte.
fn check(path: &str, line: &str, measure: fn(&str, usize) -> usize) {
    let small = measure(line, 1_000_000);
    let large = measure(line, 10_000_000);
    let huge = measure(line, 40_000_000);
    println!("FINISH_LINE {path} {line:?} 1MB={small} 10MB={large} 40MB={huge}");
    for (size, extra) in [("1 MB", small), ("10 MB", large), ("40 MB", huge)] {
        assert!(
            extra <= BOUND,
            "{path} {line}: {extra} extra bytes on {size}"
        );
    }
    // Four times the input must not move the overhead: that is what separates a bound from a
    // multiple of the input.
    assert!(
        huge <= large.saturating_add(1_048_576),
        "{path} {line}: overhead grew with the input, {large} at 10 MB and {huge} at 40 MB"
    );
}

#[test]
fn the_heap_a_finishing_line_adds_does_not_grow_with_its_input() {
    for line in [
        "cat",
        "cat > /tmp/x",
        "cat | base64",
        "cat | sh",
        "sh",
        "wc -c",
        "dd of=/tmp/y",
    ] {
        check("shell", line, extra_heap_shell);
        check("held", line, extra_heap_held);
    }
}
