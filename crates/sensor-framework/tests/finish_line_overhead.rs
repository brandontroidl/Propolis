//! Running a held line on a large input must not copy the input. `HeldInput` lends its charged
//! buffer to the shell, and the shell's readers copy no more than the line's work budget, so the
//! heap a finishing line adds on top of the (already charged) input is bounded by a constant
//! that does not grow with the input. Before this was pinned the shell copied the whole input
//! once on entry and again in each reader: about 3x a 10 MB body, uncharged, per worker thread.
//!
//! One test in this binary, because the counting allocator is process-global.

use sensor_framework::fakefs::FakeFs;
use sensor_framework::shell::{EmitContext, FakeShell, InputEnd, LineStep};
use std::alloc::{GlobalAlloc, Layout, System};
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

/// Heap a line adds while it runs on `size` bytes of input, beyond the input itself.
fn extra_heap(line: &str, size: usize) -> usize {
    let mut shell = FakeShell::exec(FakeFs::new(), ctx());
    assert!(matches!(shell.start_line(line).0, LineStep::AwaitingInput));
    let body = vec![b'A'; size];
    let base = CURRENT.load(Ordering::SeqCst);
    PEAK.store(base, Ordering::SeqCst);
    let (out, body) = shell.finish_line_owned(body, InputEnd::Eof);
    let peak = PEAK.load(Ordering::SeqCst);
    assert_eq!(body.len(), size, "{line}: the input comes back whole");
    drop(out);
    peak.saturating_sub(base)
}

/// The line's own working budget of 4_194_304 bytes (`BudgetLimits::work_per_line`), copied at
/// most five times (a reader's copy, its output, the redirect's write), plus 1 MiB for the
/// shell's bookkeeping. Not a function of the input's size.
const BOUND: usize = 5 * 4_194_304 + 1_048_576;

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
        let small = extra_heap(line, 1_000_000);
        let large = extra_heap(line, 10_000_000);
        let huge = extra_heap(line, 40_000_000);
        println!("FINISH_LINE {line:?} 1MB={small} 10MB={large} 40MB={huge}");
        assert!(large <= BOUND, "{line}: {large} extra bytes on 10 MB");
        // Four times the input must not move the overhead: that is what separates a bound from a
        // multiple of the input.
        assert!(
            huge <= large.saturating_add(1_048_576),
            "{line}: overhead grew with the input, {large} at 10 MB and {huge} at 40 MB"
        );
        assert!(huge <= BOUND, "{line}: {huge} extra bytes on 40 MB");
        let _ = small;
    }
}
