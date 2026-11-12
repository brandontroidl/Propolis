//! Storing a body the spool already holds re-hashes the file on disk. That check must stream the
//! file: `store` still holds the (charged) body it was given, and reading the file into a second
//! full-size buffer put up to 16 MiB outside every memory budget on each repeat store, which is
//! the live pattern (the same miner on every attempt).
//!
//! The largest single allocation inside the dedup call is measured, so a whole-file read shows up
//! as one allocation of the body's size. A corrupted file must still be refused on that path.
//!
//! One test in this binary, because the counting allocator is process-global.

use sensor_framework::{QuarantineSpool, SpoolError};
use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering};

struct Counting;
static LARGEST: AtomicUsize = AtomicUsize::new(0);

// SAFETY: every call forwards to `System` with the caller's own layout and pointer.
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        LARGEST.fetch_max(layout.size(), Ordering::SeqCst);
        unsafe { System.alloc(layout) }
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { System.dealloc(ptr, layout) }
    }
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        LARGEST.fetch_max(new_size, Ordering::SeqCst);
        unsafe { System.realloc(ptr, layout, new_size) }
    }
}

#[global_allocator]
static ALLOC: Counting = Counting;

const BODY_BYTES: usize = 8 * 1024 * 1024;
/// Far below the body, far above a hashing chunk and the path and error strings the call makes.
const ALLOWED_SINGLE_ALLOCATION: usize = 1024 * 1024;

#[test]
fn a_repeat_store_does_not_read_the_file_into_memory() {
    let dir = tempfile::tempdir().unwrap();
    let spool = QuarantineSpool::new(dir.path().to_path_buf(), 16 * 1024 * 1024, 100_000_000);
    let body: Vec<u8> = (0..BODY_BYTES).map(|i| (i % 251) as u8).collect();

    let first = spool.store(&body).unwrap();

    LARGEST.store(0, Ordering::SeqCst);
    let again = spool.store(&body).unwrap();
    let largest = LARGEST.load(Ordering::SeqCst);
    assert_eq!(again.sha256, first.sha256);
    assert!(
        largest <= ALLOWED_SINGLE_ALLOCATION,
        "a repeat store of a {BODY_BYTES}-byte body made a {largest}-byte allocation"
    );

    // The streamed check still refuses a file whose content is not its name.
    let path = dir.path().join(&first.sha256);
    let mut tampered = body.clone();
    tampered[BODY_BYTES / 2] ^= 0xff;
    std::fs::write(&path, &tampered).unwrap();
    assert!(matches!(
        spool.store(&body),
        Err(SpoolError::HashMismatch { .. })
    ));
}
