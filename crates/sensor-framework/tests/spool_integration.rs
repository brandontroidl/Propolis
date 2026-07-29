//! Integration tests for `QuarantineSpool`, exercised only through `sensor_framework`'s public
//! API (no submodule paths), matching this workspace's integration-test convention (see
//! `core-scoring/tests/end_to_end.rs`). The inline unit tests in `src/spool.rs` cover individual
//! guards in isolation; these two scenarios only show up across a fuller lifecycle or under real
//! concurrent load, so they belong here rather than in the unit suite.

use sensor_framework::{QuarantineSpool, SpoolError};

/// A sensor restart (crash, redeploy, host reboot) must not reset how much of the operator's
/// byte budget is already spent.
///
/// A second `QuarantineSpool` constructed over the same directory - simulating the process
/// starting back up - has to recover the bytes an earlier instance wrote, not start counting
/// from zero while those bytes still sit on disk.
#[test]
fn budget_persists_across_spool_restarts() {
    let dir = tempfile::tempdir().unwrap();

    {
        let spool = QuarantineSpool::new(dir.path().to_path_buf(), 1024, 150);
        spool.store(&[0xAAu8; 100]).unwrap();
    } // spool dropped here - simulates the sensor process exiting.

    let restarted = QuarantineSpool::new(dir.path().to_path_buf(), 1024, 150);
    let result = restarted.store(&[0xBBu8; 100]); // 100 (recovered) + 100 > 150
    assert!(
        matches!(result, Err(SpoolError::BudgetExhausted { .. })),
        "a fresh instance over the same directory must count the prior instance's bytes"
    );

    // The budget still has headroom for a smaller capture.
    restarted.store(&[0xCCu8; 40]).unwrap();
}

/// Every sensor connection is handled by its own task, and production capture hand-off shares
/// one `QuarantineSpool` across them (see Task 6's plan). Drive real OS threads against one
/// spool over a real directory and confirm the budget is a hard ceiling on bytes actually
/// written to disk: exactly as many distinct bodies are admitted as the budget allows, none are
/// double-admitted or lost, and every admitted sample reads back intact.
#[test]
fn concurrent_stores_respect_budget_and_never_corrupt_content() {
    use std::sync::Arc;

    const BODY_SIZE: u64 = 100;
    const ATTEMPTS: u64 = 20;
    const BUDGET: u64 = BODY_SIZE * 8; // exactly 8 of the 20 distinct bodies can fit.

    let dir = tempfile::tempdir().unwrap();
    let spool = Arc::new(QuarantineSpool::new(
        dir.path().to_path_buf(),
        BODY_SIZE,
        BUDGET,
    ));

    let handles: Vec<_> = (0..ATTEMPTS)
        .map(|i| {
            let spool = Arc::clone(&spool);
            std::thread::spawn(move || {
                // Distinct content per thread, so no two threads can dedup-hit each other -
                // this isolates the atomic budget counter as the only thing under test.
                let body = vec![i as u8; BODY_SIZE as usize];
                spool.store(&body)
            })
        })
        .collect();

    let results: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();

    let admitted = results.iter().filter(|r| r.is_ok()).count();
    assert_eq!(
        admitted, 8,
        "budget of {BUDGET} bytes at {BODY_SIZE} bytes each must admit exactly 8 of {ATTEMPTS}"
    );
    for result in results.iter().filter(|r| r.is_err()) {
        assert!(matches!(result, Err(SpoolError::BudgetExhausted { .. })));
    }

    // Every admitted sample is fully and correctly on disk - no interleaved or truncated write
    // from concurrent threads sharing the directory.
    let mut total_bytes_on_disk = 0u64;
    for entry in std::fs::read_dir(dir.path()).unwrap() {
        total_bytes_on_disk += entry.unwrap().metadata().unwrap().len();
    }
    assert_eq!(total_bytes_on_disk, BODY_SIZE * admitted as u64);

    for result in results.into_iter().filter_map(Result::ok) {
        spool.verify(&result.sha256).unwrap();
    }
}
