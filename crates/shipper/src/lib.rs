//! Collector-side batch assembly: reads whole NDJSON lines from a sensor log via the shared
//! `log-tailer` and assembles them into the next sequenced, hash-chained `collector_wire::frame`
//! `Batch`. Pure logic - no network I/O lives here (that arrives in a later task).
pub mod batcher;
