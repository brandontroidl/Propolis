//! Collector-side batch assembly and shipping: reads whole NDJSON lines from a sensor log via
//! the shared `log-tailer`, assembles them into the next sequenced, hash-chained
//! `collector_wire::frame` `Batch` (`batcher`), and ships each batch to the gateway over mutual
//! TLS, advancing durable state only after a confirmed ack (`client`, `state`).
pub mod batcher;
pub mod client;
pub mod state;
