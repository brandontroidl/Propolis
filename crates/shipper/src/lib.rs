//! Collector-side batch assembly and shipping: reads whole NDJSON lines from a sensor log via
//! the shared `log-tailer`, assembles them into the next sequenced, hash-chained
//! `collector_wire::frame` `Batch` (`batcher`), and ships each batch to the gateway over mutual
//! TLS, advancing durable state only after a confirmed ack (`client`, `state`). Until that ack is
//! recorded, the batch in flight is kept on disk exactly as sent (`pending`).
pub mod batcher;
pub mod client;
pub mod config;
pub mod pending;
pub mod state;
