//! `intake`: converts sensor wire-format events (`sensor-wire`) into `core-scoring` domain
//! events and, in later stages of sub-project 3, tails sensor NDJSON logs and appends the
//! converted events to the event ledger. See `internal/design/03-event-intake-aggregation.md`.

pub mod converter;
pub mod cursor;
