//! The append-only ingest gateway: a mandatory-client-auth mTLS accept loop that reads
//! length-prefixed batch frames from verified collectors and acks them. See
//! `internal/design/` for the collector/control-plane split this crate is one half of.

pub mod server;

pub use server::{BatchSink, serve};
