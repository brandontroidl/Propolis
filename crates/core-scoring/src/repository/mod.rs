//! Persistence layer: the transactional append path and the read projection.
//!
//! `append_event` is the sole write path into the ledger + projection. It
//! fails closed: `validate()` runs before any transaction opens, and every
//! error inside the transaction propagates so the transaction rolls back and
//! NO projection is committed. `read_score` is a pure read that projects the
//! stored raw score to now without ever writing the projected value back - the
//! double-decay guard depends on the stored value staying un-projected.

pub mod events;

pub use events::{append_event, read_score, RepoError};
