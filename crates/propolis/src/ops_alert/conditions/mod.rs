//! One module per operational failure-mode check. Each implements `Condition` and is evaluated by
//! the monitor poll loop.

pub mod backlog;
pub mod capacity;
pub mod subsystem;
