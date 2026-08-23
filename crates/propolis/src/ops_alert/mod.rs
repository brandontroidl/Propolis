//! Operational self-alerting: page the operator when Propolis itself degrades (distinct from the
//! Guardian, which watches for host compromise). A poll-based monitor evaluates a set of failure
//! conditions over signals the daemon already produces and dispatches ntfy alerts. See
//! docs/superpowers/specs/2026-08-23-propolis-ops-alerting-design.md.
//!
// The subsystem is built module-by-module and only wired into the daemon (main.rs) by the final
// task of the plan, so its items are legitimately unused until then. Remove this allow when the
// ops-monitor is spawned in main.rs - at that point a real dead-code warning means a genuine gap.
#![allow(dead_code)]

pub mod config;
pub mod debounce;
pub mod dispatch;

pub use config::OpsAlertConfig;
