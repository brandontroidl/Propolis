//! Operational self-alerting: page the operator when Propolis itself degrades (distinct from the
//! Guardian, which watches for host compromise). A poll-based monitor evaluates a set of failure
//! conditions over signals the daemon already produces and dispatches ntfy alerts. See
//! docs/superpowers/specs/2026-08-23-propolis-ops-alerting-design.md.

pub mod config;

pub use config::OpsAlertConfig;
