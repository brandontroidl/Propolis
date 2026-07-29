//! Aggregate operator configuration for one sensor process: which addresses to bind, the WAN
//! attribution table, the connection bounds, and the paths and sizes the event log and quarantine
//! spool are built from. One `SensorConfig` is loaded once at sensor startup and threaded through
//! to `EventEmitter`, `QuarantineSpool`, `WanResolver`, and every `run_tcp_listener`/
//! `run_udp_listener` call the sensor makes. This crate defines only the shape; loading it from
//! TOML or CLI args and validating it (a bounded port set, range-checked bounds, "zero does not
//! mean unlimited" - see `internal/design/02-sensor-framework.md`'s "Config values are validated
//! and bounded") is each sensor binary's own job, not this framework's.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;

use crate::bounds::ConnectionBounds;

#[derive(Debug, Clone)]
pub struct SensorConfig {
    pub bind_addrs: Vec<SocketAddr>,
    pub wan_map: HashMap<IpAddr, IpAddr>,
    pub bounds: ConnectionBounds,
    pub log_path: PathBuf,
    pub spool_dir: PathBuf,
    pub spool_max_file_size: u64,
    pub spool_global_budget: u64,
    pub capture_queue_size: usize,
}
