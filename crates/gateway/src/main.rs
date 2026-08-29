//! gateway: the append-only ingest gateway binary. Loads the CA + server PEMs and its own
//! `PROPOLIS_GATEWAY_*` env config (see `config.rs`), builds the mandatory-client-auth mTLS
//! server config (`collector_wire::tls::server_config`), and runs the accept loop
//! (`gateway::serve`) until `sensor_framework::shutdown_signal` fires. See `lib.rs` and
//! `internal/design/` for the collector/control-plane split this binary is one half of.
//!
//! Configuration is environment variables only - the gateway holds no `DATABASE_URL` and no
//! vendor keys; every value is validated at startup and the process refuses to start on a
//! malformed one (`config::load_config_from_env`).

mod config;

use std::sync::Arc;

use config::load_config_from_env;
use gateway::{GatewaySink, SpoolWriter};
use sensor_framework::shutdown_signal;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    let config = match load_config_from_env() {
        Ok(c) => c,
        Err(e) => {
            tracing::error!(error = %e, "gateway: invalid configuration; refusing to start");
            std::process::exit(1);
        }
    };

    let ca_pem = match std::fs::read(&config.ca_cert_path) {
        Ok(bytes) => bytes,
        Err(e) => {
            tracing::error!(
                path = %config.ca_cert_path.display(),
                error = %e,
                "gateway: failed to read CA cert; refusing to start"
            );
            std::process::exit(1);
        }
    };
    let cert_pem = match std::fs::read(&config.server_cert_path) {
        Ok(bytes) => bytes,
        Err(e) => {
            tracing::error!(
                path = %config.server_cert_path.display(),
                error = %e,
                "gateway: failed to read server cert; refusing to start"
            );
            std::process::exit(1);
        }
    };
    let key_pem = match std::fs::read(&config.server_key_path) {
        Ok(bytes) => bytes,
        Err(e) => {
            tracing::error!(
                path = %config.server_key_path.display(),
                error = %e,
                "gateway: failed to read server key; refusing to start"
            );
            std::process::exit(1);
        }
    };

    let tls = match collector_wire::tls::server_config(&ca_pem, &cert_pem, &key_pem) {
        Ok(cfg) => cfg,
        Err(e) => {
            tracing::error!(error = %e, "gateway: failed to build TLS server config; refusing to start");
            std::process::exit(1);
        }
    };

    let spool = SpoolWriter::new(config.spool_dir.clone());
    let sink = Arc::new(GatewaySink::new(config.state_dir.clone(), spool));

    let (bound, handle) = match gateway::serve(config.bind_addr, tls, config.bounds, sink).await {
        Ok(pair) => pair,
        Err(e) => {
            tracing::error!(
                addr = %config.bind_addr,
                error = %e,
                "gateway: failed to start server"
            );
            std::process::exit(1);
        }
    };

    tracing::info!(local = %bound, "gateway: listening");

    shutdown_signal().await;
    tracing::info!("gateway: shutdown signal received; stopping");
    handle.abort();
}
