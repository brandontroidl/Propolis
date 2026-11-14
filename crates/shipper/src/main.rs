//! shipper: the collector-side binary that tails this box's sensor logs and ships them to the
//! gateway over mutual TLS. Loads `PROPOLIS_SHIPPER_*` env config (`shipper::config`), validates
//! `COLLECTOR_ID` against the client certificate's own CommonName, builds the mTLS client config
//! (`collector_wire::tls::client_config`), then runs ONE ship loop until
//! `sensor_framework::shutdown_signal` fires.
//!
//! **Single multiplexed seq chain (corrected Task 12 design):** the gateway keys its
//! monotonic-seq + rolling-hash chain by the client certificate's CommonName (the collector id),
//! not by anything the collector sends per batch, and spools every accepted batch for that CN
//! into ONE `events.jsonl`. So every sensor log on this collector shares a SINGLE
//! `shipper::state::ConfirmedState` keyed by `COLLECTOR_ID` (one file in `STATE_DIR`) and a
//! SINGLE seq chain - each sensor log still keeps its own `LogTailer` and per-log cursor (in
//! `CURSOR_DIR`), but the confirmed seq/hash is collector-global. Running one independent
//! ship-cycle per sensor log, each with its own seq counter, would make two logs both ship
//! "seq 1" under the same CN; the gateway would accept the first and `Duplicate`-drop the
//! second's records. The ship loop below therefore drains the tailers SERIALLY through the one
//! shared chain, in order, one pass at a time - never as concurrent per-log tasks, since the
//! shared chain requires exactly one in-flight batch at a time.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use collector_wire::tls::client_config;
use log_tailer::LogTailer;
use sensor_framework::shutdown_signal;
use shipper::client::{
    CycleReport, RetryPolicy, ShipperClient, StopReason, settle_orphaned, ship_cycle,
};
use shipper::config::{load_config_from_env, validate_collector_id};
use shipper::pending::PendingBatch;
use tokio_rustls::rustls::ClientConfig;

/// How many consecutive gateway `Retry` acks for the same batch `ship_cycle` tolerates before
/// giving up on that batch for this pass. Not configurable via env (unlike `RETRY_BACKOFF_MS`,
/// which sets the sleep between attempts): a gateway that is merely momentarily busy resolves
/// within a handful of backed-off retries, and the outer ship loop's own next-pass retry already
/// covers a gateway down for longer than that, so a second knob here would not buy anything the
/// loop's own cadence does not already provide.
const MAX_CONSECUTIVE_RETRIES: u32 = 5;

#[tokio::main]
async fn main() {
    log_format::init(tracing::level_filters::LevelFilter::ERROR);

    let config = match load_config_from_env() {
        Ok(c) => c,
        Err(e) => {
            tracing::error!(error = %e, "shipper: invalid configuration; refusing to start");
            std::process::exit(1);
        }
    };

    let ca_pem = match std::fs::read(&config.ca_cert_path) {
        Ok(bytes) => bytes,
        Err(e) => {
            tracing::error!(
                path = %config.ca_cert_path.display(),
                error = %e,
                "shipper: failed to read CA cert; refusing to start"
            );
            std::process::exit(1);
        }
    };
    let cert_pem = match std::fs::read(&config.client_cert_path) {
        Ok(bytes) => bytes,
        Err(e) => {
            tracing::error!(
                path = %config.client_cert_path.display(),
                error = %e,
                "shipper: failed to read client cert; refusing to start"
            );
            std::process::exit(1);
        }
    };
    let key_pem = match std::fs::read(&config.client_key_path) {
        Ok(bytes) => bytes,
        Err(e) => {
            tracing::error!(
                path = %config.client_key_path.display(),
                error = %e,
                "shipper: failed to read client key; refusing to start"
            );
            std::process::exit(1);
        }
    };

    // Fail closed before ever dialing the gateway: this collector's own configured
    // COLLECTOR_ID must match what its certificate actually presents, or every batch it ships
    // would silently land under a different collector id than the operator intended.
    if let Err(e) = validate_collector_id(&cert_pem, &config.collector_id) {
        tracing::error!(
            error = %e,
            "shipper: COLLECTOR_ID does not match the client certificate; refusing to start"
        );
        std::process::exit(1);
    }

    let tls = match client_config(&ca_pem, &cert_pem, &key_pem) {
        Ok(cfg) => cfg,
        Err(e) => {
            tracing::error!(error = %e, "shipper: failed to build TLS client config; refusing to start");
            std::process::exit(1);
        }
    };

    let tailers: Vec<(String, LogTailer)> = config
        .sensor_logs
        .iter()
        .map(|log| {
            (
                log.name.clone(),
                LogTailer::new(log.log_path.clone(), config.cursor_dir.clone()),
            )
        })
        .collect();

    tracing::info!(
        collector_id = %config.collector_id,
        gateway = %config.gateway_addr,
        sensor_logs = tailers.len(),
        "shipper: starting single multiplexed ship loop"
    );

    let retry = RetryPolicy::new(
        Duration::from_millis(config.retry_backoff_ms),
        MAX_CONSECUTIVE_RETRIES,
    );

    let mut handle = tokio::spawn(run_ship_loop(
        config.gateway_addr,
        config.gateway_dns.clone(),
        tls,
        config.collector_id.clone(),
        tailers,
        config.state_dir.clone(),
        config.max_records_per_batch,
        retry,
        Duration::from_millis(config.poll_interval_ms),
    ));

    // `run_ship_loop` only ever returns on its own on a PERMANENT stop (see its doc): a shared
    // seq/hash chain broken by a `Reject` or a `ChainDiverged` divergence. Racing the join
    // handle against `shutdown_signal` makes that observable here rather than letting the
    // process sit up shipping nothing while monitoring still sees it "running" (F3): a clean
    // shutdown signal wins the race normally and aborts the loop with a zero exit, but if the
    // loop's own task finishes FIRST, that is the permanent-stop branch, not a clean shutdown -
    // exit non-zero so systemd/monitoring sees a failed unit (dead-man's-switch).
    tokio::select! {
        result = &mut handle => {
            match result {
                Ok(()) => {
                    tracing::error!(
                        "shipper: ship loop terminated on a permanent stop condition (gateway \
                         rejection, chain divergence or an unprovable duplicate); exiting \
                         non-zero so this is visible as a failed unit rather than a silently \
                         idle process"
                    );
                }
                Err(e) => {
                    tracing::error!(error = %e, "shipper: ship loop task panicked; exiting");
                }
            }
            std::process::exit(1);
        }
        _ = shutdown_signal() => {
            tracing::info!("shipper: shutdown signal received; stopping ship loop");
            handle.abort();
        }
    }
}

/// Runs the single multiplexed ship loop until a gateway `Reject`, a `ChainDiverged` or an
/// `UnprovenDuplicate` breaks the shared chain (see the module doc) - the only ways this function
/// returns on its own; `main` treats each as a permanent stop (F3) and exits non-zero. Each pass iterates `tailers` in
/// order, dials the gateway once per tailer,
/// and runs Task 11's `ship_cycle` against the SHARED `collector_id` confirmed-state key; if the
/// whole pass shipped nothing from any log, sleeps `poll_interval` before the next pass. A
/// per-tailer connect or IO error is logged and the loop moves on to the next tailer /
/// next pass rather than aborting outright, since a transient network blip on one log's batch
/// must not stall every other log sharing this chain.
#[allow(clippy::too_many_arguments)]
async fn run_ship_loop(
    gateway_addr: SocketAddr,
    gateway_dns: String,
    tls: Arc<ClientConfig>,
    collector_id: String,
    mut tailers: Vec<(String, LogTailer)>,
    state_dir: PathBuf,
    max_records: usize,
    retry: RetryPolicy,
    poll_interval: Duration,
) {
    for stray in PendingBatch::foreign_records(&state_dir, &collector_id) {
        tracing::warn!(
            path = %stray.display(),
            "shipper: a record of a batch in flight for another collector id is in the state \
             directory; it is not read or sent. Its lines are behind their logs' read positions \
             and ship under this collector id; delete the file once that chain is retired"
        );
    }

    loop {
        let mut any_shipped = false;

        // A batch in flight from a log no tailer reads would hold the shared chain for ever,
        // since only its own log's cycle settles a record.
        if let Ok(Some((label, path))) = PendingBatch::owner(&state_dir, &collector_id)
            && !tailers
                .iter()
                .any(|(name, tailer)| *name == label && tailer.log_path() == path)
        {
            tracing::warn!(
                sensor = %label,
                path = %path.display(),
                "shipper: the batch in flight was read from a log that is no longer configured; \
                 sending it again to settle its sequence number, with no read position to move"
            );
            match ShipperClient::connect(gateway_addr, tls.clone(), &gateway_dns).await {
                Ok(mut stream) => {
                    match settle_orphaned(&mut stream, &state_dir, &collector_id, retry).await {
                        Ok(CycleReport {
                            stopped: Some(reason @ StopReason::Rejected { .. }),
                            ..
                        }) => {
                            // The record stays, as in the Rejected arm of the ship loop below:
                            // a gateway whose chain state was lost or unreadable rejects a batch
                            // it may hold, and this log is no longer read, so a reset here would
                            // give up the only copy of these lines the shipper can still send.
                            tracing::error!(
                                sensor = %label,
                                ?reason,
                                "shipper: gateway rejected the batch in flight from a log no \
                                 longer configured; stopping the ship loop. The record of that \
                                 batch (<collector id>.pending) is kept, because a gateway whose \
                                 chain state was lost or unreadable rejects a batch it may hold: \
                                 once its state is put back and gateway.service restarted, that \
                                 batch is sent again and confirmed. Otherwise reset the chain on \
                                 both sides, which deletes it"
                            );
                            return;
                        }
                        Ok(CycleReport {
                            stopped:
                                Some(
                                    reason @ (StopReason::ChainDiverged { .. }
                                    | StopReason::UnprovenDuplicate { .. }),
                                ),
                            ..
                        }) => {
                            tracing::error!(
                                sensor = %label,
                                ?reason,
                                "shipper: the batch in flight from a log no longer configured \
                                 cannot be settled; stopping the ship loop for an operator to \
                                 reset the chain"
                            );
                            return;
                        }
                        Ok(_) => {}
                        Err(e) => tracing::error!(
                            sensor = %label,
                            error = %e,
                            "shipper: ship cycle IO error; will retry next pass"
                        ),
                    }
                }
                Err(e) => tracing::error!(
                    error = %e,
                    "shipper: failed to connect to gateway; will retry next pass"
                ),
            }
        }

        for (sensor_name, tailer) in tailers.iter_mut() {
            let mut stream =
                match ShipperClient::connect(gateway_addr, tls.clone(), &gateway_dns).await {
                    Ok(stream) => stream,
                    Err(e) => {
                        tracing::error!(
                            sensor = %sensor_name,
                            error = %e,
                            "shipper: failed to connect to gateway; will retry next pass"
                        );
                        continue;
                    }
                };

            let report = match ship_cycle(
                &mut stream,
                tailer,
                sensor_name,
                &state_dir,
                &collector_id,
                max_records,
                retry,
            )
            .await
            {
                Ok(report) => report,
                Err(e) => {
                    tracing::error!(
                        sensor = %sensor_name,
                        error = %e,
                        "shipper: ship cycle IO error; will retry next pass"
                    );
                    continue;
                }
            };

            if report.batches_shipped > 0 {
                any_shipped = true;
            }
            // Each refused line was already logged with its reason; this is the cycle's total,
            // so a log that keeps carrying lines it has no business carrying stands out.
            if report.refused > 0 {
                tracing::warn!(
                    sensor = %sensor_name,
                    refused = report.refused,
                    batches_shipped = report.batches_shipped,
                    "shipper: this cycle dropped lines the origin policy refuses for this log; \
                     they were not shipped"
                );
            }

            match report.stopped {
                None => {}
                Some(StopReason::RetriesExhausted) => {
                    tracing::warn!(
                        sensor = %sensor_name,
                        "shipper: gateway kept returning Retry past the consecutive-retry bound \
                         for this pass; will retry next pass"
                    );
                }
                Some(StopReason::Rejected { reason }) => {
                    // The chain is broken: the shared ConfirmedState for `collector_id` no
                    // longer agrees with what the gateway will accept next. Retrying would just
                    // repeat the same rejection, and every other tailer shares this exact chain,
                    // so there is nothing left for this loop to safely do but stop and let an
                    // operator resolve it. The record of the batch in flight stays: a gateway
                    // that lost or could not read its chain state rejects a batch it may hold,
                    // and only that exact batch may be sent once its state is back.
                    tracing::error!(
                        sensor = %sensor_name,
                        ?reason,
                        "shipper: gateway rejected a batch; the shared seq/hash chain is \
                         broken, stopping the ship loop. The record of the batch in flight \
                         (<collector id>.pending) is kept, because a gateway whose chain state \
                         was lost or unreadable rejects a batch it may hold: once its state is \
                         put back and gateway.service restarted, that batch is sent again and \
                         confirmed. Otherwise reset the chain on both sides, which deletes it"
                    );
                    return;
                }
                Some(StopReason::ChainDiverged {
                    our_seq,
                    gateway_next_expected,
                }) => {
                    // Same permanent-stop shape as Rejected above (see StopReason::ChainDiverged's
                    // doc and F1 in client.rs's module doc): the shared chain for `collector_id`
                    // has diverged from the gateway's, every other tailer shares this exact
                    // chain, and blindly continuing would keep silently losing records. Stop and
                    // let an operator resync.
                    tracing::error!(
                        sensor = %sensor_name,
                        our_seq,
                        gateway_next_expected,
                        "shipper: this collector's chain has diverged from the gateway's; \
                         stopping the ship loop for an operator to resync"
                    );
                    return;
                }
                Some(StopReason::UnprovenDuplicate { seq }) => {
                    // Confirming would risk skipping lines and resending cannot settle it, so
                    // the same permanent stop: the operator resets the chain on both sides.
                    tracing::error!(
                        sensor = %sensor_name,
                        seq,
                        "shipper: cannot prove which batch the gateway holds under this sequence \
                         number; stopping the ship loop for an operator to reset the chain"
                    );
                    return;
                }
            }
        }

        if !any_shipped {
            tokio::time::sleep(poll_interval).await;
        }
    }
}
