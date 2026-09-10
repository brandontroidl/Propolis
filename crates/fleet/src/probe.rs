//! The active reachability probe: a control-plane-originated TCP connect to each listener's
//! advertised address, with the result written to `listener_probe`.
//!
//! WHY A CONNECT, and not something cheaper. Reading `/proc/net/tcp`, `ss`, or the sensor's own
//! bind config proves only that a socket was bound; it cannot see a firewall rule, a missing DNAT,
//! or a listener bound to the wrong interface. A probe run on the collector itself traverses no
//! external path. A third-party reachability service means the control plane beacons out and
//! discloses the collector's address. Raw-socket scanning needs `CAP_NET_RAW`, which no unit
//! grants. A plain `connect()` from the control plane traverses the path an attacker traverses.
//!
//! WHAT IT DOES NOT PROVE. On a single box the control plane and the collector are the same host,
//! so the connect is a HAIRPIN: it never leaves the machine and is therefore evidence that the
//! socket answers locally, not that anything outside can reach it. [`probe_once`] detects that
//! case at the socket level (the local and peer addresses are the same address) and says so in the
//! stored detail, so the pane can never present a hairpin as external reachability.
//!
//! WHY `refused` AND `timeout` ARE KEPT APART. Both are failures and both alarm, but they point at
//! different repairs: `ECONNREFUSED` means the path works and nothing is listening (the sensor is
//! dead or misbound), while a timeout means the packet was dropped (firewall, host down, wrong
//! address). Collapsing them into one "unreachable" would throw away the whole diagnostic payload.
//!
//! EVIDENCE CONTAMINATION. Every TCP sensor emits `honeypot_connection` on accept, before reading a
//! byte, so these connects DO produce sensor events. They are dropped at intake before conversion
//! (`intake::runner`), which is also what confirms the whole collection chain works: intake is the
//! far end, so intake seeing the line is the proof wanted. Nothing here writes to `event`.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use chrono::Utc;
use sqlx::PgPool;
use tokio::net::TcpStream;
use tokio_util::sync::CancellationToken;

use crate::inventory::{Listener, Proto};
use crate::store::{ProbeOutcome, ProbeRecord, upsert_probe};

/// Sweep cadence and per-connect deadline. Both are operator-bounded in `propolis::config`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProbeConfig {
    pub interval: Duration,
    pub timeout: Duration,
}

/// What is stored when the collector has no address to dial.
const NO_ENDPOINT: &str = "no endpoint configured for collector";
/// What is stored for UDP. The catch-all answers nothing on UDP, so a connect decides nothing:
/// calling it unreachable would be a lie and calling it reachable a worse one.
const UDP_NOT_PROBEABLE: &str = "udp reachability is not provable by connect";
/// What is stored when the connect never left this host.
const HAIRPIN: &str =
    "hairpin: this connect never left the host, so it is not evidence of external reachability";

/// Probes one listener once and returns the record to store. Never fails: every outcome, including
/// "there was nothing to dial", is a recorded state rather than an error the caller must invent a
/// meaning for.
pub async fn probe_once(
    listener: &Listener,
    target: Option<&str>,
    timeout: Duration,
) -> ProbeRecord {
    let attempted_at = Utc::now();
    let record =
        |target: String, outcome: ProbeOutcome, detail: Option<&str>, latency: Option<i32>| {
            ProbeRecord {
                listener: listener.clone(),
                target,
                attempted_at,
                outcome,
                detail: detail.map(str::to_string),
                latency_ms: latency,
            }
        };

    // The missing endpoint is checked before the protocol so the operator sees the configuration
    // gap that is actually fixable, rather than a UDP note that hides it.
    let Some(target) = target else {
        return record(
            String::new(),
            ProbeOutcome::NotProbeable,
            Some(NO_ENDPOINT),
            None,
        );
    };
    if listener.protocol == Proto::Udp {
        return record(
            target.to_string(),
            ProbeOutcome::NotProbeable,
            Some(UDP_NOT_PROBEABLE),
            None,
        );
    }

    let started = Instant::now();
    match tokio::time::timeout(timeout, TcpStream::connect(target)).await {
        Ok(Ok(stream)) => {
            let elapsed = i32::try_from(started.elapsed().as_millis()).unwrap_or(i32::MAX);
            // Same address on both ends means the packets never left the machine. This is the only
            // check that can tell a real external path from a loopback or same-host connect, and
            // it is done here rather than by comparing the target against a configured list of
            // local addresses because the kernel already knows the answer.
            let hairpin = match (stream.local_addr(), stream.peer_addr()) {
                (Ok(local), Ok(peer)) => local.ip() == peer.ip(),
                _ => false,
            };
            // Dropped immediately, with no byte written: the sensors emit their connection event
            // on accept, so writing anything would only add noise to a line that is dropped at
            // intake anyway.
            drop(stream);
            record(
                target.to_string(),
                ProbeOutcome::Reachable,
                hairpin.then_some(HAIRPIN),
                Some(elapsed),
            )
        }
        Ok(Err(e)) if e.kind() == std::io::ErrorKind::ConnectionRefused => record(
            target.to_string(),
            ProbeOutcome::Refused,
            Some("connection refused: the path works and nothing is listening"),
            None,
        ),
        // The error KIND, never the `Display`, which can carry an OS string that varies by libc
        // and by locale and would then vary the stored detail for one unchanged failure.
        Ok(Err(e)) => record(
            target.to_string(),
            ProbeOutcome::Error,
            Some(&format!("connect failed: {:?}", e.kind())),
            None,
        ),
        Err(_elapsed) => record(
            target.to_string(),
            ProbeOutcome::Timeout,
            Some("no answer within the probe timeout: the packet was dropped"),
            None,
        ),
    }
}

/// Sweeps every listener each interval and stores one row per listener.
///
/// A write failure is logged and the sweep continues. The unwritten row keeps its previous
/// `attempted_at`, so it ages into the staleness rule and the pane alarms - the failure surfaces as
/// an unmeasured listener rather than as silence, which is the fail-closed direction.
pub async fn run_probe_loop(
    pool: PgPool,
    listeners: Arc<Vec<Listener>>,
    endpoints: Arc<BTreeMap<String, String>>,
    cfg: ProbeConfig,
    cancel: CancellationToken,
) {
    tracing::info!(
        listeners = listeners.len(),
        interval_secs = cfg.interval.as_secs(),
        timeout_secs = cfg.timeout.as_secs(),
        "listener-probe: sweeping"
    );
    loop {
        for listener in listeners.iter() {
            // Checked per listener, not only per sweep: with a full inventory and a timeout each,
            // a sweep can outlast the shutdown budget if it only ever checks at the top.
            if cancel.is_cancelled() {
                tracing::info!("listener-probe: stopped");
                return;
            }
            let target = listener.target(&endpoints);
            let record = probe_once(listener, target.as_deref(), cfg.timeout).await;
            if let Err(e) = upsert_probe(&pool, &record).await {
                tracing::error!(
                    sensor = %listener.sensor,
                    port = listener.port,
                    error = %e,
                    "listener-probe: storing the result failed; the row ages into stale"
                );
            }
        }

        tokio::select! {
            _ = tokio::time::sleep(cfg.interval) => {}
            _ = cancel.cancelled() => {
                tracing::info!("listener-probe: stopped");
                return;
            }
        }
    }
}
