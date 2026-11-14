//! A batch whose acknowledgement never arrived must be the only thing ever sent under its
//! sequence number, across reconnects, restarts and a pass that turns to another log, so that a
//! `Duplicate` answer always confirms the lines the shipper then moves past. A real
//! `gateway::serve` over real mutual TLS with a real spool; the only fault injected is a
//! connection the gateway drops before or after it stores a batch, which is what a reset
//! connection or a timed-out ack looks like to the shipper.

use std::io::Write;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use collector_wire::ack::{Ack, AckReason, AckStatus};
use collector_wire::frame::Batch;
use collector_wire::tls::{client_config, server_config};
use gateway::{BatchSink, GatewaySink, SpoolWriter, serve};
use log_tailer::{DurableCursor, LogTailer};
use sensor_framework::ConnectionBounds;
use shipper::client::{
    CycleReport, RetryPolicy, ShipperClient, StopReason, settle_orphaned, ship_cycle,
};
use shipper::pending::PendingBatch;

const GATEWAY_DNS: &str = "gateway.local";
const COLLECTOR_ID: &str = "collector-test";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Fault {
    None,
    /// The connection is lost before the gateway stores the batch.
    DropBeforeStoring,
    /// The gateway stores the batch, then the connection is lost before the ack is written.
    DropAfterStoring,
    /// The gateway answers `Retry` without storing, for this many sends in a row.
    Retry(u32),
    /// This many batches go through untouched, then the next one is `DropAfterStoring`: lets a
    /// single pass confirm some batches and lose the ack of a later one.
    DropAfterStoringAfter(u32),
}

/// The real verification and spool chain, with one fault armed for the next batch.
struct FaultySink {
    inner: GatewaySink<SpoolWriter>,
    next: Mutex<Fault>,
}

impl BatchSink for FaultySink {
    fn accept(&self, collector_id: &str, batch: &Batch) -> Ack {
        let fault = {
            let mut next = self.next.lock().unwrap();
            let fault = *next;
            *next = match fault {
                Fault::Retry(n) if n > 1 => Fault::Retry(n - 1),
                Fault::DropAfterStoringAfter(n) if n > 0 => Fault::DropAfterStoringAfter(n - 1),
                _ => Fault::None,
            };
            match fault {
                Fault::DropAfterStoringAfter(0) => Fault::DropAfterStoring,
                Fault::DropAfterStoringAfter(_) => Fault::None,
                other => other,
            }
        };
        if let Fault::Retry(_) = fault {
            return Ack {
                status: AckStatus::Retry,
                reason: AckReason::Busy,
                next_expected_seq: 1,
            };
        }
        // A panic ends this connection's task, so the shipper sees the stream close with no
        // ack: the same thing a reset connection shows it.
        if fault == Fault::DropBeforeStoring {
            panic!("deliberate fault: the connection is lost before the batch is stored");
        }
        let ack = self.inner.accept(collector_id, batch);
        if fault == Fault::DropAfterStoring {
            panic!("deliberate fault: the connection is lost after the batch was stored");
        }
        ack
    }
}

struct Rig {
    _dir: tempfile::TempDir,
    ca: Vec<u8>,
    gateway_cert: Vec<u8>,
    gateway_key: Vec<u8>,
    collector_cert: Vec<u8>,
    collector_key: Vec<u8>,
    addr: SocketAddr,
    sink: Arc<FaultySink>,
    gateway_state: PathBuf,
    spool: PathBuf,
    shipper_state: PathBuf,
    cursors: PathBuf,
    logs: PathBuf,
}

impl Rig {
    async fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let certs = dir.path().join("certs");
        std::fs::create_dir_all(&certs).unwrap();
        provision_certs::provision(&certs, GATEWAY_DNS, COLLECTOR_ID).unwrap();
        let read = |name: &str| std::fs::read(certs.join(name)).unwrap();
        let logs = dir.path().join("logs");
        std::fs::create_dir_all(&logs).unwrap();
        let mut rig = Rig {
            ca: read("ca.crt"),
            gateway_cert: read("gateway.crt"),
            gateway_key: read("gateway.key"),
            collector_cert: read(&format!("{COLLECTOR_ID}.crt")),
            collector_key: read(&format!("{COLLECTOR_ID}.key")),
            addr: "127.0.0.1:1".parse().unwrap(),
            sink: Arc::new(FaultySink {
                inner: GatewaySink::new(PathBuf::new(), SpoolWriter::new(PathBuf::new())),
                next: Mutex::new(Fault::None),
            }),
            gateway_state: dir.path().join("gateway-state"),
            spool: dir.path().join("spool"),
            shipper_state: dir.path().join("shipper-state"),
            cursors: dir.path().join("cursors"),
            logs,
            _dir: dir,
        };
        rig.start_gateway().await;
        rig
    }

    /// Starts a gateway over the rig's state and spool directories. Called again, it is a
    /// gateway restart: the new one reads its chain position from disk, as `gateway.service`
    /// does.
    async fn start_gateway(&mut self) {
        let sink = Arc::new(FaultySink {
            inner: GatewaySink::new(
                self.gateway_state.clone(),
                SpoolWriter::new(self.spool.clone()),
            ),
            next: Mutex::new(Fault::None),
        });
        let tls = server_config(&self.ca, &self.gateway_cert, &self.gateway_key).unwrap();
        let bounds = ConnectionBounds {
            read_timeout: Duration::from_secs(5),
            idle_timeout: Duration::from_secs(5),
            max_duration: Duration::from_secs(10),
            max_captured_bytes: 1 << 20,
            max_concurrent: 10,
        };
        let as_sink: Arc<dyn BatchSink> = sink.clone();
        let (addr, _handle) = serve("127.0.0.1:0".parse().unwrap(), tls, bounds, as_sink)
            .await
            .unwrap();
        self.addr = addr;
        self.sink = sink;
    }

    fn arm(&self, fault: Fault) {
        *self.sink.next.lock().unwrap() = fault;
    }

    fn log(&self, name: &str) -> PathBuf {
        self.logs.join(format!("{name}.jsonl"))
    }

    fn append(&self, name: &str, lines: &[&str]) {
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(self.log(name))
            .unwrap();
        for line in lines {
            writeln!(file, "{line}").unwrap();
        }
    }

    /// A tailer as a freshly started shipper builds it: from the saved cursor.
    fn tailer(&self, name: &str) -> LogTailer {
        LogTailer::new(self.log(name), self.cursors.clone())
    }

    fn cursor_file(&self, name: &str) -> PathBuf {
        DurableCursor::new(self.log(name), self.cursors.clone()).cursor_file_path()
    }

    fn record_file(&self) -> PathBuf {
        self.shipper_state.join(format!("{COLLECTOR_ID}.pending"))
    }

    async fn cycle(&self, tailer: &mut LogTailer, label: &str) -> std::io::Result<CycleReport> {
        let tls = client_config(&self.ca, &self.collector_cert, &self.collector_key).unwrap();
        let mut stream = ShipperClient::connect(self.addr, tls, GATEWAY_DNS).await?;
        ship_cycle(
            &mut stream,
            tailer,
            label,
            &self.shipper_state,
            COLLECTOR_ID,
            16,
            RetryPolicy::new(Duration::from_millis(10), 3),
        )
        .await
    }

    async fn connect(&self) -> std::io::Result<shipper::client::ShipperStream> {
        let tls = client_config(&self.ca, &self.collector_cert, &self.collector_key).unwrap();
        ShipperClient::connect(self.addr, tls, GATEWAY_DNS).await
    }

    fn confirmed_file(&self) -> PathBuf {
        self.shipper_state.join(format!("{COLLECTOR_ID}.json"))
    }

    fn damaged_file(&self) -> PathBuf {
        self.shipper_state
            .join(format!("{COLLECTOR_ID}.pending.damaged"))
    }

    fn spooled(&self) -> Vec<String> {
        match std::fs::read_to_string(self.spool.join(COLLECTOR_ID).join("events.jsonl")) {
            Ok(text) => text.lines().map(str::to_string).collect(),
            Err(_) => Vec::new(),
        }
    }

    fn reused_seq_batches(&self) -> u64 {
        self.sink.inner.reused_seq_counts().batches
    }
}

fn copy_if_present(from: &Path, to: &Path) -> bool {
    std::fs::copy(from, to).is_ok()
}

#[tokio::test]
async fn a_lost_acknowledgement_followed_by_more_lines_stores_every_line_exactly_once() {
    let rig = Rig::new().await;
    rig.append("ssh", &["ssh-1", "ssh-2"]);
    let mut tailer = rig.tailer("ssh");

    rig.arm(Fault::DropAfterStoring);
    assert!(rig.cycle(&mut tailer, "ssh").await.is_err());
    rig.append("ssh", &["ssh-3"]);

    let report = rig.cycle(&mut tailer, "ssh").await.unwrap();
    assert_eq!(report.stopped, None);
    assert_eq!(rig.spooled(), ["ssh-1", "ssh-2", "ssh-3"]);
    assert_eq!(
        rig.reused_seq_batches(),
        0,
        "the gateway saw a different batch under a used sequence number"
    );

    // The two sides still agree on the chain: the next line is accepted, not rejected.
    rig.append("ssh", &["ssh-4"]);
    let report = rig.cycle(&mut tailer, "ssh").await.unwrap();
    assert_eq!((report.batches_shipped, report.stopped), (1, None));
    assert_eq!(rig.spooled(), ["ssh-1", "ssh-2", "ssh-3", "ssh-4"]);
}

#[tokio::test]
async fn a_lost_acknowledgement_then_a_restart_stores_every_line_exactly_once() {
    let rig = Rig::new().await;
    rig.append("ssh", &["ssh-1", "ssh-2"]);
    let mut tailer = rig.tailer("ssh");
    rig.arm(Fault::DropAfterStoring);
    assert!(rig.cycle(&mut tailer, "ssh").await.is_err());
    drop(tailer);
    rig.append("ssh", &["ssh-3"]);

    let mut restarted = rig.tailer("ssh");
    let report = rig.cycle(&mut restarted, "ssh").await.unwrap();
    assert_eq!(report.stopped, None);
    assert_eq!(rig.spooled(), ["ssh-1", "ssh-2", "ssh-3"]);
    assert_eq!(rig.reused_seq_batches(), 0);
    assert!(!rig.record_file().exists(), "the settled record was kept");
}

#[tokio::test]
async fn after_a_lost_acknowledgement_the_next_log_in_the_pass_sends_nothing_until_it_is_settled() {
    let rig = Rig::new().await;
    rig.append("ssh", &["ssh-1", "ssh-2"]);
    rig.append("telnet", &["telnet-1"]);
    let mut ssh = rig.tailer("ssh");
    let mut telnet = rig.tailer("telnet");

    rig.arm(Fault::DropAfterStoring);
    assert!(rig.cycle(&mut ssh, "ssh").await.is_err());
    let report = rig.cycle(&mut telnet, "telnet").await.unwrap();
    assert_eq!(
        report.batches_shipped, 0,
        "another log was sent under the sequence number of the batch in flight"
    );

    rig.append("ssh", &["ssh-3"]);
    rig.cycle(&mut ssh, "ssh").await.unwrap();
    rig.cycle(&mut telnet, "telnet").await.unwrap();
    assert_eq!(rig.spooled(), ["ssh-1", "ssh-2", "ssh-3", "telnet-1"]);
    assert_eq!(rig.reused_seq_batches(), 0);
}

/// Where a crash lands relative to one batch's life.
#[derive(Debug, Clone, Copy)]
enum Crash {
    BeforeTheRecordIsWritten,
    AfterTheRecordIsWrittenBeforeTheSend,
    AfterTheSend,
    AfterTheAckBeforeTheCursorIsPersisted,
    AfterTheCursorIsPersistedBeforeTheRecordIsDropped,
}

/// Leaves the disks as a crash at `crash` would, appends a line, starts a fresh shipper and
/// checks that each line reached the spool exactly once.
async fn restart_after(crash: Crash) {
    let rig = Rig::new().await;
    rig.append("ssh", &["ssh-1", "ssh-2"]);
    let mut tailer = rig.tailer("ssh");
    let record_copy = rig.shipper_state.with_extension("record-copy");
    let cursor_copy = rig.shipper_state.with_extension("cursor-copy");

    match crash {
        Crash::BeforeTheRecordIsWritten => {
            // The batch was read in memory and nothing about it reached a disk.
            assert_eq!(tailer.read_batch(16).len(), 2);
        }
        Crash::AfterTheRecordIsWrittenBeforeTheSend => {
            // On disk, a batch whose send was lost before the gateway stored it is the same as
            // one that was never sent.
            rig.arm(Fault::DropBeforeStoring);
            assert!(rig.cycle(&mut tailer, "ssh").await.is_err());
        }
        Crash::AfterTheSend => {
            rig.arm(Fault::DropAfterStoring);
            assert!(rig.cycle(&mut tailer, "ssh").await.is_err());
        }
        Crash::AfterTheAckBeforeTheCursorIsPersisted
        | Crash::AfterTheCursorIsPersistedBeforeTheRecordIsDropped => {
            rig.arm(Fault::DropAfterStoring);
            assert!(rig.cycle(&mut tailer, "ssh").await.is_err());
            let had_record = copy_if_present(&rig.record_file(), &record_copy);
            let had_cursor = copy_if_present(&rig.cursor_file("ssh"), &cursor_copy);
            // The settling pass runs to completion; the files it would not have reached yet are
            // then put back as they were.
            rig.cycle(&mut tailer, "ssh").await.unwrap();
            if had_record {
                std::fs::copy(&record_copy, rig.record_file()).unwrap();
            }
            if matches!(crash, Crash::AfterTheAckBeforeTheCursorIsPersisted) {
                if had_cursor {
                    std::fs::copy(&cursor_copy, rig.cursor_file("ssh")).unwrap();
                } else {
                    std::fs::remove_file(rig.cursor_file("ssh")).unwrap();
                }
            }
        }
    }
    drop(tailer);
    rig.append("ssh", &["ssh-3"]);

    let mut restarted = rig.tailer("ssh");
    let report = rig.cycle(&mut restarted, "ssh").await.unwrap();
    assert_eq!(report.stopped, None, "{crash:?}");
    assert_eq!(rig.spooled(), ["ssh-1", "ssh-2", "ssh-3"], "{crash:?}");
    assert!(
        !rig.record_file().exists(),
        "{crash:?}: the record was kept"
    );
}

#[tokio::test]
async fn a_crash_before_the_record_is_written_stores_every_line_exactly_once() {
    restart_after(Crash::BeforeTheRecordIsWritten).await;
}

#[tokio::test]
async fn a_crash_after_the_record_is_written_and_before_the_send_stores_every_line_exactly_once() {
    restart_after(Crash::AfterTheRecordIsWrittenBeforeTheSend).await;
}

#[tokio::test]
async fn a_crash_after_the_send_stores_every_line_exactly_once() {
    restart_after(Crash::AfterTheSend).await;
}

#[tokio::test]
async fn a_crash_after_the_ack_and_before_the_cursor_is_persisted_stores_every_line_exactly_once() {
    restart_after(Crash::AfterTheAckBeforeTheCursorIsPersisted).await;
}

#[tokio::test]
async fn a_crash_after_the_cursor_is_persisted_and_before_the_record_is_dropped_stores_every_line_exactly_once()
 {
    restart_after(Crash::AfterTheCursorIsPersistedBeforeTheRecordIsDropped).await;
}

/// After the cursor was saved past a confirmed batch, lines that repeat that batch word for word
/// are new evidence, not the batch read again, and must ship.
#[tokio::test]
async fn new_lines_identical_to_a_settled_batch_are_not_mistaken_for_it_after_a_crash() {
    let rig = Rig::new().await;
    rig.append("ssh", &["probe", "probe"]);
    let mut tailer = rig.tailer("ssh");
    rig.arm(Fault::DropAfterStoring);
    assert!(rig.cycle(&mut tailer, "ssh").await.is_err());
    let record_copy = rig.shipper_state.with_extension("record-copy");
    std::fs::copy(rig.record_file(), &record_copy).unwrap();
    rig.cycle(&mut tailer, "ssh").await.unwrap();
    // A crash after the cursor was persisted and before the record was dropped.
    std::fs::copy(&record_copy, rig.record_file()).unwrap();
    drop(tailer);
    rig.append("ssh", &["probe", "probe"]);

    let mut restarted = rig.tailer("ssh");
    let report = rig.cycle(&mut restarted, "ssh").await.unwrap();
    assert_eq!(report.stopped, None);
    assert_eq!(rig.spooled(), ["probe", "probe", "probe", "probe"]);
}

/// The log is replaced while its batch is in flight, so its lines cannot be read again: the
/// stored frame still settles the sequence number, and the new file is read from its start.
#[tokio::test]
async fn a_log_replaced_while_its_batch_was_in_flight_loses_no_line() {
    let rig = Rig::new().await;
    rig.append("ssh", &["ssh-1", "ssh-2"]);
    let mut tailer = rig.tailer("ssh");
    rig.arm(Fault::DropAfterStoring);
    assert!(rig.cycle(&mut tailer, "ssh").await.is_err());
    drop(tailer);
    std::fs::remove_file(rig.log("ssh")).unwrap();
    rig.append("ssh", &["ssh-new-1"]);

    let mut restarted = rig.tailer("ssh");
    let report = rig.cycle(&mut restarted, "ssh").await.unwrap();
    assert_eq!(report.stopped, None);
    assert_eq!(rig.spooled(), ["ssh-1", "ssh-2", "ssh-new-1"]);
    assert_eq!(rig.reused_seq_batches(), 0);
}

#[tokio::test]
async fn a_damaged_record_of_a_batch_the_gateway_stored_stops_without_moving_past_any_line() {
    let rig = Rig::new().await;
    rig.append("ssh", &["ssh-1", "ssh-2"]);
    let mut tailer = rig.tailer("ssh");
    rig.arm(Fault::DropAfterStoring);
    assert!(rig.cycle(&mut tailer, "ssh").await.is_err());
    drop(tailer);
    std::fs::create_dir_all(&rig.shipper_state).unwrap();
    std::fs::write(rig.record_file(), b"not a record").unwrap();
    rig.append("ssh", &["ssh-3"]);

    let mut restarted = rig.tailer("ssh");
    let report = rig.cycle(&mut restarted, "ssh").await.unwrap();
    assert!(report.stopped.is_some(), "{report:?}");
    assert_eq!(report.batches_shipped, 0);
    assert_eq!(rig.spooled(), ["ssh-1", "ssh-2"]);
    drop(restarted);
    assert_eq!(
        rig.tailer("ssh").read_batch(16),
        ["ssh-1", "ssh-2", "ssh-3"],
        "the cursor moved past a line the gateway never stored"
    );
}

#[tokio::test]
async fn a_damaged_record_of_a_batch_the_gateway_never_stored_ships_every_line_exactly_once() {
    let rig = Rig::new().await;
    rig.append("ssh", &["ssh-1", "ssh-2"]);
    let mut tailer = rig.tailer("ssh");
    rig.arm(Fault::DropBeforeStoring);
    assert!(rig.cycle(&mut tailer, "ssh").await.is_err());
    drop(tailer);
    std::fs::create_dir_all(&rig.shipper_state).unwrap();
    std::fs::write(rig.record_file(), b"not a record").unwrap();
    rig.append("ssh", &["ssh-3"]);

    let mut restarted = rig.tailer("ssh");
    let report = rig.cycle(&mut restarted, "ssh").await.unwrap();
    assert_eq!(report.stopped, None);
    assert_eq!(rig.spooled(), ["ssh-1", "ssh-2", "ssh-3"]);
    assert!(!rig.record_file().exists());
    // The accepted batch proves the gateway never stored the damaged record's batch, so the
    // set-aside copy goes too; kept, it would turn the next ordinary lost ack into a stop.
    assert!(
        !rig.damaged_file().exists(),
        "the set-aside record outlived an accepted batch"
    );

    rig.append("ssh", &["ssh-4"]);
    rig.arm(Fault::DropAfterStoring);
    assert!(rig.cycle(&mut restarted, "ssh").await.is_err());
    let report = rig.cycle(&mut restarted, "ssh").await.unwrap();
    assert_eq!((report.batches_shipped, report.stopped), (1, None));
    assert_eq!(rig.spooled(), ["ssh-1", "ssh-2", "ssh-3", "ssh-4"]);
}

/// The set-aside copy of an unreadable record is read from disk on every pass, so a restart
/// between setting it aside and the next send does not forget it.
#[tokio::test]
async fn a_damaged_record_set_aside_before_a_restart_still_stops_a_duplicate_after_it() {
    let rig = Rig::new().await;
    rig.append("ssh", &["ssh-1", "ssh-2"]);
    let mut tailer = rig.tailer("ssh");
    rig.arm(Fault::DropAfterStoring);
    assert!(rig.cycle(&mut tailer, "ssh").await.is_err());
    drop(tailer);
    std::fs::write(rig.record_file(), b"not a record").unwrap();

    // Another log's turn comes first and has nothing to send: the record is set aside there.
    let mut telnet = rig.tailer("telnet");
    let report = rig.cycle(&mut telnet, "telnet").await.unwrap();
    assert_eq!((report.batches_shipped, report.stopped), (0, None));
    assert!(rig.damaged_file().exists());
    drop(telnet);

    rig.append("ssh", &["ssh-3"]);
    let mut restarted = rig.tailer("ssh");
    let report = rig.cycle(&mut restarted, "ssh").await.unwrap();
    assert_eq!(
        report.stopped,
        Some(StopReason::UnprovenDuplicate { seq: 1 })
    );
    assert_eq!(rig.spooled(), ["ssh-1", "ssh-2"]);
    drop(restarted);
    assert_eq!(
        rig.tailer("ssh").read_batch(16),
        ["ssh-1", "ssh-2", "ssh-3"],
        "the cursor moved past a line the gateway never stored"
    );
}

/// The unreadable record cannot be moved aside (something already occupies the name): nothing
/// may be sent on any pass, since what the record named cannot be told apart from what the
/// gateway holds, and every line stays in the log.
#[tokio::test]
async fn an_unreadable_record_that_cannot_be_set_aside_sends_nothing_on_every_pass() {
    let rig = Rig::new().await;
    rig.append("ssh", &["ssh-1", "ssh-2"]);
    std::fs::create_dir_all(rig.damaged_file()).unwrap();
    std::fs::write(rig.record_file(), b"not a record").unwrap();
    let mut tailer = rig.tailer("ssh");

    for pass in 0..2 {
        assert!(rig.cycle(&mut tailer, "ssh").await.is_err(), "pass {pass}");
        assert!(rig.spooled().is_empty(), "pass {pass}: a batch went out");
        assert!(rig.record_file().exists(), "pass {pass}");
    }
    drop(tailer);
    assert_eq!(rig.tailer("ssh").read_batch(16), ["ssh-1", "ssh-2"]);
}

#[tokio::test]
async fn a_record_that_cannot_be_written_sends_nothing_and_keeps_every_line_in_the_log() {
    let rig = Rig::new().await;
    rig.append("ssh", &["ssh-1", "ssh-2"]);
    // Running as root, permissions cannot make the write fail; a directory where the record's
    // temporary file goes does, the way a full or read-only disk would.
    let obstruction = rig
        .shipper_state
        .join(format!("{COLLECTOR_ID}.pending.tmp"));
    std::fs::create_dir_all(&obstruction).unwrap();
    let mut tailer = rig.tailer("ssh");

    assert!(rig.cycle(&mut tailer, "ssh").await.is_err());
    assert!(rig.spooled().is_empty(), "a batch went out with no record");
    assert_eq!(rig.tailer("ssh").read_batch(16), ["ssh-1", "ssh-2"]);

    // The ship loop keeps this tailer for the next pass, so the failed batch's read must have
    // been given back to it, not only left out of the saved cursor.
    std::fs::remove_dir(&obstruction).unwrap();
    let report = rig.cycle(&mut tailer, "ssh").await.unwrap();
    assert_eq!((report.batches_shipped, report.stopped), (1, None));
    assert_eq!(rig.spooled(), ["ssh-1", "ssh-2"]);
}

/// The reset in docs/operations/split-deployment.md ("Rebuilding a collector"): both units
/// stopped, both sides' chain files deleted, the record of the batch in flight with them.
#[tokio::test]
async fn the_documented_chain_reset_clears_a_batch_in_flight_and_loses_no_line() {
    let mut rig = Rig::new().await;
    rig.append("ssh", &["ssh-1"]);
    let mut tailer = rig.tailer("ssh");
    rig.cycle(&mut tailer, "ssh").await.unwrap();
    rig.append("ssh", &["ssh-2", "ssh-3"]);
    rig.arm(Fault::DropAfterStoring);
    assert!(rig.cycle(&mut tailer, "ssh").await.is_err());
    drop(tailer);

    std::fs::remove_file(rig.gateway_state.join(format!("{COLLECTOR_ID}.json"))).unwrap();
    std::fs::remove_file(rig.shipper_state.join(format!("{COLLECTOR_ID}.json"))).unwrap();
    let _ = std::fs::remove_file(rig.record_file());
    rig.start_gateway().await;
    rig.append("ssh", &["ssh-4"]);

    let mut tailer = rig.tailer("ssh");
    let report = rig.cycle(&mut tailer, "ssh").await.unwrap();
    assert_eq!(report.stopped, None);
    let spooled = rig.spooled();
    for line in ["ssh-1", "ssh-2", "ssh-3", "ssh-4"] {
        assert!(
            spooled.iter().any(|l| l == line),
            "{line} missing: {spooled:?}"
        );
    }
}

/// The same reset done without deleting the record: what it describes belongs to the chain that
/// was reset, so it is dropped as stale rather than resent into the new one.
#[tokio::test]
async fn a_chain_reset_that_leaves_the_record_behind_is_not_blocked_by_it() {
    let mut rig = Rig::new().await;
    rig.append("ssh", &["ssh-1"]);
    let mut tailer = rig.tailer("ssh");
    rig.cycle(&mut tailer, "ssh").await.unwrap();
    rig.append("ssh", &["ssh-2", "ssh-3"]);
    rig.arm(Fault::DropAfterStoring);
    assert!(rig.cycle(&mut tailer, "ssh").await.is_err());
    drop(tailer);

    std::fs::remove_file(rig.gateway_state.join(format!("{COLLECTOR_ID}.json"))).unwrap();
    std::fs::remove_file(rig.shipper_state.join(format!("{COLLECTOR_ID}.json"))).unwrap();
    rig.start_gateway().await;
    rig.append("ssh", &["ssh-4"]);

    let mut tailer = rig.tailer("ssh");
    let report = rig.cycle(&mut tailer, "ssh").await.unwrap();
    assert_eq!(report.stopped, None);
    let spooled = rig.spooled();
    for line in ["ssh-1", "ssh-2", "ssh-3", "ssh-4"] {
        assert!(
            spooled.iter().any(|l| l == line),
            "{line} missing: {spooled:?}"
        );
    }
    assert!(!rig.record_file().exists());
}

/// Batch 1 confirmed, then batch 2 stored by the gateway with its ack lost and the log grown.
/// Leaves the rig with a record for seq 2 on disk and `tailer` rewound over it.
async fn lose_the_ack_of_the_second_batch(rig: &Rig, tailer: &mut LogTailer) {
    rig.append("ssh", &["ssh-1"]);
    let report = rig.cycle(tailer, "ssh").await.unwrap();
    assert_eq!((report.batches_shipped, report.stopped), (1, None));
    rig.append("ssh", &["ssh-2", "ssh-3"]);
    rig.arm(Fault::DropAfterStoring);
    assert!(rig.cycle(tailer, "ssh").await.is_err());
    assert!(rig.record_file().exists());
    rig.append("ssh", &["ssh-4"]);
}

/// A confirmed state that cannot be read for one pass says nothing about where the chain is, so
/// the record of the batch in flight must not be judged against a fresh chain and thrown away.
#[tokio::test]
async fn an_unreadable_confirmed_state_while_a_batch_is_in_flight_keeps_the_record_and_loses_no_line()
 {
    let rig = Rig::new().await;
    let mut tailer = rig.tailer("ssh");
    lose_the_ack_of_the_second_batch(&rig, &mut tailer).await;
    let record = std::fs::read(rig.record_file()).unwrap();

    // A directory where the state file is makes the read fail, even for root.
    let aside = rig.shipper_state.with_extension("confirmed-aside");
    std::fs::rename(rig.confirmed_file(), &aside).unwrap();
    std::fs::create_dir(rig.confirmed_file()).unwrap();
    assert!(rig.cycle(&mut tailer, "ssh").await.is_err());
    assert_eq!(
        std::fs::read(rig.record_file()).ok(),
        Some(record),
        "the record of the batch in flight was dropped or replaced"
    );
    assert_eq!(rig.spooled(), ["ssh-1", "ssh-2", "ssh-3"]);

    std::fs::remove_dir(rig.confirmed_file()).unwrap();
    std::fs::rename(&aside, rig.confirmed_file()).unwrap();
    let report = rig.cycle(&mut tailer, "ssh").await.unwrap();
    assert_eq!(report.stopped, None);
    assert_eq!(rig.spooled(), ["ssh-1", "ssh-2", "ssh-3", "ssh-4"]);
    assert_eq!(rig.reused_seq_batches(), 0);
    assert!(!rig.record_file().exists());
}

/// The confirmed state cannot be stored after the gateway confirmed the batch: the record stays,
/// it is the only thing that says the seq is taken, so every other log waits, and once the disk
/// is fixed the same tailer carries on without losing or repeating a line.
#[tokio::test]
async fn a_confirmed_state_that_cannot_be_stored_while_settling_keeps_the_record_and_holds_every_log()
 {
    let rig = Rig::new().await;
    let mut tailer = rig.tailer("ssh");
    lose_the_ack_of_the_second_batch(&rig, &mut tailer).await;
    rig.append("telnet", &["telnet-1"]);
    let obstruction = rig.shipper_state.join(format!("{COLLECTOR_ID}.tmp"));
    std::fs::create_dir(&obstruction).unwrap();

    assert!(rig.cycle(&mut tailer, "ssh").await.is_err());
    assert!(rig.record_file().exists());
    let mut telnet = rig.tailer("telnet");
    let report = rig.cycle(&mut telnet, "telnet").await.unwrap();
    assert_eq!(
        report.batches_shipped, 0,
        "another log shipped past the record"
    );
    assert_eq!(rig.spooled(), ["ssh-1", "ssh-2", "ssh-3"]);

    std::fs::remove_dir(&obstruction).unwrap();
    let report = rig.cycle(&mut tailer, "ssh").await.unwrap();
    assert_eq!(report.stopped, None);
    rig.cycle(&mut telnet, "telnet").await.unwrap();
    assert_eq!(
        rig.spooled(),
        ["ssh-1", "ssh-2", "ssh-3", "ssh-4", "telnet-1"]
    );
    assert_eq!(rig.reused_seq_batches(), 0);
}

/// The cursor cannot be saved after the gateway confirmed the batch: the record stays until the
/// cursor is past the batch's lines, every other log waits, and the same tailer then carries on
/// without losing or repeating a line.
#[tokio::test]
async fn a_cursor_that_cannot_be_saved_while_settling_keeps_the_record_and_holds_every_log() {
    let rig = Rig::new().await;
    let mut tailer = rig.tailer("ssh");
    lose_the_ack_of_the_second_batch(&rig, &mut tailer).await;
    rig.append("telnet", &["telnet-1"]);
    let obstruction = rig.cursor_file("ssh").with_extension("json.tmp");
    std::fs::create_dir(&obstruction).unwrap();

    assert!(rig.cycle(&mut tailer, "ssh").await.is_err());
    assert!(rig.record_file().exists());
    let mut telnet = rig.tailer("telnet");
    let report = rig.cycle(&mut telnet, "telnet").await.unwrap();
    assert_eq!(
        report.batches_shipped, 0,
        "another log shipped past the record"
    );
    assert!(
        rig.cycle(&mut tailer, "ssh").await.is_err(),
        "the obstruction is still there"
    );

    std::fs::remove_dir(&obstruction).unwrap();
    let report = rig.cycle(&mut tailer, "ssh").await.unwrap();
    assert_eq!(report.stopped, None);
    rig.cycle(&mut telnet, "telnet").await.unwrap();
    assert_eq!(
        rig.spooled(),
        ["ssh-1", "ssh-2", "ssh-3", "ssh-4", "telnet-1"]
    );
    assert_eq!(rig.reused_seq_batches(), 0);
    assert!(!rig.record_file().exists());
}

/// Retry exhaustion stops the pass with the gateway possibly holding nothing, but the record
/// stays and the next pass sends that same batch before anything newer.
#[tokio::test]
async fn retry_exhaustion_keeps_the_record_and_the_next_pass_sends_that_same_batch() {
    let rig = Rig::new().await;
    rig.append("ssh", &["ssh-1", "ssh-2"]);
    let mut tailer = rig.tailer("ssh");
    rig.arm(Fault::Retry(10));
    let report = rig.cycle(&mut tailer, "ssh").await.unwrap();
    assert_eq!(report.stopped, Some(StopReason::RetriesExhausted));
    let record = std::fs::read(rig.record_file()).expect("the record was dropped");
    rig.arm(Fault::None);
    rig.append("ssh", &["ssh-3"]);

    // A record left as it was holds the first two lines in their own batch, so the pass ships
    // two batches; a batch rebuilt from the tailer would carry all three lines in one.
    let report = rig.cycle(&mut tailer, "ssh").await.unwrap();
    assert_eq!((report.batches_shipped, report.stopped), (2, None));
    assert_eq!(rig.spooled(), ["ssh-1", "ssh-2", "ssh-3"]);
    assert!(!record.is_empty());
    assert_eq!(rig.reused_seq_batches(), 0);
}

/// A gateway ahead of the shipper's chain stops the pass; the record is kept byte for byte and a
/// later pass sends exactly it again, never a batch rebuilt from the grown log.
#[tokio::test]
async fn a_diverged_chain_keeps_the_record_and_a_later_pass_resends_exactly_it() {
    let rig = Rig::new().await;
    let mut tailer = rig.tailer("ssh");
    rig.append("ssh", &["ssh-1"]);
    rig.cycle(&mut tailer, "ssh").await.unwrap();
    rig.append("ssh", &["ssh-2"]);
    rig.cycle(&mut tailer, "ssh").await.unwrap();
    // The shipper's chain is lost while the gateway keeps its own at seq 2.
    std::fs::remove_file(rig.confirmed_file()).unwrap();
    rig.append("ssh", &["ssh-3"]);

    let report = rig.cycle(&mut tailer, "ssh").await.unwrap();
    assert_eq!(
        report.stopped,
        Some(StopReason::ChainDiverged {
            our_seq: 1,
            gateway_next_expected: 3
        })
    );
    let record = std::fs::read(rig.record_file()).expect("the record was dropped");
    rig.append("ssh", &["ssh-4"]);

    drop(tailer);
    let mut restarted = rig.tailer("ssh");
    let report = rig.cycle(&mut restarted, "ssh").await.unwrap();
    assert!(matches!(
        report.stopped,
        Some(StopReason::ChainDiverged { our_seq: 1, .. })
    ));
    assert_eq!(std::fs::read(rig.record_file()).ok(), Some(record));
    assert_eq!(rig.spooled(), ["ssh-1", "ssh-2"]);
    assert_eq!(rig.reused_seq_batches(), 0);
    drop(restarted);
    assert_eq!(rig.tailer("ssh").read_batch(16), ["ssh-3", "ssh-4"]);
}

/// The batch's read held a line the origin policy refuses. Settling it after a restart must read
/// again every line the batch consumed, the refused one included, and no more.
#[tokio::test]
async fn settling_a_batch_with_a_refused_line_moves_the_cursor_exactly_past_that_batch() {
    let rig = Rig::new().await;
    let line = |sensor: &str, signal_type: &str, authenticated: bool, n: u32| {
        serde_json::json!({
            "v": 1,
            "source_ip": "203.0.113.80",
            "wan_ip": null,
            "sensor": sensor,
            "signal_type": signal_type,
            "protocol": "tcp",
            "authenticated": authenticated,
            "observed_at": "2026-11-13T10:00:00Z",
            "metadata": { "protocol_label": sensor, "n": n },
            "sample": null,
        })
        .to_string()
    };
    let forged = line("ssh", "honeypot_malware_upload", true, 0);
    let honest = line("catchall", "catchall_probe", false, 1);
    let later = line("catchall", "catchall_probe", false, 2);
    rig.append("catchall", &[&forged, &honest]);
    let mut tailer = rig.tailer("catchall");
    rig.arm(Fault::DropAfterStoring);
    assert!(rig.cycle(&mut tailer, "catchall").await.is_err());
    drop(tailer);
    rig.append("catchall", &[&later]);

    let mut restarted = rig.tailer("catchall");
    let report = rig.cycle(&mut restarted, "catchall").await.unwrap();
    assert_eq!(report.stopped, None);
    assert_eq!(rig.spooled(), [honest, later]);
    drop(restarted);
    assert!(rig.tailer("catchall").read_batch(16).is_empty());
}

/// A record whose log is no longer configured is settled on its own: the stored frame goes out,
/// the record goes, no cursor moves, and the chain is free for the logs that are configured.
#[tokio::test]
async fn a_record_from_a_log_no_longer_configured_is_settled_without_moving_any_cursor() {
    let rig = Rig::new().await;
    rig.append("ssh", &["ssh-1", "ssh-2"]);
    let mut tailer = rig.tailer("ssh");
    rig.arm(Fault::DropAfterStoring);
    assert!(rig.cycle(&mut tailer, "ssh").await.is_err());
    drop(tailer);
    let cursor = std::fs::read(rig.cursor_file("ssh")).ok();

    let mut stream = rig.connect().await.unwrap();
    let report = settle_orphaned(
        &mut stream,
        &rig.shipper_state,
        COLLECTOR_ID,
        RetryPolicy::new(Duration::from_millis(10), 3),
    )
    .await
    .unwrap();
    assert_eq!((report.batches_shipped, report.stopped), (1, None));
    assert!(!rig.record_file().exists());
    assert_eq!(std::fs::read(rig.cursor_file("ssh")).ok(), cursor);

    rig.append("telnet", &["telnet-1"]);
    let mut telnet = rig.tailer("telnet");
    let report = rig.cycle(&mut telnet, "telnet").await.unwrap();
    assert_eq!((report.batches_shipped, report.stopped), (1, None));
    assert_eq!(rig.spooled(), ["ssh-1", "ssh-2", "telnet-1"]);
    assert_eq!(rig.reused_seq_batches(), 0);
}

/// A record left by another collector id is reported, never read or sent, and left where it is.
#[tokio::test]
async fn a_record_of_another_collector_id_is_reported_and_left_alone() {
    let rig = Rig::new().await;
    std::fs::create_dir_all(&rig.shipper_state).unwrap();
    let foreign = rig.shipper_state.join("old-collector.pending");
    std::fs::write(&foreign, b"whatever an older chain left").unwrap();

    rig.append("ssh", &["ssh-1"]);
    let mut tailer = rig.tailer("ssh");
    // With this collector's own record in flight beside it, only the other one is reported.
    rig.arm(Fault::DropAfterStoring);
    assert!(rig.cycle(&mut tailer, "ssh").await.is_err());
    assert!(rig.record_file().exists());
    assert_eq!(
        PendingBatch::foreign_records(&rig.shipper_state, COLLECTOR_ID),
        std::slice::from_ref(&foreign)
    );

    let report = rig.cycle(&mut tailer, "ssh").await.unwrap();
    assert_eq!((report.batches_shipped, report.stopped), (1, None));
    assert_eq!(rig.spooled(), ["ssh-1"]);
    assert_eq!(rig.reused_seq_batches(), 0);
    assert_eq!(
        std::fs::read(&foreign).unwrap(),
        b"whatever an older chain left"
    );
    assert_eq!(
        PendingBatch::foreign_records(&rig.shipper_state, COLLECTOR_ID),
        [foreign]
    );
}

fn gateway_state_file(rig: &Rig) -> PathBuf {
    rig.gateway_state.join(format!("{COLLECTOR_ID}.json"))
}

/// A gateway that cannot read its state for this collector answers from a fresh chain and
/// rejects a frame it already holds in its spool. That answer is not final, so the record is
/// kept and no cursor moves; once the gateway's state is back, the same stored frame is
/// confirmed and every line is stored exactly once.
#[tokio::test]
async fn a_rejection_keeps_the_record_and_once_the_gateway_state_is_back_the_same_frame_is_confirmed()
 {
    let mut rig = Rig::new().await;
    let mut tailer = rig.tailer("ssh");
    lose_the_ack_of_the_second_batch(&rig, &mut tailer).await;
    drop(tailer);
    let record = std::fs::read(rig.record_file()).unwrap();
    let cursor = std::fs::read(rig.cursor_file("ssh")).unwrap();

    // A directory where the gateway's state file is makes its read fail, even for root.
    let aside = rig.gateway_state.with_extension("state-aside");
    std::fs::rename(gateway_state_file(&rig), &aside).unwrap();
    std::fs::create_dir(gateway_state_file(&rig)).unwrap();
    rig.start_gateway().await;

    for pass in 0..2 {
        // Each pass is a restart, as `Restart=always` gives after the permanent stop.
        let mut restarted = rig.tailer("ssh");
        let report = rig.cycle(&mut restarted, "ssh").await.unwrap();
        assert_eq!(
            report.stopped,
            Some(StopReason::Rejected {
                reason: AckReason::SeqGap
            }),
            "pass {pass}"
        );
        assert!(
            std::fs::read(rig.record_file()).ok().as_ref() == Some(&record),
            "pass {pass}: the record of a batch the gateway holds was dropped or replaced"
        );
        assert_eq!(
            std::fs::read(rig.cursor_file("ssh")).unwrap(),
            cursor,
            "pass {pass}: a read position moved on a rejection"
        );
        assert_eq!(rig.spooled(), ["ssh-1", "ssh-2", "ssh-3"], "pass {pass}");
    }

    std::fs::remove_dir(gateway_state_file(&rig)).unwrap();
    std::fs::rename(&aside, gateway_state_file(&rig)).unwrap();
    rig.start_gateway().await;
    let mut restarted = rig.tailer("ssh");
    let report = rig.cycle(&mut restarted, "ssh").await.unwrap();
    assert_eq!(report.stopped, None);
    assert_eq!(rig.spooled(), ["ssh-1", "ssh-2", "ssh-3", "ssh-4"]);
    assert_eq!(rig.reused_seq_batches(), 0);
    assert!(!rig.record_file().exists());
}

/// The reset on both sides in "Rebuilding a collector" clears a record kept after a rejection,
/// whether it is deleted with the chain files as the procedure says or left behind, and the new
/// chain carries every line.
#[tokio::test]
async fn the_documented_chain_reset_clears_a_record_kept_after_a_rejection_and_loses_no_line() {
    for delete_the_record in [true, false] {
        let mut rig = Rig::new().await;
        let mut tailer = rig.tailer("ssh");
        lose_the_ack_of_the_second_batch(&rig, &mut tailer).await;
        // The gateway's state is lost, so the resent batch is rejected.
        std::fs::remove_file(gateway_state_file(&rig)).unwrap();
        rig.start_gateway().await;
        let report = rig.cycle(&mut tailer, "ssh").await.unwrap();
        assert!(
            matches!(report.stopped, Some(StopReason::Rejected { .. })),
            "{report:?}"
        );
        assert!(rig.record_file().exists());
        drop(tailer);

        // The reset: both units stopped, both sides' chain files deleted, then both started.
        let _ = std::fs::remove_file(gateway_state_file(&rig));
        std::fs::remove_file(rig.confirmed_file()).unwrap();
        if delete_the_record {
            std::fs::remove_file(rig.record_file()).unwrap();
        }
        rig.start_gateway().await;
        rig.append("ssh", &["ssh-5"]);

        let mut tailer = rig.tailer("ssh");
        let report = rig.cycle(&mut tailer, "ssh").await.unwrap();
        assert_eq!(report.stopped, None, "record deleted: {delete_the_record}");
        let spooled = rig.spooled();
        for line in ["ssh-1", "ssh-2", "ssh-3", "ssh-4", "ssh-5"] {
            assert!(
                spooled.iter().any(|l| l == line),
                "record deleted: {delete_the_record}: {line} missing: {spooled:?}"
            );
        }
        assert!(!rig.record_file().exists());
    }
}

/// A record whose log left the configuration meets a confirmed state that exists and cannot be
/// read: the pass fails with the record untouched and nothing sent, and once the state can be
/// read again the stored frame settles the seq.
#[tokio::test]
async fn an_unreadable_confirmed_state_while_an_orphaned_record_exists_keeps_the_record_and_sends_nothing()
 {
    let rig = Rig::new().await;
    let mut tailer = rig.tailer("ssh");
    lose_the_ack_of_the_second_batch(&rig, &mut tailer).await;
    drop(tailer);
    let record = std::fs::read(rig.record_file()).unwrap();
    let retry = RetryPolicy::new(Duration::from_millis(10), 3);

    let aside = rig.shipper_state.with_extension("confirmed-aside");
    std::fs::rename(rig.confirmed_file(), &aside).unwrap();
    std::fs::create_dir(rig.confirmed_file()).unwrap();
    let mut stream = rig.connect().await.unwrap();
    assert!(
        settle_orphaned(&mut stream, &rig.shipper_state, COLLECTOR_ID, retry)
            .await
            .is_err()
    );
    assert_eq!(
        std::fs::read(rig.record_file()).ok(),
        Some(record),
        "the record of the batch in flight was dropped or replaced"
    );
    assert_eq!(rig.spooled(), ["ssh-1", "ssh-2", "ssh-3"]);

    std::fs::remove_dir(rig.confirmed_file()).unwrap();
    std::fs::rename(&aside, rig.confirmed_file()).unwrap();
    let mut stream = rig.connect().await.unwrap();
    let report = settle_orphaned(&mut stream, &rig.shipper_state, COLLECTOR_ID, retry)
        .await
        .unwrap();
    assert_eq!((report.batches_shipped, report.stopped), (1, None));
    assert_eq!(rig.reused_seq_batches(), 0);
    assert!(!rig.record_file().exists());
    assert_eq!(rig.spooled(), ["ssh-1", "ssh-2", "ssh-3"]);
}

/// A rename rotation whose old file takes more than one batch to drain: every drained batch
/// after the first is read while the saved cursor already names the new file at its start, so
/// after a crash a record of one of them looks like a batch read from there. Lines the new file
/// then holds that repeat the batch word for word are new evidence and must ship.
#[tokio::test]
async fn a_rename_rotation_drained_over_several_batches_loses_no_line_after_a_crash_before_the_record_is_dropped()
 {
    let rig = Rig::new().await;
    // One batch's worth: the rig asks for 16 records, and a batch carries at most the frame-safe
    // ceiling.
    let same = vec!["probe"; shipper::batcher::MAX_RECORDS_FRAME_SAFE];
    rig.append("ssh", &same);
    let mut tailer = rig.tailer("ssh");
    let report = rig.cycle(&mut tailer, "ssh").await.unwrap();
    assert_eq!((report.batches_shipped, report.stopped), (1, None));

    // Two more batches' worth reach the old file, which is then renamed away; the new file
    // starts empty.
    rig.append("ssh", &[&same[..], &same[..]].concat());
    std::fs::rename(rig.log("ssh"), rig.logs.join("ssh.jsonl.1")).unwrap();
    std::fs::File::create(rig.log("ssh")).unwrap();

    // The first drained batch is confirmed; the second is stored and its ack lost.
    rig.arm(Fault::DropAfterStoringAfter(1));
    assert!(rig.cycle(&mut tailer, "ssh").await.is_err());
    let record_copy = rig.shipper_state.with_extension("record-copy");
    std::fs::copy(rig.record_file(), &record_copy).unwrap();
    let report = rig.cycle(&mut tailer, "ssh").await.unwrap();
    assert_eq!((report.batches_shipped, report.stopped), (1, None));
    assert_eq!(rig.spooled().len(), 3 * same.len());
    // A crash after the cursor was persisted and before the record was dropped.
    std::fs::copy(&record_copy, rig.record_file()).unwrap();
    drop(tailer);
    rig.append("ssh", &same);

    let mut restarted = rig.tailer("ssh");
    let report = rig.cycle(&mut restarted, "ssh").await.unwrap();
    assert_eq!(report.stopped, None);
    assert_eq!(
        rig.spooled().len(),
        4 * same.len(),
        "lines of the new file were taken for the drained batch and skipped"
    );
    assert_eq!(rig.reused_seq_batches(), 0);
    assert!(!rig.record_file().exists());
}
