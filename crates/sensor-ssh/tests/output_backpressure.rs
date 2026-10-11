//! A peer that does not read cannot make the sensor hold more than a bounded amount of unsent
//! output for it. The queue is charged to the output budget and capped per channel and per
//! connection; input that would make more output waits behind it, in order, and runs when the peer
//! reads. These tests drive the real server with a real client that stops reading.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use sensor_framework::{
    CaptureMemoryBudget, CommandEventConfig, CommandEventGate, ConnectionBounds, WanResolver,
};
use sensor_ssh::output::{OUTPUT_STALL_LIMIT, OutputLedger};
use sensor_ssh::server::{
    CHANNEL_QUEUED_MAX_BYTES, LINE_OUTPUT_MAX_BYTES, OUTPUT_BUDGET_BYTES, OUTPUT_UNIT_BYTES,
};

struct TestHandler;

impl russh::client::Handler for TestHandler {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        _key: &russh::keys::PublicKey,
    ) -> Result<bool, Self::Error> {
        Ok(true)
    }
}

/// One line of `cat /dev/zero` prints exactly this many bytes (the shell's read cap).
const ZERO_LINE_BYTES: usize = 1_048_576;

/// What the output budget may hold for one channel whose peer never reads: the queue up to its
/// bound, one unit that was already running when the bound was reached, and the peer's own
/// window's worth of input waiting behind it.
const ONE_CHANNEL_BOUND: u64 =
    CHANNEL_QUEUED_MAX_BYTES + OUTPUT_UNIT_BYTES + sensor_ssh::channel::INITIAL_WINDOW_SIZE as u64;

struct Rig {
    addr: std::net::SocketAddr,
    handle: tokio::task::JoinHandle<()>,
    output: Arc<CaptureMemoryBudget>,
    log: std::path::PathBuf,
    _dir: tempfile::TempDir,
}

async fn rig(max_duration: Duration) -> Rig {
    rig_with(max_duration, OUTPUT_BUDGET_BYTES, OUTPUT_STALL_LIMIT).await
}

async fn rig_with(max_duration: Duration, output_bytes: u64, stall_limit: Duration) -> Rig {
    let dir = tempfile::tempdir().unwrap();
    let bounds = ConnectionBounds {
        read_timeout: Duration::from_secs(30),
        idle_timeout: Duration::from_secs(60),
        max_duration,
        max_captured_bytes: 1_000_000,
        max_concurrent: 64,
    };
    let ledger = OutputLedger::new(output_bytes, stall_limit);
    let output = ledger.budget().clone();
    let log = dir.path().join("events.jsonl");
    let (addr, handle, _handoff) = sensor_ssh::serve_with_budgets(
        "127.0.0.1:0".parse().unwrap(),
        log.clone(),
        dir.path().join("spool"),
        dir.path().join("host_key"),
        Arc::new(WanResolver::new(HashMap::new())),
        bounds,
        "OpenSSH_9.6p1".to_string(),
        "test".to_string(),
        dir.path().join("outbox"),
        Arc::new(CaptureMemoryBudget::new(214_748_364)),
        ledger,
        Arc::new(CommandEventGate::new(CommandEventConfig::default())),
    )
    .await
    .unwrap();
    Rig {
        addr,
        handle,
        output,
        log,
        _dir: dir,
    }
}

/// A client that opens channels with a window of `window` bytes, and so lets the server send
/// only that much until it reads.
async fn login(addr: std::net::SocketAddr, window: u32) -> russh::client::Handle<TestHandler> {
    let config = Arc::new(russh::client::Config {
        window_size: window,
        ..Default::default()
    });
    let mut session = russh::client::connect(config, addr, TestHandler)
        .await
        .unwrap();
    assert!(
        session
            .authenticate_password("root", "password")
            .await
            .unwrap()
            .success()
    );
    session
}

async fn open_shell(
    session: &russh::client::Handle<TestHandler>,
) -> russh::Channel<russh::client::Msg> {
    let channel = session.channel_open_session().await.unwrap();
    channel
        .request_pty(false, "xterm", 80, 24, 0, 0, &[])
        .await
        .unwrap();
    channel.request_shell(false).await.unwrap();
    channel
}

async fn settle(output: &CaptureMemoryBudget) {
    // The server works on its own task; wait until the budget stops moving.
    let mut last = u64::MAX;
    for _ in 0..40 {
        tokio::time::sleep(Duration::from_millis(100)).await;
        let now = output.current_bytes();
        if now == last {
            return;
        }
        last = now;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_peer_that_never_reads_leaves_a_bounded_queue_and_loses_no_output_once_it_does() {
    never_reads_then_reads(false).await;
}

/// The same lines in one packet: the rest of the packet must wait, whole, behind the output
/// already queued, rather than every line in it running at once.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn lines_packed_into_one_packet_wait_behind_the_queue_too() {
    never_reads_then_reads(true).await;
}

async fn never_reads_then_reads(packed: bool) {
    const LINES: usize = 26;
    let rig = rig(Duration::from_secs(120)).await;
    let session = login(rig.addr, 16_384).await;
    let mut channel = open_shell(&session).await;

    // Lines that each print a megabyte, sent to a peer that reads nothing.
    if packed {
        channel
            .data(&b"cat /dev/zero\r".repeat(LINES)[..])
            .await
            .unwrap();
    } else {
        for _ in 0..LINES {
            channel.data(&b"cat /dev/zero\r"[..]).await.unwrap();
        }
    }
    settle(&rig.output).await;

    let held = rig.output.current_bytes();
    let peak = rig.output.high_water_bytes();
    assert!(
        held >= CHANNEL_QUEUED_MAX_BYTES,
        "the queue filled to its bound ({held} bytes), so the test saw the gate"
    );
    assert!(
        peak <= ONE_CHANNEL_BOUND,
        "peak {peak} bytes of output budget for one channel; the bound is {ONE_CHANNEL_BOUND}"
    );
    assert!(
        LINES as u64 * ZERO_LINE_BYTES as u64 > ONE_CHANNEL_BOUND,
        "the lines would have queued far more than the bound if nothing stopped them"
    );

    // The peer starts reading: every byte of every line arrives, none dropped.
    let wanted = LINES * ZERO_LINE_BYTES;
    let mut received = 0usize;
    let finished = tokio::time::timeout(Duration::from_secs(120), async {
        while received < wanted {
            match channel.wait().await {
                Some(russh::ChannelMsg::Data { data }) => received += data.len(),
                Some(_) => {}
                None => break,
            }
        }
    })
    .await;
    assert!(
        finished.is_ok(),
        "output stalled at {received} of {wanted} bytes"
    );
    assert!(
        received >= wanted,
        "{received} of {wanted} bytes arrived: output was dropped"
    );
    assert!(
        rig.output.high_water_bytes() <= ONE_CHANNEL_BOUND,
        "the bound held while the queue drained too"
    );

    drop(channel);
    drop(session);
    rig.handle.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_peer_that_never_reads_is_still_closed_at_max_duration_and_everything_is_refunded() {
    let rig = rig(Duration::from_secs(3)).await;
    let session = login(rig.addr, 16_384).await;
    let mut channel = open_shell(&session).await;
    for _ in 0..8 {
        channel.data(&b"cat /dev/zero\r"[..]).await.unwrap();
    }
    settle(&rig.output).await;
    assert!(
        rig.output.current_bytes() > 0,
        "output is queued while the peer is not reading"
    );

    // The listener drops the session at max_duration whatever the queue holds.
    let closed = tokio::time::timeout(Duration::from_secs(30), async {
        while channel.wait().await.is_some() {}
    })
    .await;
    assert!(closed.is_ok(), "the connection outlived max_duration");

    // Dropping the session dropped its channels, queues and deferred input with it.
    let refunded = tokio::time::timeout(Duration::from_secs(10), async {
        while rig.output.current_bytes() != 0 {
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await;
    assert!(
        refunded.is_ok(),
        "{} bytes of the output budget were never refunded",
        rig.output.current_bytes()
    );
    rig.handle.abort();
}

/// When the output budget cannot even hold the input waiting behind a backed-up queue, the
/// session ends: an explicit end, with everything refunded, not input silently dropped and not
/// memory past the budget.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn input_that_outgrows_the_output_budget_ends_the_session_instead_of_being_dropped() {
    let rig = rig(Duration::from_secs(120)).await;
    let session = login(rig.addr, 16_384).await;
    let mut channel = open_shell(&session).await;
    // The first line runs and leaves its unread megabyte queued.
    channel.data(&b"cat /dev/zero\r"[..]).await.unwrap();
    settle(&rig.output).await;
    // Other connections take all but room for two 151-byte waiting packets (23 bytes of
    // payload plus 128 of overhead each).
    let room = OUTPUT_BUDGET_BYTES - rig.output.current_bytes();
    let hog = rig.output.try_reserve(room - 400).unwrap();
    // Each further packet is one more line, which waits behind that megabyte.
    for _ in 0..20 {
        if channel.data(&b"cat /dev/zero\r"[..]).await.is_err() {
            break;
        }
    }
    let ended = tokio::time::timeout(Duration::from_secs(30), async {
        while channel.wait().await.is_some() {}
    })
    .await;
    assert!(ended.is_ok(), "the session stayed open past the budget");
    assert!(
        rig.output.high_water_bytes() <= OUTPUT_BUDGET_BYTES,
        "the budget's own ceiling held"
    );
    drop(hog);
    let refunded = tokio::time::timeout(Duration::from_secs(10), async {
        while rig.output.current_bytes() != 0 {
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await;
    assert!(refunded.is_ok(), "the session's charges were not refunded");
    rig.handle.abort();
}

// ---- A budget held by peers that do not read must not stop sessions that do ----

fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::Digest;
    sha2::Sha256::digest(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// A connection that never reads: `channels` shells, each told to print a megabyte `lines` times,
/// and an exec holding a little input so that however the sensor ends the connection is written
/// into a capture. Returns the handles that keep it open.
async fn hog(
    addr: std::net::SocketAddr,
    channels: usize,
    lines: usize,
    marker: &[u8],
) -> (
    russh::client::Handle<TestHandler>,
    Vec<russh::Channel<russh::client::Msg>>,
) {
    let session = login(addr, 16_384).await;
    let mut held = Vec::new();
    let held_input = session.channel_open_session().await.unwrap();
    held_input.exec(false, b"cat > /tmp/marker").await.unwrap();
    held_input.data(marker).await.unwrap();
    held.push(held_input);
    for _ in 0..channels {
        let shell = open_shell(&session).await;
        for _ in 0..lines {
            let send = shell.data(&b"cat /dev/zero\r"[..]);
            if tokio::time::timeout(Duration::from_millis(400), send)
                .await
                .is_err()
            {
                break;
            }
        }
        held.push(shell);
    }
    (session, held)
}

/// Every upload event in the log, with the sample digest and the reason it ended.
fn uploads_in(log: &std::path::Path) -> Vec<(String, String)> {
    std::fs::read_to_string(log)
        .unwrap_or_default()
        .lines()
        .filter_map(|line| serde_json::from_str::<sensor_wire::SensorEvent>(line).ok())
        .filter(|e| e.signal_type == sensor_wire::SIGNAL_HONEYPOT_MALWARE_UPLOAD)
        .filter_map(|e| {
            Some((
                e.sample?.sha256,
                e.metadata["end_reason"].as_str()?.to_string(),
            ))
        })
        .collect()
}

async fn wait_for<F: FnMut() -> bool>(limit: Duration, mut done: F) -> bool {
    let end = tokio::time::Instant::now() + limit;
    while tokio::time::Instant::now() < end {
        if done() {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    done()
}

async fn read_until(
    channel: &mut russh::Channel<russh::client::Msg>,
    needle: &[u8],
    limit: Duration,
) -> bool {
    let mut seen = Vec::new();
    tokio::time::timeout(limit, async {
        loop {
            match channel.wait().await {
                Some(russh::ChannelMsg::Data { data }) => {
                    seen.extend_from_slice(&data);
                    if seen.windows(needle.len()).any(|w| w == needle) {
                        return true;
                    }
                }
                Some(_) => {}
                None => return false,
            }
        }
    })
    .await
    .unwrap_or(false)
}

async fn scp_put(session: &russh::client::Handle<TestHandler>, name: &str, body: &[u8]) {
    async fn ack(channel: &mut russh::Channel<russh::client::Msg>, what: &str) {
        let got = tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                match channel.wait().await {
                    Some(russh::ChannelMsg::Data { data }) => return data.to_vec(),
                    Some(_) => {}
                    None => return Vec::new(),
                }
            }
        })
        .await
        .unwrap_or_default();
        assert_eq!(got, [0], "{what} ack");
    }
    let mut channel = session.channel_open_session().await.unwrap();
    channel.exec(false, b"scp -t /tmp").await.unwrap();
    ack(&mut channel, "ready").await;
    channel
        .data(format!("C0644 {} {name}\n", body.len()).as_bytes())
        .await
        .unwrap();
    ack(&mut channel, "header").await;
    channel.data(body).await.unwrap();
    channel.data(&[0u8][..]).await.unwrap();
    ack(&mut channel, "final").await;
}

/// Five connections that never read fill a 64 MiB budget between them. A sixth, which does read,
/// still gets its shell reply and its SCP upload promptly: the sensor asks the connection holding
/// the most to let go rather than refuse the newcomer, and says so in what it recorded.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn peers_that_do_not_read_cannot_starve_one_that_does() {
    let rig = rig(Duration::from_secs(120)).await;
    let mut hogs = Vec::new();
    for i in 0..5u8 {
        hogs.push(hog(rig.addr, 2, 14, &[b'M', i]).await);
    }
    assert!(
        wait_for(Duration::from_secs(20), || rig.output.current_bytes()
            >= OUTPUT_BUDGET_BYTES - 3 * OUTPUT_UNIT_BYTES)
        .await,
        "the hogs hold the budget ({} of {})",
        rig.output.current_bytes(),
        OUTPUT_BUDGET_BYTES
    );

    let started = tokio::time::Instant::now();
    let victim = login(rig.addr, 2_097_152).await;
    let mut shell = open_shell(&victim).await;
    shell.data(&b"echo VICTIM_OK\r"[..]).await.unwrap();
    assert!(
        read_until(&mut shell, b"VICTIM_OK\r\n", Duration::from_secs(8)).await,
        "the shell reply did not come"
    );
    let upload = b"\x7fELF a small upload that must still be kept".to_vec();
    scp_put(&victim, "kept", &upload).await;
    let latency = started.elapsed();
    assert!(
        latency < Duration::from_secs(8),
        "the reading session took {latency:?}"
    );
    let digest = sha256_hex(&upload);
    drop(shell);
    drop(victim);
    assert!(
        wait_for(Duration::from_secs(10), || uploads_in(&rig.log)
            .iter()
            .any(|(sha, _)| *sha == digest))
        .await,
        "the SCP upload was not captured"
    );
    // At least one hog was the one asked to let go, and its capture says so.
    assert!(
        wait_for(Duration::from_secs(10), || uploads_in(&rig.log)
            .iter()
            .any(|(_, reason)| reason == "output_evicted"))
        .await,
        "no hog was recorded as evicted: {:?}",
        uploads_in(&rig.log)
    );
    drop(hogs);
    rig.handle.abort();
}

/// A connection whose queued output has not moved for the stall limit is closed, and the capture
/// in flight on it says why.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_connection_whose_output_makes_no_progress_is_closed_and_says_why() {
    let rig = rig_with(
        Duration::from_secs(120),
        OUTPUT_BUDGET_BYTES,
        Duration::from_secs(2),
    )
    .await;
    // Nothing here reads, so the only thing that can end this connection before max_duration is
    // the sensor's own decision about the stall.
    let _open = hog(rig.addr, 1, 6, b"stalled-marker").await;
    assert!(
        wait_for(Duration::from_secs(10), || uploads_in(&rig.log)
            .iter()
            .any(|(_, reason)| reason == "output_stalled"))
        .await,
        "no capture recorded output_stalled: {:?}",
        uploads_in(&rig.log)
    );
    assert!(
        wait_for(Duration::from_secs(10), || rig.output.current_bytes() == 0).await,
        "the stalled connection's charge was not refunded"
    );
    rig.handle.abort();
}

/// Work refused for lack of budget runs as soon as budget is refunded, not at the session's next
/// unrelated wakeup (before, a keepalive 20 s later).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn deferred_work_runs_the_moment_budget_is_refunded() {
    let rig = rig_with(
        Duration::from_secs(120),
        10 * 1024 * 1024,
        OUTPUT_STALL_LIMIT,
    )
    .await;
    // Another holder, not a connection, so there is nobody to ask to let go.
    let held = rig.output.try_reserve(4 * 1024 * 1024).unwrap();
    let session = login(rig.addr, 2_097_152).await;
    let mut shell = open_shell(&session).await;
    shell.data(&b"echo WAKE_OK\r"[..]).await.unwrap();
    assert!(
        !read_until(&mut shell, b"WAKE_OK", Duration::from_millis(800)).await,
        "the budget is short, so nothing runs yet"
    );
    let freed = tokio::time::Instant::now();
    drop(held);
    assert!(
        read_until(&mut shell, b"WAKE_OK", Duration::from_secs(3)).await,
        "the reply did not follow the refund"
    );
    assert!(freed.elapsed() < Duration::from_secs(3));
    rig.handle.abort();
}

#[test]
fn a_unit_fits_a_line_and_the_bounds_are_built_from_the_work_cap() {
    // A pty doubles the worst-case line, so the allowance covers that plus the 1 MiB around it.
    assert_eq!(
        LINE_OUTPUT_MAX_BYTES,
        2 * sensor_framework::BudgetLimits::standard().work_per_line
    );
    const {
        assert!(OUTPUT_UNIT_BYTES > LINE_OUTPUT_MAX_BYTES);
        assert!(OUTPUT_BUDGET_BYTES >= 4 * OUTPUT_UNIT_BYTES);
    }
}
