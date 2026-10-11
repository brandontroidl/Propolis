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
    _dir: tempfile::TempDir,
}

async fn rig(max_duration: Duration) -> Rig {
    rig_with_budget(max_duration, OUTPUT_BUDGET_BYTES).await
}

async fn rig_with_budget(max_duration: Duration, output_bytes: u64) -> Rig {
    let dir = tempfile::tempdir().unwrap();
    let bounds = ConnectionBounds {
        read_timeout: Duration::from_secs(30),
        idle_timeout: Duration::from_secs(60),
        max_duration,
        max_captured_bytes: 1_000_000,
        max_concurrent: 64,
    };
    let output = Arc::new(CaptureMemoryBudget::new(output_bytes));
    let (addr, handle, _handoff) = sensor_ssh::serve_with_budgets(
        "127.0.0.1:0".parse().unwrap(),
        dir.path().join("events.jsonl"),
        dir.path().join("spool"),
        dir.path().join("host_key"),
        Arc::new(WanResolver::new(HashMap::new())),
        bounds,
        "OpenSSH_9.6p1".to_string(),
        "test".to_string(),
        dir.path().join("outbox"),
        Arc::new(CaptureMemoryBudget::new(214_748_364)),
        output.clone(),
        Arc::new(CommandEventGate::new(CommandEventConfig::default())),
    )
    .await
    .unwrap();
    Rig {
        addr,
        handle,
        output,
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
