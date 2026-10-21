//! The SSH sensor under the session accounting allocator, as its binary runs: a session that
//! grows its shell past what a session may hold is disconnected and gives back what it held,
//! and a quiet holder is ended when the pool needs its room. One test, because the pool is
//! process-global.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use sensor_framework::session_memory::{self, AccountingAlloc};
use sensor_framework::{ConnectionBounds, WanResolver};

#[global_allocator]
static ALLOCATOR: AccountingAlloc = AccountingAlloc;

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

async fn login(addr: std::net::SocketAddr) -> russh::client::Handle<TestHandler> {
    login_with(addr, russh::client::Config::default()).await
}

/// A client that opens channels with a window of `window` bytes, and so lets the server send
/// only that much until it reads.
async fn login_with_window(
    addr: std::net::SocketAddr,
    window: u32,
) -> russh::client::Handle<TestHandler> {
    let config = russh::client::Config {
        window_size: window,
        ..Default::default()
    };
    login_with(addr, config).await
}

async fn login_with(
    addr: std::net::SocketAddr,
    config: russh::client::Config,
) -> russh::client::Handle<TestHandler> {
    let config = Arc::new(config);
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

/// Ask for a pty shell with a reply wanted; the channel and whether it was granted.
async fn shell(
    session: &russh::client::Handle<TestHandler>,
) -> (russh::Channel<russh::client::Msg>, bool) {
    let mut channel = session.channel_open_session().await.unwrap();
    channel
        .request_pty(false, "xterm", 80, 24, 0, 0, &[])
        .await
        .unwrap();
    channel.request_shell(true).await.unwrap();
    loop {
        match tokio::time::timeout(Duration::from_secs(10), channel.wait())
            .await
            .expect("the shell request is answered")
        {
            Some(russh::ChannelMsg::Success) => return (channel, true),
            Some(russh::ChannelMsg::Failure) => return (channel, false),
            Some(_) => {}
            None => panic!("the channel ended before the request was answered"),
        }
    }
}

/// Wait until the pool holds no more than `bytes`, or fail with `what`.
async fn pool_settles(bytes: u64, what: &str) {
    let deadline = Instant::now() + Duration::from_secs(10);
    while session_memory::pool_used() > bytes {
        assert!(
            Instant::now() < deadline,
            "{what}: the pool still holds {}",
            session_memory::pool_used()
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

/// Wait for a malware upload whose capture says the session was ended for its memory.
async fn upload_ended_for_memory(log: &std::path::Path) {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let content = tokio::fs::read_to_string(log).await.unwrap_or_default();
        let found = content
            .lines()
            .filter_map(|l| serde_json::from_str::<sensor_wire::SensorEvent>(l).ok())
            .any(|e| {
                e.signal_type == sensor_wire::SIGNAL_HONEYPOT_MALWARE_UPLOAD
                    && e.metadata.get("end_reason").and_then(|v| v.as_str()) == Some("memory_limit")
            });
        if found {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "no capture recorded end_reason memory_limit"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

/// Send one line to a pty shell and wait for its prompt. False once the server has closed the
/// channel.
async fn line(channel: &mut russh::Channel<russh::client::Msg>, text: &str) -> bool {
    if channel.data(format!("{text}\n").as_bytes()).await.is_err() {
        return false;
    }
    let mut out = Vec::new();
    loop {
        match tokio::time::timeout(Duration::from_secs(10), channel.wait()).await {
            Ok(Some(russh::ChannelMsg::Data { data })) => {
                out.extend_from_slice(&data);
                if out.ends_with(b"# ") {
                    return true;
                }
            }
            Ok(Some(russh::ChannelMsg::Close | russh::ChannelMsg::Eof) | None) => return false,
            Ok(Some(_)) => {}
            Err(_) => panic!("no prompt and no close after {text:?}"),
        }
    }
}

/// Whether the server closes `channel` within `within` while the client sends nothing.
async fn closes_while_idle(
    channel: &mut russh::Channel<russh::client::Msg>,
    within: Duration,
) -> bool {
    let deadline = Instant::now() + within;
    while Instant::now() < deadline {
        if let Ok(Some(russh::ChannelMsg::Close | russh::ChannelMsg::Eof) | None) =
            tokio::time::timeout(Duration::from_millis(100), channel.wait()).await
        {
            return true;
        }
    }
    false
}

/// With every session slot taken, a new connection could not be accounted: the sensor closes it
/// at once rather than serve it unbounded.
async fn refused_without_a_slot(addr: std::net::SocketAddr) {
    use tokio::io::AsyncReadExt;
    let held: Vec<_> = (0..session_memory::SLOT_COUNT)
        .map(|_| session_memory::scope(std::future::ready(())))
        .collect();
    let mut conn = tokio::net::TcpStream::connect(addr).await.unwrap();
    let mut chunk = [0u8; 4096];
    let deadline = Instant::now() + Duration::from_secs(5);
    let closed = loop {
        match tokio::time::timeout_at(deadline.into(), conn.read(&mut chunk)).await {
            Ok(Ok(0) | Err(_)) => break true,
            Ok(Ok(_)) => {}
            Err(_) => break false,
        }
    };
    drop(held);
    assert!(closed, "a session with no slot was closed, not served");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_session_past_its_memory_is_ended_and_a_quiet_holder_yields_to_newcomers() {
    tokio::spawn(session_memory::watchdog());
    let dir = tempfile::tempdir().unwrap();
    let (addr, handle) = sensor_ssh::serve(
        "127.0.0.1:0".parse().unwrap(),
        dir.path().join("events.jsonl"),
        dir.path().join("spool"),
        dir.path().join("host_key"),
        Arc::new(WanResolver::new(HashMap::new())),
        ConnectionBounds {
            read_timeout: Duration::from_secs(30),
            idle_timeout: Duration::from_secs(60),
            max_duration: Duration::from_secs(120),
            max_captured_bytes: 1_000_000,
            // A per-source cap of 16, so one test client can open enough sessions to fill the
            // small pool below.
            max_concurrent: 64,
        },
        "OpenSSH_9.6p1".to_string(),
        "test".to_string(),
        dir.path().join("outbox"),
    )
    .await
    .unwrap();

    // Over the retained limit and far under the peak, then quiet: only the check between packets
    // can end this session, and it does, without waiting for another packet.
    session_memory::set_retained_limit(1024 * 1024);
    let session = login(addr).await;
    let (mut channel, granted) = shell(&session).await;
    assert!(granted);
    // A binary payload streamed at the shell first, so a capture is in flight when the session is
    // ended and records why.
    let mut binary = vec![0xAAu8; 128];
    binary.push(b'\n');
    channel.data(&binary[..]).await.unwrap();
    assert!(line(&mut channel, "true").await);
    assert!(line(&mut channel, "set -- '' ''").await);
    let mut open = true;
    for _ in 0..16 {
        open = line(&mut channel, "set -- \"$@\" \"$@\"").await;
        if !open {
            break;
        }
    }
    assert!(
        !open || closes_while_idle(&mut channel, Duration::from_secs(5)).await,
        "a session holding past its retained limit was ended"
    );
    drop((channel, session));
    pool_settles(256 * 1024, "the session over its retained limit").await;
    session_memory::set_retained_limit(session_memory::RETAINED_LIMIT_BYTES);
    upload_ended_for_memory(&dir.path().join("events.jsonl")).await;

    // A peer that does not read: the output it has not taken and the input waiting behind it are
    // the output budget's to bound, not the session's memory. Megabytes of both, against a
    // retained limit of 1 MiB, and the session stays open.
    session_memory::set_retained_limit(1024 * 1024);
    let session = login_with_window(addr, 16 * 1024).await;
    let (channel, granted) = shell(&session).await;
    assert!(granted);
    for _ in 0..10 {
        channel.data(&b"cat /dev/zero\r"[..]).await.unwrap();
    }
    let mut waiting = b"#".repeat(30_000);
    waiting.push(b'\r');
    for _ in 0..50 {
        channel.data(&waiting[..]).await.unwrap();
    }
    tokio::time::sleep(Duration::from_secs(3)).await;
    assert!(
        !session.is_closed(),
        "a session whose peer does not read is not ended for its memory"
    );
    drop((channel, session));
    pool_settles(256 * 1024, "the session that did not read").await;
    session_memory::set_retained_limit(session_memory::RETAINED_LIMIT_BYTES);

    // Asked to let go while it waits for its peer: a quiet session holding the most of a pool
    // that another session needs is ended at once, not at its idle timeout. The holder grows with
    // room to spare, then the pool shrinks to what it keeps plus 1.5 MiB, for four sessions: the
    // holder keeps far more than a quarter, the newcomers far less, so when they run the pool out
    // the holder is the one asked to let go.
    session_memory::set_retained_limit(64 * 1024 * 1024);
    let holder = login(addr).await;
    let (mut held, granted) = shell(&holder).await;
    assert!(granted);
    assert!(line(&mut held, "set -- '' ''").await);
    for _ in 0..15 {
        assert!(
            line(&mut held, "set -- \"$@\" \"$@\"").await,
            "within its limits"
        );
    }
    // Drain whatever the holder's last line still sends, so the holder is truly quiet: a packet
    // from it would let the check between packets end it, not the race on its idle read.
    assert!(
        !closes_while_idle(&mut held, Duration::from_millis(500)).await,
        "the holder is still open"
    );
    session_memory::configure(session_memory::pool_used() + 1536 * 1024, 4).unwrap();
    let mut newcomers = Vec::new();
    let mut ended = false;
    for _ in 0..12 {
        let session = login(addr).await;
        let (channel, _) = shell(&session).await;
        newcomers.push((session, channel));
        if closes_while_idle(&mut held, Duration::from_millis(400)).await {
            ended = true;
            break;
        }
    }
    assert!(ended, "the quiet holder was ended for the newcomers");
    drop((held, holder, newcomers));
    pool_settles(256 * 1024, "the evicted holder").await;
    session_memory::configure(u64::MAX / 2, 64).unwrap();
    session_memory::set_retained_limit(session_memory::RETAINED_LIMIT_BYTES);

    // Doubling the positional parameters until the session is over what it may hold: the sensor
    // ends the connection rather than following it, and everything the session held comes back.
    let session = login(addr).await;
    let (mut channel, granted) = shell(&session).await;
    assert!(granted);
    channel.data(&b"set -- '' ''\n"[..]).await.unwrap();
    let started = Instant::now();
    let mut ended = false;
    while started.elapsed() < Duration::from_secs(60) {
        if channel.data(&b"set -- \"$@\" \"$@\"\n"[..]).await.is_err() {
            ended = true;
            break;
        }
        if let Ok(None | Some(russh::ChannelMsg::Close | russh::ChannelMsg::Eof)) =
            tokio::time::timeout(Duration::from_millis(200), channel.wait()).await
        {
            ended = true;
            break;
        }
    }
    assert!(ended, "the session was ended, not followed for a minute");
    drop((channel, session));
    pool_settles(256 * 1024, "the ended session").await;

    // (Which sessions a short pool still gives a shell is `shell_room_test.rs`.)
    refused_without_a_slot(addr).await;
    drop(login(addr).await);
    handle.abort();
}
