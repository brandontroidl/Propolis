//! Which sessions the SSH sensor gives a shell while the session memory pool is short. One test,
//! because the pool is process-global.
//!
//! A pool with less than a shell's room left used to refuse every new shell, including to sessions
//! far inside their floor, while a session holding many times its share was never asked to let go
//! (asking happens only when an allocation fails to reserve). A session within its floor is now
//! granted the shell and the session over its share is asked to give way; a session past its own
//! floor is still refused.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use sensor_framework::session_memory::{self, AccountingAlloc};
use sensor_framework::{ConnectionBounds, WanResolver};
use sensor_ssh::server::SHELL_ROOM_BYTES;

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
    let mut session = russh::client::connect(
        Arc::new(russh::client::Config::default()),
        addr,
        TestHandler,
    )
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

async fn settle() {
    tokio::time::sleep(Duration::from_millis(300)).await;
}

/// Send one line to a pty shell and wait for its prompt.
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

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_short_pool_gives_shells_to_sessions_within_their_floor_and_asks_the_holder_to_yield() {
    tokio::spawn(session_memory::watchdog());
    let dir = tempfile::tempdir().unwrap();
    let (addr, handle) = sensor_ssh::serve(
        "127.0.0.1:0".parse().unwrap(),
        dir.path().join("events.jsonl"),
        dir.path().join("spool"),
        dir.path().join("host_key"),
        Arc::new(WanResolver::new(HashMap::new())),
        ConnectionBounds {
            read_timeout: Duration::from_secs(60),
            idle_timeout: Duration::from_secs(120),
            max_duration: Duration::from_secs(600),
            max_captured_bytes: 1_000_000,
            max_concurrent: 64,
        },
        "OpenSSH_9.6p1".to_string(),
        "test".to_string(),
        dir.path().join("outbox"),
    )
    .await
    .unwrap();
    session_memory::configure(u64::MAX / 2, 64).unwrap();
    settle().await;

    // The room a shell is asked for must cover what the real path reserves for a new session
    // and its first shell, at the pool's 64 KiB granularity. Measured 524,288 = SHELL_ROOM_BYTES,
    // so there is no margin to spare: a larger login or shell heap fails here before it makes the
    // room check admit a shell the pool cannot back.
    let base = session_memory::pool_used();
    let fresh = login(addr).await;
    let (first, granted) = shell(&fresh).await;
    assert!(granted);
    settle().await;
    let reserved = session_memory::pool_used() - base;
    assert!(
        reserved <= SHELL_ROOM_BYTES,
        "a new session and its first shell reserve {reserved}, over the {SHELL_ROOM_BYTES} the room check allows"
    );
    println!(
        "reserve {reserved} of {SHELL_ROOM_BYTES}, margin {}",
        SHELL_ROOM_BYTES - reserved
    );
    drop((first, fresh));
    settle().await;

    // A holder with eight shells; the pool is then what it holds plus 400 KiB, for four
    // sessions: free room is between a newcomer's login and a shell's room, and the floor
    // (a quarter of the pool, about 950 KB) is far above a newcomer's need.
    let holder = login(addr).await;
    let mut held = Vec::new();
    for _ in 0..8 {
        let (channel, granted) = shell(&holder).await;
        assert!(granted);
        held.push(channel);
    }
    settle().await;
    let used = session_memory::pool_used();
    let ceiling = used + 400 * 1024;
    session_memory::configure(ceiling, 4).unwrap();
    assert!(session_memory::pool_free() < SHELL_ROOM_BYTES);

    let mut granted = 0;
    let mut refused = 0;
    let mut peak = 0;
    for _ in 0..20 {
        let session = login(addr).await;
        let (_channel, ok) = shell(&session).await;
        if ok {
            granted += 1;
        } else {
            refused += 1;
        }
        peak = peak.max(session_memory::pool_used());
        drop(session);
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    assert_eq!(
        (granted, refused),
        (20, 0),
        "every newcomer within its floor is given a shell"
    );
    assert!(
        closes_while_idle(&mut held[0], Duration::from_secs(3)).await,
        "the session holding far over its share was asked to let go"
    );
    // The pool counted past its ceiling is bounded by the floors that were granted: the pool
    // again at most.
    assert!(
        peak <= 2 * ceiling,
        "pool peaked at {peak} against a ceiling of {ceiling}"
    );
    drop((held, holder));
    settle().await;
    session_memory::configure(u64::MAX / 2, 64).unwrap();

    // A session past its own floor is still refused while the pool is short, and is not
    // closed for asking.
    let big = login(addr).await;
    let (mut channel, granted) = shell(&big).await;
    assert!(granted);
    assert!(line(&mut channel, "set -- '' ''").await);
    let before = session_memory::pool_used();
    for _ in 0..14 {
        assert!(line(&mut channel, "set -- \"$@\" \"$@\"").await);
    }
    settle().await;
    let used = session_memory::pool_used();
    assert!(used - before > 1024 * 1024, "the session grew");
    session_memory::configure(used + 100 * 1024, 4).unwrap();
    let (_second, granted) = shell(&big).await;
    assert!(
        !granted,
        "a session past its floor gets no shell from a short pool"
    );
    assert!(!big.is_closed(), "the refusal does not end the session");
    drop((channel, big));
    settle().await;
    session_memory::configure(u64::MAX / 2, 64).unwrap();
    handle.abort();
}
