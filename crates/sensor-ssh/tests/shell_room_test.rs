//! Which sessions the SSH sensor gives a shell while the session memory pool is short. One test,
//! because the pool is process-global.
//!
//! A pool with less than a shell's room left used to refuse every new shell, including to sessions
//! far inside their floor, while a session holding many times its share was never asked to let go
//! (asking happens only when an allocation fails to reserve). A session within its floor is now
//! granted the shell and the session over its share is asked to give way; a session past its own
//! floor is still refused, and so is one once the overdraft cap is spent.

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

    // The room a shell is asked for must cover what the shell itself reserves, at the pool's
    // 64 KiB granularity: the check gates the shell request, after the login's own heap is
    // already held. The first session of a process reserves less (393,216 measured) than the
    // ones after it (458,752 measured), so measure sessions after the first and take the most.
    // The margin under SHELL_ROOM_BYTES is one chunk today; a larger shell heap fails here
    // before it makes the room check admit a shell the pool cannot back.
    let first_session = login(addr).await;
    settle().await;
    let base = session_memory::pool_used();
    let (warmup, granted) = shell(&first_session).await;
    assert!(granted);
    settle().await;
    println!(
        "first session, shell-only reserve {}",
        session_memory::pool_used() - base
    );
    drop((warmup, first_session));
    settle().await;
    let mut shell_only = 0;
    for _ in 0..3 {
        let fresh = login(addr).await;
        settle().await;
        let base = session_memory::pool_used();
        let (first, granted) = shell(&fresh).await;
        assert!(granted);
        settle().await;
        shell_only = shell_only.max(session_memory::pool_used() - base);
        drop((first, fresh));
        settle().await;
    }
    assert!(
        shell_only <= SHELL_ROOM_BYTES,
        "a shell reserves {shell_only}, over the {SHELL_ROOM_BYTES} the room check allows"
    );
    println!(
        "shell-only reserve {shell_only} of {SHELL_ROOM_BYTES}, margin {}",
        SHELL_ROOM_BYTES - shell_only
    );

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
    for _ in 0..20 {
        let session = login(addr).await;
        let (_channel, ok) = shell(&session).await;
        if ok {
            granted += 1;
        } else {
            refused += 1;
        }
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
    // How far the pool may pass its ceiling is bounded by the overdraft cap, which the
    // framework's make_room tests pin; here the load never reaches it.
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

    // With the overdraft spent (a cap of nothing here), a newcomer within its floor is refused
    // too, the holder is still asked, and the shell is granted once the room is back.
    let holder = login(addr).await;
    let mut held = Vec::new();
    for _ in 0..8 {
        let (channel, granted) = shell(&holder).await;
        assert!(granted);
        held.push(channel);
    }
    settle().await;
    session_memory::configure_with_overdraft(session_memory::pool_used() + 400 * 1024, 4, 0)
        .unwrap();
    let newcomer = login(addr).await;
    let (_refused, granted) = shell(&newcomer).await;
    assert!(!granted, "no overdraft left, so no shell from a short pool");
    assert!(
        !newcomer.is_closed(),
        "the refusal does not end the session"
    );
    assert!(
        closes_while_idle(&mut held[0], Duration::from_secs(3)).await,
        "the holder was asked all the same"
    );
    drop((held, holder));
    settle().await;
    let (_second, granted) = shell(&newcomer).await;
    assert!(granted, "the room is back");
    drop((_second, newcomer));
    settle().await;
    session_memory::configure(u64::MAX / 2, 64).unwrap();
    handle.abort();
}
