//! What a session within its floor is owed from a short or full session memory pool, and the cap
//! on how much of it may be taken past the pool's ceiling: `AccountRef::make_room` (a new shell's
//! heap) and the floor grant in `charge` (an allocation the pool cannot back). The pool and the
//! slot table are process-global, so each test holds `POOL_LOCK` and puts the pool back.

use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Barrier, Mutex, MutexGuard};
use std::task::{Context, Poll, Waker};

use sensor_framework::session_memory::{
    self, AccountRef, AccountingAlloc, CHUNK_BYTES, PEAK_LIMIT_BYTES,
};

#[global_allocator]
static ALLOCATOR: AccountingAlloc = AccountingAlloc;

static POOL_LOCK: Mutex<()> = Mutex::new(());

fn exclusive() -> MutexGuard<'static, ()> {
    POOL_LOCK.lock().unwrap_or_else(|e| e.into_inner())
}

fn reset_pool() {
    session_memory::configure(u64::MAX / 2, 256).unwrap();
}

type Open<'a, R> =
    Pin<Box<session_memory::Scoped<Pin<Box<dyn Future<Output = (R, AccountRef)> + 'a>>>>>;

/// Run `f` inside a fresh accounted session that stays open until the returned session is dropped.
fn in_session<'a, R: 'a>(f: impl FnOnce() -> R + 'a) -> (R, AccountRef, Open<'a, R>) {
    let body: Pin<Box<dyn Future<Output = (R, AccountRef)> + 'a>> = Box::pin(async move {
        let account = session_memory::current_account().expect("the scope is accounted");
        (f(), account)
    });
    let mut scoped = Box::pin(session_memory::scope(body));
    let Poll::Ready((result, account)) = scoped
        .as_mut()
        .poll(&mut Context::from_waker(Waker::noop()))
    else {
        panic!("the future completes in one poll");
    };
    (result, account, scoped)
}

/// Bytes a session with a 40 KB buffer holds: it needs one 64 KiB chunk of pool room, and stays
/// under the 64 KiB floor of the pools below.
const SMALL: usize = 40_000;

/// A session holding a buffer: the buffer, its account and the session itself.
type Holder = (Vec<u8>, AccountRef, Open<'static, Vec<u8>>);

/// A pool exactly as full as it is now, with a session holding `held` bytes of it. Returns that
/// holder and the ceiling.
fn full_pool(held: usize, sessions: u32, overdraft_cap: u64) -> (Holder, u64) {
    session_memory::configure(u64::MAX / 2, 256).unwrap();
    let holder = in_session(move || vec![0u8; held]);
    let ceiling = session_memory::pool_used();
    session_memory::configure_with_overdraft(ceiling, sessions, overdraft_cap).unwrap();
    assert_eq!(session_memory::pool_free(), 0, "the pool is full");
    (holder, ceiling)
}

#[test]
fn a_newcomer_within_its_floor_asks_the_holder_to_yield_before_it_allocates() {
    let _guard = exclusive();
    session_memory::configure(u64::MAX / 2, 256).unwrap();
    let (buf, holder, holder_open) = in_session(|| vec![0u8; 2 * 1024 * 1024]);
    // 100 KiB free of a pool for four sessions: a floor of about 530 KB, a share of half the
    // pool once a second session runs, far under what the holder holds.
    session_memory::configure(session_memory::pool_used() + 100 * 1024, 4).unwrap();
    let before = session_memory::pool_used();
    let (_, newcomer, newcomer_open) = in_session(|| ());

    // Free room is enough: nobody is asked.
    assert!(newcomer.make_room(64 * 1024));
    assert!(
        !holder.is_over(),
        "room was free, so the holder is left alone"
    );

    // Not enough free, but the newcomer stays within its floor: it is granted the room and the
    // holder is asked at once, before the newcomer has allocated anything.
    assert!(session_memory::pool_free() < 256 * 1024);
    assert!(newcomer.make_room(256 * 1024));
    assert!(
        holder.is_over(),
        "the session far over its share is asked to let go"
    );
    assert!(!newcomer.is_over(), "the newcomer is not");
    assert_eq!(
        session_memory::pool_used(),
        before,
        "make_room reserves nothing itself"
    );

    // Past its own floor it is refused, and asks nobody.
    drop((buf, holder_open));
    let (buf, holder, holder_open) = in_session(|| vec![0u8; 2 * 1024 * 1024]);
    assert!(!holder.is_over());
    assert!(
        !newcomer.make_room(600 * 1024),
        "a session that would pass its floor is refused"
    );
    assert!(!holder.is_over(), "a refused session asks nobody");

    drop((buf, holder_open, newcomer_open));
    reset_pool();
}

#[test]
fn a_session_that_is_asked_or_over_its_limit_is_refused_a_shell_even_with_room_free() {
    let _guard = exclusive();
    session_memory::configure(u64::MAX / 2, 256).unwrap();
    let (buf, holder, holder_open) = in_session(|| vec![0u8; 2 * 1024 * 1024]);
    session_memory::configure(session_memory::pool_used() + 100 * 1024, 4).unwrap();
    let (_, newcomer, newcomer_open) = in_session(|| ());
    assert!(newcomer.make_room(256 * 1024));
    assert!(holder.is_over(), "the holder is the one asked");

    // The pool has all the room in the world again; the asked session is still ending.
    session_memory::configure(u64::MAX / 2, 256).unwrap();
    assert!(session_memory::pool_free() > 1024 * 1024);
    assert!(
        !holder.make_room(64 * 1024),
        "a session asked to let go gets no shell"
    );
    assert!(newcomer.make_room(64 * 1024), "a session not asked does");
    drop((buf, holder_open));

    // Over its own limit, with nobody asking it.
    let (big, over, over_open) = in_session(|| vec![0u8; PEAK_LIMIT_BYTES as usize + 1024]);
    assert!(over.is_over());
    assert!(
        !over.make_room(64 * 1024),
        "a session over its limit gets no shell"
    );

    drop((big, over_open, newcomer_open));
    reset_pool();
}

#[test]
fn make_room_grants_past_a_full_pool_only_up_to_the_overdraft_cap() {
    let _guard = exclusive();
    let cap = 4 * CHUNK_BYTES;
    // Eight sessions: a floor of about 520 KB, room for the requests below.
    let ((buf, holder, holder_open), _) = full_pool(4 * 1024 * 1024, 8, cap);
    let (_, newcomer, newcomer_open) = in_session(|| ());

    assert!(newcomer.make_room(2 * CHUNK_BYTES), "within the cap");
    assert!(holder.is_over(), "the holder is asked on the way");

    // Three sessions each take a chunk out of the cap.
    let takers: Vec<_> = (0..3).map(|_| in_session(|| vec![0u8; SMALL])).collect();
    assert!(takers.iter().all(|(_, a, _)| !a.is_over()));
    assert_eq!(
        session_memory::pool_used() - session_memory::pool_ceiling(),
        3 * CHUNK_BYTES
    );
    assert!(
        newcomer.make_room(CHUNK_BYTES),
        "one chunk of the cap is left"
    );
    assert!(
        !newcomer.make_room(2 * CHUNK_BYTES),
        "two chunks are asked of one that is left"
    );

    // Room returns when a taker ends: the same request now fits.
    let mut takers = takers;
    let (buf0, _, open0) = takers.remove(0);
    drop((buf0, open0));
    assert!(
        newcomer.make_room(2 * CHUNK_BYTES),
        "a freed chunk is the cap's again"
    );

    drop((takers, buf, holder_open, newcomer_open));
    reset_pool();
}

#[test]
fn concurrent_floor_grants_past_a_full_pool_never_pass_the_cap_and_are_given_back() {
    let _guard = exclusive();
    let cap = 10 * CHUNK_BYTES;
    let ((buf, _holder, holder_open), ceiling) = full_pool(4 * 1024 * 1024, 64, cap);

    const THREADS: usize = 32;
    let allocated = Barrier::new(THREADS + 1);
    let checked = Barrier::new(THREADS + 1);
    let stopped = AtomicU64::new(0);
    let measured = std::thread::scope(|scope| {
        for _ in 0..THREADS {
            scope.spawn(|| {
                // 40 KB is within the 64 KiB floor and asks the full pool for one chunk.
                let ((buf, line_stopped), _, open) = in_session(|| {
                    let buf = vec![0u8; SMALL];
                    (buf, session_memory::current_over())
                });
                stopped.fetch_add(u64::from(line_stopped), Ordering::Relaxed);
                allocated.wait();
                checked.wait();
                drop((buf, open));
            });
        }
        allocated.wait();
        // Read while every session is alive, assert once they have been released: a failed
        // assertion here would leave the threads waiting at the barrier.
        let used = session_memory::pool_used();
        let stopped = stopped.load(Ordering::Relaxed);
        checked.wait();
        (used, stopped)
    });
    let (used, stopped) = measured;
    let past = used - ceiling;
    assert!(past <= cap, "{past} bytes held past the ceiling, cap {cap}");
    assert_eq!(
        past, cap,
        "32 chunks were asked for and the cap is 10, so it is used up"
    );
    assert_eq!(
        stopped,
        (THREADS as u64) - cap / CHUNK_BYTES,
        "the sessions past the cap had their line stopped"
    );

    // Every session ended: what they held past the ceiling is given back.
    assert_eq!(
        session_memory::pool_used(),
        ceiling,
        "back to the full pool, no more"
    );

    // The holder lets go as the pool asked: the room returns and a newcomer is served from it,
    // not from the cap.
    drop((buf, holder_open));
    assert!(session_memory::pool_free() > 1024 * 1024);
    let (kept, newcomer, newcomer_open) = in_session(|| {
        let v = vec![0u8; SMALL];
        (v, session_memory::current_over())
    });
    assert!(
        !kept.1,
        "a within-floor allocation with room free is not stopped"
    );
    assert!(newcomer.live() >= SMALL as u64);
    assert!(
        session_memory::pool_used() <= ceiling,
        "no overdraft was needed"
    );
    drop((kept, newcomer_open));
    reset_pool();
}

/// A refusal for the cap's sake still asks the holder to let go: room only returns for the retry
/// if somebody is ending.
#[test]
fn a_shell_refused_for_the_cap_still_asks_the_holder_to_yield() {
    let _guard = exclusive();
    // A cap of nothing: any request on a full pool is refused for it.
    let ((buf, holder, holder_open), _) = full_pool(4 * 1024 * 1024, 8, 0);
    let (_, newcomer, newcomer_open) = in_session(|| ());
    assert!(!holder.is_over());

    assert!(
        !newcomer.make_room(CHUNK_BYTES),
        "within its floor, but nothing of the cap is left"
    );
    assert!(
        holder.is_over(),
        "the refusal asked the session far over its share to let go"
    );
    assert!(!newcomer.is_over());

    drop((buf, holder_open, newcomer_open));
    reset_pool();
}

/// `configure` is the framework default for telnet, ADB and MQTT and must grant floors exactly as
/// before the cap existed: unlimited. Sixty-three sessions within their floor, each needing two
/// chunks, take twice the ceiling from a full pool; a cap of the ceiling would stop about half.
#[test]
fn configure_leaves_floor_grants_past_a_full_pool_unlimited() {
    let _guard = exclusive();
    session_memory::configure(u64::MAX / 2, 256).unwrap();
    let holder = in_session(|| vec![0u8; 4 * 1024 * 1024]);
    let ceiling = session_memory::pool_used();
    let sessions = 64u32;
    session_memory::configure(ceiling, sessions).unwrap();
    let floor = ceiling / u64::from(sessions);
    let len = (floor - 200) as usize;

    let mut stopped = 0;
    let mut kept = Vec::new();
    for _ in 0..(sessions - 1) {
        let ((buf, over), account, open) = in_session(move || {
            let v = vec![0u8; len];
            (v, session_memory::current_over())
        });
        assert!(account.live() <= floor, "within its floor");
        stopped += u32::from(over);
        kept.push((buf, open));
    }
    assert!(
        session_memory::pool_used() - ceiling > ceiling,
        "the grants passed twice the ceiling, so a cap of the ceiling would have refused some"
    );
    assert_eq!(stopped, 0, "configure stopped {stopped} within-floor lines");

    drop((kept, holder));
    reset_pool();
}

#[test]
fn the_cap_does_not_touch_a_pool_that_has_room() {
    let _guard = exclusive();
    // A cap of nothing: only room past the ceiling is gated by it.
    session_memory::configure_with_overdraft(64 * 1024 * 1024, 64, 0).unwrap();
    let before = session_memory::pool_used();
    let sessions: Vec<_> = (0..40)
        .map(|_| {
            in_session(|| {
                let v = vec![0u8; SMALL];
                (v, session_memory::current_over())
            })
        })
        .collect();
    assert!(
        sessions
            .iter()
            .all(|((_, stopped), a, _)| !stopped && !a.is_over()),
        "every session was served from the pool's own room"
    );
    assert_eq!(session_memory::pool_used() - before, 40 * CHUNK_BYTES);
    let (_, newcomer, newcomer_open) = in_session(|| ());
    assert!(
        newcomer.make_room(512 * 1024),
        "a shell is granted with room free"
    );
    drop((sessions, newcomer_open));
    reset_pool();
}
