//! The session accounting allocator, installed for this test binary alone: what a session's
//! allocations charge it, where frees and reallocations land, what a panic leaves behind, and the
//! pool's limits. One test, because the pool and the slot table are process-global.

use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll, Waker};

use sensor_framework::session_memory::{
    self, AccountRef, AccountingAlloc, PEAK_LIMIT_BYTES, SLOT_COUNT,
};

#[global_allocator]
static ALLOCATOR: AccountingAlloc = AccountingAlloc;

/// Poll `fut` once with a waker that does nothing.
fn poll_once<F: Future>(fut: Pin<&mut F>) -> Poll<F::Output> {
    fut.poll(&mut Context::from_waker(Waker::noop()))
}

/// A session that stays open until dropped.
type Open<'a, R> =
    Pin<Box<session_memory::Scoped<Pin<Box<dyn Future<Output = (R, AccountRef)> + 'a>>>>>;

/// Run `f` inside a fresh accounted session, and hand back what it returned, the session's
/// account and the session itself, which ends when dropped.
fn in_session<'a, R: 'a>(f: impl FnOnce() -> R + 'a) -> (R, AccountRef, Open<'a, R>) {
    let body: Pin<Box<dyn Future<Output = (R, AccountRef)> + 'a>> = Box::pin(async move {
        let account = session_memory::current_account().expect("the scope is accounted");
        (f(), account)
    });
    let mut scoped = Box::pin(session_memory::scope(body));
    let Poll::Ready((result, account)) = poll_once(scoped.as_mut()) else {
        panic!("the future completes in one poll");
    };
    (result, account, scoped)
}

#[test]
fn a_session_is_charged_what_it_allocates_wherever_it_is_freed() {
    // Charge and refund: a kilobyte, with its header.
    let (keep, account, open) = in_session(|| vec![7u8; 1000]);
    assert!(account.live() >= 1016, "charged {}", account.live());
    drop(keep);
    assert_eq!(account.live(), 0, "freeing it refunds the session");
    drop(open);

    // Outside every session nothing is charged.
    assert!(session_memory::current_account().is_none());
    let before = session_memory::pool_used();
    let outside = vec![1u8; 100_000];
    assert_eq!(session_memory::pool_used(), before);
    drop(outside);

    // Once a sensor accounts sessions, code running outside any session is one that could not be
    // accounted, and the sensor refuses it; inside a session it is not.
    assert!(
        !session_memory::unaccounted_session(),
        "nothing configured yet"
    );
    session_memory::configure(u64::MAX / 2, 256).unwrap();
    assert!(
        session_memory::unaccounted_session(),
        "configured, no session"
    );
    let (inside, _, open) = in_session(session_memory::unaccounted_session);
    assert!(!inside, "a session with a slot is accounted");
    drop(open);

    // A free on another thread refunds the session that allocated.
    let (moved, account, open) = in_session(|| vec![3u8; 50_000]);
    assert!(account.live() >= 50_000);
    std::thread::spawn(move || drop(moved)).join().unwrap();
    assert_eq!(account.live(), 0, "the other thread's free refunded it");
    drop(open);

    // Growing a buffer someone else allocated moves the whole charge to the one growing it.
    let shared: Vec<u8> = Vec::with_capacity(16);
    let (shared, grower, open) = in_session(move || {
        let mut shared = shared;
        shared.reserve_exact(200_000);
        shared
    });
    assert!(
        grower.live() >= 200_000,
        "the grower holds it: {}",
        grower.live()
    );
    drop(shared);
    assert_eq!(grower.live(), 0);
    drop(open);

    // A panic inside a session's poll does not leave the session current on the thread.
    let panicked = std::panic::catch_unwind(|| {
        let mut scoped = Box::pin(session_memory::scope(async {
            panic!("handler panicked");
        }));
        let _ = poll_once(scoped.as_mut());
    });
    assert!(panicked.is_err());
    assert!(
        session_memory::current_account().is_none(),
        "no session left current"
    );
    let after_panic = vec![0u8; 10_000];
    drop(after_panic);

    // Past the peak limit the session is over, and code running in it can see so.
    let (seen_over, account, open) = in_session(|| {
        let big = vec![0u8; usize::try_from(PEAK_LIMIT_BYTES).unwrap() + 1];
        let over = session_memory::current_over();
        drop(big);
        over
    });
    assert!(seen_over && account.is_over(), "over its peak limit");
    drop(open);

    // Between lines, more than the retained limit makes it over too; less does not.
    let (held, account, open) = in_session(|| vec![0u8; 9 * 1024 * 1024]);
    assert!(account.check_retained(), "9 MiB held between lines");
    drop((held, open));
    let (held, account, open) = in_session(|| vec![0u8; 1024 * 1024]);
    assert!(!account.check_retained(), "1 MiB is fine");
    drop((held, open));

    // A pool of 8 MiB for four sessions (2 MiB each at the least): when it runs out, the session
    // holding the most over its fair share is asked to let go, even when the one asking is over
    // its share too; nobody within their share is asked.
    session_memory::configure(8 * 1024 * 1024, 4).unwrap();
    let (small, modest, open_modest) = in_session(|| vec![0u8; 512 * 1024]);
    let (large, greedy, open_greedy) = in_session(|| vec![0u8; 5 * 1024 * 1024]);
    let refusals = session_memory::pool_refusals();
    let (more, asker, open_asker) = in_session(|| vec![0u8; 4 * 1024 * 1024 + 512 * 1024]);
    assert!(
        session_memory::pool_refusals() > refusals,
        "the pool ran out"
    );
    assert!(greedy.is_over(), "the largest over its fair share lets go");
    assert!(
        !asker.is_over(),
        "the asker, over its share but not the largest, is not"
    );
    assert!(
        !modest.is_over(),
        "a session within its share is left alone"
    );
    // While the one asked is still giving its room back, nobody else is asked. A session refused
    // room past its share meanwhile has its line stopped, and after the line ends unless it is
    // back within its reservation or its share.
    let line_past_share = |keep: bool| {
        move || {
            let line = vec![0u8; 3 * 1024 * 1024];
            let stopped = session_memory::current_over();
            (keep.then_some(line), stopped)
        }
    };
    let ((late, stopped), latecomer, open_late) = in_session(line_past_share(true));
    assert!(
        !asker.is_over() && !latecomer.is_over(),
        "no second session is asked while room is on its way back"
    );
    assert!(stopped, "the latecomer's line was stopped");
    let ((_, stopped), shrank, open_shrank) = in_session(line_past_share(false));
    assert!(stopped, "this line was stopped too");
    assert!(
        !shrank.check_retained(),
        "back within its share after the line, it carries on"
    );
    assert!(
        latecomer.check_retained(),
        "still past its reservation and its share after the line, it ends"
    );
    drop((small, large, more, late));
    drop((open_modest, open_greedy, open_asker, open_late, open_shrank));

    // A newcomer that holds nothing yet still counts toward the share: two sessions that each
    // hold half of a 4 MiB pool for four are over a third of it once a third session asks.
    session_memory::configure(4 * 1024 * 1024, 4).unwrap();
    let (a_buf, a, open_a) = in_session(|| vec![0u8; 1900 * 1024]);
    let (b_buf, b, open_b) = in_session(|| vec![0u8; 1800 * 1024]);
    let refusals = session_memory::pool_refusals();
    let (c_buf, c, open_c) = in_session(|| vec![0u8; 900 * 1024]);
    assert!(
        session_memory::pool_refusals() > refusals,
        "the pool ran out"
    );
    assert!(
        a.is_over() && !b.is_over(),
        "the largest past a third is asked"
    );
    assert!(!c.is_over(), "the newcomer within its floor is not");
    drop((a_buf, b_buf, c_buf, open_a, open_b, open_c));

    // Sessions within their share take what they are owed even when the pool is short, so the
    // pool counts every byte they hold; then, while it is over its ceiling, the sessions over
    // their shares are asked one at a time until it is paid back, allocating or not.
    session_memory::configure(8 * 1024 * 1024, 4).unwrap();
    let mut hogs: Vec<_> = (0..3)
        .map(|_| in_session(|| vec![0u8; 2600 * 1024]))
        .collect();
    let owed: Vec<_> = (0..2)
        .map(|_| in_session(|| vec![0u8; 1900 * 1024]))
        .collect();
    assert!(
        session_memory::pool_used() > 8 * 1024 * 1024 + 3 * 1024 * 1024,
        "what the sessions within their shares hold is counted: {}",
        session_memory::pool_used()
    );
    for round in 0..2 {
        session_memory::rebalance();
        let asked: Vec<_> = (0..hogs.len()).filter(|&i| hogs[i].1.is_over()).collect();
        assert_eq!(
            asked.len(),
            1,
            "round {round}: one session over its share is asked"
        );
        drop(hogs.remove(asked[0]));
    }
    session_memory::rebalance();
    assert!(
        session_memory::pool_used() <= 8 * 1024 * 1024,
        "paid back: {}",
        session_memory::pool_used()
    );
    assert!(
        !hogs[0].1.is_over() && owed.iter().all(|(_, account, _)| !account.is_over()),
        "once it is paid back nobody else is asked, and never a session within its share"
    );
    drop((hogs, owed));

    // What is owed is the floor, not the share: a session past its floor but within its share
    // takes nothing past the ceiling while the pool is short, and its line stops.
    let (hog_buf, _, open_hog) = in_session(|| vec![0u8; 6 * 1024 * 1024]);
    let ((past_floor, stopped), _, open_past) = in_session(|| {
        let line = vec![0u8; 3 * 1024 * 1024];
        (line, session_memory::current_over())
    });
    assert!(stopped, "its line was stopped");
    assert!(
        session_memory::pool_used() <= 8 * 1024 * 1024,
        "nothing past the floor was taken past the ceiling: {}",
        session_memory::pool_used()
    );
    drop((hog_buf, past_floor, open_hog, open_past));

    // Sessions at their floor are never asked, even when what ended sessions left behind leaves
    // the pool short of all of them: the last to ask is refused room, and nobody is ended.
    let (left, _, ended) = in_session(|| vec![0u8; 256 * 1024]);
    drop(ended);
    session_memory::configure(4 * 1024 * 1024, 4).unwrap();
    let at_floor = || vec![0u8; 1024 * 1024 - 16];
    let refusals = session_memory::pool_refusals();
    let sessions: Vec<_> = (0..4).map(|_| in_session(at_floor)).collect();
    assert!(
        session_memory::pool_refusals() > refusals,
        "the pool ran out"
    );
    assert!(
        sessions.iter().all(|(_, account, _)| !account.is_over()),
        "no session at its floor was asked to let go"
    );
    drop((sessions, left));

    // Many sessions refused at once on different threads: the pool asks one at a time, and once
    // they have ended it asks again.
    session_memory::configure(8 * 1024 * 1024, 16).unwrap();
    let barrier = std::sync::Barrier::new(8);
    std::thread::scope(|threads| {
        for _ in 0..8 {
            threads.spawn(|| {
                barrier.wait();
                let (buf, _, open) = in_session(|| vec![0u8; 3 * 1024 * 1024]);
                barrier.wait();
                drop((buf, open));
            });
        }
    });
    let (big_buf, big, open_big) = in_session(|| vec![0u8; 6 * 1024 * 1024]);
    let (ask_buf, _, open_ask) = in_session(|| vec![0u8; 3 * 1024 * 1024]);
    assert!(
        big.is_over(),
        "after the storm the pool still asks the largest past its share"
    );
    drop((big_buf, ask_buf, open_big, open_ask));
    session_memory::configure(u64::MAX / 2, 256).unwrap();

    // Frees on other threads racing their session's end leave the pool exactly where it was: each
    // lands on the session or on the orphan, never half on each.
    let before = session_memory::pool_used();
    for _ in 0..50 {
        let (parts, _, open) = in_session(|| {
            (0..4)
                .map(|_| (0..16).map(|_| vec![0u8; 4096]).collect::<Vec<_>>())
                .collect::<Vec<_>>()
        });
        std::thread::scope(|threads| {
            for part in parts {
                threads.spawn(move || drop(part));
            }
            drop(open);
        });
    }
    assert_eq!(
        session_memory::pool_used(),
        before,
        "frees racing their session's end moved the pool"
    );

    // What an ended session left allocated counts against the pool as its orphan, and the slot is
    // free at once; freeing what it left refunds the orphan.
    let before = session_memory::pool_used();
    let (leftover, ended, open) = in_session(|| vec![9u8; 64 * 1024]);
    drop(open);
    assert_eq!(ended.live(), 0, "the session is gone");
    let orphan = session_memory::pool_used();
    assert!(
        orphan >= before + 64 * 1024,
        "what it left is the orphan: {orphan}"
    );
    drop(leftover);
    assert!(
        session_memory::pool_used() < orphan,
        "freeing it refunds the orphan"
    );
    // Every slot comes back: after twice as many sessions as there are slots, a new one still
    // gets a slot (`in_session` fails without one).
    for _ in 0..2 * SLOT_COUNT {
        drop(Box::pin(session_memory::scope(std::future::ready(()))));
    }
    let ((), _, open) = in_session(|| ());
    drop(open);

    // A capture body is charged to the capture budget, not to the session that received it.
    let (body, account, open) = in_session(|| {
        let mut body = sensor_framework::CaptureBody::unbudgeted();
        body.extend_from_slice(&vec![5u8; 2 * 1024 * 1024]).unwrap();
        body
    });
    assert!(
        account.live() < 256 * 1024,
        "a 2 MiB capture is not the session's: {}",
        account.live()
    );
    drop((body, open));

    // A buffer handed to a budget of its own stops counting against its session, and freeing it
    // later takes nothing from the session either.
    let (kept, account, open) = in_session(|| {
        let mut queued = vec![1u8; 1024 * 1024];
        let charged = session_memory::current_account().unwrap().live();
        session_memory::disown(&mut queued);
        (queued, charged)
    });
    let (queued, charged) = kept;
    assert!(charged >= 1024 * 1024, "it was the session's: {charged}");
    assert!(
        account.live() < 64 * 1024,
        "and is not any more: {}",
        account.live()
    );
    let small = account.live();
    drop(queued);
    assert_eq!(
        account.live(),
        small,
        "freeing it takes nothing from the session"
    );
    drop(open);

    // A session whose state panics as it is dropped still gives its room back to the pool.
    struct PanicsOnDrop(#[allow(dead_code)] Vec<u8>);
    impl Drop for PanicsOnDrop {
        fn drop(&mut self) {
            panic!("a handler destructor panicked");
        }
    }
    type Outlives = std::sync::Mutex<Option<(Vec<u8>, AccountRef)>>;
    let outlives = std::sync::Arc::new(Outlives::default());
    let handed = outlives.clone();
    let before = session_memory::pool_used();
    let mut scoped = Box::pin(session_memory::scope(async move {
        let state = PanicsOnDrop(vec![3u8; 1024 * 1024]);
        // Something it made that outlives it, so the session still holds bytes when it ends.
        let account = session_memory::current_account().unwrap();
        *handed.lock().unwrap() = Some((vec![4u8; 256 * 1024], account));
        std::future::pending::<()>().await;
        drop(state);
    }));
    assert!(poll_once(scoped.as_mut()).is_pending());
    assert!(session_memory::pool_used() >= before + 1024 * 1024);
    let unwound = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| drop(scoped)));
    assert!(unwound.is_err(), "the destructor did panic");
    let (kept, account) = outlives.lock().unwrap().take().unwrap();
    assert_eq!(
        account.live(),
        0,
        "the session ended: its slot was released"
    );
    assert!(
        session_memory::pool_used() >= before + 256 * 1024,
        "what it left is the orphan's"
    );
    // The panic's payload was allocated inside the session, and is still live until here. What the
    // runtime keeps from its first panic stays counted, a few hundred bytes; a slot never released
    // would keep every chunk it reserved.
    drop((kept, unwound));
    assert!(
        session_memory::pool_used() < before + session_memory::CHUNK_BYTES,
        "its room returned: {} after {before}",
        session_memory::pool_used()
    );
}
