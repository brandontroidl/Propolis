//! What each client session of a shell sensor really holds on the heap, and the process-wide pool
//! those sessions share.
//!
//! A fake shell has many containers a client can grow (history, levels, variables, functions,
//! positional parameters, descriptors `exec` keeps open), and modelling each one missed some
//! every time it was reviewed. This counts allocations instead: [`AccountingAlloc`] tags every
//! allocation with the session it was made in, read from a thread-local that [`scope`] sets
//! around each poll of a session's future, and charges and refunds that session's slot. The
//! shell stops a line once its session is over a limit ([`current_over`]), and the sensor ends a
//! session the pool asks to let go ([`AccountRef::evicted`]).
//!
//! The allocator itself only touches atomics: it never allocates, locks or wakes a task. Waking
//! is [`watchdog`]'s, a task that runs outside every session.

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::future::Future;
use std::mem::ManuallyDrop;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicI64, AtomicU8, AtomicU64, Ordering};
use std::task::{Context, Poll};
use std::time::Duration;

use tokio::sync::Notify;

use crate::budget::LINE_WORKING_SET_BYTES;

/// Sessions with a slot at once. Above what every accounted sensor admits (256 for each shell
/// sensor; 1,024 for HTTP, 512 on each of its two listeners), and a slot is free again the moment
/// its session ends; [`configure`] refuses a sensor that admits more.
pub const SLOT_COUNT: usize = 2048;

/// Granularity at which a session reserves pool room.
pub const CHUNK_BYTES: u64 = 64 * 1024;

/// What a session may still hold once a line has finished, unless [`set_retained_limit`] says
/// otherwise.
pub const RETAINED_LIMIT_BYTES: u64 = 8 * 1024 * 1024;

/// What a session may hold while a line runs, at the default retained limit: that plus one line's
/// working set, which a line holds and gives back as it finishes.
pub const PEAK_LIMIT_BYTES: u64 = RETAINED_LIMIT_BYTES + LINE_WORKING_SET_BYTES;

/// The retained limit in force; the peak limit follows it.
static RETAINED_LIMIT: AtomicU64 = AtomicU64::new(RETAINED_LIMIT_BYTES);

/// Change what a session may keep between lines (and with it, what it may hold while a line
/// runs). The sensors use the default; tests set a small one to reach it quickly.
pub fn set_retained_limit(bytes: u64) {
    RETAINED_LIMIT.store(bytes, Ordering::Release);
}

fn retained_limit() -> u64 {
    RETAINED_LIMIT.load(Ordering::Acquire)
}

fn peak_limit() -> u64 {
    retained_limit().saturating_add(LINE_WORKING_SET_BYTES)
}

/// The least room [`configure`] accepts per admitted session.
const MIN_FLOOR_BYTES: u64 = 64 * 1024;

/// The session memory pool for a sensor whose unit has `unit_memory_max_bytes` of `MemoryMax`:
/// 30%, beside the capture budget's 40%. The rest is the runtime's, the allocator headers' and
/// the worker threads' line working sets.
pub const fn pool_bytes(unit_memory_max_bytes: u64) -> u64 {
    unit_memory_max_bytes / 10 * 3
}

/// [`pool_bytes`] for the 256 MiB units (telnet, ADB).
pub const DEFAULT_POOL_BYTES_256M: u64 = pool_bytes(256 * 1024 * 1024);

/// How often [`watchdog`] wakes sessions that were asked to let go.
const WATCHDOG_INTERVAL: Duration = Duration::from_millis(200);

const FREE: u8 = 0;
const ACTIVE: u8 = 1;

/// A slot's live bytes and generation share one word, so a free either finds the session it was
/// charged to or sees that session ended and its bytes became the orphan, never half of each.
/// 16 GiB of live bytes, far above any unit's `MemoryMax`; 30 bits of generation, so a slot
/// wraps after a billion sessions, not the sixteen million a busy sensor reaches in months.
const LIVE_BITS: u32 = 34;
const LIVE_MASK: u64 = (1 << LIVE_BITS) - 1;
const GENERATION_MASK: u64 = (1 << (64 - LIVE_BITS)) - 1;

fn live_of(word: u64) -> u64 {
    word & LIVE_MASK
}

fn generation_of(word: u64) -> u64 {
    word >> LIVE_BITS
}

struct Slot {
    /// Generation in the high bits, bumped when the session ends; live bytes in the low.
    word: AtomicU64,
    state: AtomicU8,
    held: AtomicU64,
    /// Over its peak or retained limit: the session ends.
    over: AtomicBool,
    /// The pool refused it room while it was over its floor: the running line stops, and the
    /// session ends after it unless it is back within its reservation or its share.
    refused: AtomicBool,
    notify: Notify,
}

impl Slot {
    const fn new() -> Self {
        Self {
            word: AtomicU64::new(0),
            state: AtomicU8::new(FREE),
            held: AtomicU64::new(0),
            over: AtomicBool::new(false),
            refused: AtomicBool::new(false),
            notify: Notify::const_new(),
        }
    }

    fn live(&self) -> u64 {
        live_of(self.word.load(Ordering::Acquire))
    }
}

/// Slot 0 is never claimed: a tag of 0 means unaccounted.
static SLOTS: [Slot; SLOT_COUNT] = [const { Slot::new() }; SLOT_COUNT];

struct Pool {
    ceiling: AtomicU64,
    reserved: AtomicU64,
    /// What ended sessions left allocated: counted against the pool until it is freed. Signed: a
    /// free racing its session's end can reach it first.
    orphan: AtomicI64,
    floor: AtomicU64,
    /// The one session asked to let go, as its tag; 0 when none is. No other is asked until it
    /// ends, so its room is not counted twice.
    asked: AtomicU64,
    refused: AtomicU64,
}

static POOL: Pool = Pool {
    ceiling: AtomicU64::new(u64::MAX),
    reserved: AtomicU64::new(0),
    orphan: AtomicI64::new(0),
    floor: AtomicU64::new(u64::MAX),
    asked: AtomicU64::new(0),
    refused: AtomicU64::new(0),
};

thread_local! {
    /// The session the running code belongs to, as a tag: slot in the high half, generation in
    /// the low. Const-initialised and without a destructor, so the allocator can read it at any
    /// point of a thread's life.
    static CURRENT: Cell<u64> = const { Cell::new(0) };
}

const _: () = assert!(!std::mem::needs_drop::<Cell<u64>>());

fn current_tag() -> u64 {
    CURRENT.try_with(Cell::get).unwrap_or(0)
}

fn set_current(tag: u64) -> u64 {
    CURRENT.try_with(|c| c.replace(tag)).unwrap_or(0)
}

fn tag_of(slot: usize, generation: u64) -> u64 {
    ((slot as u64) << 32) | (generation & GENERATION_MASK)
}

fn split(tag: u64) -> (usize, u64) {
    ((tag >> 32) as usize, tag & 0xffff_ffff)
}

/// The slot `tag` still names, or `None` once that session ended.
fn slot_of(tag: u64) -> Option<&'static Slot> {
    let (index, generation) = split(tag);
    if index == 0 {
        return None;
    }
    let slot = SLOTS.get(index)?;
    (generation_of(slot.word.load(Ordering::Acquire)) == generation).then_some(slot)
}

/// Set the pool every session shares: `ceiling` bytes, for at most `max_concurrent` sessions at
/// once. A session never holding more than `ceiling / max_concurrent` is never asked to let go,
/// so all of them together fit. Errors when that share is too small to be useful or the table
/// cannot hold that many sessions.
pub fn configure(ceiling: u64, max_concurrent: u32) -> Result<(), String> {
    let sessions = u64::from(max_concurrent.max(1));
    if sessions >= SLOT_COUNT as u64 {
        return Err(format!(
            "max_concurrent {max_concurrent} exceeds the {} session memory slots",
            SLOT_COUNT - 1
        ));
    }
    let floor = ceiling / sessions;
    if floor < MIN_FLOOR_BYTES {
        return Err(format!(
            "session memory pool of {ceiling} bytes leaves {floor} per session, under {MIN_FLOOR_BYTES}"
        ));
    }
    POOL.ceiling.store(ceiling, Ordering::Release);
    POOL.floor.store(floor, Ordering::Release);
    Ok(())
}

/// Whether a sensor configured the pool: its sessions must then be accounted.
pub fn is_configured() -> bool {
    POOL.ceiling.load(Ordering::Acquire) != u64::MAX
}

/// Bytes the pool lends out at most.
pub fn pool_ceiling() -> u64 {
    POOL.ceiling.load(Ordering::Acquire)
}

fn orphan_bytes() -> u64 {
    POOL.orphan.load(Ordering::Acquire).max(0) as u64
}

/// Bytes sessions have reserved from the pool, plus what ended sessions left behind.
pub fn pool_used() -> u64 {
    POOL.reserved
        .load(Ordering::Acquire)
        .saturating_add(orphan_bytes())
}

/// Room the pool has left.
pub fn pool_free() -> u64 {
    pool_ceiling().saturating_sub(pool_used())
}

/// Times a session asked the pool for room it did not have.
pub fn pool_refusals() -> u64 {
    POOL.refused.load(Ordering::Relaxed)
}

fn pool_try_reserve(bytes: u64) -> bool {
    let limit = POOL
        .ceiling
        .load(Ordering::Acquire)
        .saturating_sub(orphan_bytes());
    POOL.reserved
        .fetch_update(Ordering::AcqRel, Ordering::Acquire, |reserved| {
            reserved.checked_add(bytes).filter(|next| *next <= limit)
        })
        .is_ok()
}

fn saturating_sub_atomic(counter: &AtomicU64, bytes: u64) -> u64 {
    counter
        .fetch_update(Ordering::AcqRel, Ordering::Acquire, |v| {
            Some(v.saturating_sub(bytes))
        })
        .unwrap_or_else(|v| v)
}

fn round_up_chunks(bytes: u64) -> u64 {
    bytes.div_ceil(CHUNK_BYTES).saturating_mul(CHUNK_BYTES)
}

/// A session's fair share of the pool: the pool divided among the sessions running, a newcomer
/// that holds nothing yet included, never under the floor that every admitted session can hold
/// at once.
fn fair_share() -> u64 {
    let sessions = SLOTS
        .iter()
        .skip(1)
        .filter(|slot| slot.state.load(Ordering::Acquire) == ACTIVE)
        .count() as u64;
    let share = POOL
        .ceiling
        .load(Ordering::Acquire)
        .saturating_sub(orphan_bytes())
        / sessions.max(1);
    share.max(POOL.floor.load(Ordering::Acquire))
}

/// Whether the session `tag` names must end: over a limit, or the session the pool asked.
fn is_asked(slot: &Slot, tag: u64) -> bool {
    slot.over.load(Ordering::Acquire) || POOL.asked.load(Ordering::Acquire) == tag
}

/// Unless a session asked earlier is still ending, ask the one holding the most over `fair` to
/// let go. Sessions at or under their share are never asked.
fn ask_one(fair: u64) {
    let asked = POOL.asked.load(Ordering::Acquire);
    if asked != 0 {
        if slot_of(asked).is_some() {
            return;
        }
        // It ended without clearing the mark (it was asked after its release had looked).
        let _ = POOL
            .asked
            .compare_exchange(asked, 0, Ordering::AcqRel, Ordering::Acquire);
    }
    let victim = SLOTS
        .iter()
        .enumerate()
        .skip(1)
        .filter_map(|(index, slot)| {
            let word = slot.word.load(Ordering::Acquire);
            (slot.state.load(Ordering::Acquire) == ACTIVE
                && !slot.over.load(Ordering::Acquire)
                && live_of(word) > fair)
                .then(|| (live_of(word), tag_of(index, generation_of(word))))
        })
        .max_by_key(|(live, _)| *live);
    if let Some((_, tag)) = victim {
        // Another refusal may have asked one in the meantime; then that one stands.
        let _ = POOL
            .asked
            .compare_exchange(0, tag, Ordering::AcqRel, Ordering::Acquire);
    }
}

/// While sessions really hold more than the pool (what they took within their floors while it was
/// short), ask the next session over its share to let go. [`watchdog`] runs this every tick, so
/// the pool comes back under its ceiling even when nobody allocates, as long as some session is
/// over its share. Counted by live bytes, not reserved chunks, so rounding alone ends nobody.
pub fn rebalance() {
    let live: u64 = SLOTS
        .iter()
        .skip(1)
        .filter(|slot| slot.state.load(Ordering::Acquire) == ACTIVE)
        .map(Slot::live)
        .sum();
    if live.saturating_add(orphan_bytes()) > pool_ceiling() {
        ask_one(fair_share());
    }
}

/// Runs only on the session's own thread, so never alongside its release.
fn charge(tag: u64, bytes: u64) {
    let Some(slot) = slot_of(tag) else {
        return;
    };
    // Saturates rather than carry into the generation; a session that big is over anyway.
    let before = slot
        .word
        .fetch_update(Ordering::AcqRel, Ordering::Acquire, |word| {
            Some(if live_of(word).saturating_add(bytes) > LIVE_MASK {
                word | LIVE_MASK
            } else {
                word + bytes
            })
        })
        .unwrap_or_else(|word| word);
    let live = live_of(before).saturating_add(bytes);
    if live > peak_limit() {
        slot.over.store(true, Ordering::Release);
    }
    // A session about to end does not ask the pool again.
    if is_asked(slot, tag) {
        return;
    }
    let held = slot.held.load(Ordering::Acquire);
    if live <= held {
        return;
    }
    let need = round_up_chunks(live - held);
    if pool_try_reserve(need) {
        slot.held.fetch_add(need, Ordering::AcqRel);
        return;
    }
    // A session already stopped for this line asks nothing more of the pool until the line ends.
    if slot.refused.load(Ordering::Acquire) {
        return;
    }
    POOL.refused.fetch_add(1, Ordering::Relaxed);
    if live > POOL.floor.load(Ordering::Acquire) {
        // Past its floor it takes no more while the pool is short: its line stops (and after the
        // line it ends only if it is past its share too).
        slot.refused.store(true, Ordering::Release);
    } else {
        // Within its floor it is owed the room: it takes it, and the pool, now over its ceiling,
        // asks sessions over their shares to let go until that is paid back. Floors add up to
        // the pool, so what is taken this way is at most the pool again.
        POOL.reserved.fetch_add(need, Ordering::AcqRel);
        slot.held.fetch_add(need, Ordering::AcqRel);
    }
    ask_one(fair_share());
}

fn refund(tag: u64, bytes: u64) {
    let (index, generation) = split(tag);
    if index == 0 {
        return;
    }
    let Some(slot) = SLOTS.get(index) else {
        return;
    };
    let updated = slot
        .word
        .fetch_update(Ordering::AcqRel, Ordering::Acquire, |word| {
            (generation_of(word) == generation).then(|| word - live_of(word).min(bytes))
        });
    let Ok(before) = updated else {
        // The session ended: what it left is the orphan's.
        POOL.orphan.fetch_sub(bytes as i64, Ordering::AcqRel);
        return;
    };
    // Only the session's own thread gives reserved room back: there it never races the session's
    // charges or its release, so it never shrinks another session's reservation after the slot is
    // reused. A free elsewhere leaves the room reserved until the next one here, or the end.
    if current_tag() != tag {
        return;
    }
    let live = live_of(before).saturating_sub(bytes);
    let held = slot.held.load(Ordering::Acquire);
    let keep = round_up_chunks(live);
    // One chunk of slack, so a session at a chunk boundary does not reserve and return the same
    // chunk on every allocation.
    if held > keep.saturating_add(CHUNK_BYTES) {
        slot.held.store(keep, Ordering::Release);
        saturating_sub_atomic(&POOL.reserved, held - keep);
    }
}

/// The global allocator of a sensor whose sessions are accounted. Every allocation carries a
/// tag of the session it was made in, just before the pointer it returns.
pub struct AccountingAlloc;

/// The layout handed to `System` and where the caller's bytes start in it: the header takes
/// `max(16, align)` bytes, so the returned pointer keeps the caller's alignment and the tag sits
/// in the 8 bytes just before it.
fn outer(layout: Layout) -> Option<(Layout, usize)> {
    let align = layout.align().max(16);
    let size = layout.size().checked_add(align)?;
    Layout::from_size_align(size, align)
        .ok()
        .map(|l| (l, align))
}

/// SAFETY: `user` is a pointer this allocator returned, so the 8 bytes before it are its header.
unsafe fn read_tag(user: *mut u8) -> u64 {
    unsafe { user.sub(8).cast::<u64>().read() }
}

/// SAFETY: as [`read_tag`], for a pointer being returned.
unsafe fn write_tag(user: *mut u8, tag: u64) {
    unsafe { user.sub(8).cast::<u64>().write(tag) }
}

// SAFETY: every method forwards to `System` with a layout that only adds a header in front of the
// caller's bytes, and returns the caller's part of it, aligned as asked.
unsafe impl GlobalAlloc for AccountingAlloc {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let Some((outer, offset)) = outer(layout) else {
            return std::ptr::null_mut();
        };
        let base = unsafe { System.alloc(outer) };
        if base.is_null() {
            return base;
        }
        let user = unsafe { base.add(offset) };
        let tag = current_tag();
        unsafe { write_tag(user, tag) };
        charge(tag, outer.size() as u64);
        user
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        let Some((outer, offset)) = outer(layout) else {
            return std::ptr::null_mut();
        };
        let base = unsafe { System.alloc_zeroed(outer) };
        if base.is_null() {
            return base;
        }
        let user = unsafe { base.add(offset) };
        let tag = current_tag();
        unsafe { write_tag(user, tag) };
        charge(tag, outer.size() as u64);
        user
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        let Some((outer, offset)) = outer(layout) else {
            return;
        };
        let tag = unsafe { read_tag(ptr) };
        refund(tag, outer.size() as u64);
        unsafe { System.dealloc(ptr.sub(offset), outer) };
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        let Some((old, offset)) = outer(layout) else {
            return std::ptr::null_mut();
        };
        let Some(new) = Layout::from_size_align(new_size, layout.align())
            .ok()
            .and_then(outer)
        else {
            return std::ptr::null_mut();
        };
        let tag = unsafe { read_tag(ptr) };
        let base = unsafe { System.realloc(ptr.sub(offset), old, new.0.size()) };
        if base.is_null() {
            return base;
        }
        // The growth belongs to whoever grows it: a structure shared between sessions does not
        // stay charged to the first that touched it.
        refund(tag, old.size() as u64);
        let user = unsafe { base.add(offset) };
        let now = current_tag();
        unsafe { write_tag(user, now) };
        charge(now, new.0.size() as u64);
        user
    }
}

/// Stop charging `buf` to the running session: for a buffer handed to a budget of its own (the
/// SSH output queue), so it is not counted twice. The bytes move to an allocation made outside
/// every session, and the original's free refunds whoever it was charged to.
pub fn disown(buf: &mut Vec<u8>) {
    if buf.capacity() == 0 {
        return;
    }
    let unowned = unaccounted(|| buf.to_vec());
    *buf = unowned;
}

/// Puts the previous tag back when dropped, a panic included, so a session's tag never outlives
/// its poll on a worker thread.
struct Enter {
    previous: u64,
}

impl Enter {
    fn new(tag: u64) -> Self {
        Self {
            previous: set_current(tag),
        }
    }
}

impl Drop for Enter {
    fn drop(&mut self) {
        set_current(self.previous);
    }
}

/// Releases a session's slot when dropped, a panic in its handler's destructors included.
struct Release(u64);

impl Drop for Release {
    fn drop(&mut self) {
        release(self.0);
    }
}

/// Claim a free slot for a new session. Slots in use never exceed the sensors' `max_concurrent`,
/// under [`SLOT_COUNT`], so one is free unless another thread just took it: try again.
fn claim() -> u64 {
    for _ in 0..SLOT_COUNT {
        let found = SLOTS.iter().enumerate().skip(1).find_map(|(index, slot)| {
            slot.state
                .compare_exchange(FREE, ACTIVE, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
                .then_some(index)
        });
        if let Some(index) = found {
            let slot = &SLOTS[index];
            slot.held.store(0, Ordering::Release);
            slot.over.store(false, Ordering::Release);
            slot.refused.store(false, Ordering::Release);
            let generation = generation_of(slot.word.load(Ordering::Acquire));
            return tag_of(index, generation);
        }
    }
    0
}

/// The session ended: give back its reserved room, count what it left allocated as the pool's
/// orphan, and free its slot. Frees of what it left then refund the orphan.
fn release(tag: u64) {
    let Some(slot) = slot_of(tag) else {
        return;
    };
    let held = slot.held.swap(0, Ordering::AcqRel);
    saturating_sub_atomic(&POOL.reserved, held);
    // One step moves its bytes to the orphan and ends its generation: a free racing it lands
    // wholly before (charged to the session, so counted here) or wholly after (the orphan's).
    let next = ((split(tag).1 + 1) & GENERATION_MASK) << LIVE_BITS;
    let left = live_of(slot.word.swap(next, Ordering::AcqRel));
    POOL.orphan.fetch_add(left as i64, Ordering::AcqRel);
    let _ = POOL
        .asked
        .compare_exchange(tag, 0, Ordering::AcqRel, Ordering::Acquire);
    slot.over.store(false, Ordering::Release);
    slot.refused.store(false, Ordering::Release);
    slot.state.store(FREE, Ordering::Release);
}

/// `fut` run as one accounted session, with a slot of its own: what it allocates while polled,
/// and while dropped, is charged to that slot, which is released when it is dropped. Without
/// [`AccountingAlloc`] installed nothing is charged.
pub fn scope<F: Future>(fut: F) -> Scoped<F> {
    let tag = claim();
    if tag == 0 {
        tracing::error!("session memory: no slot is free; the sensor refuses this session");
    }
    Scoped {
        tag,
        inner: ManuallyDrop::new(fut),
    }
}

/// See [`scope`].
pub struct Scoped<F> {
    tag: u64,
    inner: ManuallyDrop<F>,
}

impl<F: Future> Future for Scoped<F> {
    type Output = F::Output;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<F::Output> {
        // SAFETY: `inner` is never moved out of a pinned `Scoped`; it is only dropped in place.
        let this = unsafe { self.get_unchecked_mut() };
        let _enter = Enter::new(this.tag);
        // SAFETY: as above, `inner` stays where it was pinned.
        unsafe { Pin::new_unchecked(&mut *this.inner) }.poll(cx)
    }
}

impl<F> Drop for Scoped<F> {
    fn drop(&mut self) {
        // Declared first, dropped last: the slot is released after the guard below restores the
        // thread's tag, even when a destructor in the handler panics.
        let _release = Release(self.tag);
        let _enter = Enter::new(self.tag);
        // SAFETY: dropped once, here, and never used again.
        unsafe { ManuallyDrop::drop(&mut self.inner) };
    }
}

/// The session the running code belongs to, if it is accounted.
pub fn current_account() -> Option<AccountRef> {
    let tag = current_tag();
    slot_of(tag).map(|_| AccountRef { tag })
}

/// Whether the session should not run at all: the sensor accounts sessions and this one could not
/// get a slot. A sensor ends such a session at once rather than let it run unbounded.
pub fn unaccounted_session() -> bool {
    is_configured() && current_account().is_none()
}

/// Whether the running line must stop: its session is over a limit, was asked to let go, or was
/// refused room while over its floor. False outside an accounted session.
pub fn current_over() -> bool {
    let tag = current_tag();
    slot_of(tag).is_some_and(|slot| is_asked(slot, tag) || slot.refused.load(Ordering::Acquire))
}

/// Resolves once `account` is over; never when there is no account (the sensor does not
/// account sessions). For a session loop's `select!` against its next read.
pub async fn evicted(account: Option<AccountRef>) {
    match account {
        Some(account) => account.evicted().await,
        None => std::future::pending().await,
    }
}

/// Run `f` with no session current: what it allocates is charged to nobody. For memory another
/// budget already charges (capture bodies), so it is not counted twice.
pub fn unaccounted<R>(f: impl FnOnce() -> R) -> R {
    let _enter = Enter::new(0);
    f()
}

/// One accounted session, for the sensor that runs it.
#[derive(Debug, Clone, Copy)]
pub struct AccountRef {
    tag: u64,
}

impl AccountRef {
    /// Bytes the session holds now, headers included.
    pub fn live(&self) -> u64 {
        slot_of(self.tag).map_or(0, Slot::live)
    }

    /// Whether the session must end: over a limit, or asked by the pool to let go.
    pub fn is_over(&self) -> bool {
        slot_of(self.tag).is_some_and(|slot| is_asked(slot, self.tag))
    }

    /// Between lines: mark the session over when it holds more than the retained limit, or, once
    /// the pool refused it room past its floor, more than both its reservation and its share.
    /// True when it must end, for whatever reason.
    pub fn check_retained(&self) -> bool {
        let Some(slot) = slot_of(self.tag) else {
            return false;
        };
        let live = slot.live();
        if live > retained_limit() {
            slot.over.store(true, Ordering::Release);
        }
        if slot.refused.swap(false, Ordering::AcqRel)
            && live > slot.held.load(Ordering::Acquire).max(fair_share())
        {
            slot.over.store(true, Ordering::Release);
        }
        is_asked(slot, self.tag)
    }

    /// Resolves once the session must end. [`watchdog`] wakes it; a session that never must end
    /// never resolves.
    pub async fn evicted(&self) {
        let Some(slot) = slot_of(self.tag) else {
            return std::future::pending().await;
        };
        loop {
            let woken = slot.notify.notified();
            tokio::pin!(woken);
            woken.as_mut().enable();
            if is_asked(slot, self.tag) {
                return;
            }
            woken.await;
        }
    }
}

/// Every [`WATCHDOG_INTERVAL`] until the runtime stops: [`rebalance`] the pool, and wake every
/// session that must end. Spawn once per process, outside any session.
pub async fn watchdog() {
    let mut tick = tokio::time::interval(WATCHDOG_INTERVAL);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        tick.tick().await;
        rebalance();
        if let Some(slot) = slot_of(POOL.asked.load(Ordering::Acquire)) {
            slot.notify.notify_waiters();
        }
        for slot in SLOTS.iter().skip(1) {
            if slot.state.load(Ordering::Acquire) == ACTIVE && slot.over.load(Ordering::Acquire) {
                slot.notify.notify_waiters();
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_header_keeps_every_alignment_and_never_overflows() {
        for shift in 0..=12 {
            let align = 1usize << shift;
            let (outer, offset) = outer(Layout::from_size_align(24, align).unwrap()).unwrap();
            assert_eq!(offset, align.max(16), "align {align}");
            assert_eq!(outer.align(), align.max(16));
            assert_eq!(outer.size(), 24 + align.max(16));
            assert_eq!(
                offset % align,
                0,
                "the caller's pointer keeps align {align}"
            );
        }
        let huge = Layout::from_size_align(isize::MAX as usize - 8, 8).unwrap();
        assert!(
            outer(huge).is_none(),
            "a size the header would overflow is refused"
        );
    }

    #[test]
    fn tags_name_a_slot_and_a_generation() {
        let tag = tag_of(7, 0xbe_ef01);
        assert_eq!(split(tag), (7, 0xbe_ef01));
        assert!(slot_of(0).is_none(), "slot 0 is unaccounted");
        assert_eq!(
            split(tag_of(7, GENERATION_MASK + 5)).1,
            4,
            "generations wrap within the bits the slot word keeps"
        );
    }

    #[test]
    fn a_pool_too_small_for_its_sessions_is_refused() {
        assert!(configure(1024 * 1024, 256).is_err(), "4 KiB a session");
        assert!(
            configure(u64::MAX, SLOT_COUNT as u32).is_err(),
            "more sessions than slots"
        );
    }
}
