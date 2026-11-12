//! The memory a client's session can make the sensor hold, and the pool the sessions share.
//!
//! Two things in a session grow with what the client sends: the read buffer, which holds a
//! command whole until it is dispatched (up to the session's capture limit, about 1 MB), and the
//! SET store (up to 1 MiB). Each was bounded per session only, and 256 sessions per listener,
//! with the TLS listener's 256 on top, held more than the unit's `MemoryMax=256M`: the kernel
//! killed the sensor at about 230 filled sessions. Now each part is the session's own up to a
//! small floor, and every byte past it is charged to one pool for the whole process, both
//! listeners included. A buffer the pool cannot grow ends its session, as a real Redis closes a
//! client past its query buffer limit; a SET the pool cannot hold is refused with the OOM error,
//! as a real Redis refuses a write past `maxmemory`.
//!
//! What the sessions hold therefore never passes `POOL_BYTES` plus every session's floors,
//! whatever they send. The worst case against `MemoryMax` is worked through in
//! `docs/operations/capacity-planning.md` (the sensor-redis section).

use sensor_framework::{CaptureMemoryBudget, Reservation};

/// The pool every session's read buffer and store share past their floors. Attackers' observed
/// SET payloads are cron lines and keys under 1 KB, so this holds sixteen sessions at their
/// 1 MiB store limit, or a few thousand real-sized stores, while the worst case of every
/// admitted session stays a fraction of `MemoryMax`.
pub const POOL_BYTES: u64 = 16 * 1024 * 1024;

/// Read buffer capacity a session holds without drawing on the pool: room for any ordinary
/// command, so a full pool never stops a session from being read.
pub const BUFFER_FLOOR: usize = 16 * 1024;

/// Store bytes a session holds without drawing on the pool: a dozen or more real-sized SETs, so a
/// full pool never refuses an ordinary write.
pub const STORE_FLOOR: usize = 16 * 1024;

/// Room a stored key costs beyond its key and value bytes: the map's bucket for the two `Vec`
/// headers (48 bytes, with up to twice as many buckets as entries) and an allocator header for
/// each of the two allocations. Rounded up, so the charge does not fall short of the real one.
pub const ENTRY_OVERHEAD: usize = 160;

/// What one part of one session holds, charged to the pool past that part's floor. Dropping it
/// refunds the charge, so a session gives its room back however it ends: a closed socket, an
/// error, the duration limit dropping the session's future, or a panic unwinding it.
#[derive(Debug)]
pub struct Charge {
    floor: usize,
    reservation: Reservation,
}

impl Charge {
    pub fn new(pool: &CaptureMemoryBudget, floor: usize) -> Self {
        Self {
            floor,
            reservation: pool.empty_reservation(),
        }
    }

    /// Make the charge match a part now holding `bytes`. Shrinking always succeeds and refunds the
    /// difference; growing takes the difference from the pool, or returns false and changes
    /// nothing when the pool does not have it.
    pub fn set(&mut self, bytes: usize) -> bool {
        let want = bytes.saturating_sub(self.floor) as u64;
        let have = self.reservation.bytes();
        if want > have {
            return self.reservation.try_grow(want - have);
        }
        drop(self.reservation.split_off(have - want));
        true
    }

    /// Bytes this part has drawn from the pool.
    pub fn charged(&self) -> u64 {
        self.reservation.bytes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_part_within_its_floor_draws_nothing_and_past_it_draws_the_excess() {
        let pool = CaptureMemoryBudget::new(1000);
        let mut part = Charge::new(&pool, 100);
        assert!(part.set(100));
        assert_eq!((part.charged(), pool.current_bytes()), (0, 0));
        assert!(part.set(600));
        assert_eq!((part.charged(), pool.current_bytes()), (500, 500));
        assert!(part.set(250), "shrinking always succeeds");
        assert_eq!((part.charged(), pool.current_bytes()), (150, 150));
    }

    #[test]
    fn growth_the_pool_cannot_cover_is_refused_and_changes_nothing() {
        let pool = CaptureMemoryBudget::new(1000);
        let _other = pool.try_reserve(700).unwrap();
        let mut part = Charge::new(&pool, 100);
        assert!(part.set(400));
        assert!(!part.set(401), "301 past the floor, 300 free");
        assert_eq!((part.charged(), pool.current_bytes()), (300, 1000));
        assert!(part.set(50));
        assert_eq!(pool.current_bytes(), 700);
    }

    #[test]
    fn dropping_a_part_refunds_what_it_drew() {
        let pool = CaptureMemoryBudget::new(1000);
        let mut a = Charge::new(&pool, 10);
        let mut b = Charge::new(&pool, 10);
        assert!(a.set(510) && b.set(510));
        assert!(!Charge::new(&pool, 0).set(1), "the pool is full");
        drop(a);
        assert_eq!(pool.current_bytes(), 500);
        drop(b);
        assert_eq!(pool.current_bytes(), 0);
    }
}
