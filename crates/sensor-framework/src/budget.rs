//! Per-connection resource budgets for the fake shell. One [`ConnectionBudget`] belongs to one
//! connection and is shared by every [`crate::shell::FakeShell`] and [`crate::fakefs::FakeFs`] on
//! it (SSH shell and exec channels, ADB's streams, telnet's one shell), so opening more channels or
//! streams cannot multiply a ceiling. It holds counters only; the connection-level bounds in
//! [`crate::bounds::ConnectionBounds`] (duration, concurrency, captured bytes) stay where they are.
//!
//! The counters are atomics because the shells and filesystems that share a budget live across
//! `.await` points inside a spawned task, which needs `Send + Sync`. One task mutates a
//! connection's counters, so `Relaxed` ordering is enough: nothing infers cross-thread ordering
//! from them.
//!
//! Per-line work and recursion depth are line-scoped, so they live on the shell, not here.
#![deny(
    clippy::arithmetic_side_effects,
    clippy::unwrap_used,
    clippy::indexing_slicing
)]

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicU64, Ordering::Relaxed};

use crate::bounds::ConnectionBounds;
use crate::shell::MAX_COMMANDS_PER_SESSION;

/// The longest input line any transport buffers before flushing it to the shell; the resident cost
/// of one line is part of a connection's worst case.
pub const MAX_LINE_LEN: u64 = 8192;

/// Resident cost of one overlay node beyond its path: the node, its metadata and map bookkeeping.
/// A conservative constant, not a measurement. The path itself is charged to `owned_bytes`.
pub const NODE_FIXED_OVERHEAD: u64 = 64;

/// The ceilings one connection is held to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BudgetLimits {
    /// Materialized bytes of created or written overlay content (`Fill`/`Counter` blob pieces are
    /// O(1) and count zero) plus the path of every overlay node slot, which stays charged for the
    /// life of the slot. Variable values join this when the shell has variables.
    pub owned_bytes: u64,
    /// Created files, created directories and tombstones. A slot is never returned: a tombstone is
    /// a node.
    pub overlay_nodes: u64,
    /// `honeypot_command_exec` events for the connection, across every shell on it.
    pub command_events: u64,
    /// Distinct download URLs recorded for the connection.
    pub download_events: u64,
    /// Distinct download URLs recorded for one input line.
    pub download_per_line: u64,
    /// Cumulative wire bytes written to the peer. Streamed, so not resident.
    pub egress_bytes: u64,
    /// Steps plus bytes scanned or produced while running one input line, re-entry included.
    pub work_per_line: u64,
    /// Re-entrant dispatch depth (busybox applet, `sh -c`, and later script entries).
    pub max_depth: u32,
    /// Longest whole path a write may name.
    pub path_max: usize,
    /// Longest single path component a write may name.
    pub component_max: usize,
}

impl BudgetLimits {
    /// The limits every sensor runs with. Normal interactive sessions and every recorded loader
    /// session are far under each of them.
    pub const fn standard() -> Self {
        Self {
            owned_bytes: 196_608,
            overlay_nodes: 4_096,
            command_events: MAX_COMMANDS_PER_SESSION,
            download_events: 64,
            download_per_line: 8,
            egress_bytes: 16_777_216,
            work_per_line: 4_194_304,
            max_depth: 16,
            path_max: 4_096,
            component_max: 255,
        }
    }
}

impl Default for BudgetLimits {
    fn default() -> Self {
        Self::standard()
    }
}

/// The limits for one connection of a sensor running with `bounds`. Every limit is a fixed engine
/// constant today; the bounds are the interface a sensor-specific limit would come through, and
/// `max_concurrent` is what the per-connection product is checked against
/// (`tests/budget_product_test.rs`).
pub fn limits_from(_bounds: &ConnectionBounds) -> BudgetLimits {
    BudgetLimits::standard()
}

/// Why a charge was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BudgetError {
    /// `ENOSPC`: the cumulative total would pass the cap.
    NoSpace,
    /// `EFBIG`: one write is bigger than the whole cap.
    TooLarge,
    /// `ENAMETOOLONG`.
    NameTooLong,
}

/// The counter a refusal came from, for the line trace.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Resource {
    OwnedBytes,
    Nodes,
}

/// What cumulative egress says about the connection after a write.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EgressState {
    Ok,
    /// The cap is used up: the transport ends the session after the write it just made.
    Spent,
}

const REFUSED_NONE: u8 = 0;
const REFUSED_BYTES: u8 = 1;
const REFUSED_NODES: u8 = 2;

#[derive(Debug)]
pub struct ConnectionBudget {
    owned_bytes: AtomicU64,
    overlay_nodes: AtomicU64,
    command_events: AtomicU64,
    download_events: AtomicU64,
    egress_bytes: AtomicU64,
    /// One flood marker per connection, not per shell, so a connection that opens many channels
    /// cannot emit one per channel.
    command_cap_marked: AtomicBool,
    download_cap_marked: AtomicBool,
    /// The resource behind the most recent refusal, read back by the shell for its trace.
    last_refusal: AtomicU8,
    limits: BudgetLimits,
}

/// The filesystem-side counters of a budget at one moment, see [`ConnectionBudget::fs_counters`].
#[derive(Debug, Clone, Copy)]
pub(crate) struct FsCounters {
    owned_bytes: u64,
    overlay_nodes: u64,
    last_refusal: u8,
}

/// Take one unit from `counter` if it is under `limit`.
fn take_slot(counter: &AtomicU64, limit: u64) -> bool {
    counter
        .fetch_update(Relaxed, Relaxed, |used| {
            (used < limit).then(|| used.saturating_add(1))
        })
        .is_ok()
}

impl ConnectionBudget {
    pub fn new(limits: BudgetLimits) -> Arc<Self> {
        Arc::new(Self {
            owned_bytes: AtomicU64::new(0),
            overlay_nodes: AtomicU64::new(0),
            command_events: AtomicU64::new(0),
            download_events: AtomicU64::new(0),
            egress_bytes: AtomicU64::new(0),
            command_cap_marked: AtomicBool::new(false),
            download_cap_marked: AtomicBool::new(false),
            last_refusal: AtomicU8::new(REFUSED_NONE),
            limits,
        })
    }

    pub fn limits(&self) -> &BudgetLimits {
        &self.limits
    }

    /// Bytes currently charged to overlay content.
    pub fn owned_bytes_used(&self) -> u64 {
        self.owned_bytes.load(Relaxed)
    }

    /// Overlay node slots currently charged.
    pub fn overlay_nodes_used(&self) -> u64 {
        self.overlay_nodes.load(Relaxed)
    }

    /// Whether `path` is within the name limits. Pure: it charges nothing, so a refused name costs
    /// no node.
    pub fn check_name(&self, path: &str) -> Result<(), BudgetError> {
        let component_too_long = path
            .split('/')
            .any(|component| component.len() > self.limits.component_max);
        if path.len() > self.limits.path_max || component_too_long {
            Err(BudgetError::NameTooLong)
        } else {
            Ok(())
        }
    }

    /// Charge `add` bytes of new content.
    pub fn charge_bytes(&self, add: u64) -> Result<(), BudgetError> {
        self.replace_bytes(0, add)
    }

    /// Swap a node's `old` charged bytes for `new`, as one check against the cap: overwriting a
    /// big file with a smaller one needs no headroom. `TooLarge` when `new` alone is over the cap,
    /// `NoSpace` when the total would be.
    pub fn replace_bytes(&self, old: u64, new: u64) -> Result<(), BudgetError> {
        let cap = self.limits.owned_bytes;
        if new > cap {
            self.refuse(REFUSED_BYTES);
            return Err(BudgetError::TooLarge);
        }
        let result = self.owned_bytes.fetch_update(Relaxed, Relaxed, |used| {
            let next = used.saturating_sub(old).checked_add(new)?;
            (next <= cap).then_some(next)
        });
        if result.is_err() {
            self.refuse(REFUSED_BYTES);
            return Err(BudgetError::NoSpace);
        }
        Ok(())
    }

    /// Return bytes charged for content that no longer exists.
    pub fn refund_bytes(&self, sub: u64) {
        let _ = self
            .owned_bytes
            .fetch_update(Relaxed, Relaxed, |used| Some(used.saturating_sub(sub)));
    }

    /// Take one overlay node slot. Slots are never returned.
    pub fn charge_node(&self) -> Result<(), BudgetError> {
        if take_slot(&self.overlay_nodes, self.limits.overlay_nodes) {
            Ok(())
        } else {
            self.refuse(REFUSED_NODES);
            Err(BudgetError::NoSpace)
        }
    }

    /// Take a slot without checking the cap, for the tombstone a `rm` leaves. `rm` frees space on a
    /// real system and must not fail for want of it; the memory stays bounded because a tombstone
    /// is only made for a path that existed, and the persona snapshot is finite.
    pub fn charge_node_unchecked(&self) {
        let _ = self
            .overlay_nodes
            .fetch_update(Relaxed, Relaxed, |used| Some(used.saturating_add(1)));
    }

    /// Count one input line against the connection's command-event ceiling. False once the ceiling
    /// is reached; the count stops there.
    pub fn command_event_allowed(&self) -> bool {
        take_slot(&self.command_events, self.limits.command_events)
    }

    /// Count one distinct download URL against the connection's ceiling.
    pub fn download_allowed(&self) -> bool {
        take_slot(&self.download_events, self.limits.download_events)
    }

    /// True for the first caller only: the connection's one command-cap marker.
    pub fn claim_command_cap_marker(&self) -> bool {
        !self.command_cap_marked.swap(true, Relaxed)
    }

    /// True for the first caller only: the connection's one download-cap marker.
    pub fn claim_download_cap_marker(&self) -> bool {
        !self.download_cap_marked.swap(true, Relaxed)
    }

    /// Count `wire_bytes` just written to the peer (after ONLCR, the codec and any protocol
    /// framing the transport applies).
    pub fn charge_egress(&self, wire_bytes: u64) -> EgressState {
        let before = match self.egress_bytes.fetch_update(Relaxed, Relaxed, |used| {
            Some(used.saturating_add(wire_bytes))
        }) {
            Ok(previous) | Err(previous) => previous,
        };
        if before.saturating_add(wire_bytes) >= self.limits.egress_bytes {
            EgressState::Spent
        } else {
            EgressState::Ok
        }
    }

    /// The counter behind the most recent refusal, cleared by reading it.
    pub fn take_refusal(&self) -> Option<Resource> {
        match self.last_refusal.swap(REFUSED_NONE, Relaxed) {
            REFUSED_BYTES => Some(Resource::OwnedBytes),
            REFUSED_NODES => Some(Resource::Nodes),
            _ => None,
        }
    }

    fn refuse(&self, which: u8) {
        self.last_refusal.store(which, Relaxed);
    }

    /// The counters a filesystem write moves, for a shell line that is run and then rolled back
    /// (see `FakeFs::checkpoint`). The event and download counters are charged before a line runs
    /// and are not part of it.
    pub(crate) fn fs_counters(&self) -> FsCounters {
        FsCounters {
            owned_bytes: self.owned_bytes.load(Relaxed),
            overlay_nodes: self.overlay_nodes.load(Relaxed),
            last_refusal: self.last_refusal.load(Relaxed),
        }
    }

    /// Put back what [`Self::fs_counters`] read.
    pub(crate) fn restore_fs_counters(&self, saved: FsCounters) {
        self.owned_bytes.store(saved.owned_bytes, Relaxed);
        self.overlay_nodes.store(saved.overlay_nodes, Relaxed);
        self.last_refusal.store(saved.last_refusal, Relaxed);
    }

    /// The most memory this budget lets one connection hold: `owned_bytes` (content and node
    /// paths, both charged to it), a fixed slot per node, and one input line. Egress is excluded
    /// (streamed). The connection's captured bytes are governed separately by
    /// `ConnectionBounds::max_captured_bytes` and are not part of this figure.
    pub fn max_resident_bytes(&self) -> u64 {
        self.limits
            .owned_bytes
            .saturating_add(
                self.limits
                    .overlay_nodes
                    .saturating_mul(NODE_FIXED_OVERHEAD),
            )
            .saturating_add(MAX_LINE_LEN)
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::arithmetic_side_effects,
    clippy::indexing_slicing
)]
mod tests {
    use super::*;

    fn tiny() -> BudgetLimits {
        BudgetLimits {
            owned_bytes: 100,
            overlay_nodes: 3,
            command_events: 2,
            download_events: 2,
            egress_bytes: 50,
            ..BudgetLimits::standard()
        }
    }

    #[test]
    fn bytes_are_accepted_up_to_the_cap_and_refused_past_it() {
        let budget = ConnectionBudget::new(tiny());
        assert_eq!(budget.charge_bytes(60), Ok(()));
        assert_eq!(budget.charge_bytes(40), Ok(()), "exactly the cap fits");
        assert_eq!(budget.charge_bytes(1), Err(BudgetError::NoSpace));
        assert_eq!(budget.owned_bytes_used(), 100, "a refusal charges nothing");
        assert_eq!(budget.take_refusal(), Some(Resource::OwnedBytes));
        assert_eq!(budget.take_refusal(), None, "reading clears it");
    }

    #[test]
    fn one_write_over_the_whole_cap_is_too_large_not_no_space() {
        let budget = ConnectionBudget::new(tiny());
        assert_eq!(budget.charge_bytes(101), Err(BudgetError::TooLarge));
        assert_eq!(
            budget.charge_bytes(100),
            Ok(()),
            "the cap itself is allowed"
        );
        assert_eq!(budget.owned_bytes_used(), 100);
    }

    #[test]
    fn replacing_content_charges_only_the_difference() {
        let budget = ConnectionBudget::new(tiny());
        budget.charge_bytes(90).unwrap();
        assert_eq!(
            budget.replace_bytes(90, 100),
            Ok(()),
            "growing by 10 fits under 100"
        );
        assert_eq!(
            budget.replace_bytes(100, 20),
            Ok(()),
            "shrinking needs no room"
        );
        assert_eq!(budget.owned_bytes_used(), 20);
        budget.refund_bytes(500);
        assert_eq!(budget.owned_bytes_used(), 0, "a refund never underflows");
    }

    #[test]
    fn nodes_are_never_returned() {
        let budget = ConnectionBudget::new(tiny());
        for _ in 0..3 {
            assert_eq!(budget.charge_node(), Ok(()));
        }
        assert_eq!(budget.charge_node(), Err(BudgetError::NoSpace));
        assert_eq!(budget.take_refusal(), Some(Resource::Nodes));
        budget.charge_node_unchecked();
        assert_eq!(
            budget.overlay_nodes_used(),
            4,
            "an unchecked slot still counts"
        );
    }

    #[test]
    fn the_command_and_download_ceilings_count_up_to_their_limit() {
        let budget = ConnectionBudget::new(tiny());
        assert!(budget.command_event_allowed() && budget.command_event_allowed());
        assert!(!budget.command_event_allowed());
        assert!(budget.download_allowed() && budget.download_allowed());
        assert!(!budget.download_allowed());
    }

    #[test]
    fn each_flood_marker_is_claimed_once() {
        let budget = ConnectionBudget::new(tiny());
        assert!(budget.claim_command_cap_marker());
        assert!(!budget.claim_command_cap_marker());
        assert!(budget.claim_download_cap_marker());
        assert!(!budget.claim_download_cap_marker());
    }

    #[test]
    fn egress_is_spent_on_the_write_that_reaches_the_cap() {
        let budget = ConnectionBudget::new(tiny());
        assert_eq!(budget.charge_egress(49), EgressState::Ok);
        assert_eq!(budget.charge_egress(1), EgressState::Spent);
        assert_eq!(
            budget.charge_egress(1),
            EgressState::Spent,
            "and stays spent"
        );
        assert_eq!(
            ConnectionBudget::new(tiny()).charge_egress(u64::MAX),
            EgressState::Spent
        );
    }

    #[test]
    fn names_are_checked_against_both_limits_at_their_edges() {
        let budget = ConnectionBudget::new(BudgetLimits::standard());
        let component = |n: usize| format!("/tmp/{}", "a".repeat(n));
        assert_eq!(budget.check_name(&component(255)), Ok(()));
        assert_eq!(
            budget.check_name(&component(256)),
            Err(BudgetError::NameTooLong)
        );
        // 100-byte chunks (`/` plus 99 letters), cut to an exact length; no component nears 255.
        let chunk = format!("/{}", "a".repeat(99));
        let path = |n: usize| chunk.repeat(42)[..n].to_string();
        assert_eq!(budget.check_name(&path(4_096)), Ok(()));
        assert_eq!(
            budget.check_name(&path(4_097)),
            Err(BudgetError::NameTooLong)
        );
    }

    #[test]
    fn max_resident_bytes_counts_content_a_slot_per_node_and_one_line_but_not_path_max_or_egress() {
        let budget = ConnectionBudget::new(BudgetLimits {
            owned_bytes: 1_000,
            overlay_nodes: 10,
            path_max: 100,
            egress_bytes: u64::MAX,
            ..BudgetLimits::standard()
        });
        assert_eq!(budget.max_resident_bytes(), 1_000 + 10 * 64 + 8_192);
    }
}
