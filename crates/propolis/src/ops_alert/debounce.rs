//! The per-condition debounce and re-page state machine. Pure and clock-injected: `step` takes the
//! current `Instant`, so the transitions are unit-testable without sleeping or reading the clock.
//!
//! Lifecycle: a condition must stay `Firing` for `for_dur` before it pages once (debounce, so a
//! momentary blip is silent); while it stays firing it re-pages every `repage_cooldown` (a slow-burn
//! problem overnight must not rest on one missed push); when it clears after having paged, it emits
//! one `Recovered` notice.

use std::time::{Duration, Instant};

/// What the monitor observed this tick for one condition.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Signal {
    Ok,
    Firing,
}

/// What the monitor should do with the dispatcher this tick.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    None,
    Page,
    RePage,
    Recovered,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    Clear,
    Pending { since: Instant },
    Firing { last_paged: Instant },
}

/// One machine per condition. `for_dur` is the debounce; `repage_cooldown` is how often a persistent
/// firing condition re-pages.
#[derive(Debug)]
pub struct DebounceMachine {
    state: State,
    for_dur: Duration,
    repage_cooldown: Duration,
}

impl DebounceMachine {
    pub fn new(for_dur: Duration, repage_cooldown: Duration) -> Self {
        Self {
            state: State::Clear,
            for_dur,
            repage_cooldown,
        }
    }

    /// Advance the machine with this tick's `signal` at time `now`, returning the action to take.
    pub fn step(&mut self, signal: Signal, now: Instant) -> Action {
        match (self.state, signal) {
            // Not firing: any clear (or staying clear) leaves us Clear with nothing to do. A
            // Pending that clears before `for_dur` never paged, so there is nothing to recover.
            (State::Clear, Signal::Ok) => Action::None,
            (State::Pending { .. }, Signal::Ok) => {
                self.state = State::Clear;
                Action::None
            }

            // First firing tick: start the debounce clock. A zero `for_dur` (e.g. hash-chain
            // verification failing) pages immediately; a positive one waits in Pending.
            (State::Clear, Signal::Firing) => {
                if self.for_dur.is_zero() {
                    self.state = State::Firing { last_paged: now };
                    Action::Page
                } else {
                    self.state = State::Pending { since: now };
                    Action::None
                }
            }

            // Still firing during the debounce window: page once when it has held for `for_dur`.
            (State::Pending { since }, Signal::Firing) => {
                if now.duration_since(since) >= self.for_dur {
                    self.state = State::Firing { last_paged: now };
                    Action::Page
                } else {
                    Action::None
                }
            }

            // Firing and still firing: re-page only once the cooldown since the last page elapsed.
            (State::Firing { last_paged }, Signal::Firing) => {
                if now.duration_since(last_paged) >= self.repage_cooldown {
                    self.state = State::Firing { last_paged: now };
                    Action::RePage
                } else {
                    Action::None
                }
            }

            // Firing then cleared: emit exactly one recovered notice and reset.
            (State::Firing { .. }, Signal::Ok) => {
                self.state = State::Clear;
                Action::Recovered
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const FOR: Duration = Duration::from_secs(600);
    const COOLDOWN: Duration = Duration::from_secs(5400);

    fn machine() -> DebounceMachine {
        DebounceMachine::new(FOR, COOLDOWN)
    }

    #[test]
    fn a_sub_for_dur_blip_never_pages() {
        let base = Instant::now();
        let mut m = machine();
        assert_eq!(m.step(Signal::Firing, base), Action::None); // enters Pending
        // Clears before `for_dur` elapses: no page, and no recovered (it never fired).
        assert_eq!(
            m.step(Signal::Ok, base + Duration::from_secs(60)),
            Action::None
        );
    }

    #[test]
    fn crossing_for_dur_pages_exactly_once() {
        let base = Instant::now();
        let mut m = machine();
        assert_eq!(m.step(Signal::Firing, base), Action::None);
        assert_eq!(
            m.step(Signal::Firing, base + Duration::from_secs(300)),
            Action::None
        ); // still within FOR
        assert_eq!(m.step(Signal::Firing, base + FOR), Action::Page); // exactly FOR -> Page
        // Immediately after paging, no re-page until the cooldown.
        assert_eq!(
            m.step(Signal::Firing, base + FOR + Duration::from_secs(1)),
            Action::None
        );
    }

    #[test]
    fn a_persistent_condition_repages_only_after_the_cooldown() {
        let base = Instant::now();
        let mut m = machine();
        m.step(Signal::Firing, base);
        assert_eq!(m.step(Signal::Firing, base + FOR), Action::Page);
        // Just before the cooldown from the page: no re-page.
        assert_eq!(
            m.step(
                Signal::Firing,
                base + FOR + COOLDOWN - Duration::from_secs(1)
            ),
            Action::None
        );
        // At the cooldown: re-page.
        assert_eq!(
            m.step(Signal::Firing, base + FOR + COOLDOWN),
            Action::RePage
        );
    }

    #[test]
    fn clearing_after_firing_yields_one_recovered() {
        let base = Instant::now();
        let mut m = machine();
        m.step(Signal::Firing, base);
        assert_eq!(m.step(Signal::Firing, base + FOR), Action::Page);
        assert_eq!(
            m.step(Signal::Ok, base + FOR + Duration::from_secs(10)),
            Action::Recovered
        );
        // Fully reset: a later firing starts the debounce again, does not immediately page.
        assert_eq!(
            m.step(Signal::Firing, base + FOR + Duration::from_secs(20)),
            Action::None
        );
    }
}
