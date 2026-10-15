//! Throttle for `diffie-hellman-group14-sha256`, the one key exchange a client can pick that costs
//! the sensor real CPU before it has authenticated anything.
//!
//! Measured on whole connections, a group14 exchange takes 3.50-3.73 ms of CPU (two 2048-bit
//! modular exponentiations with a 256-bit exponent, about 2.7 ms of it) against 0.90-1.15 ms for
//! curve25519. The unit runs under `CPUQuota=75%`, three quarters of one core, so a scanner that
//! opens group14 exchanges back to back could use the whole quota and starve every other session
//! of the process, curve25519 ones included.
//!
//! The gate is a semaphore of [`GROUP14_PERMITS`] and a pacing rule:
//!
//! - One permit. The exponentiation runs on the blocking pool (`kex::perform_kex_server`), so the
//!   permit count is the number of cores group14 can occupy at once, and one is the smallest
//!   count there is.
//! - The permit is held for twice the exchange's cost ([`Group14Permit::release_after`]), so
//!   group14 occupies the core at most half the time: about 140 exchanges a second, 50% of a core,
//!   and 25 points of the 75% quota are left for everything else. A cap on concurrency alone would
//!   still allow 100% of a core, above the quota.
//! - A client that arrives while the permit is taken waits at most [`GROUP14_WAIT`], then is told
//!   why with `SSH_MSG_DISCONNECT` and let go. The wait is bounded so a flood cannot pile up
//!   sessions behind the permit: the queue holds as many clients as the wait can serve, and the
//!   listener's connection cap bounds the rest.
//!
//! The gate is per process, not per listener: the CPU quota is the process's.

use std::sync::{Arc, OnceLock};
use std::time::Duration;

use tokio::sync::{OwnedSemaphorePermit, Semaphore};

/// How many group14 exchanges may compute at once. See the module doc for the derivation.
pub const GROUP14_PERMITS: usize = 1;

/// The longest a client that negotiated group14 waits for the permit before it is refused. At the
/// roughly 7 ms the permit is held per exchange, this serves about 280 queued clients, far more
/// than a real client ever has ahead of it.
pub const GROUP14_WAIT: Duration = Duration::from_secs(2);

/// What the client is told when the wait ran out. Worded for a person reading a failed `ssh -v`.
pub const GROUP14_BUSY_DESCRIPTION: &str = "too many concurrent diffie-hellman-group14-sha256 exchanges, try again or use another key exchange method";

/// The wait for the permit ran out: the exchange was not started.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Group14Busy;

/// The process-wide group14 gate.
pub struct Group14Gate {
    permits: Arc<Semaphore>,
}

impl Group14Gate {
    fn new() -> Self {
        Self {
            permits: Arc::new(Semaphore::new(GROUP14_PERMITS)),
        }
    }

    /// The gate every SSH session of this process goes through.
    pub fn global() -> &'static Group14Gate {
        static GATE: OnceLock<Group14Gate> = OnceLock::new();
        GATE.get_or_init(Group14Gate::new)
    }

    /// Wait up to [`GROUP14_WAIT`] for the right to run one group14 exchange.
    pub async fn acquire(&self) -> Result<Group14Permit, Group14Busy> {
        match tokio::time::timeout(GROUP14_WAIT, self.permits.clone().acquire_owned()).await {
            Ok(Ok(permit)) => Ok(Group14Permit { _permit: permit }),
            // The semaphore is never closed, so `Ok(Err(_))` cannot happen; refusing is still the
            // safe reading of it.
            Ok(Err(_)) | Err(_) => Err(Group14Busy),
        }
    }
}

/// The right to run one group14 exchange. Dropping it hands the permit back at once; the normal
/// path is [`Self::release_after`].
pub struct Group14Permit {
    _permit: OwnedSemaphorePermit,
}

impl Group14Permit {
    /// Keep the permit for as long again as the exchange cost, then release it, without making the
    /// client wait for that time. This is what holds group14 to half a core.
    pub fn release_after(self, cost: Duration) {
        tokio::spawn(async move {
            tokio::time::sleep(cost).await;
            drop(self);
        });
    }
}
