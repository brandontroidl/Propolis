//! What the box claims its commands cost in time, and bash's `time` report of it.
//!
//! Nothing here measures anything: a command adds the time it would have taken on the modeled
//! one-core server (`sleep` its argument, `dd` the elapsed time its own summary line reports, any
//! command started from a file a process start), and `time` reports the sum over its pipeline. So
//! `time dd if=/dev/zero of=/tmp/t bs=1M count=10 2>&1` prints a `real` no shorter than the
//! `copied, ... s` line just above it, and `time true` (a builtin) prints zeros.
//!
//! Formats recorded on Ubuntu 22.04's bash 5.1 (2026-10-07 reference session): the default
//! `TIMEFORMAT` is `\nreal\t%3lR\nuser\t%3lU\nsys\t%3lS` (`real\t0m0.019s`), `time -p` prints
//! `real 0.00` with two decimals, and both go to the shell's standard error, outside the timed
//! command's own redirections. The per-process cost below is [unverified]: it is chosen near what
//! the reference showed (`time sleep 1` real 1.006 s, user and sys about 1 ms).
#![deny(
    clippy::arithmetic_side_effects,
    clippy::unwrap_used,
    clippy::indexing_slicing
)]

/// Time the session's commands claim to have taken, in nanoseconds.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(super) struct Timing {
    pub real_ns: u64,
    pub user_ns: u64,
    pub sys_ns: u64,
}

/// What starting one process from a file costs: the fork, the exec, the dynamic loader.
const PROCESS_REAL_NS: u64 = 1_700_000;
const PROCESS_USER_NS: u64 = 400_000;
const PROCESS_SYS_NS: u64 = 900_000;

impl Timing {
    /// A command started from a file. `seed` (the session's pid) varies the figure a little so
    /// two sessions do not report identical nanoseconds.
    pub(super) fn process(&mut self, seed: u32) {
        let jitter = u64::from(seed % 7).saturating_mul(90_000);
        self.real_ns = self
            .real_ns
            .saturating_add(PROCESS_REAL_NS)
            .saturating_add(jitter);
        self.user_ns = self.user_ns.saturating_add(PROCESS_USER_NS);
        self.sys_ns = self.sys_ns.saturating_add(PROCESS_SYS_NS);
    }

    /// Wall time spent waiting (`sleep`), with no CPU.
    pub(super) fn wait(&mut self, ns: u64) {
        self.real_ns = self.real_ns.saturating_add(ns);
    }

    /// Wall time spent in the kernel moving bytes (`dd`): almost all of it system time.
    pub(super) fn kernel(&mut self, ns: u64) {
        self.real_ns = self.real_ns.saturating_add(ns);
        self.sys_ns = self.sys_ns.saturating_add(ns.saturating_mul(9) / 10);
    }

    /// The time between `earlier` and this.
    pub(super) fn since(&self, earlier: &Self) -> Self {
        Self {
            real_ns: self.real_ns.saturating_sub(earlier.real_ns),
            user_ns: self.user_ns.saturating_sub(earlier.user_ns),
            sys_ns: self.sys_ns.saturating_sub(earlier.sys_ns),
        }
    }
}

/// `0m0.019s`: bash's `%3lR`, minutes and seconds to the millisecond, truncated.
fn long_form(ns: u64) -> String {
    let millis = ns / 1_000_000;
    let minutes = millis / 60_000;
    let seconds = (millis % 60_000) / 1_000;
    let fraction = millis % 1_000;
    format!("{minutes}m{seconds}.{fraction:03}s")
}

/// `0.00`: `time -p`, seconds to the hundredth, truncated.
fn posix_form(ns: u64) -> String {
    let hundredths = ns / 10_000_000;
    format!("{}.{:02}", hundredths / 100, hundredths % 100)
}

/// bash's report for `spent`.
pub(super) fn bash_report(spent: &Timing, posix: bool) -> String {
    if posix {
        format!(
            "real {}\nuser {}\nsys {}\n",
            posix_form(spent.real_ns),
            posix_form(spent.user_ns),
            posix_form(spent.sys_ns)
        )
    } else {
        format!(
            "\nreal\t{}\nuser\t{}\nsys\t{}\n",
            long_form(spent.real_ns),
            long_form(spent.user_ns),
            long_form(spent.sys_ns)
        )
    }
}

/// mksh's report [unverified: no Android capture exists].
pub(super) fn mksh_report(spent: &Timing) -> String {
    let cell = |ns: u64| {
        let hundredths = ns / 10_000_000;
        format!(
            "{}m{:02}.{:02}s",
            hundredths / 6_000,
            (hundredths % 6_000) / 100,
            hundredths % 100
        )
    };
    format!(
        "    {} real     {} user     {} system\n",
        cell(spent.real_ns),
        cell(spent.user_ns),
        cell(spent.sys_ns)
    )
}

/// The seconds `sleep` was asked for, with GNU's `s`, `m`, `h` and `d` suffixes, summed over its
/// operands; `None` for an operand that is no number.
pub(super) fn sleep_ns(operands: &[&str]) -> Option<u64> {
    let mut total: u64 = 0;
    for operand in operands {
        let (number, unit) = match operand.char_indices().last() {
            Some((at, c)) if c.is_ascii_alphabetic() => (operand.get(..at)?, c),
            _ => (*operand, 's'),
        };
        let factor: f64 = match unit {
            's' => 1.0,
            'm' => 60.0,
            'h' => 3_600.0,
            'd' => 86_400.0,
            _ => return None,
        };
        let value: f64 = number.parse().ok()?;
        if !value.is_finite() || value < 0.0 {
            return None;
        }
        // A week is more than any session lasts; the figure only has to be plausible.
        let ns = (value * factor * 1e9).min(604_800e9);
        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
        let ns = ns as u64;
        total = total.saturating_add(ns);
    }
    Some(total)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The recorded `time true`, `time -p true` and the `time dd` tail.
    #[test]
    fn reports_read_as_bash_prints_them() {
        assert_eq!(
            bash_report(&Timing::default(), false),
            "\nreal\t0m0.000s\nuser\t0m0.000s\nsys\t0m0.000s\n"
        );
        assert_eq!(
            bash_report(&Timing::default(), true),
            "real 0.00\nuser 0.00\nsys 0.00\n"
        );
        let spent = Timing {
            real_ns: 19_400_000,
            user_ns: 0,
            sys_ns: 11_000_000,
        };
        assert_eq!(
            bash_report(&spent, false),
            "\nreal\t0m0.019s\nuser\t0m0.000s\nsys\t0m0.011s\n"
        );
        let long = Timing {
            real_ns: 61_006_000_000,
            ..Timing::default()
        };
        assert!(bash_report(&long, false).starts_with("\nreal\t1m1.006s\n"));
    }

    #[test]
    fn sleep_reads_gnu_durations() {
        assert_eq!(sleep_ns(&["1"]), Some(1_000_000_000));
        assert_eq!(sleep_ns(&["0.2"]), Some(200_000_000));
        assert_eq!(sleep_ns(&["1m", "2s"]), Some(62_000_000_000));
        assert_eq!(sleep_ns(&["x"]), None);
        assert_eq!(sleep_ns(&["-1"]), None);
    }
}
