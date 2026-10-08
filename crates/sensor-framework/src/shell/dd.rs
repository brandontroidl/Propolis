//! `dd`, for the operands the recorded loaders use (`if`, `of`, `bs`, `count`, `skip`) and the
//! few more a real invocation carries (`ibs`, `obs`, `seek`, `conv=notrunc`, `status`).
//!
//! The bytes moved are computed from the operands, never by looping over blocks: the input is
//! read once, at offset `skip * ibs`, for `min(ibs * count, allowance)` bytes. `bs=1G count=1G`
//! therefore costs one bounded read, and what it hands back cannot exceed what the line has left.
//! The record counts and the byte total in the report are derived from the bytes actually moved.
//!
//! The report goes to standard error after the data. GNU dd prints two record lines and a
//! summary; the BusyBox applet on the reference host prints the two record lines only (both
//! captured, ground-truth "dd" section). The summary's elapsed time cannot be captured (each run
//! differs), so it is synthesized: a fixed function of the byte count and the session's process
//! id, so a replay is exact and two sessions differ.
#![deny(
    clippy::arithmetic_side_effects,
    clippy::unwrap_used,
    clippy::indexing_slicing
)]

use super::registry::Registry;
use super::{CommandResult, FakeShell, HandlerId, ShellFlavor, len_u64};
use crate::fakefs::{Blob, FsError};

const DD_TRY: &str = "Try 'dd --help' for more information.\n";

/// The most `if=/dev/zero of=FILE` writes in one run. The zeros are stored as a fill, in O(1), so
/// the survey's `dd if=/dev/zero of=/tmp/test bs=1M count=10` disk-speed probe gets the 10 MB a
/// server with gigabytes free writes, where copying real bytes ran into the per-line allowance and
/// answered `File too large`.
const ZERO_FILL_MAX: u64 = 1 << 30;

/// The default block size of both `ibs` and `obs`.
const DEFAULT_BLOCK: u64 = 512;

pub(super) fn register(r: &mut Registry) {
    // The phone's toolbox has no recorded answer for dd, and it answers "not found" today.
    r.register_if("dd", ubuntu, HandlerId::Dd, FakeShell::cmd_dd);
}

fn ubuntu(shell: &FakeShell, _parts: &[&str]) -> bool {
    shell.flavor == ShellFlavor::Bash
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Report {
    /// Record lines and, for GNU, the summary.
    Full,
    /// `status=noxfer`: the record lines only.
    Records,
    /// `status=none`: nothing on success.
    Silent,
}

struct DdArgs<'a> {
    input: Option<&'a str>,
    output: Option<&'a str>,
    ibs: u64,
    obs: u64,
    count: Option<u64>,
    skip: u64,
    seek: u64,
    notrunc: bool,
    report: Report,
}

/// A size operand: digits and an optional multiplier suffix. An overflowing value saturates,
/// which the allowance then bounds. `None` is not a number.
fn parse_size(text: &str) -> Option<u64> {
    let split = text
        .find(|c: char| !c.is_ascii_digit())
        .unwrap_or(text.len());
    let (digits, suffix) = text.split_at(split);
    let base: u64 = digits.parse().ok()?;
    let multiplier: u64 = match suffix {
        "" | "c" => 1,
        "w" => 2,
        "b" => 512,
        "kB" => 1_000,
        "k" | "K" | "KiB" => 1_024,
        "MB" => 1_000_000,
        "M" | "MiB" => 1_048_576,
        "GB" => 1_000_000_000,
        "G" | "GiB" => 1_073_741_824,
        _ => return None,
    };
    Some(base.saturating_mul(multiplier))
}

impl FakeShell {
    /// The operands of a dd command line, or the error text (status 1) the tool prints.
    fn parse_dd<'a>(&self, operands: &[&'a str]) -> Result<DdArgs<'a>, String> {
        let busybox = self.busybox_depth > 0;
        let mut args = DdArgs {
            input: None,
            output: None,
            ibs: DEFAULT_BLOCK,
            obs: DEFAULT_BLOCK,
            count: None,
            skip: 0,
            seek: 0,
            notrunc: false,
            report: Report::Full,
        };
        let mut both: Option<u64> = None;
        let invalid = |value: &str| {
            // [unverified] both wordings: the tools' number errors were not captured.
            if busybox {
                format!("dd: invalid number '{value}'\n")
            } else {
                format!("dd: invalid number: '{value}'\n")
            }
        };
        for &operand in operands {
            let Some((name, value)) = operand.split_once('=') else {
                return Err(unrecognized(operand));
            };
            let block = |value: &str| match parse_size(value) {
                Some(n) if n > 0 => Ok(n),
                _ => Err(invalid(value)),
            };
            let number = |value: &str| parse_size(value).ok_or_else(|| invalid(value));
            match name {
                "if" => args.input = Some(value),
                "of" => args.output = Some(value),
                "bs" => both = Some(block(value)?),
                "ibs" => args.ibs = block(value)?,
                "obs" => args.obs = block(value)?,
                "count" => args.count = Some(number(value)?),
                "skip" => args.skip = number(value)?,
                "seek" => args.seek = number(value)?,
                "conv" => {
                    args.notrunc |= value.split(',').any(|flag| flag == "notrunc");
                }
                "iflag" | "oflag" => {}
                "status" => {
                    args.report = match value {
                        "none" => Report::Silent,
                        "noxfer" => Report::Records,
                        "progress" => Report::Full,
                        other => {
                            // [unverified] wording, from coreutils' source, not a capture.
                            return Err(format!("dd: invalid status level: '{other}'\n{DD_TRY}"));
                        }
                    };
                }
                _ => return Err(unrecognized(operand)),
            }
        }
        if let Some(n) = both {
            args.ibs = n;
            args.obs = n;
        }
        Ok(args)
    }

    /// `dd`. Standard input and output stand in for an absent `if=` and `of=`.
    pub(super) fn cmd_dd(&mut self, parts: &[&str]) -> CommandResult {
        let args = match self.parse_dd(parts.get(1..).unwrap_or(&[])) {
            Ok(args) => args,
            Err(text) => return CommandResult::stderr(1, text),
        };
        let busybox = self.busybox_depth > 0;
        // The most this one run may move: never more than what the line has left to spend.
        let cap = self.read_cap().min(self.line.remaining());
        let want = args
            .count
            .map_or(cap, |count| count.saturating_mul(args.ibs))
            .min(cap);
        let start = args.skip.saturating_mul(args.ibs);
        if let Some(result) = self.dd_zero_fill(&args, busybox) {
            return result;
        }

        let read = match args.input {
            Some(path) => self.read_operand(parts, path, start, want),
            None => {
                self.stdin.take(start.min(cap));
                Ok(self.stdin.take(want))
            }
        };
        let (data, read_error) = match read {
            Ok(bytes) => (bytes, None),
            Err(FsError::IsADirectory) => (Vec::new(), Some("Is a directory")),
            Err(_) => {
                let path = args.input.unwrap_or("standard input");
                let text = if busybox {
                    format!("dd: can't open '{path}': No such file or directory\n")
                } else {
                    format!("dd: failed to open '{path}': No such file or directory\n")
                };
                return CommandResult::stderr(1, text);
            }
        };
        let moved = len_u64(data.len());
        // The copy takes the time the summary line reports, so `time dd` agrees with it.
        let pid = self.state().pid;
        self.timing.kernel(elapsed_ns(moved, pid));

        let mut acc = CommandResult::silent(0);
        let mut status = 0u8;
        if let Some(reason) = read_error {
            let path = args.input.unwrap_or("standard input");
            status = 1;
            // [unverified] both wordings for reading a directory; not captured.
            let text = if busybox {
                format!("dd: reading '{path}': {reason}\n")
            } else {
                format!("dd: error reading '{path}': {reason}\n")
            };
            acc.append(CommandResult::stderr(1, text));
        } else {
            match args.output {
                None => acc.append(CommandResult::stdout(data)),
                Some(path) => {
                    if let Err(text) = self.dd_write(&args, path, &data, cap, busybox) {
                        return CommandResult::stderr(1, text);
                    }
                }
            }
        }

        acc.append(CommandResult::stderr(
            status,
            self.dd_report(&args, moved, busybox),
        ));
        acc.status = status;
        acc
    }

    /// Put the copied bytes in `of=`: truncated first unless `conv=notrunc`, and from offset
    /// `seek * obs`, a gap before it reading as zeros. Refused, as a budget refusal is, when the
    /// offset alone is past what one line may hold.
    fn dd_write(
        &mut self,
        args: &DdArgs<'_>,
        arg: &str,
        data: &[u8],
        cap: u64,
        busybox: bool,
    ) -> Result<(), String> {
        let path = self.resolve_logical(arg);
        let at = args.seek.saturating_mul(args.obs);
        if at > cap {
            // [unverified] wording: a real disk would take the sparse file.
            return Err(format!("dd: error writing '{arg}': File too large\n"));
        }
        let existing = if args.notrunc || at > 0 {
            self.fs
                .read_all(&path, crate::fakefs::READ_CAP)
                .unwrap_or_default()
        } else {
            Vec::new()
        };
        let mut content: Vec<u8> = existing
            .iter()
            .copied()
            .take(usize::try_from(at).unwrap_or(usize::MAX))
            .collect();
        content.resize(usize::try_from(at).unwrap_or(usize::MAX), 0);
        content.extend_from_slice(data);
        if args.notrunc {
            let end = content.len();
            content.extend(existing.iter().copied().skip(end));
        }
        self.traced_write_file(&path, &content)
            .map_err(|error| write_error_text(&error, arg, busybox))
    }

    /// `if=/dev/zero of=FILE count=N` with nothing to keep from the old file: the zeros are
    /// written as one fill blob, which costs the connection no content allowance. `None` for any
    /// other run, which copies real bytes.
    fn dd_zero_fill(&mut self, args: &DdArgs<'_>, busybox: bool) -> Option<CommandResult> {
        let (Some(input), Some(output), Some(count)) = (args.input, args.output, args.count) else {
            return None;
        };
        if args.notrunc || args.seek > 0 {
            return None;
        }
        let logical = self.normalize_logical(input);
        if self
            .fs
            .stat(&logical, true)
            .is_none_or(|stat| stat.physical != "/dev/zero")
        {
            return None;
        }
        let moved = count.saturating_mul(args.ibs).min(ZERO_FILL_MAX);
        let pid = self.state().pid;
        self.timing.kernel(elapsed_ns(moved, pid));
        let path = self.resolve_logical(output);
        if let Err(error) = self.traced_write_blob(&path, Blob::fill(0, moved), 0o100_644) {
            return Some(CommandResult::stderr(
                1,
                write_error_text(&error, output, busybox),
            ));
        }
        Some(CommandResult::stderr(
            0,
            self.dd_report(args, moved, busybox),
        ))
    }

    /// The record lines and, for GNU dd, the summary of a run that moved `moved` bytes.
    fn dd_report(&self, args: &DdArgs<'_>, moved: u64, busybox: bool) -> String {
        if args.report == Report::Silent {
            return String::new();
        }
        let mut text = format!(
            "{} records in\n{} records out\n",
            records(moved, args.ibs),
            records(moved, args.obs)
        );
        if !busybox && args.report == Report::Full {
            text.push_str(&gnu_summary(moved, self.state().pid));
        }
        text
    }
}

/// What dd says when it cannot open or write `of=`.
fn write_error_text(error: &FsError, arg: &str, busybox: bool) -> String {
    let reason = match error {
        FsError::ReadOnly => "Read-only file system",
        FsError::IsADirectory => "Is a directory",
        other => super::budget_refusal_text(other).unwrap_or("No such file or directory"),
    };
    let opening = matches!(
        error,
        FsError::ReadOnly
            | FsError::IsADirectory
            | FsError::NoSuchDirectory(_)
            | FsError::NoSuchFile
            | FsError::NotADirectory
    );
    if !opening {
        format!("dd: error writing '{arg}': {reason}\n")
    } else if busybox {
        format!("dd: can't open '{arg}': {reason}\n")
    } else {
        format!("dd: failed to open '{arg}': {reason}\n")
    }
}

fn unrecognized(operand: &str) -> String {
    format!("dd: unrecognized operand '{operand}'\n{DD_TRY}")
}

/// `full+partial`: whole blocks and whether a short one followed.
fn records(moved: u64, block: u64) -> String {
    let full = moved.checked_div(block).unwrap_or(0);
    let partial = u64::from(moved.checked_rem(block).unwrap_or(0) > 0);
    format!("{full}+{partial}")
}

const SI_UNITS: [&str; 7] = ["B", "kB", "MB", "GB", "TB", "PB", "EB"];
const IEC_UNITS: [&str; 7] = ["B", "KiB", "MiB", "GiB", "TiB", "PiB", "EiB"];

/// `n` the way GNU dd's summary writes it: the largest unit that fits, then one decimal below
/// `decimal_below` and none at or above it. gnulib's `human_readable` takes two paths: the rate is
/// a floating value and keeps a decimal below 100 (captured: `133 kB/s`, `10.8 kB/s`,
/// `36.5 kB/s`), and a byte count is an integer that keeps one below 10 only (recorded on Ubuntu
/// 22.04, 2026-10-07: `10485760 bytes (10 MB, 10 MiB) copied`).
fn human(n: u64, base: u64, units: &[&str; 7], decimal_below: u128) -> String {
    let n = u128::from(n);
    let base = u128::from(base);
    let mut power = 0usize;
    let mut scale: u128 = 1;
    while power < 6 && n >= scale.saturating_mul(base) {
        scale = scale.saturating_mul(base);
        power = power.saturating_add(1);
    }
    let round = |value: u128, per: u128| {
        value
            .saturating_add(per.checked_div(2).unwrap_or(0))
            .checked_div(per)
            .unwrap_or(0)
    };
    // Rounding can carry into the next unit (999.6 kB is 1.0 MB).
    if power > 0 && power < 6 && round(n, scale) >= base {
        scale = scale.saturating_mul(base);
        power = power.saturating_add(1);
    }
    let unit = units.get(power).copied().unwrap_or("B");
    if power == 0 {
        return format!("{n} {unit}");
    }
    let tenths = round(n.saturating_mul(10), scale);
    if tenths < decimal_below.saturating_mul(10) {
        let whole = tenths.checked_div(10).unwrap_or(0);
        let frac = tenths.checked_rem(10).unwrap_or(0);
        format!("{whole}.{frac} {unit}")
    } else {
        format!("{} {unit}", round(n, scale))
    }
}

/// The synthesized elapsed time, in nanoseconds: 60 to 460 microseconds fixed by the byte count
/// and the process id, plus the cost of moving the bytes at 2 GB/s.
fn elapsed_ns(moved: u64, pid: u32) -> u64 {
    let mixed = (moved ^ (u64::from(pid) << 32)).wrapping_mul(0x9e37_79b9_7f4a_7c15);
    let jitter = (mixed >> 40).checked_rem(400_000).unwrap_or(0);
    jitter
        .saturating_add(60_000)
        .saturating_add(moved.checked_div(2).unwrap_or(0))
}

/// `ns` nanoseconds as C's `%g` writes seconds: six significant digits, trailing zeros dropped,
/// scientific below 1e-4 (`8.8379e-05`, `0.000165584`). `ns` is under a second.
fn seconds_g(ns: u64) -> String {
    let digits = ns.max(1).to_string();
    let kept: String = digits.chars().take(6).collect();
    let trimmed = kept.trim_end_matches('0');
    let trimmed = if trimmed.is_empty() { "0" } else { trimmed };
    if digits.len() >= 6 {
        let zeros = 9usize.saturating_sub(digits.len());
        return format!("0.{}{trimmed}", "0".repeat(zeros));
    }
    let exponent = 10usize.saturating_sub(digits.len());
    let mut mantissa = trimmed.chars();
    let first = mantissa.next().unwrap_or('0');
    let rest: String = mantissa.collect();
    if rest.is_empty() {
        format!("{first}e-{exponent:02}")
    } else {
        format!("{first}.{rest}e-{exponent:02}")
    }
}

fn gnu_summary(moved: u64, pid: u32) -> String {
    summary_line(moved, elapsed_ns(moved, pid))
}

/// GNU dd's last line for `moved` bytes in `ns` nanoseconds, as captured:
/// `52 bytes copied, 0.000404895 s, 128 kB/s`.
pub(super) fn summary_line(moved: u64, ns: u64) -> String {
    let si = human(moved, 1_000, &SI_UNITS, 10);
    let iec = human(moved, 1_024, &IEC_UNITS, 10);
    let noun = if moved == 1 { "byte" } else { "bytes" };
    let copied = if si == iec {
        format!("{moved} {noun} copied")
    } else {
        format!("{moved} {noun} ({si}, {iec}) copied")
    };
    let per_second = u128::from(moved)
        .saturating_mul(1_000_000_000)
        .checked_div(u128::from(ns))
        .unwrap_or(0);
    let rate = human(
        u64::try_from(per_second).unwrap_or(u64::MAX),
        1_000,
        &SI_UNITS,
        100,
    );
    format!("{copied}, {} s, {rate}/s\n", seconds_g(ns))
}
