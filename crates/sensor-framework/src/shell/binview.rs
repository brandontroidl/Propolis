//! `xxd` and `strings`: the two tools an attacker inspects a dropped payload or the self-binary
//! with after `od` and `hexdump`.
//!
//! Both read the modeled bytes of their operands (or standard input) through the same bounded
//! reader as `cat`, so a dump or a run of text comes from the file the session holds. Nothing
//! touches the host. What a tool is not asked to model it does not invent: an option or output
//! format outside the ones below (`xxd -i`, `-b`, `-a`, `strings -e`, `-f`) prints nothing and
//! succeeds, never a dump this shell made up.
//!
//! Both are applets of the captured BusyBox, so `busybox xxd` and `busybox strings` land here, on
//! the Ubuntu persona. Bare, both are "command not found" on every persona: the Ubuntu recording
//! marks `xxd` absent (binaries table, 2026-09-29), and the phone's toolbox has neither.
//!
//! The layouts are `xxd` from vim's tree and GNU binutils `strings` as run on a current host; no
//! capture of either exists on the reference box, so every wording and layout beyond the canonical
//! lines is [unverified].
#![deny(
    clippy::arithmetic_side_effects,
    clippy::unwrap_used,
    clippy::indexing_slicing
)]

use super::read::errno_text;
use super::registry::Registry;
use super::texttools::stopped;
use super::{CommandResult, FakeShell, HandlerId, len_u64};
use crate::fakefs::FsError;

pub(super) fn register(r: &mut Registry) {
    r.register_if("xxd", has_applet, HandlerId::Xxd, FakeShell::cmd_xxd);
    r.register_if(
        "strings",
        has_applet,
        HandlerId::Strings,
        FakeShell::cmd_strings,
    );
}

/// Neither is a file on either persona (Ubuntu's recording marks `xxd` absent and never probed
/// `strings`; toybox has neither), so they resolve only as BusyBox applets, which `cmd_busybox`
/// signals by raising `busybox_depth` before it resolves the applet.
fn has_applet(shell: &FakeShell, _parts: &[&str]) -> bool {
    shell.busybox_depth > 0
}

/// xxd's own default and ceiling for the bytes on a line.
const XXD_COLS: usize = 16;
const XXD_PLAIN_COLS: usize = 30;
const XXD_MAX_COLS: usize = 256;

/// A count as xxd's `strtol(..., 0)` reads it: decimal, or hex after `0x`.
fn parse_count(text: &str) -> Option<u64> {
    match text.strip_prefix("0x").or_else(|| text.strip_prefix("0X")) {
        Some(hex) => u64::from_str_radix(hex, 16).ok(),
        None => (!text.is_empty() && text.bytes().all(|b| b.is_ascii_digit()))
            .then(|| text.parse().ok())
            .flatten(),
    }
}

// --------------------------------------------------------------------------------------- xxd

#[derive(Clone, Copy)]
enum Seek {
    Start(u64),
    /// `-s -N`: the last `N` bytes.
    End(u64),
}

struct XxdPlan<'a> {
    plain: bool,
    reverse: bool,
    upper: bool,
    len: Option<u64>,
    seek: Seek,
    cols: Option<usize>,
    group: usize,
    files: Vec<&'a str>,
}

/// The plan for an `xxd` command line, or `None` for anything outside `-p -r -u -l -s -c -g` and
/// at most an input and an output operand. xxd does not cluster flags: each word is one option.
fn parse_xxd<'a>(args: &[&'a str]) -> Option<XxdPlan<'a>> {
    let mut plan = XxdPlan {
        plain: false,
        reverse: false,
        upper: false,
        len: None,
        seek: Seek::Start(0),
        cols: None,
        group: 2,
        files: Vec::new(),
    };
    let mut i = 0usize;
    while let Some(&arg) = args.get(i) {
        i = i.saturating_add(1);
        if arg == "-" || !arg.starts_with('-') {
            plan.files.push(arg);
            continue;
        }
        match arg {
            "-p" | "-ps" | "-postscript" | "-plain" => {
                plan.plain = true;
                continue;
            }
            "-r" | "-revert" => {
                plan.reverse = true;
                continue;
            }
            "-u" => {
                plan.upper = true;
                continue;
            }
            _ => {}
        }
        let (flag, attached) = match arg {
            "-len" => ('l', ""),
            "-seek" => ('s', ""),
            "-cols" => ('c', ""),
            "-groupsize" => ('g', ""),
            _ => {
                let mut chars = arg.get(1..)?.chars();
                let flag = chars.next()?;
                (flag, chars.as_str())
            }
        };
        if !matches!(flag, 'l' | 's' | 'c' | 'g') {
            return None;
        }
        let value = if attached.is_empty() {
            let next = args.get(i).copied()?;
            i = i.saturating_add(1);
            next
        } else {
            attached
        };
        match flag {
            'l' => plan.len = Some(parse_count(value)?),
            's' => {
                let value = value.strip_prefix('+').unwrap_or(value);
                plan.seek = match value.strip_prefix('-') {
                    Some(from_end) => Seek::End(parse_count(from_end)?),
                    None => Seek::Start(parse_count(value)?),
                };
            }
            'c' => {
                let cols = usize::try_from(parse_count(value)?).ok()?;
                if cols == 0 || cols > XXD_MAX_COLS {
                    return None;
                }
                plan.cols = Some(cols);
            }
            _ => plan.group = usize::try_from(parse_count(value)?).ok()?,
        }
    }
    (plan.files.len() <= 2).then_some(plan)
}

/// Whether byte `index` closes a group of `group` bytes. A group of zero never closes.
fn ends_group(index: usize, group: usize) -> bool {
    index.saturating_add(1).checked_rem(group) == Some(0)
}

fn printable(byte: u8) -> bool {
    (0x20..=0x7e).contains(&byte)
}

fn push_hex(out: &mut String, byte: u8, upper: bool) {
    if upper {
        out.push_str(&format!("{byte:02X}"));
    } else {
        out.push_str(&format!("{byte:02x}"));
    }
}

/// The dump in `xxd`'s default layout: `OFFSET: ` then each byte as two hex digits with a space
/// after every group, short lines padded to the full width, a space, and the bytes as characters
/// (`.` for what is not printable). `first` is the offset of `data[0]` in the file. Rendering
/// stops once `room` bytes of text exist.
fn xxd_render(data: &[u8], first: u64, plan: &XxdPlan<'_>, cols: usize, room: usize) -> String {
    let mut out = String::new();
    let mut offset = first;
    for chunk in data.chunks(cols) {
        if out.len() >= room {
            break;
        }
        if plan.plain {
            for &byte in chunk {
                push_hex(&mut out, byte, plan.upper);
            }
            out.push('\n');
            continue;
        }
        out.push_str(&format!("{offset:08x}: "));
        for index in 0..cols {
            match chunk.get(index) {
                Some(&byte) => push_hex(&mut out, byte, plan.upper),
                None => out.push_str("  "),
            }
            if ends_group(index, plan.group) {
                out.push(' ');
            }
        }
        out.push(' ');
        for &byte in chunk {
            out.push(if printable(byte) {
                char::from(byte)
            } else {
                '.'
            });
        }
        out.push('\n');
        offset = offset.saturating_add(len_u64(chunk.len()));
    }
    out
}

/// The text a line of dump costs per byte it shows, rounded up, so a read can be sized to what
/// the line has left.
fn xxd_cost(plan: &XxdPlan<'_>, cols: usize) -> usize {
    let hex = cols
        .saturating_mul(2)
        .saturating_add(cols.checked_div(plan.group).unwrap_or(0));
    let line = if plan.plain {
        hex.saturating_add(1)
    } else {
        hex.saturating_add(cols).saturating_add(12)
    };
    line.div_ceil(cols).max(1)
}

fn hex_value(byte: u8) -> Option<u8> {
    char::from(byte)
        .to_digit(16)
        .and_then(|digit| u8::try_from(digit).ok())
}

/// Place `byte` at `at`, filling any gap before it with zeros. False once the output would pass
/// `room`.
fn put(out: &mut Vec<u8>, at: usize, byte: u8, room: usize) -> bool {
    if at >= room {
        return false;
    }
    if at >= out.len() {
        out.resize(at, 0);
        out.push(byte);
    } else if let Some(slot) = out.get_mut(at) {
        *slot = byte;
    }
    true
}

/// `xxd -r`: the bytes a hex dump (or, with `-p`, a plain hex stream) spells. A dump line is
/// `OFFSET:` then hex pairs; the first two adjacent spaces, or a non-hex character, end its hex and
/// the character column after is ignored. The bytes land at their offsets, zero-filled between.
fn xxd_revert(text: &[u8], plain: bool, room: usize) -> Vec<u8> {
    let mut out = Vec::new();
    if plain {
        let mut high: Option<u8> = None;
        for digit in text.iter().filter_map(|byte| hex_value(*byte)) {
            match high.take() {
                None => high = Some(digit),
                Some(high) => {
                    let byte = high.wrapping_mul(16).wrapping_add(digit);
                    let at = out.len();
                    if !put(&mut out, at, byte, room) {
                        break;
                    }
                }
            }
        }
        return out;
    }
    for line in text.split(|byte| *byte == b'\n') {
        let Some(colon) = line.iter().position(|byte| *byte == b':') else {
            continue;
        };
        let (head, body) = line.split_at(colon);
        let mut at = Some(0usize);
        for digit in head.iter().filter(|byte| **byte != b' ') {
            at = hex_value(*digit)
                .and_then(|value| at?.checked_mul(16)?.checked_add(usize::from(value)));
        }
        let Some(mut at) = at else {
            continue;
        };
        let mut rest = body.get(1..).unwrap_or(&[]).iter().copied().peekable();
        let mut spaced = false;
        while let Some(&next) = rest.peek() {
            if next == b' ' {
                if spaced {
                    break;
                }
                spaced = true;
                rest.next();
                continue;
            }
            let Some(high) = hex_value(next) else {
                break;
            };
            rest.next();
            let Some(low) = rest.peek().copied().and_then(hex_value) else {
                break;
            };
            rest.next();
            spaced = false;
            if !put(&mut out, at, high.wrapping_mul(16).wrapping_add(low), room) {
                return out;
            }
            at = at.saturating_add(1);
        }
    }
    out
}

fn skip_bytes(bytes: Vec<u8>, n: u64) -> Vec<u8> {
    let from = usize::try_from(n).unwrap_or(usize::MAX);
    bytes.get(from..).map(<[u8]>::to_vec).unwrap_or_default()
}

fn write_failure(error: &FsError) -> &'static str {
    match error {
        FsError::ReadOnly => "Read-only file system",
        FsError::IsADirectory => "Is a directory",
        other => super::budget_refusal_text(other).unwrap_or("No such file or directory"),
    }
}

impl FakeShell {
    /// `xxd [-p] [-r] [-u] [-l LEN] [-s SEEK] [-c COLS] [-g GROUP] [INFILE [OUTFILE]]`.
    ///
    /// The dump is bounded by what the line has left: the read is sized to it and a file longer
    /// than that is dumped up to that point. A missing input is `xxd: FILE: No such file or
    /// directory` with status 1 (the real tool's status is 2 [unverified]). With an OUTFILE the
    /// text (or, with `-r`, the bytes) is written there instead of printed.
    pub(super) fn cmd_xxd(&mut self, parts: &[&str]) -> CommandResult {
        let Some(plan) = parse_xxd(parts.get(1..).unwrap_or(&[])) else {
            return CommandResult::silent(0);
        };
        let input = plan.files.first().copied();
        let output = plan.files.get(1).copied().filter(|path| *path != "-");
        let room = self.read_cap().min(self.line.remaining());
        let cols = plan
            .cols
            .unwrap_or(if plan.plain { XXD_PLAIN_COLS } else { XXD_COLS });
        let (bytes, first) = if plan.reverse {
            let read = self.read_source(parts, input, room);
            (read, 0)
        } else {
            let per_byte = len_u64(xxd_cost(&plan, cols));
            let budget = room.checked_div(per_byte).unwrap_or(0);
            let want = plan.len.unwrap_or(u64::MAX).min(budget);
            match plan.seek {
                Seek::Start(skip) => {
                    let read = match input {
                        Some(path) if path != "-" => self.read_operand(parts, path, skip, want),
                        _ => self
                            .read_source(parts, None, skip.saturating_add(want))
                            .map(|bytes| skip_bytes(bytes, skip)),
                    };
                    (read, skip)
                }
                Seek::End(tail) => {
                    // The length is needed first, so everything the line allows is read.
                    let read = self.read_source(parts, input, room);
                    let all = read.map(|bytes| {
                        let start = len_u64(bytes.len()).saturating_sub(tail);
                        (skip_bytes(bytes, start), start)
                    });
                    match all {
                        Ok((kept, start)) => {
                            let limited = kept
                                .into_iter()
                                .take(usize::try_from(want).unwrap_or(usize::MAX))
                                .collect();
                            (Ok(limited), start)
                        }
                        Err(error) => (Err(error), 0),
                    }
                }
            }
        };
        let bytes = match bytes {
            Ok(bytes) => bytes,
            Err(error) => {
                return CommandResult::stderr(
                    1,
                    format!("xxd: {}: {}\n", input.unwrap_or("-"), errno_text(&error)),
                );
            }
        };
        let result = if plan.reverse {
            // Parsing is work the line pays for, output or not.
            if !self.charge_work(len_u64(bytes.len())) {
                return stopped();
            }
            let room = usize::try_from(self.line.remaining()).unwrap_or(usize::MAX);
            xxd_revert(&bytes, plan.plain, room)
        } else {
            let room = usize::try_from(self.line.remaining()).unwrap_or(usize::MAX);
            xxd_render(&bytes, first, &plan, cols, room).into_bytes()
        };
        let Some(name) = output else {
            return CommandResult::stdout(result);
        };
        let path = self.resolve_logical(name);
        match self.traced_write_file(&path, &result) {
            Ok(()) => CommandResult::silent(0),
            Err(error) => {
                CommandResult::stderr(1, format!("xxd: {name}: {}\n", write_failure(&error)))
            }
        }
    }
}

// ---------------------------------------------------------------------------------- strings

#[derive(Clone, Copy)]
enum Radix {
    Decimal,
    Octal,
    Hex,
}

struct StringsPlan<'a> {
    min: usize,
    radix: Option<Radix>,
    files: Vec<&'a str>,
}

/// Where a `-n` / `-t` value comes from: attached to its flag or the next word.
fn cluster_value<'a>(
    cluster: &'a str,
    at: usize,
    args: &[&'a str],
    next: &mut usize,
) -> Option<&'a str> {
    let attached = cluster.get(at.saturating_add(1)..).unwrap_or("");
    if attached.is_empty() {
        let value = args.get(*next).copied()?;
        *next = next.saturating_add(1);
        Some(value)
    } else {
        Some(attached)
    }
}

fn parse_radix(text: &str) -> Option<Radix> {
    match text {
        "d" => Some(Radix::Decimal),
        "o" => Some(Radix::Octal),
        "x" => Some(Radix::Hex),
        _ => None,
    }
}

/// The plan for a `strings` command line, or `None` for any option outside `-a -n -t -o` and
/// their long forms.
fn parse_strings<'a>(args: &[&'a str]) -> Option<StringsPlan<'a>> {
    let mut plan = StringsPlan {
        min: 4,
        radix: None,
        files: Vec::new(),
    };
    let mut options = true;
    let mut i = 0usize;
    while let Some(&arg) = args.get(i) {
        i = i.saturating_add(1);
        if !options || arg == "-" || !arg.starts_with('-') {
            plan.files.push(arg);
            continue;
        }
        if arg == "--" {
            options = false;
            continue;
        }
        if let Some(long) = arg.strip_prefix("--") {
            let (name, value) = match long.split_once('=') {
                Some((name, value)) => (name, Some(value)),
                None => (long, None),
            };
            match (name, value) {
                ("all", None) => {}
                ("bytes", Some(value)) => plan.min = usize::try_from(parse_count(value)?).ok()?,
                ("radix", Some(value)) => plan.radix = Some(parse_radix(value)?),
                _ => return None,
            }
            continue;
        }
        let cluster = arg.get(1..).unwrap_or("");
        if !cluster.is_empty() && cluster.bytes().all(|b| b.is_ascii_digit()) {
            plan.min = usize::try_from(parse_count(cluster)?).ok()?;
            continue;
        }
        for (at, flag) in cluster.char_indices() {
            match flag {
                'a' => {}
                'o' => plan.radix = Some(Radix::Octal),
                'n' => {
                    let value = cluster_value(cluster, at, args, &mut i)?;
                    plan.min = usize::try_from(parse_count(value)?).ok()?;
                    break;
                }
                't' => {
                    let value = cluster_value(cluster, at, args, &mut i)?;
                    plan.radix = Some(parse_radix(value)?);
                    break;
                }
                _ => return None,
            }
        }
    }
    Some(plan)
}

/// What `strings` counts as a character of a string: space to tilde, and tab.
fn string_char(byte: u8) -> bool {
    printable(byte) || byte == b'\t'
}

fn emit_string(out: &mut Vec<u8>, run: &[u8], at: usize, radix: Option<Radix>) {
    match radix {
        None => {}
        Some(Radix::Decimal) => out.extend_from_slice(format!("{at:>7} ").as_bytes()),
        Some(Radix::Octal) => out.extend_from_slice(format!("{at:>7o} ").as_bytes()),
        Some(Radix::Hex) => out.extend_from_slice(format!("{at:>7x} ").as_bytes()),
    }
    out.extend_from_slice(run);
    out.push(b'\n');
}

/// Every run of at least `min` string characters, one per line, led by its offset in `radix` when
/// one was asked for. A run at the end of the data counts. Stops once `room` bytes exist.
fn strings_scan(data: &[u8], plan: &StringsPlan<'_>, room: usize) -> Vec<u8> {
    let mut out = Vec::new();
    let mut start: Option<usize> = None;
    let mut at = 0usize;
    // One position past the end is the terminator that closes a trailing run.
    while at <= data.len() {
        if out.len() >= room {
            break;
        }
        if data.get(at).copied().is_some_and(string_char) {
            start.get_or_insert(at);
        } else if let Some(from) = start.take()
            && let Some(run) = data.get(from..at)
            && run.len() >= plan.min
        {
            emit_string(&mut out, run, from, plan.radix);
        }
        at = at.saturating_add(1);
    }
    out
}

impl FakeShell {
    /// `strings [-a] [-n MIN] [-t d|o|x] [-o] [FILE...]`: every run of at least MIN (default 4)
    /// printable characters of the whole of each file, one per line. The whole file is scanned
    /// whatever `-a` says, as binutils does by default today.
    ///
    /// The scan is work the line pays for, and a file longer than what the line has left is
    /// scanned up to that point. A missing file or a directory is `strings: FILE: <errno text>`
    /// with status 1, BusyBox's wording, the only form reachable [unverified].
    pub(super) fn cmd_strings(&mut self, parts: &[&str]) -> CommandResult {
        let Some(plan) = parse_strings(parts.get(1..).unwrap_or(&[])) else {
            return CommandResult::silent(0);
        };
        if plan.min == 0 {
            // [unverified] wording.
            return CommandResult::stderr(1, "strings: invalid minimum string length 0\n");
        }
        let names: Vec<Option<&str>> = if plan.files.is_empty() {
            vec![None]
        } else {
            plan.files.iter().copied().map(Some).collect()
        };
        let mut acc = CommandResult::silent(0);
        let mut failed = false;
        for name in names {
            let room = self.read_cap().min(self.line.remaining());
            let bytes = match self.read_source(parts, name, room) {
                Ok(bytes) => bytes,
                Err(error) => {
                    let label = name.unwrap_or("-");
                    failed = true;
                    acc.append(CommandResult::stderr(
                        1,
                        format!("strings: {label}: {}\n", errno_text(&error)),
                    ));
                    continue;
                }
            };
            if !self.charge_work(len_u64(bytes.len())) {
                return stopped();
            }
            let room = usize::try_from(self.line.remaining()).unwrap_or(usize::MAX);
            acc.append(CommandResult::stdout(strings_scan(&bytes, &plan, room)));
        }
        acc.status = u8::from(failed);
        acc
    }
}
